"""资源容量：批次硬顶、扇出上限、过载拒绝，以及水位下降后重新接受。"""
import asyncio

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import models
import routers.logs as logs_router
from routers.logs import router


def _app() -> FastAPI:
    app = FastAPI()
    app.include_router(router)
    return app


@pytest.fixture()
def client():
    with TestClient(_app()) as c:
        yield c


def test_batch_plan_chunk_reject_and_absolute(monkeypatch):
    from config import settings
    from capacity import plan_batch_count

    monkeypatch.setattr(settings, "http_ingest_max_batch", 200)
    monkeypatch.setattr(settings, "http_ingest_absolute_max", 1000)
    monkeypatch.setattr(settings, "http_ingest_batch_policy", "chunk")
    assert plan_batch_count(10) == ("ok", 200)
    assert plan_batch_count(200) == ("ok", 200)
    assert plan_batch_count(201) == ("chunk", 200)
    assert plan_batch_count(1001) == ("reject", 1000)

    monkeypatch.setattr(settings, "http_ingest_batch_policy", "reject")
    assert plan_batch_count(201) == ("reject", 200)


def test_pressure_latches_until_low_watermark(monkeypatch):
    import capacity
    from capacity import kafka_fetch_paused, reset_gates
    from config import settings

    reset_gates()
    state = {"ratio": 0.0}
    monkeypatch.setattr(capacity, "audit_queue_ratio", lambda: state["ratio"])
    monkeypatch.setattr(settings, "audit_queue_high_watermark", 0.8)
    monkeypatch.setattr(settings, "audit_queue_low_watermark", 0.5)

    state["ratio"] = 0.95
    assert kafka_fetch_paused() is True
    state["ratio"] = 0.7
    assert kafka_fetch_paused() is True
    state["ratio"] = 0.4
    assert kafka_fetch_paused() is False
    state["ratio"] = 0.7
    assert kafka_fetch_paused() is False


@pytest.mark.asyncio
async def test_gate_caps_inflight_and_times_out(monkeypatch):
    from config import settings
    from capacity import GateTimeout, db_write_gate, reset_gates

    monkeypatch.setattr(settings, "db_write_max_concurrency", 2)
    reset_gates()
    gate = db_write_gate()
    current = 0
    peak = 0

    async def one():
        nonlocal current, peak
        async with gate.acquire(timeout=1):
            current += 1
            peak = max(peak, current)
            await asyncio.sleep(0.05)
            current -= 1

    await asyncio.gather(*[one() for _ in range(8)])
    assert peak == 2
    assert gate.inflight() == 0

    monkeypatch.setattr(settings, "db_write_max_concurrency", 1)
    assert await gate.try_acquire()
    with pytest.raises(GateTimeout):
        async with gate.acquire(timeout=0.05):
            pass
    assert gate.inflight() == 1
    assert gate.waiters() == 0
    await gate.release()
    assert gate.inflight() == 0


@pytest.mark.asyncio
async def test_admit_rejects_when_saturated_then_accepts(monkeypatch):
    import capacity
    from capacity import AdmissionDenied, admit_http, db_write_gate, reset_gates
    from config import settings

    monkeypatch.setattr(settings, "db_write_max_concurrency", 1)
    monkeypatch.setattr(capacity, "audit_queue_ratio", lambda: 0.0)
    reset_gates()
    gate = db_write_gate()
    assert await gate.try_acquire()
    with pytest.raises(AdmissionDenied) as raised:
        await admit_http(direct=True)
    assert raised.value.reason == "downstream_saturated"
    await gate.release()
    await admit_http(direct=True)

    monkeypatch.setattr(capacity, "audit_queue_ratio", lambda: 0.99)
    with pytest.raises(AdmissionDenied) as high:
        await admit_http(direct=False)
    assert high.value.reason == "audit_queue_high_watermark"
    monkeypatch.setattr(capacity, "audit_queue_ratio", lambda: 0.1)
    await admit_http(direct=False)


@pytest.mark.asyncio
async def test_poll_does_not_fetch_while_paused(monkeypatch):
    import capacity
    from capacity import reset_gates
    from config import settings
    from kafka_consumer import KafkaConsumerManager

    reset_gates()
    paused = {"on": True}
    monkeypatch.setattr(capacity, "kafka_fetch_paused", lambda: paused["on"])
    monkeypatch.setattr(settings, "kafka_fetch_pause_s", 0.01)
    called = []

    class Consumer:
        async def getmany(self, **kwargs):
            called.append(kwargs)
            return {"fetched": 1}

    class Tracker:
        def uncommitted(self):
            return {}

    mgr = KafkaConsumerManager()
    missed = await mgr._poll_many(Consumer(), Tracker(), timeout_ms=5, max_records=3)
    assert missed == {}
    assert called == []

    paused["on"] = False
    got = await mgr._poll_many(Consumer(), Tracker(), timeout_ms=5, max_records=3)
    assert got == {"fetched": 1}
    assert called


@pytest.mark.asyncio
async def test_produce_inflight_stays_within_cap(monkeypatch):
    from config import settings
    from capacity import kafka_produce_gate, reset_gates
    from kafka_producer import KafkaProducerWrapper

    monkeypatch.setattr(settings, "kafka_produce_max_inflight", 2)
    monkeypatch.setattr(settings, "kafka_produce_batch_size", 10)
    monkeypatch.setattr(settings, "kafka_produce_timeout_s", 2)
    reset_gates()
    peak = 0
    sent = []

    class Producer:
        def send(self, topic, key, value, headers):
            loop = asyncio.get_running_loop()
            fut = loop.create_future()

            async def work():
                nonlocal peak
                gate = kafka_produce_gate()
                peak = max(peak, gate.inflight())
                sent.append(key)
                await asyncio.sleep(0.02)
                if not fut.done():
                    fut.set_result("ok")

            asyncio.create_task(work())
            return fut

    wrapper = KafkaProducerWrapper()
    wrapper._started = True
    wrapper._producer = Producer()
    events = [{"eventId": str(i), "event": "PING"} for i in range(6)]
    n = await wrapper.produce_raw_batch(events, topic="t", key_field="eventId")
    assert n == 6
    assert 1 <= peak <= 2
    assert sorted(sent, key=int) == [str(i) for i in range(6)]


@pytest.mark.asyncio
async def test_run_many_detect_fanout_is_bounded(monkeypatch):
    import ingest_pipeline as ip
    from config import settings
    from capacity import reset_gates
    from ingest_pipeline import (
        DetectResult, DispatchResult, PersistResult, empty_anomaly, run_many,
    )

    monkeypatch.setattr(settings, "audit_batch_concurrency", 3)
    monkeypatch.setattr(settings, "http_ingest_batch_timeout_s", 5)
    monkeypatch.setattr(settings, "http_ingest_downstream_wait_s", 2)
    reset_gates()
    current = 0
    peak = 0

    async def fake_detect(payload):
        nonlocal current, peak
        current += 1
        peak = max(peak, current)
        await asyncio.sleep(0.04)
        current -= 1
        return DetectResult(log_data=payload, anomaly=empty_anomaly(), sigma={})

    async def fake_persist(session, items):
        out = []
        for i, (dr, sid) in enumerate(items):
            stored = type("Stored", (), {"id": i + 1})()
            out.append(PersistResult(
                stored=stored, log_data=dr.log_data, anomaly=dr.anomaly, session_id=sid,
            ))
        return out

    async def fake_dispatch(*args, **kwargs):
        return DispatchResult(event_id=1)

    monkeypatch.setattr(ip, "detect", fake_detect)
    monkeypatch.setattr(ip, "persist_batch", fake_persist)
    monkeypatch.setattr(ip, "dispatch", fake_dispatch)
    events = [("s", {"event": "E", "n": i}) for i in range(7)]
    results = await run_many(None, events)
    assert len(results) == 7
    assert peak == 3
    assert current == 0


@pytest.mark.asyncio
async def test_ingest_batch_chunks_and_rejects(monkeypatch):
    from config import settings
    from capacity import BatchRejected
    from log_ingestion import log_ingestor
    import ingest_pipeline as ip

    monkeypatch.setattr(settings, "http_ingest_max_batch", 2)
    monkeypatch.setattr(settings, "http_ingest_absolute_max", 10)
    monkeypatch.setattr(settings, "http_ingest_batch_policy", "chunk")
    monkeypatch.setattr(settings, "database_url", "postgresql://capacity-test")
    seen = []

    async def fake_run_many(session, events, ingestor=None):
        seen.append(len(events))
        from ingest_pipeline import RunResult
        return [
            RunResult(
                status="review_queued", event_id=i + 1, event_type="E",
                severity="info", anomaly={}, sigma={}, process_status="success",
            )
            for i, _ in enumerate(events)
        ]

    monkeypatch.setattr(ip, "run_many", fake_run_many)
    result = await log_ingestor.ingest_batch(None, "s", [{"event": str(i)} for i in range(4)])
    assert seen == [2, 2]
    assert result["count"] == 4
    assert result["chunks"] == 2

    monkeypatch.setattr(settings, "http_ingest_batch_policy", "reject")
    with pytest.raises(BatchRejected) as raised:
        await log_ingestor.ingest_batch(None, "s", [{"event": "a"}, {"event": "b"}, {"event": "c"}])
    assert raised.value.limit == 2
    assert raised.value.count == 3


@pytest.mark.asyncio
async def test_llm_rate_rejects_without_waiting(monkeypatch):
    from config import settings
    from llm_limiter import LlmRateExceeded, reset_llm_limiter

    monkeypatch.setattr(settings, "llm_rate_per_minute", 2)
    monkeypatch.setattr(settings, "llm_global_concurrency", 4)
    lim = reset_llm_limiter()
    async with lim.acquire(tier="P2", timeout=1):
        pass
    async with lim.acquire(tier="P2", timeout=1):
        pass
    started = asyncio.get_running_loop().time()
    with pytest.raises(LlmRateExceeded):
        async with lim.acquire(tier="P2", timeout=1):
            pass
    assert asyncio.get_running_loop().time() - started < 0.3
    assert lim.inflight() == 0


@pytest.mark.asyncio
async def test_background_tasks_stop_at_the_cap(monkeypatch):
    from config import settings
    from capacity import background_task_gate, reset_gates, schedule_bounded

    monkeypatch.setattr(settings, "http_background_max", 2)
    reset_gates()
    release = asyncio.Event()
    running = 0
    peak = 0

    async def work():
        nonlocal running, peak
        running += 1
        peak = max(peak, running)
        await release.wait()
        running -= 1

    gate = background_task_gate()
    assert await schedule_bounded(work(), gate=gate, label="a")
    assert await schedule_bounded(work(), gate=gate, label="b")
    await asyncio.sleep(0.02)
    assert await schedule_bounded(work(), gate=gate, label="c") is False
    assert peak == 2
    assert gate.inflight() == 2
    release.set()
    for _ in range(20):
        if gate.inflight() == 0:
            break
        await asyncio.sleep(0.01)
    assert gate.inflight() == 0
    assert running == 0


def test_pg_engine_gets_query_timeout(monkeypatch):
    from config import settings
    import models as models_mod

    captured = {}

    def fake_create(url, **kwargs):
        captured["url"] = str(url)
        captured["kwargs"] = kwargs
        return object()

    monkeypatch.setattr(models_mod, "create_async_engine", fake_create)
    monkeypatch.setattr(settings, "database_url", "postgresql+asyncpg://localhost/db")
    monkeypatch.setattr(settings, "db_query_timeout_s", 12)
    models_mod._make_engine(2, 1, 1.0)
    assert captured["kwargs"]["connect_args"]["command_timeout"] == 12

    captured.clear()
    monkeypatch.setattr(settings, "database_url", "sqlite+aiosqlite:///:memory:")
    models_mod._make_engine(2, 1, 1.0)
    assert "connect_args" not in captured["kwargs"]


def test_http_overloads_then_accepts_again(monkeypatch, client):
    import capacity
    from config import settings

    state = {"ratio": 0.95}
    called = []

    async def fake_enqueue(session_id, api_key, events):
        called.append(len(events))
        return len(events)

    monkeypatch.setattr(capacity, "audit_queue_ratio", lambda: state["ratio"])
    monkeypatch.setattr(settings, "audit_queue_high_watermark", 0.8)
    monkeypatch.setattr(settings, "audit_queue_low_watermark", 0.5)
    monkeypatch.setattr(logs_router, "_ingest_mode", lambda: "kafka")
    monkeypatch.setattr(logs_router, "_enqueue_ingest", fake_enqueue)
    monkeypatch.setattr(models, "get_session", lambda: (_ for _ in ()).throw(AssertionError("no session")))

    first = client.post("/api/logs/ingest", json={"message": {"event": "PING"}, "session_id": "s"})
    assert first.status_code == 503
    assert first.json()["status"] == "overloaded"
    assert first.json()["reason"] == "audit_queue_high_watermark"
    assert first.headers.get("retry-after")
    assert called == []

    state["ratio"] = 0.2
    second = client.post("/api/logs/ingest", json={"message": {"event": "PING"}, "session_id": "s"})
    assert second.status_code == int(settings.ingest_http_queued_status or 202)
    assert second.json()["status"] == "queued"
    assert called == [1]


def test_http_batch_reject_absolute_and_body(monkeypatch, client):
    from config import settings

    monkeypatch.setattr(logs_router, "_ingest_mode", lambda: "kafka")
    monkeypatch.setattr(settings, "http_ingest_max_batch", 2)
    monkeypatch.setattr(settings, "http_ingest_absolute_max", 4)
    monkeypatch.setattr(settings, "http_ingest_batch_policy", "reject")

    rejected = client.post("/api/logs/ingest/batch", json={"logs": [{"event": "A"}, {"event": "B"}, {"event": "C"}]})
    assert rejected.status_code == 413
    assert "exceeds limit of 2" in rejected.text

    monkeypatch.setattr(settings, "http_ingest_batch_policy", "chunk")
    absolute = client.post("/api/logs/ingest/batch", json={"logs": [{"event": str(i)} for i in range(5)]})
    assert absolute.status_code == 413
    assert "exceeds limit of 4" in absolute.text

    monkeypatch.setattr(settings, "http_ingest_max_body_bytes", 20)
    huge = client.post("/api/logs/ingest", json={"message": {"event": "PING", "message": "x" * 80}})
    assert huge.status_code == 413
