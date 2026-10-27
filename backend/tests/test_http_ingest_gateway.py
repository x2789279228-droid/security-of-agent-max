"""P2 HTTP 网关: producer 活跃 → 202 queued 且不借 OLTP session;
kafka_enabled=True 但 producer 未就绪 → 503 not_durable 拒收(禁止静默降级);
kafka_enabled=False(http 模式) → 同步 ingest, HTTP 200, dummy 结果合并。
"""
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


def _no_get_session():
    raise AssertionError("get_session must not be called when producer active")


async def _fake_session():
    yield None


@pytest.fixture()
def client():
    with TestClient(_app()) as c:
        yield c


def test_ingest_202_queued_and_no_session(monkeypatch, client):
    from config import settings

    captured = []

    async def fake_enqueue(session_id, api_key, events):
        captured.append({"session_id": session_id, "api_key": api_key, "events": list(events)})
        return len(events)

    monkeypatch.setattr(logs_router, "_ingest_mode", lambda: "kafka")
    monkeypatch.setattr(logs_router, "_enqueue_ingest", fake_enqueue)
    # producer 活跃时 get_session 绝不能被调用
    monkeypatch.setattr(models, "get_session", _no_get_session)

    resp = client.post("/api/logs/ingest", json={
        "message": {"event": "BRUTE_FORCE", "message": "<b>hi</b>", "severity": "high"},
        "session_id": "s1",
    })

    assert resp.status_code == int(settings.ingest_http_queued_status or 202)
    body = resp.json()
    assert body["status"] == "queued"
    assert body["session_id"] == "s1"
    assert body["produced"] == 1
    # sanitize 仍然生效
    assert captured[0]["api_key"] == ""
    assert captured[0]["events"][0]["message"] == "hi"
    assert captured[0]["events"][0]["eventId"]
    assert body["eventId"] == captured[0]["events"][0]["eventId"]


def test_ingest_202_preserves_client_event_id(monkeypatch, client):
    captured = []

    async def fake_enqueue(session_id, api_key, events):
        captured.append(list(events))
        return len(events)

    monkeypatch.setattr(logs_router, "_ingest_mode", lambda: "kafka")
    monkeypatch.setattr(logs_router, "_enqueue_ingest", fake_enqueue)
    monkeypatch.setattr(models, "get_session", _no_get_session)

    eid = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
    resp = client.post("/api/logs/ingest", json={
        "message": {"event": "BRUTE_FORCE", "eventId": eid, "severity": "high"},
        "session_id": "s-keep",
    })
    assert resp.status_code == 202
    assert resp.json()["eventId"] == eid
    assert captured[0][0]["eventId"] == eid


def test_batch_202_forwards_api_key(monkeypatch, client):
    captured = []

    async def fake_enqueue(session_id, api_key, events):
        captured.append({"session_id": session_id, "api_key": api_key, "events": list(events)})
        return len(events)

    # P0-3/P0-5: batch 与单条共用鉴权 —— 无效 key 会被 403 拒绝。
    # 本测试验证的是「有效 key 的值被原样转发到入队层」，先注册合法来源。
    from source_registry import source_registry

    class _Src:
        name = "sim"

    monkeypatch.setattr(source_registry, "authenticate",
                        lambda k: _Src() if k == "abc" else None)
    monkeypatch.setattr(logs_router, "_ingest_mode", lambda: "kafka")
    monkeypatch.setattr(logs_router, "_enqueue_ingest", fake_enqueue)
    monkeypatch.setattr(models, "get_session", _no_get_session)

    resp = client.post(
        "/api/logs/ingest/batch",
        json={"logs": [{"event": "PORT_SCAN"}, {"event": "C2_BEACON"}], "session_id": "sb"},
        headers={"X-API-Key": "abc"},
    )

    assert resp.status_code == 202
    body = resp.json()
    assert body["status"] == "queued"
    assert body["count"] == 2
    assert body["produced"] == 2
    assert captured[0]["api_key"] == "abc"
    assert captured[0]["session_id"] == "sb"
    assert len(captured[0]["events"]) == 2


def test_batch_403_for_invalid_api_key(monkeypatch, client):
    """P0-3/P0-5: 无效 key 的 batch 请求必须 403，且不得触达入队层。"""
    from source_registry import source_registry

    async def forbidden_enqueue(session_id, api_key, events):
        raise AssertionError("无效 key 不得写入 Kafka")

    monkeypatch.setattr(source_registry, "authenticate", lambda k: None)
    monkeypatch.setattr(logs_router, "_ingest_mode", lambda: "kafka")
    monkeypatch.setattr(logs_router, "_enqueue_ingest", forbidden_enqueue)
    monkeypatch.setattr(models, "get_session", _no_get_session)

    resp = client.post(
        "/api/logs/ingest/batch",
        json={"logs": [{"event": "PORT_SCAN"}], "session_id": "sbad"},
        headers={"X-API-Key": "forged"},
    )
    assert resp.status_code == 403


def test_batch_202_without_api_key_header(monkeypatch, client):
    captured = []

    async def fake_enqueue(session_id, api_key, events):
        captured.append({"api_key": api_key, "n": len(events)})
        return len(events)

    monkeypatch.setattr(logs_router, "_ingest_mode", lambda: "kafka")
    monkeypatch.setattr(logs_router, "_enqueue_ingest", fake_enqueue)
    monkeypatch.setattr(models, "get_session", _no_get_session)

    resp = client.post("/api/logs/ingest/batch", json={"logs": ["{\"event\": \"X\"}"]})

    assert resp.status_code == 202
    assert captured[0]["api_key"] == ""


def test_batch_207_when_kafka_partially_acks(monkeypatch, client):
    async def fake_enqueue(session_id, api_key, events):
        return 2

    monkeypatch.setattr(logs_router, "_ingest_mode", lambda: "kafka")
    monkeypatch.setattr(logs_router, "_enqueue_ingest", fake_enqueue)
    monkeypatch.setattr(models, "get_session", _no_get_session)

    resp = client.post(
        "/api/logs/ingest/batch",
        json={"logs": [{"event": "A"}, {"event": "B"}, {"event": "C"}], "session_id": "sp"},
    )
    assert resp.status_code == 207
    body = resp.json()
    assert body["status"] == "partial"
    assert body["produced"] == 2
    assert body["failed"] == 1
    assert body["count"] == 3


def test_ingest_503_when_kafka_does_not_ack(monkeypatch, client):
    async def fake_enqueue(session_id, api_key, events):
        return 0

    monkeypatch.setattr(logs_router, "_ingest_mode", lambda: "kafka")
    monkeypatch.setattr(logs_router, "_enqueue_ingest", fake_enqueue)
    monkeypatch.setattr(models, "get_session", _no_get_session)

    resp = client.post("/api/logs/ingest", json={
        "message": {"event": "BRUTE_FORCE", "severity": "high"},
        "session_id": "s-partial",
    })
    assert resp.status_code == 503
    assert resp.json()["status"] == "not_durable"
    assert resp.json()["produced"] == 0


def test_ingest_503_while_draining(monkeypatch, client):
    from drain import drain

    async def fake_enqueue(session_id, api_key, events):
        raise AssertionError("draining 时不得再写入 Kafka")

    monkeypatch.setattr(logs_router, "_ingest_mode", lambda: "kafka")
    monkeypatch.setattr(logs_router, "_enqueue_ingest", fake_enqueue)
    monkeypatch.setattr(models, "get_session", _no_get_session)
    drain.begin()
    try:
        resp = client.post("/api/logs/ingest", json={
            "message": {"event": "BRUTE_FORCE"},
            "session_id": "s-drain",
        })
    finally:
        drain.reset()
    assert resp.status_code == 503
    assert resp.json()["status"] == "draining"


def test_ingest_falls_back_to_sync_200(monkeypatch, client):
    async def dummy_ingest(session, session_id, log_data):
        return {"status": "review_queued", "event_id": 7, "event_type": "REQ"}

    async def dummy_ingest_batch(session, session_id, parsed):
        return {"status": "review_queued", "count": len(parsed)}

    class _Stub:
        ingest = staticmethod(dummy_ingest)
        ingest_batch = staticmethod(dummy_ingest_batch)

    monkeypatch.setattr(logs_router, "_ingest_mode", lambda: "http")
    monkeypatch.setattr(models, "get_session", _fake_session)
    monkeypatch.setattr(logs_router, "log_ingestor", _Stub)

    resp = client.post("/api/logs/ingest", json={
        "message": {"event": "REQ", "message": "m", "severity": "info"},
        "session_id": "s2",
    })
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "review_queued"
    assert body["event_id"] == 7
    assert body["session_id"] == "s2"


def test_batch_falls_back_to_sync_200(monkeypatch, client):
    async def dummy_ingest_batch(session, session_id, parsed):
        return {"status": "review_queued", "count": len(parsed)}

    class _Stub:
        ingest = staticmethod(lambda *a, **k: (_ for _ in ()).throw(AssertionError("no single ingest")))
        ingest_batch = staticmethod(dummy_ingest_batch)

    monkeypatch.setattr(logs_router, "_ingest_mode", lambda: "http")
    monkeypatch.setattr(models, "get_session", _fake_session)
    monkeypatch.setattr(logs_router, "log_ingestor", _Stub)

    resp = client.post(
        "/api/logs/ingest/batch",
        json={"logs": [{"event": "A"}, {"event": "B"}], "session_id": "sb2"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "review_queued"
    assert body["count"] == 2
    assert body["session_id"] == "sb2"


def test_ingest_503_when_kafka_enabled_but_producer_dead(monkeypatch, client):
    """kafka_enabled=True 但生产者未就绪必须 503 拒收 —— 静默回退直写会让
    压测把 HTTP→PG 当成 Kafka 流水线口径(2026-10-25 审计)。"""
    from source_registry import source_registry

    async def forbidden_enqueue(session_id, api_key, events):
        raise AssertionError("producer 未就绪时不得入队")

    class _Stub:
        ingest = staticmethod(lambda *a, **k: (_ for _ in ()).throw(AssertionError("不得直写 PG")))
        ingest_batch = staticmethod(lambda *a, **k: (_ for _ in ()).throw(AssertionError("不得直写 PG")))

    monkeypatch.setattr(source_registry, "authenticate", lambda k: None)
    monkeypatch.setattr(logs_router, "_ingest_mode", lambda: "kafka_unavailable")
    monkeypatch.setattr(logs_router, "_enqueue_ingest", forbidden_enqueue)
    monkeypatch.setattr(logs_router, "log_ingestor", _Stub)

    resp = client.post("/api/logs/ingest", json={
        "message": {"event": "BRUTE_FORCE", "severity": "high"},
        "session_id": "s-degraded",
    })
    assert resp.status_code == 503
    body = resp.json()
    assert body["status"] == "not_durable"
    assert body["reason"] == "kafka_unavailable"


def test_batch_503_when_kafka_enabled_but_producer_dead(monkeypatch, client):
    from source_registry import source_registry

    class _Stub:
        ingest = staticmethod(lambda *a, **k: (_ for _ in ()).throw(AssertionError("不得直写 PG")))
        ingest_batch = staticmethod(lambda *a, **k: (_ for _ in ()).throw(AssertionError("不得直写 PG")))

    monkeypatch.setattr(source_registry, "authenticate", lambda k: None)
    monkeypatch.setattr(logs_router, "_ingest_mode", lambda: "kafka_unavailable")
    monkeypatch.setattr(logs_router, "log_ingestor", _Stub)

    resp = client.post(
        "/api/logs/ingest/batch",
        json={"logs": [{"event": "A"}, {"event": "B"}], "session_id": "sb-degraded"},
    )
    assert resp.status_code == 503
    body = resp.json()
    assert body["status"] == "not_durable"
    assert body["reason"] == "kafka_unavailable"
