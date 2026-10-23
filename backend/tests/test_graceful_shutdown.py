"""关闭时内存里的审计任务必须变成可恢复记录，不能当成已经完成。"""
import asyncio

import pytest

import log_ingestion
from audit_spill import read_records
from audit_worker import AuditWorkerPool, recover_unanalyzed
from config import settings
from drain import drain


class _AR:
    anomaly_score = 0.9
    reasons = ["anomaly:0.90"]
    is_anomaly = True
    deviation_sigma = 0.0


def _hanging(block, calls):
    async def hang(session_id, event_id, log_data, anomaly_report, max_rounds=3):
        calls.append(event_id)
        await block.wait()

    class _Ing:
        _audit_pipeline = staticmethod(hang)

        @staticmethod
        def _audit_task_done(_t):
            return None

    return _Ing


@pytest.fixture()
def spill_file(tmp_path, monkeypatch):
    path = tmp_path / "audit-spill.jsonl"
    monkeypatch.setattr(settings, "audit_spill_path", str(path))
    monkeypatch.setattr(settings, "audit_workers", 1)
    monkeypatch.setattr(settings, "audit_queue_max", 10)
    drain.reset()
    yield path
    drain.reset()


@pytest.mark.asyncio
async def test_stop_spills_queued_and_inflight_instead_of_dropping(monkeypatch, spill_file):
    block = asyncio.Event()
    calls = []
    monkeypatch.setattr(log_ingestion, "log_ingestor", _hanging(block, calls))
    pool = AuditWorkerPool()
    await pool.start()
    assert await pool.submit(
        session_id="s", event_id=11, log_data={"severity": "critical"}, anomaly_report=_AR(),
    ) == "queued"
    await asyncio.sleep(0.05)
    assert await pool.submit(
        session_id="s", event_id=12, log_data={"severity": "high"}, anomaly_report=_AR(),
    ) == "queued"

    report = await pool.stop(timeout=0.05)

    assert report["volatile_lost"] == 0
    saved = {int(row["event_id"]) for row in read_records()}
    assert saved == {11, 12}
    assert pool.queue_depth() == 0
    assert not pool._p0_overflow


@pytest.mark.asyncio
async def test_draining_submit_is_journalled_before_accept(spill_file):
    pool = AuditWorkerPool()
    pool._draining = True
    status = await pool.submit(
        session_id="s", event_id=21, log_data={"severity": "critical"}, anomaly_report=_AR(),
    )
    assert status == "spilled"
    assert [int(row["event_id"]) for row in read_records()] == [21]


@pytest.mark.asyncio
async def test_restart_replays_spill_and_finished_job_leaves_the_journal(monkeypatch, spill_file):
    from audit_spill import append_record

    append_record({
        "session_id": "s",
        "event_id": 31,
        "log_data": {"severity": "high"},
        "tier": "P1",
        "priority": 10,
        "anomaly_score": 0.4,
        "is_anomaly": False,
        "deviation_sigma": 0.0,
        "reasons": [],
    })
    seen = []

    async def finish(session_id, event_id, log_data, anomaly_report, max_rounds=3):
        seen.append(event_id)

    class _Ing:
        _audit_pipeline = staticmethod(finish)

        @staticmethod
        def _audit_task_done(_t):
            return None

    monkeypatch.setattr(log_ingestion, "log_ingestor", _Ing)
    pool = AuditWorkerPool()
    await pool.start()
    for _ in range(20):
        if seen:
            break
        await asyncio.sleep(0.02)
    assert seen == [31]
    await pool.stop(timeout=1)
    assert read_records() == []


@pytest.mark.asyncio
async def test_recover_unanalyzed_from_database(monkeypatch, spill_file):
    from models import Base, SecurityEvent, async_session, engine

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    async with async_session() as session:
        row = SecurityEvent(
            session_id="crash-recover",
            event_type="BRUTE_FORCE",
            severity="high",
            src_ip="10.1.1.1",
            message="still pending",
            raw_data={"event": "BRUTE_FORCE", "severity": "high"},
            analyzed=False,
            anomaly_score=0.8,
        )
        session.add(row)
        await session.commit()
        await session.refresh(row)
        target = int(row.id)

    pool = AuditWorkerPool()
    pool._started = True
    seen = []

    async def fake_submit(**kwargs):
        seen.append(int(kwargs["event_id"]))
        return "queued"

    pool.submit = fake_submit
    import audit_worker as audit_worker_mod
    monkeypatch.setattr(audit_worker_mod, "audit_worker", pool)

    restored = await recover_unanalyzed(limit=100000)
    assert target in seen
    assert restored >= 1


@pytest.mark.asyncio
async def test_shutdown_order_drains_before_closing_brokers(monkeypatch):
    calls = []

    class _Consumer:
        async def begin_drain(self):
            calls.append("consumer_drain")

        async def stop(self):
            calls.append("consumer_stop")

    class _Producer:
        async def flush(self):
            calls.append("producer_flush")

        async def stop(self):
            calls.append("producer_stop")

    class _Audit:
        async def stop(self):
            calls.append("audit_stop")
            return {"spilled": 0, "volatile_lost": 0}

    class _Scheduler:
        async def stop(self):
            calls.append("scheduler_stop")

    class _Bus:
        async def stop_redis_bridge(self):
            calls.append("redis_bridge")

    class _Summary:
        async def close(self):
            calls.append("summary_close")

    class _Window:
        async def close(self):
            calls.append("redis_close")

    monkeypatch.setattr(settings, "kafka_enabled", True)
    import kafka_consumer
    import kafka_producer
    import audit_worker as audit_worker_mod
    import scheduler as scheduler_mod
    import event_bus as event_bus_mod
    import summary_compression
    import sliding_window as sliding_window_mod
    import models

    monkeypatch.setattr(kafka_consumer, "kafka_consumer_manager", _Consumer())
    monkeypatch.setattr(kafka_producer, "kafka_producer", _Producer())
    monkeypatch.setattr(audit_worker_mod, "audit_worker", _Audit())
    monkeypatch.setattr(scheduler_mod, "scheduler", _Scheduler())
    monkeypatch.setattr(event_bus_mod, "event_bus", _Bus())
    monkeypatch.setattr(summary_compression, "summary", _Summary())
    monkeypatch.setattr(summary_compression, "embedder", _Summary())
    monkeypatch.setattr(sliding_window_mod, "sliding_window", _Window())

    async def _dispose():
        calls.append("db_dispose")

    monkeypatch.setattr(models, "dispose_engines", _dispose)

    from lifecycle import shutdown_platform
    try:
        await shutdown_platform()
        assert drain.phase == "stopped"
    finally:
        drain.reset()

    assert calls.index("consumer_drain") < calls.index("audit_stop")
    assert calls.index("audit_stop") < calls.index("producer_flush")
    assert calls.index("producer_flush") < calls.index("producer_stop")
    assert calls.index("producer_stop") < calls.index("consumer_stop")
    assert calls.index("consumer_stop") < calls.index("redis_close")
    assert calls.index("redis_close") < calls.index("db_dispose")
