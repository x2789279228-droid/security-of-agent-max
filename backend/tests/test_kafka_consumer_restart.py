"""Kafka 消费循环在仍应运行时退出必须被拉起；stop/drain 后不得再拉起。"""
import asyncio
import inspect

import kafka_consumer
from kafka_consumer import KafkaConsumerManager, MAX_POLL_INTERVAL_MS


def test_max_poll_interval_covers_slow_audit():
    assert MAX_POLL_INTERVAL_MS >= 600_000


def test_start_wraps_loops_with_supervisor():
    src = inspect.getsource(KafkaConsumerManager.start)
    assert "_supervised_loop" in src
    consume = inspect.getsource(KafkaConsumerManager._consume_loop)
    ingest = inspect.getsource(KafkaConsumerManager._consume_python_ingest)
    cep = inspect.getsource(KafkaConsumerManager._consume_cep_partial)
    assert "max_poll_interval_ms" in consume
    assert "max_poll_interval_ms" in ingest
    assert "max_poll_interval_ms" in cep


def test_consume_loop_passes_max_poll_interval(monkeypatch):
    seen = {}

    class Cap:
        def __init__(self, *args, **kwargs):
            seen.update(kwargs)

        async def start(self):
            raise RuntimeError("constructed")

        async def stop(self):
            return None

        async def commit(self, offsets=None):
            return None

        def seek(self, *args, **kwargs):
            return None

    monkeypatch.setattr(kafka_consumer, "AIOKafkaConsumer", Cap)
    mgr = KafkaConsumerManager()
    mgr._running = True

    async def handler(event, trace_id):
        return None

    async def case():
        await mgr._consume_loop("t", "rejected", handler, "rejected_consumed")

    asyncio.run(case())
    assert seen["max_poll_interval_ms"] == MAX_POLL_INTERVAL_MS
    assert seen["enable_auto_commit"] is False


def test_supervised_loop_restarts_while_running():
    mgr = KafkaConsumerManager()
    mgr._running = True
    mgr._restart_initial_s = 0.01
    mgr._restart_max_s = 0.02
    runs = {"n": 0}

    async def factory():
        runs["n"] += 1
        if runs["n"] >= 2:
            mgr._running = False

    async def case():
        await mgr._supervised_loop("audit", factory)
        return runs["n"]

    assert asyncio.run(case()) == 2


def test_supervised_loop_restarts_after_crash():
    mgr = KafkaConsumerManager()
    mgr._running = True
    mgr._restart_initial_s = 0.01
    mgr._restart_max_s = 0.02
    runs = {"n": 0}

    async def factory():
        runs["n"] += 1
        if runs["n"] == 1:
            raise RuntimeError("boom")
        mgr._running = False

    async def case():
        await mgr._supervised_loop("rejected", factory)
        return runs["n"]

    assert asyncio.run(case()) == 2


def test_supervised_loop_does_not_restart_after_stop():
    mgr = KafkaConsumerManager()
    mgr._running = True
    mgr._restart_initial_s = 0.01
    runs = {"n": 0}

    async def factory():
        runs["n"] += 1
        mgr._running = False

    async def case():
        await mgr._supervised_loop("alerts", factory)
        return runs["n"]

    assert asyncio.run(case()) == 1


def test_supervised_loop_cancelled_does_not_restart():
    mgr = KafkaConsumerManager()
    mgr._running = True
    mgr._restart_initial_s = 0.01
    started = asyncio.Event()
    runs = {"n": 0}

    async def factory():
        runs["n"] += 1
        started.set()
        await asyncio.sleep(30)

    async def case():
        task = asyncio.create_task(mgr._supervised_loop("lag", factory))
        await started.wait()
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        return runs["n"]

    assert asyncio.run(case()) == 1
