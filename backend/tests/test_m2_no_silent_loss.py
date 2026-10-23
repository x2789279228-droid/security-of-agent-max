# -*- coding: utf-8 -*-
"""M2：告警消费的响应编排异常不得被吞掉。

此前 `_handle_alert` / `_handle_behavior_alert` 捕获异常后只 warning，
handler 正常返回 → 上层提交 offset → 威胁未处置且不进 DLQ。
本测试钉住：异常必须冒泡到消费重试/DLQ 路径。
"""
from __future__ import annotations

import pytest


class _ExplodingOrchestrator:
    async def on_threat_detected(self, **kwargs):
        raise RuntimeError("orchestrator down")


@pytest.fixture()
def no_sse(monkeypatch):
    from event_bus import event_bus
    monkeypatch.setattr(event_bus, "publish", lambda *a, **k: None)


@pytest.mark.asyncio
async def test_alert_response_failure_propagates(monkeypatch, no_sse):
    import response_engine
    import kafka_consumer

    monkeypatch.setattr(response_engine, "get_orchestrator", lambda: _ExplodingOrchestrator())
    mgr = kafka_consumer.KafkaConsumerManager()
    alert = {
        "alertType": "ANOMALY",
        "eventType": "BRUTE_FORCE",
        "severity": "high",
        "srcIp": "10.0.0.5",
        "anomalyScore": 0.9,
        "eventId": "evt-m2-alert",
    }
    with pytest.raises(RuntimeError, match="orchestrator down"):
        await mgr._handle_alert(alert, trace_id="trace-m2")


@pytest.mark.asyncio
async def test_audit_pq_missing_payload_is_counted():
    """payload 先过期时不能再静默返回 None。"""
    from prometheus_client import REGISTRY
    from audit_pq import AuditPriorityQueue

    class _FakeRedis:
        async def zpopmin(self, key, count=1):
            return [("ghost-member", 1.0)]

        async def get(self, key):
            return None

        async def delete(self, key):
            return 1

    q = AuditPriorityQueue()
    q._redis = _FakeRedis()

    def _val():
        return REGISTRY.get_sample_value(
            "soc_audit_pq_lost_total", {"reason": "payload_missing"}) or 0

    before = _val()
    assert await q.pop_highest() is None
    assert _val() == before + 1, "payload 丢失没有计数"


@pytest.mark.asyncio
async def test_audit_pq_atomic_pop_uses_eval():
    from audit_pq import AuditPriorityQueue

    class _EvalRedis:
        def __init__(self, raw):
            self.raw = raw
            self.calls = 0

        async def eval(self, script, numkeys, key, prefix):
            self.calls += 1
            return [b"member-1", self.raw]

    q = AuditPriorityQueue()
    q._redis = _EvalRedis(b'{"tier": "P0", "event_id": 7}')
    out = await q.pop_highest()
    assert out["tier"] == "P0"
    assert out["event_id"] == 7
    assert q._redis.calls == 1

    q._redis = _EvalRedis(b"")
    assert await q.pop_highest() is None


def test_kafka_producer_enables_idempotence():
    from pathlib import Path

    src = Path(__file__).resolve().parents[1].joinpath("kafka_producer.py").read_text(
        encoding="utf-8", errors="ignore")
    assert "enable_idempotence=True" in src, (
        "生产端未开启幂等：broker 已落盘但响应超时的重试会产生重复消息"
    )


def test_kafka_consumers_read_only_committed():
    """Flink EXACTLY_ONCE 的 abort 事务不得被 Python 消费者读到。"""
    from pathlib import Path

    src = Path(__file__).resolve().parents[1].joinpath("kafka_consumer.py").read_text(
        encoding="utf-8", errors="ignore")
    assert src.count('isolation_level="read_committed"') >= 3, (
        "kafka_consumer 仍有消费者使用默认 read_uncommitted"
    )


def test_temporal_faithfulness_gate_fails_closed(monkeypatch):
    """Temporal 路径的忠实度闸异常时不得默认放行。"""
    import faithfulness_gate
    from temporal.activities import _faithfulness_gate_fail_closed

    def _boom(*args, **kwargs):
        raise RuntimeError("gate down")

    monkeypatch.setattr(faithfulness_gate, "apply_faithfulness_gate", _boom)
    out = _faithfulness_gate_fail_closed(
        {"verdict": "confirmed", "response_blocked": False},
        answer="", contexts=[], query="", abstain=False, non_llm_signals={},
    )
    assert out["response_blocked"] is True, out
    assert out["needs_human_review"] is True, out
    assert "gate down" in out["faithfulness_gate_error"], out


@pytest.mark.asyncio
async def test_behavior_alert_response_failure_propagates(monkeypatch, no_sse):
    import response_engine
    import kafka_consumer

    monkeypatch.setattr(response_engine, "get_orchestrator", lambda: _ExplodingOrchestrator())
    mgr = kafka_consumer.KafkaConsumerManager()
    alert = {
        "srcIp": "10.0.0.6",
        "severity": "high",
        "anomalyScore": 0.9,
        "reasons": ["bytes_out"],
        "eventId": "evt-m2-behavior",
    }
    with pytest.raises(RuntimeError, match="orchestrator down"):
        await mgr._handle_behavior_alert(alert, trace_id="trace-m2")
