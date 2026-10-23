"""Kafka handler: 临时故障指数退避，永久错误进 DLQ，unordered 才走 retry topic。"""
import asyncio

import kafka_consumer
from kafka_consumer import KafkaConsumerManager
from tests.test_kafka_offset_commit import Rec, _manager


def _msg(offset=5, value=None):
    return Rec(0, offset, value or {"eventId": "y", "eventType": "LOGIN"})


def test_transient_uses_exponential_backoff_not_one_point_five(monkeypatch):
    sleeps = []

    async def fake_sleep(delay):
        sleeps.append(delay)

    monkeypatch.setattr(kafka_consumer.asyncio, "sleep", fake_sleep)
    from config import settings
    monkeypatch.setattr(settings, "kafka_retry_initial_s", 1.0)
    monkeypatch.setattr(settings, "kafka_retry_multiplier", 2.0)
    monkeypatch.setattr(settings, "kafka_retry_max_delay_s", 30.0)
    monkeypatch.setattr(settings, "kafka_retry_jitter", 0.0)
    monkeypatch.setattr(settings, "kafka_retry_budget_s", 60.0)
    monkeypatch.setattr(settings, "kafka_retry_topic_enabled", False)
    monkeypatch.setattr(kafka_consumer.schema_registry, "validate", lambda topic, event: [])

    mgr = _manager(monkeypatch)
    monkeypatch.setattr(kafka_consumer, "MAX_RETRY", 3)
    calls = []
    dlq = []

    async def handler(event, trace_id):
        calls.append(1)
        raise TimeoutError("downstream timeout")

    async def no_dlq(*a, **k):
        dlq.append(1)
        return True

    monkeypatch.setattr(mgr, "_send_to_dlq", no_dlq)

    async def _case():
        return await mgr._process_message(
            _msg(), {"eventId": "y", "eventType": "LOGIN"},
            "security-logs-rejected", "", handler, "rejected_consumed", "g",
        )

    ok = asyncio.run(_case())
    assert ok is False
    assert len(calls) == 3
    assert sleeps == [1.0, 2.0]
    assert dlq == []


def test_permanent_value_error_goes_dlq_without_retry_loop(monkeypatch):
    sleeps = []

    async def fake_sleep(delay):
        sleeps.append(delay)

    monkeypatch.setattr(kafka_consumer.asyncio, "sleep", fake_sleep)
    monkeypatch.setattr(kafka_consumer.schema_registry, "validate", lambda topic, event: [])
    mgr = _manager(monkeypatch)
    monkeypatch.setattr(kafka_consumer, "MAX_RETRY", 5)
    calls = []
    dlq = []

    async def handler(event, trace_id):
        calls.append(1)
        raise ValueError("contract broken")

    async def send_dlq(*a, **k):
        dlq.append(k.get("error_code") or a[2])
        return True

    monkeypatch.setattr(mgr, "_send_to_dlq", send_dlq)

    async def _case():
        return await mgr._process_message(
            _msg(), {"eventId": "y", "eventType": "LOGIN"},
            "security-logs-rejected", "", handler, "rejected_consumed", "g",
        )

    ok = asyncio.run(_case())
    assert ok is True
    assert calls == [1]
    assert sleeps == []
    assert dlq


def test_unordered_retry_topic_commits_original_offset(monkeypatch):
    from config import settings
    monkeypatch.setattr(kafka_consumer, "MAX_RETRY", 1)
    monkeypatch.setattr(settings, "kafka_retry_topic_enabled", True)
    monkeypatch.setattr(settings, "kafka_retry_ordering", "unordered")
    monkeypatch.setattr(kafka_consumer.schema_registry, "validate", lambda topic, event: [])
    mgr = _manager(monkeypatch)
    sent = []

    async def handler(event, trace_id):
        raise TimeoutError("down")

    async def send_retry(*a, **k):
        sent.append(True)
        return True

    monkeypatch.setattr(mgr, "_send_to_retry_topic", send_retry)

    async def _case():
        return await mgr._process_message(
            _msg(), {"eventId": "y", "eventType": "LOGIN"},
            "security-logs-rejected", "", handler, "rejected_consumed", "g",
        )

    ok = asyncio.run(_case())
    assert ok is True
    assert sent == [True]


def test_strict_does_not_send_retry_topic(monkeypatch):
    from config import settings
    monkeypatch.setattr(kafka_consumer, "MAX_RETRY", 1)
    monkeypatch.setattr(settings, "kafka_retry_topic_enabled", True)
    monkeypatch.setattr(settings, "kafka_retry_ordering", "strict")
    monkeypatch.setattr(kafka_consumer.schema_registry, "validate", lambda topic, event: [])
    mgr = _manager(monkeypatch)
    sent = []

    async def handler(event, trace_id):
        raise TimeoutError("down")

    async def send_retry(*a, **k):
        sent.append(True)
        return True

    monkeypatch.setattr(mgr, "_send_to_retry_topic", send_retry)

    async def _case():
        return await mgr._process_message(
            _msg(), {"eventId": "y", "eventType": "LOGIN"},
            "security-logs-rejected", "", handler, "rejected_consumed", "g",
        )

    ok = asyncio.run(_case())
    assert ok is False
    assert sent == []
