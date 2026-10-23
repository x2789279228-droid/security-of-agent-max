"""Kafka offset 只提交连续水位。

业务成功，或永久失败已经确认写入 DLQ，才允许推进。
临时失败、DLQ 写入失败，都不允许把后面的 offset 一起提交。
关闭时只提交已经连续完成的水位，未处理的记录留在 broker。
"""
import asyncio
import inspect
import json
import os

import kafka_consumer
from kafka_consumer import KafkaConsumerManager, OffsetCommitTracker


class Part:
    def __init__(self, topic, partition):
        self.topic = topic
        self.partition = partition

    def __repr__(self):
        return f"{self.topic}:{self.partition}"


class Rec:
    def __init__(self, partition, offset, value, topic="security-logs-rejected"):
        self.topic = topic
        self.partition = partition
        self.offset = offset
        self.headers = []
        if isinstance(value, bytes):
            self.value = value
        else:
            self.value = json.dumps(value).encode()


class FakeConsumer:
    def __init__(self):
        self.commits = []
        self.seeks = []

    async def commit(self, offsets=None):
        assert offsets, "无参 commit 会把本批末尾一并提交"
        self.commits.append(dict(offsets))

    def seek(self, tp, offset):
        self.seeks.append((tp.topic, tp.partition, offset))

    def pause(self, *tps):
        return None

    def resume(self, *tps):
        return None


def _manager(monkeypatch):
    monkeypatch.setattr(KafkaConsumerManager, "_retain_backoff", lambda self, tracker: 0.0)
    monkeypatch.setattr(kafka_consumer, "MAX_RETRY", 1)
    monkeypatch.setattr(kafka_consumer, "CONSUME_CONCURRENCY", 1)
    mgr = KafkaConsumerManager()
    mgr._running = True
    return mgr


def _part():
    return Part("security-logs-rejected", 0)


async def _ok_handler(event, trace_id):
    return None


def test_tracker_does_not_skip_hole_when_later_offset_finishes_first():
    tracker = OffsetCommitTracker()
    tp = ("security-alerts", 3)
    for off in (100, 101, 102):
        tracker.observe(tp, off)

    tracker.resolve(tp, 102, True)
    tracker.resolve(tp, 100, True)
    # 100 已完成，101 仍在处理：可以提交 101，不能提交 103。
    assert tracker.uncommitted()[tp] == 101
    assert tracker.next_offset(tp) == 101

    tracker.resolve(tp, 101, False)
    assert tracker.uncommitted()[tp] == 101
    assert tracker.next_offset(tp) == 101

    tracker.resolve(tp, 101, True)
    assert tracker.uncommitted()[tp] == 103
    assert tracker.next_offset(tp) == 103


def test_tracker_gap_blocks_watermark_even_if_both_sides_succeed():
    tracker = OffsetCommitTracker()
    tp = ("t", 0)
    tracker.observe(tp, 100)
    tracker.observe(tp, 102)
    tracker.resolve(tp, 100, True)
    tracker.resolve(tp, 102, True)
    assert tracker.uncommitted()[tp] == 101
    assert 103 not in tracker.uncommitted().values()


def test_tracker_partitions_are_independent_and_commit_does_not_rewind():
    tracker = OffsetCommitTracker()
    a = ("t", 0)
    b = ("t", 1)
    tracker.observe(a, 5)
    tracker.observe(b, 1)
    tracker.resolve(a, 5, True)
    tracker.resolve(b, 1, True)
    pending = tracker.uncommitted()
    assert pending[a] == 6
    assert pending[b] == 2
    tracker.mark_committed(pending)
    tracker.observe(a, 5)
    assert tracker.uncommitted() == {}
    assert tracker.next_offset(a) == 6


def test_tracker_offset_zero_failure_is_not_treated_as_missing():
    tracker = OffsetCommitTracker()
    tp = ("t", 0)
    tracker.observe(tp, 0)
    tracker.resolve(tp, 0, False)
    assert tracker.uncommitted() == {}
    assert tracker.next_offset(tp) == 0


def test_consume_loop_has_no_unconditional_commit():
    src = inspect.getsource(KafkaConsumerManager._consume_loop)
    sync = inspect.getsource(KafkaConsumerManager._sync_consumer_offsets)
    dlq = inspect.getsource(KafkaConsumerManager._send_to_dlq)
    assert "consumer.commit" not in src
    assert "commit(" in sync
    assert "send_and_wait" in dlq
    assert "await self._dlq_producer.send(" not in dlq


def test_dlq_write_must_be_acknowledged():
    from cryptography.fernet import Fernet
    from field_cipher import field_cipher

    old = os.environ.get("SHARED_MEMORY_FIELD_ENCRYPTION_KEY")
    os.environ["SHARED_MEMORY_FIELD_ENCRYPTION_KEY"] = Fernet.generate_key().decode()
    field_cipher.reload()

    async def _case():
        from models import Base, engine

        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        mgr = KafkaConsumerManager()
        secret = "super-secret-key"
        payload = {"eventId": "e", "apiKey": secret}
        assert await mgr._send_to_dlq(
            "t", payload, f"apiKey={secret} bad", 0, partition=1, offset=9,
        ) is False
        assert mgr._stats["dlq_failed"] == 1

        class Prod:
            def __init__(self):
                self.sent = []

            async def send(self, *args, **kwargs):
                raise AssertionError("buffered send is not a durable DLQ write")

            async def send_and_wait(self, topic, key=None, value=None, headers=None):
                self.sent.append(value)
                return {"offset": 1}

        prod = Prod()
        mgr._dlq_producer = prod
        assert await mgr._send_to_dlq(
            "t", payload, f"apiKey={secret} bad", 1, partition=1, offset=9,
        ) is True
        dumped = json.dumps(prod.sent[0], ensure_ascii=False)
        assert secret not in dumped
        assert "original_message" not in prod.sent[0]
        assert prod.sent[0]["original_offset"] == 9
        assert prod.sent[0]["event_id"] == "e"
        assert prod.sent[0]["payload_ciphertext"].startswith("ENC:")
        assert "apiKey=[redacted]" in prod.sent[0]["sanitized_error"]
        assert mgr._stats["dlq_sent"] == 1

        class Down:
            async def send_and_wait(self, *args, **kwargs):
                raise RuntimeError("not enough replicas")

        mgr._dlq_producer = Down()
        assert await mgr._send_to_dlq("t", payload, f"apiKey={secret} bad", 1) is False
        assert mgr._stats["dlq_failed"] == 2

    try:
        asyncio.run(_case())
    finally:
        if old is None:
            os.environ.pop("SHARED_MEMORY_FIELD_ENCRYPTION_KEY", None)
        else:
            os.environ["SHARED_MEMORY_FIELD_ENCRYPTION_KEY"] = old
        field_cipher.reload()


def test_ordered_batch_commits_only_the_contiguous_prefix(monkeypatch):
    mgr = _manager(monkeypatch)
    part = _part()
    handled = []

    async def handler(event, trace_id):
        handled.append(event["n"])
        if event["n"] == 101:
            raise TimeoutError("downstream timeout")

    fetched = {
        part: [
            Rec(0, 100, {"n": 100, "eventId": "a"}),
            Rec(0, 101, {"n": 101, "eventId": "b"}),
            Rec(0, 102, {"n": 102, "eventId": "c"}),
        ]
    }
    consumer = FakeConsumer()
    tracker = OffsetCommitTracker()

    async def _case():
        await mgr._settle_fetch(
            consumer, fetched, part.topic, handler, "rejected_consumed", "rejected", tracker,
        )

    asyncio.run(_case())
    assert handled == [100, 101]
    assert consumer.commits == [{part: 101}]
    assert consumer.seeks == [(part.topic, part.partition, 101)]
    assert mgr._stats["offsets_retained"] == 1
    assert mgr._stats["rejected_consumed"] == 1


def test_concurrent_completion_cannot_commit_past_a_hole(monkeypatch):
    mgr = _manager(monkeypatch)
    monkeypatch.setattr(kafka_consumer, "CONSUME_CONCURRENCY", 4)
    part = _part()
    done_100 = asyncio.Event()
    done_102 = asyncio.Event()

    async def handler(event, trace_id):
        n = event["n"]
        if n == 100:
            done_100.set()
            return
        if n == 102:
            await done_100.wait()
            done_102.set()
            return
        await done_102.wait()
        raise TimeoutError("downstream timeout")

    fetched = {
        part: [
            Rec(0, 100, {"n": 100, "eventId": "a"}),
            Rec(0, 101, {"n": 101, "eventId": "b"}),
            Rec(0, 102, {"n": 102, "eventId": "c"}),
        ]
    }
    consumer = FakeConsumer()
    tracker = OffsetCommitTracker()

    async def _case():
        await mgr._settle_fetch(
            consumer, fetched, part.topic, handler, "rejected_consumed", "rejected", tracker,
        )

    asyncio.run(_case())
    assert consumer.commits == [{part: 101}]
    assert all(off != 103 for batch in consumer.commits for off in batch.values())
    assert (part.topic, part.partition, 101) in consumer.seeks


def test_successful_batch_commits_the_next_offset(monkeypatch):
    mgr = _manager(monkeypatch)
    part = _part()
    fetched = {part: [Rec(0, 100, {"n": 1}), Rec(0, 101, {"n": 2}), Rec(0, 102, {"n": 3})]}
    consumer = FakeConsumer()

    async def _case():
        await mgr._settle_fetch(
            consumer, fetched, part.topic, _ok_handler, "rejected_consumed", "rejected",
            OffsetCommitTracker(),
        )

    asyncio.run(_case())
    assert consumer.commits == [{part: 103}]
    assert consumer.seeks == []


def test_partitions_commit_independently(monkeypatch):
    mgr = _manager(monkeypatch)
    p0 = Part("security-logs-rejected", 0)
    p1 = Part("security-logs-rejected", 1)

    async def handler(event, trace_id):
        if event["n"] == 6:
            raise TimeoutError("downstream timeout")

    fetched = {
        p0: [Rec(0, 5, {"n": 5}), Rec(0, 6, {"n": 6}), Rec(0, 7, {"n": 7})],
        p1: [Rec(1, 1, {"n": 1}), Rec(1, 2, {"n": 2})],
    }
    consumer = FakeConsumer()

    async def _case():
        await mgr._settle_fetch(
            consumer, fetched, p0.topic, handler, "rejected_consumed", "rejected",
            OffsetCommitTracker(),
        )

    asyncio.run(_case())
    assert consumer.commits == [{p0: 6, p1: 3}]
    assert consumer.seeks == [(p0.topic, 0, 6)]


def test_replay_after_hole_can_advance_once_the_hole_clears(monkeypatch):
    mgr = _manager(monkeypatch)
    part = _part()
    consumer = FakeConsumer()
    tracker = OffsetCommitTracker()
    state = {"fail": True}

    async def handler(event, trace_id):
        if event["n"] == 101 and state["fail"]:
            raise TimeoutError("downstream timeout")

    async def _case():
        await mgr._settle_fetch(
            consumer,
            {part: [Rec(0, 100, {"n": 100}), Rec(0, 101, {"n": 101}), Rec(0, 102, {"n": 102})]},
            part.topic, handler, "rejected_consumed", "rejected", tracker,
        )
        state["fail"] = False
        await mgr._settle_fetch(
            consumer,
            {part: [Rec(0, 101, {"n": 101}), Rec(0, 102, {"n": 102})]},
            part.topic, handler, "rejected_consumed", "rejected", tracker,
        )

    asyncio.run(_case())
    assert consumer.commits[0] == {part: 101}
    assert consumer.commits[1] == {part: 103}


def test_unparsable_message_commits_only_after_durable_dlq(monkeypatch):
    mgr = _manager(monkeypatch)
    part = _part()
    dlq_calls = []

    async def dlq(topic, msg, error, retry_count, partition=None, offset=None, **_kwargs):
        dlq_calls.append(offset)
        return False

    monkeypatch.setattr(mgr, "_send_to_dlq", dlq)
    consumer = FakeConsumer()
    fetched = {
        part: [
            Rec(0, 10, {"n": 10}),
            Rec(0, 11, b"not-json"),
            Rec(0, 12, {"n": 12}),
        ]
    }

    async def _case():
        await mgr._settle_fetch(
            consumer, fetched, part.topic, _ok_handler, "rejected_consumed", "rejected",
            OffsetCommitTracker(),
        )

    asyncio.run(_case())
    assert dlq_calls == [11]
    assert consumer.commits == [{part: 11}]
    assert consumer.seeks == [(part.topic, 0, 11)]

    async def dlq_ok(topic, msg, error, retry_count, partition=None, offset=None, **_kwargs):
        return True

    monkeypatch.setattr(mgr, "_send_to_dlq", dlq_ok)
    consumer = FakeConsumer()

    async def _acked():
        await mgr._settle_fetch(
            consumer, fetched, part.topic, _ok_handler, "rejected_consumed", "rejected",
            OffsetCommitTracker(),
        )

    asyncio.run(_acked())
    assert consumer.commits == [{part: 13}]
    assert consumer.seeks == []


def test_schema_failure_is_permanent_and_transient_handler_is_not_dlqd(monkeypatch):
    mgr = _manager(monkeypatch)
    part = _part()
    dlq_calls = []

    async def dlq(topic, msg, error, retry_count, partition=None, offset=None, **_kwargs):
        dlq_calls.append((offset, error))
        return True

    monkeypatch.setattr(mgr, "_send_to_dlq", dlq)
    monkeypatch.setattr(
        kafka_consumer.schema_registry, "validate", lambda topic, event: ["missing field"],
    )

    async def _schema():
        ok = await mgr._ack_record(
            Rec(0, 4, {"eventId": "x"}), part.topic, _ok_handler, "rejected_consumed", "rejected",
        )
        assert ok is True

    asyncio.run(_schema())
    assert dlq_calls[0][0] == 4

    monkeypatch.setattr(kafka_consumer.schema_registry, "validate", lambda topic, event: [])
    dlq_calls.clear()

    async def handler(event, trace_id):
        raise TimeoutError("downstream timeout")

    async def _transient():
        ok = await mgr._ack_record(
            Rec(0, 5, {"eventId": "y"}), part.topic, handler, "rejected_consumed", "rejected",
        )
        assert ok is False

    asyncio.run(_transient())
    assert dlq_calls == []


def test_shutdown_commits_only_the_finished_prefix(monkeypatch):
    mgr = _manager(monkeypatch)
    part = _part()
    consumer = FakeConsumer()

    async def handler(event, trace_id):
        mgr._running = False

    async def _case():
        await mgr._settle_fetch(
            consumer,
            {part: [Rec(0, 1, {"n": 1}), Rec(0, 2, {"n": 2})]},
            part.topic, handler, "rejected_consumed", "rejected", OffsetCommitTracker(),
        )

    asyncio.run(_case())
    # 第一条已经处理完，水位停在 2。第二条因为停止拉取而没有处理，不能被确认。
    assert consumer.commits == [{part: 2}]
    assert consumer.seeks == []


def test_cancelled_poll_does_not_commit(monkeypatch):
    commits = []
    started = asyncio.Event()

    class PausingConsumer:
        def __init__(self, *args, **kwargs):
            return None

        async def start(self):
            return None

        async def stop(self):
            return None

        async def getmany(self, timeout_ms=0, max_records=0):
            started.set()
            await asyncio.sleep(30)
            return {}

        async def commit(self, offsets=None):
            commits.append(offsets)

        def seek(self, *args, **kwargs):
            return None

        def pause(self, *args, **kwargs):
            return None

        def resume(self, *args, **kwargs):
            return None

    monkeypatch.setattr(kafka_consumer, "AIOKafkaConsumer", PausingConsumer)
    mgr = _manager(monkeypatch)

    async def _case():
        task = asyncio.create_task(
            mgr._consume_loop(part_topic(), "rejected", _ok_handler, "rejected_consumed")
        )
        await started.wait()
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        return list(commits)

    def part_topic():
        return "security-logs-rejected"

    assert asyncio.run(_case()) == []


def test_python_ingest_keeps_the_hole_when_dlq_or_batch_fails(monkeypatch):
    mgr = _manager(monkeypatch)
    part = Part("security-events-ingest", 2)
    ingested = []

    async def ingest_ok(events):
        ingested.append(list(events))
        from retry_policy import EventOutcome
        return [EventOutcome.success() for _ in events]

    async def dlq_fail(topic, msg, error, retry_count, partition=None, offset=None, **_kwargs):
        return False

    monkeypatch.setattr(mgr, "_ingest_python_batch", ingest_ok)
    monkeypatch.setattr(mgr, "_send_to_dlq", dlq_fail)
    consumer = FakeConsumer()
    good = {"session_id": "s", "body": {"event": "login"}}
    fetched = {
        part: [
            Rec(2, 5, good, topic=part.topic),
            Rec(2, 6, b"{", topic=part.topic),
            Rec(2, 7, good, topic=part.topic),
        ]
    }

    async def _dlq_down():
        await mgr._settle_python_ingest_fetch(consumer, fetched, OffsetCommitTracker())

    asyncio.run(_dlq_down())
    assert consumer.commits == [{part: 6}]
    assert consumer.seeks == [(part.topic, 2, 6)]
    assert [sid for sid, _body in ingested[0]] == ["s"]

    async def dlq_ok(topic, msg, error, retry_count, partition=None, offset=None, **_kwargs):
        return True

    monkeypatch.setattr(mgr, "_send_to_dlq", dlq_ok)
    consumer = FakeConsumer()
    ingested.clear()

    async def _dlq_up():
        await mgr._settle_python_ingest_fetch(consumer, fetched, OffsetCommitTracker())

    asyncio.run(_dlq_up())
    assert consumer.commits == [{part: 8}]
    assert consumer.seeks == []

    async def ingest_down(events):
        from retry_policy import EventOutcome
        return [EventOutcome.retrying(error="db down") for _ in events]

    monkeypatch.setattr(mgr, "_ingest_python_batch", ingest_down)
    consumer = FakeConsumer()

    async def _db_down():
        await mgr._settle_python_ingest_fetch(
            consumer,
            {part: [Rec(2, 5, good, topic=part.topic), Rec(2, 6, good, topic=part.topic)]},
            OffsetCommitTracker(),
        )

    asyncio.run(_db_down())
    assert consumer.commits == []
    assert consumer.seeks == [(part.topic, 2, 5)]


def test_python_ingest_partial_success_commits_prefix_only(monkeypatch):
    from retry_policy import EventOutcome

    mgr = _manager(monkeypatch)
    part = Part("security-events-ingest", 2)
    good = {"session_id": "s", "body": {"event": "login"}}

    async def ingest_mixed(events):
        return [
            EventOutcome.success(),
            EventOutcome.retrying(error="db timeout"),
            EventOutcome.success(),
        ]

    monkeypatch.setattr(mgr, "_ingest_python_batch", ingest_mixed)
    consumer = FakeConsumer()

    async def _case():
        await mgr._settle_python_ingest_fetch(
            consumer,
            {part: [
                Rec(2, 10, good, topic=part.topic),
                Rec(2, 11, good, topic=part.topic),
                Rec(2, 12, good, topic=part.topic),
            ]},
            OffsetCommitTracker(),
        )

    asyncio.run(_case())
    assert consumer.commits == [{part: 11}]
    assert consumer.seeks == [(part.topic, 2, 11)]
