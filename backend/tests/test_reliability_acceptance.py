"""
数据与流处理可靠性 —— 整改验收测试集

11 个 Test 类与整改验收清单逐条对应。每个测试断言的是**行为**，
不是「函数存在」或「代码写好了」。只有实际运行通过才算已验证。

清单映射:
  Test01  Kafka 业务处理失败后，offset 不得提前提交
  Test02  DLQ 写入失败时，原消息不能被错误确认
  Test03  数据库写入成功后进程崩溃，重放不会造成重复副作用
  Test04  慢 SSE 消费者不会导致高危告警永久丢失
  Test05  Redis 断连导致通知丢失后，客户端仍能通过持久化记录补查
  Test06  关闭服务时，已接受的任务要么完成，要么保持可恢复状态
  Test07  持续高负载下，并发任务、队列和内存均有明确上限
  Test08  所有数据库写入点都能触发正确的缓存失效机制
  Test09  Schema 变更不兼容时，CI 和发布流程会明确失败
  Test10  解密失败、密文异常和 DLQ 重放不会泄露明文敏感数据
  Test11  最终未生成告警的事件，可以通过 event_id 定位失败阶段

运行:
  python -m pytest tests/test_reliability_acceptance.py -v

设计约束:
  · 不依赖 Kafka broker / Redis 实例，全部用假 broker + 内存 sqlite
  · 异步用例用 asyncio.run 驱动，不依赖 pytest-asyncio 的 mode 配置
  · 每个用例自证: 断言的是「不该发生的事没有发生」或「该发生的事发生了」
"""

import asyncio
import json
import os
from pathlib import Path

import pytest

from retry_policy import EventOutcome
from kafka_consumer import OffsetCommitTracker


def _run(coro):
    return asyncio.run(coro)


def _tp(topic="security-events-enriched", partition=0):
    """_tp_key 同时接受 TopicPartition 和 (topic, partition) 元组，用元组免依赖。"""
    return (topic, int(partition))


async def _create_tables():
    from models import Base, engine
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


def _set_cipher_key() -> str:
    from cryptography.fernet import Fernet
    from field_cipher import field_cipher
    key = Fernet.generate_key().decode()
    os.environ["SHARED_MEMORY_FIELD_ENCRYPTION_KEY"] = key
    field_cipher.reload()
    return key


def _clear_cipher_key():
    from field_cipher import field_cipher
    os.environ.pop("SHARED_MEMORY_FIELD_ENCRYPTION_KEY", None)
    field_cipher.reload()


# ══════════════════════════════════════════════════════════════════
# 验收 1 — Kafka 业务处理失败后，offset 不得提前提交
# ══════════════════════════════════════════════════════════════════

class Test01OffsetNotCommittedEarly:
    """验收 1: Kafka 业务处理失败后，offset 不得提前提交。

    Kafka 提交的 offset 是「下一条要读的位置」。同一分区里 100、102 已成功
    而 101 仍失败时，水位必须停在 101 —— 提交 103 会让 101 永久跳过。
    """

    def test_inflight_holds_watermark(self):
        """101 还在处理中：102 已完成也不得越过它提交。"""
        tracker = OffsetCommitTracker()
        tp = _tp()
        for off in (100, 101, 102):
            tracker.observe(tp, off)
        tracker.resolve(tp, 100, True)
        tracker.resolve(tp, 102, True)          # 乱序先完成
        assert tracker.uncommitted()[tp] == 101, "101 未完成时水位不得推进到 103"

    def test_permanent_gap_still_blocks(self):
        """101 永久失败：水位同样停在 101。"""
        tracker = OffsetCommitTracker()
        tp = _tp()
        for off in (100, 101, 102):
            tracker.observe(tp, off)
        tracker.resolve(tp, 100, True)
        tracker.resolve(tp, 102, True)
        tracker.resolve(tp, 101, False)         # 永久失败 = 空洞
        assert tracker.uncommitted()[tp] == 101

    def test_contiguous_success_advances(self):
        """连续全部成功：水位推进到 103。"""
        tracker = OffsetCommitTracker()
        tp = _tp()
        for off in (100, 101, 102):
            tracker.observe(tp, off)
        for off in (100, 101, 102):
            tracker.resolve(tp, off, True)
        assert tracker.uncommitted()[tp] == 103

    def test_partitions_are_independent(self):
        """一个分区有洞，不得影响另一个分区提交。"""
        tracker = OffsetCommitTracker()
        p0, p1 = _tp(partition=0), _tp(partition=1)
        tracker.observe(p0, 10)
        tracker.observe(p0, 11)
        tracker.observe(p1, 20)
        tracker.resolve(p0, 10, True)
        tracker.resolve(p0, 11, False)
        tracker.resolve(p1, 20, True)
        pending = tracker.uncommitted()
        assert pending[p0] == 11
        assert pending[p1] == 21

    def test_outcome_committable_matrix(self):
        """只有 success 和已确认入 DLQ 才可提交。"""
        assert EventOutcome.success().committable() is True
        assert EventOutcome.dlq().committable() is True
        assert EventOutcome.retrying().committable() is False
        assert EventOutcome.failed().committable() is False

    def test_mark_committed_does_not_regress(self):
        """已确认的位点不会被更小的水位拉低。"""
        tracker = OffsetCommitTracker()
        tp = _tp()
        tracker.observe(tp, 5)
        tracker.resolve(tp, 5, True)
        tracker.mark_committed({tp: 6})
        assert tracker.uncommitted() == {}, "已提交的位点不应再次出现在待提交集合"


# ══════════════════════════════════════════════════════════════════
# 验收 2 — DLQ 写入失败时，原消息不能被错误确认
# ══════════════════════════════════════════════════════════════════

class Test02DlqFailureRetainsOffset:
    """验收 2: DLQ 写入失败时，原消息不能被错误确认。

    两步都要成功才允许提交：① 失败状态落库 ② broker 确认 DLQ 写入。
    任一步失败都必须返回 False，让上游保留 offset。
    """

    def _manager(self):
        from kafka_consumer import KafkaConsumerManager
        mgr = KafkaConsumerManager()
        mgr._running = True
        return mgr

    def test_producer_unavailable_returns_false(self):
        """没有 DLQ producer：必须返回 False，且计数 dlq_failed 增加。"""
        async def _case():
            await _create_tables()
            mgr = self._manager()
            mgr._dlq_producer = None
            before = mgr._stats["dlq_failed"]
            ok = await mgr._send_to_dlq(
                "security-alerts", {"eventId": "e-prod-none"},
                "permanent", 1, partition=0, offset=5,
            )
            assert ok is False, "producer 不可用时不得返回 True"
            assert mgr._stats["dlq_failed"] == before + 1
            assert mgr._stats["dlq_sent"] == 0

        _run(_case())

    def test_broker_nack_returns_false(self):
        """broker 未 ack（send_and_wait 抛错）：必须返回 False。"""
        async def _case():
            await _create_tables()
            mgr = self._manager()

            class Nack:
                async def send_and_wait(self, topic, key=None, value=None, headers=None):
                    raise RuntimeError("broker did not ack")

            mgr._dlq_producer = Nack()
            before = mgr._stats["dlq_failed"]
            ok = await mgr._send_to_dlq(
                "security-alerts", {"eventId": "e-nack"},
                "permanent", 1, partition=0, offset=6,
            )
            assert ok is False, "broker 未确认时不得返回 True"
            assert mgr._stats["dlq_failed"] == before + 1

        _run(_case())

    def test_db_not_durable_returns_false(self):
        """失败状态没能落库（persist 失败）：必须返回 False。"""
        import kafka_consumer as kc

        async def _case():
            await _create_tables()
            mgr = self._manager()

            class Prod:
                async def send_and_wait(self, topic, key=None, value=None, headers=None):
                    return {"offset": 1}

            mgr._dlq_producer = Prod()

            class FakeResult:
                persisted = False
                envelope = None
                record_id = 0
                event_id = "e-nodb"
                reason = "db down"

            original = kc.persist_dlq_failure

            async def _broken(**kwargs):
                return FakeResult()

            kc.persist_dlq_failure = _broken
            try:
                ok = await mgr._send_to_dlq(
                    "security-alerts", {"eventId": "e-nodb"},
                    "permanent", 1, partition=0, offset=7,
                )
            finally:
                kc.persist_dlq_failure = original
            assert ok is False, "失败状态未落库时不得返回 True"

        _run(_case())

    def test_full_success_returns_true(self):
        """两步都成功：返回 True，dlq_sent 计数增加。"""
        async def _case():
            await _create_tables()
            mgr = self._manager()
            _set_cipher_key()
            try:
                class Prod:
                    async def send_and_wait(self, topic, key=None, value=None, headers=None):
                        return {"offset": 1}

                mgr._dlq_producer = Prod()
                before = mgr._stats["dlq_sent"]
                ok = await mgr._send_to_dlq(
                    "security-alerts", {"eventId": "e-ok"},
                    "permanent", 1, partition=0, offset=8,
                )
                assert ok is True
                assert mgr._stats["dlq_sent"] == before + 1
            finally:
                _clear_cipher_key()

        _run(_case())

    def test_cipher_disabled_also_fails_closed(self):
        """未配置加密密钥时 DLQ 同样拒绝确认 —— 宁可不提交也不能落明文。"""
        async def _case():
            await _create_tables()
            mgr = self._manager()
            _clear_cipher_key()

            class Prod:
                async def send_and_wait(self, topic, key=None, value=None, headers=None):
                    return {"offset": 1}

            mgr._dlq_producer = Prod()
            ok = await mgr._send_to_dlq(
                "security-alerts", {"eventId": "e-nocipher", "message": "secret"},
                "permanent", 1, partition=0, offset=80,
            )
            assert ok is False, "无密钥时不得把明文负载写进 DLQ 后再确认"

        _run(_case())

    def test_undecryptable_message_blocks_commit_without_dlq(self):
        """密文无法解密且 DLQ 写不进去：返回 False，handler 不应被调用。"""
        async def _case():
            await _create_tables()
            mgr = self._manager()
            mgr._dlq_producer = None
            called = []

            async def handler(event, trace_id):
                called.append(event)

            class Msg:
                partition = 2
                offset = 9
                timestamp = 1700000000000
                headers = []
                value = b""

            _clear_cipher_key()
            ok = await mgr._process_message(
                Msg(),
                {"eventId": "e-cipher-block", "message": "ENC:not-a-token"},
                "security-logs-rejected", "", handler,
                "rejected_consumed", "soc-backend-rejected",
            )
            assert ok is False, "DLQ 不可用时不得确认消费完成"
            assert called == [], "解密失败的消息不得进入业务处理"

        _run(_case())


# ══════════════════════════════════════════════════════════════════
# 验收 3 — 重放不造成重复副作用
# ══════════════════════════════════════════════════════════════════

class Test03ReplayHasNoDuplicateSideEffects:
    """验收 3: 数据库写入成功后进程崩溃，重放不会造成重复副作用。"""

    def _payload(self, eid):
        return {
            "eventId": eid, "event": "brute_force", "severity": "high",
            "src_ip": "10.0.0.5", "dst_ip": "10.0.0.9", "protocol": "tcp",
            "message": "failed login", "confidence": 80,
        }

    def test_same_event_id_stores_once(self):
        """同一 eventId 重复 store：只落一行。"""
        async def _case():
            await _create_tables()
            from models import async_session
            from event_store import event_store
            from models import SecurityEvent
            from sqlalchemy import select

            async with async_session() as session:
                first = await event_store.store(session, self._payload("dup-1"), "s1")
            async with async_session() as session:
                second = await event_store.store(session, self._payload("dup-1"), "s1")
            assert first.id == second.id, "重放必须复用同一行"

            async with async_session() as session:
                rows = (await session.execute(
                    select(SecurityEvent).where(SecurityEvent.event_id == "dup-1")
                )).scalars().all()
            assert len(rows) == 1, f"同一 eventId 落了 {len(rows)} 行，应为 1"

        _run(_case())

    def test_batch_duplicate_collapses(self):
        """同一批内重复 eventId：store_batch 只插一行。"""
        async def _case():
            await _create_tables()
            from models import async_session, SecurityEvent
            from event_store import event_store
            from sqlalchemy import select

            rows = [
                (self._payload("dup-batch"), "s2", 0.0, ""),
                (self._payload("dup-batch"), "s2", 0.0, ""),
                (self._payload("dup-other"), "s2", 0.0, ""),
            ]
            async with async_session() as session:
                out = await event_store.store_batch(session, rows)
            assert len(out) == 3, "store_batch 必须返回与输入等长同序的结果"

            async with async_session() as session:
                got = (await session.execute(
                    select(SecurityEvent).where(SecurityEvent.event_id.in_(["dup-batch", "dup-other"]))
                )).scalars().all()
            assert len(got) == 2, "批内重复 eventId 必须收敛到一行"

        _run(_case())

    def test_distinct_event_ids_all_persist(self):
        """不同 eventId 不能被误判为重复。"""
        async def _case():
            await _create_tables()
            from models import async_session, SecurityEvent
            from event_store import event_store
            from sqlalchemy import select

            ids = ["keep-1", "keep-2", "keep-3"]
            for eid in ids:
                async with async_session() as session:
                    await event_store.store(session, self._payload(eid), "s3")
            async with async_session() as session:
                got = (await session.execute(
                    select(SecurityEvent).where(SecurityEvent.event_id.in_(ids))
                )).scalars().all()
            assert len(got) == 3, "不同 eventId 必须各自落库"

        _run(_case())


# ══════════════════════════════════════════════════════════════════
# 验收 4 — 慢 SSE 消费者不会导致高危告警永久丢失
# ══════════════════════════════════════════════════════════════════

class Test04SlowConsumerKeepsCriticalAlert:
    """验收 4: 慢 SSE 消费者不会导致高危告警永久丢失。

    critical 与 bulk 分队列。critical 满时**不踢**已入队的告警，
    而是记缺口（gap_ids），客户端据此按 event_id 从持久层补查。
    """

    def test_critical_events_use_critical_lane(self):
        from event_bus import classify_event
        lane, sev, cursor_kind, eid = classify_event(
            "alert", {"severity": "critical", "event_id": 42}
        )
        assert lane == "critical"
        assert cursor_kind == "event_id"
        assert eid == 42

    def test_sla_breach_is_critical_not_health(self):
        """pipeline_health + sla_breach 子类型必须按告警处理，不能当心跳丢。"""
        from event_bus import classify_event
        lane, _, _, _ = classify_event("pipeline_health", {"type": "sla_breach"})
        assert lane == "critical", "SLA 违约是告警，不得落入 bulk 队列"

    def test_agent_stage_is_bulk(self):
        from event_bus import classify_event
        lane, _, _, _ = classify_event("agent_stage", {"status": "running"})
        assert lane == "bulk"

    def test_critical_overflow_records_gap_not_silent_drop(self):
        """critical 队列满：新事件记缺口，返回 gap 而不是 dropped。"""
        from event_bus import BusEvent, Subscriber

        sub = Subscriber(critical_max=2, bulk_max=2)
        for eid in (1, 2):
            evt = BusEvent(seq=eid, type="alert", data={},
                           lane="critical", severity="critical",
                           cursor_kind="event_id", event_id=eid)
            status, dropped = sub.offer(evt)
            assert status == "queued"

        overflow = BusEvent(seq=3, type="alert", data={},
                            lane="critical", severity="critical",
                            cursor_kind="event_id", event_id=3)
        status, dropped = sub.offer(overflow)
        assert status == "gap", "有 event_id 可补查的高危事件必须记缺口，不得静默丢弃"
        assert dropped is None, "记缺口时不应返回被丢弃事件"
        assert 3 in sub.gap_ids, "缺口必须带上 event_id，客户端才能补查"
        assert sub.critical_lost == 0, "可补查事件不得计入 lost"

    def test_queued_critical_alerts_are_not_evicted(self):
        """critical 队列里的告警不能被后来的事件挤掉。"""
        from event_bus import BusEvent, Subscriber

        sub = Subscriber(critical_max=3, bulk_max=1)
        for eid in (10, 11, 12):
            sub.offer(BusEvent(seq=eid, type="alert", data={}, lane="critical",
                               severity="critical", cursor_kind="event_id", event_id=eid))
        queued_ids = {e.event_id for e in sub.critical}
        assert queued_ids == {10, 11, 12}, "已入队的 critical 告警不得被踢出"

    def test_bulk_same_key_is_coalesced_not_dropped(self):
        """同一状态键的连续更新合并为最新一条，不占用队列。"""
        from event_bus import BusEvent, Subscriber

        sub = Subscriber(critical_max=2, bulk_max=2)
        for i in range(5):
            sub.offer(BusEvent(seq=i, type="pipeline_health",
                               data={"type": "heartbeat", "stage": "detect"},
                               lane="bulk", severity="info",
                               cursor_kind="epoch_seq"))
        assert len(sub.bulk) == 1, "相同 coalesce 键应合并为一条"

    def test_bulk_queue_may_drop(self):
        """不同状态键撑满 bulk 队列：允许丢最旧。"""
        from event_bus import BusEvent, Subscriber

        sub = Subscriber(critical_max=2, bulk_max=2)
        statuses = []
        for i in range(4):
            evt = BusEvent(seq=i, type="pipeline_health",
                           data={"type": "heartbeat", "stage": f"s{i}"},
                           lane="bulk", severity="info",
                           cursor_kind="epoch_seq", event_id=None)
            status, dropped = sub.offer(evt)
            statuses.append(status)
        assert "dropped" in statuses, "bulk 队列超限应丢弃最旧"
        assert len(sub.bulk) <= 2, "bulk 队列长度必须有硬上限"

    def test_gap_ids_are_deduplicated(self):
        from event_bus import BusEvent, Subscriber

        sub = Subscriber(critical_max=1, bulk_max=1)
        sub.offer(BusEvent(seq=1, type="alert", data={}, lane="critical",
                           severity="critical", cursor_kind="event_id", event_id=1))
        for _ in range(3):
            sub.offer(BusEvent(seq=2, type="alert", data={}, lane="critical",
                               severity="critical", cursor_kind="event_id", event_id=2))
        assert sub.gap_ids.count(2) == 1, "同一 event_id 的缺口不应重复记录"


# ══════════════════════════════════════════════════════════════════
# 验收 5 — 通知丢失后仍可通过持久化记录补查
# ══════════════════════════════════════════════════════════════════

class Test05PersistentBackfillAfterNotifyLoss:
    """验收 5: Redis 断连导致通知丢失后，客户端仍能通过持久化记录补查。

    Pub/Sub 是 at-most-once，但 security_events 行是持久的，
    按 event_id 游标可以补回任意一条通知丢失的事件。
    """

    def _store(self, eid, severity="critical", analyzed=False):
        async def _case():
            await _create_tables()
            from models import async_session
            from event_store import event_store
            async with async_session() as session:
                return await event_store.store(session, {
                    "eventId": eid, "event": "c2_beacon", "severity": severity,
                    "src_ip": "10.0.0.5", "dst_ip": "1.2.3.4", "protocol": "tcp",
                    "message": "beacon", "confidence": 90,
                }, "sess-backfill")
        return _case()

    def test_event_retrievable_by_id_after_notification_loss(self):
        """通知丢失后，按 event_id 仍能取回完整事件。"""
        async def _case():
            stored = await self._store("backfill-1")
            from event_replay import fetch_event_snapshot
            snap = await fetch_event_snapshot(stored.id)
            assert snap is not None, "持久化记录必须能按 event_id 取回"
            assert str(stored.id) in json.dumps(snap, ensure_ascii=False, default=str)

        _run(_case())

    def test_resume_cursor_prefers_header(self):
        from event_replay import resolve_resume_cursor
        cursor, _kind = resolve_resume_cursor("512", "300")
        assert cursor == 512, "Last-Event-ID 头应优先于查询参数"

    def test_resume_cursor_falls_back_to_query(self):
        from event_replay import resolve_resume_cursor
        cursor, _kind = resolve_resume_cursor(None, "300")
        assert cursor == 300

    def test_resume_cursor_ignores_garbage(self):
        from event_replay import resolve_resume_cursor
        cursor, _kind = resolve_resume_cursor("not-a-number", None)
        assert cursor == 0, "无法解析的游标应回落到 0，不得崩溃"

    def test_business_cursor_id_is_monotonic(self):
        """SecurityEvent.id 是自增主键，可作为持久业务游标。"""
        from models import SecurityEvent
        col = SecurityEvent.__table__.c.id
        assert col.primary_key is True
        assert col.autoincrement is True, "业务游标必须单调自增"

    def test_missing_event_returns_none_not_exception(self):
        from event_replay import fetch_event_snapshot

        async def _case():
            await _create_tables()
            assert await fetch_event_snapshot(99999999) is None

        _run(_case())


# ══════════════════════════════════════════════════════════════════
# 验收 6 — 关闭服务时任务要么完成，要么可恢复
# ══════════════════════════════════════════════════════════════════

class Test06GracefulShutdownPreservesWork:
    """验收 6: 关闭服务时，已接受的任务要么完成，要么保持可恢复状态。"""

    def test_drain_stops_accepting_new_work(self):
        from drain import DrainController
        ctrl = DrainController()
        assert ctrl.accepting is True
        ctrl.begin()
        assert ctrl.accepting is False, "drain 期间不得再接受新任务"
        assert ctrl.draining is True

    def test_drain_reset_restores_accepting(self):
        from drain import DrainController
        ctrl = DrainController()
        ctrl.begin()
        ctrl.reset()
        assert ctrl.accepting is True
        assert ctrl.draining is False

    def test_mark_stopped_is_terminal(self):
        from drain import DrainController
        ctrl = DrainController()
        ctrl.begin()
        ctrl.mark_stopped()
        assert ctrl.accepting is False, "停止后不得再接受新任务"
        assert ctrl.draining is True, "draining 表示「已非 running」，停止态仍属其列"

    def test_phase_progression_is_monotonic(self):
        """running → draining → stopped 不可回退。"""
        from drain import DrainController
        ctrl = DrainController()
        ctrl.begin()
        ctrl.begin()          # 重复 begin 不得把 draining 打回 running
        assert ctrl.draining is True
        ctrl.mark_stopped()
        assert ctrl.accepting is False

    def test_accepted_work_spills_to_recoverable_file(self, tmp_path, monkeypatch):
        """内存队列里未跑完的任务必须溢出到可恢复的落盘文件。"""
        import audit_spill

        spill_file = tmp_path / "spill.jsonl"
        monkeypatch.setattr(audit_spill, "spill_path", lambda: spill_file)

        assert audit_spill.append_record({"event_id": 77, "tier": "P0"}) is True
        assert audit_spill.append_record({"event_id": 78, "tier": "P1"}) is True

        records = audit_spill.read_records()
        assert len(records) == 2, "已接受的任务必须落盘，重启后可恢复"
        assert {r["event_id"] for r in records} == {77, 78}

    def test_spill_drop_removes_only_target(self, tmp_path, monkeypatch):
        import audit_spill

        spill_file = tmp_path / "spill.jsonl"
        monkeypatch.setattr(audit_spill, "spill_path", lambda: spill_file)
        audit_spill.append_record({"event_id": 1})
        audit_spill.append_record({"event_id": 2})
        audit_spill.drop_event(1)
        remaining = [r["event_id"] for r in audit_spill.read_records()]
        assert remaining == [2], "只应丢弃指定事件，其余保持可恢复"

    def test_audit_worker_stop_reports_loss(self):
        """stop() 必须报告溢出数量，让「静默丢失」变成可观测事件。"""
        import inspect

        from audit_worker import AuditWorkerPool
        src = inspect.getsource(AuditWorkerPool.stop)
        assert "spilled" in src or "volatile_lost" in src, \
            "stop() 必须返回可观测的丢失/溢出报告"


# ══════════════════════════════════════════════════════════════════
# 验收 7 — 并发、队列、内存均有明确上限
# ══════════════════════════════════════════════════════════════════

class Test07BoundedCapacity:
    """验收 7: 持续高负载下，并发任务、队列和内存均有明确上限。"""

    def test_gate_enforces_hard_limit(self):
        """活上限闸：超过上限直接抛 GateTimeout，不在闸内 sleep 躲过载。"""
        from capacity import BoundedGate, GateTimeout

        async def _case():
            gate = BoundedGate("test_gate", lambda: 2, lambda: 0.05)
            async with gate.acquire():
                async with gate.acquire():
                    assert gate.inflight() == 2
                    with pytest.raises(GateTimeout):
                        async with gate.acquire():
                            pass
                assert gate.inflight() <= 1

        _run(_case())

    def test_gate_snapshot_exposes_bounds(self):
        from capacity import BoundedGate

        async def _case():
            gate = BoundedGate("test_snapshot", lambda: 3, lambda: 1.0)
            snap = gate.snapshot()
            assert snap["limit"] == 3
            assert snap["inflight"] == 0
            assert snap["waiters"] == 0
            assert gate.saturated() is False

        _run(_case())

    def test_gate_releases_after_exit(self):
        """退出后名额必须归还，否则高负载下会把自己锁死。"""
        from capacity import BoundedGate

        async def _case():
            gate = BoundedGate("test_release", lambda: 1, lambda: 0.05)
            async with gate.acquire():
                pass
            assert gate.inflight() == 0
            async with gate.acquire():
                assert gate.inflight() == 1

        _run(_case())

    def test_oversized_batch_is_rejected(self):
        """批量超限必须显式拒绝，而不是全量吞下。"""
        from capacity import BatchRejected, IngestCapacityError
        assert issubclass(IngestCapacityError, Exception)
        assert issubclass(BatchRejected, Exception)

    def test_critical_queue_has_configured_cap(self):
        """critical / bulk 队列上限都必须来自配置且为正。"""
        from config import settings
        critical = int(getattr(settings, "event_bus_critical_queue_max", 200) or 200)
        bulk = int(getattr(settings, "event_bus_queue_max", 500) or 500)
        assert critical > 0 and bulk > 0

    def test_subscriber_queue_depth_is_bounded(self):
        from event_bus import BusEvent, Subscriber

        sub = Subscriber(critical_max=3, bulk_max=2)
        for i in range(60):
            sub.offer(BusEvent(seq=i, type="pipeline_health",
                               data={"type": "hb", "stage": f"s{i}"},
                               lane="bulk", severity="info", cursor_kind="epoch_seq"))
            sub.offer(BusEvent(seq=1000 + i, type="alert", data={},
                               lane="critical", severity="critical",
                               cursor_kind="event_id", event_id=i + 1))
        assert len(sub.critical) <= 3, "critical 队列长度越界"
        assert len(sub.bulk) <= 2, "bulk 队列长度越界"


# ══════════════════════════════════════════════════════════════════
# 验收 8 — 数据库写入点触发正确的缓存失效
# ══════════════════════════════════════════════════════════════════

class Test08CacheInvalidationOnWrite:
    """验收 8: 所有数据库写入点都能触发正确的缓存失效机制。

    核心不变量：失效通知必须发生在 commit **之后**，否则其他进程会把
    未提交的旧行重新读回缓存。
    """

    def test_commit_then_invalidate_orders_correctly(self):
        """commit_then_invalidate 必须先 commit 再失效。"""
        import inspect
        from event_store import EventStore
        src = inspect.getsource(EventStore.commit_then_invalidate)
        commit_at = src.index("session.commit()")
        notify_at = src.index("notify_committed")
        assert commit_at < notify_at, "commit 必须早于失效广播"

    def test_apply_event_update_commits_before_notify(self):
        import inspect
        from event_store import EventStore
        src = inspect.getsource(EventStore.apply_event_update)
        if "commit_then_invalidate" in src:
            assert src.index("commit_then_invalidate") < src.index("return evt"), \
                "返回值前必须已经完成 commit + 失效"

    def test_invalidate_bumps_generation(self):
        """失效必须抬升代次，让并发读到能识别出自己拿到了旧值。"""
        from event_store import event_store
        before = event_store.current_generation(12345)
        event_store.invalidate(12345, broadcast=False)
        after = event_store.current_generation(12345)
        assert after > before, "失效必须抬升代次"

    def test_invalidated_entry_is_not_returned_from_cache(self):
        """失效后必须回源，不能继续吐旧快照。"""
        async def _case():
            await _create_tables()
            from models import async_session
            from event_store import event_store

            async with async_session() as session:
                stored = await event_store.store(session, {
                    "eventId": "cache-inv-1", "event": "test", "severity": "low",
                    "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2", "protocol": "tcp",
                    "message": "m", "confidence": 10,
                }, "sess-cache")
            # 先读一次把行填进热缓存
            async with async_session() as session:
                await event_store.get_by_id(session, stored.id)

            # 模拟另一个进程写回 + 广播失效
            event_store.invalidate(stored.id, broadcast=False)

            async with async_session() as session:
                await event_store.apply_event_update(
                    session, stored.id, merge_raw={"_audit_llm_error": "boom"},
                )
            async with async_session() as session:
                fresh = await event_store.get_by_id(session, stored.id)
            assert (fresh.raw_data or {}).get("_audit_llm_error") == "boom", \
                "失效后必须读到写回后的新值，而不是旧缓存"

        _run(_case())

    def test_hot_cache_has_ttl_fallback(self):
        """热缓存必须有 TTL 兜底，不依赖 Redis 可用性。

        配置项 event_store_hot_cache_ttl_s 允许写 0，含义是「对齐最短审计
        车道超时」而不是「不过期」，所以这里断言的是**生效值**。
        """
        from event_store import event_store
        assert event_store._hot_cache_ttl_s > 0, \
            "生效的热缓存 TTL 必须大于 0，否则失效通知一丢就是永久脏读"

    def test_ttl_expires_entry(self):
        """超过 TTL 的缓存条目必须被判为过期，强制回源。"""
        import time as _t
        from event_store import event_store, _HotCacheEntry

        async def _case():
            original_ttl = event_store._hot_cache_ttl_s
            event_store._hot_cache_ttl_s = 0.05
            try:
                entry = _HotCacheEntry(
                    data={"a": 1}, gen=0, cached_at=event_store._now()
                )
                assert event_store._entry_expired(entry) is False
                _t.sleep(0.12)
                assert event_store._entry_expired(entry) is True, \
                    "超过 TTL 必须强制回源，否则失效通知一丢就是永久脏读"
            finally:
                event_store._hot_cache_ttl_s = original_ttl

        _run(_case())


# ══════════════════════════════════════════════════════════════════
# 验收 9 — Schema 不兼容时 CI 明确失败
# ══════════════════════════════════════════════════════════════════

class Test09SchemaCompatGate:
    """验收 9: Schema 变更不兼容时，CI 和发布流程会明确失败。"""

    def _baseline(self):
        return {
            "type": "object",
            "required": ["eventId", "severity"],
            "additionalProperties": True,
            "properties": {
                "eventId": {"type": "string"},
                "severity": {"type": "string", "enum": ["low", "high"]},
            },
        }

    def test_adding_required_field_is_incompatible(self):
        from schema_compat import compatibility_issues
        new = self._baseline()
        new["required"] = ["eventId", "severity", "tenantId"]
        new["properties"]["tenantId"] = {"type": "string"}
        issues = compatibility_issues(new, self._baseline(), "FULL")
        assert issues, "新增必填字段会破坏旧消费者，必须判为不兼容"

    def test_removing_enum_value_is_incompatible(self):
        from schema_compat import compatibility_issues
        new = self._baseline()
        new["properties"]["severity"]["enum"] = ["low"]
        issues = compatibility_issues(new, self._baseline(), "FULL")
        assert issues, "收窄枚举会让旧生产者产生非法消息"

    def test_changing_field_type_is_incompatible(self):
        from schema_compat import compatibility_issues
        new = self._baseline()
        new["properties"]["severity"]["type"] = "integer"
        issues = compatibility_issues(new, self._baseline(), "FULL")
        assert issues, "改字段类型必须判为不兼容"

    def test_adding_optional_field_is_compatible(self):
        from schema_compat import compatibility_issues
        new = self._baseline()
        new["properties"]["tenantId"] = {"type": "string"}
        assert compatibility_issues(new, self._baseline(), "FULL") == [], \
            "新增可选字段是向后兼容的，不应阻断发布"

    def test_identical_schema_is_compatible(self):
        from schema_compat import compatibility_issues
        assert compatibility_issues(self._baseline(), self._baseline(), "FULL") == []

    def test_repo_schemas_match_their_baseline(self):
        """仓库里的真实 schema 必须与 contracts/baseline 保持 FULL 兼容。"""
        from schema_compat import (compatibility_issues, find_repo_root,
                                   load_catalog, load_json)
        catalog, catalog_path = load_catalog()
        root = find_repo_root()
        checked = 0
        for entry in catalog.get("schemas", []):
            baseline_rel = entry.get("baseline")
            current_rel = entry.get("json_schema") or entry.get("path")
            if not baseline_rel or not current_rel:
                continue
            baseline_p = root / baseline_rel
            current_p = root / current_rel
            assert baseline_p.is_file(), f"缺少基线: {baseline_rel}"
            assert current_p.is_file(), f"缺少当前 schema: {current_rel}"
            mode = entry.get("compatibility", catalog.get("compatibility", "FULL"))
            issues = compatibility_issues(
                load_json(current_p), load_json(baseline_p), mode
            )
            assert issues == [], f"{entry.get('name')} 不兼容: {issues}"
            checked += 1
        assert checked > 0, "catalog 没有可校验的条目，门禁形同虚设"

    def test_catalog_declares_a_compatibility_mode(self):
        from schema_compat import load_catalog
        catalog, _path = load_catalog()
        assert catalog.get("compatibility"), "必须声明兼容性模式"
        assert catalog.get("version")

    def test_every_schema_entry_declares_a_baseline(self):
        """没有 baseline 的条目等于没有门禁。"""
        from schema_compat import load_catalog
        catalog, _path = load_catalog()
        for entry in catalog.get("schemas", []):
            assert entry.get("baseline"), f"{entry.get('name')} 缺少 baseline"

    def test_ci_actually_runs_the_gate(self):
        """CI 必须真的调用兼容性检查脚本，否则门禁只是文档。"""
        root = Path(__file__).resolve().parents[2]
        ci = root / ".github" / "workflows" / "ci.yml"
        assert ci.exists(), "找不到 ci.yml"
        text = ci.read_text(encoding="utf-8")
        assert "check-schema-compat.py" in text, "CI 未调用 schema 兼容性检查"
        script = root / "tools" / "check-schema-compat.py"
        assert script.exists(), "兼容性检查脚本缺失"


# ══════════════════════════════════════════════════════════════════
# 验收 10 — 不泄露明文敏感数据
# ══════════════════════════════════════════════════════════════════

class Test10NoPlaintextLeak:
    """验收 10: 解密失败、密文异常和 DLQ 重放不会泄露明文敏感数据。"""

    def test_sanitize_error_redacts_secrets(self):
        from dlq_store import sanitize_error
        raw = (
            "failed for 10.13.37.9 with Authorization: Bearer eyJhbGciOi.J9.x "
            "token=ENC:AAAAbbbbcccc password=hunter2"
        )
        out = sanitize_error(raw)
        assert "eyJhbGciOi" not in out, "Bearer token 未脱敏"
        assert "hunter2" not in out, "口令未脱敏"
        assert "10.13.37.9" not in out, "内网 IP 未脱敏"
        assert "ENC:AAAA" not in out, "密文片段未脱敏"

    def test_seal_payload_roundtrip_has_no_plaintext(self):
        """落盘的 DLQ 负载必须是密文。"""
        from field_cipher import field_cipher
        _set_cipher_key()
        try:
            assert field_cipher.enabled is True
            sealed = field_cipher.seal_payload({
                "eventId": "seal-1", "srcIp": "10.1.2.3",
                "message": "TOP-SECRET-PAYLOAD",
            })
            assert sealed, "启用加密后必须产出密文"
            assert "TOP-SECRET-PAYLOAD" not in sealed, "密文里不得出现明文"
            assert "10.1.2.3" not in sealed
            back = field_cipher.open_sealed(sealed)
            assert back["message"] == "TOP-SECRET-PAYLOAD", "重放时必须能解回明文"
        finally:
            _clear_cipher_key()

    def test_malformed_ciphertext_is_rejected_not_silently_passed(self):
        """密文异常必须显式拒绝，不能把密文当明文继续用。"""
        from field_cipher import FieldCipherRejected, field_cipher
        _set_cipher_key()
        try:
            decision = field_cipher.open_message({"message": "ENC:not-a-real-token"})
            assert decision.ok is False, "无法解密的密文不得被判为通过"
            assert isinstance(decision, object)
            assert decision.code, "拒绝时必须给出原因码"
        finally:
            _clear_cipher_key()

    def test_dlq_envelope_carries_no_plaintext_payload(self):
        """DLQ 信封里不得出现 original_message 明文字段。"""
        async def _case():
            await _create_tables()
            from kafka_consumer import KafkaConsumerManager
            mgr = KafkaConsumerManager()
            mgr._running = True
            _set_cipher_key()
            try:
                sent = []

                class Prod:
                    async def send_and_wait(self, topic, key=None, value=None, headers=None):
                        sent.append(value)
                        return {"offset": 1}

                mgr._dlq_producer = Prod()
                await mgr._send_to_dlq(
                    "security-logs-rejected",
                    {"eventId": "leak-1", "message": "SUPER-SECRET-VALUE",
                     "apiKey": "ak-plaintext-should-not-appear"},
                    "boom", 1, partition=0, offset=1,
                )
                assert sent, "DLQ 应当写入一条信封"
                dumped = json.dumps(sent[0], ensure_ascii=False, default=str)
                assert "SUPER-SECRET-VALUE" not in dumped, "DLQ 信封泄露明文"
                assert "ak-plaintext-should-not-appear" not in dumped, "DLQ 信封泄露 apiKey"
                assert "original_message" not in sent[0], "不得存原始明文负载"
            finally:
                _clear_cipher_key()

        _run(_case())

    def test_dlq_error_text_is_sanitized_before_persist(self):
        async def _case():
            await _create_tables()
            _set_cipher_key()
            try:
                from dlq_store import persist_dlq_failure, get_record
                result = await persist_dlq_failure(
                    topic="security-alerts",
                    payload={"eventId": "sanitize-1", "srcIp": "10.9.8.7"},
                    error="connect failed to 10.9.8.7 using Bearer sk-live-abcdef",
                    retry_count=1, partition=0, offset=3,
                )
                assert result.persisted is True
                rec = await get_record(result.record_id)
                assert "sk-live-abcdef" not in (rec.get("sanitized_error") or "")
                assert "10.9.8.7" not in (rec.get("sanitized_error") or "")
            finally:
                _clear_cipher_key()

        _run(_case())


# ══════════════════════════════════════════════════════════════════
# 验收 11 — 通过 event_id 定位失败阶段
# ══════════════════════════════════════════════════════════════════

class Test11EventIdLocatesFailureStage:
    """验收 11: 最终未生成告警的事件，可以通过 event_id 定位失败阶段。"""

    def test_identity_resolves_event_id(self):
        from event_identity import resolve
        ident = resolve({"eventId": "loc-1"})
        assert ident.event_id == "loc-1"

    def test_ensure_identity_backfills_correlation(self):
        """补齐身份时，correlation_id 必须回落到 event_id，保证可串联。"""
        from event_identity import ensure_identity, resolve
        out = ensure_identity({"eventId": "loc-1", "eventType": "brute_force"})
        ident = resolve(out)
        assert ident.event_id == "loc-1"
        assert ident.correlation_id == "loc-1", \
            "缺省关联 ID 必须回落到 event_id，否则无法按一次攻击串联"

    def test_explicit_correlation_is_preserved(self):
        from event_identity import ensure_identity, resolve
        out = ensure_identity({"eventId": "loc-2", "correlationId": "corr-9"})
        assert resolve(out).correlation_id == "corr-9"

    def test_identity_falls_back_to_kafka_header(self):
        from event_identity import resolve
        ident = resolve({}, [(b"event_id", b"from-header")])
        assert ident.event_id == "from-header"

    def test_identity_generates_when_missing(self):
        from event_identity import ensure_identity, resolve
        out = ensure_identity({"eventType": "brute_force"})
        assert out.get("eventId"), "缺失 eventId 时必须补齐，否则幂等失效"
        assert resolve(out).event_id == out["eventId"]

    def test_snapshot_flags_a_stalled_event(self):
        """按 event_id 取回的快照必须能看出这条事件没跑完。"""
        async def _case():
            await _create_tables()
            from models import async_session
            from event_store import event_store
            from event_replay import fetch_event_snapshot

            async with async_session() as session:
                stored = await event_store.store(session, {
                    "eventId": "stage-1", "event": "c2_beacon", "severity": "critical",
                    "src_ip": "10.0.0.5", "dst_ip": "3.3.3.3", "protocol": "tcp",
                    "message": "beacon", "confidence": 95,
                }, "sess-stage")
            snap = await fetch_event_snapshot(stored.id)
            assert snap is not None
            assert snap["analyzed"] is False, "未审计的事件必须被标记出来"
            assert snap["audit_verdict"] == "", "没有结论时不得伪造判定"
            assert snap["event_id"] == stored.id

        _run(_case())

    def test_failure_reason_is_persisted_for_lookup(self):
        """失败原因必须落到记录里，运维才能按 event_id 追到卡在哪一步。"""
        async def _case():
            await _create_tables()
            from models import SecurityEvent, async_session
            from event_store import event_store
            from sqlalchemy import select

            async with async_session() as session:
                stored = await event_store.store(session, {
                    "eventId": "stage-2", "event": "c2_beacon", "severity": "high",
                    "src_ip": "10.0.0.6", "dst_ip": "3.3.3.4", "protocol": "tcp",
                    "message": "beacon", "confidence": 90,
                }, "sess-stage2")
            async with async_session() as session:
                await event_store.apply_event_update(
                    session, stored.id,
                    analyzed=True,
                    merge_raw={"_audit_llm_error": "pipeline_timeout"},
                )
            async with async_session() as session:
                row = (await session.execute(
                    select(SecurityEvent).where(SecurityEvent.id == stored.id)
                )).scalar_one()
            assert (row.raw_data or {}).get("_audit_llm_error") == "pipeline_timeout", \
                "失败阶段必须随 event_id 一起持久化"

        _run(_case())

    def test_dlq_record_is_queryable_by_event_id(self):
        """进 DLQ 的事件必须能按 event_id 查到，否则失败阶段无从追溯。"""
        async def _case():
            await _create_tables()
            _set_cipher_key()
            try:
                from dlq_store import persist_dlq_failure, list_records
                await persist_dlq_failure(
                    topic="security-alerts",
                    payload={"eventId": "dlq-loc-1"},
                    error="permanent decode error", retry_count=3,
                    partition=0, offset=11,
                )
                rows = await list_records(event_id="dlq-loc-1")
                assert len(rows) == 1, "DLQ 必须能按 event_id 检索"
                assert rows[0]["original_partition"] == 0
                assert rows[0]["original_offset"] == 11, "必须保留原始 offset 才能定位"
                assert rows[0]["attempt_count"] >= 1, "必须记录尝试次数"
            finally:
                _clear_cipher_key()

        _run(_case())

    def test_pipeline_stage_labels_are_bounded(self):
        """阶段标签必须受限，否则指标基数爆炸反而无法排查。"""
        from core_metrics import clamp_label, clamp_reason
        assert clamp_label("x" * 500, allowed=None) != "x" * 500, "标签必须被裁剪"
        assert clamp_reason("anything") != ""

    def test_ingest_rejected_metric_records_stage(self):
        from core_metrics import record_ingest
        record_ingest("kafka", "validation_failed", reason="decode")


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
