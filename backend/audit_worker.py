"""有界 Audit worker 池 — 取代每事件 asyncio.create_task(_audit_pipeline)。

内存里永远只有 N 个审计协程。队列满时 P0/P1 进 Redis PQ, P2/P3 返回 overflow
让调用方规则收口。cancel(event_id) 供 stuck reaper 回收 slot。

P0/P1 (audit_p0/p1_never_drop=True) 在内存队列满时按
Redis PQ → Kafka overflow topic → 进程内 _p0_overflow deque,
不返回 overflow。

持久性是分开的，不能把内存里的任务叫绝不丢失：
  - shed: 已进入 Redis PQ，进程崩溃后仍在
  - deferred 且 Kafka overflow 成功: 已进入 Kafka
  - queued / 本地 deque: 只在本进程内存。优雅停机会把它们写到
    Kafka 或 fsync 日志再退出；杀进程或宕机时，没写出去的会丢。
    已落库且 analyzed=False 的事件，启动时按上限再送回 worker。
"""
from __future__ import annotations

import asyncio
import logging
from collections import deque
from typing import Any, Optional

from config import settings

logger = logging.getLogger(__name__)

# 进程内 P0/P1 兜底 deque 容量上限(仅 Redis PQ 与 Kafka overflow 均失败时使用)
# 这是易失缓冲，不是持久队列。上限 10000，加上内存堆 2000，停机前最多这么多条要落盘。
P0_OVERFLOW_MAX = 10000


class AuditWorkerPool:
    def __init__(self) -> None:
        self._queue: asyncio.PriorityQueue = asyncio.PriorityQueue()
        self._tasks: list[asyncio.Task] = []
        self._inflight: dict[int, asyncio.Task] = {}
        self._busy = 0
        self._seq = 0
        self._started = False
        self._draining = False
        self._stop_pulling = False
        self._start_lock: Optional[asyncio.Lock] = None
        self._p0_overflow: deque = deque()
        self._pending_ids: set[int] = set()
        self._inflight_jobs: dict[int, dict] = {}

    @property
    def started(self) -> bool:
        return self._started

    @property
    def busy(self) -> int:
        return self._busy

    def queue_depth(self) -> int:
        try:
            return int(self._queue.qsize())
        except Exception:
            return 0

    def inflight_ids(self) -> list[int]:
        return list(self._inflight.keys())

    def _n_workers(self) -> int:
        return max(1, int(getattr(settings, "audit_workers", 12) or 12))

    def _queue_max(self) -> int:
        return max(1, int(getattr(settings, "audit_queue_max", 2000) or 2000))

    async def start(self) -> None:
        if self._started:
            return
        if self._start_lock is None:
            self._start_lock = asyncio.Lock()
        async with self._start_lock:
            if self._started:
                return
            n = self._n_workers()
            self._tasks = [
                asyncio.create_task(self._loop(i), name=f"audit-worker-{i}")
                for i in range(n)
            ]
            self._started = True
            self._draining = False
            self._stop_pulling = False
            logger.info("AuditWorkerPool started workers=%d queue_max=%d", n, self._queue_max())
            self._publish_gauges()
            await self._replay_journal()

    def holds(self, event_id: int) -> bool:
        return int(event_id) in self._pending_ids or int(event_id) in self._inflight

    async def stop(self, timeout: Optional[float] = None) -> dict:
        """进入 draining，等在途任务，再把内存里剩下的任务写成可恢复记录。

        不把取消当成这些任务已经完成。写失败的条数在 volatile_lost。
        """
        self._draining = True
        limit = self._drain_timeout(timeout)
        loop = asyncio.get_running_loop()
        deadline = loop.time() + max(0.0, limit)
        while loop.time() < deadline:
            if self.queue_depth() == 0 and not self._p0_overflow and self._busy == 0:
                break
            await asyncio.sleep(0.02)

        self._stop_pulling = True
        await asyncio.sleep(0)
        leftover = self._pop_memory_jobs()
        inflight_jobs = dict(self._inflight_jobs)
        inflight_tasks = dict(self._inflight)

        self._started = False
        for task in self._tasks:
            task.cancel()
        for task in inflight_tasks.values():
            task.cancel()
        wait = list(self._tasks) + list(inflight_tasks.values())
        if wait:
            await asyncio.gather(*wait, return_exceptions=True)
        self._tasks.clear()

        spilled = 0
        lost = 0
        for job in leftover:
            kind = await self._persist_volatile(job, reason_prefix="shutdown")
            if kind == "lost":
                lost += 1
            else:
                spilled += 1
        cancelled = 0
        for eid, task in inflight_tasks.items():
            if not task.cancelled():
                continue
            job = inflight_jobs.get(eid)
            if not job:
                continue
            cancelled += 1
            kind = await self._persist_volatile(job, reason_prefix="shutdown")
            if kind == "lost":
                lost += 1
            else:
                spilled += 1

        self._inflight.clear()
        self._inflight_jobs.clear()
        self._busy = 0
        report = {
            "spilled": spilled,
            "volatile_lost": lost,
            "inflight_cancelled": cancelled,
            "guarantee": "memory queue is volatile until spill or broker ack",
        }
        logger.info("AuditWorkerPool stopped %s", report)
        return report

    def _drain_timeout(self, timeout: Optional[float]) -> float:
        if timeout is not None:
            return float(timeout)
        return float(getattr(settings, "shutdown_drain_timeout_s", 20) or 20)

    def _pop_memory_jobs(self) -> list[dict]:
        jobs: list[dict] = []
        while True:
            try:
                _prio, _seq, job = self._queue.get_nowait()
            except asyncio.QueueEmpty:
                break
            jobs.append(job)
            self._pending_ids.discard(int(job.get("event_id") or 0))
            try:
                self._queue.task_done()
            except Exception:
                pass
        while self._p0_overflow:
            job = self._p0_overflow.popleft()
            jobs.append(job)
            self._pending_ids.discard(int(job.get("event_id") or 0))
        return jobs

    def cancel(self, event_id: int) -> bool:
        t = self._inflight.get(int(event_id))
        if t is None:
            return False
        t.cancel()
        return True

    def _publish_gauges(self) -> None:
        try:
            from metrics import set_audit_runtime
            set_audit_runtime(inflight=self._busy, queue_depth=self.queue_depth(), workers=self._n_workers())
        except Exception:
            pass

    async def submit(
        self,
        *,
        session_id: str,
        event_id: int,
        log_data: dict,
        anomaly_report: Any,
        from_overflow: bool = False,
    ) -> str:
        """投递审计任务。

        Returns:
          queued    — 进内存堆。进程崩溃会丢，除非对应 SecurityEvent 还在库里
          shed      — 队列满, 已进入 Redis PQ（可恢复）
          deferred  — 已进入 Kafka overflow，或只进了进程内 deque（后者易失）
          spilled   — draining 期间没有进内存，已写入 Kafka 或 spill 日志
          rejected  — draining 期间持久化失败，调用方不得当成已接受
          overflow  — P2/P3 (或 never_drop 关闭时 P0/P1) 队列满, 调用方规则收口
          direct    — worker 未启动(测试), 直接 create_task
        """
        from drain import drain

        if self._draining or not drain.accepting:
            from audit_triage import score_event
            score = float(getattr(anomaly_report, "anomaly_score", 0) or 0)
            triage = score_event(log_data or {}, score)
            job = self._make_job(
                session_id, event_id, log_data, anomaly_report, triage.tier, int(triage.priority),
            )
            kind = await self._persist_volatile(job, reason_prefix="drain")
            return "rejected" if kind == "lost" else "spilled"

        if not self._started:
            try:
                asyncio.get_running_loop()
            except RuntimeError:
                return "direct"
            # 测试/延迟启动: 懒启动,避免无界 create_task
            await self.start()

        from audit_triage import score_event
        score = float(getattr(anomaly_report, "anomaly_score", 0) or 0)
        triage = score_event(log_data or {}, score)
        if self.queue_depth() >= self._queue_max():
            tier = triage.tier
            never_drop = (
                (tier == "P0" and bool(getattr(settings, "audit_p0_never_drop", True)))
                or (tier == "P1" and bool(getattr(settings, "audit_p1_never_drop", True)))
            )
            if never_drop:
                # Redis PQ 与 Kafka overflow 才是可恢复接受。
                # 本地 deque 只是易失缓冲；挤出时必须先落盘，落盘失败才是真丢。
                # from_overflow=True: 已从 Kafka overflow 回灌, 禁止再 produce 以免环路
                job = self._make_job(
                    session_id, event_id, log_data, anomaly_report, tier, int(triage.priority),
                )
                if await self._enqueue_pq(
                    session_id=session_id,
                    event_id=event_id,
                    log_data=log_data,
                    anomaly_report=anomaly_report,
                    triage=triage,
                ):
                    self._shed(tier, "pq_ok")
                    return "shed"
                self._shed(tier, "pq_fail")
                if not from_overflow and await self._enqueue_kafka_overflow(job):
                    self._shed(tier, "kafka_overflow")
                    return "deferred"
                self._p0_overflow.append(job)
                self._pending_ids.add(int(event_id))
                while len(self._p0_overflow) > P0_OVERFLOW_MAX:
                    dropped = self._p0_overflow.popleft()
                    self._pending_ids.discard(int(dropped.get("event_id") or 0))
                    kind = await self._persist_volatile(dropped, reason_prefix="deque")
                    if kind == "lost":
                        logger.error(
                            "AuditWorker P0/P1 local deque lost event_id=%s (cap=%s)",
                            dropped.get("event_id"), P0_OVERFLOW_MAX,
                        )
                        self._shed(str(dropped.get("tier") or tier), "local_deque_evicted")
                    else:
                        self._shed(str(dropped.get("tier") or tier), "local_deque_spilled")
                self._shed(tier, "local_deque")
                return "deferred"
            self._shed(tier, "memory_full")
            return "overflow"

        self._seq += 1
        job = self._make_job(
            session_id, event_id, log_data, anomaly_report, triage.tier, int(triage.priority),
        )
        await self._queue.put((-int(triage.priority), self._seq, job))
        self._pending_ids.add(int(event_id))
        self._publish_gauges()
        return "queued"

    @staticmethod
    def _make_job(session_id, event_id, log_data, anomaly_report, tier, priority) -> dict:
        return {
            "session_id": session_id,
            "event_id": int(event_id),
            "log_data": log_data,
            "anomaly_report": anomaly_report,
            "tier": tier,
            "priority": int(priority),
        }

    @staticmethod
    def _job_record(job: dict) -> dict:
        report = job.get("anomaly_report")
        return {
            "session_id": job.get("session_id") or "",
            "event_id": int(job.get("event_id") or 0),
            "log_data": job.get("log_data") or {},
            "tier": job.get("tier") or "",
            "priority": int(job.get("priority") or 0),
            "anomaly_score": float(getattr(report, "anomaly_score", 0) or 0),
            "is_anomaly": bool(getattr(report, "is_anomaly", False)),
            "deviation_sigma": float(getattr(report, "deviation_sigma", 0) or 0),
            "reasons": list(getattr(report, "reasons", []) or [])[:20],
        }

    async def _persist_volatile(self, job: dict, *, reason_prefix: str) -> str:
        """内存任务在退出或挤出前写入 Kafka，失败再 fsync 到 spill 日志。"""
        if await self._enqueue_kafka_overflow(job):
            self._shed(str(job.get("tier") or "?"), f"{reason_prefix}_kafka")
            return "kafka"
        from audit_spill import append_record
        if append_record(self._job_record(job)):
            self._shed(str(job.get("tier") or "?"), f"{reason_prefix}_journal")
            return "journal"
        self._shed(str(job.get("tier") or "?"), f"{reason_prefix}_lost")
        logger.error(
            "Audit task still only in memory and could not be persisted event_id=%s",
            job.get("event_id"),
        )
        return "lost"

    async def _replay_journal(self) -> int:
        from audit_spill import read_records, replace_records

        records = read_records()
        if not records:
            return 0
        kept: list[dict] = []
        loaded = 0
        seen: set[int] = set()
        for record in records:
            eid = int(record.get("event_id") or 0)
            if eid <= 0 or eid in seen:
                continue
            seen.add(eid)
            if eid in self._pending_ids:
                kept.append(record)
                continue
            if self.queue_depth() >= self._queue_max() and len(self._p0_overflow) >= P0_OVERFLOW_MAX:
                kept.append(record)
                continue
            job = _job_from_record(record)
            if self.queue_depth() < self._queue_max():
                self._seq += 1
                await self._queue.put((-int(job.get("priority") or 0), self._seq, job))
            else:
                self._p0_overflow.append(job)
            self._pending_ids.add(eid)
            kept.append(record)
            loaded += 1
        replace_records(kept)
        if loaded:
            logger.info("AuditWorker replayed %d spilled tasks (%d still on disk)", loaded, len(kept))
        return loaded

    async def _enqueue_pq(self, *, session_id, event_id, log_data, anomaly_report, triage) -> bool:
        try:
            from audit_pq import audit_pq, pq_ttl_for_tier
            from audit_triage import lane_max_rounds
            ttl = pq_ttl_for_tier(triage.tier)
            return await audit_pq.enqueue(
                event_id=int(event_id),
                session_id=session_id,
                log_data=log_data or {},
                anomaly_score=float(getattr(anomaly_report, "anomaly_score", 0) or 0),
                anomaly_reasons=list(getattr(anomaly_report, "reasons", []) or []),
                max_rounds=lane_max_rounds(triage.lane, 3),
                priority=int(triage.priority),
                tier=triage.tier,
                ttl_s=ttl,
            )
        except Exception as e:
            logger.warning("AuditWorker PQ enqueue failed: %s", e)
            return False

    def _shed(self, tier: str, reason: str) -> None:
        try:
            from metrics import inc_audit_shed
            inc_audit_shed(tier, reason)
        except Exception:
            pass

    async def _enqueue_kafka_overflow(self, job: dict) -> bool:
        """内存队列满且 Redis PQ 失败时, 把审计任务持久化到 Kafka overflow topic。

        producer 未启动或投递失败 → False, 调用方走进程内 deque 兜底。
        """
        try:
            from kafka_producer import kafka_producer as kp
            if not bool(getattr(kp, "is_active", False)):
                return False
            ar = job.get("anomaly_report")
            payload = {
                "event_id": int(job.get("event_id") or 0),
                "session_id": job.get("session_id") or "",
                "log_data": job.get("log_data") or {},
                "anomaly_score": float(getattr(ar, "anomaly_score", 0) or 0),
                "reasons": list(getattr(ar, "reasons", []) or [])[:20],
                "tier": job.get("tier") or "",
                "priority": int(job.get("priority") or 0),
            }
            return await kp.produce_raw(
                payload,
                topic=settings.kafka_topic_audit_overflow,
                key_field="event_id",
            )
        except Exception as e:
            logger.warning("AuditWorker Kafka overflow enqueue failed: %s", e)
            return False

    async def _loop(self, idx: int) -> None:
        overflow_streak = 0
        while not self._stop_pulling:
            job = None
            from_mem = True
            try:
                if self._stop_pulling:
                    break
                if self._p0_overflow:
                    # 本地兜底 FIFO; 每 2 个 overflow 穿插 1 个普通队列, 穿插后重置 streak,
                    # 避免 streak 停在阈值导致普通队列把 deque 饿死。
                    take_mem = overflow_streak >= 2 and not self._queue.empty()
                    if take_mem:
                        try:
                            _prio, _seq, job = self._queue.get_nowait()
                            overflow_streak = 0
                        except asyncio.QueueEmpty:
                            job = self._p0_overflow.popleft()
                            from_mem = False
                            overflow_streak += 1
                    else:
                        job = self._p0_overflow.popleft()
                        from_mem = False
                        overflow_streak += 1
                else:
                    overflow_streak = 0
                    _prio, _seq, job = await self._queue.get()
            except asyncio.CancelledError:
                raise
            if job is None:
                continue
            try:
                await self._run_job(job)
            except asyncio.CancelledError:
                raise
            except Exception as e:
                logger.error("AuditWorker[%s] job failed: %s", idx, e, exc_info=True)
            finally:
                if from_mem:
                    try:
                        self._queue.task_done()
                    except Exception:
                        pass
                self._pending_ids.discard(int(job.get("event_id") or 0))
                self._publish_gauges()

    async def _run_job(self, job: dict) -> None:
        from log_ingestion import log_ingestor

        eid = int(job.get("event_id") or 0)
        self._busy += 1
        self._inflight_jobs[eid] = job
        t = asyncio.create_task(
            log_ingestor._audit_pipeline(
                job.get("session_id") or "",
                eid,
                job.get("log_data") or {},
                job.get("anomaly_report"),
            ),
            name=f"audit-job-{eid}",
        )
        t.add_done_callback(log_ingestor._audit_task_done)
        self._inflight[eid] = t
        try:
            await t
        except asyncio.CancelledError:
            raise
        else:
            from audit_spill import drop_event
            drop_event(eid)
        finally:
            self._inflight.pop(eid, None)
            self._inflight_jobs.pop(eid, None)
            self._busy = max(0, self._busy - 1)


def _job_from_record(record: dict) -> dict:
    from anomaly_detector import AnomalyReport

    eid = int(record.get("event_id") or 0)
    score = float(record.get("anomaly_score") or 0)
    report = AnomalyReport(
        event_id=eid,
        anomaly_score=score,
        is_anomaly=bool(record.get("is_anomaly")),
        deviation_sigma=float(record.get("deviation_sigma") or 0),
        reasons=list(record.get("reasons") or []),
    )
    return {
        "session_id": record.get("session_id") or "",
        "event_id": eid,
        "log_data": record.get("log_data") or {},
        "anomaly_report": report,
        "tier": record.get("tier") or "",
        "priority": int(record.get("priority") or 0),
    }


async def recover_unanalyzed(limit: Optional[int] = None) -> int:
    """把已落库、尚未分析、且不在本进程队列里的事件再送进 worker。

    这是进程崩溃后的恢复：当时若只存在内存队列里，行还在，审计可以重做。
    已经在 Redis PQ / 本进程队列里的不重复提交。单次不超过 audit_recovery_limit。
    """
    from sqlalchemy import select

    from anomaly_detector import AnomalyReport
    from models import SecurityEvent, async_session

    cap = limit
    if cap is None:
        cap = int(getattr(settings, "audit_recovery_limit", 2000) or 2000)
    cap = max(0, int(cap))
    if cap == 0 or not audit_worker.started:
        return 0
    async with async_session() as session:
        rows = (await session.execute(
            select(SecurityEvent)
            .where(SecurityEvent.analyzed == False)  # noqa: E712
            .order_by(SecurityEvent.id.asc())
            .limit(cap)
        )).scalars().all()
        pending = [
            (
                int(row.id),
                row.session_id or "",
                dict(row.raw_data or {}),
                float(row.anomaly_score or 0),
                row.event_type or "UNKNOWN",
                row.severity or "info",
                row.src_ip or "",
                row.dst_ip or "",
                row.message or "",
            )
            for row in rows
            if not audit_worker.holds(int(row.id))
        ]
    restored = 0
    for eid, session_id, raw, score, event_type, severity, src_ip, dst_ip, message in pending:
        audit = raw.get("_audit_llm") if isinstance(raw.get("_audit_llm"), dict) else {}
        if audit.get("status") == "completed":
            continue
        log_data = raw or {
            "event": event_type,
            "severity": severity,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "message": message,
        }
        reasons = []
        anomaly = log_data.get("_anomaly") if isinstance(log_data, dict) else None
        if isinstance(anomaly, dict):
            reasons = list(anomaly.get("reasons") or [])
        report = AnomalyReport(
            event_id=eid,
            anomaly_score=score,
            is_anomaly=score >= 0.6,
            deviation_sigma=0.0,
            reasons=reasons,
        )
        status = await audit_worker.submit(
            session_id=session_id,
            event_id=eid,
            log_data=log_data,
            anomaly_report=report,
        )
        if status in ("queued", "shed", "deferred", "spilled", "direct"):
            restored += 1
    if restored:
        logger.info("Recovered %d unanalyzed events into the audit worker", restored)
    return restored


audit_worker = AuditWorkerPool()
