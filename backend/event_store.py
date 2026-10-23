"""
全量日志存储 (EventStore) — 安全审计的数据底座

设计原则：
  - 所有原始日志永久保留（永不压缩、永不删除）
  - 分层存储：热(PostgreSQL) → 温(Parquet) → 冷(S3)
  - 独立于记忆系统，Agent 通过引用查询完整数据

分层策略：
  热存储 (7天):  PostgreSQL + Redis 缓存
  温存储 (90天):  本地 Parquet 文件
  冷存储 (永久):   可配置 S3/MinIO 对象存储

用法:
    store = EventStore()
    # 写入
    await store.store(session, event_data)
    # 查询
    events = await store.query(session_id, filters={
        "src_ip": "10.0.0.5",
        "time_range": ("2026-07-01", "2026-07-28"),
        "severity": "critical",
    })
    # 攻击链回溯
    chain = await store.get_chain(session_id, correlation_id)
"""
import json
import logging
import os
import time
import uuid
from collections import OrderedDict
from dataclasses import dataclass, asdict, fields as dataclass_fields
from datetime import datetime
from typing import Optional

from sqlalchemy import select, desc, and_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from models import SecurityEvent
from config import settings

logger = logging.getLogger(__name__)


@dataclass
class EventFilter:
    """事件查询过滤器"""
    session_id: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    event_type: str = ""
    severity: str = ""
    time_start: Optional[datetime] = None
    time_end: Optional[datetime] = None
    min_anomaly_score: float = 0.0
    is_anomaly: Optional[bool] = None
    limit: int = 100
    offset: int = 0


@dataclass
class StoredEvent:
    """存储在 EventStore 中的完整事件"""
    id: int
    session_id: str
    event_type: str
    severity: str
    src_ip: str
    dst_ip: str
    message: str
    raw_data: dict
    anomaly_score: float = 0.0
    correlation_id: str = ""
    created_at: str = ""
    analyzed: bool = False
    idempotent: bool = False
    event_id: str = ""
    parent_event_id: str = ""
    trace_id: str = ""


@dataclass
class _HotCacheEntry:
    """热缓存条目：业务快照 + 代次 + 写入时刻（monotonic）。"""
    data: dict
    gen: int
    cached_at: float


_STORED_EVENT_FIELDS = {f.name for f in dataclass_fields(StoredEvent)}


def _identity_for_store(event_data: dict, correlation_id: str = "") -> tuple[dict, Optional[str], str, str, str]:
    """盖章并抽出落库用的业务身份。已有 eventId 保留。"""
    from event_identity import ensure_identity, resolve
    data = ensure_identity(event_data if isinstance(event_data, dict) else {})
    ident = resolve(data)
    eid = ident.event_id[:64] if ident.event_id else None
    corr = (correlation_id or ident.correlation_id or "")[:128]
    parent = (ident.parent_event_id or "")[:64]
    tid = (ident.trace_id or "")[:128]
    if corr:
        data["_correlation_id"] = corr
        data.setdefault("correlationId", corr)
    if parent:
        data["_parent_event_id"] = parent
        data.setdefault("parentEventId", parent)
    if tid:
        data["_trace_id"] = tid
        data.setdefault("traceId", tid)
    return data, eid, corr, parent, tid


class EventStore:
    """
    全量日志存储

    支持的存储后端：
    - postgres: 通过现有的 SecurityEvent 表（热存储）
    - parquet: 本地列存文件（温存储）
    - s3: 对象存储（冷存储，可选）

    所有写入操作强制同步写入 postgres，异步归档到温/冷层。
    """

    def __init__(self):
        self.data_dir = os.path.join(
            os.path.dirname(__file__), "event_archive"
        )
        os.makedirs(self.data_dir, exist_ok=True)
        # 热缓存 LRU：容量上限 + TTL 兜底。TTL 不能替代失效广播。
        env_max = os.environ.get("EVENT_STORE_HOT_CACHE_MAX")
        if env_max:
            self._hot_cache_max = int(env_max)
        else:
            self._hot_cache_max = int(
                getattr(settings, "event_store_hot_cache_max", 2000) or 2000
            )
        ttl = float(getattr(settings, "event_store_hot_cache_ttl_s", 0) or 0)
        if ttl <= 0:
            # 流水线状态新鲜度：对齐最短审计车道超时（P2）。
            ttl = float(getattr(settings, "audit_timeout_p2_s", 20.0) or 20.0)
        self._hot_cache_ttl_s = ttl
        self._hot_cache: "OrderedDict[int, _HotCacheEntry]" = OrderedDict()
        self._generations: "OrderedDict[int, int]" = OrderedDict()
        self._origin = uuid.uuid4().hex
        self._initialized = False
        # Redis 跨进程失效通道: Temporal worker 写回后通知 backend 丢弃热缓存
        self._redis = None
        self._invalidate_channel = "soc:event_store:invalidate"
        self._invalidate_listener_task = None

    def _now(self) -> float:
        return time.monotonic()

    def current_generation(self, event_id: int) -> int:
        return int(self._generations.get(int(event_id), 0))

    def _bump_generation(self, event_id: int) -> int:
        eid = int(event_id)
        nxt = self.current_generation(eid) + 1
        self._generations[eid] = nxt
        self._generations.move_to_end(eid)
        max_gen = max(int(self._hot_cache_max) * 2, 64)
        while len(self._generations) > max_gen:
            old_id, _ = self._generations.popitem(last=False)
            self._hot_cache.pop(old_id, None)
        return nxt

    def _unpack_entry(self, event_id: int, cached) -> Optional[_HotCacheEntry]:
        if isinstance(cached, _HotCacheEntry):
            return cached
        if isinstance(cached, dict):
            return _HotCacheEntry(
                data=cached,
                gen=self.current_generation(event_id),
                cached_at=self._now(),
            )
        return None

    def _cache_data(self, event_id: int) -> Optional[dict]:
        cached = self._hot_cache.get(int(event_id))
        if cached is None:
            return None
        entry = self._unpack_entry(int(event_id), cached)
        return None if entry is None else entry.data

    def _entry_expired(self, entry: _HotCacheEntry) -> bool:
        ttl = float(self._hot_cache_ttl_s or 0)
        if ttl <= 0:
            return False
        return (self._now() - float(entry.cached_at)) > ttl

    def _drop_local(self, event_id: int) -> None:
        self._hot_cache.pop(int(event_id), None)

    def _cache_metric(self, result: str) -> None:
        try:
            from core_metrics import record_cache
            record_cache("event_store", result)
        except Exception:
            pass

    def _stored_from_cache(self, data: dict) -> StoredEvent:
        payload = {k: v for k, v in data.items() if k in _STORED_EVENT_FIELDS}
        return StoredEvent(**payload)

    def _cache_put(
        self,
        event_id: int,
        data: dict,
        *,
        expected_gen: Optional[int] = None,
    ) -> bool:
        """写入热缓存。expected_gen 与当前代次不一致则拒绝，避免失效后把旧快照写回。"""
        eid = int(event_id)
        current = self.current_generation(eid)
        if expected_gen is not None and int(expected_gen) != current:
            return False
        payload = dict(data)
        payload.pop("_cache_gen", None)
        payload.pop("_cached_at", None)
        self._hot_cache[eid] = _HotCacheEntry(
            data=payload,
            gen=current,
            cached_at=self._now(),
        )
        self._hot_cache.move_to_end(eid)
        while len(self._hot_cache) > self._hot_cache_max:
            self._hot_cache.popitem(last=False)
        return True

    def set_redis(self, redis_client) -> None:
        """接入 Redis，启用跨进程热缓存失效广播。"""
        self._redis = redis_client
        logger.info("EventStore: Redis invalidate channel enabled")

    def notify_committed(self, *event_ids: int, broadcast: bool = True) -> None:
        """数据库事务已提交之后调用：抬升代次、丢本进程缓存、再通知其他进程。

        禁止在 commit 前调用，否则其他进程会把尚未提交的旧行重新读进缓存。
        """
        for event_id in event_ids:
            if event_id is None:
                continue
            self.invalidate(int(event_id), broadcast=broadcast)

    async def commit_then_invalidate(
        self,
        session: AsyncSession,
        *event_ids: int,
        broadcast: bool = True,
    ) -> None:
        """标准顺序：先提交数据库，再失效本进程缓存并广播。"""
        await session.commit()
        self.notify_committed(*event_ids, broadcast=broadcast)

    async def apply_event_update(
        self,
        session: AsyncSession,
        event_id: int,
        *,
        analyzed: Optional[bool] = None,
        raw_data: Optional[dict] = None,
        merge_raw: Optional[dict] = None,
        status: Optional[str] = None,
        mutator=None,
        commit: bool = True,
        broadcast: bool = True,
    ) -> Optional[SecurityEvent]:
        """改变事件状态的统一入口。默认 commit 成功后才发失效通知。"""
        evt = await session.get(SecurityEvent, int(event_id))
        if evt is None:
            return None
        if analyzed is not None:
            evt.analyzed = analyzed
        if status is not None:
            evt.status = status
        if raw_data is not None:
            evt.raw_data = raw_data
        elif merge_raw is not None:
            evt.raw_data = {**(evt.raw_data or {}), **merge_raw}
        if mutator is not None:
            mutator(evt)
        if commit:
            await self.commit_then_invalidate(
                session, int(event_id), broadcast=broadcast
            )
        return evt

    def invalidate(self, event_id: int, *, broadcast: bool = True) -> None:
        """事务提交后丢弃热缓存并抬升代次。

        broadcast=True 时通过 Redis pub/sub 通知其他进程。
        必须在数据库 commit 成功之后调用。
        """
        if event_id is None:
            return
        eid = int(event_id)
        gen = self._bump_generation(eid)
        self._drop_local(eid)
        if broadcast:
            self._publish_invalidate(eid, gen)

    def _publish_invalidate(self, event_id: int, gen: int) -> None:
        if self._redis is None:
            return
        try:
            import asyncio
            pub = getattr(self._redis, "publish", None)
            if pub is None:
                return
            payload = json.dumps({
                "id": int(event_id),
                "gen": int(gen),
                "origin": self._origin,
            })
            result = pub(self._invalidate_channel, payload)
            if asyncio.iscoroutine(result):
                try:
                    loop = asyncio.get_running_loop()
                    loop.create_task(result)
                except RuntimeError:
                    pass
        except Exception as e:
            logger.debug(f"EventStore invalidate broadcast failed: {e}")
            try:
                from core_metrics import record_cache_invalidate_failure
                record_cache_invalidate_failure("event_store")
            except Exception:
                pass

    def _parse_invalidate_payload(self, data):
        if isinstance(data, bytes):
            data = data.decode()
        if isinstance(data, (int, float)):
            return int(data), None, None
        if not isinstance(data, str):
            return None, None, None
        text = data.strip()
        if not text:
            return None, None, None
        if text.startswith("{"):
            obj = json.loads(text)
            return int(obj["id"]), obj.get("gen"), obj.get("origin")
        return int(text), None, None

    def _apply_remote_invalidate(
        self,
        event_id: int,
        remote_gen: Optional[int] = None,
        origin: Optional[str] = None,
    ) -> None:
        if origin and origin == self._origin:
            return
        eid = int(event_id)
        local = self.current_generation(eid)
        if remote_gen is None:
            self._bump_generation(eid)
        else:
            if int(remote_gen) < local:
                return
            self._generations[eid] = int(remote_gen)
            self._generations.move_to_end(eid)
        self._drop_local(eid)

    def update_hot_cache(self, event_id: int, **fields) -> None:
        """就地更新热缓存字段；不存在则忽略（下次 get_by_id 走 DB）。"""
        if event_id is None:
            return
        eid = int(event_id)
        cached = self._hot_cache.get(eid)
        if cached is None:
            return
        entry = self._unpack_entry(eid, cached)
        if entry is None:
            return
        entry.data.update(fields)
        entry.cached_at = self._now()
        self._hot_cache[eid] = entry

    async def start_invalidate_listener(self) -> None:
        """订阅 Redis 失效通道，丢弃本进程热缓存。backend / worker 均可调用。"""
        if self._redis is None or self._invalidate_listener_task is not None:
            return
        try:
            pubsub = self._redis.pubsub()
            await pubsub.subscribe(self._invalidate_channel)
        except Exception as e:
            logger.warning(f"EventStore invalidate listener subscribe failed: {e}")
            return

        async def _listen():
            try:
                async for msg in pubsub.listen():
                    if not msg or msg.get("type") != "message":
                        continue
                    try:
                        eid, remote_gen, origin = self._parse_invalidate_payload(
                            msg.get("data")
                        )
                    except (TypeError, ValueError, json.JSONDecodeError, KeyError):
                        continue
                    if eid is None:
                        continue
                    self._apply_remote_invalidate(eid, remote_gen, origin)
            except Exception as e:
                logger.warning(f"EventStore invalidate listener stopped: {e}")

        import asyncio
        self._invalidate_listener_task = asyncio.create_task(
            _listen(), name="event-store-invalidate"
        )
        logger.info("EventStore: invalidate listener started")

    async def store(
        self,
        session: AsyncSession,
        event_data: dict,
        session_id: str,
        anomaly_score: float = 0.0,
        correlation_id: str = "",
    ) -> StoredEvent:
        """
        存储一条安全事件到全量存储

        自动写 PostgreSQL（热存储），异步归档到文件（温存储）。

        幂等性 (event_id 唯一约束兜底):
          上游 eventId 已存在 → 跳过插入并返回已存在记录，
          跨运行时重放/Exactly-Once 下同一条事件只落库一次。
          (替代原 kafka_consumer 的 Redis 24h 去重)
        """
        event_data, event_id, correlation_id, parent_event_id, trace_id = _identity_for_store(
            event_data, correlation_id
        )
        event_type = event_data.get("event", event_data.get("type", "UNKNOWN"))
        severity = event_data.get("severity", "info")

        # 幂等检查: eventId 已落库 → 直接返回已存在记录 (不重复插入)
        if event_id:
            existing = await self.get_by_upstream_id(session, event_id)
            if existing is not None:
                logger.info(
                    f"[Idempotent] eventId={event_id} 已存在 (#{existing.id}), 跳过重复入库"
                )
                existing.idempotent = True
                return existing

        evt_kwargs = dict(
            event_id=event_id,
            session_id=session_id,
            event_type=event_type,
            severity=severity,
            src_ip=event_data.get("src_ip", ""),
            dst_ip=event_data.get("dst_ip", ""),
            protocol=event_data.get("protocol", ""),
            action=event_data.get("action", ""),
            message=event_data.get("message", ""),
            raw_data={
                **event_data,
                "_anomaly_score": anomaly_score,
                "_correlation_id": correlation_id,
            },
            # 同步写入独立 anomaly_score 列，供 SQL 层直接过滤（见 get_unreviewed_anomalies）
            anomaly_score=anomaly_score,
            analyzed=False,
        )
        if hasattr(SecurityEvent, "correlation_id"):
            evt_kwargs["correlation_id"] = correlation_id or None
        if hasattr(SecurityEvent, "parent_event_id"):
            evt_kwargs["parent_event_id"] = parent_event_id or None
        if hasattr(SecurityEvent, "trace_id"):
            evt_kwargs["trace_id"] = trace_id or None
        evt = SecurityEvent(**evt_kwargs)
        session.add(evt)
        try:
            await session.commit()
        except IntegrityError:
            # 并发/重放下唯一索引冲突 → 回滚并返回已存在记录
            await session.rollback()
            logger.warning(
                f"[Idempotent] eventId={event_id} 唯一约束冲突, 返回已存在记录"
            )
            if event_id:
                existing = await self.get_by_upstream_id(session, event_id)
                if existing is not None:
                    existing.idempotent = True
                    return existing
            raise
        await session.refresh(evt)
        # real-time approx counters (Redis; no-op when unavailable); genuine inserts only
        try:
            from stats_counter import inc_insert
        except Exception:
            pass
        else:
            try:
                await inc_insert()
            except Exception:
                pass

        stored = StoredEvent(
            id=evt.id,
            session_id=session_id,
            event_type=event_type,
            severity=severity,
            src_ip=event_data.get("src_ip", ""),
            dst_ip=event_data.get("dst_ip", ""),
            message=event_data.get("message", ""),
            raw_data=event_data,
            anomaly_score=anomaly_score,
            correlation_id=correlation_id,
            created_at=evt.created_at.isoformat(),
            event_id=event_id or "",
            parent_event_id=parent_event_id,
            trace_id=trace_id,
        )

        # 缓存到 hot cache (LRU)
        self._cache_put(evt.id, asdict(stored))

        logger.info(
            "Stored event #%s event_id=%s: %s/%s anomaly=%.3f correlation=%s",
            evt.id, event_id or "-", event_type, severity, anomaly_score,
            correlation_id or "none",
        )

        return stored

    async def store_batch(
        self,
        session: AsyncSession,
        rows: list[tuple[dict, str, float, str]],
    ) -> list[StoredEvent]:
        """批量落库 (P1 事件驱动流水线 persist 阶段) — 一批一次 commit。

        rows: list of (event_data, session_id, anomaly_score, correlation_id)
        幂等性与 store() 一致: 已存在的 eventId 复用旧行不重复插入。

        行为:
          - 一次 SELECT(event_id IN ...) 找已存在行, 只 insert 新行, 一次 commit;
          - IntegrityError(并发/批内重复 eventId) → rollback 后逐条回退 self.store(),
            不丢已成功行 (store() 幂等, 重复 eventId 自然收敛到一行);
          - 返回与 rows 等长同序的 StoredEvent 列表;
          - inc_insert 只按真实 insert 条数计数; 每条结果写热缓存。

        store() 本身保持逐条 commit 语义不变(既有单测依赖)。
        """
        if not rows:
            return []

        parsed = []          # 每行预处理信息, 与 rows 平行
        eids = []
        for event_data, session_id, anomaly_score, correlation_id in rows:
            event_data, eid, corr, parent, tid = _identity_for_store(
                event_data, correlation_id
            )
            if eid:
                eids.append(eid)
            parsed.append({
                "event_data": event_data,
                "session_id": session_id,
                "anomaly_score": anomaly_score,
                "correlation_id": corr,
                "event_id": eid,
                "parent_event_id": parent,
                "trace_id": tid,
                "event_type": event_data.get("event", event_data.get("type", "UNKNOWN")),
                "severity": event_data.get("severity", "info"),
            })

        # 幂等检查: 一次查出本批已存在的 eventId → 旧行复用
        existing_by_eid: dict[str, SecurityEvent] = {}
        if eids:
            result = await session.execute(
                select(SecurityEvent).where(SecurityEvent.event_id.in_(eids))
            )
            for evt in result.scalars().all():
                if evt.event_id is not None:
                    existing_by_eid[str(evt.event_id)] = evt

        new_evts = []
        new_idx = []
        for i, p in enumerate(parsed):
            if p["event_id"] is not None and p["event_id"] in existing_by_eid:
                continue  # 已存在 → 复用旧行, 不重复插入
            evt_kwargs = dict(
                event_id=p["event_id"],
                session_id=p["session_id"],
                event_type=p["event_type"],
                severity=p["severity"],
                src_ip=p["event_data"].get("src_ip", ""),
                dst_ip=p["event_data"].get("dst_ip", ""),
                protocol=p["event_data"].get("protocol", ""),
                action=p["event_data"].get("action", ""),
                message=p["event_data"].get("message", ""),
                raw_data={
                    **p["event_data"],
                    "_anomaly_score": p["anomaly_score"],
                    "_correlation_id": p["correlation_id"],
                },
                # 同步独立 anomaly_score 列 (与 store() 字段映射一致)
                anomaly_score=p["anomaly_score"],
                analyzed=False,
            )
            if hasattr(SecurityEvent, "correlation_id"):
                evt_kwargs["correlation_id"] = p["correlation_id"] or None
            if hasattr(SecurityEvent, "parent_event_id"):
                evt_kwargs["parent_event_id"] = p["parent_event_id"] or None
            if hasattr(SecurityEvent, "trace_id"):
                evt_kwargs["trace_id"] = p["trace_id"] or None
            evt = SecurityEvent(**evt_kwargs)
            session.add(evt)
            new_evts.append(evt)
            new_idx.append(i)

        if new_evts:
            try:
                await session.commit()  # ← 单事务, 一批一次 commit
            except IntegrityError:
                # 并发/批内重复 eventId → 回滚整批, 逐条回退 store() (幂等兜底)
                await session.rollback()
                logger.warning(
                    f"[Idempotent] store_batch unique-constraint conflict "
                    f"({len(rows)} rows) — falling back to per-item store()"
                )
                out = []
                for event_data, session_id, anomaly_score, correlation_id in rows:
                    out.append(await self.store(
                        session, event_data, session_id,
                        anomaly_score=anomaly_score,
                        correlation_id=correlation_id,
                    ))
                return out
            # 与 store() 一致: commit 后 refresh 填充 server/python 默认值
            for evt in new_evts:
                await session.refresh(evt)
            # 真实 insert 条数才计数 (计数器语义与 store() 一致)
            await self._maybe_inc_insert(len(new_evts))

        results: list[StoredEvent] = []
        for i, p in enumerate(parsed):
            if i in new_idx:
                evt = new_evts[new_idx.index(i)]
                stored = StoredEvent(
                    id=evt.id,
                    session_id=evt.session_id,
                    event_type=evt.event_type,
                    severity=evt.severity,
                    src_ip=evt.src_ip or "",
                    dst_ip=evt.dst_ip or "",
                    message=evt.message or "",
                    raw_data=p["event_data"],
                    anomaly_score=p["anomaly_score"],
                    correlation_id=p["correlation_id"],
                    created_at=evt.created_at.isoformat() if evt.created_at else "",
                    analyzed=bool(evt.analyzed),
                    idempotent=False,
                    event_id=p["event_id"] or "",
                    parent_event_id=p["parent_event_id"],
                    trace_id=p["trace_id"],
                )
                self._cache_put(evt.id, asdict(stored))
            else:
                db_evt = existing_by_eid[p["event_id"]]
                if new_evts:
                    # commit 后旧查询对象属性过期(async session) → 重建前 refresh
                    await session.refresh(db_evt)
                stored = self._to_stored(db_evt)
                stored.idempotent = True
                # 复用旧行时不把 SELECT 时的快照写回热缓存，避免覆盖更新后的代次。
            results.append(stored)

        logger.info(
            f"Stored batch {len(rows)} events "
            f"(inserted={len(new_evts)}, idempotent={len(rows) - len(new_evts)}, "
            f"commit=1)"
        )
        return results

    async def _maybe_inc_insert(self, n: int) -> None:
        """real-time approx counter (Redis; no-op when unavailable) — 真实 insert 计数。"""
        if n <= 0:
            return
        try:
            from stats_counter import inc_insert
        except Exception:
            return
        for _ in range(n):
            try:
                await inc_insert()
            except Exception:
                pass

    async def get_by_upstream_id(
        self,
        session: AsyncSession,
        event_id: str,
    ) -> Optional[StoredEvent]:
        """按上游 eventId 查询已落库事件 (幂等检查)"""
        stmt = select(SecurityEvent).where(SecurityEvent.event_id == event_id)
        result = await session.execute(stmt)
        evt = result.scalars().first()
        if not evt:
            return None
        raw = evt.raw_data or {}
        return StoredEvent(
            id=evt.id,
            session_id=evt.session_id,
            event_type=evt.event_type,
            severity=evt.severity,
            src_ip=evt.src_ip or "",
            dst_ip=evt.dst_ip or "",
            message=evt.message or "",
            raw_data=raw,
            anomaly_score=evt.anomaly_score or 0.0,
            correlation_id=raw.get("_correlation_id", ""),
            created_at=evt.created_at.isoformat() if evt.created_at else "",
        )

    async def query(
        self,
        session: AsyncSession,
        filters: EventFilter,
    ) -> list[StoredEvent]:
        """
        查询安全事件 — 保留原始数据的溯源查询

        支持按 session_id/IP/事件类型/严重度/异常分数 筛选
        """
        conditions = []

        if filters.session_id:
            conditions.append(SecurityEvent.session_id == filters.session_id)
        if filters.src_ip:
            conditions.append(SecurityEvent.src_ip == filters.src_ip)
        if filters.dst_ip:
            conditions.append(SecurityEvent.dst_ip == filters.dst_ip)
        if filters.event_type:
            conditions.append(SecurityEvent.event_type == filters.event_type)
        if filters.severity:
            conditions.append(SecurityEvent.severity == filters.severity)
        if filters.time_start:
            conditions.append(SecurityEvent.created_at >= filters.time_start)
        if filters.time_end:
            conditions.append(SecurityEvent.created_at <= filters.time_end)

        stmt = select(SecurityEvent)
        if conditions:
            stmt = stmt.where(and_(*conditions))
        stmt = stmt.order_by(desc(SecurityEvent.created_at))
        stmt = stmt.limit(filters.limit).offset(filters.offset)

        result = await session.execute(stmt)
        rows = result.scalars().all()

        events = []
        for evt in rows:
            raw = evt.raw_data or {}
            # anomaly_score 优先读取独立列（迁移后路径），回退到 raw_data（向后兼容）
            anomaly_score = (
                evt.anomaly_score if evt.anomaly_score is not None
                else raw.get("_anomaly_score", 0.0)
            )
            events.append(StoredEvent(
                id=evt.id,
                session_id=evt.session_id,
                event_type=evt.event_type,
                severity=evt.severity,
                src_ip=evt.src_ip or "",
                dst_ip=evt.dst_ip or "",
                message=evt.message or "",
                raw_data=raw,
                anomaly_score=anomaly_score,
                correlation_id=raw.get("_correlation_id", ""),
                created_at=evt.created_at.isoformat(),
            ))

        logger.info(f"EventStore query: {len(events)} results "
                    f"(session={filters.session_id}, "
                    f"src_ip={filters.src_ip})")
        return events

    def _to_stored(self, evt: SecurityEvent) -> StoredEvent:
        from event_identity import resolve
        raw = evt.raw_data or {}
        ident = resolve(raw)
        anomaly_score = (
            evt.anomaly_score if evt.anomaly_score is not None
            else raw.get("_anomaly_score", 0.0)
        )
        return StoredEvent(
            id=evt.id,
            session_id=evt.session_id,
            event_type=evt.event_type,
            severity=evt.severity,
            src_ip=evt.src_ip or "",
            dst_ip=evt.dst_ip or "",
            message=evt.message or "",
            raw_data=raw,
            anomaly_score=anomaly_score,
            correlation_id=(
                getattr(evt, "correlation_id", None)
                or ident.correlation_id
                or raw.get("_correlation_id", "")
                or ""
            ),
            created_at=evt.created_at.isoformat() if evt.created_at else "",
            analyzed=bool(evt.analyzed),
            event_id=getattr(evt, "event_id", None) or ident.event_id or "",
            parent_event_id=(
                getattr(evt, "parent_event_id", None)
                or ident.parent_event_id
                or ""
            ),
            trace_id=getattr(evt, "trace_id", None) or ident.trace_id or "",
        )

    async def get_by_id(
        self,
        session: AsyncSession,
        event_id: int,
        *,
        prefer_db: bool = False,
    ) -> Optional[StoredEvent]:
        """按 ID 获取单条完整事件。

        Temporal worker 与 FastAPI 分进程: ingest 时写入的热缓存不含后续
        `_audit_llm` 写回。若缓存标记 analyzed=False(或强制 prefer_db),
        必须回源 DB,否则 /audit-llm/pipeline 会永远返回空报告。
        """
        cached = self._hot_cache.get(event_id)
        if cached is None and not prefer_db:
            self._cache_metric("miss")
        if cached is not None and not prefer_db:
            entry = self._unpack_entry(event_id, cached)
            if entry is not None and self._entry_expired(entry):
                self._drop_local(event_id)
                self._cache_metric("expired")
            elif (
                entry is not None
                and entry.gen == self.current_generation(event_id)
                and entry.data.get("analyzed")
                and (entry.data.get("raw_data") or {}).get("_audit_llm")
            ):
                self._hot_cache.move_to_end(event_id)
                self._cache_metric("hit")
                return self._stored_from_cache(entry.data)
            else:
                self._cache_metric("miss")
            # 未分析、代次不匹配、或 TTL 到期 → 回源 DB

        gen_at_read = self.current_generation(event_id)
        evt = await session.get(SecurityEvent, event_id)
        if not evt:
            return None

        stored = self._to_stored(evt)
        # 回填热缓存；若读期间已被失效，代次检查会拒绝把旧快照写回
        try:
            if not self._cache_put(event_id, asdict(stored), expected_gen=gen_at_read):
                self._cache_metric("stale")
        except Exception:
            pass
        return stored

    async def get_unreviewed_anomalies(
        self,
        session: AsyncSession,
        session_id: str,
        min_score: float = 0.5,
        limit: int = 50,
    ) -> list[StoredEvent]:
        """获取未审核的异常事件（供 Agent-D 使用）

        改造后：anomaly_score 下沉为 SecurityEvent 独立列 + 索引，
        min_score 过滤直接在 SQL 完成，避免低分事件挤占 limit 名额导致漏报。
        历史 SQL fallback：若部署未执行迁移（anomaly_score 列缺失），
        回退到 Python 层过滤模式保证向后兼容。
        """
        # 优先走 SQL 层（anomaly_score 列存在时）
        try:
            stmt = (
                select(SecurityEvent)
                .where(
                    SecurityEvent.session_id == session_id,
                    SecurityEvent.analyzed == False,
                    SecurityEvent.anomaly_score >= min_score,
                )
                .order_by(desc(SecurityEvent.created_at))
                .limit(limit)
            )
            result = await session.execute(stmt)
            rows = result.scalars().all()

            events = []
            for evt in rows:
                raw = evt.raw_data or {}
                events.append(StoredEvent(
                    id=evt.id,
                    session_id=evt.session_id,
                    event_type=evt.event_type,
                    severity=evt.severity,
                    src_ip=evt.src_ip or "",
                    dst_ip=evt.dst_ip or "",
                    message=evt.message or "",
                    raw_data=raw,
                    anomaly_score=evt.anomaly_score,
                    correlation_id=raw.get("_correlation_id", ""),
                    created_at=evt.created_at.isoformat() if evt.created_at else "",
                ))
            return events
        except Exception as e:
            # 兼容回退：列不存在或 SQL 失败时回到旧 Python 层过滤模式
            logger.warning(
                f"SQL anomaly_score filter failed ({e}), "
                f"falling back to Python-layer filter (likely missing column)"
            )
            stmt = (
                select(SecurityEvent)
                .where(
                    SecurityEvent.session_id == session_id,
                    SecurityEvent.analyzed == False,
                )
                .order_by(desc(SecurityEvent.created_at))
                .limit(limit)
            )
            result = await session.execute(stmt)
            rows = result.scalars().all()

            events = []
            for evt in rows:
                raw = evt.raw_data or {}
                score = raw.get("_anomaly_score", 0.0)
                if score < min_score:
                    continue
                events.append(StoredEvent(
                    id=evt.id,
                    session_id=evt.session_id,
                    event_type=evt.event_type,
                    severity=evt.severity,
                    src_ip=evt.src_ip or "",
                    dst_ip=evt.dst_ip or "",
                    message=evt.message or "",
                    raw_data=raw,
                    anomaly_score=score,
                    correlation_id=raw.get("_correlation_id", ""),
                    created_at=evt.created_at.isoformat() if evt.created_at else "",
                ))
            return events

    async def get_stats(
        self,
        session: AsyncSession,
        session_id: str,
    ) -> dict:
        """获取存储统计"""
        from sqlalchemy import func

        total = await session.execute(
            select(func.count(SecurityEvent.id)).where(
                SecurityEvent.session_id == session_id
            )
        )
        analyzed = await session.execute(
            select(func.count(SecurityEvent.id)).where(
                SecurityEvent.session_id == session_id,
                SecurityEvent.analyzed == True,
            )
        )
        by_severity = await session.execute(
            select(
                SecurityEvent.severity,
                func.count(SecurityEvent.id)
            ).where(
                SecurityEvent.session_id == session_id
            ).group_by(SecurityEvent.severity)
        )

        total_n = total.scalar() or 0
        analyzed_n = analyzed.scalar() or 0
        return {
            "total_events": total_n,
            "analyzed": analyzed_n,
            "pending": total_n - analyzed_n,
            "by_severity": dict(by_severity.all()),
        }


event_store = EventStore()
