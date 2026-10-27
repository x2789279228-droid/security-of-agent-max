"""
实时事件总线 — SSE 的低延迟提醒，不是安全事件的交付通道。

安全事件以 security_events.id 为准。总线只负责尽快通知已连接的客户端。
Redis Pub/Sub 是 at-most-once：订阅者离线时消息不会重投，断线后的遗漏从数据库补查。

两类队列：
  critical  高危告警和必须审计的通知。队列满时不踢掉已入队事件；
            带 SecurityEvent.id 的通知记入补查缺口，客户端用游标回放。
  bulk      界面状态。同一键只保留最新一条；队列满时丢最旧，并记丢弃指标。

SSE 的 id 行只在业务游标向前移动时写出（SecurityEvent.id）。
界面状态不写 id 行，避免浏览器把 epoch.seq 当成 Last-Event-ID。
"""
import asyncio
import itertools
import json
import logging
import os
import time
import uuid
from collections import OrderedDict, deque
from dataclasses import dataclass, field, replace
from typing import Optional

logger = logging.getLogger(__name__)

# 进程纪元：只标识本次进程，不作为业务游标。业务游标是 SecurityEvent.id。
BOOT_TS = time.time()
REDIS_CHANNEL = "soc:event_bus"

_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info"})
_CRITICAL_TYPES = frozenset({
    "security_event",
    "alert",
    "audit_complete",
    "response_action",
    "tool_anomaly",
    "audit_degraded",
    "edr_correlation",
    "data_security_llm_verdict",
    "phishing_llm_verdict",
})
# pipeline_health 的告警藏在 payload.type，不能按事件名当成心跳丢掉。
_PIPELINE_CRITICAL_SUBTYPES = frozenset({"sla_breach", "alert"})
_HYDRATE_TYPES = frozenset({"audit_complete", "response_action", "audit_degraded"})


def positive_event_id(data: dict | None) -> int | None:
    """载荷里的 SecurityEvent.id。0、布尔、UUID 都不是游标。"""
    if not isinstance(data, dict):
        return None
    from event_identity import stored_id_of
    number = stored_id_of(data)
    return number if number > 0 else None


def severity_of(event_type: str, data: dict | None) -> str:
    """与前端 severityOf 对齐。显式 severity 优先；sla_breach 缺省为 high，不再落成 medium。"""
    payload = data if isinstance(data, dict) else {}
    named = str(payload.get("severity") or "").lower()
    if named in _SEVERITIES:
        return named
    subtype = str(payload.get("type") or "").lower()
    if event_type == "pipeline_health" and subtype in _PIPELINE_CRITICAL_SUBTYPES:
        return "high"
    if event_type == "alert" or event_type == "tool_anomaly":
        return "high"
    if event_type == "pipeline_health":
        return "medium"
    if event_type == "agent_stage" and str(payload.get("status") or "") in ("error", "timeout"):
        return "high"
    return "info"


def lane_of(event_type: str, data: dict | None) -> str:
    """critical 不能当心跳丢掉；其余走可合并的 bulk。"""
    payload = data if isinstance(data, dict) else {}
    if event_type == "pipeline_health":
        subtype = str(payload.get("type") or "").lower()
        if subtype in _PIPELINE_CRITICAL_SUBTYPES:
            return "critical"
        return "bulk"
    if event_type in _CRITICAL_TYPES:
        return "critical"
    return "bulk"


def classify_event(event_type: str, data: dict | None) -> tuple[str, str, str, int | None]:
    """返回 (lane, severity, cursor_kind, event_id)。

    只有 critical 且带有 SecurityEvent.id 的事件使用 event_id 游标。
    agent_stage 等状态事件即使载荷里有 event_id，也不推进业务游标。
    """
    severity = severity_of(event_type, data)
    lane = lane_of(event_type, data)
    eid = positive_event_id(data)
    if lane == "critical" and eid is not None:
        return lane, severity, "event_id", eid
    return lane, severity, "epoch_seq", None


def coalesce_key(event_type: str, data: dict | None, lane: str) -> tuple | None:
    """界面状态的合并键。相同键只保留最新一条。"""
    if lane != "bulk":
        return None
    payload = data if isinstance(data, dict) else {}
    if event_type == "agent_stage":
        return ("agent_stage", payload.get("event_id"), payload.get("stage"), payload.get("phase"))
    if event_type == "agent_thought":
        return ("agent_thought", payload.get("event_id"))
    if event_type == "ledger":
        # 账本快照: 只留最新一帧, 慢消费者积压时不放大过期账目
        return ("ledger",)
    if event_type == "attack_geo":
        # 攻击态势快照: 同上, 只留最新一帧
        return ("attack_geo",)
    if event_type == "pipeline_health":
        return (
            "pipeline_health",
            payload.get("type"),
            payload.get("stage") or payload.get("name") or "",
        )
    return None


@dataclass
class BusEvent:
    seq: int = 0
    type: str = ""
    data: dict = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    lane: str = "bulk"
    severity: str = "info"
    cursor_kind: str = "epoch_seq"
    event_id: int | None = None

    def to_sse(self, *, sse_id: str | None = None) -> dict:
        payload = {
            **self.data,
            "_seq": self.seq,
            "_ts": self.timestamp,
            "_lane": self.lane,
            "_severity": self.severity,
            "_cursor_kind": self.cursor_kind,
        }
        if self.cursor_kind == "event_id" and self.event_id is not None:
            payload["_event_id"] = self.event_id
        else:
            payload["_ephemeral_id"] = f"{int(BOOT_TS)}.{self.seq}"
        frame = {
            "event": self.type,
            "data": json.dumps(payload, ensure_ascii=False, default=str),
        }
        if sse_id:
            frame["id"] = str(sse_id)
        return frame


def dedup_key(evt: BusEvent) -> str:
    if evt.cursor_kind == "event_id" and evt.event_id is not None:
        return f"e:{evt.type}:{evt.event_id}"
    return f"p:{int(BOOT_TS)}.{evt.seq}"


def render_sse(evt: BusEvent, high_water: int) -> tuple[dict, int]:
    """id 行只在业务游标不倒退时写出。更小的 event_id 和界面状态都不写 id。"""
    sse_id = None
    if (
        evt.cursor_kind == "event_id"
        and evt.event_id is not None
        and evt.event_id >= high_water
    ):
        sse_id = str(evt.event_id)
        high_water = evt.event_id
    return evt.to_sse(sse_id=sse_id), high_water


def should_skip_live(evt: BusEvent, resume_from: int, sent_keys: set[str]) -> bool:
    """补查与实时重叠时按类型+事件 ID 丢掉实时副本。

    已补查过的 security_event 不再从队列投一次。
    audit_complete 等后续通知使用不同的键，不会被 security_event 误伤。
    游标及之前的 security_event 认为客户端已经有行，刷新帧负责更新状态。
    """
    if dedup_key(evt) in sent_keys:
        return True
    if (
        evt.type == "security_event"
        and evt.cursor_kind == "event_id"
        and evt.event_id is not None
        and resume_from > 0
        and evt.event_id <= resume_from
    ):
        return True
    return False


class Subscriber:
    """一个 SSE 客户端。critical 与 bulk 分开，get() 总是先取 critical。"""

    def __init__(self, critical_max: int, bulk_max: int):
        self.critical_max = max(1, int(critical_max))
        self.bulk_max = max(1, int(bulk_max))
        self.critical: deque[BusEvent] = deque()
        self.bulk: deque[BusEvent] = deque()
        self.missed_critical = 0
        self.critical_lost = 0
        self.gap_ids: deque[int] = deque(maxlen=32)
        self._wake = asyncio.Event()

    def qsize(self) -> int:
        return len(self.critical) + len(self.bulk)

    def _signal(self) -> None:
        self._wake.set()

    def _pop(self) -> BusEvent | None:
        if self.critical:
            return self.critical.popleft()
        if self.bulk:
            return self.bulk.popleft()
        return None

    def get_nowait(self) -> BusEvent:
        item = self._pop()
        if item is None:
            raise asyncio.QueueEmpty
        return item

    async def get(self) -> BusEvent:
        while True:
            item = self._pop()
            if item is not None:
                return item
            self._wake.clear()
            item = self._pop()
            if item is not None:
                return item
            await self._wake.wait()

    def _note_gap(self, evt: BusEvent) -> None:
        self.missed_critical += 1
        if evt.event_id is not None:
            if evt.event_id not in self.gap_ids:
                self.gap_ids.append(evt.event_id)

    def _evict_replayable(self) -> BusEvent | None:
        for index, queued in enumerate(self.critical):
            if queued.cursor_kind == "event_id" and queued.event_id is not None:
                del self.critical[index]
                return queued
        return None

    def offer(self, evt: BusEvent) -> tuple[str, BusEvent | None]:
        """放入对应队列。返回 (queued|coalesced|gap|dropped, 被丢弃的事件)。"""
        if evt.lane == "critical":
            return self._offer_critical(evt)
        return self._offer_bulk(evt)

    def _offer_critical(self, evt: BusEvent) -> tuple[str, BusEvent | None]:
        if len(self.critical) < self.critical_max:
            self.critical.append(evt)
            self._signal()
            return "queued", None
        # 已入队的 critical 不踢。能按事件 ID 补查的，记缺口即可。
        if evt.cursor_kind == "event_id" and evt.event_id is not None:
            self._note_gap(evt)
            return "gap", None
        evicted = self._evict_replayable()
        if evicted is not None:
            self._note_gap(evicted)
            EventBus._metric_gap(evicted)
            self.critical.append(evt)
            self._signal()
            return "queued", None
        self.critical_lost += 1
        return "dropped", evt

    def _offer_bulk(self, evt: BusEvent) -> tuple[str, BusEvent | None]:
        key = coalesce_key(evt.type, evt.data, evt.lane)
        if key is not None:
            for index, queued in enumerate(self.bulk):
                if coalesce_key(queued.type, queued.data, queued.lane) == key:
                    self.bulk[index] = evt
                    self._signal()
                    return "coalesced", None
        if len(self.bulk) >= self.bulk_max:
            dropped = self.bulk.popleft()
            self.bulk.append(evt)
            self._signal()
            return "dropped", dropped
        self.bulk.append(evt)
        self._signal()
        return "queued", None


class EventBus:
    def __init__(self, max_subscribers: int = 0):
        from config import settings
        self._subscribers: list[Subscriber] = []
        self._max = int(max_subscribers or getattr(settings, "event_bus_max_subscribers", 256) or 256)
        # 诊断环形缓冲。业务事件的恢复不依赖它。
        self._history: list[BusEvent] = []
        self._history_max = 500
        self._seq = itertools.count(1)
        self._redis = None
        self._bridge_task: Optional[asyncio.Task] = None
        self._bridge_stop = False
        self._bridge_retry_initial = 1.0
        self._origin_id = uuid.uuid4().hex[:12]
        bulk = (
            os.environ.get("EVENT_BUS_BULK_QUEUE_MAX")
            or os.environ.get("EVENT_BUS_QUEUE_MAX")
            or getattr(settings, "event_bus_queue_max", 500)
            or 500
        )
        critical = (
            os.environ.get("EVENT_BUS_CRITICAL_QUEUE_MAX")
            or getattr(settings, "event_bus_critical_queue_max", 200)
            or 200
        )
        self._queue_max = max(1, int(bulk))
        self._critical_queue_max = max(1, int(critical))
        self._redis_seen: "OrderedDict[str, float]" = OrderedDict()
        self._redis_seen_max = 4096
        self._redis_seen_ttl = 60.0

    def _redis_recently_seen(self, key: str) -> bool:
        now = time.time()
        ts = self._redis_seen.get(key)
        if ts is not None and now - ts < self._redis_seen_ttl:
            self._redis_seen.move_to_end(key)
            return True
        self._redis_seen[key] = now
        self._redis_seen.move_to_end(key)
        while len(self._redis_seen) > self._redis_seen_max:
            self._redis_seen.popitem(last=False)
        return False

    def set_redis(self, redis_client) -> None:
        """接入 Redis。Pub/Sub 只做跨进程提醒，不保证送达。"""
        self._redis = redis_client
        logger.info("EventBus: Redis bridge enabled (channel=%s)", REDIS_CHANNEL)

    def publish(self, event_type: str, data: dict, *, _from_redis: bool = False):
        if not isinstance(data, dict):
            data = {"raw": data}
        lane, severity, cursor_kind, eid = classify_event(event_type, data)
        evt = BusEvent(
            seq=next(self._seq),
            type=event_type,
            data=data,
            lane=lane,
            severity=severity,
            cursor_kind=cursor_kind,
            event_id=eid,
        )
        self._history.append(evt)
        if len(self._history) > self._history_max:
            self._history = self._history[-self._history_max:]

        for sub in list(self._subscribers):
            try:
                outcome, victim = sub.offer(evt)
            except Exception:
                logger.exception("EventBus offer failed type=%s", event_type)
                continue
            if outcome == "gap":
                self._metric_gap(evt)
            elif outcome == "dropped":
                dropped = victim or evt
                self._metric_drop(dropped)
                try:
                    from core_metrics import log_process, note_eventbus_drop
                    note_eventbus_drop(dropped.lane)
                    log_process(
                        logger,
                        event_id=str(dropped.event_id or ""),
                        stage="push", result="dropped",
                        reason="queue_full",
                    )
                except Exception:
                    pass

        try:
            from core_metrics import set_eventbus_queue_depth
            crit, bulk = self.queue_depth_by_lane()
            set_eventbus_queue_depth(crit, bulk)
        except Exception:
            pass

        if not _from_redis and self._redis is not None:
            self._broadcast_redis(event_type, data)

    @staticmethod
    def _metric_gap(evt: BusEvent) -> None:
        try:
            from metrics import inc_eventbus_gap
            inc_eventbus_gap(1, evt.type, evt.severity)
        except Exception:
            pass

    @staticmethod
    def _metric_drop(evt: BusEvent) -> None:
        try:
            from metrics import inc_eventbus_drop
            inc_eventbus_drop(1, evt.type, evt.severity, evt.lane)
        except Exception:
            pass

    def _broadcast_redis(self, event_type: str, data: dict) -> None:
        try:
            payload = json.dumps(
                {
                    "origin": self._origin_id,
                    "type": event_type,
                    "event_id": (data or {}).get("event_id"),
                    "data": data,
                    "ts": time.time(),
                },
                ensure_ascii=False,
                default=str,
            )
            result = self._redis.publish(REDIS_CHANNEL, payload)
            if not asyncio.iscoroutine(result):
                return
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                result.close()
                return
            task = loop.create_task(result)
            task.add_done_callback(self._on_broadcast_done)
        except Exception as e:
            logger.warning("EventBus redis broadcast failed: %s", e)
            self._metric_redis("broadcast")

    @staticmethod
    def _on_broadcast_done(task: asyncio.Task) -> None:
        try:
            task.result()
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.warning("EventBus redis broadcast failed: %s", e)
            EventBus._metric_redis("broadcast")

    @staticmethod
    def _metric_redis(op: str) -> None:
        try:
            from metrics import inc_eventbus_redis_failure
            inc_eventbus_redis_failure(op)
        except Exception:
            pass

    async def start_redis_bridge(self) -> None:
        """订阅 Redis。监听协程自己重连，不依赖再次调用本方法。"""
        if self._redis is None:
            return
        task = self._bridge_task
        if task is not None and not task.done():
            return
        self._bridge_stop = False
        self._bridge_task = asyncio.create_task(self._listen_forever(), name="event-bus-redis")
        logger.info("EventBus: redis bridge listener started")

    async def stop_redis_bridge(self) -> None:
        self._bridge_stop = True
        task = self._bridge_task
        self._bridge_task = None
        if task is not None and not task.done():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

    async def _listen_forever(self) -> None:
        delay = self._bridge_retry_initial
        while self._redis is not None and not self._bridge_stop:
            pubsub = None
            try:
                pubsub = self._redis.pubsub()
                await pubsub.subscribe(REDIS_CHANNEL)
                delay = self._bridge_retry_initial
                async for msg in pubsub.listen():
                    if self._bridge_stop:
                        break
                    self._handle_redis_message(msg)
            except asyncio.CancelledError:
                raise
            except Exception as e:
                logger.warning("EventBus redis bridge interrupted: %s", e)
                self._metric_redis("listen")
            finally:
                await self._close_pubsub(pubsub)
            if self._bridge_stop or self._redis is None:
                break
            await asyncio.sleep(delay)
            delay = min(delay * 2, 30.0)

    @staticmethod
    async def _close_pubsub(pubsub) -> None:
        if pubsub is None:
            return
        close = getattr(pubsub, "aclose", None) or getattr(pubsub, "close", None)
        if close is None:
            return
        try:
            result = close()
            if asyncio.iscoroutine(result):
                await result
        except Exception:
            pass

    def _handle_redis_message(self, msg) -> None:
        if not msg or msg.get("type") != "message":
            return
        raw = msg.get("data")
        try:
            if isinstance(raw, (bytes, bytearray)):
                raw = raw.decode()
            envelope = json.loads(raw)
        except Exception:
            return
        if envelope.get("origin") == self._origin_id:
            return
        event_type = envelope.get("type") or ""
        data = envelope.get("data") or {}
        if not isinstance(data, dict):
            data = {"raw": data}
        eid = envelope.get("event_id")
        if eid is None:
            eid = data.get("event_id")
        dedup = f"{envelope.get('origin')}|{event_type}|{eid}"
        if eid is not None and self._redis_recently_seen(dedup):
            return
        # 通知正文不可作为唯一副本。带 event_id 的审计/响应在 SSE 侧回源数据库。
        if event_type in _HYDRATE_TYPES:
            data = {**data, "_notice": True}
        self.publish(event_type, data, _from_redis=True)

    def subscribe(self) -> Optional[Subscriber]:
        """注册订阅者。满员时返回 None，不踢掉已有连接。"""
        if len(self._subscribers) >= self._max:
            logger.warning(
                "EventBus: subscriber slots full (%d), rejecting new subscription",
                self._max,
            )
            return None
        sub = Subscriber(self._critical_queue_max, self._queue_max)
        self._subscribers.append(sub)
        return sub

    def unsubscribe(self, sub: Subscriber):
        if sub in self._subscribers:
            self._subscribers.remove(sub)
            try:
                from core_metrics import inc_eventbus_disconnect
                inc_eventbus_disconnect()
            except Exception:
                pass

    def queue_depth_by_lane(self) -> tuple[int, int]:
        crit = 0
        bulk = 0
        for sub in self._subscribers:
            crit += len(sub.critical)
            bulk += len(sub.bulk)
        return crit, bulk

    def recent(self, limit: int = 50, since_seq: int = 0) -> list[dict]:
        """内存诊断窗口，按进程内 seq 过滤。断线补查不走这里。"""
        evts = [e for e in self._history if e.seq > since_seq]
        out = []
        for evt in evts[-limit:]:
            sse_id = None
            if evt.cursor_kind == "event_id" and evt.event_id is not None:
                sse_id = str(evt.event_id)
            item = evt.to_sse(sse_id=sse_id)
            item["seq"] = evt.seq
            item["ts"] = evt.timestamp
            out.append(item)
        return out

    @property
    def subscriber_count(self) -> int:
        return len(self._subscribers)

    @property
    def max_subscribers(self) -> int:
        return self._max

    @property
    def last_seq(self) -> int:
        return self._history[-1].seq if self._history else 0

    @property
    def oldest_seq(self) -> int:
        return self._history[0].seq if self._history else 0


async def hydrate_notice(evt: BusEvent) -> BusEvent:
    """审计/响应通知以数据库当前行为准。查不到时仍发出提醒，并标明来源是通知。"""
    if evt.type not in _HYDRATE_TYPES or evt.event_id is None:
        return evt
    try:
        from event_replay import fetch_event_snapshot
        snap = await asyncio.wait_for(
            fetch_event_snapshot(evt.event_id, include_response=evt.type == "response_action"),
            timeout=2.0,
        )
    except Exception as exc:
        logger.debug("event notice hydrate failed id=%s: %s", evt.event_id, exc)
        snap = None
    data = {**evt.data, "_notice": True, "_source": "db" if snap else "notice"}
    if snap:
        data["persisted"] = snap
    return replace(evt, data=data)


event_bus = EventBus()
