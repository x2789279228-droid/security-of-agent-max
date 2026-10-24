"""
Kafka 消费者 — 从 Flink 处理后的 topic 消费事件

替代原来的 HTTP 直连接入模式：
  - 消费 security-audit-queue → 送入 Audit-LLM 流水线
  - 消费 security-alerts → 触发响应引擎
  - 消费 security-events-enriched → 全量存储 + 记忆树索引

数据流:
  Kafka(security-audit-queue) → LogIngestor.ingest() → Audit-LLM
  Kafka(security-alerts)      → ResponseOrchestrator.on_threat_detected()
  Kafka(security-behavior-alerts) → ResponseOrchestrator (BEHAVIOR_ANOMALY / L4)
  Kafka(security-events-enriched) → EventStore.store() + MemoryTree

可靠性保障:
  ① 手动 Offset 提交 — 只提交每个分区上连续完成的水位。业务成功，或永久
     失败已经确认写入 DLQ，才算完成。临时失败、DLQ 写入失败都不提交。
     关闭时同样只提交已经连续完成的水位；取消或还在处理的记录留在 broker。
  ② 最终幂等 — PG security_events.event_id 唯一索引兜底 (event_store.store 已实现,
     替换原 Redis 24h 去重; 跨重放同一条事件只落库一次)
  ③ 死信队列 (DLQ) — 无法解析、契约非法或无法确认字段安全性的消息，
     先把失败状态写入数据库（原始负载只存密文），再等 broker 确认写入
     security-logs-dlq。两步都成功才允许提交原 offset。
  ④ 背压控制 — max_poll_records + 审计信号量，防止下游过载
  ⑤ 消费 Lag 监控 — 实时计算各分区 lag，暴露到 /api/kafka/status
  ⑥ trace_id 传播 — 从 Kafka headers 提取 trace_id，贯穿全链路

架构定位 (Flink 唯一流处理事实源):
  本模块是"薄消费者" — 只做 传输/存储/LLM审计/响应编排,
  不再重复实现校验/去重/异常评分 (这些由 Flink 作业负责)。
"""
import asyncio
import json
import logging
import os
import time
from typing import Optional

from config import settings
from kafka_security import aiokafka_security_kwargs
from dlq_store import mark_kafka_acked, persist_dlq_failure, sanitize_error
from field_cipher import field_cipher
from metrics import inc_kafka_consumed
from retry_policy import (
    KIND_PERMANENT,
    STATUS_DLQ,
    STATUS_FAILED,
    STATUS_SUCCESS,
    EventOutcome,
    allows_key_overtake,
    backoff_delay,
    budget_exhausted,
    clamp_delay_to_budget,
    classify_exception,
)
from event_identity import (
    apply_headers,
    get_event_id,
    identity_headers,
    resolve,
)
from schema_registry import schema_registry

logger = logging.getLogger(__name__)

try:
    from aiokafka import AIOKafkaConsumer, AIOKafkaProducer, TopicPartition
    HAS_KAFKA = True
except ImportError:
    HAS_KAFKA = False
    logger.warning("aiokafka not installed — Kafka consumer disabled")

# ── 常量 ──
DLQ_TOPIC = "security-logs-dlq"
# 测试会 monkeypatch 这个全局。运行时默认跟 settings.kafka_retry_max_attempts。
MAX_RETRY = max(1, int(getattr(settings, "kafka_retry_max_attempts", 5) or 5))


def _env_int(name: str, fallback: int) -> int:
    """旧的无前缀环境变量优先于 settings，避免改掉已经在跑的覆盖。"""
    raw = os.environ.get(name)
    if raw is None or str(raw).strip() == "":
        return int(fallback)
    try:
        return int(raw)
    except ValueError:
        return int(fallback)


# 仅限制 Kafka audit-queue 的 store 并发(store 完成后立即释放,不限 LLM)。
AUDIT_SEMAPHORE_LIMIT = max(1, _env_int(
    "KAFKA_AUDIT_STORE_CONCURRENCY",
    int(getattr(settings, "kafka_audit_store_concurrency", 12) or 12),
))
MAX_POLL_RECORDS = max(1, _env_int(
    "KAFKA_MAX_POLL_RECORDS",
    int(getattr(settings, "kafka_max_poll_records", 50) or 50),))
# 单次 poll 后的处理上限。默认 10 分钟，覆盖慢审计；过短会被踢出组。
MAX_POLL_INTERVAL_MS = max(60_000, _env_int(
    "KAFKA_MAX_POLL_INTERVAL_MS",
    int(getattr(settings, "kafka_max_poll_interval_ms", 600_000) or 600_000),
))
# 1 = 同一分区按 offset 顺序处理，遇到不可提交的消息就停住该分区后续记录。
# >1 时同一批按这个宽度分窗完成。无论完成顺序如何，都只提交连续水位。
# 测试会改这个模块全局；运行时以它为准。
CONSUME_CONCURRENCY = max(1, _env_int(
    "KAFKA_CONSUME_CONCURRENCY",
    int(getattr(settings, "kafka_consume_concurrency", 1) or 1),
))
RETAIN_BACKOFF_STEP = 1.0
RETAIN_BACKOFF_MAX = 30.0


def _allow_blocking_for(alert: dict) -> tuple:
    """由告警**声明的动作**判定是否允许阻断 → ``(allow_blocking, action)``。

    ## 为什么需要这个函数

    Sigma 单事件阶段已把执行类动作降级成 ``alert`` —— 规则自己声明了
    ``x-soc-aggregation``（count > N in T），单条事件证据不足，不允许处置。
    于是「窗口超阈值后该怎么处置」的决定权转移到聚合告警这条链路上。

    修复前 :meth:`_handle_alert` 这里硬编码 ``allow_blocking=True``：
    无论规则声明了什么动作，只要 ``severity`` 是 high 就允许封禁。
    规则作者的意图在聚合边界上被完全忽略。

    ## 三条口径

    1. **显式声明了动作** → 以动作为准。``block_ip`` 允许阻断，
       ``alert`` / ``require_confirmation`` 不允许。
    2. **没声明动作**（CEP、行为基线等其它告警源）→ 保持既有行为 ``True``。
       本次改动不应顺带改变其它链路的处置。
    3. **判不出来**（``ENFORCEMENT_ACTIONS`` 导入失败）→ ``False``，
       fail-safe：无法确认规则声明了执行类动作时，宁可少封也不要误封。

    ⚠️ 这里必须区分「字段缺失」与「字段为空/非执行类」——
    ``alert.get("action_recommend") or ""`` 会把两者都变成空串，
    于是口径 1 和口径 2 就合并了，一条声明 ``action: ""`` 的规则会被
    当成「没声明」而放行阻断。用 ``in`` 判存在、用 ``strip()`` 判内容。
    """
    if "action_recommend" not in alert:
        return True, ""
    action = str(alert.get("action_recommend") or "").strip()
    if not action:
        # 显式声明为空 —— 不是「没声明」，不允许阻断
        return False, ""
    try:
        from sigma_engine.engine import ENFORCEMENT_ACTIONS
    except Exception:
        ENFORCEMENT_ACTIONS = frozenset()
        logger.warning(
            "[Kafka-Alert] ENFORCEMENT_ACTIONS unavailable, "
            "treating action=%s as non-blocking", action)
    return (action in ENFORCEMENT_ACTIONS), action


def _tp_key(tp) -> tuple:
    """TopicPartition 或 (topic, partition) → 稳定键。"""
    topic = getattr(tp, "topic", None)
    partition = getattr(tp, "partition", None)
    if topic is None:
        topic, partition = tp[0], tp[1]
    return (topic, int(partition))


def _business_key(event: Optional[dict]) -> str:
    if not isinstance(event, dict):
        return ""
    eid = get_event_id(event)
    if eid:
        return eid[:256]
    body = event.get("body") if isinstance(event.get("body"), dict) else {}
    for key in ("sourceId", "srcIp", "src_ip", "session_id"):
        val = event.get(key)
        if val in (None, "") and body:
            val = body.get(key)
        if val not in (None, ""):
            return str(val)[:256]
    return ""


def _outcome_from_run_result(rr, event=None) -> EventOutcome:
    ps = str(getattr(rr, "process_status", STATUS_SUCCESS) or STATUS_SUCCESS)
    stored_id = int(getattr(rr, "event_id", 0) or 0)
    event_id = (
        str(getattr(rr, "eventId", "") or "")
        or get_event_id(event)
        or (str(stored_id) if stored_id else "")
    )
    error = str(getattr(rr, "error", "") or "")
    error_class = str(getattr(rr, "error_class", "") or "")
    error_code = str(getattr(rr, "error_code", "") or "")
    idempotent = bool(getattr(rr, "idempotent", False))
    if ps == STATUS_SUCCESS:
        return EventOutcome.success(
            event_id=event_id, stored_id=stored_id, idempotent=idempotent,
        )
    if ps == STATUS_DLQ:
        return EventOutcome.dlq(
            error=error, error_class=error_class, error_code=error_code or "permanent_failure",
            event_id=event_id,
        )
    if ps == STATUS_FAILED:
        return EventOutcome.failed(
            error=error, error_class=error_class, error_code=error_code or "permanent_failure",
            event_id=event_id,
        )
    return EventOutcome.retrying(
        error=error, error_class=error_class, error_code=error_code or "transient",
        event_id=event_id,
    )


def _decode_kafka_value(raw) -> tuple[Optional[dict], Optional[str]]:
    """把 Kafka value 解成 dict。失败原因是永久错误，调用方负责 DLQ。"""
    if isinstance(raw, dict):
        return raw, None
    if raw is None:
        return None, "empty kafka payload"
    if isinstance(raw, bytes):
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            return None, f"payload is not utf-8: {exc}"
    elif isinstance(raw, str):
        text = raw
    else:
        return None, f"unsupported payload type: {type(raw).__name__}"
    try:
        event = json.loads(text)
    except json.JSONDecodeError as exc:
        # 空文本单独说清楚：解出来是 "" 再交给 json.loads 会得到
        # 「Expecting value: line 1 column 1 (char 0)」，
        # 排障时看不出「这条消息本来就是空的」。
        if not text.strip():
            return None, "empty kafka payload"
        return None, f"payload is not json: {exc}"
    except RecursionError:
        # 深度嵌套的 JSON 在 CPython 的 C 扫描器里直接爆栈，抛的是
        # RecursionError 而**不是** JSONDecodeError。不单独接住它，
        # 这条消息会一路穿出 _ack_record：_settle_fetch 外面没有
        # except Exception（只有 CancelledError），最终被消费循环顶层的
        # "consumer crashed" 接住 —— 整个 topic 的消费就此退出。
        # 一条畸形消息不该有能力停掉一条链路。
        return None, "payload JSON nesting is too deep to parse"
    except ValueError as exc:
        # Python 3.11+ 对超长整数字面量抛的是**裸** ValueError
        # （int 转换上限 4300 位），同样不是 JSONDecodeError。
        # 它必须排在 JSONDecodeError 之后：JSONDecodeError 是 ValueError
        # 的子类，反过来写会被它先吃掉，错误信息就丢了。
        return None, f"payload JSON value is out of range: {exc}"
    if not isinstance(event, dict):
        return None, "payload JSON is not an object"
    return event, None


class OffsetCommitTracker:
    """按 TopicPartition 记录处理结果，只暴露连续可提交水位。

    Kafka 提交的 offset 是下一条要读的位置，不是“程序读到了哪里”。
    同一分区里 100、102 已成功而 101 还在处理或失败时，水位停在 101，
    不能提交 103，否则重启后 101 会被跳过。

    调用顺序：先 observe 本批要处理的全部 offset，再 resolve。
    resolve(committable=True) 表示业务成功，或永久失败已经确认进入 DLQ。
    """

    def __init__(self):
        self._next: dict[tuple, int] = {}
        self._safe: dict[tuple, int] = {}
        self._committed: dict[tuple, int] = {}
        self._done: dict[tuple, set[int]] = {}
        self._blocked: dict[tuple, set[int]] = {}
        self._inflight: dict[tuple, set[int]] = {}
        self._tp_obj: dict[tuple, object] = {}
        self.retain_streak = 0

    def observe(self, tp, offset: int) -> None:
        """登记一条已取出、尚未完成的记录。"""
        key = _tp_key(tp)
        self._tp_obj[key] = tp
        safe = self._safe.get(key)
        if safe is not None and offset < safe:
            return
        committed = self._committed.get(key)
        if committed is not None and offset < committed:
            return
        self._inflight.setdefault(key, set()).add(offset)
        nxt = self._next.get(key)
        if nxt is None or offset < nxt:
            self._next[key] = offset

    def resolve(self, tp, offset: int, committable: bool) -> None:
        """记录一条消息的最终结果。committable 为 False 时形成空洞。"""
        key = _tp_key(tp)
        self._tp_obj[key] = tp
        self._inflight.setdefault(key, set()).discard(offset)
        safe = self._safe.get(key)
        if safe is not None and offset < safe:
            return
        if key not in self._next:
            self._next[key] = offset
        done = self._done.setdefault(key, set())
        blocked = self._blocked.setdefault(key, set())
        if committable:
            blocked.discard(offset)
            done.add(offset)
        else:
            done.discard(offset)
            blocked.add(offset)
        self._advance(key)

    def _advance(self, key: tuple) -> None:
        nxt = self._next.get(key)
        if nxt is None:
            return
        done = self._done.setdefault(key, set())
        blocked = self._blocked.setdefault(key, set())
        inflight = self._inflight.setdefault(key, set())
        moved = False
        while nxt not in blocked and nxt not in inflight and nxt in done:
            done.discard(nxt)
            nxt += 1
            moved = True
        self._next[key] = nxt
        if moved:
            prev = self._safe.get(key)
            if prev is None or nxt > prev:
                self._safe[key] = nxt

    def next_offset(self, tp) -> Optional[int]:
        """该分区下一条还不能跳过的 offset。"""
        return self._next.get(_tp_key(tp))

    def uncommitted(self) -> dict:
        """返回已经连续完成、但还没向 broker 确认的 {tp: next_offset}。"""
        out = {}
        for key, safe in self._safe.items():
            committed = self._committed.get(key)
            if committed is None or safe > committed:
                out[self._tp_obj[key]] = safe
        return out

    def mark_committed(self, offsets: dict) -> None:
        for tp, off in offsets.items():
            key = _tp_key(tp)
            prev = self._committed.get(key)
            if prev is None or off > prev:
                self._committed[key] = off


class KafkaConsumerManager:
    """
    Kafka 消费者管理器

    启动多个后台消费任务，分别消费不同 topic。
    所有消费到的事件最终汇入现有的 LogIngestor / ResponseOrchestrator。

    可靠性特性:
    - 手动 offset 提交（连续水位：业务成功或 DLQ 确认写入后才 commit）
    - 最终幂等（PG event_id 唯一索引, 替代 Redis 去重）
    - 死信队列（无法解析 / 契约非法 / 字段安全性无法确认 → 密文索引 + security-logs-dlq，两步都确认后才提交）
    - 背压控制（max_poll_records + 审计信号量）
    - 消费 lag 实时监控
    """

    def __init__(self):
        self._tasks: list[asyncio.Task] = []
        self._running = False
        self._draining = False
        self._dlq_producer = None
        self._audit_semaphore = asyncio.Semaphore(AUDIT_SEMAPHORE_LIMIT)
        self._rejection_log: list[dict] = []  # 最近 200 条拒绝记录
        self._rejection_by_type: dict[str, int] = {}  # 按类型聚合
        self._cep_partial: list[dict] = []  # 最近 100 条 CEP 部分匹配
        self._otel_tracer = self._make_tracer()
        self._stats = {
            "enriched_consumed": 0,
            "audit_consumed": 0,
            "alerts_consumed": 0,
            "python_ingest_consumed": 0,
            "audit_overflow_consumed": 0,
            "behavior_alerts_consumed": 0,
            "rejected_consumed": 0,
            "errors": 0,
            "idempotent_skipped": 0,
            "dlq_sent": 0,
            "dlq_failed": 0,
            "offsets_retained": 0,
            "offset_commits": 0,
            "commit_failed": 0,
            "retry_consumed": 0,
            "last_message_at": 0,
            "lag": {},
            "oldest_lag_seconds": {},
        }
        self._live_consumers: dict[str, object] = {}
        # P1: poll 批内原地退避的累计 sleep。串行批 50 条 × 每条 60s 预算
        # 远超 max_poll_interval_ms → 消费者被踢出组 → rebalance → 重放,
        # 下游持续降级时形成踢组循环。批开始时清零, 超过批预算即停止原地重试。
        self._batch_sleep_s: float = 0.0
        self._oldest_record_ts: dict[str, float] = {}
        self._restart_initial_s = float(
            getattr(settings, "kafka_consumer_restart_initial_s", 1.0) or 1.0
        )
        self._restart_max_s = float(
            getattr(settings, "kafka_consumer_restart_max_s", 30.0) or 30.0
        )

    def _make_tracer(self):
        """返回 OTel tracer; OTel 不可用时返回空 tracer (start_as_current_span 空转)"""
        try:
            from opentelemetry import trace as otel_trace
            return otel_trace.get_tracer("soc-backend-kafka", "2.0.0")
        except ImportError:
            class _NullTracer:
                @staticmethod
                def start_as_current_span(name, context=None, attributes=None):
                    from contextlib import nullcontext
                    return nullcontext()
            return _NullTracer()

    async def _supervised_loop(self, name: str, factory):
        """工厂协程在 _running 时退出就指数退避拉起。stop()/drain 后不再拉起。"""
        delay = max(0.0, float(self._restart_initial_s or 0.0))
        max_delay = max(delay, float(self._restart_max_s or delay or 30.0))
        while self._running:
            try:
                from core_metrics import note_kafka_loop_restart, set_kafka_loop_alive
            except Exception:
                set_kafka_loop_alive = None
                note_kafka_loop_restart = None
            if set_kafka_loop_alive:
                set_kafka_loop_alive(name, True)
            try:
                await factory()
            except asyncio.CancelledError:
                if set_kafka_loop_alive:
                    set_kafka_loop_alive(name, False)
                raise
            except Exception as e:
                logger.error("[Kafka] %s crashed: %s", name, e)
            if set_kafka_loop_alive:
                set_kafka_loop_alive(name, False)
            if not self._running:
                break
            logger.warning(
                "[Kafka] %s exited while running; restart in %.1fs", name, delay,
            )
            if note_kafka_loop_restart:
                note_kafka_loop_restart(name)
            try:
                await asyncio.sleep(delay)
            except asyncio.CancelledError:
                if set_kafka_loop_alive:
                    set_kafka_loop_alive(name, False)
                raise
            delay = min(delay * 2.0 if delay > 0 else 0.01, max_delay)

    async def start(self):
        """启动所有消费者"""
        if not HAS_KAFKA or not settings.kafka_enabled:
            logger.info("Kafka consumer: disabled (kafka_enabled=False or aiokafka missing)")
            return

        # 初始化 DLQ 生产者
        await self._init_dlq_producer()

        self._running = True
        loops = [
            ("enriched", self._consume_enriched),
            ("audit", self._consume_audit_queue),
            ("alerts", self._consume_alerts),
            ("behavior", self._consume_behavior_alerts),
            ("rejected", self._consume_rejected),
            ("cep", self._consume_cep_partial),
            ("lag", self._lag_monitor),
            ("overflow", self._consume_audit_overflow),
        ]
        if settings.python_process_ingest_queue and settings.kafka_enabled:
            loops.append(("ingestpy", self._consume_python_ingest))
        if (
            bool(getattr(settings, "kafka_retry_topic_enabled", False))
            and allows_key_overtake(getattr(settings, "kafka_retry_ordering", "strict"))
        ):
            loops.append(("retry", self._consume_retry))
        self._tasks = [
            asyncio.create_task(
                self._supervised_loop(name, factory), name=f"kafka-{name}",
            )
            for name, factory in loops
        ]
        logger.info(
            f"Kafka consumer started: {settings.kafka_bootstrap}, "
            f"topics=[{settings.kafka_topic_enriched}, "
            f"{settings.kafka_topic_audit_queue}, "
            f"{settings.kafka_topic_alerts}], "
            f"DLQ={DLQ_TOPIC}, backpressure={AUDIT_SEMAPHORE_LIMIT}"
        )

    async def begin_drain(self) -> None:
        """停止拉取新消息。不取消正在处理的这一批，也不在这里提交位点。"""
        self._draining = True
        self._running = False

    async def stop(self):
        """等当前批次结束，超时后再取消。只确认已经完成的位点。"""
        self._draining = True
        self._running = False
        timeout = float(getattr(settings, "shutdown_drain_timeout_s", 20) or 20)
        leftover = 0
        if self._tasks:
            _done, pending = await asyncio.wait(self._tasks, timeout=max(0.0, timeout))
            leftover = len(pending)
            for task in pending:
                task.cancel()
            await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()
        if leftover:
            try:
                from core_metrics import record_shutdown_leftover
                record_shutdown_leftover("kafka_consumer", leftover=leftover)
            except Exception:
                pass
        if self._dlq_producer:
            try:
                await self._dlq_producer.stop()
            except Exception as exc:
                logger.warning(f"[Kafka] DLQ producer stop failed: {exc}")
            self._dlq_producer = None
        logger.info("Kafka consumer stopped")

    # ── 初始化 ──

    async def _init_dlq_producer(self):
        """初始化 DLQ 生产者"""
        try:
            from kafka_security import aiokafka_security_kwargs
            self._dlq_producer = AIOKafkaProducer(
                bootstrap_servers=settings.kafka_bootstrap,
                value_serializer=lambda v: json.dumps(v, ensure_ascii=False).encode("utf-8"),
                key_serializer=lambda k: k.encode("utf-8") if k else None,
                acks="all",
                **aiokafka_security_kwargs(),
            )
            await self._dlq_producer.start()
            logger.info(f"[Kafka] DLQ producer started → {DLQ_TOPIC}")
        except Exception as e:
            logger.warning(f"[Kafka] DLQ producer failed to start: {e}")
            self._dlq_producer = None

    # ── 死信队列 ──

    async def _send_to_dlq(
        self,
        topic: str,
        msg_value: dict,
        error: str,
        retry_count: int,
        partition: Optional[int] = None,
        offset: Optional[int] = None,
        *,
        consumer_group: str = "",
        message_timestamp_ms=None,
        error_class: str = "",
        error_code: str = "",
        raw_bytes: Optional[bytes] = None,
        trace_id: str = "",
        headers=None,
    ) -> bool:
        """先落库再等 DLQ acks=all。只有返回 True 才允许提交原 offset。"""
        if not isinstance(msg_value, dict):
            msg_value = {"eventId": ""}
        if headers:
            msg_value = apply_headers(msg_value, headers)
        ident = resolve(msg_value, headers)
        if ident.event_id and not msg_value.get("eventId"):
            msg_value = dict(msg_value)
            msg_value["eventId"] = ident.event_id
        outcome = await persist_dlq_failure(
            topic=topic,
            payload=msg_value,
            error=error,
            retry_count=retry_count,
            partition=partition,
            offset=offset,
            consumer_group=consumer_group,
            message_timestamp_ms=message_timestamp_ms,
            error_class=error_class,
            error_code=error_code,
            trace_id=trace_id or ident.trace_id or str(msg_value.get("_trace_id") or ""),
            raw_bytes=raw_bytes,
            headers=headers,
        )
        if not outcome.persisted or not outcome.envelope:
            self._stats["dlq_failed"] += 1
            logger.error(
                "[Kafka-DLQ] failure state not durable; offset retained "
                "topic=%s partition=%s offset=%s reason=%s",
                topic, partition, offset, outcome.reason,
            )
            return False
        if not self._dlq_producer:
            self._stats["dlq_failed"] += 1
            logger.error(
                "[Kafka-DLQ] Producer unavailable; offset retained "
                "topic=%s partition=%s offset=%s",
                topic, partition, offset,
            )
            return False
        try:
            await self._dlq_producer.send_and_wait(
                DLQ_TOPIC,
                key=outcome.event_id,
                value=outcome.envelope,
                headers=identity_headers(
                    {"eventId": outcome.event_id, "traceId": trace_id or ident.trace_id},
                    trace_id=trace_id or ident.trace_id,
                ),
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self._stats["dlq_failed"] += 1
            logger.error(
                "[Kafka-DLQ] broker did not ack DLQ record; offset retained "
                "topic=%s partition=%s offset=%s error=%s",
                topic, partition, offset, type(exc).__name__,
            )
            return False
        await mark_kafka_acked(outcome.record_id)
        self._stats["dlq_sent"] += 1
        logger.warning(
            "[Kafka-DLQ] stored topic=%s partition=%s offset=%s event_id=%s code=%s",
            topic, partition, offset, outcome.event_id, outcome.envelope.get("error_code", ""),
        )
        try:
            from core_metrics import inc_pipeline_result, log_process
            log_process(
                logger,
                event_id=outcome.event_id,
                stage="dlq",
                result="dlq",
                reason=outcome.envelope.get("error_code", "") or error_code,
                retry_count=retry_count,
                topic=topic,
            )
            inc_pipeline_result("dlq", "dlq")
        except Exception:
            pass
        return True

    async def _send_to_retry_topic(
        self,
        topic: str,
        event: dict,
        error: str,
        retry_count: int,
        partition: Optional[int] = None,
        offset: Optional[int] = None,
        *,
        hops: int = 1,
        business_key: str = "",
        error_class: str = "",
        error_code: str = "",
        trace_id: str = "",
    ) -> bool:
        """unordered 模式才调用。成功后原 offset 可提交；同一业务键后续消息可以越过它。"""
        if not self._dlq_producer:
            return False
        delay_s = max(0.0, float(getattr(settings, "kafka_retry_topic_delay_s", 15) or 15))
        retry_at_ms = int((time.time() + delay_s) * 1000)
        payload = event if isinstance(event, dict) else {"eventId": ""}
        ident = resolve(payload)
        envelope = {
            "original_topic": topic,
            "original_partition": partition,
            "original_offset": offset,
            "retry_count": int(retry_count or 0),
            "retry_hops": int(hops or 1),
            "retry_at_ms": retry_at_ms,
            "business_key": business_key or _business_key(event) or ident.event_id,
            "ordering": "unordered",
            "error": sanitize_error(error, 300),
            "error_class": error_class,
            "error_code": error_code or "transient",
            "trace_id": trace_id or ident.trace_id,
            "event_id": ident.event_id,
            "eventId": ident.event_id,
            "correlation_id": ident.correlation_id,
            "parent_event_id": ident.parent_event_id,
            "payload": payload,
        }
        dst = str(getattr(settings, "kafka_topic_retry", "security-logs-retry") or "security-logs-retry")
        try:
            await self._dlq_producer.send_and_wait(
                dst,
                key=envelope["business_key"] or ident.event_id or str(offset or ""),
                value=envelope,
                headers=identity_headers(payload, trace_id=trace_id or ident.trace_id),
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.error(
                "[Kafka-Retry] retry topic ack failed topic=%s offset=%s err=%s",
                topic, offset, type(exc).__name__,
            )
            return False
        logger.warning(
            "[Kafka-Retry] deferred topic=%s offset=%s hops=%s retry_at_ms=%s key=%s",
            topic, offset, hops, retry_at_ms, envelope["business_key"],
        )
        try:
            from core_metrics import log_process, record_retry
            record_retry(error_code or "transient")
            log_process(
                logger, event_id=ident.event_id, stage="retry", result="retrying",
                reason=error_code or "transient", retry_count=hops,
            )
        except Exception:
            pass
        return True

    def _handler_for_topic(self, topic: str):
        mapping = {
            settings.kafka_topic_enriched: (self._handle_enriched, "enriched_consumed", "enriched"),
            settings.kafka_topic_audit_queue: (
                self._handle_audit_with_backpressure, "audit_consumed", "audit",
            ),
            settings.kafka_topic_alerts: (self._handle_alert, "alerts_consumed", "alerts"),
            settings.kafka_topic_behavior_alerts: (
                self._handle_behavior_alert, "behavior_alerts_consumed", "behavior-alerts",
            ),
            settings.kafka_topic_rejected: (self._handle_rejected, "rejected_consumed", "rejected"),
            settings.kafka_topic_audit_overflow: (
                self._handle_audit_overflow, "audit_overflow_consumed", "audit-overflow",
            ),
            settings.kafka_topic_ingest_process: (
                self._handle_python_ingest, "python_ingest_consumed", "ingestpy",
            ),
        }
        return mapping.get(topic)

    # ── trace 头提取 ──

    @staticmethod
    def _extract_trace_carrier(msg) -> dict:
        """从 Kafka message headers 提取 W3C traceparent / 旧 trace_id"""
        from event_identity import parse_kafka_headers, HEADER_TRACE_ID, HEADER_TRACEPARENT
        parsed = parse_kafka_headers(getattr(msg, "headers", None))
        carrier: dict = {}
        if parsed.get(HEADER_TRACEPARENT):
            carrier["traceparent"] = parsed[HEADER_TRACEPARENT]
        if parsed.get(HEADER_TRACE_ID):
            carrier["trace_id"] = parsed[HEADER_TRACE_ID]
        return carrier

    # ── 消费 Lag 监控 ──

    def _note_fetch_timestamps(self, topic: str, fetched) -> None:
        """用本批最早的 Kafka 记录时间戳作为积压年龄下界。"""
        stamps = []
        for msgs in (fetched or {}).values():
            for msg in msgs:
                ts = getattr(msg, "timestamp", None)
                if ts and int(ts) > 0:
                    stamps.append(int(ts) / 1000.0)
        if stamps:
            self._oldest_record_ts[topic] = min(stamps)

    async def _refresh_lag_metrics(self) -> None:
        """用真实消费者的 highwater-position，不再另开 probe 组。"""
        from core_metrics import refresh_dlq_gauges_from_db, set_kafka_lag

        lag_info = {}
        oldest_info = {}
        now = time.time()
        for topic_name, consumer in list(self._live_consumers.items()):
            try:
                assignment = consumer.assignment()
                if not assignment:
                    continue
                end_offsets = await consumer.end_offsets(list(assignment))
                total_lag = 0
                for tp in assignment:
                    pos = await consumer.position(tp)
                    end = end_offsets.get(tp, pos) or 0
                    total_lag += max(0, int(end) - int(pos or 0))
                oldest_age = 0.0
                if total_lag > 0:
                    ts = self._oldest_record_ts.get(topic_name)
                    if ts:
                        oldest_age = max(0.0, now - float(ts))
                lag_info[topic_name] = total_lag
                oldest_info[topic_name] = oldest_age
                set_kafka_lag(topic_name, total_lag, oldest_age)
            except Exception:
                lag_info[topic_name] = -1
        self._stats["lag"] = lag_info
        self._stats["oldest_lag_seconds"] = oldest_info
        total = sum(v for v in lag_info.values() if v > 0)
        if total > 100:
            logger.warning(f"[Kafka-Lag] High consumer lag: {lag_info}")
        try:
            await refresh_dlq_gauges_from_db()
        except Exception:
            pass

    async def _lag_monitor(self):
        """定期计算各 topic 的消费 lag 与最老积压年龄。"""
        while self._running:
            try:
                await asyncio.sleep(15)
                await self._refresh_lag_metrics()
            except asyncio.CancelledError:
                raise
            except Exception as e:
                logger.debug(f"[Kafka-Lag] Monitor error: {e}")

    # ── 通用消费循环 ──

    def _retain_backoff(self, tracker: OffsetCommitTracker) -> float:
        """同一消费循环反复保留 offset 时拉长间隔，避免打满 poll。"""
        tracker.retain_streak += 1
        return backoff_delay(
            tracker.retain_streak,
            initial=float(getattr(settings, "kafka_retry_initial_s", RETAIN_BACKOFF_STEP) or RETAIN_BACKOFF_STEP),
            multiplier=float(getattr(settings, "kafka_retry_multiplier", 2.0) or 2.0),
            max_delay=float(getattr(settings, "kafka_retry_max_delay_s", RETAIN_BACKOFF_MAX) or RETAIN_BACKOFF_MAX),
            jitter=float(getattr(settings, "kafka_retry_jitter", 0.2) or 0.0),
        )

    async def _commit_completed(self, consumer, tracker: OffsetCommitTracker) -> None:
        """只提交 tracker 上已经连续完成的水位。不使用无参 commit()。"""
        pending = tracker.uncommitted()
        if not pending:
            return
        try:
            await consumer.commit(dict(pending))
        except asyncio.CancelledError:
            raise
        except Exception as e:
            self._stats["commit_failed"] += 1
            logger.error(f"[Kafka] offset commit failed; offsets stay uncommitted: {e}")
        else:
            tracker.mark_committed(pending)
            self._stats["offset_commits"] += 1

    async def _sync_consumer_offsets(self, consumer, fetched, tracker: OffsetCommitTracker) -> None:
        """提交连续水位；有空洞则把该分区 seek 回第一条未完成记录。

        不用无参 commit()。无参 commit 提交的是消费者当前位置，也就是本批
        最后一条的下一位，会把中间没完成的 offset 一起确认掉。
        停止拉取之后仍然提交已完成水位，但不再 seek，也不再拉下一批。
        """
        await self._commit_completed(consumer, tracker)
        if not self._running:
            return

        behind = []
        for tp, msgs in fetched.items():
            if not msgs:
                continue
            nxt = tracker.next_offset(tp)
            if nxt is None:
                continue
            end = max(m.offset for m in msgs) + 1
            if nxt < end:
                behind.append((tp, nxt))
        if not behind:
            tracker.retain_streak = 0
            return

        delay = self._retain_backoff(tracker)
        tps = [tp for tp, _ in behind]
        if delay > 0:
            try:
                consumer.pause(*tps)
            except Exception as e:
                logger.debug(f"[Kafka] pause failed: {e}")
            try:
                await asyncio.sleep(delay)
            finally:
                if self._running:
                    try:
                        consumer.resume(*tps)
                    except Exception as e:
                        logger.debug(f"[Kafka] resume failed: {e}")
        if not self._running:
            return
        for tp, nxt in behind:
            try:
                # getmany 已经把本地位置推到本批末尾，必须 seek 回去，
                # 否则下一次 poll 不会再读到空洞里的消息。
                consumer.seek(tp, nxt)
            except Exception as e:
                logger.error(f"[Kafka] seek {tp} to {nxt} failed: {e}")

    async def _ack_record(self, msg, topic: str, handler, stat_key: str, group_suffix: str) -> bool:
        """处理一条消息。返回 True 才表示这个 offset 可以参与连续提交。"""
        if not self._running:
            return False

        event, decode_error = _decode_kafka_value(msg.value)
        carrier = self._extract_trace_carrier(msg)
        msg_headers = getattr(msg, "headers", None)
        if event is not None:
            event = apply_headers(event, msg_headers)
        if event is not None and not carrier.get("traceparent"):
            payload_tp = event.get("_traceparent", "")
            if not payload_tp:
                rawd = event.get("rawData")
                payload_tp = rawd.get("_traceparent", "") if isinstance(rawd, dict) else ""
            if payload_tp:
                carrier["traceparent"] = payload_tp
        ident = resolve(event, msg_headers)
        trace_id = ""
        if event is not None:
            trace_id = carrier.get("trace_id", "") or event.get("traceId", "") or ident.trace_id
        else:
            trace_id = carrier.get("trace_id", "") or ident.trace_id

        if decode_error is not None:
            try:
                from core_metrics import log_process, record_ingest
                record_ingest("kafka", "validation_failed", reason="decode")
                log_process(
                    logger, event_id=ident.event_id, stage="consume",
                    result="dlq", reason="decode_error",
                )
            except Exception:
                pass
            raw_bytes = msg.value if isinstance(msg.value, (bytes, bytearray)) else None
            stored = await self._send_to_dlq(
                topic,
                {"eventId": ident.event_id, "_trace_id": trace_id},
                decode_error,
                0,
                partition=getattr(msg, "partition", None),
                offset=getattr(msg, "offset", None),
                consumer_group=f"{settings.kafka_consumer_group}-{group_suffix}",
                message_timestamp_ms=getattr(msg, "timestamp", None),
                error_class="DecodeError",
                error_code="decode_error",
                raw_bytes=raw_bytes,
                trace_id=trace_id,
                headers=msg_headers,
            )
            if not stored:
                logger.error(
                    f"[Kafka] {topic} p{getattr(msg, 'partition', '?')} "
                    f"offset {getattr(msg, 'offset', '?')} unparsable and DLQ write failed; retained"
                )
            return stored

        from otel_setup import extract_context
        ctx = extract_context(carrier) if carrier else None
        importance = "high" if topic in (
            settings.kafka_topic_alerts, settings.kafka_topic_audit_queue
        ) else "normal"
        root = self._otel_tracer.start_as_current_span(
            f"kafka.consume.{group_suffix}",
            context=ctx,
            attributes={
                "messaging.system": "kafka",
                "messaging.destination.name": topic,
                "messaging.kafka.consumer.group": f"{settings.kafka_consumer_group}-{group_suffix}",
                "messaging.kafka.partition": getattr(msg, "partition", -1),
                "messaging.kafka.offset": getattr(msg, "offset", -1),
                "soc.importance": importance,
                "soc.event_id": get_event_id(event),
            },
        )
        try:
            with root:
                return await self._process_message(
                    msg, event, topic, trace_id, handler, stat_key,
                    f"{settings.kafka_consumer_group}-{group_suffix}",
                )
        except asyncio.CancelledError:
            raise

    async def _settle_ordered(self, fetched, topic, handler, stat_key, group_suffix, tracker):
        """分区内按 offset 顺序处理。遇到不可提交的记录就停住该分区。"""
        self._batch_sleep_s = 0.0
        for tp, msgs in fetched.items():
            for msg in sorted(msgs, key=lambda m: m.offset):
                if not self._running:
                    return
                tracker.observe(tp, msg.offset)
                try:
                    ok = await self._ack_record(msg, topic, handler, stat_key, group_suffix)
                except asyncio.CancelledError:
                    raise
                except Exception as e:
                    self._stats["errors"] += 1
                    logger.error(
                        "[Kafka] %s p%s offset %s settle error: %s",
                        topic, getattr(msg, "partition", "?"), msg.offset, sanitize_error(str(e)),
                    )
                    ok = False
                tracker.resolve(tp, msg.offset, ok)
                if not ok:
                    self._stats["offsets_retained"] += 1
                    break

    async def _settle_concurrent(self, fetched, topic, handler, stat_key, group_suffix, tracker):
        """同一批并发完成。提交仍由 tracker 按分区连续水位决定。"""
        self._batch_sleep_s = 0.0
        records = []
        for tp, msgs in fetched.items():
            ordered = sorted(msgs, key=lambda m: m.offset)
            for msg in ordered:
                tracker.observe(tp, msg.offset)
                records.append((tp, msg))
        if not records:
            return
        # 窗口宽度就是并发上限。不要先为整批各建一个任务再让它们堵在信号量上。
        width = max(1, int(CONSUME_CONCURRENCY))

        async def _one(tp, msg):
            if not self._running:
                return tp, msg.offset, False
            try:
                ok = await self._ack_record(msg, topic, handler, stat_key, group_suffix)
            except asyncio.CancelledError:
                raise
            except Exception as e:
                self._stats["errors"] += 1
                logger.error(
                    "[Kafka] %s p%s offset %s settle error: %s",
                    topic, getattr(msg, "partition", "?"), msg.offset, sanitize_error(str(e)),
                )
                ok = False
            return tp, msg.offset, ok

        for start in range(0, len(records), width):
            window = records[start:start + width]
            tasks = [asyncio.create_task(_one(tp, msg)) for tp, msg in window]
            try:
                results = await asyncio.gather(*tasks, return_exceptions=True)
            except asyncio.CancelledError:
                for task in tasks:
                    if not task.done():
                        task.cancel()
                raise
            for slot, result in zip(window, results):
                tp, msg = slot
                if isinstance(result, asyncio.CancelledError):
                    for task in tasks:
                        if not task.done():
                            task.cancel()
                    raise result
                if isinstance(result, Exception):
                    self._stats["errors"] += 1
                    tracker.resolve(tp, msg.offset, False)
                    self._stats["offsets_retained"] += 1
                    continue
                res_tp, offset, ok = result
                tracker.resolve(res_tp, offset, ok)
                if not ok:
                    self._stats["offsets_retained"] += 1

    async def _settle_fetch(self, consumer, fetched, topic, handler, stat_key, group_suffix, tracker):
        self._note_fetch_timestamps(topic, fetched)
        if CONSUME_CONCURRENCY <= 1:
            await self._settle_ordered(fetched, topic, handler, stat_key, group_suffix, tracker)
        else:
            await self._settle_concurrent(fetched, topic, handler, stat_key, group_suffix, tracker)
        await self._sync_consumer_offsets(consumer, fetched, tracker)

    async def _poll_many(self, consumer, tracker, *, timeout_ms: int, max_records: int):
        """审计队列到高水位时不拉取。已完成的位点照常提交，积压留在 broker。"""
        from capacity import fetch_pause_interval, kafka_fetch_paused
        if kafka_fetch_paused():
            if tracker is not None and tracker.uncommitted():
                await self._sync_consumer_offsets(consumer, {}, tracker)
            await asyncio.sleep(fetch_pause_interval())
            return {}
        return await consumer.getmany(timeout_ms=timeout_ms, max_records=max_records)

    async def _consume_loop(
        self,
        topic: str,
        group_suffix: str,
        handler,
        stat_key: str,
    ):
        """
        通用消费循环 — 连续水位提交 + PG 幂等 + DLQ + 背压

        解码放在循环内，而不是 value_deserializer。反序列化抛错会让
        aiokafka 丢掉这条记录或打垮整个循环，无法先确认 DLQ。

        Args:
            topic: 消费的 topic 名称
            group_suffix: 消费者组后缀
            handler: 异步处理函数 (event_dict, trace_id) → None
            stat_key: 统计计数器名称
        """
        consumer = AIOKafkaConsumer(
            topic,
            bootstrap_servers=settings.kafka_bootstrap,
            group_id=f"{settings.kafka_consumer_group}-{group_suffix}",
            auto_offset_reset="earliest",
            enable_auto_commit=False,
            max_poll_records=MAX_POLL_RECORDS,
            max_poll_interval_ms=MAX_POLL_INTERVAL_MS,
            # Flink 使用 EXACTLY_ONCE 事务；消费端必须只读已提交，
            # 否则已 abort 的事务记录仍会到达响应引擎（重复告警）。
            isolation_level="read_committed",
            **aiokafka_security_kwargs(),
        )
        tracker = OffsetCommitTracker()
        try:
            await consumer.start()
            self._live_consumers[topic] = consumer
            logger.info(
                f"Consuming {topic} (contiguous manual-commit, PG-idempotent, DLQ={DLQ_TOPIC})..."
            )
            while self._running:
                try:
                    fetched = await self._poll_many(
                        consumer, tracker, timeout_ms=1000, max_records=MAX_POLL_RECORDS,
                    )
                except asyncio.CancelledError:
                    raise
                except Exception as e:
                    logger.warning(f"[Kafka] {topic} poll error: {e}")
                    await asyncio.sleep(0.5)
                    continue
                if not self._running:
                    break
                if not fetched:
                    if tracker.uncommitted():
                        await self._sync_consumer_offsets(consumer, {}, tracker)
                    continue
                try:
                    await self._settle_fetch(
                        consumer, fetched, topic, handler, stat_key, group_suffix, tracker,
                    )
                except asyncio.CancelledError:
                    raise
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.error(f"{topic} consumer crashed: {e}")
        finally:
            if self._live_consumers.get(topic) is consumer:
                self._live_consumers.pop(topic, None)
            await self._close_consumer(consumer, tracker)

    async def _close_consumer(self, consumer, tracker: OffsetCommitTracker) -> None:
        """退出前只提交已完成水位，然后关闭。取消继续向外抛。"""
        try:
            try:
                await self._commit_completed(consumer, tracker)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.error(f"[Kafka] shutdown commit failed: {exc}")
        finally:
            try:
                await consumer.stop()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.warning(f"[Kafka] consumer stop failed: {exc}")

    async def _process_message(self, msg, event, topic, trace_id, handler, stat_key, consumer_group: str = "") -> bool:
        """确认字段安全 → Schema → 业务处理。返回值决定这条 offset 能不能提交。"""
        wire = event
        group = consumer_group or settings.kafka_consumer_group
        # ⓪ 字段安全性。解不开、密钥不可用、明文绕过或异常类型都不得继续当明文处理。
        decision = field_cipher.open_message(event)
        if not decision.ok:
            try:
                from core_metrics import log_process, record_ingest
                record_ingest("kafka", "validation_failed", reason="cipher")
                log_process(
                    logger, event_id=resolve(event, getattr(msg, "headers", None)).event_id,
                    stage="consume", result="dlq", reason=decision.code or "cipher",
                )
            except Exception:
                pass
            stored = await self._send_to_dlq(
                topic, wire, decision.detail, 0,
                partition=getattr(msg, "partition", None),
                offset=getattr(msg, "offset", None),
                consumer_group=group,
                message_timestamp_ms=getattr(msg, "timestamp", None),
                error_class="FieldCipherRejected",
                error_code=decision.code,
                trace_id=trace_id,
                headers=getattr(msg, "headers", None),
            )
            self._mark_root_error(decision.code)
            if not stored:
                logger.error(
                    "[Kafka] %s p%s offset %s cipher code=%s and DLQ write failed; retained",
                    topic, getattr(msg, "partition", "?"), getattr(msg, "offset", "?"), decision.code,
                )
            return stored
        event = apply_headers(decision.message, getattr(msg, "headers", None))

        # ① 幂等: 由 event_store.store 的 PG event_id 唯一索引兜底
        #    (同一条事件重放/双路径扇出只落库一次, 此处不再做 Redis 去重)

        # ② 跨运行时 Schema 校验。契约非法是永久错误：DLQ 确认写入后才可提交。
        schema_errors = schema_registry.validate(topic, event)
        if schema_errors:
            try:
                from core_metrics import log_process, record_ingest
                record_ingest("kafka", "validation_failed", reason="schema")
                log_process(
                    logger, event_id=resolve(event, getattr(msg, "headers", None)).event_id,
                    stage="consume", result="dlq", reason="schema_invalid",
                )
            except Exception:
                pass
            stored = await self._send_to_dlq(
                topic, wire,
                sanitize_error(f"Schema 校验失败: {'; '.join(schema_errors[:5])}"),
                MAX_RETRY,
                partition=getattr(msg, "partition", None),
                offset=getattr(msg, "offset", None),
                consumer_group=group,
                message_timestamp_ms=getattr(msg, "timestamp", None),
                error_class="SchemaError",
                error_code="schema_invalid",
                trace_id=trace_id,
                headers=getattr(msg, "headers", None),
            )
            self._mark_root_error("schema_invalid")
            if not stored:
                logger.error(
                    "[Kafka] %s p%s offset %s schema-invalid and DLQ write failed; retained",
                    topic, getattr(msg, "partition", "?"), getattr(msg, "offset", "?"),
                )
            return stored

        # ③ 注入 trace_id 到事件
        if trace_id:
            event["_trace_id"] = trace_id

        # ④ 业务处理。临时故障指数退避；永久错误进 DLQ。gather 的返回值不是成功判定。
        last_error = ""
        last_verdict = None
        slept = 0.0
        attempts_cap = max(1, int(MAX_RETRY))
        budget = max(0.0, float(getattr(settings, "kafka_retry_budget_s", 60) or 60))
        # P1: 批内原地 sleep 不得超过 max_poll_interval 的一半 — 否则串行批
        # 累计超时触发消费者被踢组/rebalance 风暴。超出即提前放弃原地重试,
        # 走 retry topic / retain-offset 路径(下游自会重试)。
        batch_headroom = max(0.0, (MAX_POLL_INTERVAL_MS / 1000.0) * 0.5 - self._batch_sleep_s)
        budget = min(budget, batch_headroom)
        hops = int(event.get("_retry_hops") or 0)
        for attempt in range(1, attempts_cap + 1):
            if not self._running:
                return False
            try:
                await handler(event, trace_id)
                self._stats[stat_key] += 1
                self._stats["last_message_at"] = time.time()
                inc_kafka_consumed(topic)
                try:
                    from core_metrics import inc_pipeline_result, log_process
                    log_process(
                        logger,
                        event_id=resolve(event, getattr(msg, "headers", None)).event_id,
                        stage="consume", result="success", reason="",
                        retry_count=max(0, attempt - 1),
                    )
                    inc_pipeline_result("consume", "success")
                except Exception:
                    pass
                return True
            except asyncio.CancelledError:
                raise
            except Exception as e:
                last_verdict = classify_exception(e)
                last_error = last_verdict.message or str(e)
                self._stats["errors"] += 1
                try:
                    from core_metrics import record_retry
                    if last_verdict.retryable and last_verdict.kind != KIND_PERMANENT:
                        record_retry(last_verdict.error_code or "transient")
                except Exception:
                    pass
                logger.error(
                    "[Kafka] %s p%s offset %s handler error (attempt %s/%s kind=%s) %s: %s",
                    topic, getattr(msg, "partition", "?"), getattr(msg, "offset", "?"),
                    attempt, attempts_cap, last_verdict.kind,
                    resolve(event, getattr(msg, "headers", None)).log_fields(),
                    sanitize_error(str(e)),
                )
                if last_verdict.kind == KIND_PERMANENT or not last_verdict.retryable:
                    stored = await self._send_to_dlq(
                        topic, wire, sanitize_error(last_error),
                        attempt,
                        partition=getattr(msg, "partition", None),
                        offset=getattr(msg, "offset", None),
                        consumer_group=group,
                        message_timestamp_ms=getattr(msg, "timestamp", None),
                        error_class=last_verdict.error_class,
                        error_code=last_verdict.error_code,
                        trace_id=trace_id,
                        headers=getattr(msg, "headers", None),
                    )
                    self._mark_root_error(last_verdict.error_code or "permanent_failure")
                    return stored
                if attempt >= attempts_cap or budget_exhausted(slept, budget):
                    break
                delay = backoff_delay(
                    attempt,
                    initial=float(getattr(settings, "kafka_retry_initial_s", 1.0) or 1.0),
                    multiplier=float(getattr(settings, "kafka_retry_multiplier", 2.0) or 2.0),
                    max_delay=float(getattr(settings, "kafka_retry_max_delay_s", 30.0) or 30.0),
                    jitter=float(getattr(settings, "kafka_retry_jitter", 0.2) or 0.0),
                )
                delay = clamp_delay_to_budget(delay, slept, budget)
                if delay > 0 and self._running:
                    await asyncio.sleep(delay)
                    slept += delay
                    self._batch_sleep_s += delay
                if budget_exhausted(slept, budget):
                    break

        if not self._running:
            return False
        self._mark_root_error(sanitize_error(last_error, 200))
        max_hops = max(1, int(getattr(settings, "kafka_retry_topic_max_hops", 5) or 5))
        unordered = allows_key_overtake(getattr(settings, "kafka_retry_ordering", "strict"))
        retry_topic_on = bool(getattr(settings, "kafka_retry_topic_enabled", False))
        if unordered and retry_topic_on:
            next_hops = hops + 1
            if next_hops >= max_hops:
                stored = await self._send_to_dlq(
                    topic, wire, sanitize_error(last_error or "retry exhausted"),
                    attempts_cap,
                    partition=getattr(msg, "partition", None),
                    offset=getattr(msg, "offset", None),
                    consumer_group=group,
                    message_timestamp_ms=getattr(msg, "timestamp", None),
                    error_class=(last_verdict.error_class if last_verdict else "RetryExhausted"),
                    error_code="retry_exhausted",
                    trace_id=trace_id,
                    headers=getattr(msg, "headers", None),
                )
                return stored
            sent = await self._send_to_retry_topic(
                topic, event, last_error, attempts_cap,
                partition=getattr(msg, "partition", None),
                offset=getattr(msg, "offset", None),
                hops=next_hops,
                business_key=_business_key(event),
                error_class=last_verdict.error_class if last_verdict else "",
                error_code=last_verdict.error_code if last_verdict else "transient",
                trace_id=trace_id,
            )
            if sent:
                # unordered：原 offset 可提交。同一业务键后续消息可以越过这条。
                return True
        logger.error(
            "[Kafka] retain offset topic=%s partition=%s offset=%s reason=transient:%s ordering=%s",
            topic, getattr(msg, "partition", "?"), getattr(msg, "offset", "?"),
            sanitize_error(last_error, 300),
            "unordered" if unordered else "strict",
        )
        return False

    def _mark_root_error(self, message: str):
        """把当前 OTel 根 span 标记为错误 (供 Tempo 排查)"""
        try:
            from opentelemetry import trace as otel_trace
            span = otel_trace.get_current_span()
            if span and span.is_recording():
                span.record_exception(Exception(message))
                span.set_status(otel_trace.Status(otel_trace.StatusCode.ERROR, message))
        except Exception:
            pass

    # ── 各 topic 消费入口 ──
    # ── Python 权威处理: HTTP 网关队列(security-events-ingest) ──
    async def _consume_python_ingest(self):
        # 整批 detect + store；offset 仍按分区连续水位提交，不使用无参 commit。
        if not settings.python_process_ingest_queue or not settings.kafka_enabled:
            logger.info("Python ingest queue consumer disabled")
            return
        poll_ms = int(os.environ.get("KAFKA_INGEST_POLL_MS", "500") or "500")
        consumer = AIOKafkaConsumer(
            settings.kafka_topic_ingest_process,
            bootstrap_servers=settings.kafka_bootstrap,
            group_id=f"{settings.kafka_consumer_group}-ingestpy",
            auto_offset_reset="earliest",
            enable_auto_commit=False,
            max_poll_records=MAX_POLL_RECORDS,
            max_poll_interval_ms=MAX_POLL_INTERVAL_MS,
            # Flink 使用 EXACTLY_ONCE 事务；消费端必须只读已提交，
            # 否则已 abort 的事务记录仍会到达响应引擎（重复告警）。
            isolation_level="read_committed",
            **aiokafka_security_kwargs(),
        )
        tracker = OffsetCommitTracker()
        topic = settings.kafka_topic_ingest_process
        try:
            await consumer.start()
            self._live_consumers[topic] = consumer
            logger.info(
                f"Consuming python-ingest {settings.kafka_topic_ingest_process} "
                f"(poll={poll_ms}ms, contiguous-commit)"
            )
            while self._running:
                try:
                    fetched = await self._poll_many(
                        consumer, tracker, timeout_ms=poll_ms, max_records=MAX_POLL_RECORDS,
                    )
                except asyncio.CancelledError:
                    raise
                except Exception as e:
                    logger.warning(f"Python-ingest poll error: {e}")
                    await asyncio.sleep(0.5)
                    continue
                if not fetched:
                    if tracker.uncommitted():
                        await self._sync_consumer_offsets(consumer, {}, tracker)
                    continue
                try:
                    await self._settle_python_ingest_fetch(consumer, fetched, tracker)
                except asyncio.CancelledError:
                    raise
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.error(f"Python-ingest consumer crashed: {e}")
        finally:
            if self._live_consumers.get(topic) is consumer:
                self._live_consumers.pop(topic, None)
            await self._close_consumer(consumer, tracker)

    async def _settle_python_ingest_fetch(self, consumer, fetched, tracker: OffsetCommitTracker):
        """永久解析失败确认写入 DLQ 后可提交；下游失败整段保留，不跳过空洞。"""
        topic = settings.kafka_topic_ingest_process
        self._note_fetch_timestamps(topic, fetched)
        parsed = []
        for tp, msgs in fetched.items():
            for msg in sorted(msgs, key=lambda m: m.offset):
                tracker.observe(tp, msg.offset)
                event, err = _decode_kafka_value(msg.value)
                group = f"{settings.kafka_consumer_group}-ingestpy"
                msg_headers = getattr(msg, "headers", None)
                if isinstance(event, dict):
                    event = apply_headers(event, msg_headers)
                if err or not isinstance(event, dict):
                    try:
                        from core_metrics import log_process, record_ingest
                        record_ingest("kafka", "validation_failed", reason="decode")
                        log_process(
                            logger, event_id=get_event_id(event or {}, msg_headers),
                            stage="consume", result="dlq", reason="decode_error",
                        )
                    except Exception:
                        pass
                    stored = await self._send_to_dlq(
                        topic,
                        event or {"eventId": get_event_id({}, msg_headers)},
                        err or "payload JSON is not an object",
                        0,
                        partition=getattr(msg, "partition", None),
                        offset=msg.offset,
                        consumer_group=group,
                        message_timestamp_ms=getattr(msg, "timestamp", None),
                        error_class="DecodeError",
                        error_code="decode_error",
                        raw_bytes=msg.value if isinstance(msg.value, (bytes, bytearray)) else None,
                        headers=msg_headers,
                    )
                    tracker.resolve(tp, msg.offset, stored)
                    if not stored:
                        self._stats["offsets_retained"] += 1
                        break
                    continue
                body = event.get("body")
                if not isinstance(body, dict):
                    stored = await self._send_to_dlq(
                        topic,
                        event,
                        "python ingest wrapper lacks dict body",
                        0,
                        partition=getattr(msg, "partition", None),
                        offset=msg.offset,
                        consumer_group=group,
                        message_timestamp_ms=getattr(msg, "timestamp", None),
                        error_class="IngestWrapper",
                        error_code="ingest_wrapper",
                        headers=msg_headers,
                    )
                    tracker.resolve(tp, msg.offset, stored)
                    if not stored:
                        self._stats["offsets_retained"] += 1
                        break
                    continue
                decision = field_cipher.open_message(event)
                if not decision.ok:
                    try:
                        from core_metrics import log_process, record_ingest
                        record_ingest("kafka", "validation_failed", reason="cipher")
                        log_process(
                            logger, event_id=get_event_id(event, msg_headers),
                            stage="consume", result="dlq",
                            reason=decision.code or "cipher",
                        )
                    except Exception:
                        pass
                    stored = await self._send_to_dlq(
                        topic,
                        event,
                        decision.detail,
                        0,
                        partition=getattr(msg, "partition", None),
                        offset=msg.offset,
                        consumer_group=group,
                        message_timestamp_ms=getattr(msg, "timestamp", None),
                        error_class="FieldCipherRejected",
                        error_code=decision.code,
                        headers=msg_headers,
                    )
                    tracker.resolve(tp, msg.offset, stored)
                    if not stored:
                        self._stats["offsets_retained"] += 1
                        break
                    continue
                session_id = str(
                    event.get("session_id") or ("http-" + str(event.get("uuid", "")))
                )
                opened = apply_headers(
                    decision.message if isinstance(decision.message, dict) else event,
                    msg_headers,
                )
                opened_body = opened.get("body") if isinstance(opened, dict) else None
                if not isinstance(opened_body, dict):
                    tracker.resolve(tp, msg.offset, False)
                    self._stats["offsets_retained"] += 1
                    break
                parsed.append((tp, msg.offset, session_id, opened_body))

        if parsed:
            if not self._running:
                for tp, offset, _sid, _body in parsed:
                    tracker.resolve(tp, offset, False)
                    self._stats["offsets_retained"] += 1
            else:
                events = [(sid, body) for _tp, _off, sid, body in parsed]
                outcomes = await self._ingest_python_batch(events)
                if len(outcomes) < len(parsed):
                    outcomes = list(outcomes) + [
                        EventOutcome.retrying(error="missing outcome")
                        for _ in range(len(parsed) - len(outcomes))
                    ]
                topic = settings.kafka_topic_ingest_process
                group = f"{settings.kafka_consumer_group}-ingestpy"
                n_retrying = 0
                for (tp, offset, _sid, body), outcome in zip(parsed, outcomes):
                    committable = False
                    if outcome.status == STATUS_SUCCESS:
                        committable = True
                    elif outcome.status in (STATUS_DLQ, STATUS_FAILED):
                        part_no = getattr(tp, "partition", None)
                        if part_no is None and isinstance(tp, tuple) and len(tp) > 1:
                            part_no = tp[1]
                        stored = await self._send_to_dlq(
                            topic,
                            body if isinstance(body, dict) else {"eventId": ""},
                            outcome.error or "permanent ingest failure",
                            max(1, int(outcome.attempts or 1)),
                            partition=part_no,
                            offset=offset,
                            consumer_group=group,
                            error_class=outcome.error_class or "IngestError",
                            error_code=outcome.error_code or "permanent_failure",
                        )
                        committable = stored
                    else:
                        n_retrying += 1
                    tracker.resolve(tp, offset, committable)
                    if not committable:
                        self._stats["offsets_retained"] += 1
                if n_retrying:
                    logger.warning(
                        "[Python-ingest] partial batch success=%s retrying=%s failed/dlq=%s",
                        sum(1 for o in outcomes if o.status == STATUS_SUCCESS),
                        n_retrying,
                        sum(1 for o in outcomes if o.status in (STATUS_FAILED, STATUS_DLQ)),
                    )
        await self._sync_consumer_offsets(consumer, fetched, tracker)

    async def _ingest_python_batch(self, events: list) -> list:
        """detect+persist 一批 python-ingest 事件。返回与 events 等长的 EventOutcome。"""
        from ingest_pipeline import run_many
        from models import async_session as db_session

        if not events:
            return []
        outcomes: list[EventOutcome] = []
        batch_size = max(
            1, int(getattr(settings, "ingest_store_batch_size", 50) or 50)
        )

        def _from_exc(exc: BaseException) -> EventOutcome:
            verdict = classify_exception(exc)
            if verdict.retryable:
                return EventOutcome.retrying(
                    error=verdict.message,
                    error_class=verdict.error_class,
                    error_code=verdict.error_code,
                )
            return EventOutcome.failed(
                error=verdict.message,
                error_class=verdict.error_class,
                error_code=verdict.error_code,
            )

        try:
            async with db_session() as session:
                for i in range(0, len(events), batch_size):
                    chunk = events[i:i + batch_size]
                    try:
                        results = await run_many(session, chunk)
                    except asyncio.CancelledError:
                        raise
                    except Exception as e:
                        logger.error("[Python-ingest] chunk ingest failed: %s", e)
                        outcomes.extend(_from_exc(e) for _ in chunk)
                        continue
                    for rr, (_sid, body) in zip(results, chunk):
                        outcomes.append(_outcome_from_run_result(rr, body))
                    if len(results) < len(chunk):
                        outcomes.extend(
                            EventOutcome.retrying(error="missing run_many result")
                            for _ in range(len(chunk) - len(results))
                        )
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.error("[Python-ingest] batch ingest failed: %s", e)
            while len(outcomes) < len(events):
                outcomes.append(_from_exc(e))
        n_ok = sum(1 for item in outcomes if item.status == STATUS_SUCCESS)
        if n_ok:
            self._stats["python_ingest_consumed"] = self._stats.get(
                "python_ingest_consumed", 0
            ) + n_ok
            self._stats["last_message_at"] = time.time()
            try:
                topic = getattr(settings, "kafka_topic_ingest_process", "")
                for _ in range(n_ok):
                    inc_kafka_consumed(topic)
            except Exception:
                pass
        if len(outcomes) < len(events):
            outcomes.extend(
                EventOutcome.retrying(error="incomplete batch")
                for _ in range(len(events) - len(outcomes))
            )
        return outcomes[: len(events)]

    async def _safe_py_handle(self, msg) -> bool:
        try:
            event = msg.value if isinstance(msg.value, dict) else json.loads(msg.value)
            await self._handle_python_ingest(event, "")
            self._stats["python_ingest_consumed"] = self._stats.get("python_ingest_consumed", 0) + 1
            self._stats["last_message_at"] = time.time()
            inc_kafka_consumed(getattr(settings, "kafka_topic_ingest_process", ""))
            return True
        except Exception as e:
            self._stats["errors"] = self._stats.get("errors", 0) + 1
            logger.error(f"[Python-ingest] handle error: {e}")
            return False


    async def _handle_python_ingest(self, wrapper: dict, trace_id: str):
        from log_ingestion import log_ingestor
        from models import async_session as db_session
        wrapper = apply_headers(wrapper, None)
        body = wrapper.get("body")
        if not isinstance(body, dict):
            raise ValueError("python ingest wrapper lacks dict body")
        if not get_event_id(body) and get_event_id(wrapper):
            body = dict(body)
            body["eventId"] = get_event_id(wrapper)
        session_id = str(wrapper.get("session_id") or ("http-" + str(wrapper.get("uuid", "") or get_event_id(body))))
        async with db_session() as session:
            await log_ingestor.ingest(session, session_id, body)


    async def _consume_enriched(self):
        """消费 security-events-enriched → 全量存储 + 记忆树索引"""
        await self._consume_loop(
            topic=settings.kafka_topic_enriched,
            group_suffix="enriched",
            handler=self._handle_enriched,
            stat_key="enriched_consumed",
        )

    async def _consume_audit_queue(self):
        """消费 security-audit-queue → Audit-LLM 流水线（带背压）"""
        await self._consume_loop(
            topic=settings.kafka_topic_audit_queue,
            group_suffix="audit",
            handler=self._handle_audit_with_backpressure,
            stat_key="audit_consumed",
        )

    async def _consume_alerts(self):
        """消费 security-alerts → 触发响应引擎"""
        await self._consume_loop(
            topic=settings.kafka_topic_alerts,
            group_suffix="alerts",
            handler=self._handle_alert,
            stat_key="alerts_consumed",
        )

    async def _consume_behavior_alerts(self):
        """消费 security-behavior-alerts → L4 行为基线响应"""
        await self._consume_loop(
            topic=settings.kafka_topic_behavior_alerts,
            group_suffix="behavior-alerts",
            handler=self._handle_behavior_alert,
            stat_key="behavior_alerts_consumed",
        )

    async def _consume_rejected(self):
        """消费 security-logs-rejected → 拒绝原因可观测"""
        await self._consume_loop(
            topic=settings.kafka_topic_rejected,
            group_suffix="rejected",
            handler=self._handle_rejected,
            stat_key="rejected_consumed",
        )

    async def _consume_audit_overflow(self):
        """P0/P1 审计 overflow topic → 回灌 AuditWorker (from_overflow 防环)。"""
        await self._consume_loop(
            topic=settings.kafka_topic_audit_overflow,
            group_suffix="audit-overflow",
            handler=self._handle_audit_overflow,
            stat_key="audit_overflow_consumed",
        )

    async def _consume_retry(self):
        """延迟重试 Topic。仅 kafka_retry_ordering=unordered 时启动。

        此路径允许同一业务键的后续消息越过未完成记录。strict 模式不会走到这里。
        """
        topic = str(getattr(settings, "kafka_topic_retry", "security-logs-retry") or "security-logs-retry")
        await self._consume_loop(
            topic=topic,
            group_suffix="retry",
            handler=self._handle_retry_envelope,
            stat_key="retry_consumed",
        )

    async def _handle_retry_envelope(self, envelope: dict, trace_id: str):
        retry_at = int(envelope.get("retry_at_ms") or 0)
        now_ms = int(time.time() * 1000)
        if retry_at > now_ms:
            delay = min(5.0, max(0.05, (retry_at - now_ms) / 1000.0))
            await asyncio.sleep(delay)
            if int(time.time() * 1000) < retry_at:
                raise TimeoutError("retry_not_due")
        original = str(envelope.get("original_topic") or "")
        payload = envelope.get("payload")
        if not isinstance(payload, dict):
            raise ValueError("retry envelope payload is not an object")
        mapped = self._handler_for_topic(original)
        if mapped is None:
            raise ValueError(f"unknown original topic for retry: {original}")
        handler, _stat, _suffix = mapped
        payload["_retry_hops"] = int(envelope.get("retry_hops") or 1)
        if envelope.get("eventId") or envelope.get("event_id"):
            payload = apply_headers(payload, [
                ("event_id", str(envelope.get("eventId") or envelope.get("event_id") or "").encode("utf-8")),
                ("correlation_id", str(envelope.get("correlation_id") or "").encode("utf-8")),
                ("trace_id", str(envelope.get("trace_id") or trace_id or "").encode("utf-8")),
                ("parent_event_id", str(envelope.get("parent_event_id") or "").encode("utf-8")),
            ])
        await handler(payload, trace_id or str(envelope.get("trace_id") or ""))

    async def _handle_audit_overflow(self, event: dict, trace_id: str):
        """把 Kafka overflow 上的审计作业重新提交进 worker。

        from_overflow=True: 队列仍满时只进 Redis PQ / 本地 deque, 不再二次 produce。
        """
        from audit_worker import audit_worker
        from anomaly_detector import AnomalyReport

        eid = int(event.get("event_id") or 0)
        if eid <= 0:
            logger.warning("[Audit-overflow] drop payload without event_id")
            return
        score = float(event.get("anomaly_score") or 0)
        ar = AnomalyReport(
            event_id=eid,
            anomaly_score=score,
            is_anomaly=score >= 0.6,
            deviation_sigma=0.0,
            reasons=list(event.get("reasons") or []),
        )
        await audit_worker.submit(
            session_id=str(event.get("session_id") or ""),
            event_id=eid,
            log_data=event.get("log_data") or {},
            anomaly_report=ar,
            from_overflow=True,
        )

    async def _consume_cep_partial(self):
        """消费 security-cep-partial → 攻击链部分匹配可视化"""
        consumer = AIOKafkaConsumer(
            settings.kafka_topic_cep_partial,
            bootstrap_servers=settings.kafka_bootstrap,
            group_id=f"{settings.kafka_consumer_group}-cep-partial",
            # P1: 不设 value_deserializer — 反序列化在迭代器内抛错会打垮整个
            # 消费循环(毒丸消息→crash→offset 未提交→重读同一条→永久卡死)。
            # 与其他消费者一致: 保留原始 bytes, 用 _decode_kafka_value 解码,
            # 失败走 DLQ(下方 payload None 分支)。
            auto_offset_reset="latest",
            enable_auto_commit=False,
            max_poll_records=MAX_POLL_RECORDS,
            max_poll_interval_ms=MAX_POLL_INTERVAL_MS,
            # Flink 使用 EXACTLY_ONCE 事务；消费端必须只读已提交，
            # 否则已 abort 的事务记录仍会到达响应引擎（重复告警）。
            isolation_level="read_committed",
            **aiokafka_security_kwargs(),
        )
        topic = settings.kafka_topic_cep_partial
        try:
            await consumer.start()
            self._live_consumers[topic] = consumer
            logger.info(f"Consuming {settings.kafka_topic_cep_partial}...")
            async for msg in consumer:
                if not self._running:
                    break
                try:
                    cep_event, cep_decode_error = _decode_kafka_value(msg.value)
                    payload = cep_event if isinstance(cep_event, dict) else None
                    group = f"{settings.kafka_consumer_group}-cep-partial"
                    if payload is None:
                        try:
                            from core_metrics import record_ingest
                            record_ingest("kafka", "validation_failed", reason="decode")
                        except Exception:
                            pass
                        stored = await self._send_to_dlq(
                            settings.kafka_topic_cep_partial,
                            {"eventId": ""},
                            cep_decode_error or "cep payload is not an object",
                            0,
                            partition=msg.partition,
                            offset=msg.offset,
                            consumer_group=group,
                            message_timestamp_ms=getattr(msg, "timestamp", None),
                            error_class="DecodeError",
                            error_code="decode_error",
                        )
                        if not stored:
                            logger.error("[CEP-Partial] undecodable and DLQ write failed; offset retained")
                            break
                    else:
                        decision = field_cipher.open_message(payload)
                        if not decision.ok:
                            try:
                                from core_metrics import record_ingest
                                record_ingest("kafka", "validation_failed", reason="cipher")
                            except Exception:
                                pass
                            stored = await self._send_to_dlq(
                                settings.kafka_topic_cep_partial,
                                payload,
                                decision.detail,
                                0,
                                partition=msg.partition,
                                offset=msg.offset,
                                consumer_group=group,
                                message_timestamp_ms=getattr(msg, "timestamp", None),
                                error_class="FieldCipherRejected",
                                error_code=decision.code,
                            )
                            if not stored:
                                logger.error(
                                    "[CEP-Partial] cipher code=%s and DLQ write failed; offset retained",
                                    decision.code,
                                )
                                break
                            if HAS_KAFKA:
                                await consumer.commit({
                                    TopicPartition(msg.topic, msg.partition): msg.offset + 1,
                                })
                            continue
                        # 列表接口目前没有单独鉴权，这里保留原始消息，不把解开的明文放进去。
                        self._cep_partial.append(payload)
                    if len(self._cep_partial) > 100:
                        self._cep_partial = self._cep_partial[-100:]
                    if HAS_KAFKA:
                        await consumer.commit({
                            TopicPartition(msg.topic, msg.partition): msg.offset + 1,
                        })
                except asyncio.CancelledError:
                    raise
                except Exception as e:
                    logger.debug("[CEP-Partial] Error: %s", sanitize_error(str(e)))
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.error(f"CEP partial consumer crashed: {e}")
        finally:
            if self._live_consumers.get(topic) is consumer:
                self._live_consumers.pop(topic, None)
            try:
                await consumer.stop()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.warning(f"[Kafka] CEP consumer stop failed: {exc}")

    # ── 业务处理函数 ──

    async def _handle_enriched(self, event: dict, trace_id: str):
        """处理 Flink 富化后的事件：存储 + 索引"""
        from models import async_session as db_session
        from event_store import event_store
        from memory_tree import memory_tree

        session_id = event.get("sourceId", event.get("session_id", "kafka-" + str(event.get("eventId", ""))))
        # Flink AnomalyDetectionJob 把评分写入嵌套的 rawData._anomalyScore,
        # 兼容顶层键以支持其它生产者
        raw = event.get("rawData") or {}
        if not isinstance(raw, dict):
            raw = {}
        anomaly_score = event.get("_anomalyScore", raw.get("_anomalyScore", event.get("anomalyScore", 0.0)))
        anomaly_reasons = event.get("_anomalyReasons", raw.get("_anomalyReasons", []))

        ident = resolve(event)
        log_data = {
            "eventId": ident.event_id or event.get("eventId", ""),
            "correlationId": ident.correlation_id,
            "parentEventId": ident.parent_event_id,
            "traceId": ident.trace_id or trace_id,
            "event": event.get("eventType", event.get("event", "UNKNOWN")),
            "severity": event.get("severity", "info"),
            "src_ip": event.get("srcIp", event.get("src_ip", "")),
            "dst_ip": event.get("dstIp", event.get("dst_ip", "")),
            "protocol": event.get("protocol", ""),
            "message": event.get("message", ""),
            "confidence": event.get("confidence", 50),
            "_anomaly": {
                "score": anomaly_score,
                "is_anomaly": anomaly_score >= 0.6,
                "reasons": anomaly_reasons,
                "sigma": 0,
            },
            "_flink_processed": True,
            "_source_id": event.get("sourceId", ""),
            "_trace_id": ident.trace_id or trace_id,
        }

        async with db_session() as session:
            stored = await event_store.store(
                session, log_data, session_id,
                anomaly_score=anomaly_score,
            )
            # 残留修复(2026-10-24): 幂等命中(replay)只保留落库,
            # 不再重复挂记忆树 —— 修复前重启重放会重复索引。
            is_replay = bool(getattr(stored, "idempotent", False))
            if not is_replay:
                event_text = json.dumps(log_data, ensure_ascii=False)
                await memory_tree.add_leaf(
                    session, session_id, log_data, event_text,
                    correlation_group="anomaly" if anomaly_score >= 0.6 else "",
                )

        if getattr(stored, "idempotent", False):
            logger.debug("[Kafka-Enriched] replay event #%s — side effects skipped",
                         stored.id)
            return

        from event_bus import event_bus
        from event_identity import bus_fields
        event_bus.publish("security_event", {
            **bus_fields(stored_id=stored.id, event=log_data, trace_id=trace_id),
            "event_type": log_data["event"],
            "severity": log_data["severity"],
            "src_ip": log_data["src_ip"],
            "anomaly_score": anomaly_score,
            "source": "kafka-flink",
        })

        # ── P0 修复(审计闭环) ──
        # Flink 只把"中危以下"事件路由进 security-audit-queue；高异常 / critical / high
        # 的事件走 security-alerts 响应路径，导致这些"真正的问题"从未进入 Audit-LLM，
        # 在日志中心永远停留在"待审计/审核中"。此处对命中告警路径的事件同样排队审计，
        # 使高优先级问题进入审计闭环并标记为已分析。
        severity = log_data["severity"]
        if getattr(stored, "idempotent", False):
            return  # replay: 审计闭环已在首次处理时提交, 不重复排队
        if anomaly_score >= 0.6 or severity in ("critical", "high"):
            await self._queue_audit(
                log_data=log_data,
                anomaly_score=anomaly_score,
                anomaly_reasons=anomaly_reasons,
                session_id=session_id,
                stored_id=stored.id,
                trace_id=trace_id,
            )

    async def _queue_audit(
        self,
        log_data: dict,
        anomaly_score: float,
        anomaly_reasons: list,
        session_id: str,
        stored_id: int,
        trace_id: str,
    ):
        """将事件排入 Audit-LLM 流水线（enriched 告警路径与 audit-queue 共用）。"""
        from anomaly_detector import AnomalyReport

        report = AnomalyReport(
            event_id=stored_id,
            anomaly_score=anomaly_score,
            is_anomaly=anomaly_score >= 0.6,
            deviation_sigma=anomaly_score * 5,
            reasons=anomaly_reasons,
        )
        from audit_worker import audit_worker
        await audit_worker.submit(
            session_id=session_id,
            event_id=stored_id,
            log_data=log_data,
            anomaly_report=report,
        )
        logger.info(
            f"[Kafka-Enriched-Audit] Queued event #{stored_id} for Audit-LLM "
            f"(alert-path closure): {log_data.get('event')} score={anomaly_score:.2f} "
            f"{resolve(log_data).log_fields()} "
            f"trace={trace_id[:8] if trace_id else 'none'}"
        )

    async def _handle_audit_with_backpressure(self, event: dict, trace_id: str):
        """Audit-LLM 入口 — 通过信号量控制并发（背压）"""
        async with self._audit_semaphore:
            await self._handle_audit(event, trace_id)

    async def _handle_audit(self, event: dict, trace_id: str):
        """将事件送入 Audit-LLM 流水线"""
        from models import async_session as db_session
        from anomaly_detector import AnomalyReport

        session_id = event.get("sourceId", event.get("session_id", "kafka-audit"))
        # Flink 评分位于嵌套 rawData._anomalyScore（同 _handle_enriched）
        raw = event.get("rawData") or {}
        if not isinstance(raw, dict):
            raw = {}
        anomaly_score = event.get("_anomalyScore", raw.get("_anomalyScore", event.get("anomalyScore", 0.3)))
        anomaly_reasons = event.get("_anomalyReasons", raw.get("_anomalyReasons", []))

        ident = resolve(event)
        log_data = {
            "eventId": ident.event_id or event.get("eventId", ""),
            "correlationId": ident.correlation_id,
            "parentEventId": ident.parent_event_id,
            "traceId": ident.trace_id or trace_id,
            "event": event.get("eventType", event.get("event", "UNKNOWN")),
            "severity": event.get("severity", "info"),
            "src_ip": event.get("srcIp", event.get("src_ip", "")),
            "dst_ip": event.get("dstIp", event.get("dst_ip", "")),
            "protocol": event.get("protocol", ""),
            "message": event.get("message", ""),
            "confidence": event.get("confidence", 50),
            "_anomaly": {
                "score": anomaly_score,
                "is_anomaly": anomaly_score >= 0.6,
                "reasons": anomaly_reasons,
                "sigma": 0,
            },
            "_flink_processed": True,
            "_trace_id": ident.trace_id or trace_id,
        }

        report = AnomalyReport(
            event_id=0,
            anomaly_score=anomaly_score,
            is_anomaly=anomaly_score >= 0.6,
            deviation_sigma=anomaly_score * 5,
            reasons=anomaly_reasons,
        )

        async with db_session() as session:
            from event_store import event_store
            stored = await event_store.store(
                session, log_data, session_id,
                anomaly_score=anomaly_score,
            )

        # 残留修复(2026-10-24): replay 不重复提交 Audit-LLM (幂等命中只保落库)
        if getattr(stored, "idempotent", False):
            logger.debug("[Kafka-Audit] replay event #%s — audit submit skipped",
                         stored.id)
            return

        from audit_worker import audit_worker
        await audit_worker.submit(
            session_id=session_id,
            event_id=stored.id,
            log_data=log_data,
            anomaly_report=report,
        )

        logger.info(
            f"[Kafka-Audit] Queued event #{stored.id} for Audit-LLM: "
            f"{log_data['event']} score={anomaly_score:.2f} "
            f"{resolve(log_data).log_fields()} "
            f"trace={trace_id[:8] if trace_id else 'none'}"
        )

    async def _handle_alert(self, alert: dict, trace_id: str):
        """处理 Flink 产生的告警 → 响应引擎"""
        from models import async_session as db_session
        from response_engine import get_orchestrator
        from event_bus import event_bus

        alert_type = alert.get("alertType", "ANOMALY")
        severity = alert.get("severity", "high")
        src_ip = alert.get("srcIp", alert.get("src_ip", ""))

        # ── 阻断门槛由告警**声明的动作**派生，不是一律 True ──
        # 详见 _allow_blocking_for 的 docstring（口径与 fail-safe 行为）。
        allow_blocking, declared_action = _allow_blocking_for(alert)
        if declared_action:
            logger.info(
                "[Kafka-Alert] declared action=%s -> allow_blocking=%s",
                declared_action, allow_blocking)

        ident = resolve(alert)

        # 置信度来源: anomalyScore 优先, 其次 confidence。
        # 与 _handle_behavior_alert 同一写法 —— Sigma 聚合告警(SIGMA_AGGREGATE)
        # 只带 confidence, 不带 anomalyScore。
        #
        # 修复前这里只读 anomalyScore → Sigma 聚合告警实算 0.0 →
        # 策略「暴力破解自动阻断」要求 min_confidence=0.5 → NO_ACTION →
        # **allow_blocking 判定对了也永远不封禁**。
        try:
            anomaly_score = float(
                alert.get("anomalyScore") or alert.get("confidence") or 0.0)
        except (TypeError, ValueError):
            anomaly_score = 0.0

        logger.warning(
            f"[Kafka-Alert] {alert_type}: {alert.get('eventType', '')} "
            f"from {src_ip} score={anomaly_score:.2f} "
            f"action={declared_action or '-'} blocking={allow_blocking} "
            f"{ident.log_fields()} "
            f"trace={trace_id[:8] if trace_id else 'none'}"
        )

        from event_identity import bus_fields
        event_bus.publish("alert", {
            **bus_fields(event=alert, trace_id=trace_id),
            "alert_type": alert_type,
            "event_type": alert.get("eventType", ""),
            "severity": severity,
            "src_ip": src_ip,
            "anomaly_score": anomaly_score,
            "reasons": alert.get("reasons", []),
            "source": "flink-cep",
            "action_recommend": declared_action,
            "allow_blocking": allow_blocking,
        })

        if anomaly_score >= 0.5 or severity in ("critical", "high"):
            try:
                # 资产重要性加成
                from routers.assets import get_asset_weight
                dst_ip = alert.get("dstIp", alert.get("dst_ip", ""))
                asset_weight = get_asset_weight(dst_ip)
                if asset_weight > 1.0:
                    anomaly_score = min(1.0, anomaly_score * asset_weight)
                    logger.info(
                        f"[Kafka-Alert] Asset boost: dst={dst_ip} "
                        f"weight={asset_weight} score→{anomaly_score:.2f}"
                    )

                resp_orch = get_orchestrator()
                threat_info = {
                    "threat_type": alert.get("eventType", "UNKNOWN"),
                    "confidence": min(1.0, anomaly_score * 1.2),
                    "severity": severity,
                    "src_ip": src_ip,
                    "dst_ip": alert.get("dstIp", alert.get("dst_ip", "")),
                    "message": alert.get("message", f"Flink {alert_type} alert"),
                    "session_id": "flink-alert",
                    "event_id": 0,
                    "eventId": ident.event_id,
                    "parentEventId": ident.parent_event_id,
                    "policy_name": f"flink_{alert_type.lower()}",
                    "trace_id": ident.trace_id or trace_id,
                    "response_source": "flink_alert",
                    "allow_blocking": allow_blocking,
                    "action_recommend": declared_action,
                }
                async with db_session() as session:
                    await resp_orch.on_threat_detected(
                        session=session,
                        threat_info=threat_info,
                        event_id=None,
                        session_id="flink-alert",
                        allow_blocking=allow_blocking,
                    )
            except Exception as e:
                # 2026-10-21：响应编排失败**不能**被吞掉。
                # 此前这里只 warning 后正常返回 → 上层提交 offset →
                # 威胁既未处置、又未落 security_events、又未进 DLQ，
                # 形成不可恢复的静默丢失。现在让异常冒泡到统一重试/DLQ 路径。
                logger.exception(f"[Kafka-Alert] Response trigger failed: {e}")
                raise

    async def _handle_behavior_alert(self, alert: dict, trace_id: str):
        """L4: Flink 行为基线告警 → 固定 BEHAVIOR_ANOMALY，强信号可封禁。"""
        from models import async_session as db_session
        from response_engine import get_orchestrator
        from event_bus import event_bus

        src_ip = alert.get("srcIp") or alert.get("src_ip") or ""
        severity = str(alert.get("severity") or "high").lower()
        try:
            anomaly_score = float(alert.get("anomalyScore") or alert.get("confidence") or 0.0)
        except (TypeError, ValueError):
            anomaly_score = 0.0
        reasons = alert.get("reasons") or []
        if isinstance(reasons, str):
            reasons = [reasons]
        category = (
            alert.get("category")
            or ("EXFIL" if any("bytes_out" in str(r) for r in reasons) else "SCAN")
        )

        ident = resolve(alert)
        logger.warning(
            f"[Kafka-Behavior] BEHAVIOR_ANOMALY from {src_ip} "
            f"score={anomaly_score:.2f} cat={category} reasons={reasons} "
            f"{ident.log_fields()} "
            f"trace={trace_id[:8] if trace_id else 'none'}"
        )

        from event_identity import bus_fields
        event_bus.publish("alert", {
            **bus_fields(event=alert, trace_id=trace_id),
            "alert_type": "BEHAVIOR_ANOMALY",
            "event_type": "BEHAVIOR_ANOMALY",
            "severity": severity,
            "src_ip": src_ip,
            "anomaly_score": anomaly_score,
            "reasons": reasons,
            "source": "flink_baseline",
        })

        if not src_ip:
            return
        if anomaly_score < 0.5 and severity not in ("critical", "high"):
            return

        try:
            resp_orch = get_orchestrator()
            threat_info = {
                "threat_type": "BEHAVIOR_ANOMALY",
                "category": category,
                "confidence": min(1.0, max(anomaly_score, 0.6)),
                "severity": severity if severity in (
                    "info", "low", "medium", "high", "critical"
                ) else "high",
                "src_ip": src_ip,
                "dst_ip": alert.get("dstIp") or alert.get("dst_ip") or "",
                "message": alert.get("message") or (
                    "Flink behavior baseline: " + "; ".join(str(r) for r in reasons)
                ),
                "reason": (
                    f"flink_baseline score={anomaly_score:.2f} "
                    f"reasons={','.join(str(r) for r in reasons)}"
                ),
                "session_id": "flink-behavior",
                "event_id": 0,
                "eventId": ident.event_id,
                "parentEventId": ident.parent_event_id,
                "policy_name": "flink_behavior_anomaly",
                "trace_id": ident.trace_id or trace_id,
                "response_source": "flink_baseline",
                "allow_blocking": True,
                "anomaly_reasons": list(reasons),
            }
            async with db_session() as session:
                await resp_orch.on_threat_detected(
                    session=session,
                    threat_info=threat_info,
                    event_id=None,
                    session_id="flink-behavior",
                    allow_blocking=True,
                )
        except Exception as e:
            # 同 _handle_alert：失败必须进入重试/DLQ，不能提交 offset 后静默丢失。
            logger.exception(f"[Kafka-Behavior] Response trigger failed: {e}")
            raise

    async def _handle_rejected(self, record: dict, trace_id: str):
        """处理被拒绝的事件 — 聚合统计 + 环形日志"""
        rejection_type = record.get("rejectionType", "UNKNOWN")
        reason = record.get("rejectionReason", "")
        stage = record.get("stage", "UNKNOWN")

        # 按类型聚合
        self._rejection_by_type[rejection_type] = \
            self._rejection_by_type.get(rejection_type, 0) + 1

        # 环形日志（保留最近 200 条）
        original = record.get("originalEvent") if isinstance(record.get("originalEvent"), dict) else {}
        ident = resolve(original or record)
        self._rejection_log.append({
            "type": rejection_type,
            "reason": reason[:200],
            "stage": stage,
            "at": record.get("rejectedAt", 0),
            "event_type": original.get("eventType", "") if original else "",
            "eventId": ident.event_id,
        })
        logger.debug(
            "[Kafka-Rejected] %s: %s %s",
            rejection_type, reason[:100], ident.log_fields(),
        )
        if len(self._rejection_log) > 200:
            self._rejection_log = self._rejection_log[-200:]

    def rejection_stats(self) -> dict:
        """拒绝原因统计（供 API 暴露）"""
        return {
            "total": self._stats["rejected_consumed"],
            "by_type": dict(self._rejection_by_type),
            "recent": self._rejection_log[-20:],
        }

    def cep_partial_matches(self) -> list[dict]:
        """CEP 部分匹配状态（供 API 暴露）"""
        return self._cep_partial[-50:]

    def stats(self) -> dict:
        return {**self._stats, "running": self._running}


kafka_consumer_manager = KafkaConsumerManager()
