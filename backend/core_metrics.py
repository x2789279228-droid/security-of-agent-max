"""六组核心运营指标。

event_id / trace_id / correlation_id 只进结构化日志，禁止作为 Prometheus 标签。
高基数 ID 会把监控系统本身打满。

监控组:
  数据接入     吞吐量、拒绝数、校验失败数
  Kafka 消费   Consumer Lag、最老积压消息年龄
  流水线处理   端到端延迟、各阶段耗时、失败率
  重试与 DLQ   DLQ 数量和等待时间
  事件推送     队列深度、丢弃数、断线次数、补查事件数
  缓存与生命周期  命中率、失效失败、过期读取、关闭时遗留任务数

告警优先: 队列丢弃、DLQ 积压、关闭未完成任务、承诺不丢类别的非预期丢弃。
"""
from __future__ import annotations

import logging
import re
import time
from typing import Any, Optional

from prometheus_client import Counter, Gauge, Histogram

logger = logging.getLogger("soc.core_metrics")

# ── 标签约束 ──────────────────────────────────────────────
_UUIDISH = re.compile(r"^[0-9a-f]{8}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{12}$", re.I)
_FORBIDDEN_LABEL_NAMES = frozenset({
    "event_id", "eventid", "trace_id", "traceid", "correlation_id", "correlationid",
    "parent_event_id", "parenteventid", "stored_id", "uuid",
})
_SOURCE_ALLOW = frozenset({"http", "kafka", "syslog", "unknown"})
_STAGE_ALLOW = frozenset({
    "ingest", "detect", "persist", "dispatch", "consume", "retry", "dlq",
    "push", "cache", "shutdown",
})
_RESULT_ALLOW = frozenset({
    "success", "fail", "retrying", "rejected", "dlq", "dropped", "queued",
    "partial", "accepted", "expired", "hit", "miss", "stale",
    # 检测五态（整改方案 §二 / §十一）。
    # ⚠️ `inconclusive` 原来**不在**这个白名单里：谁把检测状态喂给
    # `inc_pipeline_result(stage="detect", ...)`，它会被 clamp 到默认值
    # `"success"` —— 「判定不出来」被记成「判定成功」。这正是 §十一
    # 警告的「把状态压成一个计数」的具体形态，而且**不报错**。
    "inconclusive", "detected", "not_detected", "error",
})
_CACHE_ALLOW = frozenset({"event_store", "audit_cache"})
_LANE_ALLOW = frozenset({"critical", "bulk"})
_KIND_ALLOW = frozenset({
    "eventbus_critical", "audit_volatile", "ingest_never_drop", "other",
})
_COMPONENT_ALLOW = frozenset({
    "audit_worker", "kafka_consumer", "scheduler", "event_bus", "other",
})
#: 检测器名 —— 必须低基数。白名单外的落到 "other"，绝不把规则 id / src_ip
#: 之类的高基数值塞进来。
_DETECTOR_ALLOW = frozenset({
    "sigma", "anomaly", "correlation", "causal",
    "variant_cluster", "sandbox", "behavior", "other",
})
#: 检测五态。与 detection_contract.ALL_STATUSES 对齐。
_DETECTION_OUTCOME_ALLOW = frozenset({
    "detected", "not_detected", "partial", "inconclusive", "error",
})
#: 案例自动派单的结果三态。
#:
#: `failed` 与 `skipped` 必须分开 —— 修复前二者都是「没有工单」，
#: 在指标上完全同形：`failed` 意味着**案例建好了却没人派单**。
_CASE_DISPATCH_RESULT_ALLOW = frozenset({"ok", "skipped", "failed"})
#: 告警发布结果。
#:
#: `not_started` / `schema_rejected` / `error` / `send_failed` 四种失败
#: 修复前**全部**只留一行日志 —— 告警彻底消失，运维不知道有威胁。
_KAFKA_ALERT_RESULT_ALLOW = frozenset({
    "ok", "not_started", "schema_rejected", "error", "send_failed",
})
#: 工单审批结果。
#:
#: `skipped` = 不是本次可审批的对象（工单不存在 / 已审批）；
#: `failed` = 审批写下去了，但**审批后的推进步骤**抛了异常 ——
#: 修复前这条失败只留一行 warning 日志，指标上完全不可见。
_WORK_ORDER_APPROVE_ALLOW = frozenset({"approved", "skipped", "failed"})
_LOOP_ALLOW = frozenset({
    "enriched", "audit", "alerts", "behavior", "rejected",
    "ingestpy", "overflow", "retry", "cep", "lag", "other",
})
_ALERT_NAMES = (
    "SocEventBusDrop",
    "SocDlqBacklog",
    "SocShutdownLeftoverTasks",
    "SocUnexpectedDrop",
)

_REASON_ALLOW = frozenset({
    "draining", "overloaded", "too_large", "batch_too_large", "auth",
    "not_durable", "schema", "cipher", "decode", "invalid_json",
    "admission", "producer_down", "schema_invalid", "decode_error",
    "ingest_wrapper", "ciphertext_malformed", "plaintext_bypass",
    "key_unavailable", "cipher_error", "permanent_failure", "retry_exhausted",
    "transient", "timeout", "slots_full", "other", "unknown",
})


def _clip(value: Any, default: str = "unknown", maxlen: int = 40) -> str:
    text = str(value or "").strip().lower()
    if not text:
        return default
    return text[:maxlen]


def clamp_label(value: Any, allowed: Optional[set[str]] = None,
                default: str = "unknown", maxlen: int = 40) -> str:
    """低基数标签。UUID、长数字、不明字符串一律落到 default/other。"""
    text = _clip(value, default=default, maxlen=maxlen)
    if _UUIDISH.match(text) or (text.isdigit() and len(text) > 8):
        return "other" if allowed is None or "other" in allowed else default
    if allowed is not None:
        if text in allowed:
            return text
        return default if default in allowed else next(iter(allowed))
    if re.match(r"^[a-z][a-z0-9_.-]{0,39}$", text):
        return text
    return default


def clamp_reason(value: Any) -> str:
    text = _clip(value, default="unknown", maxlen=40)
    if _UUIDISH.match(text) or (text.isdigit() and len(text) > 6):
        return "other"
    if text in _REASON_ALLOW:
        return text
    if re.match(r"^[a-z][a-z0-9_]{0,39}$", text):
        return text
    return "other"


def clamp_topic(value: Any) -> str:
    text = str(value or "").strip()[:80]
    if not text:
        return "unknown"
    if _UUIDISH.match(text.lower()):
        return "other"
    return text


# ── 1. 数据接入 ──────────────────────────────────────────
INGEST_RECEIVED = Counter(
    "soc_ingest_received_total",
    "接入吞吐量（网关接受/入队的事件）",
    ["source"],
)
INGEST_REJECTED = Counter(
    "soc_ingest_rejected_total",
    "接入拒绝数（过载、关闭、鉴权、体过大、未持久化）",
    ["source", "reason"],
)
INGEST_VALIDATION_FAILED = Counter(
    "soc_ingest_validation_failed_total",
    "接入校验失败数（schema / 字段加密 / 解码）",
    ["source", "reason"],
)

# ── 2. Kafka 消费 ────────────────────────────────────────
KAFKA_LAG = Gauge(
    "soc_kafka_consumer_lag",
    "Consumer lag（highwater - position，按 topic 合计）",
    ["topic"],
)
KAFKA_OLDEST_LAG_SECONDS = Gauge(
    "soc_kafka_oldest_lag_seconds",
    "最老积压消息年龄（秒）。lag=0 时为 0",
    ["topic"],
)
KAFKA_LOOP_ALIVE = Gauge(
    "soc_kafka_consumer_alive",
    "Kafka 消费循环是否存活（1=在跑）",
    ["loop"],
)
KAFKA_LOOP_RESTARTS = Counter(
    "soc_kafka_consumer_restarts_total",
    "Kafka 消费循环在仍应运行时异常退出后的重启次数",
    ["loop"],
)

# ── 3. 流水线处理 ────────────────────────────────────────
PIPELINE_E2E_SECONDS = Histogram(
    "soc_pipeline_e2e_seconds",
    "流水线端到端耗时（秒）",
    ["result"],
    buckets=(0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60),
)
PIPELINE_STAGE_SECONDS = Histogram(
    "soc_pipeline_stage_seconds",
    "流水线各阶段耗时（秒）",
    ["stage"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30),
)
PIPELINE_RESULTS = Counter(
    "soc_pipeline_results_total",
    "流水线各阶段结果（失败率 = fail / (success+fail)）",
    ["stage", "result"],
)

# ── 4. 重试与 DLQ ────────────────────────────────────────
DLQ_MESSAGES = Counter(
    "soc_dlq_messages_total",
    "写入 DLQ 索引的消息数",
    ["reason"],
)
DLQ_DEPTH = Gauge(
    "soc_dlq_depth",
    "待处理 DLQ 条数（pending/replaying/replay_failed）",
)
DLQ_WAIT_SECONDS = Histogram(
    "soc_dlq_wait_seconds",
    "消息进入 DLQ 时已等待的时间（秒）",
    buckets=(1, 5, 15, 30, 60, 300, 900, 3600, 14400),
)
DLQ_OLDEST_WAIT_SECONDS = Gauge(
    "soc_dlq_oldest_wait_seconds",
    "当前积压中最老 DLQ 记录的等待时间（秒）",
)
RETRY_TOTAL = Counter(
    "soc_retry_total",
    "重试次数（进程内退避或发往 retry topic）",
    ["reason"],
)

# ── 5. 检测引擎 ──────────────────────────────────────────
# 整改方案 §十一 P2「各引擎要统一输出哪些运行指标」的前两行：
#   · 各检测器耗时分布 —— 定位性能瓶颈
#   · 成功、命中、未命中、部分失败、执行错误计数 —— 判断引擎是否正常工作
#
# 单列一组指标而不是复用 PIPELINE_*：Prometheus 的 label 组合在指标
# 定义时就固定了，加 detector 标签去改 PIPELINE_STAGE_SECONDS 会让
# 历史数据全部作废。单列的成本是多两个指标定义，换来的是互不干扰。
DETECTION_SECONDS = Histogram(
    "soc_detection_seconds",
    "各检测器单次调用耗时（秒）",
    ["detector"],
    buckets=(0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5),
)
DETECTION_OUTCOMES = Counter(
    "soc_detection_outcomes_total",
    "检测五态计数（detected/not_detected/partial/inconclusive/error）。"
    "把 inconclusive 单独计数的意义：它既不是阴性也不是故障，"
    "压进 not_detected 会让准确率虚高",
    ["detector", "outcome"],
)

# ── 5b. 案例自动派单 ────────────────────────────────────
#
# 整改方案 §十一.1 要求「成功、命中、未命中、部分失败、执行错误计数」。
# 案例域的「执行错误」此前**没有任何计数**：自动派单失败只记一行 warning，
# 而案例**已经建好并提交**、却**没有工单**、没人被叫醒 ——
# 在指标上与「本来就不需要派单」完全同形。
WORK_ORDER_APPROVE = Counter(
    "soc_work_order_approve_total",
    "工单审批结果计数（approved=审批通过；skipped=不是可审批对象；"
    "failed=审批后的推进步骤异常）",
    ["result"],
)

KAFKA_ALERT_PUBLISH = Counter(
    "soc_kafka_alert_publish_total",
    "告警发布结果计数（ok=已发出；not_started=producer 未启动；"
    "schema_rejected=schema 拒收；error=盖章/加密异常；"
    "send_failed=broker 发送失败）",
    ["result"],
)

CASE_AUTO_DISPATCH = Counter(
    "soc_case_auto_dispatch_total",
    "案例自动派单结果计数（ok=已派单；skipped=不需要派单；"
    "failed=派单失败 —— 案例已建但没有工单）",
    ["result"],
)

TLS_SESSION_EVICTED = Counter(
    "soc_tls_session_evicted_total",
    "TLS 挂起会话因缓冲区溢出被驱逐的次数（背压信号："
    "驱逐前已 flush 落库，但说明高峰期有会话被提前收走）",
)

RESPONSE_GROUNDING_GATE = Counter(
    "soc_response_grounding_gate_total",
    "响应动作的 grounding 硬门控状态计数（evaluated_pass=评估通过；"
    "evaluated_block=评估不通过被拦；not_evaluated=**根本没有 grounding 分数** → "
    "这道闸门未评估，不提供任何保护，整改报告 §9.51）",
    ["state"],
)

RESPONSE_IDEMPOTENCY_CHECK = Counter(
    "soc_response_idempotency_check_total",
    "响应动作的幂等检查状态计数（evaluated_hit=查了且命中重复；"
    "evaluated_miss=查了且不是重复；unavailable=**Redis 不可用 → 检查根本没跑**，"
    "此刻这道幂等保护不生效，整改报告 §9.52）",
    ["state"],
)

AUTO_UNBLOCK_SCHEDULED = Counter(
    "soc_response_auto_unblock_scheduled_total",
    "响应动作的自动解封调度计数（按 action=block_ip|isolate_host）；"
    "这些解封靠的是**进程内**的定时任务 —— 进程重启/发布/崩溃会**静默丢失**"
    "（规则一直留存），整改报告 §9.53",
    ["action"],
)

RESPONSE_AUDIT_FAILED = Counter(
    "soc_response_audit_failed_total",
    "响应动作**审计**失败计数（phase=threat=触发记录写失败；action=动作记录写失败；"
    "query=审计查询失败）—— 写失败意味着「动作发生了但审计里没有这条」；"
    "查询失败在旧实现里会返回**空列表**（看起来像「没有响应动作」），"
    "整改报告 §9.55",
    ["phase"],
)

RESPONSE_POLICY_LOAD_FAILED = Counter(
    "soc_response_policy_load_failed_total",
    "响应**策略文件**加载失败计数（reason=parse=解析失败/不是映射；invalid=校验不过；"
    "load_failed=整库加载异常）—— 失败的文件对应的策略**根本没生效**，"
    "而旧实现只留一行 warning，整改报告 §9.56",
    ["reason"],
)

REPUTATION_PRIOR_LOOKUP_FAILED = Counter(
    "soc_reputation_prior_lookup_failed_total",
    "信誉**先验 delta** 读取失败次数 —— 失败时 delta 退化为 0，"
    "而 delta 会**加到主评分上**（clip ±learn_loop_prior_clip）→ "
    "评分少一个先验修正、可能跨 clean/suspicious/malicious 档位；"
    "原先只有一行 debug 日志（生产看不见），整改报告 §9.57",
)

# ── 6. 事件推送 ──────────────────────────────────────────
EVENTBUS_QUEUE_DEPTH = Gauge(
    "soc_eventbus_queue_depth",
    "SSE 订阅者队列深度",
    ["lane"],
)
EVENTBUS_DISCONNECTS = Counter(
    "soc_eventbus_disconnects_total",
    "SSE 断线次数（unsubscribe）",
)
EVENTBUS_CATCHUP = Counter(
    "soc_eventbus_catchup_events_total",
    "断线后从数据库补查发出的事件数",
)

# ── 7. 缓存与生命周期 ────────────────────────────────────
CACHE_REQUESTS = Counter(
    "soc_cache_requests_total",
    "缓存读取（hit/miss/expired/stale）",
    ["cache", "result"],
)
CACHE_INVALIDATE_FAILURES = Counter(
    "soc_cache_invalidate_failures_total",
    "缓存失效广播失败",
    ["cache"],
)
LIFECYCLE_LEFTOVER = Gauge(
    "soc_lifecycle_leftover_tasks",
    "关闭时未完成任务数",
    ["component"],
)
LIFECYCLE_LEFTOVER_TOTAL = Counter(
    "soc_lifecycle_shutdown_leftover_total",
    "关闭时遗留任务累计（spilled 已落可恢复记录，lost 为非预期丢失）",
    ["component", "disposition"],
)
UNEXPECTED_DROPS = Counter(
    "soc_unexpected_drops_total",
    "承诺不丢的事件类别发生非预期丢弃",
    ["kind"],
)
CORE_ALERTS_ACTIVE = Gauge(
    "soc_core_alerts_active",
    "进程内核心告警是否处于触发状态（1=firing）",
    ["alert"],
)

_DLQ_OPEN: dict[int, float] = {}
_ALERT_STATE: dict[str, int] = {name: 0 for name in _ALERT_NAMES}


def _safe(fn):
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except Exception:
            return None
    return wrapper


# ── 结构化处理日志 ───────────────────────────────────────
def log_process(
    log: Optional[logging.Logger] = None,
    *,
    event_id: str = "",
    stage: str = "",
    result: str = "",
    reason: str = "",
    retry_count: int = 0,
    **fields: Any,
) -> None:
    """记录一次事件处理。event_id 只出现在日志里，不进指标标签。"""
    sink = log or logger
    payload = {
        "event_id": str(event_id or ""),
        "stage": str(stage or ""),
        "result": str(result or ""),
        "reason": str(reason or ""),
        "retry_count": int(retry_count or 0),
    }
    for key, value in fields.items():
        if key in payload or value is None:
            continue
        payload[key] = value
    msg = (
        "event.process"
        f" event_id={payload['event_id'] or '-'}"
        f" stage={payload['stage'] or '-'}"
        f" result={payload['result'] or '-'}"
        f" reason={payload['reason'] or '-'}"
        f" retry={payload['retry_count']}"
    )
    level = logging.DEBUG
    if payload["result"] in ("fail", "dlq", "dropped", "rejected", "lost"):
        level = logging.WARNING
    elif payload["result"] in ("retrying", "partial", "expired", "stale"):
        level = logging.INFO
    try:
        sink.log(level, msg, extra={"soc_event": payload})
    except Exception:
        sink.log(level, msg)


# ── 写入助手 ─────────────────────────────────────────────
@_safe
def record_ingest(source: str, result: str, reason: str = "", n: int = 1) -> None:
    src = clamp_label(source, _SOURCE_ALLOW, "unknown")
    count = max(1, int(n))
    if result in ("received", "queued", "accepted"):
        INGEST_RECEIVED.labels(source=src).inc(count)
        return
    why = clamp_reason(reason)
    if result == "validation_failed":
        INGEST_VALIDATION_FAILED.labels(source=src, reason=why).inc(count)
        return
    INGEST_REJECTED.labels(source=src, reason=why).inc(count)


#: Kafka lag 的进程内可读副本（topic → 最新 lag），供背压信号同步读取。
#: 消费循环停止刷新后这里会陈旧 —— 背压只做趋势判断（滞回闩）不做会计，
#: 陈旧偏高只会多拒绝一会儿，不会误放行。
_KAFKA_LAG_STATE: dict[str, int] = {}


@_safe
def set_kafka_lag(topic: str, lag: int, oldest_age_seconds: float = 0.0) -> None:
    name = clamp_topic(topic)
    _KAFKA_LAG_STATE[name] = max(0, int(lag))
    KAFKA_LAG.labels(topic=name).set(max(0, int(lag)))
    age = max(0.0, float(oldest_age_seconds or 0.0))
    if int(lag) <= 0:
        age = 0.0
    KAFKA_OLDEST_LAG_SECONDS.labels(topic=name).set(age)


def total_kafka_lag() -> int:
    """全部受监 topic 的 lag 总和（0 当无数据/无消费者；不抛异常）。"""
    return sum(v for v in _KAFKA_LAG_STATE.values() if isinstance(v, int) and v > 0)


@_safe
def set_kafka_loop_alive(loop: str, alive: bool) -> None:
    name = clamp_label(loop, _LOOP_ALLOW, "other")
    KAFKA_LOOP_ALIVE.labels(loop=name).set(1 if alive else 0)


@_safe
def note_kafka_loop_restart(loop: str) -> None:
    name = clamp_label(loop, _LOOP_ALLOW, "other")
    KAFKA_LOOP_RESTARTS.labels(loop=name).inc()
    set_kafka_loop_alive(name, False)


@_safe
def observe_pipeline_stage(stage: str, seconds: float, result: str = "") -> None:
    st = clamp_label(stage, _STAGE_ALLOW, "ingest")
    PIPELINE_STAGE_SECONDS.labels(stage=st).observe(max(0.0, float(seconds or 0.0)))
    if result:
        inc_pipeline_result(st, result)


@_safe
def observe_pipeline_e2e(seconds: float, result: str = "success") -> None:
    res = clamp_label(result, _RESULT_ALLOW, "success")
    PIPELINE_E2E_SECONDS.labels(result=res).observe(max(0.0, float(seconds or 0.0)))


@_safe
def inc_pipeline_result(stage: str, result: str, n: int = 1) -> None:
    PIPELINE_RESULTS.labels(
        stage=clamp_label(stage, _STAGE_ALLOW, "ingest"),
        result=clamp_label(result, _RESULT_ALLOW, "success"),
    ).inc(max(1, int(n)))


@_safe
def record_retry(reason: str = "transient", n: int = 1) -> None:
    RETRY_TOTAL.labels(reason=clamp_reason(reason)).inc(max(1, int(n)))


def _sync_dlq_gauges() -> None:
    DLQ_DEPTH.set(len(_DLQ_OPEN))
    if _DLQ_OPEN:
        oldest = min(_DLQ_OPEN.values())
        DLQ_OLDEST_WAIT_SECONDS.set(max(0.0, time.time() - oldest))
    else:
        DLQ_OLDEST_WAIT_SECONDS.set(0)
    evaluate_core_alerts()


@_safe
def note_dlq_open(record_id: int, first_failed_epoch: float) -> None:
    rid = int(record_id)
    if rid <= 0:
        return
    _DLQ_OPEN[rid] = float(first_failed_epoch or time.time())
    _sync_dlq_gauges()


@_safe
def note_dlq_closed(record_id: int) -> None:
    _DLQ_OPEN.pop(int(record_id), None)
    _sync_dlq_gauges()


@_safe
def record_dlq_persisted(reason: str, wait_seconds: float = 0.0,
                         record_id: int = 0, first_failed_epoch: float = 0.0) -> None:
    DLQ_MESSAGES.labels(reason=clamp_reason(reason)).inc()
    DLQ_WAIT_SECONDS.observe(max(0.0, float(wait_seconds or 0.0)))
    if record_id:
        note_dlq_open(record_id, first_failed_epoch or (time.time() - max(0.0, wait_seconds)))
    evaluate_core_alerts()


@_safe
def record_detection(detector: str, outcome: str, seconds: float = 0.0) -> None:
    """记录一次检测调用的**耗时**与**五态结果**。

    ## 为什么 outcome 必须能表达 inconclusive

    整改方案 §二要求区分「真实阴性 / 不可判定 / 执行失败 / 部分成功」，
    §十一进一步要求监控能区分它们。只暴露 detected / not_detected 两个值时，
    「不可判定」只能被塞进其中一个 —— 塞进 not_detected 会让准确率虚高，
    塞进 detected 会误报，两者都不会报错。所以这里用 detection_contract
    的五态原词，不做归并。

    ## detector 必须低基数

    调用方若传了规则 id / src_ip 之类，会被 clamp 到 "other"。
    这不是保守而是对的：高基数标签会把监控系统本身打满
    （见本文件顶部说明）。
    """
    det = clamp_label(detector, _DETECTOR_ALLOW, "other")
    DETECTION_SECONDS.labels(detector=det).observe(max(0.0, float(seconds or 0.0)))
    DETECTION_OUTCOMES.labels(
        detector=det,
        outcome=clamp_label(outcome, _DETECTION_OUTCOME_ALLOW, "error"),
    ).inc()


@_safe
def record_work_order_approve(result: str) -> None:
    """记录一次工单审批的结果。

    `failed` 值得单独一档：审批**已经写进数据库**了，
    但审批后的推进步骤（把案例推到 responding）抛了异常 ——
    修复前它只有一行 warning 日志，
    指标上与「审批通过」完全同形。
    """
    WORK_ORDER_APPROVE.labels(
        result=clamp_label(result, _WORK_ORDER_APPROVE_ALLOW, "failed"),
    ).inc()


@_safe
def record_kafka_alert_publish(result: str) -> None:
    """记录一次告警发布的**结果**。

    四种失败（未启动 / schema 拒收 / 盖章加密异常 / broker 发送失败）
    修复前**全部**只留一行日志 —— 告警就此消失，
    而原始事件路径的同类拒收**是有计数的**
    （`record_ingest("kafka","validation_failed",...)`）。
    这个不对称意味着：**丢告警比丢原始事件更难被发现**。
    """
    KAFKA_ALERT_PUBLISH.labels(
        result=clamp_label(result, _KAFKA_ALERT_RESULT_ALLOW, "error"),
    ).inc()


@_safe
def record_case_auto_dispatch(result: str) -> None:
    """记录一次案例自动派单的结果。

    三个取值：
      · `ok`      —— 已派单（或已有工单，只补齐状态）
      · `skipped` —— 不需要派单（优先级不够）
      · `failed`  —— **派单失败**：案例已建好却没有工单

    `failed` 与 `skipped` 分开是关键：修复前二者都是「没有工单」，
    而只有前者需要人介入。
    """
    CASE_AUTO_DISPATCH.labels(
        result=clamp_label(result, _CASE_DISPATCH_RESULT_ALLOW, "failed"),
    ).inc()


@_safe
def record_response_grounding_gate(state: str) -> None:
    """记录一次响应动作的 grounding 闸门状态。

    2026-10-20（整改报告 §9.51）：这道闸门此前**永远不会触发** ——
    `grounding_score` 在整个 `response_engine` 包里只出现在闸门自己，
    没有任何生产代码传它；而动作函数也不转发 `**kwargs`，
    就算传了也会在半路丢掉。**而审计里却记成「通过、满分」。**

    现在把三种状态分开计数：`not_evaluated` 是最重要的一档 ——
    它说明「这道闸门此刻没有提供任何保护」。
    """
    if state not in ("evaluated_pass", "evaluated_block", "not_evaluated"):
        state = "not_evaluated"
    RESPONSE_GROUNDING_GATE.labels(state=state).inc()


@_safe
def record_response_idempotency_check(state: str) -> None:
    """记录一次响应动作的幂等检查状态。

    2026-10-20（整改报告 §9.52）：`SafeExecutor._idempotency_check` 是
    **纯 Redis** 的（而同一事务的回滚侧 `RollbackStore` 是「内存为主、
    Redis 兜底」）→ Redis 故障时**执行侧**的幂等保护**整体消失**，
    而此前审计里只记 `{"hit": False}` —— **看不出这道检查当时没跑**。
    """
    if state not in ("evaluated_hit", "evaluated_miss", "unavailable"):
        state = "unavailable"
    RESPONSE_IDEMPOTENCY_CHECK.labels(state=state).inc()


@_safe
def record_auto_unblock_scheduled(action: str) -> None:
    """记录一次「自动解封已调度」（用的是扛不住重启的进程内机制）→ §9.53。

    这个计数的意义：**有多少条封禁正依赖那个扛不住重启的机制** ——
    也就是「一次发布会让多少条封禁失去自动解封」。
    """
    AUTO_UNBLOCK_SCHEDULED.labels(action=action or "unknown").inc()


@_safe
def record_response_audit_failed(phase: str) -> None:
    """记录一次响应动作审计失败（写失败 / 查询失败）→ §9.55。

    写侧失败的后果是「动作发生了但审计里没有这条」——
    这是**审计缺口**，必须能被数出来（§十一.1：运行错误要单独计数）。
    """
    if phase not in ("threat", "action", "query"):
        phase = "unknown"
    RESPONSE_AUDIT_FAILED.labels(phase=phase).inc()


@_safe
def record_response_policy_load_failed(reason: str = "unknown") -> None:
    """记录一次响应策略文件加载失败 → §9.56。

    这个计数的意义：**有几条响应规则此刻根本没生效** ——
    少一条 = 有一条本该拦的威胁不被拦。
    """
    if reason not in ("parse", "invalid", "load_failed"):
        reason = "unknown"
    RESPONSE_POLICY_LOAD_FAILED.labels(reason=reason).inc()


@_safe
def record_reputation_prior_lookup_failed() -> None:
    """记录一次信誉先验读取失败 → §9.57。

    这个计数的意义：**有多少次检测的评分少掉了一个先验修正**。
    """
    REPUTATION_PRIOR_LOOKUP_FAILED.inc()


@_safe
def record_tls_session_evicted(n: int = 1) -> None:
    """记录一次因挂起缓冲区溢出而被驱逐的 TLS 会话。

    这是一个**背压信号**：它说明这一刻并发握手数超过了
    `_MAX_PENDING`，有一批会话被**提前**收走（已落库，但不再等
    完整的 ServerHello/Certificate）。

    修复前这条路径**既不落库也不计数** —— 证据静默消失，
    而 `stats` 也没有消费方，于是「高峰期在丢会话」这件事
    在指标和日志里都**看不见**。
    """
    TLS_SESSION_EVICTED.inc(max(1, int(n)))


@_safe
def set_eventbus_queue_depth(critical: int = 0, bulk: int = 0) -> None:
    EVENTBUS_QUEUE_DEPTH.labels(lane="critical").set(max(0, int(critical)))
    EVENTBUS_QUEUE_DEPTH.labels(lane="bulk").set(max(0, int(bulk)))


@_safe
def inc_eventbus_disconnect(n: int = 1) -> None:
    EVENTBUS_DISCONNECTS.inc(max(1, int(n)))


@_safe
def inc_eventbus_catchup(n: int = 1) -> None:
    if int(n) <= 0:
        return
    EVENTBUS_CATCHUP.inc(int(n))


@_safe
def record_cache(cache: str, result: str, n: int = 1) -> None:
    CACHE_REQUESTS.labels(
        cache=clamp_label(cache, _CACHE_ALLOW, "event_store"),
        result=clamp_label(result, _RESULT_ALLOW, "miss"),
    ).inc(max(1, int(n)))


@_safe
def record_cache_invalidate_failure(cache: str = "event_store") -> None:
    CACHE_INVALIDATE_FAILURES.labels(
        cache=clamp_label(cache, _CACHE_ALLOW, "event_store"),
    ).inc()


@_safe
def record_shutdown_leftover(
    component: str,
    leftover: int = 0,
    *,
    spilled: int = 0,
    lost: int = 0,
) -> None:
    comp = clamp_label(component, _COMPONENT_ALLOW, "other")
    total = max(0, int(leftover or 0))
    LIFECYCLE_LEFTOVER.labels(component=comp).set(total)
    if int(spilled) > 0:
        LIFECYCLE_LEFTOVER_TOTAL.labels(component=comp, disposition="spilled").inc(int(spilled))
    if int(lost) > 0:
        LIFECYCLE_LEFTOVER_TOTAL.labels(component=comp, disposition="lost").inc(int(lost))
        record_unexpected_drop("audit_volatile" if comp == "audit_worker" else "other", n=int(lost))
    elif total > 0 and int(spilled) <= 0 and int(lost) <= 0:
        LIFECYCLE_LEFTOVER_TOTAL.labels(component=comp, disposition="leftover").inc(total)
    evaluate_core_alerts()


@_safe
def note_eventbus_drop(lane: str, n: int = 1) -> None:
    _fire_alert("SocEventBusDrop", True, f"lane={lane} n={n}")
    if clamp_label(lane, _LANE_ALLOW, "bulk") == "critical":
        record_unexpected_drop("eventbus_critical", n=n)


@_safe
def record_unexpected_drop(kind: str, n: int = 1) -> None:
    count = max(1, int(n))
    UNEXPECTED_DROPS.labels(kind=clamp_label(kind, _KIND_ALLOW, "other")).inc(count)
    _fire_alert("SocUnexpectedDrop", True, f"kind={kind} n={count}")
    if kind == "eventbus_critical":
        _fire_alert("SocEventBusDrop", True, f"critical drop n={count}")


def _fire_alert(name: str, active: bool, detail: str = "") -> None:
    if name not in _ALERT_NAMES:
        return
    CORE_ALERTS_ACTIVE.labels(alert=name).set(1 if active else 0)
    was = _ALERT_STATE.get(name, 0)
    _ALERT_STATE[name] = 1 if active else 0
    if active and not was:
        logger.error("core.alert.firing alert=%s %s", name, detail)


@_safe
def evaluate_core_alerts() -> None:
    """根据当前 Gauge 刷新进程内告警状态。丢弃类告警在发生时立即 fire。"""
    depth = 0.0
    try:
        depth = float(DLQ_DEPTH._value.get())  # type: ignore[attr-defined]
    except Exception:
        depth = float(len(_DLQ_OPEN))
    _fire_alert("SocDlqBacklog", depth > 0, f"depth={int(depth)}")

    leftover = 0.0
    for comp in _COMPONENT_ALLOW:
        try:
            leftover += float(LIFECYCLE_LEFTOVER.labels(component=comp)._value.get())  # type: ignore
        except Exception:
            continue
    _fire_alert("SocShutdownLeftoverTasks", leftover > 0, f"leftover={int(leftover)}")


async def refresh_dlq_gauges_from_db() -> None:
    """用数据库校正 DLQ 深度（进程重启后内存为空）。失败静默。"""
    try:
        from datetime import timezone
        from sqlalchemy import select
        from models import DlqRecord, async_session

        async with async_session() as session:
            rows = (await session.execute(
                select(DlqRecord.id, DlqRecord.first_failed_at).where(
                    DlqRecord.replay_status.in_(("pending", "replaying", "replay_failed"))
                )
            )).all()
        _DLQ_OPEN.clear()
        now = time.time()
        for rid, ts in rows:
            if rid is None:
                continue
            epoch = now
            if ts is not None:
                if getattr(ts, "tzinfo", None) is None:
                    ts = ts.replace(tzinfo=timezone.utc)
                epoch = ts.timestamp()
            _DLQ_OPEN[int(rid)] = epoch
        _sync_dlq_gauges()
    except Exception:
        return


def assert_no_high_cardinality_labels() -> list[str]:
    """测试用：所有本模块指标的标签名不得包含 event_id 等。"""
    offenders = []
    for metric in (
        INGEST_RECEIVED, INGEST_REJECTED, INGEST_VALIDATION_FAILED,
        KAFKA_LAG, KAFKA_OLDEST_LAG_SECONDS, KAFKA_LOOP_ALIVE, KAFKA_LOOP_RESTARTS,
        PIPELINE_E2E_SECONDS, PIPELINE_STAGE_SECONDS, PIPELINE_RESULTS,
        DLQ_MESSAGES, RETRY_TOTAL,
        DETECTION_SECONDS, DETECTION_OUTCOMES,
        EVENTBUS_QUEUE_DEPTH, CACHE_REQUESTS, CACHE_INVALIDATE_FAILURES,
        LIFECYCLE_LEFTOVER, LIFECYCLE_LEFTOVER_TOTAL, UNEXPECTED_DROPS,
        CORE_ALERTS_ACTIVE,
    ):
        names = [str(n).lower() for n in getattr(metric, "_labelnames", ())]
        bad = [n for n in names if n in _FORBIDDEN_LABEL_NAMES]
        if bad:
            offenders.append(f"{metric._name}:{bad}")
    return offenders
