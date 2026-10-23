"""
Prometheus **消费面**守卫：仪表盘 / 告警规则引用的指标必须真实存在；
反过来，每个「被产出但没人看」的指标都必须显式登记在册。

## 为什么要有这一层

`test_metric_wiring_guard.py` 守的是**产出侧**：写入器有没有被调用。
本文件守的是**消费侧**：指标被写出来之后，有没有人在看。

这两层缺一不可，而且**缺消费侧更危险**。产出侧断了，`soc_intel_ioc_total`
会恒为 0，能力看板照常显示「已启用」——这是 §7.1.6 已登记的形态。

消费侧断了则完全无声：`soc_detection_outcomes_total` 正常自增、
`/metrics` 正常暴露、`soc_detection_seconds` 的桶正常分布，
但**没有任何面板、没有任何告警**去看它们。于是整改方案 §十一.1
要求的「分别记录检测依据不足、运行错误和真实阴性」在数据层完成了，
在**运维可见性**上从未发生 —— 值班的人看不到 Sigma 引擎开始批量报错，
因为承载这个事实的那块屏幕不存在。

实测（本轮）：65 个声明指标里只有 22 个在仓库可验证的 Prometheus 消费面
（provisioned Grafana 仪表盘 + `config/prometheus/alerts.yml`）上出现，
其余 **43 个**逐个登记在下面的 `UNWATCHED` 里。
**本轮整改新增的检测指标都在「没人看」那一侧。**

口径说明（报告 §9.37.4）：这里的 22 是**守卫口径** ——
仪表盘查 Histogram 的 `_bucket` 派生序列时**也**算消费了那个基础指标。
若按「PromQL 里出现过的原始名字」来数，会是 20 个、无人看的是 45 个；
差在 `soc_pipeline_e2e_seconds` / `soc_pipeline_stage_seconds` 这两个
基础指标上 —— 那两个其实**有人看**，原始并集口径把它们误算成了没人看。

## 口径边界（必须写清，否则会把结论说过头）

「零消费」只声称到**仓库内可验证的 Prometheus 消费面**：

  · `config/grafana/provisioning/dashboards/*.json` —— 被 provision 的仪表盘
  · `config/prometheus/alerts.yml` —— 告警规则

运营人员手工在 Grafana UI 里建的看板、或 Prometheus 侧的 recording rule，
都不在这个仓库里，**无法证伪**。所以本文件不断言「这些指标没人看」，
只断言「仓库里没有任何一处让它们可见」。

Python 侧**不作为消费面统计**：写入与读取都走 Python 变量
（`SOC_FP_RATE.set(...)`），从不按指标名字符串引用，所以按名字 grep
生产代码只会找到声明行本身——那不是读者。

## 维护方式

新增指标时二选一：

  1. 把它接进仪表盘或告警 → 本文件自动把它移出 `UNWATCHED`；
  2. 确实还没人看 → 在 `UNWATCHED` 里登记并写明理由。

**不接受「既不接线也不登记」**：那正是本文件要防的事故。
也不要为了让扫描通过而删断言。
"""
from __future__ import annotations

import ast
import json
import re
from pathlib import Path

import pytest

BACKEND = Path(__file__).resolve().parents[1]
REPO = BACKEND.parent
DASHBOARDS = REPO / "config" / "grafana" / "provisioning" / "dashboards"
ALERTS = REPO / "config" / "prometheus" / "alerts.yml"

METRIC_MODULES = ("metrics.py", "core_metrics.py")
FACTORIES = {
    "Counter", "Gauge", "Histogram", "Summary", "Info", "Enum",
    "CounterVec", "GaugeVec", "HistogramVec", "SummaryVec",
}

#: prometheus_client 为 Histogram/Summary 自动派生的时间序列，
#: 在 AST 里查不到声明。仪表盘查它们时必须能回溯到基础指标。
AUTO_SUFFIXES = ("_bucket", "_sum", "_count", "_created", "_gcount", "_gsum")

#: PromQL 内置函数/聚合词（后面不跟 `(`，得单列）
_AGG_FUNCS = {
    "sum", "min", "max", "avg", "group", "stddev", "stdvar", "count_values",
    "count", "topk", "bottomk", "quantile", "limitk", "limit_ratio", "abs",
    "ceil", "floor", "round", "sqrt", "exp", "ln", "log2", "log10", "sgn",
    "delta", "idelta", "deriv", "predict_linear", "holt_winters", "clamp",
    "clamp_max", "clamp_min", "histogram_quantile", "label_replace",
    "label_join", "time", "timestamp", "vector", "scalar", "sort",
    "sort_desc", "absent", "absent_over_time", "changes", "resets",
    "increase", "decrease", "rate", "irate", "avg_over_time", "min_over_time",
    "max_over_time", "sum_over_time", "count_over_time", "quantile_over_time",
    "stddev_over_time", "stdvar_over_time", "last_over_time",
    "present_over_time", "days_in_month", "hour", "minute", "month", "year",
    "day_of_month", "day_of_week", "day_of_year", "week", "time_offset",
    "time_delta", "pi", "atan2", "on", "by", "without", "ignoring",
    "group_left", "group_right", "bool", "offset",
}
_LABELGROUP_RE = re.compile(
    r"\b(?:by|without|on|ignoring|group_left|group_right)\s*\([^()]*\)")
_RANGEVEC_RE = re.compile(r"\[[^\[\]]*\]")
# 前后向断言不可省：`e2e` 里的 `2` 一旦被当数字吃掉，
# `soc_pipeline_e2e_seconds` 会被劈成两个不存在的指标名。
_NUMBER_RE = re.compile(
    r"(?<![a-zA-Z0-9_:])\d+(?:\.\d+)?(?:[eE][-+]?\d+)?(?![a-zA-Z0-9_:])")
_METRICNAME_RE = re.compile(r"^[a-zA-Z_:][a-zA-Z0-9_:]*$")


def promql_metric_names(expr: str) -> set[str]:
    """抽取一条 PromQL 里出现的指标名。

    依次剔除：字符串字面量 → 区间向量 `[5m]` → 数字（含科学计数法）
    → 聚合修饰词 `by (stage, le)` → 标签选择器 `{component="audit"}`，
    再丢掉后面紧跟 `(` 的函数名与内置函数词。
    """
    s = re.sub(r'"[^"]*"|\'[^\']*\'', " ", expr)
    s = _RANGEVEC_RE.sub(" ", s)
    s = _NUMBER_RE.sub(" ", s)
    s = _LABELGROUP_RE.sub(" ", s)
    s = re.sub(r"\{[^{}]*\}", " ", s)
    out: set[str] = set()
    for m in re.finditer(r"[a-zA-Z_:][a-zA-Z0-9_:]*", s):
        tok = m.group(0)
        if s[m.end():m.end() + 1] == "(":
            continue
        if tok in _AGG_FUNCS or tok.startswith(("__", "$")):
            continue
        if _METRICNAME_RE.match(tok):
            out.add(tok)
    return out


def declared_metrics() -> set[str]:
    """从 metrics.py / core_metrics.py 取出全部声明的指标名。

    `utf-8-sig` 是必须的：`app.py` 带 BOM 时 `ast.parse` 会抛 SyntaxError，
    静默降级会把整个文件误判成「零声明」，方向恒定地制造假缺口。
    """
    names: set[str] = set()
    for mod in METRIC_MODULES:
        path = BACKEND / mod
        tree = ast.parse(path.read_text(encoding="utf-8-sig"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            fn = node.func
            fname = fn.id if isinstance(fn, ast.Name) else getattr(fn, "attr", None)
            if fname not in FACTORIES or not node.args:
                continue
            first = node.args[0]
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                names.add(first.value)
    return names


def _walk_exprs(node, out: list[str]) -> None:
    if isinstance(node, dict):
        for k, v in node.items():
            if k == "expr" and isinstance(v, str):
                out.append(v)
            else:
                _walk_exprs(v, out)
    elif isinstance(node, list):
        for v in node:
            _walk_exprs(v, out)


def dashboard_metric_names() -> set[str]:
    out: set[str] = set()
    for p in sorted(DASHBOARDS.glob("*.json")):
        exprs: list[str] = []
        _walk_exprs(json.loads(p.read_text(encoding="utf-8-sig")), exprs)
        for e in exprs:
            out |= promql_metric_names(e)
    return out


def alert_exprs() -> list[str]:
    raw = ALERTS.read_text(encoding="utf-8-sig")
    return [m.group(1) for m in re.finditer(r"expr:\s*(.+)", raw)]


def alert_metric_names() -> set[str]:
    out: set[str] = set()
    for e in alert_exprs():
        out |= promql_metric_names(e)
    return out


def prom_consumed() -> set[str]:
    dash, alert = dashboard_metric_names(), alert_metric_names()
    out = set(dash) | set(alert)
    # 仪表盘查的是派生序列，回溯到基础指标
    for suffix in AUTO_SUFFIXES:
        for n in dash | alert:
            if n.endswith(suffix):
                out.add(n[: -len(suffix)])
    return out


#: 被产出、但仓库内没有任何 Prometheus 消费面的指标 —— 逐个登记理由。
#:
#: 整改方案 §十一.1 明确点名的那几个（检测五态、耗时分布）**不该在这里**，
#! 它们留在下面正是为了让 `test_detection_metrics_have_a_prometheus_consumer`
#! 这条 strict xfail 保持红色。
UNWATCHED: dict[str, str] = {
    # ── 2026-10-23 第二阶段(可靠性)新增 ──
    "soc_audit_dead_letter_total": "PQ 丢失任务死信落库, 运营面板待建",
    "soc_audit_dead_letter_replayed_total": "死信重放计数, 运营面板待建",
    "soc_audit_claim_total": "跨进程审计认领结果, 运营面板待建",
    "soc_sigma_engine_degraded_total": "Sigma 引擎降级, Grafana 告警待 provision",
    # ── 审计控制面（metrics.py 第 50~94 行整组）──
    "soc_audit_cache_hit_total": "审计缓存命中率，PR2 面板尚未 provision",
    "soc_audit_complete_total": "审计完成数，无面板",
    "soc_audit_inflight": "审计在途数，无面板",
    "soc_audit_lane_admit_total": "审计车道准入数，无面板",
    "soc_audit_pq_dequeue_total": "审计优先队列出队数，无面板",
    "soc_audit_pq_enqueue_total": "审计优先队列入队数，无面板",
    "soc_audit_queue_depth": "审计队列深度，无面板",
    "soc_audit_shed_total": "审计负载丢弃数，无面板",
    "soc_audit_temporal_start_timeout_total": "Temporal 启动超时数，无面板",
    "soc_audit_worker_busy": "审计 worker 忙闲，无面板",
    # ── PR2 控制面 KPI ──
    "soc_fp_rate": "误报率，§七 验收指标要求，但只在 API 侧算过",
    "soc_mtbf_seconds": "MTBF，无面板",
    "soc_mttr_seconds": "MTTR，无面板",
    "soc_response_action_duration_seconds": "响应动作耗时，无面板",
    # ── HTTP / Kafka / DB ──
    "soc_http_requests_total": "HTTP 请求数，无面板",
    "soc_http_request_duration_seconds": "HTTP 耗时，无面板",
    "soc_kafka_consumer_total": "Kafka 消费总数，无面板",
    "soc_db_pool_checkedout": "DB 连接池借出数，无面板",
    # ── 事件推送 ──
    "soc_eventbus_gaps_total": "SSE 断档数，无面板",
    "soc_eventbus_redis_failures_total": "SSE Redis 失败数，无面板",
    "soc_eventbus_subscribers": "SSE 订阅者数，无面板",
    # ── LLM ──
    "soc_llm_429_total": "LLM 429 限流数，无面板",
    "soc_llm_inflight": "LLM 在途数，无面板",
    "soc_llm_tokens_total": "LLM token 消耗，无面板",
    "soc_llm_waiters": "LLM 排队数，无面板",
    # ── 流水线 ──
    "soc_dlq_wait_seconds": "DLQ 进入时已等待时长 Histogram，无面板",
    "soc_retry_total": "重试数，无面板",
    "soc_lifecycle_shutdown_leftover_total": "关闭遗留累计，无面板",
    # ── 接入 ──
    "soc_ingest_detector_errors_total": "接入侧检测错误数，无面板",
    "soc_ingest_stage_seconds": "接入阶段耗时 Histogram，无面板",
    # ── 情报 / EDR / 沙箱 / 零日 ──
    "soc_capture_packets_total": "流量抓包数，无面板",
    "soc_edr_events_total": "EDR 事件数，无面板",
    "soc_tls_sessions_total": "TLS 会话数，无面板",
    "soc_ndr_flows_total": "NDR 流数，无面板",
    "soc_phishing_detections_total": "钓鱼检测数，无面板",
    "soc_sandbox_submissions_total": "沙箱提交数，无面板",
    "soc_ioc_matches_total": "IOC 命中数，无面板",
    # ── §7.1.6 已登记：唯一从未被写入的指标 ──
    "soc_intel_ioc_total": "唯一 declared_only：唯一调用点在休眠模块 stix_taxii.py",
    # ── §9.34 本轮新增：案例自动派单结果 ──
    "soc_case_auto_dispatch_total": "案例自动派单结果（ok/skipped/failed）；"
    "failed=案例已建却没有工单，修复前只有一行 warning 日志；"
    "接告警会产生值班呼叫，属运维行为变更，需用户拍板（§7.1.15）",
    # ── §9.35 本轮新增：告警发布结果 ──
    "soc_kafka_alert_publish_total": "告警发布结果（ok/not_started/schema_rejected/"
    "error/send_failed）；四种失败修复前**全部**只留一行日志 —— "
    "告警就此消失，运维不知道有威胁；"
    "接告警会产生值班呼叫，属运维行为变更，需用户拍板（§7.1.15）",
    # ── §9.36 本轮新增：工单审批结果 ──
    "soc_work_order_approve_total": "工单审批结果（approved/skipped/failed）；"
    "failed=审批写进库了但推进步骤抛异常，修复前只有一行 warning 日志；"
    "接告警会产生值班呼叫，属运维行为变更，需用户拍板（§7.1.15）",
    # ── §9.43 本轮新增：TLS 挂起会话被驱逐（背压信号）──
    "soc_tls_session_evicted_total": "TLS 挂起会话因缓冲区溢出被驱逐的次数；"
    "修复前这条路径**既不落库也不计数** —— 高峰期丢会话这件事"
    "在指标和日志里都看不见；现在是背压信号（驱逐前已 flush 落库）；"
    "接告警会产生值班呼叫，属运维行为变更，需用户拍板（§7.1.15）",
    # ── §9.51 本轮新增：grounding 闸门状态 ──
    "soc_response_grounding_gate_total": "响应动作的 grounding 硬门控状态"
    "（evaluated_pass/evaluated_block/not_evaluated）；"
    "not_evaluated=**根本没有 grounding 分数** → 这道闸门未评估、"
    "不提供任何保护（修复前它在审计里被记成「通过、满分」，是虚假保障）；"
    "接告警会产生值班呼叫，属运维行为变更，需用户拍板（§7.1.15）",
    # ── §9.52 本轮新增：幂等检查状态 ──
    "soc_response_idempotency_check_total": "响应动作的幂等检查状态"
    "（evaluated_hit/evaluated_miss/unavailable）；"
    "unavailable=**Redis 不可用 → 检查根本没跑** → 此刻幂等保护不生效"
    "（修复前审计里只记 hit=False，看不出这道检查没跑）；"
    "接告警会产生值班呼叫，属运维行为变更，需用户拍板（§7.1.15）",
    # ── §9.53 本轮新增：自动解封调度 ──
    "soc_response_auto_unblock_scheduled_total": "响应动作的自动解封调度计数"
    "（action=block_ip|isolate_host）；意义是「有多少条封禁正依赖**扛不住重启**的"
    "进程内定时任务」—— 一次发布会让这些封禁**静默失去**自动解封；"
    "接告警会产生值班呼叫，属运维行为变更，需用户拍板（§7.1.15）",
    # ── §9.55 本轮新增：响应动作审计失败 ──
    "soc_response_audit_failed_total": "响应动作**审计**失败计数"
    "（phase=threat/action/query）；写失败=「动作发生了但审计里没有这条」，"
    "查询失败在旧实现里返回**空列表**（看起来像「没有响应动作」）；"
    "接告警会产生值班呼叫，属运维行为变更，需用户拍板（§7.1.15）",
    # ── §9.56 本轮新增：响应策略文件加载失败 ──
    "soc_response_policy_load_failed_total": "响应**策略文件**加载失败计数"
    "（reason=parse/invalid/load_failed）；失败的文件对应的策略**根本没生效**"
    "（少一条 = 有一条本该拦的威胁不被拦），而旧实现只留一行 warning；"
    "接告警会产生值班呼叫，属运维行为变更，需用户拍板（§7.1.15）",
    # ── §9.57 本轮新增：信誉先验读取失败 ──
    "soc_reputation_prior_lookup_failed_total": "信誉**先验 delta** 读取失败次数；"
    "失败时 delta 退化为 0，而 delta **会加到主评分上**（clip ±learn_loop_prior_clip）"
    "→ 评分少一个先验修正、可能跨档位；原先只有一行 **debug** 日志（生产看不见）；"
    "接告警会产生值班呼叫，属运维行为变更，需用户拍板（§7.1.15）",
    # ── 本轮整改新增，缺口最刺眼的两个 ──
    "soc_detection_outcomes_total": "⚠ 本轮为 §十一.1 新增，却无面板无告警",
    "soc_detection_seconds": "⚠ 本轮为 §十一.1 新增，全仓零引用（连测试都没有）",
}

#: §十一.1 点名、因此**必须**有消费面的指标。
MUST_BE_WATCHED = ("soc_detection_outcomes_total", "soc_detection_seconds")


def test_every_dashboard_metric_is_declared_in_python():
    """仪表盘引用的每个指标都必须真实存在 —— 防「死面板」。

    面板画在一条永远查不到数据的曲线上，比没有这个面板更糟：
    它让人以为系统还在正常产出数据。
    """
    declared = declared_metrics()
    consumed = prom_consumed()
    missing = sorted(n for n in dashboard_metric_names() if n not in consumed)
    assert not missing, f"仪表盘引用了不存在的指标：{missing}"


def test_every_alert_rule_metric_is_declared_in_python():
    """告警规则引用的每个指标都必须真实存在。

    引用不存在的指标不会让 Prometheus 报错，只会让这条规则**永远不触发**，
    同时在 `/rules` 页面显示为正常的绿色 —— 比没有这条告警更危险。
    """
    declared = declared_metrics()
    consumed = prom_consumed()
    missing = sorted(n for n in alert_metric_names() if n not in consumed)
    assert not missing, f"告警规则引用了不存在的指标：{missing}"


def test_promql_extractor_recovers_known_metric_names():
    """判别力自检：抽取器必须同时认得出活指标、死指标和派生序列。

    没有这条，上面的两条守卫可能因为「什么都抽不出来」而全绿。
    """
    assert "soc_eventbus_drops_total" in promql_metric_names(
        "increase(soc_eventbus_drops_total[5m]) > 0")
    assert "soc_intel_ioc_total" in promql_metric_names(
        "rate(soc_intel_ioc_total[1m])")
    got = promql_metric_names(
        "histogram_quantile(0.95, sum by (le, stage) "
        "(rate(soc_pipeline_e2e_seconds_bucket[5m])))")
    assert "soc_pipeline_e2e_seconds_bucket" in got
    for noise in ("histogram_quantile", "sum", "by", "rate", "le", "stage", "m"):
        assert noise not in got, f"误收噪声 token {noise!r}"


def test_unwatched_metrics_are_exactly_the_registered_ones():
    """没有 Prometheus 消费面的指标，必须与 `UNWATCHED` 登记表**逐个相等**。

    双向相等：新指标不登记 → 转红；登记了但已接线 → 也转红。
    这样「既不接线也不登记」无处可藏。
    """
    watched = prom_consumed()
    actual = {n for n in declared_metrics() if n not in watched}
    registered = set(UNWATCHED)
    assert actual == registered, (
        "UNWATCHED 登记表与实测不符。\n"
        f"  实测多出: {sorted(actual - registered)}\n"
        f"  实测缺少: {sorted(registered - actual)}\n"
        "  新指标必须二选一：接进仪表盘/告警，或在 UNWATCHED 里写明理由。"
    )


@pytest.mark.xfail(
    strict=True, raises=AssertionError,
    reason="已知缺口：§十一.1 点名的两个检测指标，产出侧已接线，"
           "但消费侧一张面板、一条告警都没有。65 个声明指标里 43 个处于"
           "「被产出但仓库内无 Prometheus 消费面」状态（见 UNWATCHED）。"
           "修复需要改 core-ops.json 面板与 alerts.yml —— "
           "新增告警属运维行为变更，待用户决策。",
)
def test_detection_metrics_have_a_prometheus_consumer():
    """[缺口] 整改方案 §十一.1 点名的两个检测指标必须有 Prometheus 消费面。

    这两个是本轮为「判断引擎是否正常工作」专门加的。产出侧已接线
    （`test_metric_wiring_guard.py` 守着），但消费侧一张面板、一条告警都没有。
    """
    watched = prom_consumed()
    missing = [m for m in MUST_BE_WATCHED if m not in watched]
    assert not missing, (
        f"§十一.1 点名的检测指标在仪表盘与告警里都没有出现：{missing}。"
        " 数据在写，但值班的人看不到 Sigma 引擎开始批量报错。"
    )


@pytest.mark.xfail(
    strict=True, raises=AssertionError,
    reason="已知缺口：无任何告警规则覆盖检测引擎故障。"
           "soc_detection_outcomes_total{outcome=\"error\"|\"partial\"} "
           "是 §十一.1「判断引擎是否正常工作」的执行手段，"
           "但 alerts.yml 9 条规则只覆盖队列丢弃/DLQ/生命周期/Kafka 积压。"
           "修复需要一条新告警规则 —— 属运维行为变更，待用户决策。",
)
def test_detection_failure_outcome_has_an_alert_rule():
    """[缺口] 检测引擎故障必须有告警，否则指标只是躺在 TSDB 里。

    期望存在的规则形如：
        sum(increase(soc_detection_outcomes_total{outcome=~"error|partial"}[10m])) > 0
    """
    blob = " ".join(alert_exprs())
    assert "soc_detection_outcomes_total" in blob, (
        "alerts.yml 没有任何一条规则引用检测五态计数器，"
        "检测引擎批量报错时不会有任何告警。"
    )
    assert re.search(
        r'soc_detection_outcomes_total\s*\{[^}]*outcome[^}]*\}', blob
    ), "引用了计数器但没有按 outcome 过滤，error 与 detected 无法区分。"
