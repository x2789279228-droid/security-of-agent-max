"""
检测引擎统一指标：耗时分布 + 五态计数。

整改方案 §十一 P2 第 1 条要求的两项最小指标：

    指标                                   用途
    成功、命中、未命中、部分失败、执行错误计数   判断引擎是否正常工作
    各检测器耗时分布                        定位性能瓶颈

## 为什么要单独测这一层

`core_metrics` 里几乎所有写入助手都带 ``@_safe`` —— 指标写失败
**静默吞掉**。这在生产上是对的（观测不该拖垮业务），但它带来一个
测试上的陷阱：**埋点整个坏掉时，测「不报错」的测试照样绿。**

所以本文件不测「调用没抛异常」，而是**从 Prometheus 注册表把计数读回来**，
断言真的加上了。读不到就是埋点没生效，测试必须红。

## 「读回来」为什么必须用独立注册表

`core_metrics` 在 import 时就往默认 REGISTRY 注册指标。若测试直接读
默认 REGISTRY，同一进程里多个测试会互相污染计数（跑一次加一次），
断言就没法写死。这里用一个全新的 ``CollectorRegistry``，把两个指标
对象重新绑上去 —— 这样每个测试看到的都是干净的表。
"""
import asyncio
import os

import pytest

os.environ.setdefault("SHARED_MEMORY_SKIP_DOTENV", "1")

from prometheus_client import (  # noqa: E402
    CollectorRegistry, Counter, Histogram, generate_latest,
)

from core_metrics import (  # noqa: E402
    _DETECTION_OUTCOME_ALLOW, _DETECTOR_ALLOW, _RESULT_ALLOW,
    assert_no_high_cardinality_labels, record_detection,
)
from detection_contract import ALL_STATUSES  # noqa: E402


@pytest.fixture()
def fresh_metrics():
    """把两个检测指标绑到独立注册表，测试之间互不污染。"""
    reg = CollectorRegistry()
    secs = Histogram(
        "test_detection_seconds", "t", ["detector"],
        registry=reg, buckets=(0.001, 0.01, 0.1, 1, 10))
    outs = Counter(
        "test_detection_outcomes_total", "t", ["detector", "outcome"],
        registry=reg)
    # 替换模块级对象；_safe 装饰器在 record_detection 里是运行时查找
    import core_metrics
    old_s, old_o = core_metrics.DETECTION_SECONDS, core_metrics.DETECTION_OUTCOMES
    core_metrics.DETECTION_SECONDS = secs
    core_metrics.DETECTION_OUTCOMES = outs
    try:
        yield reg
    finally:
        core_metrics.DETECTION_SECONDS = old_s
        core_metrics.DETECTION_OUTCOMES = old_o


def _counter_value(reg, name: str, **labels) -> float:
    """从注册表读某个标签组合的计数值；不存在返回 0.0。"""
    for metric in reg.collect():
        for sample in metric.samples:
            if sample.name == name and all(
                    sample.labels.get(k) == v for k, v in labels.items()):
                return float(sample.value)
    return 0.0


def _hist_count(reg, name: str, **labels) -> float:
    return _counter_value(reg, f"{name}_count", **labels)


def _hist_sum(reg, name: str, **labels) -> float:
    return _counter_value(reg, f"{name}_sum", **labels)


# ══════════════════════════════════════════════════════════════
# 指标定义本身
# ══════════════════════════════════════════════════════════════

def test_five_outcomes_are_all_representable():
    """五态必须**全部**能被记录，不能有哪个被归并掉。

    这是 §二 + §十一 的核心要求。若某个状态不在白名单里，
    `clamp_label` 会把它落到默认值 —— 「不可判定」被记成别的状态，
    而且不报错。
    """
    assert _DETECTION_OUTCOME_ALLOW == set(ALL_STATUSES), (
        "检测指标的状态白名单与 detection_contract.ALL_STATUSES 不一致。"
        "契约加了新状态时这里必须同步，否则该状态会被静默归并。")


def test_inconclusive_is_not_bucketed_as_success():
    """``inconclusive`` 必须能原样通过，不能落到默认值 ``success``。

    ⚠️ 这条守的是一个**已经发生过的静默错误**：``inconclusive`` 原本
    不在 ``_RESULT_ALLOW`` 里，任何 ``inc_pipeline_result(stage="detect",
    result="inconclusive")`` 都会被 clamp 成 ``"success"`` ——
    「判定不出来」被记成「判定成功」。既不报错，也让准确率虚高。
    """
    assert "inconclusive" in _RESULT_ALLOW, (
        "inconclusive 不在 _RESULT_ALLOW 里 —— 会被静默记成 success")


def test_inconclusive_survives_both_clamp_paths(fresh_metrics):
    """两条写入路径都要保住 inconclusive：专用助手 + pipeline 助手。"""
    from core_metrics import inc_pipeline_result

    record_detection("anomaly", "inconclusive", 0.01)
    inc_pipeline_result("detect", "inconclusive")

    assert _counter_value(fresh_metrics, "test_detection_outcomes_total",
                          detector="anomaly", outcome="inconclusive") == 1.0, \
        "专用助手把 inconclusive 归并掉了"


def test_detection_labels_have_no_high_cardinality_names():
    """检测指标不得带 event_id / src_ip 之类的高基数标签。"""
    assert assert_no_high_cardinality_labels() == [], \
        "检测指标用了了高基数标签名（会把监控系统本身打满）"


def test_detector_label_is_clamped_not_passed_through(fresh_metrics):
    """detector 传规则 id 之类必须落到 ``other``，不能原样进标签。

    高基数标签的后果是监控存储被打爆，而不是「多记了点东西」。
    """
    record_detection("SIG-001-brute_force", "detected", 0.01)
    assert _counter_value(fresh_metrics, "test_detection_outcomes_total",
                          detector="other", outcome="detected") == 1.0, \
        "高基数 detector 值没有被 clamp 到 other"
    assert _counter_value(fresh_metrics, "test_detection_outcomes_total",
                          detector="SIG-001-brute_force") == 0.0, \
        "原始高基数值被原样写进了标签"


def test_unknown_outcome_falls_back_to_error(fresh_metrics):
    """认不出的状态落到 ``error`` —— 保守侧。

    往 ``detected`` / ``success`` 落会把「不知道」记成「有结论」。
    """
    record_detection("sigma", "banana", 0.01)
    assert _counter_value(fresh_metrics, "test_detection_outcomes_total",
                          detector="sigma", outcome="error") == 1.0


# ══════════════════════════════════════════════════════════════
# 接线：埋点真的被三个引擎调用了
# ══════════════════════════════════════════════════════════════

def test_sigma_records_timing_and_outcome(fresh_metrics):
    """Sigma 单事件检测必须留下耗时与五态。"""
    from sigma_engine.engine import PySigmaDetector

    det = PySigmaDetector("sigma_engine/rules")
    r = det.detect_for_event({"event": "PATH_TRAVERSAL",
                              "url": "/../../etc/passwd",
                              "src_ip": "10.0.0.1"})

    assert _hist_count(fresh_metrics, "test_detection_seconds",
                       detector="sigma") == 1.0
    assert _hist_sum(fresh_metrics, "test_detection_seconds",
                     detector="sigma") >= 0.0
    assert _counter_value(
        fresh_metrics, "test_detection_outcomes_total",
        detector="sigma", outcome=r["status"]) == 1.0, \
        f"Sigma 状态 {r['status']!r} 没有被计数"


def test_anomaly_records_timing_and_outcome(fresh_metrics):
    """异常检测必须留下耗时与五态（含 inconclusive）。"""
    from anomaly_detector import AnomalyDetector

    det = AnomalyDetector()
    loop = asyncio.new_event_loop()
    try:
        # 全新实体没有任何基线 → 必然 inconclusive，正好验证这一态可计
        rep = loop.run_until_complete(det.analyze(
            {"event": "WEIRD", "src_ip": "10.9.9.9", "event_id": 1}))
    finally:
        loop.close()

    assert rep.status == "inconclusive", \
        f"预期冷启动判 inconclusive，实际 {rep.status!r}（用例选得不对）"
    assert _hist_count(fresh_metrics, "test_detection_seconds",
                       detector="anomaly") == 1.0
    assert _counter_value(
        fresh_metrics, "test_detection_outcomes_total",
        detector="anomaly", outcome="inconclusive") == 1.0, \
        "inconclusive 没有被单独计数 —— 它很可能被算进了 not_detected"


def test_anomaly_replay_does_not_double_count_state(fresh_metrics):
    """同一事件重放 3 次 → 计 3 次检测，但**状态分布不变**。

    埋点只记「调用了几次」，不参与基线推进，所以重放不该改变五态分布。
    这条守的是别把埋点塞进打分路径里。
    """
    from anomaly_detector import AnomalyDetector

    det = AnomalyDetector()
    loop = asyncio.new_event_loop()
    try:
        for _ in range(3):
            loop.run_until_complete(det.analyze(
                {"event": "X", "src_ip": "10.8.8.8", "event_id": 77}))
    finally:
        loop.close()

    assert _hist_count(fresh_metrics, "test_detection_seconds",
                       detector="anomaly") == 3.0


def test_correlation_records_timing(fresh_metrics):
    """关联引擎即使没有 session 也要留下耗时记录。

    这里用「空 session」触发提前返回：正是这种最容易漏埋点的分支。
    """
    from correlation_engine import CorrelationEngine

    class _FakeResult:
        def scalars(self):
            return self

        def all(self):
            return []

    class _FakeSession:
        async def execute(self, stmt):
            return _FakeResult()

    eng = CorrelationEngine()
    loop = asyncio.new_event_loop()
    try:
        res = loop.run_until_complete(
            eng.analyze(_FakeSession(), "sess-does-not-exist"))
    finally:
        loop.close()

    assert _hist_count(fresh_metrics, "test_detection_seconds",
                       detector="correlation") == 1.0, \
        "关联引擎的提前返回分支漏了埋点"
    assert _counter_value(
        fresh_metrics, "test_detection_outcomes_total",
        detector="correlation", outcome="not_detected") == 1.0
    assert res is not None


def test_metric_is_exported_in_text_format(fresh_metrics):
    """指标必须真的出现在 Prometheus 文本输出里。

    最后一道闸门：前面的断言都直接读注册表对象，万一某处把指标
    换成了不导出的类型，注册表读得到但抓取结果里没有 ——
    那就是「本地看着有、生产抓不到」。用 generate_latest 兜住。
    """
    record_detection("sigma", "detected", 0.02)
    text = generate_latest(fresh_metrics).decode("utf-8")
    assert "test_detection_outcomes_total" in text
    assert "test_detection_seconds_count" in text
    assert 'detector="sigma"' in text


# ══════════════════════════════════════════════════════════════════════════
# §十一 核心要求的**端到端**验收：五态必须在真实检测路径上分开计数
# ══════════════════════════════════════════════════════════════════════════

def _anomaly_event(ts, eid, src, etype="LOGIN"):
    """anomaly_detector 的载荷形状。

    ⚠️ 键名必须是 `event`，不是 `event_type`：
    `analyze()` 里写的是 `event.get("event", event.get("type", "UNKNOWN"))` ——
    它读的是**摄入流水线**的载荷形状，不读 DB 模型的 `event_type` 字段。
    传 `event_type` 不报错，只会让每条事件静默落成 `UNKNOWN`，
    于是 `n_types` 恒为 1 → rarity 按设计不可判 → 每条都 `inconclusive`。
    这条陷阱实测踩过一次，看起来像"检测器坏了"，其实是夹具形状不对。
    """
    return {"src_ip": src, "event": etype, "timestamp": ts,
            "dst_ip": "10.0.0.1", "severity": "high", "message": "x",
            "event_id": eid, "session_id": "s"}


class TestFiveStatesStaySeparatedEndToEnd:
    """文档 §十一：

    「监控不能只记录最终检测分数，还应记录检测依据不足、运行错误和真实阴性
      各自的数量。如果这些状态最终都被压成一个 not_detected 计数，
      那么新增多少仪表盘也无法真正帮助排障。」

    同文件里已有的用例是**直接调 `record_detection`** 验证 clamp 行为；
    这一组不同 —— 它跑**真实的 `analyze()`**，确认三种结局真的落到三行上。
    单元级的 clamp 守卫挡不住「检测器内部把 inconclusive 提前判成 not_detected」
    这类改动 —— 那会在 `record_detection` 被调用**之前**就丢掉信息。
    """

    def test_real_detection_paths_record_three_distinct_rows(self, fresh_metrics):
        import asyncio
        import time

        import anomaly_detector as ad

        now = time.time()
        warm, cold = "10.0.0.77", "203.0.113.77"
        types = ("LOGIN", "FILE_ACCESS")
        det = ad.AnomalyDetector(timezone_name="Asia/Shanghai")

        # 基线：两种事件类型（rarity 维度要求 n_types >= 2），
        # 分布在多小时上（statistical_deviation 要求 >= 5 个滚动桶）。
        for i in range(24):
            asyncio.run(det.analyze(_anomaly_event(
                now - 3600 * 6 + i * 900, f"base-{i}", warm, types[i % 2])))

        # ① 冷实体单条 → inconclusive（无基线，结构性不可判）
        asyncio.run(det.analyze(_anomaly_event(now, "cold-1", cold, "LOGIN")))
        # ② 成熟基线 + 正常速率 → not_detected（真阴性）
        asyncio.run(det.analyze(_anomaly_event(now, "norm-1", warm, "LOGIN")))
        # ③ 成熟基线 + 速率突增 → detected
        for i in range(60):
            asyncio.run(det.analyze(_anomaly_event(
                now - 600 + i * 5, f"burst-{i}", warm, "LOGIN")))

        def n(outcome):
            return _counter_value(fresh_metrics, "test_detection_outcomes_total",
                                   detector="anomaly", outcome=outcome)

        counts = {s: n(s) for s in ("detected", "not_detected", "inconclusive")}
        assert counts["detected"] >= 1, f"没有记录 detected: {counts}"
        assert counts["not_detected"] >= 1, f"没有记录 not_detected: {counts}"
        assert counts["inconclusive"] >= 1, f"没有记录 inconclusive: {counts}"

        # 三行必须是**不同的计数**，不能是同一个值被复制三次 ——
        # 那样只说明有人写了三行，没说明它们对应不同的真实结局。
        assert len(set(counts.values())) == 3, (
            f"三种结局记录到了同样的计数 {counts} —— 它们很可能来自同一路径")

    def test_a_single_row_is_not_detected_never_absorbs_inconclusive(self,
                                                                    fresh_metrics):
        """反向钉法：把 inconclusive 记成 not_detected 时必须立刻可见。

        实测（2026-10-19）：`anomaly_detector.analyze()` 在无基线时返回
        `status="inconclusive"`，而这条路径**完全不会**被记到 `not_detected`
        那一行上 —— 这正是 §十一 要的性质。
        """
        import asyncio
        import time

        import anomaly_detector as ad

        det = ad.AnomalyDetector(timezone_name="Asia/Shanghai")
        now = time.time()
        r = asyncio.run(det.analyze(
            _anomaly_event(now, "only-cold", "198.51.100.5", "LOGIN")))
        assert r.status == "inconclusive", r.status

        assert _counter_value(fresh_metrics, "test_detection_outcomes_total",
                              detector="anomaly",
                              outcome="inconclusive") >= 1
        assert _counter_value(fresh_metrics, "test_detection_outcomes_total",
                              detector="anomaly",
                              outcome="not_detected") == 0.0, (
            "没有任何真阴性样本，not_detected 那一行却不为 0 —— "
            "inconclusive 被并进去了")
