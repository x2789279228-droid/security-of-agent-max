"""
检测指标链路的**端到端**守卫：引擎产出的 status 必须真的流进计数器。

## 为什么已有测试不够

`tests/test_detection_metrics.py` 直接调用 `record_detection(...)` 并替换
模块级 registry，验证的是**计数器本身**的行为（clamp、白名单、不被合并）。

`tests/test_p3_detection_calibration.py` 验证的是**引擎**的行为
（`status == "partial"`、`pending_aggregation` 非空）。

**两者之间那一段没人测**：

    真实检测调用 → 引擎算出 status → record_detection(detector, status)
                 → soc_detection_outcomes_total{detector,outcome}

中间任一环脱节（引擎改了 status 名、包装层忘了透传、计数器被换掉），
两边测试照样全绿，而面板上的五态分布**全是错的**。

这不是假想。验收报告 §7.1 曾同时写着两句互相矛盾的话：
表格里「部分失败 ✅ 本轮补齐」，正文里却说「跨事件的累计口径还没建」——
因为没有任何一条测试会去回答「真实跑一遍标定集，partial 计数到底涨不涨」。

## 本文件怎么回答

直接跑**真实** `PySigmaDetector` 过标定集，前后取计数器差值，
断言差值与期望状态一一对应。最关键的一条是
`test_every_call_lands_in_exactly_one_bucket`：
五次调用的结果之和必须等于调用数 —— 任何一个 status 若不在白名单里，
`clamp_label` 会把它落到 `error` 而**不报错**，那时只有这条能抓到。

（`clamp_label` 静默兜底的行为本身由 test_detection_metrics.py 负责；
这里负责的是「兜底有没有被触发」。）
"""
from __future__ import annotations

import pytest
from prometheus_client import REGISTRY

from detection_contract import ALL_STATUSES
from eval_datasets.detection_cases import sigma_cases
from sigma_engine.engine import PySigmaDetector

RULES_DIR = "sigma_engine/rules"
METRIC = "soc_detection_outcomes_total"
ALL_OUTCOMES = tuple(sorted(ALL_STATUSES))


def _count(detector: str, outcome: str) -> float:
    v = REGISTRY.get_sample_value(METRIC, {"detector": detector, "outcome": outcome})
    return float(v) if v is not None else 0.0


@pytest.fixture(scope="module")
def detector() -> PySigmaDetector:
    return PySigmaDetector(RULES_DIR)


def _classify(result: dict) -> str:
    """与标定评估器同口径：全部命中都待聚合 → partial，否则按引擎 status。"""
    hits = result.get("hits", []) or []
    pending = set(result.get("pending_aggregation") or [])
    if hits and not [h for h in hits if h["rule_id"] not in pending]:
        return "partial"
    return result.get("status", "") or ""


@pytest.fixture(scope="module")
def sigma_run(detector) -> list[tuple[str, str]]:
    """跑一遍标定集，返回 [(case_id, 五态)]。"""
    return [(c["id"], _classify(detector.detect_for_event(dict(c["event"]))))
            for c in sigma_cases()]


def test_calibration_set_actually_contains_every_state_it_claims(sigma_run):
    """前提守卫：标定集必须真的产出 partial，否则下面的断言会空跑。

    这类「样本里根本没有该状态」的测试会**恒绿**，是假守卫的典型来源。
    """
    seen = {outcome for _cid, outcome in sigma_run}
    assert "partial" in seen, \
        f"标定集没有产出任何 partial（实际产出 {sorted(seen)}）—— " \
        "端到端断言将失去意义"
    assert "not_detected" in seen
    assert "detected" in seen


def test_partial_status_reaches_the_counter_end_to_end(detector, sigma_run):
    """核心：真实引擎产出的 partial 必须累加进 partial 桶。

    这是「引擎 → 计数器」那一段的唯一覆盖。
    """
    expected = sum(1 for _cid, oc in sigma_run if oc == "partial")

    before = _count("sigma", "partial")
    for c in sigma_cases():
        detector.detect_for_event(dict(c["event"]))
    delta = _count("sigma", "partial") - before

    assert delta == expected, (
        f"partial 桶涨了 {delta}，但引擎实际产出 {expected} 个 partial —— "
        "引擎到计数器之间有断点，或某次调用落进了别的桶"
    )


def test_partial_is_not_absorbed_into_not_detected(detector):
    """partial 必须单列，不能被并进 not_detected。

    §二要求 partial「不可以直接视为完整阴性」；指标上并进去，
    等于把「没结论」重新伪装成「阴性」。
    """
    partial_cases = [c for c in sigma_cases()
                     if _classify(PySigmaDetector(RULES_DIR)
                                  .detect_for_event(dict(c["event"]))) == "partial"]
    assert partial_cases, "前提：标定集里要有 partial 用例"

    det = PySigmaDetector(RULES_DIR)
    b_part, b_neg = _count("sigma", "partial"), _count("sigma", "not_detected")
    for c in partial_cases:
        det.detect_for_event(dict(c["event"]))
    d_part = _count("sigma", "partial") - b_part
    d_neg = _count("sigma", "not_detected") - b_neg

    assert d_part == len(partial_cases), f"partial 桶只涨了 {d_part}"
    assert d_neg == 0, (
        f"partial 用例同时让 not_detected 涨了 {d_neg} —— "
        "「没结论」被记成了「阴性」"
    )


def test_every_call_lands_in_exactly_one_bucket(sigma_run):
    """五次调用的计数增量之和必须等于调用数。

    若某个 status 不在白名单里，`clamp_label` 会静默落到 `error`：
    不报错、不丢数据，但分布已经失真。只有这条能抓到。
    """
    from collections import Counter

    counts = Counter(oc for _cid, oc in sigma_run)
    total_calls = len(sigma_run)

    assert sum(counts.values()) == total_calls
    for outcome, n in counts.items():
        assert outcome in ALL_OUTCOMES, (
            f"引擎产出白名单外的状态 {outcome!r}（{n} 次）—— "
            f"会被 clamp_label 静默记成 error。合法值：{list(ALL_OUTCOMES)}"
        )
