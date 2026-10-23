# -*- coding: utf-8 -*-
"""阈值可行性守卫：标定集上**没有任何阈值**能让三类样本同时自洽（整改报告 §9.60）。

## 背景

`eval_datasets/evaluate_detection.py::sweep_anomaly_threshold` 修复前**只**检查
「不漏掉应检出样本」→ 它给出的 `exact_upper_bound` 只是一个**召回下界**；
而工具的渲染把它印成「精确**可行**区间」，报告 §4.4 / §6.2 / 待决项 18 /
§9.28.2 又照着这个区间给行动项（「把阈值降到 0.4357 以内」）。

实测（2026-10-20）：标定集里「结构性不可判」那两条（全新源 IP + critical + 凌晨）
得分 **0.4957 / 0.4357**，**高于**那个上界 → 任何 `t < 0.4357` 的阈值都会把
「全新源 IP」判成 `detected`。于是：

* 负类下界   = 0.1714（阈值必须 ≥ 它，否则已知正常样本变误报）
* 不可判下界 = 0.4957（阈值低于它 ⇒ 不可判样本被报成 detected）
* 完整可行区间 = [0.4957, 0.4357) —— **空集**

**没有任何阈值**能同时满足「正样本全检出 ∧ 负类不误报 ∧ 不可判类不翻转」
⇒ 异常检测的召回缺口**不是阈值问题**，必须走整改方案 §七.2 的重设计
（新证据维度 + 独立的冷启动规则）。

## 本守卫盯什么

1. **决定性**：在**密集**阈值网格上**独立重算**不一致集合 → 每个阈值都至少有
   1 条与标注不一致（**不采信工具自己的表** —— 采信它就成了自证）；
2. **工具口径**：扫描必须报出「完整可行区间为空」与两侧下界；
3. **文案**：渲染输出**不得**把召回下界印成「可行区间」；
4. **否定结论**：只看负类时 `t > 0.1714` 永远不会误报 ——
   钉住它，让 §4.4 的更正精确到「原句**对负类为真**、但它**只**看了负类」，
   而不是含糊地说「原句是错的」；
5. **生产事实**：`is_anomaly` **不因**证据维度不可判而否决（→ 待决项 41）。
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND))

from eval_datasets.evaluate_detection import (      # noqa: E402
    render,
    run_anomaly,
    run_correlation,
    run_sigma,
    sigma_breakdown,
    sweep_anomaly_threshold,
)

#: 标定集里「结构性不可判」那一类的标注。它们的得分是**上界**而不是下界。
INCONCLUSIVE_LABEL = "inconclusive"


@pytest.fixture(scope="module")
def anomaly_rows():
    return run_anomaly()


@pytest.fixture(scope="module")
def sigma_rows():
    return run_sigma()


@pytest.fixture(scope="module")
def corr_rows():
    return run_correlation()


@pytest.fixture(scope="module")
def sweep(anomaly_rows):
    return sweep_anomaly_threshold(anomaly_rows)


def _inconsistent(rows, t):
    """独立重算：阈值 t 下，标定集里与标注不一致的样本。

    判定式与真检测器一致（`anomaly_score > t or sigma > 3`）。
    **刻意不复用** `sweep_anomaly_threshold` 里的逻辑 —— 采信工具自己的
    输出等于自证，判据会永远绿。
    """
    bad = []
    for r in rows:
        if r.get("known_gap") is not None:
            continue
        hit = (r["anomaly_score"] is not None and r["anomaly_score"] > t) \
            or (r["deviation_sigma"] > 3.0)
        if r["expect"] == "detected" and not hit:
            bad.append((r["id"], "missed_positive"))
        elif r["expect"] == "not_detected" and hit:
            bad.append((r["id"], "false_positive"))
        elif r["expect"] == INCONCLUSIVE_LABEL and hit:
            bad.append((r["id"], "inconclusive_reported_detected"))
    return bad


class TestNoThresholdWorks:
    def test_every_threshold_breaks_something(self, anomaly_rows):
        """**决定性**：密集网格上，**每个**阈值都至少有一条与标注不一致。

        「把阈值调到 X 就能补上召回缺口」这句话，只有在存在某个 X 让
        标定集完全自洽时才成立。实测：不存在。
        """
        feasible = []
        for i in range(0, 101):
            t = round(i / 100, 4)
            if not _inconsistent(anomaly_rows, t):
                feasible.append(t)
        assert not feasible, (
            f"这些阈值能让标定集完全自洽：{feasible} —— "
            "§9.60 的结论（可行区间为空）需要更正，报告 §4.4 / §6.2 的"
            "行动项也要跟着改")

    def test_the_complete_feasible_interval_is_empty(self, sweep):
        """工具必须报出「完整可行区间为空」，而不是只给一个召回上界。"""
        assert sweep["complete_feasible"] is False, (
            "扫描认为存在完整可行区间 —— 与 §9.60 的实测矛盾")
        assert sweep["complete_feasible_interval"] is None, (
            sweep["complete_feasible_interval"])
        assert sweep["feasible_thresholds"] == [], sweep["feasible_thresholds"]

    def test_the_three_bounds_are_pinned(self, sweep):
        """三个数是整个结论的骨架 —— 变了就得同步报告。"""
        assert sweep["exact_upper_bound"] == pytest.approx(0.4357), (
            "召回下界变了 —— 报告 §4.4 / §6.2 引用的 0.4357 需要更新")
        assert sweep["false_positive_lower_bound"] == pytest.approx(0.1714), (
            "负类下界变了 —— §9.60 引用的 0.1714 需要更新")
        assert sweep["inconclusive_lower_bound"] == pytest.approx(0.4957), (
            "不可判下界变了 —— §9.60 引用的 0.4957 需要更新")
        assert sweep["complete_lower_bound"] == pytest.approx(0.4957), (
            sweep["complete_lower_bound"])

    def test_the_empty_interval_is_analytical_not_sampled(self, sweep):
        """空集是**解析**结论：下界 ≥ 上界。

        这一条不依赖网格采样 —— 网格可能刚好错过一个很窄的可行窗口。
        """
        lower = sweep["complete_lower_bound"]
        upper = sweep["exact_upper_bound"]
        assert lower is not None and upper is not None
        assert lower >= upper, (
            f"下界 {lower} < 上界 {upper} ⇒ 存在非空可行区间 —— "
            "§9.60 的结论需要更正")


class TestTheOutputDoesNotOverclaim:
    def test_the_rendered_output_does_not_call_it_a_feasible_interval(
            self, sigma_rows, anomaly_rows, corr_rows, sweep):
        """渲染输出**不得**把召回下界印成「精确可行区间」。

        修复前那行是「精确可行区间 = [0, 0.4357)」，而同一个工具的
        `note` 又写着「这是一个召回下限，不是完整的最优阈值」——
        **工具自己跟自己矛盾**，而下游照着那行去调阈值。
        """
        out = render(sigma_rows, anomaly_rows, corr_rows,
                     sigma_breakdown(sigma_rows), sweep)
        assert "精确可行区间 = [0, 0.4357)" not in out, (
            "召回下界又被印成「可行区间」了")
        assert "召回下界" in out, out[-1500:]
        assert "空集" in out, (
            "渲染输出没有说明完整可行区间为空 —— 缺口不是阈值问题这件事"
            "必须出现在工具输出里，而不是只写在报告里")

    def test_the_sweep_note_says_it_is_a_recall_bound(self, sweep):
        """`note` 必须自己说清楚它是召回下界，并指向权威字段。"""
        assert "召回下界" in sweep["note"], sweep["note"]
        assert "complete_feasible" in sweep["note"], (
            "note 没有指向 complete_feasible —— 读的人仍然不知道"
            "「有没有可行区间」这个问题该看哪个字段：\n" + sweep["note"])

    def test_the_sibling_evaluator_uses_the_same_wording(self):
        """**正向**文案检查：`evaluate_scale_window.py` 的注释也必须说「召回下界」。

        只做**正向**断言（必须出现「召回下界」），不做「不得出现『精确可行
        区间』」的反向断言 —— 反向断言会被「合法引用旧话做说明」误伤
        （那是对旧结论的引用，不是缺陷）。
        """
        src = (BACKEND / "eval_datasets" / "evaluate_scale_window.py").read_text(
            encoding="utf-8")
        head = "\n".join(src.splitlines()[:40])
        assert "召回下界" in head, (
            "evaluate_scale_window.py 的开头注释里没有「召回下界」—— "
            "同一个错误说法又回来了（它原本写的是「精确可行区间 [0, 0.4357)」）")


class TestTheNegativeConclusions:
    def test_the_negative_class_alone_never_breaks_above_its_bound(
            self, anomaly_rows):
        """**否定结论**：只看负类，`t > 0.1714` 永远不会误报。

        ⇒ §4.4 原句「降到上界以内不会引入误报」**对负类为真**，
        它错在**只**看了负类。钉住这条，让更正精确而不是含糊。
        """
        negs = [r for r in anomaly_rows if r["expect"] == "not_detected"]
        assert negs, "负类为空 —— 这条断言会变成空断言"
        bound = max(r["anomaly_score"] for r in negs if r["anomaly_score"] is not None)
        for i in range(0, 101):
            t = round(i / 100, 4)
            if t <= bound:
                continue
            bad = [r["id"] for r in negs
                   if (r["anomaly_score"] is not None and r["anomaly_score"] > t)
                   or (r["deviation_sigma"] > 3.0)]
            assert not bad, (t, bad)

    def test_the_false_positive_claim_rests_on_two_samples(self, anomaly_rows):
        """事实钉住：负类只有 **n=2**。

        「不会引入误报」这句话的样本量很薄 —— 这是它必须被更正的原因之一。
        哪天负类样本变多，这个数字要更新。
        """
        negs = [r for r in anomaly_rows if r["expect"] == "not_detected"]
        assert len(negs) == 2, (
            f"负类样本数变了（{len(negs)}）—— §9.60 引用的 n=2 需要更新")

    def test_the_inconclusive_class_is_not_counted_as_a_negative(self, sweep):
        """否定结论：不可判类**不计入**负类。

        它既不是漏报也不是误报，而是「结构上无法判定」——
        把它算进负类会把「新实体看不见」这个盲区藏起来（整改方案 §七.3）。
        """
        assert sweep["false_positive_lower_bound"] == pytest.approx(0.1714), (
            "负类下界被不可判类污染了 —— 不可判样本不得算成阴性")


class TestTheProductionFactIsPinned:
    def test_inconclusive_dimensions_do_not_veto_a_detection(self, monkeypatch):
        """生产事实钉住：`is_anomaly` **不因**证据维度不可判而否决。

        整改方案 §七.2 要求「对缺乏历史数据的新实体，单独采用经过评估的
        冷启动规则」——**当前实现没有这条规则**：不可判维度只被记下来，
        不参与否决。于是「全新源 IP + critical + 凌晨」（ANO-I-01）在
        阈值低于 0.4957 时会被报成 `detected`。

        这是**待决项 41** 的依据（收紧型：要不要让 `is_anomaly` 在存在
        不可判维度时不得成立，或把 status 改成 `partial`）。本轮**不做**
        —— 但事实必须钉住，免得将来误以为「它已经这样了」。
        """
        import anomaly_detector as ad
        from eval_datasets.detection_cases import anomaly_cases
        from eval_datasets.evaluate_detection import _feed, _probe_report

        case = next(c for c in anomaly_cases() if c["id"] == "ANO-I-01")
        det = ad.AnomalyDetector()
        _feed(det, case["baseline"])
        monkeypatch.setattr(ad, "ANOMALY_SCORE_THRESHOLD", 0.40)
        rep = _probe_report(det, case["probe"])
        assert rep.inconclusive_dimensions, (
            "这条样本本该有不可判维度（全新源 IP → 统计维度不可判）")
        assert rep.is_anomaly is True, (
            "阈值降到 0.40 后这条本该被报成 detected —— 若哪天实现改成"
            "「不可判维度否决检出」，本条会转红，请同步待决项 41 与 §9.60")
        assert rep.status == "detected", rep.status


if __name__ == "__main__":       # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
