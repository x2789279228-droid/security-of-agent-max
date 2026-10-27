# -*- coding: utf-8 -*-
"""阈值可行性守卫：标定集上可行区间的边界事实（§9.60 → 2026-10-25 两段演进）。

## 演进史（更正过程全部保留，勿删）

**第一段（2026-10-20, §9.60）**：`sweep_anomaly_threshold` 修复前只检查
「不漏掉应检出样本」，把召回下界印成「精确可行区间」。实测 3 条应检出
全部进入约束面、得分 0.7143/0.4357/0.4957，而「结构性不可判」类得分
0.4957/0.4357 与正类重叠 → 完整可行区间为空集 ⇒ 缺口不是阈值问题。

**第二段（2026-10-25a, known_gap 登记）**：ANO-P-02/03 以 known_gap
显式登记后测量面只剩 1 条 sigma 命中的正类 → exact_upper_bound=None，
测量面可行 —— 但缺口在测量面之外，仍需 §七.2 重设计。

**第三段（2026-10-25b, severity_shift 维度, 本文件现状）**：§七.2 的
「新证据维度」落地 —— 成熟基线实体窗口内零高危史、突然发出 high/critical
记 1.0 证据；全量权重重归一到 1.0，证据分母 0.70→0.74）。
ANO-P-02 → 0.6435、ANO-P-03 → 0.6955 过阈值，known_gap 摘除回到约束面。现在：

* 负类下界   = 0.1297（负类分数因权重重归一整体下移）
* 不可判下界 = 0.3982（新实体无基线 → severity_shift 缺席，分数反而更低）
* 完整可行区间 = **[0.3982, 0.6435) 非空**，当前阈值 0.60 在区间内
  ⇒ §9.60 的行动项（重设计证据维度）**已完成并验证**，
  「缺口不是阈值问题」的结论被新证据维度终结 —— 这是结论的终点，
  不是对 §9.60 的否定：正因为它当年指认了「必须走 §七.2」，才有本段。

## 本守卫盯什么

1. **决定性**：密集网格上**独立重算**（不采信工具自己的表）——
   t < 0.3982 必有不可判翻转，t ≥ 0.6435 必漏 P-02，中间全段自洽；
2. **工具口径**：扫描报出非空完整可行区间与三个解析下界；
3. **文案**：渲染不得把召回下界印成「可行区间」；
4. **否定结论**：只看负类时 `t > 0.1297` 永远不会误报（n=2，样本薄）；
5. **生产事实**：`is_anomaly` 不因证据维度不可判而否决（→ 待决项 41）。
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND))

from anomaly_detector import ANOMALY_SCORE_THRESHOLD    # noqa: E402
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


class TestFeasibleIntervalNowExists:
    """severity_shift 接入后的三段式结论（见模块 docstring 第三段）。"""

    def test_every_threshold_below_the_bound_flips_inconclusive(self, anomaly_rows):
        """**决定性（下界侧）**：t < 0.4205 的每个阈值都翻不可判类。

        「把阈值调低就能补召回」依然不成立 —— 全新源 IP 会被翻成 detected。
        """
        for i in range(0, 40):
            t = round(i / 100, 4)
            bad = _inconsistent(anomaly_rows, t)
            assert bad, (
                f"t={t} 完全自洽 —— 不可判下界 0.3982 的实测依据变了, "
                "本守卫与报告需要同步")

    def test_every_threshold_at_or_above_the_bound_misses_a_positive(self, anomaly_rows):
        """**决定性（上界侧）**：t ≥ 0.6435 必漏 ANO-P-02（纯分数正类）。

        P-02 的 sigma=0，只能靠分数命中 —— 它是唯一的上界约束。
        """
        for i in range(65, 101):
            t = round(i / 100, 4)
            bad = _inconsistent(anomaly_rows, t)
            assert any(reason == "missed_positive" for _, reason in bad), (
                f"t={t} 没有漏掉任何正类 —— ANO-P-02 的上界约束地位变了: {bad}")

    def test_the_interval_interior_is_fully_consistent(self, anomaly_rows):
        """**决定性（区间内）**：[0.45, 0.60] 网格段完全自洽。

        当前阈值 0.60 落在段内 —— 标定集第一次有了「不用调阈值就自洽」
        的完整解（§9.60 行动项的完成证据）。
        """
        for i in range(45, 61):
            t = round(i / 100, 4)
            bad = _inconsistent(anomaly_rows, t)
            assert not bad, f"t={t} 仍不一致: {bad}"

    def test_the_three_bounds_are_pinned(self, sweep):
        """三个数是整个结论的骨架 —— 变了就得同步报告。

        演进：0.4357（第一段）→ None（第二段）→ 0.6435（本段）。
        """
        assert sweep["exact_upper_bound"] == pytest.approx(0.6435), (
            "召回上界变了 —— ANO-P-02 的分数是它，§9.60 终点结论需同步")
        assert sweep["false_positive_lower_bound"] == pytest.approx(0.1297), (
            "负类下界变了（权重重归一 1.0 的效应）")
        assert sweep["inconclusive_lower_bound"] == pytest.approx(0.3982), (
            "不可判下界变了")
        assert sweep["complete_lower_bound"] == pytest.approx(0.3982), (
            sweep["complete_lower_bound"])

    def test_the_complete_interval_is_analytical(self, sweep):
        """非空是**解析**结论：下界(不可判类) < 上界(P-02 分数)，且当前阈值在区间内。"""
        assert sweep["complete_feasible"] is True
        assert sweep["complete_feasible_interval"] is not None
        lower, upper = sweep["complete_feasible_interval"]
        assert lower == pytest.approx(0.3982)
        assert upper == pytest.approx(0.6435)
        assert lower < ANOMALY_SCORE_THRESHOLD < upper, (
            "当前阈值不在可行区间内 —— 阈值或维度权重被改动")
        assert sweep["current_is_perfect"] is True


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
        assert "完整可行区间" in out, out[-1500:]
        # 完整可行区间非空且当前阈值在内 —— 这个事实必须出现在工具输出里
        assert sweep["complete_feasible_interval"][0] < ANOMALY_SCORE_THRESHOLD \
            < sweep["complete_feasible_interval"][1], (
            "可行区间与当前阈值的关系变了 —— 渲染断言需同步")

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
        """**否定结论**：只看负类，`t > 0.1297` 永远不会误报。

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
        assert sweep["false_positive_lower_bound"] == pytest.approx(0.1297), (
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
        # 0.35（原 0.40）：severity_shift 接入时全量权重重归一，
        # I-01 的分数从 0.4957 下移到 0.3982 —— patched 阈值跟随下移，
        # 测试意图不变（阈值低于其分数时，不可判维度不得否决检出）。
        monkeypatch.setattr(ad, "ANOMALY_SCORE_THRESHOLD", 0.35)
        rep = _probe_report(det, case["probe"])
        assert rep.inconclusive_dimensions, (
            "这条样本本该有不可判维度（全新源 IP → 统计维度不可判）")
        assert rep.is_anomaly is True, (
            "阈值降到 0.35 后这条本该被报成 detected —— 若哪天实现改成"
            "「不可判维度否决检出」，本条会转红，请同步待决项 41 与 §9.60")
        assert rep.status == "detected", rep.status


if __name__ == "__main__":       # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
