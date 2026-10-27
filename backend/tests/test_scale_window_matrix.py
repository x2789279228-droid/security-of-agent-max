# -*- coding: utf-8 -*-
"""§七 的「不同部署规模」「不同时间窗口」两维：矩阵守卫。

整改方案 §七「异常检测验收指标」：

> 至少按新实体、成熟实体、**不同部署规模**、**不同时间窗口**分别报告

前两维由 `evaluate_detection.cold_start_breakdown()` 覆盖；
本文件守的是 `eval_datasets/evaluate_scale_window.py` 这两维。

## 这两条守卫在守什么

1. **窗口维度必须是「真的」** —— 窗口短到小于基线年龄时，
   老基线必须被淘汰（基线样本量下降）。
   要是窗口不影响任何东西，这一维就只是**装饰**，报告成「已覆盖」是骗人。
2. **矩阵不得污染既有标定集** —— §9.3 的阈值扫描
   （精确可行区间 `[0, 0.4357)`）来自既有 8 条标定集，
   矩阵是**另起**的一套，两处测量互不干扰。

## 性能

完整矩阵 54 个格子约 12 秒。所以：
* 主体断言用 **module 级 fixture 只跑一次**；
* 复现性检查把突增阶梯缩到 1 档（够验证「钉住时钟」这件事）。
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from eval_datasets import evaluate_scale_window as esw  # noqa: E402


@pytest.fixture(scope="module")
def matrix():
    return esw.run_matrix()


@pytest.fixture(scope="module")
def adapt():
    return esw.run_adaptation_matrix()


class TestAdaptationSpeedIsMeasured:
    """基线适应速度（§9.28.6 登记的缺口：窗口维度的「适应速度」没测）。

    场景：实体先处在旧常态，Δ 小时前换到新常态；探针是**合法的新常态**流量。
    被报成 `detected` = 误报。
    """

    def test_one_hour_after_the_switch_the_new_regime_must_be_flagged(self, adapt):
        """⚠ **前提守卫** —— 本轮第一版把桶映射写反了。

        写反的表现是「换常态才 1 小时，基线就适应了」——
        因为旧常态反而占据了**最近**的历史。
        抓住它靠的就是这条直觉：
        换常态 1 小时，基线几乎全是旧常态，探针**必须**被报成异常。
        """
        cells = [c for c in adapt["cells"] if c["delta_hours"] == 1]
        assert cells, "矩阵里没有 Δ=1 小时的格子"
        for c in cells:
            assert c["flagged_as_anomaly"], (
                f"窗口 {c['window_days']}d：换常态才 1 小时却不报 —— "
                f"场景的桶映射可能又反了（得分 {c['anomaly_score']}，"
                f"σ {c['deviation_sigma']}）")

    def test_the_score_falls_as_the_new_regime_settles_in(self, adapt):
        """Δ 越大 → 得分越低（基线越来越认新常态）。

        这条也是**场景方向**的守卫：反了的话得分会随 Δ 上升。"""
        for w in adapt["windows"]:
            cs = sorted([c for c in adapt["cells"] if c["window_days"] == w],
                        key=lambda c: c["delta_hours"])
            scores = [c["anomaly_score"] for c in cs]
            assert scores == sorted(scores, reverse=True), (
                f"窗口 {w}d 的得分没有随 Δ 单调下降：{scores}")

    def test_a_short_window_forgets_the_old_regime_sooner(self, adapt):
        """1 天窗口在 Δ=24h 时，保留的 24h **全是**新常态 → σ 归零。

        7 天 / 30 天窗口仍留着 12 小时旧常态 → σ > 0。
        这就是「窗口越长，基线越难忘掉旧常态」的直接证据。
        """
        by = {(c["window_days"], c["delta_hours"]): c
              for c in adapt["cells"]}
        short = by[(1, 24)]
        long_ = by[(7, 24)]
        assert short["deviation_sigma"] == 0.0, (
            f"1 天窗口在 Δ=24h 时 σ 应为 0（保留的全是新常态），"
            f"实际 {short['deviation_sigma']}")
        assert long_["deviation_sigma"] > 0.0, (
            "7 天窗口在 Δ=24h 时仍应留着旧常态（σ > 0）")
        assert short["anomaly_score"] < long_["anomaly_score"], (
            f"短窗口的得分应更低（{short['anomaly_score']} vs "
            f"{long_['anomaly_score']}）")

    def test_the_false_positive_is_triggered_by_the_sigma_bypass(self, adapt):
        """⚠ 实测到的机制：Δ=8h 的误报**不是**得分超阈值触发的。

        得分 0.572 ≤ 阈值 0.60，但 σ = 3.59 > 3.0 ——
        判定是 `score > 阈值 or sigma > 3` 的**或**语义，
        于是**旁路**把这条合法流量报成了异常。

        这条要钉住：它决定着「调阈值能不能消掉这批误报」——
        **不能**（得分本来就没超阈值）。
        """
        bypass = [c for c in adapt["cells"] if c["flagged_by_sigma_bypass"]]
        assert bypass, "没有格子由 σ 旁路触发 —— 与实测不符，判据需重新核"
        for c in bypass:
            assert c["anomaly_score"] <= 0.60, c
            assert c["deviation_sigma"] > 3.0, c

    def test_the_legitimate_new_regime_eventually_stops_being_flagged(self, adapt):
        """最终必须能适应 —— 否则基线就永远学不会新常态。"""
        for w in adapt["windows"]:
            h = adapt["adaptation_hours"].get(str(w))
            assert h is not None, (
                f"窗口 {w}d 在整个 Δ 阶梯上都没适应 —— 基线学不会新常态？")
            assert h <= max(adapt["deltas"]), adapt["adaptation_hours"]


class TestMatrixCoversTheTwoDimensions:
    def test_all_three_scales_and_all_three_windows_are_measured(self, matrix):
        combos = {(c["scale"], c["window_days"]) for c in matrix["cells"]}
        assert len(combos) == 9, f"矩阵只覆盖了 {len(combos)} 个组合：{combos}"
        assert len(matrix["scales"]) == 3
        assert len(matrix["windows"]) == 3
        # 每个组合都必须跑满突增阶梯
        for s, w in combos:
            n = len([c for c in matrix["cells"]
                     if c["scale"] == s and c["window_days"] == w])
            assert n == len(matrix["burst_mults"]), (
                f"{s} × {w}d 只跑了 {n} 档突增")

    def test_every_cell_carries_the_measurement_fields(self, matrix):
        for c in matrix["cells"]:
            for k in ("status", "detected", "anomaly_score", "deviation_sigma",
                      "baseline_samples"):
                assert k in c, f"格子缺字段 {k}：{c}"
            assert c["status"] in ("detected", "not_detected", "inconclusive",
                                   "error", "partial"), c["status"]


class TestTheWindowDimensionIsReal:
    """窗口维度必须**真的影响**什么，否则它只是装饰。"""

    def test_a_short_window_prunes_an_aged_baseline(self, matrix):
        """1 天窗口必须把 168 小时的老基线砍掉。"""
        aged = [c for c in matrix["cells"]
                if c["scale"] == "aged_168h_x10" and c["burst_mult"] == 2]
        by_w = {c["window_days"]: c for c in aged}
        assert by_w[1]["baseline_samples"] < by_w[7]["baseline_samples"], (
            f"1 天窗口没有削减老基线（{by_w[1]['baseline_samples']} vs "
            f"{by_w[7]['baseline_samples']}）—— 窗口维度是装饰")
        assert by_w[7]["baseline_samples"] == by_w[30]["baseline_samples"], (
            "7 天与 30 天窗口都容得下 168 小时基线，样本数应当相同")

    def test_a_short_window_lowers_the_score_for_the_same_burst(self, matrix):
        """⚠ 本轮实测到的**真发现**（方向是漏报）。

        同一个 168 小时老实体、同一个 1.2 倍突增：
        窗口 1 天 → 得分 0.567；窗口 7/30 天 → 得分 0.597。

        原因：1 天窗口把 168 小时的老基线砍到 24 个样本，
        统计维度的证据变弱 → 得分变低 → **更容易漏报**。

        这条要钉住：它是一个**配置选择的后果**，
        改了窗口长度就改了漏报面 —— 属于运维必须知道的事。
        """
        aged = [c for c in matrix["cells"]
                if c["scale"] == "aged_168h_x10" and c["burst_mult"] == 1.2]
        by_w = {c["window_days"]: c for c in aged}
        assert by_w[1]["anomaly_score"] < by_w[7]["anomaly_score"], (
            f"短窗口下的得分没有更低（{by_w[1]['anomaly_score']} vs "
            f"{by_w[7]['anomaly_score']}）—— 与本轮实测相反，判据需重新核")
        assert by_w[7]["anomaly_score"] == by_w[30]["anomaly_score"], (
            "7 天与 30 天窗口得分应相同")

    def test_a_window_longer_than_the_baseline_changes_nothing(self, matrix):
        """窗口比基线年龄还长时，**不该**有任何差别 ——
        否则说明窗口在乱动别的东西。"""
        for scale in ("young_12h_x20", "steady_24h_x50"):
            cs = [c for c in matrix["cells"]
                  if c["scale"] == scale and c["burst_mult"] == 2]
            by_w = {c["window_days"]: c for c in cs}
            assert by_w[7]["anomaly_score"] == by_w[30]["anomaly_score"], (
                f"{scale}：7 天与 30 天窗口的得分不同（{by_w[7]} vs {by_w[30]}）")
            assert by_w[7]["baseline_samples"] == by_w[30]["baseline_samples"]


class TestTheMatrixIsReproducible:
    def test_two_runs_give_identical_results(self, monkeypatch):
        """矩阵必须**可复现**。

        窗口淘汰用的是**墙钟**（`time.time() - window_days*86400`），
        而矩阵锚在固定历史时刻 —— 不钉住时钟的话，
        同一份代码在不同时间跑会淘汰掉不同的桶，矩阵就不可复现。

        ⚠ **突增倍数必须取未饱和的那一档（1.2×）**：
        2× 及以上 σ 已撞上夹紧上限 10.0、得分维度饱和在 1.0，
        于是**基线的任何差异都被抹平** —— 用 2× 检查复现性，
        哪怕时钟乱跳也会「通过」（实测踩过：注入抖动时钟后这条没转红）。
        """
        monkeypatch.setattr(esw, "BURST_MULTS", [1.2])
        a = esw.run_matrix()
        b = esw.run_matrix()
        ka = [(c["scale"], c["window_days"], c["burst_mult"], c["status"],
               c["anomaly_score"], c["baseline_samples"]) for c in a["cells"]]
        kb = [(c["scale"], c["window_days"], c["burst_mult"], c["status"],
               c["anomaly_score"], c["baseline_samples"]) for c in b["cells"]]
        assert ka == kb, "同一份代码两次跑出的矩阵不一样 —— 时钟没钉住"
        assert a["matrix_now"] == b["matrix_now"]

    def test_the_clock_is_restored_after_the_matrix(self):
        """钉时钟的上下文管理器必须**还原** `time.time` ——
        否则评测器后面的代码会被影响。"""
        import time as _t
        real = _t.time
        with esw.pinned_clock(1000.0):
            assert _t.time() == 1000.0
        assert _t.time is real, "pinned_clock 退出后没有还原 time.time"


class TestTheMatrixDoesNotContaminateTheCalibrationSet:
    def test_the_main_evaluator_still_has_eight_anomaly_cases(self):
        """§9.3 的阈值扫描来自既有 8 条标定集。
        矩阵是**另起**的一套 —— 两者互不干扰。"""
        from eval_datasets.evaluate_detection import run_anomaly

        rows = run_anomaly()
        assert len(rows) == 8, (
            f"既有标定集变成 {len(rows)} 条了 —— 矩阵不该动它")

    def test_the_sweep_bounds_are_unchanged(self):
        """扫描口径骨架不能被矩阵改动。

        演进（2026-10-25）：0.4357（severity_shift 前）→ None（known_gap
        登记期）→ **0.6435**（severity_shift 维度接入后, known_gap 摘除）。
        钉住非空可行区间 + 当前阈值在内 —— 矩阵若改动扫描口径，这里先红。
        """
        from eval_datasets.evaluate_detection import (
            run_anomaly, sweep_anomaly_threshold)

        sweep = sweep_anomaly_threshold(run_anomaly())
        assert sweep["exact_upper_bound"] == pytest.approx(0.6435, abs=1e-4), sweep
        assert sweep["current"] == 0.6, sweep
        assert sweep["current_is_perfect"] is True, sweep
        assert sweep["false_positive_lower_bound"] == pytest.approx(0.1297, abs=1e-4), sweep
        assert sweep["inconclusive_lower_bound"] == pytest.approx(0.3982, abs=1e-4), sweep


if __name__ == "__main__":       # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
