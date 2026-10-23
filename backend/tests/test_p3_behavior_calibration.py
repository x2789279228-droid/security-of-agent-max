"""
P3: 行为检测权重与阈值的标定门禁。

守护三件事：

A. **标定集本身是有效的**（完整性 + 覆盖 + 可复现）
B. **评估器是可用量具**：当前 0.6/0.8/0.95 落在数据支持区间内，
   且档位重实现必须与真检测器逐条一致（否则阈值扫描扫的是自己）
C. **两条已记录的结构性限制被钉住**，使它们是「被知道的」而非
   「被误以为不存在的」：
     · 加权分的分母只累加**实际存在**的维度
     · ``target_hash_top`` / ``weekday_counts`` / ``ewma_*``
       被累积、被持久化，但 ``score_params`` / ``score_time`` 从不读取

C 这两条现在被标为限制而非缺陷：改动它们会全局改变判分，
在有了更多标注样本之前动它属于无数据的猜测。
"""
import ast
import inspect

import pytest

from eval_datasets.behavior_cases import BASELINE_N, same_length, scenarios
from eval_datasets.evaluate_behavior import (
    ACTIONS,
    DEFAULT_CONFIRM,
    DEFAULT_DENY,
    DEFAULT_WARN,
    EvalReport,
    ScenarioResult,
    _action_for,
    _assert_reimplementation_matches,
    _feasible,
    exact_conditional_bounds,
    normalization_sensitivity,
    render_report,
    run_scenarios,
    sweep_thresholds,
)
from mcp_guard.behavior_detector import BehaviorDetector
from mcp_guard.call_record import ToolCallRecord

CACHE = {}


def _report():
    """场景跑一次即可复用 —— 跑标定集要建几十条基线指纹，不便宜。"""
    if "r" not in CACHE:
        CACHE["r"] = run_scenarios()
    return CACHE["r"]


def _by_id(scn_id):
    return next(r for r in _report().results if r.scenario_id == scn_id)


# ═══════════════════════════════════════════
# A. 标定集完整性
# ═══════════════════════════════════════════

class TestDatasetIntegrity:
    def test_scenarios_have_required_fields(self):
        for scn in scenarios():
            for key in ("id", "baseline", "probe", "expect"):
                assert key in scn, f"场景 {scn.get('id')} 缺少字段 {key}"
            assert scn["baseline"], f"场景 {scn['id']} 的基线为空"

    def test_ids_unique(self):
        ids = [s["id"] for s in scenarios()]
        assert len(ids) == len(set(ids)), f"重复场景 id：{ids}"

    def test_all_actions_covered(self):
        """每档至少一条 —— 缺哪档，那档就从未被数据检验过。"""
        seen = {s["expect"] for s in scenarios()}
        assert seen == set(ACTIONS), f"档位覆盖不全：{seen}"

    def test_baseline_is_large_enough_to_be_ready(self):
        """基线长度必须 ≥ 默认 min_samples=30，否则指纹根本不 ready。"""
        for scn in scenarios():
            assert len(scn["baseline"]) >= BASELINE_N, (
                f"场景 {scn['id']} 基线只有 {len(scn['baseline'])} 条，"
                f"不足 {BASELINE_N}"
            )

    def test_deny_scenarios_declare_deny_mode(self):
        """默认 mode=confirm 永远产生不了 deny —— 标注与 mode 必须自洽。"""
        for scn in scenarios():
            if scn["expect"] == "deny":
                assert (scn.get("detector_kwargs") or {}).get("mode") == "deny", (
                    f"场景 {scn['id']} 标注 deny 却未把 mode 设为 deny —— "
                    f"该标注永远无法成立"
                )

    def test_same_length_helper_actually_equalises(self):
        base = "block 10.0.0.5 by analyst after manual review"
        out = same_length(base, "short")
        assert len(out) == len(base)
        assert out != base, "同长构造不应等于原串"
        long_out = same_length(base, "x" * 500)
        assert len(long_out) == len(base)

    def test_probe_hour_is_covered_by_baseline_except_when_intended(self):
        """**真实约束不是时间先后，而是探针的小时是否被基线覆盖过。**

        `score_time` 要求该小时历史占比 ≥ 8% 才不告警。40 个样本
        按 700 秒间隔只跨约 7.8 小时，最多覆盖 8 个小时 ——
        探针一旦落在未覆盖的小时，time 维必然给 0.85，
        于是**所有**场景都会变成 confirm，标注全废。

        所以：除刻意制造时段偏离的场景外，探针的小时必须在基线里出现过。
        两种情况不适用本约束：
          · 场景刻意要打未覆盖的小时（off_hours_only）
          · **探针工具不在基线里** —— 此时该工具没有指纹，
            param 与 time 两维压根不出现（不是 0，是缺席），
            小时覆盖与否不影响判分。
        """
        for scn in scenarios():
            if scn["expect"] == "confirm" and scn["id"] == "off_hours_only":
                continue  # 本条就是要打未覆盖的小时
            if scn.get("known_gap"):
                continue  # 缺口场景只考察 param 维
            baseline_tools = {b["tool_name"] for b in scn["baseline"]}
            if scn["probe"]["tool_name"] not in baseline_tools:
                continue  # 无指纹 → param/time 缺席
            hours = {b["ts"].hour for b in scn["baseline"]}
            assert scn["probe"]["ts"].hour in hours, (
                f"场景 {scn['id']} 的探针落在 {scn['probe']['ts'].hour} 时，"
                f"而基线只覆盖 {sorted(hours)} —— time 维会主导判分"
            )


class TestDeterminism:
    def test_repeated_runs_agree(self):
        """标定集必须可复现 —— 两次独立跑出同一结果。"""
        a = {r.scenario_id: (r.got, r.score, r.max_dim)
             for r in run_scenarios().results}
        b = {r.scenario_id: (r.got, r.score, r.max_dim)
             for r in run_scenarios().results}
        assert a == b, "同一标定集两次运行结果不同 —— 存在未固定的随机源"

    def test_results_are_stable_within_process(self):
        assert _report() is _report()


# ═══════════════════════════════════════════
# B. 评估器是可用量具
# ═══════════════════════════════════════════

class TestEvaluationHarness:
    def test_all_labeled_scenarios_pass(self):
        rep = _report()
        assert not rep.misses, (
            "标定集未全对："
            + "; ".join(
                f"{r.scenario_id} 标注 {r.expect} 实得 {r.got}"
                f"(score={r.score}, max_dim={r.max_dim})"
                for r in rep.misses
            )
        )
        assert rep.accuracy == 1.0

    def test_every_class_has_perfect_precision_and_recall(self):
        for label, m in _report().per_class.items():
            assert m["precision"] == 1.0, f"{label} 精确率不足：{m}"
            assert m["recall"] == 1.0, f"{label} 召回率不足：{m}"

    def test_thresholds_within_data_supported_region(self):
        """0.6/0.8/0.95 从「看起来合理」升级为「数据支持」。"""
        sweep = sweep_thresholds(_report())
        assert sweep["current_is_perfect"], (
            f"当前阈值 {sweep['current']} 已越出标定集支持的区间"
        )

    def test_separation_margin_is_positive(self):
        """logged 与应处置之间必须留有间隔，否则阈值无从下手。"""
        m = _report().separation["margin"]
        assert m is not None and m > 0, f"两组分数无间隔（{m}）"

    def test_known_gap_excluded_from_accuracy(self):
        rep = _report()
        gaps = [r for r in rep.results if r.known_gap]
        assert gaps, "标定集未登记任何 known_gap"
        counted = {r.scenario_id for r in rep.results if r.counted}
        for g in gaps:
            assert g.scenario_id not in counted

    def test_reimplementation_guard_fires(self, monkeypatch):
        """反向测试：故意弄坏档位重实现，扫描必须抛错而不是自说自话。"""
        rep = _report()
        monkeypatch.setattr(
            "eval_datasets.evaluate_behavior._action_for",
            lambda *a, **k: "logged",
        )
        with pytest.raises(AssertionError, match="重实现与真检测器不一致"):
            _assert_reimplementation_matches(rep)

    def test_reimplementation_agrees_when_intact(self):
        _assert_reimplementation_matches(_report())


class TestActionRecomputation:
    def test_shadow_mode_never_acts(self):
        assert _action_for(0.99, 0.99, True, "shadow", 0.0, 0.0, 0.0) == "logged"

    def test_not_anomaly_is_logged(self):
        assert _action_for(0.1, 0.1, False, "deny", 0.0, 0.0, 0.0) == "logged"

    def test_deny_mode_uses_deny_threshold(self):
        assert _action_for(0.96, 0.0, True, "deny", 0.6, 0.8, 0.95) == "deny"

    def test_confirm_mode_cannot_produce_deny(self):
        """mode=confirm 时无论多高都只能 confirm —— 与真实现一致。"""
        assert _action_for(0.99, 0.99, True, "confirm", 0.6, 0.8, 0.95) == "confirm"

    def test_single_high_dim_triggers_without_weighted_score(self):
        """**并行触发路径**：加权分只有 0.13，单维度 0.85 仍须 confirm。"""
        got = _action_for(0.1275, 0.85, True, "confirm",
                          DEFAULT_WARN, DEFAULT_CONFIRM, DEFAULT_DENY)
        assert got == "confirm"

    def test_single_high_dim_confirm_mode_gives_confirm_not_deny(self):
        got = _action_for(0.33, 0.96, True, "confirm",
                          DEFAULT_WARN, DEFAULT_CONFIRM, DEFAULT_DENY)
        assert got == "confirm", (
            "max_dim 0.96 在 confirm 模式下被升成了 deny —— 与真实现不符"
        )


# ═══════════════════════════════════════════
# C. 已记录的结构性限制（钉住真实行为）
# ═══════════════════════════════════════════

class TestDocumentedLimitationPresentDimsNormalisation:
    """加权分的分母**只累加实际存在的维度**。

    实测后果：同一个 0.95 的单维信号，得分可以是 0.3325 也可以是 0.925，
    相差 2.8 倍 —— 差别只在于该维度有没有基线可比。
    这不是 bug（改它会全局改变判分），但必须是被知道的。
    """

    def test_single_dim_with_all_four_available(self):
        r = _by_id("new_ip_class_public")
        assert r.dimensions.get("param") == pytest.approx(0.95)
        assert r.score == pytest.approx(0.3325, abs=1e-4), (
            f"四维齐备时单维 0.95 的加权分应为 0.95*0.35=0.3325，实际 {r.score}"
        )

    def test_same_single_dim_with_only_two_available(self):
        r = _by_id("impossible_transition")
        assert r.max_dim == pytest.approx(0.95)
        assert r.score == pytest.approx(0.925, abs=1e-4), (
            f"仅两维参与时 0.95 的加权分应为 ~0.925，实际 {r.score}"
        )

    def test_normalisation_is_over_present_dims(self):
        """分母是「出现过的维度权重之和」，不是四个权重之和。"""
        import inspect as _i
        src = _i.getsource(BehaviorDetector._score_locked)
        assert "denom += w" in src
        assert "for name, value in dims.items()" in src, (
            "分母若改成对全部四维归一，加权分的含义会整体变化 —— "
            "请同步更新本测试与本文件头部说明"
        )

    def test_absent_dimensions_are_dropped_not_zero(self):
        """维度缺失（指纹未就绪）与「该维度得 0」不是一回事。"""
        r = _by_id("caller_uses_new_tool")
        assert "param" not in r.dimensions, (
            "该场景 param 维度应当缺失（alert_only 无基线）"
        )
        assert r.score == pytest.approx(0.925, abs=1e-4)


class TestDocumentedLimitationDeadFields:
    """被累积、被持久化，但从不参与判分的字段。

    ``target_hash_top`` 记录了每个目标的精确指纹（做哈希），
    但 ``score_params`` 只读 ip_class / categorical / numeric / str_len。
    实测后果（见 known_gap 场景 new_target_same_class）：
    换成一个从未见过、但**同类且等长**的目标，四个维度全是 0.0，
    检测器完全看不见。
    """

    def test_target_hash_top_is_never_read_by_scoring(self):
        from mcp_guard.behavior_signature import ToolBehaviorSignature

        src = inspect.getsource(ToolBehaviorSignature.score_params)
        assert "target_hash_top" not in src, (
            "score_params 已开始读取 target_hash_top —— "
            "精确目标指纹不再有缺口，请更新本测试与 known_gap 标注"
        )

    def test_weekday_and_rate_fields_are_never_scored(self):
        from mcp_guard.behavior_signature import ToolBehaviorSignature

        p = inspect.getsource(ToolBehaviorSignature.score_params)
        t = inspect.getsource(ToolBehaviorSignature.score_time)
        for dead in ("weekday_counts", "ewma_per_min", "minute_buckets"):
            assert dead not in p and dead not in t, (
                f"{dead} 已被接入判分 —— 请更新本测试与本文件头部说明"
            )

    def test_fields_are_still_learned_and_persisted(self):
        """它们确实在累积 —— 这正是「看起来像防御」的地方，必须继续记账。"""
        from mcp_guard.behavior_signature import ToolBehaviorSignature

        src = inspect.getsource(ToolBehaviorSignature.update)
        for dead in ("weekday_counts", "ewma_per_min", "target_hash_top"):
            assert dead in src, f"{dead} 不再被累积"

    def test_known_gap_scenarios_are_currently_invisible(self):
        """钉住缺口的**当前形态**：两条都判 logged 且四维全 0。

        若哪天有人接上了 target_hash_top，这条会变红 —— 那正是我们要的：
        它会提示「known_gap 标注需要更新」，而不是默默失去覆盖。
        """
        for sid in ("new_payload_same_length", "new_target_same_class"):
            r = _by_id(sid)
            assert r.got == "logged", (
                f"{sid} 现在被判 {r.got} —— "
                f"若这是修复而非回归，请更新 known_gap 标注"
            )
            assert all(v == 0.0 for v in r.dimensions.values()), (
                f"{sid} 的维度不再是全 0：{r.dimensions}"
            )

    def test_detector_module_has_no_unexpected_top_level_statements(self):
        import eval_datasets.evaluate_behavior as mod

        tree = ast.parse(inspect.getsource(mod))
        for node in tree.body:
            assert isinstance(
                node, (ast.Import, ast.ImportFrom, ast.Assign, ast.AnnAssign,
                       ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef,
                       ast.Expr, ast.If)
            ), f"评估器顶层出现意外语句：{type(node).__name__}"


# ═══════════════════════════════════════════
# D. 与 P3-1 的接线一致性
# ═══════════════════════════════════════════

class TestWiredToAuditNamespace:
    """标定出的档位必须在审计工具侧真的被执行（P3-1 的收敛契约）。"""

    def test_deny_scenario_would_block_audit_tool(self):
        import mcp_guard
        import tool_registry as tr_mod
        from mcp_guard.behavior_detector import SignatureReport

        rep = _by_id("impossible_transition")
        assert rep.got == "deny"

        class _Stub:
            def observe_pre_exec(self, rec):
                return SignatureReport(
                    anomaly_score=rep.score, is_anomaly=True,
                    reasons=rep.reasons, dimensions=rep.dimensions,
                    cold_start=False, sample_count=BASELINE_N,
                    action="deny",
                )

        original = mcp_guard.mcp_guard.detector
        try:
            mcp_guard.mcp_guard.detector = _Stub()
            res = tr_mod._pre_execute_check(
                "event_store.query", {"risk_level": "low"}, {},
            )
        finally:
            mcp_guard.mcp_guard.detector = original
        assert res["passed"] is False, (
            "标定集判定的 deny 在审计工具侧未生效 —— 标定与执行脱节"
        )

    def test_confirm_scenario_records_but_does_not_block(self):
        import mcp_guard
        import tool_registry as tr_mod
        from mcp_guard.behavior_detector import SignatureReport

        rep = _by_id("off_hours_only")
        assert rep.got == "confirm"

        class _Stub:
            def observe_pre_exec(self, rec):
                return SignatureReport(
                    anomaly_score=rep.score, is_anomaly=True,
                    reasons=rep.reasons, dimensions=rep.dimensions,
                    cold_start=False, sample_count=BASELINE_N,
                    action="confirm",
                )

        original = mcp_guard.mcp_guard.detector
        try:
            mcp_guard.mcp_guard.detector = _Stub()
            res = tr_mod._pre_execute_check(
                "event_store.query", {"risk_level": "low"}, {},
            )
        finally:
            mcp_guard.mcp_guard.detector = original
        assert res["passed"] is True
        assert "确认" in res["reason"], "confirm 未在 reason 中显式标注"


# ══════════════════════════════════════════════════════════════════
# E. 归一口径缺口：实测它到底影响什么
# ══════════════════════════════════════════════════════════════════

class TestNormalizationSensitivityIsMeasured:
    """把「加权分只按实际存在的维度归一」从猜测变成实测结论。

    背景：``_score_locked`` 的分母只累加**实际存在**维度的权重，
    所以同一个 0.95 单维信号，四维齐备时得 0.3325、只有两维时得 0.925。
    直觉上这像是「维度少时虚高」，但**没测过就只是猜测**。

    实测结论（11 条标定样本）：

        · 只有 2 条存在维度缺失，均为 caller+seq 两维
        · 这 2 条的加权分确实从 0.925 掉到 0.4625（跨过 warn 与 confirm）
        · 但**判定一条都没翻转** —— 因为 max_dim=0.95 独立满足阈值

    也就是说：改归一改变的是**上报的分数**（运维看到的 anomaly_score），
    不是**门控的结果**。在没有更多标注样本之前动它属于无数据猜测，
    本组测试把这个结论钉住，使它成为「被知道的限制」而非「被误以为已修」。
    """

    def test_only_two_scenarios_have_missing_dimensions(self):
        s = normalization_sensitivity(_report())
        assert s["full_denom"] == pytest.approx(1.0)
        assert s["n_missing_dims"] == 2, (
            f"维度缺失的样本数变成 {s['n_missing_dims']} 条 —— "
            f"若新增了样本请重新评估本组结论"
        )
        assert {x["scenario_id"] for x in s["rows"] if x["n_dims"] < 4} == {
            "caller_uses_new_tool", "impossible_transition",
        }

    def test_alternative_normalization_changes_score_but_not_decision(self):
        s = normalization_sensitivity(_report())
        assert s["n_flipped"] == 0, (
            "改按全维归一后出现了判定翻转 —— 本缺口已不再「无影响」，"
            "需要重新评估并更新本登记"
        )
        for x in s["rows"]:
            if x["n_dims"] < 4:
                assert x["score_now"] == pytest.approx(0.925)
                assert x["score_alt"] == pytest.approx(0.4625)
                # 加权分已经跌破 confirm 阈值，决策靠的是单维度路径
                assert x["score_alt"] < DEFAULT_CONFIRM
                assert x["max_dim"] >= DEFAULT_CONFIRM

    def test_single_dim_path_is_independent_of_dimension_count(self):
        """strong / max_dim 读原始维度值，与维度数量无关 —— 这是结论成立的前提。"""
        src = inspect.getsource(BehaviorDetector._score_locked)
        assert "max_dim = max(" in src
        assert "dims.values() if v is not None" in src
        assert "len(dims)" not in src, (
            "单维度路径开始依赖维度数量了 —— "
            "「改归一不影响判定」这个前提已不成立"
        )


# ══════════════════════════════════════════════════════════════════════════
# G. 阈值扫描的呈现与精确边界
# ══════════════════════════════════════════════════════════════════════════
#
# 本组针对的缺陷不是「算错了」，而是**算对了却报错了对象**：
#
#   1. sweep 用 `continue` 静默跳过 confirm < warn 与 deny < confirm 的组合，
#      却把受限域上的投影印成「完全满足的 X 区间」。实测 21^3=9261 个网格
#      组合里只有 1771 个进入枚举域 —— 81% 被跳过，且从未声明。
#   2. 三个投影是**边缘投影**（含义是「存在其余两维可行」），
#      不是精确边界，也不是可行域。旧渲染把它们当成区间直接呈现。
#   3. 「我能不能单独调这一个阈值、调多少」这个问题，投影根本回答不了：
#      它把 warn 的上界说成 0.80，而固定 confirm=0.8/deny=0.95 后
#      warn 的精确可行区间是 [0.00, 1.00] —— 少说了 0.20。
#
# 第 3 条的量最实：confirm 与 deny 的上侧余量实测均为 **+0.0000**，
# 即当前阈值正卡在精确上界上，**一点都调不上去**。旧工具从未说过这件事。

class TestSweepDomainIsDeclared:
    def test_sweep_declares_the_ordering_domain_it_enforces(self):
        sw = sweep_thresholds(_report())
        assert sw["domain"] == "warn <= confirm <= deny"
        assert "不参与扫描" in sw["domain_note"]
        assert sw["n_enumerated"] < sw["n_grid_combos"], (
            "本用例的前提是 sweep 确实会跳过部分组合；"
            "若将来不再跳过，这条守卫的前提就失效了，需要改写而不是删掉"
        )

    def test_n_enumerated_matches_an_independent_recount(self):
        """登记的数字必须能被独立复算出来，而不是 sweep 自说自话。"""
        sw = sweep_thresholds(_report())
        step = sw["step"]
        grid = [round(x * step, 4) for x in range(int(1 / step) + 1)]
        n = sum(
            1
            for w in grid
            for c in grid
            if c >= w
            for d in grid
            if d >= c
        )
        assert sw["n_enumerated"] == n
        assert sw["n_grid_combos"] == len(grid) ** 3

    def test_projection_box_equals_the_feasible_set_once_ordered(self):
        """三投影交叉 ∩ 序约束 == 可行集（本数据集实测成立）。

        这条不是「盒子论」教条，是一次实测：5168 个交叉组合里，
        满足 warn<=confirm<=deny 的 1408 个恰好全部可行。
        写成守卫是为了让「序约束被删掉」或「投影被改算法」时立刻转红 ——
        两者都会让这个等式破裂。
        """
        rep = _report()
        scored = [r for r in rep.results if r.counted]
        sw = sweep_thresholds(rep)
        regs = set(sw["perfect_regions"])
        ws = sorted({r[0] for r in regs})
        cs = sorted({r[1] for r in regs})
        ds = sorted({r[2] for r in regs})
        box = {
            (w, c, d)
            for w in ws for c in cs for d in ds
            if w <= c <= d
        }
        assert box == regs
        assert all(_feasible(scored, *t) for t in box)


class TestExactConditionalBounds:
    def test_bounds_respect_the_declared_domain(self):
        """域约束：精确可行区间必须落在 ``warn <= confirm <= deny`` 之内。

        ⚠️ **本条在 §9.66 被改写过**（原断言是 ``warn.upper == 1.0``）。
        旧断言把「未施加域约束的上界」当成正确答案钉住了 ——
        而 (1.0, 0.8, 0.95) 越过了 confirm 门槛，是**该工具自己声明为
        不可搜索**的配置。运维照着调会得到 confirm 低于 warn 的组合。

        改写后的契约**更强**：不是「精确区间比投影宽」，而是
        「精确区间的每一条边都必须在声明域内」，并且原值保留在
        ``unconstrained_*`` 里可供追溯。
        """
        rep = _report()
        ex = exact_conditional_bounds(rep)
        cur = (DEFAULT_WARN, DEFAULT_CONFIRM, DEFAULT_DENY)
        for idx, name in enumerate(("warn", "confirm", "deny")):
            b = ex[name]
            for edge in ("lower", "upper"):
                t = list(cur)
                t[idx] = b[edge]
                assert t[0] <= t[1] <= t[2], (
                    f"{name}.{edge} = {b[edge]} 落在域外（组合 {tuple(t)}）—— "
                    "精确可行区间必须与网格扫描用同一个域"
                )

    def test_unconstrained_values_are_kept_for_traceability(self):
        """未施加域约束时的原始边界必须保留，但**不能**被当成可运维区间。"""
        ex = exact_conditional_bounds(_report())
        for name, b in ex.items():
            assert "unconstrained_lower" in b and "unconstrained_upper" in b
            assert b["unconstrained_lower"] <= b["lower"]
            assert b["unconstrained_upper"] >= b["upper"]

    def test_grid_projection_still_differs_from_the_conditional_slice(self):
        """两者回答的仍不是同一个问题 —— 不能用投影去断言精确区间。

        域约束施加后，两者在**上侧**已经一致（warn 都是 0.80）；
        但在**下侧**仍然不同：投影的 confirm 下界是 0.05，
        精确条件区间（其余两维固定）是 0.60 —— 后者被域约束
        「confirm >= warn = 0.6」顶住。**投影不能替代精确区间**。
        """
        rep = _report()
        ex = exact_conditional_bounds(rep)
        sw = sweep_thresholds(rep)
        grid_lo = min(r[1] for r in sw["perfect_regions"])
        assert grid_lo == pytest.approx(0.05)
        assert ex["confirm"]["lower"] == pytest.approx(0.60)
        assert ex["confirm"]["lower"] > grid_lo, (
            "投影与精确条件区间在 confirm 下界上必须仍可区分；"
            "若将来相等，说明其中一个的口径变了，需要重新评估本条"
        )

    def test_endpoints_sit_on_data_breakpoints(self):
        """端点必须落在数据值、域边界或 0/1 上 —— 证明是断点枚举而非又一次量化网格。

        ⚠️ §9.66 起允许的断点集**扩大**了一项：域约束的边界
        （其余两个阈值的当前值）也必须算作断点 ——
        否则扫描会跳过域边界、退而报出更窄的区间
        （实测：confirm 的域内下界本应是 0.6，漏掉后报成 0.8）。
        """
        rep = _report()
        scored = [r for r in rep.results if r.counted]
        allowed = {0.0, 1.0}
        allowed |= {r.score for r in scored if r.score is not None}
        allowed |= {r.max_dim for r in scored}
        allowed |= {DEFAULT_WARN, DEFAULT_CONFIRM, DEFAULT_DENY}
        ex = exact_conditional_bounds(rep)
        for name, b in ex.items():
            assert b["lower"] in allowed, f"{name} 下界 {b['lower']} 不在断点集上"
            assert b["upper"] in allowed, f"{name} 上界 {b['upper']} 不在断点集上"

    def test_infeasible_current_is_flagged_not_reported_as_zero_width(self):
        """当前值不可行时必须明说，不能退化成 0 宽度区间。

        退化成 [x, x] 会被读成「正好卡在边界上」，而真相是「这个点本身不可行」——
        这正是本轮在 §4.4/§4.7 修的那类谎报，只是换了个方向。
        """
        ex = exact_conditional_bounds(_report(), current=(0.0, 0.0, 0.0))
        for name in ("warn", "confirm", "deny"):
            b = ex[name]
            assert b["feasible_at_current"] is False, f"{name} 应被判为不可行"
            assert b["lower"] is None and b["upper"] is None

    def test_confirm_and_deny_have_zero_upward_headroom(self):
        """决策相关事实：当前 confirm=0.8 / deny=0.95 正卡在精确上界。

        若这条转红，说明标定集变了 —— 上侧余量从 0 变成了正数，
        意味着现在**可以**把这两个阈值往上调，这是运维行为变更，
        需要重新评估并更新本条登记，而不是直接改断言。
        """
        ex = exact_conditional_bounds(_report())
        assert ex["confirm"]["upper"] - ex["confirm"]["current"] == pytest.approx(0.0)
        assert ex["deny"]["upper"] - ex["deny"]["current"] == pytest.approx(0.0)
        assert ex["warn"]["upper"] - ex["warn"]["current"] > 0.1


    def test_bounds_are_exact_on_an_offgrid_dataset(self):
        """鉴别力守卫：真实标定集上三个边界恰好都落在网格点上，
        因此上面几条**无法**区分「精确」与「又一次 0.05 网格」。
        本用例用合成数据把上界放到 0.8034 —— 离网格点 0.80 有 0.0034 之差，
        任何网格化实现都会在这里露馅。

        构造：expect=confirm / mode=confirm / score=0.8034 / max_dim=0.0。
        is_anom 只能靠 `score >= warn_t` 成立（max_dim 0.0 够不到 0.8），
        所以 warn 的精确上界就是 0.8034，且因判据是 `>=` 而**闭**。

        ⚠️ **§9.66 改写了本条的取值来源**：域约束 ``warn <= confirm``
        会把 warn 的**域内**上界压到 confirm 当前值 0.8 —— 0.8034 那一段
        越域、不可运维。鉴别力因此改从 ``unconstrained_upper`` 取：
        它仍须精确等于 0.8034（证明是断点枚举而非 0.05 网格），
        同时域内上界须**不等于** 0.8034（证明域约束真的生效了）。
        两条合起来比原断言更强。
        """
        rep = EvalReport([
            ScenarioResult("synthetic_offgrid", "confirm", "confirm",
                           0.8034, 0.0, mode="confirm"),
        ])
        ex = exact_conditional_bounds(rep)
        # 鉴别力（未施加域约束时）：仍是精确的 0.8034，不是网格点
        assert ex["warn"]["unconstrained_upper"] == pytest.approx(0.8034)
        assert ex["warn"]["unconstrained_upper_closed"] is True, (
            "判据是 score >= t，上界应为闭"
        )
        assert ex["confirm"]["upper"] == pytest.approx(0.8034)
        # 域约束生效：warn 的域内上界被 confirm=0.8 顶住
        assert ex["warn"]["upper"] == pytest.approx(DEFAULT_CONFIRM)
        assert ex["warn"]["upper"] != pytest.approx(0.8034)
        # deny 对 mode=confirm 的样本不参与判定，因此全域可行（但域内下界是 confirm）
        assert ex["deny"]["upper"] == pytest.approx(1.0)
        assert ex["deny"]["lower"] == pytest.approx(DEFAULT_CONFIRM)
        assert ex["deny"]["unconstrained_lower"] == pytest.approx(0.0)
        # 明确排除网格解：0.80 与 0.85 都必须不等于真实上界
        assert ex["warn"]["unconstrained_upper"] not in (pytest.approx(0.80),
                                                        pytest.approx(0.85))


class TestSweepRenderingIsHonest:
    def test_render_declares_domain_and_labels_projections_as_grid(self):
        out = render_report(_report(), sweep_thresholds(_report()))
        assert "搜索域 = warn <= confirm <= deny" in out
        assert "网格(步长 0.05)上的投影" in out
        assert "精确可行区间" in out
        # 旧文案把网格投影说成「完全满足的 X 区间」，读起来像精确可行域
        assert "完全满足的 warn 区间" not in out
        assert "完全满足的 confirm 区间" not in out
        assert "完全满足的 deny 区间" not in out

    def test_render_does_not_fabricate_a_residual_between_incomparable_objects(self):
        """精确区间与网格投影回答的不是同一个问题，相减没有意义。

        这条钉的是「不给残差」这个决定本身 —— 防止后来者看到上面那组数字
        手痒补一行「差 +0.20」，那会把两个不同的量说成同一个量的误差。
        """
        out = render_report(_report(), sweep_thresholds(_report()))
        assert "不给残差" in out