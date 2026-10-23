# -*- coding: utf-8 -*-
"""行为检测阈值的「余量」到底意味着什么（整改报告 §9.66）。

## 背景

整改报告 §4.8 曾给出这样一张表：

| 阈值 | 精确可行区间 | 当前值 | 上侧余量 |
|---|---|---|---|
| behavior `warn` | `[0.0000, 1.0000]` | 0.6 | +0.4000 |
| behavior `confirm` | `[0.0000, 0.8000]` | 0.8 | +0.0000 |
| behavior `deny` | `[0.0000, 0.9500]` | 0.95 | +0.0000 |

§9.2 学到一条纪律：「某阈值的余量恰好是 0，写进结论前应先怀疑输入」。
本文件把那条纪律用到 behavior 上，并给出**三层**结论：

## 三层结论（本轮实测钉住）

### 一、「余量恰好 0」的成因不是数据稀疏，而是**离散常量与阈值同值**

behavior 的维度分是**离散常量**（`_score_caller` 返回 0.55/0.7/0.75/0.8/
0.85/0.9，`_score_seq` 返回 0.95/0.8/0.0，`score_params` 返回
0.95/0.9/0.8/0.7/0.65）。而 confirm 阈值恰好是 **0.8**、deny 阈值恰好是 **0.95**
—— 与常量集**重合**。

实测上界的代数式（不是拟合出来的）：

    confirm 上界 = min over confirm 族样本的 max(score, max_dim)
                = min(0.8, 0.85, 0.95) = 0.8   ← 由 non_exact_tool_match 钉住
    deny    上界 = min over deny 族样本的 max(score, max_dim)
                = min(0.95, 0.95, 1.0) = 0.95  ← 由 new_ip_class_public 钉住

⇒ **扩样本并不能放宽上界**（实测：加 0.90/0.95/1.00 的 confirm 样本、
加 0.97/1.00 的 deny 样本，上界纹丝不动）。
「合成集代表性不足所以调不上去」这个解释**不成立**。

### 二、「精确可行区间」原本**没有**施加该工具自己声明的序约束

`sweep_thresholds` 显式声明 `domain = "warn <= confirm <= deny"` 并用 `continue`
跳过越域组合；但 `exact_conditional_bounds` 这条路径**不施加**同一个域，
于是报出的区间里混进了该工具自己声明为不可搜索的配置：
warn 上界 1.0（越过 confirm）、confirm 下界 0.0（低于 warn）、deny 下界 0.0。

⇒ 修复后（其余两阈值固定在当前值）：
    warn    域内 [0.0000, 0.8000]  上余量 +0.2000
    confirm 域内 [0.6000, 0.8000]  上余量 +0.0000
    deny    域内 [0.8000, 0.9500]  上余量 +0.0000
⚠ 下界由**域约束**（语义序关系）决定，不是由样本决定 —— 读作「不能低于 X」。

### 三、「可行区间宽」≠「旋钮有用」

区间宽度只保证「标定集仍然全对」，不保证「行为真的变了」。
实测：三个阈值在各自域内区间上，**没有任何一个取值点改变过任何一条样本的
处置档位**。因为维度分是离散常量，样本的 score / max_dim 落在
0.0 / 0.2 / 0.8 / 0.85 / 0.95 / 1.0 这些**固定值**上，
阈值在相邻取值之间移动不改变任何 `>=` 的结果。

⇒ 「余量 +0.4000」不能被读成「有 0.40 的调节空间」。

## 本文件钉住什么

* 上述三层事实**不被悄悄改掉**（含各自的判据）；
* `strong` 门限在生产与评估器里**只有一处定义**（单一真源）；
* 域约束一旦被移除，守卫必须转红（注入验红）。
"""
from __future__ import annotations

import ast
import inspect
import textwrap

import pytest

from eval_datasets.evaluate_behavior import (
    DEFAULT_CONFIRM,
    DEFAULT_DENY,
    DEFAULT_WARN,
    EvalReport,
    ScenarioResult,
    _action_for,
    _within_domain,
    exact_conditional_bounds,
    knob_effectiveness,
    render_report,
    run_scenarios,
    sweep_thresholds,
)
from mcp_guard import behavior_detector, behavior_signature
from mcp_guard.behavior_detector import (
    SEVERITY_HIGH_SCORE,
    STRONG_DIM_THRESHOLD,
    BehaviorDetector,
)

CACHE: dict = {}


def _report():
    if "r" not in CACHE:
        CACHE["r"] = run_scenarios()
    return CACHE["r"]


def _scored():
    return [r for r in _report().results if r.counted]


# ═══════════════════════════════════════════
# 一、维度分是离散常量，阈值与常量**同值**
# ═══════════════════════════════════════════

class TestDimensionScoresAreDiscreteConstants:
    def test_confirm_and_deny_thresholds_coincide_with_dimension_constants(self):
        """confirm=0.8 / deny=0.95 都落在维度分的**离散常量集**里。

        这不是巧合的数字，而是「余量恰好 0」的**成因**：
        判据是 `max_dim >= t`，而 max_dim 只会取那几个常量值 ——
        阈值一旦等于某个常量，该常量对应的整类信号就恰好卡在阈值上，
        往上挪一丁点就整类失效。
        """
        consts = set()
        for cls, meth in (
            (behavior_detector.BehaviorDetector, "_score_seq"),
            (behavior_detector.BehaviorDetector, "_score_caller"),
            (behavior_signature.ToolBehaviorSignature, "score_params"),
            (behavior_signature.ToolBehaviorSignature, "score_time"),
        ):
            src = textwrap.dedent(inspect.getsource(getattr(cls, meth)))
            tree = ast.parse(src)
            for node in ast.walk(tree):
                if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
                    if not isinstance(node.value, bool) and 0.0 < node.value <= 1.0:
                        consts.add(float(node.value))
        assert STRONG_DIM_THRESHOLD in consts
        assert DEFAULT_CONFIRM in consts, (
            "confirm 阈值不再与任何维度分常量重合 —— "
            "「余量恰好 0」的成因已变，请重新评估本文件的三层结论"
        )
        assert DEFAULT_DENY in consts, (
            "deny 阈值不再与任何维度分常量重合 —— "
            "「余量恰好 0」的成因已变，请重新评估本文件的三层结论"
        )

    def test_upper_bound_equals_min_over_family_of_max_score_and_max_dim(self):
        """上界的**代数式**：min over 该档样本的 max(score, max_dim)。

        这是可独立重算的结构不变式，不是拟合出来的数字。
        """
        scored = _scored()
        ex = exact_conditional_bounds(_report())
        for name, family in (("confirm", ("confirm",)), ("deny", ("deny",))):
            vals = [
                max(r.score, r.max_dim)
                for r in scored if r.expect in family
            ]
            assert vals, f"{name} 族没有样本"
            assert ex[name]["upper"] == pytest.approx(min(vals)), (
                f"{name} 上界不等于族内 min(max(score,max_dim))={min(vals)}"
            )

    def test_adding_same_family_samples_cannot_widen_the_upper_bound(self):
        """扩样本**不能**放宽上界 —— 「合成集代表性不足」不是上界为 0 的原因。

        构造：加入与当前实现**一致**（got == expect）的同族样本，
        上界必须**纹丝不动**。若哪天变成能放宽，说明区间语义变了，
        本文件的三层结论需要重新评估。
        """
        base = exact_conditional_bounds(_report())
        extra_rows = [
            ("extra_confirm_090", "confirm", "confirm", 0.3, 0.90),
            ("extra_confirm_095", "confirm", "confirm", 0.3, 0.95),
            ("extra_confirm_100", "confirm", "confirm", 0.3, 1.00),
            ("extra_deny_097", "deny", "deny", 0.4, 0.97),
            ("extra_deny_100", "deny", "deny", 0.4, 1.00),
        ]
        rows = list(_report().results)
        for sid, exp, mode, score, md in extra_rows:
            is_anom = (
                (score is not None and score >= DEFAULT_WARN)
                or md >= STRONG_DIM_THRESHOLD
            )
            got = _action_for(score, md, is_anom, mode,
                              DEFAULT_WARN, DEFAULT_CONFIRM, DEFAULT_DENY)
            assert got == exp, f"{sid}: 构造的样本与当前实现不一致（got={got}）"
            rows.append(ScenarioResult(sid, exp, got, score, md, mode=mode))
        grown = exact_conditional_bounds(EvalReport(rows))
        for name in ("confirm", "deny"):
            assert grown[name]["upper"] == pytest.approx(base[name]["upper"]), (
                f"加入同族样本后 {name} 上界变了 —— "
                "「扩样本不能放宽上界」这条前提已失效"
            )


# ═══════════════════════════════════════════
# 二、域约束：精确可行区间必须在声明域内
# ═══════════════════════════════════════════

class TestDomainConstraintIsApplied:
    def test_every_endpoint_of_the_conditional_interval_is_in_domain(self):
        rep = _report()
        ex = exact_conditional_bounds(rep)
        cur = (DEFAULT_WARN, DEFAULT_CONFIRM, DEFAULT_DENY)
        for idx, name in enumerate(("warn", "confirm", "deny")):
            b = ex[name]
            for edge in ("lower", "upper"):
                t = list(cur)
                t[idx] = b[edge]
                assert _within_domain(*t), (
                    f"{name}.{edge}={b[edge]} → 组合 {tuple(t)} 越域；"
                    "精确可行区间必须与 sweep_thresholds 用同一个域"
                )

    def test_sweep_and_conditional_bounds_use_the_same_domain(self):
        """两条路径必须用**同一个**域 —— 同一个工具里不能有两套标准。"""
        sw = sweep_thresholds(_report())
        assert sw["domain"] == "warn <= confirm <= deny"
        ex = exact_conditional_bounds(_report())
        for name, b in ex.items():
            assert b["domain"] == sw["domain"], (
                f"{name} 声明的域与 sweep 不一致："
                f"{b['domain']!r} vs {sw['domain']!r}"
            )

    def test_the_domain_boundary_is_a_breakpoint(self):
        """域边界必须进断点集，否则扫描会跳过边界、报出更窄的区间。

        实测：confirm 的域内下界本应是 0.6（被 confirm >= warn 顶住），
        漏掉域边界后会报成 0.8。
        """
        ex = exact_conditional_bounds(_report())
        assert ex["confirm"]["lower"] == pytest.approx(DEFAULT_WARN), (
            "confirm 的域内下界应被「confirm >= warn」顶在 warn 当前值上；"
            "若变成别的值，说明域边界没进断点集"
        )
        assert ex["deny"]["lower"] == pytest.approx(DEFAULT_CONFIRM), (
            "deny 的域内下界应被「deny >= confirm」顶在 confirm 当前值上"
        )

    def test_unconstrained_values_are_reported_but_flagged_as_not_operable(self):
        """原始（越域）值保留供追溯，但不能冒充可运维区间。"""
        ex = exact_conditional_bounds(_report())
        # warn 的越域上界是 1.0 —— 越过了 confirm 门槛
        assert ex["warn"]["unconstrained_upper"] == pytest.approx(1.0)
        assert ex["warn"]["upper"] < ex["warn"]["unconstrained_upper"], (
            "域约束若失效，warn 的上界会回到 1.0"
        )
        # confirm / deny 的越域下界是 0.0
        assert ex["confirm"]["unconstrained_lower"] == pytest.approx(0.0)
        assert ex["deny"]["unconstrained_lower"] == pytest.approx(0.0)

    def test_domain_removal_makes_the_interval_out_of_domain(self):
        """反向证明：把域约束去掉，区间立刻含越域点。

        这条让「域约束真的在起作用」这件事**可观察**，
        而不是靠读代码相信。
        """
        scored = _scored()
        cur = (DEFAULT_WARN, DEFAULT_CONFIRM, DEFAULT_DENY)
        # 不施加域约束时，warn 的上界可以到 1.0
        from eval_datasets.evaluate_behavior import _feasible

        assert _feasible(scored, 1.0, DEFAULT_CONFIRM, DEFAULT_DENY) is True
        assert _within_domain(1.0, DEFAULT_CONFIRM, DEFAULT_DENY) is False


# ═══════════════════════════════════════════
# 三、旋钮有效性：区间宽 ≠ 旋钮有用
# ═══════════════════════════════════════════

class TestKnobEffectiveness:
    def test_no_threshold_changes_any_action_within_its_domain_interval(self):
        """三个阈值在各自域内区间上，都不改变任何一条样本的处置档位。

        这是「余量 ≠ 调节空间」的**决定性**证据。
        若哪天转红，说明维度分不再是离散常量、或阈值挪到了常量之间 ——
        那时「余量」才真的开始有意义，本条需要重新评估。
        """
        eff = knob_effectiveness(_report())
        for name in ("warn", "confirm", "deny"):
            e = eff[name]
            assert e["action_changes"] == 0, (
                f"{name} 区间内出现了 {e['action_changes']} 个改变处置档位的取值点 —— "
                "维度分可能不再是离散常量，请重新评估本文件结论"
            )
            assert e["inert"] is True, f"{name} 区间应被判定为整段无效旋钮"

    def test_inert_is_judged_by_action_not_by_is_anomaly(self):
        """``inert`` 只看处置档位 —— is_anomaly 翻转不改变处置后果。

        实测：warn=0.0 会让三条 logged 样本的 is_anomaly 变 True，
        但它们的 action 仍是 logged（档位判定还要过 confirm/deny 门限）。
        拿 is_anomaly 充数会把「整段无效旋钮」误判成「有效果」。
        """
        eff = knob_effectiveness(_report())
        assert eff["warn"]["anomaly_changes"] >= 0
        assert eff["warn"]["inert"] is True, (
            "warn 区间内确有 is_anomaly 翻转点（端点 0.0），"
            "但处置档位未变 ⇒ 必须仍判为 inert"
        )

    def test_effectiveness_uses_the_domain_interval(self):
        """有效性必须建立在**域内**区间上 —— 越域取值不是可运维的。"""
        eff = knob_effectiveness(_report())
        ex = exact_conditional_bounds(_report())
        for name in ("warn", "confirm", "deny"):
            assert eff[name]["interval"] == (ex[name]["lower"], ex[name]["upper"])
        # 越域的 confirm=0.0 也不该被算进 warn 的有效性
        assert eff["confirm"]["interval"][0] == pytest.approx(DEFAULT_WARN)


# ═══════════════════════════════════════════
# 四、strong 门限的单一真源
# ═══════════════════════════════════════════

class TestStrongThresholdHasOneSource:
    def test_production_exposes_the_constant(self):
        assert STRONG_DIM_THRESHOLD == 0.8
        assert SEVERITY_HIGH_SCORE == 0.8

    def test_production_uses_the_named_constant_not_a_literal(self):
        """生产判分处必须引用常量，而不是再写一个字面量 0.8。"""
        src = inspect.getsource(BehaviorDetector._score_locked)
        assert "STRONG_DIM_THRESHOLD" in src, (
            "_score_locked 不再引用 STRONG_DIM_THRESHOLD —— "
            "strong 门限的单一真源已断"
        )
        # 方法体带缩进，直接 ast.parse 会 IndentationError —— 先 dedent
        tree = ast.parse(textwrap.dedent(src))
        for node in ast.walk(tree):
            if isinstance(node, ast.Compare):
                for c in node.comparators:
                    assert not (
                        isinstance(c, ast.Constant) and c.value == 0.8
                    ), "_score_locked 里又出现了字面量 0.8 的比较"

    def test_evaluator_imports_the_constant_instead_of_hardcoding(self):
        """评估器不得自带一份 0.8 —— 两份定义迟早会漂移。"""
        import eval_datasets.evaluate_behavior as mod

        src = inspect.getsource(mod)
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if isinstance(node, ast.Compare):
                for c in node.comparators:
                    assert not (
                        isinstance(c, ast.Constant) and c.value == 0.8
                    ), (
                        "evaluate_behavior 里出现了字面量 0.8 的比较 —— "
                        "请改为引用 STRONG_DIM_THRESHOLD"
                    )

    def test_strong_threshold_is_not_configurable_and_that_is_registered(self):
        """strong 门限**没有**配置项 —— 这是已登记的缺口，不是遗漏。

        实测后果：把 confirm 阈值调到 0.9 后，单维 0.85 的样本
        is_anomaly=True 却 action=logged（记为异常但不做处置）。
        这条把该缺口钉住，防止将来被当成「忘了加」而随手补上 ——
        补它会改变处置语义，属需要决策的改动。
        """
        import config as cfg

        names = [n for n in dir(cfg.Settings) if "tool_signature" in n]
        assert not any("strong" in n for n in names), (
            "strong 门限已变成可配置项 —— 缺口已闭合，"
            "请更新本条与整改报告 §9.66 的登记"
        )

    def test_strong_threshold_does_not_follow_the_confirm_threshold(self, monkeypatch):
        """strong 门限**不跟随** confirm 阈值 —— 这是已登记的缺口，不是遗漏。

        实测（用真实检测器）：把 confirm 阈值调到 0.9 后，单维 0.85 的样本
        ``is_anomaly=True`` 却 ``action=logged`` ——
        **记为异常但不做任何处置**。

        对照：默认 confirm=0.8 时同一条样本的 action 是 confirm。
        两条合起来说明 strong 门限（硬编码 0.8）与 confirm 阈值**各走各的**。

        这条钉的是**当前行为**，不是理想行为。修它（让 strong 跟随
        confirm，或加独立旋钮）会改变处置语义，属需要决策的改动。
        """
        import config as cfg
        from datetime import datetime, timedelta, timezone

        from mcp_guard.call_record import ToolCallRecord

        base_ts = datetime(2026, 10, 19, 10, 0, 0, tzinfo=timezone.utc)

        def _probe():
            det = BehaviorDetector(min_samples=30, enabled=True, persist=False,
                                   mode="confirm", warn_threshold=0.6)
            for i in range(40):
                rec = ToolCallRecord.from_kwargs(
                    user_role="admin", tool_name="query", arguments={"s": "x"},
                    decision="allow", reason="baseline", caller="alice",
                    source="mcp_guard",
                    ts=base_ts + timedelta(seconds=i * 700),
                )
                rep = det.observe_pre_exec(rec)
                det.observe_post_exec(rec, rep)
            rec = ToolCallRecord.from_kwargs(
                user_role="admin", tool_name="query", arguments={"s": "x"},
                decision="allow", reason="probe", caller="alice",
                source="mcp_guard", ts=base_ts.replace(hour=3),
            )
            return det.observe_pre_exec(rec)

        # 默认 confirm=0.8：单维 0.85 足以触发 strong 路径并被确认
        r0 = _probe()
        assert r0 is not None
        dims = {k: v for k, v in (r0.dimensions or {}).items() if v}
        assert dims.get("time", 0) >= 0.8, (
            f"本用例的前提没成立：单维 time 分不是 0.85，实测 dims={r0.dimensions}"
        )
        assert r0.is_anomaly is True
        assert r0.action == "confirm", (
            f"默认 confirm 下档位是 {r0.action}，前提已变"
        )

        # confirm 调到 0.9：strong 门限仍命中（is_anomaly=True），
        # 但 confirm 门限够不到 ⇒ 记为异常却**不做任何处置**
        monkeypatch.setattr(
            cfg.settings, "tool_signature_confirm_threshold", 0.9,
            raising=False,
        )
        r1 = _probe()
        assert r1 is not None
        assert r1.is_anomaly is True, (
            "is_anomaly 不再为真 —— strong 门限与 confirm 阈值的关系变了"
        )
        assert r1.action == "logged", (
            f"处置档位变成了 {r1.action} —— "
            "strong 门限与 confirm 阈值的关系变了，请重新评估本条"
        )


# ═══════════════════════════════════════════
# 五、渲染层：把新口径说出来
# ═══════════════════════════════════════════

class TestRenderStatesTheNewSemantics:
    def _out(self):
        from eval_datasets.evaluate_behavior import sweep_thresholds as _sw
        return render_report(_report(), _sw(_report()))

    def test_render_declares_the_domain_on_the_conditional_interval(self):
        out = self._out()
        assert "域约束 = warn <= confirm <= deny" in out

    def test_render_flags_out_of_domain_values_as_not_operable(self):
        out = self._out()
        assert "不可运维" in out

    def test_render_explains_the_lower_bound_comes_from_the_domain(self):
        out = self._out()
        assert "不能低于" in out, (
            "渲染必须说明下界余量由域约束决定 —— "
            "否则读者会把「不能低于 X」误读成「数据只支持到 X」"
        )

    def test_render_shows_knob_effectiveness(self):
        out = self._out()
        assert "旋钮有效性" in out
        assert "可行区间宽" in out and "旋钮有用" in out
        assert "整段无效旋钮" in out

    def test_render_does_not_claim_a_wide_interval_means_usable_headroom(self):
        """渲染不得把「区间宽」说成「有调节空间」。"""
        out = self._out()
        assert "有 0.40 的调节空间" not in out
        assert "余量 上 +0.4000" not in out, (
            "warn 的域内上侧余量是 +0.2000；+0.4000 是越域的旧值"
        )
