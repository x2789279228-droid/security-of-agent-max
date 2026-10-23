# -*- coding: utf-8 -*-
"""配置项的 falsy 陷阱与「评估器基线必须读生产真源」（整改报告 §9.67）。

## 背景

§9.66 修完「余量」的成因之后，顺着同一条线又查出两处：

### 一、`X or default` 把**合法的 0** 当成「没配」

行为检测的四个阈值/样本数都这么读配置：

```python
return float(getattr(s, "tool_signature_warn_threshold", 0.6) or 0.6) if s else 0.6
```

实测：把 `tool_signature_warn_threshold` 配成 **0**
（语义 = 一切都触发），生产实际拿到的是 **0.6**；
confirm / deny / min_samples 四个**全部**如此。

⇒ 运维**改了配置却看不到效果**，且没有任何日志提示。
`0` 对这些字段是**合法且有意义**的取值，不能被静默吞掉。

正确的兜底条件是「**没配**」（None / 属性不存在），不是「值为 0」。

### 二、评估器的「当前阈值」与生产**脱钩**

`evaluate_behavior.py` 把三个阈值写死成 `DEFAULT_WARN/CONFIRM/DENY`，
**不读 config**。实测：运维把 confirm 配成 0.9、warn 配成 0.5、deny 配成 0.97 后，
评估器算的「上侧余量」仍然是相对于**旧基线**（0.6/0.8/0.95）的。

⇒ 报告里那张「余量」表，在运维改过阈值之后就是**过期的**。

## 本文件钉住什么

* 四个阈值在「配 0」时**必须**拿到 0（不被吞）；
* 评估器的当前阈值**必须**等于生产当前阈值（改 config 后仍跟随）；
* 生产改阈值导致标定集不可行时，工具**必须如实报告**，
  而不是报出旧基线的余量；
* 兜底的正确判据是「没配」而不是「值为 0」。

## 测试手法说明（踩过的坑）

`config.settings` 是**模块级单例**，且 conftest 有一个 autouse fixture
会在每个用例后**复位全局状态与 settings**。
⇒ 想测「不同配置下的行为」，**不能**靠 `importlib.reload`（它会被
fixture 复位掉），必须**直接改 settings 对象上的字段**
（`monkeypatch.setattr`），并在用例后由 monkeypatch 自动还原。
本文件统一用 `monkeypatch.setattr(settings, ...)`。
"""
from __future__ import annotations

import ast
import inspect

import pytest

import config as cfg
from eval_datasets import evaluate_behavior as eb
from mcp_guard import behavior_detector as bd
from mcp_guard.behavior_detector import BehaviorDetector

THRESHOLD_FIELDS = (
    ("tool_signature_warn_threshold", "warn_threshold", 0.0),
    ("tool_signature_confirm_threshold", "confirm_threshold", 0.0),
    ("tool_signature_deny_threshold", "deny_threshold", 0.0),
    ("tool_signature_min_samples", "min_samples", 0),
)


# ═══════════════════════════════════════════
# 一、`or` 兜底吞掉合法的 0
# ═══════════════════════════════════════════

class TestZeroIsNotSwallowed:
    @pytest.mark.parametrize("field,getter,zero", THRESHOLD_FIELDS)
    def test_configured_zero_is_preserved(self, field, getter, zero, monkeypatch):
        """配 0 → 生产必须拿到 0，而不是退回默认值。

        这是「运维改了配置却看不到效果」的那类缺陷：
        阈值 0 的语义是「一切命中」，是完全合法的取值。
        """
        monkeypatch.setattr(cfg.settings, field, type(
            getattr(cfg.settings, field))(zero))
        det = BehaviorDetector()
        got = getattr(det, getter)()
        assert float(got) == float(zero), (
            f"{field} 配 0 时生产拿到 {got!r} —— "
            f"兜底把合法的 0 当成「没配」了"
        )

    @pytest.mark.parametrize("field,getter,zero", THRESHOLD_FIELDS)
    def test_absent_setting_falls_back_to_the_declared_default(self, field, getter, zero):
        """**没配**时仍要退回默认 —— 兜底条件是「没配」，不是「值为 0」。"""
        det = BehaviorDetector()
        expected = getattr(cfg.settings, field)
        got = getattr(det, getter)()
        assert float(got) == float(expected), (
            f"{field} 未配时拿到 {got!r}，应为 config 声明的 {expected!r}"
        )

    def test_the_reading_helper_uses_is_none_not_truthiness(self):
        """兜底判据必须是「值为 None」，不能是「falsy」。"""
        src = inspect.getsource(bd._config_number)
        assert "is None" in src, (
            "_config_number 必须用 `is None` 判定「没配」；"
            "用 truthiness 会把 0 当成没配"
        )
        for line in src.splitlines():
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith('"'):
                continue
            assert not (
                "getattr(" in stripped and " or " in stripped
            ), f"_config_number 里仍有 `getattr(...) or ...` 形态：{stripped}"

    def test_no_or_pattern_remains_in_the_threshold_readers(self):
        """四个阈值读取方法里不得再有 `or` 兜底形态。"""
        for getter in ("warn_threshold", "confirm_threshold", "deny_threshold", "min_samples"):
            src = inspect.getsource(getattr(BehaviorDetector, getter))
            assert " or " not in src, (
                f"{getter} 里仍有 `or` 兜底：{src.strip()[:120]}"
            )

    def test_threshold_readers_delegate_to_the_shared_helper(self):
        """四个读取方法都走同一个 `_config_number` —— 单一真源。"""
        for getter in ("warn_threshold", "confirm_threshold", "deny_threshold", "min_samples"):
            src = inspect.getsource(getattr(BehaviorDetector, getter))
            assert "_config_number" in src, (
                f"{getter} 没有走 _config_number —— 兜底逻辑会再次分叉"
            )


# ═══════════════════════════════════════════
# 二、评估器的当前阈值必须读生产真源
# ═══════════════════════════════════════════

class TestEvaluatorBaselineComesFromProduction:
    def test_current_thresholds_matches_the_production_detector(self):
        """默认配置下，评估器的当前阈值必须等于生产实际用的。"""
        det = BehaviorDetector()
        prod = (det.warn_threshold(), det.confirm_threshold(), det.deny_threshold())
        assert eb.current_thresholds() == prod

    def test_current_thresholds_follows_a_config_change(self, monkeypatch):
        """运维改了阈值后，评估器必须**跟随**，不能停在旧基线。"""
        monkeypatch.setattr(cfg.settings, "tool_signature_warn_threshold", 0.5)
        monkeypatch.setattr(cfg.settings, "tool_signature_confirm_threshold", 0.9)
        monkeypatch.setattr(cfg.settings, "tool_signature_deny_threshold", 0.97)
        det = BehaviorDetector()
        prod = (det.warn_threshold(), det.confirm_threshold(), det.deny_threshold())
        assert prod == (0.5, 0.9, 0.97)
        assert eb.current_thresholds() == prod, (
            "评估器没有跟随生产阈值 —— 它的「当前值」仍停在旧基线上"
        )

    def test_evaluator_does_not_hardcode_the_current_thresholds(self):
        """评估器里不得再用 DEFAULT_* 充当「当前值」。"""
        tree = ast.parse(inspect.getsource(eb))
        for node in ast.walk(tree):
            if isinstance(node, ast.Tuple) and len(node.elts) == 3:
                names = [e.id for e in node.elts
                         if isinstance(e, ast.Name) and e.id.startswith("DEFAULT_")]
                if len(names) == 3:
                    raise AssertionError(
                        "评估器里仍有 (DEFAULT_WARN, DEFAULT_CONFIRM, DEFAULT_DENY) "
                        "充当当前值的写法 —— 必须改用 current_thresholds()"
                    )

    def test_bounds_use_the_current_thresholds_as_the_baseline(self):
        """`exact_conditional_bounds` 的默认基线必须来自生产真源。"""
        src = inspect.getsource(eb.exact_conditional_bounds)
        assert "current_thresholds()" in src, (
            "exact_conditional_bounds 的默认 current 必须走 current_thresholds()"
        )
        assert "DEFAULT_WARN, DEFAULT_CONFIRM, DEFAULT_DENY" not in src

    def test_sweep_reports_the_current_thresholds_it_actually_used(self):
        """sweep 的 `current` 必须是生产当前值，不是常量。"""
        sw = eb.sweep_thresholds(eb.run_scenarios())
        assert sw["current"] == eb.current_thresholds()
        assert sw["current"] == (cfg.settings.tool_signature_warn_threshold,
                                  cfg.settings.tool_signature_confirm_threshold,
                                  cfg.settings.tool_signature_deny_threshold)

    def test_default_constants_are_still_documented_as_factory_defaults(self):
        """DEFAULT_* 保留为「出厂默认值」，且与 config 声明一致。"""
        assert eb.DEFAULT_WARN == cfg.settings.tool_signature_warn_threshold
        assert eb.DEFAULT_CONFIRM == cfg.settings.tool_signature_confirm_threshold
        assert eb.DEFAULT_DENY == cfg.settings.tool_signature_deny_threshold
        doc = inspect.getsource(eb.current_thresholds)
        assert "生产**当前实际在用**" in doc, (
            "current_thresholds 的文档必须说清它与 DEFAULT_* 的区别"
        )


# ═══════════════════════════════════════════
# 三、生产改阈值后，工具必须**如实报告**
# ═══════════════════════════════════════════

class TestHonestReportingWhenProductionChanged:
    def test_a_changed_threshold_makes_the_current_point_infeasible_and_is_reported(
            self, monkeypatch):
        """运维把 confirm 调到 0.9 ⇒ 该点在标定集上不可行 ⇒ 工具必须**明说**。

        修复前：评估器用旧基线算，报出「confirm 上侧余量 +0.0000」——
        那个数字是相对于**生产并不在用**的 0.8 算的。
        修复后：当前值不可行时返回 `feasible_at_current=False`，
        渲染层打印「★★ 当前值本身不可行，无可行区间可言」。
        """
        monkeypatch.setattr(cfg.settings, "tool_signature_confirm_threshold", 0.9)
        ex = eb.exact_conditional_bounds(eb.run_scenarios())
        assert ex["confirm"]["feasible_at_current"] is False, (
            "生产 confirm 已是 0.9，评估器必须报「当前值本身不可行」"
        )
        assert ex["confirm"]["lower"] is None and ex["confirm"]["upper"] is None

    def test_render_states_the_infeasible_current_instead_of_a_number(self, monkeypatch):
        """渲染层遇到不可行当前值时，必须明说而不是印一个区间。"""
        monkeypatch.setattr(cfg.settings, "tool_signature_confirm_threshold", 0.9)
        out = eb.render_report(eb.run_scenarios(), eb.sweep_thresholds(eb.run_scenarios()))
        assert "★★ 当前值本身不可行" in out, (
            "渲染必须明说当前值不可行，不能印一个来自旧基线的区间"
        )
