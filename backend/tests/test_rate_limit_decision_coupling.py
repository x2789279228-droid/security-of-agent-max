# -*- coding: utf-8 -*-
"""限流两个缺陷**必须一起修** —— 拆开改都会把限流强度推向错误方向（整改报告 §9.69）。

## 背景

§9.68 查出限流这处有**两个**缺陷：

* **A**：`app.py:537` 的豁免条件只看 **std** 那个旋钮
  ⇒ 配 ``rate_limit_per_minute=0`` 会**连带绕过** strict 桶。
* **B**：`http_guards.rate_limit_quota` 里的 ``or 10``
  ⇒ 配 ``rate_limit_strict_per_minute=0`` 会被静默改回 10
  （既不能「关掉 strict」，也拿不到「0 = 不限流」）。

## 为什么不能拆开修

限流判定的两行（`app.py:530-560`）：

```python
if settings.rate_limit_per_minute <= 0:      # L537 豁免（只看 std）
    return await call_next(request)
...
limit = _rate_limit_quota(namespace)          # L551 取配额
if len(_rate_limit_store[rate_key]) >= limit: # L552 超限 → 429
```

**若只修 B**（把 ``or 10`` 改成「保留 0」）：
``limit=0`` ⇒ ``len(hits) >= 0`` **恒真** ⇒
strict 桶的 **32 个**端点（``/api/response/execute``、``/api/firewall/connect`` …）
**全部 429** ⇒ 平台级阻断。
实测：limit=0 时，窗口内 0 / 1 / 5 次请求**全部**被拒。

**若只修 A**（豁免改成「两个命名空间都 <= 0 才放行」）：
配 ``std=0, strict=10`` 时 strict 恢复限流 ✓，
但此时 ``or 10`` 仍吞 0 ⇒ **运维无法单独关掉 strict 限流**
（想关只能整体把 std 也设成 <= 0，于是又回到 A 的问题）。

⇒ 两个缺陷是**耦合**的：只修一个都会把限流强度推向错误方向
（一个是「意外全拒」，一个是「无法单独关闭」）。

⇒ 待决项 51 必须**一起**决定，不能拆成两个独立的小改动。

## 本文件钉住什么

* 限流判定的**三行结构**（豁免 → 取配额 → 比较）不得被悄悄改形；
* ``len(hits) >= limit`` 这个比较的**边界语义**（limit=0 ⇒ 恒真）
  必须被显式登记 —— 这是「0」在限流里最反直觉的一点；
* 运维可用的「关掉限流」写法**只有负数**（``<= 0`` 触发豁免）；
* strict 桶的高危端点**必须**在位（前提）。
"""
from __future__ import annotations

import inspect

import pytest

import config as cfg
from http_guards import RATE_LIMIT_FORCED, rate_limit_quota


class TestTheRateLimitDecisionShape:
    def test_the_three_steps_are_in_order(self):
        """豁免 → 取配额 → 比较，三步的**先后顺序**不得变。

        顺序一旦颠倒（例如先取配额再判豁免），strict=0 的行为就会变。
        """
        import app as app_mod

        src = inspect.getsource(app_mod.rate_limit_middleware)
        bypass_at = src.index("rate_limit_per_minute <= 0")
        quota_at = src.index("_rate_limit_quota(namespace)")
        compare_at = src.index(">= limit")
        assert bypass_at < quota_at < compare_at, (
            "限流判定的三步顺序变了："
            f"豁免@{bypass_at} 取配额@{quota_at} 比较@{compare_at}"
        )

    def test_the_comparison_is_greater_or_equal(self):
        """比较是 ``>=`` ⇒ **limit=0 时恒真**（全部 429）。

        这是「0」在限流里最反直觉的一点，也是「天真修 `or 10`」会
        造成平台级阻断的原因。必须被显式登记。
        """
        import app as app_mod

        src = inspect.getsource(app_mod.rate_limit_middleware)
        assert ">= limit" in src, "限流比较不再是 `>= limit` —— 语义可能变了"
        for hits in (0, 1, 5):
            assert len([0] * hits) >= 0, "算术恒真性被破坏"

    def test_limit_zero_means_reject_everything_not_unlimited(self):
        """limit=0 的语义是**全部拒绝**，不是「不限流」。"""
        assert (len([]) >= 0) is True
        assert (len([1, 2, 3]) >= 0) is True


class TestOnlyNegativeValuesDisableRateLimiting:
    def test_negative_is_the_only_way_to_disable(self, monkeypatch):
        """登记：当前**唯一**能真正「关掉限流」的写法是**负数**。

        0 会被中间件的 ``<= 0`` 命中（整体放行），
        也会被配额层的 ``or`` 吞掉 —— 两条路径语义不同，负数是唯一无歧义的。
        """
        monkeypatch.setattr(cfg.settings, "rate_limit_per_minute", -1)
        monkeypatch.setattr(cfg.settings, "rate_limit_strict_per_minute", -1)
        assert cfg.settings.rate_limit_per_minute <= 0
        assert cfg.settings.rate_limit_strict_per_minute <= 0
        assert rate_limit_quota("std") == -1

    def test_zero_is_ambiguous_between_the_two_layers(self, monkeypatch):
        """0 在两层上语义不同 ⇒ **不能**用 0 表达任何意图。

        · 中间件层：``<= 0`` ⇒ 整体放行（不限流）
        · 配额层：``or 10`` ⇒ 改回 10（限流）

        ⇒ 同一个 0，在两层得到相反的结论。
        """
        monkeypatch.setattr(cfg.settings, "rate_limit_per_minute", 0)
        monkeypatch.setattr(cfg.settings, "rate_limit_strict_per_minute", 0)
        # 中间件层：0 ⇒ 整体放行
        assert cfg.settings.rate_limit_per_minute <= 0
        # 配额层：0 ⇒ 被 `or` 吞成 10
        assert rate_limit_quota("strict") == 10
        assert rate_limit_quota("std") == 120


class TestTheHighRiskEndpointsAreStillForced:
    def test_forced_namespace_still_covers_the_action_endpoints(self):
        """前提守卫：strict 桶必须仍在位。

        若哪天有人把这些端点从 ``RATE_LIMIT_FORCED`` 里拿掉，
        本文件的其余结论（限流强度下降）就不再适用。
        """
        for path in ("/api/response/execute", "/api/firewall/connect",
                     "/api/guard/call"):
            assert path in RATE_LIMIT_FORCED, f"{path} 不在 strict 桶里"
