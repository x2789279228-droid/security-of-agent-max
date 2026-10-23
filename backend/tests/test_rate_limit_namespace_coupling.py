# -*- coding: utf-8 -*-
"""限流的「一个旋钮管两个命名空间」耦合（整改报告 §9.68）。

## 背景

`http_guards` 的限流有**两个命名空间**：

* ``std``    —— 普通流量，配额 ``rate_limit_per_minute``（默认 120）
* ``strict`` —— **高危动作端点**，配额 ``rate_limit_strict_per_minute``（默认 10）

``RATE_LIMIT_FORCED`` 把 32 个端点划进 strict 桶，其中包括
``/api/response/execute``、``/api/firewall/connect``、``/api/guard/call``、
``/api/response/rollback``、``/api/logs/ingest`` 等**会真正改动生产状态**的接口。

## 本轮查清的两件事

### 一、限流豁免只由 **std 那个旋钮**决定（app.py:537）

```python
if settings.rate_limit_per_minute <= 0:
    return await call_next(request)      # ← 整体绕过，**含 strict 桶**
```

⇒ 运维只想放开 std（``rate_limit_per_minute=0``），
   结果 **strict 的 10 次/分钟也被连带关掉** ——
   高危端点从此不受任何限流保护。

### 二、配 ``rate_limit_strict_per_minute=0`` 会被静默改回 10

```python
return int(getattr(settings, "rate_limit_strict_per_minute", 10) or 10)
```

`or 10` 把合法的 0 当成「没配」⇒ **想关掉 strict 限流做不到**。

⇒ 合起来：**运维的直觉「0 = 关掉」在限流这两处都不成立**，
而 ``config.py`` 里没有一行注释说明这一点。

## 修法为什么本轮不做

两条路都**改变限流强度**（收紧）：

* (a) 豁免条件改成「两个命名空间都 <= 0 才整体放行」
* (b) 保持现状，配 std<=0 且 strict>0 时告警

⇒ 属**收紧型 / 行为变更**，按纪律不单方面做。
本轮只做：把耦合**暴露出来**（本文件钉住当前事实）+ 上交决策（待决项 51）。

## 本文件钉住什么

* 豁免条件**确实**只看 std 旋钮（当前事实）；
* 配 std=0 ⇒ strict 桶**确实**被连带绕过；
* 配 strict=0 ⇒ 配额**确实**被静默改回 10；
* 这些是**当前行为**的登记，不是「正确行为」的断言 ——
  若将来修好（方案 a / b），本文件会红，那正是需要更新登记的信号。
"""
from __future__ import annotations

import inspect

import pytest

import config as cfg
from http_guards import RATE_LIMIT_FORCED, rate_limit_quota


@pytest.fixture
def restore_limits():
    old_std = cfg.settings.rate_limit_per_minute
    old_str = cfg.settings.rate_limit_strict_per_minute
    try:
        yield
    finally:
        cfg.settings.rate_limit_per_minute = old_std
        cfg.settings.rate_limit_strict_per_minute = old_str


class TestTheStrictBucketIsWiredToHighRiskEndpoints:
    def test_strict_covers_the_state_changing_endpoints(self):
        """strict 桶必须覆盖真正会改动生产状态的端点 —— 前提。"""
        for path in ("/api/response/execute", "/api/firewall/connect",
                     "/api/guard/call", "/api/response/rollback"):
            assert path in RATE_LIMIT_FORCED, (
                f"{path} 不在 strict 桶里 —— strict 限流的前提已变"
            )
        assert len(RATE_LIMIT_FORCED) >= 20, (
            f"强制限流端点只剩 {len(RATE_LIMIT_FORCED)} 个 —— 覆盖面变小，"
            "请重新评估本文件的结论"
        )


class TestTheExemptionIsDrivenByTheStdKnobOnly:
    """**当前事实**登记：豁免条件只读 std 那个旋钮。"""

    def test_the_middleware_bypass_reads_only_the_std_knob(self):
        """中间件的豁免条件里**没有** strict 旋钮。

        这是「配 std=0 会连带关掉 strict」的**根因**。
        """
        import app as app_mod

        src = inspect.getsource(app_mod.rate_limit_middleware)
        assert "rate_limit_per_minute <= 0" in src, (
            "中间件的豁免条件变了 —— 请重新评估本文件的结论"
        )
        # 豁免那一行**不得**同时读 strict 旋钮
        bypass_line = [ln for ln in src.splitlines()
                        if "rate_limit_per_minute <= 0" in ln]
        assert bypass_line, "找不到豁免条件所在行"
        assert "strict" not in bypass_line[0], (
            "豁免条件已经开始同时看 strict 旋钮了 —— "
            "耦合已解，请更新本文件与整改报告 §9.68"
        )

    def test_configuring_std_to_zero_bypasses_the_strict_bucket(self, restore_limits):
        """配 std=0 ⇒ 整个限流被绕过，**strict 桶也一起**。

        ⚠️ 这是**当前行为**的登记，不是「应该这样」的断言。
        若将来改成「两个命名空间都 <= 0 才放行」，本条会红 ——
        那正是需要更新登记（并重新评估待决项 51）的信号。
        """
        cfg.settings.rate_limit_per_minute = 0
        cfg.settings.rate_limit_strict_per_minute = 10
        assert cfg.settings.rate_limit_per_minute <= 0, (
            "豁免条件不再对 std=0 生效 —— 本文件的登记需要更新"
        )
        # 配额层仍然算出 strict=10，但中间件在它之前就返回了 ⇒ 形同虚设
        assert rate_limit_quota("strict") == 10

    def test_the_strict_quota_is_never_reached_when_std_is_zero(self, restore_limits):
        """std=0 时，strict 的配额数**根本不会被检查**。"""
        cfg.settings.rate_limit_per_minute = 0
        cfg.settings.rate_limit_strict_per_minute = 10
        import app as app_mod

        src = inspect.getsource(app_mod.rate_limit_middleware)
        bypass_at = src.index("rate_limit_per_minute <= 0")
        quota_at = src.index("_rate_limit_quota(namespace)")
        assert bypass_at < quota_at, (
            "配额取用点跑到了豁免点之前 —— 本文件的时序登记需要更新"
        )


class TestStrictZeroIsSilentlyRewritten:
    def test_configuring_strict_to_zero_yields_ten_not_zero(self, restore_limits):
        """配 ``rate_limit_strict_per_minute=0`` ⇒ 实际得到 **10**。

        `or 10` 把合法的 0 当成「没配」。
        ⚠️ 当前行为登记 —— 修好后本条会红。
        """
        cfg.settings.rate_limit_strict_per_minute = 0
        assert rate_limit_quota("strict") == 10, (
            "strict=0 现在会被保留 —— `or 10` 已修，"
            "请更新本文件与整改报告 §9.68"
        )

    def test_the_or_pattern_is_what_causes_it(self, restore_limits):
        """根因是 `or 10` 这个形态 —— 钉住它，避免有人「顺手优化」掉。"""
        import http_guards

        src = inspect.getsource(http_guards.rate_limit_quota)
        assert "or 10" in src, (
            "rate_limit_quota 里不再有 `or 10` —— "
            "strict=0 的处理方式变了，请重新评估本文件"
        )


class TestTheDocumentedWayToDisableRateLimiting:
    def test_negative_values_are_the_documented_way(self, restore_limits):
        """唯一能真正「两个都不限流」的写法是**负数**（<= 0 触发中间件豁免）。

        登记这一点，是为了给运维一条**能用的**路径
        （而不是让他们以为 0 就是「关掉」）。
        """
        cfg.settings.rate_limit_per_minute = -1
        cfg.settings.rate_limit_strict_per_minute = -1
        assert cfg.settings.rate_limit_per_minute <= 0
        assert cfg.settings.rate_limit_strict_per_minute <= 0
        # 中间件豁免条件读的是 std 旋钮 ⇒ <= 0 即整体放行
        assert rate_limit_quota("std") == -1


class TestTheNamespaceTaxonomy:
    """限流其实有**三个**命名空间，不是两个 —— §9.69.1 的更正。"""

    def test_the_three_namespaces_exist(self):
        """`crit` / `strict` / `std` 三个标签都真实存在。

        `http_guards.py:158` 的注释写着「namespace 仅允许低基数标签：crit / strict」，
        而 `RATE_LIMIT_FORCED_NESTED` 里确实有 `crit`。
        """
        from http_guards import RATE_LIMIT_FORCED_NESTED

        namespaces = {ns for _, _, _, ns in RATE_LIMIT_FORCED_NESTED}
        assert "crit" in namespaces, (
            f"RATE_LIMIT_FORCED_NESTED 里没有 crit 了（现有 {namespaces}）—— "
            "命名空间结构变了，请重新评估本文件"
        )
        assert "strict" in namespaces

    def test_crit_falls_back_to_the_std_quota(self):
        """**`crit` 落回 std 的 120/分** —— `rate_limit_quota` 只识别 `strict`。

        ⇒ 「不可逆高危动作」与「普通流量」**共用同一个配额**。
        这**不是** bug（`RATE_LIMIT_FORCED` 的作用是「不被白名单豁免」，
        而不是「配额更低」），但命名会让人误解 ⇒ 可发现性缺口。

        ⚠️ 当前事实登记 —— 若将来给 crit 配上独立配额，本条会红。
        """
        assert rate_limit_quota("crit") == rate_limit_quota("std"), (
            "crit 现在有自己的配额了 —— 可发现性缺口已闭合，"
            "请更新本文件与整改报告 §9.69.1"
        )

    def test_the_strict_namespace_covers_exactly_one_endpoint(self):
        """`strict`（10/分）**只**覆盖 `/api/dlq/replay` 一个端点。

        ⚠️ 注意 strict 那个端点来自 ``RATE_LIMIT_FORCED_NESTED``（形如
        ``/api/dlq/{id}/tail`` 的更具体匹配，**覆盖**了 ``RATE_LIMIT_FORCED``
        里的 ``/api/dlq`` 前缀），所以判据要同时看两张表。

        ⚠️ 当前事实登记 —— 若 strict 的覆盖范围变大，本条会红。
        """
        from http_guards import (
            RATE_LIMIT_FORCED, RATE_LIMIT_FORCED_NESTED, _forced_namespace,
        )

        strict_paths = []
        # ① NESTED 表里的更具体匹配（覆盖 FORCED 表）
        for prefix, tail, methods, ns in RATE_LIMIT_FORCED_NESTED:
            path = f"{prefix}/{tail}"
            if _forced_namespace(path, methods[0]) == "strict":
                strict_paths.append(path)
        # ② FORCED 表里的精确前缀
        for path, methods in RATE_LIMIT_FORCED.items():
            m = "POST" if methods is None else methods[0]
            if _forced_namespace(path, m) == "strict":
                strict_paths.append(path)
        assert sorted(strict_paths) == ["/api/dlq/replay"], (
            f"strict 覆盖的端点变了：{sorted(strict_paths)} —— "
            "请更新本文件与整改报告 §9.69.1"
        )


class TestConfigDoesNotDocumentTheSemantics:
    """config.py 里**没有**说明「0 = 关掉」不成立 —— 这是可发现性缺口。"""

    def test_the_rate_limit_fields_have_no_description(self):
        """两个限流字段都**没有** description（pydantic 的 `Field(description=...)`）。

        ⇒ 运维在 config.py 里看不到「0 会被 `or` 吞掉」、
        「0 还会连带关掉 strict」这两条事实。

        ⚠️ 当前事实登记 —— 若将来补上 description，请把本条改成断言其内容。
        """
        for field in ("rate_limit_per_minute", "rate_limit_strict_per_minute"):
            desc = cfg.Settings.model_fields[field].description
            assert not desc, (
                f"{field} 现在有 description 了（{desc!r}）—— "
                "若内容说明了「0 不等于关掉」与「std=0 会连带关掉 strict」，"
                "请把本条改成断言其内容"
            )

    def test_the_source_line_carries_no_explanatory_comment(self):
        """config.py 里这两个字段的**声明行**也没有行末注释。

        ⚠️ 与上一条同源：注释与 description 都不存在 ⇒ 运维无从得知
        「0 不等于关掉」。行末注释不进 pydantic 的 description，
        所以这一条与上一条**互补**（一条查 description，一条查源码文本）。
        """
        import re
        from pathlib import Path

        src = Path(cfg.__file__).read_text(encoding="utf-8")
        for field in ("rate_limit_per_minute", "rate_limit_strict_per_minute"):
            m = re.search(rf"^\s*{field}\s*:\s*\w+\s*=\s*\S+.*$", src, re.M)
            assert m, f"config.py 里找不到 {field} 的声明行"
            line = m.group(0)
            assert "#" not in line, (
                f"{field} 的声明行现在有注释了（{line.strip()!r}）—— "
                "若注释说明了「0 不等于关掉」，请把本条改成断言其内容"
            )
