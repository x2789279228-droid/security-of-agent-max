# -*- coding: utf-8 -*-
"""「核心资产保护」的**保护范围**必须可见（整改报告 §9.54）。

## 背景

`response_engine/asset_whitelist.py` 的模块 docstring 写着
「内置默认保护（**平台自身组件的 IP/网段**）」，实测**内置默认只有
`127.0.0.0/8`（loopback）一条** → 平台自己的 DB / 缓存 / Kafka
**不在**保护范围内 → 文档承诺落空（待决项 36）。

另外两处：

* 内置清单里原有一条 `("0.0.0.0/0", "default-route-placeholder", ...)`，
  注释写「仅用于占位，check 中特殊处理」——
  但 `initialize` **直接跳过**它，`check()` 里**从来没有**任何
  0.0.0.0/0 的特殊处理 → 那条注释在**撒谎**（而它正是维护者判断
  「check 里有没有处理」的唯一依据）。已删除（死代码）。
* 审计里写的是 `{"passed": not is_protected, "reason": asset_reason}`，
  而 `check()` 在「没命中」时返回的 reason 是**空串** →
  审计里是「**通过、理由为空**」，**分不出**「没命中受保护清单」
  与「清单里根本没有可保护的东西」。

## 本守卫盯什么

1. **事实钉住**：内置默认**只有 loopback**（文档承诺 ≠ 实现）；
2. **死代码已删**：内置清单里没有 `0.0.0.0/0` 占位符，注释也不再声称
   「check 中特殊处理」；
3. **审计的理由非空** + **带保护范围**（条数 / 是否只含内置项）；
4. **反向判据**：受保护 IP **仍然被拦**（保护行为一个字没改）。
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND))

import pytest  # noqa: E402

CMD = ("iptables -I INPUT -s 10.0.0.5 -j DROP "
       "-m comment --comment 'FW-RULE-11111'")


async def _live_fn(cmd):
    return {"success": True, "stdout": "", "stderr": "", "returncode": 0}


def _executor():
    from response_engine.safe_executor import SafeExecutor
    se = SafeExecutor()
    se.initialize()
    return se


class TestTheBuiltinScopeIsPinned:
    def test_the_builtin_default_is_only_loopback(self):
        """**事实钉住**：默认保护范围**只有 loopback**。

        docstring 原先声称是「平台自身组件的 IP/网段」—— 与实现不符。
        待决项 36：内置清单要不要覆盖平台自身组件网段。
        """
        from response_engine.asset_whitelist import AssetWhitelist
        aw = AssetWhitelist()
        aw.initialize("")
        nets = sorted(str(a["network"]) for a in aw.list_assets())
        assert nets == ["127.0.0.0/8"], (
            f"内置默认保护清单变了：{nets} —— 若这是**按待决项 36 扩充**的结果，"
            "请先更新待决项 36 与报告 §9.54，再改这条守卫")

    def test_the_placeholder_is_gone(self):
        """`0.0.0.0/0` 占位符是死代码（initialize 跳过、check 无处理）→ 已删。

        判据看**导入后的真实清单**，不看文件文本 ——
        说明性注释里合法地提到「这条被删掉了」是文档，不是缺陷。
        """
        import importlib
        # ⚠ 包 __init__ 里的 `asset_whitelist` 是**实例**，会遮住同名模块 → 用 importlib
        aw_mod = importlib.import_module("response_engine.asset_whitelist")
        nets = [str(c[0]) for c in aw_mod._BUILTIN_PROTECTED]
        assert "0.0.0.0/0" not in nets, (
            f"占位符还在内置清单里：{nets} —— 它是死代码"
            "（initialize 跳过它、check 里也没有任何特殊处理）")
        aw = aw_mod.AssetWhitelist()
        aw.initialize("")
        assert not any(a["network"] == "0.0.0.0/0" for a in aw.list_assets()), (
            "0.0.0.0/0 仍然生效了 —— 那会保护**所有**地址")


class TestTheAuditShowsTheScope:
    @pytest.mark.asyncio
    async def test_the_reason_is_not_empty_when_not_protected(self):
        """没命中时理由**不得是空串** —— 旧代码给的是 ""。"""
        se = _executor()
        result = await se.execute(
            action_name="block_ip", command=CMD,
            params={"src_ip": "10.0.0.5"},
            platform="linux", live_fn=_live_fn,
        )
        entry = result["audit"]["checks"]["asset_whitelist"]
        assert entry["reason"], f"审计里的理由是空串：{entry}"
        assert entry["passed"] is True, entry

    @pytest.mark.asyncio
    async def test_the_scope_is_recorded(self):
        """审计里必须能看出「这道检查当时覆盖了多大范围」。"""
        se = _executor()
        result = await se.execute(
            action_name="block_ip", command=CMD,
            params={"src_ip": "10.0.0.5"},
            platform="linux", live_fn=_live_fn,
        )
        entry = result["audit"]["checks"]["asset_whitelist"]
        assert "protected_count" in entry, entry
        assert entry["protected_count"] >= 1, entry
        assert entry["scope"] in ("empty", "builtin_only", "configured"), entry

    @pytest.mark.asyncio
    async def test_a_configured_asset_makes_the_scope_configured(self):
        """配了业务资产 → `scope` 必须是 `configured`。"""
        from response_engine.asset_whitelist import asset_whitelist
        se = _executor()
        asset_whitelist.initialize(protected_assets_str="10.0.0.99",
                                   labels_str="probe")
        try:
            result = await se.execute(
                action_name="block_ip", command=CMD,
                params={"src_ip": "10.0.0.5"},
                platform="linux", live_fn=_live_fn,
            )
            entry = result["audit"]["checks"]["asset_whitelist"]
            assert entry["scope"] == "configured", entry
            assert entry["protected_count"] >= 2, entry
        finally:
            asset_whitelist.initialize("")


class TestTheReverseCriterion:
    @pytest.mark.asyncio
    async def test_a_protected_ip_is_still_blocked(self):
        """**反向判据**：保护行为**一个字没改** —— 受保护 IP 仍然被拦。"""
        from response_engine.asset_whitelist import asset_whitelist
        se = _executor()
        asset_whitelist.initialize(protected_assets_str="10.0.0.1",
                                   labels_str="core-gw")
        try:
            result = await se.execute(
                action_name="block_ip",
                command=("iptables -I INPUT -s 10.0.0.1 -j DROP "
                         "-m comment --comment 'FW-RULE-11111'"),
                params={"src_ip": "10.0.0.1"},
                platform="linux", live_fn=_live_fn,
            )
            assert result.get("blocked") is True, result
            assert result.get("blocked_by") == "asset_whitelist", result
            entry = result["audit"]["checks"]["asset_whitelist"]
            assert entry["passed"] is False, entry
            assert entry["reason"], entry
        finally:
            asset_whitelist.initialize("")
