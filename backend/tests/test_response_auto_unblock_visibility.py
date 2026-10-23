# -*- coding: utf-8 -*-
"""自动解封的**机制与局限**必须写进动作结果（整改报告 §9.53）。

## 背景

`block_ip` / `isolate_host` 的「到期自动解封」用的是**进程内**的定时任务：

```python
asyncio.create_task(_auto_rollback(rule_id, duration_minutes * 60, ...))
```

它是 `asyncio.sleep(...)` + 回滚，**只活在当前进程的内存里** →
进程重启 / 发布 / 崩溃都会**静默丢失**这次解封
（`_auto_rollback` 里的 `except Exception` 连 `CancelledError` 都接不住，
退出时**连一行日志都不会有**）→ 规则**一直留存**：
误报的封禁不会自愈，误报的**主机隔离**会把机器一直关在网外。

而**能扛重启**的机制（`response_engine/ttl_manager.py`：Redis TTL + 后台扫描器）
**已实现但从未接线** —— 实测三处都没接：

* `safe_executor` 第 ⑧ 步的 `ttl_manager.register(...)` 条件是
  `ttl_seconds > 0 and rule_id`，而**没有任何生产代码**传 `_ttl_seconds` /
  `_rule_id`（全仓只有 `response_registry._exec` 里的两处 `fields.pop`）→ **不可达**；
* `ttl_manager.start_scanner()` **从未被调用**（docstring 说「在 app startup 中调用」）；
* `set_redis(...)` / `set_rollback_callback(...)` 也没有调用方 → 即使可达也跑不起来。

## 本守卫盯什么

1. **动作结果必须说清机制与局限**（`auto_unblock` 字段）；
2. **反向判据**：调度**仍然发生**（本轮只加可见性，不改行为）；
3. **计数**：调度次数可数（= 有多少条封禁依赖那个扛不住重启的机制）；
4. **事实钉住**：`ttl_manager` 的四个入口在生产里**都没有调用方** ——
   一旦有人接线，本守卫转红，要求同步**待决项 35** 与报告 §9.53 的结论。
"""
from __future__ import annotations

import ast
import asyncio
import importlib
import os
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND))

import pytest  # noqa: E402


def _registry():
    return importlib.import_module("response_engine.response_registry")


class TestTheMechanismIsVisible:
    def test_the_info_helper_states_the_mechanism_and_the_limit(self):
        rr = _registry()
        info = rr._auto_unblock_info("block_ip", "FW-RULE-1", 60)
        assert info["scheduled"] is True
        assert info["mechanism"] == "in_process_task", info
        assert info["restart_survives"] is False, info
        assert info["duration_minutes"] == 60, info
        assert "重启" in info["note"] and "9.53" in info["note"], info

    def test_no_schedule_means_scheduled_false(self):
        rr = _registry()
        info = rr._auto_unblock_info("block_ip", "", 0)
        assert info["scheduled"] is False, info
        assert info["mechanism"] == "", info

    @pytest.mark.asyncio
    async def test_the_block_result_carries_the_info(self, monkeypatch):
        """live 路径下，动作结果里必须有 `auto_unblock`。"""
        rr = _registry()

        async def _fake_ensure():
            return None

        async def _fake_auto_rollback(rule_id, delay_seconds, label):
            return None

        class _FakeFW:
            def block_ip(self, ip, duration=0, rule_id=None):
                return {"status": "success", "rule_id": "FW-RULE-1", "family": "ipv4"}

        monkeypatch.setattr(rr, "_execution_mode", lambda: "live")
        monkeypatch.setattr(rr, "_ensure_firewall_connected", _fake_ensure)
        monkeypatch.setattr(rr, "_auto_rollback", _fake_auto_rollback)
        from response_engine import ssh_firewall as fw_mod
        monkeypatch.setattr(fw_mod.ssh_firewall, "block_ip",
                            lambda ip, duration=0, rule_id=None: _FakeFW().block_ip(ip, duration, rule_id))

        result = await rr._block_ip("10.0.0.5", reason="probe", duration_minutes=60)
        assert result.get("success") is True, result
        info = result.get("auto_unblock")
        assert info, f"结果里没有 auto_unblock：{result}"
        assert info["scheduled"] is True, info
        assert info["mechanism"] == "in_process_task", info
        assert info["restart_survives"] is False, info

    @pytest.mark.asyncio
    async def test_the_unblock_is_still_scheduled(self, monkeypatch):
        """**反向判据**：本轮只加可见性 —— 调度**仍然发生**。"""
        rr = _registry()
        calls = []

        async def _fake_ensure():
            return None

        async def _fake_auto_rollback(rule_id, delay_seconds, label):
            calls.append((rule_id, delay_seconds))

        class _FakeFW:
            def block_ip(self, ip, duration=0, rule_id=None):
                return {"status": "success", "rule_id": "FW-RULE-1", "family": "ipv4"}

        monkeypatch.setattr(rr, "_execution_mode", lambda: "live")
        monkeypatch.setattr(rr, "_ensure_firewall_connected", _fake_ensure)
        monkeypatch.setattr(rr, "_auto_rollback", _fake_auto_rollback)
        from response_engine import ssh_firewall as fw_mod
        monkeypatch.setattr(fw_mod.ssh_firewall, "block_ip",
                            lambda ip, duration=0, rule_id=None: _FakeFW().block_ip(ip, duration, rule_id))

        await rr._block_ip("10.0.0.5", reason="probe", duration_minutes=60)
        # create_task 之后要让事件循环转一下，任务才会真的跑起来
        await asyncio.sleep(0)
        assert calls, "自动解封没有被调度 —— 本轮**不改变**这个行为"
        # rule_id 现在由 registry 预生成并下发给 ssh_firewall（SafeExecutor 需要它做 TTL）
        assert calls[0][0].startswith("FW-RULE-"), calls
        assert calls[0][1] == 60 * 60, calls


class TestTheCounter:
    @pytest.mark.asyncio
    async def test_the_scheduling_is_counted(self, monkeypatch):
        from prometheus_client import REGISTRY

        def _val():
            return REGISTRY.get_sample_value(
                "soc_response_auto_unblock_scheduled_total", {"action": "block_ip"})

        before = _val()
        assert before is not None, "指标没被注册"

        rr = _registry()

        async def _fake_ensure():
            return None

        async def _fake_auto_rollback(rule_id, delay_seconds, label):
            return None

        class _FakeFW:
            def block_ip(self, ip, duration=0, rule_id=None):
                return {"status": "success", "rule_id": "FW-RULE-1", "family": "ipv4"}

        monkeypatch.setattr(rr, "_execution_mode", lambda: "live")
        monkeypatch.setattr(rr, "_ensure_firewall_connected", _fake_ensure)
        monkeypatch.setattr(rr, "_auto_rollback", _fake_auto_rollback)
        from response_engine import ssh_firewall as fw_mod
        monkeypatch.setattr(fw_mod.ssh_firewall, "block_ip",
                            lambda ip, duration=0, rule_id=None: _FakeFW().block_ip(ip, duration, rule_id))

        await rr._block_ip("10.0.0.5", reason="probe", duration_minutes=60)
        assert _val() == before + 1, f"调度没有被计数：{before} → {_val()}"


class TestTheWiringFactIsPinned:
    def test_the_restart_surviving_ttl_mechanism_is_still_not_wired(self):
        """**事实钉住**：`ttl_manager` 的四个入口在生产里**都没有调用方**。

        * `register(...)` —— `safe_executor` 第 ⑧ 步调用它，但条件
          `ttl_seconds > 0 and rule_id` 永远不成立（**没人传** `_ttl_seconds` /
          `_rule_id`）→ 不可达；
        * `start_scanner()` —— 从未被调用；
        * `set_redis(...)` / `set_rollback_callback(...)` —— 没有调用方。

        一旦有人把它们接上（= 待决项 35 的落地），本守卫转红 ——
        那时请同步更新**待决项 35** 与报告 §9.53 的结论。
        """
        pkg = BACKEND / "response_engine"
        calls = {"start_scanner": [], "set_redis": [], "set_rollback_callback": []}
        ttl_kwargs = []
        for p in sorted(pkg.rglob("*.py")):
            if "__pycache__" in p.parts:
                continue
            if p.name == "ttl_manager.py":
                continue          # 模块自身不算调用方
            src = p.read_text(encoding="utf-8", errors="replace")
            try:
                tree = ast.parse(src)
            except SyntaxError:
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    f = node.func
                    if isinstance(f, ast.Attribute) and f.attr in calls:
                        recv = f.value
                        name = getattr(recv, "id", "") or getattr(recv, "attr", "")
                        if name == "ttl_manager":
                            calls[f.attr].append(
                                "%s:%d" % (p.relative_to(pkg), node.lineno))
                # 有人传 _ttl_seconds / _rule_id 吗？—— 传了 register 才可达
                if isinstance(node, ast.Call):
                    for kw in node.keywords:
                        if kw.arg in ("_ttl_seconds", "_rule_id"):
                            ttl_kwargs.append("%s:%d %s" % (
                                p.relative_to(pkg), node.lineno, kw.arg))
        wired = {k: v for k, v in calls.items() if v}
        assert not wired, (
            "ttl_manager 的入口出现了生产调用方：%s —— "
            "若这是**接线**（待决项 35 落地），请先更新待决项与报告 §9.53 再改这条守卫"
            % wired)
        assert not ttl_kwargs, (
            "有生产代码传了 _ttl_seconds/_rule_id：%s —— "
            "那么 `safe_executor` 第 ⑧ 步的 ttl_manager.register 就**可达**了，"
            "本守卫的事实前提变了（请先更新待决项 35 与报告 §9.53）" % ttl_kwargs)
