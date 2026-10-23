# -*- coding: utf-8 -*-
"""响应动作注册表的**隔离性**（整改报告 §9.47）。

## 背景（一次真实踩坑）

`response_engine/response_registry.py` 里的 `response_registry` 是**模块级全局单例**。
本轮实测：`tests/test_rollback_idempotent.py` 在**模块顶层**（import 期即执行）
把两个假动作 `fake_pr2_block` / `fake_pr2_gone` 注册进了这个**生产单例**，
且**永不还原**。

后果不是「测试不干净」这么轻：

1. 全局单例是**生产对象**，`routers/response.py` 的动作清单接口读的就是它
   → 任何读动作列表的代码都会看到测试动作；
2. 依赖「生产动作集」做断言的守卫会**变成顺序依赖** ——
   实测参数契约漂移守卫**单独跑 9/9 绿、全量跑红**，
   红的位置与真实缺陷毫无关系（第 18 次全量回归因此转红）。

## 本守卫盯什么

1. **生产动作集是确定的**：用**独立实例**重建的干净注册表 == 显式声明的 12 个；
2. **构造干净注册表不碰全局单例**（隔离真的成立，而不只是「恰好没人读」）；
3. **全局单例不被污染**（金丝雀：出现任何非生产动作 → 转红）；
4. **注册是幂等的**（重复初始化不产生漂移）；
5. **每个注册的动作都有可执行函数**（注册了但没实现 = 假功能）。

## 为什么用「独立实例」而不是直接读全局单例

因为**全局单例就是被污染的那个东西**。守卫若读它，
就等于用「当前进程状态」当「生产事实」——
而进程状态会被别的测试改掉。独立实例是唯一稳定的测量面。
"""
from __future__ import annotations

import importlib
import os
import sys

os.environ.setdefault("SHARED_MEMORY_SKIP_DOTENV", "1")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


#: **生产动作集**（显式声明，2026-10-20 实测干净注册表 = 12 个）。
#: 生产增删动作 → 本守卫转红 → 必须同步更新这里（否则守卫在说谎）。
PRODUCTION_ACTIONS = {
    "block_ip", "clean_persistence", "disable_account", "dns_sinkhole",
    "forensic_snapshot", "isolate_host", "kill_process", "kill_session",
    "quarantine_file", "rate_limit", "recall_email", "send_alert",
}


def _module():
    """拿**模块**（不是包 `__init__` 导出的那个同名实例 —— 它会遮住模块）。"""
    return importlib.import_module("response_engine.response_registry")


def _clean_registry():
    """构造一份**干净的生产动作集**：独立实例，**不碰全局单例**。"""
    mod = _module()
    reg = mod.ResponseRegistry()
    mod._init_registry(reg)
    return reg


def _names(reg) -> set:
    return {a.name for a in reg.list_actions()}


class TestTheProductionActionSetIsDeterministic:
    def test_the_clean_registry_has_exactly_the_declared_actions(self):
        """干净注册表 == 显式声明的 12 个（双向）。"""
        measured = _names(_clean_registry())
        assert measured == PRODUCTION_ACTIONS, (
            f"生产动作集变了 —— 多: {sorted(measured - PRODUCTION_ACTIONS)} "
            f"少: {sorted(PRODUCTION_ACTIONS - measured)}")

    def test_every_production_action_has_an_executor(self):
        """注册了但**没有可执行函数** = 假功能（`execute` 会抛 "No executor"）。"""
        reg = _clean_registry()
        missing = sorted(n for n in _names(reg) if n not in reg._exec_fns)
        assert not missing, f"这些动作注册了但没有执行函数：{missing}"

    def test_building_a_clean_registry_does_not_touch_the_global(self):
        """【隔离性核心】构造独立 registry **不得**动到全局单例。

        判据用**动作定义对象的身份**（`id`），不是动作名集合 ——
        因为重注册是**幂等**的：动作名集合一模一样，
        只有对象被换掉。比对名字的话，这条**永远抓不到**「注册流向了全局」。
        """
        mod = _module()
        before = {a.name: id(a) for a in mod.response_registry.list_actions()}
        _clean_registry()
        after = {a.name: id(a) for a in mod.response_registry.list_actions()}
        assert after == before, (
            f"构造干净注册表重建了全局单例的动作定义："
            f"被换掉的={sorted(n for n in before if before[n] != after.get(n))}")

    def test_registering_twice_does_not_change_the_action_set(self):
        """幂等：重复初始化不得产生重复或漂移的动作集。"""
        mod = _module()
        reg = mod.ResponseRegistry()
        mod._init_registry(reg)
        once = _names(reg)
        mod._init_registry(reg)
        assert _names(reg) == once, "重复初始化改变了动作集"


class TestTheGlobalSingletonIsNotPolluted:
    def test_the_global_singleton_holds_exactly_the_production_actions(self):
        """**金丝雀**：全局单例里出现任何非生产动作 → 有人在污染它。

        这是本轮第 18 次全量回归转红的直接原因：
        `tests/test_rollback_idempotent.py` 顶层注册 `fake_pr2_*` 且永不还原。
        """
        mod = _module()
        measured = _names(mod.response_registry)
        assert measured == PRODUCTION_ACTIONS, (
            f"全局单例被污染 —— 多: {sorted(measured - PRODUCTION_ACTIONS)} "
            f"少: {sorted(PRODUCTION_ACTIONS - measured)}")

    def test_the_pollution_can_be_undone_exactly(self):
        """钉住「快照-还原」这个约定：还原后**逐项**回到原状。"""
        mod = _module()
        reg = mod.response_registry
        before = (dict(reg._actions), dict(reg._exec_fns), dict(reg._rollback_fns))

        async def _noop(**kwargs):
            return {"success": True}

        try:
            reg.register("fake_probe_isolation", _noop, description="probe")
            assert "fake_probe_isolation" in _names(reg)
        finally:
            reg._actions.clear()
            reg._actions.update(before[0])
            reg._exec_fns.clear()
            reg._exec_fns.update(before[1])
            reg._rollback_fns.clear()
            reg._rollback_fns.update(before[2])
        assert "fake_probe_isolation" not in _names(reg)
        assert _names(reg) == PRODUCTION_ACTIONS


if __name__ == "__main__":       # pragma: no cover
    import pytest
    raise SystemExit(pytest.main([__file__, "-q"]))
