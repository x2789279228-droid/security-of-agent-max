"""F2 live 演练 (2026-10-30) 发现的两个跨进程回滚缺陷的回归钉。

实测形态（docs/upgrade/evidence/M1-response-safety.md F2 节）：
  1. 封禁进程退出后, `get_active_rules_async` 的合并视图(内存台账+本进程
     TTL 索引)缺该记录 → `_unblock_ip` src_ip 分支循环零命中 → deleted=0,
     且冗余 rule_id 未被用于直连扫描 → 规则残留。
  2. `response_registry.rollback` 包装无条件 success=True(只要不抛异常)
     → deleted_count=0/success=false 被计成回滚成功(虚报)。
"""
import sys

import pytest

import response_engine.response_registry  # noqa: F401  确保模块已加载
# 包 __init__ 把 `response_registry` 再导出为单例实例，直接 import 会拿到实例而非模块
rr = sys.modules["response_engine.response_registry"]
from response_engine.response_registry import response_registry


@pytest.mark.asyncio
async def test_rollback_wrapper_does_not_mask_inner_failure(monkeypatch):
    """回滚函数自报 success=False → 包装层必须 False（不虚报）。"""
    async def _fail_rollback(**kwargs):
        return {"action": "unblock_ip", "success": False, "deleted_count": 0}

    monkeypatch.setitem(response_registry._rollback_fns, "block_ip", _fail_rollback)
    wrapped = await response_registry.rollback("block_ip", src_ip="1.2.3.4")
    assert wrapped["success"] is False
    assert wrapped["result"]["deleted_count"] == 0

    async def _ok_rollback(**kwargs):
        return {"action": "unblock_ip", "success": True, "deleted_count": 1}

    monkeypatch.setitem(response_registry._rollback_fns, "block_ip", _ok_rollback)
    wrapped = await response_registry.rollback("block_ip", src_ip="1.2.3.4")
    assert wrapped["success"] is True


@pytest.mark.asyncio
async def test_unblock_rule_id_direct_fallback_when_view_missing(monkeypatch):
    """合并视图零命中时, 冗余 rule_id 直连 ssh_firewall.rollback 扫真实 iptables。"""
    calls = {}

    class _FakeFw:
        # _ensure_firewall_connected 的就绪短路: 已连接 + 已配置 host
        _connected = True
        _config = {"host": "soc-firewall"}

        async def get_active_rules_async(self):
            return []  # 跨进程形态: 视图为空

        def rollback(self, rule_id):
            calls["rule_id"] = rule_id
            return {"status": "success", "deleted": 1}

    fake_fw = _FakeFw()
    monkeypatch.setattr(rr, "_execution_mode", lambda: "live")
    import response_engine.response_registry as mod
    monkeypatch.setattr("response_engine.ssh_firewall.ssh_firewall", fake_fw)

    cleared = {}
    from response_engine.safe_executor import safe_executor
    async def _fake_clear(action, target):
        cleared[(action, target)] = True
    monkeypatch.setattr(safe_executor, "clear_idempotency_for_target", _fake_clear)

    marked = {}
    async def _fake_mark(**kwargs):
        marked.update(kwargs)
    monkeypatch.setattr(rr, "_mark_containment_rolled_back", _fake_mark)

    result = await rr._unblock_ip(src_ip="203.0.113.66", rule_id="FW-RULE-1429485173")
    assert result["success"] is True
    assert result["deleted_count"] == 1
    assert calls["rule_id"] == "FW-RULE-1429485173"  # 直连用的冗余 rule_id
    assert cleared.get(("block_ip", "203.0.113.66")) is True
    assert marked.get("target_id") == "203.0.113.66"


@pytest.mark.asyncio
async def test_unblock_view_hit_takes_precedence_over_direct(monkeypatch):
    """视图能命中时仍走视图路径（多规则同 IP 全解）, 不触发直连兜底。"""
    rollback_calls = []

    class _FakeFw:
        _connected = True
        _config = {"host": "soc-firewall"}

        async def get_active_rules_async(self):
            return [
                {"rule_id": "FW-RULE-A", "ip": "10.0.0.1", "status": "active"},
                {"rule_id": "FW-RULE-B", "ip": "10.0.0.1", "status": "active"},
            ]

        def rollback(self, rule_id):
            rollback_calls.append(rule_id)
            return {"status": "success", "deleted": 1}

    monkeypatch.setattr(rr, "_execution_mode", lambda: "live")
    monkeypatch.setattr("response_engine.ssh_firewall.ssh_firewall", _FakeFw())
    monkeypatch.setattr(rr, "_mark_containment_rolled_back", _fake_noop_mark())

    result = await rr._unblock_ip(src_ip="10.0.0.1", rule_id="FW-RULE-C")
    assert result["success"] is True
    assert result["deleted_count"] == 2
    assert sorted(rollback_calls) == ["FW-RULE-A", "FW-RULE-B"]  # 未用直连 C


def _fake_noop_mark():
    async def _mark(**kwargs):
        return None
    return _mark
