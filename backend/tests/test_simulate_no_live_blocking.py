# -*- coding: utf-8 -*-
"""R19: /api/response/simulate 不得旁路 HIGH 动作审批分级 (P2)。

修复前: simulate 不传 allow_blocking → orchestrator 缺省回落 True → live 模式下
operator 借 simulate 注入 threat_type 命中 auto_execute 策略即可对任意 src_ip
触发真实 iptables DROP, 绕过 /api/response/execute 的强制审批。
双轨过滤语义本身由既有 v5 测试覆盖; 这里锁定 simulate 端点的服务端强制。
"""
from __future__ import annotations

import os
import sys
from unittest.mock import AsyncMock

import pytest

os.environ.setdefault("SHARED_MEMORY_SKIP_DOTENV", "1")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.mark.asyncio
async def test_simulate_endpoint_forces_allow_blocking_false(monkeypatch):
    """端点层: 传给 orchestrator 的 allow_blocking 恒为 False(服务端写死)。"""
    from routers import response as response_mod

    captured = {}

    async def _fake_orch(session=None, threat_info=None, event_id=None,
                        session_id=None, allow_blocking=None, **kw):
        captured["allow_blocking"] = allow_blocking
        captured["threat_info"] = threat_info
        return {"match_status": "certain", "actions": [], "actions_executed": 0}

    monkeypatch.setattr(response_mod.response_orchestrator,
                        "on_threat_detected", _fake_orch)

    class _Req:
        headers = {}
        client = None

    class _User:
        username = "op"
        role = "operator"

    req = response_mod.SimulateThreatRequest(
        threat_type="ddos", confidence=0.9, severity="critical", src_ip="1.2.3.4",
    )
    monkeypatch.setattr(response_mod, "_audit", AsyncMock(return_value=None))
    await response_mod.simulate_threat(req, _Req(), session=None, user=_User())

    assert captured["allow_blocking"] is False
    assert captured["threat_info"]["allow_blocking"] is False


def test_dual_track_registry_excludes_block_ip():
    """双轨白名单语义锁定: 仅告警轨不含任何阻断/隔离/限速动作。"""
    from response_engine.response_orchestrator import ALERT_ONLY_ACTIONS
    forbidden = {"block_ip", "isolate_host", "rate_limit", "kill_process",
                 "quarantine_file", "clean_persistence"}
    assert ALERT_ONLY_ACTIONS.isdisjoint(forbidden)
    assert ALERT_ONLY_ACTIONS == {"send_alert"}
