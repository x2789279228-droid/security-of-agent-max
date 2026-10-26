# -*- coding: utf-8 -*-
"""MCP Guard 审批闭环回归 — POST /guard/approvals/{id}/approve|deny 接线。

修复前(2026-10-27 评审发现): mcp_guard.approvals 的 approve()/deny() 方法
已实现, 但全库没有任何 HTTP 路由调用 —— require_confirmation 产生的工单
只能 GET 查看、永久 pending, "四层工具调用控制"的审批闭环在 Web 侧断裂。

本测试钉住四件事:
  1. admin 可批准/拒绝 pending 工单, decided_by 强制取 JWT 身份(非请求体);
  2. 已决策/不存在的工单 → 404, 二次决策不生效;
  3. 决策必须写审计(guard.approval_approve / guard.approval_deny, actor=JWT);
  4. deny 的 reason 逐字落库。
"""
from __future__ import annotations

import asyncio
import os
import sys
from types import SimpleNamespace

import pytest

os.environ.setdefault("SHARED_MEMORY_SKIP_DOTENV", "1")
os.environ.setdefault("SHARED_MEMORY_DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("SHARED_MEMORY_JWT_SECRET", "test-secret")
os.environ.setdefault("SHARED_MEMORY_LLM_API_KEY", "test")
os.environ.setdefault("SHARED_MEMORY_EMBEDDING_API_KEY", "test")
os.environ.setdefault("SHARED_MEMORY_ADMIN_PASSWORD", "test")

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import HTTPException  # noqa: E402

import routers.audit as audit_router  # noqa: E402
from mcp_guard import mcp_guard  # noqa: E402


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


class _FakeRequest:
    """log_from_request 只用 client/headers, 直接调用端点函数时的 stub"""

    class _Client:
        host = "127.0.0.1"

    client = _Client()
    headers = {"user-agent": "pytest"}


@pytest.fixture()
def admin():
    return SimpleNamespace(username="alice", role="admin")


@pytest.fixture()
def audit_records(monkeypatch):
    """打桩 audit.py 命名空间里的 log_from_request, 记录 (action, actor, target)。"""
    records: list[dict] = []

    async def _fake_log(session, request, user, action, target_type="",
                        target_id="", before=None, after=None, reason=""):
        records.append({
            "action": action,
            "actor": getattr(user, "username", ""),
            "target_id": target_id,
            "reason": reason,
            "after": after,
        })

    monkeypatch.setattr(audit_router, "log_from_request", _fake_log)
    return records


@pytest.fixture(autouse=True)
def _clean_queue():
    mcp_guard.approvals.clear()
    yield
    mcp_guard.approvals.clear()


def _ticket(**kw) -> str:
    defaults = dict(
        tool_name="isolate_host",
        arguments={"ip": "203.0.113.9"},
        user_role="operator",
        reason="演示工单",
        decision_reason="policy: require_confirmation",
    )
    defaults.update(kw)
    return mcp_guard.approvals.create_ticket(**defaults)["ticket_id"]


def test_approve_pending_ticket_records_jwt_actor(admin, audit_records):
    tid = _ticket()
    res = _run(audit_router.guard_approval_approve(
        tid, _FakeRequest(), session=None, user=admin))
    assert res["status"] == "approved"
    ticket = mcp_guard.approvals.get_ticket(tid)
    assert ticket["status"] == "approved"
    # actor 取 JWT 身份, 不是默认值 "admin"(工单创建者角色是 operator)
    assert ticket["decided_by"] == "alice"
    assert audit_records and audit_records[0]["action"] == "guard.approval_approve"
    assert audit_records[0]["actor"] == "alice"
    assert audit_records[0]["target_id"] == tid


def test_double_decision_returns_404(admin, audit_records):
    tid = _ticket()
    _run(audit_router.guard_approval_approve(tid, _FakeRequest(), session=None, user=admin))
    with pytest.raises(HTTPException) as ei:
        _run(audit_router.guard_approval_approve(tid, _FakeRequest(), session=None, user=admin))
    assert ei.value.status_code == 404

    tid2 = _ticket()
    _run(audit_router.guard_approval_deny(tid2, _FakeRequest(), reason="误报",
                                          session=None, user=admin))
    with pytest.raises(HTTPException) as ei2:
        _run(audit_router.guard_approval_deny(tid2, _FakeRequest(), reason="再拒",
                                              session=None, user=admin))
    assert ei2.value.status_code == 404
    # 第一次决策的结果不被二次请求覆盖
    assert mcp_guard.approvals.get_ticket(tid2)["deny_reason"] == "误报"


def test_deny_records_reason(admin, audit_records):
    tid = _ticket()
    res = _run(audit_router.guard_approval_deny(
        tid, _FakeRequest(), reason="工单参数与告警不符", session=None, user=admin))
    assert res == {"status": "denied", "ticket_id": tid,
                   "reason": "工单参数与告警不符"}
    ticket = mcp_guard.approvals.get_ticket(tid)
    assert ticket["status"] == "denied"
    assert ticket["decided_by"] == "alice"
    assert audit_records[0]["action"] == "guard.approval_deny"
    assert audit_records[0]["reason"] == "工单参数与告警不符"


def test_unknown_ticket_404(admin, audit_records):
    with pytest.raises(HTTPException) as ei:
        _run(audit_router.guard_approval_approve(
            "TK-DOESNOTEXIST", _FakeRequest(), session=None, user=admin))
    assert ei.value.status_code == 404
    assert not audit_records, "未命中工单不得写审计"
