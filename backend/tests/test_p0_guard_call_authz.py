"""
P0-B-1 负面测试: /guard/call 的授权主体必须来自可信认证机制

修复前 (B-1):
    routers/audit.py 的 guard_call 用 `user_role=req.user_role`（请求体）做 RBAC 判定，
    JWT 解析出的 `user` 只被用作 caller 的兜底。
    → 任意已认证用户（含 viewer）在 body 里填 "user_role":"admin" 即可越过 RBAC
      调用 isolate_host / block_ip 等高危工具。

修复后:
    授权与审计身份唯一来源 = 已验证的 JWT 主体 (user.role / user.username)。
    请求模型不再声明 user_role / caller；旧客户端继续发送时被静默丢弃 (fail-closed)。

验收: 新测试在旧代码下失败，修复后通过。
"""
import asyncio
import os
import sys
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ.setdefault("SHARED_MEMORY_DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("SHARED_MEMORY_JWT_SECRET", "test-secret")
os.environ.setdefault("SHARED_MEMORY_LLM_API_KEY", "test")
os.environ.setdefault("SHARED_MEMORY_EMBEDDING_API_KEY", "test")
os.environ.setdefault("SHARED_MEMORY_ADMIN_PASSWORD", "test")

import sqlalchemy.ext.asyncio as _sa_async

_orig = _sa_async.create_async_engine


def _patched(url, **kw):
    for k in ("pool_size", "max_overflow", "pool_pre_ping", "pool_recycle"):
        kw.pop(k, None)
    return _orig(url, **kw)


_sa_async.create_async_engine = _patched
import models  # noqa: F401

from routers.audit import GuardCallRequest, guard_call

USER_ADMIN = SimpleNamespace(username="bob", role="admin", jti="j1")
USER_VIEWER = SimpleNamespace(username="carol", role="viewer", jti="j2")
USER_ANALYST = SimpleNamespace(username="dave", role="analyst", jti="j3")


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


class TestGuardCallAuthorizationSource:
    def test_viewer_cannot_escalate_via_body_user_role(self):
        """viewer 在请求体里自称 admin，必须被拒绝。

        这是 B-1 的核心回归：修复前 user_role 取自 req，viewer 可直接提权。
        """
        async def t():
            req = GuardCallRequest(
                tool_name="isolate_host",
                arguments={"host": "victim-host-01"},
                # 攻击者可控的提权字段 —— 修复后必须被丢弃
                user_role="admin",
                caller="i-am-admin",
            )
            result = await guard_call(req, USER_VIEWER)
            assert result["decision"] == "deny", (
                "viewer 自称 admin 竟然通过了 RBAC —— B-1 未修复"
            )
            permission = [c for c in result["checks"] if c["check"] == "permission"]
            assert permission and permission[0]["passed"] is False
            assert result.get("execution") is None, "被拒绝的调用不得执行工具"
        _run(t())

    def test_viewer_cannot_call_any_tool_even_without_privilege_claim(self):
        """viewer 的 RBAC 工具集为空，任何工具都应被拒绝。"""
        async def t():
            for tool, args in (
                ("block_ip", {"ip": "10.0.0.9"}),
                ("vulnerability_scan", {"target": "10.0.0.0/24"}),
                ("alert_only", {"message": "hi"}),
            ):
                req = GuardCallRequest(tool_name=tool, arguments=args)
                result = await guard_call(req, USER_VIEWER)
                assert result["decision"] == "deny", f"viewer 不应能调用 {tool}"
        _run(t())

    def test_caller_identity_is_not_spoofable(self):
        """caller（审计身份）同样必须来自 JWT，不能由请求体伪造。"""
        async def t():
            req = GuardCallRequest(
                tool_name="alert_only",
                arguments={"message": "probe"},
                caller="definitely-not-bob",
            )
            result = await guard_call(req, USER_ADMIN)
            assert result["decision"] == "allow"
            # ⚠ 2026-10-20 更正（§9.46）：这行原先断言 `status == "success"`。
            # MCP 的执行器是**模拟实现**，原先把模拟执行报成 success ——
            # 那正是 §9.46 修掉的谎报；留着它等于**把谎报钉成契约**。
            # 本用例的主体是「请求体里的 caller 不得被采纳」，
            # 所以要断言的是「**调用确实到达了工具**」，而不是「工具谎报成功」。
            # 断言 `action` 比断言 `status` 更能说明**哪个**工具跑了 → 并不放宽。
            assert result["execution"]["action"] == "alert_only"
            assert result["execution"]["status"] != "success", (
                "模拟执行器不许报成功（§9.46）")
        _run(t())

    def test_admin_still_allowed_via_authenticated_role(self):
        """正向对照：admin 凭 JWT 身份仍可调用低危工具（防止修复过头）。"""
        async def t():
            req = GuardCallRequest(
                tool_name="alert_only", arguments={"message": "ok"},
            )
            result = await guard_call(req, USER_ADMIN)
            assert result["decision"] == "allow"
        _run(t())

    def test_analyst_cannot_reach_high_risk_tool(self):
        """analyst 角色对 block_ip 无权 —— 证明 RBAC 仍按真实角色生效。"""
        async def t():
            req = GuardCallRequest(
                tool_name="block_ip",
                arguments={"ip": "203.0.113.5"},
                user_role="security_operator",  # 试图自称更高角色
            )
            result = await guard_call(req, USER_ANALYST)
            assert result["decision"] == "deny"
        _run(t())

    def test_request_model_does_not_declare_identity_fields(self):
        """模型层不得再声明 user_role / caller —— 防止未来有人重新接上。"""
        fields = set(GuardCallRequest.model_fields.keys())
        assert "user_role" not in fields, "GuardCallRequest 不得接受 user_role"
        assert "caller" not in fields, "GuardCallRequest 不得接受 caller"
        # 且多传字段不报错（静默丢弃 = fail-closed）
        req = GuardCallRequest(
            tool_name="alert_only", arguments={}, user_role="admin", caller="x"
        )
        assert not hasattr(req, "user_role")


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v", "--tb=short"])
