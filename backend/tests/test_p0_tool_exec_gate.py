"""
P0-B-2 / B-3 负面测试: 统一执行检查入口 + 高风险工具失败关闭 + 遥测不伪造 allow

B-2 (统一执行检查入口):
    修复前 tool_registry.execute 的函数体只有 `self._tools.get(name)`，
    随后直接 `await tool["fn"](**kwargs)` —— RBAC / 参数校验 / 规则引擎 /
    行为签名全部缺席。审计链路的 11 个真实工具全部经由这条无检查路径。

B-3 (失败关闭):
    修复前不存在「高风险工具遇检测器异常时拒绝」这一语义。
    现按工具 risk_level 区分：high/critical 失败关闭，low 降级放行并告警。
    register() 的默认 risk_level=high（fail-secure）——未显式声明风险等级
    的新工具不会默认获得放行。

遥测: 未经过 Guard 的调用不再记录成 decision="allow"。

验收: 新测试在旧代码下失败，修复后通过。
"""
import asyncio
import os
import sys

import pytest

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

import tool_registry as tr_mod
from tool_registry import ToolRegistry, ToolExecutionDenied, RISK_LOW, RISK_HIGH


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


def _make_registry(risk_level):
    reg = ToolRegistry()
    calls = []

    async def _fn(**kwargs):
        calls.append(kwargs)
        return {"ok": True}

    reg.register("t.probe", _fn, description="probe", risk_level=risk_level)
    return reg, calls


class _BrokenDetector:
    """模拟 MCP Guard 行为检测器故障。"""

    def observe_pre_exec(self, rec):
        raise RuntimeError("detector down")


class _NoopDetector:
    def observe_pre_exec(self, rec):
        return None


@pytest.fixture()
def broken_guard(monkeypatch):
    monkeypatch.setattr(tr_mod, "_pre_execute_check", tr_mod._pre_execute_check)
    import mcp_guard
    monkeypatch.setattr(mcp_guard.mcp_guard, "detector", _BrokenDetector())


@pytest.fixture()
def noop_guard(monkeypatch):
    import mcp_guard
    monkeypatch.setattr(mcp_guard.mcp_guard, "detector", _NoopDetector())


# ═══════════════════════════════════════════
# B-3: 失败关闭语义
# ═══════════════════════════════════════════

class TestFailClosed:
    def test_high_risk_tool_denied_when_detector_broken(self, broken_guard):
        reg, calls = _make_registry(RISK_HIGH)
        with pytest.raises(ToolExecutionDenied):
            _run(reg.execute("t.probe", a=1))
        assert not calls, "被拒绝的工具函数不得被执行"

    def test_medium_risk_tool_denied_when_detector_broken(self, broken_guard):
        reg, calls = _make_registry(tr_mod.RISK_MEDIUM)
        with pytest.raises(ToolExecutionDenied):
            _run(reg.execute("t.probe", a=1))
        assert not calls

    def test_low_risk_tool_degrades_open_when_detector_broken(self, broken_guard):
        """只读工具允许降级放行 —— 这是显式配置，不是默认行为。"""
        reg, calls = _make_registry(RISK_LOW)
        result = _run(reg.execute("t.probe", a=1))
        assert result == {"ok": True}
        assert len(calls) == 1

    def test_missing_guard_module_denies_high_risk(self, monkeypatch):
        """整个 Guard 模块不可用时，高风险工具仍须失败关闭。"""
        import builtins
        real_import = builtins.__import__

        def _blocked(name, *a, **k):
            if name == "mcp_guard" or name.startswith("mcp_guard."):
                raise ImportError("guard unavailable")
            return real_import(name, *a, **k)

        monkeypatch.setattr(builtins, "__import__", _blocked)
        reg, calls = _make_registry(RISK_HIGH)
        with pytest.raises(ToolExecutionDenied):
            _run(reg.execute("t.probe"))
        assert not calls


class TestDefaultRiskIsFailSecure:
    def test_new_tool_defaults_to_high_risk(self):
        reg = ToolRegistry()

        async def _fn(**kwargs):
            return 1

        reg.register("t.undeclared", _fn)      # 未声明 risk_level
        assert reg.risk_level("t.undeclared") == RISK_HIGH

    def test_undeclared_tool_is_high_risk(self):
        reg = ToolRegistry()
        assert reg.risk_level("t.does_not_exist") == RISK_HIGH

    def test_all_registered_audit_tools_are_readonly_low(self):
        """已注册的审计工具都显式声明为 low —— 不得靠默认值蒙混。"""
        assert tool_registry_low_tools_declared()


def tool_registry_low_tools_declared():
    reg = tr_mod.tool_registry
    names = reg.list_tools()
    assert names, "工具注册表不应为空"
    bad = [n for n in names if reg.risk_level(n) != RISK_LOW]
    assert not bad, f"这些工具未显式声明为 low（只读）: {bad}"
    return True


# ═══════════════════════════════════════════
# B-2: 未知工具不做模糊匹配
# ═══════════════════════════════════════════

class TestUnknownToolNoFuzzyMatch:
    def test_unknown_tool_raises_value_error(self, noop_guard):
        reg, _ = _make_registry(RISK_LOW)
        with pytest.raises(ValueError):
            _run(reg.execute("t.probee"))        # 少一个字母

    def test_near_miss_names_all_rejected(self, noop_guard):
        reg, calls = _make_registry(RISK_LOW)
        for bad in ("t.pro", "t.PROBE", "probe", "t.probe.extra", ""):
            with pytest.raises(ValueError):
                _run(reg.execute(bad))
        assert not calls, "模糊匹配把未知工具解析成了已注册工具"


# ═══════════════════════════════════════════
# 遥测诚实性
# ═══════════════════════════════════════════

class TestTelemetryHonesty:
    def test_executor_records_unguarded_not_allow(self, monkeypatch):
        """P2 验收项：未经过 Guard 的调用不得记录成 decision="allow"。"""
        from agents import agent_executor as ex
        from audit_types import ToolCall, ToolResult

        seen = {}

        def _fake_ingest(**kwargs):
            seen.update(kwargs)
            return None

        import mcp_guard.telemetry as tel
        monkeypatch.setattr(tel, "ingest_tool_call", _fake_ingest)

        ex.Executor._emit_tool_telemetry(
            ToolCall(call_id="c1", task_id="t1", tool="event_store.query", args={}),
            ToolResult(call_id="c1", task_id="t1", tool="event_store.query",
                       success=True, data={}, duration_ms=1.0),
            {"session_id": "s1"},
        )
        assert seen["decision"] != "allow", (
            f"遥测仍把未受 Guard 的调用记为 allow: {seen['decision']!r}"
        )
        assert seen["decision"] == "unguarded"
        checks = seen.get("checks") or []
        assert checks, "必须显式列出实际执行过的检查"
        assert any(c.get("check") == "pre_exec_signature" for c in checks)


class TestPreExecHookRuns:
    def test_hook_is_invoked_before_tool_function(self, noop_guard):
        reg, calls = _make_registry(RISK_LOW)
        _run(reg.execute("t.probe", x=7))
        assert calls == [{"x": 7}]

    def test_session_arg_stripped_from_signature_payload(self, broken_guard):
        """session 对象不得进入指纹参数（不可序列化且噪声大）。"""
        reg = ToolRegistry()
        seen_args = []

        class _Rec:
            def __init__(self, **kw):
                seen_args.append(kw["arguments"])

        class _Det:
            def observe_pre_exec(self, rec):
                raise RuntimeError("stop")

        import mcp_guard
        import mcp_guard.call_record as cr
        orig = cr.ToolCallRecord.from_kwargs
        cr.ToolCallRecord.from_kwargs = classmethod(
            lambda cls, **kw: _Rec(**kw)
        )
        try:
            import mcp_guard
            mcp_guard.mcp_guard.detector = _Det()
            reg2 = ToolRegistry()

            async def _fn(**kwargs):
                return 1

            reg2.register("t.probe", _fn, risk_level=RISK_LOW)
            _run(reg2.execute("t.probe", session=object(), _internal=1, real="v"))
        finally:
            cr.ToolCallRecord.from_kwargs = orig

        assert seen_args, "应当构造过签名记录"
        assert "session" not in seen_args[0]
        assert "_internal" not in seen_args[0]
        assert seen_args[0].get("real") == "v"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
