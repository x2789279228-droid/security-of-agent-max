# -*- coding: utf-8 -*-
"""工具参数契约的**三方一致性**（整改方案 §三.1 / §九.1，§9.46.9）。

## 三份声明

同一个响应动作的参数，在**三个地方**各有一份声明：

1. `stabilizer/param_coercer.py::PARAM_SCHEMAS` —— 转换器用的；
2. `mcp_guard/tool_registry.py::_PLATFORM_TOOLS` —— **给 LLM 看的**那一份；
3. `response_engine/response_registry.py` 的 `params_schema` + 动作函数签名 —— 真正执行的那一份。

实测它们**互相不一致**（详见报告 §9.46.5）。本守卫把这份漂移**钉住**，
这样「以哪份为准」被决定之前，漂移**不会继续扩大**，
而一旦有人修好，就必须同步更新这里（否则守卫转红）。

## 本守卫盯什么

1. **空 schema 不得剥光参数**（本轮已修的真缺陷）；
2. **非空 schema 仍然剥离未知字段** —— 那是**防参数走私**的安全措施，不能放松；
3. 三方漂移的**具体清单**必须与登记一致（双向）。

⚠ 判据用**行为**（实际转换结果 / 实际签名），不用源码文本。
"""
from __future__ import annotations

import importlib
import inspect
import os
import sys

import pytest

os.environ.setdefault("SHARED_MEMORY_SKIP_DOTENV", "1")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from stabilizer.param_coercer import PARAM_SCHEMAS, ParamCoercer  # noqa: E402


def _registry():
    """拿一份**干净的生产响应动作注册表**。

    2026-10-20 修复（整改报告 §9.47）：此前这里返回**模块级全局单例**
    `response_registry` → 全局单例一旦被任何代码注册过（哪怕只是测试），
    本守卫测到的「生产动作集」就会被污染 → **守卫变成顺序依赖**
    （实测：单独跑 9/9 绿，全量跑红，红的位置与真实缺陷无关）。

    现在用**独立实例**重建一份干净的生产动作集（不碰全局单例）。
    模块名被包 `__init__` 的实例遮住了，所以要用 importlib。
    """
    mod = importlib.import_module("response_engine.response_registry")
    reg = mod.ResponseRegistry()
    mod._init_registry(reg)
    return reg


def _mcp_tools():
    mod = importlib.import_module("mcp_guard.tool_registry")
    out = {}
    for t in mod._PLATFORM_TOOLS:
        props = (t.get("parameters") or {}).get("properties") or {}
        out[t["name"]] = set(props.keys())
    return out


#: MCP 面（**给 LLM 看的**那份）承诺了、但**响应引擎里根本没有**的动作
#: → 即使把 MCP 路径接到响应引擎，这三个也**无动作可调**。
MCP_ONLY = {"alert_only", "terminate_process", "vulnerability_scan"}
#: 响应引擎注册了、但**转换器没有**声明的动作（9 个）
REGISTRY_ONLY = {
    "clean_persistence", "disable_account", "dns_sinkhole", "forensic_snapshot",
    "kill_process", "kill_session", "quarantine_file", "recall_email", "send_alert",
}
#: 两边都有、但**字段名**不一致的（转换器 → 动作注册表）
FIELD_DRIFT = {
    "block_ip": ({"ip", "duration", "reason"}, {"src_ip", "reason", "duration_minutes"}),
    "isolate_host": ({"hostname", "isolation_type", "reason"},
                     {"host_ip", "reason", "extra_ips", "duration_minutes"}),
    "rate_limit": ({"target", "rate", "duration", "unit", "reason"},
                   {"src_ip", "bandwidth_kbps", "reason"}),
}


@pytest.fixture(scope="module")
def coercer():
    return ParamCoercer()


class TestTheEmptySchemaMustNotStripEverything:
    def test_an_empty_schema_keeps_the_parameters(self, coercer):
        """【核心性质】空 schema = 「没有声明任何字段」→ **不剥离**。

        修复前：`known_fields = set()` → 所有参数被当「未知字段」剥掉，
        而必填校验对空 schema 又不做任何检查 → **静默地以空参被调用**。
        """
        out, changes = coercer.coerce("causal.graph",
                                     {"entity": "1.2.3.4", "depth": 3})
        assert out == {"entity": "1.2.3.4", "depth": 3}, out
        assert not [c for c in changes if c[1] == "strip_unknown"], changes

    def test_a_nonempty_schema_still_strips_unknown_fields(self, coercer):
        """**反向判据**：非空 schema 仍然剥离未知字段。

        那是**防参数走私**的安全措施（不让调用方夹带 `cmd` 之类），
        不能因为上面那条就放松。
        """
        out, changes = coercer.coerce(
            "block_ip", {"ip": "1.2.3.4", "cmd": "rm -rf /"})
        assert "cmd" not in out, out
        assert any(c[0] == "cmd" and c[1] == "strip_unknown" for c in changes), changes

    def test_an_unknown_tool_is_left_untouched(self, coercer):
        """未注册的工具**原样返回**（与空 schema 同一条原则）。"""
        params = {"whatever": 1}
        out, changes = coercer.coerce("no.such.tool", dict(params))
        assert out == params, out
        assert changes == [], changes


class TestTheThreeDeclarationsDriftIsPinned:
    def test_the_mcp_face_covers_everything_the_coercer_declares(self, coercer):
        """MCP 面（给 LLM 的）6 个工具，转换器**全部**声明了 —— 这一层是自洽的。"""
        mcp = set(_mcp_tools())
        missing = mcp - set(PARAM_SCHEMAS)
        assert not missing, f"转换器漏了 MCP 面的工具：{missing}"

    def test_the_mcp_only_tools_are_pinned(self, coercer):
        """MCP 面承诺了、但**响应引擎里根本没有**的动作 —— 清单必须一致。

        这三个尤其要紧：即使把 MCP 路径接到响应引擎，
        它们也**无动作可调**（`alert_only` / `terminate_process` / `vulnerability_scan`）。
        """
        reg = _registry()
        registry_names = {a.name for a in reg.list_actions()}
        measured = set(_mcp_tools()) - registry_names
        assert measured == MCP_ONLY, (
            f"MCP 面与响应引擎的动作名差异变了：{measured}")

    def test_the_registry_only_tools_are_pinned(self, coercer):
        """响应引擎注册了、但转换器**没有**声明的动作 —— 清单必须一致。"""
        reg = _registry()
        registry_names = {a.name for a in reg.list_actions()}
        measured = {n for n in registry_names if n not in PARAM_SCHEMAS}
        assert measured == REGISTRY_ONLY, (
            f"响应引擎/转换器的工具名差异变了：{measured}")

    def test_the_field_name_drift_is_pinned(self, coercer):
        """同名工具的**字段名**漂移必须与登记一致（双向）。"""
        reg = _registry()
        measured = {}
        for tool in ("block_ip", "isolate_host", "rate_limit"):
            action = reg.get_action(tool)
            assert action is not None, tool
            registry_fields = set((action.params_schema or {}).keys())
            measured[tool] = (set(PARAM_SCHEMAS[tool].keys()), registry_fields)
        assert measured == FIELD_DRIFT, (
            "参数字段名的漂移清单变了 —— 修好了就同步更新本守卫（待决项 28）")


class TestThePremises:
    def test_the_mcp_face_is_the_one_the_llm_sees(self):
        """前提：MCP 面那份就是**给 LLM 看的**声明。"""
        mcp = _mcp_tools()
        assert "block_ip" in mcp, sorted(mcp)
        # 它给 LLM 的字段名与动作签名**不同** —— 这正是漂移本身
        assert mcp["block_ip"] == {"ip", "duration"}, mcp["block_ip"]

    def test_the_registry_schema_matches_the_action_signature(self):
        """前提：动作注册表的 `params_schema` 与动作签名**一致**（它是唯一自洽的一份）。"""
        reg = _registry()
        for action in reg.list_actions():
            fn = reg._exec_fns.get(action.name)
            if fn is None:
                continue
            sig = {p for p in inspect.signature(fn).parameters
                   if p not in ("self", "kwargs")}
            declared = set((action.params_schema or {}).keys())
            missing = declared - sig
            assert not missing, (
                f"{action.name} 的注册表 schema 声明了动作签名里没有的字段：{missing}")


if __name__ == "__main__":       # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
