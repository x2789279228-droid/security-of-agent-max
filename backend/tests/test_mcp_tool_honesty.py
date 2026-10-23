# -*- coding: utf-8 -*-
"""MCP 工具**不许把模拟执行报成成功**（整改方案 §二/§十三，§9.46）。

## 缺陷

`mcp_guard/tool_registry.py` 的 6 个执行器**全是模拟实现**
（作者自己的 docstring 写着「模拟防火墙封禁IP」…），但它们返回：

```python
{"status": "success", "detail": f"扫描完成: 目标={target}, 类型={scan_type}, 发现0个漏洞",
 "device": "scanner"}
```

而这条路径是**活的**：
`POST /api/audit/guard/call`（需 JWT 鉴权，`mcp_guard_enabled` 默认 True）
→ `guard_server.call_tool()` → `_finish()` 里 `decision.status == "allow"`
→ `registry.execute()` → 模拟执行器 → `status: success`。

实测哪些会被**直接放行**并真的落到模拟器：

| 工具 | 风险 | 决策 | 修复前 |
|---|---|---|---|
| `rate_limit` | MEDIUM | **allow** | **谎报成功** |
| `vulnerability_scan` | LOW | **allow** | **谎报成功**（还谎称「发现0个漏洞」） |
| `block_ip` / `terminate_process` | HIGH | require_confirmation | 不执行 |
| `isolate_host` | CRITICAL | require_confirmation | 不执行 |

`vulnerability_scan` 那种最恶劣：它声称**做了一次安全扫描**并给出
「**发现 0 个漏洞**」的结论 —— 一个从没跑过的扫描。

## 本守卫盯什么

1. **核心性质**：MCP 注册表里**每个**执行器返回的 `status` 都**不是** `success`；
2. 每个模拟执行器都必须带 `executed: False` 与 `simulated: True`；
3. detail 必须说明**未实际下发**；
4. **端到端**：走完整 Guard 链，被放行的工具返回的 `execution` 不能是 `success`；
5. 审计记录里的 `exec_status` 同样不能是 `success`；
6. **前提守卫**：这些执行器确实是模拟实现（作者自己的 docstring 写着「模拟」）——
   所以「报 simulated」是**准确**的，不是给真执行套上一层。

⚠ 判据用**行为**（实际返回值 / 端到端链路），不用源码文本。
"""
from __future__ import annotations

import os
import sys

import pytest

os.environ.setdefault("SHARED_MEMORY_SKIP_DOTENV", "1")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mcp_guard import mcp_guard, tool_registry as mcp_tr  # noqa: E402
from mcp_guard.guard_server import ToolCallRequest  # noqa: E402

#: 会被策略**直接放行**（因而真的会落到模拟器）的工具
ALLOWED_CASES = [
    ("rate_limit", {"ip": "1.2.3.4", "rate": 100}),
    ("vulnerability_scan", {"target": "10.0.0.5", "scan_type": "fast"}),
]

#: 高风险 → require_confirmation，不会执行
CONFIRM_CASES = [
    ("block_ip", {"ip": "1.2.3.4", "duration": 3600}),
    ("isolate_host", {"host": "10.0.0.5", "isolation_type": "network"}),
    ("terminate_process", {"pid": 1234}),
]


#: 每个执行器的**最小合法参数**（逐个调用时用）
MIN_ARGS = {
    "block_ip": {"ip": "1.2.3.4", "duration": 3600},
    "isolate_host": {"host": "10.0.0.5", "isolation_type": "network"},
    "rate_limit": {"ip": "1.2.3.4", "rate": 100},
    "terminate_process": {"pid": 1234},
    "alert_only": {"message": "probe"},
    "vulnerability_scan": {"target": "10.0.0.5", "scan_type": "fast"},
}


def _call(name, args, role="admin"):
    req = ToolCallRequest(tool_name=name, arguments=args, user_role=role,
                          reason="guard-test", caller="guard-test", source="api")
    return mcp_guard.call_tool(req)


class TestNoSimulatedToolMayClaimSuccess:
    def test_no_executor_reports_success(self):
        """【核心性质】**每个**执行器都不得返回 `status == "success"`。"""
        offenders = []
        for name, fn in sorted(mcp_tr._EXECUTORS.items()):
            out = fn(**MIN_ARGS.get(name, {}))
            if out.get("status") == "success":
                offenders.append((name, out))
        assert not offenders, (
            f"这些执行器把模拟执行报成了成功：{offenders}")

    def test_every_executor_marks_itself_as_not_executed(self):
        """每个执行器都必须带 `executed: False` 与 `simulated: True`。"""
        bad = []
        for name, fn in sorted(mcp_tr._EXECUTORS.items()):
            out = fn(**MIN_ARGS.get(name, {}))
            if out.get("executed") is not False or out.get("simulated") is not True:
                bad.append((name, out))
        assert not bad, f"缺少「未执行」标记的执行器：{bad}"

    def test_the_detail_says_it_was_not_dispatched(self):
        """detail 必须说明**未实际下发** —— 免得下游只读 detail。"""
        bad = []
        for name, fn in sorted(mcp_tr._EXECUTORS.items()):
            out = fn(**MIN_ARGS.get(name, {}))
            if "未实际下发" not in str(out.get("detail", "")):
                bad.append((name, out.get("detail")))
        assert not bad, f"detail 没有说明未实际下发：{bad}"


class TestTheEndToEndPathDoesNotClaimSuccess:
    @pytest.mark.parametrize("name,args", ALLOWED_CASES)
    def test_an_allowed_tool_does_not_report_success(self, name, args):
        """端到端：被**放行**的工具，返回的 execution 不能是 `success`。"""
        res = _call(name, args)
        assert res.get("decision") == "allow", res.get("reason")
        execution = res.get("execution") or {}
        assert execution.get("status") != "success", (
            f"{name} 被放行后报告了成功：{execution}")
        assert execution.get("executed") is False, execution

    @pytest.mark.parametrize("name,args", ALLOWED_CASES)
    def test_the_audit_record_does_not_record_success(self, name, args):
        """审计记录里的 `exec_status` 同样不能是 `success`。

        能力看板与审计回放读的是**记录**而不是返回值 ——
        记录说成功，谎报就成立了。
        """
        res = _call(name, args)
        checks = res.get("checks") or []
        for c in checks:
            if isinstance(c, dict) and c.get("check") == "execution":
                assert c.get("status") != "success", c
        execution = res.get("execution") or {}
        assert execution.get("status") != "success", execution

    @pytest.mark.parametrize("name,args", CONFIRM_CASES)
    def test_high_risk_tools_still_require_confirmation(self, name, args):
        """高风险工具**仍然**要求人工确认（这次修复没碰策略）。"""
        res = _call(name, args)
        assert res.get("decision") == "require_confirmation", res.get("reason")
        execution = res.get("execution") or {}
        assert execution.get("status") == "pending", execution


class TestThePremises:
    def test_these_executors_are_really_simulations(self):
        """前提守卫：这些执行器**确实是模拟**（作者自己的 docstring 写着「模拟」）。

        所以「报 simulated」是**准确**的 ——
        而不是给一次真执行套上一层含糊的标签。
        """
        for name, fn in sorted(mcp_tr._EXECUTORS.items()):
            doc = (fn.__doc__ or "")
            assert "模拟" in doc, (
                f"{name} 的 docstring 不再声明它是模拟实现 —— "
                "前提变了，守卫的结论要重估")

    def test_the_mcp_path_is_reachable(self):
        """前提守卫：这条路径是**活的**（`mcp_guard_enabled` 默认 True + 有 API 端点）。

        不活的话严重级别要重估（见 §7.1.4 的休眠纪律）。
        """
        from config import settings
        assert getattr(settings, "mcp_guard_enabled", False) is True, (
            "mcp_guard 默认关闭 —— 这条路径不是活的，严重级别要重估")
        import importlib
        audit = importlib.import_module("routers.audit")
        src = open(audit.__file__, "rb").read().decode("utf-8")
        assert "/guard/call" in src, "审计路由里没有 /guard/call 端点"


if __name__ == "__main__":       # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
