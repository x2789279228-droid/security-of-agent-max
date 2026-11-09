"""MCP 协议端点测试 — JSON-RPC 2.0 符合性 + 治理语义不放松。

无需 pytest-asyncio: 显式 asyncio.run() 驱动 async 分发函数(仓库既有惯例)。

覆盖:
  1. initialize / ping / tools/list / tools/call 协议形状
  2. JSON-RPC 错误码(-32601 未知方法 / -32602 坏参数 / -32600 非法请求)
  3. 通知(无 id)不产生应答; 批量请求逐条应答
  4. 治理语义: RBAC 拒绝 → isError 工具结果(而非协议错误), 决策明细透出;
     防幻觉(未注册工具) → deny
"""
import asyncio

from mcp_protocol import PROTOCOL_VERSION, handle_jsonrpc


def _run(coro):
    return asyncio.run(coro)


def _req(method, params=None, req_id=1):
    msg = {"jsonrpc": "2.0", "method": method}
    if params is not None:
        msg["params"] = params
    if req_id is not None:
        msg["id"] = req_id
    return msg


# ── 1. 协议形状 ───────────────────────────────────────────────

def test_initialize_returns_protocol_info():
    resp = _run(handle_jsonrpc(_req("initialize", {"protocolVersion": PROTOCOL_VERSION})))
    assert resp["jsonrpc"] == "2.0" and resp["id"] == 1
    result = resp["result"]
    assert result["protocolVersion"] == PROTOCOL_VERSION
    assert "tools" in result["capabilities"]
    assert result["serverInfo"]["name"] == "watchtower-soc-mcp"
    # 治理层自报: 客户端能感知调用会经过检查链
    assert "MCP Guard" in result["instructions"]


def test_initialize_echoes_client_version():
    resp = _run(handle_jsonrpc(_req("initialize", {"protocolVersion": "2099-01-01"})))
    assert resp["result"]["protocolVersion"] == "2099-01-01"


def test_ping():
    resp = _run(handle_jsonrpc(_req("ping")))
    assert resp["result"] == {}


def test_tools_list_shape_and_governance_metadata():
    resp = _run(handle_jsonrpc(_req("tools/list"), user_role="admin"))
    tools = resp["result"]["tools"]
    names = {t["name"] for t in tools}
    # 与 guard 注册表对齐(6 个治理工具)
    assert {"block_ip", "isolate_host", "alert_only"} <= names
    for t in tools:
        assert t["inputSchema"].get("type") == "object", "inputSchema 必须是 JSON Schema"
        assert t["annotations"]["riskLevel"], "风险等级必须透出"
    # HIGH 风险工具的注解如实标注
    block = next(t for t in tools if t["name"] == "block_ip")
    assert block["annotations"]["riskLevel"] == "HIGH"


# ── 2. JSON-RPC 错误码 ────────────────────────────────────────

def test_unknown_method_is_32601():
    resp = _run(handle_jsonrpc(_req("resources/list")))
    assert resp["error"]["code"] == -32601


def test_bad_jsonrpc_version_is_32600():
    resp = _run(handle_jsonrpc({"jsonrpc": "1.0", "id": 7, "method": "ping"}))
    assert resp["error"]["code"] == -32600


def test_tools_call_missing_name_is_32602():
    resp = _run(handle_jsonrpc(_req("tools/call", {"arguments": {}})))
    assert resp["error"]["code"] == -32602


def test_tools_call_bad_arguments_type_is_32602():
    resp = _run(handle_jsonrpc(_req("tools/call", {"name": "alert_only", "arguments": ["not", "dict"]})))
    assert resp["error"]["code"] == -32602


def test_empty_batch_is_32600():
    resp = _run(handle_jsonrpc([]))
    assert resp["error"]["code"] == -32600


# ── 3. 通知与批量 ─────────────────────────────────────────────

def test_notification_gets_no_response():
    # notifications/initialized 与任意无 id 消息: 不应答
    assert _run(handle_jsonrpc(_req("notifications/initialized", req_id=None))) is None
    assert _run(handle_jsonrpc(_req("ping", req_id=None))) is None


def test_batch_mixed():
    batch = [
        _req("ping", req_id=1),
        _req("notifications/initialized", req_id=None),
        _req("no_such_method", req_id=2),
    ]
    replies = _run(handle_jsonrpc(batch))
    assert len(replies) == 2, "通知不得产生应答条目"
    assert replies[0]["result"] == {}
    assert replies[1]["error"]["code"] == -32601


# ── 4. 治理语义不放松 ─────────────────────────────────────────

def test_low_risk_tool_call_succeeds_for_operator():
    resp = _run(handle_jsonrpc(
        _req("tools/call", {"name": "alert_only", "arguments": {"message": "mcp 协议自检"}}),
        user_role="operator",
    ))
    result = resp["result"]
    assert result["isError"] is False
    assert result["content"][0]["type"] == "text"
    guard = result["structuredContent"]
    assert guard["decision"] == "allow"


def test_rbac_deny_is_tool_level_error_not_protocol_error():
    # security_operator 角色无 alert_only 权限(perm: admin/security_operator/analyst)
    # —— 治理拒绝必须是 isError 工具结果, 不能伪装成协议错误
    resp = _run(handle_jsonrpc(
        _req("tools/call", {"name": "alert_only", "arguments": {"message": "x"}}),
        user_role="viewer",
    ))
    result = resp["result"]
    assert result["isError"] is True
    guard = result["structuredContent"]
    assert guard["decision"] in ("deny", "require_confirmation")
    assert guard["checks"], "检查明细必须透出, 拒绝不许黑箱"


def test_hallucinated_tool_is_denied():
    resp = _run(handle_jsonrpc(
        _req("tools/call", {"name": "rm -rf /", "arguments": {}}),
        user_role="admin",
    ))
    guard = resp["result"]["structuredContent"]
    assert resp["result"]["isError"] is True
    assert guard["decision"] == "deny"
    assert any("幻觉" in c.get("message", "") for c in guard["checks"])


def test_client_cannot_self_declare_role():
    # params 里塞 role 字段不生效 —— 角色只来自传输层认证
    resp = _run(handle_jsonrpc(
        _req("tools/call", {
            "name": "alert_only",
            "arguments": {"message": "x"},
            "user_role": "admin",  # 伪报
        }),
        user_role="viewer",
    ))
    assert resp["result"]["isError"] is True, "伪报角色不得提权"
