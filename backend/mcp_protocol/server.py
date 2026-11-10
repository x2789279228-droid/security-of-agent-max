"""MCP JSON-RPC 2.0 协议服务 — 翻译层, 治理语义全部委托 mcp_guard。

设计要点:
  - handle_jsonrpc(): async 分发入口, 不依赖 FastAPI —— 测试可直接
    asyncio.run 驱动(仓库既有测试的惯用模式);
  - tools/call 的 McpGuardServer.call_tool 是同步方法(内部含阻塞 IO),
    一律经 asyncio.to_thread 调用, 不阻塞事件循环;
  - router: FastAPI APIRouter, POST /mcp, 认证与 /guard/call 同口径
    (RequireRole admin/operator), 批量请求(list body)按规范逐条应答;
  - 通知(无 id 的消息)按 JSON-RPC 规范不产生响应条目;
  - mcp_guard 单例初始化失败时返回 -32603 并说明原因(fail-visible)。
"""
import asyncio
import logging
from typing import Any, Optional

from fastapi import APIRouter, Body, Depends

from auth import UserInfo, RequireRole

logger = logging.getLogger(__name__)

# MCP 协议基线版本(2024-11-05 spec); initialize 时若客户端携带更高版本
# 则原样回显以保持兼容, 能力面不变。
PROTOCOL_VERSION = "2024-11-05"
SERVER_INFO = {"name": "watchtower-soc-mcp", "version": "1.0.0"}

# JSON-RPC 2.0 标准错误码
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603


def _result(req_id: Any, result: dict) -> dict:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _error(req_id: Any, code: int, message: str, data: Any = None) -> dict:
    err: dict = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return {"jsonrpc": "2.0", "id": req_id, "error": err}


def _guard() -> Any:
    """取 mcp_guard 单例; 初始化失败时它会是 None(见 routers/audit.py 同款判空)。"""
    from mcp_guard import mcp_guard
    return mcp_guard


# HTTP JWT 角色 → guard RBAC 角色(两套词表对齐: permission_manager.py)
# guard 侧: admin / security_operator / analyst / viewer
_ROLE_MAP = {
    "admin": "admin",
    "operator": "security_operator",
    "security_operator": "security_operator",
    "analyst": "analyst",
    "viewer": "viewer",
}


def _map_role(user_role: str) -> str:
    return _ROLE_MAP.get(str(user_role or "viewer"), "viewer")


# ── 协议方法实现 ──────────────────────────────────────────────

def _mcp_initialize(params: dict) -> dict:
    client_version = str(params.get("protocolVersion") or "")
    return {
        "protocolVersion": client_version or PROTOCOL_VERSION,
        "capabilities": {
            "tools": {"listChanged": False},
        },
        "serverInfo": dict(SERVER_INFO),
        # 自报治理能力: 客户端可感知该端点背后的治理层
        "instructions": (
            "本端点的 tools/call 全部经过 MCP Guard 治理链"
            "(注册表防幻觉/RBAC/参数校验/规则引擎/审批队列),"
            "拒绝与挂起会以 isError 结果返回, structuredContent.guard 携带决策明细。"
        ),
    }


def _mcp_tools_list() -> dict:
    guard = _guard()
    if guard is None:
        raise RuntimeError("mcp_guard 单例不可用")
    tools = []
    for t in guard.list_tools():
        tools.append({
            "name": t.get("name", ""),
            "description": t.get("description", ""),
            "inputSchema": t.get("parameters") or {"type": "object", "properties": {}},
            # MCP annotations(自定义扩展): 治理元数据透出给客户端
            "annotations": {
                "riskLevel": t.get("risk_level", ""),
                "requiredPermission": t.get("required_permission", []),
                "title": t.get("name", ""),
            },
        })
    return {"tools": tools}


async def _mcp_tools_call(params: dict, user_role: str) -> dict:
    from mcp_guard.guard_server import ToolCallRequest

    guard = _guard()
    if guard is None:
        raise RuntimeError("mcp_guard 单例不可用")

    name = params.get("name")
    if not isinstance(name, str) or not name:
        raise ValueError("tools/call 缺少 name 参数")
    arguments = params.get("arguments")
    if arguments is None:
        arguments = {}
    if not isinstance(arguments, dict):
        raise ValueError("tools/call 的 arguments 必须是对象")

    request = ToolCallRequest(
        tool_name=name,
        arguments=arguments,
        user_role=_map_role(user_role),
        reason=str(params.get("reason") or "mcp tools/call"),
        caller=str(params.get("caller") or "mcp-client"),
        source="mcp_protocol",
    )
    # call_tool 为同步方法(可能含阻塞 IO) —— 按其 docstring 要求经 to_thread 调用
    call_result = await asyncio.wait_for(
        asyncio.to_thread(guard.call_tool, request), timeout=20
    )

    decision = call_result.get("decision", "")
    execution = call_result.get("execution") or {}
    is_error = decision != "allow"
    payload = execution.get("result") if isinstance(execution, dict) else None
    text = str(payload if payload is not None else call_result.get("reason", ""))

    return {
        "content": [{"type": "text", "text": text}],
        "isError": is_error,
        "structuredContent": {
            "decision": decision,
            "reason": call_result.get("reason", ""),
            "finalRisk": call_result.get("final_risk", ""),
            "checks": call_result.get("checks", []),
            "execution": execution,
        },
    }


# ── JSON-RPC 分发 ─────────────────────────────────────────────

async def _dispatch_one(msg: dict, user_role: str) -> Optional[dict]:
    """单条 JSON-RPC 消息 → 应答(通知返回 None)。"""
    if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0":
        return _error(None, INVALID_REQUEST, "jsonrpc 字段必须为 \"2.0\"")
    req_id = msg.get("id")  # 无 id = 通知
    method = msg.get("method")
    params = msg.get("params") or {}
    if not isinstance(method, str) or not method:
        return _error(req_id, INVALID_REQUEST, "缺少 method") if req_id is not None else None

    try:
        if method == "initialize":
            result = _mcp_initialize(params)
        elif method == "notifications/initialized":
            return None  # 通知: 规范要求不应答
        elif method == "ping":
            result = {}
        elif method == "tools/list":
            result = _mcp_tools_list()
        elif method == "tools/call":
            result = await _mcp_tools_call(params, user_role)
        else:
            if req_id is None:
                return None
            return _error(req_id, METHOD_NOT_FOUND, f"Method not found: {method}")
        return _result(req_id, result) if req_id is not None else None
    except ValueError as e:
        # 参数语义错误(缺 name / arguments 类型错)
        return _error(req_id, INVALID_PARAMS, str(e)) if req_id is not None else None
    except Exception as e:  # noqa: BLE001 — 协议层兜底, 必须以 JSON-RPC error 应答
        logger.warning("mcp dispatch %s failed: %s", method, e)
        return _error(req_id, INTERNAL_ERROR, f"internal error: {e}") \
            if req_id is not None else None


async def handle_jsonrpc(body: Any, user_role: str = "operator") -> Any:
    """JSON-RPC 入口: 单条 dict → 单条应答; list → 批量应答(可能为空 list)。

    供 FastAPI 端点与测试共同使用。user_role 由传输层(HTTP 认证)决定,
    协议层不信任客户端自报角色。
    """
    if isinstance(body, list):
        if not body:
            return _error(None, INVALID_REQUEST, "空批量请求")
        replies = []
        for m in body:
            r = await _dispatch_one(m, user_role)
            if r is not None:
                replies.append(r)
        return replies
    return await _dispatch_one(body, user_role)


# ── FastAPI 传输层 ────────────────────────────────────────────

router = APIRouter(prefix="/api/mcp", tags=["mcp-protocol"])


@router.post("")
async def mcp_endpoint(
    payload: "dict | list" = Body(...),
    user: UserInfo = Depends(RequireRole("admin", "operator")),
):
    """MCP JSON-RPC 2.0 端点(单条与批量)。

    认证与 /api/audit/guard/call 同口径(operator 及以上); 角色取自 JWT,
    客户端无法通过参数自报角色提权。
    注: 参数必须显式 Body —— 此前注解为裸 Any, FastAPI 将其解析为
    query 参数, HTTP 层 POST 一律 422(2026-11-10 开放体验测试首次
    走到 HTTP 层暴露; 此前 15 条协议测试全走函数直调未覆盖)。
    """
    return await handle_jsonrpc(payload, user_role=user.role)
