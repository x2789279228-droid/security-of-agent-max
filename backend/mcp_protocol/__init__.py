"""MCP 协议端点 — Model Context Protocol (JSON-RPC 2.0) 真协议接入层。

2026-11-09 AI 深度增强(阶段4A): 此前平台的 "MCP Guard" 是自研治理网关,
以 REST POST /api/audit/guard/call 暴露, 不含 MCP 协议本体。本模块在
治理网关之上补齐标准 MCP 协议面:

    initialize / notifications/initialized / ping / tools/list / tools/call

tools/call 的每一次调用仍走 McpGuardServer 四层检查链
(防幻觉注册表 → RBAC → Pydantic 参数校验 → 规则引擎 → 行为签名/审批),
协议层只做翻译, 不放松任何治理语义:
  - 协议错误(未知方法/坏参数) → JSON-RPC error(-32601/-32602)
  - 治理拒绝(权限/策略/审批挂起) → MCP 工具级结果 isError=true,
    决策与检查明细放入 structuredContent.guard, 客户端可见全部理由
"""
from .server import PROTOCOL_VERSION, SERVER_INFO, handle_jsonrpc, router

__all__ = ["PROTOCOL_VERSION", "SERVER_INFO", "handle_jsonrpc", "router"]
