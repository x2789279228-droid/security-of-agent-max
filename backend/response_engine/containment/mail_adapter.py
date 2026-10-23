"""Phishing mail recall via Microsoft Graph. Unconfigured live → fail, never fake SMTP."""
from __future__ import annotations

import logging
import re
from urllib.parse import quote

from config import settings

from .types import BACKEND_GRAPH, STATUS_UNCONFIGURED

logger = logging.getLogger(__name__)


#: Graph **路径段**里绝不允许出现的字符：路径分隔符、`..`、控制字符。
#:
#: 为什么 `quote()` 不够：它的默认 `safe='/'` **不转义 `/`**，
#: 于是 `mailbox="../../users/victim@corp.com"` 原样进入 URL 路径，
#: 服务端规范化后落到**另一个用户**的邮箱 —— 而且请求带着
#: **应用自己的 Graph token**（client_credentials + `.default` 作用域）。
_PATH_FORBIDDEN_RE = re.compile(r"[\x00-\x1f\x7f/\\]|\.\.")

#: 控制字符（任何标识符里都不合法）。
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


def _odata_escape(value: str) -> str:
    """OData 字符串字面量转义：单引号**翻倍**（OData v4 ABNF）。

    为什么 `quote()` 不能替代它：URL 编码只保护 **URL 语法**；
    Graph 收到 URL 后会**先解码**再交给 OData 解析器 ——
    于是值里的 `'` 仍然会闭合字面量、改写表达式。

    实测（修复前，2026-10-20）：
        mid = "msg-1' or contains(subject,'x') or 'a'='a"
        → Graph 看到的 $filter =
          internetMessageId eq 'msg-1' or contains(subject,'x') or 'a'='a'
        → 过滤器不再只匹配那一封邮件 → `items[0]` 可能是**别人的邮件**
          → 平台把它 move 到 recoverableitemsdeletions（**删掉别人的邮件**）。
    """
    return str(value or "").replace("'", "''")


def _odata_filter(mid: str) -> str:
    """构造 `internetMessageId eq '...'`（**已做 OData 转义**）。

    返回的是**未做 URL 编码**的 OData 表达式；调用方负责 URL 编码。
    """
    return f"internetMessageId eq '{_odata_escape(mid)}'"


def _graph_path_segment(value: str, what: str) -> str:
    """校验并编码一个**用户提供**的、要放进 Graph 路径的片段（mailbox）。

    合法 UPN（`user@domain.com`）与 `me` 都不含被禁字符 → 零误拒。
    """
    raw = str(value or "").strip()
    if not raw:
        return ""
    if _PATH_FORBIDDEN_RE.search(raw):
        raise ValueError(
            f"{what} 含非法字符（路径分隔符 / .. / 控制字符）")
    return quote(raw, safe="")


def _graph_opaque_id(value: str, what: str) -> str:
    """Graph **自己返回**的 id（message id）：只校验，**不改写**。

    它的字符集由 Graph 决定（base64，可含 `/` `+` `=`），
    重新编码反而可能把请求打到错误的路径上 → 只拒绝明显的路径控制。
    """
    raw = str(value or "")
    if not raw:
        raise ValueError(f"{what} 为空")
    if _CONTROL_RE.search(raw) or ".." in raw:
        raise ValueError(f"{what} 含非法字符（.. / 控制字符）")
    return raw


def _mode() -> str:
    return (getattr(settings, "execution_mode", "live") or "live").lower()


def graph_configured() -> bool:
    return bool(
        getattr(settings, "graph_tenant", "")
        and getattr(settings, "graph_client_id", "")
        and getattr(settings, "graph_client_secret", "")
    )


async def recall_email(
    internet_message_id: str = "",
    message_id: str = "",
    mailbox: str = "",
    reason: str = "",
    **kwargs,
) -> dict:
    mid = str(internet_message_id or message_id or "").strip()
    if not mid:
        return {"action": "recall_email", "success": False, "mode": "invalid",
                "error": "internet_message_id required"}
    if _mode() != "live":
        return {
            "action": "recall_email", "success": True, "mode": _mode(),
            "internet_message_id": mid, "mailbox": mailbox,
            "backend": BACKEND_GRAPH, "would_execute": _mode() == "dry_run",
            "message": "simulated graph move to recoverableitemsdeletions",
        }
    if not graph_configured():
        return {
            "action": "recall_email", "success": False, "mode": STATUS_UNCONFIGURED,
            "error": "graph unconfigured", "internet_message_id": mid,
            "backend": BACKEND_GRAPH,
        }
    try:
        import httpx
        token = await _graph_token()
        user = mailbox or "me"
        try:
            user_seg = _graph_path_segment(user, "mailbox")
            filt = quote(_odata_filter(mid), safe="")
        except ValueError as e:
            # 标识符不合法 → **不发请求**（把恶意标识符挡在 Graph 之前）
            return {"action": "recall_email", "success": False,
                    "mode": "invalid", "error": str(e),
                    "internet_message_id": mid, "mailbox": mailbox}
        headers = {"Authorization": f"Bearer {token}"}
        async with httpx.AsyncClient(timeout=20) as client:
            search = await client.get(
                f"https://graph.microsoft.com/v1.0/users/{user_seg}/messages?$filter={filt}",
                headers=headers,
            )
            search.raise_for_status()
            items = (search.json() or {}).get("value") or []
            if not items:
                return {"action": "recall_email", "success": False, "mode": "live",
                        "error": "message not found", "internet_message_id": mid}
            gid = items[0].get("id")
            try:
                gid_seg = _graph_opaque_id(gid, "message id")
            except ValueError as e:
                return {"action": "recall_email", "success": False,
                        "mode": "invalid", "error": str(e),
                        "internet_message_id": mid}
            moved = await client.post(
                f"https://graph.microsoft.com/v1.0/users/{user_seg}/messages/{gid_seg}/move",
                headers=headers,
                json={"destinationId": "recoverableitemsdeletions"},
            )
            moved.raise_for_status()
        return {
            "action": "recall_email", "success": True, "mode": "live",
            "internet_message_id": mid, "backend": BACKEND_GRAPH,
        }
    except Exception as e:
        logger.warning("recall_email failed: %s", e)
        return {"action": "recall_email", "success": False, "mode": "error",
                "error": str(e), "internet_message_id": mid}


async def _graph_token() -> str:
    import httpx
    tenant = settings.graph_tenant
    data = {
        "client_id": settings.graph_client_id,
        "client_secret": settings.graph_client_secret,
        "grant_type": "client_credentials",
        "scope": "https://graph.microsoft.com/.default",
    }
    async with httpx.AsyncClient(timeout=20) as client:
        resp = await client.post(
            f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
            data=data,
        )
        resp.raise_for_status()
        return resp.json()["access_token"]


def register(registry) -> None:
    if registry.get_action("recall_email"):
        return
    registry.register(
        "recall_email", recall_email,
        description="已投递钓鱼邮件撤回（Microsoft Graph move）",
        severity="high",
        category="mail",
        reversible=False,
        params_schema={
            "internet_message_id": "str (required)",
            "message_id": "str 别名",
            "mailbox": "str 可选 UPN",
            "reason": "str",
        },
    )
