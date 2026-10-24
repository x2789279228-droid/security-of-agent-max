"""LDAP/AD account disable. Live requires ldap_url; mock/dry_run does not bind."""
from __future__ import annotations

import asyncio
import logging

from config import settings

from .types import BACKEND_LDAP, STATUS_UNCONFIGURED

logger = logging.getLogger(__name__)

PROTECTED_SAM = frozenset({"krbtgt", "administrator"})
PROTECTED_DN_NEEDLES = (
    "CN=DOMAIN ADMINS",
    "CN=ENTERPRISE ADMINS",
    "CN=SCHEMA ADMINS",
    "DOMAIN ADMINS",
    "ENTERPRISE ADMINS",
    "SCHEMA ADMINS",
)
ACCOUNTDISABLE = 2


def _mode() -> str:
    # 失败关闭：空/缺失配置按 dry_run，不得回落到 live。
    try:
        from response_engine.preview import preview_mode
        if preview_mode.get():
            return "dry_run"
    except Exception:
        pass
    return (getattr(settings, "execution_mode", "dry_run") or "dry_run").lower()


def ldap_configured() -> bool:
    return bool(getattr(settings, "ldap_url", "") or "")


#: RFC 4515 —— LDAP 过滤器**值**里必须转义的 6 个字符。
#:
#: 与 `ldap3.utils.conv.escape_filter_chars` 同一套规则；
#: 这里自带一份，是为了让**不装 ldap3** 的环境也能测（活路径本来就
#: 需要 ldap3），而且行为只有一条、不会随依赖版本漂移。
_LDAP_FILTER_ESCAPE = {
    "\\": "\\5c",
    "*": "\\2a",
    "(": "\\28",
    ")": "\\29",
    "\x00": "\\00",
    "/": "\\2f",
}


def escape_ldap_filter(value: str) -> str:
    """RFC 4515 的过滤器**值**转义。

    修复前 `acct` **原样**拼进过滤器（见下面 filt 那行的原写法），
    → `acct = "x)(objectClass=*"` 会把过滤器的**结构**改写
      （子句数从 2 变成 4，其中一个是 `objectClass=*` → 匹配所有对象），
      平台于是禁用了**另一个**账户 —— 而审批单上写的是攻击者给的那个。
    """
    out = []
    for ch in str(value or ""):
        out.append(_LDAP_FILTER_ESCAPE.get(ch, ch))
    return "".join(out)


def build_ldap_filter(acct: str) -> str:
    """构造账户查找过滤器（**值已按 RFC 4515 转义**）。

    抽成函数是为了让「过滤器的**结构**不受输入影响」这条性质
    **可测**：守卫直接比对结构，而不是比对某个具体字符串。
    """
    esc = escape_ldap_filter(acct)
    return f"(|(sAMAccountName={esc})(userPrincipalName={esc}))"


def is_protected_account(account: str, dn: str = "", rid: int = 0) -> bool:
    if int(rid or 0) == 500:
        return True
    sam = str(account or "").split("@")[0].strip().lower()
    if sam in PROTECTED_SAM:
        return True
    hay = str(dn or "").upper()
    return any(n in hay for n in PROTECTED_DN_NEEDLES)


def _unconfigured(action: str, **extra) -> dict:
    return {"action": action, "success": False, "mode": STATUS_UNCONFIGURED,
            "error": "ldap unconfigured", "backend": BACKEND_LDAP, **extra}


def _sync_modify_uac(account: str, *, disable: bool, override_protected: bool = False) -> dict:
    """同步 LDAP UAC 位修改(在 to_thread 里跑 — ldap3 是同步网络 IO)。

    P1: 修复前 disable 的 bind/search/modify 直接跑在事件循环上, AD 慢一点
    整个后端 API/告警链路一起停摆。enable 此前恒返回失败却标 reversible=True
    (审批人以为可恢复) — 现实现真实启用路径, 两条车道对称。
    """
    import ldap3

    action = "disable_account" if disable else "enable_account"
    url = settings.ldap_url
    bind_dn = settings.ldap_bind_dn
    password = settings.ldap_bind_password
    base = settings.ldap_base_dn
    server = ldap3.Server(url, get_info=ldap3.NONE, connect_timeout=10)
    conn = ldap3.Connection(server, user=bind_dn, password=password,
                            auto_bind=True, receive_timeout=15)
    try:
        filt = build_ldap_filter(account)
        conn.search(base, filt,
                    attributes=["distinguishedName", "userAccountControl", "objectSid"])
        if not conn.entries:
            return {"action": action, "success": False, "mode": "live",
                    "error": "account not found", "account": account}
        entry = conn.entries[0]
        found_dn = str(entry.distinguishedName)
        if disable and is_protected_account(account, dn=found_dn) and not override_protected:
            return {"action": action, "success": False, "mode": "denied",
                    "error": "protected account", "account": account, "dn": found_dn}
        uac = int(entry.userAccountControl.value)
        new_uac = (uac | ACCOUNTDISABLE) if disable else (uac & ~ACCOUNTDISABLE)
        ok = conn.modify(found_dn, {"userAccountControl": [(ldap3.MODIFY_REPLACE, [new_uac])]})
        return {
            "action": action, "success": bool(ok), "mode": "live",
            "account": account, "dn": found_dn, "backend": BACKEND_LDAP,
        }
    finally:
        try:
            conn.unbind()
        except Exception:
            pass


async def disable_account(
    account: str = "",
    domain: str = "",
    dn: str = "",
    rid: int = 0,
    override_protected: bool = False,
    reason: str = "",
    **kwargs,
) -> dict:
    acct = str(account or "").strip()
    if not acct:
        return {"action": "disable_account", "success": False, "mode": "invalid",
                "error": "account required"}
    if is_protected_account(acct, dn=dn, rid=rid) and not override_protected:
        return {"action": "disable_account", "success": False, "mode": "denied",
                "error": "protected account", "account": acct}
    if _mode() != "live":
        return {
            "action": "disable_account", "success": True, "mode": _mode(),
            "account": acct, "domain": domain, "backend": BACKEND_LDAP,
            "uac_bit": ACCOUNTDISABLE, "would_execute": _mode() == "dry_run",
        }
    if not ldap_configured():
        return _unconfigured("disable_account", account=acct, domain=domain)
    try:
        import ldap3  # noqa: F401 — 仅探测可用性
    except ImportError:
        return {**_unconfigured("disable_account", account=acct),
                "error": "ldap3 not installed"}
    try:
        result = await asyncio.to_thread(
            _sync_modify_uac, acct, disable=True, override_protected=override_protected,
        )
        return result
    except Exception as e:
        logger.warning("disable_account ldap failed: %s", e)
        return {"action": "disable_account", "success": False, "mode": "error",
                "error": str(e), "account": acct}


async def enable_account(account: str = "", dn: str = "", **kwargs) -> dict:
    acct = str(account or "").strip()
    if _mode() != "live":
        return {"action": "enable_account", "success": True, "mode": _mode(),
                "account": acct, "backend": BACKEND_LDAP}
    if not ldap_configured():
        return _unconfigured("enable_account", account=acct)
    try:
        import ldap3  # noqa: F401 — 仅探测可用性
    except ImportError:
        return {**_unconfigured("enable_account", account=acct),
                "error": "ldap3 not installed"}
    try:
        return await asyncio.to_thread(_sync_modify_uac, acct, disable=False)
    except Exception as e:
        logger.warning("enable_account ldap failed: %s", e)
        return {"action": "enable_account", "success": False, "mode": "error",
                "error": str(e), "account": acct}


def register(registry) -> None:
    if registry.get_action("disable_account"):
        return
    registry.register(
        "disable_account", disable_account,
        description="通过 LDAP/AD 立即禁用失陷账户",
        severity="critical",
        category="identity",
        reversible=True,
        rollback_fn=enable_account,
        params_schema={
            "account": "str (required) sAMAccountName 或 UPN",
            "domain": "str 可选",
            "override_protected": "bool 仅审批工单可显式带 true",
            "reason": "str",
        },
    )
