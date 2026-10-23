# -*- coding: utf-8 -*-
"""外部可控标识符进入**查询表达式 / URL 路径**的注入面（整改报告 §9.62）。

## 背景

按 §9.61 的方法论做「同一能力是否接在所有面上」的普查，结果很干净：

| 适配器 | 面 | 防护 |
|---|---|---|
| `host_adapter.py` | PowerShell 命令 / 文件路径 | ✅ **有**（`reject_path` 拒 `..` 与系统目录 + 引号剥离） |
| `mail_adapter.py` | Microsoft Graph（OData 过滤器 + URL 路径） | ❌ **无** |
| `directory_adapter.py` | LDAP/AD 过滤器 | ❌ **无** |

**决定性实测（修复前）**：

* `internet_message_id = "msg-1' or contains(subject,'x') or 'a'='a"`
  → Graph 看到的 `$filter` = `internetMessageId eq 'msg-1' or contains(subject,'x') or 'a'='a'`
  → 过滤器**不再只匹配那一封邮件** → `items[0]` 可能是**别人的邮件**
  → 平台把它 move 到 `recoverableitemsdeletions`（**删掉别人的邮件**）。
* `mailbox = "../../users/victim@corp.com"`
  → URL 路径 `/v1.0/users/../../users/victim%40corp.com/messages`
  → 服务端规范化后 → `/users/victim%40corp.com/messages`
  → **落到另一个用户的邮箱**，而且请求带着**应用自己的 Graph token**
  （client_credentials + `.default` 作用域）。
* `account = "x)(objectClass=*"` → LDAP 过滤器
  `(|(sAMAccountName=x)(objectClass=*)(userPrincipalName=x)(objectClass=*))`
  → 子句从 2 个变成 4 个，其中 `objectClass=*` 匹配**所有**对象
  → 平台禁用了**另一个**账户 —— 而审批单上写的是攻击者给的那个。

## 本守卫盯什么

1. **结构不变式**（决定性）：无论输入是什么，
   OData 表达式与 LDAP 过滤器的**结构**都不变；
2. **端到端**：恶意 mailbox **根本不会**产生 Graph 消息请求；
3. **反向**（防过度收紧）：合法 UPN / 消息 id / 账户名**原样通过**；
4. **否定结论**：`host_adapter` 的路径防护**确实在**（钉住它，
   免得将来把「不必修」的地方当缺陷乱改）。
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND))

from response_engine.containment.directory_adapter import (   # noqa: E402
    build_ldap_filter, escape_ldap_filter,
)
from response_engine.containment.mail_adapter import (        # noqa: E402
    _graph_path_segment, _odata_filter,
)

#: 恶意 / 边界输入（覆盖三种注入形态：闭合字面量、结构改写、路径穿越）
MALICIOUS = [
    "msg-1' or contains(subject,'x') or 'a'='a",
    "' or ''='",
    "x' or '1'='1",
    "a)(objectClass=*",
    "x)(|(uid=*",
    "*",
    "../../users/victim@corp.com",
    "..\\..\\users\\victim",
    "a/b",
    "x\x00y",
]

#: RFC 4515 的十六进制转义序列
_LDAP_ESC_RE = re.compile(r"\\[0-9a-fA-F]{2}")


def _strip_ldap_escapes(text: str) -> str:
    return _LDAP_ESC_RE.sub("", text)


def _unbalanced_quote(inner: str) -> bool:
    """OData 字面量里若还有**没配对**的单引号 → 说明有值逃出了字面量。"""
    return "'" in inner.replace("''", "")


def _ldap_clause_count(filt: str) -> int:
    """过滤器最外层 `(|...)` 里的**子句数**（按括号深度计）。

    注意：**不能**先把转义序列剥掉再数括号 —— 剥掉后值里的 `(` 又回来了，
    数出来的就不是结构了。转义后的值里没有裸括号，所以**直接数原串**。
    """
    depth = 0
    clauses = 0
    for ch in filt:
        if ch == "(":
            depth += 1
            if depth == 2:
                clauses += 1
        elif ch == ")":
            depth -= 1
    return clauses


class TestTheGraphODataFilter:
    def test_the_filter_always_has_exactly_one_literal(self):
        """**决定性**：无论 mid 是什么，过滤器**结构**不变。

        结构 = `internetMessageId eq '<一个字面量>'`，
        且字面量内部不允许出现没配对的单引号（OData 的转义是**翻倍**）。
        """
        for mid in MALICIOUS:
            filt = _odata_filter(mid)
            assert filt.startswith("internetMessageId eq '"), filt
            assert filt.endswith("'"), filt
            inner = filt[len("internetMessageId eq '"):-1]
            assert not _unbalanced_quote(inner), (
                f"mid={mid!r} 让值逃出了 OData 字面量：{filt}")

    def test_a_legit_message_id_passes_through_unchanged(self):
        """**反向**（防过度收紧）：合法 Graph id 原样通过。"""
        assert _odata_filter("AAMkAGI2AAA=") == "internetMessageId eq 'AAMkAGI2AAA='"

    def test_the_odata_injection_never_reaches_graph(self, monkeypatch):
        """**端到端**：恶意 mid 发出的 `$filter` 仍然只有一个字面量。"""
        import asyncio

        import httpx
        from config import settings
        from response_engine.containment.mail_adapter import recall_email

        seen: list = []

        class _Resp:
            status_code = 200

            def __init__(self, payload=None):
                self._payload = payload if payload is not None else {"value": [{"id": "GRAPH-ID-1"}]}

            def raise_for_status(self):
                pass

            def json(self):
                return self._payload

        async def _fake_get(self, url, **kw):
            seen.append(str(url))
            return _Resp()

        async def _fake_post(self, url, **kw):
            seen.append(str(url))
            # 取 token 的那个 POST 要返回 access_token，其余返回空体
            if "oauth2" in str(url):
                return _Resp({"access_token": "TOKEN"})
            return _Resp({})

        monkeypatch.setattr(httpx.AsyncClient, "get", _fake_get, raising=True)
        monkeypatch.setattr(httpx.AsyncClient, "post", _fake_post, raising=True)
        old = (settings.execution_mode, settings.graph_tenant,
               settings.graph_client_id, settings.graph_client_secret)
        settings.execution_mode = "live"
        settings.graph_tenant = "t"
        settings.graph_client_id = "c"
        settings.graph_client_secret = "s"
        try:
            asyncio.run(recall_email(
                internet_message_id="msg-1' or contains(subject,'x') or 'a'='a"))
        finally:
            (settings.execution_mode, settings.graph_tenant,
             settings.graph_client_id, settings.graph_client_secret) = old
        filters = [u for u in seen if "$filter=" in u]
        assert filters, f"没有发出带过滤器的请求：{seen}"
        raw = filters[0].split("$filter=", 1)[1]
        from urllib.parse import unquote
        decoded = unquote(raw)
        inner = decoded[len("internetMessageId eq '"):-1]
        assert not _unbalanced_quote(inner), (
            f"Graph 看到的 $filter 里值逃出了字面量：{decoded}")


class TestTheGraphPath:
    @pytest.mark.parametrize("mailbox", [
        "../../users/victim@corp.com",
        "..\\..\\users\\victim",
        "a/b",
        "a\\b",
        "..",
        "x\x00y",
    ])
    def test_the_traversal_mailbox_is_rejected(self, mailbox):
        with pytest.raises(ValueError):
            _graph_path_segment(mailbox, "mailbox")

    def test_a_legit_upn_is_accepted(self):
        """**反向**（防过度收紧）：合法 UPN 与 `me` 原样通过。"""
        assert _graph_path_segment("user@corp.com", "mailbox") == "user%40corp.com"
        assert _graph_path_segment("me", "mailbox") == "me"

    def test_the_recall_never_reaches_graph_for_a_malicious_mailbox(self, monkeypatch):
        """**端到端**：恶意 mailbox **根本不会**产生 Graph 消息请求。"""
        import asyncio

        import httpx
        from config import settings
        from response_engine.containment.mail_adapter import recall_email

        seen: list = []

        class _Resp:
            status_code = 200

            def __init__(self, payload=None):
                self._payload = payload if payload is not None else {"value": [{"id": "GRAPH-ID-1"}]}

            def raise_for_status(self):
                pass

            def json(self):
                return self._payload

        async def _fake_get(self, url, **kw):
            seen.append(str(url))
            return _Resp()

        async def _fake_post(self, url, **kw):
            seen.append(str(url))
            if "oauth2" in str(url):
                return _Resp({"access_token": "TOKEN"})
            return _Resp({})

        monkeypatch.setattr(httpx.AsyncClient, "get", _fake_get, raising=True)
        monkeypatch.setattr(httpx.AsyncClient, "post", _fake_post, raising=True)
        old = (settings.execution_mode, settings.graph_tenant,
               settings.graph_client_id, settings.graph_client_secret)
        settings.execution_mode = "live"
        settings.graph_tenant = "t"
        settings.graph_client_id = "c"
        settings.graph_client_secret = "s"
        try:
            res = asyncio.run(recall_email(
                internet_message_id="msg-1",
                mailbox="../../users/victim@corp.com"))
        finally:
            (settings.execution_mode, settings.graph_tenant,
             settings.graph_client_id, settings.graph_client_secret) = old
        assert res.get("success") is False, res
        assert res.get("mode") == "invalid", res
        assert not [u for u in seen if "graph.microsoft.com" in u], (
            f"仍然向 Graph 发了消息请求：{seen}")


class TestTheLdapFilter:
    def test_the_filter_structure_is_invariant(self):
        """**决定性**：无论 account 是什么，过滤器的**结构**都不变。

        结构 = 最外层 `(|...)` 里的**子句数**恒为 2。

        ⚠ 判据曾经写错过一版：曾要求「剥掉转义后剩下的值必须是空的」——
        那等于要求「值里不能有任何字符」，而 RFC 4515 里 `'` **本就没有**
        特殊含义（过滤器语言的结构字符是 `( ) | & ! = < > ~ :` 与
        `* \\ ( ) NUL /`）→ 那个判据既过严又不贴切。子句数才是结构。
        """
        for acct in MALICIOUS:
            filt = build_ldap_filter(acct)
            assert _ldap_clause_count(filt) == 2, (
                f"account={acct!r} 改写了过滤器结构（子句数="
                f"{_ldap_clause_count(filt)}）：{filt}")

    def test_a_legit_account_is_unchanged(self):
        """**反向**（防过度收紧）：合法账户名原样通过。"""
        assert build_ldap_filter("alice") == (
            "(|(sAMAccountName=alice)(userPrincipalName=alice))")

    def test_the_escaping_follows_rfc4515(self):
        """转义规则 = RFC 4515 的 6 个字符（\\XX 形式）。"""
        assert escape_ldap_filter("a(b)c*d\\e/f\x00") == (
            "a\\28b\\29c\\2ad\\5ce\\2ff\\00")

    def test_the_escaped_value_has_no_structure_characters(self):
        """转义后的值里不得再有**裸**的结构字符（括号 / 星号 / NUL）。"""
        for acct in MALICIOUS:
            esc = escape_ldap_filter(acct)
            assert "(" not in esc, esc
            assert ")" not in esc, esc
            assert "*" not in esc, esc
            assert "\x00" not in esc, esc


class TestTheNegativeConclusion:
    def test_the_host_adapter_path_guard_is_really_there(self):
        """**否定结论**：主机适配器的路径防护**确实在**。

        钉住它，免得将来把「不必修」的地方当缺陷乱改 ——
        也提醒：Graph/LDAP 侧**缺**的正是这一类防护。
        """
        from response_engine.containment.host_adapter import reject_path
        assert reject_path("../../etc/passwd") == "path traversal"
        assert reject_path("C:\\Windows\\System32\\drivers\\etc\\hosts") == (
            "system directory")
        assert reject_path("") == "empty path"
        assert reject_path("/opt/app/bin/service") == ""
