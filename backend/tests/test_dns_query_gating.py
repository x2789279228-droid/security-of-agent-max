# -*- coding: utf-8 -*-
"""W1-6: 泛化 "query" 别名的 DNS 语境门禁 (复审 P2 — 跨源误报发生器)。

修复前: _normalize_fields 把任何日志源的 `query` 字段归一为 dns_query,
SQL 审计/HTTP 参数日志的 query 会被 Sigma DNS 规则命中, 误报带 ATT&CK 标签。
"""
from __future__ import annotations

import os
import sys

os.environ.setdefault("SHARED_MEMORY_SKIP_DOTENV", "1")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _normalize(log: dict) -> dict:
    from log_ingestion import LogIngestor
    return LogIngestor()._normalize_fields(log)


def test_sql_audit_query_not_dns():
    out = _normalize({
        "event": "SQL_AUDIT",
        "query": "SELECT * FROM users WHERE 1=1",
        "src_ip": "10.0.0.5",
    })
    assert not out.get("dns_query"), "SQL 审计日志的 query 不得归一为 dns_query"


def test_http_param_query_not_dns():
    out = _normalize({
        "event": "WEB_ACCESS",
        "url": "/search?q=x",
        "query": "page=2&sort=desc",
    })
    assert not out.get("dns_query"), "HTTP 参数 query 不得归一为 dns_query"


def test_dns_event_query_still_normalized():
    out = _normalize({
        "event": "DNS_QUERY",
        "query": "xk7fh2.evil-example.net",
    })
    assert out.get("dns_query") == "xk7fh2.evil-example.net"


def test_domain_shaped_query_normalized():
    out = _normalize({"event": "NET", "query": "cdn-metrics-sync.net"})
    assert out.get("dns_query") == "cdn-metrics-sync.net"


def test_explicit_dns_keys_unchanged():
    """DNS 专属键(rrname/queryName)不受门禁影响 — 原路径照旧。"""
    out = _normalize({"event": "NET", "rrname": "a.evil.com"})
    assert out.get("dns_query") == "a.evil.com"
    out2 = _normalize({"event": "NET", "queryName": "b.evil.com"})
    assert out2.get("dns_query") == "b.evil.com"
