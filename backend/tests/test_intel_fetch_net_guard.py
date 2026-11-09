# -*- coding: utf-8 -*-
"""R14: 情报链路出网安全 (P1-2)。

锁定四件事:
  1) SSRF — csv_http/kev_json/TAXII/MISP 的目标 URL 禁 loopback/私网/云元数据;
  2) 本地文件读 — csv/stix_bundle 的 url 受 intel_local_feed_dir 白名单约束,
     /etc/passwd、../.env 一律拒绝;
  3) 重定向 — 逐跳复检(跳内网即拒), 跨 host 跳转剥离 Authorization;
  4) 限长 — 流式读取, 超 _MAX_FEED_BYTES 提前中止(不整包入内存)。
"""
from __future__ import annotations

import asyncio
import os
import sys

import pytest

os.environ.setdefault("SHARED_MEMORY_SKIP_DOTENV", "1")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from threat_intel.stix_taxii import taxii_client  # noqa: E402

SSRF_URLS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://10.0.0.1/feed.csv",
    "http://192.168.1.10/x",
    "http://127.0.0.1:8001/api",
    "http://[::1]/x",
    "file:///etc/passwd",
    "ftp://example.com/x",
]


@pytest.mark.parametrize("url", SSRF_URLS)
@pytest.mark.asyncio
async def test_csv_http_rejects_ssrf_targets(url, monkeypatch):
    async def _boom(*a, **k):  # pragma: no cover — 被调用即失败
        raise AssertionError("_fetch_text 不应被调用")

    monkeypatch.setattr(taxii_client, "_fetch_text", _boom)
    iocs = await taxii_client.poll_feed({"feed_type": "csv_http", "url": url, "name": "evil"})
    assert iocs == [], f"SSRF 目标 {url} 必须空手而归"


@pytest.mark.asyncio
async def test_taxii_misp_reject_ssrf(monkeypatch):
    from net_guard import UrlRejected
    calls = []

    class _Boom:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            raise AssertionError("session 不应创建")

        async def __aexit__(self, *a):
            return False

    monkeypatch.setattr("aiohttp.ClientSession", _Boom)
    assert await taxii_client.poll_feed({
        "feed_type": "taxii", "url": "http://169.254.169.254/taxii", "collection": "c",
    }) == []
    assert await taxii_client.poll_feed({
        "feed_type": "misp", "url": "http://10.9.9.9", "api_key": "k",
    }) == []


@pytest.mark.asyncio
async def test_local_csv_path_allowlist(tmp_path, monkeypatch):
    from config import settings

    # 白名单目录外的绝对路径(经典 /etc/passwd 形态) → 拒绝
    monkeypatch.setattr(settings, "intel_local_feed_dir", str(tmp_path))
    assert await taxii_client.poll_feed({
        "feed_type": "csv", "url": "/etc/passwd", "name": "evil",
    }) == []
    assert await taxii_client.poll_feed({
        "feed_type": "csv", "url": str(tmp_path.parent / "outside.csv"), "name": "evil",
    }) == []
    # 穿越(即便中间路径解析后仍在目录外) → 拒绝
    assert await taxii_client.poll_feed({
        "feed_type": "csv", "url": str(tmp_path / ".." / "escape.csv"), "name": "evil",
    }) == []
    # 白名单目录内的文件 → 正常解析
    f = tmp_path / "ok.csv"
    f.write_text("type,value\nip,203.0.113.9\n", encoding="utf-8")
    iocs = await taxii_client.poll_feed({"feed_type": "csv", "url": str(f), "name": "local"})
    assert {(i["ioc_type"], i["ioc_value"]) for i in iocs} == {("ip", "203.0.113.9")}


@pytest.mark.asyncio
async def test_local_csv_disabled_by_default(monkeypatch):
    """默认(未配置白名单目录) → 本地导入整体禁用。"""
    from config import settings
    monkeypatch.setattr(settings, "intel_local_feed_dir", "")
    assert await taxii_client.poll_feed({
        "feed_type": "csv", "url": "/tmp/anything.csv", "name": "x",
    }) == []


@pytest.mark.asyncio
async def test_redirect_hop_revalidated_and_strips_auth(monkeypatch):
    """302 跳内网 → 拒绝; 302 跳其它公网 host → 不带 Authorization。"""
    import httpx as _httpx_mod

    # 沙箱无外网 DNS: 公网测试域免解析放行, 其余目标(内网/元数据)仍走真校验
    import net_guard
    _real_validate = net_guard.validate_submittable_url
    _PUBLIC_TEST_HOSTS = {"feeds.example.com", "public.example.com"}

    def _validate(url, **k):
        from urllib.parse import urlsplit
        host = (urlsplit(url).hostname or "").lower()
        if host in _PUBLIC_TEST_HOSTS:
            return url
        return _real_validate(url, **k)

    monkeypatch.setattr(net_guard, "validate_submittable_url", _validate)
    seen = []

    class _Resp:
        def __init__(self, status, headers):
            self.status_code = status
            self.headers = headers
            self.is_redirect = status in (301, 302, 307, 308)

        def raise_for_status(self):
            return None

        async def aiter_bytes(self, n):
            yield b"type,value\nip,203.0.113.10\n"

    class _Client:
        def __init__(self, **kw):
            assert kw.get("follow_redirects") is False, "必须手动逐跳"

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def get(self, url, headers=None):
            seen.append((str(url), dict(headers or {})))
            if len(seen) == 1:
                return _Resp(302, {"location": "http://10.0.0.5/steal"})  # 跳内网
            return _Resp(302, {"location": "https://public.example.com/final.csv"})

    monkeypatch.setattr(_httpx_mod, "AsyncClient", _Client)

    # 跳内网: 抛 ValueError(被 _import_csv_http 捕获 → 空手而归)
    iocs = await taxii_client.poll_feed({
        "feed_type": "csv_http", "url": "https://feeds.example.com/a.csv",
        "name": "t", "api_key": "secret-token",
    })
    assert iocs == []
    assert len(seen) == 1
    assert seen[0][1].get("Authorization") == "Token secret-token"

    # 跳公网: 第二跳不带凭证
    seen.clear()

    class _Client2(_Client):
        async def get(self, url, headers=None):
            seen.append((str(url), dict(headers or {})))
            if len(seen) == 1:
                return _Resp(302, {"location": "https://public.example.com/final.csv"})
            return _Resp(200, {})

    monkeypatch.setattr(_httpx_mod, "AsyncClient", _Client2)
    iocs = await taxii_client.poll_feed({
        "feed_type": "csv_http", "url": "https://feeds.example.com/a.csv",
        "name": "t", "api_key": "secret-token",
    })
    assert iocs and iocs[0]["ioc_value"] == "203.0.113.10"
    assert seen[1][1].get("Authorization") is None, "跨 host 跳转必须剥离凭证"


@pytest.mark.asyncio
async def test_streaming_size_cap(monkeypatch):
    """超大响应在 ~10MB 处中止, 不整包入内存。"""
    import httpx as _httpx_mod
    from threat_intel import stix_taxii as mod

    sent = bytearray()

    class _Resp:
        status_code = 200
        headers = {}
        is_redirect = False

        def raise_for_status(self):
            return None

        async def aiter_bytes(self, n):
            chunk = b"x" * (64 * 1024)
            while True:  # 无限流
                sent.extend(chunk)
                yield chunk

    class _Client:
        def __init__(self, **kw):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def get(self, url, headers=None):
            return _Resp()

    monkeypatch.setattr(_httpx_mod, "AsyncClient", _Client)

    import net_guard
    monkeypatch.setattr(net_guard, "validate_submittable_url",
                        lambda u, **k: u)  # 沙箱无外网 DNS, 本用例只测限长
    text = await taxii_client._fetch_text("https://feeds.example.com/big.csv")
    assert len(text) <= mod._MAX_FEED_BYTES + 64 * 1024, "必须流式截断"
    assert len(sent) < mod._MAX_FEED_BYTES + 2 * 1024 * 1024, "读入量必须被中止在限额附近"


@pytest.mark.asyncio
async def test_kev_json_rejects_ssrf(monkeypatch):
    async def _boom(*a, **k):
        raise AssertionError("_fetch_text 不应被调用")

    monkeypatch.setattr(taxii_client, "_fetch_text", _boom)
    iocs = await taxii_client.poll_feed({
        "feed_type": "kev_json", "url": "http://metadata.google.internal/kev.json", "name": "kev",
    })
    assert iocs == []
