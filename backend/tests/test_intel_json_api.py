"""json_api 通用 JSON 情报源 + ja3 IOC 类型（REMEDIATION-PLAN-2026-10-30 路线 D）。

覆盖三类真实免费源的形态：
  - abuse.ch ThreatFox：POST JSON，items_path=data，ioc_type 含 "ip:port"
  - abuse.ch MalwareBazaar：POST JSON，sha256_hash 字段 → file_hash
  - ransomware.live：GET JSON 列表 → domain
以及红线：SSRF 校验前置（私网 URL 不发请求）、ja3 脏数据不进匹配缓存。
"""
import json

import pytest

import threat_intel.stix_taxii as stix_taxii
from threat_intel.stix_taxii import taxii_client


THREATFOX_RESP = json.dumps({
    "status": "success",
    "data": [
        {"ioc": "1.2.3.4:8080", "ioc_type": "ip:port", "malware": "gozi",
         "confidence": 75},
        {"ioc": "evil-c2.example", "ioc_type": "domain", "malware": "gozi"},
        {"ioc": "hxxp://evil.example/pay", "ioc_type": "url", "malware": "gozi"},
        {"ioc": "5.6.7.8", "ioc_type": "weird_type", "malware": "x"},  # 未知类型 → 跳过
    ],
})

MALWAREBAZAAR_RESP = json.dumps({
    "query_status": "ok",
    "data": [
        {"sha256_hash": "A" * 64, "signature": "AgentTesla"},
        {"sha256_hash": "b" * 64, "signature": "Formbook"},
    ],
})


def test_parse_threatfox_shape():
    cfg = {
        "feed_type": "json_api",
        "name": "abuse.ch-threatfox",
        "url": "https://threatfox.abuse.ch/api/v1/",
        "config": {
            "method": "POST",
            "body": {"query": "get_iocs", "days": 1},
            "items_path": "data",
            "value_path": "ioc",
            "type_path": "ioc_type",
            "type_map": {"ip:port": "ip", "domain": "domain", "url": "url"},
            "strip_port": True,
            "threat_path": "malware",
        },
    }
    iocs = taxii_client._parse_json_api(THREATFOX_RESP, cfg)
    by_type = {(i["ioc_type"], i["ioc_value"]) for i in iocs}
    # ip:port 剥端口成纯 IP
    assert ("ip", "1.2.3.4") in by_type
    assert ("domain", "evil-c2.example") in by_type
    assert ("url", "hxxp://evil.example/pay") in by_type
    # 未知 ioc_type 且无 fixed_type → 丢弃
    assert all(i["ioc_value"] != "5.6.7.8" for i in iocs)
    assert iocs[0]["threat_type"] == "gozi"
    assert iocs[0]["source"] == "abuse.ch-threatfox"


def test_parse_malwarebazaar_fixed_type():
    cfg = {
        "feed_type": "json_api",
        "name": "abuse.ch-malwarebazaar",
        "url": "https://malwarebazaar.abuse.ch/api/v1/",
        "config": {
            "method": "POST",
            "body": {"query": "get_taginfo", "tag": "AgentTesla", "limit": 100},
            "items_path": "data",
            "value_path": "sha256_hash",
            "fixed_type": "file_hash",
            "threat_path": "signature",
        },
    }
    iocs = taxii_client._parse_json_api(MALWAREBAZAAR_RESP, cfg)
    assert len(iocs) == 2
    assert all(i["ioc_type"] == "file_hash" for i in iocs)
    assert iocs[0]["threat_type"] == "AgentTesla"


def test_parse_root_list_and_bad_payload():
    # 根即列表 + fixed domain（ransomware.live 形态）
    resp = json.dumps(["gang1alpha.example", "gang2infra.example"])
    cfg = {"config": {"value_path": "domain", "fixed_type": "domain"}}
    assert taxii_client._parse_json_api(resp, cfg) == []  # 列表项非 dict → 空
    # 嵌套 items + 非法 JSON
    assert taxii_client._parse_json_api("not-json", cfg) == []
    # items_path 取不到列表
    assert taxii_client._parse_json_api(json.dumps({"nope": 1}), {"config": {"items_path": "data"}}) == []


def test_dig_supports_list_index_and_missing():
    obj = {"a": [{"b": 1}, {"b": 2}]}
    assert taxii_client._dig(obj, "a.1.b") == 2
    assert taxii_client._dig(obj, "a.5.b") is None
    assert taxii_client._dig(obj, "x.y") is None


@pytest.mark.asyncio
async def test_poll_feed_json_api_dispatch(monkeypatch, no_dns_url_guard):
    """feed_type=json_api 走 POST 通道并返回解析结果。"""
    seen = {}

    async def _fake_post(url, body, headers=None):
        seen["url"], seen["body"] = url, body
        return THREATFOX_RESP

    monkeypatch.setattr(taxii_client, "_post_json_text", _fake_post)
    cfg = {
        "feed_type": "json_api",
        "name": "abuse.ch-threatfox",
        "url": "https://threatfox.abuse.ch/api/v1/",
        "config": {"method": "POST", "body": {"query": "get_iocs", "days": 1},
                   "items_path": "data", "value_path": "ioc", "type_path": "ioc_type",
                   "type_map": {"ip:port": "ip", "domain": "domain", "url": "url"},
                   "strip_port": True},
    }
    iocs = await taxii_client.poll_feed(cfg)
    assert seen["url"].startswith("https://threatfox")
    assert seen["body"] == {"query": "get_iocs", "days": 1}
    assert any(i["ioc_value"] == "1.2.3.4" for i in iocs)


@pytest.mark.asyncio
async def test_json_api_get_passes_extra_headers(monkeypatch, no_dns_url_guard):
    """D 第二批: GET + 源特定 header（OTX X-OTX-API-KEY 形态）透传到传输层。"""
    seen = {}

    async def _fake_get(url, api_key="", extra_headers=None):
        seen["url"], seen["api_key"], seen["extra_headers"] = url, api_key, extra_headers
        return json.dumps([{"ioc": "9.9.9.9", "type": "ip"}])

    monkeypatch.setattr(taxii_client, "_fetch_text", _fake_get)
    iocs = await taxii_client.poll_feed({
        "feed_type": "json_api",
        "name": "otx-export",
        "url": "https://otx.alienvault.com/api/v1/indicators/export",
        "api_key": "k-123",
        "config": {"method": "GET",
                   "headers": {"X-OTX-API-KEY": "k-123"},
                   "value_path": "ioc", "type_path": "type",
                   "type_map": {"ip": "ip"}},
    })
    assert seen["extra_headers"] == {"X-OTX-API-KEY": "k-123"}
    assert seen["api_key"] == "k-123"
    assert iocs and iocs[0]["ioc_value"] == "9.9.9.9"


@pytest.mark.asyncio
async def test_json_api_rejects_private_url(monkeypatch):
    """SSRF 红线：私网 URL 在发请求前即被拒（fetch/post 都不得被调用）。"""

    async def _boom(*a, **k):
        raise AssertionError("不应发起请求")

    monkeypatch.setattr(taxii_client, "_fetch_text", _boom)
    monkeypatch.setattr(taxii_client, "_post_json_text", _boom)
    iocs = await taxii_client.poll_feed({
        "feed_type": "json_api",
        "name": "evil",
        "url": "http://127.0.0.1:8001/api/leak",
        "config": {"value_path": "ioc", "fixed_type": "ip"},
    })
    assert iocs == []


def test_ja3_normalization_in_ingest():
    from threat_intel.ioc_ingest import _normalize

    good = _normalize({"ioc_type": "ja3", "ioc_value": "6734F37431670B3AB4292B8AE60F8EE2",
                       "source": "sslbl"}, "sslbl")
    assert good and good["ioc_value"] == "6734f37431670b3ab4292b8ae60f8ee2"

    # 非 32 位 hex 的脏数据 → 拒绝（不进精确匹配缓存）
    assert _normalize({"ioc_type": "ja3", "ioc_value": "nothex"}, "x") is None
    assert _normalize({"ioc_type": "ja3", "ioc_value": "z" * 32}, "x") is None


@pytest.mark.asyncio
async def test_matcher_ja3_exact_match():
    from threat_intel.ioc_matcher import IocHit, IocMatcher

    m = IocMatcher()
    digest = "6734f37431670b3ab4292b8ae60f8ee2"
    m._cache = {digest: IocHit(ioc_type="ja3", ioc_value=digest,
                               threat_type="c2", severity="high",
                               confidence=0.9, source="sslbl")}
    m._last_refresh = 1e18  # 跳过自动刷新

    hits = await m.match(ja3=digest.upper())  # 大小写不敏感
    assert len(hits) == 1 and hits[0].ioc_type == "ja3"
    assert await m.match(ja3="0" * 32) == []
