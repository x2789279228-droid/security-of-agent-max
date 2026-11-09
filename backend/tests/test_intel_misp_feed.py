"""D 第二批实拉通道：misp_feed（MISP feed 静态目录，免 key）单测。

botvrij.eu OSINT feed 实测结构：manifest.json(435 事件) + 事件UUID.json
(Event.Attribute[] 含 sha256/ip-dst/yara/link/mutex/filename)。
"""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import threat_intel.stix_taxii as st
from threat_intel.stix_taxii import taxii_client


def test_misp_type_map_covers_botvrij_observed_types():
    """botvrij 实测属性类型的可映射子集必须全覆盖。"""
    for t in ("ip-src", "ip-dst", "domain", "url", "sha256", "md5"):
        assert t in taxii_client._MISP_TYPE_MAP


@pytest.mark.asyncio
async def test_poll_misp_feed_via_manifest_and_events(monkeypatch):
    """manifest → 最新 N 事件 → 属性抽取 → 类型映射 全链。"""
    manifest = {
        "ev-old": {"timestamp": 1600000000},
        "ev-new": {"timestamp": 1700000000},
    }
    events = {
        "ev-new": {"Event": {"Attribute": [
            {"type": "sha256", "value": "A" * 64, "category": "Payload delivery"},
            {"type": "ip-dst", "value": "203.0.113.9", "category": "Network activity"},
            {"type": "domain|ip", "value": "bad.example|198.51.100.7",
             "category": "Network activity"},
            {"type": "mutex", "value": "not-an-ioc-type"},
        ]}},
        "ev-old": {"Event": {"Attribute": [
            {"type": "url", "value": "https://old.example/x", "category": "External analysis"},
        ]}},
    }
    fetched = {}

    async def fake_fetch(url, api_key="", extra_headers=None):
        fetched[url] = True
        if url.endswith("manifest.json"):
            return json.dumps(manifest)
        for uuid_, body in events.items():
            if url.endswith(f"{uuid_}.json"):
                return json.dumps(body)
        return "{}"

    monkeypatch.setattr(taxii_client, "_fetch_text", fake_fetch)
    iocs = await taxii_client.poll_feed({
        "feed_type": "misp_feed", "name": "botvrij-test",
        "url": "https://www.botvrij.eu/data/feed-osint/",
        "config": {"max_events": 1},   # 只取最新 → ev-new
    })
    # 只拉最新一个事件(ev-new), 旧的 url 不在
    vals = {i["ioc_value"] for i in iocs}
    assert "A" * 64 in vals and "203.0.113.9" in vals
    assert "bad.example" in vals            # domain|ip → domain 部分
    assert "https://old.example/x" not in vals
    assert all(i["ioc_type"] != "mutex" for i in iocs)  # 未映射类型剔除
    assert iocs[0]["source"] == "botvrij-test"
    assert any(i["stix_id"] == "ev-new" for i in iocs)


@pytest.mark.asyncio
async def test_misp_feed_rejects_private_url(monkeypatch):
    async def _boom(*a, **k):
        raise AssertionError("不应发起请求")
    monkeypatch.setattr(taxii_client, "_fetch_text", _boom)
    out = await taxii_client.poll_feed({
        "feed_type": "misp_feed", "name": "evil",
        "url": "http://127.0.0.1:8001/leak", "config": {}})
    assert out == []


def test_allowed_types_includes_misp_feed():
    assert "misp_feed" in st.ALLOWED_FEED_TYPES
