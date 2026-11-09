# -*- coding: utf-8 -*-
"""情报源注册白名单守卫 (R1)。

背景(2026-10-29 复审 P1-3): `edr_intel.py` 的 feed_type 白名单漏掉 `kev_json`,
导致 tools/seed-free-intel-feeds.sh 以 kev_json 注册第 4 源(CISA KEV)时 400,
脚本在 `set -euo pipefail` 下中途退出 —— 文档宣称的"4 免费源一键接线"实际
3/4 源即断。解析侧(stix_taxii.poll_feed)早已实现 kev_json 方言, 但 API 注册
路径上是死代码。

本测试锁定:
  1. API 白名单与解析侧 ALLOWED_FEED_TYPES 同源(六种全可注册);
  2. 白名单外的类型仍被拒(防止反向放宽);
  3. kev_json 注册的行能真正走 poll_feed 分发(方言接线端到端)。
"""
from __future__ import annotations

import os
import sys

import pytest

os.environ.setdefault("SHARED_MEMORY_SKIP_DOTENV", "1")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class _FakeRequest:
    def __init__(self, body: dict):
        self._body = body

    async def json(self):
        return self._body


def _admin() -> "UserInfo":  # noqa: F821
    from auth import UserInfo

    return UserInfo(username="tester", role="admin", jti="test-jti")


@pytest.mark.asyncio
async def test_register_kev_json_feed():
    """kev_json 必须可注册(修复前 400 → 红; 白名单补齐 → 绿)。"""
    from models import Base, engine, async_session
    from routers.edr_intel import intel_create_feed

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)

    req = _FakeRequest({
        "name": "cisa-kev",
        "feed_type": "kev_json",
        "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "poll_interval_min": 1440,
    })
    async with async_session() as s:
        resp = await intel_create_feed(request=req, session=s, user=_admin())
        assert resp["status"] == "ok"
        assert resp["id"] is not None

        from models import ThreatIntelFeed
        feed = await s.get(ThreatIntelFeed, resp["id"])
        assert feed is not None
        assert feed.feed_type == "kev_json"


@pytest.mark.asyncio
async def test_register_all_seven_feed_types():
    """解析侧支持的七种方言全部可注册 — 白名单与 ALLOWED_FEED_TYPES 同源。

    2026-10-30 +json_api（REMEDIATION-PLAN 路线 D：ThreatFox/MalwareBazaar 类
    免费源，见 docs/upgrade/INTEL-FEEDS.md）。
    """
    from threat_intel.stix_taxii import ALLOWED_FEED_TYPES

    # 2026-10-30 D 第二批: +misp_feed(botvrij OSINT 静态目录, 免 key 真拉取通道)
    assert set(ALLOWED_FEED_TYPES) == {
        "taxii", "misp", "misp_feed", "csv", "csv_http", "kev_json", "json_api",
        "stix_bundle",
    }
    from models import Base, engine, async_session
    from routers.edr_intel import intel_create_feed

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)

    for ft in ALLOWED_FEED_TYPES:
        req = _FakeRequest({"name": f"t-{ft}", "feed_type": ft, "url": "https://example.com/x"})
        async with async_session() as s:
            resp = await intel_create_feed(request=req, session=s, user=_admin())
            assert resp["status"] == "ok", ft


@pytest.mark.asyncio
async def test_register_rejects_unknown_feed_type():
    """白名单外仍拒绝 — 防反向放宽。"""
    from models import Base, engine, async_session
    from routers.edr_intel import intel_create_feed

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)

    from fastapi import HTTPException
    req = _FakeRequest({"name": "evil", "feed_type": "file://", "url": "/etc/passwd"})
    async with async_session() as s:
        with pytest.raises(HTTPException) as ei:
            await intel_create_feed(request=req, session=s, user=_admin())
        assert ei.value.status_code == 400


@pytest.mark.asyncio
async def test_kev_json_dialect_dispatch(monkeypatch, no_dns_url_guard):
    """kev_json 走 poll_feed 分发且方言解析正确(注册后的下一跳)。"""
    from threat_intel.stix_taxii import taxii_client

    kev_sample = """{
      "title": "CISA Catalog of Known Exploited Vulnerabilities",
      "vulnerabilities": [
        {"cveID": "CVE-2026-1234", "knownRansomwareCampaignUse": "Known",
         "vendorProject": "X", "product": "Y", "shortDescription": "d",
         "dateAdded": "2026-10-01"},
        {"cveID": "CVE-2026-5678", "knownRansomwareCampaignUse": "Unknown",
         "vendorProject": "A", "product": "B", "shortDescription": "d",
         "dateAdded": "2026-10-02"}
      ]
    }"""

    async def _fake_fetch(url, api_key=""):
        return kev_sample

    monkeypatch.setattr(taxii_client, "_fetch_text", _fake_fetch)
    iocs = await taxii_client.poll_feed({
        "feed_type": "kev_json",
        "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "name": "cisa-kev",
    })
    assert {i["ioc_value"] for i in iocs} == {"CVE-2026-1234", "CVE-2026-5678"}
    assert all(i["ioc_type"] == "cve" for i in iocs)
