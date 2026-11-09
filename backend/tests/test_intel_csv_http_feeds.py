# -*- coding: utf-8 -*-
"""csv_http 免费情报源 — 接线守卫。

背景: 2026-10-25 前 `_import_csv` 只读本地文件, TAXII/MISP 的 url 配置为空,
平台情报库处于"客户端就绪、零真实情报"状态(质量评审短板之一)。
本文件锁定新 `csv_http` 源的解析与落库语义, 样例文本用
**当天实抓的 abuse.ch Feodo ipblocklist.csv 真实表头** ——
上游改版导致解析失效时这里第一时间红。
"""
from __future__ import annotations

import os
import sys

import pytest

os.environ.setdefault("SHARED_MEMORY_SKIP_DOTENV", "1")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ── 2026-03-04 实抓的 Feodo 真实文本(注释块 + 表头 + 数据行) ──
FEODO_SAMPLE = """\
################################################################
# abuse.ch Feodo Tracker Botnet C2 IP Blocklist (CSV)          #
# Last updated: 2026-03-04 14:28:39 UTC                        #
#                                                              #
"first_seen_utc","dst_ip","dst_port","c2_status","last_online","malware"
"2022-06-04 21:24:53","162.243.103.246","8080","offline","2026-03-07","Emotet"
"2025-12-30 13:56:31","50.16.16.211","443","online","2026-03-12","QakBot"
this-is-not-an-ip-and-must-not-crash,999.999.999.999,80,online,2026-01-01,Emotet
"""

OPENPHISH_SAMPLE = """\
https://login-example.com/verify/account
https://secure-bank-example.top/auth
"""


def _feodo_config() -> dict:
    return {
        "feed_type": "csv_http",
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
        "name": "abuse.ch-feodo",
        "config": {
            "format": "csv",
            "value_column": "dst_ip",
            "fixed_type": "ip",
            "threat_column": "malware",
            "severity": "high",
        },
    }


def test_parse_feodo_dialect():
    from threat_intel.stix_taxii import taxii_client

    iocs = taxii_client._parse_csv_text(FEODO_SAMPLE, _feodo_config())
    # 解析层忠实透传(含畸形行); 非法 IP 由 store_iocs 的 _normalize 过滤 ——
    # 分层职责: parse 不管校验, store 不懂方言。
    assert {i["ioc_value"] for i in iocs} == {
        "162.243.103.246", "50.16.16.211", "999.999.999.999",
    }
    emotet = next(i for i in iocs if i["ioc_value"] == "162.243.103.246")
    assert emotet["ioc_type"] == "ip"
    assert emotet["threat_type"] == "Emotet"
    assert emotet["severity"] == "high"
    assert emotet["source"] == "abuse.ch-feodo"


def test_parse_plain_url_list():
    from threat_intel.stix_taxii import taxii_client

    cfg = {
        "name": "openphish",
        "config": {"format": "plain", "fixed_type": "url", "severity": "high"},
    }
    iocs = taxii_client._parse_csv_text(OPENPHISH_SAMPLE, cfg)
    assert [i["ioc_value"] for i in iocs] == [
        "https://login-example.com/verify/account",
        "https://secure-bank-example.top/auth",
    ]
    assert all(i["ioc_type"] == "url" for i in iocs)


def test_legacy_local_csv_semantics_preserved(tmp_path, monkeypatch):
    """旧 `csv` 本地文件路径的列名回退(value|ioc_value / type|ioc_type)不能被改坏。"""
    from config import settings
    from threat_intel.stix_taxii import taxii_client

    # R14: 本地 csv 导入受 intel_local_feed_dir 白名单约束 — 测试把白名单指向 tmp_path
    monkeypatch.setattr(settings, "intel_local_feed_dir", str(tmp_path))

    f = tmp_path / "legacy.csv"
    f.write_text(
        "type,value\nip,203.0.113.7\ndomain,evil.example.com\n",
        encoding="utf-8",
    )
    import asyncio

    iocs = asyncio.run(taxii_client._import_csv({"url": str(f), "name": "legacy"}))
    got = {(i["ioc_type"], i["ioc_value"]) for i in iocs}
    assert got == {("ip", "203.0.113.7"), ("domain", "evil.example.com")}


@pytest.mark.asyncio
async def test_poll_feed_csv_http_dispatch_and_store(monkeypatch, no_dns_url_guard):
    """dispatch → 拉取(monkeypatch) → store_iocs 落库 全链路。"""
    from models import ThreatIoc, async_session
    from threat_intel import stix_taxii
    from threat_intel.ioc_ingest import poll_feed_and_store

    from models import Base, engine
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)

    async def _fake_fetch(url, api_key=""):
        return FEODO_SAMPLE

    monkeypatch.setattr(stix_taxii.taxii_client, "_fetch_text", _fake_fetch)

    from threat_intel.stix_taxii import taxii_client
    iocs = await taxii_client.poll_feed(_feodo_config())
    assert len(iocs) == 3  # 含 1 条畸形行, 由 _normalize 在落库时过滤

    async with async_session() as s:
        stats = await poll_feed_and_store(s, _feodo_config())
        await s.commit()
        assert stats["inserted"] == 2, "畸形 IP 必须在 normalize 层被过滤"
        rows = (await s.execute(select(ThreatIoc))).scalars().all()
        assert {r.ioc_value for r in rows} == {"162.243.103.246", "50.16.16.211"}
        assert all(r.source == "abuse.ch-feodo" for r in rows)


@pytest.mark.asyncio
async def test_csv_http_rejects_non_http_url(monkeypatch):
    """url 不是 http(s) 时必须空手而归, 不允许读本地路径(路径穿越面)。"""
    from threat_intel.stix_taxii import taxii_client

    async def _boom(*a, **k):  # pragma: no cover — 被调用即失败
        raise AssertionError("_fetch_text 不应被调用")

    monkeypatch.setattr(taxii_client, "_fetch_text", _boom)
    iocs = await taxii_client.poll_feed({
        "feed_type": "csv_http", "url": "/etc/passwd", "name": "evil",
        "config": {},
    })
    assert iocs == []


from sqlalchemy import select  # noqa: E402  — 置底避免干扰 env 设置读取
