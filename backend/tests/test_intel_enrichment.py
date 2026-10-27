# -*- coding: utf-8 -*-
"""路线 3(2026-10-27)回归: 免费情报全家桶 + 富化闭环。

钉住五件事:
  1. URLhaus csv_recent 方言(# 注释头 + url/threat 列)解析正确;
  2. CISA KEV JSON 方言解析 → cve 类型 IOC, 形状不对的条目跳过不炸整批;
  3. ioc_matcher 支持 cve 精确匹配(小写归一);
  4. 富化统一入口 enrich_event_if_enabled 的四态契约:
     关闭=零行为变化 / 命中写 raw_data.threat_intel / 超时与异常 fail-open;
  5. KEV 特权提级: severity 升一档 + kev_hit 标注落 raw_data(可查证据)。
"""
from __future__ import annotations

import asyncio
import importlib
import json
import os
import sys
from types import SimpleNamespace

import pytest

os.environ.setdefault("SHARED_MEMORY_SKIP_DOTENV", "1")
os.environ.setdefault("SHARED_MEMORY_DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("SHARED_MEMORY_JWT_SECRET", "test-secret")
os.environ.setdefault("SHARED_MEMORY_LLM_API_KEY", "test")
os.environ.setdefault("SHARED_MEMORY_EMBEDDING_API_KEY", "test")
os.environ.setdefault("SHARED_MEMORY_ADMIN_PASSWORD", "test")

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import settings  # noqa: E402
from threat_intel.ioc_matcher import ioc_matcher, IocHit  # noqa: E402
from threat_intel.stix_taxii import taxii_client  # noqa: E402
from threat_intel import intel_enricher as enricher_mod  # noqa: E402


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


# ── fixtures: 真实源格式样本(按官方文档结构) ──

URLHAUS_CSV = """# URLhaus CSV dump
# Last updated: 2026-10-27 00:00:00 UTC
id,dateadded,url,url_status,threat,tags,urlhaus_link
1,"2026-10-26 23:11:02","http://185.2.14.9/kekware.bin",online,malware_download,"elf,mirai","https://urlhaus.abuse.ch/download/1/"
2,"2026-10-26 22:40:51","http://malware.example.com/payload.exe",online,malware_download,"exe,lokibot","https://urlhaus.abuse.ch/download/2/"
"""

KEV_JSON = json.dumps({
    "title": "CISA Catalog of Known Exploited Vulnerabilities",
    "catalogVersion": "2026-10-27-0001",
    "dateReleased": "2026-10-27T00:00:00.0000Z",
    "count": 3,
    "vulnerabilities": [
        {
            "cveID": "CVE-2021-44228",
            "vendorProject": "Apache",
            "product": "Log4j2",
            "vulnerabilityName": "Apache Log4j2 Remote Code Execution Vulnerability",
            "dateAdded": "2021-12-10",
            "shortDescription": "Apache Log4j2 contains a remote code execution vulnerability.",
            "requiredAction": "Apply updates per vendor instructions.",
            "dueDate": "2021-12-24",
            "knownRansomwareCampaignUse": "Known",
            "notes": "https://logging.apache.org/log4j/2.x/security.html",
            "cwes": ["CWE-502"],
        },
        {
            "cveID": "CVE-2023-34362",
            "vendorProject": "Progress",
            "product": "MoveIt",
            "vulnerabilityName": "Progress MoveIt SQL Injection Vulnerability",
            "dateAdded": "2023-06-02",
            "knownRansomwareCampaignUse": "Known",
            "cwes": ["CWE-89"],
        },
        {
            # 形状不对的条目: 缺 cveID 前缀 —— 必须被跳过, 不炸整批
            "vendorProject": "Broken",
            "product": "Entry",
        },
    ],
})


# ── 1. URLhaus 方言 ──

def test_urlhaus_csv_dialect_parses():
    config = {
        "name": "urlhaus-free",
        "config": {
            "format": "csv", "value_column": "url", "threat_column": "threat",
            "fixed_type": "url", "fixed_threat": "malware_distribution",
            "severity": "high", "comment_prefix": "#",
        },
    }
    iocs = taxii_client._parse_csv_text(URLHAUS_CSV, config)
    assert len(iocs) == 2, f"# 注释行应被跳过, 得到 {len(iocs)} 条"
    assert iocs[0]["ioc_type"] == "url"
    assert iocs[0]["ioc_value"] == "http://185.2.14.9/kekware.bin"
    assert iocs[0]["threat_type"] == "malware_download"
    assert iocs[0]["severity"] == "high"
    assert iocs[0]["source"] == "urlhaus-free"


# ── 2. CISA KEV 方言 ──

def test_kev_json_parse():
    config = {"name": "cisa-kev", "config": {"severity": "critical"}}
    iocs = taxii_client._parse_kev_json(KEV_JSON, config)
    assert len(iocs) == 2, "形状不对的条目必须跳过(3 条里 2 条有效)"
    values = {i["ioc_value"] for i in iocs}
    # 解析器保留官方大小写; 小写归一发生在 ioc_ingest._normalize(落库层)
    assert values == {"CVE-2021-44228", "CVE-2023-34362"}
    first = iocs[0]
    assert first["ioc_type"] == "cve"
    assert first["severity"] == "critical"
    assert first["confidence"] == 0.95
    assert first["context"]["ransomware_use"] == "Known"
    assert first["context"]["product"] == "Log4j2"


def test_kev_json_rejects_malformed():
    config = {"name": "cisa-kev"}
    assert taxii_client._parse_kev_json("not json at all {{", config) == []
    assert taxii_client._parse_kev_json('{"title": "no vulns here"}', config) == []


def test_kev_fetch_path(monkeypatch):
    """拉取→解析全链(传输打桩): feed_type=kev_json 走 _import_kev_json。"""

    async def _fake_fetch(url, api_key=""):
        return KEV_JSON

    monkeypatch.setattr(taxii_client, "_fetch_text", _fake_fetch)
    config = {
        "feed_type": "kev_json", "name": "cisa-kev",
        "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "config": {"severity": "critical"},
    }
    iocs = _run(taxii_client.poll_feed(config))
    assert len(iocs) == 2 and iocs[0]["ioc_type"] == "cve"


def test_cve_allowed_by_ingest_normalize():
    """cve 类型必须过 ioc_ingest 白名单(否则 KEV 拉到了落不了库)。"""
    from threat_intel.ioc_ingest import _normalize
    norm = _normalize({
        "ioc_type": "cve", "ioc_value": "CVE-2021-44228",
        "severity": "critical", "confidence": 0.95,
        "source": "cisa-kev", "threat_type": "Apache Log4j2 RCE",
    }, "cisa-kev")
    assert norm is not None
    assert norm["ioc_type"] == "cve"
    assert norm["ioc_value"] == "cve-2021-44228"  # 统一小写(与 matcher 查询口径一致)


# ── 3. matcher cve 匹配 ──

def test_matcher_cve_exact_match():
    ioc_matcher._cache["cve-2021-44228"] = IocHit(
        ioc_type="cve", ioc_value="cve-2021-44228",
        threat_type="Apache Log4j2 RCE", severity="critical",
        confidence=0.95, source="cisa-kev",
    )
    try:
        hits = _run(ioc_matcher.match(cve="CVE-2021-44228"))
        assert len(hits) == 1
        assert hits[0].severity == "critical"
        # 刷新间隔内的重复查询不再回源 —— 直接查缓存口径
        assert _run(ioc_matcher.match(cve="cve-2021-44228"))
        assert not _run(ioc_matcher.match(cve="CVE-2099-0000"))
    finally:
        ioc_matcher._cache.pop("cve-2021-44228", None)


# ── 4/5. 富化入口契约 + KEV 提级 ──

@pytest.fixture()
def _fresh_enricher():
    importlib.reload(enricher_mod)
    yield enricher_mod
    importlib.reload(enricher_mod)


def _patch_matcher(monkeypatch, hits_by_kind):
    class _FakeMatcher:
        async def match(self, session=None, **kw):
            out = []
            for kind, value in kw.items():
                if kind == "session":
                    continue
                for h in hits_by_kind.get(kind, []):
                    # 真实 matcher 大小写不敏感(缓存统一小写), 桩保持同口径
                    if str(h.get("value")).lower() == str(value).lower():
                        out.append(IocHit(**h["hit"]))
            return out

    import threat_intel.ioc_matcher as m
    monkeypatch.setattr(m, "ioc_matcher", _FakeMatcher())


def test_enrich_disabled_is_passthrough(_fresh_enricher, monkeypatch):
    monkeypatch.setattr(settings, "intel_enrich_enabled", False)
    ev = {"src_ip": "185.2.14.9", "severity": "low", "raw_data": {}}
    out = _run(_fresh_enricher.enrich_event_if_enabled(ev))
    assert out is ev, "关闭富化时必须原样返回(零行为变化)"
    assert "threat_intel" not in (out.get("raw_data") or {})


def test_enrich_kev_hit_boosts_severity(_fresh_enricher, monkeypatch):
    monkeypatch.setattr(settings, "intel_enrich_enabled", True)
    _patch_matcher(monkeypatch, {
        "cve": [{"value": "cve-2021-44228", "hit": {
            "ioc_type": "cve", "ioc_value": "cve-2021-44228",
            "threat_type": "Apache Log4j2 RCE", "severity": "critical",
            "confidence": 0.95, "source": "cisa-kev",
        }}],
    })
    ev = {"event_type": "WEB_ATTACK", "cve": "CVE-2021-44228",
          "severity": "medium", "raw_data": {}}
    out = _run(_fresh_enricher.enrich_event_if_enabled(ev))
    ti = out["raw_data"]["threat_intel"]
    assert ti.get("kev_hit") is True
    assert "CVE-2021-44228" in ti.get("kev_boost_reason", "")
    assert out["severity"] == "high", "medium 升一档 = high(不是跳档到 critical)"
    assert ti["cve_ioc"][0]["ioc_type"] == "cve"


def test_enrich_kev_caps_at_critical(_fresh_enricher, monkeypatch):
    monkeypatch.setattr(settings, "intel_enrich_enabled", True)
    _patch_matcher(monkeypatch, {
        "cve": [{"value": "cve-2021-44228", "hit": {
            "ioc_type": "cve", "ioc_value": "cve-2021-44228",
            "severity": "critical", "confidence": 0.95, "source": "cisa-kev",
        }}],
    })
    ev = {"cve": "CVE-2021-44228", "severity": "critical", "raw_data": {}}
    out = _run(_fresh_enricher.enrich_event_if_enabled(ev))
    assert out["severity"] == "critical", "已 critical 不再上跳"


def test_enrich_exception_fails_open(_fresh_enricher, monkeypatch):
    monkeypatch.setattr(settings, "intel_enrich_enabled", True)

    class _Boom:
        async def enrich_event(self, session, event):
            raise RuntimeError("reputation db down")

    monkeypatch.setattr(_fresh_enricher, "intel_enricher", _Boom())
    ev = {"src_ip": "1.2.3.4", "severity": "low", "raw_data": {}}
    out = _run(_fresh_enricher.enrich_event_if_enabled(ev))
    assert out is ev, "富化失败必须 fail-open 放行原事件"
    assert "threat_intel" not in out["raw_data"]


def test_enrich_timeout_fails_open(_fresh_enricher, monkeypatch):
    monkeypatch.setattr(settings, "intel_enrich_enabled", True)
    monkeypatch.setattr(settings, "intel_enrich_timeout_ms", 5)

    class _Slow:
        async def enrich_event(self, session, event):
            await asyncio.sleep(0.5)
            return event

    monkeypatch.setattr(_fresh_enricher, "intel_enricher", _Slow())
    ev = {"src_ip": "1.2.3.4"}
    out = _run(_fresh_enricher.enrich_event_if_enabled(ev))
    assert out is ev, "超时必须放行原事件(富化不成为新的丢数据点)"


# ── 6. 接线守卫: 两条接入链都调了统一入口 ──

def test_enrich_wired_into_both_ingest_chains():
    import ast
    from pathlib import Path

    backend = Path(__file__).resolve().parent.parent
    checks = {
        "ingest_pipeline.py": ("HTTP ingest 链", "detect"),
        "kafka_consumer.py": ("Kafka enriched 链", "_handle_enriched"),
    }
    for fname, (label, func) in checks.items():
        tree = ast.parse((backend / fname).read_text(encoding="utf-8"))
        found = False
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if node.name != func:
                continue
            for sub in ast.walk(node):
                if (
                    isinstance(sub, ast.ImportFrom)
                    and sub.module == "threat_intel.intel_enricher"
                    and any(a.name == "enrich_event_if_enabled" for a in sub.names)
                ):
                    found = True
        assert found, f"{label}({fname}:{func}) 未调用 enrich_event_if_enabled —— 富化闭环断了"
