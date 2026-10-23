# -*- coding: utf-8 -*-
"""IOC 落库链路：拉取 → threat_iocs → ioc_matcher 命中。"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select


async def _reset():
    from models import Base, engine
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)


def _entry(**kw):
    base = {
        "ioc_type": "ip",
        "ioc_value": "203.0.113.9",
        "threat_type": "c2",
        "severity": "high",
        "confidence": 0.9,
        "source": "unit",
    }
    base.update(kw)
    return base


@pytest.mark.asyncio
async def test_store_iocs_inserts_and_dedupes():
    from models import ThreatIoc, async_session
    from threat_intel.ioc_ingest import store_iocs

    await _reset()
    async with async_session() as s:
        stats = await store_iocs(s, [_entry(), _entry()], source="unit")
        await s.commit()
        assert stats["inserted"] == 1
        assert stats["skipped"] == 1
        rows = (await s.execute(select(ThreatIoc))).scalars().all()
        assert len(rows) == 1
        assert rows[0].ioc_value == "203.0.113.9"
        assert rows[0].source == "unit"


@pytest.mark.asyncio
async def test_upsert_refreshes_last_seen_not_first_seen():
    from models import ThreatIoc, async_session
    from threat_intel.ioc_ingest import store_iocs

    await _reset()
    async with async_session() as s:
        await store_iocs(s, [_entry(severity="medium")], source="unit")
        await s.commit()
        row = (await s.execute(select(ThreatIoc))).scalar_one()
        first = row.first_seen
        assert row.severity == "medium"
        await store_iocs(s, [_entry(severity="critical")], source="unit2")
        await s.commit()
        row = (await s.execute(select(ThreatIoc))).scalar_one()
        assert row.severity == "critical"
        assert row.source == "unit"  # 空 source 不覆盖旧 source；这里都是 unit
        assert row.first_seen == first


@pytest.mark.asyncio
async def test_expired_and_invalid_iocs_are_not_stored():
    from models import ThreatIoc, async_session
    from threat_intel.ioc_ingest import store_iocs

    await _reset()
    past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    async with async_session() as s:
        stats = await store_iocs(s, [
            _entry(ioc_value="198.51.100.1", expires_at=past),
            _entry(ioc_type="domain", ioc_value=""),
            _entry(ioc_type="domain", ioc_value="evil.example.com"),
        ])
        await s.commit()
        rows = (await s.execute(select(ThreatIoc))).scalars().all()
        assert stats["inserted"] == 1
        assert [r.ioc_value for r in rows] == ["evil.example.com"]


@pytest.mark.asyncio
async def test_ioc_matcher_hits_after_ingest_and_ignores_expired():
    from models import ThreatIoc, async_session
    from threat_intel.ioc_ingest import store_iocs
    from threat_intel.ioc_matcher import IocMatcher

    await _reset()
    past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    async with async_session() as s:
        await store_iocs(s, [
            _entry(ioc_value="203.0.113.77"),
            _entry(ioc_value="203.0.113.88", expires_at=past),
        ])
        await s.commit()
        m = IocMatcher()
        await m.refresh_cache(s)
        assert await m.match(ip="203.0.113.77")
        assert await m.match(ip="203.0.113.88") == []


class _FakeRequest:
    def __init__(self, body):
        self._body = body

    async def json(self):
        return self._body


@pytest.mark.asyncio
async def test_admin_ingest_endpoint_writes_and_refreshes():
    from models import ThreatIoc, async_session
    from routers.edr_intel import intel_upsert_iocs

    await _reset()
    entry = _entry(ioc_value="203.0.113.99")
    entry.pop("source", None)  # 让端点级 source 生效
    async with async_session() as s:
        out = await intel_upsert_iocs(
            request=_FakeRequest({"iocs": [entry], "source": "api"}),
            session=s, user=None,
        )
        assert out["inserted"] == 1
        row = (await s.execute(select(ThreatIoc))).scalar_one()
        assert row.source == "api"


@pytest.mark.asyncio
async def test_scheduler_polls_due_feeds_and_respects_interval(monkeypatch):
    from models import ThreatIntelFeed, ThreatIoc, async_session
    from scheduler import scheduler
    from threat_intel import stix_taxii

    await _reset()
    async with async_session() as s:
        feed = ThreatIntelFeed(name="due-feed", feed_type="stix_bundle",
                               url="", enabled=True, poll_interval_min=60)
        s.add(feed)
        await s.commit()

        async def _fake_poll(cfg):
            return [_entry(ioc_value="203.0.113.200")]

        monkeypatch.setattr(stix_taxii.taxii_client, "poll_feed", _fake_poll)
        assert await scheduler._poll_due_feeds(s) == 1
        rows = (await s.execute(select(ThreatIoc))).scalars().all()
        assert rows and rows[0].ioc_value == "203.0.113.200"
        assert feed.last_poll_status == "success"
        # 间隔未到，第二次不得重复拉取
        assert await scheduler._poll_due_feeds(s) == 0


@pytest.mark.asyncio
async def test_feed_poll_writes_iocs_and_updates_status(monkeypatch):
    from models import ThreatIntelFeed, ThreatIoc, async_session
    from routers.edr_intel import intel_poll_feed
    from threat_intel import stix_taxii

    await _reset()
    async with async_session() as s:
        feed = ThreatIntelFeed(name="unit-feed", feed_type="stix_bundle",
                               url="", enabled=True)
        s.add(feed)
        await s.commit()
        feed_id = feed.id

        async def _fake_poll(cfg):
            return [_entry(ioc_value="203.0.113.123")]

        monkeypatch.setattr(stix_taxii.taxii_client, "poll_feed", _fake_poll)
        out = await intel_poll_feed(feed_id=feed_id, session=s, user=None)
        assert out["status"] == "ok"
        assert out["inserted"] == 1
        feed = await s.get(ThreatIntelFeed, feed_id)
        assert feed.last_poll_status == "success"
        assert feed.last_poll_count == 1
        rows = (await s.execute(select(ThreatIoc))).scalars().all()
        assert rows and rows[0].ioc_value == "203.0.113.123"
