# -*- coding: utf-8 -*-
"""R12: demo 数据与真实检测/统计路径隔离。

四件套:
  1) IOC 隔离 — demo-seed 源的 IOC 不进 ioc_matcher 检测缓存(P1-6);
  2) KPI 可回滚 — _seed_kpi 不覆盖已有快照, 产出行打 demo_seed 标记,
     clear 按标记删除(P1-7);
  3) demo 路由按 SHARED_MEMORY_DEMO_MODE 开关挂载(P1-8);
  4) ingest 认证扶正 — 配置了数据源密钥后, 无 key 一律 401(倒挂修复)。
"""
from __future__ import annotations

import os
import sys
from datetime import datetime, timezone

import pytest

os.environ.setdefault("SHARED_MEMORY_SKIP_DOTENV", "1")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import select, func  # noqa: E402


async def _fresh_tables():
    from models import Base, engine
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)


# ── 1. IOC 隔离 ──

@pytest.mark.asyncio
async def test_demo_ioc_excluded_from_matching_cache():
    from models import ThreatIoc, async_session
    from threat_intel.ioc_matcher import ioc_matcher

    await _fresh_tables()
    async with async_session() as s:
        s.add(ThreatIoc(ioc_type="ip", ioc_value="23.129.64.33", threat_type="c2",
                        severity="critical", confidence=0.95, source="demo-seed",
                        is_active=True))
        s.add(ThreatIoc(ioc_type="ip", ioc_value="203.0.113.66", threat_type="c2",
                        severity="high", confidence=0.9, source="misp",
                        is_active=True))
        await s.commit()
        await ioc_matcher.refresh_cache(s)

    hit_demo = await ioc_matcher.match("23.129.64.33")
    assert not hit_demo, "demo-seed IOC 不得参与真实检测匹配"
    hit_real = await ioc_matcher.match("203.0.113.66")
    assert hit_real and hit_real[0].source == "misp"


# ── 2. KPI 隔离与回滚 ──

@pytest.mark.asyncio
async def test_kpi_seed_never_overwrites_existing_snapshots():
    from models import KpiSnapshot, async_session
    from routers.demo_seed import _seed_kpi, _KPI_DEMO_TAG

    await _fresh_tables()
    d = datetime.now(timezone.utc).date()

    # 预置一行"真实快照"
    async with async_session() as s:
        s.add(KpiSnapshot(snapshot_date=d, period="daily", metric_key="mttr",
                          metric_value=42.0, dimensions={}))
        await s.commit()

    async with async_session() as s:
        await _seed_kpi(s)
        await s.commit()

    async with async_session() as s:
        rows = (await s.execute(
            select(KpiSnapshot).where(KpiSnapshot.snapshot_date == d)
        )).scalars().all()
        real = [r for r in rows if not (r.dimensions or {}).get(_KPI_DEMO_TAG)]
        assert len(real) == 1 and real[0].metric_value == 42.0, \
            "真实快照必须原样保留(修复前被 upsert 覆盖)"


@pytest.mark.asyncio
async def test_kpi_seed_tags_and_clear_rolls_back():
    from models import KpiSnapshot, async_session
    from routers.demo_seed import _seed_kpi, _clear_kpi, _KPI_DEMO_TAG

    await _fresh_tables()
    async with async_session() as s:
        n = await _seed_kpi(s)
        await s.commit()
    if n == 0:
        pytest.skip("空库快照全部失败(无事件数据) — 隔离逻辑由上一用例覆盖")

    async with async_session() as s:
        total = (await s.execute(
            select(func.count()).select_from(KpiSnapshot))).scalar()
        tagged = (await s.execute(select(KpiSnapshot))).scalars().all()
        assert all((r.dimensions or {}).get(_KPI_DEMO_TAG) for r in tagged), \
            "demo 产出的快照行必须全部带标记"
        assert total == len(tagged)

        removed = await _clear_kpi(s)
        await s.commit()
        assert removed == total
        left = (await s.execute(
            select(func.count()).select_from(KpiSnapshot))).scalar()
        assert left == 0, "clear 后 demo 快照必须完全回滚"


# ── 3. demo_mode 路由开关 ──

def _openapi_paths(app_obj) -> set:
    """跨 FastAPI 版本的路由路径集合。

    FastAPI ≥0.16x 的 include_router 改为惰性 `_IncludedRouter` 包装,
    `app.routes` 里的条目**没有** `.path` 属性 —— 直接反射路由对象会
    两条用例一起失真(mounted 用例假红、gated 用例假绿, 2026-11-09 实测)。
    通过 openapi() 物化 schema 取 paths, 行为在任何版本都稳定。
    """
    return set(app_obj.openapi().get("paths", {}))


def test_demo_router_gated_by_config(monkeypatch):
    """demo_mode=False 时 /api/demo 不挂载。"""
    import importlib

    import config
    import app as app_mod
    monkeypatch.setattr(config.settings, "demo_mode", False)
    try:
        importlib.reload(app_mod)
        paths = _openapi_paths(app_mod.app)
        assert not any(p.startswith("/api/demo") for p in paths), \
            "demo_mode=false 时不得挂载 /api/demo/*"
    finally:
        # 用真实 settings 状态重载, 不给后续测试留全局态污染(P0-2 纪律)
        importlib.reload(app_mod)


def test_demo_router_mounted_when_enabled(monkeypatch):
    import importlib

    import config
    import app as app_mod
    monkeypatch.setattr(config.settings, "demo_mode", True)
    try:
        importlib.reload(app_mod)
        paths = _openapi_paths(app_mod.app)
        assert any(p.startswith("/api/demo") for p in paths)
    finally:
        importlib.reload(app_mod)


# ── 4. ingest 认证扶正 ──

def test_ingest_auth_matrix(monkeypatch):
    """{无key, 坏key} × {keys已配置, 未配置dev, 未配置prod} 的服务端判定。"""
    from fastapi import HTTPException
    from routers import logs as logs_mod

    class _Req:
        def __init__(self, key: str):
            self.headers = {"X-API-Key": key} if key else {}

    class _Registry:
        def __init__(self, keys):
            self._sources = keys

        def authenticate(self, k):
            return object() if k in self._sources else None

    # R17 纪律: 一律走 monkeypatch(自动还原), 不许裸赋值全局单例
    # keys 已配置: 无 key 401 / 坏 key 403
    monkeypatch.setattr(logs_mod, "source_registry", _Registry({"good-key"}))
    with pytest.raises(HTTPException) as e1:
        logs_mod._authenticate_source(_Req(""))
    assert e1.value.status_code == 401
    with pytest.raises(HTTPException) as e2:
        logs_mod._authenticate_source(_Req("bad"))
    assert e2.value.status_code == 403

    # 未配置 + dev: 匿名放行(演示兼容)
    monkeypatch.setattr(logs_mod, "source_registry", _Registry({}))
    assert logs_mod._authenticate_source(_Req("")) == ""

    # 未配置 + prod: 拒绝
    from config import settings
    monkeypatch.setattr(settings, "env_name", "prod")
    with pytest.raises(HTTPException) as e3:
        logs_mod._authenticate_source(_Req(""))
    assert e3.value.status_code == 401
