# -*- coding: utf-8 -*-
"""R16: 案例聚合边界 (P1-10)。

  1) event_ids 封顶 — 超 _MAX_EVENTS_PER_CASE 不再 append, metadata 打
     events_capped 标记, event_count 继续计数;
  2) 同 session 聚合时间窗 — 超窗(SESSION_CASE_WINDOW_MINUTES 无更新)不并入,
     新开案例;
  3) timeline 批查 — post_mortem._build_timeline 不再逐 id N+1。
"""
from __future__ import annotations

import os
import sys
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

os.environ.setdefault("SHARED_MEMORY_SKIP_DOTENV", "1")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import select  # noqa: E402


async def _fresh_tables():
    from models import Base, engine
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)


def _mk_event(i: int, session_id: str = "sess-1"):
    from models import SecurityEvent  # noqa: F811 — 延迟导入避免测试收集期建表
    return SecurityEvent(
        event_type="BRUTE_FORCE", severity="high", src_ip="9.9.9.9",
        dst_ip="10.0.0.1", message=f"ev-{i}", session_id=session_id,
        status="new",
    )


@pytest.mark.asyncio
async def test_event_ids_capped_at_limit():
    from case_manager import case_manager as cm, _MAX_EVENTS_PER_CASE
    from models import SecurityCase, async_session

    await _fresh_tables()
    async with async_session() as s:
        case = SecurityCase(case_number="CASE-T-CAP-1", title="t", status="open")
        s.add(case)
        await s.flush()

        # 注入上限 + 50 个事件
        for i in range(_MAX_EVENTS_PER_CASE + 50):
            evt = _mk_event(i)
            s.add(evt)
            await s.flush()
            evt.id  # assign
            await cm._add_event_to_case(s, case, evt)

        assert len(case.event_ids) == _MAX_EVENTS_PER_CASE, "event_ids 必须封顶"
        assert case.event_count == _MAX_EVENTS_PER_CASE + 50, "计数不受封顶影响"
        assert (case.metadata_ or {}).get("events_capped") is True, "必须打截断标记"


@pytest.mark.asyncio
async def test_session_aggregation_window(monkeypatch):
    """超窗的旧 session 案例不再吸收新事件 → 走新建分支。"""
    from case_manager import case_manager as cm, SESSION_CASE_WINDOW_MINUTES
    from models import SecurityCase, SecurityEvent, async_session

    await _fresh_tables()
    async with async_session() as s:
        stale = SecurityCase(case_number="CASE-T-STALE", title="old", status="open")
        stale.updated_at = datetime.now(timezone.utc) - timedelta(
            minutes=SESSION_CASE_WINDOW_MINUTES + 5)
        s.add(stale)
        await s.flush()

        found = await cm._find_active_case_by_session(s, "sess-stale")
        # 反查依赖事件挂 case_id — 造一条挂到 stale 的旧事件
        evt = SecurityEvent(
            event_type="BRUTE_FORCE", severity="high", src_ip="9.9.9.9",
            message="old", session_id="sess-stale", case_id=stale.id, status="new",
        )
        s.add(evt)
        await s.flush()

        found = await cm._find_active_case_by_session(s, "sess-stale")
        assert found is None, "超窗案例不得再吸收同 session 新事件"

        # 窗口内的活跃案例 → 正常并入
        fresh = SecurityCase(case_number="CASE-T-FRESH", title="new", status="open")
        s.add(fresh)
        await s.flush()
        evt2 = SecurityEvent(
            event_type="BRUTE_FORCE", severity="high", src_ip="9.9.9.9",
            message="new", session_id="sess-fresh", case_id=fresh.id, status="new",
        )
        s.add(evt2)
        await s.flush()
        found2 = await cm._find_active_case_by_session(s, "sess-fresh")
        assert found2 is not None and found2.id == fresh.id


@pytest.mark.asyncio
async def test_post_mortem_timeline_batch_query():
    """timeline 构建用 in_() 批查 — 100 事件案例只发 1 次事件 SELECT。"""
    from case_manager import case_manager as cm
    from models import SecurityCase, SecurityEvent, async_session
    from post_mortem_service import post_mortem_service as pm

    await _fresh_tables()
    async with async_session() as s:
        case = SecurityCase(case_number="CASE-T-TL", title="t", status="open")
        s.add(case)
        await s.flush()
        ids = []
        for i in range(100):
            evt = SecurityEvent(
                event_type="BRUTE_FORCE", severity="high", src_ip="9.9.9.9",
                message=f"m{i}", status="new", session_id=f"s-{i}",
            )
            s.add(evt)
            await s.flush()
            ids.append(evt.id)
        case.event_ids = ids
        await s.commit()

        queries = {"n": 0}

        def _count_before(conn, cursor, statement, parameters, context, executemany):
            if "security_events" in str(statement):
                queries["n"] += 1

        from sqlalchemy import event as sa_event
        sa_event.listen(s.bind.sync_engine, "before_cursor_execute", _count_before)
        try:
            timeline = await pm._build_timeline(s, case)
        finally:
            sa_event.remove(s.bind.sync_engine, "before_cursor_execute", _count_before)

        assert len(timeline) >= 100
        assert queries["n"] <= 2, f"事件 SELECT 应为批量(实测 {queries['n']} 次) — N+1 复发"
