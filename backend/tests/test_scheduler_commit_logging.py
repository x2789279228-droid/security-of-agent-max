# -*- coding: utf-8 -*-
"""R4: scheduler 案例收口路径 commit 失败必须留痕。

修复前: `except Exception: pass` 后照打"已 breach N 条 / 已 auto-closed N 条"
—— commit 失败与成功在日志上同形, SLA 标记与自动关案可能长期静默不生效。

本测试: 让 session.commit 抛异常, 断言
  1) ERROR 级日志出现且含"commit 失败";
  2) 不向上抛(调度循环不被打断);
  3) rollback 被调用;
  4) "成功"口径日志不再出现。
"""
from __future__ import annotations

import os
import sys
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest

os.environ.setdefault("SHARED_MEMORY_SKIP_DOTENV", "1")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class _Row:
    """SecurityCase 替身: 待 breach 的活跃案例。"""

    id = "case-1"
    status = "open"
    sla_breached = False
    sla_deadline = datetime(2026, 1, 1, tzinfo=timezone.utc)
    closed_at = None
    updated_at = datetime(2025, 1, 1, tzinfo=timezone.utc)


def _make_session(commit_raises: bool):
    s = AsyncMock()
    if commit_raises:
        s.commit.side_effect = RuntimeError("db gone")
    # await session.execute(...) 的返回值走同步链 .scalars().all() —
    # 必须是 MagicMock(AsyncMock 的属性调用会产生协程)。
    result = MagicMock()
    result.scalars.return_value.all.return_value = [_Row()]
    s.execute.return_value = result
    return s


@pytest.mark.asyncio
async def test_sla_breach_commit_failure_logs_error(monkeypatch, caplog):
    import scheduler as _sched_mod

    async def _zero(session, now=0):
        return 0

    async def _noop_update(session, case_id, status, by=None):
        return None

    async def _no_pending(session, case):
        return False

    monkeypatch.setattr("case_manager.case_manager.auto_resolve_idle_cases", _zero)
    monkeypatch.setattr("case_manager.case_manager.has_pending_approval", _no_pending)
    monkeypatch.setattr("case_manager.case_manager.update_status", _noop_update)

    import logging
    with caplog.at_level(logging.ERROR, logger="scheduler"):
        session = _make_session(commit_raises=True)
        # 不应抛出 — 调度循环存活
        await _sched_mod.scheduler._run_case_sla_once(session, datetime.now(timezone.utc))

    assert session.rollback.await_count >= 1
    err_texts = [r.getMessage() for r in caplog.records if r.levelno == logging.ERROR]
    assert any("commit 失败" in t for t in err_texts), f"缺少 ERROR 留痕: {err_texts}"
    # 假成功口径不再出现
    warn_texts = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert not any("breached SLA" in t for t in warn_texts)


@pytest.mark.asyncio
async def test_sla_breach_success_path_still_logs(monkeypatch, caplog):
    """commit 成功时保留原有 warning 口径(不破坏既有观测)。"""
    import scheduler as _sched_mod

    async def _zero(session, now=0):
        return 0

    async def _noop_update(session, case_id, status, by=None):
        return None

    async def _no_pending(session, case):
        return False

    monkeypatch.setattr("case_manager.case_manager.auto_resolve_idle_cases", _zero)
    monkeypatch.setattr("case_manager.case_manager.has_pending_approval", _no_pending)
    monkeypatch.setattr("case_manager.case_manager.update_status", _noop_update)

    import logging
    with caplog.at_level(logging.WARNING, logger="scheduler"):
        session = _make_session(commit_raises=False)
        await _sched_mod.scheduler._run_case_sla_once(session, datetime.now(timezone.utc))

    warn_texts = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
    assert any("breached SLA" in t for t in warn_texts)


@pytest.mark.asyncio
async def test_close_stale_resolved_commit_failure_returns_zero(monkeypatch, caplog):
    """自动关案 commit 失败 → 返回 0(不虚报关闭数)且 ERROR 留痕。"""
    import scheduler as _sched_mod

    monkeypatch.setattr("config.settings.case_auto_close_hours", 24, raising=False)

    async def _noop_update(session, case_id, status, by=None):
        return None

    monkeypatch.setattr("case_manager.case_manager.update_status", _noop_update)

    import logging
    with caplog.at_level(logging.ERROR, logger="scheduler"):
        session = _make_session(commit_raises=True)
        now = datetime.now(timezone.utc)
        n = await _sched_mod.scheduler._close_stale_resolved(session, now)

    assert n == 0
    assert session.rollback.await_count >= 1
    err_texts = [r.getMessage() for r in caplog.records if r.levelno == logging.ERROR]
    assert any("commit 失败" in t for t in err_texts)
