# -*- coding: utf-8 -*-
"""响应动作的**审计**失败必须**可见**（整改报告 §9.55）。

## 背景

响应动作的审计有三处静默失败：

| 位置 | 旧行为 | 后果 |
|---|---|---|
| `log_threat` 写失败 | `logger.warning` → 吞 | 动作照常发生，但「谁触发的」在审计里**没有** |
| `log_action` 写失败 | `logger.warning` → 吞 | 动作执行了，审计里**没有**这条 |
| `query_logs` 查失败 | `return []` | 运维看到**空列表** = 「**没有响应动作记录**」，而真相是「**查不出来**」 |

第三条是**假阴性**：它让「读不到审计」被读成「没做过处置」。

## 本守卫盯什么

1. **写侧**：失败 → 返回 `False`（调用方能知道）+ 计数 + 不再只留 warning；
2. **读侧**：失败 → **上抛**（端点转 503），**不得**返回空列表；
3. **反向判据**：成功路径**行为不变**（写入返回 True、查询照常返回记录）；
4. **计数**：三种失败都可数。
"""
from __future__ import annotations

import asyncio
import importlib
import os
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND))

import pytest  # noqa: E402


class _BoomSession:
    """任何写/读都失败的会话（模拟 DB 故障）。"""

    def add(self, *a, **k):
        return None

    async def commit(self, *a, **k):
        raise RuntimeError("db down")

    async def execute(self, *a, **k):
        raise RuntimeError("db down")


def _logger():
    return importlib.import_module("response_engine.response_log").response_logger


def _count(phase: str):
    from prometheus_client import REGISTRY
    # ⚠ Prometheus 的 label 样本是**懒创建**的：某档还没发生过失败时取不到样本 → 按 0 算
    v = REGISTRY.get_sample_value(
        "soc_response_audit_failed_total", {"phase": phase})
    return 0 if v is None else v


async def _reset_db():
    """⚠ 测试本身已在事件循环里 → 这里必须 await，**不能**用 asyncio.run。"""
    from models import Base, engine
    async with engine.connect() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)


class TestTheWriteSideReportsFailure:
    @pytest.mark.asyncio
    async def test_log_action_returns_false_on_failure(self):
        before = _count("action")
        ok = await _logger().log_action(
            session=_BoomSession(), session_id="s", event_id=1,
            threat_info={}, action_name="block_ip", action_params={},
            success=True, result={}, rollback_token="", auto_execute=True,
        )
        assert ok is False, "写失败必须返回 False，而不是静默 None"
        assert _count("action") == before + 1, "写失败没有被计数"

    @pytest.mark.asyncio
    async def test_log_threat_returns_false_on_failure(self):
        before = _count("threat")
        ok = await _logger().log_threat(
            session=_BoomSession(), threat_info={}, policy_name="p",
            actions=[], auto_execute=True, needs_approval=False,
            match_status="", skip_reason="", category="",
        )
        assert ok is False, "写失败必须返回 False"
        assert _count("threat") == before + 1, "写失败没有被计数"

    @pytest.mark.asyncio
    async def test_a_successful_write_returns_true(self):
        """**反向判据**：成功路径行为不变。"""
        await _reset_db()
        from models import async_session
        async with async_session() as session:
            ok = await _logger().log_action(
                session=session, session_id="s", event_id=1,
                threat_info={}, action_name="block_ip", action_params={},
                success=True, result={}, rollback_token="", auto_execute=True,
            )
        assert ok is True, "成功写入必须返回 True"


class TestTheReadSideDoesNotFakeAnEmptyResult:
    @pytest.mark.asyncio
    async def test_query_logs_raises_instead_of_returning_empty(self):
        before = _count("query")
        with pytest.raises(Exception):
            await _logger().query_logs(session=_BoomSession())
        assert _count("query") == before + 1, "查询失败没有被计数"

    @pytest.mark.asyncio
    async def test_a_successful_query_still_returns_the_rows(self):
        """**反向判据**：成功路径行为不变。"""
        await _reset_db()
        from models import async_session
        async with async_session() as session:
            await _logger().log_action(
                session=session, session_id="s", event_id=1,
                threat_info={"threat_type": "C2_BEACON"}, action_name="block_ip",
                action_params={}, success=True, result={}, rollback_token="",
                auto_execute=True,
            )
        async with async_session() as session:
            rows = await _logger().query_logs(session=session)
        assert len(rows) == 1, f"成功查询应返回 1 条，实际 {len(rows)}"
        assert rows[0].action_name == "block_ip", rows[0]

    @pytest.mark.asyncio
    async def test_the_endpoint_turns_the_failure_into_503(self, monkeypatch):
        """端点必须把查询失败变成 **503**（明确「查不出来」），而不是 200 + []。"""
        from fastapi import HTTPException
        routers = importlib.import_module("routers.response")

        async def _boom(*a, **k):
            raise RuntimeError("db down")

        monkeypatch.setattr(routers.response_logger, "query_logs", _boom)
        with pytest.raises(HTTPException) as exc:
            await routers.query_response_logs(
                session_id="", threat_type="", src_ip="", limit=10,
                session=_BoomSession(), user=None,
            )
        assert exc.value.status_code == 503, exc.value.status_code
        assert "审计" in str(exc.value.detail), exc.value.detail


if __name__ == "__main__":       # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
