# -*- coding: utf-8 -*-
"""containment_records 台账接线守卫(2026-10-25 审计 #4)。

insert_record 此前在生产代码中零调用方: 封禁成功与否 containment_records
都是 0 行。现在 block_ip 的 mock/live 成功路径必须入账,
dry_run/idempotent_skip 不入账; 回滚成功后状态翻 rolled_back。
"""
from unittest.mock import patch

import pytest


async def _create_tables():
    from models import Base, engine

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


@pytest.fixture()
def _mode():
    from config import settings

    old = settings.execution_mode
    yield settings
    settings.execution_mode = old


async def _rows_for(target_ip: str) -> list:
    from sqlalchemy import select

    from models import ContainmentRecord, async_session

    async with async_session() as session:
        rows = (await session.execute(
            select(ContainmentRecord).order_by(ContainmentRecord.id.desc())
        )).scalars().all()
        return [r for r in rows if r.target_id == target_ip]


@pytest.mark.asyncio
async def test_mock_block_ip_writes_containment_ledger(_mode):
    await _create_tables()
    _mode.execution_mode = "mock"
    from response_engine.response_registry import _block_ip

    result = await _block_ip("203.0.113.99", reason="pytest", duration_minutes=30)
    assert result.get("success") is True, result
    assert result.get("mode") == "mock", result

    rows = await _rows_for("203.0.113.99")
    assert rows, "mock block_ip 成功后 containment_records 必须有行"
    top = rows[0]
    assert top.action_name == "block_ip"
    assert top.status == "applied"
    assert top.expires_at is not None, "duration_minutes 必须换算成 expires_at"
    assert top.rollback_token, "rollback_token 必须写规则 ID, 供回滚对账"
    assert top.payload.get("rule_name")


@pytest.mark.asyncio
async def test_dry_run_block_ip_does_not_write_ledger(_mode):
    await _create_tables()
    _mode.execution_mode = "dry_run"
    from response_engine.response_registry import _block_ip

    result = await _block_ip("203.0.113.98", reason="pytest", duration_minutes=30)
    assert result.get("mode") == "dry_run", result
    assert await _rows_for("203.0.113.98") == [], "dry_run 预览什么都没执行, 不得入账"


@pytest.mark.asyncio
async def test_ttl_rollback_marks_containment_rolled_back(_mode):
    await _create_tables()
    _mode.execution_mode = "mock"
    from response_engine.response_registry import _block_ip, ttl_rollback

    await _block_ip("203.0.113.97", reason="pytest", duration_minutes=30)
    rows = await _rows_for("203.0.113.97")
    assert rows
    token = rows[0].rollback_token

    with patch("response_engine.ssh_firewall.ssh_firewall") as fw:
        fw.rollback.return_value = {"status": "success", "deleted": 1}
        out = await ttl_rollback(token, "block_ip", {})
    assert out["success"] is True, out

    rows2 = await _rows_for("203.0.113.97")
    assert rows2 and rows2[0].status == "rolled_back", rows2[0].status
