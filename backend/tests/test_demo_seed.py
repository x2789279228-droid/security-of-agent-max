# -*- coding: utf-8 -*-
"""demo_seed 演示数据供给守卫(2026-10-26)。

契约(backend/routers/demo_seed.py):
- 所有行打 demo-seed 标记(各表借既有标注列: source / sensor_id /
  correlation_key / case_number 前缀 / created_by);
- 幂等: 同表已有标记行则跳过, 不重复灌;
- 可清空: clear 只删标记行(含关联复盘/工单/反馈), 绝不触碰真实数据;
- 未知场景 → 400;
- status 逐表报标记行计数。

守护的是"演示数据不能污染真实数据"这条边界: clear 若误删真实行,
演示环境一灌就把真实数据洗掉了 —— 不可逆, 所以用例直接对真实行断言。

已知缺陷(见本文件末尾 xfail 用例):
models.py 把 SandboxTask 的四个 list 型 JSON 列
(mitre_techniques / network_iocs / file_iocs / process_tree) 声明成了
MutableJSON(= MutableDict, 只收 dict), 而 demo_seed 传的是 list
→ ValueError: Attribute 'mitre_techniques' does not accept objects of type list
→ POST /api/demo/seed 整个 500。仓库在 ThreatIoc.tags 上修过同一类问题
(见 models.py "tags 是数组"注释), 这四列漏了。
按要求不改产品代码, 这里用 xfail(strict=True) 把缺陷钉住:
缺陷修好后该用例会 XPASS(strict) 报错, 提醒摘掉标记。
"""
import pytest
from fastapi import HTTPException
from sqlalchemy import func, select

from models import (
    Base,
    EdrEvent,
    NetworkFlow,
    SandboxTask,
    SecurityCase,
    ThreatIoc,
    TlsSession,
    async_session,
    engine,
)

MARKER = "demo-seed"


class _User:
    """路由的 user 只用于鉴权依赖, 函数体不读它。"""

    username = "pytest-admin"
    role = "admin"


async def _create_tables() -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def _count(model, filter_) -> int:
    async with async_session() as session:
        r = await session.execute(select(func.count()).select_from(model).where(filter_))
        return int(r.scalar() or 0)


async def _reset() -> None:
    """清掉标记行 —— 幂等断言必须从干净状态起步。"""
    from routers.demo_seed import demo_seed_clear

    await _create_tables()
    async with async_session() as session:
        await demo_seed_clear(session, _User())


async def _seed(scene: str = "ops") -> dict:
    from routers.demo_seed import SeedBody, demo_seed

    async with async_session() as session:
        return await demo_seed(SeedBody(scene=scene), session, _User())


@pytest.mark.asyncio
async def test_unknown_scene_rejected():
    """未知场景必须 400 —— 拼错 scene 时静默灌空会让人以为灌成功了。"""
    from routers.demo_seed import SeedBody, demo_seed

    await _reset()
    async with async_session() as session:
        with pytest.raises(HTTPException) as exc:
            await demo_seed(SeedBody(scene="not-a-scene"), session, _User())
    assert exc.value.status_code == 400
    assert "not-a-scene" in str(exc.value.detail)


@pytest.mark.asyncio
async def test_seed_ops_is_idempotent():
    """第二次灌必须全部 skipped 且行数不变 —— 重复灌会把演示数据翻倍。"""
    from routers.demo_seed import _case_filter

    await _reset()
    first = await _seed("ops")
    assert first["seeded"], first
    assert not first["skipped"], first
    assert first["marker"] == MARKER

    cases_after_first = await _count(SecurityCase, _case_filter())
    assert cases_after_first > 0

    second = await _seed("ops")
    assert not second["seeded"], second
    assert "security_cases" in second["skipped"], second
    assert await _count(SecurityCase, _case_filter()) == cases_after_first


@pytest.mark.asyncio
async def test_seeded_rows_carry_marker_in_expected_columns():
    """标记行必须落在约定的列上 —— clear 靠这些列定位, 列错位就删不掉。"""
    from routers.demo_seed import _case_filter

    await _reset()
    seeded = await _seed("ops")
    assert seeded["seeded"], seeded
    assert await _count(SecurityCase, _case_filter()) > 0, "案卷必须用 CASE-DEMO-* 前缀"

    async with async_session() as session:
        cases = (await session.execute(select(SecurityCase))).scalars().all()
    demo_cases = [c for c in cases if c.case_number.startswith("CASE-DEMO-")]
    assert demo_cases, "demo 案卷的 case_number 必须以 CASE-DEMO- 开头"
    assert all(MARKER in (c.tags or []) for c in demo_cases), "demo 案卷必须打 tags=demo-seed 标记"


@pytest.mark.asyncio
async def test_clear_removes_only_marked_rows():
    """clear 只能删标记行: 真实数据必须原样保留(误删不可逆)。"""
    from routers.demo_seed import _case_filter, _ioc_filter

    await _reset()
    real_value = "203.0.113.77"
    async with async_session() as session:
        # 一行真实 IOC(非标记) + 一行标记 IOC(手工插: sensing 场景当前被
        # SandboxTask 的 list 列缺陷挡住, 不能依赖播种路径来产生它)
        session.add(ThreatIoc(
            ioc_type="ip", ioc_value=real_value, source="misp",
            threat_type="c2", severity="high",
        ))
        session.add(ThreatIoc(
            ioc_type="domain", ioc_value="demo-seed.example", source=MARKER,
            threat_type="c2", severity="high",
        ))
        await session.commit()

    seeded = await _seed("ops")
    assert seeded["seeded"], seeded
    assert await _count(SecurityCase, _case_filter()) > 0
    assert await _count(ThreatIoc, _ioc_filter()) == 1

    from routers.demo_seed import demo_seed_clear

    async with async_session() as session:
        cleared = await demo_seed_clear(session, _User())
    assert cleared["marker"] == MARKER
    assert cleared["deleted"]["security_cases"] > 0, cleared
    assert cleared["deleted"]["threat_iocs"] == 1, cleared

    assert await _count(SecurityCase, _case_filter()) == 0, "标记行必须被清掉"
    assert await _count(ThreatIoc, _ioc_filter()) == 0, "标记 IOC 必须被清掉"
    async with async_session() as session:
        survivor = (await session.execute(
            select(ThreatIoc).where(ThreatIoc.ioc_value == real_value)
        )).scalars().first()
    assert survivor is not None, "clear 绝不能删真实数据行"
    assert survivor.source == "misp"


@pytest.mark.asyncio
async def test_status_reports_marker_counts_and_clears_to_zero():
    """status 逐表报标记行计数, clear 后归零 —— 演示页据此显示"已灌入/已清空"。"""
    from routers.demo_seed import (
        _case_filter,
        _edr_filter,
        _flow_filter,
        _ioc_filter,
        _sandbox_filter,
        _tls_filter,
        demo_seed_status,
    )

    await _reset()
    await _seed("ops")

    async with async_session() as session:
        st = await demo_seed_status(session, _User())
    assert st["marker"] == MARKER
    assert st["security_cases"] == await _count(SecurityCase, _case_filter())
    assert st["edr_events"] == await _count(EdrEvent, _edr_filter())
    assert st["threat_iocs"] == await _count(ThreatIoc, _ioc_filter())
    assert st["sandbox_tasks"] == await _count(SandboxTask, _sandbox_filter())
    assert st["network_flows"] == await _count(NetworkFlow, _flow_filter())
    assert st["tls_sessions"] == await _count(TlsSession, _tls_filter())
    assert st["security_cases"] > 0

    await _reset()
    async with async_session() as session:
        st2 = await demo_seed_status(session, _User())
    assert st2["security_cases"] == 0
    assert st2["edr_events"] == 0
    assert st2["threat_iocs"] == 0


@pytest.mark.xfail(
    strict=True,
    reason=(
        "已知缺陷: SandboxTask 的 mitre_techniques/network_iocs/file_iocs/process_tree "
        "是 list 型 JSON 列却声明成 MutableJSON(只收 dict) → demo_seed 传 list 时 "
        "ValueError → POST /api/demo/seed 500。修好 models.py 后本用例会 XPASS(strict)。"
    ),
)
@pytest.mark.asyncio
async def test_seed_sensing_scene_succeeds():
    """sensing 场景必须能灌进去 —— 演示页"一键灌入"走的就是它。"""
    from routers.demo_seed import _edr_filter, _ioc_filter

    await _reset()
    seeded = await _seed("sensing")
    assert seeded["seeded"], seeded
    assert await _count(ThreatIoc, _ioc_filter()) > 0
    assert await _count(EdrEvent, _edr_filter()) > 0
