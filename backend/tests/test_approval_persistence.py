"""审批工单持久化（2026-10-23 第一阶段止血）

修复前的缺陷: ApprovalQueue 是纯进程内存 dict, 后端重启即丢全部
PENDING 高危操作工单 —— 提交方等不到批准, 审批人看不到待办。

覆盖:
  - submit/approve/reject 异步落库 (approval_tickets 表)
  - 新队列实例 restore() 把 PENDING 工单拉回内存, 且 HMAC 签名仍可验
  - 已过期工单 restore 时置 EXPIRED, 不进入待办
  - 终态(Approved/Rejected)不重复进入待办
  - 未注入 session factory 时维持纯内存行为 (向后兼容)
"""
import asyncio
import time

import pytest
from sqlalchemy import func, select

import models
from models import ApprovalTicketRecord
from response_engine.human_approval import ApprovalQueue, ApprovalStatus


async def _reset_db():
    async with models.engine.begin() as conn:
        await conn.run_sync(models.Base.metadata.drop_all)
        await conn.run_sync(models.Base.metadata.create_all)


def _submit(q: ApprovalQueue, tid_prefix: str = "t") -> object:
    return q.submit(
        threat_info={"threat_type": "BRUTE_FORCE", "src_ip": "203.0.113.9"},
        policy_name="brute-force-isolate",
        actions=[{"name": "isolate_host", "params": {"host": "203.0.113.9"}}],
        timeout_minutes=15,
        priority="p1",
    )


@pytest.mark.asyncio
async def test_submit_persists_and_restore_recovers_pending():
    await _reset_db()
    q1 = ApprovalQueue()
    q1.set_session_factory(models.async_session)

    ticket = _submit(q1)
    await q1.drain_persistence()

    async with models.async_session() as s:
        n = (await s.execute(select(func.count(ApprovalTicketRecord.id)))).scalar()
        assert n == 1

    # 模拟进程重启: 全新队列实例从 DB 恢复
    q2 = ApprovalQueue()
    q2.set_session_factory(models.async_session)
    restored = await q2.restore()
    assert restored == 1

    pending = q2.list_pending()
    assert len(pending) == 1
    t = pending[0]
    assert t.id == ticket.id
    assert t.policy_name == ticket.policy_name
    assert t.actions == ticket.actions
    assert t.priority == "p1"
    assert t.sig == ticket.sig

    # 恢复下来的工单必须能走完整审批链 (HMAC 重验)
    ok = q2.approve(t.id, "admin2")
    assert ok is not None and ok.status == ApprovalStatus.APPROVED
    await q2.drain_persistence()

    async with models.async_session() as s:
        rec = await s.get(ApprovalTicketRecord, t.id)
        assert rec.status == ApprovalStatus.APPROVED.value
        assert rec.approved_by == "admin2"


@pytest.mark.asyncio
async def test_expired_ticket_is_not_restored_and_marked_expired():
    await _reset_db()
    q1 = ApprovalQueue()
    q1.set_session_factory(models.async_session)
    q1.submit(
        threat_info={"threat_type": "X"}, policy_name="p",
        actions=[{"name": "noop"}], timeout_minutes=-1,  # 立即过期
    )
    await q1.drain_persistence()

    q2 = ApprovalQueue()
    q2.set_session_factory(models.async_session)
    restored = await q2.restore()
    assert restored == 0
    assert q2.list_pending() == []

    async with models.async_session() as s:
        rec = (await s.execute(select(ApprovalTicketRecord))).scalars().one()
        assert rec.status == ApprovalStatus.EXPIRED.value


@pytest.mark.asyncio
async def test_terminal_tickets_stay_terminal_after_restore():
    await _reset_db()
    q1 = ApprovalQueue()
    q1.set_session_factory(models.async_session)
    t_ok = _submit(q1)
    q1.approve(t_ok.id, "admin")
    t_rej = _submit(q1)
    q1.reject(t_rej.id, "too risky", rejected_by="admin")
    await q1.drain_persistence()

    q2 = ApprovalQueue()
    q2.set_session_factory(models.async_session)
    restored = await q2.restore()
    assert restored == 0
    # 终态工单仍可从 DB 审计
    async with models.async_session() as s:
        rows = (await s.execute(select(ApprovalTicketRecord))).scalars().all()
        assert {r.status for r in rows} == {
            ApprovalStatus.APPROVED.value, ApprovalStatus.REJECTED.value,
        }


@pytest.mark.asyncio
async def test_cleanup_db_removes_only_old_terminal_rows():
    await _reset_db()
    q = ApprovalQueue()
    q.set_session_factory(models.async_session)
    t1 = _submit(q)
    q.approve(t1.id, "admin")
    t2 = _submit(q)  # 保持 PENDING
    await q.drain_persistence()

    # 0 小时保留期: 终态立即清除, PENDING 保留
    removed = await q.cleanup_db(max_age_hours=0)
    assert removed == 1
    async with models.async_session() as s:
        rows = (await s.execute(select(ApprovalTicketRecord))).scalars().all()
        assert [r.id for r in rows] == [t2.id]


def test_no_session_factory_keeps_in_memory_only():
    """未注入 session factory(旧测试/纯内存场景)不落库也不报错。"""
    q = ApprovalQueue()
    t = q.submit(
        threat_info={}, policy_name="p", actions=[{"name": "noop"}],
    )
    assert t.id in {x.id for x in q.list_pending()}
    # _persist_async 无事件循环/session 时静默跳过, 不产生任务
    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(q.drain_persistence())
    finally:
        loop.close()


def test_global_singleton_defaults_to_memory_only():
    """全局单例默认无 session factory —— 测试环境互不影响; lifespan 负责接线。"""
    from response_engine.human_approval import approval_queue
    if approval_queue._session_factory is None:
        # 未接线时 restore/cleanup_db 是 no-op, submit 只进内存
        t = approval_queue.submit(threat_info={}, policy_name="wiring-probe",
                                  actions=[{"name": "noop"}])
        assert t.id in {x.id for x in approval_queue.list_pending()}
        approval_queue._tickets.pop(t.id, None)  # 不污染其它测试
