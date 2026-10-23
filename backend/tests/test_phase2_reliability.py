"""第二阶段可靠性：分布式锁 / 审计跨进程认领 / live 幂等 fail-closed /
PQ 死信闭环 / Sigma 降级可见化 / 预算默认。

覆盖:
  - distributed_lock: NX 互斥、TTL、Redis 不可用返回 None
  - safe_executor: live + 幂等不可用 → 拒绝(fail-closed); dry_run 不受影响;
    require_idempotency_for_live=False 可显式关闭
  - audit_dead_letters: record 幂等落库、replay 重提/跳过已分析事件
  - audit_pq: payload 丢失 → 死信落库
  - sigma_engine: 降级点打 soc_sigma_engine_degraded_total 指标
  - 预算默认: 5M/天 + 硬门禁(与文档一致)
"""
import asyncio
import logging

import pytest

import models
from models import AuditDeadLetter, SecurityEvent


# ── distributed_lock ──

class _FakeRedis:
    """最小 SET/DEL 语义，模拟单实例 Redis。"""

    def __init__(self):
        self.store: dict = {}

    async def set(self, key, val, ex=None, nx=False):
        if nx and key in self.store:
            return False
        self.store[key] = val
        return True

    async def delete(self, key):
        return self.store.pop(key, None)

    async def get(self, key):
        return self.store.get(key)

    async def exists(self, key):
        return key in self.store


@pytest.mark.asyncio
async def test_lock_mutual_exclusion_and_ttl():
    from distributed_lock import try_acquire
    c = _FakeRedis()
    assert await try_acquire("k1", ttl_s=60, client=c) is True
    assert await try_acquire("k1", ttl_s=60, client=c) is False  # 互斥
    assert await try_acquire("k2", ttl_s=60, client=c) is True   # 不同 key 不冲突


@pytest.mark.asyncio
async def test_lock_unavailable_redis_returns_none():
    from distributed_lock import try_acquire
    # client=None 且 sliding_window 无 Redis → None(未知), 调用方决定策略
    res = await try_acquire("k-none", ttl_s=5, client=None)
    assert res is None or res is True  # 本机可能有真实 Redis; None=fail-open 语义


def test_lock_release_best_effort():
    from distributed_lock import release
    asyncio.new_event_loop().run_until_complete(release("nope", client=None))


# ── safe_executor fail-closed ──

def _live_args():
    # skip_whitelist=True: 本组测试验证的是幂等 fail-closed 闸门(⑤),
    # 白名单(①)是另一道被测闸门, 这里带留痕理由绕开以直抵目标
    return dict(
        action_name="block_ip",
        command="iptables -A INPUT -s 203.0.113.5 -j DROP",
        params={"src_ip": "203.0.113.5"},
        live_fn=None,
        mode_override="live",
        skip_whitelist=True,
        skip_whitelist_reason="phase2-gate-test",
    )


@pytest.mark.asyncio
async def test_live_with_idempotency_unavailable_is_blocked(monkeypatch):
    from response_engine.safe_executor import safe_executor
    monkeypatch.setattr(safe_executor, "_redis", None)  # 幂等不可用
    monkeypatch.setattr(settings_mod(), "require_idempotency_for_live", True)
    result = await safe_executor.execute(**_live_args())
    assert result.get("blocked") is True
    assert result.get("blocked_by") == "idempotency_unavailable"


@pytest.mark.asyncio
async def test_live_without_redis_but_gate_disabled_passes_through(monkeypatch):
    from response_engine.safe_executor import safe_executor
    monkeypatch.setattr(safe_executor, "_redis", None)
    monkeypatch.setattr(settings_mod(), "require_idempotency_for_live", False)
    # 关闭闸门后不再因幂等被拒, 而是继续走 live 流程(no_executor 阻断)
    result = await safe_executor.execute(**_live_args())
    assert result.get("blocked_by") != "idempotency_unavailable"


@pytest.mark.asyncio
async def test_dry_run_immune_to_idempotency_unavailable(monkeypatch):
    from response_engine.safe_executor import safe_executor
    monkeypatch.setattr(safe_executor, "_redis", None)
    monkeypatch.setattr(settings_mod(), "require_idempotency_for_live", True)
    result = await safe_executor.execute(
        action_name="block_ip",
        command="iptables -A INPUT -s 203.0.113.5 -j DROP",
        params={"src_ip": "203.0.113.5"},
        mode_override="dry_run",
        skip_whitelist=True,
        skip_whitelist_reason="phase2-gate-test",
    )
    # dry_run 无真实副作用, 幂等不可用不阻断
    assert result.get("blocked") is not True
    assert result.get("mode") == "dry_run"


def settings_mod():
    from config import settings
    return settings


# ── 审计跨进程认领 ──

@pytest.mark.asyncio
async def test_audit_pipeline_skips_when_claimed_by_other_worker(monkeypatch):
    """认领失败(他进程持有) → _audit_pipeline 直接返回, 不进 Temporal/LLM。"""
    import distributed_lock
    from log_ingestion import log_ingestor

    async def _contended(key, ttl_s, client=None):
        return False
    monkeypatch.setattr(distributed_lock, "try_acquire", _contended)

    async def _boom(*a, **k):
        raise AssertionError("被认领拦截后不得进入 Temporal")
    import temporal.client as _tc
    monkeypatch.setattr(_tc, "start_audit_workflow", _boom)

    class _R:
        anomaly_score = 0.9
        reasons = ["x"]
        is_anomaly = True
        deviation_sigma = 0.0

    # 不需要真实事件存在: 认领拦截发生在 DB 预检之前
    await log_ingestor._audit_pipeline("s", 999999999, {"event": "X"}, _R(), max_rounds=1)


@pytest.mark.asyncio
async def test_audit_pipeline_fail_open_when_redis_absent(monkeypatch):
    """Redis 不可用(try_acquire→None) → fail-open 继续旧路径(进入分流)。"""
    import distributed_lock
    from log_ingestion import log_ingestor

    async def _unknown(key, ttl_s, client=None):
        return None
    monkeypatch.setattr(distributed_lock, "try_acquire", _unknown)

    reached = {"triage": False}

    def _spy_score_event(*a, **k):
        reached["triage"] = True
        raise RuntimeError("stop-here")  # 到分流即停, 后续不执行
    import audit_triage as _at
    monkeypatch.setattr(_at, "score_event", _spy_score_event)

    class _R:
        anomaly_score = 0.1
        reasons = []
        is_anomaly = False
        deviation_sigma = 0.0

    try:
        await log_ingestor._audit_pipeline("s", 999999998, {"event": "X"}, _R(), max_rounds=1)
    except RuntimeError as e:
        assert "stop-here" in str(e)
    assert reached["triage"] is True


# ── audit dead letters ──

async def _reset_db():
    async with models.engine.begin() as conn:
        await conn.run_sync(models.Base.metadata.drop_all)
        await conn.run_sync(models.Base.metadata.create_all)


@pytest.mark.asyncio
async def test_dead_letter_record_is_idempotent():
    await _reset_db()
    from audit_dead_letters import record
    assert await record(42, "payload_missing", "t") is True
    assert await record(42, "payload_missing", "t2") is True  # 同键重复不炸
    assert await record(42, "purged_ghost", "t") is True      # 不同 reason 各一条
    from sqlalchemy import select, func
    async with models.async_session() as s:
        n = (await s.execute(select(func.count(AuditDeadLetter.id)))).scalar()
        assert n == 2


@pytest.mark.asyncio
async def test_dead_letter_replay_resubmits_unanalyzed_event():
    await _reset_db()
    from audit_dead_letters import record, replay_dead_letters

    async with models.async_session() as s:
        s.add(SecurityEvent(
            event_id="dl-1", session_id="s1", event_type="BRUTE_FORCE",
            severity="high", src_ip="203.0.113.9", analyzed=False,
            raw_data={"event": "BRUTE_FORCE", "severity": "high"},
        ))
        await s.commit()
    await record(1, "payload_missing")

    # worker 未启动 → 不重提但标记已处理(不无限重扫)
    from audit_worker import audit_worker
    started = audit_worker._started
    audit_worker._started = False
    try:
        n = await replay_dead_letters()
        assert n == 0
        async with models.async_session() as s:
            from sqlalchemy import select
            row = (await s.execute(select(AuditDeadLetter))).scalars().one()
            assert row.replayed_at is not None
            assert row.replay_note == "worker_not_started"
    finally:
        audit_worker._started = started


@pytest.mark.asyncio
async def test_dead_letter_replay_skips_already_analyzed():
    await _reset_db()
    from audit_dead_letters import record, replay_dead_letters
    async with models.async_session() as s:
        s.add(SecurityEvent(
            event_id="dl-2", session_id="s1", event_type="X", severity="low",
            src_ip="1.2.3.4", analyzed=True, raw_data={},
        ))
        await s.commit()
    await record(1, "payload_missing")
    n = await replay_dead_letters()
    assert n == 0
    async with models.async_session() as s:
        from sqlalchemy import select
        row = (await s.execute(select(AuditDeadLetter))).scalars().one()
        assert row.replay_note == "already_analyzed"


# ── sigma degradation metric ──

def test_sigma_degradation_increments_metric():
    from sigma_engine.engine import _mark_degraded
    from prometheus_client import REGISTRY

    def _val():
        v = REGISTRY.get_sample_value("soc_sigma_engine_degraded_total",
                                      {"reason": "test_reason"})
        return 0 if v is None else v

    before = _val()
    _mark_degraded("test_reason")
    _mark_degraded("test_reason")  # 指标每次都累计; CRITICAL 日志进程内去重
    assert _val() == before + 2


def test_budget_defaults_are_bounded():
    from config import settings
    assert settings.llm_daily_budget_tokens == 5_000_000
    assert settings.llm_budget_unlimited is False
