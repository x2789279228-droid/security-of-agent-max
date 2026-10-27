# -*- coding: utf-8 -*-
"""回滚断链修复回归（PERF-2026-10-26 Wave 0-1）。

修复前两个缺陷（docs/benchmark/PERF-2026-10-26.md「封禁链路的可用性缺口」）：
  1. `execute_actions` 落库**未注入 src_ip 的原始 params** → 策略批次
     （params 只有 duration_minutes/severity）批量回滚时 `_unblock_ip()`
     缺必填参 TypeError → iptables 规则永远删不掉，封禁只能等 TTL；
  2. 批次必含的 `send_alert` 是 reversible=False 无回滚函数 → 被计成
     **failed** 而非 skipped → rollback 恒报 failed>0，且幂等标记
     （mark_rolled 依赖 failed==0）永不执行。

本文件钉住修复后的三个不变量：
  I1 回滚记录存**执行时有效 params**（含注入的 src_ip）→ 可回滚；
  I2 不可逆动作计 skipped 不计 failed，且批次正常打幂等标记；
  I3 block_ip 结果中的 firewall_rule_id 提取进回滚记录（冗余保险）。
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ.setdefault("SHARED_MEMORY_DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("SHARED_MEMORY_JWT_SECRET", "test-secret")
os.environ.setdefault("SHARED_MEMORY_LLM_API_KEY", "test")
os.environ.setdefault("SHARED_MEMORY_EMBEDDING_API_KEY", "test")
os.environ.setdefault("SHARED_MEMORY_ADMIN_PASSWORD", "test")

import pytest

from response_engine.response_executor import (
    ResponseExecutor,
    rollback_store,
)
from response_engine.response_registry import response_registry


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


ROLLBACK_SEEN: list[dict] = []


async def _fake_block_exec(**kwargs):
    # 模拟 block_ip 经 SafeExecutor 的返回形态（含 firewall_rule_id）。
    # 刻意挂在**真实动作名** "block_ip" 下 —— 威胁上下文注入按动作名分派
    # （"block_ip"/"send_alert"...），假名字走不进注入分支，测不出断链。
    return {
        "action": "block_ip", "success": True, "mode": "stub",
        "src_ip": kwargs.get("src_ip", ""),
        "firewall_rule_id": "FW-RULE-0000004242",
    }


async def _fake_block_rollback(**kwargs):
    ROLLBACK_SEEN.append(dict(kwargs))
    return {"action": "block_ip", "success": True, "deleted": 1}


async def _fake_alert_exec(**kwargs):
    return {"action": "send_alert", "success": True, "mode": "stub"}


@pytest.fixture
def fake_actions():
    """注册假动作并在 teardown 精确还原（与 test_rollback_idempotent 同纪律）。"""
    reg = response_registry
    before = (dict(reg._actions), dict(reg._exec_fns), dict(reg._rollback_fns))
    # 覆盖真实动作名（注入分派按名字走），teardown 精确还原
    reg.register(
        "block_ip", _fake_block_exec, description="test only",
        severity="low", rollback_fn=_fake_block_rollback,
    )
    # 不可逆动作：与真实 send_alert 同规格（无 rollback_fn, reversible=False）
    reg.register(
        "send_alert", _fake_alert_exec, description="test only",
        severity="low", reversible=False,
    )
    ROLLBACK_SEEN.clear()
    try:
        yield reg
    finally:
        reg._actions.clear()
        reg._actions.update(before[0])
        reg._exec_fns.clear()
        reg._exec_fns.update(before[1])
        reg._rollback_fns.clear()
        reg._rollback_fns.update(before[2])


def _reset_store():
    rollback_store._store.clear()
    rollback_store._rolled.clear()
    rollback_store.set_redis(None)


class TestEffectiveParamsRecorded:
    def test_policy_style_batch_rollback_uses_injected_src_ip(self, fake_actions):
        """I1：策略批次 params 不含 src_ip（靠威胁上下文注入）→ 回滚必须拿到它。

        修复前：回滚记录存原始 params → 逆向回滚缺 src_ip → TypeError → failed。
        """
        _reset_store()
        ex = ResponseExecutor()
        actions = [
            {"name": "block_ip", "params": {"duration_minutes": 3}},
            {"name": "send_alert", "params": {"severity": "high"}},
        ]
        threat = {"src_ip": "203.0.113.66", "threat_type": "brute_force",
                  "confidence": 0.9}
        batch = _run(ex.execute_actions(actions, threat_info=threat))
        assert batch.succeeded == 2

        rb = _run(ex.rollback_batch(batch.batch_rollback_token))
        assert rb.failed == 0, f"回滚失败: {[r.error for r in rb.results]}"
        assert rb.succeeded == 1
        # 注入后的有效 params 必须到达回滚函数
        assert ROLLBACK_SEEN, "block_ip 的回滚函数未被调用"
        assert ROLLBACK_SEEN[0].get("src_ip") == "203.0.113.66"

    def test_rollback_record_keeps_rule_id(self, fake_actions):
        """I3：firewall_rule_id 提取进回滚记录（定向删除的冗余保险）。"""
        _reset_store()
        ex = ResponseExecutor()
        batch = _run(ex.execute_actions(
            [{"name": "block_ip", "params": {"src_ip": "198.51.100.9"}}],
            threat_info=None,
        ))
        records = _run(rollback_store.get(batch.batch_rollback_token))
        assert records[0]["rule_id"] == "FW-RULE-0000004242"


class TestNonReversibleSkipped:
    def test_send_alert_style_action_is_skipped_not_failed(self, fake_actions):
        """I2：不可逆动作回滚 = skipped（成功计数、幂等标记正常打上）。"""
        _reset_store()
        ex = ResponseExecutor()
        batch = _run(ex.execute_actions([
            {"name": "block_ip", "params": {"src_ip": "198.51.100.10"}},
            {"name": "send_alert", "params": {"severity": "high"}},
        ]))
        rb = _run(ex.rollback_batch(batch.batch_rollback_token))
        assert rb.failed == 0, (
            "不可逆动作不得计 failed —— 修复前含 send_alert 的批次恒 failed>0"
        )
        assert rb.skipped == 1
        # 幂等标记依赖 failed==0 —— skipped 不得再阻塞它
        assert _run(rollback_store.is_rolled(batch.batch_rollback_token)) is True

    def test_skipped_batch_replay_is_idempotent(self, fake_actions):
        """I2（续）：含 skipped 的批次第二次回滚走幂等短路，不重复执行。"""
        _reset_store()
        ex = ResponseExecutor()
        batch = _run(ex.execute_actions([
            {"name": "block_ip", "params": {"src_ip": "198.51.100.11"}},
            {"name": "send_alert", "params": {}},
        ]))
        rb1 = _run(ex.rollback_batch(batch.batch_rollback_token))
        assert rb1.failed == 0 and rb1.skipped == 1
        seen_after_first = len(ROLLBACK_SEEN)
        rb2 = _run(ex.rollback_batch(batch.batch_rollback_token))
        assert rb2.failed == 0
        assert all(r.idempotent for r in rb2.results), "重放应全走幂等短路"
        assert len(ROLLBACK_SEEN) == seen_after_first, "重放不得再次执行回滚"
