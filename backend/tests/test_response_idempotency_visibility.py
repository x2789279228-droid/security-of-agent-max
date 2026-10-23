# -*- coding: utf-8 -*-
"""幂等检查「**没查成**」必须与「查了、确实没重复」分开记（整改报告 §9.52）。

## 背景

`SafeExecutor` 的检查链第 ④ 步是「幂等检查 (Redis)」。修复前它只返回 bool，
于是这两种情形**返回同一个值** `False`：

* 「查了，Redis 里没有这条 → 不是重复」；
* 「**根本没查成**」—— Redis 未配置（`self._redis is None`）或调用出错。

审计里写的是 `{"hit": False}` → **看不出这道检查当时有没有跑**。

而同一个事务的**另一侧**（回滚幂等，`RollbackStore`）是
「**内存为主、Redis 兜底**」→ 同一故障下保护仍在，
**执行侧**却是纯 Redis → 保护**整体消失**（Kafka 重放会重复执行动作）。

本守卫盯什么：

1. **没查成** → 审计必须写 `state="unavailable"`（不是「查了、没重复」）；
2. **查了** → `state="evaluated"`，命中就跳过、没命中就执行；
3. **标记是否写成功**也要如实记（写不成功 ⇒ 下次重放不会被拦）；
4. **计数**：`unavailable` 要能被单独数出来；
5. **前提守卫**：回滚侧在 Redis 不可用时**仍有**保护（内存兜底），
   执行侧没有 —— 这个**不对称**必须被看见（待决项 34）。

⚠ 本守卫**不改变拦截行为**（Redis 不可用时动作照常执行，与修复前一致）。
「执行侧要不要补内存兜底」属**收紧型**改动 → 待决项 34。
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND))

import pytest  # noqa: E402

CMD = ("iptables -I INPUT -s 10.0.0.5 -j DROP "
       "-m comment --comment 'FW-RULE-11111'")


@pytest.fixture(autouse=True)
def _force_live_mode():
    """本文件验证的是 live 执行链；默认值已改为 dry_run，必须显式开启。"""
    from response_engine.execution_modes import execution_router, MODE_LIVE
    old = execution_router.mode
    execution_router.mode = MODE_LIVE
    try:
        yield
    finally:
        execution_router.mode = old


class _FakeRedis:
    def __init__(self, exists_result: int = 0,
                 raise_on_exists: bool = False,
                 raise_on_set: bool = False):
        self.exists_result = exists_result
        self.raise_on_exists = raise_on_exists
        self.raise_on_set = raise_on_set
        self.sets: list = []

    async def exists(self, key):
        if self.raise_on_exists:
            raise RuntimeError("redis down")
        return self.exists_result

    async def set(self, key, value, ex=None):
        if self.raise_on_set:
            raise RuntimeError("redis write failed")
        self.sets.append(key)
        return True


async def _live_fn(cmd):
    return {"success": True, "stdout": "", "stderr": "", "returncode": 0}


def _executor(redis_client=None):
    from response_engine.safe_executor import SafeExecutor
    from response_engine.execution_modes import execution_router, MODE_LIVE
    se = SafeExecutor()
    se.initialize()
    # initialize() 会按 settings.execution_mode 复位；本文件验证 live 链。
    execution_router.mode = MODE_LIVE
    if redis_client is not None:
        se.set_redis(redis_client)
    return se


async def _run(redis_client=None, params=None):
    se = _executor(redis_client)
    return await se.execute(
        action_name="block_ip", command=CMD,
        params=params or {"src_ip": "10.0.0.5"},
        platform="linux", live_fn=_live_fn,
    )


@pytest.mark.asyncio
class TestTheUnavailableStateMustNotLookLikeACleanCheck:
    async def test_without_redis_the_audit_says_unavailable(self):
        """Redis 未配置 → 幂等检查**没跑** → 审计必须如实写。"""
        result = await _run(redis_client=None)
        idem = result["audit"]["checks"]["idempotency"]
        assert idem["state"] == "unavailable", idem
        assert idem["hit"] is False, idem
        assert idem.get("reason"), "必须说明为什么没评估"

    async def test_a_redis_error_says_unavailable(self):
        """Redis 报错 → 同样算「没跑成」。"""
        result = await _run(redis_client=_FakeRedis(raise_on_exists=True))
        idem = result["audit"]["checks"]["idempotency"]
        assert idem["state"] == "unavailable", idem
        assert idem.get("reason"), idem

    async def test_the_action_still_executes(self):
        """**反向判据**：诚实性改动的本意不变 —— gate 关闭(测试默认)时仍执行。

        2026-10-23 第二阶段补充生产契约: gate 开启(require_idempotency_for_live=true)
        时 live + 幂等不可用 → fail-closed 拒绝(见 test_phase2_reliability)。
        """
        result = await _run(redis_client=None)
        assert result.get("success") is True, result


@pytest.mark.asyncio
class TestTheEvaluatedState:
    async def test_a_redis_hit_is_evaluated_and_skips(self):
        result = await _run(redis_client=_FakeRedis(exists_result=1))
        idem = result["audit"]["checks"]["idempotency"]
        assert idem["state"] == "evaluated", idem
        assert idem["hit"] is True, idem
        assert result.get("mode") == "idempotent_skip", result

    async def test_a_redis_miss_is_evaluated_and_executes(self):
        result = await _run(redis_client=_FakeRedis(exists_result=0))
        idem = result["audit"]["checks"]["idempotency"]
        assert idem["state"] == "evaluated", idem
        assert idem["hit"] is False, idem
        assert result.get("success") is True, result


@pytest.mark.asyncio
class TestTheMarkResultIsRecorded:
    async def test_a_failed_mark_is_recorded(self):
        """标记写不成功 ⇒ 下一次重放不会被幂等拦下（必须如实写）。"""
        result = await _run(redis_client=_FakeRedis(raise_on_set=True))
        idem = result["audit"]["checks"]["idempotency"]
        assert idem.get("marked") is False, idem
        assert idem.get("mark_reason"), idem

    async def test_a_successful_mark_is_recorded(self):
        fake = _FakeRedis()
        result = await _run(redis_client=fake)
        idem = result["audit"]["checks"]["idempotency"]
        assert idem.get("marked") is True, idem
        assert fake.sets, "标记没写出去"


@pytest.mark.asyncio
class TestTheCounter:
    async def test_the_unavailable_state_is_counted(self):
        from prometheus_client import REGISTRY

        def _val(state):
            return REGISTRY.get_sample_value(
                "soc_response_idempotency_check_total", {"state": state})

        before = _val("unavailable")
        assert before is not None, "指标没被注册"
        await _run(redis_client=None)
        assert _val("unavailable") == before + 1, (
            f"unavailable 没有被计数：{before} → {_val('unavailable')}")


class TestTheAsymmetryIsVisible:
    def test_the_rollback_side_keeps_its_protection_without_redis(self):
        """**前提守卫**：同一事务的两侧，Redis 不可用时**不对称**。

        * 回滚侧 `RollbackStore`：**内存为主、Redis 兜底** → 没有 Redis
          也记得「这批已回滚过」；
        * 执行侧 `SafeExecutor._idempotency_check`：**纯 Redis** → 没有 Redis
          就**完全没有**幂等保护（审计里现在会如实写 `unavailable`）。

        这条不对称是**待决项 34** 的事实依据。
        """
        import asyncio

        from response_engine.response_executor import rollback_store

        async def scenario():
            store = rollback_store
            store._redis = None
            store._rolled.clear()
            try:
                await store.mark_rolled("tok-probe")
                assert await store.is_rolled("tok-probe") is True, (
                    "回滚侧连内存兜底都没有了 —— 前提变了")
            finally:
                store._rolled.discard("tok-probe")

            se = _executor(redis_client=None)
            hit, state = await se._idempotency_check(
                "block_ip", {"src_ip": "10.0.0.5"}, "")
            assert state == "unavailable", (hit, state)

        asyncio.run(scenario())
