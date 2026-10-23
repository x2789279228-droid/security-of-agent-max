"""
Uncertain 遏制 × SecurityGuard 护栏语义回归

未知类型走「未知威胁保守遏制」(Uncertain) 后的预期行为:
  - severity≥high: send_alert + block_ip(5min) 均通过护栏, 自动执行 + AUTO_EXECUTED P1 工单
  - severity≤medium: IntentChecker 拦截 block_ip, 仅 send_alert + PENDING P1 工单
  - 自然语言事件名("C2 通信")经 orchestrator 兜底链推断为 C2_BEACON,
    命中 C2 专属自动封禁策略(priority=100)而非 Uncertain

验证层级: 真实策略引擎 + 真实 SecurityGuard, 仅 mock 底层动作执行器。
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import models  # noqa: F401

from response_engine.response_executor import (
    ActionResult,
    BatchActionResult,
    response_executor,
)
from response_engine.human_approval import ApprovalStatus, approval_queue
from response_engine.response_orchestrator import response_orchestrator
from response_engine.response_policies import UNCERTAIN_POLICY_NAME, policy_engine
from security_guard.security_guard import security_guard


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


async def _reset():
    from models import Base, engine
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)


def _patch_executor(calls: list):
    """替换底层动作执行器(护栏仍真实运行), 记录通过审查的动作名列表。"""
    async def fake_execute(actions, threat_info, **kw):
        calls.append([a.get("name", "") for a in actions])
        return BatchActionResult(
            total=len(actions), succeeded=len(actions), failed=0,
            results=[
                ActionResult(action_name=a.get("name", ""), success=True)
                for a in actions
            ],
            batch_rollback_token="tok_guard_test",
        )

    response_executor.execute_actions = fake_execute

    def restore():
        try:
            del response_executor.execute_actions
        except AttributeError:
            pass

    return restore


async def _trigger(info: dict):
    from models import async_session
    async with async_session() as s:
        return await response_orchestrator.on_threat_detected(s, info)


def test_high_severity_uncertain_executes_block_ip():
    """高危未知威胁走 Uncertain: block_ip(5min) 通过护栏自动执行 + P1 工单。"""
    async def t():
        await _reset()
        security_guard.reset()
        policy_engine.clear_cooldowns()
        approval_queue._tickets.clear()
        calls = []
        restore = _patch_executor(calls)
        try:
            result = await _trigger({
                "threat_type": "SOME_UNKNOWN_THREAT",
                "confidence": 0.9, "severity": "high",
                "src_ip": "10.8.1.1", "session_id": "sess-guard-1",
            })
        finally:
            restore()
        assert result["matched"]
        assert result["match_status"] == "uncertain"
        assert result["policy_name"] == UNCERTAIN_POLICY_NAME
        assert len(calls) == 1
        assert set(calls[0]) == {"send_alert", "block_ip"}, \
            "high 级别下 send_alert 与 block_ip 均应通过护栏"
        assert result["actions_executed"] == 2
        ticket = approval_queue.get_ticket(result["approval_ticket_id"])
        assert ticket is not None
        assert ticket.priority == "p1"
        assert ticket.status == ApprovalStatus.AUTO_EXECUTED
    _run(t())


def test_medium_severity_uncertain_only_alerts():
    """中危未知威胁走 Uncertain: block_ip 被 IntentChecker 拦截, 仅发告警 + PENDING P1。"""
    async def t():
        await _reset()
        security_guard.reset()
        policy_engine.clear_cooldowns()
        approval_queue._tickets.clear()
        calls = []
        restore = _patch_executor(calls)
        try:
            result = await _trigger({
                "threat_type": "SOME_UNKNOWN_THREAT",
                "confidence": 0.9, "severity": "medium",
                "src_ip": "10.8.1.2", "session_id": "sess-guard-2",
            })
        finally:
            restore()
        assert result["matched"]
        assert result["match_status"] == "uncertain"
        assert len(calls) == 1
        assert calls[0] == ["send_alert"], \
            "medium 级别下 block_ip 应被护栏拦截, 仅 send_alert 执行"
        ticket = approval_queue.get_ticket(result["approval_ticket_id"])
        assert ticket.status == ApprovalStatus.PENDING
        assert ticket.priority == "p1"
    _run(t())


def test_natural_language_name_hits_c2_policy():
    """自然语言事件名兜底推断: "C2 通信" → C2_BEACON → 命中 C2 专属封禁策略。

    2026-10-03 修正断言。
      原断言是 `calls[0][0] == "block_ip"`，即"策略命中后立即自动执行封禁"。
      之所以一直通过，是因为 conftest 此前**没有**固定 RESPONSE_POLICIES_DIR，
      而开发者 `.env` 里该变量指向 /data/response_policies（Linux 容器路径），
      导致 YAML 策略加载失败、回退到**代码内置兜底策略**——那条策略没有审批要求，
      于是 block_ip 被"自动执行"。

      也就是说：**这条测试一直在验证降级路径，从未验证真实策略。**

      指针向仓库内真实 policies 目录后，YAML 策略 POL-C2-BEACON 生效，而
      response_registry.needs_approval() 对 block_ip 这类破坏性动作一律返回 True，
      因此真实行为是"生成审批工单、人工确认后才执行"，而不是自动封禁。

      注意策略文件自身是矛盾的：name 叫「C2通信自动封禁」，但同时写着
      `auto_execute: false` 与 `require_approval: false`。若确实期望自动封禁，
      需要给 needs_approval() 增加策略级豁免，而不是靠回退到兜底策略。
      见 docs/AUDIT-2026-10-03-非安全类优化点.md。
    """
    async def t():
        await _reset()
        security_guard.reset()
        policy_engine.clear_cooldowns()
        calls = []
        restore = _patch_executor(calls)
        try:
            result = await _trigger({
                "threat_type": "", "event": "C2 通信",
                "confidence": 0.85, "severity": "high",
                "src_ip": "10.8.1.3", "session_id": "sess-guard-3",
            })
        finally:
            restore()
        # 1) 自然语言兜底推断能命中 C2 专属策略（这部分原断言是对的，予以保留）
        assert result["matched"]
        assert result["match_status"] == "matched"
        assert result["policy_name"] == "C2通信自动封禁", \
            "推断出的 C2_BEACON 应命中专属策略而非 Uncertain"
        # 2) 真实策略下，破坏性动作走审批而非直接执行
        assert calls == [], \
            "含 block_ip 的策略不应在无审批时直接执行（needs_approval 恒为 True）"
        ticket = approval_queue.get_ticket(result["approval_ticket_id"])
        assert ticket is not None, "应生成审批工单"
        assert ticket.status == ApprovalStatus.PENDING
    _run(t())
