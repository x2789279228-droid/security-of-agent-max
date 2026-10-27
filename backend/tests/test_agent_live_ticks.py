# -*- coding: utf-8 -*-
"""agent_tick 实况事件(A1 多智能体实况面板)——逐工具/逐块完成推送回归。

钉住四个不变量:
  T1 build_tool_tick_step 的 step_id 与 emit_tool_result 落库批次完全一致
     —— 前端 mergeSteps 按 step_id 去重,tick 先到、阶段末批次后到,无缝合并;
  T2 publish_tick 走 agent_tick 类型,且 event_bus 对该类型**不合并**
     (coalesce_key 返回 None → bulk 逐条送达;agent_thought 同键只留最新);
  T3 _execute_parallel 仅在 emit_ticks=True 时发工具 tick ——
     tools_only/rule_close 车道占审计大头(PERF 实测 ~76%),
     逐工具 tick 会以百条/秒刷爆 SSE,必须闸在 LLM 车道;
  T4 _audit_chunks_parallel 逐块完成即发 tick,异常块发 error tick
     且不改变原有"保守兜底 ChunkVerdict"语义。
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

from event_bus import EventBus
from trace_hook import clear_trace_context, set_trace_context


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


@pytest.fixture
def tick_ctx():
    """给定 trace 上下文(event_id/round),收尾清理;返回已发布的 tick 列表。"""
    from event_bus import event_bus as global_bus

    set_trace_context(
        caller="audit_pipeline", event_id=4242, session_id="sess-tick", round=2,
    )
    seen: list[tuple[str, dict]] = []
    original = global_bus.publish
    global_bus.publish = lambda t, d, **kw: seen.append((t, dict(d)))
    try:
        yield seen
    finally:
        global_bus.publish = original
        clear_trace_context()


class TestStepIdCompat:
    def test_tool_tick_step_id_matches_persisted_batch(self, tick_ctx):
        """T1: 与 emit_tool_result 的 step_id 逐字一致。"""
        from observability.thought_events import build_tool_tick_step, emit_tool_result

        tick = build_tool_tick_step(
            "event_store.query", success=True, duration_ms=12.3,
        )
        batch = emit_tool_result("event_store.query", success=True, duration_ms=12.3)
        assert tick is not None and batch
        assert tick["step_id"] == batch[0]["step_id"]
        assert tick["step_id"] == "e4242-r2-executor-tool-event_store-query"

    def test_chunk_tick_uses_chunk_kind_and_id(self, tick_ctx):
        from observability.thought_events import build_chunk_tick_step

        step = build_chunk_tick_step(
            "c1", index=1, total=3, threat_detected=True, confidence=0.87,
            severity="high", label="IP 10.0.0.5 的15条事件",
        )
        assert step["step_id"] == "e4242-r2-executor-chunk-c1"
        assert step["kind"] == "chunk"
        assert step["status"] == "success"
        assert step["metrics"]["chunk_index"] == 1
        assert step["metrics"]["chunk_total"] == 3

    def test_publish_tick_goes_out_as_agent_tick(self, tick_ctx):
        """T2a: publish_tick → event_bus.publish("agent_tick", 载荷)。"""
        from observability.thought_events import build_tool_tick_step, publish_tick

        publish_tick(build_tool_tick_step("correlation.chains", duration_ms=5.0))
        assert len(tick_ctx) == 1
        evt_type, payload = tick_ctx[0]
        assert evt_type == "agent_tick"
        assert payload["step_id"] == "e4242-r2-executor-tool-correlation-chains"
        assert payload["event_id"] == 4242

    def test_agent_tick_is_not_coalesced(self):
        """T2b: 同键连发两条 agent_tick,订阅者必须收到两条
        (对照:agent_thought 同键只留最新)。"""
        bus = EventBus(max_subscribers=2)
        sub = bus.subscribe()
        bus.publish("agent_tick", {"step_id": "t1", "title": "工具A"})
        bus.publish("agent_tick", {"step_id": "t2", "title": "工具B"})
        assert sub.qsize() == 2
        bus.publish("agent_thought", {"event_id": 1})
        bus.publish("agent_thought", {"event_id": 1})
        assert sub.qsize() == 3  # 第二条 agent_thought 被 key 合并
        bus.unsubscribe(sub)

    def test_tick_without_event_context_is_dropped(self):
        """无 trace 上下文(如单测直调)→ 缺 event_id → 静默丢弃。"""
        from observability.thought_events import build_tool_tick_step

        clear_trace_context()
        assert build_tool_tick_step("event_store.query") is None


class TestExecutorTicks:
    def _fake_registry(self, monkeypatch, fail_tool=""):
        import contextlib

        from agents import agent_executor as ex

        async def fake_execute(tool, **kwargs):
            if tool == fail_tool:
                raise RuntimeError("boom")
            return {"rows": 1}
        monkeypatch.setattr(ex.tool_registry, "execute", fake_execute)

        # _execute_parallel 会打开全局 models 引擎的真实连接 —— 连接池的
        # asyncio 原语绑定到本测试的一次性事件循环, 泄漏给后续测试
        # (asyncio.locks bound to a different event loop)。工具桩不用
        # session, 直接给个假会话工厂隔离。
        @contextlib.asynccontextmanager
        async def fake_session():
            yield None
        monkeypatch.setattr("models.async_session", fake_session)
        return ex

    def test_tool_ticks_emitted_only_when_gated_on(self, monkeypatch, tick_ctx):
        """T3: emit_ticks=True 发 tick;False(规则车道)一条不发。"""
        from audit_types import ToolCall

        ex = self._fake_registry(monkeypatch)
        calls = [ToolCall(call_id=f"c{i}", task_id=f"t{i}",
                          tool=f"tool_{i}", args={}) for i in range(3)]
        ex.executor._run = None  # 占位,防误读
        _run(ex.executor._execute_parallel(calls, session=None, emit_ticks=True))
        tool_ticks = [d for t, d in tick_ctx if t == "agent_tick"
                      and d.get("kind") == "tool"]
        assert len(tool_ticks) == 3

        tick_ctx.clear()
        _run(ex.executor._execute_parallel(calls, session=None, emit_ticks=False))
        assert [d for t, d in tick_ctx if t == "agent_tick"] == []

    def test_failed_tool_tick_marks_error(self, monkeypatch, tick_ctx):
        from audit_types import ToolCall

        ex = self._fake_registry(monkeypatch, fail_tool="tool_1")
        calls = [ToolCall(call_id="c0", task_id="t0", tool="tool_1", args={})]
        _run(ex.executor._execute_parallel(calls, session=None, emit_ticks=True))
        # 注: 工具执行还会经 mcp_guard 遥测发一条 agent_thought(同 step_id,
        # 被 bulk 车道按 event_id 合并)—— 这是既有双通道, tick 过滤后单独计数
        ticks = [d for t, d in tick_ctx if t == "agent_tick"]
        assert len(ticks) == 1
        assert ticks[0]["status"] == "error"

    def test_chunk_ticks_progressive_with_error_fallback(self, monkeypatch, tick_ctx):
        """T4: 两块(一成一败)→ 2 条 tick;失败块 status=error,
        且收集循环仍产出保守兜底 ChunkVerdict(原语义不变)。"""
        from agents import agent_executor as ex
        from agents.chunker import AuditChunk

        chunks = [
            AuditChunk(chunk_id="c0", strategy="manual", label="块0", events=[{"id": 1}]),
            AuditChunk(chunk_id="c1", strategy="manual", label="块1", events=[{"id": 2}]),
        ]

        async def fake_audit(chunk, knowledge_chunks=None):
            if chunk.chunk_id == "c1":
                raise RuntimeError("llm down")
            class _V:
                threat_detected = True
                confidence = 0.9
                severity = "high"
                summary = "块0发现威胁"
                alert = ""
                unsubstantiated = False
                hallucination_risk = 0.1
                all_event_ids_in_chunk = [1]
                schema_valid = True
                schema_errors = []
                suspicious_entities = []
                grounding_score = 0.95
            return _V()

        monkeypatch.setattr(ex.sub_auditor, "audit", fake_audit)
        verdicts = _run(ex.executor._audit_chunks_parallel(chunks))
        assert len(verdicts) == 2
        # 失败块仍走保守兜底(原语义)
        assert verdicts[1].schema_valid is False
        assert verdicts[1].hallucination_risk == 1.0

        ticks = {d["chunk_id"]: d for t, d in tick_ctx if t == "agent_tick"
                 and d.get("kind") == "chunk"}
        assert set(ticks) == {"c0", "c1"}
        assert ticks["c0"]["status"] == "success"
        assert ticks["c1"]["status"] == "error"
