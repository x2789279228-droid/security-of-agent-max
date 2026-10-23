"""
验收 · 第五组：Executor 预算 / 并发 / 终止状态（9 场景）→ 门槛 B + C + D

规范原文（§二.5）：
  · 「LLM 调用次数必须被真实记账，而不是估算」
  · 「并发必须有上限、超时和明确的取消语义」
  · 「未完成的分析不得被归类为 false_positive」
  · 「终止状态必须互斥且可审计：completed / budget_exhausted / security_denied」

本组全部实际执行：
  · 账目：真实驱动 executor.execute()，把 summary.llm.chat 的**真实调用次数**
    与 llm_calls_made / llm_calls_planned 对账 —— 不是读字段自证。
  · 并发：注册一个会自计数的慢工具，真实并发发起 N 次 tool_registry.execute，
    用工具内部观测到的峰值并发与闸的 inflight 交叉核对。
  · 超时：注册 timeout_ms 很小且真的 sleep 的工具。
  · 取消：真的 cancel 掉 gather 的宿主 task。
  · 终止状态：真值表 + 端到端。
"""
import asyncio

import pytest

from quality_scoring import BudgetLedger, budget_for
from veto_gates import (
    TERMINAL_BUDGET_EXHAUSTED,
    TERMINAL_COMPLETED,
    TERMINAL_SECURITY_DENIED,
    classify_terminal_state,
)


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


# ══════════════════════════════════════════════════════════════
# G5-S1 · hop 账目必须与真实 LLM 调用对得上
# ══════════════════════════════════════════════════════════════

def _drive_executor(monkeypatch, *, n_chunks=1, depth="deep"):
    """真实驱动 executor.execute，返回 (result, 真实 chat 调用次数)。

    **不**替换 sub_auditor：桩掉它就等于把「每个 chunk 一次 SubAuditor
    LLM 调用」这一跳从账目里抹掉，量出来的差值就是我自造的。
    计数点放在 ``summary.llm.chat`` 上 —— 它是全链路的单一 LLM 出口。

    夹具复用**已人工标注为 grounded 的** eval_datasets.grounding_cases 样本
    （clean_c2_beacon 的那条），而不是自己编事件。理由：断言引用的 ID 必须
    真在块内、引文必须真出现在原文里、威胁类型要与事件名一致，否则 grounding
    失败会触发 hop 早停，deep 三跳（kb/deep/recheck）根本不执行 ——
    那样量到的「账目 = 真实调用数」只是在早停路径上自洽，毫无意义。
    """
    from agents import agent_executor as ex
    from audit_types import ToolCall
    from eval_datasets.grounding_cases import C2_BEACON

    calls = {"n": 0}

    async def fake_chat(messages, **kw):
        calls["n"] += 1
        return json_text()

    monkeypatch.setattr(ex.summary.llm, "chat", fake_chat)

    chunks = [
        ex.AuditChunk(chunk_id=f"c{i}", strategy="manual", label="ip",
                      events=[dict(C2_BEACON)])
        for i in range(n_chunks)
    ]
    monkeypatch.setattr(ex.chunker, "chunk",
                        lambda events, chain_event_ids=None: chunks)

    res = _run(ex.executor.execute(
        tool_calls=[ToolCall(call_id="c0", task_id="t0",
                             tool="llm.deep_analyze", args={})],
        depth=depth,
        raw_event=dict(C2_BEACON),
    ))
    return res, calls["n"]


def json_text() -> str:
    """一份同时满足 SubAuditor / Synthesis / Reviewer 三种输出契约的合法响应。

    键取三者并集：sub_auditor 与 synthesis 读 threat_detected/threat_claims/
    confidence/severity/summary，reviewer 读 conclusion/reasoning。
    evidence_ids / evidence_quotes 与 grounding_cases.C2_BEACON 对齐
    （标注为 grounded 的 clean_c2_beacon 样本）。
    """
    import json
    return json.dumps({
        "threat_detected": True,
        "threat_type": "C2_BEACON",
        "confidence": 0.9,
        "severity": "high",
        "summary": "检测到周期性外连",
        "threat_claims": [{
            "type": "C2", "confidence": 0.85,
            "evidence_ids": [2],
            "evidence_quotes": ["outbound beacon to 203.0.113.45 every 60s"],
            "severity": "high",
            "summary": "主机 10.0.0.5 周期性向 203.0.113.45 外连，疑似 C2",
        }],
        "affected_entities": {},
        "suggested_actions": [],
        "evidence_summary": "证据来自事件原文",
        "abstain": False,
        "conclusion": "confirmed",
        "reasoning": "存在周期性外连",
    }, ensure_ascii=False)


class TestHopAccounting:
    def test_s0_fixture_really_runs_the_deep_path(self, monkeypatch):
        """前置校验：本组的账目用例必须跑在 **deep 全路径** 上。

        若 grounding 失败触发 hop 早停，kb/deep/recheck 三跳不会执行，
        后面两条「账目 = 真实调用数」就只是在早停路径上自洽。
        这条先钉住前提，否则结论会被一个失效的夹具架空。
        """
        res, actual = _drive_executor(monkeypatch, n_chunks=1, depth="deep")
        assert res.terminal_state == "completed", \
            f"deep 路径未正常完成: {res.terminal_state}/{res.terminal_reason}"
        assert res.llm_calls_planned == 1 + 1 + 3
        assert res.llm_calls_made > 1 + 1, (
            f"deep 三跳被早停跳过了（made={res.llm_calls_made}），"
            "本组其余账目断言失去意义"
        )
        assert actual > 1 + 1

    # ── 验收发现 G5-F1：llm_calls_made 记的是「跳数」，不是「调用数」 ──
    # 实测（deep 全路径，planned=5）：
    #   · 知识库检索失败（本环境 pgvector 不可用）时 kb 一跳**一次 LLM 都没发**，
    #     但 executor 无条件 += 1 → made=4 / 实际=3（**多记**）
    #   · 知识库有命中时，evidence_verifier 对**每条断言**各发一次 LLM，
    #     整跳仍只 += 1 → made=5 / 实际=6（**少记**）
    # 也就是说这个字段与「实际 LLM 调用次数」在两个方向上都会脱钩。
    # 影响面：hop_stats.llm_calls_skipped → hop 预算早停判据；
    # 真实用量以 summary_compression.LLMClient.http_request_stats() 为准。
    @pytest.mark.xfail(
        strict=True, raises=AssertionError,
        reason="验收发现 G5-F1：llm_calls_made 是跳数计数器，与真实 LLM 调用数双向脱钩",
    )
    def test_s1_made_equals_actual_llm_invocations(self, monkeypatch):
        """G5-S1：llm_calls_made 必须等于真实发生的 LLM 调用次数。

        deep 档计划 = chunk 数 + 1(synthesize) + 3(kb/deep/recheck)。
        """
        res, actual = _drive_executor(monkeypatch, n_chunks=1, depth="deep")
        assert res.llm_calls_planned == 1 + 1 + 3, \
            f"计划数口径不符: {res.llm_calls_planned}"
        assert res.llm_calls_made == actual, (
            f"账目说 {res.llm_calls_made} 次，真实发生 {actual} 次 "
            f"(planned={res.llm_calls_planned}, terminal={res.terminal_state})"
        )

    def test_s1b_plan_arithmetic_and_hop_stats_are_consistent(self):
        """正对照：**计划**侧的口径是对的，且 hop 账目在「跳」这个粒度上自洽。

        有了这条，G5-F1 才不会被读成「整个 hop 账目都是坏的」。
        """
        from veto_gates import HopStats, hop_stats_from_verdicts

        led = budget_for(chunks=1, llm_calls_planned=5, llm_calls_made=3)
        assert led.hop_budget == 5
        assert led.llm_calls_skipped == 2

        stats = HopStats(llm_calls_planned=5, llm_calls_made=3)
        assert stats.llm_calls_planned == 5
        assert stats.llm_calls_made == 3
        assert callable(hop_stats_from_verdicts)

    def test_s2_non_deep_plan_has_no_deep_hops(self, monkeypatch):
        """正对照：standard 档不加 deep 三跳，计划数相应减少。"""
        res, actual = _drive_executor(monkeypatch, n_chunks=1, depth="standard")
        assert res.llm_calls_planned == 1 + 1, f"计划数口径不符: {res.llm_calls_planned}"
        assert res.llm_calls_made == actual, (
            f"standard 档账目说 {res.llm_calls_made} 次，真实发生 {actual} 次"
        )

    @pytest.mark.xfail(
        strict=True, raises=AssertionError,
        reason="验收发现 G5-F1：知识库有命中时 kb 一跳会发多次 LLM，账目只记 1 次",
    )
    def test_s3_kb_hop_counts_every_verification_call(self, monkeypatch):
        """G5-S1 专项：知识库有命中时，kb 一跳会发**多次** LLM 请求。

        ``evidence_verifier.verify_claim`` 是**每条断言**调一次 LLM，
        而 executor 对这一整跳只 ``+= 1``。于是知识库里条目越多，
        账目与真实调用数的偏差越大 —— 方向是**少记**。

        这不是本轮要修的缺陷，是要如实记下的口径偏差：
        字段名叫 ``llm_calls_made``，实际记的是「被走过的跳数」。
        strict=True：谁把它接成真实计数，这条会 XPASS 失败。
        """
        import importlib
        # `rag/__init__.py` 把**实例** evidence_verifier 挂在包属性上，
        # `import rag.evidence_verifier as ev` 拿到的是实例而不是模块。
        ev = importlib.import_module("rag.evidence_verifier")
        builder = importlib.import_module("rag.context_builder")

        class _Hit:
            def __init__(self, i):
                self.chunk_id = f"kb{i}"
                self.doc_id = f"doc{i}"
                self.content = f"知识库条目 {i}：C2 心跳按固定周期外连"
                self.title = f"KB{i}"
                self.source = "kb"
                self.threat_types = ["C2"]
                self.severity = "high"
                self.tags = ["c2"]
                self.score = 0.9

        class _Result:
            def __init__(self, n):
                self.chunks = [_Hit(i) for i in range(n)]

        async def with_hits(session, query, **kw):
            return _Result(3)

        monkeypatch.setattr(ev.evidence_verifier.retriever, "retrieve", with_hits)
        # build_verification_prompt 依赖真实上下文拼装，这里只保证非空
        monkeypatch.setattr(
            builder.rag_context_builder, "build_context",
            lambda result, max_tokens=1500: "KB 上下文",
        )

        res, actual = _drive_executor(monkeypatch, n_chunks=2, depth="deep")
        assert res.kb_verification.get("verified") is True, \
            f"知识库命中路径未被走到: {res.kb_verification}"
        assert res.llm_calls_made == actual, (
            f"账目说 {res.llm_calls_made} 次，真实发生 {actual} 次 —— "
            "kb 一跳只记 1 次，实际每条断言各发一次"
        )

    def test_s3_zero_made_is_not_swallowed_by_falsy_fallback(self):
        """G5-S2：made=0（预算耗尽，一次都没跑）必须被如实记账。

        这条专门盯 ``x or 默认值``：0 是 falsy，
        ``llm_calls_made if llm_calls_made else chunks`` 会把 0 吃掉。
        """
        led = budget_for(chunks=3, llm_calls_planned=5, llm_calls_made=0)
        assert led.llm_calls_made == 0, "made=0 被回落成了 chunk 数"
        assert led.llm_calls_skipped == 5, f"跳过数记账错误: {led}"

        # 未显式给出时才回落
        default = budget_for(chunks=4)
        assert default.llm_calls_planned == 4
        assert default.llm_calls_made == 4

        # 超发不产生负数
        over = BudgetLedger(llm_calls_planned=2, llm_calls_made=5, chunks=2)
        assert over.llm_calls_skipped == 0
        assert over.hop_budget == 2


# ══════════════════════════════════════════════════════════════
# G5-S4/S5 · 终止状态互斥
# ══════════════════════════════════════════════════════════════

class TestTerminalState:
    def test_s4_truth_table_is_mutually_exclusive(self):
        """G5-S4：三类终态互斥，安全拒绝优先于预算终止。"""
        assert classify_terminal_state() == TERMINAL_COMPLETED
        assert classify_terminal_state(skip_reasoning=True) == TERMINAL_BUDGET_EXHAUSTED
        assert classify_terminal_state(short_circuit="budget") == TERMINAL_BUDGET_EXHAUSTED
        assert classify_terminal_state(security_denied=True) == TERMINAL_SECURITY_DENIED
        # 同时命中时，安全拒绝优先（两者都成立时只能落进一个终态）
        both = classify_terminal_state(
            security_denied=True, short_circuit="budget", skip_reasoning=True)
        assert both == TERMINAL_SECURITY_DENIED
        # 三种终态互不相同
        assert len({TERMINAL_COMPLETED, TERMINAL_BUDGET_EXHAUSTED,
                    TERMINAL_SECURITY_DENIED}) == 3

    def test_s5_security_denied_run_is_not_reported_as_clean(self, monkeypatch):
        """G5-S5：整轮工具都被安全层拒绝 → 终态 security_denied，
        强制人审，且**不得**说成 false_positive。

        这是「未完成 ≠ 已排除」的直接验收：终态若落成 completed，
        上层就会把「因安全策略没取证」读成「查过了，干净」。
        """
        from agents import agent_executor as ex
        from audit_types import ToolCall
        import audit_types

        calls = {"n": 0}

        async def fake_chat(messages, **kw):
            calls["n"] += 1
            return json_text()

        monkeypatch.setattr(ex.summary.llm, "chat", fake_chat)
        chunk = ex.AuditChunk(
            chunk_id="c0", strategy="manual", label="ip",
            events=[{"id": 1, "event_type": "C2_BEACON",
                     "severity": "high", "message": "beacon"}],
        )
        monkeypatch.setattr(ex.chunker, "chunk",
                            lambda events, chain_event_ids=None: [chunk])

        async def fake_audit(ch, knowledge_chunks=None):
            return ex.ChunkVerdict(
                chunk_id="c0", threat_detected=False, confidence=0.0,
                severity="info", summary="未发现威胁",
                all_event_ids_in_chunk=[1],
            )

        monkeypatch.setattr(ex.sub_auditor, "audit", fake_audit)

        def deny(*a, **k):
            raise ex.ToolExecutionDenied("策略拒绝", "permission")

        monkeypatch.setattr(ex.tool_registry, "execute", deny)

        res = _run(ex.executor.execute(
            tool_calls=[ToolCall(call_id="x1", task_id="t1",
                                 tool="isolate_host", args={"host": "h1"})],
            depth="standard",
            raw_event={"event": "C2_BEACON", "severity": "high", "src_ip": "10.0.0.5"},
        ))

        denied = [r for r in res.tool_results if getattr(r, "security_denied", False)]
        assert denied, "安全拒绝未被记录为 security_denied"
        assert res.terminal_state == TERMINAL_SECURITY_DENIED, \
            f"终态错误: {res.terminal_state}（reason={res.terminal_reason!r}）"
        assert res.needs_human_review is True, "安全拒绝后未强制人审"
        assert res.verdict != "false_positive", \
            f"未完成的分析被归类为 false_positive: {res.verdict!r}"


# ══════════════════════════════════════════════════════════════
# G5-S6/S7/S8 · 并发上限、超时、取消
# ══════════════════════════════════════════════════════════════

class _PeakTool:
    """注册进 tool_registry 的慢工具，自己记录同时在跑的数量与峰值。"""

    def __init__(self):
        self.cur = 0
        self.peak = 0
        self.finished = 0

    async def __call__(self, **kwargs):
        self.cur += 1
        self.peak = max(self.peak, self.cur)
        try:
            await asyncio.sleep(0.05)
            self.finished += 1
            return {"ok": True}
        finally:
            self.cur -= 1


def _register_probe_tool(monkeypatch, tool, *, timeout_ms=5000, name="acc_g5_probe"):
    """把探针挂到真实的 tool_registry 上，并保证测试后摘掉。"""
    import tool_registry as tr

    tr.tool_registry.register(
        name=name, category="diagnostic", risk_level=tr.RISK_LOW,
        description="验收用并发探针", fn=tool, timeout_ms=timeout_ms,
    )
    return name


def _unregister(name):
    import tool_registry as tr
    tr.tool_registry._tools.pop(name, None)


class TestConcurrencyAndTimeout:
    def test_s6_concurrency_ceiling_is_enforced(self, monkeypatch):
        """G5-S6：并发峰值不得超过闸的上限。

        两个独立口径交叉核对：工具内部自计的峰值，以及闸的 limit。
        只看其中一个都可能自证（工具自己限流、或闸根本没被走到）。
        """
        from capacity import reset_gates
        import tool_registry as tr
        from config import settings

        reset_gates()
        monkeypatch.setattr(settings, "tool_exec_max_concurrency", 3)

        probe = _PeakTool()
        name = _register_probe_tool(monkeypatch, probe)
        try:
            async def t():
                return await asyncio.gather(*[
                    tr.tool_registry.execute(name) for _ in range(12)
                ])

            results = _run(t())
            gate = tr.tool_exec_gate()
            limit = gate.limit()

            assert limit == 3, f"闸上限读数不对: {limit}"
            assert probe.peak <= limit, \
                f"并发峰值 {probe.peak} 超过上限 {limit}"
            assert probe.peak > 1, f"并发根本没发生（peak={probe.peak}）—— 场景无效"
            assert all(r == {"ok": True} for r in results)
            assert probe.finished == 12, f"有任务未完成: {probe.finished}/12"
            assert gate.inflight() == 0, "闸未归还名额"
        finally:
            _unregister(name)
            reset_gates()

    def test_s7_below_ceiling_all_tools_actually_run_in_parallel(self, monkeypatch):
        """正对照：不超过上限时全部工具都必须真正执行成功。

        没有这条，s6 可能是因为「工具根本没跑起来」才没超限。
        """
        from capacity import reset_gates
        import tool_registry as tr
        from config import settings

        reset_gates()
        monkeypatch.setattr(settings, "tool_exec_max_concurrency", 16)

        probe = _PeakTool()
        name = _register_probe_tool(monkeypatch, probe)
        try:
            async def t():
                return await asyncio.gather(*[
                    tr.tool_registry.execute(name) for _ in range(4)
                ])

            results = _run(t())
            assert len(results) == 4 and all(r == {"ok": True} for r in results)
            assert probe.finished == 4
            assert probe.peak == 4, f"正对照并发度不对: {probe.peak}"
        finally:
            _unregister(name)
            reset_gates()

    def test_s8_timeout_is_enforced_and_typed(self, monkeypatch):
        """G5-S7：注册时声明的 timeout_ms 必须真的生效。

        timeout_ms 曾是死字段 —— 只存进注册表，从未被读取。
        """
        from capacity import reset_gates
        import tool_registry as tr

        reset_gates()
        slow = _PeakTool()

        async def forever(**kwargs):
            await asyncio.sleep(30)
            return {"ok": True}

        name = _register_probe_tool(monkeypatch, forever, timeout_ms=120)
        try:
            with pytest.raises(tr.ToolExecutionTimeout) as ei:
                _run(tr.tool_registry.execute(name))
            assert ei.value.timeout_ms == 120
        finally:
            _unregister(name)
            reset_gates()

    def test_s9_timeout_reaches_executor_as_distinct_failure(self, monkeypatch):
        """G5-S7 端到端：超时必须成为独立一类 ToolResult，不是普通失败。"""
        from capacity import reset_gates
        from agents import agent_executor as ex
        from audit_types import ToolCall
        import audit_types

        reset_gates()
        calls = {"n": 0}

        async def fake_chat(messages, **kw):
            calls["n"] += 1
            return json_text()

        monkeypatch.setattr(ex.summary.llm, "chat", fake_chat)
        chunk = ex.AuditChunk(
            chunk_id="c0", strategy="manual", label="ip",
            events=[{"id": 1, "event_type": "C2_BEACON",
                     "severity": "high", "message": "beacon"}],
        )
        monkeypatch.setattr(ex.chunker, "chunk",
                            lambda events, chain_event_ids=None: [chunk])

        async def fake_audit(ch, knowledge_chunks=None):
            return ex.ChunkVerdict(
                chunk_id="c0", threat_detected=False, confidence=0.0,
                severity="info", summary="未发现威胁",
                all_event_ids_in_chunk=[1],
            )

        monkeypatch.setattr(ex.sub_auditor, "audit", fake_audit)

        async def forever(**kwargs):
            await asyncio.sleep(30)
            return {"ok": True}

        name = _register_probe_tool(monkeypatch, forever, timeout_ms=120)
        try:
            res = _run(ex.executor.execute(
                tool_calls=[ToolCall(call_id="x1", task_id="t1",
                                     tool=name, args={})],
                depth="standard",
                raw_event={"event": "C2_BEACON", "severity": "high",
                           "src_ip": "10.0.0.5"},
            ))
        finally:
            _unregister(name)
            reset_gates()

        to = [r for r in res.tool_results if r.tool == name]
        assert to, "探针工具的 ToolResult 丢失"
        assert to[0].success is False
        assert to[0].timed_out is True, \
            f"超时未标记为独立一类: error={to[0].error!r}"
        assert "tool_timeout" in (to[0].error or "")

    def test_s10_cancellation_propagates_instead_of_becoming_a_failed_tool(self, monkeypatch):
        """G5-S8：取消必须向上传播，不得被收成 success=False 的 ToolResult。

        取消被降级成「工具失败」时，流水线会以为还能继续跑完并产出结论。
        """
        from capacity import reset_gates
        import tool_registry as tr

        reset_gates()

        started = asyncio.Event()

        async def blocker(**kwargs):
            started.set()
            await asyncio.sleep(30)
            return {"ok": True}

        name = _register_probe_tool(monkeypatch, blocker)
        try:
            async def t():
                runner = asyncio.ensure_future(asyncio.gather(*[
                    tr.tool_registry.execute(name) for _ in range(3)
                ]))
                await asyncio.wait_for(started.wait(), timeout=2)
                runner.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await runner
                return True

            assert _run(t()) is True
        finally:
            _unregister(name)
            reset_gates()

    def test_s11_tool_registry_gate_rejects_unknown_tool(self, monkeypatch):
        """正对照：闸没坏 —— 未知工具仍然被明确拒绝，不是挂起。"""
        from capacity import reset_gates
        import tool_registry as tr

        reset_gates()
        with pytest.raises(ValueError):
            _run(tr.tool_registry.execute("acc_g5_no_such_tool"))


# ══════════════════════════════════════════════════════════════
# G5-S9 · chunk 审核异常的保守包装
# ══════════════════════════════════════════════════════════════

class TestChunkFailureWrapping:
    def test_s12_failed_chunk_becomes_conservative_verdict_not_dropped(self, monkeypatch):
        """G5-S9：单个 chunk 审核异常不得让整批坍缩，
        但必须标记为高幻觉风险 + schema 非法 + 需人审。"""
        from agents import agent_executor as ex

        chunks = [
            ex.AuditChunk(chunk_id="ok", strategy="manual", label="ip",
                          events=[{"id": 1, "event_type": "X",
                                   "severity": "high", "message": "m"}]),
            ex.AuditChunk(chunk_id="boom", strategy="manual", label="ip",
                          events=[{"id": 2, "event_type": "Y",
                                   "severity": "high", "message": "m"}]),
        ]

        async def fake_audit(ch, knowledge_chunks=None):
            if ch.chunk_id == "boom":
                raise RuntimeError("sub_auditor exploded")
            return ex.ChunkVerdict(
                chunk_id="ok", threat_detected=False, confidence=0.0,
                severity="info", summary="未发现威胁",
                all_event_ids_in_chunk=[1],
            )

        monkeypatch.setattr(ex.sub_auditor, "audit", fake_audit)

        verdicts = _run(ex.executor._audit_chunks_parallel(chunks))
        assert len(verdicts) == 2, f"异常 chunk 被丢弃，整批坍缩: {len(verdicts)}"

        bad = [v for v in verdicts if v.chunk_id == "boom"]
        assert bad, "异常 chunk 的保守 verdict 丢失"
        bad = bad[0]
        assert bad.schema_valid is False
        assert bad.hallucination_risk == 1.0
        assert bad.unsubstantiated is True
        assert bad.threat_detected is False, "异常被当成威胁（会虚增告警）"
        assert "需人工复核" in bad.alert

    def test_s13_control_all_chunks_fine(self, monkeypatch):
        """正对照：全部正常时不得凭空产生 schema 非法 / 满幻觉风险。"""
        from agents import agent_executor as ex

        chunks = [
            ex.AuditChunk(chunk_id=f"c{i}", strategy="manual", label="ip",
                          events=[{"id": i + 1, "event_type": "X",
                                   "severity": "high", "message": "m"}])
            for i in range(3)
        ]

        async def fake_audit(ch, knowledge_chunks=None):
            return ex.ChunkVerdict(
                chunk_id=ch.chunk_id, threat_detected=False, confidence=0.0,
                severity="info", summary="未发现威胁",
                all_event_ids_in_chunk=[1],
            )

        monkeypatch.setattr(ex.sub_auditor, "audit", fake_audit)
        verdicts = _run(ex.executor._audit_chunks_parallel(chunks))
        assert len(verdicts) == 3
        assert all(v.schema_valid for v in verdicts)
        assert all(v.hallucination_risk < 1.0 for v in verdicts)
