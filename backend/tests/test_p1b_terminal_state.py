"""
P1-b 负面测试 ①: Executor 真实 LLM hop 计数 + 三类终态 + 未完成 ≠ false_positive

修复前的两个真实缺陷（本文件逐条对应）：

A) **「hop 预算」在实现上不存在。**
   `hop_stats_from_verdicts` 里没有任何计数器 —— 该 dataclass 六个字段
   全是质量指标（幻觉风险 / 完整度 / grounding / claim 数）。
   「预算」只存在于命名与日志措辞中，代码里既不统计计划调用数，
   也不统计实际调用数，于是无法回答「这一轮到底花了多少次 LLM」。

B) **未完成的分析被归类为 false_positive。**
   三类早停成因（幻觉风险 / grounding / 证据完整度）加上「depth 不是 deep」
   折叠成一个 bool `skip_reasoning`；轮次里不留任何「没跑完」的痕迹。
   硬预算短路的 Temporal 轮次更是 audit={} + 无标记，于是在
   `merge_audit_rounds` 里与「审完且干净」走进同一个 else 分支，
   得到**完全相同的 verdict 字符串** `false_positive`。
   下游因此把「没查成」读成「已排除」—— 漏报且不可审计。

验收: 新测试在旧代码下失败，修复后通过。
"""
import asyncio
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ.setdefault("SHARED_MEMORY_DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("SHARED_MEMORY_JWT_SECRET", "test-secret")
os.environ.setdefault("SHARED_MEMORY_LLM_API_KEY", "test")
os.environ.setdefault("SHARED_MEMORY_EMBEDDING_API_KEY", "test")
os.environ.setdefault("SHARED_MEMORY_ADMIN_PASSWORD", "test")

import sqlalchemy.ext.asyncio as _sa_async

_orig = _sa_async.create_async_engine


def _patched(url, **kw):
    for k in ("pool_size", "max_overflow", "pool_pre_ping", "pool_recycle"):
        kw.pop(k, None)
    return _orig(url, **kw)


_sa_async.create_async_engine = _patched
import models  # noqa: F401


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


# ═══════════════════════════════════════════
# A) 真实 LLM hop 计数
# ═══════════════════════════════════════════


class _V:
    """最小 ChunkVerdict 替身。"""

    def __init__(self, risk=0.0, grounding=1.0, claims=(), dumped=()):
        self.hallucination_risk = risk
        self.grounding_score = grounding
        self.threat_claims = list(claims)
        self.discarded_claims = list(dumped)


class TestRealLlmHopAccounting:
    def test_hop_stats_carries_actual_call_counters(self):
        """hop 预算必须是**可计数的量**，不能只是命名。"""
        from veto_gates import hop_stats_from_verdicts

        stats = hop_stats_from_verdicts([_V(), _V(), _V()])
        assert stats.llm_calls_planned >= 3, "计划调用数缺失 —— 预算不可核"
        assert stats.llm_calls_made >= 3, "实调用数缺失"
        assert stats.chunks == 3

    def test_explicit_counters_are_not_overwritten_by_defaults(self):
        """调用方给出真实账目时必须原样保留。"""
        from veto_gates import hop_stats_from_verdicts

        stats = hop_stats_from_verdicts(
            [_V(), _V()], llm_calls_planned=9, llm_calls_made=4
        )
        assert stats.llm_calls_planned == 9
        assert stats.llm_calls_made == 4

    def test_budget_is_comparable_to_made(self):
        from veto_gates import hop_stats_from_verdicts

        stats = hop_stats_from_verdicts([_V()], llm_calls_planned=6, llm_calls_made=2)
        assert stats.hop_budget == 6
        assert stats.llm_calls_made < stats.hop_budget, "预算/实耗不可比较则预算无意义"

    def test_skipped_calls_are_computed(self):
        """「跳过了几次」必须可核 —— 声明了字段却不赋值等于没有。"""
        from veto_gates import hop_stats_from_verdicts

        stats = hop_stats_from_verdicts([_V(), _V()],
                                         llm_calls_planned=5, llm_calls_made=2)
        assert stats.llm_calls_skipped == 3

    def test_skipped_never_negative(self):
        from veto_gates import hop_stats_from_verdicts

        stats = hop_stats_from_verdicts([_V()],
                                         llm_calls_planned=1, llm_calls_made=3)
        assert stats.llm_calls_skipped == 0

    def test_empty_verdicts_still_exposes_planned_budget(self):
        """0 chunk 也要能说明「本来打算调几次」。"""
        from veto_gates import hop_stats_from_verdicts

        stats = hop_stats_from_verdicts([], llm_calls_planned=5, llm_calls_made=0)
        assert stats.llm_calls_planned == 5
        assert stats.llm_calls_made == 0

    def test_audit_result_serialises_hop_ledger(self):
        """终态与 hop 账目必须能被 to_dict 带出去，否则落库后不可审计。"""
        from audit_types import AuditResult

        d = AuditResult(
            terminal_state="budget_exhausted",
            terminal_reason="hop_early_stop:grounding",
            llm_calls_made=2,
            llm_calls_planned=6,
        ).to_dict()
        assert d["terminal_state"] == "budget_exhausted"
        assert d["llm_calls_made"] == 2
        assert d["llm_calls_planned"] == 6
        assert d["terminal_reason"]


# ═══════════════════════════════════════════
# 三类早停成因必须分开记账
# ═══════════════════════════════════════════


class TestSkipReasonDecomposition:
    def test_grounding_only_early_stop(self):
        from veto_gates import hop_stats_from_verdicts

        stats = hop_stats_from_verdicts([_V(risk=0.0, grounding=0.1)])
        assert stats.skip_reasoning is True
        assert stats.skip_reasons == ["grounding"]

    def test_hallucination_only_early_stop(self):
        from veto_gates import hop_stats_from_verdicts

        stats = hop_stats_from_verdicts([_V(risk=0.9, grounding=1.0)])
        assert stats.skip_reasons == ["hallucination_risk"]

    def test_completeness_only_early_stop(self):
        from veto_gates import hop_stats_from_verdicts

        stats = hop_stats_from_verdicts(
            [_V(claims=(), dumped=({"summary": "x"},) * 4)]
        )
        assert "evidence_completeness" in stats.skip_reasons

    def test_multiple_causes_are_all_recorded(self):
        from veto_gates import hop_stats_from_verdicts

        stats = hop_stats_from_verdicts([_V(risk=0.9, grounding=0.1)])
        assert set(stats.skip_reasons) == {"hallucination_risk", "grounding"}

    def test_healthy_stats_have_no_skip_reason(self):
        from veto_gates import hop_stats_from_verdicts

        stats = hop_stats_from_verdicts([_V()])
        assert stats.skip_reasoning is False
        assert stats.skip_reasons == []


# ═══════════════════════════════════════════
# B) 未完成的分析不得塌成 false_positive
# ═══════════════════════════════════════════


class TestIncompleteNeverBecomesFalsePositive:
    def test_round_incomplete_detects_short_circuit(self):
        from veto_gates import round_incomplete

        bad, why = round_incomplete({"audit": {}, "short_circuit": "budget_exhausted"})
        assert bad is True
        assert "budget_exhausted" in why

    def test_round_incomplete_detects_empty_audit(self):
        from veto_gates import round_incomplete

        bad, _ = round_incomplete({"audit": {}, "verdict": {}})
        assert bad is True

    def test_completed_round_is_not_incomplete(self):
        from veto_gates import round_incomplete

        bad, why = round_incomplete(
            {"audit": {"verdict": "false_positive", "confidence": 0.1}}
        )
        assert bad is False and why == ""

    def test_budget_exhausted_merge_is_not_false_positive(self):
        """核心回归：硬预算短路不得产出 false_positive。"""
        from veto_gates import merge_audit_rounds, VERDICT_INSUFFICIENT

        rounds = [{
            "audit": {},
            "verdict": {},
            "short_circuit": "budget_exhausted",
        }]
        merged = merge_audit_rounds(rounds)
        assert merged["verdict"] == VERDICT_INSUFFICIENT, (
            "预算耗尽被归类为 false_positive —— 未完成伪装成已排除"
        )
        assert merged["incomplete_rounds"] == 1
        assert merged["incomplete_reasons"]

    def test_genuine_clean_round_still_false_positive(self):
        """对照组：真正审完且干净的轮次**必须**还能是 false_positive。"""
        from veto_gates import merge_audit_rounds, VERDICT_FALSE_POSITIVE

        rounds = [{
            "audit": {
                "threat_detected": False, "confidence": 0.1,
                "severity": "info", "needs_human_review": False,
                "verdict": "false_positive",
            },
            "terminal_state": "completed",
        }]
        merged = merge_audit_rounds(rounds)
        assert merged["verdict"] == VERDICT_FALSE_POSITIVE
        assert merged["incomplete_rounds"] == 0

    def test_incomplete_round_forces_human_review(self):
        from veto_gates import merge_audit_rounds

        merged = merge_audit_rounds([{"audit": {}, "short_circuit": "budget_exhausted"}])
        assert merged["needs_human"] is True, "未完成却无需人审"

    def test_mixed_complete_and_incomplete_is_not_clean(self):
        """一轮干净 + 一轮没跑完 ≠ 整体干净。"""
        from veto_gates import merge_audit_rounds, VERDICT_INSUFFICIENT

        merged = merge_audit_rounds([
            {
                "audit": {"threat_detected": False, "confidence": 0.05,
                          "severity": "info", "needs_human_review": False},
                "terminal_state": "completed",
            },
            {"audit": {}, "short_circuit": "budget_exhausted"},
        ])
        assert merged["verdict"] == VERDICT_INSUFFICIENT
        assert merged["incomplete_rounds"] == 1

    def test_confirmed_is_not_downgraded_by_incomplete_sibling(self):
        """已确认的威胁不得因同批有未完成轮次而被降级。"""
        from veto_gates import merge_audit_rounds, VERDICT_CONFIRMED, NonLlmSignals

        merged = merge_audit_rounds([
            {
                "audit": {"threat_detected": True, "confidence": 0.9,
                          "severity": "high", "needs_human_review": False},
                "terminal_state": "completed",
            },
            {"audit": {}, "short_circuit": "budget_exhausted"},
        ], NonLlmSignals(sigma_hit=True, reasons=["sigma:x"]))
        assert merged["verdict"] == VERDICT_CONFIRMED


# ═══════════════════════════════════════════
# 终态分类
# ═══════════════════════════════════════════


class TestTerminalStateClassification:
    def test_normal_path_is_completed(self):
        from veto_gates import classify_terminal_state

        assert classify_terminal_state() == "completed"

    def test_early_stop_is_budget_exhausted(self):
        from veto_gates import classify_terminal_state

        assert classify_terminal_state(skip_reasoning=True) == "budget_exhausted"

    def test_short_circuit_is_budget_exhausted(self):
        from veto_gates import classify_terminal_state

        assert classify_terminal_state(short_circuit="budget_exhausted") == "budget_exhausted"

    def test_security_denial_wins_over_everything(self):
        """安全拒绝优先级最高：它意味着「没取到数据」，比早停更不可用。"""
        from veto_gates import classify_terminal_state

        assert classify_terminal_state(
            skip_reasoning=True, security_denied=True, short_circuit="x",
        ) == "security_denied"


# ═══════════════════════════════════════════
# Temporal 硬预算短路必须声明终态
# ═══════════════════════════════════════════


class TestTemporalShortCircuitTerminalState:
    def _short_circuit_round(self, monkeypatch):
        from temporal import activities as acts
        import agents.llm_fallback as fb

        monkeypatch.setattr(fb, "should_short_circuit_for_tier", lambda tier: True)
        monkeypatch.setattr(acts.logger, "warning", lambda *a, **k: None)
        return _run(acts.audit_round({
            "event_id": 1,
            "log_data": {"event": "C2_BEACON", "severity": "high",
                         "_audit_triage": {"tier": "P2"}},
            "session_id": "s1",
            "round_num": 1,
            "mode": "full",
        }))

    def test_short_circuit_round_declares_terminal_state(self, monkeypatch):
        rd = self._short_circuit_round(monkeypatch)
        assert rd["short_circuit"] == "budget_exhausted"
        assert rd.get("terminal_state") == "budget_exhausted", (
            "短路轮未声明终态 —— merge 层无法区分「没跑」与「干净」"
        )
        assert rd.get("terminal_reason")

    def test_short_circuit_round_merges_to_insufficient(self, monkeypatch):
        from veto_gates import merge_audit_rounds, VERDICT_INSUFFICIENT

        rd = self._short_circuit_round(monkeypatch)
        merged = merge_audit_rounds([rd])
        assert merged["verdict"] == VERDICT_INSUFFICIENT
        assert merged["needs_human"] is True


# ═══════════════════════════════════════════
# Executor 端到端：终态真的被写出来
# ═══════════════════════════════════════════


def _make_chunk(ex):
    return ex.AuditChunk(
        chunk_id="c1", strategy="manual", label="ip",
        events=[{"id": 1, "event_type": "C2_BEACON", "severity": "high",
                 "message": "beacon"}],
    )


class TestExecutorTerminalStateEndToEnd:
    def _setup(self, monkeypatch, *, synth_verdict, risk=0.0, grounding=1.0,
               claims=None):
        from agents import agent_executor as ex
        from agents.sub_auditor import ChunkVerdict

        async def fake_chat(messages, **kw):
            return json.dumps(synth_verdict)

        monkeypatch.setattr(ex.summary.llm, "chat", fake_chat)

        chunk = _make_chunk(ex)
        monkeypatch.setattr(
            ex.chunker, "chunk", lambda events, chain_event_ids=None: [chunk]
        )

        if claims is None:
            claims = [{
                "type": "C2", "confidence": 0.3,
                "evidence_ids": [1], "evidence_quotes": ["beacon"],
                "severity": "low", "summary": "c2 beacon",
            }]
        verdict = ChunkVerdict(
            chunk_id="c1", threat_detected=False,
            threat_claims=claims, all_event_ids_in_chunk=[1],
            hallucination_risk=risk, grounding_score=grounding,
        )
        monkeypatch.setattr(ex.sub_auditor, "audit", _mk_audit(verdict))
        return ex

    def test_budget_terminated_round_is_not_false_positive(self, monkeypatch):
        """hop 早停 + 汇总说 false_positive → 终态必须是 budget_exhausted 且
        verdict 不得停留在 false_positive。"""
        ex = self._setup(
            monkeypatch,
            synth_verdict={"threat_detected": False, "confidence": 0.1,
                           "severity": "info", "summary": "无威胁",
                           "verdict": "false_positive"},
            risk=0.95,   # 触发幻觉风险早停
            grounding=0.1,
        )
        from audit_types import ToolCall

        res = _run(ex.executor.execute(
            tool_calls=[ToolCall(call_id="c1", task_id="t1",
                                 tool="llm.recheck", args={})],
            depth="deep",
            raw_event={"event": "USER_LOGIN", "severity": "info",
                       "src_ip": "10.0.0.5"},
        ))
        assert res.terminal_state == "budget_exhausted"
        assert res.verdict != "false_positive", (
            "预算终止的分析仍被说成 false_positive —— 未完成伪装成已排除"
        )
        assert res.verdict == "insufficient_evidence"
        assert res.needs_human_review is True

    def test_hop_trace_records_call_ledger(self, monkeypatch):
        ex = self._setup(
            monkeypatch,
            synth_verdict={"threat_detected": False, "confidence": 0.1,
                           "severity": "info", "summary": "无",
                           "verdict": "false_positive"},
        )
        from audit_types import ToolCall

        res = _run(ex.executor.execute(
            tool_calls=[ToolCall(call_id="c1", task_id="t1",
                                 tool="llm.recheck", args={})],
            depth="deep",
            raw_event={"event": "C2_BEACON", "severity": "high"},
        ))
        term = [h for h in res.hop_trace if h.get("hop") == "terminal"]
        assert term, "hop_trace 缺少终态条目"
        assert term[0]["llm_calls_made"] >= 1, "实调用数未记账"
        assert term[0]["llm_calls_planned"] >= term[0]["llm_calls_made"]
        assert res.llm_calls_made >= 1
        assert res.llm_calls_planned >= res.llm_calls_made

    def test_healthy_deep_round_is_completed(self, monkeypatch):
        """对照组：证据健康且未早停时终态是 completed，结论不被改写。

        事件名必须避开 TYPE_SIGNAL_EVENTS（如 C2_BEACON），否则
        apply_confirmation_gate 会走 detector_hit_llm_cleared 分支给出
        suspicious —— 那是既有行为，与终态无关。
        """
        ex = self._setup(
            monkeypatch,
            synth_verdict={"threat_detected": False, "confidence": 0.1,
                           "severity": "info", "summary": "无",
                           "verdict": "false_positive"},
        )
        from audit_types import ToolCall

        res = _run(ex.executor.execute(
            tool_calls=[ToolCall(call_id="c1", task_id="t1",
                                 tool="llm.recheck", args={})],
            depth="deep",
            raw_event={"event": "USER_LOGIN", "severity": "info"},
        ))
        assert res.terminal_state == "completed"
        assert res.verdict == "false_positive", "正常完成时不得误改结论"


def _mk_audit(verdict):
    async def _audit(chunk, knowledge_chunks=None):
        return verdict
    return _audit


# ═══════════════════════════════════════════
# 安全拒绝：与工具自身报错必须可区分
# ═══════════════════════════════════════════


class TestSecurityDenialIsDistinctFromToolError:
    def test_tool_result_marks_security_denial(self):
        from audit_types import ToolResult

        denied = ToolResult(
            call_id="c1", task_id="t1", tool="event_store.query",
            success=False, error="security_denied:rule_blocked",
            security_denied=True,
        )
        crashed = ToolResult(
            call_id="c2", task_id="t2", tool="event_store.query",
            success=False, error="connection reset",
        )
        assert denied.to_dict()["security_denied"] is True
        assert crashed.to_dict()["security_denied"] is False

    def test_execute_parallel_flags_denied_tool(self, monkeypatch):
        """_execute_parallel 必须把安全拒绝与工具崩溃分开标记。"""
        from agents import agent_executor as ex
        from audit_types import ToolCall
        from tool_registry import ToolExecutionDenied
        import models as _models

        class _FakeCM:
            async def __aenter__(self):
                return object()

            async def __aexit__(self, *a):
                return False

        monkeypatch.setattr(_models, "async_session", lambda: _FakeCM())

        async def denied_exec(name, **kw):
            raise ToolExecutionDenied("risk_level high + detector down", "behavior")

        monkeypatch.setattr(ex.tool_registry, "execute", denied_exec)
        monkeypatch.setattr(ex.Executor, "_emit_tool_telemetry",
                            staticmethod(lambda *a, **k: None))

        res = _run(ex.executor._execute_parallel(
            [ToolCall(call_id="c1", task_id="t1", tool="x.y", args={})], None
        ))
        assert len(res) == 1
        assert res[0].security_denied is True
        assert "security_denied" in res[0].error

    def test_tool_crash_is_not_marked_denied(self, monkeypatch):
        from agents import agent_executor as ex
        from audit_types import ToolCall
        from tool_registry import ToolExecutionDenied
        import models as _models

        class _FakeCM:
            async def __aenter__(self):
                return object()

            async def __aexit__(self, *a):
                return False

        monkeypatch.setattr(_models, "async_session", lambda: _FakeCM())

        async def crash_exec(name, **kw):
            raise RuntimeError("db down")

        monkeypatch.setattr(ex.tool_registry, "execute", crash_exec)
        monkeypatch.setattr(ex.Executor, "_emit_tool_telemetry",
                            staticmethod(lambda *a, **k: None))

        res = _run(ex.executor._execute_parallel(
            [ToolCall(call_id="c1", task_id="t1", tool="x.y", args={})], None
        ))
        assert res[0].success is False
        assert res[0].security_denied is False, "工具自身故障被误标为安全拒绝"


# ═══════════════════════════════════════════
# tools-only 车道：0 次 LLM 调用也要显式记账
# ═══════════════════════════════════════════


class TestToolsOnlyHopLedger:
    def test_tools_only_reports_zero_llm_calls(self, monkeypatch):
        from agents import agent_executor as ex
        from audit_types import ToolResult

        # _deterministic_from_non_llm 是同步函数（无 await）
        res = ex.executor._deterministic_from_non_llm(
            {"event": "C2_BEACON", "severity": "high", "_sigma": {"detected": True}},
            [ToolResult(call_id="c1", task_id="t1", tool="sigma.match", success=True)],
            depth="quick",
        )
        assert res.llm_calls_made == 0
        assert res.llm_calls_planned == 0
        assert res.terminal_state == "completed"

    def test_tools_only_all_denied_marks_security_denied(self, monkeypatch):
        from agents import agent_executor as ex
        from audit_types import ToolResult

        res = ex.executor._deterministic_from_non_llm(
            {"event": "C2_BEACON", "severity": "high"},
            [ToolResult(call_id="c1", task_id="t1", tool="sigma.match",
                        success=False, error="security_denied:rule",
                        security_denied=True)],
            depth="quick",
        )
        assert res.terminal_state == "security_denied"
        assert "tool_denied" in res.terminal_reason
