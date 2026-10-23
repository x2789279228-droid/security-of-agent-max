"""
验收 · 第二轮：集成与故障注入（LLM / CAD / Executor / 安全 四类故障 + 跳模块一致性）

规范原文（§三.2）：
  「注入四类真实故障：LLM 不可用、CAD 不可用、Executor 中途失败、安全层拒绝；
    每一类都必须能在最终结论与审计轨迹里被识别，而不是被吸收成正常完成。」

规范并要求（§二.7 跳模块一致性）：
  「同一个安全决策在 /guard/call 与真实工具执行入口上必须一致；
    同一条审计结论在直连异步路径与 Temporal 编排路径上必须一致；
    LLM 必须只有一个出口。」

本文件全部是**端到端**：从 agent 执行入口一路跑到结论字段，
断言「失败被记录」而不是「失败被吞掉」。
"""
import asyncio
import inspect
import json
import pathlib

import pytest

from veto_gates import evaluate_auto_response_gate


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


_LLM_OK = json.dumps({
    "threat_detected": True, "threat_type": "C2_BEACON",
    "confidence": 0.9, "severity": "high",
    "summary": "检测到周期性外连",
    "threat_claims": [{
        "type": "C2", "confidence": 0.85, "evidence_ids": [2],
        "evidence_quotes": ["outbound beacon to 203.0.113.45 every 60s"],
        "severity": "high", "summary": "主机周期性外连",
    }],
    "conclusion": "confirmed", "reasoning": "存在周期性外连",
}, ensure_ascii=False)


def _drive(monkeypatch, *, chat_reply=_LLM_OK, tool_behavior=None,
           depth="deep", n_chunks=1, extra_tools=()):
    """端到端驱动 executor.execute（真实 sub_auditor / synthesize / recheck）。

    ⚠️ ``llm.deep_analyze`` 是**伪工具**，不会走 ``tool_registry.execute``；
    只传它的话，``tool_behavior`` 一次都不会被调用，场景会静默失效。
    要测工具侧故障必须额外传至少一个 data 工具。
    """
    from agents import agent_executor as ex
    from audit_types import ToolCall
    from eval_datasets.grounding_cases import C2_BEACON

    calls = {"n": 0}

    async def fake_chat(messages, **kw):
        calls["n"] += 1
        return chat_reply() if callable(chat_reply) else chat_reply

    monkeypatch.setattr(ex.summary.llm, "chat", fake_chat)

    chunks = [
        ex.AuditChunk(chunk_id=f"c{i}", strategy="manual", label="ip",
                      events=[dict(C2_BEACON)])
        for i in range(n_chunks)
    ]
    monkeypatch.setattr(ex.chunker, "chunk",
                        lambda events, chain_event_ids=None: chunks)

    if tool_behavior is not None:
        monkeypatch.setattr(ex.tool_registry, "execute", tool_behavior)

    tool_calls = [ToolCall(call_id="x1", task_id="t1",
                           tool="llm.deep_analyze", args={})]
    tool_calls += list(extra_tools)

    res = _run(ex.executor.execute(
        tool_calls=tool_calls, depth=depth, raw_event=dict(C2_BEACON),
    ))
    return res, calls["n"]


# ══════════════════════════════════════════════════════════════
# 故障一：LLM 不可用（四种降级形态）
# ══════════════════════════════════════════════════════════════

_DEGRADATIONS = {
    "budget_exhausted": json.dumps(
        {"error": "每日 LLM 预算已用尽", "fallback": True}, ensure_ascii=False),
    "llm_not_configured": json.dumps(
        {"error": "LLM未配置", "fallback": True}, ensure_ascii=False),
    "request_timeout": json.dumps(
        {"error": "LLM request timeout", "fallback": True,
         "error_type": "llm_request_timeout", "retryable": True}, ensure_ascii=False),
    "upstream_503": json.dumps(
        {"error": "LLM 上游错误 503", "fallback": True,
         "error_type": "upstream_503", "retryable": False}, ensure_ascii=False),
    "unparsable": "模型今天不想输出 JSON。",
}


class TestLlmFailureInjection:
    # ── 验收发现 G7-F1：LLM 完全不可用时，终态仍是「completed」 ──
    # 实测五种 LLM 不可用形态（预算耗尽 / 未配置 / 请求超时 / 上游 503 /
    # 输出不可解析），AuditResult 全部是：
    #     terminal_state  = "completed"        ← 「正常跑完」
    #     terminal_reason = "llm_fallback:…"   ← 原因倒是对
    #     threat_detected = False, confidence = 0.0
    # 而 ``if terminal_state != "completed": needs_human_review = True``
    # 这道兜底因此**不会触发**。
    #
    # 缓解事实（已逐条实测，不靠推断）：
    #   · threat_detected=False → 自动响应闸门不会放行误封；
    #   · terminal_reason 完整记录了降级原因，可审计。
    # 残留风险：C 门槛「故障状态明确」只做到一半 ——
    # 记录说「正常跑完」，实际一次分析都没发生；且没有强制人审，
    # 运维在「跑完了」和「结论是零风险」之间无法区分。
    # strict=True：谁把 LLM 降级接进终态，这条会 XPASS 失败。
    @pytest.mark.xfail(
        strict=True, raises=AssertionError,
        reason="验收发现 G7-F1：LLM 完全不可用时 terminal_state 仍为 completed，"
               "且不触发 needs_human_review 兜底",
    )
    @pytest.mark.parametrize("kind", sorted(_DEGRADATIONS))
    def test_s1_llm_outage_never_becomes_a_clean_verdict(self, monkeypatch, kind):
        """R2-1：LLM 完全不可用时，结论不得是「正常完成且无威胁」。"""
        res, _ = _drive(monkeypatch, chat_reply=_DEGRADATIONS[kind])

        assert res.terminal_state != "completed", (
            f"[{kind}] 状态={res.terminal_state} reason={res.terminal_reason!r} "
            f"verdict={res.verdict!r} threat={res.threat_detected} "
            f"needs_human={res.needs_human_review} —— "
            "LLM 不可用却记为 completed"
        )
        assert res.needs_human_review is True, f"[{kind}] 未强制人审"
        assert res.verdict != "false_positive", (
            f"[{kind}] 未完成的分析被归类为 false_positive: {res.verdict!r}"
        )
        assert res.terminal_reason, f"[{kind}] 终态没有原因说明"

    #: 这四种是 summary_compression 主动降级的形态，带 fallback 标记，
    #: ``is_llm_fallback`` 能识别，terminal_reason 里有据可查。
    _RECOVERABLE = {k: v for k, v in _DEGRADATIONS.items() if k != "unparsable"}

    def test_s1b_degradation_is_still_recorded_and_auditable(self, monkeypatch):
        """正向确认：即便终态标签不对，**降级本身没有被吞掉**。

        有了这条，G7-F1 就不会被误读成「LLM 故障完全不可见」。
        """
        for kind, payload in self._RECOVERABLE.items():
            res, _ = _drive(monkeypatch, chat_reply=payload)
            assert res.terminal_reason, f"[{kind}] 降级原因丢失"
            assert "llm_fallback" in res.terminal_reason, \
                f"[{kind}] 终态原因未标注来源: {res.terminal_reason!r}"
            assert res.threat_detected is False, (
                f"[{kind}] LLM 没给出任何结论，却报了威胁"
            )
            assert "降级" in (res.summary or ""), \
                f"[{kind}] summary 未标注这是降级结果: {res.summary!r}"

    @pytest.mark.xfail(
        strict=True, raises=AssertionError,
        reason="验收发现 G7-F1b：LLM 输出不可解析时 terminal_reason 为空，"
               "终态既非 completed 可解释、也无原因可查",
    )
    def test_s1c_unparsable_output_still_leaves_a_terminal_reason(self, monkeypatch):
        """LLM 返回了内容但完全无法解析 —— 这一类连降级原因都不会留下。

        前四种是「客户端主动降级」，带 fallback 标记所以能识别；
        这一种是「模型返回了垃圾」，is_llm_fallback 识别不了，
        于是 ``terminal_reason`` 是空串，``terminal_state`` 仍是 completed。
        唯一线索只剩 ``summary="汇总解析失败"``。
        """
        res, _ = _drive(monkeypatch, chat_reply=_DEGRADATIONS["unparsable"])
        assert res.terminal_reason, (
            f"state={res.terminal_state} reason={res.terminal_reason!r} "
            f"verdict={res.verdict!r} —— 解析失败在终态里没有任何痕迹"
        )

    def test_s2_control_healthy_llm_completes(self, monkeypatch):
        """正对照：LLM 正常时必须正常完成。

        没有这条，上一条可能是因为「流水线本来就跑不完」而通过。
        """
        res, actual = _drive(monkeypatch)
        assert res.terminal_state == "completed", \
            f"正常路径未完成: {res.terminal_state}/{res.terminal_reason}"
        assert res.verdict == "confirmed"
        assert res.needs_human_review is False
        assert actual > 0


# ══════════════════════════════════════════════════════════════
# 故障二 / 三：Executor 中途失败（安全拒绝 / 工具超时 / chunk 异常）
# ══════════════════════════════════════════════════════════════

class TestExecutorFailureInjection:
    def test_s3_security_denial_is_not_a_tool_crash(self, monkeypatch):
        """R2-3：安全拒绝必须与「工具崩了」在结论上可区分。"""
        from agents import agent_executor as ex
        from audit_types import ToolCall

        def deny(*a, **kw):
            raise ex.ToolExecutionDenied("角色无权调用", "permission")

        res, _ = _drive(monkeypatch, tool_behavior=deny, depth="standard",
                        extra_tools=[ToolCall(call_id="d1", task_id="t1",
                                              tool="event_store.query", args={})])

        denied = [r for r in res.tool_results if getattr(r, "security_denied", False)]
        assert denied, f"安全拒绝未被单独标记: {res.tool_results}"
        assert "security_denied" in denied[0].error
        assert res.terminal_state == "security_denied"
        assert "tool_denied" in res.terminal_reason
        assert res.needs_human_review is True

    def test_s4_tool_crash_is_not_a_security_denial(self, monkeypatch):
        """对照组：同样的入口，普通异常必须落在**另一个**标志上。"""
        from audit_types import ToolCall

        def boom(*a, **kw):
            raise ValueError("tool internal error")

        res, _ = _drive(monkeypatch, tool_behavior=boom, depth="standard",
                        extra_tools=[ToolCall(call_id="d1", task_id="t1",
                                              tool="event_store.query", args={})])

        denied = [r for r in res.tool_results if getattr(r, "security_denied", False)]
        assert denied == [], "普通工具异常被误标为安全拒绝"
        crashed = [r for r in res.tool_results if not r.success]
        assert crashed, f"工具异常未被记录: {res.tool_results}"
        assert res.terminal_state != "security_denied", \
            "工具崩溃被归类成安全拒绝 —— 两类故障无法区分"

    def test_s5_multiple_failure_kinds_still_yield_one_terminal_state(self, monkeypatch):
        """R2-3：多类故障同时发生时，终态仍是**互斥**的单一取值。"""
        from agents import agent_executor as ex
        from audit_types import ToolCall
        from eval_datasets.grounding_cases import C2_BEACON

        state = {"n": 0}

        async def flaky(*a, **kw):
            state["n"] += 1
            if state["n"] == 1:
                raise ex.ToolExecutionDenied("拒绝", "permission")
            if state["n"] == 2:
                raise ex.ToolExecutionTimeout("event_store.query", 30000)
            raise ValueError("third call exploded")

        async def fake_chat(messages, **kw):
            return _LLM_OK

        monkeypatch.setattr(ex.summary.llm, "chat", fake_chat)
        chunk = ex.AuditChunk(chunk_id="c0", strategy="manual", label="ip",
                              events=[dict(C2_BEACON)])
        monkeypatch.setattr(ex.chunker, "chunk",
                            lambda events, chain_event_ids=None: [chunk])
        monkeypatch.setattr(ex.tool_registry, "execute", flaky)

        res = _run(ex.executor.execute(
            tool_calls=[
                ToolCall(call_id="a", task_id="t", tool="event_store.query", args={}),
                ToolCall(call_id="b", task_id="t", tool="memory_tree.related", args={}),
                ToolCall(call_id="c", task_id="t", tool="sliding_window.get", args={}),
            ],
            depth="standard", raw_event=dict(C2_BEACON),
        ))

        assert res.terminal_state in ("completed", "budget_exhausted",
                                      "security_denied")
        denied = [r for r in res.tool_results if getattr(r, "security_denied", False)]
        timed = [r for r in res.tool_results if getattr(r, "timed_out", False)]
        assert denied, "安全拒绝标志丢失"
        assert timed, "超时标志丢失"
        # 三类失败在错误串里必须是三种不同的类别
        classes = {
            (r.error or "").split(":")[0]
            for r in res.tool_results if not r.success
        }
        assert len(classes) >= 3, f"多类失败被折叠成 {classes}"


# ══════════════════════════════════════════════════════════════
# 故障四：CAD 不可用（监督能力丧失）
# ══════════════════════════════════════════════════════════════

class TestCadFailureInjection:
    def test_s6_cad_outage_is_reported_as_supervision_failure_not_as_verdict(self):
        """R2-2：CAD 挂掉时结论必须是「无法确认」，不是「没发现问题」。

        同时验证这条 supervision_failed 确实会挡住自动响应（接 G3 的闸门）。
        """
        blocked = evaluate_auto_response_gate(
            {"threat_detected": True, "verdict": "confirmed", "confidence": 0.9},
            supervision_ok=False, supervision_error="CAD exploded",
        )
        assert blocked.allowed is False
        assert blocked.blocking_factors == ["supervision_failed"]
        assert blocked.blocked_by_supervision is True

        control = evaluate_auto_response_gate(
            {"threat_detected": True, "verdict": "confirmed", "confidence": 0.9},
            supervision_ok=True,
        )
        assert control.allowed is True, "正对照失败：监督正常时必须放行"

    def test_s7_cad_cannot_verify_event_is_not_a_supervision_failure(self, monkeypatch):
        """R2-2 关键区分：「CAD 无法验证事件」≠「CAD 自身运行失败」。

        前者是**有效业务结果**（没有可穿透核验的断言），应当正常放行；
        后者是监督能力丧失，必须阻断。把两者混为一谈，要么误封，
        要么在 CAD 真挂掉时继续自动响应。
        """
        from cad import CircuitBreaker

        br = CircuitBreaker(persist=False)
        for _ in range(20):
            br.record_na(notes="single-source: 无分解证据可穿透验证")

        st = br.get_status()
        assert st["state"] == "closed", "无可验断言被当成故障"
        assert st["tripped"] is False
        assert st["supervision_failures"] == 0

        gate = evaluate_auto_response_gate(
            {"threat_detected": True, "verdict": "confirmed", "confidence": 0.9},
            cad_report={"circuit_breaker": st},
        )
        assert gate.allowed is True, "「无法验证」被当成了「监督故障」，误封合法请求"


# ══════════════════════════════════════════════════════════════
# 跳模块一致性
# ══════════════════════════════════════════════════════════════

class TestCrossModuleConsistency:
    def test_s8_escalation_verdict_is_identical_on_both_entry_points(self, monkeypatch):
        """J1：行为签名升级在两条入口上必须给出**同一个**决策。

        P3-1 的原始缺陷是「策略在一处配置、两处执行，其中一处根本没接线」：
        同一份 action="deny" 的报告，MCP Guard 侧 deny，
        tool_registry 侧却 passed=True。
        这里在**同一次**执行里对两个入口注入同一份签名报告，
        断言两边都拒绝；再注入一份 logged 报告，断言两边都放行。

        ⚠️ 只比较结论不够 —— 必须同时确认「注入确实生效」，
        否则两条路径可能都在走「检测器没输出」的分支。
        """
        import mcp_guard
        from mcp_guard.behavior_detector import SignatureReport
        from mcp_guard.tool_registry import ToolInfo
        from security_guard.security_guard import security_guard
        from tool_registry import (
            ToolExecutionDenied,
            tool_registry as audit_registry,
        )
        from routers.audit import GuardCallRequest, guard_call
        from types import SimpleNamespace

        # 两个入口用的是**互不相交**的工具注册表：
        #   · /guard/call          → mcp_guard.tool_registry（响应动作面）
        #   · tool_registry.execute → backend tool_registry（审计查询面）
        # 实测 sliding_window.get 在前者直接被判「未注册，疑似幻觉工具」。
        # 所以「同一决策在两条入口一致」只能在**共同的名字**上验证 ——
        # 这里往两个注册表各注入一个同名探针，跑完再摘掉。
        from mcp_guard.validator import TOOL_ARG_MODELS

        tool = "acceptance.j1_probe"

        from pydantic import BaseModel

        class _ProbeParams(BaseModel):
            """Guard 第 3 层按 ``TOOL_ARG_MODELS`` 查参数模型，
            查不到即判「无参数模型」直接 deny —— 模型要注册到这张表里，
            光塞进 ToolInfo.parameters 不生效。"""

        TOOL_ARG_MODELS[tool] = _ProbeParams

        async def probe_fn(**kwargs):
            return {"ok": True}

        audit_registry.register(
            name=tool, category="diagnostic", risk_level="low",
            description="验收用跨入口一致性探针", fn=probe_fn, timeout_ms=2000,
        )
        guard_registry = mcp_guard.mcp_guard.registry
        guard_registry._tools[tool] = ToolInfo(
            name=tool, description="验收用跨入口一致性探针",
            risk_level="low", required_permission="low_risk",
            parameters=_ProbeParams,
        )
        guard_registry._executors[tool] = lambda **kw: {"ok": True}

        seen = {"n": 0}

        def _drive_both(action):
            seen["n"] += 1

            class _StubDetector:
                def observe_pre_exec(self, rec):
                    return SignatureReport(
                        anomaly_score=0.97, is_anomaly=True,
                        action=action,
                        reasons=["acceptance: 与历史画像显著偏离"],
                        dimensions={"param": 0.97},
                        sample_count=200,
                    )

                def observe_post_exec(self, rec, *a, **kw):
                    return None

            security_guard.reset()
            mcp_guard.mcp_guard.detector = _StubDetector()
            try:
                admin = SimpleNamespace(username="root", role="admin", jti="j1")
                req = GuardCallRequest(
                    tool_name=tool, arguments={},
                    reason="acceptance", session_id="acc-j1",
                )
                g = _run(guard_call(req, admin))
                try:
                    _run(audit_registry.execute(tool))
                    exec_decision = "allow"
                except ToolExecutionDenied:
                    exec_decision = "deny"
                except Exception:
                    # 工具**自身**失败 —— 与安全判定无关，仍说明安全层放行了。
                    # 这里量的是安全决策，不是工具业务成功。
                    exec_decision = "allow"
                return g, exec_decision
            finally:
                mcp_guard.mcp_guard.detector = None
                security_guard.reset()

        from mcp_guard import permission_manager as pm

        server_permission = mcp_guard.mcp_guard.permission
        _admin_tools = server_permission.rbac["admin"]["tools"]
        _admin_tools.append(tool)   # Guard 的 RBAC 是**枚举白名单**，不是通配
        try:
            denied_guard, denied_exec = _drive_both("deny")
            assert denied_exec == "deny", "tool_registry 入口未执行 deny 升级"
            assert denied_guard["decision"] == "deny", \
                f"/guard/call 未执行 deny 升级: {denied_guard}"

            logged_guard, logged_exec = _drive_both("logged")
            assert logged_exec == "allow", "logged 模式在 tool_registry 被误当成 deny"
            assert logged_guard["decision"] == "allow", \
                f"logged 模式在 /guard/call 被误拒: {logged_guard}"

            assert seen["n"] == 2, "探针未被两个入口都调用到 —— 场景无效"
        finally:
            audit_registry._tools.pop(tool, None)
            guard_registry._tools.pop(tool, None)
            guard_registry._executors.pop(tool, None)
            TOOL_ARG_MODELS.pop(tool, None)
            if tool in _admin_tools:
                _admin_tools.remove(tool)

    def test_s9_llm_has_exactly_one_egress(self):
        """J2：LLM 出口唯一。

        结构性检查（非执行）：全仓只有 summary_compression 构造
        /chat/completions 与 /embeddings 请求。任何新引入的直连 HTTP 客户端
        都会让「重试/超时/预算/降级识别」这些保障对它失效。
        """
        backend = pathlib.Path(__file__).resolve().parent.parent
        hits = []
        for py in backend.rglob("*.py"):
            rel = py.relative_to(backend).as_posix()
            if rel.startswith("tests/") or "__pycache__" in rel:
                continue
            text = py.read_text(encoding="utf-8")
            for marker in ("/chat/completions", "/embeddings"):
                if marker in text and not rel.startswith("summary_compression"):
                    hits.append(f"{rel}: {marker}")
        assert not hits, "出现 summary_compression 之外的 LLM 出口: " + "; ".join(hits)

    def test_s10_both_orchestration_paths_share_one_gate(self):
        """J3：直连异步路径与 Temporal 编排路径必须走同一个闸门函数。"""
        import log_ingestion
        import temporal.workflows as twf

        src_ing = inspect.getsource(log_ingestion)
        src_wf = inspect.getsource(twf)
        assert "evaluate_auto_response_gate(" in src_ing
        assert "evaluate_auto_response_gate(" in src_wf
        # 两处都必须把 CAD 结论与监督异常喂进闸门
        for name, src in (("log_ingestion", src_ing), ("workflows", src_wf)):
            assert "supervision_ok=" in src, f"{name} 未把 supervision_ok 接入闸门"
            assert "cad_report=" in src, f"{name} 未把 cad_report 接入闸门"

    def test_s11_quality_accounting_has_one_source(self):
        """J4：质量评分与 hop 账目只有一个来源，不允许旁路自算。"""
        import quality_scoring
        import agents.agent_executor as ex

        # executor 必须走 quality_scoring 的账目构造，不能自己拼 BudgetLedger
        src = inspect.getsource(ex)
        assert "quality_scoring" in src or "budget_for" in src, \
            "executor 未使用 quality_scoring 的统一账目"
        assert quality_scoring.budget_for(3).chunks == 3
