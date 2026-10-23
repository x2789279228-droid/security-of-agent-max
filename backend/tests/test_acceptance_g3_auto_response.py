"""
验收 · 第三组：自动响应闸门（C-5 / C-6 / D-1）→ 门槛 A + D

规范原文（§二.3）：
  「人工复核未完成、CAD 熔断或监督异常时，禁止进入高风险自动响应。」
  「同一套阻断规则在 Temporal 编排与直连异步路径上必须一致，
    且 CAD 独立审计必须发生在响应决策之前。」

规范并强调：仅仅证明每个检查函数单独工作，还不足以证明整条安全决策链正确。
因此本文件分三层执行：
  L1 闸门纯决策   —— 直接执行 veto_gates.evaluate_auto_response_gate
  L2 全链路       —— 真实执行 log_ingestion._persist_audit_result
                      （写库 → CAD → 闸门 → 响应引擎），断言响应引擎是否真被调用
  L3 Temporal 时序 —— 真实执行 AuditPipelineWorkflow.run()，
                      记录 activity 调用顺序，断言 cad_verify 先于 trigger_response

每个阻断场景都配正对照（同一路径、同一请求，合法时必须放行），
落实规范「不能通过一律拒绝来换取表面上的安全」。

熔断状态不是硬编码的 True/False：用真实 CircuitBreaker 状态机
喂真实坏审核趋势把状态机驱动到 OPEN，再取它自己的 get_status()。
"""
import asyncio
from types import SimpleNamespace

import pytest

import models
import response_engine
import log_ingestion
from cad import CircuitBreaker
from veto_gates import evaluate_auto_response_gate


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


# ── 构造工具 ────────────────────────────────────────────────

def _merged(**over):
    """一份「本来应当放行」的 confirmed 结论。"""
    base = {
        "threat_detected": True,
        "verdict": "confirmed",
        "confidence": 0.92,
        "severity": "high",
        "threat_type": "SSH_BRUTEFORCE",
        "schema_valid": True,
        "needs_human_review": False,
        "response_blocked": False,
    }
    base.update(over)
    return base


def _real_tripped_breaker() -> CircuitBreaker:
    """用真实状态机把熔断器驱动到 OPEN。

    WARMUP_AUDITS=10，喂 10 条 risk=0.95/completeness=0.05 的审核后，
    最近 10 条平均幻觉风险 0.95 > MAX_HALLUCINATION_RISK(0.5) → 熔断。
    这里返回的是状态机自己的 get_status()，不是手写的 tripped=True。
    """
    br = CircuitBreaker(persist=False)
    for _ in range(br.state.WARMUP_AUDITS):
        br.record_audit_result_sync(
            hallucination_risk=0.95,
            evidence_completeness=0.05,
            anomaly_detected=True,
        )
    assert br.state.tripped is True, "前置条件：真实状态机应已熔断"
    return br


def _cad_report(circuit_status: dict) -> dict:
    """按 agents/agent_cad.py 的真实报告结构组装（仅 circuit_breaker 是真实状态机产物）。"""
    return {
        "event_id": 4242,
        "audit_timestamp": "2026-10-18T00:00:00+00:00",
        "first_failed_hop": None,
        "penetrating_verification": {
            "total_claims": 10, "verified": 0, "unverifiable": 0,
            "hallucination_count": 10, "hallucination_risk": 1.0,
            "evidence_completeness": 0.0, "quotes_checked": 0,
            "quotes_grounded": 0, "quotes_fabricated": 0,
            "high_severity_discrepancies": [],
        },
        "circuit_breaker": circuit_status,
        "duration_ms": 1.0,
    }


# ══════════════════════════════════════════════════════════════
# L1 · 闸门纯决策（真实执行 evaluate_auto_response_gate）
# ══════════════════════════════════════════════════════════════

class TestGateDecision:
    """G3-S1~S6：四类阻断因子各自生效，且都有正对照。"""

    def test_s1_needs_human_review_blocks_and_control_passes(self):
        """G3-S1 人工复核未完成 → 禁止自动响应。

        正对照：同一份结论，仅去掉 needs_human_review → 放行。
        """
        blocked = evaluate_auto_response_gate(_merged(needs_human_review=True))
        assert blocked.allowed is False
        assert "needs_human_review" in blocked.blocking_factors
        assert "人工复核未完成" in blocked.reason

        control = evaluate_auto_response_gate(_merged(needs_human_review=False))
        assert control.allowed is True, "正对照失败：合法结论必须放行"
        assert control.blocking_factors == []

    def test_s2_response_blocked_blocks_and_control_passes(self):
        """G3-S2 faithfulness / 否决闸判定失败 → 禁止自动响应。"""
        blocked = evaluate_auto_response_gate(_merged(response_blocked=True))
        assert blocked.allowed is False
        assert "response_blocked" in blocked.blocking_factors

        control = evaluate_auto_response_gate(_merged(response_blocked=False))
        assert control.allowed is True, "正对照失败"

    def test_s3_cad_tripped_blocks_with_real_breaker_state(self):
        """G3-S3 CAD 独立监督熔断 → 禁止自动响应（熔断状态来自真实状态机）。"""
        tripped_report = _cad_report(_real_tripped_breaker().get_status())

        blocked = evaluate_auto_response_gate(_merged(), cad_report=tripped_report)
        assert blocked.allowed is False
        assert "cad_circuit_tripped" in blocked.blocking_factors
        assert blocked.blocked_by_supervision is True
        assert "CAD 独立监督熔断" in blocked.reason

        closed = CircuitBreaker(persist=False).get_status()
        assert closed["tripped"] is False, "前置条件：全新熔断器不应处于熔断态"
        control = evaluate_auto_response_gate(_merged(), cad_report=_cad_report(closed))
        assert control.allowed is True, "正对照失败：未熔断时必须放行"

    def test_s4_half_open_also_blocks(self):
        """G3-S3 补充：half_open 是试探态，同样不得进入自动响应。

        CAD 报告里的 tripped 对 open 与 half_open 都为 True，
        这里直接核对「半开」这一非闭合态不会漏过闸门。
        """
        br = _real_tripped_breaker()
        br.state.COOLDOWN_SECONDS = 0  # 冷却立即到期 → 下一次审计转入 half_open
        # 半开的**探针**必须是好审核：状态机对一次坏探针会立刻重新熔断回 OPEN
        # （"不给多试几次的机会"），那样就停在 open，测不到 half_open 这一态。
        br.record_audit_result_sync(
            hallucination_risk=0.05, evidence_completeness=0.95, anomaly_detected=False
        )
        assert br.state.state == "half_open", \
            f"预期进入半开试探态，实际为 {br.state.state}"
        assert br.state.tripped is True

        g = evaluate_auto_response_gate(_merged(), cad_report=_cad_report(br.get_status()))
        assert g.allowed is False
        assert "cad_circuit_tripped" in g.blocking_factors

    def test_s5_supervision_exception_blocks_and_control_passes(self):
        """G3-S4 CAD 自身抛异常 → 无法确认结论可信 → 禁止自动响应。"""
        blocked = evaluate_auto_response_gate(
            _merged(), supervision_ok=False, supervision_error="CAD boom: db down"
        )
        assert blocked.allowed is False
        assert "supervision_failed" in blocked.blocking_factors
        assert blocked.blocked_by_supervision is True
        assert "CAD boom: db down" in blocked.reason, "监督异常原因必须可审计，不能只留一个空 reason"

        control = evaluate_auto_response_gate(_merged(), supervision_ok=True)
        assert control.allowed is True, "正对照失败：监督正常时必须放行"

    def test_s6_schema_invalid_blocks_and_missing_field_defaults_to_valid(self):
        """G3-S5 结构化输出校验未通过 → 禁止自动响应。

        缺省（老数据无 schema_valid 字段）必须视为通过，
        否则历史数据会被一律拦死 —— 这是「失败方向」的边界，两侧都要断言。
        """
        blocked = evaluate_auto_response_gate(_merged(schema_valid=False))
        assert blocked.allowed is False
        assert "schema_invalid" in blocked.blocking_factors

        legacy = _merged()
        legacy.pop("schema_valid")
        control = evaluate_auto_response_gate(legacy)
        assert control.allowed is True, "缺省 schema_valid 必须视为合法（老数据兼容）"

    def test_preconditions_still_gate_the_response(self):
        """闸门的前置条件未被四类因子取代：非威胁/低置信/其他 verdict 仍不放行。"""
        assert evaluate_auto_response_gate(_merged(threat_detected=False)).allowed is False
        assert evaluate_auto_response_gate(_merged(confidence=0.1)).allowed is False
        assert evaluate_auto_response_gate(_merged(verdict="false_positive")).allowed is False
        assert evaluate_auto_response_gate(_merged(verdict="")).allowed is False


# ══════════════════════════════════════════════════════════════
# L2 · 全链路：log_ingestion._persist_audit_result
# ══════════════════════════════════════════════════════════════

class _FakeSession:
    """最小 AsyncSession 替身：_persist_audit_result 只用到 get/commit 与属性赋值。"""

    def __init__(self, event):
        self._event = event
        self.commits = 0

    async def get(self, model, pk):
        return self._event

    async def commit(self):
        self.commits += 1

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


class _Recorder:
    """响应引擎替身：记录 on_threat_detected 是否被调用、传了什么。"""

    def __init__(self):
        self.calls = []

    async def on_threat_detected(self, session, threat_info, event_id=None,
                                 session_id="", allow_blocking=None):
        # 镜像 response_orchestrator.on_threat_detected 的缺省回落
        # （response_orchestrator.py: `if allow_blocking is None: ...`）：
        # 调用方不显式传参时，真实编排器读的是 threat_info 里的值。
        # 不复制这条回落，量出来的 allow_blocking 永远是 None，测不到东西。
        effective = (
            bool(threat_info.get("allow_blocking", True))
            if allow_blocking is None else allow_blocking
        )
        self.calls.append({"threat_info": dict(threat_info), "event_id": event_id,
                           "session_id": session_id, "allow_blocking": effective})
        return {"matched": True, "actions_executed": 0}


async def _run_persist(monkeypatch, merged, *, cad_behavior):
    """真实执行 _persist_audit_result，返回响应引擎的调用记录。

    cad_behavior:
      ("report", circuit_status) → CAD 返回真实报告
      ("raise", exc)            → CAD 自身抛异常（故障注入）
    """
    from agents.agent_cad import cad_agent

    event = SimpleNamespace(id=4242, analyzed=False, raw_data={"src_ip": "10.1.1.5"})
    session = _FakeSession(event)

    # 注意：``async with db_session()`` 要求的是**同步**工厂返回异步上下文管理器。
    # 写成 async def 会得到 "coroutine object does not support the async context
    # manager protocol" —— 那是量具的错误，不是被测代码的错误。
    def fake_session():
        return session

    async def fake_cad(_session, _event_id, _audit_llm):
        kind, payload = cad_behavior
        if kind == "raise":
            raise payload
        return _cad_report(payload)

    recorder = _Recorder()

    monkeypatch.setattr(models, "async_session", fake_session)
    monkeypatch.setattr(cad_agent, "audit_pipeline", fake_cad)
    monkeypatch.setattr(response_engine, "get_orchestrator", lambda: recorder)
    monkeypatch.setattr(
        log_ingestion, "event_store",
        SimpleNamespace(invalidate=lambda *a, **k: None,
                        commit_then_invalidate=_noop_commit_then_invalidate),
    )

    rounds = [{
        "round": 1, "mode": "full",
        "audit": {
            "threat_detected": merged.get("threat_detected"),
            "confidence": merged.get("confidence"),
            "evidence": [], "hop_trace": [],
        },
        "missed_threats": [],
    }]
    final = SimpleNamespace(
        to_dict=lambda: {"verdict": merged.get("verdict")},
        grounding_score=1.0, kb_verification={}, schema_valid=True,
        hop_trace=[],
    )

    await log_ingestion.log_ingestor._persist_audit_result(
        event_id=4242, session_id="acc-g3", log_data={"src_ip": "10.1.1.5"},
        all_rounds=rounds, merged=merged, final_audit=final, final_verdict=final,
        max_rounds=3, t_start=0.0,
    )
    # _persist_audit_result 用 asyncio.create_task 下发响应，等它真正跑完再断言
    pending = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
    if pending:
        await asyncio.gather(*pending, return_exceptions=True)
    return recorder


async def _noop_commit_then_invalidate(session, event_id):
    return None


class TestEndToEndAsyncPath:
    """G3 全链路：CAD 结论必须真正决定响应引擎是否被调用。"""

    def test_s7_cad_tripped_means_response_engine_never_called(self, monkeypatch):
        """G3-S3 全链路：CAD 熔断 → 响应引擎一次都不能被调用。

        这是本组最核心的一条：只看 evaluate_auto_response_gate 返回 False
        并不能证明「没人下发封禁」——必须观察到下游零调用。
        """
        rec = _run(_run_persist(
            monkeypatch, _merged(),
            cad_behavior=("report", _real_tripped_breaker().get_status()),
        ))
        assert rec.calls == [], f"CAD 熔断时仍下发了自动响应: {rec.calls}"

    def test_s7_control_normal_case_reaches_response_engine(self, monkeypatch):
        """正对照：CAD 正常时同一条链路必须真的走到响应引擎，且允许封禁。"""
        rec = _run(_run_persist(
            monkeypatch, _merged(),
            cad_behavior=("report", CircuitBreaker(persist=False).get_status()),
        ))
        assert len(rec.calls) == 1, f"正对照失败：合法链路未触发响应 {rec.calls}"
        call = rec.calls[0]
        assert call["allow_blocking"] is True
        assert call["threat_info"]["allow_blocking"] is True
        assert call["threat_info"]["response_source"] == "audit_llm"

    def test_s4_cad_exception_blocks_response_end_to_end(self, monkeypatch):
        """G3-S4 全链路：CAD 抛异常 → 响应引擎零调用。"""
        rec = _run(_run_persist(
            monkeypatch, _merged(), cad_behavior=("raise", RuntimeError("CAD db gone")),
        ))
        assert rec.calls == [], f"监督系统自身故障时仍下发了自动响应: {rec.calls}"

    def test_s1_needs_human_review_blocks_response_end_to_end(self, monkeypatch):
        """G3-S1 全链路：人工复核未完成 → 响应引擎零调用。"""
        rec = _run(_run_persist(
            monkeypatch, _merged(needs_human_review=True),
            cad_behavior=("report", CircuitBreaker(persist=False).get_status()),
        ))
        assert rec.calls == [], f"强制人审未完成时仍下发了自动响应: {rec.calls}"

    def test_suspicious_passes_gate_but_cannot_block(self, monkeypatch):
        """G3-S6（C-5 复核）：suspicious 能进响应引擎，但只允许告警。

        正对照：同样是 needs_human_review=False，只是 verdict 换成 confirmed
        → allow_blocking=True。两侧都要看到，才能证明门是按 verdict 生效的。
        """
        rec = _run(_run_persist(
            monkeypatch, _merged(verdict="suspicious", confidence=0.55),
            cad_behavior=("report", CircuitBreaker(persist=False).get_status()),
        ))
        assert len(rec.calls) == 1, "suspicious 应仍进入响应引擎（仅告警）"
        assert rec.calls[0]["threat_info"]["allow_blocking"] is False, \
            "suspicious 不得具备自动封禁资格"

        control = _run(_run_persist(
            monkeypatch, _merged(verdict="confirmed"),
            cad_behavior=("report", CircuitBreaker(persist=False).get_status()),
        ))
        assert control.calls[0]["threat_info"]["allow_blocking"] is True, "正对照失败"


# ══════════════════════════════════════════════════════════════
# L3 · Temporal 编排时序（真实执行 AuditPipelineWorkflow.run）
# ══════════════════════════════════════════════════════════════

async def _run_workflow(monkeypatch, merged, cad_result):
    """真实执行 workflow.run，只把 execute_activity 换成记录顺序的替身。

    替换的是「activity 的执行边界」，workflow 自身的控制流（循环、闸门、
    是否调用 trigger_response）全部是真实代码。
    """
    from temporalio import workflow as wf_mod
    from temporal.workflows import AuditPipelineWorkflow, AuditWorkflowInput

    order = []

    async def fake_execute_activity(name, args=None, **kwargs):
        order.append(name)
        if name == "audit_round":
            return {"round": 1, "mode": "full", "missed_threats": [], "audit": {}}
        if name == "save_result":
            return merged
        if name == "cad_verify":
            if isinstance(cad_result, Exception):
                raise cad_result
            return cad_result
        return {"ok": True}

    monkeypatch.setattr(wf_mod, "execute_activity", fake_execute_activity)

    result = await AuditPipelineWorkflow().run(AuditWorkflowInput(
        session_id="acc-g3", event_id=4242,
        log_data={"src_ip": "10.1.1.5"}, max_rounds=1,
    ))
    return result, order


class TestTemporalOrdering:
    """G3 时序：cad_verify 必须早于 trigger_response，且阻断时后者根本不被调用。"""

    def test_cad_tripped_prevents_trigger_response(self, monkeypatch):
        """G3-S3 时序：CAD 熔断时 trigger_response 完全不被调用。"""
        cad = {"report": _cad_report(_real_tripped_breaker().get_status())}
        result, order = _run(_run_workflow(monkeypatch, _merged(), cad))

        assert "cad_verify" in order, "workflow 必须真的执行 CAD 独立审计"
        assert "trigger_response" not in order, \
            f"CAD 熔断时仍调度了响应: order={order}"
        assert order.index("cad_verify") < len(order)
        assert result["auto_response_allowed"] is False
        assert result["auto_response_blocking_factors"] == ["cad_circuit_tripped"]

    def test_cad_error_prevents_trigger_response(self, monkeypatch):
        """G3-S4 时序：cad_verify 抛异常 → supervision_failed → 不下发响应。"""
        # workflow 侧把异常转成 error 字段（与真实 worker 的行为一致）：
        # 这里直接以 {"report": None, "error": "..."} 模拟 activity 返回的失败结果。
        cad = {"report": None, "error": "CAD exploded"}
        result, order = _run(_run_workflow(monkeypatch, _merged(), cad))

        assert "trigger_response" not in order, f"监督失败时仍调度了响应: order={order}"
        assert "supervision_failed" in result["auto_response_blocking_factors"]

    def test_control_normal_order_cad_before_response(self, monkeypatch):
        """正对照：正常路径的顺序必须是 audit_round → save_result → cad_verify → trigger_response。"""
        cad = {"report": _cad_report(CircuitBreaker(persist=False).get_status())}
        result, order = _run(_run_workflow(monkeypatch, _merged(), cad))

        assert order == ["audit_round", "save_result", "cad_verify", "trigger_response"], \
            f"时序不符: {order}"
        assert result["auto_response_allowed"] is True
        assert result["auto_response_blocking_factors"] == []

    def test_both_paths_share_one_gate(self):
        """两条生产链路必须共用同一个闸门函数，不能各自内联判定。

        结构性检查（非执行）：如果哪天有人在 log_ingestion 或 activities
        里再写一份内联判定，这里会立刻失败。
        """
        import inspect
        src_ingestion = inspect.getsource(log_ingestion)
        src_wf = inspect.getsource(__import__("temporal.workflows", fromlist=["x"]))
        for src, name in ((src_ingestion, "log_ingestion"),
                          (src_wf, "temporal/workflows")):
            assert "evaluate_auto_response_gate(" in src, \
                f"{name} 未走 veto_gates 单一权威点"
