"""
P3-1: MCP Guard 与真实工具注册体系统一为一套权威策略与执行边界。

修复的具体缺陷（已实测复现）：
    `SignatureReport.action` 由 `tool_signature_mode` 决定，只在
    `is_anomaly and mode != "shadow"` 时才可能是 confirm / deny。
    MCP Guard 的 `_apply_enforcement` 会据此升级决策；
    而 `tool_registry._pre_execute_check` 修复前只把分数拼进 reason 字符串，
    然后无条件 `passed=True` —— 于是该策略在审计侧**没有执行点**。

    实测：同一份 action="deny" 的报告
        MCP Guard 侧  → 最终决策 = deny
        审计工具侧     → passed=True（reason 仅「行为签名 score=0.97」）

    后果：运维把 tool_signature_mode 配成 deny 之后，响应侧工具会拦，
    11 个审计工具一个都不会拦。策略旋钮存在、有文档、只接了一半。

验收口径不是「deny 能拦住」，而是**收敛契约本身**：
    同一份报告送进两个执行点，得到的处置必须一致 ——
    这才是「一套权威策略」的定义，且能在任一侧被单独改坏时立刻报警。
"""
import pytest

import mcp_guard
import tool_registry as tr_mod
from mcp_guard.behavior_detector import (
    DECISION_RANK,
    SignatureReport,
    escalate_decision,
)
from mcp_guard.call_record import ToolCallRecord
from mcp_guard.guard_server import GuardDecision, McpGuardServer, ToolCallRequest
from tool_registry import RISK_HIGH, RISK_LOW, ToolExecutionDenied


# ═══════════════════════════════════════════
# 夹具
# ═══════════════════════════════════════════

class _StubDetector:
    """返回固定 action 的检测器替身。"""

    def __init__(self, action):
        self._action = action
        self.calls = 0

    def observe_pre_exec(self, rec):
        self.calls += 1
        return SignatureReport(
            anomaly_score=0.97,
            is_anomaly=True,
            reasons=["参数模式偏离已学习指纹"],
            dimensions={"param": 0.97},
            cold_start=False,
            sample_count=50,
            action=self._action,
        )

    def mode(self):
        return "deny" if self._action == "deny" else "confirm"


def _report(action: str) -> SignatureReport:
    return SignatureReport(
        anomaly_score=0.97,
        is_anomaly=True,
        reasons=["参数模式偏离已学习指纹"],
        dimensions={"param": 0.97},
        cold_start=False,
        sample_count=50,
        action=action,
    )


def _make_registry(risk_level: str):
    """注册一个记录调用次数的探针工具。"""
    calls = []

    async def _fn(**kwargs):
        calls.append(kwargs)
        return {"ok": True}

    reg = tr_mod.ToolRegistry()
    reg.register("t.probe", _fn, description="probe", risk_level=risk_level)
    return reg, calls


def _run(coro):
    import asyncio
    return asyncio.run(coro)


@pytest.fixture()
def stub_guard(monkeypatch):
    """可注入 action 的检测器。"""
    def _install(action):
        d = _StubDetector(action)
        monkeypatch.setattr(mcp_guard.mcp_guard, "detector", d)
        return d
    return _install


# ═══════════════════════════════════════════
# A. 收敛契约：同一份报告，两个执行点处置一致
# ═══════════════════════════════════════════

class TestConvergenceContract:
    """这是 P3-1 的核心断言，不是「deny 能拦住」而是「两边一致」。"""

    def _guard_decision(self, action: str) -> str:
        g = McpGuardServer()
        request = ToolCallRequest(
            tool_name="block_ip", arguments={}, user_role="admin",
        )
        decision = GuardDecision(status="allow", reason="前置检查通过")
        rec = ToolCallRecord.from_kwargs(
            user_role="admin", tool_name="block_ip",
            arguments={}, decision="allow",
        )
        g._apply_enforcement(request, decision, rec, _report(action))
        return decision.status

    def _audit_decision(self, action: str, stub_guard) -> dict:
        stub_guard(action)
        return tr_mod._pre_execute_check(
            "event_store.query", {"risk_level": "low"}, {"session_id": "s1"},
        )

    @pytest.mark.parametrize("action,expected", [
        ("deny", "deny"),
        ("confirm", "require_confirmation"),
        ("logged", "allow"),
    ])
    def test_both_entry_points_agree(self, action, expected, stub_guard):
        """两个执行点对同一 action 必须给出同一档位。"""
        guard = self._guard_decision(action)
        audit = self._audit_decision(action, stub_guard)

        assert guard == expected, (
            f"MCP Guard 侧对 action={action} 给出 {guard}，预期 {expected}"
        )
        # 审计侧：deny 阻断；confirm / logged 放行
        if expected == "deny":
            assert audit["passed"] is False, (
                f"审计侧对 action=deny 仍然 passed=True —— "
                f"reason={audit['reason']!r}；策略旋钮在审计侧仍未接线"
            )
        else:
            assert audit["passed"] is True

    def test_escalate_is_the_only_rule(self):
        """两个执行点都必须经由 escalate_decision，规则不得各写一份。

        防的是「改了 escalate_decision 但某个执行点绕过它」——
        那种情况下本文件其余测试仍会全绿。
        """
        import inspect

        src = inspect.getsource(tr_mod._pre_execute_check)
        # 匹配的是**调用**而不是名字：裸名字在 import 行里也会出现，
        # 只查名字的话「导入但没调用」也能通过这道断言。
        assert "escalate_decision(" in src, (
            "_pre_execute_check 未调用共用的 escalate_decision，"
            "审计侧存在第二份策略判定"
        )
        from mcp_guard import guard_server
        gsrc = inspect.getsource(guard_server.McpGuardServer._apply_enforcement)
        assert "escalate_decision(" in gsrc, (
            "_apply_enforcement 未调用共用的 escalate_decision"
        )

    def test_guard_server_no_longer_inlines_its_own_rule(self):
        """guard_server 里不得残留内联的档位判定。"""
        import inspect
        from mcp_guard import guard_server

        src = inspect.getsource(guard_server.McpGuardServer._apply_enforcement)
        # 旧实现里有这两行特征
        assert '"deny" if report.action' not in src, (
            "_apply_enforcement 仍在内联判定，未收敛到 escalate_decision"
        )


# ═══════════════════════════════════════════
# B. 升级规则本身的语义
# ═══════════════════════════════════════════

class TestEscalateDecision:
    def test_none_report_never_escalates(self):
        assert escalate_decision("allow", None) == ("allow", "")

    def test_logged_never_escalates(self):
        assert escalate_decision("allow", _report("logged")) == ("allow", "")

    def test_deny_upgrades_allow(self):
        d, why = escalate_decision("allow", _report("deny"))
        assert d == "deny"
        assert "behavior_signature" in why

    def test_confirm_upgrades_allow(self):
        d, _ = escalate_decision("allow", _report("confirm"))
        assert d == "require_confirmation"

    def test_never_downgrades(self):
        """已 deny 的决策不得被 confirm 拉回 —— 只升不降。"""
        assert escalate_decision("deny", _report("confirm"))[0] == "deny"
        assert escalate_decision(
            "require_confirmation", _report("confirm")
        )[0] == "require_confirmation"

    def test_deny_beats_confirm(self):
        assert escalate_decision(
            "require_confirmation", _report("deny")
        )[0] == "deny"

    def test_decision_rank_is_ordered(self):
        assert DECISION_RANK["allow"] < DECISION_RANK["require_confirmation"]
        assert DECISION_RANK["require_confirmation"] < DECISION_RANK["deny"]

    def test_reason_mentions_score_when_no_reasons(self):
        rep = _report("deny")
        rep.reasons = []
        _, why = escalate_decision("allow", rep)
        assert "0.97" in why, "无 reasons 时 reason 应回落到 score"


# ═══════════════════════════════════════════
# C. 审计侧端到端：deny 必须真的拦住执行
# ═══════════════════════════════════════════

class TestAuditToolDenialIsEnforced:
    def test_deny_blocks_tool_execution(self, stub_guard):
        stub_guard("deny")
        reg, calls = _make_registry(RISK_LOW)
        with pytest.raises(ToolExecutionDenied) as ei:
            _run(reg.execute("t.probe", a=1))
        assert not calls, "被行为签名拒绝的工具函数仍被执行了"
        assert "签名" in str(ei.value) or "signature" in str(ei.value).lower()

    def test_deny_reason_carries_the_policy_text(self, stub_guard):
        stub_guard("deny")
        res = tr_mod._pre_execute_check(
            "event_store.query", {"risk_level": "low"}, {},
        )
        assert res["passed"] is False
        assert "拒绝" in res["reason"], (
            f"拒绝原因未说明策略依据：{res['reason']!r}"
        )

    def test_high_risk_tool_also_blocked_by_deny(self, stub_guard):
        """风险等级只决定「检测器故障时」的处置，不该削弱 deny 的强度。"""
        stub_guard("deny")
        reg, calls = _make_registry(RISK_HIGH)
        with pytest.raises(ToolExecutionDenied):
            _run(reg.execute("t.probe", a=1))
        assert not calls


# ═══════════════════════════════════════════
# D. confirm：显式标注，不得静默
# ═══════════════════════════════════════════

class TestConfirmIsExplicit:
    def test_confirm_passes_but_says_so(self, stub_guard):
        """confirm 在审计命名空间按记录放行，但 reason 必须写出这一点。

        这条是防「静默降级」的：若实现把 confirm 当成 logged 处理，
        运维会以为策略生效了，实际什么都没发生。
        """
        stub_guard("confirm")
        res = tr_mod._pre_execute_check(
            "event_store.query", {"risk_level": "low"}, {},
        )
        assert res["passed"] is True
        assert "确认" in res["reason"], (
            f"confirm 未在 reason 中显式标注：{res['reason']!r}"
        )

    def test_confirm_does_not_silently_look_like_clean_pass(self, stub_guard):
        """confirm 的 reason 与「无异常」路径的 reason 必须可区分。"""
        stub_guard("confirm")
        with_confirm = tr_mod._pre_execute_check(
            "event_store.query", {"risk_level": "low"}, {},
        )
        stub_guard("logged")
        with_logged = tr_mod._pre_execute_check(
            "event_store.query", {"risk_level": "low"}, {},
        )
        assert with_confirm["reason"] != with_logged["reason"], (
            "confirm 与 logged 的原因文本相同 —— "
            "「策略要求确认」被静默吞掉了"
        )

    def test_confirm_does_not_block_by_default(self, stub_guard):
        """防过度收紧：默认 mode=confirm，且只读查询在真实攻击流量上
        本就会频繁偏离指纹，confirm 改判 deny 会系统性打断审计流水线。"""
        stub_guard("confirm")
        reg, calls = _make_registry(RISK_LOW)
        result = _run(reg.execute("t.probe", a=1))
        assert result == {"ok": True}
        assert len(calls) == 1


# ═══════════════════════════════════════════
# E. 防过度收紧：正常路径不受影响
# ═══════════════════════════════════════════

class TestNoRegressionOnNormalPath:
    def test_no_report_passes(self, monkeypatch):
        import mcp_guard as mg

        class _NoneDetector:
            def observe_pre_exec(self, rec):
                return None
        monkeypatch.setattr(mg.mcp_guard, "detector", _NoneDetector())
        res = tr_mod._pre_execute_check(
            "event_store.query", {"risk_level": "low"}, {},
        )
        assert res["passed"] is True

    def test_real_registry_tools_still_execute(self, monkeypatch):
        """真实注册表里的只读工具不得因本改动被拦。"""
        import mcp_guard as mg

        class _NoneDetector:
            def observe_pre_exec(self, rec):
                return None
        monkeypatch.setattr(mg.mcp_guard, "detector", _NoneDetector())
        assert "event_store.query" in tr_mod.tool_registry.list_tools()
        res = tr_mod._pre_execute_check(
            "event_store.query",
            {"risk_level": tr_mod.tool_registry.risk_level("event_store.query")},
            {"session_id": "s1"},
        )
        assert res["passed"] is True

    def test_detector_failure_semantics_unchanged(self, monkeypatch):
        """P0 的失败关闭语义不得被本次改动破坏：
        检测器抛异常时 high/medium 拒绝、low 降级放行。"""
        import mcp_guard as mg

        class _Broken:
            def observe_pre_exec(self, rec):
                raise RuntimeError("detector down")
        monkeypatch.setattr(mg.mcp_guard, "detector", _Broken())

        high = tr_mod._pre_execute_check("t.x", {"risk_level": RISK_HIGH}, {})
        low = tr_mod._pre_execute_check("t.x", {"risk_level": RISK_LOW}, {})
        assert high["passed"] is False
        assert low["passed"] is True

    def test_unknown_tool_still_rejected(self):
        reg, _ = _make_registry(RISK_LOW)
        with pytest.raises(ValueError, match="Unknown tool"):
            _run(reg.execute("nope.tool"))


# ══════════════════════════════════════════════════════════════════
# F. P3-6：审计查询工具的参数上界
# ══════════════════════════════════════════════════════════════════
#
# 修复的缺陷（P3-1 第一轮定位时端到端实测确认）：
#   event_store.query 的 limit 原样透传给 event_store.query，
#   而 event_ids 分支**连 limit 都不看**（直接 .scalars().all()）。
#   两者都可经 missed_threats[].evidence 自由文本被放大到任意规模 ——
#   实测一个 28891 字符的逗号分隔 blob 能把 5000 个 ID 一路送进 SQL 的 IN，
#   且下游 limit 被设成 len(target_ids)，等于把上界直接让给输入长度。
#   同一循环里 target_ips 却写着 [:3]：ID 侧与 IP 侧不对称。
#
# 行为分级（不夸大）：这是**资源耗尽面**，不是权限绕过或注入 ——
# P2-B-4 的并发闸（8）与 timeout_ms 已经把单次调用的爆炸半径封住了。
#
# 关键取舍：工具侧**拒绝**（ToolParameterRejected），Decomposer 侧**截断并留痕**。
#   工具侧若截断，event_ids 只查了一部分却会被记成「已复核该遗漏威胁」，
#   那是一份无法从结果里看出来的假保证；拒绝则让调用显式失败、威胁留在
#   「已遗漏」的可见状态。Decomposer 属规划层，为一个超大 blob 中止整个
#   补审批次代价过大，所以截断，但 truncation 必须出现在返回的 plan 里。

class _FakeEvent:
    """_event_store_query 结果构造所需的最小事件对象。

    注意两个返回块读的**不是同一组字段**：event_ids 分支取
    ``(e.raw_data or {}).get("_anomaly_score")``，通用分支取 ``e.anomaly_score``。
    这里是事实记录，不是笔误。
    """

    def __init__(self, eid: int):
        self.id = eid
        self.event_type = "ssh_bruteforce"
        self.severity = "high"
        self.src_ip = "8.8.8.8"
        self.dst_ip = "10.0.0.5"
        self.message = "x" * 300          # 故意超长：验证是否被截到 200
        self.raw_data = {"_anomaly_score": 0.9}
        self.anomaly_score = 0.9
        self.created_at = None


class _ScalarResult:
    def __init__(self, rows):
        self._rows = rows

    def scalars(self):
        return self

    def all(self):
        return list(self._rows)


class _CapturingSession:
    """记录 execute() 收到的语句，用于检验 SQL 上到底有没有 limit。"""

    def __init__(self, rows):
        self.rows = rows
        self.stmts = []

    async def execute(self, stmt):
        self.stmts.append(stmt)
        return _ScalarResult(self.rows)


class TestQueryParamBounds:
    """越界必须被拒绝 / 截断，且必须**可见**。

    本段原先是 4 项「缺口登记测试」——它们断言的是缺陷本身还在。
    P3-6 修复后全部改写为负面测试：旧代码下必然失败，修复后通过。
    """

    def test_event_ids_over_bound_is_rejected(self):
        """event_ids 超过上界 → 拒绝，而不是悄悄查前 N 条。"""
        sess = _CapturingSession([_FakeEvent(1)])
        ids = list(range(1, 502))          # 501 > 默认上界 500
        with pytest.raises(tr_mod.ToolParameterRejected) as ei:
            _run(tr_mod._event_store_query(sess, event_ids=ids, limit=501))
        assert ei.value.field == "event_ids"
        assert ei.value.limit == 500
        assert not sess.stmts, "越界的查询不应打到数据库"

    def test_limit_over_bound_is_rejected(self):
        sess = _CapturingSession([_FakeEvent(1)])
        with pytest.raises(tr_mod.ToolParameterRejected) as ei:
            _run(tr_mod._event_store_query(sess, event_ids=[1], limit=100000))
        assert ei.value.field == "limit"

    def test_nonpositive_limit_is_rejected(self):
        """limit=0 返回空列表，与「没查到威胁」在下游完全同形。"""
        sess = _CapturingSession([])
        with pytest.raises(tr_mod.ToolParameterRejected) as ei:
            _run(tr_mod._event_store_query(sess, event_ids=[], limit=0))
        assert ei.value.field == "limit"

    def test_within_bound_query_still_executes(self):
        """防过度收紧：正好等于上界的合法查询必须照常执行。"""
        sess = _CapturingSession([_FakeEvent(i) for i in range(1, 501)])
        ids = list(range(1, 501))          # 500 == 上界，放行
        out = _run(tr_mod._event_store_query(sess, event_ids=ids, limit=500))
        assert len(out) == 500
        assert len(sess.stmts) == 1

    def test_bounds_are_configurable_and_honour_zero(self):
        """上界来自 config，且**显式 0 必须被尊重**。

        capacity._int_setting 写的是 ``int(getattr(...) or default)``，
        会把配置里的 0 吞成默认值 —— 对「上界」而言 0 的含义是全部拒绝，
        经它读出来会变成 1000，一个安全边界被静默放宽。
        这条测试就是钉住 strict_int_setting 与 _int_setting 的这个差别。
        """
        from capacity import _int_setting, strict_int_setting
        from config import settings

        monkey = pytest.MonkeyPatch()
        try:
            monkey.setattr(settings, "tool_query_max_limit", 0)
            assert strict_int_setting("tool_query_max_limit", 1000) == 0, (
                "显式 0 被吞成默认值 —— 上界配置形同虚设"
            )
            assert _int_setting("tool_query_max_limit", 1000) == 1000, (
                "_int_setting 的既有语义变了；本修复不应改它，"
                "只是新增 strict_int_setting 绕开它"
            )
            sess = _CapturingSession([])
            with pytest.raises(tr_mod.ToolParameterRejected):
                _run(tr_mod._event_store_query(sess, event_ids=[], limit=1))

            monkey.setattr(settings, "tool_query_max_limit", 5)
            sess2 = _CapturingSession([])
            with pytest.raises(tr_mod.ToolParameterRejected):
                _run(tr_mod._event_store_query(sess2, event_ids=[], limit=6))
        finally:
            monkey.undo()

    def test_free_text_evidence_is_capped_and_recorded(self):
        """源头封顶，且截断**必须留痕**——静默截断就是静默降级。

        同函数内 target_ips 明确写了 [:3]，target_ids 此前没有任何等价上限。
        """
        from agents.agent_decomposer import Decomposer

        n = 5000
        missed = [{
            "description": "补审",
            "evidence": ",".join(str(i) for i in range(1, n + 1)),
        }]
        out = _run(Decomposer()._decompose_supplement(
            event={}, session_id="s1", anomaly_score=0.9,
            missed_threats=missed,
        ))
        t1 = next(t for t in out["sub_tasks"] if t["task_id"] == "s1")
        assert len(t1["params"]["event_ids"]) == 500
        assert t1["params"]["limit"] == 500
        trunc = out["param_truncations"]
        assert trunc, "截断没有出现在 plan 里 —— 补审只覆盖了一部分却无人知晓"
        assert trunc[0]["requested"] == n
        assert trunc[0]["used"] == 500

    def test_no_truncation_record_when_within_bound(self):
        """防过度收紧：没截断时不要凭空造一条 truncation 记录。"""
        from agents.agent_decomposer import Decomposer

        missed = [{"description": "补审", "evidence": "1,2,3"}]
        out = _run(Decomposer()._decompose_supplement(
            event={}, session_id="s1", anomaly_score=0.9,
            missed_threats=missed,
        ))
        assert out["param_truncations"] == []


class TestTruncationActuallyReachesObservability:
    """截断记录必须**真的**能被下游读到，而不只是躺在返回 dict 里。

    背景：P3-6 第一版把 ``param_truncations`` 放进了 Decomposer 的返回 dict，
    注释里写「必须能被下游读到」。但 ``emit_plan`` 当时只挑
    ``sub_tasks`` / ``mode`` / ``depth_reason`` 等固定字段，
    整个键**没有任何消费者** —— 实际效果与只打一行日志完全相同。

    这条测试钉的是「读得到」这个事实本身，不是键的存在。
    """

    def _plan(self, truncations):
        return {
            "audit_depth": "supplement",
            "sub_tasks": [{"task_id": "s1", "type": "query_events"}],
            "llm_analysis": "",
            "depth_reason": "补审 1 项遗漏威胁",
            "mode": "supplement",
            "param_truncations": truncations,
        }

    def test_truncation_lands_in_thought_metrics(self):
        from observability.thought_events import emit_plan, thought_buffer

        eid = 987654
        thought_buffer.clear(eid)
        trunc = [{"field": "event_ids", "requested": 5000,
                  "used": 500, "limit": 500}]
        emit_plan(self._plan(trunc), event_id=eid, session_id="s1")
        steps = thought_buffer.get(eid)
        assert steps, "思维链里没有这条 plan 步骤"
        assert steps[0]["metrics"]["param_truncations"] == trunc, (
            "截断记录没落进运维面 —— 与只打日志无异"
        )

    def test_absent_truncation_yields_empty_list_not_missing_key(self):
        """稳定形状：没有截断时给 []，消费者不必处理 None。"""
        from observability.thought_events import emit_plan, thought_buffer

        eid = 987655
        thought_buffer.clear(eid)
        emit_plan(self._plan([]), event_id=eid, session_id="s1")
        steps = thought_buffer.get(eid)
        assert steps[0]["metrics"]["param_truncations"] == []


class TestParamRejectionIsVisible:
    """拒绝要**看得见**：落成独立一类结果，而不是一次普通工具失败。

    理由与 ``security_denied`` / ``timed_out`` 同源 ——
    「因为上游给的计划不合法所以没查」和「工具崩了」在下游要做不同反应：
    前者说明规划层出了问题（值得告警），后者说明工具不可靠。
    混进同一个 success=False，这两种情况就再也分不开了。
    """

    def test_executor_marks_param_rejected_distinctly(self, monkeypatch):
        from agents import agent_executor as ex
        from audit_types import ToolCall
        import models as _models

        class _FakeCM:
            async def __aenter__(self):
                return object()

            async def __aexit__(self, *a):
                return False

        monkeypatch.setattr(_models, "async_session", lambda: _FakeCM())

        async def reject(name, **kw):
            raise tr_mod.ToolParameterRejected(name, "event_ids", 5000, 500)

        monkeypatch.setattr(ex.tool_registry, "execute", reject)
        monkeypatch.setattr(ex.Executor, "_emit_tool_telemetry",
                            staticmethod(lambda *a, **k: None))

        res = _run(ex.executor._execute_parallel(
            [ToolCall(call_id="c1", task_id="t1",
                      tool="event_store.query", args={})], None
        ))
        assert len(res) == 1
        assert res[0].success is False
        assert res[0].param_rejected is True, "参数越界未被标记"
        assert res[0].security_denied is False, "参数越界被误标为安全拒绝"
        assert res[0].timed_out is False, "参数越界被误标为超时"
        assert "param_rejected" in res[0].error

    def test_tool_result_serialises_param_rejected(self):
        from audit_types import ToolResult

        d = ToolResult(
            call_id="c", task_id="t", tool="x", success=False,
            error="param_rejected:event_ids=5000>500", param_rejected=True,
        ).to_dict()
        assert d["param_rejected"] is True

    def test_failure_class_reaches_persisted_telemetry(self, monkeypatch):
        """类别必须落进**已持久化**的遥测记录，而不只是 ToolResult 上的标志。

        修复前 _emit_tool_telemetry 只取 success/error，
        三类失败在审计日志里完全同形 —— 只有 ToolResult.to_dict() 带得出去，
        而生产路径上没有任何地方调它（序列化 ≠ 可消费）。
        """
        from agents import agent_executor as ex
        from audit_types import ToolCall, ToolResult
        import mcp_guard.telemetry as tm

        captured = {}
        monkeypatch.setattr(tm, "ingest_tool_call",
                            lambda **kw: captured.update(kw))

        for flag, expect in (
            ("security_denied", "security_denied"),
            ("param_rejected", "param_rejected"),
            ("timed_out", "timeout"),
        ):
            captured.clear()
            res = ToolResult(call_id="c", task_id="t", tool="x.y",
                             success=False, error="boom", **{flag: True})
            tc = ToolCall(call_id="c", task_id="t", tool="x.y", args={})
            ex.Executor._emit_tool_telemetry(tc, res, {})
            assert captured["exec_result"]["failure_class"] == expect, (
                f"{flag} 未进入遥测记录"
            )
            assert captured["exec_status"] == "error"

    def test_success_path_carries_no_failure_class(self, monkeypatch):
        """防过度收紧：成功调用不得被塞进 failure_class。"""
        from agents import agent_executor as ex
        from audit_types import ToolCall, ToolResult
        import mcp_guard.telemetry as tm

        captured = {}
        monkeypatch.setattr(tm, "ingest_tool_call",
                            lambda **kw: captured.update(kw))
        res = ToolResult(call_id="c", task_id="t", tool="x.y", success=True,
                         data=[1])
        ex.Executor._emit_tool_telemetry(
            ToolCall(call_id="c", task_id="t", tool="x.y", args={}), res, {})
        assert captured["exec_status"] == "success"
        assert captured["exec_result"] is None

    def test_telemetry_no_longer_claims_no_param_validation(self, monkeypatch):
        """P3-6 给查询路径加了参数校验，那句声明必须跟着改。

        一条会随代码漂移成假话的审计轨迹声明，比没有声明更糟。
        """
        from agents import agent_executor as ex
        from audit_types import ToolCall, ToolResult
        import mcp_guard.telemetry as tm

        captured = {}
        monkeypatch.setattr(tm, "ingest_tool_call",
                            lambda **kw: captured.update(kw))
        res = ToolResult(call_id="c", task_id="t", tool="event_store.query",
                         success=False, error="param_rejected:x>500",
                         param_rejected=True)
        ex.Executor._emit_tool_telemetry(
            ToolCall(call_id="c", task_id="t", tool="event_store.query",
                     args={}), res, {})
        blob = " ".join(c.get("message", "") for c in captured["checks"])
        assert "不经过 RBAC/参数校验/规则引擎" not in blob, (
            "遥测仍在声明本链路不做参数校验 —— P3-6 之后这句话是假的"
        )
        assert any(c["check"] == "query_param_bounds"
                   for c in captured["checks"]), (
            "参数越界时遥测里没有对应的检查项"
        )

    def test_rejection_escapes_registry_execute(self, monkeypatch):
        """异常必须穿过 execute() 的并发闸与 except 分支**原样上抛**。

        少了这一条，``execute`` 里那个兜底的 ``except Exception: raise``
        就可能把「参数被拒」压成「工具崩了」。
        """
        import mcp_guard as mg

        class _NoneDetector:
            def observe_pre_exec(self, rec):
                return None

        monkeypatch.setattr(mg.mcp_guard, "detector", _NoneDetector())

        reg = tr_mod.ToolRegistry()
        reg.register("t.q", tr_mod._event_store_query, description="q",
                     risk_level=RISK_LOW)
        with pytest.raises(tr_mod.ToolParameterRejected):
            _run(reg.execute("t.q", session=None,
                             event_ids=list(range(501)), limit=501))
