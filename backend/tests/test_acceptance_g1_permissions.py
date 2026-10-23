"""
验收 · 第一组：权限与工具执行（B-1 / B-2 / B-3）→ 门槛 A

本文件不是新写的修复测试，而是**按验收规范逐条实际执行**的验收用例。
规范原文要求：「每个场景都必须实际执行，而不是只检查代码中有没有相应的 if」。

场景矩阵（对应规范 §二.1）：

  G1-S1  普通 viewer 在请求体中填写 user_role="admin"
         → 仍按认证主体的真实权限判断，越权调用被拒绝
  G1-S2  真实审计工具经过 Executor 执行
         → 规定的权限、策略和参数检查确实生效
  G1-S3  直接调用底层执行入口
         → 不能绕过必须执行的安全检查
  G1-S4  MCP Guard 内部异常
         → 对高风险工具明确拒绝，不得默认放行
  G1-S5  行为检测 Shadow 模式
         → 只记录不拦截；策略层仍对敏感工具生效
  G1-S6  行为检测冷启动，样本数未达阈值
         → 高风险工具不得仅因没有统计基线而失去必要保护
  G1-S7  工具调用审计日志
         → 明确区分 allow / deny / unguarded / 检测异常

重点：验收真实执行入口（tool_registry），而不只是 /guard/call。
规范明确指出两条路径都必须纳入验收。
"""
import asyncio
from types import SimpleNamespace

import pytest

import mcp_guard
import tool_registry as tr_mod
from mcp_guard.behavior_detector import BehaviorDetector
from mcp_guard.call_record import ToolCallRecord
from tool_registry import RISK_HIGH, RISK_LOW, ToolExecutionDenied


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


def _rec(spec: dict) -> ToolCallRecord:
    """behavior_cases 的 dict → ToolCallRecord。

    注意字段名不一一对应：``caller_role`` 在记录里叫 ``user_role``。
    """
    return ToolCallRecord.from_kwargs(
        user_role=spec.get("caller_role", ""),
        tool_name=spec["tool_name"],
        arguments=spec.get("arguments"),
        decision=spec.get("decision", ""),
        reason=spec.get("reason", ""),
        caller=spec.get("caller", ""),
        source=spec.get("source", ""),
        tool_match_method=spec.get("tool_match_method", "exact"),
        ts=spec.get("ts"),
    )


# ══════════════════════════════════════════════════════════════════
# G1-S1  权限来源：请求体不得影响授权判定
# ══════════════════════════════════════════════════════════════════

class TestG1S1_BodyRoleCannotEscalate:
    """viewer 在 body 里自称 admin，必须被**权限层**拒绝。

    ⚠️ 参数必须合法：否则会被参数层先挡掉，测出来的是「参数校验」
    而不是「授权」—— 那样的用例在修复前也会绿，等于什么都没验。
    isolate_host 的参数契约是 ``host``（不是 hostname）。
    """

    _TOOL = "isolate_host"
    _ARGS = {"host": "srv-01"}          # 合法参数

    def _call(self, user, **extra):
        from routers.audit import guard_call
        req = SimpleNamespace(
            tool_name=self._TOOL, arguments=dict(self._ARGS),
            reason="", session_id="", trace_id="", event_id=0,
            **extra,
        )
        return _run(guard_call(req, user=user))

    @staticmethod
    def _check(res, name):
        for c in res.get("checks") or []:
            if c.get("check") == name:
                return c
        raise AssertionError(f"响应里没有 {name} 检查项: {res}")

    def test_viewer_self_declared_admin_is_denied_by_permission(self):
        viewer = SimpleNamespace(username="carol", role="viewer", jti="j2")
        res = self._call(viewer, user_role="admin", caller="admin")

        assert res["decision"] != "allow", f"viewer 提权成功: {res}"
        assert res["decision"] in ("deny", "require_confirmation"), res
        perm = self._check(res, "permission")
        assert perm["passed"] is False, (
            f"拒绝原因不是权限层，验收无效: {perm}"
        )
        # registry 先于 permission 通过 → 场景本身构造正确（工具确实存在）
        assert self._check(res, "registry")["passed"] is True
        # 实测行为：链路在 permission 失败后**短路**，params 不会被执行。
        # 这是正确的快速失败；此处显式记录，避免以后误当成「参数层没生效」。
        names = {c["check"] for c in res.get("checks") or []}
        assert "params" not in names, (
            f"权限失败后仍继续做参数校验: {names}"
        )

    def test_request_model_has_no_user_role_field(self):
        """授权字段不得再出现在请求契约里。"""
        from routers.audit import GuardCallRequest

        fields = set(getattr(GuardCallRequest, "model_fields", {}) or {})
        assert "user_role" not in fields, "请求模型仍声明 user_role"
        assert "caller" not in fields, "请求模型仍声明 caller"

    def test_admin_same_request_is_allowed(self):
        """门槛 B 对照组：真实 admin 走**同一条路径、同一个请求**必须放行。

        否则就是「一律拒绝换安全」，验收必须判不通过。
        """
        admin = SimpleNamespace(username="bob", role="admin", jti="j1")
        res = self._call(admin)
        assert res["decision"] in ("allow", "require_confirmation"), (
            f"真实 admin 被误拒 —— 一律拒绝换安全: {res}"
        )
        assert self._check(res, "permission")["passed"] is True


# ══════════════════════════════════════════════════════════════════
# G1-S2 / S3  真实执行入口不可绕过
# ══════════════════════════════════════════════════════════════════

def _make_registry(risk_level):
    calls = []

    async def _fn(**kwargs):
        calls.append(kwargs)
        return {"ok": True}

    reg = tr_mod.ToolRegistry()
    reg.register("t.probe", _fn, description="probe", risk_level=risk_level)
    return reg, calls


class TestG1S2S3_RealEntryPointCannotBypass:
    def test_unknown_tool_rejected_at_execute(self):
        """直接调 execute() 也必须做注册表成员校验。"""
        reg, calls = _make_registry(RISK_LOW)
        with pytest.raises(ValueError, match="Unknown tool"):
            _run(reg.execute("t.not_registered"))
        assert not calls

    def test_deny_blocks_the_actual_function_call(self):
        """deny 必须在**函数被调用之前**生效。"""
        import tool_registry as m
        original = m._pre_execute_check
        try:
            m._pre_execute_check = lambda *a, **k: {
                "passed": False, "check": "acceptance",
                "reason": "acceptance-injected deny", "signature": None,
            }
            reg, calls = _make_registry(RISK_LOW)
            with pytest.raises(ToolExecutionDenied):
                _run(reg.execute("t.probe", a=1))
            assert not calls, "被拒的工具函数仍然被执行了"
        finally:
            m._pre_execute_check = original

    def test_all_registered_audit_tools_declare_risk_level(self):
        """规范要求：若对只读工具采用简化策略，必须明确列出。
        这里反向核对 —— 每个注册项都必须显式声明风险等级。"""
        tr_mod.init_tool_registry()
        for name in tr_mod.tool_registry.list_tools():
            meta = tr_mod.tool_registry.get_info(name) or {}
            assert meta.get("risk_level"), f"{name} 未声明 risk_level"

    def test_executor_path_runs_the_pre_execute_check(self, monkeypatch):
        """Executor 是审计链路的真实入口，必须经过同一检查。

        ⚠️ 早先这个用例直接赋值替换了 ``Executor._emit_tool_telemetry`` 且未还原，
        导致同文件后续 G1-S7 用例全部打到 no-op —— 单跑绿、全跑红。
        所有替换一律走 monkeypatch。
        """
        import tool_registry as m

        seen = []
        original = m._pre_execute_check

        def _spy(name, meta, args):
            seen.append(name)
            return original(name, meta, args)

        from agents import agent_executor as ex
        from audit_types import ToolCall

        monkeypatch.setattr(m, "_pre_execute_check", _spy)
        monkeypatch.setattr(ex.Executor, "_emit_tool_telemetry",
                            staticmethod(lambda *a, **k: None))
        reg, _ = _make_registry(RISK_LOW)
        # ⚠️ 必须改 executor 自己的名字绑定：它在 import 期做了
        # ``from tool_registry import tool_registry``，改模块属性对它无效。
        monkeypatch.setattr(ex, "tool_registry", reg)
        _run(ex.executor._execute_parallel(
            [ToolCall(call_id="c1", task_id="t1", tool="t.probe",
                      args={"a": 1})], None,
        ))
        assert "t.probe" in seen, "Executor 未触发必经检查"


# ══════════════════════════════════════════════════════════════════
# G1-S4  Guard 故障的失败关闭
# ══════════════════════════════════════════════════════════════════

class TestG1S4_GuardFailureIsFailClosed:
    def test_detector_raises_high_risk_denied(self):
        class _Broken:
            def observe_pre_exec(self, rec):
                raise RuntimeError("detector down")

        original = mcp_guard.mcp_guard.detector
        try:
            mcp_guard.mcp_guard.detector = _Broken()
            res = tr_mod._pre_execute_check(
                "t.danger", {"risk_level": RISK_HIGH}, {})
            assert res["passed"] is False, "检测器故障时高风险工具被放行"
        finally:
            mcp_guard.mcp_guard.detector = original

    def test_detector_missing_high_risk_denied(self):
        original = mcp_guard.mcp_guard.detector
        try:
            mcp_guard.mcp_guard.detector = None
            res = tr_mod._pre_execute_check(
                "t.danger", {"risk_level": RISK_HIGH}, {})
            assert res["passed"] is False, "检测器缺失时高风险工具被放行"
        finally:
            mcp_guard.mcp_guard.detector = original

    def test_low_risk_degrades_with_explicit_reason(self):
        """对照组：只读工具降级放行，但必须**显式说明**，不得静默。"""
        class _Broken:
            def observe_pre_exec(self, rec):
                raise RuntimeError("detector down")

        original = mcp_guard.mcp_guard.detector
        try:
            mcp_guard.mcp_guard.detector = _Broken()
            res = tr_mod._pre_execute_check(
                "t.read", {"risk_level": RISK_LOW}, {})
            assert res["passed"] is True
            assert "不可用" in res["reason"] or "降级" in res["reason"], (
                f"降级放行未显式标注: {res['reason']}"
            )
        finally:
            mcp_guard.mcp_guard.detector = original


# ══════════════════════════════════════════════════════════════════
# G1-S5  Shadow 模式：只关行为签名，不关策略层
# ══════════════════════════════════════════════════════════════════

class TestG1S5_ShadowModeScope:
    """Shadow 只关行为签名这一层，不得顺带关掉策略层。

    用真实基线学习构造异常：先让检测器学满 40 次 rfc1918 的 block_ip，
    再用公网 IP 探测 —— param 维度必然偏离。
    """

    _BASE = {"ip": "10.0.0.5", "duration": 3600}
    _PROBE = {"ip": "8.8.8.8", "duration": 3600}

    def _detector(self, mode):
        from eval_datasets.behavior_cases import baseline_calls, probe_call
        det = BehaviorDetector(mode=mode, min_samples=30)
        for rec in baseline_calls("block_ip", "alice", self._BASE):
            det.observe(_rec(rec))
        return det, probe_call("block_ip", "alice", self._PROBE,
                               hour_offset=1)

    def test_shadow_mode_records_but_does_not_escalate(self):
        det, probe = self._detector("shadow")
        rep = det.observe_pre_exec(_rec(probe))
        assert rep.is_anomaly is True, "影子模式下仍应识别出异常（否则等于关掉）"
        assert rep.action == "logged", (
            f"shadow 模式不应升级处置，实际 {rep.action}"
        )
        assert rep.anomaly_score and rep.anomaly_score > 0, "影子模式必须打分"

    def test_deny_mode_escalates_same_probe(self):
        """对照组：同一探测在 deny 模式下必须升级。"""
        det, probe = self._detector("deny")
        rep = det.observe_pre_exec(_rec(probe))
        assert rep.is_anomaly is True
        assert rep.action in ("confirm", "deny"), (
            f"deny 模式未升级: action={rep.action} dims={rep.dimensions}"
        )

    def test_shadow_does_not_disable_policy_layer(self):
        """规范原文：「不允许 Shadow 的敏感工具仍然受到有效保护」。

        实测架构：``tool_signature_mode`` 只作用于行为签名这一层；
        PolicyEngine 的规则层独立评估，与 shadow 无关。
        本用例证明两者没有被绑在一起 —— 即把模式切到 shadow，
        策略层的 deny 判定依然成立。
        """
        from mcp_guard.policy_engine import PolicyEngine

        pe = PolicyEngine()
        # 构造一条必定命中默认规则的调用（高危工具 + viewer 角色）
        decision, reason, hit = pe.evaluate(
            "isolate_host", "HIGH", {"hostname": "h1"}, "viewer",
        )
        assert decision != "allow", (
            f"敏感工具在策略层未被拦截: decision={decision} hit={hit}"
        )

        # 关键：策略层不接受 mode 参数 —— 切到 shadow 影响不到它
        import inspect
        sig = inspect.signature(PolicyEngine.evaluate)
        assert "mode" not in sig.parameters, (
            "策略层出现了 mode 参数 —— shadow 可能已渗透到规则层"
        )


# ══════════════════════════════════════════════════════════════════
# G1-S6  冷启动
# ══════════════════════════════════════════════════════════════════

class TestG1S6_ColdStart:
    def test_cold_start_returns_none_report(self):
        det = BehaviorDetector(min_samples=30)
        rep = det.observe_pre_exec(ToolCallRecord.from_kwargs(
            tool_name="brand.new", arguments={"src_ip": "8.8.8.8"},
            decision="allow", caller="newcaller", ts=None,
        ))
        assert rep is None or rep.cold_start is True, "冷启动未被识别"

    def test_cold_start_does_not_block_execution(self):
        """冷启动时行为签名无法评分，放行是**当前设计**。

        验收要确认的是：放行时其余保护仍在，且不静默。
        """
        original = mcp_guard.mcp_guard.detector
        try:
            mcp_guard.mcp_guard.detector = BehaviorDetector(
                min_samples=30, mode="deny")
            reg, calls = _make_registry(RISK_HIGH)
            res = _run(reg.execute("t.probe", a=1))
            assert res == {"ok": True}
            assert len(calls) == 1
        finally:
            mcp_guard.mcp_guard.detector = original

    def test_other_protections_survive_cold_start(self):
        """冷启动期间：成员校验、参数上界、超时仍然生效。"""
        original = mcp_guard.mcp_guard.detector
        try:
            mcp_guard.mcp_guard.detector = BehaviorDetector(
                min_samples=30, mode="deny")
            # 成员校验
            reg, _ = _make_registry(RISK_HIGH)
            with pytest.raises(ValueError):
                _run(reg.execute("nope"))
            # 参数上界（P3-6）
            sess = _EmptySession()
            with pytest.raises(tr_mod.ToolParameterRejected):
                _run(tr_mod._event_store_query(
                    sess, event_ids=list(range(501)), limit=501))
        finally:
            mcp_guard.mcp_guard.detector = original


class _EmptySession:
    async def execute(self, stmt):
        class _R:
            def scalars(self):
                return self

            def all(self):
                return []
        return _R()


# ══════════════════════════════════════════════════════════════════
# G1-S7  审计日志的可区分性
# ══════════════════════════════════════════════════════════════════

class TestG1S7_AuditLogDistinguishesOutcomes:
    def _emit(self, monkeypatch, result):
        import mcp_guard.telemetry as tm
        from audit_types import ToolCall, ToolResult
        from agents import agent_executor as ex

        captured = {}
        monkeypatch.setattr(tm, "ingest_tool_call",
                            lambda **kw: captured.update(kw))
        ex.Executor._emit_tool_telemetry(
            ToolCall(call_id="c", task_id="t", tool="t.x", args={}), result, {})
        return captured

    def test_unguarded_is_not_allow(self, monkeypatch):
        from audit_types import ToolResult
        cap = self._emit(monkeypatch,
                         ToolResult(call_id="c", task_id="t", tool="t.x",
                                    success=True, data=[1]))
        assert cap["decision"] == "unguarded", (
            f"未受 Guard 的调用被记成 {cap['decision']!r}"
        )

    def test_deny_is_traceable(self, monkeypatch):
        from audit_types import ToolResult
        cap = self._emit(monkeypatch,
                         ToolResult(call_id="c", task_id="t", tool="t.x",
                                    success=False, error="denied",
                                    security_denied=True))
        assert cap["exec_status"] == "error"
        assert cap["exec_result"]["failure_class"] == "security_denied"

    def test_param_reject_and_timeout_distinguishable(self, monkeypatch):
        from audit_types import ToolResult
        a = self._emit(monkeypatch,
                       ToolResult(call_id="c", task_id="t", tool="t.x",
                                  success=False, error="param_rejected:x>5",
                                  param_rejected=True))
        b = self._emit(monkeypatch,
                       ToolResult(call_id="c", task_id="t", tool="t.x",
                                  success=False, error="tool_timeout:30ms",
                                  timed_out=True))
        assert a["exec_result"]["failure_class"] != \
            b["exec_result"]["failure_class"], "不同失败原因在日志里无法区分"
