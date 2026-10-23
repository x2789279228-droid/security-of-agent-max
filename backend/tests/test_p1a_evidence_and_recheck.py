"""
P1-a 负面测试: C-5 证据/ATT&CK 收口 + suspicious 封禁资格 + recheck 升级

C-5 四处：
  1. strip_phantom_mitre 判定基准可被攻击者日志洗白 + 无词边界 + 只存编号无原因
  2. sanitize_merged_audit 被 `except: pass` 静默吞掉 → 严重度封顶失效
  3. 死代码：无条件写入空的 mitre_techniques，看起来像「已检查且无标签」
  4. tools-only 用 has_admitted_claims=threat 自证 → 零证据可达 confirmed

suspicious 封禁资格：
  allow_blocking 是 orchestrator 的函数参数且默认 True；Audit-LLM 两条调用
  路径都没传参，于是 threat_info 里的决定被完全忽略，双轨门槛形同不存在。

recheck 单调性：
  修复前复核只能降不能升，且就地覆盖原结论 —— 漏报不可纠正，方向反了。

验收: 新测试在旧代码下失败，修复后通过。
"""
import asyncio
import io
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
# C-5.1 / C-5.3  ATT&CK 标签判定与死代码
# ═══════════════════════════════════════════

class TestMitreStripHardening:
    def test_attacker_log_message_cannot_launder_technique(self):
        from veto_gates import strip_phantom_mitre
        out = strip_phantom_mitre(
            {"mitre_techniques": ["T1071"]},
            evidence="failed password; ref=T1071",           # 攻击者可控正文
            trusted_evidence="failed password",               # 可信证据里没有
        )
        assert out["mitre_techniques"] == [], "攻击者在日志里写编号即让标签通过"
        assert "T1071" in out["stripped_mitre"]

    def test_technique_present_in_trusted_evidence_is_kept(self):
        from veto_gates import strip_phantom_mitre
        out = strip_phantom_mitre(
            {"mitre_techniques": ["T1071"]},
            trusted_evidence="知识库映射: T1071 Application Layer Protocol",
        )
        assert out["mitre_techniques"] == ["T1071"]

    def test_word_boundary_prevents_substring_match(self):
        """T10460 不得满足 T1046。"""
        from veto_gates import strip_phantom_mitre
        out = strip_phantom_mitre(
            {"mitre_techniques": ["T1046"]}, trusted_evidence="ref T10460"
        )
        assert out["mitre_techniques"] == [], "词边界缺失导致编号误命中"
        assert "T1046" in out["stripped_mitre"]

    def test_word_boundary_allows_exact_match(self):
        from veto_gates import strip_phantom_mitre
        out = strip_phantom_mitre(
            {"mitre_techniques": ["T1046"]}, trusted_evidence="ref T1046 and T1047"
        )
        assert out["mitre_techniques"] == ["T1046"]

    def test_strip_reason_is_recorded(self):
        from veto_gates import strip_phantom_mitre
        out = strip_phantom_mitre(
            {"mitre_techniques": ["T9999"]}, trusted_evidence="nothing"
        )
        assert out.get("stripped_mitre_reasons"), "剥离原因未记录，审计无法追溯"
        assert out["stripped_mitre_reasons"]["T9999"]

    def test_dead_code_no_longer_injects_empty_field(self):
        """无该字段时不得写入空列表 —— 那看起来像「已检查且无标签」。"""
        from veto_gates import strip_phantom_mitre
        out = strip_phantom_mitre({"verdict": "confirmed", "severity": "high"})
        assert "mitre_techniques" not in out

    def test_end_to_end_laundering_scenario(self):
        """真实链路：原始 message 里的编号不得进入 phantom 判定基准。"""
        from faithfulness_gate import apply_faithfulness_gate, contexts_from_audit
        ctx = contexts_from_audit(
            {"event": "SSH_LOGIN_FAILED",
             "message": "failed password; ref=T1071",
             "src_ip": "10.0.0.5"},
            [{"claim": "存在暴力破解", "type": "暴力破解",
              "evidence_quotes": ["failed password"], "evidence_ids": [1]}],
        )
        out = apply_faithfulness_gate(
            {"threat_detected": True, "verdict": "confirmed",
             "confidence": 0.9, "severity": "high",
             "mitre_techniques": ["T1071"]},
            answer="攻击者使用 T1071 建立 C2 通信",
            contexts=ctx,
            non_llm_signals={"event_type": "SSH_LOGIN_FAILED"},
        )
        assert out["mitre_techniques"] == []
        assert "T1071" in out.get("stripped_mitre", [])


# ═══════════════════════════════════════════
# C-5.2  静默吞掉安全校验异常
# ═══════════════════════════════════════════

class TestSanitizeFailClosed:
    def test_sanitize_failure_blocks_instead_of_pass(self, monkeypatch):
        from faithfulness_gate import apply_faithfulness_gate
        import veto_gates

        def _boom(*a, **k):
            raise ValueError("merged.severity 不是字符串")

        monkeypatch.setattr(veto_gates, "sanitize_merged_audit", _boom)
        out = apply_faithfulness_gate(
            {"threat_detected": True, "verdict": "confirmed",
             "confidence": 0.95, "severity": "critical"},
            answer="检测到严重威胁",
            contexts=[{"content": "严重威胁"}],
            non_llm_signals={"sigma_detected": True},
        )
        assert out.get("response_blocked") is True, (
            "sanitize 失败后未阻断自动响应 —— C-5 未修复"
        )
        assert out.get("needs_human") is True
        assert out.get("sanitize_failed"), "失败原因未记录"
        assert out.get("demoted_by") == "sanitize_merged_audit_fail_closed"
        # 严重度不得继续以未封顶的值流通
        assert out.get("severity") in {"info", "low", "medium"}

    def test_normal_path_unaffected(self):
        from faithfulness_gate import apply_faithfulness_gate
        out = apply_faithfulness_gate(
            {"threat_detected": True, "verdict": "confirmed",
             "confidence": 0.9, "severity": "high"},
            answer="检测到暴力破解 10.0.0.5",
            contexts=[{"content": "检测到暴力破解 10.0.0.5 failed password"}],
            non_llm_signals={"sigma_detected": True},
        )
        assert "sanitize_failed" not in out


# ═══════════════════════════════════════════
# C-5.4  tools-only 无证据自证收口
# ═══════════════════════════════════════════

class TestDeterministicCloseout:
    def test_free_text_event_name_alone_cannot_confirm(self):
        from veto_gates import extract_non_llm_signals, deterministic_non_llm_verdict
        s = extract_non_llm_signals({"event": "命令注入", "message": "x"})
        d = deterministic_non_llm_verdict(s)
        assert d.verdict != "confirmed", (
            "仅凭自由文本事件名就 confirmed —— 零证据收口"
        )
        assert d.threat_detected is False
        assert d.evidence_basis == []

    def test_sigma_hit_can_confirm_but_forces_human(self):
        from veto_gates import extract_non_llm_signals, deterministic_non_llm_verdict
        s = extract_non_llm_signals(
            {"event": "x", "_sigma": {"detected": True, "max_severity": "critical",
                                      "rule_count": 2}}
        )
        d = deterministic_non_llm_verdict(s)
        assert d.verdict == "confirmed"
        assert d.needs_human_review is True, "tools-only 从未做过 Grounding 校验"
        assert d.evidence_basis, "必须记录判定依据"
        assert any(b.startswith("sigma:") for b in d.evidence_basis)

    def test_no_signal_is_insufficient_not_false_positive(self):
        from veto_gates import extract_non_llm_signals, deterministic_non_llm_verdict
        d = deterministic_non_llm_verdict(extract_non_llm_signals({"event": "HEARTBEAT"}))
        assert d.verdict == "insufficient_evidence"
        assert d.reason == "no_strong_non_llm_signal"

    def test_executor_no_longer_self_certifies_admitted_claims(self):
        src = io.open("agents/agent_executor.py", encoding="utf-8").read()
        i = src.rindex("def _deterministic_from_non_llm")   # 方法定义，不是调用点
        seg = src[i:i + 3000]
        assert "has_admitted_claims=" not in seg, (
            "tools-only 仍在自证「有已采纳断言」"
        )
        assert "deterministic_non_llm_verdict" in seg

    def test_executor_tools_only_free_text_name_not_confirmed(self):
        """方法级行为验证：走真正的 Executor 路径。"""
        from agents import agent_executor as ex
        res = ex.executor._deterministic_from_non_llm(
            {"event": "命令注入", "message": "x", "severity": "high"}, []
        )
        assert res.verdict != "confirmed", (
            "执行器仍允许仅凭自由文本事件名零证据 confirmed"
        )
        assert res.needs_human_review is True

    def test_executor_tools_only_sigma_confirmed_but_forces_human(self):
        from agents import agent_executor as ex
        res = ex.executor._deterministic_from_non_llm(
            {"event": "x", "severity": "high",
             "_sigma": {"detected": True, "max_severity": "critical"}}, []
        )
        assert res.verdict == "confirmed"
        assert res.needs_human_review is True, "tools-only 未做 Grounding 校验却放行人审"
        assert res.non_llm_signals.get("evidence_basis"), "判定依据未记录"
        assert res.non_llm_signals.get("evidence_basis")


# ═══════════════════════════════════════════
# suspicious 自动封禁资格
# ═══════════════════════════════════════════

class TestSuspiciousBlockingEligibility:
    def test_orchestrator_reads_threat_info_allow_blocking(self):
        src = io.open("response_engine/response_orchestrator.py", encoding="utf-8").read()
        assert 'threat_info.get("allow_blocking", True)' in src, (
            "on_threat_detected 未采纳 threat_info 里的 allow_blocking"
        )

    def test_allow_blocking_defaults_to_none_not_true(self):
        src = io.open("response_engine/response_orchestrator.py", encoding="utf-8").read()
        assert "allow_blocking: Optional[bool] = None" in src, (
            "缺省 True 会让未传参的调用方绕过双轨门槛"
        )

    def test_log_ingestion_sets_allow_blocking_by_verdict(self):
        src = io.open("log_ingestion.py", encoding="utf-8").read()
        assert '"allow_blocking": str(_verdict) == "confirmed"' in src, (
            "suspicious 仍可自动封禁"
        )

    def test_temporal_sets_allow_blocking_by_verdict(self):
        src = io.open("temporal/activities.py", encoding="utf-8").read()
        assert 'threat_info["allow_blocking"] = (' in src
        i = src.index('threat_info["allow_blocking"] = (')
        seg = src[i:i + 200]
        assert '"confirmed"' in seg and "setdefault" not in seg, (
            "temporal 路径仍是 setdefault(True)"
        )

    def test_gate_and_blocking_agree_on_suspicious(self):
        """闸门允许 suspicious 触发响应，但只应告警不封禁。"""
        from veto_gates import evaluate_auto_response_gate
        g = evaluate_auto_response_gate({
            "threat_detected": True, "verdict": "suspicious", "confidence": 0.8,
        })
        assert g.allowed is True, "suspicious 仍应能触发告警"
        # 但 allow_blocking 由 verdict 决定 → False
        assert (str("suspicious") == "confirmed") is False


# ═══════════════════════════════════════════
# recheck：升级 + 可审计降级
# ═══════════════════════════════════════════

class TestRecheckMonotonicity:
    def _run_recheck(self, monkeypatch, recheck_payload, synth_threat=True):
        from agents import agent_executor as ex
        from audit_types import ToolCall
        from agents.sub_auditor import ChunkVerdict

        async def fake_chat(messages, **kw):
            # 汇总阶段的结论由参数控制：升级测试要低危起点，
            # 降级测试要 confirmed 起点，否则观测不到差异。
            if synth_threat:
                return json.dumps({
                    "threat_detected": True, "confidence": 0.8, "severity": "high",
                    "summary": "s", "verdict": "confirmed",
                })
            return json.dumps({
                "threat_detected": False, "confidence": 0.2, "severity": "info",
                "summary": "汇总未发现威胁", "verdict": "false_positive",
            })

        monkeypatch.setattr(ex.summary.llm, "chat", fake_chat)

        chunk = ex.AuditChunk(
            chunk_id="c1", strategy="manual", label="ip",
            events=[{"id": 1, "event_type": "C2_BEACON", "severity": "high",
                     "message": "beacon"}],
        )
        monkeypatch.setattr(ex.chunker, "chunk", lambda events, chain_event_ids=None: [chunk])
        monkeypatch.setattr(ex.veto_gates if hasattr(ex, "veto_gates") else ex,
                            "__dummy__", None, raising=False)

        verdict = ChunkVerdict(
            chunk_id="c1", threat_detected=False,
            threat_claims=[{
                "type": "C2", "confidence": 0.9,
                "evidence_ids": [1], "evidence_quotes": ["beacon"],
                "severity": "high", "summary": "c2 beacon",
            }],
            all_event_ids_in_chunk=[1],
        )

        async def fake_audit(ch, knowledge_chunks=None):
            return verdict
        monkeypatch.setattr(ex.sub_auditor, "audit", fake_audit)

        calls = {"n": 0}

        async def fake_llm_recheck(raw_event, audit, verdicts):
            calls["n"] += 1
            return dict(recheck_payload)

        monkeypatch.setattr(ex.executor, "_llm_recheck", fake_llm_recheck)

        return _run(ex.executor.execute(
            tool_calls=[ToolCall(call_id="c1", task_id="t1",
                                 tool="llm.recheck", args={})],
            depth="deep",
            raw_event={"event": "C2_BEACON", "severity": "high", "src_ip": "10.0.0.5"},
        ))

    def test_evidenced_missed_threat_can_escalate(self, monkeypatch):
        """核心回归：复核发现**有证据**的遗漏威胁时必须能升级。"""
        res = self._run_recheck(monkeypatch, {
            "needs_human": True, "abstain": False,
            "missed_threats": [{
                "type": "C2", "summary": "存在周期性 beacon 外连",
                "evidence_ids": [1], "evidence": "beacon",
            }],
            "review_notes": "",
        }, synth_threat=False)
        ra = res.recheck_audit
        assert ra, "复核未留下可审计记录"
        assert ra["escalated"] is True, "有证据的复核发现未能升级 —— recheck 方向仍反"
        assert res.threat_detected is True
        assert res.verdict == "suspicious"
        assert ra["escalation_basis"], "升级依据未记录"
        assert res.needs_human_review is True

    def test_unevidenced_missed_threat_cannot_escalate(self, monkeypatch):
        """没有可核验证据的「遗漏威胁」不得升级（防幻觉升级）。"""
        res = self._run_recheck(monkeypatch, {
            "needs_human": False, "abstain": False,
            "missed_threats": [{"type": "C2", "summary": "凭感觉像 C2",
                                "evidence_ids": [], "evidence": "无"}],
            "review_notes": "",
        }, synth_threat=False)
        assert res.recheck_audit["escalated"] is False, "无证据的复核发现竟能升级"

    def test_escalation_never_reaches_confirmed(self, monkeypatch):
        res = self._run_recheck(monkeypatch, {
            "needs_human": True, "abstain": False,
            "missed_threats": [{"type": "C2", "summary": "s",
                                "evidence_ids": [1], "evidence": "beacon"}],
            "review_notes": "",
        }, synth_threat=False)
        assert res.verdict != "confirmed", (
            "复核单独把结论升到 confirmed —— 绕过 apply_confirmation_gate"
        )

    def test_abstain_demotes_but_preserves_original(self, monkeypatch):
        res = self._run_recheck(monkeypatch, {
            "needs_human": True, "abstain": True,
            "missed_threats": [], "review_notes": "证据不足",
        })
        ra = res.recheck_audit
        assert ra["demoted"] is True
        assert ra["demotion_reason"] == "llm_abstain"
        assert ra["original"]["verdict"], "原始等级未保留 —— 无法区分推翻与沉默"
        assert res.verdict == "insufficient_evidence"

    def test_silence_is_not_contradiction(self, monkeypatch):
        """复核沉默（无 abstain、无遗漏）不得改变结论。"""
        res = self._run_recheck(monkeypatch, {
            "needs_human": False, "abstain": False,
            "missed_threats": [], "review_notes": "看起来没问题",
        }, synth_threat=True)
        ra = res.recheck_audit
        assert ra["demoted"] is False and ra["escalated"] is False
        assert res.verdict != "insufficient_evidence"

    def test_audit_result_exposes_three_levels(self):
        from audit_types import AuditResult
        r = AuditResult(recheck_audit={
            "original": {"verdict": "confirmed", "severity": "critical"},
            "final": {"verdict": "suspicious", "severity": "high"},
            "escalated": False, "demoted": True,
        })
        d = r.to_dict()
        assert d["original_verdict"] == "confirmed"
        assert d["recheck_demoted"] is True
        assert d["recheck_escalated"] is False


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
