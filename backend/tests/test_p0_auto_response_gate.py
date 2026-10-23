"""
P0-C-6 / D-1 / D-3 负面测试: 人工复核未完成 / CAD 熔断 / 监督异常时禁止高风险自动响应

C-6 (needs_human_review 不参与发布判定):
    修复前两条生产路径各自内联 4 字段判定：
        threat_detected ∧ verdict∈{confirmed,suspicious} ∧ conf≥0.4 ∧ ¬response_blocked
    实测 apply_confirmation_gate(extra_human=True) 返回 needs_human_review=True，
    该条件仍为 True —— 「强制人审」不阻止自动封禁。

D-1 (CAD 无否决权):
    修复前 CAD 跑在 commit 之后、temporal 路径更排在 trigger_response 之后，
    tripped 的全部副作用是一行 logger.critical，且不在响应闸门里。

D-3 (监督异常被静默吞掉):
    修复前 cad_verify / audit_pipeline 抛异常只 warning，熔断器保持 CLOSED、
    响应照常下发 —— 监督层在最需要它的时刻静默消失。

验收: 新测试在旧代码下失败，修复后通过。
"""
import asyncio
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

from veto_gates import evaluate_auto_response_gate


def _clean_merged(**kw):
    base = {
        "threat_detected": True,
        "verdict": "confirmed",
        "confidence": 0.9,
        "threat_type": "C2",
    }
    base.update(kw)
    return base


def _tripped_cad():
    return {"circuit_breaker": {"tripped": True, "reason": "幻觉率超标"}}


class TestAutoResponseGate:
    def test_clean_threat_is_allowed(self):
        g = evaluate_auto_response_gate(_clean_merged())
        assert g.allowed is True
        assert g.blocking_factors == []

    def test_needs_human_review_blocks(self):
        """C-6 核心回归。"""
        g = evaluate_auto_response_gate(_clean_merged(needs_human_review=True))
        assert g.allowed is False, "人工复核未完成却放行了自动响应"
        assert "needs_human_review" in g.blocking_factors

    def test_needs_human_review_blocks_even_with_max_confidence(self):
        """置信度再高也不能绕过强制人审。"""
        g = evaluate_auto_response_gate(_clean_merged(
            needs_human_review=True, confidence=1.0
        ))
        assert g.allowed is False

    def test_cad_tripped_blocks(self):
        """D-1 核心回归。"""
        g = evaluate_auto_response_gate(_clean_merged(), cad_report=_tripped_cad())
        assert g.allowed is False, "CAD 熔断却仍放行自动响应"
        assert "cad_circuit_tripped" in g.blocking_factors
        assert g.blocked_by_supervision is True

    def test_supervision_failure_blocks(self):
        """D-3 核心回归：监督自身异常 = 无法确认结论可信。"""
        g = evaluate_auto_response_gate(
            _clean_merged(), supervision_ok=False, supervision_error="db down"
        )
        assert g.allowed is False
        assert "supervision_failed" in g.blocking_factors
        assert g.blocked_by_supervision is True

    def test_schema_invalid_blocks(self):
        """P0-E-4 联动：schema 校验失败的结论不得触发封禁。"""
        g = evaluate_auto_response_gate(_clean_merged(schema_valid=False))
        assert g.allowed is False
        assert "schema_invalid" in g.blocking_factors

    def test_response_blocked_still_blocks(self):
        g = evaluate_auto_response_gate(_clean_merged(response_blocked=True))
        assert g.allowed is False
        assert "response_blocked" in g.blocking_factors

    def test_all_blockers_reported_together(self):
        g = evaluate_auto_response_gate(
            _clean_merged(needs_human_review=True, schema_valid=False,
                          response_blocked=True),
            cad_report=_tripped_cad(), supervision_ok=False,
        )
        assert set(g.blocking_factors) == {
            "response_blocked", "needs_human_review", "schema_invalid",
            "cad_circuit_tripped", "supervision_failed",
        }

    def test_legacy_payload_without_schema_valid_still_allowed(self):
        """防回归过度：老数据无 schema_valid 字段时不应一律阻断。"""
        assert evaluate_auto_response_gate(_clean_merged()).allowed is True

    def test_non_threat_not_allowed_but_not_flagged_as_blocked(self):
        g = evaluate_auto_response_gate(_clean_merged(threat_detected=False))
        assert g.allowed is False
        assert g.blocking_factors == []

    def test_low_confidence_not_allowed(self):
        g = evaluate_auto_response_gate(_clean_merged(confidence=0.2))
        assert g.allowed is False
        assert g.blocking_factors == []

    def test_malformed_confidence_does_not_crash(self):
        for bad in ("abc", None, [], {}):
            g = evaluate_auto_response_gate(_clean_merged(confidence=bad))
            assert g.allowed is False

    def test_verdict_false_positive_not_allowed(self):
        g = evaluate_auto_response_gate(_clean_merged(verdict="false_positive"))
        assert g.allowed is False

    def test_empty_merged_is_safe(self):
        g = evaluate_auto_response_gate({})
        assert g.allowed is False
        g2 = evaluate_auto_response_gate(None)
        assert g2.allowed is False

    def test_cad_report_none_does_not_block(self):
        """未跑 CAD 的链路（如 tools_only）不应被无理由阻断。"""
        assert evaluate_auto_response_gate(_clean_merged(), cad_report=None).allowed


class TestTemporalCadPrecedesResponse:
    def test_cad_verify_runs_before_trigger_response(self):
        """静态顺序断言：CAD 必须排在响应之前且结果被使用。"""
        import io
        src = io.open("temporal/workflows.py", encoding="utf-8").read()
        i_cad = src.index('"cad_verify"')
        i_resp = src.index('"trigger_response"')
        assert i_cad < i_resp, "CAD 仍排在 trigger_response 之后 —— D-1 未修复"

        i_assign = src.index("cad_result = await workflow.execute_activity")
        assert i_assign < i_resp, "CAD 返回值未被用于响应决策"

        gate_idx = src.index("evaluate_auto_response_gate")
        assert gate_idx < i_resp, "响应判定未走统一闸门"

    def test_cad_result_not_discarded(self):
        import io
        src = io.open("temporal/workflows.py", encoding="utf-8").read()
        assert "auto_response_blocking_factors" in src, (
            "CAD 阻断因子未随 workflow 返回值暴露，运维无从观测"
        )


class TestLogIngestionUsesGate:
    def test_log_ingestion_calls_unified_gate(self):
        import io
        src = io.open("log_ingestion.py", encoding="utf-8").read()
        assert "evaluate_auto_response_gate" in src
        assert "cad_report_for_gate" in src, "CAD 结论未接入响应闸门"
        assert "supervision_ok_for_gate" in src, "监督异常状态未接入响应闸门"

    def test_response_branch_uses_gate_not_inline_condition(self):
        """旧的 4 字段内联判定不得残留 —— 否则 needs_human_review 形同虚设。"""
        import io
        src = io.open("log_ingestion.py", encoding="utf-8").read()
        assert "if _auto_gate.allowed:" in src
        assert 'and _verdict in ("confirmed", "suspicious")' not in src, (
            "响应分支仍在使用旧的内联判定，未走统一闸门"
        )

    def test_supervision_failure_marked_on_cad_exception(self):
        import io
        src = io.open("log_ingestion.py", encoding="utf-8").read()
        idx = src.index("audit_pipeline failed")
        seg = src[idx:idx + 600]
        assert "supervision_ok_for_gate = False" in seg, (
            "CAD 异常后未标记监督失败 —— D-3 未修复"
        )


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
