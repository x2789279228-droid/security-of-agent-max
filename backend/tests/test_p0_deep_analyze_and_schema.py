"""
P0-E-1 / E-4 负面测试: 失败状态不得伪装成成功，Schema 错误不得放行非法结果

E-1 (deep_analyze fallback 伪装成功):
    修复前 `_llm_deep_analyze` 无 is_llm_fallback 检查。budget_exhausted / 429 /
    超时返回的 {"fallback": true, ...} 被当成"深度分析初步研判"注入 synthesize
    prompt（提示词还要求模型"纳入或显式反驳"），且 ToolResult 标记 success=True。

E-4 (schema 失败仍放行非法值):
    修复前 validate_synthesis_output 校验失败时 `return parsed, errors`，
    调用方只判 `parsed is None` → 非法 severity 原样写入 AuditResult.severity。

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

from audit_schemas import validate_synthesis_output, validate_reviewer_output
from agents.sub_auditor import ChunkVerdict

FALLBACK_JSON = json.dumps(
    {"error": "每日 LLM 预算已用尽", "fallback": True, "budget_stats": {"used": 1}}
)


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


# ═══════════════════════════════════════════
# E-4: Schema 值域强制收敛
# ═══════════════════════════════════════════

class TestSchemaSanitization:
    def test_illegal_severity_never_reaches_caller(self):
        parsed, errors = validate_synthesis_output(json.dumps({
            "threat_detected": True,
            "threat_type": "C2",
            "confidence": 0.9,
            "severity": "严重!!!",      # 非法枚举
            "summary": "s",
        }))
        assert parsed is not None, "JSON 可解析时不应返回 None"
        assert errors, "非法 severity 必须产生 schema error"
        assert parsed["severity"] in {"critical", "high", "medium", "low", "info"}, (
            f"非法 severity 未被收敛，仍为 {parsed.get('severity')!r}"
        )

    def test_out_of_range_confidence_is_clamped(self):
        parsed, errors = validate_synthesis_output(json.dumps({
            "threat_detected": True,
            "confidence": 42.0,          # 越界
            "severity": "high",
            "summary": "s",
        }))
        assert errors
        assert 0.0 <= float(parsed["confidence"]) <= 1.0

    def test_nan_and_inf_confidence_rejected(self):
        for bad in (float("nan"), float("inf"), "not-a-number"):
            parsed, errors = validate_synthesis_output(json.dumps({
                "threat_detected": True,
                "confidence": bad,
                "severity": "high",
                "summary": "s",
            }))
            assert errors, f"confidence={bad!r} 应触发 schema error"
            c = float(parsed["confidence"])
            assert 0.0 <= c <= 1.0, f"confidence={bad!r} 未被收敛为 {c}"

    def test_illegal_reviewer_conclusion_becomes_suspicious(self):
        parsed, errors = validate_reviewer_output(json.dumps({
            "conclusion": "confirmed_high_trust_gg",
            "confidence": 0.8,
        }))
        assert errors
        assert parsed["conclusion"] == "suspicious", (
            f"非法 conclusion 未收敛: {parsed.get('conclusion')!r}"
        )

    def test_wrong_container_types_replaced_with_safe_defaults(self):
        parsed, errors = validate_synthesis_output(json.dumps({
            "threat_detected": True,
            "confidence": 0.7,
            "severity": "medium",
            "summary": "s",
            "affected_entities": "not-a-dict",     # 类型错误
            "suggested_actions": "not-a-list",     # 类型错误
        }))
        assert errors
        assert isinstance(parsed["affected_entities"], dict)
        assert isinstance(parsed["suggested_actions"], list)

    def test_valid_output_passes_without_errors(self):
        """正向对照：合法输出不应被误伤。"""
        parsed, errors = validate_synthesis_output(json.dumps({
            "threat_detected": True,
            "threat_type": "C2",
            "confidence": 0.8,
            "severity": "high",
            "summary": "s",
        }))
        assert parsed is not None
        assert not errors, f"合法输出不应报错: {errors}"
        assert parsed["severity"] == "high"


# ═══════════════════════════════════════════
# E-4: schema 失败 → 强制人工复核
# ═══════════════════════════════════════════

class TestSchemaFailureForcesHumanReview:
    def test_invalid_schema_marks_result_and_forces_review(self, monkeypatch):
        from agents import agent_executor as ex
        from audit_types import ToolCall

        captured = []

        async def fake_chat(messages, **kw):
            captured.append(messages)
            return json.dumps({
                "threat_detected": True,
                "threat_type": "C2",
                "confidence": 0.95,
                "severity": "严重",          # 非法 → schema 失败
                "summary": "检测到 C2",
                "verdict": "confirmed",
            })

        monkeypatch.setattr(ex.summary.llm, "chat", fake_chat)

        chunk = ex.AuditChunk(
            chunk_id="c1", strategy="manual", label="test", events=[]
        )
        v = ChunkVerdict(
            chunk_id="c1",
            threat_detected=True,
            threat_claims=[{
                "type": "C2", "confidence": 0.9,
                "evidence_ids": [1], "evidence_quotes": ["x"],
                "severity": "high", "summary": "c2 beacon",
            }],
            all_event_ids_in_chunk=[1],
        )

        res = _run(ex.executor._synthesize_from_chunks(
            raw_event={"event": "C2_BEACON", "severity": "high"},
            chunks=[chunk], verdicts=[v],
            chain_info="", depth="deep",
        ))
        assert res.schema_valid is False, "schema 校验失败必须标记 schema_valid=False"
        assert res.schema_errors, "必须记录 schema 错误原因"
        assert res.needs_human_review is True, "schema 失败必须强制人工复核"
        assert res.severity in {"critical", "high", "medium", "low", "info"}, (
            f"非法 severity 泄漏到结果: {res.severity!r}"
        )


# ═══════════════════════════════════════════
# E-1: deep_analyze 降级不得伪装成功
# ═══════════════════════════════════════════

class TestDeepAnalyzeFallbackNotFaked:
    def _run_deep(self, monkeypatch, chat_return):
        from agents import agent_executor as ex
        from audit_types import ToolCall

        captured = []

        async def fake_chat(messages, **kw):
            captured.append(messages)
            return chat_return

        monkeypatch.setattr(ex.summary.llm, "chat", fake_chat)

        # chunker / sub_auditor 打桩 → 一个"有内容"的流水线，
        # 这样 synthesize 一定会渲染 prompt，能观测到 deep_section 是否被污染。
        chunk = ex.AuditChunk(
            chunk_id="c1", strategy="manual", label="ip",
            events=[{"id": 1, "event_type": "C2_BEACON", "severity": "high",
                     "message": "beacon"}],
        )
        monkeypatch.setattr(ex.chunker, "chunk", lambda events, chain_event_ids=None: [chunk])
        verdict = ChunkVerdict(
            chunk_id="c1", threat_detected=True,
            threat_claims=[{
                "type": "C2", "confidence": 0.9,
                "evidence_ids": [1], "evidence_quotes": ["beacon"],
                "severity": "high", "summary": "c2 beacon 周期上报",
            }],
            all_event_ids_in_chunk=[1],
        )

        async def fake_audit(ch, knowledge_chunks=None):
            return verdict
        monkeypatch.setattr(ex.sub_auditor, "audit", fake_audit)

        res = _run(ex.executor.execute(
            tool_calls=[ToolCall(call_id="c1", task_id="t1",
                                 tool="llm.deep_analyze", args={})],
            depth="deep",
            raw_event={"event": "C2_BEACON", "severity": "high", "src_ip": "10.0.0.5"},
        ))
        return res, captured

    def test_fallback_deep_analyze_marked_failed(self, monkeypatch):
        res, _ = self._run_deep(monkeypatch, FALLBACK_JSON)
        deep = [r for r in res.tool_results if r.tool == "llm.deep_analyze"]
        assert deep, "deep_analyze 的 ToolResult 必须保留（供审计追溯）"
        assert deep[0].success is False, (
            "降级的 deep_analyze 被标记为 success=True —— E-1 未修复"
        )
        assert "llm_fallback" in (deep[0].error or "")

    def test_fallback_body_never_enters_synthesis_prompt(self, monkeypatch):
        _, captured = self._run_deep(monkeypatch, FALLBACK_JSON)
        blob = json.dumps(captured, ensure_ascii=False)
        assert "fallback" not in blob, (
            "降级 JSON 进入了 LLM prompt —— 模型会被要求采信一段报错"
        )
        assert "预算已用尽" not in blob

    def test_deep_analysis_field_empty_on_fallback(self, monkeypatch):
        res, _ = self._run_deep(monkeypatch, FALLBACK_JSON)
        assert res.deep_analysis == "", "降级正文不得留在 deep_analysis 字段"

    def test_normal_deep_analysis_still_works(self, monkeypatch):
        """正向对照：正常 deep 输出仍应保留并标记成功。"""
        res, captured = self._run_deep(
            monkeypatch, "深度研判：观察到固定周期外连，疑似 C2 心跳。"
        )
        deep = [r for r in res.tool_results if r.tool == "llm.deep_analyze"]
        assert deep and deep[0].success is True
        assert "疑似 C2 心跳" in res.deep_analysis


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
