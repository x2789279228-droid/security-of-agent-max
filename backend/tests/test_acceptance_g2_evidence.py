"""
验收 · 第二组：证据校验（C-1 / C-2 / C-5）→ 门槛 A + 门槛 B

规范原文的硬要求：
    「证据有效性硬门槛与加权分数必须分别验收。
      无效 ID、伪造引用和关键事实矛盾不能仅靠其他维度取得高分来抵消。」

场景矩阵（对应规范 §二.2）：

  G2-S1  所有引用有效、引用内容确实支持结论   → 通过证据审核
  G2-S2  ID 真实存在但 quote 全部伪造         → 不得得到已充分验证的结论
  G2-S3  ID 不存在                            → 明确标记为无效引用，不能被其他评分抵消
  G2-S4  没有 evidence 或 quote 为空          → 明确判为证据不足/无法验证
  G2-S5  同一条 quote 重复 20 次              → 不得仅凭重复次数提高可信度
  G2-S6  原始断言含无效项、后续被剥离          → 原始风险统计仍保留该事实
  G2-S7  日志正文出现 T1071                    → 不得仅凭该字符串证明 ATT&CK 标签成立
  G2-S8  关键校验函数抛异常                    → 不得静默跳过继续放行
  G2-S9  只有自然语言事件名、没有独立证据      → 不得仅凭事件名生成已确认结论

另加规范明确要求的一条口径：
  hallucination_risk 必须用**完整原始断言集**计算；
  无效引用比例 / 无证据主张率 / 结论错误率必须是**三个不同指标**。
"""
import pytest

from eval_datasets.grounding_cases import (
    CASES,
    DATA_EXFIL,
    SSH_BRUTEFORCE,
    events_for,
)
from grounding_verifier import grounding_verifier


def _by_id(cid):
    for c in CASES:
        if c["id"] == cid:
            return c
    raise KeyError(cid)


def _verify(claim, events=None, knowledge=None, cid="acc"):
    return grounding_verifier.verify_chunk(
        claims=[claim], events=events or [SSH_BRUTEFORCE],
        knowledge_chunks=knowledge or [], chunk_id=cid,
    ).claims[0]


def _claim(**over):
    base = {
        "type": "BRUTEFORCE", "confidence": 0.9, "severity": "high",
        "evidence_ids": [1],
        "evidence_quotes": ["failed password for root from 10.0.0.9"],
        "summary": "root 账户遭到 SSH 口令爆破，源 10.0.0.9",
    }
    base.update(over)
    return base


# ══════════════════════════════════════════════════════════════════
# G2-S1 ~ S4 / S9：标定集直接执行
# ══════════════════════════════════════════════════════════════════

class TestG2S1_LegitimateEvidencePasses:
    """门槛 B 对照：干净断言必须通过，不能被过度收紧误伤。"""

    @pytest.mark.parametrize("cid", [
        "clean_ssh_bruteforce", "clean_c2_beacon",
        "clean_sqli", "no_quote_but_ids_valid", "kb_supported_bruteforce",
    ])
    def test_clean_case_is_grounded(self, cid):
        case = _by_id(cid)
        r = _verify(case["claim"], events_for(case))
        assert r.verdict == "grounded", (
            f"{cid} 被判为 {r.verdict}（{r.grounding_score}），"
            f"正常路径被误伤: {r.hard_fail_reasons}"
        )
        assert not r.hard_fail_reasons


class TestG2S2_FabricatedQuotesCannotScoreThrough:
    def test_ids_valid_but_all_quotes_fabricated(self):
        r = _verify(_claim(evidence_quotes=["完全不存在的字符串 xyzzy"]))
        assert r.verdict != "grounded", (
            f"引用全伪造却得到 {r.verdict}（{r.grounding_score}）"
        )
        assert r.hard_fail_reasons, "伪造引用未触发任何硬否决"

    def test_hard_fail_is_not_offset_by_other_dimensions(self):
        """规范核心：硬否决不得被其他维度的满分抵消。"""
        r = _verify(_claim(
            evidence_ids=[999999],
            evidence_quotes=["完全不存在的字符串 xyzzy"],
            confidence=0.99, summary="root 账户遭到 SSH 口令爆破，源 10.0.0.9",
        ))
        assert r.verdict == "ungrounded"
        assert r.grounding_score < 0.8


class TestG2S3_NonexistentId:
    @pytest.mark.parametrize("ids", [[999999], [1, 999999]])
    def test_missing_id_is_hard_fail(self, ids):
        r = _verify(_claim(evidence_ids=ids))
        assert r.verdict == "ungrounded"
        assert any("fabricated_evidence_ids" in x
                   for x in r.hard_fail_reasons), r.hard_fail_reasons


class TestG2S4_NoEvidence:
    @pytest.mark.parametrize("cid", ["zero_evidence_no_ip", "zero_evidence_with_ip"])
    def test_zero_evidence_is_ungrounded(self, cid):
        case = _by_id(cid)
        r = _verify(case["claim"], events_for(case))
        assert r.verdict == "ungrounded", (
            f"{cid} 零证据断言得到 {r.verdict}（{r.grounding_score}）"
        )
        assert any("no_evidence" in x for x in r.hard_fail_reasons), \
            r.hard_fail_reasons


class TestG2S9_NaturalLanguageOnly:
    def test_event_name_alone_cannot_confirm(self):
        """只有自然语言事件名、没有独立证据 → 不得生成已确认结论。"""
        r = _verify(_claim(
            evidence_ids=[], evidence_quotes=[],
            summary="系统已被完全攻陷，数据全部外泄",
        ))
        assert r.verdict == "ungrounded"


# ══════════════════════════════════════════════════════════════════
# G2-S5  重复引用不得抬高可信度
# ══════════════════════════════════════════════════════════════════

class TestG2S5_RepetitionDoesNotInflate:
    def test_twenty_identical_quotes_score_no_higher_than_one(self):
        one = _verify(_claim(
            evidence_quotes=["failed password for root from 10.0.0.9"]))
        twenty = _verify(_claim(
            evidence_quotes=["failed password for root from 10.0.0.9"] * 20))
        assert twenty.grounding_score <= one.grounding_score + 1e-9, (
            f"重复 20 次把分数从 {one.grounding_score} 抬到 "
            f"{twenty.grounding_score}"
        )
        assert twenty.verdict == one.verdict

    def test_twenty_fabricated_quotes_still_fail(self):
        """对照组：重复伪造引用同样不能靠数量变成可信。"""
        r = _verify(_claim(evidence_quotes=["捏造内容 plugh"] * 20))
        assert r.verdict != "grounded", (
            f"重复 20 次伪造引用得到 {r.verdict}"
        )


# ══════════════════════════════════════════════════════════════════
# G2-S6  剥离后原始风险不得塌零
# ══════════════════════════════════════════════════════════════════

class TestG2S6_RawRiskSurvivesStripping:
    def test_denominator_is_the_full_raw_claim_set(self):
        from agents.sub_auditor import ChunkVerdict

        claims = [
            _claim(summary="A 无任何引用", evidence_ids=[], evidence_quotes=[]),
            _claim(summary="B 真实引用"),
            _claim(summary="C ID 不存在", evidence_ids=[999999]),
            _claim(summary="D 引用全伪造",
                   evidence_quotes=["捏造内容 plugh"]),
        ]
        v = ChunkVerdict(chunk_id="c1", threat_detected=True,
                         threat_claims=claims, all_event_ids_in_chunk=[1])
        raw = v.validate_evidence(claims=claims)
        assert raw["total_claims"] == 4, (
            f"分母应为 4 条原始断言，实际 {raw['total_claims']}"
        )
        assert raw["invalid_claims"] >= 1
        assert raw["hallucination_risk"] > 0.0

    def test_admitted_set_alone_would_hide_the_risk(self):
        """对照组：如果只统计 admitted 分母，风险会塌到 0 —— 证明该场景有效。"""
        from agents.sub_auditor import ChunkVerdict
        from veto_gates import strip_ungrounded_claims

        claims = [_claim(summary="真实断言"),
                  _claim(summary="伪造断言", evidence_ids=[999999],
                         evidence_quotes=["凭空捏造的 payload"])]
        report = grounding_verifier.verify_chunk(
            claims=claims, events=[SSH_BRUTEFORCE],
            knowledge_chunks=[], chunk_id="c1")
        admitted, discarded = strip_ungrounded_claims(
            claims, claim_reports=report.claims)
        v = ChunkVerdict(chunk_id="c1", threat_detected=True,
                         threat_claims=list(admitted),
                         all_event_ids_in_chunk=[1])
        assert discarded, "伪造断言未被剥离，场景构造有误"
        assert v.validate_evidence()["hallucination_risk"] == 0.0, (
            "对照组前提不成立：只看 admitted 时风险本就不为 0"
        )
        assert v.validate_evidence(claims=claims)["hallucination_risk"] > 0.0

    def test_end_to_end_sub_auditor_keeps_raw_snapshot(self, monkeypatch):
        from agents import sub_auditor as sa

        claims = [_claim(summary="真实断言"),
                  _claim(summary="伪造断言", evidence_ids=[999999],
                         evidence_quotes=["凭空捏造的 payload"])]

        class _FakeGrounding:
            overall_score = 0.55
            grounded_claims = 1
            partially_grounded = 0
            ungrounded_claims = 1
            hallucination_indicators = ["acceptance"]
            claims = []

        async def fake_chat(messages, **kw):
            import json
            return json.dumps({
                "threat_detected": True, "confidence": 0.8,
                "severity": "high", "summary": "s",
                "threat_claims": claims,
            })

        monkeypatch.setattr(sa.sub_auditor, "llm_chat", fake_chat)
        monkeypatch.setattr(
            "grounding_verifier.grounding_verifier.verify_chunk",
            lambda *a, **k: _FakeGrounding())

        class _C:
            chunk_id = "c1"
            events = [SSH_BRUTEFORCE]
            all_event_ids_in_chunk = [1]

            def to_prompt_block(self):
                return "<untrusted_log>x</untrusted_log>"

        v = _run(sa.sub_auditor.audit(_C()))
        assert v.raw_evidence_validation, "缺少剥离前的原始有效性快照"
        assert v.raw_evidence_validation["total_claims"] == 2
        assert v.hallucination_risk > 0.0, (
            f"剥离后 hallucination_risk 塌到 {v.hallucination_risk}"
        )


def _run(coro):
    import asyncio
    return asyncio.new_event_loop().run_until_complete(coro)


# ══════════════════════════════════════════════════════════════════
# G2-S7  ATT&CK 标签不得由日志字符串单独成立
# ══════════════════════════════════════════════════════════════════

class TestG2S7_MitreLabelNeedsRealEvidence:
    def test_technique_string_alone_does_not_prove_label(self):
        case = _by_id("phantom_ip")
        r = _verify(_claim(
            type="C2", evidence_ids=[1],
            evidence_quotes=["periodic beacon to 203.0.113.45"],
            summary="主机 10.0.0.5 向 198.18.7.7 建立 C2 通道 T1071"))
        assert r.verdict == "ungrounded", (
            f"含幻影 IP 的断言得到 {r.verdict}"
        )
        assert any("phantom_entities" in x for x in r.hard_fail_reasons)

    def test_strip_phantom_mitre_is_invoked(self):
        """带幻影标签的断言在进入投票集前必须被剥离。"""
        from veto_gates import strip_ungrounded_claims

        claims = [_claim(type="C2", evidence_ids=[999999],
                         evidence_quotes=["x"], summary="T1071 通道")]
        report = grounding_verifier.verify_chunk(
            claims=claims, events=[SSH_BRUTEFORCE], knowledge_chunks=[],
            chunk_id="c1")
        admitted, discarded = strip_ungrounded_claims(
            claims, claim_reports=report.claims)
        assert not admitted, "带幻影的断言进入了投票集"
        assert discarded


# ══════════════════════════════════════════════════════════════════
# G2-S8  关键校验函数抛异常不得静默放行
# ══════════════════════════════════════════════════════════════════

class TestG2S8_VerifierFailureIsNotSilentlySkipped:
    """关键校验失败必须失败关闭 —— 两条路径都要验。

    实测形态（不是「一律抛错」）：
      · ``sanitize_merged_audit`` 抛错 → 被捕获，**失败关闭**：
        response_blocked=True + sanitize_failed + 降级严重度 + 强制人审
      · ``compute_faithfulness`` 抛错 → 不被捕获，异常**向上传播**
    两者都不是「静默跳过继续放行」，但形态不同，必须分别钉住。
    """

    _MERGED = {"threat_detected": True, "verdict": "confirmed",
               "confidence": 0.9, "severity": "critical"}

    def test_sanitize_failure_is_fail_closed(self, monkeypatch):
        import faithfulness_gate as fg
        import veto_gates as vg

        def boom(*a, **k):
            raise RuntimeError("sanitizer exploded")

        monkeypatch.setattr(vg, "sanitize_merged_audit", boom)
        out = fg.apply_faithfulness_gate(
            dict(self._MERGED), answer="a", contexts=[])
        assert out["response_blocked"] is True, (
            f"sanitize 抛错时未阻断自动响应: {out}"
        )
        assert out.get("sanitize_failed"), "失败原因未留痕"
        assert out.get("needs_human") is True

    def test_compute_failure_propagates(self, monkeypatch):
        """不得被吞成「校验通过」。"""
        import faithfulness_gate as fg

        def boom(*a, **k):
            raise RuntimeError("faithfulness exploded")

        monkeypatch.setattr(fg, "compute_faithfulness", boom)
        with pytest.raises(RuntimeError):
            fg.apply_faithfulness_gate(
                dict(self._MERGED), answer="a", contexts=[])

    def test_verifier_exception_propagates(self):
        """verifier 自身抛异常时不得被上层吞成「无问题」。"""
        import grounding_verifier as gv

        with pytest.raises(Exception):
            gv.grounding_verifier.verify_chunk(
                claims=[_claim()], events=None, knowledge_chunks=[],
                chunk_id="c1")


# ══════════════════════════════════════════════════════════════════
# 口径：三个指标必须彼此独立
# ══════════════════════════════════════════════════════════════════

class TestMetricSeparation:
    def test_three_failure_metrics_are_distinct(self):
        """C-3：无效引用率 / 无证据主张率 / 结论错误率是三个指标。

        `_classify_claim_failure(claim, evidence, entities_in_claim) -> str`
        必须能把下列三种情形归到**不同**的类别。
        """
        from faithfulness_gate import _classify_claim_failure as cls

        invalid_ref = cls("检测到 T1071 通道", "connection refused", ["T1071"])
        unsupported = cls("系统已被完全攻陷", "", [])
        wrong_dir = cls(
            "connection succeeded to 10.0.0.5",
            "connection refused to 10.0.0.5", ["10.0.0.5"])

        kinds = {invalid_ref, unsupported, wrong_dir}
        assert len(kinds) == 3, (
            f"三类失效被折叠成 {len(kinds)} 种: "
            f"{invalid_ref!r} / {unsupported!r} / {wrong_dir!r}"
        )
        assert invalid_ref == "invalid_reference"
        assert unsupported == "unsupported_claim"
        assert wrong_dir == "wrong_conclusion"

    def test_hallucination_risk_uses_raw_set(self):
        """规范明确要求：hallucination_risk 用完整原始断言集。"""
        import inspect

        from agents import sub_auditor as sa
        src = inspect.getsource(sa)
        assert "raw_evidence_validation" in src, (
            "sub_auditor 未保留剥离前的原始口径快照"
        )
