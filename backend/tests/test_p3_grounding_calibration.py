"""
P3: Grounding 标定与评估流程 —— 负面测试。

这一批测试守护两件事：

A. **零证据断言不得被当成可信证据**（P3 标定工作直接挖出的缺陷）
   修复前：`evidence_ids=[]` 的断言靠五个维度的空真拿到 0.9000 = grounded，
   与逐字可溯源的干净断言**同分**，且不触发任何其他硬否决。
   端到端后果：schema 层虽已写明「每条断言必须有证据」，但该拒绝未落地，
   断言以 severity=critical 进入投票集。

B. **标定流程本身是可用的量具**（不是永远绿的摆设）
   包含对评估器自检闸门的反向测试：故意弄坏档位重实现，
   断言 `sweep_thresholds` 会抛错而不是给出一条自说自话的标定曲线。
"""
import json

import pytest

from audit_schemas import validate_sub_auditor_output
from eval_datasets.evaluate_grounding import (
    _assert_reimplementation_matches,
    _verdict_for,
    run_dataset,
    sweep_thresholds,
)
from eval_datasets.grounding_cases import CASES, knowledge_for
from grounding_verifier import grounding_verifier
from veto_gates import strip_ungrounded_claims


EVENT = {
    "id": 1,
    "event_type": "SSH_BRUTEFORCE",
    "severity": "high",
    "src_ip": "10.0.0.9",
    "dst_ip": "10.0.0.5",
    "message": "failed password for root from 10.0.0.9 port 51234 ssh2",
    "created_at": "2026-10-18T00:00:00+00:00",
}


def _zero_evidence_claim(with_ip: bool = False):
    summary = (
        "内网主机 10.0.0.5 已被完全控制并向外传输了全部数据库"
        if with_ip
        else "数据库已被完全控制，全部客户数据被加密后外传至境外"
    )
    return {
        "type": "DATA_EXFILTRATION",
        "confidence": 0.93,
        "evidence_ids": [],
        "evidence_quotes": [],
        "severity": "critical",
        "summary": summary,
    }


def _llm_output(*claims):
    return json.dumps(
        {
            "threat_detected": True,
            "threat_claims": list(claims),
            "confidence": 0.93,
            "severity": "critical",
            "summary": "检测到严重的入侵与大规模数据外泄",
            "suspicious_entities": [],
            "alert": "",
        },
        ensure_ascii=False,
    )


# ═══════════════════════════════════════════
# A. 零证据断言不得被判 grounded
# ═══════════════════════════════════════════

class TestZeroEvidenceHardFail:
    def test_zero_evidence_claim_is_ungrounded(self):
        """核心回归：没有证据的断言不得得到可信结论。

        修复前：五个维度空真记满分 → 0.9000 → verdict=grounded。
        """
        rep = grounding_verifier.verify_chunk(
            [_zero_evidence_claim()], [EVENT], knowledge_chunks=[], chunk_id="c",
        ).claims[0]
        assert rep.verdict == "ungrounded", (
            f"零证据断言得到 {rep.verdict}（score={rep.grounding_score}）—— "
            f"它与逐字可溯源的干净断言同分"
        )

    def test_zero_evidence_records_no_evidence_reason(self):
        rep = grounding_verifier.verify_chunk(
            [_zero_evidence_claim()], [EVENT], knowledge_chunks=[], chunk_id="c",
        ).claims[0]
        assert any("no_evidence" in r for r in rep.hard_fail_reasons), (
            f"未记录 no_evidence 硬否决原因，实际为 {rep.hard_fail_reasons}"
        )

    def test_zero_evidence_produces_indicator(self):
        """修复前零证据断言连告警都没有 ——
        既有告警条件要求 evidence_ids 非空，于是这类断言静默通过。"""
        report = grounding_verifier.verify_chunk(
            [_zero_evidence_claim()], [EVENT], knowledge_chunks=[], chunk_id="c",
        )
        assert report.hallucination_indicators, "零证据断言未产生任何幻觉风险告警"

    def test_zero_evidence_cannot_enter_voting_set(self):
        """端到端：不得被 strip_ungrounded_claims 放行进投票集。"""
        claim = _zero_evidence_claim()
        report = grounding_verifier.verify_chunk(
            [claim], [EVENT], knowledge_chunks=[], chunk_id="c",
        )
        admitted, discarded = strip_ungrounded_claims(
            [claim], claim_reports=report.claims,
        )
        assert not admitted, "零证据断言被放行进投票集"
        assert len(discarded) == 1

    def test_zero_evidence_with_ip_still_caught(self):
        """带 IP 的零证据断言此前是被**巧合**拦下的：
        空 evidence_ids → 无引用事件 → 任何 IP 都成幻影 IP。
        这里确保加了 no_evidence 之后，两条路径都在。"""
        rep = grounding_verifier.verify_chunk(
            [_zero_evidence_claim(with_ip=True)], [EVENT],
            knowledge_chunks=[], chunk_id="c",
        ).claims[0]
        assert rep.verdict == "ungrounded"
        assert any("no_evidence" in r for r in rep.hard_fail_reasons)

    def test_legitimate_claim_still_grounded(self):
        """防过度收紧：正常断言不得被 no_evidence 误伤。"""
        claim = {
            "type": "BRUTEFORCE", "confidence": 0.9,
            "evidence_ids": [1],
            "evidence_quotes": ["failed password for root from 10.0.0.9"],
            "severity": "high",
            "summary": "root 账户遭到 SSH 口令爆破，源 10.0.0.9",
        }
        rep = grounding_verifier.verify_chunk(
            [claim], [EVENT], knowledge_chunks=[], chunk_id="c",
        ).claims[0]
        assert rep.verdict == "grounded"
        assert not rep.hard_fail_reasons


# ═══════════════════════════════════════════
# B. schema 层的拒绝必须真正落地
# ═══════════════════════════════════════════

class TestSubAuditorSchemaEnforcement:
    def test_zero_evidence_claim_is_dropped(self):
        """修复前 validate_sub_auditor_output 失败时 `return parsed, errors`
        原样交回未校验 dict，schema 的拒绝只剩一条 warning。"""
        parsed, errors = validate_sub_auditor_output(
            _llm_output(_zero_evidence_claim())
        )
        assert errors, "前置条件不成立：schema 应当拒绝这条输出"
        assert parsed["threat_claims"] == [], (
            "零证据断言未被丢弃，仍在 threat_claims 中："
            f"{parsed['threat_claims']}"
        )

    def test_mixed_payload_keeps_only_valid_claims(self):
        good = {
            "type": "BRUTEFORCE", "confidence": 0.9,
            "evidence_ids": [1],
            "evidence_quotes": ["failed password for root from 10.0.0.9"],
            "severity": "high",
            "summary": "root 账户遭到 SSH 口令爆破，源 10.0.0.9",
        }
        parsed, errors = validate_sub_auditor_output(
            _llm_output(_zero_evidence_claim(), good)
        )
        assert errors
        kept = parsed["threat_claims"]
        assert len(kept) == 1, f"应只保留 1 条合法断言，实际 {len(kept)}"
        assert kept[0]["type"] == "BRUTEFORCE"

    def test_string_evidence_ids_still_accepted(self):
        """防过度收紧：LLM 返回 '#552' / '552' 属格式噪音，应被吸收而非丢弃。"""
        claim = {
            "type": "BRUTEFORCE", "confidence": 0.9,
            "evidence_ids": ["#1", 1],
            "evidence_quotes": ["failed password for root from 10.0.0.9"],
            "severity": "high",
            "summary": "root 账户遭到 SSH 口令爆破，源 10.0.0.9",
        }
        parsed, _ = validate_sub_auditor_output(_llm_output(claim))
        kept = parsed["threat_claims"]
        assert len(kept) == 1, "字符串形式的证据 ID 被误丢弃"
        assert kept[0]["evidence_ids"] == [1, 1]

    def test_illegal_severity_in_claim_converged(self):
        """P0-E-4 的 fail-closed 收敛同样要覆盖 claim 内部的越界 severity。"""
        claim = {
            "type": "BRUTEFORCE", "confidence": 5.0,
            "evidence_ids": [1], "evidence_quotes": ["failed password"],
            "severity": "APOCALYPTIC", "summary": "root 账户遭到 SSH 口令爆破",
        }
        parsed, errors = validate_sub_auditor_output(_llm_output(claim))
        assert errors, "前置条件不成立：非法 severity 应当报错"
        kept = parsed["threat_claims"]
        assert len(kept) == 1
        assert kept[0]["severity"] == "info", (
            f"非法 severity 未被收敛，实际 {kept[0]['severity']}"
        )
        assert kept[0]["confidence"] == 1.0

    def test_non_dict_output_returns_none(self):
        parsed, errors = validate_sub_auditor_output("[1, 2, 3]")
        assert parsed is None
        assert errors


# ═══════════════════════════════════════════
# C. 端到端：原始 LLM 输出 → 投票集
# ═══════════════════════════════════════════

class TestZeroEvidenceEndToEnd:
    def test_zero_evidence_claim_never_admitted(self):
        """复现原始缺陷的完整路径。"""
        claim = _zero_evidence_claim()
        parsed, _ = validate_sub_auditor_output(_llm_output(claim))
        claims = parsed.get("threat_claims", [])
        report = grounding_verifier.verify_chunk(
            claims, [EVENT], knowledge_chunks=[], chunk_id="c",
        )
        admitted, _ = strip_ungrounded_claims(claims, claim_reports=report.claims)
        assert not admitted, "零证据断言经完整链路后仍进入投票集"

    def test_dropping_all_claims_leaves_no_threat_detected(self):
        """全部断言被丢弃时，threat_detected 必须收敛为 False。

        调用方 sub_auditor.py 用 `threat_detected and len(claims) > 0`，
        这里钉住该前提。
        """
        parsed, _ = validate_sub_auditor_output(_llm_output(_zero_evidence_claim()))
        claims = parsed.get("threat_claims", [])
        assert not (parsed.get("threat_detected", False) and len(claims) > 0), (
            "所有断言被丢弃后仍判定 threat_detected=True"
        )

    def test_schema_error_signal_is_preserved(self):
        """收敛不得掩盖错误：errors 仍须非空，
        上层据此置 schema_valid=False 并由 veto_gates 阻断自动响应。"""
        _, errors = validate_sub_auditor_output(_llm_output(_zero_evidence_claim()))
        assert errors, "收敛后错误信号丢失 —— veto_gates 的 schema_valid 闸门会失效"


# ═══════════════════════════════════════════
# D. 标定数据集自身的完整性
# ═══════════════════════════════════════════

class TestDatasetIntegrity:
    def test_cases_have_required_fields(self):
        for case in CASES:
            for key in ("id", "events", "claim", "expect"):
                assert key in case, f"样本 {case.get('id')} 缺少字段 {key}"
            assert case["events"], f"样本 {case['id']} 的事件池为空"

    def test_case_ids_unique(self):
        ids = [c["id"] for c in CASES]
        assert len(ids) == len(set(ids)), f"存在重复样本 id：{ids}"

    def test_expects_are_valid_labels(self):
        for case in CASES:
            assert case["expect"] in ("grounded", "partial", "ungrounded"), (
                f"样本 {case['id']} 的 expect 非法：{case['expect']}"
            )

    def test_known_gap_cases_declare_reason(self):
        """检不出的类别必须显式登记，不能靠「悄悄标成通过的样本」掩盖。"""
        for case in CASES:
            if case.get("known_gap"):
                assert isinstance(case["known_gap"], str) and case["known_gap"]

    def test_dataset_covers_each_verdict(self):
        """每个档位都至少要有一条样本，否则该档位是标定盲区。"""
        seen = {c["expect"] for c in CASES}
        assert seen == {"grounded", "partial", "ungrounded"}, (
            f"档位覆盖不全：{seen}（缺哪一档，那一档就从未被数据检验过）"
        )

    def test_zero_evidence_cases_are_in_dataset(self):
        """零证据这一整类失效模式必须被覆盖 —— 它曾是标定盲区。"""
        zero = [c for c in CASES if not c["claim"].get("evidence_ids")]
        assert zero, "数据集没有任何零证据样本，该失效模式仍处于盲区"


# ═══════════════════════════════════════════
# E. 评估器是可用量具，不是永远绿的摆设
# ═══════════════════════════════════════════

class TestEvaluationHarness:
    def test_all_labeled_cases_pass(self):
        report = run_dataset()
        assert not report.misses, (
            "标定集未全对："
            + "; ".join(
                f"{r.case_id} 标注 {r.expect} 实得 {r.got}(score={r.score})"
                for r in report.misses
            )
        )
        assert report.accuracy == 1.0

    def test_thresholds_within_data_supported_region(self):
        """0.8 / 0.4 从「看起来合理」升级为「数据支持」。"""
        report = run_dataset()
        sweep = sweep_thresholds(report)
        assert sweep["current_is_perfect"], (
            f"当前阈值 {sweep['current']} 已越出标定集支持的区间"
        )

    def test_separation_margin_is_positive(self):
        """裕度必须为正，否则该指标无法检测回归。

        known_gap 样本若被算进裕度，裕度会恒为 0 —— 那等于把指标废掉。
        """
        report = run_dataset()
        margin = report.separation["margin_without_hard_fail"]
        assert margin is not None and margin > 0, (
            f"干净样本与越界样本的分数没有分离（裕度={margin}），"
            f"阈值无法承担区分职责"
        )

    def test_known_gap_excluded_from_accuracy(self):
        report = run_dataset()
        gaps = [r for r in report.results if r.known_gap]
        assert gaps, "数据集未登记任何 known_gap"
        counted_ids = {r.case_id for r in report.results if r.counted}
        for g in gaps:
            assert g.case_id not in counted_ids

    def test_hard_fail_does_the_bulk_of_the_work(self):
        """记录当前的责任分布：P0-C-1 的硬否决承担了大部分拦截。

        这不是「硬否决越多越好」的断言，而是一条把现状钉住的基线 ——
        若哪天硬否决命中率塌下去，这条会先红。
        """
        report = run_dataset()
        cov = report.hard_fail_coverage
        assert cov["caught_by_hard_fail"] >= cov["decided_by_threshold_only"], (
            f"拦截责任分布反转：硬否决 {cov['caught_by_hard_fail']} "
            f"< 阈值 {cov['decided_by_threshold_only']}"
        )

    def test_sweep_detects_impossible_thresholds(self):
        """扫描必须能给出「无解」结论，而不是默认全绿。

        这是 P3 标定工作最关键的一次输出：在实现修复前，
        全部 (grounded_t, partial_t) 组合都无法让零证据样本判对，
        正是这条结论证明了「重调阈值救不了，必须加硬性条件」。
        """
        report = run_dataset()
        # 构造一个只有「干净 + 无硬否决越界」两类分数的极小数据集，
        # 把两类分数压到完全相同 —— 任何阈值都分不开。
        # `got` 必须填实现真会产出的值（0.90 无硬否决 → grounded），
        # 否则 _assert_reimplementation_matches 会正确地判定 fixture 自相矛盾。
        from eval_datasets.evaluate_grounding import CaseResult, EvalReport

        squeezed = EvalReport([
            CaseResult("clean", "grounded", "grounded", 0.90, []),
            CaseResult("bad", "ungrounded", "grounded", 0.90, []),
        ])
        sweep = sweep_thresholds(squeezed, step=0.05)
        assert not sweep["perfect_regions"], (
            "当干净样本与越界样本同分时，扫描却报告存在可行阈值 —— "
            "扫描逻辑本身有问题"
        )

    def test_verdict_reimplementation_guard_fires(self, monkeypatch):
        """反向测试自检闸门：故意弄坏档位重实现，必须抛错。

        没有这条，evaluate_grounding 的阈值扫描可能对着一个与真 verifier
        行为不一致的重实现跑，输出一条漂亮但无意义的标定曲线。
        """
        report = run_dataset()

        monkeypatch.setattr(
            "eval_datasets.evaluate_grounding._verdict_for",
            lambda *a, **k: "grounded",          # 故意返回错档位
        )
        with pytest.raises(AssertionError, match="重实现与真 verifier 不一致"):
            _assert_reimplementation_matches(report)

    def test_verdict_reimplementation_agrees_when_intact(self):
        """反向测试的正向一侧：闸门完好时不得误报。"""
        report = run_dataset()
        _assert_reimplementation_matches(report)  # 不抛异常即通过


# ═══════════════════════════════════════════
# E2. 阈值区间的精确边界（网格值不能当边界用）
# ═══════════════════════════════════════════
#
# 判定是 `score >= g_t`，所以：
#   · 干净样本要留在 grounded   → g_t <= min_grounded              （**闭**上界）
#   · 越界样本不能被当成 grounded → g_t > max_bad_without_hard_fail （**开**下界）
#
# 网格扫描只能报出「小于它的最后一个网格点」，于是：
#   · 上界可能低估（真实 0.8034 → 网格 0.80，余量被说成 0.00）
#   · 下界可能高估（真实 >0.60 即可 → 网格 0.65，白严 0.05）
# 而用网格上界做「是否越界」的判断，会在真实上界 0.8034、当前阈值 0.802 时
# **误报「已越出数据支持区间」**，进而推动人不必要地调低阈值。

class TestExactThresholdBounds:
    def test_sweep_reports_exact_bounds_beside_the_grid(self):
        from eval_datasets.evaluate_grounding import run_dataset
        sweep = sweep_thresholds(run_dataset())
        sep = run_dataset().separation
        assert sweep["exact_upper_inclusive"] == pytest.approx(sep["min_grounded"])
        assert sweep["exact_lower_exclusive"] == pytest.approx(
            sep["max_bad_without_hard_fail"])

    def test_grid_lower_bound_can_be_stricter_than_the_exact_one(self):
        """合成一组分数，让网格下界比真实下界更严。

        干净样本 0.90 / 越界样本 0.60 → 真实要求 g_t > 0.60，
        但 0.05 网格里第一个 >0.60 的点是 0.65 —— 白严 0.05。
        """
        from eval_datasets.evaluate_grounding import CaseResult, EvalReport
        rep = EvalReport([
            CaseResult("clean", "grounded", "grounded", 0.90, []),
            CaseResult("bad", "partially_grounded", "partially_grounded", 0.60, []),
        ])
        sweep = sweep_thresholds(rep, step=0.05)
        assert sweep["exact_lower_exclusive"] == pytest.approx(0.60)
        assert sweep["perfect_regions"], "合成数据应存在可行阈值"
        grid_lo = min(r[0] for r in sweep["perfect_regions"])
        assert grid_lo == 0.65
        assert grid_lo > sweep["exact_lower_exclusive"], (
            "本用例专门构造网格下界偏严的场景")

    def test_out_of_range_check_uses_the_exact_upper_bound(self, monkeypatch):
        """当前阈值在**精确**上界之内时，不得报「已越出数据支持区间」。

        真实上界 0.8034、当前阈值 0.802：网格上界是 0.80，
        用网格判就会误报越界，进而推动人把阈值调低。
        """
        from eval_datasets.evaluate_grounding import (
            CaseResult, EvalReport, render_report,
        )
        monkeypatch.setattr(
            "eval_datasets.evaluate_grounding._VERDICT_GROUNDED_THRESHOLD", 0.802)
        rep = EvalReport([
            CaseResult("clean", "grounded", "grounded", 0.8034, []),
            CaseResult("bad", "partially_grounded", "partially_grounded", 0.60, []),
        ])
        sweep = sweep_thresholds(rep, step=0.01)
        assert sweep["exact_upper_inclusive"] == pytest.approx(0.8034)
        grid_hi = max(r[0] for r in sweep["perfect_regions"])
        assert grid_hi == 0.80
        out = render_report(rep, sweep)
        assert "已越出数据支持区间" not in out, (
            "0.802 <= 精确上界 0.8034，不算越界；用网格 0.80 判会误报")
        assert "已低于数据支持下界" not in out

    def test_exact_upper_bound_is_inclusive_and_lower_is_exclusive(self):
        """开闭语义：等于干净样本最低分可以，等于越界样本最高分不行。"""
        from eval_datasets.evaluate_grounding import CaseResult, EvalReport
        rep = EvalReport([
            CaseResult("clean", "grounded", "grounded", 0.8000, []),
            CaseResult("bad", "partially_grounded", "partially_grounded", 0.6000, []),
        ])
        sweep = sweep_thresholds(rep, step=0.01)
        assert sweep["exact_upper_inclusive"] == pytest.approx(0.8000)
        assert sweep["exact_lower_exclusive"] == pytest.approx(0.6000)


# ═══════════════════════════════════════════
# F. 阈值常量本身被钉住
# ═══════════════════════════════════════════

class TestThresholdConstants:
    def test_weights_sum_to_one(self):
        import grounding_verifier as gv

        total = (
            gv._WEIGHT_ID_VALIDITY
            + gv._WEIGHT_GROUNDING_RATIO
            + gv._WEIGHT_ENTITY_CONSISTENCY
            + gv._WEIGHT_KNOWLEDGE
            + gv._WEIGHT_FRESHNESS
            + gv._WEIGHT_CHAIN_INTEGRITY
        )
        assert abs(total - 1.0) < 1e-9, f"六个层权重之和为 {total}，不是 1.0"

    def test_thresholds_are_ordered(self):
        import grounding_verifier as gv

        assert gv._VERDICT_PARTIAL_THRESHOLD < gv._VERDICT_GROUNDED_THRESHOLD

    def test_knowledge_layer_is_actually_covered(self):
        """KB 命中样本得分应高于未命中样本 ——
        否则 Layer4 就是又一层空真（这正是 P0-C-1 之前的病因形态）。"""
        case = next(c for c in CASES if c["id"] == "kb_supported_bruteforce")
        no_kb = grounding_verifier.verify_chunk(
            [case["claim"]], case["events"], knowledge_chunks=[], chunk_id="c",
        ).claims[0]
        with_kb = grounding_verifier.verify_chunk(
            [case["claim"]], case["events"],
            knowledge_chunks=knowledge_for(case), chunk_id="c",
        ).claims[0]
        assert with_kb.grounding_score > no_kb.grounding_score, (
            "KB 命中与未命中得分相同 —— knowledge 层未真正参与评分"
        )
