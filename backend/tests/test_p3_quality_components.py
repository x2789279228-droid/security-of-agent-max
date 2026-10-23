"""
P3-2: LLM 质量评分 / 资源预算 / 执行状态 —— 拆成独立组件。

修复前不是「算错了」，而是**同一份指标在两处各算一遍且算法不同**：

    指标               veto_gates                agent_executor
    hallucination_risk 只取 verdict 属性         max(属性, raw 快照)
    grounding_score    `or 1.0` 兜住 None         无 None 保护

实测（修复前）：
    · raw 快照大于属性时，两个「平均幻觉风险」相差 0.7000
    · grounding_score=None 时，veto_gates 记 1.0，executor 抛 TypeError

线上没出事靠的是 sub_auditor 里 P0-C-2 的恢复语句，而那在**另一个模块** ——
「两个同名指标相等」因此是跨模块巧合，不是结构保证。

验收锚点：
  1. `score_verdicts` 是唯一实现，两个消费方都调它（结构断言 + 行为断言）
  2. 两个都叫过 evidence_completeness 但含义不同的度量被显式区分，
     且各自的旧数值被钉住 —— 不允许借「统一」之名悄悄改掉任何一个
  3. 质量评分 / 资源预算互不越界：预算对象不该知道阈值，评分对象不该知道准入
"""
import ast
import inspect

import pytest

import quality_scoring as qs
import veto_gates
from quality_scoring import (
    BudgetLedger,
    QualityScore,
    budget_for,
    score_verdicts,
)


class _V:
    """最小 ChunkVerdict 替身。"""

    def __init__(self, risk=0.0, grounding=1.0, claims=(), dumped=(),
                 raw=None):
        self.hallucination_risk = risk
        self.grounding_score = grounding
        self.threat_claims = list(claims)
        self.discarded_claims = list(dumped)
        if raw is not None:
            self.raw_evidence_validation = raw


# ═══════════════════════════════════════════
# A. 唯一实现约束
# ═══════════════════════════════════════════

class TestSingleImplementation:
    def test_both_consumers_call_score_verdicts(self):
        """两个消费方都必须调 score_verdicts，不得各写一份。"""
        gate_src = inspect.getsource(veto_gates.hop_stats_from_verdicts)
        assert "score_verdicts(" in gate_src, (
            "hop_stats_from_verdicts 未调用共用的 score_verdicts"
        )
        from agents import agent_executor
        ex_src = inspect.getsource(agent_executor)
        assert "score_verdicts(" in ex_src, (
            "agent_executor 未调用共用的 score_verdicts，"
            "质量评分仍存在第二份实现"
        )

    def test_no_inline_grounding_average_left_in_executor(self):
        """executor 里不得残留自己那套 avg_grounding 求法。

        旧实现是 `sum(v.grounding_score for v in verdicts) / len(verdicts)`
        —— 对 None 会 TypeError。允许对 verdicts 做别的遍历，
        但不能自己求 grounding 平均。
        """
        from agents import agent_executor
        src = inspect.getsource(agent_executor)
        assert "sum(v.grounding_score for v in verdicts)" not in src, (
            "agent_executor 仍在内联求 grounding 平均，未收敛到 score_verdicts"
        )

    def test_quality_scoring_does_not_import_gate_thresholds(self):
        """质量评分组件不得依赖 veto_gates 的阈值 —— 那会造成循环依赖
        且让「算分」与「判定阈值」重新纠缠。

        必须查**真实 import**而不是子串：模块 docstring 里为了说明
        「修复前两处各算一遍」而提到 veto_gates，那是叙述不是耦合。
        """
        tree = ast.parse(inspect.getsource(qs))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
        assert "veto_gates" not in imported, (
            f"quality_scoring 真的 import 了 veto_gates：{sorted(imported)}"
        )

    def test_quality_scoring_has_no_such_thresholds(self):
        """阈值（早停线）应当留在 veto_gates，不进评分组件。"""
        for name in ("HALLUCINATION_EARLY_STOP", "GROUNDING_EARLY_STOP",
                     "COMPLETENESS_EARLY_STOP"):
            assert not hasattr(qs, name), (
                f"{name} 不应出现在评分组件里 —— 它是判定阈值而非评分结果"
            )


# ═══════════════════════════════════════════
# B. 两个同名度量的区分（本轮最容易被改坏的地方）
# ═══════════════════════════════════════════

class TestTwoDifferentCompletenessMetrics:
    """修复前两处都叫 evidence_completeness，但分母定义不同。

    悄悄统一其中任何一个都会改变行为：
      · claim_support_ratio 驱动 executor 的 needs_human_review 与置信度打折
      · admitted_ratio      驱动 veto_gates.COMPLETENESS_EARLY_STOP
    """

    def test_metrics_can_differ(self):
        """构造两者必然不同的场景：断言有 ID 但引文全假。

        validate_evidence 只看 ID 是否存在 → 计入 valid；
        grounding 剥离会把它丢掉 → 计入 discarded。
        """
        v = _V(
            risk=0.0,
            grounding=1.0,
            claims=(),                      # 被剥离
            dumped=({"type": "X", "summary": "引文全假"},),
            raw={"total_claims": 2, "valid_claims": 2, "invalid_claims": 0,
                 "hallucination_risk": 0.0, "issues": []},
        )
        q = score_verdicts([v])
        assert q.claim_support_ratio == 1.0, "断言层面：两条都有 ID 支撑"
        assert q.admitted_ratio == 0.0, "投票层面：两条都没通过剥离"
        assert q.claim_support_ratio != q.admitted_ratio

    def test_hopstats_keeps_admitted_ratio_semantics(self):
        """HopStats.evidence_completeness 必须仍是投票层面的通过率。"""
        vs = [
            _V(claims=(), dumped=({"a": 1},)),
            _V(claims=({"b": 2},), dumped=()),
        ]
        stats = veto_gates.hop_stats_from_verdicts(vs)
        # admitted=1, discarded=1 → 0.5
        assert stats.evidence_completeness == pytest.approx(0.5)

    def test_hopstats_completeness_uses_admitted_ratio(self):
        """显式钉住：HopStats 不得改用 claim_support_ratio。

        若误改成断言层面的支撑率，上面的「引文全假」场景会从 0.0 变成 1.0，
        COMPLETENESS_EARLY_STOP 随之永不触发 —— 这正是要防的静默失效。
        """
        v = _V(
            claims=(), dumped=({"a": 1},),
            raw={"total_claims": 1, "valid_claims": 1, "invalid_claims": 0},
        )
        stats = veto_gates.hop_stats_from_verdicts([v])
        assert stats.evidence_completeness == 0.0, (
            f"早停口径被改成了断言支撑率（{stats.evidence_completeness}）—— "
            f"投票层面的通过率被旁路了"
        )


# ═══════════════════════════════════════════
# C. 评分算法本身
# ═══════════════════════════════════════════

class TestScoreVerdicts:
    def test_empty_verdicts_is_neutral(self):
        q = score_verdicts([])
        assert q.avg_grounding == 1.0
        assert q.avg_hallucination_risk == 0.0
        assert q.claim_support_ratio == 1.0
        assert q.admitted_ratio == 1.0

    def test_none_verdicts_is_neutral(self):
        assert score_verdicts(None) == score_verdicts([])

    def test_risk_takes_max_of_attr_and_raw_snapshot(self):
        """P0-C-2 语义：剥离不得把已发生的证据问题从指标里抹掉。"""
        q = score_verdicts([_V(risk=0.1, raw={"hallucination_risk": 0.8})])
        assert q.avg_hallucination_risk == pytest.approx(0.8)

        q2 = score_verdicts([_V(risk=0.9, raw={"hallucination_risk": 0.1})])
        assert q2.avg_hallucination_risk == pytest.approx(0.9)

    def test_grounding_none_is_treated_as_no_risk(self):
        """旧 executor 在这里会 TypeError；口径统一后两处都是 1.0。"""
        q = score_verdicts([_V(grounding=None)])
        assert q.avg_grounding == pytest.approx(1.0)

    def test_grounding_zero_is_preserved(self):
        """None 兜底不得把真实的 0 也吃掉。"""
        q = score_verdicts([_V(grounding=0.0)])
        assert q.avg_grounding == pytest.approx(0.0)

    def test_missing_grounding_attr_defaults_to_one(self):
        class _Bare:
            hallucination_risk = 0.0
        q = score_verdicts([_Bare()])
        assert q.avg_grounding == pytest.approx(1.0)

    def test_averages_over_verdicts(self):
        q = score_verdicts([_V(risk=0.0, grounding=1.0),
                            _V(risk=1.0, grounding=0.0)])
        assert q.avg_hallucination_risk == pytest.approx(0.5)
        assert q.avg_grounding == pytest.approx(0.5)

    def test_claim_counts_come_from_snapshot(self):
        q = score_verdicts([
            _V(raw={"total_claims": 5, "valid_claims": 3, "invalid_claims": 2}),
            _V(raw={"total_claims": 5, "valid_claims": 5, "invalid_claims": 0}),
        ])
        assert q.total_claims == 10
        assert q.valid_claims == 8
        assert q.invalid_claims == 2
        assert q.claim_support_ratio == pytest.approx(0.8)

    def test_issues_are_collected(self):
        q = score_verdicts([
            _V(raw={"issues": ["断言A无证据ID"]}),
            _V(raw={"issues": ["断言B无证据ID"]}),
        ])
        assert len(q.issues) == 2

    def test_falls_back_to_validate_evidence_when_no_snapshot(self):
        class _Legacy:
            hallucination_risk = 0.4
            grounding_score = 0.6
            threat_claims = []
            discarded_claims = []

            def validate_evidence(self):
                return {"total_claims": 4, "valid_claims": 2,
                        "invalid_claims": 2, "hallucination_risk": 0.5,
                        "issues": ["x"]}

        q = score_verdicts([_Legacy()])
        assert q.avg_hallucination_risk == pytest.approx(0.5)
        assert q.claim_support_ratio == pytest.approx(0.5)
        assert q.avg_grounding == pytest.approx(0.6)

    def test_validate_evidence_failure_does_not_propagate(self):
        class _Broken:
            hallucination_risk = 0.2
            grounding_score = 0.9
            threat_claims = []
            discarded_claims = []

            def validate_evidence(self):
                raise RuntimeError("boom")

        q = score_verdicts([_Broken()])
        assert q.avg_hallucination_risk == pytest.approx(0.2)
        assert q.avg_grounding == pytest.approx(0.9)

    def test_confidence_penalty_bounds(self):
        assert QualityScore(avg_hallucination_risk=0.0).confidence_penalty == 1.0
        assert QualityScore(
            avg_hallucination_risk=1.0).confidence_penalty == pytest.approx(0.7)


# ═══════════════════════════════════════════
# D. 资源预算账目
# ═══════════════════════════════════════════

class TestBudgetLedger:
    def test_defaults_to_one_call_per_chunk(self):
        b = budget_for(3)
        assert b.llm_calls_planned == 3
        assert b.llm_calls_made == 3
        assert b.llm_calls_skipped == 0
        assert b.chunks == 3

    def test_explicit_counters_win(self):
        b = budget_for(1, llm_calls_planned=6, llm_calls_made=2)
        assert b.llm_calls_planned == 6
        assert b.llm_calls_made == 2
        assert b.llm_calls_skipped == 4

    def test_zero_made_is_respected(self):
        """made=0 是有意义的（预算耗尽），不得被默认值覆盖成 chunks。"""
        b = budget_for(5, llm_calls_planned=5, llm_calls_made=0)
        assert b.llm_calls_made == 0
        assert b.llm_calls_skipped == 5

    def test_skipped_never_negative(self):
        b = budget_for(1, llm_calls_planned=2, llm_calls_made=5)
        assert b.llm_calls_skipped == 0

    def test_hop_budget_never_negative(self):
        assert BudgetLedger(llm_calls_planned=-3).hop_budget == 0

    def test_ledger_is_frozen(self):
        """预算账目不应被下游随手改写。"""
        with pytest.raises(Exception):
            BudgetLedger().llm_calls_planned = 99

    def test_hopstats_uses_ledger(self):
        stats = veto_gates.hop_stats_from_verdicts(
            [_V(), _V()], llm_calls_planned=6, llm_calls_made=2,
        )
        assert stats.llm_calls_planned == 6
        assert stats.llm_calls_made == 2
        assert stats.llm_calls_skipped == 4
        assert stats.hop_budget == 6

    def test_omitted_counters_fall_back_to_chunk_count(self):
        """不传 = 按 chunk 数推导。哨兵值必须是 None。

        修复过程中踩过的坑：hop_stats_from_verdicts 的默认值曾是 0，
        而 budget_for 判断 `is None` —— 两者对「未给出」的说法不一致，
        于是默认路径下 planned 变成 0，预算不可核。
        """
        stats = veto_gates.hop_stats_from_verdicts([_V(), _V(), _V()])
        assert stats.chunks == 3
        assert stats.llm_calls_planned >= 3, "计划调用数缺失 —— 预算不可核"
        assert stats.llm_calls_made >= 3, "实调用数缺失"

    def test_hopstats_honours_zero_made(self):
        """经由 hop_stats 传入 made=0 时也必须被尊重（预算耗尽）。"""
        stats = veto_gates.hop_stats_from_verdicts(
            [_V(), _V()], llm_calls_planned=5, llm_calls_made=0,
        )
        assert stats.llm_calls_made == 0, (
            f"made=0 被当成「未给出」覆盖了，实际 {stats.llm_calls_made}"
        )
        assert stats.llm_calls_skipped == 5


# ═══════════════════════════════════════════
# E. 组件边界
# ═══════════════════════════════════════════

class TestComponentBoundaries:
    def test_budget_does_not_know_about_quality(self):
        """预算账目不该带任何质量字段，反之亦然。"""
        budget_fields = set(BudgetLedger.__dataclass_fields__)
        quality_fields = set(QualityScore.__dataclass_fields__)
        assert not (budget_fields & quality_fields), (
            f"预算与评分字段重叠：{budget_fields & quality_fields}"
        )

    def test_module_imports_cleanly(self):
        """组件可独立导入 —— 不依赖 veto_gates 的加载副作用。"""
        import importlib
        m = importlib.import_module("quality_scoring")
        assert hasattr(m, "score_verdicts")
        assert hasattr(m, "budget_for")

    def test_no_module_level_side_effects(self):
        """导入组件不得产生副作用（连接 DB / 注册工具 / 读配置）。"""
        src = inspect.getsource(qs)
        tree = ast.parse(src)
        # 只允许 import / 赋值 / def / class / docstring 这类语句
        for node in tree.body:
            assert isinstance(
                node, (ast.Import, ast.ImportFrom, ast.Assign, ast.AnnAssign,
                       ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef,
                       ast.Expr, ast.If)
            ), f"模块顶层出现意外语句：{type(node).__name__}"
