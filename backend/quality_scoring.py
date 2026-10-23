"""
P3-2: 把 LLM 质量评分、资源预算、执行状态拆成清晰的独立组件。

修复前的问题不是「算错了」，而是**同一份指标在两个地方各算一遍**：

  · ``veto_gates.hop_stats_from_verdicts``  —— 供早停判定（skip_reasons）
  · ``agents/agent_executor``                 —— 供 needs_human_review 与置信度打折

两处算法并不相同：

  ==================  ==========================  ==========================
  指标                 hop_stats_from_verdicts      agent_executor
  ==================  ==========================  ==========================
  hallucination_risk  只取 verdict 属性            max(属性, raw 快照)
  grounding_score     ``or 1.0`` 兜住 None         不做 None 保护（会 TypeError）
  ==================  ==========================  ==========================

修复前实测：

  · 正常场景两者一致
  · raw 快照大于属性时，两者相差 **0.7000**
  · ``grounding_score=None`` 时 hop_stats 记 1.0，executor 抛 TypeError

线上之所以没出事，靠的是 ``sub_auditor`` 在 P0-C-2 里那句
``hallucination_risk = max(剥离后, 剥离前)`` 恢复语句 ——
而那在**另一个模块**。于是「两个同名指标相等」成了跨模块的巧合，
而不是结构保证：任何人只改其中一处，两边就静默分叉。

本模块把三类关注点各自独立：

  · :class:`QualityScore` —— 证据质量评分（grounding / hallucination / 完整度）
  · :class:`BudgetLedger` —— 资源账目（计划 / 实际 / 跳过 / 块数）
  · :func:`score_verdicts` —— 质量评分的**唯一**实现，两处都必须调它

执行状态不在这里：``TERMINAL_*`` 三态与 ``classify_terminal_state()``
已经是 ``veto_gates`` 里的独立单元，且被 log_ingestion / temporal 广泛消费。
为了「看起来整齐」把它搬走只会扩大回归面而不增加清晰度 ——
它现在的问题不是位置，是没有跨模块的一致性约束。

``HopStats`` 保留为**对外数据契约**：``ops_loop`` / ``thought_events`` /
``agent_executor`` 都直接读它的字段，它也是 ``hop_trace`` 的形状来源。
本模块只提供算出它的那两个组件，不动这个契约。
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

# 置信度打折系数：证据风险每满 1.0 扣 30% 置信度（上限 30%）。
# 原本内联在 agent_executor 的 `confidence_penalty = 1.0 - (risk * 0.3)`。
HALLUCINATION_PENALTY_WEIGHT = 0.3


@dataclass(frozen=True)
class QualityScore:
    """一轮审计的证据质量评分。纯数据 + 派生量，不含阈值策略。"""

    avg_hallucination_risk: float = 0.0
    avg_grounding: float = 1.0
    admitted_claims: int = 0
    discarded_claims: int = 0
    total_claims: int = 0
    valid_claims: int = 0
    invalid_claims: int = 0
    issues: tuple = ()

    # ── 两个都叫过 evidence_completeness、但含义不同的度量 ──
    # 修复前它们共用一个名字，且分母定义不一样。这里拆成两个显式名字，
    # 而不是替谁做主 —— 两者的用途不同，悄悄统一其中一个会改变早停行为。
    @property
    def claim_support_ratio(self) -> float:
        """断言层面：有多少条断言有真实事件 ID 支撑（P0-C-2 的剥离前口径）。

        executor 用它决定 needs_human_review 与置信度打折。
        """
        return (self.valid_claims / self.total_claims) if self.total_claims > 0 else 1.0

    @property
    def admitted_ratio(self) -> float:
        """投票层面：多少条断言通过了 grounding 剥离、进入投票集。

        ``veto_gates.COMPLETENESS_EARLY_STOP`` 用它做早停判定 ——
        驱动的是「有多少结论可用」，不是「有多少断言有 ID」。
        """
        denom = self.admitted_claims + self.discarded_claims
        return (self.admitted_claims / denom) if denom else 1.0

    @property
    def confidence_penalty(self) -> float:
        """证据质量对 LLM 自评置信度的折扣系数（0.7 ~ 1.0）。"""
        return 1.0 - (self.avg_hallucination_risk * HALLUCINATION_PENALTY_WEIGHT)


@dataclass(frozen=True)
class BudgetLedger:
    """一轮审计的 LLM 调用账目。只记账，不做准入决策。"""

    llm_calls_planned: int = 0
    llm_calls_made: int = 0
    chunks: int = 0

    @property
    def llm_calls_skipped(self) -> int:
        """计划了却没跑的预算。"""
        return max(self.llm_calls_planned - self.llm_calls_made, 0)

    @property
    def hop_budget(self) -> int:
        return max(self.llm_calls_planned, 0)


def _validation_for(v: Any) -> dict:
    """取该 verdict 的证据校验结果。

    P0-C-2 起 SubAuditor 会把**剥离前**的口径快照留在
    ``raw_evidence_validation`` 里 —— 那才是真实分母（见 sub_auditor.py:271）。
    没有快照的（测试替身、早期版本）退回按需计算；连方法都没有的
    （最小替身）返回空 dict，最终由属性兜底。
    """
    raw = getattr(v, "raw_evidence_validation", None) or {}
    if raw:
        return raw
    fn = getattr(v, "validate_evidence", None)
    if callable(fn):
        try:
            return fn() or {}
        except Exception:
            return {}
    return {}


def _risk_for(v: Any, validation: dict) -> float:
    """单条 verdict 的幻觉风险：属性与剥离前快照取较大者。

    取 max 是 P0-C-2 的语义 —— 剥离不得把已发生的证据问题从指标里抹掉。
    """
    attr = getattr(v, "hallucination_risk", None)
    raw = validation.get("hallucination_risk")
    return max(
        0.0 if attr is None else float(attr),
        0.0 if raw is None else float(raw),
    )


def _grounding_for(v: Any) -> float:
    """单条 verdict 的溯源分。None 兜成 1.0（视为无风险）。

    ⚠️ 这里必须是 **显式 None 判断**，不能用 `or 1.0`。
    Python 里 ``0.0`` 是 falsy，``0.0 or 1.0`` 会得到 **1.0** ——
    而修复前的 veto_gates 与 agent_executor 都写的 ``or 1.0``：
    一个溯源分为 0（完全无据）的 verdict 会被记成 1.0（完全可信），
    连带 avg_grounding 恒高，GROUNDING_EARLY_STOP（<0.5 早停）与
    executor 的 ``avg_grounding < 0.5`` 强制人审就此永不触发。
    这是 P3-2 抽取职责时暴露出来的既有缺陷，不是新引入的。
    """
    g = getattr(v, "grounding_score", None)
    return 1.0 if g is None else float(g)


def score_verdicts(verdicts: list) -> QualityScore:
    """质量评分的**唯一**实现。

    ``veto_gates.hop_stats_from_verdicts`` 与 ``agents/agent_executor``
    都必须调用本函数，不得各写一份 —— 这是 P3-2 的核心约束。
    """
    verdicts = list(verdicts or [])
    if not verdicts:
        return QualityScore()

    risks: list[float] = []
    grounds: list[float] = []
    total_claims = valid_claims = invalid_claims = 0
    admitted = discarded = 0
    issues: list[str] = []

    for v in verdicts:
        validation = _validation_for(v)
        risks.append(_risk_for(v, validation))
        grounds.append(_grounding_for(v))
        total_claims += int(validation.get("total_claims", 0) or 0)
        valid_claims += int(validation.get("valid_claims", 0) or 0)
        invalid_claims += int(validation.get("invalid_claims", 0) or 0)
        admitted += len(getattr(v, "threat_claims", None) or [])
        discarded += len(getattr(v, "discarded_claims", None) or [])
        issues.extend(validation.get("issues", []) or [])

    n = len(verdicts)
    return QualityScore(
        avg_hallucination_risk=sum(risks) / n,
        avg_grounding=sum(grounds) / n,
        admitted_claims=admitted,
        discarded_claims=discarded,
        total_claims=total_claims,
        valid_claims=valid_claims,
        invalid_claims=invalid_claims,
        issues=tuple(issues),
    )


def budget_for(
    chunks: int,
    llm_calls_planned: Optional[int] = None,
    llm_calls_made: Optional[int] = None,
) -> BudgetLedger:
    """账目构造。

    未显式给出时，计划数下限 = chunk 审核次数（每块一次 SubAuditor 调用）；
    deep 档另加 deep/recheck/kb 三跳，由 Executor 传入真实计划数覆盖。

    ⚠️ 判断「是否显式给出」必须用 ``is None``，不能用真值判断。
    修复前这里是 ``llm_calls_made if llm_calls_made else n`` ——
    ``made=0``（预算耗尽、一次都没跑）是**有意义**的取值，
    却被 falsy 判断吃掉、回落到 chunk 数，于是「跳过了几次 hop」
    在最该记账的那个场景里恰好记成 0。
    """
    chunks = int(chunks or 0)
    planned = chunks if llm_calls_planned is None else int(llm_calls_planned)
    made = chunks if llm_calls_made is None else int(llm_calls_made)
    return BudgetLedger(
        llm_calls_planned=planned,
        llm_calls_made=made,
        chunks=chunks,
    )
