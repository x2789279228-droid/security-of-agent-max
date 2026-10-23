"""统一检测结果契约 (Detection Contract)。

来源：2026-10-18 检测引擎正确性审查 P0-1 / 整改方案 §二。

**为什么需要这个模块**

修复前，Sigma、异常检测、EDR 关联、零日、因果链五个检测器各用各的
「无结果」表示法：空列表、`0.0`、`clean`、`UNKNOWN`、`None`。同一个
「我不知道」的语义散落在五处不同的值上，于是下游无法区分
「检测器挂了」与「确实干净」。

实测后果：Sigma 引擎崩溃时，一条真实的 critical 命中从
`P0 / llm_agent / pri=100` 降级为 `P3 / rule_close / pri=20`，
响应编排完全不触发；而引擎**内部**吞掉单条规则 SQL 失败那条路径
（`sigma_engine/engine.py` 的 `except Exception: hit = False`）连一行
WARNING 都不打，`errors` 为空、指标不触发——比崩溃更危险。

**五种状态的语义**

| 状态 | 含义 | 能否当作阴性 |
|---|---|---|
| `detected` | 已得到符合要求的正向检测结果 | 否 |
| `not_detected` | 检测完整执行，没有发现符合条件的信号 | 是 |
| `inconclusive` | 基线不足、数据不足或因果不可识别 | 否 |
| `error` | 检测器执行失败 | 否 |
| `partial` | 只完成部分规则或检测任务，仍有缺失 | 否 |

**关键约束**：`not_detected` 不能只代表「结果列表为空」。它必须同时
携带「预定检测范围已被完整执行」这一事实。例如 Sigma 有 100 条规则，
其中一条 critical 规则执行失败，即使另外 99 条都没有命中，也不能返回
普通的 `not_detected`，而应是 `partial`。

**关键约束**：`score` 在没有有效评分时必须是 `None`，不得用 `0` 代替。
`0.0` 是一个有意义的分数（"我算过了，就是 0"），`None` 才是"我算不出来"。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Literal, Optional, Sequence

CONTRACT_VERSION = "1.0"

DetectionStatus = Literal[
    "detected",
    "not_detected",
    "inconclusive",
    "error",
    "partial",
]

STATUS_DETECTED: DetectionStatus = "detected"
STATUS_NOT_DETECTED: DetectionStatus = "not_detected"
STATUS_INCONCLUSIVE: DetectionStatus = "inconclusive"
STATUS_ERROR: DetectionStatus = "error"
STATUS_PARTIAL: DetectionStatus = "partial"

ALL_STATUSES: frozenset[str] = frozenset({
    STATUS_DETECTED, STATUS_NOT_DETECTED, STATUS_INCONCLUSIVE,
    STATUS_ERROR, STATUS_PARTIAL,
})

#: 只有这两种状态是「有定论」的：要么找到了东西，要么完整地确认没有。
DEFINITIVE_STATUSES: frozenset[str] = frozenset({STATUS_DETECTED, STATUS_NOT_DETECTED})

#: 这些状态表示「没能得出完整的阴性结论」，下游不得当作干净收口。
INCOMPLETE_STATUSES: frozenset[str] = frozenset({
    STATUS_INCONCLUSIVE, STATUS_ERROR, STATUS_PARTIAL,
})

#: 这些状态代表检测器自身出了问题（区别于「数据不足」）。
FAILED_STATUSES: frozenset[str] = frozenset({STATUS_ERROR, STATUS_PARTIAL})


def is_definitive(status: Optional[str]) -> bool:
    """是否为有定论的状态（detected / not_detected）。"""
    return status in DEFINITIVE_STATUSES


def is_incomplete(status: Optional[str]) -> bool:
    """是否为「未能得出完整阴性结论」的状态。"""
    return status in INCOMPLETE_STATUSES


def can_treat_as_negative(status: Optional[str]) -> bool:
    """能否把该状态当作本检测器的阴性结果。

    只有 `not_detected` 可以。`detected` 不是阴性；其余三种都表示
    「我们没有足够依据说它干净」。
    """
    return status == STATUS_NOT_DETECTED


def combine_status(statuses: Sequence[str]) -> DetectionStatus:
    """把多个检测器的状态合并成整体分析状态。

    规则（整改方案 §二.2）：
      - 某引擎失败时**保留其他引擎的有效结果**，整体标注为 partial；
      - 没有失败、至少一个命中 → detected；
      - 没有失败、全部完整阴性 → not_detected；
      - 没有命中但有 inconclusive → inconclusive；
      - 全部 error → error。
    """
    vals = [s for s in statuses if s]
    if not vals:
        return STATUS_INCONCLUSIVE
    for v in vals:
        if v not in ALL_STATUSES:
            raise ValueError(f"unknown detection status: {v!r}")

    has_failure = any(s in FAILED_STATUSES for s in vals)
    positives = [s for s in vals if s == STATUS_DETECTED]

    if has_failure:
        if positives:
            # 有正向证据 + 有失败 → 证据可用，但分析不完整
            return STATUS_PARTIAL
        if all(s == STATUS_ERROR for s in vals):
            return STATUS_ERROR
        return STATUS_PARTIAL
    if positives:
        return STATUS_DETECTED
    if all(s == STATUS_NOT_DETECTED for s in vals):
        return STATUS_NOT_DETECTED
    return STATUS_INCONCLUSIVE


@dataclass
class DetectionResult:
    """单个检测器对单个事件的统一输出。

    注意 `score=None` 与 `score=0.0` 的区别：
      - `0.0`  → 检测器执行了，得分为 0（"我算过了"）
      - `None` → 检测器没有可用分数（"我算不出来"）
    """

    detector: str
    detector_version: str
    event_id: str
    status: DetectionStatus
    score: Optional[float] = None
    score_type: Optional[str] = None
    severity: Optional[str] = None
    evidence_ids: list[str] = field(default_factory=list)
    rule_version: Optional[str] = None
    analysis_window: Optional[dict[str, Any]] = None
    error_code: Optional[str] = None
    error_message: Optional[str] = None
    #: 失败发生在**哪个阶段**（detect / persist / dispatch …）。
    #::
    #: 整改方案 §二 验收要求 3 要求融合层记录「哪个检测器、哪个版本、
    #: **在哪个阶段**失败」。修复前这个信息只以 `error_message` 的
    #: 方括号前缀（`"[detect] ..."`）存在 —— 下游只能靠**解析字符串**取，
    #: 消息一改格式阶段信息就静默丢失。本字段是它的**结构化**载体。
    phase: str = ""

    def __post_init__(self) -> None:
        if self.status not in ALL_STATUSES:
            raise ValueError(f"unknown detection status: {self.status!r}")
        if self.score is not None:
            try:
                self.score = float(self.score)
            except (TypeError, ValueError) as exc:
                raise ValueError(
                    f"[{self.detector}] score must be a real number or None, "
                    f"got {self.score!r}"
                ) from exc

    # ── 状态判定 ──

    @property
    def is_definitive(self) -> bool:
        """状态是否有定论。"""
        return is_definitive(self.status)

    @property
    def can_treat_as_negative(self) -> bool:
        """能否当作本检测器的阴性结果。"""
        return can_treat_as_negative(self.status)

    @property
    def is_incomplete(self) -> bool:
        """分析是否不完整（不能干净收口）。"""
        return is_incomplete(self.status)

    @property
    def is_failure(self) -> bool:
        """检测器自身是否失败（error / partial）。"""
        return self.status in FAILED_STATUSES

    def to_dict(self) -> dict[str, Any]:
        return {
            "detector": self.detector,
            "detector_version": self.detector_version,
            "event_id": self.event_id,
            "status": self.status,
            "score": self.score,
            "score_type": self.score_type,
            "severity": self.severity,
            "evidence_ids": list(self.evidence_ids),
            "rule_version": self.rule_version,
            "analysis_window": self.analysis_window,
            "error_code": self.error_code,
            "error_message": self.error_message,
            "phase": self.phase,
        }

    @classmethod
    def from_error(
        cls,
        detector: str,
        event_id: str,
        *,
        error_code: str,
        error_message: str,
        detector_version: str = "",
        phase: str = "detect",
    ) -> "DetectionResult":
        """构造一个 `error` 状态的检测结果。"""
        return cls(
            detector=detector,
            detector_version=detector_version,
            event_id=str(event_id),
            status=STATUS_ERROR,
            score=None,          # 绝不用 0.0 冒充失败
            error_code=error_code,
            error_message=f"[{phase}] {error_message}" if phase else error_message,
            # 阶段同时进**结构化字段**（消息里的前缀保持不变，向后兼容）
            phase=phase or "",
        )


@dataclass
class AnalysisStatus:
    """整条事件的分析完整性（跨检测器聚合）。"""

    status: DetectionStatus
    detectors: dict[str, str] = field(default_factory=dict)
    results: list[DetectionResult] = field(default_factory=list)

    # ── 便捷判定 ──

    @property
    def complete(self) -> bool:
        """分析是否完整（每个检测器都给出了有定论的结果）。"""
        return not is_incomplete(self.status)

    @property
    def can_close_as_negative(self) -> bool:
        """是否允许按「阴性」收口。"""
        return self.status == STATUS_NOT_DETECTED

    @property
    def has_detection(self) -> bool:
        """是否存在正向证据（含 partial 情形下的正向证据）。"""
        return any(r.status == STATUS_DETECTED for r in self.results)

    @property
    def failed_detectors(self) -> list[str]:
        return sorted({r.detector for r in self.results if r.is_failure})

    @property
    def incomplete_detectors(self) -> list[str]:
        return sorted({
            r.detector for r in self.results
            if r.status in INCOMPLETE_STATUSES
        })

    def error_summary(self) -> list[dict[str, Any]]:
        """可落库 / 可上报的失败明细：哪个检测器、哪个版本、哪个阶段。"""
        return [
            {
                "detector": r.detector,
                "detector_version": r.detector_version or "",
                "status": r.status,
                "error_code": r.error_code or "",
                "error_message": r.error_message or "",
                # 「哪个阶段」的结构化载体（此前只藏在消息前缀里）
                "phase": r.phase or "",
            }
            for r in self.results
            if r.status in INCOMPLETE_STATUSES
        ]

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "complete": self.complete,
            "can_close_as_negative": self.can_close_as_negative,
            "detectors": dict(self.detectors),
            "failed_detectors": self.failed_detectors,
            "errors": self.error_summary(),
            "contract_version": CONTRACT_VERSION,
        }

    # ── 构造 ──

    @classmethod
    def build(cls, results: Iterable[DetectionResult]) -> "AnalysisStatus":
        """从各检测器结果聚合出整体分析状态。"""
        rs = list(results)
        by_name: dict[str, str] = {}
        for r in rs:
            # 同一检测器重复出现时，取最严重的状态
            prev = by_name.get(r.detector)
            if prev is None or (prev in DEFINITIVE_STATUSES
                                and r.status in INCOMPLETE_STATUSES):
                by_name[r.detector] = r.status
        return cls(status=combine_status(list(by_name.values())),
                   detectors=by_name, results=rs)
