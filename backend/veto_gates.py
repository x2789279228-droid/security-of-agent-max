"""
否决闸 — Audit-LLM 程序化硬约束（不依赖 LLM）

对应修复计划 PR1:
  P0-1  ungrounded 主张不得进入 threat_detected
  P0-3  confirmed 必须绑定非 LLM 信号（Sigma / CEP / 异常 / IOC）
  P0-4  多轮禁止 OR 合并
  P0-8  逐步错误预算、早停、Reviewer 只准降级
  P0-9  默认路径 LLM hop ≤ 3
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

# P3-2: 质量评分与资源预算的计算收敛到独立组件，本模块只保留阈值与判定策略。
from quality_scoring import budget_for, score_verdicts


# ── 常量 ──

GROUNDED = "grounded"
PARTIALLY_GROUNDED = "partially_grounded"
UNGROUNDED = "ungrounded"

VERDICT_CONFIRMED = "confirmed"
VERDICT_SUSPICIOUS = "suspicious"
VERDICT_FALSE_POSITIVE = "false_positive"
VERDICT_INSUFFICIENT = "insufficient_evidence"

CONCLUSION_CONFIRMED = "threat_confirmed"
CONCLUSION_SUSPICIOUS = "suspicious"
CONCLUSION_FALSE_POSITIVE = "false_positive"
CONCLUSION_INSUFFICIENT = "insufficient_evidence"

CONCLUSION_RANK = {
    CONCLUSION_FALSE_POSITIVE: 0,
    CONCLUSION_INSUFFICIENT: 1,
    CONCLUSION_SUSPICIOUS: 2,
    CONCLUSION_CONFIRMED: 3,
}

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]

ADMITTED_VERDICTS = {GROUNDED, PARTIALLY_GROUNDED}

# 非 LLM 异常分达到该值才算"检测信号"（与 fallback_analysis 一致）
ANOMALY_SIGNAL_THRESHOLD = 0.6

# SubAuditor 平均幻觉风险超过该值 → 跳过后续推理 hop
HALLUCINATION_EARLY_STOP = 0.3
GROUNDING_EARLY_STOP = 0.5
COMPLETENESS_EARLY_STOP = 0.3

HIGH_RISK_EVENT_TYPES = {
    "C2_BEACON", "DATA_EXFIL", "MALWARE_DETECT",
    "RANSOMWARE", "LATERAL_MOVE", "PRIV_ESC",
    "PRIVILEGE_ESCALATION", "COMMAND_INJECTION",
}

# 单事件审计严重度封顶：LLM 不得把扫描类抬到 critical
SEVERITY_CEILING_BY_TYPE = {
    "PORT_SCAN": "high",
    "XSS_ATTACK": "high",
    "DNS_QUERY": "medium",
    "USER_LOGIN": "medium",
}


# ═══════════════════════════════════════════
# P0-1 主张剥离
# ═══════════════════════════════════════════

def strip_ungrounded_claims(
    claims: list[dict],
    claim_reports: Optional[list[Any]] = None,
) -> tuple[list[dict], list[dict]]:
    """
    将 ungrounded 主张从可投票集合中剥离。

    claim_reports: GroundingVerifier 返回的 ClaimGroundingReport 列表（按 claims 对齐）。
    无 report 时，缺少 evidence_ids 的主张视为 ungrounded。

    Returns:
        (admitted, discarded)
    """
    admitted: list[dict] = []
    discarded: list[dict] = []

    if not claims:
        return admitted, discarded

    for i, claim in enumerate(claims):
        annotated = dict(claim)
        verdict = UNGROUNDED
        score = 0.0

        if claim_reports is not None and i < len(claim_reports):
            report = claim_reports[i]
            verdict = getattr(report, "verdict", None) or report.get("verdict", UNGROUNDED)
            score = getattr(report, "grounding_score", None)
            if score is None and isinstance(report, dict):
                score = report.get("grounding_score", 0.0)
            score = float(score or 0.0)
        else:
            ev_ids = claim.get("evidence_ids") or []
            quotes = claim.get("evidence_quotes") or []
            if ev_ids and quotes:
                verdict = PARTIALLY_GROUNDED
                score = 0.5
            elif ev_ids:
                verdict = PARTIALLY_GROUNDED
                score = 0.4
            else:
                verdict = UNGROUNDED
                score = 0.0

        annotated["grounding_verdict"] = verdict
        annotated["grounding_score"] = round(score, 4)

        if verdict in ADMITTED_VERDICTS:
            admitted.append(annotated)
        else:
            discarded.append(annotated)

    return admitted, discarded


def has_admitted_threat_claims(admitted: list[dict]) -> bool:
    """
    列表里是否有 grounding_verdict 属于 ADMITTED_VERDICTS 的 claim。

    ⚠ §十一.2 查证结论：**不要把它接到 apply_confirmation_gate 的
    has_admitted_claims 入参上。** 名字读起来正是那个入参该用的东西，
    但两者语义并不等价：

      * 生产判定用的是 `len(threat_claims) > 0`
        （ChunkVerdict.threat_claims 由 strip_ungrounded_claims 写入，
         只收 ADMITTED_VERDICTS —— 故两者在生产路径上恒等；
         executor:917 的异常分支 threat_claims 为空，两种写法也一致）；
      * 本函数判的是 **grounding_verdict 字段在不在**，不是 grounding 本身。

    接上它会让「带真实 evidence_ids + evidence_quotes、只是没带
    grounding_verdict 注解」的 claim 被判为无据 —— 有证据的威胁被降级成
    insufficient_evidence 并强制人审。实测这让 test_p1a_evidence_and_recheck
    与 test_p1b_terminal_state 共 3 条既有用例转红（结论被改写），
    才暴露出本函数的判据与意图不符。

    要不要把「注解是否存在」换成「真正判 grounding」是独立的语义决策，
    不属于死代码清理，不在本次范围内。
    """
    return any(c.get("grounding_verdict") in ADMITTED_VERDICTS for c in admitted)


# ═══════════════════════════════════════════
# P0-3 非 LLM 信号 + confirmed 闸
# ═══════════════════════════════════════════

# 事件类型本身即可视为检测信号（结论型告警），避免无 Sigma 时 LLM 结论被抹除。
# 注意: extract_non_llm_signals 会把事件类型 upper() 后比较，
# 因此此处必须用全大写（历史上混写的 "DDoS_TRAFFIC" 永远无法命中）。
TYPE_SIGNAL_EVENTS = frozenset({
    "BRUTE_FORCE", "SSH_BRUTE", "C2_BEACON", "DATA_EXFIL",
    "LATERAL_MOVE", "LATERAL_MOVEMENT", "PORT_SCAN", "MALWARE_DETECT",
    "RANSOMWARE", "DDOS_TRAFFIC", "DDOS",
    # v5 修复(C2):补齐词表缺口（此前「命令注入」/提权类永远拿不到 type_signal）
    "COMMAND_INJECTION", "SQL_INJECTION", "XSS_ATTACK",
    "PRIVILEGE_ESCALATION", "PRIV_ESC",
})


@dataclass
class NonLlmSignals:
    sigma_hit: bool = False
    sigma_severity: str = ""
    cep_chain: bool = False
    anomaly_triggered: bool = False
    anomaly_score: float = 0.0
    ioc_hit: bool = False
    type_signal: bool = False
    reasons: list[str] = field(default_factory=list)

    @property
    def has_signal(self) -> bool:
        return bool(
            self.sigma_hit
            or self.cep_chain
            or self.anomaly_triggered
            or self.ioc_hit
            or self.type_signal
        )

    def to_dict(self) -> dict:
        return {
            "sigma_hit": self.sigma_hit,
            "sigma_severity": self.sigma_severity,
            "cep_chain": self.cep_chain,
            "anomaly_triggered": self.anomaly_triggered,
            "anomaly_score": round(self.anomaly_score, 4),
            "ioc_hit": self.ioc_hit,
            "type_signal": self.type_signal,
            "has_signal": self.has_signal,
            "reasons": self.reasons[:8],
        }


def extract_non_llm_signals(
    raw_event: Optional[dict] = None,
    tool_results: Optional[Iterable[Any]] = None,
    chain_info: str = "",
    anomaly_score: Optional[float] = None,
) -> NonLlmSignals:
    """从原始事件 / 工具结果提取非 LLM 检测信号。"""
    event = raw_event or {}
    signals = NonLlmSignals()

    sigma = event.get("_sigma") or {}
    if isinstance(sigma, dict) and sigma.get("detected"):
        signals.sigma_hit = True
        signals.sigma_severity = str(sigma.get("max_severity") or "")
        signals.reasons.append(
            f"sigma:{sigma.get('rule_count', 1)}:{','.join(sigma.get('attack_types') or [])}"
        )

    evt_type = str(
        event.get("event") or event.get("event_type") or event.get("type") or ""
    ).strip().upper().replace("-", "_").replace(" ", "_")
    # v5 修复(C2):自然语言事件名(如「命令注入」/「C2 通信」)upper() 后仍是中文，
    # 无法直接命中 ASCII 词表 — 先经 infer_threat_type 归一为标准枚举再匹配
    if evt_type not in TYPE_SIGNAL_EVENTS:
        try:
            from correlation_engine import infer_threat_type
            inferred = infer_threat_type(
                str(event.get("event") or event.get("event_type") or event.get("type") or "")
            )
            if inferred:
                evt_type = str(inferred).strip().upper()
        except Exception:
            pass
    if evt_type in TYPE_SIGNAL_EVENTS:
        signals.type_signal = True
        signals.reasons.append(f"type_signal:{evt_type}")

    score = anomaly_score
    if score is None:
        score = event.get("_anomaly_score")
        if score is None:
            anomaly = event.get("_anomaly") or {}
            if isinstance(anomaly, dict):
                score = anomaly.get("score")
    try:
        signals.anomaly_score = float(score or 0.0)
    except (TypeError, ValueError):
        signals.anomaly_score = 0.0
    if signals.anomaly_score >= ANOMALY_SIGNAL_THRESHOLD:
        signals.anomaly_triggered = True
        signals.reasons.append(f"anomaly:{signals.anomaly_score:.2f}")

    ioc = event.get("_ioc") or event.get("_ioc_matches") or event.get("ioc_matches")
    intel = event.get("_intel") or {}
    if ioc:
        if isinstance(ioc, list) and len(ioc) > 0:
            signals.ioc_hit = True
        elif isinstance(ioc, dict) and ioc.get("matched"):
            signals.ioc_hit = True
        elif ioc is True:
            signals.ioc_hit = True
    if isinstance(intel, dict) and (intel.get("matched") or intel.get("hit")):
        signals.ioc_hit = True
    if signals.ioc_hit:
        signals.reasons.append("ioc")

    chain_text = (chain_info or "").strip()
    if chain_text and chain_text not in ("（无）", "(无)", "无"):
        signals.cep_chain = True
        signals.reasons.append("cep_chain_text")

    if tool_results:
        for r in tool_results:
            tool = getattr(r, "tool", None) or (r.get("tool") if isinstance(r, dict) else "")
            success = getattr(r, "success", True)
            if isinstance(r, dict):
                success = r.get("success", True)
            data = getattr(r, "data", None)
            if isinstance(r, dict):
                data = r.get("data")
            if not success or not data:
                continue
            if str(tool).startswith("causal"):
                continue
            if tool == "correlation.chains" and isinstance(data, list) and data:
                signals.cep_chain = True
                signals.reasons.append(f"cep_tool:{len(data)}")

    return signals


@dataclass
class ConfirmationDecision:
    threat_detected: bool
    verdict: str
    needs_human_review: bool
    reason: str

    def to_dict(self) -> dict:
        return {
            "threat_detected": self.threat_detected,
            "verdict": self.verdict,
            "needs_human_review": self.needs_human_review,
            "reason": self.reason,
        }


def apply_confirmation_gate(
    *,
    llm_threat_detected: bool,
    llm_abstain: bool = False,
    signals: Optional[NonLlmSignals] = None,
    has_admitted_claims: bool = False,
    extra_human: bool = False,
) -> ConfirmationDecision:
    """
    LLM 不得单独把事件升级为 confirmed。

    confirmed 必要条件: 非 LLM 信号 AND 至少一条 admitted claim AND LLM 未弃权。
    """
    signals = signals or NonLlmSignals()

    if llm_abstain:
        return ConfirmationDecision(
            threat_detected=False,
            verdict=VERDICT_INSUFFICIENT,
            needs_human_review=True,
            reason="llm_abstain",
        )

    if not has_admitted_claims:
        return ConfirmationDecision(
            threat_detected=False,
            verdict=VERDICT_INSUFFICIENT,
            needs_human_review=True,
            reason="no_grounded_claims",
        )

    if llm_threat_detected and signals.has_signal:
        return ConfirmationDecision(
            threat_detected=True,
            verdict=VERDICT_CONFIRMED,
            needs_human_review=extra_human,
            reason="grounded+non_llm_signal",
        )

    if llm_threat_detected and not signals.has_signal:
        return ConfirmationDecision(
            threat_detected=False,
            verdict=VERDICT_SUSPICIOUS,
            needs_human_review=True,
            reason="llm_threat_without_detector",
        )

    if not llm_threat_detected and signals.has_signal:
        return ConfirmationDecision(
            threat_detected=False,
            verdict=VERDICT_SUSPICIOUS,
            needs_human_review=True,
            reason="detector_hit_llm_cleared",
        )

    return ConfirmationDecision(
        threat_detected=False,
        verdict=VERDICT_FALSE_POSITIVE,
        needs_human_review=extra_human,
        reason="no_threat",
    )


# ═══════════════════════════════════════════
# P0-4 多轮合并（禁止 OR）
# ═══════════════════════════════════════════

def _severity_index(sev: str) -> int:
    try:
        return SEVERITY_ORDER.index((sev or "info").lower())
    except ValueError:
        return 0


def cap_reported_severity(
    llm_severity: str,
    *,
    event_type: str = "",
    event_severity: str = "",
    sigma_severity: str = "",
    has_chain: bool = False,
) -> str:
    """限制 LLM 相对原始事件/Sigma 的严重度抬升（最多 +1 级）。

    无事件上下文时不改写（避免单测/缺字段路径误伤）。
    PORT_SCAN 等扫描类即使有链，单事件审计仍不超过类型天花板。
    """
    llm = (llm_severity or "info").lower()
    if llm not in SEVERITY_ORDER:
        llm = "info"
    if not (event_type or event_severity or sigma_severity):
        return llm

    base_idx = 0
    for cand in (event_severity, sigma_severity):
        base_idx = max(base_idx, _severity_index(cand))
    max_idx = min(base_idx + 1, len(SEVERITY_ORDER) - 1)

    et = (event_type or "").upper().replace("-", "_")
    if et in HIGH_RISK_EVENT_TYPES:
        max_idx = len(SEVERITY_ORDER) - 1
    elif has_chain:
        max_idx = max(max_idx, _severity_index("high"))

    ceiling = SEVERITY_CEILING_BY_TYPE.get(et)
    if ceiling:
        max_idx = min(max_idx, _severity_index(ceiling))

    return SEVERITY_ORDER[min(_severity_index(llm), max_idx)]


# ═══════════════════════════════════════════
# P1-C-5: ATT&CK / CVE 编号的词边界校验
# ═══════════════════════════════════════════
# ATT&CK 技术编号形如 T1071；CVE 形如 CVE-2021-44228。
# 必须要求编号两侧不是字母/数字，否则 "T10460" 会满足 "T1046"、
# "T10711" 会满足 "T1071"，编号校验形同虚设。
_TECHNIQUE_ID_RE = re.compile(r"(?<![A-Za-z0-9])T\d{4}(?![0-9])", re.IGNORECASE)


def _identifier_supported(entity: str, evidence: str) -> bool:
    """编号是否在证据中出现（词边界锚定，大小写不敏感）。"""
    target = str(entity or "").strip().upper()
    if not target or not evidence:
        return False
    if not target.startswith("T"):
        # 非 ATT&CK 编号（CVE 等）交由 faithfulness_gate 的规则处理
        return target in evidence.upper()
    for m in _TECHNIQUE_ID_RE.finditer(evidence):
        if m.group(0).upper() == target:
            return True
    return False


def strip_phantom_mitre(
    merged: dict, evidence: str = "", trusted_evidence: str = ""
) -> dict:
    """去掉没有可信证据支撑的 ATT&CK 技术编号。

    P1-C-5 三处修正：
      1. **判定基准**：修复前直接在含原始 ``message`` 的全文里做裸子串匹配。
         攻击者只要在日志正文写上 "T1071"，就能给自己的幻影 ATT&CK 标签洗白。
         现只认 ``trusted_evidence``（字段引用 + 工具输出，不含自由文本）。
      2. **词边界**：修复前无边界锚定 —— 证据含 "T10460" 会让 "T1046" 误命中。
      3. **可追溯**：修复前 ``stripped_mitre`` 只存编号，没有「为何剥离」。

    另修死代码：修复前无条件写入 ``out["mitre_techniques"] = kept``，
    而本管线根本没有 mitre_techniques 这个键（无任何 prompt 要求 LLM 输出），
    于是每次都写入空列表，看起来像「已检查且无标签」。
    现在只在确有该字段时才改写它。
    """
    out = dict(merged or {})
    trusted = trusted_evidence or evidence

    def _tid(item) -> str:
        if isinstance(item, dict):
            return str(item.get("id") or item.get("technique") or item.get("mitre_id") or "")
        return str(item or "")

    def _keep(tid: str) -> bool:
        return _identifier_supported(tid, trusted)

    had_field = "mitre_techniques" in out or "techniques" in out
    techs = list(out.get("mitre_techniques") or out.get("techniques") or [])
    kept = [t for t in techs if _keep(_tid(t))]
    stripped = [_tid(t) for t in techs if _tid(t) and not _keep(_tid(t))]
    phantoms = (out.get("faithfulness") or {}).get("phantom_entities") or []
    mitre_phantoms = [
        p for p in phantoms
        if isinstance(p, str) and p.upper().startswith("T")
    ]

    if had_field:
        out["mitre_techniques"] = kept

    reasons = {}
    for tid in stripped:
        reasons[tid] = "not_in_trusted_evidence"
    for tid in mitre_phantoms:
        reasons.setdefault(tid, "flagged_phantom_by_faithfulness")

    labeled = list(dict.fromkeys([s for s in stripped + mitre_phantoms if s]))
    if labeled:
        out["stripped_mitre"] = labeled
        # P1-C-5: 记录剥离原因，供审计追溯
        out["stripped_mitre_reasons"] = {
            k: v for k, v in reasons.items() if k in labeled
        }
    return out


def sanitize_merged_audit(
    merged: dict,
    *,
    evidence: str = "",
    trusted_evidence: str = "",
    event_type: str = "",
    event_severity: str = "",
    sigma_severity: str = "",
    has_chain: bool = False,
) -> dict:
    """程序化收口 LLM 合并结果：严重度封顶 + 剥离幻觉 MITRE。"""
    out = dict(merged or {})
    out["severity"] = cap_reported_severity(
        out.get("severity") or "info",
        event_type=event_type,
        event_severity=event_severity,
        sigma_severity=sigma_severity,
        has_chain=has_chain,
    )
    return strip_phantom_mitre(
        out, evidence=evidence, trusted_evidence=trusted_evidence
    )


def _median_severity(severities: list[str], cap: str = "medium") -> str:
    """无证据合并时取下中位数，并封顶 cap，禁止抬到 critical。"""
    if not severities:
        return "info"
    idxs = sorted(_severity_index(s) for s in severities)
    mid = idxs[(len(idxs) - 1) // 2]
    sev = SEVERITY_ORDER[mid]
    if cap and _severity_index(sev) > _severity_index(cap):
        return cap
    return sev


# ═══════════════════════════════════════════
# P1-Executor: 三类终态 + 「未完成」判定
# ═══════════════════════════════════════════
#
# 修复前 Executor 的 hop 预算只有三种成因（幻觉风险 / grounding / 证据完整度）
# 折叠成一个 bool `skip_reasoning`，且没有任何地方记录「这一轮到底跑没跑完」。
# 后果有两层：
#   1. 语义丢失 —— 「因为证据太差所以不推理」与「因为 depth 不是 deep」
#      在 hop_trace 里长得一模一样，无法审计资源决策是否合理。
#   2. 更严重：预算耗尽的轮次落进 merge_audit_rounds 的 else 分支，
#      拿到与「审完且干净」完全相同的 verdict 字符串 false_positive。
#      未完成被伪装成已排除 = 漏报，且不可审计。

TERMINAL_COMPLETED = "completed"              # 正常跑完
TERMINAL_BUDGET_EXHAUSTED = "budget_exhausted"  # 预算/早停终止
TERMINAL_SECURITY_DENIED = "security_denied"   # 被安全层拒绝执行

TERMINAL_STATES = (
    TERMINAL_COMPLETED,
    TERMINAL_BUDGET_EXHAUSTED,
    TERMINAL_SECURITY_DENIED,
)

# hop 早停的三类成因 —— 必须分开记账，不能再折叠成一个 bool
HOP_SKIP_HALLUCINATION = "hallucination_risk"
HOP_SKIP_GROUNDING = "grounding"
HOP_SKIP_COMPLETENESS = "evidence_completeness"


def classify_terminal_state(
    *,
    skip_reasoning: bool = False,
    security_denied: bool = False,
    short_circuit: str = "",
) -> str:
    """把执行路径归入三类终态之一（互斥，安全拒绝优先）。"""
    if security_denied:
        return TERMINAL_SECURITY_DENIED
    if short_circuit:
        return TERMINAL_BUDGET_EXHAUSTED
    if skip_reasoning:
        return TERMINAL_BUDGET_EXHAUSTED
    return TERMINAL_COMPLETED


def round_incomplete(round_data: dict) -> tuple[bool, str]:
    """判定单轮是否「未完成」，返回 (是否未完成, 原因码)。

    未完成的两种可观察形态：
      1. 顶层 ``short_circuit`` 非空（硬预算短路，audit 载荷为空）
      2. ``audit`` 为空 dict —— 没有产出任何结论
    """
    if not isinstance(round_data, dict):
        return True, "malformed_round"
    sc = str(round_data.get("short_circuit") or "")
    if sc:
        return True, f"short_circuit:{sc}"
    audit = round_data.get("audit")
    if audit is None or (isinstance(audit, dict) and not audit):
        return True, "empty_audit"
    return False, ""


def merge_audit_rounds(
    all_rounds: list[dict],
    signals: Optional[NonLlmSignals] = None,
) -> dict:
    """
    多轮合并：禁止"任意一轮发现威胁 → 最终有威胁"。

    confirmed 当且仅当:
      至少一轮 threat_detected（已经过单轮闸）且 has_non_llm_signal。
    单轮 LLM 喊威胁、无检测信号 → suspicious + 人审。
    severity: 有 confirmed 轮取其中最高；否则取中位数，禁止无证据抬到 critical。
    """
    if not all_rounds:
        return {
            "threat_detected": False,
            "verdict": VERDICT_INSUFFICIENT,
            "confidence": 0.0,
            "severity": "info",
            "needs_human": False,
            "total_rounds": 0,
            "all_missed_count": 0,
            "confirming_rounds": 0,
        }

    signals = signals or NonLlmSignals()

    # ── P1: 未完成的分析不得冒充「全部清白」 ──
    # 修复前：硬预算短路 / hop 预算早停 / 工具被安全层拒绝的轮次，
    # 其 audit 载荷要么为空、要么看不出「没跑完」，于是这里直接落到
    # else 分支输出 VERDICT_FALSE_POSITIVE —— 与真正审完且干净的轮次
    # **字符串完全相同**，仅 confidence 不同。下游无法区分
    # 「查过了，确实没有威胁」与「根本没查成」。
    incomplete = [r for r in all_rounds if round_incomplete(r)[0]]
    incomplete_reasons = sorted({round_incomplete(r)[1] for r in incomplete})

    # 单轮闸可能已把 CEP/工具信号写进 audit.non_llm_signal；合并时并入，避免只看原始日志漏掉链检测
    if any((r.get("audit") or {}).get("non_llm_signal") for r in all_rounds):
        signals = NonLlmSignals(
            sigma_hit=signals.sigma_hit,
            sigma_severity=signals.sigma_severity,
            cep_chain=True,
            anomaly_triggered=signals.anomaly_triggered,
            anomaly_score=signals.anomaly_score,
            type_signal=signals.type_signal,
            ioc_hit=signals.ioc_hit,
            reasons=list(signals.reasons) + ["round_non_llm_signal"],
        )

    threat_rounds = [
        r for r in all_rounds
        if (r.get("audit") or {}).get("threat_detected")
        or (r.get("audit") or {}).get("verdict") == VERDICT_CONFIRMED
    ]
    verdicts = [
        (r.get("audit") or {}).get("verdict")
        or ((r.get("verdict") or {}).get("conclusion") if isinstance(r.get("verdict"), dict) else None)
        for r in all_rounds
    ]
    confirming = len(threat_rounds)

    weights = [0.6, 0.3, 0.1]
    total_weight = 0.0
    weighted_conf = 0.0
    for i, r in enumerate(all_rounds):
        w = weights[i] if i < len(weights) else 0.05
        weighted_conf += float((r.get("audit") or {}).get("confidence") or 0) * w
        total_weight += w
    confidence = weighted_conf / total_weight if total_weight > 0 else 0.0

    needs_human = any(
        (r.get("audit") or {}).get("needs_human_review")
        for r in all_rounds
    )

    seen_descriptions: set[str] = set()
    all_missed: list = []
    for r in all_rounds:
        for mt in r.get("missed_threats") or []:
            if not isinstance(mt, dict):
                continue
            if not missed_threat_is_actionable(mt):
                continue
            desc = mt.get("description", "")
            if desc and desc not in seen_descriptions:
                seen_descriptions.add(desc)
                all_missed.append(mt)

    # 核心：无非 LLM 信号不得 confirmed，即使多轮 LLM 一致
    if confirming >= 1 and signals.has_signal:
        verdict = VERDICT_CONFIRMED
        threat_detected = True
        sev_pool = [
            (r.get("audit") or {}).get("severity", "info")
            for r in threat_rounds
        ]
        severity = max(sev_pool, key=_severity_index) if sev_pool else "info"
    elif confirming >= 1 and not signals.has_signal:
        verdict = VERDICT_SUSPICIOUS
        threat_detected = False
        needs_human = True
        severity = _median_severity([
            (r.get("audit") or {}).get("severity", "info") for r in all_rounds
        ], cap="medium")
    elif VERDICT_SUSPICIOUS in verdicts or any(
        (r.get("audit") or {}).get("verdict") == VERDICT_SUSPICIOUS for r in all_rounds
    ):
        verdict = VERDICT_SUSPICIOUS
        threat_detected = False
        needs_human = True
        severity = _median_severity([
            (r.get("audit") or {}).get("severity", "info") for r in all_rounds
        ], cap="medium")
    else:
        # P1: 无任何轮次声称威胁时，若存在「没跑完」的轮次，
        # verdict 必须是 insufficient_evidence（未完成 ≠ 干净），
        # 而不是 false_positive。
        if incomplete:
            verdict = VERDICT_INSUFFICIENT
            threat_detected = False
            needs_human = True
            severity = _median_severity([
                (r.get("audit") or {}).get("severity", "info") for r in all_rounds
            ], cap="medium")
        else:
            verdict = VERDICT_FALSE_POSITIVE
            threat_detected = False
            severity = _median_severity([
                (r.get("audit") or {}).get("severity", "info") for r in all_rounds
            ], cap="medium")

    return {
        "threat_detected": threat_detected,
        "verdict": verdict,
        "confidence": round(min(confidence, 1.0), 4),
        "severity": severity,
        "needs_human": needs_human,
        "total_rounds": len(all_rounds),
        "all_missed_count": len(all_missed),
        "confirming_rounds": confirming,
        # P1: 终态语义。incomplete_rounds>0 表示本轮审计**未跑完**，
        # verdict=insufficient_evidence 是「没结论」而非「已排除」。
        "incomplete_rounds": len(incomplete),
        "incomplete_reasons": incomplete_reasons,
    }


# ═══════════════════════════════════════════
# P0-8 逐步错误预算 / 早停 / Reviewer 只准降级
# ═══════════════════════════════════════════

@dataclass
class HopStats:
    avg_hallucination_risk: float = 0.0
    evidence_completeness: float = 1.0
    avg_grounding: float = 1.0
    admitted_claims: int = 0
    discarded_claims: int = 0
    # P1-Executor: 真实 hop 账目。修复前本 dataclass 全是质量指标，
    # 一个「调用了几次 LLM」的计数器都没有 —— 「hop 预算」这个概念
    # 在实现上是不存在的，只有质量阈值早停。
    llm_calls_planned: int = 0
    llm_calls_made: int = 0
    llm_calls_skipped: int = 0
    chunks: int = 0

    @property
    def skip_reasoning(self) -> bool:
        return bool(self.skip_reasons)

    @property
    def skip_reasons(self) -> list:
        """三类早停成因分别记账（修复前折叠成一个 bool）。"""
        out = []
        if self.avg_hallucination_risk > HALLUCINATION_EARLY_STOP:
            out.append(HOP_SKIP_HALLUCINATION)
        if self.avg_grounding < GROUNDING_EARLY_STOP:
            out.append(HOP_SKIP_GROUNDING)
        if self.evidence_completeness < COMPLETENESS_EARLY_STOP:
            out.append(HOP_SKIP_COMPLETENESS)
        return out

    @property
    def hop_budget(self) -> int:
        """本轮允许的 LLM 调用上限（用于与 llm_calls_made 对照）。"""
        return max(self.llm_calls_planned, 0)


def hop_stats_from_verdicts(
    verdicts: list,
    *,
    llm_calls_planned: Optional[int] = None,
    llm_calls_made: Optional[int] = None,
) -> HopStats:
    """汇总一轮审计的 hop 账目与质量指标。

    ``llm_calls_*`` 传 None 表示「未给出，按 chunk 数推导」。
    哨兵值必须是 None 而不是 0：``made=0``（预算耗尽、一次都没跑）
    是有意义的取值，用 0 当哨兵会把它和「没传」混为一谈。
    """
    if not verdicts:
        return HopStats(
            llm_calls_planned=int(llm_calls_planned or 0),
            llm_calls_made=int(llm_calls_made or 0),
            chunks=0,
        )

    # P3-2: 质量与预算各自交给独立组件计算，本函数只做组装。
    # 修复前这里是质量指标的唯一实现，而 agent_executor 又另算了一遍同名指标
    # 且算法不同（max(属性, raw 快照) vs 只取属性）—— 两个「平均幻觉风险」
    # 在 raw 快照大于属性时会相差 0.70，靠 sub_auditor 的恢复语句才碰巧相等。
    quality = score_verdicts(verdicts)
    ledger = budget_for(
        len(verdicts), llm_calls_planned=llm_calls_planned,
        llm_calls_made=llm_calls_made,
    )
    return HopStats(
        avg_hallucination_risk=quality.avg_hallucination_risk,
        # 保持修复前的定义：投票层面的通过率（驱动 COMPLETENESS_EARLY_STOP）。
        # 断言层面的支撑率是另一个量，见 QualityScore.claim_support_ratio。
        evidence_completeness=quality.admitted_ratio,
        avg_grounding=quality.avg_grounding,
        admitted_claims=quality.admitted_claims,
        discarded_claims=quality.discarded_claims,
        llm_calls_planned=ledger.llm_calls_planned,
        llm_calls_made=ledger.llm_calls_made,
        # 未跑掉的预算。修复前这个字段只有声明没有赋值 ——
        # 「跳过了几次 hop」同样是不可核的。
        llm_calls_skipped=ledger.llm_calls_skipped,
        chunks=ledger.chunks,
    )


def should_skip_reasoning_hops(stats: HopStats) -> bool:
    return stats.skip_reasoning


def executor_conclusion_floor(
    *,
    threat_detected: bool,
    verdict: str,
    needs_human_review: bool,
) -> str:
    """Executor 结论映射到 Reviewer conclusion 上限。"""
    if verdict == VERDICT_CONFIRMED or (threat_detected and verdict != VERDICT_SUSPICIOUS):
        return CONCLUSION_CONFIRMED
    if verdict == VERDICT_INSUFFICIENT:
        return CONCLUSION_INSUFFICIENT
    if verdict == VERDICT_SUSPICIOUS or needs_human_review:
        return CONCLUSION_SUSPICIOUS
    return CONCLUSION_FALSE_POSITIVE


def clamp_reviewer_conclusion(
    executor_level: str,
    reviewer_conclusion: str,
) -> str:
    """Reviewer 只准降级，禁止升级。"""
    if reviewer_conclusion not in CONCLUSION_RANK:
        reviewer_conclusion = CONCLUSION_SUSPICIOUS
    if executor_level not in CONCLUSION_RANK:
        executor_level = CONCLUSION_SUSPICIOUS
    if CONCLUSION_RANK[reviewer_conclusion] > CONCLUSION_RANK[executor_level]:
        return executor_level
    return reviewer_conclusion


def missed_threat_is_actionable(missed: dict) -> bool:
    """
    复核"新发现"必须自带可核验证据，否则视为幻觉，不触发补审轮。
    """
    if not isinstance(missed, dict):
        return False
    evidence = str(missed.get("evidence") or "")
    evidence_ids = missed.get("evidence_ids") or []
    if evidence_ids:
        return True
    # 证据字段里至少要有一个数字 ID
    return any(part.strip().isdigit() for part in evidence.replace("，", ",").split(","))


def filter_missed_threats(missed: list) -> list:
    return [m for m in (missed or []) if missed_threat_is_actionable(m)]


def should_run_llm_reviewer(depth: str) -> bool:
    """P0-9: 仅 deep 走 LLM 复核；quick/standard 确定性映射，不增加 hop。"""
    return (depth or "") == "deep"


def should_run_deep_llm_hops(depth: str, skip_reasoning: bool) -> bool:
    """deep_analyze / recheck / EvidenceVerifier LLM 仅在 deep 且未早停时运行。"""
    return (depth or "") == "deep" and not skip_reasoning


# ═══════════════════════════════════════════
# P1-C-5: tools-only 确定性收口（不借 LLM，也不自证）
# ═══════════════════════════════════════════
# 修复前 Executor._deterministic_from_non_llm 这样调用：
#     apply_confirmation_gate(llm_threat_detected=threat,
#                             has_admitted_claims=threat, ...)
# `has_admitted_claims` 与 `llm_threat_detected` 同源 → 「有已采纳断言」这道
# confirmed 必要条件被无条件满足，等于自己给自己背书；而该车道根本不产生
# 任何 claim。再叠加 type_signal（由自由文本事件名推断），一条
# event="命令注入" 的日志即可零证据达到 confirmed 且 needs_human_review=False。
#
# 提前收口是一种显式的决策路径，但它必须说明**凭什么**：
#   · 强信号（Sigma / IoC / 异常分 / CEP 工具链）→ 可达 confirmed，但记录依据
#   · 仅弱信号（自由文本事件名、任意非空链文本）→ 最多 suspicious + 强制人审
#   · 无论何种情况都不得声称存在"已采纳断言"

_STRONG_SIGNAL_REASONS = ("sigma:", "ioc", "anomaly:", "cep_tool:")


def _strong_signal_basis(signals: NonLlmSignals) -> list[str]:
    """从 reasons 中筛出**可独立支撑结论**的强信号依据。"""
    basis = []
    for r in signals.reasons or []:
        rs = str(r)
        if rs.startswith("sigma:"):
            basis.append(rs)
        elif rs == "ioc":
            basis.append("ioc_hit")
        elif rs.startswith("anomaly:"):
            basis.append(rs)
        elif rs.startswith("cep_tool:"):
            basis.append(rs)
    return list(dict.fromkeys(basis))


@dataclass
class DeterministicDecision:
    threat_detected: bool
    verdict: str
    confidence: float
    needs_human_review: bool
    evidence_basis: list = field(default_factory=list)
    reason: str = ""


def deterministic_non_llm_verdict(
    signals: Optional[NonLlmSignals] = None,
    *,
    sigma_severity: str = "",
) -> DeterministicDecision:
    """tools-only 车道的确定性收口（无 LLM、无 claim 自证）。

    与 ``apply_confirmation_gate`` 的区别：本函数**不要求也不假装**存在
    已采纳断言，而是显式要求强信号并记录依据，供审计追溯。
    """
    signals = signals or NonLlmSignals()
    basis = _strong_signal_basis(signals)

    if not basis:
        weak = [r for r in (signals.reasons or []) if r]
        return DeterministicDecision(
            threat_detected=False,
            verdict=VERDICT_INSUFFICIENT,
            confidence=0.0,
            needs_human_review=True,
            evidence_basis=[],
            reason=(
                "no_strong_non_llm_signal"
                + (f" (weak_only={weak[:3]})" if weak else "")
            ),
        )

    conf = 0.0
    if signals.sigma_hit:
        conf = max(conf, 0.55)
        if str(sigma_severity or signals.sigma_severity or "").lower() == "critical":
            conf = max(conf, 0.75)
    if signals.anomaly_triggered:
        conf = max(conf, float(signals.anomaly_score or 0.0))
    if signals.ioc_hit:
        conf = max(conf, 0.7)
    if signals.cep_chain and any(b.startswith("cep_tool:") for b in basis):
        conf = max(conf, 0.6)
    if signals.type_signal:
        conf = max(conf, 0.5)

    return DeterministicDecision(
        threat_detected=True,
        verdict=VERDICT_CONFIRMED,
        confidence=round(min(1.0, conf), 4),
        # 强信号可达 confirmed，但仍强制人审复核 —— tools-only 从未做过
        # Grounding 校验（无 claim / 无 evidence_ids），不应自动封禁生产资产。
        needs_human_review=True,
        evidence_basis=basis,
        reason="strong_non_llm_signal",
    )


# ═══════════════════════════════════════════
# P0-C-6 / D-1 / D-3: 统一自动响应闸门
# ═══════════════════════════════════════════
# 修复前两条生产路径各自内联了一份判定条件，且都只看 4 个字段：
#     threat_detected ∧ verdict∈{confirmed,suspicious} ∧ confidence≥0.4 ∧ ¬response_blocked
# 结果是三类"结论不可信"的状态完全不影响是否下发封禁/隔离：
#     · needs_human_review=True（强制人审未完成）   —— 仍照常下发
#     · schema_valid=False（结构校验失败）           —— 仍照常下发
#     · CAD 熔断 tripped（监督判定结论不可信）      —— 仍照常下发
#     · 监督系统自身异常（CAD 抛异常）              —— 仍照常下发
#
# 本函数是**唯一**权威判定点。提前收口是一种显式的决策路径，
# 但不允许等价于绕过安全校验。

# 阻断因子 → 人可读原因。顺序即判定优先级。
_AUTO_RESPONSE_BLOCKERS = (
    "response_blocked",
    "needs_human_review",
    "schema_invalid",
    "cad_circuit_tripped",
    "supervision_failed",
)

_BLOCK_REASON = {
    "response_blocked": "faithfulness / 否决闸阻止自动响应",
    "needs_human_review": "人工复核未完成，禁止自动响应",
    "schema_invalid": "结构化输出校验未通过，禁止自动响应",
    "cad_circuit_tripped": "CAD 独立监督熔断，禁止自动响应",
    "supervision_failed": "独立监督自身异常，无法确认结论可信",
}


@dataclass
class AutoResponseGate:
    allowed: bool
    reason: str
    blocking_factors: list = None

    def __post_init__(self):
        if self.blocking_factors is None:
            self.blocking_factors = []

    @property
    def blocked_by_supervision(self) -> bool:
        return any(
            f in ("cad_circuit_tripped", "supervision_failed")
            for f in self.blocking_factors
        )

    def to_dict(self) -> dict:
        return {
            "allowed": self.allowed,
            "reason": self.reason,
            "blocking_factors": list(self.blocking_factors),
        }


def evaluate_auto_response_gate(
    merged: dict,
    *,
    cad_report: Optional[dict] = None,
    supervision_ok: bool = True,
    supervision_error: str = "",
    min_confidence: float = 0.4,
) -> AutoResponseGate:
    """判定是否允许进入高风险自动响应（封禁 / 隔离）。

    Args:
        merged: 流水线合并后的结论 dict（threat_detected/verdict/confidence/…）
        cad_report: CAD 独立审计报告；None 表示本轮未执行 CAD
        supervision_ok: 独立监督是否成功完成。False 视为「无法确认结论可信」
        supervision_error: 监督异常原因，仅用于日志
        min_confidence: 自动响应置信度下限

    Returns:
        AutoResponseGate
    """
    merged = merged if isinstance(merged, dict) else {}

    # ── 前置：是否构成威胁 ──
    if not merged.get("threat_detected"):
        return AutoResponseGate(False, "非威胁结论，不触发自动响应", [])

    verdict = str(merged.get("verdict") or "")
    if verdict not in ("confirmed", "suspicious"):
        return AutoResponseGate(
            False, f"verdict={verdict or '空'} 不在自动响应范围", []
        )

    try:
        confidence = float(merged.get("confidence", 0) or 0)
    except (TypeError, ValueError):
        confidence = 0.0
    if confidence < min_confidence:
        return AutoResponseGate(
            False, f"置信度 {confidence:.2f} < 阈值 {min_confidence}", []
        )

    # ── 安全阻断因子（任一命中即拒绝）──
    factors: list[str] = []

    if merged.get("response_blocked"):
        factors.append("response_blocked")
    if merged.get("needs_human_review"):
        factors.append("needs_human_review")
    # schema_valid 缺省视为 True（老数据无此字段时不应一律阻断）
    if merged.get("schema_valid") is False:
        factors.append("schema_invalid")

    if cad_report is not None:
        breaker = cad_report.get("circuit_breaker") or {}
        if isinstance(breaker, dict) and breaker.get("tripped"):
            factors.append("cad_circuit_tripped")

    if not supervision_ok:
        factors.append("supervision_failed")

    if factors:
        ordered = [f for f in _AUTO_RESPONSE_BLOCKERS if f in factors]
        reasons = [_BLOCK_REASON[f] for f in ordered]
        if supervision_error:
            reasons.append(f"（{supervision_error[:120]}）")
        return AutoResponseGate(
            False,
            "；".join(reasons),
            ordered,
        )

    return AutoResponseGate(
        True,
        f"verdict={verdict} confidence={confidence:.2f}，通过自动响应闸门",
        [],
    )
