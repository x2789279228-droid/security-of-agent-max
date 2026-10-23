"""
审计主路径忠实度闸 — PR3 / P0-2、P0-5

每次 Audit 合并后、自动响应前：
  1. 词法支撑阈值 0.35
  2. 程序化蕴含：summary 中的 IP/CVE/ATT&CK/端口必须出现在证据里
  3. faithfulness < 0.75 或无支撑断言过多 → 强制人审、禁止 confirmed 自动响应
"""
from __future__ import annotations

import logging
import re
from typing import Optional

from eval_metrics import (
    LEXICAL_SUPPORT_THRESHOLD,
    claim_is_supported,
    context_text,
    extract_grounding_entities,
    lexical_overlap_score,
    split_claims,
)

logger = logging.getLogger(__name__)


FAITHFULNESS_THRESHOLD = 0.75
UNSUPPORTED_RATIO_THRESHOLD = 0.75  # 1 - unsupported/total 须 ≥ 0.75
BENIGN_LLM_FP_SLO = 0.05            # LLM 单独 FP ≤ 5%

# ATT&CK 技术编号：T + 4 位数字。CVE：CVE-YYYY-NNNN+
_IDENT_PATTERNS = (
    re.compile(r"(?<![A-Za-z0-9])T\d{4}(?![0-9])", re.IGNORECASE),
    re.compile(r"(?<![A-Za-z0-9-])CVE-\d{4}-\d{4,}(?![0-9])", re.IGNORECASE),
)


def _identifier_present(entity: str, evidence: str) -> bool:
    """编号型实体是否在可信证据中出现（词边界锚定）。

    裸子串匹配会让 "T10460" 满足 "T1046"、让 "T10711" 满足 "T1071"，
    使编号校验形同虚设。这里要求编号两侧不是字母/数字。
    """
    if not evidence:
        return False
    target = str(entity or "").strip()
    if not target:
        return False
    for pat in _IDENT_PATTERNS:
        for m in pat.finditer(evidence):
            if m.group(0).upper() == target.upper():
                return True
    return False


def _evidence_blob(contexts: list[dict]) -> str:
    return "\n".join(context_text(c) for c in (contexts or []) if c)


def _trusted_evidence_blob(contexts: list[dict]) -> str:
    """P1-C-5: 只取**可信**证据，排除攻击者/厂商可控的自由文本。

    原始事件的 ``message`` 字段完全由数据源与攻击者控制。
    ATT&CK / CVE 这类编号型实体若允许在 message 里匹配，
    攻击者只要在日志正文写上 "T1071" 就能给自己的幻影标签"洗白"。
    因此编号型实体的存在性校验只认结构化证据：
    evidence_trail 的字段引用（已过 GroundingVerifier 逐字校验）与工具输出。
    """
    parts = []
    for c in (contexts or []):
        if not c:
            continue
        if isinstance(c, dict) and c.get("trusted") is False:
            continue
        parts.append(context_text(c))
    return "\n".join(p for p in parts if p)


def _classify_claim_failure(claim: str, evidence: str, entities_in_claim: list) -> str:
    """把一条失败的断言归入**三类互斥**的失败原因（P2-C-3）。

    修复前三类完全不同的质量问题被压成一个 ``unsupported_count``：

      1. ``invalid_reference``  —— 断言引用了一个**具体但错误**的编号
         （T1071 / CVE-…），证据里根本没有。这是编造实体，最严重。
      2. ``unsupported_claim`` —— 断言里没有编号型实体，但整句在证据里
         找不到任何支撑。这是无证据主张。
      3. ``wrong_conclusion``   —— 断言的**可验证部分**（编号、IP、端口）
         都在证据里，但它表达的**结论方向**与证据相反。
         例如证据是 "connection refused"（连接被拒），
         断言却写 "连接成功建立"。编号校验发现不了这种错误 ——
         它正是「引用全部有效、结论却错」的那一类。

    拆开的意义：一个笼统的 0.4 既可能是"编造了 ATT&CK 编号"，
    也可能是"措辞不准"，两者的处置完全不同（前者要追溯模型/数据源，
    后者多半只是阈值偏紧）。合成一个数字就无法分别告警。
    """
    text = str(claim or "").lower()
    ev = str(evidence or "").lower()

    # ── 1) 编造实体：断言里出现编号/IP/端口，但证据里没有 ──
    if entities_in_claim:
        for e in entities_in_claim:
            es = str(e).lower()
            if es.startswith("port:"):
                probe = es.split(":", 1)[1]
            else:
                probe = es
            if probe and probe not in ev:
                return "invalid_reference"

    # ── 3) 结论方向相反：可验证片段都在，但断言给出相反判断 ──
    # 只在双方都出现了明确的肯定/否定标记时才判，否则不做武断推断。
    positive = ("成功", "已建立", "succeeded", "established", "accepted",
                "allowed", "completed")
    negative = ("失败", "被拒", "拒绝", "failed", "refused", "rejected",
                "denied", "blocked", "timeout")
    has_pos = any(p in text for p in positive)
    has_neg = any(n in text for n in negative)
    if has_pos != has_neg:
        # 断言方向与证据方向相反 → 结论错误
        ev_pos = any(p in ev for p in positive)
        ev_neg = any(n in ev for n in negative)
        if (ev_pos or ev_neg) and ev_pos != has_pos:
            return "wrong_conclusion"

    # ── 2) 其余：整句无任何支撑 ──
    return "unsupported_claim"


def compute_faithfulness(
    answer: str,
    contexts: list[dict],
    query: str = "",
    trusted_evidence: str = "",
) -> dict:
    """同步忠实度计算，不落库、不调 LLM。

    Args:
        trusted_evidence: 用于校验**编号型实体**（ATT&CK / CVE）的可信证据。
            缺省时退化为全部证据（保持既有调用行为）。

    P2-C-3: 额外返回 ``failure_breakdown``，把三类失败分开计数：
        invalid_reference（编造实体）/ unsupported_claim（无证据主张）/
        wrong_conclusion（引用有效但结论相反）。原有的
        unsupported_count 保持不变，向后兼容。
    """
    evidence = _evidence_blob(contexts)
    trusted = trusted_evidence or evidence
    claims = split_claims(answer)
    if not claims:
        # 无可检验断言：视为通过（没有胡编的句子）
        return {
            "claim_count": 0,
            "supported_count": 0,
            "unsupported_count": 0,
            "faithfulness": 1.0,
            "unsupported_claim_ratio_score": 1.0,
            "entity_entailment": 1.0,
            "entity_count": 0,
            "phantom_entities": [],
            "support_scores": [],
            # P2-C-3: 与有断言分支保持同一契约
            "invalid_reference_count": 0,
            "unsupported_claim_count": 0,
            "wrong_conclusion_count": 0,
            "failure_breakdown": {
                "invalid_reference": 0,
                "unsupported_claim": 0,
                "wrong_conclusion": 0,
            },
            "failure_examples": {
                "invalid_reference": [],
                "unsupported_claim": [],
                "wrong_conclusion": [],
            },
            "passed": True,
            "reasons": [],
        }

    support_scores = [
        lexical_overlap_score(c, evidence) if evidence else 0.0 for c in claims
    ]
    supported_flags = [claim_is_supported(c, evidence) for c in claims]
    supported_count = sum(1 for f in supported_flags if f)
    unsupported_count = len(claims) - supported_count
    faithfulness = round(supported_count / len(claims), 4)
    unsupported_score = round(1 - (unsupported_count / len(claims)), 4)

    # P2-C-3: 三类失败分开计数（互斥）
    failure_breakdown = {
        "invalid_reference": 0,
        "unsupported_claim": 0,
        "wrong_conclusion": 0,
    }
    failure_examples = {"invalid_reference": [], "unsupported_claim": [],
                        "wrong_conclusion": []}

    all_ents = set()
    phantom = []
    for idx, c in enumerate(claims):
        ents = extract_grounding_entities(c)
        all_ents |= ents
        if not supported_flags[idx]:
            kind = _classify_claim_failure(c, evidence, list(ents))
            failure_breakdown[kind] += 1
            if len(failure_examples[kind]) < 3:
                failure_examples[kind].append(str(c)[:120])
        for e in ents:
            probe = e.split(":", 1)[1] if e.startswith("port:") else e
            if e.startswith("port:"):
                if probe not in evidence:
                    phantom.append(e)
            elif e.startswith("CVE-") or (e.startswith("T") and len(e) >= 5):
                # P1-C-5: 编号型实体只在**可信证据**里找，且用词边界锚定。
                # 修复前 (a) 直接在含 message 的全文里做裸子串匹配 ——
                #            攻击者在日志正文写 "T1071" 即可让幻影标签通过；
                #          (b) 无边界锚定 —— 证据含 "T10460" 会让 "T1046" 误命中。
                if not _identifier_present(e, trusted):
                    phantom.append(e)
            else:
                if e not in evidence.lower():
                    phantom.append(e)
    entity_entailment = 0.0 if phantom else 1.0

    reasons = []
    passed = True
    if faithfulness < FAITHFULNESS_THRESHOLD:
        passed = False
        reasons.append(f"faithfulness={faithfulness:.2f}<{FAITHFULNESS_THRESHOLD}")
    if unsupported_score < UNSUPPORTED_RATIO_THRESHOLD:
        passed = False
        reasons.append(f"unsupported_ratio_score={unsupported_score:.2f}")
    if phantom:
        passed = False
        reasons.append(f"phantom_entities={phantom[:8]}")

    return {
        "claim_count": len(claims),
        "supported_count": supported_count,
        "unsupported_count": unsupported_count,
        "faithfulness": faithfulness,
        "unsupported_claim_ratio_score": unsupported_score,
        "entity_entailment": entity_entailment,
        "entity_count": len(all_ents),
        "phantom_entities": phantom[:12],
        "support_scores": [round(s, 4) for s in support_scores],
        # P2-C-3: 三类失败口径（新增，不改既有字段语义）
        "invalid_reference_count": failure_breakdown["invalid_reference"],
        "unsupported_claim_count": failure_breakdown["unsupported_claim"],
        "wrong_conclusion_count": failure_breakdown["wrong_conclusion"],
        "failure_breakdown": failure_breakdown,
        "failure_examples": failure_examples,
        "passed": passed,
        "reasons": reasons,
        "lexical_threshold": LEXICAL_SUPPORT_THRESHOLD,
    }


def has_non_llm_threat_signal(signals: Optional[dict] = None) -> bool:
    """Sigma / 异常 / 显式 admitted 等非 LLM 背书信号。"""
    if not signals:
        return False
    if signals.get("sigma_detected") or signals.get("detected"):
        return True
    if signals.get("has_admitted_claims") or signals.get("confirmation_admitted"):
        return True
    try:
        if float(signals.get("anomaly_score") or 0) >= 0.6:
            return True
    except (TypeError, ValueError):
        pass
    hits = signals.get("hits") or signals.get("sigma_hits") or []
    return bool(hits)


def apply_faithfulness_gate(
    merged: dict,
    *,
    answer: str,
    contexts: list[dict],
    query: str = "",
    abstain: bool = False,
    non_llm_signals: Optional[dict] = None,
) -> dict:
    """
    就地/返回更新 merged：
      闸失败或 abstain：
        - 无非 LLM 信号 → 硬降级（threat=False，禁自动响应，人审）
        - 有非 LLM 信号 → 软降级（保留 threat，verdict≤suspicious，强制人审）
    """
    out = dict(merged or {})
    trusted_blob = _trusted_evidence_blob(contexts or [])
    report = compute_faithfulness(
        answer or "", contexts or [], query=query, trusted_evidence=trusted_blob
    )
    out["faithfulness"] = report

    blocked = (not report["passed"]) or bool(abstain)
    if abstain:
        report["reasons"] = list(report["reasons"]) + ["llm_abstain"]
        report["passed"] = False
        out["faithfulness"] = report

    if blocked:
        out["needs_human"] = True
        backed = has_non_llm_threat_signal(non_llm_signals)
        if backed and (out.get("verdict") == "confirmed" or out.get("threat_detected")):
            # 规则/异常已背书：保留威胁事实，仅取消 confirmed 自动信任
            out["verdict"] = "suspicious"
            out["threat_detected"] = True
            out["response_blocked"] = False
            out["demoted_by"] = "faithfulness_gate_soft"
            report["reasons"] = list(report.get("reasons") or []) + ["soft_demote_non_llm_signal"]
            out["faithfulness"] = report
        else:
            out["response_blocked"] = True
            if out.get("verdict") == "confirmed" or out.get("threat_detected"):
                out["verdict"] = "suspicious"
                out["threat_detected"] = False
                out["demoted_by"] = "faithfulness_gate"
            if abstain and out.get("verdict") not in ("false_positive",):
                # 弃权优先于 suspicious：证据不足（仅硬降级路径）
                if not out.get("threat_detected"):
                    out["verdict"] = "insufficient_evidence"
    else:
        out.setdefault("response_blocked", False)

    # P1-C-5: 程序化收口（严重度封顶 + ATT&CK 幻觉剥离）是**安全校验**，
    # 失败必须关闭而不是放行。
    # 修复前这里是 `except Exception: pass` —— sanitize_merged_audit 一旦抛错
    # （merged 含非 dict 的 severity、phantom_entities 非 list 等），
    # 严重度封顶被整体跳过且无日志无告警，下游照常按未封顶的严重度响应。
    try:
        from veto_gates import sanitize_merged_audit
        signals = non_llm_signals or {}
        out = sanitize_merged_audit(
            out,
            evidence=_evidence_blob(contexts or []),
            trusted_evidence=_trusted_evidence_blob(contexts or []),
            event_type=str(signals.get("event_type") or ""),
            event_severity=str(signals.get("event_severity") or ""),
            sigma_severity=str(signals.get("sigma_severity") or ""),
            has_chain=bool(signals.get("cep_chain") or signals.get("chain")),
        )
    except Exception as sanitize_err:
        # 失败关闭：降级严重度 + 阻断自动响应 + 强制人审，并留下可追溯原因。
        logger.error(
            "P1-C-5 sanitize_merged_audit failed, fail-closed: %s", sanitize_err,
            exc_info=True,
        )
        out["needs_human"] = True
        out["response_blocked"] = True
        out["sanitize_failed"] = str(sanitize_err)[:200]
        out["demoted_by"] = "sanitize_merged_audit_fail_closed"
        try:
            from veto_gates import _severity_index
            cur = out.get("severity") or "info"
            if _severity_index(cur) > _severity_index("medium"):
                out["severity"] = "medium"
        except Exception:
            out["severity"] = "info"
        if out.get("threat_detected") or out.get("verdict") == "confirmed":
            out["verdict"] = "suspicious"
            out["threat_detected"] = False
        out.setdefault("faithfulness", {})
        if isinstance(out["faithfulness"], dict):
            out["faithfulness"]["reasons"] = list(
                out["faithfulness"].get("reasons") or []
            ) + [f"sanitize_failed:{str(sanitize_err)[:80]}"]
            out["faithfulness"]["passed"] = False

    return out


def contexts_from_audit(
    log_data: Optional[dict] = None,
    evidence_trail: Optional[list] = None,
    tool_preview: str = "",
) -> list[dict]:
    """把原始事件 + 证据链拼成 faithfulness 的 contexts。

    P1-C-5: 标注 ``trusted``。原始事件上下文含自由文本 ``message``，
    对 ATT&CK / CVE 这类编号型实体**不可信**（数据源与攻击者可控），
    因此标 trusted=False；结构化证据（字段引用 + 工具输出）标 trusted=True。
    该标注只影响编号型实体校验，不影响词法忠实度打分。
    """
    ctx: list[dict] = []
    event = log_data or {}
    bits = [
        str(event.get("event") or event.get("type") or ""),
        str(event.get("src_ip") or ""),
        str(event.get("dst_ip") or ""),
        str(event.get("message") or ""),
        str(event.get("severity") or ""),
        str(event.get("protocol") or ""),
    ]
    # 含 message → 编号型实体不可信
    ctx.append({"content": " ".join(b for b in bits if b), "trusted": False})
    for item in evidence_trail or []:
        if not isinstance(item, dict):
            continue
        quotes = item.get("evidence_quotes") or []
        ctx.append({
            "content": " ".join([
                str(item.get("claim") or ""),
                str(item.get("type") or ""),
                " ".join(str(q) for q in quotes),
                " ".join(str(i) for i in (item.get("evidence_ids") or [])),
            ]),
            # 字段引用已过 GroundingVerifier 逐字溯源校验
            "trusted": True,
        })
    if tool_preview:
        ctx.append({"content": tool_preview[:4000], "trusted": True})
    return ctx


def llm_alone_false_positive_rate(decisions: list[dict]) -> float:
    """
    良性样本上，LLM 单独把事件判成 confirmed 的比例。
    SLO: ≤ BENIGN_LLM_FP_SLO (5%)。
    """
    if not decisions:
        return 0.0
    fp = sum(1 for d in decisions if d.get("verdict") == "confirmed" or d.get("threat_detected"))
    return fp / len(decisions)
