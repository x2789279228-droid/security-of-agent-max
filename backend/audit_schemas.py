"""
结构化输出验证 — 用 Pydantic 模型强制校验 LLM 输出

解决问题：
  当前所有 LLM 输出解析都是 json.loads + try/except，
  格式错误时静默降级，无法发现 LLM 的结构性幻觉。

三层验证：
  1. JSON 可解析性（json.loads）
  2. 结构完整性（Pydantic 模型验证）
  3. 语义一致性（字段值域检查）

用法：
    from audit_schemas import validate_sub_auditor_output
    result, errors = validate_sub_auditor_output(llm_raw_text)
    if errors:
        # 重试或降级
"""
import json
import logging
import re
from typing import Optional

from pydantic import BaseModel, Field, field_validator

logger = logging.getLogger(__name__)

VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
VALID_THREAT_TYPES = {
    "C2", "DDoS", "数据外泄", "横向移动", "勒索软件",
    "端口扫描", "暴力破解", "SQL注入", "XSS", "恶意软件",
    "权限提升", "未授权访问", "其他", "混合",
}
VALID_CONCLUSIONS = {
    "threat_confirmed", "false_positive", "suspicious", "insufficient_evidence",
}


# ═══════════════════════════════════════════
# SubAuditor 输出模型
# ═══════════════════════════════════════════

class ThreatClaimSchema(BaseModel):
    """单条威胁断言 — 强制 Grounding 字段"""
    type: str = Field(..., description="威胁类型")
    confidence: float = Field(..., ge=0.0, le=1.0)
    evidence_ids: list[int] = Field(..., description="支撑该断言的事件 ID 列表")
    evidence_quotes: list[str] = Field(
        default_factory=list,
        description="从原始事件中引用的具体字段值（如 message 片段、IP 地址）",
    )
    severity: str = Field(..., description="严重度")
    summary: str = Field(..., description="断言描述")

    @field_validator("severity")
    @classmethod
    def check_severity(cls, v: str) -> str:
        v = v.lower().strip()
        if v not in VALID_SEVERITIES:
            raise ValueError(f"无效 severity: {v}，必须是 {VALID_SEVERITIES}")
        return v

    @field_validator("evidence_ids", mode="before")
    @classmethod
    def coerce_evidence_ids(cls, v):
        """兼容 LLM 返回 '#552' / '552' 字符串 ID。"""
        if v is None:
            return []
        if not isinstance(v, list):
            v = [v]
        out = []
        for item in v:
            if isinstance(item, int):
                out.append(item)
                continue
            s = str(item).strip().lstrip("#")
            if s.isdigit():
                out.append(int(s))
        return out

    @field_validator("evidence_ids")
    @classmethod
    def check_evidence_ids(cls, v: list[int]) -> list[int]:
        if not v:
            raise ValueError("evidence_ids 不能为空 — 每条断言必须有证据")
        return v


class SubAuditorOutputSchema(BaseModel):
    """SubAuditor LLM 输出的结构化验证"""
    threat_detected: bool
    threat_claims: list[ThreatClaimSchema] = Field(default_factory=list)
    confidence: float = Field(..., ge=0.0, le=1.0)
    severity: str
    summary: str
    suspicious_entities: list[str] = Field(default_factory=list)
    alert: str = ""

    @field_validator("severity")
    @classmethod
    def check_severity(cls, v: str) -> str:
        return v.lower().strip()

    # 注：原先 threat_detected=True 且 threat_claims=[] 时强制 raise，
    # 反幻觉设计意图正确，但实践会逼迫 LLM 为通过 schema 而捏造 claim
    # （伪造 evidence_ids 与 evidence_quotes），反而破坏 GroundingVerifier 的输入。
    # 改为允许通过 — 上层 sub_auditor.audit 通过 hallucination_risk 阈值机制
    # 对"疑似威胁但无证据"语义进行软惩罚，避免诱发 LLM 幻觉。


# ═══════════════════════════════════════════
# Executor 汇总输出模型
# ═══════════════════════════════════════════

class SynthesisOutputSchema(BaseModel):
    """Executor 汇总结论的结构化验证"""
    threat_detected: bool
    threat_type: str = ""
    confidence: float = Field(..., ge=0.0, le=1.0)
    severity: str
    summary: str
    affected_entities: dict = Field(default_factory=dict)
    suggested_actions: list[str] = Field(default_factory=list)
    needs_human_review: bool = False
    evidence_summary: str = ""
    abstain: bool = False

    @field_validator("evidence_summary", mode="before")
    @classmethod
    def coerce_evidence_summary(cls, v):
        """LLM 偶发返回 list（事件 id 列表），归一为字符串。"""
        if v is None:
            return ""
        if isinstance(v, list):
            return ", ".join(str(x) for x in v)
        return str(v)

    @field_validator("severity")
    @classmethod
    def check_severity(cls, v: str) -> str:
        v = v.lower().strip()
        if v not in VALID_SEVERITIES:
            raise ValueError(f"无效 severity: {v}")
        return v


# ═══════════════════════════════════════════
# Reviewer 输出模型
# ═══════════════════════════════════════════

class HallucinationCheckSchema(BaseModel):
    """Reviewer 的幻觉检查结果"""
    has_unsubstantiated_claims: bool = False
    unsubstantiated_details: list[str] = Field(default_factory=list)
    data_consistency: str = "consistent"
    confidence_overinflation: bool = False


class ReviewerOutputSchema(BaseModel):
    """Reviewer LLM 输出的结构化验证"""
    conclusion: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    hallucination_check: HallucinationCheckSchema = Field(
        default_factory=HallucinationCheckSchema
    )
    missed_threats: list[dict] = Field(default_factory=list)
    evidence_chain: list[str] = Field(default_factory=list)
    human_intervention: bool = False
    final_summary: str = ""
    reviewer_notes: str = ""
    abstain: bool = False

    @field_validator("conclusion")
    @classmethod
    def check_conclusion(cls, v: str) -> str:
        v = v.strip()
        if v not in VALID_CONCLUSIONS:
            raise ValueError(f"无效 conclusion: {v}，必须是 {VALID_CONCLUSIONS}")
        return v


# ═══════════════════════════════════════════
# 值域强制收敛（P0-E-4）
# ═══════════════════════════════════════════
# 修复前: Pydantic 校验失败时 `return parsed, errors` 把**未校验的原始 dict**
#         交回调用方，而调用方只判 `parsed is None`。
#         → severity 枚举拦截只产生一条 warning，非法值原样写入 AuditResult.severity。
#
# 修复后: 校验失败仍返回可用结构，但所有越界值被强制收敛到合法域（fail-closed），
#         且 errors 非空 → 调用方必须把该结论标记为 schema_valid=False 并强制人工复核。
#
# P3 补: 上述收敛原先只覆盖 _sanitize_synthesis / _sanitize_reviewer，
#        **漏了 SubAuditor**。于是 `return parsed, errors` 在这条路径上原样放行，
#        ThreatClaimSchema.check_evidence_ids 的「每条断言必须有证据」只产生一条
#        warning —— 零证据断言照样进入 verify_chunk。配合 GroundingVerifier 的空真
#        评分（五个维度记满分 → 0.9000 = grounded），这条断言最终以
#        severity=critical 进入投票集。详见 _sanitize_sub_auditor。

def _safe_severity(value, fallback: str = "info") -> str:
    """把任意 severity 收敛到 VALID_SEVERITIES；非法值一律降级为 info。"""
    s = str(value or "").lower().strip()
    return s if s in VALID_SEVERITIES else fallback


def _safe_float(value, lo: float = 0.0, hi: float = 1.0, fallback: float = 0.0) -> float:
    try:
        f = float(value)
    except (TypeError, ValueError):
        return fallback
    if f != f or f in (float("inf"), float("-inf")):  # NaN / inf
        return fallback
    return max(lo, min(hi, f))


def _sanitize_synthesis(parsed: dict) -> dict:
    """把 LLM 汇总输出强制收敛到合法域（不新增/不删除业务字段）。"""
    out = dict(parsed)
    out["severity"] = _safe_severity(out.get("severity"))
    out["confidence"] = _safe_float(out.get("confidence"))
    out["threat_detected"] = bool(out.get("threat_detected", False))
    out["abstain"] = bool(out.get("abstain", False))
    out["needs_human_review"] = bool(out.get("needs_human_review", False))
    for key in ("threat_type", "summary", "evidence_summary"):
        if not isinstance(out.get(key), str):
            out[key] = "" if out.get(key) is None else str(out[key])
    for key in ("affected_entities",):
        if not isinstance(out.get(key), dict):
            out[key] = {}
    for key in ("suggested_actions",):
        if not isinstance(out.get(key), list):
            out[key] = []
    return out


def _sanitize_reviewer(parsed: dict) -> dict:
    """把 Reviewer 输出强制收敛到合法域。"""
    out = dict(parsed)
    concl = str(out.get("conclusion") or "").strip()
    out["conclusion"] = concl if concl in VALID_CONCLUSIONS else "suspicious"
    out["confidence"] = _safe_float(out.get("confidence"))
    for key in ("human_intervention", "abstain"):
        out[key] = bool(out.get(key, False))
    for key in ("missed_threats", "evidence_chain"):
        if not isinstance(out.get(key), list):
            out[key] = []
    for key in ("final_summary", "reviewer_notes"):
        if not isinstance(out.get(key), str):
            out[key] = "" if out.get(key) is None else str(out[key])
    return out


def _sanitize_claim(claim: dict) -> dict | None:
    """收敛单条 threat_claim；证据缺失无法修复时返回 None（整条丢弃）。

    与顶层字段的差别：severity / confidence / 引文这些越界值都可以**修**，
    但 `evidence_ids 为空` 修不了 —— 凭空补一个 ID 就是伪造证据。
    所以这里对它是 fail-closed：宁可丢掉整条断言，也不能让一条无证据断言
    以合法形状继续往下走。
    """
    out = dict(claim)
    out["severity"] = _safe_severity(out.get("severity"))
    out["confidence"] = _safe_float(out.get("confidence"))
    for key in ("type", "summary"):
        if not isinstance(out.get(key), str):
            out[key] = "" if out.get(key) is None else str(out[key])
    quotes = out.get("evidence_quotes")
    out["evidence_quotes"] = [str(q) for q in quotes] if isinstance(quotes, list) else []

    # 与 ThreatClaimSchema.coerce_evidence_ids 同一套规则（'#552' / '552' 兼容），
    # 区别只在于这里不抛错，空列表直接判定为不可修复。
    ids = out.get("evidence_ids")
    if not isinstance(ids, list):
        ids = [ids] if ids is not None else []
    coerced: list[int] = []
    for item in ids:
        if isinstance(item, int):
            coerced.append(item)
            continue
        s = str(item).strip().lstrip("#")
        if s.isdigit():
            coerced.append(int(s))
    if not coerced:
        return None
    out["evidence_ids"] = coerced
    return out


def _sanitize_sub_auditor(parsed: dict) -> dict:
    """把 SubAuditor 输出强制收敛到合法域。

    claim 是**列表**，因此除了逐条收敛，还要处理「有的能留、有的留不下」：
    这里只丢弃证据为空的那几条，其余照常返回 ——
    丢掉全部 claim 时 threat_detected 由调用方的 `and len(claims) > 0` 收敛为 False。
    """
    out = dict(parsed)
    out["severity"] = _safe_severity(out.get("severity"))
    out["confidence"] = _safe_float(out.get("confidence"))
    out["threat_detected"] = bool(out.get("threat_detected", False))
    for key in ("summary", "alert"):
        if not isinstance(out.get(key), str):
            out[key] = "" if out.get(key) is None else str(out[key])
    if not isinstance(out.get("suspicious_entities"), list):
        out["suspicious_entities"] = []

    kept: list[dict] = []
    for claim in (out.get("threat_claims") or []):
        if isinstance(claim, dict):
            sanitized = _sanitize_claim(claim)
            if sanitized is not None:
                kept.append(sanitized)
    out["threat_claims"] = kept
    return out


# ═══════════════════════════════════════════
# 验证函数（带 JSON 提取 + 重试逻辑）
# ═══════════════════════════════════════════
def extract_json(text: str) -> Optional[dict]:
    """
    从 LLM 输出中提取 JSON

    处理常见情况：
    - 纯 JSON
    - ```json ... ``` 代码块
    - JSON 前后有解释文字
    - 单引号 / 尾逗号 / 未加引号键（通过 stabilizer.json_repair 兜底）
    """
    text = text.strip()

    # 尝试直接解析
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # 尝试提取 ```json ... ``` 代码块
    match = re.search(r"```(?:json)?\s*\n?(.*?)\n?\s*```", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1).strip())
        except json.JSONDecodeError:
            pass

    # 尝试找到第一个 { 和最后一个 }
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1 and end > start:
        try:
            return json.loads(text[start:end + 1])
        except json.JSONDecodeError:
            pass

    # 兜底: 使用 stabilizer 的 JsonRepair 修复畸形 JSON
    try:
        from stabilizer.json_repair import JsonRepair
        repaired, _ = JsonRepair().repair(text)
        if repaired is not None:
            return repaired
    except Exception:
        pass

    return None


def validate_sub_auditor_output(raw_text: str) -> tuple[Optional[dict], list[str]]:
    """
    验证 SubAuditor 的 LLM 输出

    Returns:
        (parsed_dict, errors) — errors 为空表示验证通过
    """
    errors = []

    parsed = extract_json(raw_text)
    if parsed is None:
        return None, ["JSON 解析失败：无法从 LLM 输出中提取有效 JSON"]

    try:
        model = SubAuditorOutputSchema(**parsed)
        return model.model_dump(), []
    except Exception as e:
        errors.append(f"结构验证失败: {e}")
        if not isinstance(parsed, dict):
            return None, errors
        # fail-closed：返回**收敛后**的结构，零证据断言在此被丢弃。
        # 修复前直接 return parsed（原样未校验 dict），于是 schema 层的拒绝
        # 只剩一条 warning，断言照常进入 verify_chunk。
        return _sanitize_sub_auditor(parsed), errors


def validate_synthesis_output(raw_text: str) -> tuple[Optional[dict], list[str]]:
    """验证 Executor 汇总输出"""
    errors = []

    parsed = extract_json(raw_text)
    if parsed is None:
        return None, ["JSON 解析失败"]

    try:
        model = SynthesisOutputSchema(**parsed)
        return model.model_dump(), []
    except Exception as e:
        errors.append(f"结构验证失败: {e}")
        if not isinstance(parsed, dict):
            return None, errors
        # fail-closed：返回收敛后的结构，越界值不会流入下游；
        # errors 非空 → 调用方须标记 schema_valid=False 并强制人工复核。
        return _sanitize_synthesis(parsed), errors


def validate_reviewer_output(raw_text: str) -> tuple[Optional[dict], list[str]]:
    """验证 Reviewer 输出"""
    errors = []

    parsed = extract_json(raw_text)
    if parsed is None:
        return None, ["JSON 解析失败"]

    try:
        model = ReviewerOutputSchema(**parsed)
        return model.model_dump(), []
    except Exception as e:
        errors.append(f"结构验证失败: {e}")
        if not isinstance(parsed, dict):
            return None, errors
        # fail-closed：非法 conclusion 收敛为 suspicious（不放行任意值）
        return _sanitize_reviewer(parsed), errors
