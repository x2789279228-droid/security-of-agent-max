"""
审计角色 (CAD) — 独立、穿透、免疫

三大职责（不生产任何审核内容，只监督和验证）:

1. 穿透式验证 (Verify)
   - 不信任其他 Agent 的"汇报"
   - 直接查询 EventStore、Timeline、执行日志等底层数据
   - 比对 Agent 断言与原始数据是否一致

2. 上下文审计 (AuditCtx)
   - 审查系统指令是否存在模糊/矛盾/易被利用的漏洞
   - 审查工具描述是否准确
   - 审查检索文档是否有盲区

3. 免疫与熔断 (Circuit)
   - 常态化监控风险趋势
   - 设定阈值，超限自动熔断
   - 熔断后限制风险扩散
"""
import logging
import os
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from event_store import event_store

logger = logging.getLogger(__name__)


# ════════════════════════════════════════════
# 1. 穿透式验证器 (Penetrating Verifier)
# ════════════════════════════════════════════

@dataclass
class VerificationReport:
    """单条验证结果"""
    claim: str                           # Agent 的断言原文
    claim_source: str                    # 哪个 Agent 输出的
    claimed_evidence_ids: list[int]      # Agent 声称的证据 ID
    actual_evidence_ids: list[int]       # 实际查询到的证据 ID
    verified: bool                       # 是否验证通过（真实存在/一致）
    discrepancy: str = ""                # 差异描述
    severity: str = "info"               # 差异严重度
    # 不可穿透验证标记: 断言未附带任何可查证据 ID，本身无法穿透核验。
    # 这不是"查无此 ID 的幻觉"，而是"数据源无可拆分证据(如单源告警)"，
    # 不应计入 hallucination/证据缺失而累积熔断。
    unverifiable: bool = False
    # P1-D-4: 引用原文核验结果。修复前 CAD 只做「ID 是否存在」检查，
    # evidence_quotes 字段从未被读取 —— 声称引用一段真实事件里
    # 根本不存在的话，也能拿到 verified=True。
    quote_checked: int = 0
    quote_grounded: int = 0
    ungrounded_quotes: list = field(default_factory=list)


def _norm(text: str) -> str:
    """归一化：转小写 + 连续空白压缩为单空格 + 去首尾。"""
    import re as _re
    return _re.sub(r"\s+", " ", str(text or "").lower()).strip()


# CAD 独立核验时比对的字段。与 grounding_verifier._EVENT_STRING_FIELDS
# 保持一致，但**不依赖它** —— CAD 必须是独立监督者，
# 复用被监督方的实现会让两边一起错。
_CAD_QUOTE_FIELDS = (
    "message", "src_ip", "dst_ip", "event_type", "severity", "protocol",
)


def _event_text_blob(evt) -> str:
    """把事件的所有可核验文本字段拼成一个搜索语料。"""
    parts = []
    getter = (lambda k: evt.get(k)) if isinstance(evt, dict) else (lambda k: getattr(evt, k, None))
    for name in _CAD_QUOTE_FIELDS:
        v = getter(name)
        if v is not None:
            parts.append(str(v))
    raw = getter("raw_data")
    if isinstance(raw, dict):
        for k, v in list(raw.items())[:50]:
            if isinstance(v, str):
                parts.append(v)
            elif isinstance(v, (int, float)):
                parts.append(str(v))
    return "  ".join(parts)


class PenetratingVerifier:
    """
    穿透式验证器

    不信任任何 Agent 的中间结论，直接从底层数据源验证。
    """

    async def verify_claims(
        self,
        session: AsyncSession,
        session_id: str,
        evidence_trail: list[dict],
    ) -> list[VerificationReport]:
        """
        逐条验证 evidence_trail 中的断言

        验证步骤:
        1. 获取 Agent 声称的 evidence_ids
        2. 直接从 EventStore 查询这些 ID 的原始数据
        3. 比对：声称的事件是否真实存在？内容是否一致？
        4. 输出差异报告
        """
        reports = []

        for item in evidence_trail:
            claim_text = item.get("claim", "")
            claimed_ids = item.get("evidence_ids", [])
            item.get("type", "unknown")
            claim_source = item.get("source", "executor")

            if not claimed_ids:
                # 无可查证据 ID: 视为“不可穿透验证 (unverifiable)”而非幻觉。
                # 差异类型（单源告警/孤立日志没有可分解子证据）并非 Agent 发明证据。
                reports.append(VerificationReport(
                    claim=claim_text,
                    claim_source=claim_source,
                    claimed_evidence_ids=[],
                    actual_evidence_ids=[],
                    verified=False,
                    unverifiable=True,
                    discrepancy="断言未附带任何证据 ID — 无证据可穿透验证(unverifiable)，不计幻觉",
                    severity="low",
                ))
                continue

            # 穿透：直接查 EventStore
            actual_events = []
            for eid in claimed_ids:
                evt = await event_store.get_by_id(session, eid)
                if evt:
                    actual_events.append(evt)

            actual_ids = [e.id for e in actual_events]

            # 比对
            claimed_set = set(claimed_ids)
            actual_set = set(actual_ids)

            missing = claimed_set - actual_set          # Agent 声称但实际不存在

            # ── P1-D-4: 真正独立的核验是**引用原文是否真实存在** ──
            # 修复前这里还有一个 extra = actual_set - claimed_set，
            # 而 actual_ids 完全来自对 claimed_ids 的逐个查询，
            # 于是 actual_set ⊆ claimed_set，extra **恒为空集** ——
            # 一段永远不触发的死代码，看起来像「还检查了未引用的证据」。
            # 真正没做、且有安全意义的是：拿 evidence_quotes 去比对
            # 事件的真实字段。声称引用「failed password for root」，
            # 而事件里根本没有这句话 → 这是伪造引用，不是「ID 存在」。
            quotes = item.get("evidence_quotes") or []
            checked = 0
            grounded = 0
            ungrounded: list = []
            if quotes and actual_events:
                corpus = _norm("  ".join(_event_text_blob(e) for e in actual_events))
                for q in quotes:
                    checked += 1
                    qn = _norm(q)
                    if qn and qn in corpus:
                        grounded += 1
                    else:
                        ungrounded.append(str(q)[:120])
            elif quotes and not actual_events:
                # 声称有引用原文，但一个事件都没查到 → 全部无溯源
                checked = len(quotes)
                ungrounded = [str(q)[:120] for q in quotes]

            # 引用全伪造 → 断言失实（严重），与「查无此 ID」同级
            quotes_fully_fabricated = bool(ungrounded) and grounded == 0

            if not missing and not quotes_fully_fabricated and not ungrounded:
                reports.append(VerificationReport(
                    claim=claim_text,
                    claim_source=claim_source,
                    claimed_evidence_ids=claimed_ids,
                    actual_evidence_ids=actual_ids,
                    verified=True,
                    quote_checked=checked,
                    quote_grounded=grounded,
                    ungrounded_quotes=ungrounded,
                ))
            else:
                discrepancy_parts = []
                severity = "low"

                if missing:
                    discrepancy_parts.append(f"声称的事件 ID {sorted(missing)} 在数据库中不存在")
                    severity = "high"
                if ungrounded:
                    discrepancy_parts.append(
                        f"{len(ungrounded)}/{checked} 段引用原文在事件字段中不存在: "
                        f"{ungrounded[:3]}"
                    )
                    severity = "high" if quotes_fully_fabricated else (
                        "medium" if severity != "high" else severity
                    )

                reports.append(VerificationReport(
                    claim=claim_text[:100],
                    claim_source=claim_source,
                    claimed_evidence_ids=claimed_ids,
                    actual_evidence_ids=actual_ids,
                    verified=False,
                    discrepancy="; ".join(discrepancy_parts),
                    severity=severity,
                    quote_checked=checked,
                    quote_grounded=grounded,
                    ungrounded_quotes=ungrounded,
                ))

        valid = sum(1 for r in reports if r.verified)
        logger.info(
            f"PenetratingVerifier: {valid}/{len(reports)} claims verified, "
            f"{len(reports) - valid} discrepancies found"
        )
        for r in reports:
            if not r.verified:
                logger.warning(f"  Discrepancy [{r.severity}]: {r.discrepancy}")

        return reports

    async def verify_tool_results(
        self,
        session: AsyncSession,
        tool_results: list[dict],
    ) -> list[VerificationReport]:
        """
        验证工具调用结果是否真实

        某些场景下 Agent 可能声称"调用了工具X返回了结果Y"，
        但实际上工具从未被调用或返回了不同的结果。
        """
        # 当前架构中工具调用由代码执行而非 LLM 执行，此风险已消除
        # 保留接口以备未来扩展
        return []


# ════════════════════════════════════════════
# 2. 上下文审计器 (Context Auditor)
# ════════════════════════════════════════════

@dataclass
class ContextRisk:
    """上下文风险点"""
    source: str              # "system_prompt" | "tool_description" | "config"
    risk_type: str           # "ambiguous" | "contradictory" | "exploitable" | "blind_spot"
    description: str
    severity: str            # "critical" | "high" | "medium" | "low"
    suggestion: str = ""


class ContextAuditor:
    """
    上下文审计器

    不审计 AI 的输出，而是审计 AI 运行的"环境"：
    - 系统指令是否有模糊/矛盾/易被利用的漏洞
    - 工具描述是否准确
    - 权限配置是否合理
    - 检索策略是否有盲区
    """

    async def audit_system_prompts(self) -> list[ContextRisk]:
        """审计所有 Agent 的系统指令"""
        risks = []

        # 读取各 Agent 的系统 prompt 进行检查。
        # 优先从 prompts/*.j2 模板渲染实际 system prompt（单一事实源，避免快照漂移）；
        # 模板渲染失败时回退内联快照。
        _template_map = {
            "Decomposer": "audit/decomposer_initial_analysis_system",
            "SubAuditor": "audit/sub_auditor_system",
            "Executor": "audit/executor_synthesize_system",
            "Reviewer": "audit/reviewer_review_system",
        }
        _fallback_snapshot = {
            "Decomposer": "你是安全分析专家，输出JSON格式。",
            "SubAuditor": "你是严谨的安全分析专家。严格遵循输出格式",
            "Executor": "你是严谨的安全审计专家。只采纳有证据支撑的结论，输出JSON。",
            "Reviewer": "你是一个严格的安全审计复核专家，专门负责防幻觉检查。",
        }
        prompts_to_check = {}
        try:
            from prompts import render as _render_prompt
        except Exception as _e:  # noqa: BLE001
            _render_prompt = None
        for _agent, _tpl in _template_map.items():
            if _render_prompt is not None:
                try:
                    prompts_to_check[_agent] = _render_prompt(_tpl)
                    continue
                except Exception as _e:  # noqa: BLE001
                    logger.warning(f"[CAD] render {_tpl} 失败, 回退快照: {_e}")
            prompts_to_check[_agent] = _fallback_snapshot[_agent]

        for agent, prompt_text in prompts_to_check.items():
            # 检查 1: 指令是否清晰明确
            if "严格" not in prompt_text and "严谨" not in prompt_text:
                risks.append(ContextRisk(
                    source=f"system_prompt:{agent}",
                    risk_type="ambiguous",
                    description=f"{agent} 系统指令缺少严谨性要求，可能导致输出松散",
                    severity="medium",
                    suggestion="添加'严格遵循输出格式'等约束性指令",
                ))

            # 检查 2: 是否要求了证据引用
            if "证据" not in prompt_text and "ID" not in prompt_text:
                risks.append(ContextRisk(
                    source=f"system_prompt:{agent}",
                    risk_type="blind_spot",
                    description=f"{agent} 系统指令未要求引用证据ID，存在幻觉风险",
                    severity="high",
                    suggestion="添加'每条结论必须附带事件ID'的要求",
                ))

        return risks

    async def audit_tool_descriptions(self) -> list[ContextRisk]:
        """审计工具描述是否准确、不被滥用"""
        risks = []

        # 从 tool_registry 获取工具信息
        from tool_registry import tool_registry
        for tool_name in tool_registry.list_tools():
            info = tool_registry.get_info(tool_name)
            if not info:
                continue

            desc = info.get("description", "")

            # 检查描述是否足够清晰
            if len(desc) < 20:
                risks.append(ContextRisk(
                    source=f"tool_description:{tool_name}",
                    risk_type="ambiguous",
                    description=f"工具 {tool_name} 的描述过于简短({len(desc)}字)，"
                                f"可能导致 LLM 误用",
                    severity="medium",
                    suggestion="补充详细的参数说明和返回格式描述",
                ))

            # 检查是否有"可写"操作（安全审计场景应只读）
            if "write" in tool_name or "delete" in tool_name or "update" in tool_name:
                risks.append(ContextRisk(
                    source=f"tool_description:{tool_name}",
                    risk_type="exploitable",
                    description=f"工具 {tool_name} 具有写操作权限，安全审计场景应限制为只读",
                    severity="critical",
                    suggestion="移除写权限或增加二次确认",
                ))

        return risks

    async def audit_config(self) -> list[ContextRisk]:
        """审计系统配置"""
        risks = []
        from config import settings

        # 检查 LLM 配置
        if not settings.llm_api_key:
            risks.append(ContextRisk(
                source="config:llm_api_key",
                risk_type="exploitable",
                description="LLM API Key 未配置，系统使用降级模式，所有审计结论不可信",
                severity="critical",
                suggestion="配置有效的 LLM API Key",
            ))

        # 检查 temperature 设置（高 temperature 会增加幻觉）
        # 从各 Agent 配置获取
        return risks

    async def full_audit(self) -> list[ContextRisk]:
        """完整上下文审计"""
        all_risks = []
        all_risks.extend(await self.audit_system_prompts())
        all_risks.extend(await self.audit_tool_descriptions())
        all_risks.extend(await self.audit_config())

        by_severity = defaultdict(list)
        for r in all_risks:
            by_severity[r.severity].append(r)

        logger.info(
            f"ContextAuditor: {len(all_risks)} risks found "
            f"(critical={len(by_severity['critical'])}, "
            f"high={len(by_severity['high'])}, "
            f"medium={len(by_severity['medium'])})"
        )
        return all_risks


# ════════════════════════════════════════════
# 3. 免疫与熔断系统 (Circuit Breaker)
# ════════════════════════════════════════════

@dataclass
class CircuitBreakerState:
    """熔断器状态（阈值支持环境变量覆盖）

    P1-D-2: ``tripped: bool`` 无法表达三态状态机。修复前：
      · 日志宣称 "transitioning to HALF_OPEN"，代码却直接 ``tripped=False``
        —— 那是 CLOSED，不是半开，等于冷却一过就无条件全量放行，
        没有任何试探；
      · ``self._bad_count`` 被 __init__ 初始化后**从未自增**，
        于是"连续失败"这条熔断条件永远不会触发；
      · 条件 3 实为「最近 10 条里 ≥5 条差」，与
        ``CONSECUTIVE_BAD_AUDITS``（"连续"）语义完全不符。
    """
    # 三态: "closed" | "open" | "half_open"
    state: str = "closed"
    reason: str = ""
    # 熔断发生时刻（epoch 秒）。跨进程比较冷却期必须用它。
    tripped_at: float = 0.0
    # 真正的连续坏审核计数
    consecutive_bad: int = 0
    # 监控指标
    hallucination_risk_trend: list[float] = field(default_factory=list)
    evidence_completeness_trend: list[float] = field(default_factory=list)
    audit_count: int = 0
    anomaly_rate: float = 0.0
    last_na_note: str = ""          # 最近一条“无可验断言”的说明(可观测性)

    # ── P1-D-3: 监督系统自身故障是一类独立状态 ──
    # 修复前 CAD 抛异常只在调用点 warning，熔断器保持 CLOSED，
    # /cad/status 显示一切正常 —— 监督层静默消失且无痕迹。
    supervision_failures: int = 0
    last_supervision_error: str = ""

    # half_open 探针预算：冷却后只允许有限次试探
    half_open_probes_left: int = 0
    half_open_successes: int = 0

    # 跨进程乐观锁版本号
    version: int = 0

    # 阈值（环境变量 SHARED_MEMORY_CAD_* 覆盖）
    MAX_HALLUCINATION_RISK: float = field(default_factory=lambda: float(
        os.environ.get("SHARED_MEMORY_CAD_MAX_HALLUCINATION_RISK", "0.5")))
    MIN_EVIDENCE_COMPLETENESS: float = field(default_factory=lambda: float(
        os.environ.get("SHARED_MEMORY_CAD_MIN_EVIDENCE_COMPLETENESS", "0.3")))
    CONSECUTIVE_BAD_AUDITS: int = field(default_factory=lambda: int(
        os.environ.get("SHARED_MEMORY_CAD_CONSECUTIVE_BAD_AUDITS", "5")))
    WARMUP_AUDITS: int = field(default_factory=lambda: int(
        os.environ.get("SHARED_MEMORY_CAD_WARMUP_AUDITS", "10")))
    COOLDOWN_SECONDS: float = field(default_factory=lambda: float(
        os.environ.get("SHARED_MEMORY_CAD_COOLDOWN_SECONDS", "300")))
    # half_open 试探次数上限（冷却后放行多少条审计）
    HALF_OPEN_PROBES: int = field(default_factory=lambda: int(
        os.environ.get("SHARED_MEMORY_CAD_HALF_OPEN_PROBES", "3")))
    # 连续多少条好审核才真正关闭（half_open 通过条件）
    HALF_OPEN_SUCCESSES: int = field(default_factory=lambda: int(
        os.environ.get("SHARED_MEMORY_CAD_HALF_OPEN_SUCCESSES", "2")))
    # 连续多少次监督自身故障直接熔断（监督不可信时不能继续自动响应）
    SUPERVISION_FAILURE_THRESHOLD: int = field(default_factory=lambda: int(
        os.environ.get("SHARED_MEMORY_CAD_SUPERVISION_FAILURE_THRESHOLD", "3")))

    @property
    def tripped(self) -> bool:
        """是否处于「不可自动响应」状态。

        half_open 也算 tripped —— 试探期间结论仍不可全信，
        自动响应闸门必须继续拦截。修复前这里只有一个 bool，
        half_open 无从表达。
        """
        return self.state in ("open", "half_open")


CLOSED = "closed"
OPEN = "open"
HALF_OPEN = "half_open"


class CircuitBreaker:
    """
    熔断器

    参考生物免疫系统：
    - 免疫: 常态化监控风险趋势，提前发现异常
    - 熔断: 风险超限时自动切断，防止扩散

    状态:
      CLOSED (正常) → OPEN (熔断) → HALF_OPEN (有限试探) → CLOSED/OPEN

    P1-D-2 跨进程一致性:
      本类是**进程内**状态机；权威状态存在 DB 单行 ``cad_circuit_state``。
      ``_persist`` 用乐观并发（version CAS）写入，冲突时重载后重放，
      因此 FastAPI 进程与 Temporal worker 进程看到的是同一个熔断状态。
    """

    def __init__(self, *, persist: bool = False):
        self.state = CircuitBreakerState()
        self._na_count = 0          # 无可验(单源/孤立无分解证据)审计次数——不计入幻觉趋势
        # CAD 自身准确率追踪
        self._cad_decisions: list[dict] = []  # {event_id, tripped, overridden, timestamp}
        self._override_count = 0
        self._false_trip_count = 0
        # 跨进程持久化开关。测试用纯内存实例（persist=False）。
        self._persist_enabled = persist
        self._store_error: str = ""
        # 持久化失败时的递归守卫（_persist ↔ record_supervision_failure 互调）
        self._in_persist_failure = False

    # ── 跨进程持久化 ──────────────────────────────────────

    async def _load_persisted(self) -> bool:
        """从 DB 载入权威状态。返回是否成功。"""
        if not self._persist_enabled:
            return False
        try:
            from models import CadCircuitState, async_session
            async with async_session() as s:
                row = await s.get(CadCircuitState, 1)
                if row is None:
                    return False
                # 只把**权威字段**拉过来；趋势数组是本进程观测指标，不跨进程同步。
                #
                # P3-5: 状态值必须校验。原实现原样读入 row.state，而 tripped
                # 判据是 `state in ("open", "half_open")` —— 实测 'TRIPPED' /
                # 'Open' / 'OPEN' / 'half-open' / 'bogus' 全部 tripped=False，
                # 即一条**状态不可读**的记录等于熔断器被静默关闭。
                # 安全闸门的缺省方向必须是「拿不准就不放行」。
                raw_state = str(row.state or "").strip().lower()
                if raw_state not in (CLOSED, OPEN, HALF_OPEN):
                    self.state.state = OPEN
                    # reason 每次都重算：同一实例先读到损坏行、后来读到正常行时，
                    # 不能把上一条「不可识别」的说明留在状态里。
                    self.state.reason = (
                        f"持久化状态不可识别({row.state!r})，按失败关闭处理"
                    )
                    self._store_error = f"unknown_state:{row.state!r}"
                    logger.warning(
                        "[CAD] 持久化熔断状态不可识别 %r，按 OPEN 处理", row.state
                    )
                else:
                    self.state.state = raw_state
                    self.state.reason = row.reason or ""
                self.state.tripped_at = float(row.tripped_at or 0.0)
                self.state.consecutive_bad = int(row.consecutive_bad or 0)
                self.state.audit_count = int(row.audit_count or 0)
                self.state.supervision_failures = int(row.supervision_failures or 0)
                self.state.last_supervision_error = row.last_supervision_error or ""
                self.state.half_open_probes_left = int(row.half_open_probes_left or 0)
                self.state.version = int(row.version or 0)
                return True
        except Exception as e:
            self._store_error = f"load_failed:{type(e).__name__}"
            logger.warning(f"[CAD] 熔断状态载入失败，使用进程内状态: {e}")
            return False

    async def _persist(self) -> bool:
        """写回熔断状态。当前实现是 **last-write-wins**（WHERE 无 version 谓词）。

        WHERE 只有 ``id == 1``，**没有 version 谓词**，所以：
          · ``version`` 列被读取、递增、写入，但**从不被比较** ——
            它是一个只写字段，和 ``target_hash_top`` 属于同一族；
          · 「版本冲突」在本函数里**无法被检测到**。

        ⚠️ 修复前本 docstring 声称的是乐观并发 + version 冲突时重载重放，
        而实现并不提供该属性。与其留一句假话，这里如实记录当前形态；
        真正补上需要正确区分 ``rowcount == 0`` 的两种成因
        （行尚不存在 / version 不匹配），目前一律当作「行不存在」。

        跨进程一致性现在靠的是**先载入权威状态再写**的纪律
        （所有写路径在 P1-b 后都先 ``await self._load_persisted()``），
        不是靠本函数。真正并发的交错窗口（两进程同时载入、先后写回）
        仍存在，且未被检出。

        必须处理「行尚不存在」的情况：只用 UPDATE 的话，
        UPDATE 对空表匹配 0 行 → **首次熔断永远不会落库**，
        跨进程一致性在最关键的时刻失效。
        """
        if not self._persist_enabled:
            return True
        for attempt in range(2):
            try:
                from sqlalchemy import update
                from models import CadCircuitState, async_session
                async with async_session() as s:
                    async with s.begin():
                        res = await s.execute(
                            update(CadCircuitState)
                            .where(CadCircuitState.id == 1)
                            .values(
                                state=self.state.state,
                                reason=self.state.reason,
                                tripped_at=self.state.tripped_at,
                                consecutive_bad=self.state.consecutive_bad,
                                audit_count=self.state.audit_count,
                                supervision_failures=self.state.supervision_failures,
                                last_supervision_error=self.state.last_supervision_error,
                                half_open_probes_left=self.state.half_open_probes_left,
                                version=self.state.version + 1,
                                updated_at=datetime.now(timezone.utc),
                            )
                        )
                        # 行不存在 → 插入（INSERT 后 UPDATE 永不生效的场景）
                        if not res.rowcount:
                            s.add(CadCircuitState(
                                id=1,
                                state=self.state.state,
                                reason=self.state.reason,
                                tripped_at=self.state.tripped_at,
                                consecutive_bad=self.state.consecutive_bad,
                                audit_count=self.state.audit_count,
                                supervision_failures=self.state.supervision_failures,
                                last_supervision_error=self.state.last_supervision_error,
                                half_open_probes_left=self.state.half_open_probes_left,
                                version=self.state.version + 1,
                            ))
                self.state.version += 1
                return True
            except Exception as e:
                self._store_error = f"persist_failed:{type(e).__name__}"
                logger.warning(f"[CAD] 熔断状态写入失败(attempt={attempt}): {e}")
                if attempt == 0:
                    # 这是**通用的持久化失败**重试，不是版本冲突处理 ——
                    # 没有 version 谓词，版本冲突在本函数里检测不到。
                    # 重载权威状态后再试一次，至少避免用陈旧值硬写。
                    await self._load_persisted()
                    continue
                # 持久化彻底失败 = 监督状态不可跨进程同步。
                # 这是一类**监督自身故障**，不能静默继续。
                #
                # ⚠️ 递归守卫：`record_supervision_failure` 内部会再调 _persist，
                # 不守卫就是 _persist → failure → _persist → … 无限递归。
                # persist=False / count=False：
                #   · persist=False —— DB 刚证明不可用，再写一次只会递归；
                #   · count=False  —— 「写不进去」是同一次故障的后果，
                #     不是又一次故障；重复计数会让熔断阈值实际减半。
                if not self._in_persist_failure:
                    self._in_persist_failure = True
                    try:
                        await self.record_supervision_failure(
                            f"circuit_state_persist_failed:{type(e).__name__}",
                            persist=False,
                            count=False,
                        )
                    finally:
                        self._in_persist_failure = False
                return False
        return False

    async def _maybe_transition(self) -> None:
        """检查是否需要熔断（并持久化）。"""
        self._check_trip()
        await self._persist()

    # ── 记录入口 ──────────────────────────────────────────

    async def record_audit_result(
        self,
        hallucination_risk: float,
        evidence_completeness: float,
        anomaly_detected: bool,
    ):
        """记录一次审计结果到监控趋势，并做状态机判定。

        P1-D-2: 决策前**必须**先载入 DB 权威状态。
        修复前熔断判定完全基于本进程内存 —— 一个刚启动的 worker 进程
        不知道别的进程早已熔断，会按 closed 继续放行。
        """
        await self._load_persisted()
        self._append_trend(hallucination_risk, evidence_completeness)
        await self._maybe_transition()

    def _append_trend(self, hallucination_risk: float, evidence_completeness: float):
        """写入趋势并更新异常率。"""
        self.state.audit_count += 1
        self.state.hallucination_risk_trend.append(hallucination_risk)
        self.state.evidence_completeness_trend.append(evidence_completeness)

        # 仅保留最近 100 条记录
        if len(self.state.hallucination_risk_trend) > 100:
            self.state.hallucination_risk_trend.pop(0)
        if len(self.state.evidence_completeness_trend) > 100:
            self.state.evidence_completeness_trend.pop(0)

        # 计算近期异常率
        recent = self.state.hallucination_risk_trend[-20:]
        self.state.anomaly_rate = sum(1 for r in recent if r > 0.3) / max(len(recent), 1)

    def record_audit_result_sync(
        self,
        hallucination_risk: float,
        evidence_completeness: float,
        anomaly_detected: bool,
    ):
        """同步版本（纯内存实例 / 单测）。

        生产路径必须用 ``record_audit_result``（async，先重载权威状态再落库）。
        保留同步入口是为了让「忘记 await」变成**立即可见的错误**
        （record_audit_result 本身是协程，未 await 会产生 RuntimeWarning），
        而不是静默地不落库。
        """
        self._append_trend(hallucination_risk, evidence_completeness)
        self._check_trip()

    # 旧名保持同步语义：既有调用点（测试 / 纯内存用法）不改也能工作
    record_audit_result_blocking = record_audit_result_sync

    def reset_sync(self):
        """同步重置（仅纯内存实例 / 单测）"""
        if self.state.state == CLOSED:
            return
        self._close("manual_reset")

    def record_na(self, notes: str = ""):
        """记录一次“无可验断言”审计(孤立单源/暂无分解证据)。

        这类事件没有可穿透验证的 claims，不等于证据质量低(D的完整度不是 0)，
        也不等于幻觉——因此不写入 hallucination/evidence trend,避免累积 0 触发熔断。
        仅做计数与可观测性暴露；真实坏趋势(查无此 ID /断言失实)仍照常走
        record_audit_result 触发熔断。
        """
        self.state.audit_count += 1
        self._na_count += 1
        self.state.last_na_note = notes
        logger.info(
            f"[CAD] 无可验断言审计 #{self._na_count}: {notes or '无分解证据'} "
            f"(不计入幻觉趋势, 不触发熔断)"
        )

    async def record_supervision_failure(self, error: str = "", *,
                                         persist: bool = True, count: bool = True):
        """P1-D-3: 记录一次**监督系统自身故障**。

        修复前这类故障完全不存在：CAD 抛异常时调用点只 warning，
        熔断器保持 CLOSED，/cad/status 显示正常。监督层在最需要它的
        时刻静默消失，既不阻断自动响应，也不留下任何可审计痕迹。

        现在：连续 N 次监督故障直接熔断，且状态/原因可查。

        Args:
            persist: 由 ``_persist`` 的失败路径回灌时传 False ——
                那时 DB 刚证明不可用，再写一次只会递归。
            count: 同上。**写不进去不是又一次故障**，而是同一次故障的
                后果；不置 False 会把一次故障数成两次，阈值形同减半。
        """
        if persist:
            await self._load_persisted()
        if count:
            self.state.supervision_failures += 1
        self.state.last_supervision_error = str(error)[:500]
        logger.warning(
            f"[CAD] 监督系统自身故障 #{self.state.supervision_failures}: "
            f"{self.state.last_supervision_error[:200]}"
        )
        if (
            self.state.supervision_failures
            >= self.state.SUPERVISION_FAILURE_THRESHOLD
            and self.state.state != OPEN
        ):
            self._trip(
                f"监督系统自身连续 {self.state.supervision_failures} 次故障: "
                f"{self.state.last_supervision_error[:120]}",
                kind="supervision_failed",
            )
        if persist:
            await self._persist()

    async def clear_supervision_failures(self):
        """一次成功的监督运行后清零自身故障计数。

        P3-5: **必须先载入权威状态**。本方法原先是四条落库路径里唯一
        直接 `_persist()` 的 —— 一个持有陈旧内存副本的进程跑成功监督，
        就会把自己的陈旧状态（可能是 closed）覆盖回 DB，
        抹掉别的进程刚写入的熔断。跨进程保护靠的是「先载入再写」
        这条纪律，不是 version 字段（`_persist` 的 WHERE 里没有 version 谓词）。
        """
        if not self._persist_enabled:
            if self.state.supervision_failures:
                self.state.supervision_failures = 0
                self.state.last_supervision_error = ""
            return
        await self._load_persisted()
        if self.state.supervision_failures:
            self.state.supervision_failures = 0
            self.state.last_supervision_error = ""
            await self._persist()

    # ── 状态机 ────────────────────────────────────────────

    def _is_audit_bad(self, risk: float, completeness: float) -> bool:
        """单条审计是否算"差"。"""
        return risk > 0.4 or completeness < 0.5

    def _check_trip(self):
        """检查是否需要熔断 / 半开试探是否通过"""
        # ── OPEN: 冷却期满 → HALF_OPEN（有限试探，不是全量放行）──
        if self.state.state == OPEN:
            # cooldown<=0 视为「立即可试探」；否则要求 tripped_at 非零
            # （未熔断过的进程不能凭空进入半开）。
            cooldown_done = (
                self.state.COOLDOWN_SECONDS <= 0
                or (
                    self.state.tripped_at > 0
                    and time.time() - self.state.tripped_at
                    >= self.state.COOLDOWN_SECONDS
                )
            )
            if not cooldown_done:
                return
            logger.info(
                f"Circuit breaker cooldown expired ({self.state.COOLDOWN_SECONDS}s), "
                f"OPEN → HALF_OPEN (probes={self.state.HALF_OPEN_PROBES})"
            )
            self.state.state = HALF_OPEN
            self.state.half_open_probes_left = self.state.HALF_OPEN_PROBES
            self.state.half_open_successes = 0
            # 注意：**不重置 reason**，试探期间仍需可追溯当初为何熔断。
            # 继续往下走 —— 触发转换的这次审计**本身就是第一根探针**。

        # ── HALF_OPEN: 用有限探针试探，通过则关闭，失败则重新熔断 ──
        if self.state.state == HALF_OPEN:
            if self.state.half_open_probes_left <= 0:
                # 试探预算用尽仍未通过足够次数 → 回到 OPEN，重新计冷却
                self._trip(
                    f"半开试探预算耗尽({self.state.HALF_OPEN_PROBES}次)，未恢复",
                    kind="half_open_failed",
                )
                return
            self.state.half_open_probes_left -= 1
            # 本次探针的结果就是刚落盘的那条趋势，评估它：
            cur_risk = self.state.hallucination_risk_trend[-1]
            cur_comp = self.state.evidence_completeness_trend[-1]
            if self._is_audit_bad(cur_risk, cur_comp):
                # 一次坏探针即判定未恢复：立刻回到 OPEN，不给"多试几次"的机会
                self._trip(
                    f"半开试探失败(risk={cur_risk:.2f} completeness={cur_comp:.2f})",
                    kind="half_open_probe_failed",
                )
                return
            self.state.half_open_successes += 1
            if self.state.half_open_successes >= self.state.HALF_OPEN_SUCCESSES:
                self._close(
                    f"半开试探连续 {self.state.half_open_successes} 次通过"
                )
            return

        # ── CLOSED: 正常熔断判定 ──
        # 预热期：前 N 次审计不触发熔断（系统刚启动，基线未建立）
        if self.state.audit_count < self.state.WARMUP_AUDITS:
            return

        recent_h = self.state.hallucination_risk_trend[-10:]
        recent_e = self.state.evidence_completeness_trend[-10:]

        if not recent_h:
            return

        # P1-D-2: 真正的**连续**坏审核计数。
        # 修复前 self._bad_count 在 __init__ 置 0 后从未自增，
        # CONSECUTIVE_BAD_AUDITS 这条条件是纯装饰。
        if self._is_audit_bad(recent_h[-1], recent_e[-1] if recent_e else 1.0):
            self.state.consecutive_bad += 1
        else:
            self.state.consecutive_bad = 0

        avg_risk = sum(recent_h) / len(recent_h)
        avg_completeness = sum(recent_e) / len(recent_e) if recent_e else 1.0

        # 条件 1: 平均幻觉风险超限
        if avg_risk > self.state.MAX_HALLUCINATION_RISK:
            self._trip(
                f"平均幻觉风险 {avg_risk:.2f} 超过阈值 {self.state.MAX_HALLUCINATION_RISK}"
            )
            return

        # 条件 2: 证据完整度低于阈值
        if avg_completeness < self.state.MIN_EVIDENCE_COMPLETENESS:
            self._trip(
                f"证据完整度 {avg_completeness:.2f} 低于阈值 {self.state.MIN_EVIDENCE_COMPLETENESS}"
            )
            return

        # 条件 3: **连续**差审核（修复前统计的是「最近 10 条里 ≥5 条」滑窗多数，
        # 与 CONSECUTIVE_BAD_AUDITS 的"连续"语义完全不符）
        if self.state.consecutive_bad >= self.state.CONSECUTIVE_BAD_AUDITS:
            self._trip(
                f"连续 {self.state.consecutive_bad} 次审核质量低于标准"
            )
            return

    def _trip(self, reason: str, *, kind: str = "quality"):
        """触发熔断（→ OPEN）"""
        self.state.state = OPEN
        self.state.tripped_at = time.time()
        self.state.reason = reason
        self.state.half_open_probes_left = 0
        self.state.half_open_successes = 0
        logger.critical(f"CIRCUIT BREAKER TRIPPED [{kind}]: {reason}")

    def _close(self, reason: str = ""):
        """关闭熔断器（→ CLOSED），仅 half_open 试探全部通过时调用"""
        self.state.state = CLOSED
        self.state.tripped_at = 0.0
        self.state.reason = ""
        self.state.consecutive_bad = 0
        self.state.half_open_probes_left = 0
        self.state.half_open_successes = 0
        logger.info(f"Circuit breaker CLOSED ({reason})")

    async def reset(self):
        """重置熔断（人工介入后）

        P1-D-2: 必须先载入 DB 权威状态再判定，且必须落库。
        修复前两点都错：
          · 只改进程内存 —— 管理员在 API 进程点「重置」，
            worker 进程仍认为熔断中；
          · 判定用本进程内存里的 state，而新进程初始恒为 closed，
            于是「看起来无需重置」而直接跳过，落库更是从未发生。
        """
        await self._load_persisted()
        if self.state.state == CLOSED:
            return
        logger.info("Circuit breaker reset (manual intervention)")
        self._close("manual_reset")
        await self._persist()

    def update_thresholds(self, **kwargs) -> dict:
        """运行时更新熔断阈值"""
        updated = {}
        field_map = {
            "max_hallucination_risk": "MAX_HALLUCINATION_RISK",
            "min_evidence_completeness": "MIN_EVIDENCE_COMPLETENESS",
            "consecutive_bad_audits": "CONSECUTIVE_BAD_AUDITS",
            "warmup_audits": "WARMUP_AUDITS",
            "cooldown_seconds": "COOLDOWN_SECONDS",
            "half_open_probes": "HALF_OPEN_PROBES",
            "half_open_successes": "HALF_OPEN_SUCCESSES",
            "supervision_failure_threshold": "SUPERVISION_FAILURE_THRESHOLD",
        }
        for api_key, attr in field_map.items():
            if api_key in kwargs and kwargs[api_key] is not None:
                old_val = getattr(self.state, attr)
                setattr(self.state, attr, type(old_val)(kwargs[api_key]))
                updated[api_key] = {"old": old_val, "new": getattr(self.state, attr)}
        if updated:
            logger.info(f"[CAD] Thresholds updated: {updated}")
        return updated

    def record_decision(self, event_id: int, tripped: bool):
        """记录 CAD 决策（用于自身准确率评估）"""
        self._cad_decisions.append({
            "event_id": event_id,
            "tripped": tripped,
            "overridden": False,
            "timestamp": time.time(),
        })
        if len(self._cad_decisions) > 500:
            self._cad_decisions = self._cad_decisions[-500:]

    def record_override(self, event_id: int):
        """记录人工 override（标记 CAD 误报）"""
        self._override_count += 1
        for d in self._cad_decisions:
            if d["event_id"] == event_id and d["tripped"]:
                d["overridden"] = True
                self._false_trip_count += 1
                break
        logger.info(f"[CAD] Override recorded for event #{event_id}")

    def accuracy_stats(self) -> dict:
        """CAD 自身准确率统计"""
        total_trips = sum(1 for d in self._cad_decisions if d["tripped"])
        overridden = sum(1 for d in self._cad_decisions if d.get("overridden"))
        accuracy = 1.0 - (overridden / max(total_trips, 1))
        return {
            "total_decisions": len(self._cad_decisions),
            "total_trips": total_trips,
            "overridden": overridden,
            "false_trip_rate": round(overridden / max(total_trips, 1), 4),
            "accuracy": round(accuracy, 4),
        }

    def get_status(self) -> dict:
        """获取熔断器状态"""
        return {
            # tripped 由 state 派生：half_open 同样阻断自动响应
            "tripped": self.state.tripped,
            "state": self.state.state,
            "tripped_at": self.state.tripped_at,
            "reason": self.state.reason,
            "audit_count": self.state.audit_count,
            "half_open_probes_left": self.state.half_open_probes_left,
            "avg_hallucination_risk": (
                sum(self.state.hallucination_risk_trend[-10:]) / 10
                if len(self.state.hallucination_risk_trend) >= 10 else 0.0
            ),
            "avg_evidence_completeness": (
                sum(self.state.evidence_completeness_trend[-10:]) / 10
                if len(self.state.evidence_completeness_trend) >= 10 else 1.0
            ),
            "anomaly_rate": self.state.anomaly_rate,
            "unverifiable_count": self._na_count,   # 无可验断言审计(不计入幻觉趋势)
            "last_na_note": self.state.last_na_note,
            # P1-D-3: 监督系统自身故障（修复前状态里完全没有这两项）
            "supervision_failures": self.state.supervision_failures,
            "last_supervision_error": self.state.last_supervision_error,
            # 跨进程一致性
            "version": self.state.version,
            "persistent": self._persist_enabled,
            "store_error": self._store_error,
            "thresholds": {
                "max_hallucination_risk": self.state.MAX_HALLUCINATION_RISK,
                "min_evidence_completeness": self.state.MIN_EVIDENCE_COMPLETENESS,
                "consecutive_bad": self.state.CONSECUTIVE_BAD_AUDITS,
                "warmup_audits": self.state.WARMUP_AUDITS,
                "cooldown_seconds": self.state.COOLDOWN_SECONDS,
                "half_open_probes": self.state.HALF_OPEN_PROBES,
                "half_open_successes": self.state.HALF_OPEN_SUCCESSES,
                "supervision_failure_threshold": self.state.SUPERVISION_FAILURE_THRESHOLD,
            },
            "accuracy": self.accuracy_stats(),
        }


# ════════════════════════════════════════════
# 全局单例
# ════════════════════════════════════════════

verifier = PenetratingVerifier()
context_auditor = ContextAuditor()
# P1-D-2: persist=True —— 熔断状态跨进程共享。
# 本项目是 FastAPI + Temporal worker 分进程部署（见 event_store.get_by_id 注释），
# 修复前熔断器是纯进程内存：/cad/status 在 API 进程显示 CLOSED，
# 而 worker 进程早已 tripped，两边对同一份监督状态给出相反答案；
# 且任何一次重启都把熔断记忆清零。
circuit_breaker = CircuitBreaker(persist=True)
