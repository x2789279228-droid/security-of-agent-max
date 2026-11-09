"""
分解者 (Decomposer) — Audit-LLM 第一层

职责：
  1. 分析安全事件的类型、严重度、异常分数
  2. 决定审核深度（quick / standard / deep）
  3. 按深度产生对应的子任务列表

决策逻辑：
  - LLM 分析事件特征 + 输出审核方案
  - 或：规则引擎快速决策（低风险走规则，高风险走LLM）

输出：
  - audit_depth: 审核深度
  - sub_tasks: list[SubTask]
  - analysis_summary: LLM 对事件的初步判断
"""
import json
import logging

from audit_types import (
    SubTask,
    AUDIT_DEPTH_QUICK, AUDIT_DEPTH_STANDARD, AUDIT_DEPTH_DEEP,
    SUBTASK_QUERY_EVENTS, SUBTASK_ANALYZE_IP, SUBTASK_FIND_CHAINS,
    SUBTASK_CHECK_MEMORY, SUBTASK_KNOWLEDGE_SEARCH,
    SUBTASK_DEEP_ANALYZE, SUBTASK_RECHECK,
    SUBTASK_ENTITY_LINK,
)
# D3: 继承 BaseAuditComponent 统一 LLM 调用入口的 trace
from .base import BaseAuditComponent

logger = logging.getLogger(__name__)


# ── 规则引擎（非LLM快速决策路径） ──

def _rule_based_depth(event: dict, anomaly_score: float) -> str:
    """基于规则的快速审核深度决策。

    PR1 / P0-9: deep 只在非 LLM 信号或 critical 时开启（默认路径 LLM hop ≤ 3）。
    """
    from veto_gates import extract_non_llm_signals, HIGH_RISK_EVENT_TYPES

    severity = event.get("severity", "info")
    event_type = event.get("event", event.get("type", ""))
    signals = extract_non_llm_signals(event, anomaly_score=anomaly_score)

    # deep：critical / 高异常 / 检测器命中 / 高危事件类型（来自日志源/检测器，非 LLM）
    if (
        severity == "critical"
        or anomaly_score > 0.7
        or signals.has_signal
        or event_type in HIGH_RISK_EVENT_TYPES
    ):
        return AUDIT_DEPTH_DEEP
    if severity in ("high", "medium") or anomaly_score > 0.4:
        return AUDIT_DEPTH_STANDARD
    if anomaly_score > 0.2:
        return AUDIT_DEPTH_STANDARD

    return AUDIT_DEPTH_QUICK


def _get_subtasks_quick(session_id: str, event: dict,
                        anomaly_score: float) -> list[SubTask]:
    """快速审核子任务"""
    src_ip = event.get("src_ip", "")
    tasks = []
    idx = 0

    # t1: 查询同IP近期事件
    idx += 1
    tasks.append(SubTask(
        task_id=f"t{idx}",
        type=SUBTASK_QUERY_EVENTS,
        params={"session_id": session_id, "src_ip": src_ip,
                "time_window_minutes": 30, "limit": 20},
        priority=3,
        description=f"快速查询 {src_ip} 近30分钟的事件",
    ))

    return tasks


def _get_subtasks_standard(session_id: str, event: dict,
                           anomaly_score: float) -> list[SubTask]:
    """标准审核子任务"""
    src_ip = event.get("src_ip", "")
    event_type = event.get("event", event.get("type", ""))
    tasks = []
    idx = 0

    # t1: 查询同IP近期事件
    idx += 1
    tasks.append(SubTask(
        task_id=f"t{idx}",
        type=SUBTASK_QUERY_EVENTS,
        params={"session_id": session_id, "src_ip": src_ip,
                "time_window_minutes": 120, "limit": 50},
        priority=4,
        description=f"查询 {src_ip} 近2小时事件",
    ))

    # t2: IP基线分析
    idx += 1
    tasks.append(SubTask(
        task_id=f"t{idx}",
        type=SUBTASK_ANALYZE_IP,
        params={"src_ip": src_ip},
        priority=3,
        description=f"{src_ip} 历史行为基线",
    ))

    # t3: 攻击链检测
    idx += 1
    tasks.append(SubTask(
        task_id=f"t{idx}",
        type=SUBTASK_FIND_CHAINS,
        params={"session_id": session_id, "time_window_minutes": 1440},
        priority=3,
        description="24小时内攻击链检测",
    ))

    # t4: 向量记忆检索
    idx += 1
    tasks.append(SubTask(
        task_id=f"t{idx}",
        type=SUBTASK_CHECK_MEMORY,
        params={"query": f"{event_type} {src_ip}"},
        priority=2,
        description="语义相关历史记忆",
    ))

    # t5: 安全知识库检索 (RAG)
    idx += 1
    tasks.append(SubTask(
        task_id=f"t{idx}",
        type=SUBTASK_KNOWLEDGE_SEARCH,
        params={"query": f"{event_type} 攻击特征 检测方法",
                "threat_type": event_type, "severity": event.get("severity", "")},
        priority=3,
        description=f"检索 {event_type} 相关安全知识 (MITRE/CAPEC)",
    ))

    return tasks


def _get_subtasks_deep(session_id: str, event: dict,
                       anomaly_score: float,
                       selected: "list[str] | None" = None) -> list[SubTask]:
    """深度审核子任务。

    2026-11-09 阶段4B(LLM 真决策): 支持 ``selected`` 能力键子集 —— deep 档的
    LLM 规划器可从取证类能力中挑选实际需要的子任务(防幻觉: 只接受本函数
    认识的键; 越权键静默丢弃)。两条安全底线不参与挑选:
      - deep_analyze: 综合分析必须保留(Executor 的 synthesize 依赖)
      - review: 复核必须保留(Reviewer 只准降级的安全语义依赖)
    selected=None → 全量构建(规则模板默认行为, 与历史版本完全一致)。
    """
    src_ip = event.get("src_ip", "")
    dst_ip = event.get("dst_ip", "")
    event_type = event.get("event", event.get("type", ""))
    by_key: dict[str, SubTask] = {}

    # t1: 全量事件查询
    by_key["query_events_24h"] = SubTask(
        task_id="t?",
        type=SUBTASK_QUERY_EVENTS,
        params={"session_id": session_id, "src_ip": src_ip,
                "time_window_minutes": 1440, "limit": 200},
        priority=5,
        description=f"{src_ip} 24小时全量事件",
    )

    # t2: IP基线
    by_key["ip_baseline"] = SubTask(
        task_id="t?",
        type=SUBTASK_ANALYZE_IP,
        params={"src_ip": src_ip},
        priority=4,
        description=f"{src_ip} 基线分析",
    )

    # t3: 如果目标IP存在，查目标事件
    if dst_ip:
        by_key["target_events"] = SubTask(
            task_id="t?",
            type=SUBTASK_QUERY_EVENTS,
            params={"session_id": session_id, "src_ip": dst_ip,
                    "time_window_minutes": 1440, "limit": 100},
            priority=4,
            description=f"目标 {dst_ip} 的事件",
        )

    # t4: 攻击链
    by_key["attack_chains"] = SubTask(
        task_id="t?",
        type=SUBTASK_FIND_CHAINS,
        params={"session_id": session_id, "time_window_minutes": 2880},
        priority=4,
        description="48小时攻击链检测",
    )

    # t5: 实体图关联
    by_key["entity_link"] = SubTask(
        task_id="t?",
        type=SUBTASK_ENTITY_LINK,
        params={"session_id": session_id, "time_window_minutes": 1440},
        priority=3,
        description="实体关联分析",
    )

    # t6: 记忆检索
    by_key["memory_check"] = SubTask(
        task_id="t?",
        type=SUBTASK_CHECK_MEMORY,
        params={"query": f"{event_type} {src_ip} {dst_ip}"},
        priority=3,
        description="相关记忆",
    )

    # t6b: 安全知识库检索 (RAG)
    by_key["knowledge_search"] = SubTask(
        task_id="t?",
        type=SUBTASK_KNOWLEDGE_SEARCH,
        params={"query": f"{event_type} 攻击手法 检测指标 IOC 响应建议",
                "threat_type": event_type, "severity": event.get("severity", "")},
        priority=4,
        description=f"深度检索 {event_type} 安全知识 (MITRE/CAPEC)",
    )

    # 能力键稳定顺序(取证类可被 LLM 规划挑选; 后两个为安全底线, 不可挑选)
    evidence_keys = _DEEP_EVIDENCE_KEYS

    if selected is None:
        chosen = [k for k in evidence_keys if k in by_key]
    else:
        # 防幻觉: 只接受认识的键; 条件键(dst_ip 缺失时的 target_events)自然剔除
        chosen = [k for k in evidence_keys if k in by_key and k in set(selected)]
        if not chosen:
            chosen = [k for k in evidence_keys if k in by_key]

    # t7: 深度LLM分析（依赖前序实际存在的取证任务）
    deep_analyze = SubTask(
        task_id="t?",
        type=SUBTASK_DEEP_ANALYZE,
        params={"event": event},
        priority=2,
        description="综合所有数据深度分析",
    )
    # t8: 复核
    review = SubTask(
        task_id="t?",
        type=SUBTASK_RECHECK,
        params={},
        priority=1,
        description="复核审计结论",
    )

    # 按 chosen → deep_analyze → review 的顺序重编号并接依赖
    tasks: list[SubTask] = []
    for k in chosen:
        tasks.append(by_key[k])
    prev_ids: list[str] = []
    for i, t in enumerate(tasks, start=1):
        t.task_id = f"t{i}"
        prev_ids.append(t.task_id)
    deep_analyze.task_id = f"t{len(tasks) + 1}"
    deep_analyze.depends_on = list(prev_ids)
    tasks.append(deep_analyze)
    review.task_id = f"t{len(tasks) + 1}"
    review.depends_on = [deep_analyze.task_id]
    tasks.append(review)

    return tasks


# ── Decomposer 主类 ──

# deep 档取证能力键(LLM 规划器的合法选择域; 防幻觉白名单的唯一来源)
_DEEP_EVIDENCE_KEYS = [
    "query_events_24h", "ip_baseline", "target_events", "attack_chains",
    "entity_link", "memory_check", "knowledge_search",
]


class Decomposer(BaseAuditComponent):
    """
    分解者 (D3: 继承 BaseAuditComponent 统一 trace 入口)

    decompose() 输出: {
        "audit_depth": "quick|standard|deep",
        "sub_tasks": [SubTask, ...],
        "llm_analysis": "LLM的初步判断（如需要）",
    }
    """

    def __init__(self):
        super().__init__(
            agent_id="decomposer",
            display_name="分解者 (Decomposer)",
        )

    async def decompose(
        self,
        event: dict,
        session_id: str,
        anomaly_score: float = 0.0,
        anomaly_reasons: list[str] = None,
        mode: str = "full",
        missed_threats: list[dict] = None,
    ) -> dict:
        """
        分解审核任务

        Args:
            event: 原始事件
            session_id: 会话ID
            anomaly_score: 异常检测分数
            anomaly_reasons: 异常原因列表
            mode: "full" | "supplement"
            missed_threats: 前序轮次遗漏的威胁列表（mode=supplement时传入）

        Returns:
            {"audit_depth": str, "sub_tasks": list[SubTask],
             "llm_analysis": str, "depth_reason": str}
        """
        missed_threats = missed_threats or []
        event_type = event.get("event", event.get("type", "UNKNOWN"))
        severity = event.get("severity", "info")
        src_ip = event.get("src_ip", "")
        anomaly_reasons = anomaly_reasons or []

        if mode == "supplement":
            return await self._decompose_supplement(
                event, session_id, anomaly_score, missed_threats
            )

        # ── 首次审核（full mode） ──
        depth = _rule_based_depth(event, anomaly_score)
        depth_reason = (
            f"severity={severity}, anomaly_score={anomaly_score:.3f}"
        )
        # triage 车道可覆盖规则深度(P0→deep / P3→quick)
        triage = event.get("_audit_triage") or {}
        force_depth = str(triage.get("force_depth") or "").lower()
        if force_depth in (AUDIT_DEPTH_QUICK, AUDIT_DEPTH_STANDARD, AUDIT_DEPTH_DEEP):
            if force_depth != depth:
                depth_reason += f", triage_override={force_depth}(was {depth})"
            depth = force_depth

        logger.info(
            f"Decomposer(full): depth={depth} type={event_type} "
            f"src={src_ip} score={anomaly_score:.3f} "
            f"tier={triage.get('tier', '')} lane={triage.get('lane', '')}"
        )

        llm_analysis = ""
        # 阶段4B(2026-11-09): deep 档 LLM 真决策 —— 规划器输出直接决定取证子任务集合。
        # 失败/超时/schema 不过 → selected=None 回退规则模板(可解释降级)。
        _selected: "list[str] | None" = None
        plan_source = "rules"
        # 硬预算下 P0 仍 deep,但可跳过昂贵 pre-analyze(保留 SubAuditor+synthesize)
        _sig = triage.get("signals") or {}
        _skip_pre = bool(triage.get("skip_pre_analyze") or _sig.get("skip_pre_analyze"))
        if depth == AUDIT_DEPTH_DEEP and not _skip_pre:
            plan = await self._llm_plan_subtasks(event, anomaly_score, anomaly_reasons)
            if plan is not None:
                _selected, llm_analysis = plan
                plan_source = "llm"
            else:
                llm_analysis = await self._llm_pre_analyze(event, anomaly_score, anomaly_reasons)
                plan_source = "rules_fallback"

        depth_to_tasks = {
            AUDIT_DEPTH_QUICK: _get_subtasks_quick,
            AUDIT_DEPTH_STANDARD: _get_subtasks_standard,
            AUDIT_DEPTH_DEEP: _get_subtasks_deep,
        }
        task_fn = depth_to_tasks.get(depth, _get_subtasks_standard)
        if depth == AUDIT_DEPTH_DEEP and _selected is not None:
            sub_tasks = task_fn(session_id, event, anomaly_score, selected=_selected)
        else:
            sub_tasks = task_fn(session_id, event, anomaly_score)

        logger.info(
            f"Decomposer(full): {len(sub_tasks)} sub-tasks plan_source={plan_source}"
        )

        return {
            "audit_depth": depth,
            "sub_tasks": [st.to_dict() for st in sub_tasks],
            "llm_analysis": llm_analysis,
            "depth_reason": depth_reason,
            "mode": "full",
            # 规划溯源: llm=LLM 挑选取证面 / rules=quick|standard 或未启用 /
            # rules_fallback=deep 档 LLM 规划失败回退模板
            "plan_source": plan_source,
            "planning": {
                "source": plan_source,
                "selected": _selected or [],
                "evidence_keys": _DEEP_EVIDENCE_KEYS,
                "notes": llm_analysis if plan_source == "llm" else "",
            },
        }

    async def _decompose_supplement(
        self,
        event: dict,
        session_id: str,
        anomaly_score: float,
        missed_threats: list[dict],
    ) -> dict:
        """
        补审模式：只针对遗漏的威胁生成子任务
        """
        logger.info(
            f"Decomposer(supplement): {len(missed_threats)} missed threats to re-audit"
        )

        tasks = []
        idx = 0

        # 从遗漏威胁中提取需要关注的事件ID和IP
        target_ids = set()
        target_ips = set()
        for mt in missed_threats:
            desc = mt.get("description", "")
            evidence = mt.get("evidence", "")
            # 尝试从evidence中提取事件ID
            for part in evidence.split(","):
                part = part.strip()
                if part.isdigit():
                    target_ids.add(int(part))
            # 尝试从description中提取IP
            import re
            ips = re.findall(r'\d+\.\d+\.\d+\.\d+', desc)
            target_ips.update(ips)

        # P3-6: 事件ID 侧原本**没有任何上界**，而同一个循环里的 IP 侧写着 [:3]。
        # evidence 是 LLM 自由文本，一个逗号分隔的 blob 能被放大到任意规模
        # （实测 5000 个 ID），而下游 limit 被设成 len(target_ids) ——
        # 等于把上界直接拱手让给输入长度。
        #
        # 这里**截断并留痕**，而不是拒绝：
        # 规划层为一个超大的 evidence blob 中止整个补审批次代价过大，
        # 截断后这次补审仍能跑完 —— 代价是它只覆盖了一部分，
        # 所以 truncation 必须显式出现在返回的 plan 里，不能只写日志。
        param_truncations = []
        # 延迟导入：与 tool_registry._check_query_bounds 同一理由，
        # capacity 会经 agents 侧回引，模块级导入会形成环。
        from capacity import strict_int_setting

        _max_ids = strict_int_setting("tool_query_max_event_ids", 500)
        if len(target_ids) > _max_ids:
            requested = len(target_ids)
            target_ids = set(sorted(target_ids)[:_max_ids])
            param_truncations.append({
                "field": "event_ids", "requested": requested,
                "used": len(target_ids), "limit": _max_ids,
            })
            logger.warning(
                f"Decomposer(supplement): evidence 中的事件ID {requested} 个"
                f"超过上界 {_max_ids}，已截断 —— 本次补审只覆盖前 {_max_ids} 个"
            )

        # t1: 按ID精确查询遗漏事件
        if target_ids:
            idx += 1
            tasks.append(SubTask(
                task_id=f"s{idx}",
                type=SUBTASK_QUERY_EVENTS,
                params={
                    "session_id": session_id,
                    # 排序：集合转列表不排序，顺序随进程哈希种子变
                    # （§9.59）。此处元素是整数，跨进程本就稳定，
                    # 但要与下面 description 里的 sorted(...) 保持一致 ——
                    # 「计划里写的」和「参数里传的」必须是同一个顺序。
                    "event_ids": sorted(target_ids),
                    "limit": len(target_ids),
                },
                priority=5,
                description=f"精确查询遗漏事件 ID={sorted(target_ids)}",
            ))

        # t2: 查询遗漏IP的完整活动
        #
        # IP 侧也有上限（[:3]），而上限必须**留痕** —— 同一个函数里
        # event_ids 的截断写进了 param_truncations，IP 的截断却一个字
        # 都没有，于是「本次补审只覆盖了 3 个 IP」对运维是不可见的。
        #
        # 更糟的是**选哪 3 个**：IP 是字符串，字符串哈希每进程随机，
        # `list(target_ips)[:3]` 取到的是任意 3 个 → 同一份证据在不同
        # 进程里查出不同的 IP，补审覆盖到谁变成一枚骰子。
        #
        # 现在按字典序取前 3 个：确定、可解释（缺谁、按什么顺序都能从
        # 计划里读出来），并把丢弃的数量记进 param_truncations。
        _max_ips = 3
        sorted_ips = sorted(target_ips)
        if len(sorted_ips) > _max_ips:
            param_truncations.append({
                "field": "src_ips", "requested": len(sorted_ips),
                "used": _max_ips, "limit": _max_ips,
            })
            logger.warning(
                f"Decomposer(supplement): 遗漏IP {len(sorted_ips)} 个"
                f"超过上界 {_max_ips}，已按字典序取前 {_max_ips} 个 —— "
                f"本次补审不覆盖其余 {len(sorted_ips) - _max_ips} 个"
            )
        for ip in sorted_ips[:_max_ips]:
            idx += 1
            tasks.append(SubTask(
                task_id=f"s{idx}",
                type=SUBTASK_QUERY_EVENTS,
                params={
                    "session_id": session_id,
                    "src_ip": ip,
                    "time_window_minutes": 1440,
                    "limit": 100,
                },
                priority=4,
                description=f"遗漏IP {ip} 的24小时活动",
            ))

        # t3: 如果连IP和ID都没有，扩大时间窗口重查
        if not target_ids and not target_ips:
            idx += 1
            tasks.append(SubTask(
                task_id=f"s{idx}",
                type=SUBTASK_QUERY_EVENTS,
                params={
                    "session_id": session_id,
                    "time_window_minutes": 2880,
                    "limit": 200,
                },
                priority=3,
                description="扩大窗口至48小时重查所有事件",
            ))

        # t4: 攻击链补查
        idx += 1
        tasks.append(SubTask(
            task_id=f"s{idx}",
            type=SUBTASK_FIND_CHAINS,
            params={"session_id": session_id, "time_window_minutes": 2880},
            priority=3,
            description="扩大窗口攻击链补查",
        ))

        return {
            "audit_depth": "supplement",
            "sub_tasks": [st.to_dict() for st in tasks],
            "llm_analysis": "",
            "depth_reason": f"补审 {len(missed_threats)} 项遗漏威胁",
            "mode": "supplement",
            # P3-6: 非空表示本次计划因参数上界做过裁剪。
            # 消费端是 observability.thought_events.emit_plan —— 它把这个字段
            # 写进思维链 step 的 metrics，随缓冲与 SSE 落到运维面。
            # （最初只把它留在返回 dict 里，而 emit_plan 当时只挑固定字段，
            #   记录下游无人可读，等同于只打了日志；已补上接线。）
            "param_truncations": param_truncations,
        }

    async def _llm_pre_analyze(
        self, event: dict, anomaly_score: float,
        anomaly_reasons: list[str],
    ) -> str:
        """LLM 对事件的初步分析（仅深度审核）"""
        event_json = json.dumps(event, ensure_ascii=False, indent=2)
        reasons_str = "\n".join(anomaly_reasons) if anomaly_reasons else "无"

        from prompts import render
        prompt = render(
            "audit/decomposer_initial_analysis",
            event_json=event_json,
            anomaly_score=anomaly_score,
            reasons_str=reasons_str,
        )

        # D3: 统一使用 self.llm_chat（继承自 BaseAuditComponent）
        # 原 set_trace_context 调用已合并到 llm_chat，避免重复设置
        result = await self.llm_chat([
            {"role": "system", "content": render("audit/decomposer_initial_analysis_system")},
            {"role": "user", "content": prompt},
        ])
        return result

    async def _llm_plan_subtasks(
        self, event: dict, anomaly_score: float,
        anomaly_reasons: list[str],
    ) -> "tuple[list[str], str] | None":
        """deep 档 LLM 规划(2026-11-09 阶段4B): 让 LLM 真正决定取证子任务集合。

        返回 (selected_keys, planning_notes); 失败/超时/schema 不过 → None(回退规则模板)。
        约束(见 _get_subtasks_deep): 只能在取证类能力键中挑选,
        deep_analyze 与 review 由代码强制保留 —— LLM 只能裁剪取证面, 不能拆安全底线。
        """
        from pydantic import BaseModel, ValidationError

        class _PlannedTask(BaseModel):
            capability: str
            reason: str = ""

        class _Plan(BaseModel):
            sub_tasks: list[_PlannedTask]
            planning_notes: str = ""

        event_json = json.dumps(event, ensure_ascii=False, indent=2)
        reasons_str = "\n".join(anomaly_reasons) if anomaly_reasons else "无"
        from prompts import render
        prompt = render(
            "audit/decomposer_planning",
            event_json=event_json,
            anomaly_score=anomaly_score,
            reasons_str=reasons_str,
        )
        raw = await self.llm_chat([
            {"role": "system", "content": render("audit/decomposer_planning_system")},
            {"role": "user", "content": prompt},
        ])
        # 降级标记(预算耗尽/无 key)不是可解析输出 —— 交由上层回退
        if not raw or "fallback" in raw[:60]:
            return None

        from audit_schemas import extract_json
        data = extract_json(raw)
        if not isinstance(data, dict):
            return None
        try:
            plan = _Plan.model_validate(data)
        except ValidationError:
            return None

        known = set(_DEEP_EVIDENCE_KEYS)
        selected = [t.capability for t in plan.sub_tasks if t.capability in known]
        if not selected:
            return None
        return selected, plan.planning_notes


decomposer = Decomposer()
