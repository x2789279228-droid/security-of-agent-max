"""
统一工具注册入口 (ToolRegistry)

为 Audit-LLM 的 Tool Builder 和 Executor 提供统一工具接口。
所有工具函数在此注册，Tool Builder 通过工具名称查找，Executor 通过名称调用。

设计原则：
  - 每个工具是一个异步函数，接收 **kwargs
  - 工具注册时附带元信息（参数描述、返回类型、预估耗时）
  - Executor 根据工具信息做并行调度决策

初始化策略:
  - D2 改造：模块加载时仍自动调 init_tool_registry() 保持向后兼容
  - 加 _initialized 守门防止重复注册与日志噪音
  - 显式 init_tool_registry() 调用幂等（多次调用只首次注册）
"""
import asyncio
import logging
import time
from typing import Any, Callable, Coroutine, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from event_store import event_store, EventFilter
from anomaly_detector import anomaly_detector
from correlation_engine import correlation_engine
from vector_store import vector_store
from memory_tree import memory_tree
from sliding_window import sliding_window
from summary_compression import embedder

logger = logging.getLogger(__name__)


# ── P2-B-4: 工具执行并发闸 ──
# 修复前 Executor 的两处 asyncio.gather 既无 Semaphore 也无 wait_for：
# 一批工具里只要有一个挂死，整轮审计就再也回不来。
# 复用 capacity.BoundedGate —— 与 db_write / kafka_produce 同一套机制，
# 配置与快照都进 /capacity 观测面，不另造一套概念。
def tool_exec_gate():
    """工具执行的并发上限闸（延迟导入，避免与 capacity 形成导入环）。"""
    from capacity import _float_setting, _gate, _int_setting

    return _gate(
        "tool_exec",
        lambda: _int_setting("tool_exec_max_concurrency", 8),
        lambda: _float_setting("tool_exec_admit_timeout_s", 5.0),
    )

# ── P0-B-2/B-3: 工具风险等级 ──
# low    = 只读查询，无副作用
# medium = 有外部调用但不改状态
# high   = 可能产生副作用 / 影响生产
#
# 注册默认值刻意取 **high**（fail-secure）：新增工具若未显式声明风险等级，
# 在行为检测器异常时一律拒绝执行，而不是默认放行。
# 已显式声明为 low 的都是只读查询工具，它们在检测器故障时降级放行并告警。
RISK_HIGH = "high"
RISK_MEDIUM = "medium"
RISK_LOW = "low"

# 失败关闭口径：medium 及以上一律拒绝；只有显式声明为 low 的纯只读工具
# 才允许在检测器故障时降级放行。降级必须显式配置，不能因异常处理方便而默认放行。
_FAIL_CLOSED_RISKS = {RISK_MEDIUM, RISK_HIGH, "critical"}


class ToolExecutionDenied(Exception):
    """P0-B-2: 必经检查未通过时的拒绝。

    独立异常类型，使调用方能区分「策略拒绝」与「工具自身报错」——
    后者属于业务失败，不应被当成安全拒绝。
    """

    def __init__(self, reason: str, check: str = "pre_execute"):
        super().__init__(reason)
        self.reason = reason
        self.check = check


class ToolExecutionTimeout(Exception):
    """P2-B-4: 工具执行超过注册时声明的 ``timeout_ms``。

    修复前 ``timeout_ms`` 只被存进注册表，从未被读取 ——
    一个挂死的工具协程会永久占住 Executor 的 ``asyncio.gather``，
    整条审计流水线的这一轮就再也回不来，且没有任何日志说明它在等什么。

    与 ``ToolExecutionDenied`` 分开：超时不是安全拒绝，是可用性问题。
    """

    def __init__(self, name: str, timeout_ms: int):
        super().__init__(f"tool {name} exceeded timeout {timeout_ms}ms")
        self.tool = name
        self.timeout_ms = int(timeout_ms)


class ToolParameterRejected(Exception):
    """P3-6: 工具参数越界。

    独立异常类型，与 ``ToolExecutionDenied`` / ``ToolExecutionTimeout`` 同构 ——
    「参数不合法」既不是安全策略拒绝，也不是工具崩溃，
    混进同一个 success=False 会让上层无法区分「拒绝执行」与「参数被拒」。

    为什么是**拒绝**而不是截断：
    ``event_ids`` 是精确过滤条件，截到上界就等于只查了一部分，
    而上层会把这次补审记成「已复核该遗漏威胁」——
    那是一份无法从结果里看出来的假保证。
    宁可让这次工具调用显式失败、把威胁留在「已遗漏」的可见状态。
    """

    def __init__(self, name: str, field: str, value, limit):
        super().__init__(
            f"tool {name}: {field}={value!r} 超过上界 {limit}"
        )
        self.tool = name
        self.field = field
        self.value = value
        self.limit = limit


def _check_query_bounds(
    tool: str, *, limit=None, event_ids=None,
) -> None:
    """P3-6: 查询类工具的参数上界校验，越界即抛 ``ToolParameterRejected``。

    判定规则本身在 ``capacity.check_query_bounds`` —— 与规则沙箱
    ``rule_manager.sandbox_test`` 共用同一份，两处的上界不会各自漂移。
    这里只负责把「判定结果」翻译成工具契约的异常。
    延迟导入 capacity 以避免导入环，与 ``tool_exec_gate`` 同一写法。
    """
    from capacity import check_query_bounds

    violation = check_query_bounds(limit=limit, event_ids=event_ids)
    if violation is not None:
        field, value, bound = violation
        raise ToolParameterRejected(tool, field, value, bound)


def _pre_execute_check(name: str, tool_meta: dict, args: dict) -> dict:
    """工具执行前的必经检查（P0-B-2/B-3）。

    这是审计链路唯一进入 ``tool_registry.execute`` 的入口，因此这里是
    插入策略检查的正确位置 —— 修复前本函数体只有一次 ``self._tools.get``，
    随后直接 await 工具函数，RBAC / 参数校验 / 规则引擎 / 行为签名全部缺席。

    当前实现（P3-1 收敛后）：
      1. 注册表成员校验 —— 未知工具直接拒绝，不做模糊匹配
      2. 风险等级判定   —— 决定检测器故障时是失败关闭还是降级放行
      3. 行为签名处置   —— 与 MCP Guard 共用 `escalate_decision` 一份规则：
                          deny 真正拒绝；require_confirmation 按记录放行并
                          显式标注（审计命名空间无内联审批通道）；logged 只打分

    P3-1 之前的形态是「影子/打分模式只记录不拦截」：签名分数被拼进 reason
    字符串后无条件 passed=True，使 `tool_signature_mode=deny` 对全部审计工具
    失效 —— 策略在一处配置、两处执行，其中一处根本没接线。

    Returns:
        {"passed": bool, "reason": str, "check": str, "signature": dict|None}

    Raises:
        本函数不抛异常；检查不通过时返回 passed=False，由调用方决定拒绝。
    """
    risk = str(tool_meta.get("risk_level") or RISK_HIGH).lower()
    fail_closed = risk in _FAIL_CLOSED_RISKS

    # 1) 行为签名打分（复用 MCP Guard 检测器，失败按风险等级处置）
    signature = None
    try:
        from mcp_guard import mcp_guard
        detector = getattr(mcp_guard, "detector", None)
    except Exception as e:  # Guard 模块不可用
        logger.warning("pre_exec_check: mcp_guard unavailable for %s: %s", name, e)
        detector = None

    if detector is None:
        if fail_closed:
            return {
                "passed": False,
                "check": "pre_exec_signature",
                "reason": f"行为检测器不可用，风险等级={risk}，按失败关闭拒绝",
                "signature": None,
            }
        return {
            "passed": True,
            "check": "pre_exec_signature",
            "reason": "行为检测器不可用；只读工具降级放行",
            "signature": None,
        }

    try:
        from mcp_guard.call_record import ToolCallRecord
        safe_args = {
            k: v for k, v in dict(args or {}).items()
            if k != "session" and not str(k).startswith("_")
        }
        rec = ToolCallRecord.from_kwargs(
            user_role="system",
            tool_name=name,
            arguments=safe_args,
            decision="allow",
            reason="pre_execute_check",
            caller="tool_registry",
            source="audit_llm",
        )
        signature = detector.observe_pre_exec(rec)
    except Exception as e:
        logger.warning("pre_exec_check: signature failed for %s: %s", name, e)
        if fail_closed:
            return {
                "passed": False,
                "check": "pre_exec_signature",
                "reason": f"行为签名检测异常，风险等级={risk}，按失败关闭拒绝: {e}",
                "signature": None,
            }
        return {
            "passed": True,
            "check": "pre_exec_signature",
            "reason": f"行为签名检测异常；只读工具降级放行: {e}",
            "signature": None,
        }

    # 检测器正常返回：按统一策略处置（P3-1）
    #
    # 修复前这里无论检测器判定什么都 passed=True，只把分数拼进 reason 字符串，
    # 于是 MCP Guard 的 _apply_enforcement 在审计侧**没有对应执行点** ——
    # 运维把 tool_signature_mode 配成 deny 之后，响应侧工具会拦，
    # 11 个审计工具一个都不会拦。实测同一份 action="deny" 的报告：
    #   MCP Guard 侧最终决策=deny；本函数 passed=True（reason 仅「score=0.97」）。
    #
    # 现在两个执行点共用 mcp_guard.behavior_detector.escalate_decision 一份规则。
    try:
        from mcp_guard.behavior_detector import escalate_decision
        escalated, why = escalate_decision("allow", signature)
    except Exception as e:
        # 升级规则本身不可用：按风险等级失败关闭，不静默放行
        logger.warning("pre_exec_check: escalate_decision unavailable for %s: %s", name, e)
        if fail_closed:
            return {
                "passed": False,
                "check": "pre_exec_signature",
                "reason": f"策略升级规则不可用，风险等级={risk}，按失败关闭拒绝: {e}",
                "signature": signature.to_dict() if signature is not None else None,
            }
        return {
            "passed": True,
            "check": "pre_exec_signature",
            "reason": f"策略升级规则不可用；只读工具降级放行: {e}",
            "signature": signature.to_dict() if signature is not None else None,
        }

    sig_dict = signature.to_dict() if signature is not None else None

    if escalated == "deny":
        # 强信号：策略明确要求拒绝。这里必须真的拒绝 ——
        # 「拒绝」如果在这条路径上退化成记录，就等于策略旋钮是装饰。
        return {
            "passed": False,
            "check": "pre_exec_signature",
            "reason": f"行为签名判定拒绝执行: {why}",
            "signature": sig_dict,
        }

    if escalated == "require_confirmation":
        # 审计命名空间没有内联审批通道：execute() 是流水线上的必经 await 点，
        # 挂起等人工确认在这里没有落点（审批队列属于响应侧那套执行模型）。
        # 因此按记录放行，但**必须把「策略要求确认」显式写进 reason** ——
        # 静默忽略一个已生效的策略，与没有这条策略不可区分。
        # 说明：tool_signature_mode 默认就是 confirm，且只读查询在真实攻击流量上
        # 本就会频繁偏离指纹，所以 confirm 不改判 deny（否则会系统性打断审计）。
        return {
            "passed": True,
            "check": "pre_exec_signature",
            "reason": (
                f"行为签名要求确认: {why}；"
                f"审计命名空间不支持内联审批，按记录放行待人工复核"
            ),
            "signature": sig_dict,
        }

    return {
        "passed": True,
        "check": "pre_exec_signature",
        "reason": (
            f"行为签名 score={signature.anomaly_score}"
            if signature is not None else "无签名报告"
        ),
        "signature": sig_dict,
    }


class ToolRegistry:
    """
    工具注册表

    用法:
        registry = ToolRegistry()
        result = await registry.execute("event_store.query",
                                         session=session,
                                         session_id="xxx",
                                         src_ip="10.0.0.5")
    """

    def __init__(self):
        self._tools: dict[str, dict] = {}
        # D2: 守门标志 — init_tool_registry() 只首次生效，幂等
        self._initialized = False

    def register(
        self,
        name: str,
        fn: Callable[..., Coroutine],
        description: str = "",
        category: str = "data",
        estimated_ms: int = 100,
        timeout_ms: int = 30000,
        risk_level: str = RISK_HIGH,
    ):
        """注册一个工具

        risk_level 默认 high（fail-secure）：未显式声明风险等级的新工具，
        在行为检测器异常时会被拒绝执行。只读查询工具应显式传 risk_level="low"。
        """
        self._tools[name] = {
            "fn": fn,
            "description": description,
            "category": category,   # "data" | "analysis" | "search"
            "estimated_ms": estimated_ms,
            "timeout_ms": timeout_ms,
            "risk_level": risk_level,
        }
        logger.info(f"Registered tool: {name} ({category}, risk={risk_level})")

    async def execute(self, name: str, **kwargs) -> Any:
        """执行工具调用（P0-B-2：这里是审计链路进入工具的唯一必经点）

        P2-B-4: 强制 ``timeout_ms`` 并施加并发上限。
        修复前本方法只 await 工具函数：注册表里那个 timeout_ms 是死字段，
        ``asyncio.gather`` 也没有 Semaphore / wait_for，
        所以 N 个慢工具可以无限期并行挂着，一轮审计永不返回。
        """
        tool = self._tools.get(name)
        if not tool:
            # 未知工具：拒绝，且**不做任何模糊匹配**（防幻觉工具被"纠正"成近似名）
            raise ValueError(f"Unknown tool: {name}")

        # 必经安全检查（P0-B-2/B-3）。修复前此处无任何检查直接 await 工具函数。
        check = _pre_execute_check(name, tool, kwargs)
        if not check["passed"]:
            raise ToolExecutionDenied(check["reason"], check["check"])

        timeout_ms = int(tool.get("timeout_ms") or 0)
        start = time.time()

        # 并发闸：限制同时在跑的工具数。闸本身可配置、可观测，
        # 复用 capacity.BoundedGate（与 db_write/kafka_produce 同一套机制）。
        gate = tool_exec_gate()
        try:
            async with gate.acquire():
                try:
                    if timeout_ms > 0:
                        result = await asyncio.wait_for(
                            tool["fn"](**kwargs), timeout=timeout_ms / 1000
                        )
                    else:
                        result = await tool["fn"](**kwargs)
                except asyncio.TimeoutError as te:
                    duration = (time.time() - start) * 1000
                    logger.error(
                        f"Tool {name} timed out after {duration:.0f}ms "
                        f"(limit {timeout_ms}ms)"
                    )
                    raise ToolExecutionTimeout(name, timeout_ms) from te
                except asyncio.CancelledError:
                    # P2-B-4: 取消必须向上传播，不能被 except Exception 吞成
                    # 「工具失败」。静默降级会让上层以为只是工具出错，
                    # 而实际上整个流水线已被要求停止。
                    logger.warning(f"Tool {name} cancelled after "
                                   f"{(time.time() - start) * 1000:.0f}ms")
                    raise
                except Exception:
                    duration = (time.time() - start) * 1000
                    logger.error(f"Tool {name} failed after {duration:.0f}ms")
                    raise
        except (ToolExecutionDenied, ToolExecutionTimeout):
            raise
        except Exception as e:
            if type(e).__name__ == "GateTimeout":
                duration = (time.time() - start) * 1000
                logger.error(
                    f"Tool {name} not admitted by concurrency gate after {duration:.0f}ms"
                )
                raise ToolExecutionTimeout(name, timeout_ms or 0) from e
            raise

        duration = (time.time() - start) * 1000
        logger.info(f"Tool {name} completed in {duration:.0f}ms")
        return result

    def risk_level(self, name: str) -> str:
        """查询工具风险等级（未注册返回 high，保持 fail-secure）。"""
        tool = self._tools.get(name)
        return str((tool or {}).get("risk_level") or RISK_HIGH).lower()

    def get_info(self, name: str) -> Optional[dict]:
        """获取工具元信息"""
        return self._tools.get(name)

    def list_tools(self, category: str = "") -> list[str]:
        """列出所有工具，可选按类别筛选"""
        if category:
            return [
                n for n, t in self._tools.items()
                if t["category"] == category
            ]
        return list(self._tools.keys())

    def estimate_duration(self, names: list[str]) -> int:
        """估算一组工具的总执行时间（用于并行调度决策）"""
        total = 0
        for name in names:
            tool = self._tools.get(name)
            if tool:
                total += tool["estimated_ms"]
        return total


# ── 全局单例 ──

tool_registry = ToolRegistry()


# ── 工具实现（注册到 registry） ──

async def _event_store_query(
    session: AsyncSession,
    session_id: str = "",
    src_ip: str = "",
    dst_ip: str = "",
    event_type: str = "",
    severity: str = "",
    event_ids: list[int] = None,
    limit: int = 100,
    time_window_minutes: int = 0,
) -> list[dict]:
    """查询完整原始事件

    P3-6: 入口处校验参数上界。
    修复前本函数体没有任何边界检查 ——
    ``limit`` 原样装进 EventFilter 透传给 event_store.query，
    而 ``event_ids`` 分支**连 limit 都不看**，直接 ``.scalars().all()``。
    两者都可经 ``missed_threats[].evidence`` 自由文本被 LLM 放大到任意规模
    （实测 5000 个逗号分隔 ID 会一路走到这里）。
    """
    from datetime import datetime, timezone, timedelta

    _check_query_bounds("event_store.query", limit=limit, event_ids=event_ids)

    # 如果传入了 event_ids，按 ID 精确查询
    if event_ids:
        from sqlalchemy import select
        from models import SecurityEvent
        stmt = select(SecurityEvent).where(SecurityEvent.id.in_(event_ids))
        result = await session.execute(stmt)
        events = result.scalars().all()
        return [
            {
                "id": e.id, "event_type": e.event_type,
                "severity": e.severity, "src_ip": e.src_ip or "",
                "dst_ip": e.dst_ip or "", "message": (e.message or "")[:200],
                "anomaly_score": (e.raw_data or {}).get("_anomaly_score", 0.0),
                "created_at": e.created_at.isoformat() if e.created_at else "",
            }
            for e in events
        ]

    time_start = None
    if time_window_minutes > 0:
        time_start = datetime.now(timezone.utc) - timedelta(minutes=time_window_minutes)
    events = await event_store.query(
        session, EventFilter(
            session_id=session_id,
            src_ip=src_ip,
            dst_ip=dst_ip,
            event_type=event_type,
            severity=severity,
            time_start=time_start,
            limit=limit,
        )
    )
    return [
        {
            "id": e.id,
            "event_type": e.event_type,
            "severity": e.severity,
            "src_ip": e.src_ip,
            "dst_ip": e.dst_ip,
            "message": e.message[:200],
            "anomaly_score": e.anomaly_score,
            "created_at": e.created_at,
        }
        for e in events
    ]


async def _anomaly_baseline(session_id: str = "", src_ip: str = "", **kwargs) -> dict:
    """获取实体的异常检测基线"""
    # anomaly_detector 维护着内存基线，直接查询
    bl = anomaly_detector.baselines.get("src_ip", {}).get(src_ip)
    if not bl:
        return {"src_ip": src_ip, "status": "no_baseline"}
    return {
        "src_ip": src_ip,
        "total_count": bl.total_count,
        "first_seen": bl.first_seen,
        "last_seen": bl.last_seen,
        "hourly_distribution": bl.hourly_counts,
        # 排序：这是**给 LLM 看的**工具输出。集合不排序 → 同一份
        # 基线在不同进程里给出不同的顺序 → 工具输出不可复现
        # （§9.59）。注意 §9.58 修过本文件的另一处集合转列表，
        # 但那次扫描只认「list(set(...))」字面形态，漏了这一处。
        "event_types": sorted(bl.event_types),
    }


async def _correlation_chains(
    session: AsyncSession,
    session_id: str = "",
    time_window_minutes: int = 1440,
) -> list[dict]:
    """获取攻击链"""
    result = await correlation_engine.analyze(
        session, session_id, time_window_minutes=time_window_minutes
    )
    chains = [
        {
            "chain_id": c.chain_id,
            "pattern_name": c.pattern_name,
            "confidence": c.confidence,
            "event_ids": [e["id"] for e in c.events],
            "events": [{"id": e["id"], "event_type": e.get("event_type")} for e in c.events],
            "time_span_minutes": c.time_span_minutes,
            "alert": c.alert,
            # 共享事件标记（整改方案 §八「下游不得把同一事件算成两份证据」）。
            # 引擎已经算好了这两个字段，但此前**没有出现在载荷里** ——
            # 于是「不能按链累加」这件事对下游（以及读这条链的 LLM）不可见。
            "shared_event_ids": list(getattr(c, "shared_event_ids", []) or []),
            "overlaps_other_chain": bool(getattr(c, "overlaps_other_chain", False)),
        }
        for c in result.chains
    ]
    try:
        from causal_chain.store import latest_graph
        from causal_chain.learn import annotate_chains
        g = await latest_graph(session)
        if g:
            chains = annotate_chains(chains, g, data=None)
    except Exception:
        pass
    return chains


async def _causal_graph(session: AsyncSession, **_kw) -> dict:
    from causal_chain.store import latest_graph
    g = await latest_graph(session)
    return g or {"ok": False, "reason": "no_graph", "directed": []}


async def _correlation_temporal(
    session: AsyncSession,
    session_id: str = "",
    time_window_minutes: int = 60,
) -> list[dict]:
    """获取时间窗口事件分组"""
    from datetime import datetime, timezone, timedelta
    from sqlalchemy import select
    from models import SecurityEvent

    cutoff = datetime.now(timezone.utc) - timedelta(minutes=time_window_minutes)
    stmt = (
        select(SecurityEvent)
        .where(
            SecurityEvent.session_id == session_id,
            SecurityEvent.created_at >= cutoff,
        )
        .order_by(SecurityEvent.created_at)
    )
    result = await session.execute(stmt)
    events = result.scalars().all()

    # 按 IP 分组
    from collections import defaultdict
    by_ip = defaultdict(list)
    for evt in events:
        by_ip[evt.src_ip or "unknown"].append({
            "id": evt.id, "type": evt.event_type, "severity": evt.severity,
            "src_ip": evt.src_ip, "created_at": evt.created_at.isoformat(),
        })

    groups = []
    for ip, ip_events in by_ip.items():
        if len(ip_events) >= 2:
            groups.append({
                "src_ip": ip,
                "count": len(ip_events),
                # 2026-10-20 修复（整改报告 §9.58）：排序 → 输出可复现
                "types": sorted({e["type"] for e in ip_events}),
                "events": ip_events,
            })

    return groups[:20]


async def _correlation_entity_link(
    session: AsyncSession,
    session_id: str = "",
    time_window_minutes: int = 1440,
) -> list[dict]:
    """获取实体图关联"""
    result = await correlation_engine.analyze(
        session, session_id, time_window_minutes=time_window_minutes
    )
    return result.entity_links


async def _vector_search(
    session: AsyncSession,
    query: str = "",
    top_k: int = 5,
) -> list[dict]:
    """向量检索语义相关记忆（memories 表，通用记忆）

    note: agent 记忆是自指语义(doc 与 query 同源), 保持 db-db 对称编码, 与写入端一致;
    不对称检索(query vs db)仅适用于 knowledge 知识库这类"文档↔自然语言问题"场景。"""
    embedding = await embedder.embed(query)
    memories = await vector_store.search_similar(
        session, embedding, top_k=top_k, for_llm=True,
    )
    from memory_guard import memory_trust_value
    return [
        {"id": m.id, "content": m.content[:200], "agent_id": m.agent_id,
         "created_at": m.created_at.isoformat(),
         "trust": memory_trust_value(m),
         "source_type": getattr(m, "source_type", "") or "",
         }
        for m in memories
    ]


async def _knowledge_search(
    session: AsyncSession,
    query: str = "",
    threat_type: str = "",
    severity: str = "",
    top_k: int = 5,
    **kwargs,
) -> list[dict]:
    """检索安全知识库（knowledge_chunks 表，MITRE ATT&CK / CAPEC / 预置知识）"""
    from rag import retriever as rag_retriever

    result = await rag_retriever.retrieve(
        session,
        query=query,
        query_embedding=None,
        threat_type=threat_type,
        severity=severity,
        top_k=top_k,
        min_score=0.4,
    )

    return [
        {
            "id": c["id"],
            "chunk_id": c.get("chunk_id") or c.get("id"),
            "title": c.get("title", ""),
            "content": c.get("content", ""),
            "source": c.get("source", ""),
            "threat_types": c.get("threat_types", []),
            "severity": c.get("severity", ""),
            "score": c.get("score", 0),
            "strategy": c.get("strategy", ""),
        }
        for c in result.chunks
    ]


async def _memory_tree_related(
    session: AsyncSession,
    session_id: str = "",
    src_ip: str = "",
    event_type: str = "",
    time_window_minutes: int = 60,
) -> list[dict]:
    """获取记忆树关联事件"""
    return await memory_tree.find_related(
        session, session_id,
        src_ip=src_ip, event_type=event_type,
        time_window_minutes=time_window_minutes,
    )


async def _sliding_window_get(session_id: str = "", **kwargs) -> list[dict]:
    """获取滑动窗口近期上下文"""
    return await sliding_window.get_window(session_id)


async def _sliding_window_evicted(session_id: str = "", limit: int = 50, **kwargs) -> list[dict]:
    """获取被滑窗淘汰的历史消息"""
    return await sliding_window.get_evicted(session_id, limit=limit)


# ── 注册所有工具 ──

def init_tool_registry():
    """初始化并注册所有可用工具

    D2 改造：加 _initialized 守门，使该函数幂等
    - 多次调用只首次注册，避免日志噪音和重复覆盖
    - reload 时仍可强制触发：手动重置 tool_registry._initialized = False 后再调
    """
    if tool_registry._initialized:
        logger.debug(
            f"Tool registry already initialized "
            f"({len(tool_registry._tools)} tools) — skipping re-registration"
        )
        return

    tool_registry.register(
        "event_store.query", _event_store_query,
        description="查询完整原始事件（支持按IP/类型/严重度/时间窗口筛选）",
        category="data", estimated_ms=50,
        risk_level=RISK_LOW,
    )
    tool_registry.register(
        "anomaly.baseline", _anomaly_baseline,
        description="获取源IP的异常检测基线（历史行为统计）",
        category="data", estimated_ms=10,
        risk_level=RISK_LOW,
    )
    tool_registry.register(
        "correlation.chains", _correlation_chains,
        description="攻击链模式匹配（检测已知攻击路径）",
        category="analysis", estimated_ms=200,
        risk_level=RISK_LOW,
    )
    tool_registry.register(
        "causal.graph", _causal_graph,
        description="最近一次 PC/GES 因果图(只读,不得作为封禁依据)",
        category="analysis", estimated_ms=50,
        risk_level=RISK_LOW,
    )
    tool_registry.register(
        "correlation.temporal", _correlation_temporal,
        description="时间窗口事件分组（同IP短时内事件聚合）",
        category="analysis", estimated_ms=100,
        risk_level=RISK_LOW,
    )
    tool_registry.register(
        "correlation.entity_link", _correlation_entity_link,
        description="实体图关联（通过共同目标发现关联源IP）",
        category="analysis", estimated_ms=200,
        risk_level=RISK_LOW,
    )
    tool_registry.register(
        "vector.search", _vector_search,
        description="向量检索语义相关的历史记忆（memories 表）",
        category="search", estimated_ms=300,
        risk_level=RISK_LOW,
    )
    tool_registry.register(
        "knowledge.search", _knowledge_search,
        description="检索安全知识库（MITRE ATT&CK / CAPEC / 威胁情报），支持按威胁类型过滤 + LLM 重排",
        category="search", estimated_ms=500,
        risk_level=RISK_LOW,
    )
    tool_registry.register(
        "memory_tree.related", _memory_tree_related,
        description="查找与事件关联的记忆树节点（同IP/同类型）",
        category="search", estimated_ms=50,
        risk_level=RISK_LOW,
    )
    tool_registry.register(
        "sliding_window.get", _sliding_window_get,
        description="获取滑动窗口内的近期上下文",
        category="data", estimated_ms=10,
        risk_level=RISK_LOW,
    )
    tool_registry.register(
        "sliding_window.evicted", _sliding_window_evicted,
        description="获取被窗口淘汰的历史消息",
        category="data", estimated_ms=10,
        risk_level=RISK_LOW,
    )
    logger.info(f"Tool registry initialized with {len(tool_registry._tools)} tools")
    tool_registry._initialized = True


# 模块加载时自动初始化（保持向后兼容）。
# 应用启动入口（app.py）若已 import 本模块则自动完成注册；
# 若运行时新工具需要 reload，可手动 tool_registry._initialized = False 后再调 init。
init_tool_registry()
