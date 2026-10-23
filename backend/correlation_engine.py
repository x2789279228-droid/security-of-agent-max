"""
攻击链关联引擎 — 跨事件模式识别

核心功能：
  1. 时间窗口关联 — 同 IP 在 T 分钟内的事件序列
  2. 攻击链模式 — 已知攻击路径的模式匹配
  3. 低频组合检测 — 多个低严重度事件的组合分析
  4. 图关联 — 通过共同目标 IP 关联不同源

设计理念：
  安全审计的核心不是"记住重要的事"，而是"发现事件之间的关系"。
  单个 info 事件不危险，但 DNS 查询 + 文件访问 + C2 回连 = 攻击链。

用法:
    engine = CorrelationEngine()
    chains = await engine.analyze(session, session_id)
    # chains 包含所有识别出的攻击链
"""
import hashlib
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from detection_contract import (
    STATUS_DETECTED,
    STATUS_ERROR,
    STATUS_NOT_DETECTED,
    STATUS_PARTIAL,
)
from models import SecurityEvent

logger = logging.getLogger(__name__)

# ── 攻击链模式定义 ──

# 中文事件名 → 标准英文类型名映射
ZH_EVENT_MAP = {
    # 认证/凭据攻击（L1: 不再误标为 DATA_EXFIL，避免走「需审批隔离」而不自动短封）
    "未授权获取密码信息": "UNAUTHORIZED_ACCESS",
    "未授权获取明文密码信息": "UNAUTHORIZED_ACCESS",
    "请求数据存在明文密码信息": "DATA_EXFIL",
    # 未授权访问
    "非敏感接口未鉴权": "UNAUTHORIZED_ACCESS",
    "日志接口未授权访问": "UNAUTHORIZED_ACCESS",
    # 暴力破解
    "登录弱密码": "BRUTE_FORCE",
    "暴力破解": "BRUTE_FORCE",
    # 端口扫描
    "端口扫描": "PORT_SCAN",
    # C2
    "C2通信": "C2_BEACON",
    # 恶意软件
    "恶意软件": "MALWARE_DETECT",
    # Web攻击
    "SQL注入": "SQL_INJECTION",
    "跨站脚本": "XSS_ATTACK",
    "命令注入": "COMMAND_INJECTION",
    # 横向移动
    "横向移动": "LATERAL_MOVE",
    # 登录相关
    "登录成功": "USER_LOGIN",
    "登录失败": "SUSPICIOUS_LOGIN",
    # 文件相关
    "文件访问": "FILE_ACCESS",
    # 网络相关
    "DNS查询": "DNS_QUERY",
    "DDoS": "DDoS_TRAFFIC",
}

# 英文别名归一（Kill Chain 常见写法）
EVENT_TYPE_ALIASES = {
    "LATERAL_MOVEMENT": "LATERAL_MOVE",
    "DATA_EXFILTRATION": "DATA_EXFIL",
    "DATA_EXFILTRATE": "DATA_EXFIL",
    "C2_COMM": "C2_BEACON",
    "SSH_BRUTE": "BRUTE_FORCE",
    # v5 修复(C2):上游常把 "DDoS_TRAFFIC" 写成全大写，归一后才能命中
    # 策略引擎的 threat_type 与 TYPE_SIGNAL_EVENTS 词表
    "DDOS_TRAFFIC": "DDoS_TRAFFIC",
}


def normalize_event_type(raw_type: str) -> str:
    """将事件名归一化为标准英文类型名"""
    if not raw_type:
        return "UNKNOWN"
    # 中文映射
    mapped = ZH_EVENT_MAP.get(raw_type)
    if mapped:
        return mapped
    upper = raw_type.strip().upper().replace("-", "_").replace(" ", "_")
    return EVENT_TYPE_ALIASES.get(upper, upper if raw_type.isascii() else raw_type)


# 关键词 → 威胁类型枚举：上游告警名常为自然语言（如 "C2 通信" 带空格、
# 审计结论用中文词表 "数据外泄"），精确匹配失败时按子串推断。
# L3: 「密码」不再单独映射 DATA_EXFIL（避免凭据类误判）；优先走 taxonomy。
KEYWORD_THREAT_MAP = [
    ("C2", "C2_BEACON"),
    ("WebShell", "MALWARE_DETECT"),
    ("恶意软件", "MALWARE_DETECT"),
    ("勒索", "RANSOMWARE"),
    ("外泄", "DATA_EXFIL"),
    ("暴力破解", "BRUTE_FORCE"),
    ("弱密码", "BRUTE_FORCE"),
    ("端口扫描", "PORT_SCAN"),
    ("SQL注入", "SQL_INJECTION"),
    ("命令注入", "COMMAND_INJECTION"),
    ("跨站脚本", "XSS_ATTACK"),
    ("横向移动", "LATERAL_MOVE"),
    ("DDoS", "DDoS_TRAFFIC"),
    ("未授权", "UNAUTHORIZED_ACCESS"),
    ("未鉴权", "UNAUTHORIZED_ACCESS"),
    ("凭证枚举", "UNAUTHORIZED_ACCESS"),
    ("异常凭证", "UNAUTHORIZED_ACCESS"),
]

# 全部已知威胁枚举值：ASCII 名归一化后仅在其为已知枚举时采纳,
# 避免短名(如审计词表 "C2")被当成未知名直接透传而跳过关键词匹配
_KNOWN_THREAT_ENUMS = (
    set(ZH_EVENT_MAP.values())
    | set(EVENT_TYPE_ALIASES.values())
    | {t for _, t in KEYWORD_THREAT_MAP}
)


def infer_threat_classification(name: str) -> tuple[str, str]:
    """自然语言/枚举 → (leaf, category)。

    优先 taxonomy.yml；失败时回退 ZH_EVENT_MAP / KEYWORD_THREAT_MAP。
    """
    if not name or not str(name).strip():
        return "", ""
    try:
        from response_engine.threat_taxonomy import classify, category_for_leaf
        result = classify(name)
        if result.leaf or result.category:
            leaf = result.leaf
            cat = result.category or (category_for_leaf(leaf) if leaf else "")
            return leaf, cat
    except Exception:
        pass

    # 回退：旧词表
    name_s = str(name).strip()
    compact = name_s.replace(" ", "").replace("　", "")
    mapped = ZH_EVENT_MAP.get(compact) or ZH_EVENT_MAP.get(name_s)
    if mapped:
        try:
            from response_engine.threat_taxonomy import category_for_leaf
            return mapped, category_for_leaf(mapped)
        except Exception:
            return mapped, ""
    if name_s.isascii():
        normalized = normalize_event_type(name_s)
        if normalized in _KNOWN_THREAT_ENUMS:
            try:
                from response_engine.threat_taxonomy import category_for_leaf
                return normalized, category_for_leaf(normalized)
            except Exception:
                return normalized, ""
    lowered = name_s.lower()
    for keyword, threat_type in KEYWORD_THREAT_MAP:
        if keyword.lower() in lowered or keyword in compact:
            try:
                from response_engine.threat_taxonomy import category_for_leaf
                return threat_type, category_for_leaf(threat_type)
            except Exception:
                return threat_type, ""
    return "", ""


def infer_threat_type(name: str) -> str:
    """从自然语言事件名/威胁名推断标准威胁类型枚举（leaf）。

    兼容旧调用方；需要 category 时请用 infer_threat_classification()。
    无法推断时返回 ""（区别于 normalize_event_type 的 "UNKNOWN"）。
    """
    leaf, _cat = infer_threat_classification(name)
    return leaf

# 已知的攻击路径模式：有序的事件类型序列
ATTACK_CHAIN_PATTERNS = {
    "port_scan_to_c2": {
        "name": "端口扫描→漏洞利用→C2回连",
        "steps": ["PORT_SCAN", "BRUTE_FORCE", "C2_BEACON"],
        "max_gap_minutes": 30,
        "max_chain_duration_minutes": 45,
        "severity_required": False,
        "min_match": 3,
    },
    "classic_killchain": {
        "name": "经典杀伤链",
        "steps": ["PORT_SCAN", "BRUTE_FORCE", "LATERAL_MOVE", "C2_BEACON", "DATA_EXFIL"],
        "max_gap_minutes": 60,
        "max_chain_duration_minutes": 150,
        "severity_required": False,
        "min_match": 3,  # 允许部分有序子序列（可跳过未出现的中间步）
        "skippable": ["LATERAL_MOVE"],
    },
    # 无横向移动的外部入侵→失陷外联（演示与常见跳板场景）
    "external_compromise_exfil": {
        "name": "外部入侵→失陷外联",
        "steps": ["PORT_SCAN", "BRUTE_FORCE", "C2_BEACON", "DATA_EXFIL"],
        "max_gap_minutes": 60,
        "max_chain_duration_minutes": 120,
        "severity_required": False,
        "min_match": 3,
    },
    "lateral_movement": {
        "name": "横向移动",
        "steps": ["SUSPICIOUS_LOGIN", "FILE_ACCESS", "LATERAL_MOVE", "C2_BEACON"],
        "max_gap_minutes": 60,
        "max_chain_duration_minutes": 120,
        "severity_required": False,
        "min_match": 2,
    },
    "post_compromise": {
        "name": "失陷后扩散",
        "steps": ["LATERAL_MOVE", "C2_BEACON", "DATA_EXFIL"],
        "max_gap_minutes": 30,
        "max_chain_duration_minutes": 45,
        "severity_required": False,
        "min_match": 2,
    },
    "data_exfil": {
        "name": "数据外泄",
        "steps": ["FILE_ACCESS", "DATA_EXFIL"],
        "max_gap_minutes": 15,
        "max_chain_duration_minutes": 15,
        "severity_required": False,
    },
    "web_attack": {
        "name": "Web攻击链",
        "steps": ["PORT_SCAN", "SQL_INJECTION", "PRIV_ESC", "C2_BEACON"],
        "max_gap_minutes": 45,
        "max_chain_duration_minutes": 90,
        "severity_required": False,
    },
    "ransomware": {
        "name": "勒索软件",
        "steps": ["PHISHING", "SUSPICIOUS_LOGIN", "FILE_ACCESS", "RANSOMWARE"],
        "max_gap_minutes": 120,
        "max_chain_duration_minutes": 240,
        "severity_required": False,
    },
    "dns_anomaly": {
        "name": "DNS异常→C2",
        "steps": ["DNS_QUERY", "DNS_QUERY", "C2_BEACON"],
        "max_gap_minutes": 10,
        "max_chain_duration_minutes": 20,
        "severity_required": False,
    },
    # 新增：未授权访问类攻击
    "unauthorized_access": {
        "name": "未授权访问",
        "steps": ["UNAUTHORIZED_ACCESS", "DATA_EXFIL"],
        "max_gap_minutes": 30,
        "max_chain_duration_minutes": 30,
        "severity_required": False,
    },
    "data_leak_chain": {
        "name": "数据泄露",
        "steps": ["UNAUTHORIZED_ACCESS", "UNAUTHORIZED_ACCESS", "DATA_EXFIL"],
        "max_gap_minutes": 60,
        "max_chain_duration_minutes": 90,
        "severity_required": False,
    },
}


#: 无法归因的攻击者分组前缀。
#:
#: 整改方案 §八：
#: > 「来源实体的绑定必须清晰。如果没有 src_ip，也没有其他能够关联
#: > 攻击者身份的字段，不能把所有未知来源事件都当成同一个攻击者的行为。」
#:
#: 修复前这里用的是 `evt.src_ip or "unknown"` —— **全部**无 src_ip 的事件
#: 被塞进同一个虚拟攻击者「unknown」，于是来源完全无关的事件会被串成
#: 一条「攻击链」（一个 P1 误报）。
#:
#: 现在：每条无法归因的事件各占一个键（`unattributed:<事件id>`），
#: 它们永远不会被合并，也就无法凑成一条链。
UNATTRIBUTED_PREFIX = "unattributed:"

#: 备用身份分组前缀（src_ip 缺失，但 raw_data 里有能标识同一行为体的字段）。
IDENTITY_PREFIX = "ident:"

#: 攻击者身份字段（`src_ip` 缺失时的回退），按优先级。
#:
#: 只收**能确定标识「谁做的」**的字段。刻意**不收** `host` / `hostname`：
#: 在 web 日志里 `host` 通常是**被访问的目标**而不是攻击者，
#: 按它分组会把「很多不同攻击者打同一个站点」并成一个行为体 ——
#: 那是用一个误报换另一个误报。
#:
#: 需要按部署场景扩充时改这一个常量即可（分组逻辑不依赖具体字段名）。
ACTOR_IDENTITY_FIELDS = (
    # 账号类 —— 明确标识「谁」
    "user", "user_name", "username", "account", "account_name",
    "用户", "用户名", "账号",
    # 端点/设备类 —— 标识「哪台机」
    "agent_id", "device_id", "src_host",
)


def actor_key(evt) -> str:
    """事件的攻击者绑定键。

    三种形态：

    · ``<ip>``                    —— `src_ip` 存在（正常路径，行为不变）
    · ``ident:<字段>=<值>``        —— `src_ip` 缺失，但 `raw_data` 里有能标识
      同一行为体的字段。此时它们**确实是**同一个行为体，可以成链
      （整改方案 §八 允许这种情况）。
    · ``unattributed:<事件id>``     —— `src_ip` 缺失且没有任何身份字段。
      **每条事件一个独立的键** —— 它们永远不会被合并，既不会被当成同一个
      攻击者，也无法凑成一条链。

    `raw_data` 装的是**原始事件载荷**（`event_store` 落库时写入
    `raw_data={**event_data, ...}`，而 `event_data` 是 `dict(log_data)` 的
    归一化结果，原字段全部保留），所以身份字段是取得到的。
    """
    src_ip = (getattr(evt, "src_ip", "") or "").strip()
    if src_ip:
        return src_ip
    raw = getattr(evt, "raw_data", None)
    if isinstance(raw, dict):
        for field in ACTOR_IDENTITY_FIELDS:
            val = raw.get(field)
            if isinstance(val, str) and val.strip():
                return f"{IDENTITY_PREFIX}{field}={val.strip()}"
    return f"{UNATTRIBUTED_PREFIX}{getattr(evt, 'id', '')}"


def actor_label(key: str) -> str:
    """分组键 → 给人看的行为体标签。"""
    if key.startswith(IDENTITY_PREFIX):
        return key[len(IDENTITY_PREFIX):].replace("=", ":", 1)
    if key.startswith(UNATTRIBUTED_PREFIX):
        return "unattributed"
    return key


def stable_chain_id(pattern_key: str, src_ip: str, events: list) -> str:
    """内容寻址的 chain_id（整改方案 §提交 E：去重确定性）。

    修复前用 `matched_events[0]["id"]`，即**输入顺序里的第一条**。
    同一个事件集合换个顺序（或换个分片方式）就会得到不同 chain_id，
    于是「同一条攻击链被拆成两条」「同一条链被重复去重」都无从判断。

    现在取匹配事件 ID 的排序指纹：
      - 与输入顺序无关（ID 先排序）；
      - 与「多了一条无关事件」无关（只对匹配上的事件取指纹）；
      - 事件没有 id 时退化到 (event_type, created_at) 组合，仍然稳定。

    注意 src_ip 单独进指纹：跨源枢纽链的 src_ips 与 pattern_key 都不足以
    唯一定位一条链，而 src_ip + 事件集合已经足够。
    """
    parts = []
    for e in events:
        eid = e.get("id")
        if eid is None or eid == "":
            ts = getattr(e.get("created_at"), "isoformat", lambda: "")()
            eid = f"{normalize_event_type(e.get('event_type') or '')}@{ts}"
        parts.append(str(eid))
    digest = hashlib.sha256(
        "|".join(sorted(parts)).encode("utf-8")).hexdigest()[:12]
    return f"chain_{pattern_key}_{src_ip}_{digest}"


@dataclass
class AttackChain:
    """攻击链 — 一组关联的安全事件序列"""
    chain_id: str
    pattern_name: str
    confidence: float          # 0-1
    events: list[dict]         # 原始事件列表
    src_ips: set               # 涉及的源IP
    dst_ips: set               # 涉及的目标IP
    time_span_minutes: float   # 时间跨度
    alert: str                 # 简要告警描述
    # ── 模式完整性（整改方案 §提交 E：模式退化必须可观测）──
    matched_steps: list = field(default_factory=list)   # 实际命中的步骤
    skipped_steps: list = field(default_factory=list)   # 被跳过（未出现）的步骤
    required_steps: list = field(default_factory=list)  # 不可跳过的步骤
    partial: bool = False      # True = 命中的是不完整链
    shared_event_ids: list = field(default_factory=list)  # 与其它保留链共享的事件
    overlaps_other_chain: bool = False
    #: 行为体标签（整改方案 §八「来源实体的绑定必须清晰」）。
    #:
    #: `src_ip` 缺失时，链的行为体不是 IP —— 要么是备用身份（`user:alice`），
    #: 要么根本无从归因。这种情况下 `src_ips` 会是**空集**（不塞假 IP），
    #: 行为体身份放在这个字段里。
    actor: str = ""


@dataclass
class CorrelationResult:
    """关联分析结果"""
    chains: list[AttackChain] = field(default_factory=list)
    temporal_groups: list[dict] = field(default_factory=list)   # 时间窗口分组
    entity_links: list[dict] = field(default_factory=list)      # 实体关联
    total_events_analyzed: int = 0
    # ── 可观测性（整改方案 §十一）──
    matched_patterns: list = field(default_factory=list)   # 命中的模式
    reject_reasons: dict = field(default_factory=dict)     # 被拒绝的链及原因
    source_ip_count: int = 0
    # ── 本次分析自身的完整性（整改方案 §八 末段 / §二）──
    #
    # 命名警告：`AttackChain.partial` 早已占用 partial 这个名字，且含义
    # **完全不同** —— 那是「命中的这条链本身跳了步」（模式退化），
    # 属于链的属性；而这里是「引擎这次没跑完」（匹配器抛异常），属于
    # 分析的属性。两个 partial 混用会让下游分不清到底是链不完整还是
    # 分析不完整，所以这里改用 pattern_errors / hub_error。
    pattern_errors: int = 0    # 抛异常的模式数（按 pattern_key 去重，非尝试次数）
    hub_error: bool = False    # 枢纽主机关联抛异常
    #: 无法归因的事件数（既无 src_ip，也无任何身份字段）。
    #:
    #: 这些事件**不会**被并成同一个攻击者，所以它们无法参与攻击链匹配
    #: （整改方案 §八）。单列一个计数，是为了让「为什么没出链」可回答 ——
    #: 否则「没有攻击」与「有事件但归因不了」在指标上完全同形。
    unattributed_source_events: int = 0

    @property
    def analysis_complete(self) -> bool:
        """本次分析是否完整跑完（与「有没有命中链」无关）。"""
        return not (self.pattern_errors or self.hub_error)

    @property
    def status(self) -> str:
        """本次关联分析的状态 —— 复用 `detection_contract` 的五态词表。

        整改方案 §八 末段明确要求：
        「存在模式匹配错误时，必须标记本次分析为部分失败，
        不能直接当成没有攻击链。」

        修复前本引擎只报二态（`detected if chains else not_detected`），
        于是**全部 11 个模式匹配器崩溃**与**这段时间确实没有攻击**
        在 `soc_detection_outcomes_total` 上完全同形 ——
        这正是 §二 禁止的「检测失败被编码成真实阴性」。

        取值规则与 `detection_contract.combine_status` 对齐：
          · 有命中、无失败           → detected
          · 有命中、有失败           → partial（保留有效结果 + 标注不完整）
          · 无命中、无失败           → not_detected
          · 无命中、**全部**模式失败 → error（一点有效证据都没有）
          · 无命中、仅部分模式失败   → partial
        """
        failed = bool(self.pattern_errors or self.hub_error)
        if self.chains:
            return STATUS_PARTIAL if failed else STATUS_DETECTED
        if not failed:
            return STATUS_NOT_DETECTED
        # 只有「一个模式都没跑成」才算 error。枢纽主机是跨源补充路径：
        # 主路径全部模式都正常跑完时它失败，只说明丢了跨源串联，属 partial。
        if self.pattern_errors >= len(ATTACK_CHAIN_PATTERNS):
            return STATUS_ERROR
        return STATUS_PARTIAL

    @property
    def observability(self) -> dict:
        """模式匹配的可观测口径。

        `chains_matched=0` 有两种完全不同的原因：
        这段时间真的没有攻击（`reject_reasons` 里全是时间/事件数约束），
        或者模式已经退化到永远匹配不上（同一个 rejected 计数异常高）。
        把两者压成一个数字，仪表盘就再也帮不上排障。

        整改方案 §八 要求「存在模式匹配错误时必须标记为部分失败」，
        所以除了诊断计数，这里还带上 `status` / `analysis_complete` ——
        有了这两个键，运维不必自己比对 `reject_reasons` 就能分清
        「没攻击」和「没跑成」。
        """
        return {
            "chains_matched": len(self.chains),
            "chains_partial": sum(1 for c in self.chains if c.partial),
            "chains_overlapping": sum(
                1 for c in self.chains if c.overlaps_other_chain),
            "matched_patterns": list(self.matched_patterns),
            "reject_reasons": dict(self.reject_reasons),
            "source_ip_count": self.source_ip_count,
            "unattributed_source_events": self.unattributed_source_events,
            "total_events_analyzed": self.total_events_analyzed,
            "status": self.status,
            "analysis_complete": self.analysis_complete,
            "pattern_errors": self.pattern_errors,
            "hub_error": self.hub_error,
        }


class CorrelationEngine:
    """
    攻击链关联引擎

    分析流程:
    1. 获取 session 的所有事件（从 SecurityEvent 表）
    2. 按源 IP 分组，时间排序
    3. 对每个 IP 的事件序列进行攻击链模式匹配
    4. 输出所有匹配的攻击链
    """

    def __init__(self):
        self.patterns = ATTACK_CHAIN_PATTERNS

    async def analyze(
        self,
        session: AsyncSession,
        session_id: str,
        time_window_minutes: int = 1440,  # 默认回溯24小时
    ) -> CorrelationResult:
        """对 session 的安全事件进行关联分析（**带耗时埋点**的外层）。

        埋点放在外层：本函数内部有多个提前返回分支，漏埋点不会让
        任何测试变红，只会让仪表盘少一段时间数据。
        """
        import time as _time
        _t0 = _time.perf_counter()
        result = await self._analyze_inner(
            session, session_id, time_window_minutes)
        try:
            from core_metrics import record_detection
            # 报**本次分析的真实状态**（detected / not_detected /
            # partial / error），而不是「有没有链」这个二态。
            # 整改方案 §八：模式匹配出错时必须标记为部分失败，
            # 不能当成没有攻击链。修复前这里写死二态，于是
            # 「11 个匹配器全崩」与「确实没有攻击」在指标上完全同形。
            record_detection(
                "correlation", result.status,
                _time.perf_counter() - _t0)
        except Exception:
            pass
        return result

    async def _analyze_inner(
        self,
        session: AsyncSession,
        session_id: str,
        time_window_minutes: int = 1440,
    ) -> CorrelationResult:
        """
        对 session 的安全事件进行关联分析

        Args:
            session: DB session
            session_id: 会话ID
            time_window_minutes: 分析时间窗口

        Returns:
            CorrelationResult
        """
        # 1. 获取事件
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

        if not events:
            logger.info(f"No events found for {session_id}")
            return CorrelationResult()

        logger.info(f"Analyzing {len(events)} events for {session_id}")

        # 2. 按**行为体**分组（整改方案 §八：来源实体的绑定必须清晰）
        #
        # 修复前是 `evt.src_ip or "unknown"` —— **全部**无 src_ip 的事件被并进
        # 同一个虚拟攻击者「unknown」，于是来源完全无关的事件会被串成一条
        # 「攻击链」（P1 误报），且链的 `src_ips` 里躺着一个并不存在的
        # 「unknown」IP。
        #
        # 现在按 `actor_key()` 绑定行为体：
        #   · 有 src_ip          → 按 IP（正常路径，行为不变）
        #   · 无 src_ip 但有身份  → 按身份（文档允许：确实是同一行为体）
        #   · 两者都没有          → **每条事件一个独立键**，永不与他人合并
        events_by_ip: dict[str, list[dict]] = defaultdict(list)
        unattributed = 0
        for evt in events:
            actor = actor_key(evt)
            if actor.startswith(UNATTRIBUTED_PREFIX):
                unattributed += 1
            events_by_ip[actor].append({
                "id": evt.id,
                "event_type": evt.event_type,
                "severity": evt.severity,
                "src_ip": evt.src_ip,
                "dst_ip": evt.dst_ip,
                "message": evt.message or "",
                "created_at": evt.created_at,
            })

        # 3. 对每个 IP 进行攻击链模式匹配
        chains = []
        temporal_groups = []
        entity_links = []
        # §十一：「关联链匹配数、**被拒绝的链及原因**」必须可观测，
        # 否则「模式退化」与「这段时间确实没有攻击」在指标上长得一样。
        reject_reasons: dict = {}
        matched_patterns: set = set()
        #: 抛异常的模式 key（去重）。整改方案 §八：模式匹配错误必须让本次
        #: 分析变成 partial/error，而不是被吞掉后当成「没有攻击链」。
        broken_patterns: set = set()
        hub_error = False

        for actor, ip_events in events_by_ip.items():
            ip_events.sort(key=lambda e: e["created_at"])

            # 3a. 攻击链模式匹配
            for pattern_key, pattern in self.patterns.items():
                try:
                    chain = self._match_pattern(
                        pattern_key, pattern, actor, ip_events,
                        rejects=reject_reasons,
                    )
                    if chain:
                        chains.append(chain)
                        matched_patterns.add(pattern_key)
                except Exception as e:
                    logger.warning(f"Pattern match failed for {pattern_key}: {e}")
                    reject_reasons["pattern_error"] = \
                        reject_reasons.get("pattern_error", 0) + 1
                    broken_patterns.add(pattern_key)

            # 3b. 时间窗口分组（同一行为体在短时内的事件）
            groups = self._temporal_grouping(actor, ip_events, window_minutes=10)
            temporal_groups.extend(groups)

        # 3c. 枢纽主机模式：先作受害者(dst)后作攻击源(src)的 IP 串联跨源 Kill Chain
        try:
            hub_chains = self._match_hub_hosts(events)
            chains.extend(hub_chains)
        except Exception as e:
            logger.warning(f"Hub-host correlation failed: {e}")
            # 修复前这里**只记日志**，连 reject_reasons 都不写 ——
            # 于是「跨源 Kill Chain 这条路径崩了」在结果对象上不留任何痕迹，
            # 与干净路径逐位相同。现在至少要有 hub_error 标记。
            reject_reasons["hub_error"] = reject_reasons.get("hub_error", 0) + 1
            hub_error = True

        # 4. 图关联：通过共同目标IP发现不同源IP的关联
        entity_links = self._entity_linking(events_by_ip)

        # 5. 去重
        chains = self._dedup_chains(chains)

        # 只数**真实**的源 IP。修复前 `len(events_by_ip)` 把虚拟的「unknown」
        # 也算成是一个来源，源 IP 数因此被灌水（一个虚拟桶顶一个真来源）。
        real_src_ips = {
            (e.get("src_ip") or "").strip()
            for grp in events_by_ip.values() for e in grp
        } - {""}

        result = CorrelationResult(
            chains=chains,
            temporal_groups=temporal_groups,
            entity_links=entity_links,
            total_events_analyzed=len(events),
            matched_patterns=sorted(matched_patterns),
            reject_reasons=dict(sorted(reject_reasons.items())),
            source_ip_count=len(real_src_ips),
            # 按**去重后的模式数**记，不是尝试次数：一个源 IP 跑 11 次
            # 不该把「1 个模式坏了」说成「11 个模式坏了」。
            pattern_errors=len(broken_patterns),
            hub_error=hub_error,
            unattributed_source_events=unattributed,
        )

        if chains:
            logger.info(f"Found {len(chains)} attack chains for {session_id}")
            for c in chains:
                logger.info(f"  Chain: {c.pattern_name} "
                            f"confidence={c.confidence:.2f} "
                            f"events={len(c.events)} "
                            f"partial={c.partial} skipped={c.skipped_steps} "
                            f"alert={c.alert[:80]}")
        if reject_reasons:
            logger.info("Chain reject reasons for %s: %s",
                        session_id, dict(sorted(reject_reasons.items())))

        return result

    def _match_hub_hosts(self, events: list) -> list[AttackChain]:
        """以「先作 dst、后作 src」的枢纽主机串联跨源攻击链。"""
        # 统一为 dict 视图
        rows = []
        for evt in events:
            rows.append({
                "id": evt.id,
                "event_type": evt.event_type,
                "severity": evt.severity,
                "src_ip": evt.src_ip,
                "dst_ip": evt.dst_ip,
                "message": evt.message or "",
                "created_at": evt.created_at,
            })

        dst_set = {r["dst_ip"] for r in rows if r.get("dst_ip")}
        src_set = {r["src_ip"] for r in rows if r.get("src_ip")}
        hubs = dst_set & src_set
        chains: list[AttackChain] = []

        # 优先匹配无强制横向移动的外联模式，再尝试完整经典杀伤链
        hub_patterns = []
        if "external_compromise_exfil" in self.patterns:
            hub_patterns.append(
                ("hub_external_exfil", self.patterns["external_compromise_exfil"])
            )
        hub_patterns.append((
            "hub_killchain",
            self.patterns.get("classic_killchain") or {
                "name": "枢纽主机杀伤链",
                "steps": ["PORT_SCAN", "BRUTE_FORCE", "LATERAL_MOVE", "C2_BEACON", "DATA_EXFIL"],
                "max_gap_minutes": 60,
                "max_chain_duration_minutes": 150,
                "min_match": 3,
                "skippable": ["LATERAL_MOVE"],
            },
        ))

        for hub in hubs:
            inbound = [r for r in rows if r.get("dst_ip") == hub]
            outbound = [r for r in rows if r.get("src_ip") == hub]
            # 时间轴：先入站侦察/突破，再出站横向/外联
            timeline = sorted(inbound + outbound, key=lambda e: e["created_at"])
            # 去重同 id
            seen = set()
            deduped = []
            for e in timeline:
                if e["id"] in seen:
                    continue
                seen.add(e["id"])
                deduped.append(e)
            for pattern_key, pattern in hub_patterns:
                chain = self._match_pattern(
                    pattern_key,
                    {**pattern, "name": f"{pattern.get('name', '枢纽杀伤链')}({hub})"},
                    hub,
                    deduped,
                )
                if chain:
                    chain.chain_id = stable_chain_id(
                        "hub_killchain", hub, chain.events)
                    chain.src_ips = {e.get("src_ip") for e in chain.events if e.get("src_ip")}
                    chain.dst_ips = {e.get("dst_ip") for e in chain.events if e.get("dst_ip")}
                    chains.append(chain)
                    break  # 同一 hub 只保留最高优先级命中
        return chains

    def _match_pattern(
        self,
        pattern_key: str,
        pattern: dict,
        src_ip: str,
        events: list[dict],
        rejects: Optional[dict] = None,
    ) -> Optional[AttackChain]:
        """
        在事件序列中匹配攻击链模式

        使用滑动窗口 + 有序子序列匹配算法。
        不要求严格连续，只要求按顺序出现且时间间隔在阈值内。

        `src_ip` 是**行为体键**（`actor_key()` 的结果），不一定是 IP：
        无 src_ip 但有身份字段时是 `ident:<字段>=<值>`，两者都没有时是
        `unattributed:<事件id>`。

        整改方案 §八：「来源实体的绑定必须清晰。…不能把所有未知来源事件
        都当成同一个攻击者的行为。」—— 所以**无法归因的行为体不许成链**。
        这道闸放在**断言点**（这里）而不只是分组点：分组已经保证它们
        不会被合并，但断言点再挡一次，任何绕过分组直接调本方法的调用方
        （旧测试就曾这么干）也拿不到一条「攻击者叫 unknown」的链。

        整改方案 §提交 E（攻击链语义 / 时间窗口 / 去重确定性）：

        1. **必需步骤 vs 可选步骤显式化**。修复前跳步条件是
           `all(middle 可跳过) or pattern.get("allow_skip_missing", True)`
           —— `allow_skip_missing` 默认 True，于是**任何**步骤都能被跳过。
           实测后果：`lateral_movement`（步骤含 LATERAL_MOVE，min_match=2）
           在完全没有横向移动事件时也能命中；`post_compromise` 同理。
           现在：只有 `skippable` 里显式声明的步骤才允许跳过，
           `allow_skip_missing` 保留但默认 False（要放宽必须显式打开）。

        2. **`max_gap` 与 `max_chain_duration` 分离**。修复前只有相邻间隔
           上限，于是「每步间隔 29 分钟、共 5 步」的链可以跨越 2 小时，
           而模式声明的语义是「30 分钟内的一次攻击」。
           现在额外校验**整条链的总跨度**。

        3. **chain_id 由内容决定**。修复前是
           `f"chain_{pattern_key}_{src_ip}_{matched_events[0]['id']}"`，
           依赖输入顺序的第一条事件；同样的事件集合换个顺序就换 ID，
           去重与追踪都对不上。现在取匹配事件 ID 的**排序指纹**。
        """
        steps = pattern["steps"]
        max_gap = pattern["max_gap_minutes"]
        max_duration = pattern.get("max_chain_duration_minutes")
        n = len(steps)
        skippable = {
            normalize_event_type(s) for s in (pattern.get("skippable") or [])
        }
        allow_any_skip = bool(pattern.get("allow_skip_missing", False))
        # 必需步骤 = 全部步骤 - 显式声明可跳过的步骤
        required = [s for s in steps if normalize_event_type(s) not in skippable]
        min_match = int(pattern.get("min_match") or n)

        def reject(reason: str) -> None:
            """记录拒绝原因（§十一：被拒绝的链及原因必须可观测）。

            修复前所有 `return None` 走的是同一条静默路径 ——
            「没有攻击」和「模式永远匹配不上」在指标上完全一样。
            """
            if rejects is not None:
                rejects[reason] = rejects.get(reason, 0) + 1
            return None

        # ── 归因闸：无法归因的行为体不许成链 ──
        #
        # 整改方案 §八：「如果没有 src_ip，也没有其他能够关联攻击者身份的
        # 字段，不能把所有未知来源事件都当成同一个攻击者的行为。」
        #
        # 「unknown」与空串都是「我不知道这个行为体是谁」的标记，
        # 不是身份。拿它们去断言一条攻击链，等于凭空造出一个攻击者。
        # `unattributed:` 前缀是本引擎给「无法归因」事件分配的独立键 ——
        # 每条一个，永不与他人合并。
        #
        # 这里**不**走 `reject()` 计数：无法归因的事件是**每条一个**分组，
        # 走 reject 会按「事件数 × 模式数」把计数灌爆（100 条无源事件
        # → 1100 次拒绝），把真正有诊断价值的拒绝原因淹掉。
        # 归因不了的事件数由 `CorrelationResult.unattributed_source_events`
        # 单独统计。
        if src_ip.startswith(UNATTRIBUTED_PREFIX) or src_ip in ("unknown", ""):
            return None

        if len(events) < min_match:
            return reject("too_few_events")

        # 将事件类型转换为序列（支持中文事件名映射）
        event_types = [normalize_event_type(e["event_type"]) for e in events]

        # 有序子序列匹配：只能跳过 skippable（或显式放开）的中间步。
        # matched_indices 记的是**事件**下标，matched_step_pos 记的是
        # **步骤**下标 —— 修复前只有一个变量被两种用途混用，
        # 顺带把「命中了哪些步骤」丢掉了。
        matched_indices = []
        matched_step_pos = []
        step_idx = 0

        for i, et in enumerate(event_types):
            if step_idx >= n:
                break
            # 当前事件匹配当前期望步骤
            if et == steps[step_idx]:
                matched_indices.append(i)
                matched_step_pos.append(step_idx)
                step_idx += 1
                continue
            # 向前查找：跳过可跳过步骤，看是否能匹配更后面的步骤
            advanced = False
            for look_ahead in range(step_idx + 1, n):
                # 仅当中间步骤均可跳过（或模式显式允许任意跳过）时前进
                middle = steps[step_idx:look_ahead]
                if allow_any_skip or all(
                    normalize_event_type(m) in skippable for m in middle
                ):
                    if et == steps[look_ahead]:
                        matched_indices.append(i)
                        matched_step_pos.append(look_ahead)
                        step_idx = look_ahead + 1
                        advanced = True
                        break
                else:
                    break
            if advanced:
                continue

        if len(matched_indices) < min_match:
            return reject("min_match_not_reached")

        # 命中的步骤与**被跳过**的步骤都要落库。修复前链只带 events，
        # 下游看到 pattern_name="横向移动" 却无从知道横向移动那一步
        # 根本没出现 —— 模式退化是完全静默的（整改方案 §提交 E：
        # 「关联链匹配数、被拒绝的链及原因」需要可观测）。
        matched_step_names = [steps[p] for p in matched_step_pos]
        seen_positions = set(matched_step_pos)
        skipped_step_names = [
            steps[k] for k in range(n) if k not in seen_positions
        ]

        # 验证时间间隔（相邻）
        matched_events = [events[i] for i in matched_indices]
        for j in range(1, len(matched_events)):
            gap = (matched_events[j]["created_at"]
                   - matched_events[j-1]["created_at"]).total_seconds() / 60
            if gap > max_gap:
                return reject("adjacent_gap_exceeded")

        # 验证整条链的总跨度（与相邻间隔是两个不同的约束）
        if max_duration is not None:
            span = (matched_events[-1]["created_at"]
                    - matched_events[0]["created_at"]).total_seconds() / 60
            if span > max_duration:
                return reject("chain_duration_exceeded")

        # 计算置信度
        severity_scores = {
            "critical": 1.0, "high": 0.8, "medium": 0.5,
            "low": 0.2, "info": 0.1,
        }
        max_sev = max(
            severity_scores.get(e["severity"], 0.1) for e in matched_events
        )
        match_ratio = len(matched_indices) / max(len(steps), 1)
        confidence = min(1.0, max_sev * 0.4 + match_ratio * 0.6)

        time_span = (
            matched_events[-1]["created_at"]
            - matched_events[0]["created_at"]
        ).total_seconds() / 60

        dst_ips = {e.get("dst_ip", "") for e in matched_events if e.get("dst_ip")}

        # `src_ips` 只装**真实**的源 IP。
        #
        # 修复前是 `src_ips={src_ip}` —— 分组键直接塞进去。而分组键可能是
        # 「unknown」这种并不存在的 IP，于是链的 `src_ips` 会向 API
        # （`routers/ops.py` 的 `list(c.src_ips)`）吐出一个假地址，
        # 下游据此去封禁「unknown」。
        #
        # 现在从匹配事件里取真实 src_ip：正常 IP 路径结果完全不变
        # （同一组的事件 src_ip 都相同）；备用身份路径得到**空集**，
        # 行为体身份改由 `actor` 字段承载 —— 空集比假值诚实。
        chain_src_ips = {e.get("src_ip") for e in matched_events if e.get("src_ip")}
        actor = actor_label(src_ip)

        sev_tags = [e["severity"].upper() for e in matched_events]
        alert = (
            f"[{pattern['name']}] {actor} → "
            f"{', '.join(sev_tags)} "
            f"({len(matched_events)}步, {time_span:.0f}分钟)"
        )

        return AttackChain(
            chain_id=stable_chain_id(pattern_key, src_ip, matched_events),
            pattern_name=pattern["name"],
            confidence=round(confidence, 3),
            events=matched_events,
            src_ips=chain_src_ips,
            dst_ips=dst_ips,
            time_span_minutes=round(time_span, 1),
            alert=alert,
            matched_steps=matched_step_names,
            skipped_steps=skipped_step_names,
            required_steps=required,
            partial=bool(skipped_step_names),
            actor=actor,
        )

    def _temporal_grouping(
        self,
        src_ip: str,
        events: list[dict],
        window_minutes: int = 10,
    ) -> list[dict]:
        """
        时间窗口分组：同一源IP在短时内的事件聚为一组
        
        用于记忆树关联和 Agent 上下文提示
        """
        if not events:
            return []

        # 分组键是**行为体键**，不一定是 IP。`src_ip` 字段只放真实源 IP
        # （没有就空串），行为体身份另放 `actor` —— 免得把
        # 「ident:user=alice」这种非 IP 值塞进一个叫 src_ip 的字段。
        actor = actor_label(src_ip)
        real_src = "" if (actor == "unattributed"
                          or src_ip.startswith(IDENTITY_PREFIX)) else src_ip

        groups = []
        current_group = [events[0]]

        for evt in events[1:]:
            gap = (evt["created_at"] - current_group[-1]["created_at"]).total_seconds() / 60
            if gap <= window_minutes:
                current_group.append(evt)
            else:
                if len(current_group) >= 2:
                    types = [e["event_type"] for e in current_group]
                    groups.append({
                        "src_ip": real_src,
                        "actor": actor,
                        "events": current_group,
                        "types": types,
                        "start": current_group[0]["created_at"].isoformat(),
                        "end": current_group[-1]["created_at"].isoformat(),
                        "count": len(current_group),
                    })
                current_group = [evt]

        if len(current_group) >= 2:
            types = [e["event_type"] for e in current_group]
            groups.append({
                "src_ip": real_src,
                "actor": actor,
                "events": current_group,
                "types": types,
                "start": current_group[0]["created_at"].isoformat(),
                "end": current_group[-1]["created_at"].isoformat(),
                "count": len(current_group),
            })

        return groups

    def _entity_linking(
        self,
        events_by_ip: dict[str, list[dict]],
    ) -> list[dict]:
        """
        实体关联：通过共同目标IP发现不同源IP的关联
        
        如果两个不同源IP都访问了同一个目标IP，它们可能协同攻击。
        """
        dst_to_srcs: dict[str, set] = defaultdict(set)
        for _actor, events in events_by_ip.items():
            for evt in events:
                dst = evt.get("dst_ip", "")
                # 只用**真实**的源 IP 建关联。
                #
                # 修复前这里加的是**分组键** —— 而分组键可能是并不存在的
                # 「unknown」。分组修好之后，无 src_ip 的事件各占一个独立键，
                # 于是「两条无源事件打同一个目标」反而会凑出 len(srcs)>=2
                # 的一条「协同攻击」关联 —— 用一个误报换另一个误报。
                # 所以这里取事件自己的真实 src_ip，取不到就不参与关联。
                real_src = (evt.get("src_ip") or "").strip()
                if dst and real_src:
                    dst_to_srcs[dst].add(real_src)

        links = []
        for dst, srcs in dst_to_srcs.items():
            if len(srcs) >= 2:
                links.append({
                    "dst_ip": dst,
                    # 排序：集合直接 list() 的顺序随进程哈希种子变
                    # （§9.59）→ 同一份数据在不同进程里给出不同的
                    # 关联输出。
                    "src_ips": sorted(srcs),
                    "type": "共同目标关联",
                })

        return links

    def _dedup_chains(self, chains: list[AttackChain]) -> list[AttackChain]:
        """去重：丢弃被完全包含的链，并把**共享事件显式标注**出来。

        整改方案 §提交 E（去重确定性）：

        修复前有两个问题。
        1. `chains.sort(key=len(events), reverse=True)` 对同长度链是**稳定
           排序**，并列项保持输入序 —— 而输入序来自 `events_by_ip` 的遍历
           序与模式字典定义序，两者都不是语义优先级。于是同样的链集合，
           换个输入顺序就得到不同的保留结果。
           现在排序键是显式的：事件数多 → 完整链（partial=False）→
           置信度高 → chain_id 字典序（最后一项纯粹为了确定性兜底）。

        2. 判定用的是「完全包含」（`event_ids - used_event_ids` 为空才丢），
           所以两条**共享一个事件、各有独有事件**的链都会保留，同一事件
           被两条链各认领一次。这里不改成「重叠即丢」—— 那会把两条真实的
           不同攻击链误删；改成把共享事件**标注出来**（`shared_event_ids`），
           让下游知道自己不能按链累加。
        """
        if not chains:
            return []

        def rank(c: AttackChain):
            return (-len(c.events), bool(c.partial),
                    -float(c.confidence or 0.0), str(c.chain_id))

        # sorted 而不是 list.sort：不改调用方传进来的列表
        ordered = sorted(chains, key=rank)

        kept: list[AttackChain] = []
        used_event_ids: set = set()
        for chain in ordered:
            event_ids = {e["id"] for e in chain.events}
            if event_ids - used_event_ids:
                kept.append(chain)
                used_event_ids.update(event_ids)

        # 标注保留链之间的共享事件（下游据此避免重复计数/重复告警）
        seen: dict = {}
        for idx, chain in enumerate(kept):
            for e in chain.events:
                seen.setdefault(e["id"], []).append(idx)
        for idx, chain in enumerate(kept):
            shared = sorted(
                {e["id"] for e in chain.events
                 if len(seen.get(e["id"], ())) > 1}
            )
            chain.shared_event_ids = shared
            chain.overlaps_other_chain = bool(shared)
        return kept


correlation_engine = CorrelationEngine()
