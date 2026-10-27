"""
异常检测引擎 — 替代原来的重要性评分

核心区别：
  原来: severity + confidence → 重要性分数(0-1) → 高重要性保留，低重要性丢弃
  现在: 统计偏离度 + 频率分析 + 模式匹配 → 异常分数 → 所有事件保留，异常事件标记

检测维度（整改方案 §七要求与实现一致）:
  1. 统计偏离度：某实体的行为偏离其历史基线        权重 0.35
  2. 事件罕见度：事件类型在全局中的占比               权重 0.20
  3. 时序异常：配置时区的非活跃时段                   权重 0.15
  4. 严重度先验：上游 severity 作为**上下文**而非证据   权重 0.15
  5. 目标IP统计：被攻击目标的集中度                   权重 0.15

整改记录（2026-10-18 审查 P0-4 / P1-1~P1-5 / P2-2~P2-7）：
  - P0-4：时序维度原先用服务器 `datetime.now(timezone.utc)` 的钟点，
    北京时间正常上班（UTC 0-5）被判「非活跃时段 +0.4」，
    北京时间真正的凌晨（UTC 16-21）恒为 0。现在改用**事件自身时间戳**
    + **可配置时区**（默认 Asia/Shanghai）。
  - P1-1/P1-2：基线样本不足时偏离度返回 0.0，与「确实无偏离」同值，
    且缺失维度按 0 分计入总分，导致新实体理论上限 0.51 < 阈值 0.60，
    **永远判不出异常**。现在改为 `inconclusive`（样本不足不出证据）。
  - P1-2b（整改中自查发现）：把可用维度「剔除 + 重新归一」会让
    **新实体只剩 severity_prior 时被归一成 1.0 分直接告警** ——
    换了个方向的冷启动误报。现在证据维度分母恒为 `EVIDENCE_TOTAL`，
    上下文维度只能加成不能发起告警；无证据时分数封顶
    `COLD_START_SCORE_CAP`(< 阈值) 且状态为 `inconclusive`。
  - P1-3：`analyze()` 先读基线再更新基线，同一事件重放得到不同分数。
    现在按 event_id 幂等，重放结果可复现。
  - P2-2：`mean == 0` 分支绕过 `min(sigma, 10.0)` 上限，`deviation_sigma`
    可达 5000.0。现在统一夹紧并对异常输入显式标记。
"""
import logging
import math
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

try:  # Python 3.9+
    from zoneinfo import ZoneInfo
    _HAS_ZONEINFO = True
except Exception:  # pragma: no cover
    ZoneInfo = None
    _HAS_ZONEINFO = False

logger = logging.getLogger(__name__)

#: 默认评估时区（整改方案 §四.2：不要依赖服务器本地时区）
DEFAULT_TIMEZONE = "Asia/Shanghai"

#: 事件时间戳的候选字段名（按优先级）
EVENT_TIME_FIELDS = (
    "event_time", "@timestamp", "timestamp", "ts",
    "created_at", "occurred_at", "time",
)

#: **接收时间**的候选字段名（整改方案 §四.4 / §七.1）。
#:
#: 与 `EVENT_TIME_FIELDS` 分开，因为它们是**不同的量**：
#: 事件时间是「事情发生的时间」，接收时间是「数据到达本系统的时间」。
#: 迟到事件（凌晨发生、白天才送达）两者可差十几个小时。
#:
#: 注意 `created_at` **不在**这里 —— 它已在事件时间候选表里，
#: 且在不同链路上的语义不统一（DB 行里是落库时间，事件 dict 里可能已被
#: 上游填成事件时间）。把它当接收时间读会把两件事搅在一起。
RECEIVED_TIME_FIELDS = (
    "received_at", "ingested_at", "ingest_time", "ingest_ts",
    "consumed_at", "receive_time",
)

#: **证据维度**：由本实体/全局基线算出的独立异常证据。
#: 权重分母恒为 EVIDENCE_TOTAL —— 缺失证据维度不会让分母变小，
#: 因此单个弱维度**无法**通过「重新归一」把自己放大到阈值以上。
#: 全量权重（证据+上下文）和恒为 1.0（声明一致性问题，见
#: tests/test_review_anomaly.py::TestQ6WeightedScore）—— 新增维度时
#: 必须**重归一**而不是追加，2026-10-25 severity_shift 即按此办理。
EVIDENCE_DIMENSIONS = {
    "statistical_deviation": 0.28,
    "rarity": 0.16,
    "target_concentration": 0.08,
    # 严重度偏移（2026-10-25, 整改方案 §七.2 的「新证据维度」）：
    # 成熟基线实体历史上从未出现 high/critical，突然发出一条 ——
    # 这是**基线相对**的行为证据，与 severity_prior（上游给的静态先验，
    # 属上下文）有本质区别：它必须先有实体基线、且窗口内零高危史才成立，
    # 因此不违反 §七.4「severity 不能独立发起告警」的纪律 ——
    # 独立发起的是「基线偏移」这件事本身，severity 只是偏移的方向。
    # 消融证据：修复前 ANO-P-02(0.4357)/ANO-P-03(0.4957) 双双低于阈值
    # （known_gap 登记），接入后 0.6435/0.6955 过阈值，负类不受影响。
    "severity_shift": 0.22,
}

#: **上下文维度**：上游 severity、非活跃时段。它们只能**放大**已有证据，
#: 不能独立发起告警（整改方案 §七.4：severity 是上下文不是独立证据）。
CONTEXT_DIMENSIONS = {
    "temporal": 0.13,
    "severity_prior": 0.13,
}

#: 全量权重（文档/报告展示口径）
DIMENSION_WEIGHTS = {**EVIDENCE_DIMENSIONS, **CONTEXT_DIMENSIONS}
EVIDENCE_TOTAL = sum(EVIDENCE_DIMENSIONS.values())    # 0.74
CONTEXT_TOTAL = sum(CONTEXT_DIMENSIONS.values())      # 0.26

#: **实体相对证据维度**（2026-10-26 聚合降级判定用，PERF-OPT Wave 0-2）。
#: 这些维度由**本实体（src，行为主体）**的基线算出；它们至少一个可用 ⇒
#: 报告就有了「对这条事件的行为面判断依据」，其余维度的不可判（dst 侧
#: 无基线、全局罕见度样本不足、事件无时间戳）降级为 per-dimension 披露，
#: 不再否决整体状态 —— 修复前"任一维度 inconclusive ⇒ 整体 inconclusive"
#: 会让一个 src 基线充分、仅 dst 侧缺历史的成熟报告被整个作废成
#: 「无法判定」，这是误报方向的反面：**有证据的阴性被谎报成不可判**。
#:
#: ⚠ `target_concentration` 刻意**不在**本集合：它是 **dst 侧**维度，
#: 描述的是目标的暴露集中度而不是行为主体的异常 —— 若算作实体证据，
#: 全新攻击者 IP 会踩着受害者的成熟基线拿到干净的阴性判定
#: （tests/test_anomaly_partial_evidence.py 首触用例钉住这一点）。
#: 全新实体（没有任何 src 相对证据）仍然整体 inconclusive ——
#: q6_3 防误报语义保持不变（待决项 41 的冷启动规则是另一条路，
#: 需要独立的 FP 评估，不在本次范围）。
ENTITY_EVIDENCE_DIMENSIONS = frozenset({
    "statistical_deviation", "severity_shift",
})

#: 判定阈值
ANOMALY_SCORE_THRESHOLD = 0.60
SIGMA_EQUIVALENT_THRESHOLD = 3.0

#: 冷启动（没有任何证据维度可用）时的分数上界。
#: 刻意低于阈值：任何按 `>= 阈值` 消费 score 的下游都不会被冷启动误触。
COLD_START_SCORE_CAP = ANOMALY_SCORE_THRESHOLD - 0.01   # 0.59

#: 冷启动：低于该样本量时统计维度判 inconclusive（不产生证据）
COLD_START_MIN_SAMPLES = 5

#: 罕见度维度的最小全局样本量（低于此判 inconclusive，不产生证据）
RARITY_MIN_SAMPLES = 10


@dataclass
class AnomalyReport:
    """单条事件的异常检测报告"""
    event_id: int
    anomaly_score: float          # 0-1, >ANOMALY_SCORE_THRESHOLD 视为异常
    is_anomaly: bool
    deviation_sigma: float        # 统计偏离度（标准差倍数，0~10 夹紧）
    reasons: list[str]            # 异常原因描述
    dimensions: dict = field(default_factory=dict)  # 各维度分数
    # ── 统一检测契约 (整改方案 §二, 2026-10-18 审查 P0-1) ──
    status: str = "not_detected"  # detected|not_detected|inconclusive|error|partial
    error_code: str = ""
    error_message: str = ""
    analysis_window: dict = field(default_factory=dict)
    # ── 可观测性（整改方案 §十一）──
    inconclusive_dimensions: list = field(default_factory=list)
    effective_weights: dict = field(default_factory=dict)
    baseline_samples: int = 0
    event_time_source: str = ""
    #: 打分所依据的基线代数（见 ``AnomalyDetector.baseline_version``）。
    #: 光有 ``baseline_samples`` 解释不了「同样 20 个样本，昨天 0.3 今天 0.7」
    #: —— 样本数一样但内容换了。只有代数能回答「基线变过没有」。
    baseline_version: int = 0


@dataclass
class EntityBaseline:
    """实体（IP/用户/事件类型）的统计基线

    整改方案 §七.1：`hourly_counts` 是「历史第 h 个钟点」的**累计**量，
    不是本小时的量；`total_count` 与 `hourly_counts` 同口径累加且**永不
    衰减**，于是基线越厚灵敏度越低（实测 60 天基线触发 3σ 需要的突增量
    是 1 天基线的 7.5 倍）。

    现在新增 `recent`（带时间戳的滚动窗口桶）作为**主要口径**，
    `hourly_counts`/`total_count` 仅保留用于展示与 Redis 兼容。
    """
    hourly_counts: list = field(default_factory=lambda: [0] * 24)
    daily_count: int = 0
    weekly_count: int = 0
    last_seen: float = 0
    total_count: int = 0
    event_types: set = field(default_factory=set)
    first_seen: float = 0
    #: 滚动窗口桶 [[ts, count], ...]（JSON 友好）
    recent: list = field(default_factory=list)
    #: 窗口内高危事件（high/critical）滚动桶 [[ts, count], ...] ——
    #: severity_shift 证据维度的历史面。与 `recent` 同一套合并/过期纪律；
    #: 旧 Redis 基线没有该字段 → 默认空表（= 无高危史，对既有实体
    #: 这在语义上等价于「历史上没见过高危」，不会造成行为突变）。
    recent_sev: list = field(default_factory=list)
    #: 窗口内已计入的事件 ID（重放幂等，整方案 §七.1）
    seen_ids: set = field(default_factory=set)

    def window_count(self, since_ts: float) -> tuple:
        """滚动窗口计数 → (总数, 各小时均值)。"""
        total = 0
        for entry in self.recent:
            if isinstance(entry, (list, tuple)) and len(entry) == 2:
                ts, c = entry
                if float(ts) >= since_ts:
                    total += int(c)
        return total, (total / 24.0)

    def count_since(self, since_ts: float, until_ts: float) -> int:
        """[since_ts, until_ts] 闭区间内的滚动窗口计数。

        带上界是必要的：事件时间可能来自**乱序/迟到的历史事件**，
        只按下界统计会把「窗口之后」的数据也算进来，
        实测会让窗口均值被稀释、σ 系统性偏低。
        """
        total = 0
        for entry in self.recent:
            if isinstance(entry, (list, tuple)) and len(entry) == 2:
                try:
                    ts, c = float(entry[0]), int(entry[1])
                except (TypeError, ValueError):
                    continue
                if since_ts <= ts <= until_ts:
                    total += c
        return total


class AnomalyDetector:
    """
    统计偏离度异常检测器

    维护每个实体的行为基线，新事件到来时计算其偏离程度。
    基线基于滑动窗口（默认7天）自动更新。

    用法:
        detector = AnomalyDetector()
        report = await detector.analyze(session, event_data)
        if report.is_anomaly:
            # 标记事件、触发深入审核
    """

    def __init__(self, window_days: int = 7, timezone_name: str = ""):
        self.window_days = window_days
        #: 统一检测契约要求每个检测器自报版本 (整改方案 §二.3 验收 3)
        self.version = "anomaly-2.0"
        #: 评估时区（整改方案 §四.2：显式配置，不依赖服务器本地时区）
        self.timezone_name = timezone_name or self._configured_timezone()
        self.tz = self._resolve_tz(self.timezone_name)
        #: **配置时区与实际生效时区不一致**（§四）。
        #:
        #: 为什么单独记：修复前结果载荷无条件上报 `timezone_name`，
        #: 于是缺 tzdata 的机器上会写出 `"timezone": "Asia/Shanghai"`
        #: 而实际按 UTC 打分 —— 审计记录在**撒谎**。
        #: 排查时序评分异常的人会据此认为时区语义是对的，从而找错方向。
        self.timezone_fallback = str(self.tz) != self.timezone_name
        # 实体基线: {entity_type: {entity_key: EntityBaseline}}
        self.baselines: dict[str, dict[str, EntityBaseline]] = {
            "src_ip": defaultdict(EntityBaseline),
            "event_type": defaultdict(EntityBaseline),
            "dst_ip": defaultdict(EntityBaseline),
        }
        # 全局统计
        self.global_hourly_counts = [0] * 24
        self.global_event_types: dict[str, int] = defaultdict(int)
        self._last_prune = time.time()
        # Redis 持久化
        self.redis = None
        self._redis_prefix = "anomaly:baseline:"
        self._last_save = 0
        self._save_interval = 60  # 每60秒异步保存一次
        #: **基线代数**：每次基线被真正更新（非重放）就 +1，跨重启单调递增。
        #:
        #: 为什么需要它（整改方案 §十一 P2）：
        #: 有了它才能解释「同一个事件昨天 0.3、今天 0.7」——是模型变了，
        #: 还是基线变了。`baseline_samples` 只说「有多少样本」，
        #: 样本数相同但内容不同的情况它区分不了。
        #:
        #: 刻意**不**用内容哈希：哈希在每次读报告时都要重算全量基线，
        #: 成本远高于收益；而「有没有变过」这个问题只需要单调量。
        self.baseline_version = 0

    def set_redis(self, redis_client):
        """设置 Redis 客户端（用于持久化基线）"""
        self.redis = redis_client
        logger.info("AnomalyDetector: Redis persistence enabled")

    # ── 时区与事件时间（整改方案 §四）──────────────────

    @property
    def effective_timezone(self) -> str:
        """**实际生效**的时区名（不是配置值）。

        载荷里的 `timezone` 必须是这个：`timezone_name` 只是「我们想要什么」，
        而评分用的是 `self.tz` —— 两者不一致时上报配置值就是谎报。
        """
        return str(self.tz)

    def timezone_audit(self) -> dict:
        """时区解析结果的可审计快照。

        三个字段各有分工，缺一不可：
          · `timezone`          —— 实际生效的（评分真的按它做的）
          · `timezone_configured` —— 配置里写的（即使它没生效）
          · `timezone_fallback`  —— 两者是否不一致（运维告警入口）
        """
        return {
            "timezone": self.effective_timezone,
            "timezone_configured": self.timezone_name,
            "timezone_fallback": self.timezone_fallback,
        }

    @staticmethod
    def _configured_timezone() -> str:
        try:
            from config import settings
            return str(getattr(settings, "anomaly_timezone", "") or
                       DEFAULT_TIMEZONE)
        except Exception:
            return DEFAULT_TIMEZONE

    @staticmethod
    def _resolve_tz(name: str):
        """解析时区。**任何回退都必须留痕**（整改方案 §四）。

        修复前 `if not _HAS_ZONEINFO or not name: return timezone.utc`
        是一条**完全静默**的回退（实测确认无任何日志）。问题在于：
        它回退到的正是 P0-4 要消灭的那个东西 —— 服务器 UTC 钟点。
        于是缺 `tzdata` 的机器（Windows、精简 Linux 镜像）上，
        配好的 `Asia/Shanghai` 根本不生效，北京时间白天上班被判
        「非活跃时段 +0.4」、北京凌晨拿不到加分 ——
        **缺陷本身原样复活，而且一行日志都没有**。

        对照组：未知时区名一直有 warning（`Mars/Olympus`），所以
        「三条回退路径里只有最危险的那条没有告警」。
        """
        if not name:
            return timezone.utc
        if not _HAS_ZONEINFO:
            logger.warning(
                "zoneinfo 不可用（缺 tzdata？），时区 %r 配置被忽略，"
                "回退 UTC —— 时序维度将按 UTC 钟点评分，"
                "这正是整改方案 §四 要修的缺陷", name)
            return timezone.utc
        try:
            return ZoneInfo(name)
        except Exception:
            logger.warning("未知时区 %r，回退 UTC", name)
            return timezone.utc

    @staticmethod
    def _parse_timestamp(raw):
        """任意时间戳值 → aware datetime | None。

        单独抽出来是因为**事件时间**和**接收时间**共用同一套解析
        （epoch 秒 / 毫秒 / ISO8601 都要认）。两处各写一遍必然漂移：
        同一个 `1767225600000` 在两个字段里被解释成不同时间，
        是最难发现的一类缺陷。
        """
        if raw is None or raw == "":
            return None
        # epoch 秒 / 毫秒
        if isinstance(raw, (int, float)) and not isinstance(raw, bool):
            sec = float(raw)
            if sec > 1e11:              # 毫秒时间戳
                sec /= 1000.0
            try:
                return datetime.fromtimestamp(sec, tz=timezone.utc)
            except (OverflowError, OSError, ValueError):
                return None
        if isinstance(raw, str):
            text = raw.strip().replace("Z", "+00:00")
            try:
                dt = datetime.fromisoformat(text)
            except ValueError:
                try:
                    sec = float(text)
                except ValueError:
                    return None
                if sec > 1e11:
                    sec /= 1000.0
                try:
                    dt = datetime.fromtimestamp(sec, tz=timezone.utc)
                except (OverflowError, OSError, ValueError):
                    return None
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        return None

    def resolve_event_time(self, event: dict) -> tuple:
        """事件自身的时间 → (aware datetime | None, 来源字段名)。

        整改方案 §四.1/§四.5：优先用事件时间戳，而不是分析发生时的
        `datetime.now()`；缺失或非法时返回 None，由调用方标记
        inconclusive，**不静默采用当前时间**。
        """
        for fname in EVENT_TIME_FIELDS:
            if fname not in event:
                continue
            dt = self._parse_timestamp(event.get(fname))
            if dt is not None:
                return dt, fname
        return None, ""

    def _resolve_received_time(self, event: dict):
        """事件的数据接收时间 → epoch 秒 | None（整改方案 §四.4.4）。

        与 `resolve_event_time` 分开实现，因为**这是另一个量**：
        事件时间是「事情什么时候发生」，接收时间是「数据什么时候到」。

        **缺失就返回 None，不用当前时间顶替。** 修复前这里直接
        `received_ts = time.time()`，于是：

        · 名为 `received_at` 的字段，实际记录的是**分析时刻**；
        · 重放一条三个月前的事件，它显示的是「刚刚到达」；
        · **更正（2026-10-19 深夜，§9.27）**：这句原写着
          「§十三 要求的『检测延迟 = 从异常出现到被识别的时间』
          在本模块**根本算不出来**，因为没有起点」—— **过强了**。
          没有起点的是「**到达** → 识别」这一段（生产无写入方填接收时间）；
          而「**异常出现** → 识别」这一段的起点是**事件时间**，
          事件自带时间戳时它是有的。
          两者已分开计算并分别上报：
          `detection_latency_seconds`（事件时间 → 分析时刻）与
          `ingest_latency_seconds`（接收时间 → 分析时刻）。

        实测：全仓生产代码里没有任何一处写入接收时间字段，
        所以本函数目前绝大多数时候返回 None —— 这是**诚实的**：
        它把「这个量还不存在」显式暴露出来，而不是造一个看起来有的数。
        """
        for fname in RECEIVED_TIME_FIELDS:
            if fname not in event:
                continue
            # 与事件时间共用同一个解析器（`_parse_timestamp`）
            dt = self._parse_timestamp(event.get(fname))
            if dt is not None:
                return dt.timestamp()
        return None

    async def load_baselines_from_redis(self):
        """启动时从 Redis 恢复基线"""
        if not self.redis:
            return
        try:
            # 加载全局统计
            hourly = await self.redis.get(f"{self._redis_prefix}global:hourly")
            if hourly:
                import json
                self.global_hourly_counts = json.loads(hourly)
            types_data = await self.redis.get(f"{self._redis_prefix}global:event_types")
            if types_data:
                import json
                self.global_event_types = defaultdict(int, json.loads(types_data))
            ver_data = await self.redis.get(f"{self._redis_prefix}global:version")
            if ver_data:
                import json
                try:
                    self.baseline_version = int(
                        (json.loads(ver_data) or {}).get("v", 0))
                except Exception:
                    self.baseline_version = 0

            # 加载实体基线
            for entity_type in ("src_ip", "dst_ip", "event_type"):
                pattern = f"{self._redis_prefix}{entity_type}:*"
                # SCAN 分批迭代：键空间大时 KEYS 会阻塞 Redis 单线程
                keys = [
                    key async for key in self.redis.scan_iter(match=pattern, count=500)
                ]
                for key in keys:
                    data = await self.redis.get(key)
                    if data:
                        import json
                        bl_dict = json.loads(data)
                        bl = EntityBaseline(
                            hourly_counts=bl_dict.get("hourly_counts", [0] * 24),
                            daily_count=bl_dict.get("daily_count", 0),
                            weekly_count=bl_dict.get("weekly_count", 0),
                            last_seen=bl_dict.get("last_seen", 0),
                            total_count=bl_dict.get("total_count", 0),
                            event_types=set(bl_dict.get("event_types", [])),
                            first_seen=bl_dict.get("first_seen", 0),
                            recent=[tuple(x) for x in (bl_dict.get("recent") or [])
                                    if isinstance(x, (list, tuple)) and len(x) == 2],
                            # 旧基线无 recent_sev → 默认空表（无高危史）：
                            # 对既有实体等价于「窗口内没见过高危」，不会突变。
                            recent_sev=[tuple(x) for x in (bl_dict.get("recent_sev") or [])
                                        if isinstance(x, (list, tuple)) and len(x) == 2],
                            seen_ids=set(bl_dict.get("seen_ids", [])),
                        )
                        entity_key = key.decode() if isinstance(key, bytes) else key
                        entity_key = entity_key.replace(f"{self._redis_prefix}{entity_type}:", "")
                        self.baselines[entity_type][entity_key] = bl

            total_entities = sum(len(v) for v in self.baselines.values())
            logger.info(
                f"AnomalyDetector: loaded baselines from Redis: "
                f"{total_entities} entities, {sum(self.global_hourly_counts)} total events"
            )
        except Exception as e:
            logger.warning(f"Failed to load baselines from Redis: {e}")

    async def _save_baselines_to_redis(self, force: bool = False):
        """异步保存基线到 Redis（默认受 _save_interval 节流; force=True 跳过节流）"""
        if not self.redis:
            return
        now = time.time()
        if not force and now - self._last_save < self._save_interval:
            return
        self._last_save = now
        try:
            import json
            pipe = self.redis.pipeline()

            # 全局统计
            pipe.setex(
                f"{self._redis_prefix}global:hourly", 86400 * 7,
                json.dumps(self.global_hourly_counts)
            )
            pipe.setex(
                f"{self._redis_prefix}global:event_types", 86400 * 7,
                json.dumps(dict(self.global_event_types))
            )
            # 基线代数必须一起持久化：进程重启后它要继续增长，
            # 否则重启一次版本就归零，「今天比昨天基线新」这个判断
            # 会因为一次重启而变得不可信。
            pipe.setex(
                f"{self._redis_prefix}global:version", 86400 * 7,
                json.dumps({"v": int(self.baseline_version)})
            )

            # 实体基线（只保存最近活跃的）
            for entity_type in ("src_ip", "dst_ip", "event_type"):
                cutoff = now - 86400 * self.window_days
                for key, bl in list(self.baselines[entity_type].items()):
                    if bl.last_seen < cutoff:
                        continue
                    redis_key = f"{self._redis_prefix}{entity_type}:{key}"
                    pipe.setex(
                        redis_key, 86400 * 7,
                        json.dumps({
                            "hourly_counts": bl.hourly_counts,
                            "daily_count": bl.daily_count,
                            "weekly_count": bl.weekly_count,
                            "last_seen": bl.last_seen,
                            "total_count": bl.total_count,
                            # 集合型字段必须**排序**后再落库：字符串哈希每进程
                            # 随机，未排序的集合会让同一份基线在两个进程里落出
                            # **逐字节不同**的 JSON（整改方案 §七.2「重放一致性」
                            # / §9.59）。
                            "event_types": sorted(bl.event_types),
                            "first_seen": bl.first_seen,
                            "recent": [list(x) for x in bl.recent],
                            "recent_sev": [list(x) for x in (bl.recent_sev or [])],
                            "seen_ids": sorted(bl.seen_ids)[-5000:],
                            "version": self.version,
                            **self.timezone_audit(),
                        })
                    )
            await pipe.execute()
        except Exception as e:
            logger.warning(f"Failed to save baselines to Redis: {e}")

    def _prune_baselines(self):
        """清理过期基线（超过窗口期的实体）"""
        now = time.time()
        cutoff = now - self.window_days * 86400
        for entity_type in self.baselines:
            expired = [
                key for key, bl in self.baselines[entity_type].items()
                if bl.last_seen < cutoff
            ]
            for key in expired:
                del self.baselines[entity_type][key]
            if expired:
                logger.debug(f"Pruned {len(expired)} expired {entity_type} baselines")
        self._last_prune = now

    @staticmethod
    def _entity_key(value) -> tuple:
        """把事件字段规范化成**可哈希**的实体键，并标出「不可解释」的值。

        整改方案 §七.3 点名的缺陷：
          「输入中的 src_ip 等字段类型异常，可能导致统计数据结构操作失败的问题。」

        修复前 `event_type` / `src_ip` / `dst_ip` 直接当 dict 键用，
        上游传进来一个 list / dict 就抛 `TypeError: unhashable type`，
        整条分析路径崩掉。实测三种崩法：
          `baselines["src_ip"].get(src_ip)`、
          `_calc_event_rarity(event_type)`（经 `global_event_types`）、
          `_update_baseline(...)`（经 `bl.event_types.add(...)`）。

        规则（返回 `(key, usable)`）：
          - `None` / `str` / `int` / `float` / `bool` → 原样当键（都可哈希）
          - `list` / `tuple` 且**恰好一个元素** → 递归取该元素
              （`["10.0.0.1"]` 与 `"10.0.0.1"` 必须是**同一个实体**：
                否则同一条连接的两种写法会分裂成两个基线，而这是个
                上游可任意填的字段）
          - 其它（多元素序列 / dict / set / 自定义对象） → `("", False)`
              = **不可解释**。调用方据此把该维度按 inconclusive 处理、
              实体不入基线、并且**不计入全局事件类型统计**
              （否则一个畸形类型会立刻变成「从未见过」→ rarity=1.0 → 误报）。
        """
        if value is None or isinstance(value, (str, int, float, bool)):
            return value, True
        if isinstance(value, (list, tuple)):
            if len(value) == 1:
                return AnomalyDetector._entity_key(value[0])
            return "", False
        return "", False

    def _update_baseline(self, entity_type: str, entity_key: str,
                         event_type: str, hour: int, ts: float = 0.0,
                         event_id: str = "", severity: str = "info") -> bool:
        """更新实体基线。

        整改方案 §七.1：
          - 写入带时间戳的滚动窗口桶（`recent`），并按窗口过期；
          - **先读后写分离**：打分在 `_update_baseline` 之前完成；
          - 按 event_id 幂等：同一条事件重复投递不会重复计入。
          - `severity` 只服务 recent_sev（severity_shift 历史面）：
            high/critical 计 1，其余不计 —— 与打分用的 severity_prior
            是两回事，这里记录的是**实体高危史**。
        返回 False 表示该事件此前已计入，本次是重放。
        """
        bl = self.baselines[entity_type][entity_key]
        now = ts or time.time()
        if event_id:
            eid = str(event_id)
            if eid in bl.seen_ids:
                return False
            bl.seen_ids.add(eid)
            if len(bl.seen_ids) > 5000:       # 有界，防止无限增长
                # 集合**没有顺序**：`list(...) [-2500:]` 取到的是任意
                # 2500 个，而不是「最近的 2500 个」—— 而 seen_ids 是
                # **重放幂等账本**：哪条事件 id 被淘汰掉，决定了它下次
                # 重投时算不算重复消费。
                #
                # 字符串哈希每进程随机 → 淘汰结果**跨进程不确定** →
                # 同一串事件在两个进程里得到不同的基线（整改方案 §七.2
                # 「重放一致性」/ §9.59）。按字典序淘汰后结果确定。
                bl.seen_ids = set(sorted(bl.seen_ids)[-2500:])
        if bl.total_count == 0:
            bl.first_seen = now
        # `last_seen` 是**活跃度**判据（`_prune_baselines` 与落盘都只读它），
        # 所以必须是高水位：所有已见事件时间的最大值。
        #
        # 修复前这里是 `bl.last_seen = now`（覆盖式）。实测后果是
        # **乱序投递会直接杀死基线**：一条时间戳早于已见事件的事件
        # （迟到重放、离线补传、时钟漂移 —— 全都是正常业务形态，
        # 不需要伪造时间戳）会把 `last_seen` 回退到过去；而剪枝的判据只有
        # `bl.last_seen < cutoff`，于是一小时前还在活动的实体被**整条删除**，
        # 四个维度全变 inconclusive、`anomaly_score=0.0`、无异常无告警 ——
        # 该实体从此彻底失明，且没有任何痕迹表明它曾经有基线。
        #
        # 方向性提醒：下面窗口淘汰**刻意**用墙上时钟而非事件时间戳，
        # 就是为了让「发旧时间戳无限续命」失效。这两条防线必须同向，
        # 否则旧时间戳续不了命，却能让实体立刻暴毙。
        #
        # 改成 max 不会让基线超期存活：真死掉的实体（最新事件也已超窗口）
        # `last_seen` 照样停在旧值，照样被剪掉。`first_seen` 不对称
        # （仍是「首条被处理的事件」而非最早事件），但它只用于展示与落盘，
        # 不参与任何判据，本次不动。
        bl.last_seen = max(bl.last_seen, now)
        bl.total_count += 1
        bl.hourly_counts[hour % 24] += 1
        bl.event_types.add(event_type)
        # 窗口淘汰以**墙上时钟**为准，而不是事件自身时间戳。
        # 用事件时间做截止点的话，一条迟到的/被伪造时间戳的历史事件
        # 会把 cutoff 一起拉回过去，让早已过期的桶重新变得「有效」，
        # 过期数据可以靠发旧时间戳无限续命。
        cutoff = time.time() - self.window_days * 86400
        merged: dict = {}
        for entry in list(bl.recent) + [(int(now // 3600) * 3600, 1)]:
            if not (isinstance(entry, (list, tuple)) and len(entry) == 2):
                continue
            try:
                ets, c = float(entry[0]), int(entry[1])
            except (TypeError, ValueError):
                continue
            if c <= 0 or ets < cutoff:
                continue
            merged[int(ets // 3600) * 3600] = \
                merged.get(int(ets // 3600) * 3600, 0) + c
        bl.recent = sorted(merged.items())
        # 高危史与总量同一套合并/过期纪律（severity_shift 的历史面）。
        merged_sev: dict = {}
        sev_inc = 1 if str(severity or "").lower() in ("high", "critical") else 0
        for entry in list(getattr(bl, "recent_sev", []) or []) + \
                [(int(now // 3600) * 3600, sev_inc)]:
            if not (isinstance(entry, (list, tuple)) and len(entry) == 2):
                continue
            try:
                ets, c = float(entry[0]), int(entry[1])
            except (TypeError, ValueError):
                continue
            if c <= 0 or ets < cutoff:
                continue
            merged_sev[int(ets // 3600) * 3600] = \
                merged_sev.get(int(ets // 3600) * 3600, 0) + c
        bl.recent_sev = sorted(merged_sev.items())
        return True

    def decay_entity(self, entity_type: str, entity_key: str, factor: float = 0.5) -> bool:
        """按 factor 衰减实体的计数基线(learn_loop FP 收敛用)。

        只缩放 hourly_counts / daily_count / weekly_count / total_count,
        永不删除实体; 实体不存在返回 False。
        """
        bl = self.baselines.get(entity_type, {}).get(entity_key)
        if bl is None:
            return False
        try:
            factor = max(0.0, min(1.0, float(factor)))
        except (TypeError, ValueError):
            factor = 0.5
        bl.hourly_counts = [int(c * factor) for c in bl.hourly_counts]
        bl.daily_count = int(bl.daily_count * factor)
        bl.weekly_count = int(bl.weekly_count * factor)
        bl.total_count = int(bl.total_count * factor)
        bl.recent = [(ts, max(1, int(c * factor))) for ts, c in bl.recent]
        # 高危史随衰减淡出（不设 min 1 下限）：FP 收敛衰减后实体应能
        # 重新获得「窗口内零高危史」的判定 —— 否则一次误报高危永久
        # 关闭 severity_shift 证据面。归零的桶会在下次合并时被过期淘汰。
        bl.recent_sev = [(ts, int(c * factor)) for ts, c in (bl.recent_sev or [])]
        logger.info(
            f"AnomalyDetector: decayed {entity_type}/{entity_key} "
            f"by {factor:.2f} → total_count={bl.total_count}"
        )
        return True

    def _legacy_sigma(self, bl: "EntityBaseline", hour: int) -> Optional[float]:
        """旧基线回退口径：基线没有 `recent` 滚动桶时用 `hourly_counts` 计算。

        为什么要留这条路径：`hourly_counts` 是「历史第 h 个钟点的累计量」，
        不能直接当滚动窗口用；但如果对没有 `recent` 的基线直接返回 0.0，
        就会把「算不出来」谎报成「确定无偏离」—— 那是最危险的一种 bug
        （全量漏报且没有任何告警痕迹）。旧 Redis 基线在 7 天窗口被重新灌满前
        都会走这里，之后自动切回滚动窗口口径。

        与旧实现的三处刻意差异：
          1. 其余小时均值为 0 → 返回 None（无法比较），不再返回 5000.0；
          2. 所有分支统一过 `min(sigma, 10.0)`；
          3. 样本不足返回 None 而不是 0.0。

        口径自洽性：分母取 `sum(hourly_counts)` 而不是 `total_count`。
        旧实现用 `total_count - current` 做分母，而 `total_count` 与
        `hourly_counts` 并非总是同步（Redis 里的旧数据、衰减后的实体都会
        脱节），两者一脱节 `mean` 就会算错 —— 实测把同一段基线的
        「触发 3σ 所需突增量」从 22 变成「永远触发不了」。
        """
        if not (0 <= hour < len(bl.hourly_counts)):
            return None
        total = sum(bl.hourly_counts) or bl.total_count
        if total < COLD_START_MIN_SAMPLES:
            return None
        current = bl.hourly_counts[hour]
        other_total = max(0, total - current)
        mean = other_total / 23.0
        if mean <= 0:
            # 全部历史都落在同一个钟点：没有任何比较基准 → 无法判断
            return None
        std = max(1.0, math.sqrt(mean))
        if current <= mean:
            return 0.0
        return max(0.0, min((current - mean) / std, 10.0))

    def _calc_statistical_deviation(self, entity_type: str,
                                     entity_key: str,
                                     hour: int, now_ts: float = 0.0
                                     ) -> Optional[float]:
        """统计偏离度（σ）。

        整改方案 §七.3：
          - 样本不足 → 返回 **None**（= inconclusive），不再返回 0.0 冒充「无偏离」；
          - 口径改为**滚动窗口**：近 1 小时 vs 窗口内**每小时**均值；
          - 所有分支统一过 `min(sigma, 10.0)`，`mean==0` 早退不再绕过上限；
          - 旧基线（无 `recent`）走 `_legacy_sigma`，而不是静默返回 0.0。

        时均口径（整改中自查发现的真漏报）：窗口跨度是 `window_days × 24`
        小时，不是 24 小时。曾用 `window_total / 24.0` 当「每小时均值」，
        那是**日均**：7 天窗口下稳态 50 条/小时的实体算出 350 的「均值」，
        于是 σ 恒为 0，真实的 7 倍速率突增完全看不见。现在用实际跨度
        （`recent` 里最早一条到现在，上限 window_days×24）做分母，
        使成熟实体（≥ window_days）的灵敏度与基线年龄无关 —— 这正是
        §七.1「基线越厚灵敏度越低」的正解。

        Returns: σ ∈ [0, 10]，或 None（样本不足 / 无法比较）
        """
        bl = self.baselines[entity_type].get(entity_key)
        if not bl:
            return None
        if not bl.recent:
            return self._legacy_sigma(bl, hour)
        ts = now_ts or (bl.last_seen or time.time())
        samples = len(bl.recent) or bl.total_count
        if samples < COLD_START_MIN_SAMPLES:
            return None                      # 冷启动 → inconclusive

        # 近 1 小时 vs 窗口内每小时均值（滚动窗口口径）
        hour_total = bl.count_since(ts - 3600, ts)
        window_total = bl.count_since(ts - self.window_days * 86400, ts)
        if window_total <= 0:
            return None                      # 窗口内没有任何历史 → 无法比较
        span_hours = self._window_span_hours(bl, ts)
        hourly_mean = window_total / span_hours
        if hourly_mean <= 0:
            return None

        # 泊松近似：std ≈ sqrt(mean)，下限 1（计数型数据）
        std = max(1.0, math.sqrt(hourly_mean))
        if hour_total <= hourly_mean:
            return 0.0                       # 低于均值不是异常（确定结论）
        sigma = (hour_total - hourly_mean) / std
        return max(0.0, min(sigma, 10.0))    # 统一夹紧

    def _window_span_hours(self, bl: "EntityBaseline", ts: float) -> float:
        """基线实际覆盖的小时数（下限 1，上限 window_days×24）。

        用实际跨度而不是固定 window_days×24，是为了让**年轻实体**的
        均值不会被 7 天的空窗稀释 —— 否则刚上线 10 分钟的实体只要来
        1 条就会被算成 500σ。成熟实体自动收敛到固定窗口。
        """
        oldest = None
        for entry in bl.recent:
            if isinstance(entry, (list, tuple)) and len(entry) == 2:
                try:
                    t = float(entry[0])
                except (TypeError, ValueError):
                    continue
                if t > ts:
                    continue          # 迟到的历史事件：窗口右界之外不算跨度
                if oldest is None or t < oldest:
                    oldest = t
        cap = float(self.window_days * 24) or 24.0
        if oldest is None:
            return cap
        span = (ts - oldest) / 3600.0
        return max(1.0, min(span, cap))

    def _event_type_share(self, event_type: str) -> float:
        """事件类型在全局统计中的占比（分母与 _calc_event_rarity 同口径）。"""
        total = sum(self.global_hourly_counts)
        if total <= 0:
            return 0.0
        return self.global_event_types.get(event_type, 0) / total

    def _calc_event_rarity(self, event_type: str) -> Optional[float]:
        """事件类型罕见度 ∈ [0,1]，样本不足返回 None（inconclusive）。

        整改方案 §七.2：修复前的 `1 - ratio * 100` 里那个 **100 是没有依据的
        魔法数** —— 它让 rarity 变成「部署规模」的函数而不是「事件稀有性」
        的函数（实测 10 条主流 + 1 条稀有 → rarity=0，需要主流计数超过
        稀有 100 倍 rarity 才非零），小规模部署下这 20% 权重恒为 0。

        现在把 100 换成**观测到的均匀占比** `uniform = 1 / 观测类型数`：

            rarity = 1 - ratio / uniform     （ratio < uniform 时）

        语义明确且可解释：「比均匀分布罕见多少」。10:1 就是 0.82 分，
        100:1 是 0.98 分，从未见过是 1.0，与部署规模无关。

        曾试过对数写法 `1 + log10(uniform / ratio)` —— 它在 `ratio < uniform`
        的分支里恒 ≥ 1，**永远被夹到 1.0**，除了两个端点整个 [0,1] 区间
        不可达，等于把一个连续维度退化成布尔值。
        """
        total = sum(self.global_hourly_counts)
        n_types = len(self.global_event_types)
        if total < RARITY_MIN_SAMPLES or n_types < 2:
            return None
        type_count = self.global_event_types.get(event_type, 0)
        ratio = type_count / total
        uniform = 1.0 / n_types
        if ratio <= 0:
            return 1.0                      # 从未见过 → 最稀有
        if ratio >= uniform:
            # 不比均匀分布更罕见 → 0 分（有明确依据，不是魔法数）
            return 0.0
        return max(0.0, min(1.0 - ratio / uniform, 1.0))

    def _calc_temporal_anomaly(self, hour: int) -> float:
        """时序异常（在**配置时区**的小时上判定）。

        整改方案 §四：hour 必须来自事件时间 + 配置时区，
        不能再用服务器 UTC 钟点。
        """
        if hour in (0, 1, 2, 3, 4, 5):      # 凌晨
            return 0.4
        if hour in (22, 23):                # 深夜
            return 0.2
        return 0.0

    def _calc_target_concentration(self, dst_ip: str, now_ts: float) -> Optional[float]:
        """第五维：被攻击目标的速率集中度。

        刻意**复用** `_calc_statistical_deviation` 的口径，而不是另立一套
        标度 —— 整改方案 §十一要求「同一套经过校准的数学只维护一处」。
        旧实现用 `hour_total / window_total` 与固定的 `1/24` 作比较，
        那个 `1/24` 在 7 天窗口下等于「日均占比」，于是恒定速率的目标
        永远得 0 分，只有 24 倍以上的突增才有分 —— 口径不自洽。

        Returns: [0, 1] 的目标侧速率异常度，或 None（无法判断）
        """
        if not dst_ip:
            return None
        sigma = self._calc_statistical_deviation("dst_ip", dst_ip, 0, now_ts)
        if sigma is None:
            return None
        return max(0.0, min(sigma / 5.0, 1.0))

    def _calc_severity_shift(self, entity_type: str, entity_key: str,
                             severity: str, now_ts: float = 0.0) -> Optional[float]:
        """严重度偏移（§七.2 新证据维度，2026-10-25）。

        语义：**成熟基线**实体在滚动窗口内从未出现 high/critical 事件，
        当前却发出一条 → 基线相对的行为偏移，得 1.0。

        与 severity_prior（上下文）的三条硬边界：
          1. 必须有实体基线 —— 全新实体返回 None（能力不可用，维度缺席，
             不进 inconclusive：那会把「没有历史」说成「证据不足」，
             而它其实是「无从偏移」）；
          2. 窗口样本量必须 ≥ COLD_START_MIN_SAMPLES —— 与统计维度
             同一成熟度门槛，防止 2 个样本的「基线」给出满分偏移；
          3. 探针 severity 不是 high/critical → 恒 0.0（不产生证据，
             维度缺席 —— 与 temporal 的「平静即缺席」同一惯例，
             避免把现有场景的 effective_weights 全部改掉）。

        Returns: 1.0 / 0.0（可判定），None（维度缺席：无基线/样本不足）
        """
        sev_l = str(severity or "").lower()
        if sev_l not in ("high", "critical"):
            return None
        bl = self.baselines.get(entity_type, {}).get(entity_key)
        if bl is None:
            return None
        if len(bl.recent) < COLD_START_MIN_SAMPLES:
            return None
        cutoff = (now_ts or time.time()) - self.window_days * 86400
        prior = sum(
            int(c) for ts, c in (bl.recent_sev or [])
            if isinstance(ts, (int, float)) and float(ts) >= cutoff
        )
        return 0.0 if prior > 0 else 1.0

    async def analyze(self, event: dict) -> AnomalyReport:
        """分析单条事件，返回异常检测报告（**带耗时与五态埋点**的外层）。

        埋点抽在外层而不是散进 return：``_analyze_inner`` 内部有多个提前
        返回路径，漏埋点不会让任何测试变红，只会让仪表盘少一类数据。
        「inconclusive」必须单独计数 —— 把它算进 not_detected 会让
        准确率虚高（整改方案 §二 / §十一）。
        """
        _t0 = time.perf_counter()
        report = await self._analyze_inner(event)
        try:
            from core_metrics import record_detection
            record_detection("anomaly", report.status,
                             time.perf_counter() - _t0)
        except Exception:
            pass
        return report

    async def _analyze_inner(self, event: dict) -> AnomalyReport:
        """分析单条事件，返回异常检测报告。

        整改方案 §四 / §七：
          - 时序维度使用**事件时间戳 + 配置时区**，不再用 `datetime.now()`；
          - 事件时间缺失 → temporal 维度 inconclusive（不是静默用当前时间）；
          - **先读基线打分，再更新基线**（读评分分离）；
          - 证据维度分母固定，缺失维度不出证据也不抬高分母；
          - 上下文维度（severity/时段）只加成、不能独立发起告警；
          - 基线样本不足 → statistical_deviation 判 inconclusive。
        """
        event_id = event.get("event_id", 0)
        eid_key = event.get("eventId") or event_id
        severity = event.get("severity", "info")

        # ── 字段类型规范化（整改方案 §七.3 最后一条）──
        # 修复前这三个字段直接当 dict 键用；上游传进来一个 list / dict
        # 就抛 `TypeError: unhashable type`，整条分析路径崩掉
        # （生产上被 ingest 的 except 兜成 error —— 事件从此不可判定，
        #  而报告里没有任何痕迹说明是**类型**问题）。
        #
        # 现在统一规范化成可哈希的实体键，并单独标出「不可解释」的值。
        src_ip, src_ip_ok = self._entity_key(event.get("src_ip", ""))
        dst_ip, dst_ip_ok = self._entity_key(event.get("dst_ip", ""))
        event_type, event_type_ok = self._entity_key(
            event.get("event", event.get("type", "UNKNOWN")))

        # ── 事件时间（整改方案 §四.1 / §四.5）──
        event_dt, time_src = self.resolve_event_time(event)
        event_time_missing = event_dt is None
        if event_dt is not None:
            local_dt = event_dt.astimezone(self.tz)
            hour = local_dt.hour
            now_ts = event_dt.timestamp()
        else:
            # 时序维度**不**采用当前时间，标记为无法判断。
            #
            # 但统计维度（statistical_deviation / target_concentration）
            # 与基线写入仍然需要一个时间锚点，只能退到墙上时钟。
            # 这一步必须**显式披露**（见下面的 `ingest:event_time_missing`
            # 与 `analysis_window["event_time_fallback"]`），否则报告读起来
            # 像「事件自带时间」，而统计口径其实锚在「现在」。
            #
            # 顺带说明这个退让的实际代价：实测把 200 条**无时间戳**的
            # 历史日志回填进来（模拟上游丢时间戳），它们会全落进当前小时桶，
            # 该小时计数 203、σ 顶到 10.0；而同样这批事件带上真实历史
            # 时间戳时，当前小时计数只有 4、σ=0.54。是否应禁止无时间戳事件
            # 入基线，是**取舍**（挡住误报洪水 vs 丢掉「攻击者剥掉时间戳」
            # 这一路的检测力），已作为决策项上交，不在此单方面改。
            hour = None
            now_ts = time.time()
        # ── 三个时间必须分清（整改方案 §四.4.4）──
        #   event_at   —— 事情什么时候发生的（来自事件自带时间戳）
        #   received_at—— 数据什么时候到达系统的（**事件没带就是没有**）
        #   analysis_at—— 本次分析什么时候跑的（墙上时钟）
        #
        # 修复前这里写的是 `received_ts = time.time()`：分析时刻被
        # 冠以「接收时间」的名字。后果是**接收时间这个东西其实并不存在** ——
        # 重放一条三个月前的事件，`received_at` 显示的是「现在」，
        # 读的人会以为事件是刚到的；而真正的到达时间 nowhere 可查。
        # **更正（2026-10-19 深夜，§9.27）**：这里原写着
        # 「于是 §十三 要求的『检测延迟（从异常出现到被识别的时间）』
        # 在本模块根本算不出来」—— **过强了**：
        # 没有起点的是「**到达** → 识别」这一段；
        # 「**异常出现** → 识别」的起点是**事件时间**，
        # 事件自带时间戳时它是有的。
        # 两段已分开计算并分别上报（见下面的 detection_latency / ingest_latency）。
        analysis_ts = time.time()
        received_ts = self._resolve_received_time(event)
        received_at_out = None if received_ts is None else round(received_ts, 3)

        # ── 检测延迟（整改方案 §四 验收指标表）────────────────────
        #   文档原文：「检测延迟 | 从异常出现到被识别的时间」
        #
        #   **起点是事件时间**（「异常出现」），**终点是分析时刻**
        #   （「被识别」）。分析时刻即本次分析的墙钟起点。
        #
        #   事件时间缺失时**没有起点** → None，
        #   **不用墙钟顶替**：那条分支里 now_ts = time.time()，
        #   相减会得到 ~0 —— 等于谎报「延迟 0 秒」，
        #   而真实情况是「不知道这条事件是什么时候发生的」。
        #   缺就是缺，与 `received_at` 同一个口径。
        detection_latency = (
            None if event_time_missing
            else round(analysis_ts - now_ts, 3)
        )
        # 「到达 → 识别」是**另一段**，单列：
        # 生产上没有任何写入方填接收时间（实测见 §9.27），
        # 所以它当前恒为 None —— 这正是「这个量还不存在」的诚实表达。
        ingest_latency = (
            None if received_ts is None
            else round(analysis_ts - received_ts, 3)
        )

        # 定期清理过期基线（用分析时刻：基线老化本就与墙钟相关）
        if analysis_ts - self._last_prune > 3600:
            self._prune_baselines()

        # 全局统计先读后写（当前事件不参与自己的 rarity 分母）
        reasons: list[str] = []
        dimensions: dict = {}
        inconclusive: list[str] = []
        baseline_samples = 0

        if received_at_out is None:
            # 不拿分析时间顶替 —— 缺就是缺，宁可 None 也不要谎报
            reasons.append("ingest:received_time_unavailable")
        if event_time_missing:
            # 统计维度与基线写入锚在墙上时钟（见上面 else 分支的说明），
            # 留痕才不至于让「按现在统计」被读成「按事件时间统计」。
            #
            # `ingest:` 前缀不在 `veto_gates._STRONG_SIGNAL_REASONS`
            # （sigma: / ioc / anomaly: / cep_tool:）里，所以这条既不会
            # 变成强信号、也不会改变任何判定 —— 纯披露，不改分。
            reasons.append("ingest:event_time_missing")
        # 不可解释的字段类型同样留痕（同样是 `ingest:` 前缀 = 纯披露，
        # 不改分、不进 `veto_gates._STRONG_SIGNAL_REASONS`）。
        # 不留痕的话，读报告的人只会看到「这个维度 inconclusive」，
        # 猜不出是**上游字段类型坏了**还是真的样本不足。
        if not src_ip_ok:
            reasons.append("ingest:invalid_src_ip_type")
        if not dst_ip_ok:
            reasons.append("ingest:invalid_dst_ip_type")
        if not event_type_ok:
            reasons.append("ingest:invalid_event_type")

        # ── 1. 统计偏离度（先读基线）──
        dev_sigma = None
        if src_ip:
            _bl = self.baselines["src_ip"].get(src_ip)
            # 打分时**可见**的样本量（更新基线之前读），用于解释冷启动结论
            baseline_samples = len(_bl.recent) if _bl else 0
            dev_sigma = self._calc_statistical_deviation(
                "src_ip", src_ip, hour if hour is not None else 0, now_ts)
        if dev_sigma is None:
            inconclusive.append("statistical_deviation")
        else:
            dim = min(1.0, dev_sigma / 5.0)
            dimensions["statistical_deviation"] = dim
            if dev_sigma > 3:
                reasons.append(f"统计异常: {src_ip} 当前活跃度偏离基线 {dev_sigma:.1f}σ")
            elif dev_sigma > 2:
                reasons.append(f"轻度偏离: {src_ip} 活跃度偏高 ({dev_sigma:.1f}σ)")

        # ── 2. 事件罕见度（先读全局统计）──
        if event_type_ok:
            rarity = self._calc_event_rarity(event_type)
        else:
            # 事件类型不可解释 → 无法判断稀有度。
            # 绝不能把它当成「从未见过」：那会直接给出 rarity=1.0
            # 的满分罕见度，每条畸形事件都变成误报。
            rarity = None
        if rarity is None:
            inconclusive.append("rarity")
        else:
            dimensions["rarity"] = rarity
            if rarity > 0.8:
                reasons.append(
                    f"罕见事件类型: {event_type} "
                    f"(出现率约 {self._event_type_share(event_type):.2%})")

        # ── 3. 时序（事件时间 + 配置时区）──
        if hour is None:
            inconclusive.append("temporal")
        else:
            temporal = self._calc_temporal_anomaly(hour)
            if temporal > 0:
                dimensions["temporal"] = temporal
                if temporal >= 0.4:
                    reasons.append(
                        f"非活跃时段活动: {self.timezone_name} {hour} 时")

        # ── 4. 严重度先验（作为上下文，不是独立证据）──
        severity_prior = {
            "critical": 1.0, "high": 0.6, "medium": 0.3,
            "low": 0.0, "info": 0.0,
        }.get(str(severity).lower(), 0.0)
        if severity_prior > 0:
            dimensions["severity_prior"] = severity_prior

        # ── 5. 目标集中度（原先从不参与打分）──
        conc = self._calc_target_concentration(dst_ip, now_ts)
        if conc is None:
            inconclusive.append("target_concentration")
        else:
            dimensions["target_concentration"] = conc
            if conc > 0.8:
                reasons.append(f"目标集中: {dst_ip} 近一小时流量高度集中")

        # ── 6. 严重度偏移（§七.2 新证据维度, 2026-10-25）──
        # 基线相对证据：成熟实体窗口内零高危史，突然发出 high/critical。
        # 维度缺席（None）= 无基线或探针非高危 —— 不进 inconclusive，
        # 理由见 _calc_severity_shift 的 docstring。
        shift = self._calc_severity_shift(
            "src_ip", src_ip, str(severity), now_ts) if src_ip else None
        if shift is not None:
            dimensions["severity_shift"] = shift
            if shift > 0:
                reasons.append(
                    f"严重度偏移: {src_ip} 窗口内无 high/critical 史，"
                    f"当前事件 severity={severity}")

        # ── 打分：证据归一 + 上下文加成 ──
        # 证据分母固定为 EVIDENCE_TOTAL（不是「可用维度之和」）：
        # 若按可用维度重新归一，一个全新实体只剩 severity_prior 可用时
        # 会被归一成 1.0 分直接越过阈值 —— 那是冷启动误报，不是检测。
        ev_used = {k: v for k, v in EVIDENCE_DIMENSIONS.items() if k in dimensions}
        ctx_used = {k: v for k, v in CONTEXT_DIMENSIONS.items() if k in dimensions}
        effective = {}
        if ev_used:
            evidence_score = sum(
                v * dimensions[k] for k, v in ev_used.items()) / EVIDENCE_TOTAL
            context_bonus = sum(v * dimensions[k] for k, v in ctx_used.items())
            effective.update({k: round(v / EVIDENCE_TOTAL, 4) for k, v in ev_used.items()})
            effective.update({k: round(v, 4) for k, v in ctx_used.items()})
            anomaly_score = max(0.0, min(1.0, evidence_score + context_bonus))
            max_sigma = dev_sigma if (dev_sigma and dev_sigma > 0) else 0.0
            is_anomaly = anomaly_score > ANOMALY_SCORE_THRESHOLD or \
                max_sigma > SIGMA_EQUIVALENT_THRESHOLD
        else:
            # 没有任何证据维度可用 → 无法判断，只能给出上下文上限
            context_bonus = sum(v * dimensions[k] for k, v in ctx_used.items())
            effective.update({k: round(v, 4) for k, v in ctx_used.items()})
            # `sum()` 在空生成器上返回 **int 0**，而上面正常路径用
            # `max(0.0, ...)` 兜住了类型 —— 于是两条分支出来的分数类型
            # 不一致：冷启动是 `int`，正常是 `float`。
            # 值一样（0 == 0.0），但 `AnomalyReport.anomaly_score` 声明的是
            # `float`，序列化后一条是 `0` 一条是 `0.0`，
            # 任何 `isinstance(score, float)` 的消费方都会在冷启动上翻车。
            anomaly_score = float(min(context_bonus, COLD_START_SCORE_CAP))
            max_sigma = 0.0
            is_anomaly = False
        if not ev_used:
            inconclusive.append("no_evidence_dimension")

        if not reasons and is_anomaly:
            reasons.append(f"综合异常评分: {anomaly_score:.2f}")

        # ── 更新基线（打分之后；按 event_id 幂等）──
        counted = self._update_baseline("src_ip", src_ip, event_type,
                                        hour if hour is not None else 0,
                                        now_ts, eid_key,
                                        severity=str(severity)) if src_ip else False
        if dst_ip:
            # 去重键就是**事件 id 本身**。曾经写成 f"{eid_key}:dst"，
            # 而没有 event_id 时 eid_key 是 int 0 → 键变成真值字符串 "0:dst"，
            # 于是**所有**无 id 事件共享同一个去重键 → 每个 dst_ip 实体
            # 只计进第一条事件（实测 30 条只进 1 条）。
            # 后果是漏报方向：dst_ip 基线样本量不足 → 第五维
            # target_concentration 恒为 inconclusive → 它 0.2143 的有效权重
            # 结构性失效，而评分分母固定，于是分数被系统性压低。
            #
            # 后缀本来就是多余的：每个实体类型有各自的 seen_ids 集合，
            # 不共享对象，不需要靠后缀隔开命名空间。
            self._update_baseline("dst_ip", dst_ip, event_type,
                                  hour if hour is not None else 0,
                                  now_ts, eid_key,
                                  severity=str(severity))
        # 不可解释的事件类型**不入基线、也不进全局分布**：
        # 基线是「这个实体长什么样」，用一个都读不懂的值去建基线，
        # 建出来的也是读不懂的；而进了全局分布就会被当成新型事件。
        #
        # `counted_type` 是「这条事件计过没有」的判据之一（按 event_id 幂等），
        # 全局统计的幂等判定要用它（见下面的 is_replay）。
        counted_type = None
        if event_type_ok:
            counted_type = self._update_baseline(
                "event_type", event_type, event_type,
                hour if hour is not None else 0,
                now_ts, eid_key)

        # ── 全局统计也必须按 event_id 幂等（整改方案 §七.1）──
        # 「同一条事件重复投递多次，不能因为重复消费改变后续事件的评分。」
        #
        # 修复前这两行是**无条件**自增的。实体基线早就按 event_id 幂等了
        # （`bl.seen_ids`），但全局计数不是 —— 而全局计数决定 rarity 维度，
        # rarity 直接进最终加权分。实测（2026-10-19）：
        #   重投同一条事件 20 次 → global_total +21、
        #   global_event_types['BENIGN'] +20，
        #   后续事件的 rarity 0.7778 → 0.8182、总分 0.2222 → 0.2338。
        # 反方向更危险：重投一条**罕见**事件会把它自己的占比推高、
        # rarity 拉低 —— 攻击事件因此变得「不罕见」，这是**漏报**方向。
        #
        # 判据用**实体级 seen_ids**（已随基线持久化到 Redis），不新增状态面：
        # 任一实体说「这条事件我见过」就算重投。
        is_replay = (src_ip and not counted) or (event_type_ok and not counted_type)
        if not is_replay:
            self.global_hourly_counts[hour if hour is not None else 0] += 1
            if event_type_ok:
                self.global_event_types[event_type] += 1

        # ── 状态（有证据不足的维度 → inconclusive，不当作完整阴性）──
        #
        # 聚合降级（2026-10-26, PERF-OPT Wave 0-2 / 整改报告 §9.x）：
        # 修复前"任一维度 inconclusive ⇒ 整体 inconclusive"——一个 src 基线
        # 充分的成熟报告，会因 dst 侧无基线（target_concentration None）或
        # 事件缺时间戳（temporal None）被**整个作废**成「无法判定」。
        # 那是谎报的反方向：有实体证据的阴性被谎报成不可判，
        # SOC 读到的是"什么都判不了"。现在：
        #   · 至少一个**实体相对证据**可用 → 按证据判定（detected/not_detected），
        #     不可判维度保留在 inconclusive_dimensions 里逐维披露；
        #   · 一个实体相对证据都没有（全新实体/冷启动）→ 仍然整体
        #     inconclusive —— q6_3 防误报语义保持（新实体不判、不假装能判）。
        entity_evidence = any(k in dimensions for k in ENTITY_EVIDENCE_DIMENSIONS)
        if is_anomaly:
            status = "detected"
        elif inconclusive and not entity_evidence:
            status = "inconclusive"
        else:
            status = "not_detected"
        if inconclusive and entity_evidence and not is_anomaly:
            # 降级发生时留痕：这不是"干净"的阴性，而是"部分证据下的阴性"
            reasons.append(
                "partial_evidence: "
                + ",".join(sorted(inconclusive)) + " 不可判但实体证据已足判定")
        if not counted and src_ip:
            # 重放：本次没有改变基线
            reasons.append("replay:baseline_not_updated")
        if is_replay:
            # 重放：全局统计也没有被重复计数（否则会改变后续事件的 rarity）
            reasons.append("replay:global_stats_not_updated")
        elif counted:
            # 只有**真正改变了基线**才推进代数。幂等重放不打分也不改基线，
            # 若在这里也 +1，版本号就会随重放次数漂移，失去判别力。
            self.baseline_version += 1

        report = AnomalyReport(
            event_id=event_id,
            anomaly_score=round(anomaly_score, 4),
            is_anomaly=is_anomaly,
            deviation_sigma=round(max_sigma, 2),
            reasons=reasons,
            dimensions=dimensions,
            status=status,
            error_code=("cold_start_no_evidence" if not ev_used else
                        ("inconclusive_dimensions"
                         if (inconclusive and not is_anomaly and not entity_evidence)
                         else ("partial_evidence_disclosure"
                               if (inconclusive and not is_anomaly) else ""))),
            error_message=("; ".join(sorted(inconclusive)) if inconclusive else ""),
            analysis_window={
                "window_days": self.window_days,
                **self.timezone_audit(),
                "event_time_source": time_src,
                "event_time_hour": hour,
                # True = 统计维度锚在墙上时钟（事件没带时间戳）
                "event_time_fallback": event_time_missing,
                "received_at": received_at_out,
                "analysis_at": round(analysis_ts, 3),
                # 事件时间 → 分析时刻（§四 的「检测延迟」）
                "detection_latency_seconds": detection_latency,
                # 接收时间 → 分析时刻（另一段，当前生产恒为 None）
                "ingest_latency_seconds": ingest_latency,
            },
            inconclusive_dimensions=sorted(inconclusive),
            effective_weights={k: round(v, 4) for k, v in effective.items()},
            baseline_samples=baseline_samples,
            event_time_source=time_src,
            baseline_version=self.baseline_version,
        )

        if is_anomaly:
            logger.info(f"Anomaly detected: event #{event_id} "
                        f"{event_type} score={anomaly_score:.3f} "
                        f"sigma={max_sigma:.1f} reasons={reasons}")

        # 异步持久化到 Redis
        await self._save_baselines_to_redis()
        return report


# 全局单例
anomaly_detector = AnomalyDetector()
