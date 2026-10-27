"""Q5 / Q6 异常检测引擎（anomaly_detector.py）正确性审查。

**[FIXED]** 前缀 = 断言的是**整改后应当成立的行为**；
每条 docstring 都写清「修复前实测是什么」，这样测试既是回归网也是
缺陷档案。整改依据：`DETECTION_ENGINE_REVIEW.md` 的
R5-xx / R6-xx 发现，以及整改方案 §四 / §七。

修复后新增的两条硬性口径（本文件全程依赖）：

1. **事件时间驱动时序维度**。`analyze()` 不再用 `datetime.now()`，
   而是从事件的 `event_time` / `@timestamp` / `timestamp` / … 解析。
   所以测试必须显式给 `event_time`，不能再用 `frozen_clock` 冻结时钟 ——
   冻结服务器时钟在修复后**不影响** hour，这是 P0-4 的修复目标本身。

2. **打分先读基线、后更新基线**。同一 event_id 重放不再推进基线，
   因此重放得到稳定分数（修复前是 4 种分数、is_anomaly 会翻转）。

关键口径提醒（第一版探针踩过）：
`analyze()` 读的是 `event.get("event", event.get("type", ...))`，
**不是** docstring 里写的 `event_type`。生产路径
`ingest_pipeline._normalize_event()` 已保证 `log_data["event"]` 存在，
所以测试里必须用 `event=` 才能复现真实行为。
"""
import asyncio
import math
import time
from datetime import datetime, timedelta, timezone

import pytest

from anomaly_detector import (
    ANOMALY_SCORE_THRESHOLD,
    COLD_START_SCORE_CAP,
    CONTEXT_DIMENSIONS,
    CONTEXT_TOTAL,
    DIMENSION_WEIGHTS,
    EVIDENCE_DIMENSIONS,
    EVIDENCE_TOTAL,
    RARITY_MIN_SAMPLES,
    AnomalyDetector,
    EntityBaseline,
)

try:
    from zoneinfo import ZoneInfo
    _TZ = ZoneInfo("Asia/Shanghai")
except Exception:                      # pragma: no cover
    _TZ = timezone(timedelta(hours=8))

BASE = dict(event="BENIGN", severity="info", src_ip="10.0.0.1")

_LOOP = asyncio.new_event_loop()


def run(coro):
    """复用同一个事件循环 —— 每次新建 loop 会让本文件慢 1~2 个数量级。"""
    return _LOOP.run_until_complete(coro)


def ev(**kw):
    d = dict(BASE)
    d.update(kw)
    return d


def ts_at_local_hour(hour: int, days_ago: int = 1) -> float:
    """返回「days_ago 天前的本地 hour:30」的 epoch 秒。

    固定成过去时间是为了让滚动窗口基线（以 now 为右界）能覆盖它。
    """
    now = datetime.now(_TZ)
    d = (now - timedelta(days=days_ago)).replace(
        hour=hour, minute=30, second=0, microsecond=0)
    return d.timestamp()


def local_hour_of(ts: float) -> int:
    return datetime.fromtimestamp(ts, _TZ).hour


def seed_rolling(det, key, hours=7 * 24, per_hour=50, now=None,
                 etype="src_ip") -> EntityBaseline:
    """构造一个「hours 小时内每小时 per_hour 条」的稳态滚动窗口基线。

    桶从 `now - (hours-1) 小时` 排到**当前小时**，因此当前小时本身
    也有 per_hour 条 —— 否则基线缺了这一格，往当前小时注入的突增
    会与「0 条基线」比较，测出来的阈值完全不是那个意思。
    """
    now = now if now is not None else time.time()
    bl = EntityBaseline()
    t0 = int((now - (hours - 1) * 3600) // 3600) * 3600
    bl.recent = [(t0 + h * 3600, per_hour) for h in range(hours)]
    bl.total_count = hours * per_hour
    bl.hourly_counts = [per_hour * max(1, hours // 24)] * 24
    bl.last_seen = now
    det.baselines[etype][key] = bl
    return bl


def add_burst(bl: EntityBaseline, at_ts: float, count: int) -> None:
    """在 at_ts 所在小时注入一次速率突增（用于制造 statistical_deviation）。"""
    bl.recent = sorted(list(bl.recent) + [(int(at_ts // 3600) * 3600, count)])


def seed(det, n, **kw):
    for _ in range(n):
        run(det.analyze(ev(**kw)))


def seed_history(det, n, ts, event="BENIGN", **kw):
    """灌入 n 条历史事件（用给定 event_time，保证落在滚动窗口内）。"""
    for _ in range(n):
        run(det.analyze(ev(event=event, event_time=ts, **kw)))


# ══════════════════════════════════════════════════════════════
# Q6 · 五维加权评分
# ══════════════════════════════════════════════════════════════

class TestQ6WeightedScore:
    def test_q6_1_all_five_dimensions_actually_score(self):
        """[FIXED] 五个维度全部产出分数并进入最终得分。

        修复前：文件头声称 5 个检测维度，实际只有 4 个进入加权分数 ——
        第 5 项「目标IP统计」只调 `_update_baseline`，从不产出
        `dimensions` 条目、也不加 `total_score`。这是**声明与实现不符**。
        """
        T = ts_at_local_hour(3)
        det = AnomalyDetector()
        seed_history(det, 60, T - 7200)
        # rarity 需要 ≥2 种已知事件类型，否则判 inconclusive
        seed_history(det, 20, T - 7200, event="DNS_QUERY")
        bl_src = seed_rolling(det, "10.0.0.1", now=T)
        bl_dst = seed_rolling(det, "10.6.6.6", now=T, etype="dst_ip")
        add_burst(bl_src, T - 1800, 300)
        add_burst(bl_dst, T - 1800, 300)

        r = run(det.analyze(ev(src_ip="10.0.0.1", dst_ip="10.6.6.6",
                               event="ATTACK_BRUTEFORCE", severity="critical",
                               event_time=T)))
        assert set(r.dimensions) == set(DIMENSION_WEIGHTS), \
            f"只有 {sorted(r.dimensions)} 进入打分，维度声明与实现不符"
        assert r.inconclusive_dimensions == []
        assert r.status == "detected"
        assert r.is_anomaly is True

    def test_q6_2_weights_are_declared_and_split_by_role(self):
        """[FIXED] 权重和为 1.0，并显式区分「证据维度」与「上下文维度」。

        修复前：权重 0.35+0.20+0.15+0.25 = **0.95**，理论最大分 0.86，
        声明的和实现的又不一致（声明 severity 0.15，实现 0.25）。
        现在全量权重和为 1.0，且 severity 被显式归入 context ——
        上游 severity 是**上下文**，不是独立检测证据（整改方案 §七.4）。
        """
        assert abs(sum(DIMENSION_WEIGHTS.values()) - 1.0) < 1e-9
        # 证据/上下文的质量分配是**标定参数**（2026-10-25 severity_shift
        # 接入时全量重归一：0.70/0.30 → 0.74/0.26）；本条钉住的不变量是
        # 「全量权重和 = 1.0」（声明一致性）与「角色不混」（基线相对 →
        # 证据；上游静态先验 → 上下文）。
        assert abs(EVIDENCE_TOTAL - 0.74) < 1e-9
        assert abs(CONTEXT_TOTAL - 0.26) < 1e-9
        assert abs(EVIDENCE_TOTAL + CONTEXT_TOTAL - 1.0) < 1e-9
        assert set(EVIDENCE_DIMENSIONS) & set(CONTEXT_DIMENSIONS) == set()
        assert "severity_prior" in CONTEXT_DIMENSIONS
        assert "statistical_deviation" in EVIDENCE_DIMENSIONS

    def test_q6_3_new_entity_is_inconclusive_not_definitive_negative(self):
        """[FIXED] 新实体（无 src 基线）永远判不出异常，且**明确报 inconclusive**。

        修复前有两个叠加问题：
          1. `_calc_statistical_deviation` 在样本不足时返回 `0.0`，
             与「确实没有偏离」**同值不可区分** ——「没有证据 ≠ 没有威胁」
             在本模块的具体表现；
          2. 缺失维度按 0 分计入总分，新实体理论上限 0.51 < 阈值 0.60，
             于是基线不足的新实体**永远**判不出异常（漏报，且无痕迹）。

        现在：样本不足 → 该维度不出证据；整体状态是 `inconclusive`，
        `error_code` 与 `inconclusive_dimensions` 明确记录原因，
        下游融合层可以据此拒绝把它当成完整阴性。
        """
        T = ts_at_local_hour(3)
        for prior in (0, 10, 100, 300, 1000, 2000):
            det = AnomalyDetector()
            seed_history(det, prior, T - 7200)
            r = run(det.analyze(ev(src_ip="10.9.9.9", severity="critical",
                                   event="ATTACK_BRUTEFORCE", event_time=T)))
            assert r.anomaly_score < ANOMALY_SCORE_THRESHOLD, \
                f"prior={prior} 新实体得分 {r.anomaly_score} 已达阈值"
            assert r.is_anomaly is False
            assert r.status == "inconclusive", \
                f"prior={prior} 状态是 {r.status}，会被下游当成完整阴性"
            assert "statistical_deviation" in r.inconclusive_dimensions
            assert r.baseline_samples == 0

    def test_q6_3b_no_evidence_at_all_caps_score_below_threshold(self):
        """[FIXED] 一个证据维度都没有时，分数封顶在阈值以下。

        整改中自查发现的**新缺陷**：最初把「可用维度剔除 + 重新归一」
        当作 P1-2 的修法，结果新实体只剩 `severity_prior` 可用，
        被归一成 1.0 分**直接越过阈值告警** —— 换了个方向的冷启动误报。
        现在证据维度分母恒为 `EVIDENCE_TOTAL`，上下文只能加成；
        无证据时分数封顶 `COLD_START_SCORE_CAP`，且恒 < 阈值，
        这样任何按 `>= 阈值` 消费 score 的下游都不会被冷启动误触。
        """
        det = AnomalyDetector()
        r = run(det.analyze(ev(src_ip="10.9.9.9", dst_ip="10.8.8.8",
                               severity="critical",
                               event_time=ts_at_local_hour(3))))
        assert r.effective_weights                     # 只有上下文维度
        assert set(r.effective_weights) <= set(CONTEXT_DIMENSIONS)
        assert r.anomaly_score <= COLD_START_SCORE_CAP
        assert COLD_START_SCORE_CAP < ANOMALY_SCORE_THRESHOLD
        assert r.is_anomaly is False
        assert r.error_code == "cold_start_no_evidence"

    def test_q6_4_missing_evidence_dimension_does_not_inflate_score(self):
        """[FIXED] 缺失的证据维度既不记 0 分，也不把分母缩小。

        修复前：缺失维度按 0 分计入总分。修复后如果简单改成
        「剔除 + 对剩余权重归一」，一个全新的实体只剩 severity 可用时
        会被归一成 1.0 分直接告警（见 test_q6_3b）。

        现在：**证据维度分母固定**，所以
          - 老实体（有基线 + 当前小时突增）→ statistical_deviation 满分；
          - 新实体（无基线）→ 该维度不出证据；
        两者分数关系仍然是「证据越充分分越高」，但弱维度无法自我放大。
        """
        T = ts_at_local_hour(3)

        fresh = AnomalyDetector()
        seed_history(fresh, 60, T - 7200)
        r_new = run(fresh.analyze(ev(src_ip="10.9.9.9", severity="critical",
                                     event="ATTACK_BRUTEFORCE", event_time=T)))

        est = AnomalyDetector()
        seed_history(est, 60, T - 7200, src_ip="10.0.0.9")
        bl = seed_rolling(est, "10.9.9.9", now=T)
        add_burst(bl, T - 1800, 300)
        r_old = run(est.analyze(ev(src_ip="10.9.9.9", severity="critical",
                                   event="ATTACK_BRUTEFORCE", event_time=T)))

        assert "statistical_deviation" not in r_new.dimensions
        assert "statistical_deviation" in r_old.dimensions
        assert r_old.anomaly_score > r_new.anomaly_score, \
            "证据充分的老实体分数反而更低 —— 权重口径有问题"
        assert r_old.is_anomaly is True
        assert r_new.is_anomaly is False
        # 证据维度的实际权重分母恒定。
        # effective_weights 是 4 位显示口径（round(v,4)），比较全精度值时
        # 容差必须容纳显示舍入（abs=1e-4），默认 rel 容差会太紧。
        assert r_old.effective_weights["statistical_deviation"] == \
            pytest.approx(EVIDENCE_DIMENSIONS["statistical_deviation"] / EVIDENCE_TOTAL,
                          abs=1e-4)

    def test_q6_5_severity_is_context_not_evidence(self):
        """[FIXED] severity 只作为上下文加成，权重 0.15，且不能独立发起告警。

        修复前：severity 是**权重最大的维度之一**（0.25，仅次于 0.35），
        同一条日志只改 severity 字段分数就线性变化 0.25 —— 它是输入回显，
        不构成任何独立检测信号，却占 25% 的决定权。
        现在降为上下文权重 0.15，且**必须先有证据维度**才参与判定。
        """
        T = ts_at_local_hour(3)

        def seeded():
            d = AnomalyDetector()
            seed_history(d, 200, T - 7200)
            return d

        base = run(seeded().analyze(ev(severity="info", event_time=T)))
        crit = run(seeded().analyze(ev(severity="critical", event_time=T)))
        assert crit.anomaly_score - base.anomaly_score == \
            pytest.approx(CONTEXT_DIMENSIONS["severity_prior"], abs=1e-9)
        assert CONTEXT_DIMENSIONS["severity_prior"] < EVIDENCE_DIMENSIONS["rarity"]
        assert base.dimensions.get("severity_prior") is None, \
            "severity=info 时不应产出 severity_prior 维度"

    def test_q6_6_rarity_has_no_magic_constant(self):
        """[FIXED] rarity 与部署规模无关，用「观测到的均匀占比」取代魔法数 100。

        修复前：`1 - ratio * 100` 里的 100 没有依据，导致
        10 条主流 + 1 条稀有 → rarity=0，要主流计数超过稀有 **100 倍**
        rarity 才非零。小规模部署下这 20% 权重的维度恒为 0。

        （整改中途试过对数写法 `1 + log10(uniform/ratio)`，发现它在
          `ratio < uniform` 分支里恒 ≥ 1、**永远被夹到 1.0**，
          等于把连续维度退化成布尔值，已弃用。）
        """
        def rarity_of(n_benign, n_attack):
            det = AnomalyDetector()
            det.global_event_types = {"BENIGN": n_benign,
                                      "ATTACK_BRUTEFORCE": n_attack}
            det.global_hourly_counts = [0] * 24
            det.global_hourly_counts[0] = n_benign + n_attack
            return det._calc_event_rarity("ATTACK_BRUTEFORCE")

        assert rarity_of(10, 1) > 0.8, "10:1 的不平衡仍判为不稀有 —— 魔法数还在"
        assert rarity_of(99, 1) == pytest.approx(1 - (1 / 100) / 0.5, abs=1e-9)
        assert rarity_of(9, 9) == 0.0           # 与均匀分布相同 → 不算罕见
        assert rarity_of(1, 99) == 0.0          # 比均匀分布更常见 → 0
        assert rarity_of(20, 0) == 1.0          # 从未见过 → 最稀有
        assert rarity_of(9999, 1) > rarity_of(99, 1), "越罕见分越高"
        assert rarity_of(RARITY_MIN_SAMPLES - 1, 0) is None
        assert rarity_of(RARITY_MIN_SAMPLES, 0) is not None


# ══════════════════════════════════════════════════════════════
# Q5 · 统计偏离度的输入、边界与口径
# ══════════════════════════════════════════════════════════════

class TestQ5PoissonBounds:
    def test_q5_1_sigma_is_always_clamped(self):
        """[FIXED] σ 恒 ≤ 10.0；没有比较基准时返回 None 而不是天文数字。

        修复前：`other_hours_total == 0` 的早退分支**绕过了**
        `min(sigma, 10.0)`，实测返回 5000.0，直接进
        `AnomalyReport.deviation_sigma` 与日志文本（分数侧被
        `min(1.0, dev/5.0)` 兜住了，报告字段没有）。

        而且那条早退分支的语义本身是错的：全部历史都落在同一个钟点，
        意味着**没有任何比较基准**，不是「偏离 5000σ」。
        现在这种情况返回 None（无法判断），不会变成异常。
        """
        det = AnomalyDetector()
        bl = EntityBaseline(total_count=5000)
        bl.hourly_counts = [0] * 24
        bl.hourly_counts[3] = 5000             # 历史全部落在 03 点
        det.baselines["src_ip"]["10.5.5.5"] = bl
        assert det._calc_statistical_deviation("src_ip", "10.5.5.5", 3) is None

        # 对照：口径自洽的基线，03 点突增 +400 → σ 被夹在 10
        hourly = [1000] * 24
        hourly[3] += 400
        det.baselines["src_ip"]["10.5.6.6"] = EntityBaseline(
            total_count=sum(hourly), hourly_counts=hourly)
        assert det._calc_statistical_deviation("src_ip", "10.5.6.6", 3) == 10.0

    def test_q5_2_too_few_samples_is_none_not_zero(self):
        """[FIXED] 样本不足返回 None，并被记进 inconclusive_dimensions。

        修复前：`total_count < 3` 返回 `0.0`，与「偏离度确实为 0」同值，
        报告里没有任何标记。正例场景：基线只有 2 条的源 IP，
        此刻可能正在高速爆发 —— 那正是新源 IP 扫描的形态。
        """
        det = AnomalyDetector()
        seed_history(det, 2, ts_at_local_hour(3), src_ip="10.7.7.7")
        bl = det.baselines["src_ip"]["10.7.7.7"]
        assert bl.total_count == 2             # 计数确实存在
        assert det._calc_statistical_deviation("src_ip", "10.7.7.7", 3) is None

        r = run(det.analyze(ev(src_ip="10.7.7.7", event_time=time.time())))
        assert "statistical_deviation" not in r.dimensions
        assert "statistical_deviation" in r.inconclusive_dimensions
        assert r.status == "inconclusive"

    def test_q5_3_analyze_is_idempotent_on_replay(self):
        """[FIXED] 同一事件重放 6 次得到同一个分数，is_anomaly 不翻转。

        修复前：`analyze()` 内部先读基线、后 `_update_baseline`，
        属于有状态推进 —— 同一事件重放得到 4 种分数
        `[0.15, 0.15, 0.15, 0.36, 0.43, 0.50]`，is_anomaly 在第 5 次翻转。
        审查问题「相同输入能否稳定复现」对异常检测的答案曾是「不能」。

        现在：打分先读基线、打分后才更新基线，且基线更新按 event_id 幂等。
        """
        det = AnomalyDetector()
        e = ev(src_ip="10.0.0.5", severity="high", event="X", event_id=4242)
        seq = [run(det.analyze(dict(e))) for _ in range(6)]
        scores = [r.anomaly_score for r in seq]
        flags = [r.is_anomaly for r in seq]
        assert len(set(scores)) == 1, f"重放序列仍有漂移: {scores}"
        assert len(set(flags)) == 1, f"is_anomaly 仍会翻转: {flags}"
        assert any("replay:baseline_not_updated" in r.reasons for r in seq), \
            "重放没有留下任何痕迹 —— 幂等是靠静默实现的"
        # 幂等后基线只应该被计入一次
        assert det.baselines["src_ip"]["10.0.0.5"].total_count == 1

    def test_q5_4_temporal_uses_event_time_in_configured_timezone(self):
        """[FIXED] temporal 由**事件时间 + 配置时区**决定，与服务器时钟无关。

        修复前：temporal 用服务器 UTC 钟点。
        UTC 0-5 点 = 北京 8-13 点（正常上班）→ 被判「非活跃时段 +0.4」；
        北京真正的凌晨 0-5 点 = UTC 16-21 → temporal 恒为 0.0。
        对国内部署语义完全反转，且**没有任何开关能改**。
        """
        det = AnomalyDetector()
        assert det._calc_temporal_anomaly(2) == 0.4       # 本地 02:00
        assert det._calc_temporal_anomaly(23) == 0.2      # 本地 23:00
        assert det._calc_temporal_anomaly(12) == 0.0      # 本地中午

        # 北京凌晨 03:30 的事件，无论分析发生在什么钟点，都要判为时序异常
        T = ts_at_local_hour(3)
        assert local_hour_of(T) == 3
        r = run(AnomalyDetector().analyze(ev(event_time=T)))
        assert r.dimensions.get("temporal") == 0.4
        assert r.analysis_window["event_time_source"] == "event_time"

        # 事件没有时间戳 → temporal 不可判，而不是静默用「现在」
        r2 = run(AnomalyDetector().analyze(ev()))
        assert "temporal" not in r2.dimensions
        assert "temporal" in r2.inconclusive_dimensions
        assert r2.event_time_source == ""

    def test_q5_5_baseline_slides_out_of_the_window(self):
        """[FIXED] 基线是**滚动窗口**，超窗数据会被淘汰。

        修复前：文档声称「滑动窗口（默认7天）」，实际
        `hourly_counts` / `total_count` 无限累计永不衰减 ——
        7 天只体现在 Redis TTL 与 `_prune_baselines` 的实体删除上。

        判定口径：`recent` 滚动桶里只保留 window_days 天内的数据，
        `total_count` 保留累计值仅作展示/兼容（不再参与打分）。
        """
        det = AnomalyDetector()
        now = time.time()
        bl = seed_rolling(det, "10.0.0.1", hours=7 * 24, now=now)
        assert len(bl.recent) == 7 * 24
        assert det.window_days == 7

        # 8 天前的桶在下次更新时被淘汰
        det._update_baseline("src_ip", "10.0.0.1", "BENIGN", 3,
                             now - 8 * 86400, "e1")
        cutoff = time.time() - 7 * 86400
        assert all(ts >= cutoff for ts, _ in det.baselines["src_ip"]["10.0.0.1"].recent)

    def test_q5_6_sensitivity_is_independent_of_baseline_age(self):
        """[FIXED] 触发同一 σ 所需的突增量**不随基线年龄增长**。

        修复前：实测触发 σ>3 的最小突增量（基准每小时 50 条）
        1 天需 +21、7 天 +54、30 天 +112、60 天 +158 ——
        老实体基线越厚越难被判异常，**越老的资产越安全**，与直觉相反。

        根因是 `hourly_counts[h]` 是「历史第 h 个钟点的累计量」，
        分母随历史无限增长，σ = (current - mean)/std 的分子被摊薄。

        现在口径是滚动窗口 + **实际跨度小时数**做分母
        （上限 window_days×24），成熟实体的每小时均值恒等于自身速率，
        于是灵敏度与年龄无关。
        """
        thresholds = {}
        for days in (1, 7, 30, 60, 120):
            det = AnomalyDetector()
            bl = seed_rolling(det, "old", hours=days * 24, now=time.time())
            lo, hi = 0, 200
            while lo < hi:
                mid = (lo + hi) // 2
                bl2 = seed_rolling(det, "probe", hours=days * 24)
                add_burst(bl2, time.time(), mid)
                v = det._calc_statistical_deviation("src_ip", "probe", 0,
                                                     time.time())
                if (v or 0) > 3.0:
                    hi = mid
                else:
                    lo = mid + 1
            thresholds[days] = lo
        assert thresholds[7] == thresholds[30] == thresholds[60] \
            == thresholds[120], f"灵敏度仍随基线年龄衰减: {thresholds}"
        # 1 天基线的跨度还没填满窗口（span < window_days×24），
        # 均值天然偏高一点点，阈值略高属于**预期**，不是年龄衰减。
        assert thresholds[1] >= thresholds[7], \
            f"阈值随基线年龄单调上升: {thresholds}"
        assert thresholds[1] - thresholds[7] <= 5, \
            f"年轻实体的灵敏度偏差过大: {thresholds}"

    def test_q5_6b_rolling_window_mean_is_hourly_not_daily(self):
        """[FIXED] 窗口均值是**每小时**均值，不是日均。

        整改中自查发现的真漏报：曾用 `window_total / 24.0` 当
        「每小时均值」，那其实是**日均**。7 天窗口下稳态 50 条/小时的
        实体算出 350 的「均值」，于是 σ 恒为 0 ——
        **真实的 7 倍速率突增完全看不见，而且没有任何告警痕迹**。
        """
        now = time.time()
        det = AnomalyDetector()
        bl = seed_rolling(det, "steady7", hours=7 * 24, per_hour=50, now=now)
        assert det._calc_statistical_deviation("src_ip", "steady7", 0, now) == 0.0
        add_burst(bl, now, 300)               # 50/h → 350/h，7 倍
        assert bl.count_since(now - 3600, now) == 350
        assert det._calc_statistical_deviation("src_ip", "steady7", 0, now) == 10.0

    def test_q5_7_steady_entity_scores_exactly_zero(self):
        """[FIXED] 完全规律的实体 σ 恒为 0.0（有比较基准且确实无偏离）。"""
        det = AnomalyDetector()
        now = time.time()
        seed_rolling(det, "steady", hours=30 * 24, per_hour=50, now=now)
        assert det._calc_statistical_deviation("src_ip", "steady", 0, now) == 0.0

    def test_q5_8_empty_src_ip_marks_dimension_inconclusive(self):
        """[FIXED] src_ip 为空时该维度标记为不可判，而不是静默消失。

        修复前：`src_ip` 为空时 dim1 连 0 都不记，报告里既没有维度、
        也没有任何标记，**无法区分「无 IP」与「无偏离」**。
        """
        det = AnomalyDetector()
        seed_history(det, 300, time.time() - 7200)
        r = run(det.analyze(ev(src_ip="", severity="critical")))
        assert "statistical_deviation" not in r.dimensions
        assert "statistical_deviation" in r.inconclusive_dimensions
        assert r.status == "inconclusive"
        assert r.anomaly_score <= COLD_START_SCORE_CAP
# ══════════════════════════════════════════════════════════════
# 畸形字段类型 · 整改方案 §七.3 最后一条
# ══════════════════════════════════════════════════════════════

class TestMalformedFieldTypeRobustness:
    """输入字段类型异常不得让统计数据结构操作失败。

    整改方案 §七.3 点名的最后一条缺陷：
      「输入中的 src_ip 等字段类型异常，可能导致统计数据结构操作失败的问题。」

    修复前（2026-10-19 实测复现）：`event_type` / `src_ip` / `dst_ip`
    直接当 dict 键用，上游传进来一个 list / dict 就抛
    `TypeError: unhashable type` —— 整条分析路径崩掉，三种崩法：

        baselines["src_ip"].get(src_ip)
        _calc_event_rarity(event_type)          # 经 global_event_types
        _update_baseline(...)                   # 经 bl.event_types.add(...)

    生产上它被 ingest 的 `except` 兜成 error：事件从此不可判定，
    而报告里没有任何痕迹说明这是**上游字段类型坏了**。
    """

    # 真正「不可解释」的值：dict / 多元素序列
    MALFORMED = [
        ("src_ip", {"ip": "10.0.0.1"}),
        ("src_ip", ["10.0.0.1", "10.0.0.2"]),
        ("dst_ip", {"ip": "10.0.0.2"}),
        ("dst_ip", ["10.0.0.2", "10.0.0.3"]),
        ("event", {"type": "BENIGN"}),
        ("event", ["BENIGN", "OTHER"]),
    ]

    def test_mf_1_malformed_field_types_do_not_crash_the_analysis(self):
        """【已修复】畸形字段类型不得让分析路径崩溃。"""
        det = AnomalyDetector()
        for field, value in self.MALFORMED:
            r = run(det.analyze(ev(**{field: value})))
            # 前提守卫：报告真的产出了（不是被 except 吞掉的 None）
            assert r is not None, (field, value)
            assert r.anomaly_score is not None, (field, value, r.anomaly_score)
            # 不可解释 → 该维度不可判定，**不能**当成完整阴性
            assert r.status == "inconclusive", (field, value, r.status)
            assert r.inconclusive_dimensions, (field, value, r.inconclusive_dimensions)
            # 必须留下痕迹，否则读报告的人猜不出是类型坏了还是样本不足
            assert any(x.startswith("ingest:invalid_") for x in r.reasons), \
                (field, value, r.reasons)

    def test_mf_2_malformed_event_type_stays_out_of_the_global_distribution(self):
        """【已修复】畸形事件类型不得进全局分布。

        否则它会立刻变成「从未见过」→ rarity=1.0 → 每条畸形事件都误报。
        方向很重要：这一条防的是**误报**，不是漏报。
        """
        det = AnomalyDetector()
        # 先灌两种正常事件类型，把稀有度的分母建立起来
        seed(det, 30, event="BENIGN")
        seed(det, 30, event="DNS_QUERY")
        before = dict(det.global_event_types)
        assert len(before) >= 2, "前提守卫：全局事件类型不足两种，稀有度判不了"

        r = run(det.analyze(ev(event={"type": "BENIGN"})))
        assert r.status == "inconclusive", r.status
        assert "rarity" in r.inconclusive_dimensions, r.inconclusive_dimensions
        assert "ingest:invalid_event_type" in r.reasons, r.reasons
        assert det.global_event_types == before, \
            "畸形事件类型进了全局分布：%r" % dict(det.global_event_types)

    def test_mf_3_single_element_list_is_the_same_entity(self):
        """【已修复】`["10.0.0.1"]` 与 `"10.0.0.1"` 必须是**同一个实体**。

        否则同一条连接的两种写法会分裂成两个基线 ——
        而 `src_ip` 是个上游可任意填的字段。
        """
        det = AnomalyDetector()
        run(det.analyze(ev(src_ip="10.0.0.1", event_id=1)))
        r2 = run(det.analyze(ev(src_ip=["10.0.0.1"], event_id=2)))

        keys = set(det.baselines["src_ip"].keys())
        assert keys == {"10.0.0.1"}, \
            "单元素列表与标量分裂成了两个基线实体：%r" % keys
        # 单元素列表是**可解释**的（就是那个标量），不应被标成非法类型
        assert not any(x.startswith("ingest:invalid_") for x in r2.reasons), r2.reasons

    def test_mf_4_malformed_values_create_no_baseline_entities(self):
        """【已修复】不可解释的值不得建出基线实体。

        基线是「这个实体长什么样」——用一个都读不懂的值去建基线，
        建出来的也是读不懂的。

        注意口径：BASE 事件里**合法**的 `src_ip` / `event` 仍然会正常建基线，
        所以这里断言的是「占位键没进来」与「畸形字段所属的实体类型为空」，
        而不是「一个基线都不许有」。
        """
        det = AnomalyDetector()
        for field, value in self.MALFORMED:
            run(det.analyze(ev(**{field: value})))
        for entity_type in ("src_ip", "dst_ip", "event_type"):
            keys = set(det.baselines[entity_type].keys())
            # 不可解释的值会落到占位键 ""，它**不得**进基线
            assert "" not in keys, \
                "%s 建出了无法解释的基线实体：%r" % (entity_type, keys)
        # dst_ip 的两个用例都是畸形值，其余用例根本没带 dst_ip
        # → 不得建出任何 dst_ip 实体
        assert set(det.baselines["dst_ip"].keys()) == set(), \
            "畸形 dst_ip 建出了基线实体：%r" % set(det.baselines["dst_ip"].keys())
# ══════════════════════════════════════════════════════════════
# 重放幂等 · 整改方案 §七.1 末条
# ══════════════════════════════════════════════════════════════

class TestReplayIdempotency:
    """重复投递同一条事件，不得改变后续事件的评分。

    整改方案 §七.1：
      「如果平台允许重复消息，基线更新还应当对事件 ID 幂等。
        同一条事件重复投递多次，不能因为重复消费改变后续事件的评分。」

    修复前（2026-10-19 实测复现）：**实体基线**早就按 event_id 幂等了
    （`bl.seen_ids`），但**全局统计**是无条件自增的 —— 而全局统计
    （`global_hourly_counts` / `global_event_types`）决定 rarity 维度，
    rarity 直接进最终加权分。实测重投同一条事件 20 次：

        global_total        +21   （期望 +0）
        global_event_types  BENIGN +20 （期望 +0）
        后续事件 rarity     0.7778 → 0.8182
        后续事件 总分        0.2222 → 0.2338

    反方向更危险：重投一条**罕见**事件会把它自己的占比推高、rarity 拉低
    —— 攻击事件因此变得「不罕见」，这是**漏报**方向。
    """

    @staticmethod
    def _build():
        """建一个内容确定的检测器（两种常见类型 + 一种罕见类型）。"""
        det = AnomalyDetector()
        for i in range(40):
            run(det.analyze(ev(event="BENIGN", event_id=f"b{i}")))
        for i in range(5):
            run(det.analyze(ev(event="RARE_TYPE", event_id=f"r{i}")))
        return det

    def test_rp_1_replaying_the_same_event_does_not_change_global_stats(self):
        """【已修复】重投同一条事件不得改变全局统计。"""
        det = self._build()
        before_total = sum(det.global_hourly_counts)
        before_types = dict(det.global_event_types)
        assert before_total > 0, "前提守卫：全局统计为空，比对无意义"

        for _ in range(20):
            run(det.analyze(ev(event="BENIGN", event_id="b0")))

        assert sum(det.global_hourly_counts) == before_total, (
            "重投 20 次把全局总数从 %d 推到 %d" % (
                before_total, sum(det.global_hourly_counts)))
        assert dict(det.global_event_types) == before_types, (
            "重投 20 次改了全局事件类型分布：%r -> %r" % (
                before_types, dict(det.global_event_types)))

    def test_rp_2_replays_do_not_change_the_score_of_later_events(self):
        """【已修复】重复投递不得改变后续事件的评分（§七.1 原文要求）。

        对照实验：两个**内容完全相同**的检测器，一个被重投 20 次同一条事件，
        一个没有；随后给两者各送一条**同样的**后续事件 →
        评分、维度、状态必须逐位相同。
        """
        a = self._build()
        b = self._build()

        # 前提守卫：实体基线本来就幂等（这条是修复前就成立的性质），
        # 用来证明「这 20 次确实是重投、且去重机制是活的」
        assert (a.baselines["src_ip"]["10.0.0.1"].total_count
                == b.baselines["src_ip"]["10.0.0.1"].total_count), \
            "前提失效：实体基线本身就没幂等"

        # 只有 a 被重投同一条事件（Kafka 至少一次投递的常态）
        for _ in range(20):
            run(a.analyze(ev(event="BENIGN", event_id="b0")))

        probe_a = run(a.analyze(ev(event="RARE_TYPE", event_id="probe")))
        probe_b = run(b.analyze(ev(event="RARE_TYPE", event_id="probe")))

        assert probe_a.anomaly_score == probe_b.anomaly_score, (
            "重复消费改变了后续事件的评分：%r vs %r" % (
                probe_a.anomaly_score, probe_b.anomaly_score))
        assert probe_a.dimensions == probe_b.dimensions, (
            "重复消费改变了后续事件的维度分：%r vs %r" % (
                probe_a.dimensions, probe_b.dimensions))
        assert probe_a.status == probe_b.status, (
            "重复消费改变了后续事件的状态：%r vs %r" % (
                probe_a.status, probe_b.status))
# ══════════════════════════════════════════════════════════════
# 去重键撞车 · 整改方案 §七.1 幂等前提
# ══════════════════════════════════════════════════════════════

class TestDedupKeyCollision:
    """去重键不能因为「合成后缀」而互相撞车。

    整改方案 §七.1 要求基线更新按 event_id 幂等。
    但**幂等的前提是能区分「不同的事件」**。

    修复前（2026-10-19 实测复现）：`_update_baseline` 的调用把去重键写成

        src_ip     → eid_key
        dst_ip     → f"{eid_key}:dst"
        event_type → f"{eid_key}:type"

    而没有 event_id 时 `eid_key` 是 int 0 → 两个键都变成**真值**字符串
    "0:dst" / "0:type"，于是**所有**无 id 事件共享同一个去重键 →
    每个实体只计进**第一条**事件（实测灌 30 条只进 1 条）。

    后果是**漏报**方向：dst_ip 基线样本量不足 → 第五维
    `target_concentration` 恒为 inconclusive → 它 0.2143 的有效权重
    （0.15/0.70）在无 id 事件上**结构性失效**；而评分分母固定
    （EVIDENCE_TOTAL），于是每条无 id 事件的分数被系统性压低最多 0.2143。

    这一条此前**没有任何测试发现**：既有用例要么用唯一 id（不撞车），
    要么用 `seed_rolling()` 直接改 `bl.recent`（绕过 `_update_baseline`）。
    """

    @staticmethod
    def _seed(det, n=30, **kw):
        for _ in range(n):
            run(det.analyze(ev(**kw)))

    def test_dk_1_events_without_event_id_accumulate_the_baseline(self):
        """【已修复】无 event_id 的事件必须正常累进基线。"""
        det = AnomalyDetector()
        self._seed(det, 30, src_ip="10.0.0.1", dst_ip="10.0.0.2")
        for etype, key in (("src_ip", "10.0.0.1"),
                           ("dst_ip", "10.0.0.2"),
                           ("event_type", "BENIGN")):
            n = det.baselines[etype][key].total_count
            assert n == 30,                 "%s 基线只记进 %d 条（期望 30）—— 去重键互相撞车了" % (etype, n)

    def test_dk_2_replays_still_do_not_accumulate(self):
        """【已修复】去重键改了，但**重投仍然要去重**。

        本组用例的另一半：只修撞车不修幂等，等于把重投也放进来。
        """
        det = AnomalyDetector()
        self._seed(det, 5, src_ip="10.0.0.1", dst_ip="10.0.0.2", event_id="same")
        for etype, key in (("src_ip", "10.0.0.1"),
                           ("dst_ip", "10.0.0.2"),
                           ("event_type", "BENIGN")):
            n = det.baselines[etype][key].total_count
            assert n == 1,                 "%s 基线把同一条事件计了 %d 次（期望 1）" % (etype, n)

    def test_dk_3_fifth_dimension_is_not_structurally_dead(self):
        """【已修复】第五维 `target_concentration` 不得对无 id 事件恒为 inconclusive。

        这是本缺陷的**检测层后果**：dst_ip 基线记不满 → 样本量不足 →
        第五维永远判不了 → 它那 0.2143 的有效权重结构性失效。
        """
        det = AnomalyDetector()
        now = time.time()
        # 跨 8 个小时桶播种（样本量按**桶数**算，COLD_START_MIN_SAMPLES=5）
        for h in range(8):
            for _ in range(5):
                run(det.analyze(ev(src_ip="10.0.0.1", dst_ip="10.0.0.2",
                                    event_time=now - h * 3600)))
        r = run(det.analyze(ev(src_ip="10.0.0.1", dst_ip="10.0.0.2",
                               event_time=now)))
        assert "target_concentration" in r.dimensions, (
            "第五维对无 id 事件不可判定（inconclusive=%r）" % r.inconclusive_dimensions)
        assert "target_concentration" not in r.inconclusive_dimensions, \
            r.inconclusive_dimensions
        assert r.effective_weights.get("target_concentration", 0) > 0, \
            r.effective_weights
