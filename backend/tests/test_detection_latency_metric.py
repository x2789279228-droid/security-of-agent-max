# -*- coding: utf-8 -*-
"""整改方案 §四 验收指标表的「检测延迟 | 从异常出现到被识别的时间」。

## 这条指标此前**既没算也没报**

§四 的「异常检测验收指标」表列了 6 项，其中第 4 项是：

    检测延迟 | 从异常出现到被识别的时间

实测（修复前）：`anomaly_detector.analyze()` 的 `analysis_window` 里
有 `event_time_source` / `received_at` / `analysis_at` 三个时间，
**但没有任何一个是它们的差** —— 延迟这个量在整仓里不存在。
评估器也不报它。

而 `anomaly_detector.py` 的注释里还写着「§十三 要求的『检测延迟』在本模块
**根本算不出来**，因为没有起点」——**这句话过强了**（见 §9.27）：
没有起点的是「**到达** → 识别」这一段（生产无写入方填接收时间），
而「**异常出现** → 识别」的起点是**事件时间**，事件自带时间戳时它是有的。

## 两条延迟必须分开

| 字段 | 起点 → 终点 | 生产可得性 |
|---|---|---|
| `detection_latency_seconds` | **事件时间** → 分析时刻 | 事件带时间戳时可得 |
| `ingest_latency_seconds` | **接收时间** → 分析时刻 | 当前**恒为 None**（无写入方） |

混成一条就会把「不知道」读成「很快」。

## 判据为什么这样写

* **缺就是缺，不给 0** —— 事件时间缺失时那条分支里 `now_ts = time.time()`，
  相减会得到 ~0，等于**谎报「延迟 0 秒」**。
* **纯披露** —— 指标不得进入 `reasons`（`reasons` 喂 `veto_gates`）、
  不得影响 `status` / `score` / `effective_weights`。
* **前提守卫** —— 必须证明延迟取自**事件时间**而不是墙钟；
  否则某天有人改成 `analysis_ts - time.time()`，它会恒为 0 而**照样绿**。
"""
import asyncio
import os
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from anomaly_detector import AnomalyDetector  # noqa: E402

# ── helpers ─────────────────────────────────────────────────────────


def _ev(ts=None, **extra):
    e = {"event_id": "lat-1", "event": "BENIGN", "severity": "info",
         "src_ip": "10.1.1.1"}
    if ts is not None:
        e["timestamp"] = ts
    e.update(extra)
    return e


def _analyze(det, event):
    return asyncio.run(det.analyze(dict(event)))


def _win(rep):
    return rep.analysis_window or {}


# ── 生产路径：这条指标真的被算出来了 ────────────────────────────────


class TestDetectionLatencyIsComputed:
    def test_latency_equals_the_gap_between_event_time_and_analysis(self):
        """事件 3 小时前发生 → 延迟 ≈ 10800 秒。"""
        det = AnomalyDetector()
        event_ts = time.time() - 3 * 3600
        rep = _analyze(det, _ev(ts=event_ts))
        w = _win(rep)
        assert w.get("detection_latency_seconds") is not None, (
            f"事件带时间戳却没报检测延迟：{w}")
        assert w["detection_latency_seconds"] == pytest.approx(3 * 3600, abs=5), (
            f"延迟不是「事件时间 → 分析时刻」的差：{w['detection_latency_seconds']}")
        # 必须与 analysis_window 里的两个端点自洽
        assert w["detection_latency_seconds"] == pytest.approx(
            w["analysis_at"] - event_ts, abs=1.0), (
            "延迟与 analysis_window 里的端点对不上")

    def test_latency_is_none_when_the_event_time_is_missing(self):
        """**缺就是缺，不给 0。**

        事件时间缺失时 `now_ts` 退化成墙钟，相减会得到 ~0 ——
        那是谎报「延迟 0 秒」，而真实情况是「不知道这条事件什么时候发生」。
        """
        det = AnomalyDetector()
        rep = _analyze(det, _ev())
        w = _win(rep)
        assert w.get("event_time_fallback") is True, (
            f"前提不成立：事件没时间戳却没走回退分支：{w}")
        assert w.get("detection_latency_seconds") is None, (
            f"事件时间缺失时延迟必须是 None，实际 {w.get('detection_latency_seconds')!r} "
            f"—— 那是在谎报「延迟 0 秒」")
        assert any("event_time_missing" in x for x in rep.reasons), (
            f"事件时间缺失却没留痕：{rep.reasons}")

    def test_the_latency_tracks_the_event_time_not_the_wall_clock(self, monkeypatch):
        """**前提守卫**：延迟必须取自**事件时间**。

        把墙钟钉在远离事件时间的地方，延迟必须随之变化 ——
        若某天有人改成 `analysis_ts - time.time()`，它会恒为 0
        而本用例**照样绿**（只要断言只检查「是个数字」）。
        """
        det = AnomalyDetector()
        event_ts = 1_000_000.0
        fake_now = event_ts + 500.0
        monkeypatch.setattr(time, "time", lambda: fake_now)
        rep = _analyze(det, _ev(ts=event_ts))
        got = _win(rep).get("detection_latency_seconds")
        assert got is not None, "延迟没算出来"
        assert got == pytest.approx(500.0, abs=1.0), (
            f"延迟没有跟着「分析时刻 − 事件时间」走，实际 {got} —— "
            f"它可能取错了起点")

    def test_ingest_latency_is_computed_when_the_arrival_time_is_present(self):
        """另一段：接收时间 → 分析时刻，事件带 `received_at` 时可算。"""
        det = AnomalyDetector()
        event_ts = time.time() - 3 * 3600
        arrived = time.time() - 60
        rep = _analyze(det, _ev(ts=event_ts, received_at=arrived))
        w = _win(rep)
        assert w.get("ingest_latency_seconds") == pytest.approx(60, abs=5), (
            f"接收→分析的延迟不对：{w.get('ingest_latency_seconds')!r}")
        # 两段必须同时在场且互不相等
        assert w["detection_latency_seconds"] > w["ingest_latency_seconds"], (
            "「事件→识别」必然不短于「到达→识别」")

    def test_ingest_latency_is_none_without_an_arrival_time(self):
        """生产当前**没有**接收时间的写入方 → 必须是 None，不能是 0。"""
        det = AnomalyDetector()
        rep = _analyze(det, _ev(ts=time.time() - 3600))
        assert _win(rep).get("ingest_latency_seconds") is None, (
            "没有接收时间却报出了延迟 —— 那是在拿分析时刻顶替")

    def test_the_two_segments_are_not_confused(self):
        """两条延迟必须各归各：给了 `received_at` 不许影响 detection_latency。"""
        det_a = AnomalyDetector()
        det_b = AnomalyDetector()
        event_ts = time.time() - 3600
        a = _analyze(det_a, _ev(ts=event_ts))
        b = _analyze(det_b, _ev(ts=event_ts, received_at=time.time() - 30))
        assert _win(a)["detection_latency_seconds"] == pytest.approx(
            _win(b)["detection_latency_seconds"], abs=10), (
            "有没有 received_at 竟然改变了「事件→识别」的延迟")


# ── 纯披露：指标不得影响任何判定 ────────────────────────────────────


class TestTheMetricIsPureDisclosure:
    def test_reasons_never_mention_the_latency(self):
        """`reasons` 喂 `veto_gates._STRONG_SIGNAL_REASONS`，
        指标名进去就可能被当成强信号 → 判定会被改。"""
        det = AnomalyDetector()
        rep = _analyze(det, _ev(ts=time.time() - 3600))
        assert not [x for x in rep.reasons if "latency" in x.lower()], (
            f"延迟进了 reasons：{rep.reasons}")

    def test_the_decision_is_unchanged_by_the_metrics_presence(self):
        """同一个事件，带/不带 `received_at`（即两条延迟里有一条 None），
        **判定必须完全一样**。"""
        det_a = AnomalyDetector()
        det_b = AnomalyDetector()
        event_ts = time.time() - 3600
        a = _analyze(det_a, _ev(ts=event_ts))
        b = _analyze(det_b, _ev(ts=event_ts, received_at=time.time() - 30))
        assert a.status == b.status
        assert a.anomaly_score == pytest.approx(b.anomaly_score)
        assert a.dimensions == b.dimensions
        assert a.effective_weights == b.effective_weights
        assert a.inconclusive_dimensions == b.inconclusive_dimensions

    def test_the_metric_is_published_through_the_existing_channel(self):
        """指标必须走**既有的** `analysis_window` 通道，
        不能另建一条只有测试看得见的通路。"""
        from detection_contract import DetectionResult

        det = AnomalyDetector()
        rep = _analyze(det, _ev(ts=time.time() - 3600))
        win = _win(rep)
        assert "detection_latency_seconds" in win, win
        # analysis_window 原样进 DetectionResult → 进 HTTP 载荷
        dr = DetectionResult(
            detector="anomaly", detector_version="anomaly-2.0", event_id="lat-1",
            status=rep.status, score=rep.anomaly_score,
            analysis_window=win)
        assert dr.analysis_window.get("detection_latency_seconds") is not None


# ── 评估器：这条指标被报出来了 ──────────────────────────────────────


class TestEvaluatorReportsTheLatency:
    def test_rows_carry_the_latency_and_the_summary_counts_them(self):
        from eval_datasets.evaluate_detection import latency_summary, run_anomaly

        rows = run_anomaly()
        assert rows, "异常标定集是空的"
        for r in rows:
            assert "detection_latency_seconds" in r, (
                f"评估器的异常行没带检测延迟字段：{r.get('id')}")
            assert "ingest_latency_seconds" in r, r.get("id")
        lat = latency_summary(rows)
        assert lat["measured"] + lat["unavailable"] == len(rows), (
            f"可算 + 不可算 应当等于总条数：{lat}")
        assert lat["measured"] > 0, "一条都算不出来 —— 指标没接上"
        assert lat["unavailable"] > 0, (
            "标定集里有一条无时间戳的样本（ANO-I-02），它必须算不出来；"
            "若这里为 0，说明「缺就是缺」这条性质被破坏了")
        assert lat["median_seconds"] is not None
        assert "_note" in lat and lat["_note"], "汇总必须带口径说明"

    def test_the_unmeasurable_row_is_exactly_the_one_without_a_timestamp(self):
        """前提守卫：不可算的那条必须**就是**无时间戳那条，不是随机的。"""
        from eval_datasets.evaluate_detection import run_anomaly

        rows = run_anomaly()
        by_id = {r["id"]: r for r in rows}
        no_ts = by_id.get("ANO-I-02")
        assert no_ts is not None, "标定集里没有 ANO-I-02 —— 前提变了"
        assert no_ts["detection_latency_seconds"] is None, (
            f"ANO-I-02（事件无时间戳）却报出了延迟："
            f"{no_ts['detection_latency_seconds']!r}")
        others = [r for r in rows if r["id"] != "ANO-I-02"]
        assert all(r["detection_latency_seconds"] is not None for r in others), (
            "除 ANO-I-02 外都应可算："
            f"{[(r['id'], r['detection_latency_seconds']) for r in others]}")

    def test_summary_gives_none_not_zero_when_nothing_is_measurable(self):
        """一条都算不出来时，min/max/中位必须是 None，不是 0。"""
        from eval_datasets.evaluate_detection import latency_summary

        rows = [{"detection_latency_seconds": None,
                 "ingest_latency_seconds": None} for _ in range(3)]
        lat = latency_summary(rows)
        assert lat["measured"] == 0 and lat["unavailable"] == 3
        assert lat["min_seconds"] is None, lat
        assert lat["max_seconds"] is None, lat
        assert lat["median_seconds"] is None, (
            f"没测到却报了中位数 {lat['median_seconds']!r} —— "
            f"「没测到」和「测到是 0」必须能区分开")


# ── 冷启动分档：§七「冷启动检测表现」+「分别报告」 ──────────────────


class TestColdStartIsReportedSeparately:
    """§七 要求「至少按新实体、成熟实体…分别报告」，
    且指标表里有一项「冷启动检测表现 | 检查新 IP 或新资产不会系统性失明」。

    修复前评估器只给**单一汇总** —— 冷启动那一档根本没被单独报出来。
    """

    def test_the_two_groups_partition_all_rows(self):
        from eval_datasets.evaluate_detection import (
            cold_start_breakdown, run_anomaly)

        rows = run_anomaly()
        cs = cold_start_breakdown(rows)
        assert cs["mature"]["n"] + cs["fresh"]["n"] == len(rows), (
            f"两档没把全部样本分完：{cs}")
        assert cs["mature"]["n"] > 0, "成熟实体档不应为空"
        assert cs["fresh"]["n"] > 0, "新实体档不应为空（标定集里有冷启动样本）"

    def test_the_fresh_group_never_reports_not_detected(self):
        """**「冷启动检测表现」这条指标的可执行形式。**

        新实体没有基线 → 结构上判不出统计维度 →
        正确的表现是判 **inconclusive**（不可判定），
        而不是判 `not_detected`（真实阴性）——
        后者就是「把新 IP 系统性当成阴性」，即**结构性失明**。
        """
        from eval_datasets.evaluate_detection import (
            cold_start_breakdown, run_anomaly)

        rows = run_anomaly()
        cs = cold_start_breakdown(rows)
        assert not cs["fresh_structurally_blind"], (
            f"新实体被判成了真实阴性：{cs['fresh_structurally_blind']} —— "
            f"那是结构性失明（漏报），不是「不可判定」")
        assert cs["fresh"]["not_detected"] == 0, cs["fresh"]
        assert cs["fresh"]["inconclusive"] > 0, (
            f"新实体档一条 inconclusive 都没有，那它是怎么判的？{cs['fresh']}")

    def test_structural_blindness_is_flagged_not_buried_in_a_count(self):
        """真出现结构性失明时，必须**点名**列出是哪几条，
        不能只留一个「阴性 1」这样的计数。"""
        from eval_datasets.evaluate_detection import cold_start_breakdown

        rows = [
            {"id": "FAKE-1", "expect": "detected", "status": "not_detected",
             "baseline_samples": 0},
            {"id": "FAKE-2", "expect": "not_detected", "status": "not_detected",
             "baseline_samples": 12},
        ]
        cs = cold_start_breakdown(rows)
        assert cs["fresh_structurally_blind"] == ["FAKE-1"], cs
        assert cs["fresh"]["not_detected"] == 1, cs["fresh"]

    def test_the_thresholds_used_for_the_split_are_the_production_ones(self):
        """分档门槛必须用**生产常量**，不能在评估器里另写一个数。"""
        from anomaly_detector import COLD_START_MIN_SAMPLES
        from eval_datasets.evaluate_detection import cold_start_breakdown

        cs = cold_start_breakdown([])
        assert cs["cold_start_min_samples"] == COLD_START_MIN_SAMPLES, (
            f"评估器用的门槛 {cs['cold_start_min_samples']} "
            f"与生产常量 {COLD_START_MIN_SAMPLES} 不一致")

    def test_the_uncovered_dimensions_are_declared(self):
        """「不同部署规模」「不同时间窗口」两档**没覆盖** ——
        必须写在输出里，不能让人以为已经按这四维都报过了。"""
        from eval_datasets.evaluate_detection import cold_start_breakdown

        cs = cold_start_breakdown([])
        assert "_note" in cs and cs["_note"], "缺少口径说明"
        assert "部署规模" in cs["_note"] and "时间窗口" in cs["_note"], (
            f"未覆盖的两维必须点名：{cs['_note']}")


if __name__ == "__main__":       # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
