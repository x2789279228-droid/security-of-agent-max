"""§四：时区解析的**回退路径**不得静默，也不得让载荷说谎。

整改方案 §四（P0-4）修的是「时序维度用服务器 UTC 钟点」这个缺陷，
核心改动是把默认时区定为 `Asia/Shanghai` 并改用**事件自身时间戳**。
那部分实测是对的（`astimezone(self.tz)` + 配置化时区）。

本轮发现的是**同一修复的尾部漏洞**：时区解析有三条回退路径，
其中一条——`zoneinfo` 不可用（缺 `tzdata`，Windows 与精简 Linux 镜像常见）——
**既不告警，又让载荷写出与实际计算不符的时区名**。

## 实测（修复前）

| 场景 | `_resolve_tz` 返回 | 日志 |
|---|---|---|
| `Asia/Shanghai`（本机 tzdata 齐全） | `Asia/Shanghai` | 无（正常） |
| 未知名 `Mars/Olympus` | `UTC` | **有** WARNING |
| **`_HAS_ZONEINFO = False`** | **`UTC`** | **无 —— 完全静默** |

第三条回退到的正是 §四 要消灭的服务器 UTC 钟点。也就是说：
缺 tzdata 的机器上，配好的 `Asia/Shanghai` 根本不生效，
北京白天上班被判「非活跃时段 +0.4」、北京凌晨拿不到加分 ——
**缺陷本身原样复活，一行日志都没有**。

## 更糟的一层：载荷在撒谎

结果载荷原本无条件写 `"timezone": self.timezone_name`。
在上述场景下它会写出 `"timezone": "Asia/Shanghai"`，
而实际打分用的是 UTC。排查时序评分异常的人看到这行会认为时区语义正确，
从而找错方向 —— 审计记录主动把人带偏。

## 修复

1. `_resolve_tz` 的 `not _HAS_ZONEINFO` 分支补 warning，与未知时区名那条对齐；
2. 载荷改报 `timezone_audit()`：**实际生效的** `timezone` +
   `timezone_configured`（配置值，即使没生效）+ `timezone_fallback` 标志。

`["timezone"]` 这个键全仓**零消费方**，所以改它的值不破坏任何调用点。
（顺带一提：它同时也是「字段在、没人读」的又一例。）
"""
import logging

import pytest


@pytest.fixture
def no_zoneinfo(monkeypatch):
    """模拟缺 tzdata 的部署机。"""
    import anomaly_detector as ad
    monkeypatch.setattr(ad, "_HAS_ZONEINFO", False, raising=False)
    return ad


@pytest.fixture
def warnings(monkeypatch):
    import anomaly_detector as ad
    recs = []

    class _H(logging.Handler):
        def emit(self, r):
            if r.levelno >= logging.WARNING:
                recs.append(r.getMessage())

    h = _H()
    ad.logger.addHandler(h)
    prev = ad.logger.level
    ad.logger.setLevel(logging.DEBUG)
    monkeypatch.setattr(ad.logger, "propagate", True)
    yield recs
    ad.logger.removeHandler(h)
    ad.logger.setLevel(prev)


# ══════════════════════════════════════════════════════════════════════════
# 告警：三条回退路径必须都有
# ══════════════════════════════════════════════════════════════════════════

class TestEveryFallbackIsLoud:
    def test_missing_tzdata_fallback_is_logged(self, no_zoneinfo, warnings):
        """缺 tzdata 时必须告警 —— 修复前这条路径**完全静默**。"""
        no_zoneinfo.AnomalyDetector(timezone_name="Asia/Shanghai")
        assert warnings, (
            "zoneinfo 不可用时静默回退 UTC —— 缺 tzdata 的机器上，"
            "配置的 Asia/Shanghai 不生效且无人知晓，P0-4 缺陷原样复活")
        assert any("zoneinfo" in m for m in warnings), warnings

    def test_unknown_timezone_name_is_still_logged(self, warnings):
        """对照组：这条一直有告警，不许因重构丢掉。"""
        import anomaly_detector as ad
        ad.AnomalyDetector(timezone_name="Mars/Olympus")
        assert any("Mars/Olympus" in m for m in warnings), warnings

    def test_working_timezone_does_not_warn(self, warnings):
        """前提守卫：正常路径不得被误报成告警。

        否则这条守卫会因为「什么都告警」而恒绿，失去鉴别力。
        """
        import anomaly_detector as ad
        det = ad.AnomalyDetector(timezone_name="Asia/Shanghai")
        assert det.timezone_fallback is False
        assert warnings == [], f"正常时区不该告警：{warnings}"


# ══════════════════════════════════════════════════════════════════════════
# 载荷：不得写出与实际计算不符的时区
# ══════════════════════════════════════════════════════════════════════════

class TestPayloadTellsTheTruth:
    def test_reported_timezone_is_the_one_actually_used(self, no_zoneinfo):
        det = no_zoneinfo.AnomalyDetector(timezone_name="Asia/Shanghai")
        audit = det.timezone_audit()

        assert str(det.tz) == "UTC", "本用例的前提是确实回退到了 UTC"
        assert audit["timezone"] == str(det.tz), (
            f"载荷上报 {audit['timezone']!r}，实际用的是 {det.tz} —— "
            "审计记录在撒谎")
        assert audit["timezone"] != "Asia/Shanghai"

    def test_configured_value_is_kept_for_audit(self, no_zoneinfo):
        """配置值也必须留着 —— 否则事后无从知道「本来想用的是什么」。"""
        det = no_zoneinfo.AnomalyDetector(timezone_name="Asia/Shanghai")
        audit = det.timezone_audit()

        assert audit["timezone_configured"] == "Asia/Shanghai"
        assert audit["timezone_fallback"] is True

    def test_normal_machine_reports_no_fallback(self):
        import anomaly_detector as ad
        audit = ad.AnomalyDetector(timezone_name="Asia/Shanghai").timezone_audit()

        assert audit["timezone"] == "Asia/Shanghai"
        assert audit["timezone_configured"] == "Asia/Shanghai"
        assert audit["timezone_fallback"] is False

    def test_effective_timezone_property_matches_resolved_tz(self):
        import anomaly_detector as ad
        det = ad.AnomalyDetector(timezone_name="Asia/Shanghai")
        assert det.effective_timezone == str(det.tz)


class TestThePayloadItselfTellsTheTruth:
    """**端到端**看载荷，不看方法。

    这组是被一次注入逼出来的：把两个 `**self.timezone_audit()`
    换回 `"timezone": self.timezone_name`，8 条用例**全绿** ——
    因为它们直接调 `timezone_audit()`，而那个方法本身仍然是正确的。

    **方法对、接线错**，而测试只测了方法。守卫没有连到它声称保护的东西。

    所以这里必须跑真实的 `analyze()`，检查真正写进
    `report.analysis_window` 的内容 —— 那才是下游和排障看到的东西。
    """

    @staticmethod
    def _analyze_once(det):
        import asyncio
        import datetime as dt
        ts = int(dt.datetime(2026, 10, 19, 2, 0, tzinfo=dt.timezone.utc).timestamp())
        event = {
            "src_ip": "10.0.0.7", "event_type": "LOGIN", "timestamp": ts,
            "dst_ip": "10.0.0.9", "severity": "low", "message": "x",
            "session_id": "tz-probe",
        }
        return asyncio.run(det.analyze(event))

    def test_analysis_window_reports_the_timezone_actually_used(self, no_zoneinfo):
        det = no_zoneinfo.AnomalyDetector(timezone_name="Asia/Shanghai")
        report = self._analyze_once(det)
        win = report.analysis_window or {}

        assert str(det.tz) == "UTC", "本用例的前提是确实回退到了 UTC"
        assert win.get("timezone") == str(det.tz), (
            f"载荷 analysis_window 写的是 {win.get('timezone')!r}，"
            f"实际打分用的是 {det.tz} —— 审计记录在撒谎")
        assert win.get("timezone") != "Asia/Shanghai", (
            "回退到 UTC 却仍上报 Asia/Shanghai")

    def test_analysis_window_carries_configured_value_and_fallback_flag(self, no_zoneinfo):
        det = no_zoneinfo.AnomalyDetector(timezone_name="Asia/Shanghai")
        win = (self._analyze_once(det).analysis_window) or {}

        assert win.get("timezone_configured") == "Asia/Shanghai"
        assert win.get("timezone_fallback") is True

    def test_normal_machine_payload_is_consistent(self):
        import anomaly_detector as ad
        det = ad.AnomalyDetector(timezone_name="Asia/Shanghai")
        win = (self._analyze_once(det).analysis_window) or {}

        assert win.get("timezone") == "Asia/Shanghai"
        assert win.get("timezone_fallback") is False


class TestTheFallbackActuallyChangesScoring:

    def test_beijing_ten_am_is_read_as_utc_seven_when_tzdata_missing(self, no_zoneinfo):
        import datetime as dt

        det = no_zoneinfo.AnomalyDetector(timezone_name="Asia/Shanghai")
        # 2026-10-19 02:00 UTC == 北京时间 10:00
        ts = int(dt.datetime(2026, 10, 19, 2, 0, tzinfo=dt.timezone.utc).timestamp())
        event_dt, _src = det.resolve_event_time(
            {"src_ip": "1.1.1.1", "event_type": "LOGIN", "timestamp": ts})

        hour_used = event_dt.astimezone(det.tz).hour
        assert hour_used == 2, "回退到 UTC 后应取到 UTC 钟点 2 点"

        # 同一事件在时区可用时应当取到北京钟点 10 点。
        # 注意：这里**不能**再建一个 AnomalyDetector 作对照 ——
        # `no_zoneinfo` fixture 把 `_HAS_ZONEINFO` 置成了 False（monkeypatch
        # 在整个用例内生效），第二个 detector 同样会回退到 UTC，
        # 对照组会跟着一起坏掉，直接把断言变成同义反复。
        # 所以对照用真正的 ZoneInfo，不经过任何回退路径。
        from zoneinfo import ZoneInfo
        assert event_dt.astimezone(ZoneInfo("Asia/Shanghai")).hour == 10, (
            "本用例的前提是同一事件在北京时区下应取到 10 点；"
            "若这条失败，说明 zoneinfo/tzdata 环境本身有问题，"
            "本用例的对照不成立")
