"""§四 第 6 条点名却零覆盖的两条边界：重放一致性与迟到事件；外加 §四.4.4 的三个时间。

整改方案 §四.6：

> 「尤其是同一事件重放，必须采用原始事件时间戳。否则同一事件在不同 UTC
> 小时执行时，结果可能改变，使异常检测无法复现。」
> 「建议建立边界用例：UTC 时间、北京时间以及夏令时适用时区的转换；
> 事件产生于凌晨但在白天延迟送达；同一事件在不同时间重放。」

仓库里这三条此前**都没有用例**。本轮实测后分两类：

- **重放一致性：成立**（否定结论）—— 固定基线与同一事件，打分结果与墙钟无关。
- **迟到事件：成立**（否定结论）—— 时序维度只认事件时间，送达时间不影响打分。

另外实测发现并修掉一个真缺陷：`received_at` 原本是 `time.time()`
（分析时刻顶替接收时间），于是**接收时间这个东西其实并不存在**。
详见 `TestThreeTimesAreNotConflated`。

## 这份测试自己也踩过的两个坑

1. **把 `analysis_at` / `received_at` 放进快照** —— 它们按设计就随墙钟变，
   断言「完全相同」必然失败。守卫必须先分清「哪些字段**应该**变」。
2. **把墙钟推 +30 天** —— 基线本就按墙钟做 7 天窗口淘汰（§2.4「窗口淘汰基准」，
   刻意改用墙上时钟），推 30 天后基线合法地过期，维度随之变成 inconclusive。
   **那是正确行为**，不是缺陷。所以本文件只测「基线仍在窗口内」时的确定性。
"""
import asyncio
import copy
import datetime as dt
import time

import pytest

T = dt.timezone.utc
CST = dt.timezone(dt.timedelta(hours=8))

#: 本文件所有固定时刻的基准日（北京时间）。
#:
#: 刻意**不再手写 epoch 秒**。上一版把 `1792365600` 注释成「北京 03:00」，
#: 实测它是北京 07:20 —— 手算的魔数错了整整 4 小时 20 分，而断言
#: `event_time_hour == 3` 照样「看起来很合理」。前提守卫
#: (`TestLateArrivingEvent::test_premise_hours_are_what_we_think`) 是当场抓住它的，
#: 说明前提守卫必须真的跑、且必须独立于被它守护的常量。
BASE_DATE = (2026, 10, 19)


def _cst_ts(hour, minute=0, second=0):
    """构造「北京 BASE_DATE 当天 hour 点」的 epoch 秒。

    前提由构造保证：注释写 03:00，拿到的就真的是 03:00。
    """
    return int(dt.datetime(*BASE_DATE, hour, minute, second, tzinfo=CST).timestamp())


#: 北京 10:00 —— 本文件统一的「事件发生时刻」
EVENT_TS = _cst_ts(10)
#: 北京 14:00 —— 「送达时刻」基准（比事件晚 4 小时）
RECEIVED_TS = _cst_ts(14)


def _ev(ts, eid="e-1", **extra):
    e = {
        "src_ip": "10.0.0.7", "event_type": "LOGIN", "timestamp": ts,
        "dst_ip": "10.0.0.9", "severity": "low", "message": "x",
        "event_id": eid, "session_id": "s",
    }
    e.update(extra)
    return e


def _det_tz(tzname):
    """按配置时区建检测器 —— 夏令时用例需要非 Asia/Shanghai 的时区。"""
    import anomaly_detector as ad
    return ad.AnomalyDetector(timezone_name=tzname)


def _det():
    return _det_tz("Asia/Shanghai")


def _has_tzdata(name):
    """能不能真的加载这个时区。

    检测器在缺 tzdata 时会**静默回退 UTC**（并打 warning）。若不先判断，
    夏令时用例会以「DST 转换错误」的面貌红掉，把人指向完全错误的方向。
    """
    try:
        from zoneinfo import ZoneInfo
        ZoneInfo(name)
        return True
    except Exception:            # noqa: BLE001
        return False


def _analyze(det, event):
    return asyncio.run(det.analyze(event))


def _ev_no_ts(**overrides):
    """构造一个**根本不带** `timestamp` 键的事件。

    `_ev(None)` 做不到这件事 —— 它会把 `"timestamp": None` 写进去，
    于是「字段缺失」与「字段为 None」两种情形被混为一谈，
    而它们恰恰要分开验证。
    """
    e = {
        "src_ip": "10.0.0.7", "event_type": "LOGIN",
        "dst_ip": "10.0.0.9", "severity": "low", "message": "x",
        "event_id": "e-1", "session_id": "s",
    }
    e.update(overrides)
    return e


def _verdict_snapshot(r):
    """**只含应当与墙钟无关**的判定内容。

    刻意排除：`analysis_at`（分析时刻）、`received_at`（可能随来源变）、
    `window_days`/`timezone*`（常量）、`baseline_version`（会随基线推进）。
    """
    return (
        float(r.anomaly_score), r.status, float(r.deviation_sigma),
        r.is_anomaly,
        tuple(sorted((r.dimensions or {}).items())),
        tuple(sorted(r.inconclusive_dimensions)),
        tuple(sorted(x for x in r.reasons if not x.startswith("ingest:"))),
        (r.analysis_window or {}).get("event_time_hour"),
        r.event_time_source,
    )


def _seeded_detector():
    """喂足历史事件，让基线非空且仍在 7 天窗口内。"""
    det = _det()
    now = time.time()
    for i in range(400):
        _analyze(det, _ev(now - 3600 * (i % 200 + 1), eid=f"h-{i}"))
    return det


# ══════════════════════════════════════════════════════════════════════════
# 否定结论 1：重放一致性成立
# ══════════════════════════════════════════════════════════════════════════

class TestReplayIsDeterministic:
    def test_same_event_same_baseline_same_verdict_across_wall_clocks(self, monkeypatch):
        """§四.6：同一事件在不同时间执行，判定不得改变。

        基线快照固定，只改墙钟 —— 因为基线本来就该随时间推进（§2.4）。
        要验的是**打分本身有没有偷看墙钟**。
        偏移量刻意控制在几分钟内，确保基线不越出 7 天窗口 ——
        越出后维度变成 inconclusive 属于**正确行为**，不是本用例要测的东西。
        """
        det = _seeded_detector()
        saved = copy.deepcopy(det.baselines)
        ver = det.baseline_version
        gh = list(det.global_hourly_counts)
        ge = dict(det.global_event_types)

        target = EVENT_TS          # 固定的事件时间戳
        real_now = time.time()
        snaps = []
        for fake in (real_now, real_now + 60, real_now + 600, real_now + 3600):
            det.baselines = copy.deepcopy(saved)
            det.baseline_version = ver
            det.global_hourly_counts = list(gh)
            det.global_event_types = dict(ge)
            monkeypatch.setattr(time, "time", lambda f=fake: f)
            snaps.append(_verdict_snapshot(_analyze(det, _ev(target))))
        monkeypatch.undo()

        assert len(set(map(str, snaps))) == 1, (
            "同一事件 + 同一基线，墙钟推进 1 小时内结果却变了：\n"
            + "\n".join(str(s) for s in snaps))

    def test_analysis_at_is_the_only_thing_that_moves(self, monkeypatch):
        """对照：唯一该随墙钟变的是 `analysis_at`。

        上一条如果只断言「值相同」，哪天有人把 `event_time_hour` 也改成
        取墙钟，它仍会因为别的原因失败；这条把「该变的确实变了」钉住。
        """
        det = _det()
        ts = EVENT_TS
        real_now = time.time()
        got = []
        for fake in (real_now, real_now + 1234):
            monkeypatch.setattr(time, "time", lambda f=fake: f)
            got.append((_analyze(det, _ev(ts)).analysis_window or {}).get("analysis_at"))
        monkeypatch.undo()
        assert got[0] != got[1], "analysis_at 没有随墙钟变化 —— 它不该被冻结"

    def test_event_time_hour_comes_from_the_event_not_the_clock(self):
        """时序维度取的小时必须来自事件时间戳（北京时间 10:00）。"""
        r = _analyze(_det(), _ev(EVENT_TS))
        assert (r.analysis_window or {}).get("event_time_hour") == 10
        assert r.event_time_source == "timestamp"


# ══════════════════════════════════════════════════════════════════════════
# 否定结论 2：迟到事件成立
# ══════════════════════════════════════════════════════════════════════════

class TestLateArrivingEvent:
    #: 北京 03:00 发生（按基准日构造 —— 前提由构造保证，不靠手算）
    EV_TS = _cst_ts(3)
    #: 北京 14:00 才送达 —— 比发生晚 11 小时
    RECV_TS = RECEIVED_TS

    def test_premise_hours_are_what_we_think(self):
        """前提守卫：常量真的是注释里写的那个钟点，且确实构成「迟到」。

        这条守卫上一版就存在，而且**当场抓到了自己的 bug**：
        手写的 `1792365600` 被注释成北京 03:00，实测是 07:20。
        留着它 —— 被它守护的常量一旦又变回魔数，它会立刻转红。
        """
        ev = dt.datetime.fromtimestamp(self.EV_TS, T).astimezone(CST)
        rc = dt.datetime.fromtimestamp(self.RECV_TS, T).astimezone(CST)
        assert (ev.hour, ev.minute, ev.second) == (3, 0, 0), f"事件时刻是 {ev}"
        assert (rc.hour, rc.minute, rc.second) == (14, 0, 0), f"送达时刻是 {rc}"
        assert self.RECV_TS - self.EV_TS == 11 * 3600, (
            f"送达只比发生晚 {self.RECV_TS - self.EV_TS}s，"
            "「凌晨发生、白天送达」的前提不成立，本用例失去意义")

    def test_delivery_time_does_not_change_the_verdict(self):
        """§四.6：「事件产生于凌晨但在白天延迟送达」。

        带 `received_at` 与不带，必须得到相同判定 —— 用事件时间，
        而不是「现在几点」。
        """
        a = _verdict_snapshot(_analyze(_det(), _ev(self.EV_TS)))
        b = _verdict_snapshot(
            _analyze(_det(), _ev(self.EV_TS, received_at=self.RECV_TS)))
        assert a == b, f"送达时间改变了判定：\n{a}\n{b}"

    def test_late_event_is_scored_on_its_own_hour(self):
        r = _analyze(_det(), _ev(self.EV_TS, received_at=self.RECV_TS))
        assert (r.analysis_window or {}).get("event_time_hour") == 3, (
            "凌晨发生的事件必须按凌晨评分，哪怕下午才送到")


# ══════════════════════════════════════════════════════════════════════════
# 实测发现的真缺陷：迟到事件把 `last_seen` 拉回过去 → 活跃实体被整条剪除
# ══════════════════════════════════════════════════════════════════════════

class TestLateEventMustNotKillTheBaseline:
    """`_update_baseline` 原本写的是 `bl.last_seen = now` —— 覆盖式，不是高水位。

    实测（修复前）：只要有一条**时间戳早于已见事件**的事件进来
    （乱序投递、迟到重放、离线补传 —— 全都是正常业务形态，不需要伪造时间戳），
    `last_seen` 就回退到那条旧事件的时间。而 `_prune_baselines` 的判据只有
    `bl.last_seen < cutoff`，于是把这条**一小时前还在活动**的实体基线整条删掉。

    后果不是「少算一点分」，而是四个维度全部变成 inconclusive、
    `anomaly_score = 0.0`、无异常无告警：该实体从此彻底失明，
    而且没有任何痕迹表明它曾经有基线 —— 全量漏报且零告警痕迹。

    讽刺之处：同一函数下面几行的窗口淘汰**刻意**用墙上时钟，
    就是为了防止「发旧时间戳无限续命」。两条防线方向相反 ——
    旧时间戳续不了命，却能让实体**立刻暴毙**。
    """

    def _live_baseline(self):
        """灌出一个**确实还活着**的基线（最新事件 1 小时前，远在 7 天窗口内）。"""
        det = _seeded_detector()
        return det, det.baselines["src_ip"]["10.0.0.7"]

    def test_last_seen_never_moves_backwards(self):
        det, bl = self._live_baseline()
        before = bl.last_seen
        _analyze(det, _ev(before - 8 * 86400, eid="late-old"))
        got = det.baselines["src_ip"]["10.0.0.7"].last_seen
        assert got >= before, (
            f"last_seen 被一条 8 天前的迟到事件从 {before} 回退到 {got}。"
            "它是活跃度判据（剪枝/落盘都用它），必须是所有已见事件时间的最大值")

    def test_live_entity_is_not_pruned_by_a_late_arrival(self):
        det, bl = self._live_baseline()
        _analyze(det, _ev(bl.last_seen - 8 * 86400, eid="late-old"))
        det._prune_baselines()          # 直接调，避开 3600s 的触发间隔
        assert "10.0.0.7" in det.baselines["src_ip"], (
            "基线里最新事件只有 1 小时前，却因一条 8 天前的迟到事件被整条剪除")

    def test_detection_does_not_go_silent_after_a_late_arrival(self):
        """真正的验收口径：不是「分数偏低」，而是**根本没有分数可算**。

        `_prune_baselines` 直接调用而非走 `analyze` 的定时触发，
        是为了让断言只依赖这一个变量 —— 墙钟偏移由上一组用例负责。
        """
        det, bl = self._live_baseline()
        _analyze(det, _ev(bl.last_seen - 8 * 86400, eid="late-old"))
        det._prune_baselines()
        r = _analyze(det, _ev(time.time(), eid="after"))
        assert "statistical_deviation" not in r.inconclusive_dimensions, (
            f"迟到事件之后该实体彻底失明：dims={r.dimensions} "
            f"inconclusive={sorted(r.inconclusive_dimensions)}")
        assert r.dimensions, "基线被剪除后没有任何维度可算"


# ══════════════════════════════════════════════════════════════════════════
# 实测发现的真缺陷：分数类型在两条分支上不一致
# ══════════════════════════════════════════════════════════════════════════

class TestScoreIsAlwaysFloat:
    """`anomaly_score` 声明 `float`，冷启动分支却返回 `int`。

    修复前：`sum()` 在空生成器上返回 `int 0`，于是冷启动路径的分数是
    `int`；正常路径因为 `max(0.0, ...)` 是 `float`。
    两者**数值相等**（0 == 0.0），只看分数值永远发现不了 —— 必须查类型。
    序列化后一条是 `0` 一条是 `0.0`，任何 `isinstance(score, float)`
    的消费方都会在冷启动上翻车。
    """

    def test_cold_start_path_returns_float(self):
        r = _analyze(_det(), _ev(EVENT_TS))
        assert r.status == "inconclusive", (
            f"本用例的前提是冷启动（status={r.status}）")
        assert isinstance(r.anomaly_score, float), (
            f"冷启动分数类型是 {type(r.anomaly_score).__name__}，"
            f"值 {r.anomaly_score!r} —— AnomalyReport 声明的是 float")

    def test_both_branches_agree_on_type(self):
        cold = _analyze(_det(), _ev(EVENT_TS, eid="cold"))
        warm = _analyze(_seeded_detector(), _ev(EVENT_TS, eid="warm"))
        assert type(cold.anomaly_score) is type(warm.anomaly_score), (
            f"两条分支类型不一致：冷启动 {type(cold.anomaly_score).__name__}"
            f" vs 正常 {type(warm.anomaly_score).__name__}")

    def test_score_stays_within_declared_range(self):
        for det in (_det(), _seeded_detector()):
            r = _analyze(det, _ev(EVENT_TS))
            assert 0.0 <= float(r.anomaly_score) <= 1.0, r.anomaly_score


# ══════════════════════════════════════════════════════════════════════════
# §四.4.4：事件时间 / 接收时间 / 分析时间三者不得混淆
# ══════════════════════════════════════════════════════════════════════════

class TestThreeTimesAreNotConflated:
    """修复前 `received_ts = time.time()` —— 分析时刻顶着接收时间的名字。

    实测（修复前）：重放一条三个月前的事件，`received_at` 显示的是「现在」，
    读的人会以为事件刚到；而真正的到达时间 nowhere 可查
    ——**全仓生产代码里没有任何一处写入接收时间字段**。

    于是 §十三 要求的「检测延迟 = 从异常出现到被识别的时间」没有起点，
    §七.1.1 要求的「区分事件发生时间与数据接收时间」只有一个量的名字。
    """

    def test_received_at_is_none_when_the_event_carries_none(self):
        r = _analyze(_det(), _ev(EVENT_TS))
        assert (r.analysis_window or {}).get("received_at") is None, (
            "事件没带接收时间时不得拿分析时刻顶替 —— 缺就是缺")

    def test_missing_receipt_time_is_flagged_in_reasons(self):
        r = _analyze(_det(), _ev(EVENT_TS))
        assert any("received_time_unavailable" in x for x in r.reasons), (
            "接收时间缺失必须留痕，否则「没有这个量」与「忘了记」无法区分")

    @pytest.mark.parametrize("field", [
        "received_at", "ingested_at", "ingest_time", "ingest_ts",
        "consumed_at", "receive_time",
    ])
    def test_receipt_time_is_read_when_the_event_provides_it(self, field):
        r = _analyze(_det(), _ev(EVENT_TS, eid="x", **{field: RECEIVED_TS}))
        got = (r.analysis_window or {}).get("received_at")
        assert got == pytest.approx(float(RECEIVED_TS)), (
            f"事件带了 {field} 却被忽略（读到 {got!r}）")

    def test_millisecond_timestamps_are_understood(self):
        r = _analyze(_det(), _ev(EVENT_TS, received_at=int(RECEIVED_TS * 1000)))
        assert (r.analysis_window or {}).get("received_at") == pytest.approx(float(RECEIVED_TS))

    def test_iso8601_is_understood(self):
        iso = dt.datetime.fromtimestamp(RECEIVED_TS, T).isoformat()
        r = _analyze(_det(), _ev(EVENT_TS, received_at=iso))
        assert (r.analysis_window or {}).get("received_at") == pytest.approx(float(RECEIVED_TS))

    def test_analysis_at_is_always_present_and_is_the_wall_clock(self, monkeypatch):
        real_now = time.time()
        monkeypatch.setattr(time, "time", lambda: 1234567890.5)
        r = _analyze(_det(), _ev(EVENT_TS))
        monkeypatch.undo()
        assert (r.analysis_window or {}).get("analysis_at") == pytest.approx(1234567890.5)

    def test_the_three_times_are_distinguishable(self):
        """事件时间 ≠ 接收时间 ≠ 分析时间，事件带齐时三个值必须各不相同。

        这是本节的核心不变量：三者被混成一个数时，
        「凌晨发生、下午到达」这类最需要区分的场景就再也测不出来了。
        """
        r = _analyze(_det(), _ev(EVENT_TS, received_at=RECEIVED_TS))
        w = r.analysis_window or {}
        assert w["event_time_hour"] == 10          # 事件时间（北京 10:00）
        assert w["received_at"] == pytest.approx(float(RECEIVED_TS))
        assert w["analysis_at"] > w["received_at"]  # 分析在接收之后
        assert w["received_at"] != w["analysis_at"]


# ══════════════════════════════════════════════════════════════════════════
# §四.6 点名的第三条边界用例：夏令时适用时区的转换（此前零覆盖）
# ══════════════════════════════════════════════════════════════════════════

@pytest.mark.skipif(
    not _has_tzdata("America/New_York"),
    reason="缺 tzdata：检测器会静默回退 UTC，本组用例会指向错误的方向")
class TestDstTimezone:
    """配置时区带夏令时时，`event_time_hour` 仍须是**本地钟点**。

    实测结论（否定结论）：`ZoneInfo` + `astimezone` 这条路径是对的。
    本组用例是把它钉住，防止哪天有人为了「省一次时区换算」
    换成固定 UTC 偏移。

    ## 这组用例为什么必须冬夏**成对**

    最直觉的写法是「取一个时刻，断言它等于某个钟点」——
    但那样**分辨不出坏实现**：把配置时区当成固定偏移的坏实现，
    在冬季样本上与正确实现**完全一致**。

    实测（同一 UTC 12:00，纽约）：

        正确实现：1 月 -> 7 时，7 月 -> 8 时（差 1，EST/EDT 之别）
        坏实现：  1 月 -> 7 时，7 月 -> 7 时（差 0）

    只有成对比较才能暴露它。`test_a_single_instant_cannot_discriminate`
    把这个分辨力本身钉成断言，防止后人把成对断言「简化」成单点，
    还以为覆盖的是同一件事。
    """

    NY = "America/New_York"

    # 跳变瞬间用 ZoneInfo 实测核过，不靠记忆：
    #   2026-03-08 UTC06:00 -> 01:00 EST，UTC07:00 -> 03:00 EDT（本地 02 时不存在）
    #   2026-11-01 UTC05:00 -> 01:00 EDT，UTC06:00 -> 01:00 EST（本地 01 时出现两次）
    SPRING = (2026, 3, 8)
    AUTUMN = (2026, 11, 1)

    @staticmethod
    def _utc(y, mo, d, h, mi=0):
        return dt.datetime(y, mo, d, h, mi, tzinfo=T).timestamp()

    def _hour(self, ts):
        return (_analyze(_det_tz(self.NY), _ev(ts)).analysis_window or {})["event_time_hour"]

    def test_premise_transition_days_really_are_transition_days(self):
        """前提守卫：这两日必须真的是切换日，否则下面两条测不到跳变。

        用 `utcoffset()` 核 —— 那是 **tzdata 的事实**，不是被测逻辑，
        所以不构成自证。
        """
        from zoneinfo import ZoneInfo
        ny = ZoneInfo(self.NY)
        # 当天**结束**时的偏移：春季跳变当天由 EST(-5) 变 EDT(-4)，
        # 秋季回拨当天由 EDT(-4) 变 EST(-5)。开始偏移反过来。
        for day, start_h, end_h in ((self.SPRING, -5, -4), (self.AUTUMN, -4, -5)):
            before = dt.datetime(*day, hour=0, tzinfo=ny).utcoffset()
            after = dt.datetime(*day, hour=23, tzinfo=ny).utcoffset()
            assert before != after, f"{day} 当天偏移没变（{before}），这不是切换日"
            assert int(before.total_seconds() // 3600) == start_h, (
                f"{day} 当天起始偏移是 {before}，与预期 {start_h}h 不符")
            assert int(after.total_seconds() // 3600) == end_h, (
                f"{day} 当天结束偏移是 {after}，与预期 {end_h}h 不符")

    def test_same_utc_instant_reads_one_hour_apart_across_seasons(self):
        winter = self._hour(self._utc(2026, 1, 15, 12))
        summer = self._hour(self._utc(2026, 7, 15, 12))
        assert (winter, summer) == (7, 8), (
            f"同一 UTC 12:00 在纽约冬夏应读出 7 时 / 8 时（EST/EDT 之别），"
            f"实得 {winter} / {summer}；若两者相同，说明配置时区"
            "被当成了固定 UTC 偏移")

    def test_a_single_instant_cannot_discriminate(self):
        """分辨力守卫：坏实现在**单个**时刻上与正确实现无法区分。

        留着这条是为了记录「为什么上面那条必须成对」，
        也是为了防止有人把成对断言简化成单点。
        """
        fixed_est = dt.timezone(dt.timedelta(hours=-5))      # 全年按 EST 算
        assert dt.datetime.fromtimestamp(self._utc(2026, 1, 15, 12), fixed_est).hour == 7, (
            "前提失效：固定偏移在冬季本应与正确实现一致（都是 7 时）")
        assert dt.datetime.fromtimestamp(self._utc(2026, 7, 15, 12), fixed_est).hour == 7, (
            "前提失效：固定偏移在夏季本应读出 7 时（正确实现是 8 时）")

    def test_spring_forward_never_reads_the_nonexistent_local_hour(self):
        """春季跳变：本地 02:00 这一小时**根本不存在**，任何 UTC 时刻都不该读成 2。"""
        for h in range(0, 12):
            got = self._hour(self._utc(*self.SPRING, h))
            assert got != 2, f"UTC {h:02d}:00 被读成本地 2 时（该钟点当天不存在）"

    def test_fall_back_reads_one_hour_twice(self):
        """秋季回拨：本地 01:00 出现两次（一次 EDT 一次 EST），两次都读成 1 时。"""
        first = self._hour(self._utc(*self.AUTUMN, 5))       # 01:30 EDT
        second = self._hour(self._utc(*self.AUTUMN, 6))      # 01:30 EST
        assert (first, second) == (1, 1), (
            f"回拨当日 01 时应出现两次且都读成 1，实读 {first} / {second}")

    def test_reported_zone_is_the_configured_zone_not_a_fixed_offset(self):
        """上报的 `timezone` 必须是时区名，且不得谎称已回退。

        固定偏移实现会报 `-05:00` 这类字符串 —— 运维看到它无法判断
        「配置生效了没有」。
        """
        for ts in (self._utc(2026, 1, 15, 12), self._utc(2026, 7, 15, 12)):
            w = _analyze(_det_tz(self.NY), _ev(ts)).analysis_window or {}
            assert w["timezone"] == self.NY, f"上报 {w['timezone']!r} 而非时区名"
            assert w["timezone_configured"] == self.NY
            assert w["timezone_fallback"] is False, (
                "时区明明可用却报回退 —— 运维告警入口会一直误报")


# ══════════════════════════════════════════════════════════════════════════
# §四.5：缺失/非法时间戳要给出**明确输入状态**，而不是静默采用当前时间
# ══════════════════════════════════════════════════════════════════════════

class TestMissingEventTimeIsDisclosed:
    """时序维度早就标了 inconclusive；**统计维度**没有。

    实测（修复前）：事件没带时间戳时 `now_ts` 退到墙上时钟，
    于是 `statistical_deviation` / `target_concentration` 以及基线写入
    全部锚在「现在」—— 而报告里只有 `event_time_source=''`，
    没有任何一处说明统计口径其实没拿到事件时间。

    代价实测：200 条无时间戳的历史日志回填 → 当前小时计数 203、σ 顶到 10.0；
    同一批事件带上真实历史时间戳 → 当前小时计数 4、σ=0.54。

    本轮只做**披露**（加 reason + 加 `event_time_fallback` 字段），
    不改任何打分 —— 改口径是取舍，不是缺陷修复，理由见
    `anomaly_detector.analyze` 里 else 分支的注释。
    """

    @pytest.mark.parametrize("missing", [
        {},                              # 字段根本没有
        {"timestamp": None},
        {"timestamp": ""},
        {"timestamp": "not-a-time"},
        {"timestamp": True},             # bool 不算数字
        {"timestamp": [1, 2]},           # 类型不对
        {"timestamp": 1e300},            # 溢出
    ], ids=["absent", "none", "empty", "garbage", "bool", "list", "overflow"])
    def test_missing_or_illegal_timestamp_is_flagged(self, missing):
        r = _analyze(_det(), _ev_no_ts(**missing))
        w = r.analysis_window or {}
        assert w.get("event_time_fallback") is True, (
            f"事件时间解析不出来，统计维度已锚在墙上时钟却没披露：{w}")
        assert any("event_time_missing" in x for x in r.reasons), (
            f"缺事件时间必须留痕，否则「按现在统计」与「按事件时间统计」"
            f"读起来一模一样：{r.reasons}")

    def test_present_timestamp_is_not_flagged(self):
        r = _analyze(_det(), _ev(EVENT_TS))
        w = r.analysis_window or {}
        assert w.get("event_time_fallback") is False
        assert not any("event_time_missing" in x for x in r.reasons), r.reasons

    def test_the_disclosure_reason_can_never_become_a_strong_signal(self):
        """结构守卫：这条 reason **不得**被 veto 闸读成「检测到了东西」。

        `veto_gates._strong_signal_basis` 按前缀筛强信号。
        若后人把 `ingest:` 也加进白名单，这条纯披露信息就会
        静默变成一条「有发现」的依据 —— 那是本轮改动最坏的可能后果，
        所以把它钉死。
        """
        from veto_gates import _strong_signal_basis, _STRONG_SIGNAL_REASONS
        reasons = ["ingest:event_time_missing", "ingest:received_time_unavailable"]
        assert _strong_signal_basis(type("S", (), {"reasons": reasons})()) == [], (
            "披露用 reason 被当成了强信号 —— 它会改变否决判定")
        assert not any(p in "ingest:" for p in _STRONG_SIGNAL_REASONS), (
            f"强信号白前缀 { _STRONG_SIGNAL_REASONS } 已包含 ingest:")


# ══════════════════════════════════════════════════════════════════════════
# §七.1 量化验收：基线年龄不得钝化灵敏度
# ══════════════════════════════════════════════════════════════════════════

class TestBaselineWindowIsAgeInvariant:
    """基线越厚，同一 3σ 突增量越难触发 —— 整改方案 §七.1 点名的缺陷。

    文档原文：「基线累积 60 天后，触发相同 3σ 事件所需的突增量达到一天基线的
    7.5 倍。」根因是 `hourly_counts` 按小时类别**累计**且永不衰减。

    整改后以带时间戳的滚动桶 `recent` 为准，并且用**实际跨度**（上限
    `window_days×24`）做分母。实测（2026-10-19，速率恒定 1.25 条/小时）：

        基线 1 天  → 6 条突发触达 3σ
        基线 7 天  → 5 条          （滚动桶饱和在 168 = 7×24）
        基线 30 天 → 5 条
        基线 60 天 → 5 条          → 60 天/1 天 = 0.83×，文档的 7.5× 已消失

    这里的守卫用的是**同一个「最近一小时计数 + 不同历史跨度」**的构造，
    所以判据是逐位相等，不依赖任何具体阈值数字。
    """

    RATE = 5                      # 稳态 5 条/小时
    SRC = "10.0.0.7"

    def _baseline(self, hours, last_hour_count, ts):
        import anomaly_detector as ad
        bl = ad.EntityBaseline()
        for h in range(hours - 1):
            bl.recent.append([ts - (hours - h) * 3600, self.RATE])
        bl.recent.append([ts - 60, last_hour_count])
        bl.last_seen = ts
        return bl

    def _sigma(self, hours, last_hour_count, ts):
        det = _det()
        det.baselines["src_ip"][self.SRC] = self._baseline(
            hours, last_hour_count, ts)
        return det._calc_statistical_deviation("src_ip", self.SRC, 3, ts)

    def test_the_same_burst_scores_identically_at_7_21_and_60_days(self):
        """超出窗口的历史对 σ 必须**零影响**。"""
        import anomaly_detector as ad
        ts = time.time()
        week = self._sigma(7 * 24, self.RATE + 15, ts)
        three_weeks = self._sigma(21 * 24, self.RATE + 15, ts)
        sixty = self._sigma(60 * 24, self.RATE + 15, ts)

        assert week == three_weeks == sixty, (
            "同一个突增量在不同基线年龄下得到不同 σ —— 基线厚度仍在钝化灵敏度:\n"
            f"7d={week!r} 21d={three_weeks!r} 60d={sixty!r}")
        assert week >= ad.SIGMA_EQUIVALENT_THRESHOLD, (
            f"同一突增量在 60 天基线上不再触达 3σ（σ={week}）—— "
            "这正是文档 §七.1 描述的「基线越厚越判不出」")

    def test_the_invariance_assertion_has_resolving_power(self):
        """空断言守卫：上面那条「三者相等」在判据恒返回常数时也会绿。

        所以必须同时证明判据**对输入有反应**：突增量翻倍 → σ 上升；
        且两者的底层桶数确实不同（168 vs 1440），否则「相等」可能
        来自根本没读历史。
        """
        ts = time.time()
        calm = self._sigma(60 * 24, self.RATE + 15, ts)
        hot = self._sigma(60 * 24, self.RATE + 25, ts)
        assert hot > calm, (
            f"突增量翻倍 σ 却没变（{calm} → {hot}）—— 判据没有分辨力，"
            "上面的相等断言是空的")

        week_bl = self._baseline(7 * 24, self.RATE + 15, ts)
        long_bl = self._baseline(60 * 24, self.RATE + 15, ts)
        assert len(long_bl.recent) == 1440 and len(week_bl.recent) == 168, (
            "构造失效：两份基线的桶数应当是 168 与 1440，"
            f"实得 {len(week_bl.recent)} 与 {len(long_bl.recent)}")
        assert self._sigma(7 * 24, self.RATE + 15, ts) == self._sigma(
            60 * 24, self.RATE + 15, ts)
