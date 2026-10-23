# -*- coding: utf-8 -*-
"""§七 的「不同部署规模」「不同时间窗口」两维：分档报告。

整改方案 §七「异常检测验收指标」：

> 至少按新实体、成熟实体、**不同部署规模**、**不同时间窗口**分别报告

前两维由 :mod:`eval_datasets.evaluate_detection` 的 `cold_start_breakdown()`
覆盖（新实体 / 成熟实体）；本模块覆盖后两维。

## 为什么单独一个模块

1. **不动既有 8 条标定集** —— §9.3 的阈值扫描（**召回下界**
   `[0, 0.4357)`）因此**不受影响**，两处测量互不污染。
   （注：那个区间是「不漏掉应检出样本」的**下界**，不是可行区间；
   完整可行区间另有其值且在当前标定集上为**空集** —— 见 §9.60。）
2. **要钉住时钟**。窗口淘汰用的是**墙钟**：
   `anomaly_detector._update_baseline` 里
   `cutoff = time.time() - window_days * 86400`。
   而标定集锚在固定历史时刻 —— 不钉住时钟的话，
   同一份代码在不同时间跑会淘汰掉不同的桶，矩阵就**不可复现**。
   （这与 `tests/test_anomaly_replay_determinism.py` 的做法一致。）

## 矩阵的含义

行 = **部署规模**（基线有多厚：历史多长、每小时多少事件）
列 = **时间窗口**（`AnomalyDetector(window_days=...)`）

每个格子做同一件事：喂一份基线 + 一段 6 倍速率突增，然后探一条事件，
报出**是否检出**、得分、σ、基线样本量。

⚠ 单元格里的数字来自**合成基线**，量的是「配置组合下的表现」，
**不是生产误报率**（那条要真实流量，§9.27 已登记为待验证）。
"""
from __future__ import annotations

import contextlib
import json
import os
import sys
import time
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from anomaly_detector import (  # noqa: E402
    ANOMALY_SCORE_THRESHOLD,
    SIGMA_EQUIVALENT_THRESHOLD,
    AnomalyDetector,
)

try:
    from zoneinfo import ZoneInfo
    _TZ = ZoneInfo("Asia/Shanghai")
except Exception:                                   # pragma: no cover
    _TZ = timezone(timedelta(hours=8))

#: 矩阵的「现在」。固定值 = 可复现（理由见模块 docstring）。
MATRIX_NOW = datetime(2026, 10, 20, 3, 0, 0, tzinfo=_TZ)

#: 部署规模：(标签, 基线小时数, 每小时事件数)
SCALES = [
    ("young_12h_x20", 12, 20),
    ("steady_24h_x50", 24, 50),
    ("aged_168h_x10", 168, 10),
]

#: 时间窗口（天）
WINDOWS = [1, 7, 30]

#: 突增倍数阶梯。扫一串而不是只取一个 ——
#: 固定倍数只能回答「检不检得出」，扫一串才能回答「**多小的突增检得出**」
#: （灵敏度），那才是「不同部署规模/窗口下的表现」这个问题想问的。
BURST_MULTS = [1.2, 1.5, 2, 3, 4, 6]

# ══════════════════════════════════════════════════════════════
# 基线适应矩阵（§9.28.6 登记的缺口：窗口维度的「适应速度」没测）
# ══════════════════════════════════════════════════════════════
#: 场景：实体先处在旧常态（ADAPT_OLD_RATE 条/小时），
#: Δ 小时前**换到新常态**（ADAPT_NEW_RATE），
#: 然后探一条**新常态**的流量 —— 它**不该**被当成异常。
#:
#: 问的是：换常态之后要过多久，基线才把新常态认下来？
#: 期间新常态的流量被当成异常 = **误报**。
#: 窗口长度如何影响这个适应时间，就是这一维要回答的。
ADAPT_OLD_HOURS = 12          # 旧常态持续多少小时
ADAPT_OLD_RATE = 50           # 旧常态速率（条/小时）
ADAPT_NEW_RATE = 100          # 新常态速率
ADAPT_DELTAS = [1, 2, 4, 8, 12, 24, 48]   # 换常态后过了多少小时

SRC_IP = "10.60.0.1"


_CALLS = [0]


@contextlib.contextmanager
def pinned_clock(ts: float):
    """把 ``time.time()`` 钉在 ts 上（退出时恢复）。"""
    real = time.time
    time.time = lambda: ts
    try:
        yield
    finally:
        time.time = real


def _ev(event_id: str, event_type: str, ts: float, severity: str = "info") -> dict:
    return {
        "event_id": event_id,
        "event_type": event_type,
        "event": event_type,          # 两个键都要写（见 detection_cases._ev 的说明）
        "src_ip": SRC_IP,
        "dst_ip": "10.60.0.2",
        "dst_port": 443,
        "severity": severity,
        "url": "",
        "message": "",
        "timestamp": ts,
    }


def _cell(scale, window_days: int, burst_mult: int) -> dict:
    """跑一个格子：基线 + 突增 + 探针。"""
    label, hours, per_hour = scale
    now = MATRIX_NOW.timestamp()
    det = AnomalyDetector(window_days=window_days)

    events = []
    eid = 0
    # 基线：每小时一个桶，每桶 per_hour 条
    for h in range(hours, 0, -1):
        bucket_ts = now - h * 3600
        for k in range(per_hour):
            eid += 1
            events.append(_ev(
                f"bl-{eid}",
                "BENIGN" if k % 5 else "HEALTH_CHECK",
                bucket_ts + k * 0.01))
    # 突增：当前小时内 burst_mult 倍（取整，最少 1 条）
    burst_ts = now - 60
    n_burst = max(1, int(round(per_hour * burst_mult)))
    for k in range(n_burst):
        eid += 1
        events.append(_ev(f"burst-{eid}", "BENIGN", burst_ts + k * 0.001))
    # 探针：当前小时内再一条
    probe = _ev("probe", "BENIGN", now - 1)

    import asyncio

    async def go():
        for e in events:
            await det.analyze(dict(e))
        return await det.analyze(dict(probe))

    with pinned_clock(now):
        rep = asyncio.run(go())

    win = rep.analysis_window or {}
    return {
        "scale": label,
        "baseline_hours": hours,
        "events_per_hour": per_hour,
        "window_days": window_days,
        "burst_mult": burst_mult,
        "status": rep.status,
        "detected": rep.status == "detected",
        "anomaly_score": rep.anomaly_score,
        "deviation_sigma": rep.deviation_sigma,
        "baseline_samples": rep.baseline_samples,
        "effective_weights": dict(rep.effective_weights),
        "inconclusive_dimensions": list(rep.inconclusive_dimensions),
        "event_time_source": rep.event_time_source,
        "analysis_window_window_days": win.get("window_days"),
    }


def run_matrix() -> dict:
    """跑完整矩阵。"""
    cells = []
    for scale in SCALES:
        for w in WINDOWS:
            for m in BURST_MULTS:
                cells.append(_cell(scale, w, m))

    # 灵敏度：每个 (规模, 窗口) 下**能被检出的最小突增倍数**
    threshold = {}
    for scale in SCALES:
        for w in WINDOWS:
            cs = [c for c in cells
                  if c["scale"] == scale[0] and c["window_days"] == w]
            hit = [c["burst_mult"] for c in cs if c["detected"]]
            threshold["%s|w%d" % (scale[0], w)] = min(hit) if hit else None

    detected = sum(1 for c in cells if c["detected"])
    by_window = {}
    for w in WINDOWS:
        ws = [c for c in cells if c["window_days"] == w]
        by_window[str(w)] = {
            "detected": sum(1 for c in ws if c["detected"]),
            "n": len(ws),
            "min_detectable_burst_mult": min(
                [c["burst_mult"] for c in ws if c["detected"]] or [None]),
        }
    by_scale = {}
    for s in SCALES:
        ss = [c for c in cells if c["scale"] == s[0]]
        by_scale[s[0]] = {
            "detected": sum(1 for c in ss if c["detected"]),
            "n": len(ss),
            "min_detectable_burst_mult": min(
                [c["burst_mult"] for c in ss if c["detected"]] or [None]),
        }
    return {
        "matrix_now": MATRIX_NOW.isoformat(),
        "burst_mults": BURST_MULTS,
        "scales": [{"label": s[0], "baseline_hours": s[1], "events_per_hour": s[2]}
                   for s in SCALES],
        "windows": WINDOWS,
        "cells": cells,
        "detected_total": detected,
        "cells_total": len(cells),
        "min_detectable_burst_mult": threshold,
        "by_window": by_window,
        "by_scale": by_scale,
        "_note": "合成基线，量的是「配置组合下的表现」，不是生产误报率；"
                 "真实指标需真实流量（§9.27 登记为待验证）。",
    }


def _adapt_cell(window_days: int, delta_hours: int) -> dict:
    """一个适应格子：旧常态历史 + 新常态 Δ 小时 + 探一条新常态流量。

    探针**不该**被当成异常；被当成异常 = 该配置在这个 Δ 上
    仍会把**合法的新常态**误报出去。
    """
    now = MATRIX_NOW.timestamp()
    det = AnomalyDetector(window_days=window_days)
    events = []
    eid = 0
    total_hours = ADAPT_OLD_HOURS + delta_hours
    for h in range(total_hours, 0, -1):
        bucket_ts = now - h * 3600
        # 桶 h 是「h 小时前」。换常态发生在 Δ 小时前，
        # 所以**距现在 ≤ Δ 小时的桶**属于新常态，更早的是旧常态。
        #
        # ⚠ 这里第一版写反了（用 `total_hours - h` 判断），
        # 于是「旧常态」反而占据了最近的历史 ——
        # 结果看起来「立刻就适应」，其实场景整个反了。
        # 抓住它靠的是「Δ=1 小时就该误报」这个直觉：
        # 换常态才 1 小时，基线几乎全是旧常态，探针**必须**被报成异常。
        rate = ADAPT_NEW_RATE if h <= delta_hours else ADAPT_OLD_RATE
        for k in range(rate):
            eid += 1
            events.append(_ev(
                f"h-{eid}",
                "BENIGN" if k % 5 else "HEALTH_CHECK",
                bucket_ts + k * (3600.0 / max(1, rate))))
    # 探针：当前小时，新常态
    probe = _ev("probe", "BENIGN", now - 1)

    import asyncio

    async def go():
        for e in events:
            await det.analyze(dict(e))
        return await det.analyze(dict(probe))

    with pinned_clock(now):
        rep = asyncio.run(go())

    return {
        "window_days": window_days,
        "delta_hours": delta_hours,
        "status": rep.status,
        "flagged_as_anomaly": rep.status == "detected",
        "anomaly_score": rep.anomaly_score,
        "deviation_sigma": rep.deviation_sigma,
        "baseline_samples": rep.baseline_samples,
        "dimensions": dict(rep.dimensions),
        "effective_weights": dict(rep.effective_weights),
        "inconclusive_dimensions": list(rep.inconclusive_dimensions),
        # 判定是 `score > 阈值 or sigma > 3` 的**或**语义。
        # 得分没过阈值却被判 detected 的，必须能区分出来 ——
        # 那说明触发误报的是**σ 旁路**，不是得分。
        "flagged_by_sigma_bypass": (
            rep.status == "detected"
            and rep.anomaly_score <= ANOMALY_SCORE_THRESHOLD
            and rep.deviation_sigma > SIGMA_EQUIVALENT_THRESHOLD),
    }


def run_adaptation_matrix() -> dict:
    """跑「基线适应速度」矩阵。"""
    cells = []
    for w in WINDOWS:
        for d in ADAPT_DELTAS:
            cells.append(_adapt_cell(w, d))

    # 适应时间：最小 Δ（小时）使得新常态**不再**被报成异常
    adaptation_hours = {}
    for w in WINDOWS:
        cs = sorted([c for c in cells if c["window_days"] == w],
                    key=lambda c: c["delta_hours"])
        adapted = [c["delta_hours"] for c in cs if not c["flagged_as_anomaly"]]
        adaptation_hours[str(w)] = min(adapted) if adapted else None

    return {
        "old_rate": ADAPT_OLD_RATE,
        "new_rate": ADAPT_NEW_RATE,
        "old_hours": ADAPT_OLD_HOURS,
        "deltas": ADAPT_DELTAS,
        "windows": WINDOWS,
        "cells": cells,
        "adaptation_hours": adaptation_hours,
        "flagged_total": sum(1 for c in cells if c["flagged_as_anomaly"]),
        "cells_total": len(cells),
        "_note": "探针是**合法的新常态**流量 —— 被报成 detected 就是误报。"
                 "合成场景，量的是「配置组合下的表现」，不是生产误报率。",
    }


def render(m: dict) -> str:
    L = []
    L.append("【§七 · 不同部署规模 × 不同时间窗口】" + "-" * 40)
    L.append(f"矩阵「现在」= {m['matrix_now']}（固定值，可复现）")
    L.append(f"突增倍数阶梯 = {m['burst_mults']}")
    L.append("")
    L.append("检出情况（格子 = 得分 / 状态；σ 恒为 10.0 时显示 'σmax'）：")
    for s in m["scales"]:
        for w in m["windows"]:
            cs = [c for c in m["cells"]
                  if c["scale"] == s["label"] and c["window_days"] == w]
            cs.sort(key=lambda c: c["burst_mult"])
            parts = []
            for c in cs:
                mark = "✓" if c["detected"] else "·"
                parts.append(f"{c['burst_mult']}x {mark}{c['anomaly_score']:.3f}")
            thr = m["min_detectable_burst_mult"].get("%s|w%d" % (s["label"], w))
            thr_txt = ("最小可检 %dx" % thr) if thr else ("**全部未检出**")
            L.append(f"  {s['label']:<18} 窗口 {w:>2}d  "
                     f"{'  '.join(parts):<44} {thr_txt}")
    L.append("")
    L.append("  样本量（基线样本数）与 σ：")
    for c in m["cells"]:
        L.append(f"    {c['scale']:<18} 窗口 {c['window_days']:>2}d "
                 f"突增 {c['burst_mult']}x  样本 {c['baseline_samples']:>4}  "
                 f"σ {c['deviation_sigma']:>5}  {c['status']:<14} 不可判维度: "
                 f"{','.join(c['inconclusive_dimensions']) or '-'}")
    L.append("")
    L.append(f"  检出 {m['detected_total']} / {m['cells_total']} 个格子")
    L.append(f"  按窗口：{m['by_window']}")
    L.append(f"  按规模：{m['by_scale']}")
    L.append("")
    L.append("  ⚠ " + m["_note"])
    L.append("")
    return "\n".join(L)


def render_adaptation(a: dict) -> str:
    L = []
    L.append("【基线适应速度】合法的新常态流量被误报的时长" + "-" * 22)
    L.append(f"场景：旧常态 {a['old_rate']} 条/小时 × {a['old_hours']} 小时 → "
             f"换到新常态 {a['new_rate']} 条/小时；探针是**新常态**流量")
    L.append("")
    L.append(f"{'换常态后经过':<14}" + "".join(
        f"{'窗口 ' + str(w) + 'd':>18}" for w in a["windows"]))
    for d in a["deltas"]:
        row = f"{str(d) + ' 小时':<14}"
        for w in a["windows"]:
            c = next(x for x in a["cells"]
                     if x["window_days"] == w and x["delta_hours"] == d)
            mark = "误报" if c["flagged_as_anomaly"] else "已适应"
            row += f"{mark + ' ' + format(c['anomaly_score'], '.3f'):>18}"
        L.append(row)
    L.append("")
    L.append("  适应时间（新常态不再被误报所需的最短时长）：")
    for w in a["windows"]:
        h = a["adaptation_hours"].get(str(w))
        L.append(f"    窗口 {w:>2}d → " + (f"{h} 小时" if h else "**在本矩阵范围内未适应**"))
    L.append("")
    L.append(f"  被误报的格子：{a['flagged_total']} / {a['cells_total']}")
    L.append("  ⚠ " + a["_note"])
    L.append("")
    return "\n".join(L)


def main(argv: list | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if "--adapt-only" in argv:
        a = run_adaptation_matrix()
        if "--json" in argv:
            print(json.dumps(a, ensure_ascii=False, indent=2, default=str))
        else:
            print(render_adaptation(a))
        return 0
    m = run_matrix()
    if "--adapt" in argv:
        m["adaptation"] = run_adaptation_matrix()
    if "--json" in argv:
        print(json.dumps(m, ensure_ascii=False, indent=2, default=str))
    else:
        print(render(m))
        if "adaptation" in m:
            print(render_adaptation(m["adaptation"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
