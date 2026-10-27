# -*- coding: utf-8 -*-
"""Sigma 检测分段耗时剖析（PERF-OPT Wave 1-1，2026-10-26）。

压测实测 42.46 ms/事件（150 规则，`soc_detection_seconds` 734s/17299 次），
本工具把 detect() 的成本拆成三段，为 Wave 1-3（预筛）/1-4（批量）定向：

  seg_mapping   canonical_matching_view + apply_mapping（规范化视图+字段映射）
  seg_table     每事件私有 :memory: SQLite 的 connect + CREATE TABLE + INSERT + commit
  seg_rules     逐条执行已编译规则 SQL（150 条 execute+fetchone）

用法（backend/ 下）::

    python tools/profile_sigma_detect.py [--events 200]

口径：真实规则库（sigma_engine/rules + community_active），三类代表事件
（web 攻击 URL / 端口探测 / 纯文本告警）各 1/3；每段独立计时再合计，
合计与黑盒 detect() 墙钟互相校验。
"""
from __future__ import annotations

import argparse
import os
import sqlite3
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("SHARED_MEMORY_SKIP_DOTENV", "1")

EVENT_SHAPES = [
    {   # web 攻击（URL 承载, 规则命中面最大）
        "event": "SQL_INJECTION", "event_type": "SQL_INJECTION",
        "severity": "high", "src_ip": "203.0.113.10", "dst_ip": "10.0.0.5",
        "dst_port": 443, "method": "GET",
        "url": "/search?q=%27%20UNION%20SELECT%20password%20FROM%20users--",
        "message": "SQLi probe", "confidence": 80,
    },
    {   # 端口探测（端口型规则面）
        "event": "PORT_SCAN", "event_type": "PORT_SCAN",
        "severity": "medium", "src_ip": "185.220.101.44", "dst_ip": "10.0.0.5",
        "dst_port": 9200, "message": "scan 22,80,443,3389,8001", "confidence": 60,
    },
    {   # 纯文本告警（无 url/端口, 预筛收益的最大受益形态）
        "event": "C2_BEACON", "event_type": "C2_BEACON",
        "severity": "critical", "src_ip": "10.0.30.7", "dst_ip": "10.0.0.6",
        "message": "JA3 match beacon 5min cycle", "confidence": 70,
    },
]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--events", type=int, default=200)
    args = ap.parse_args()

    from sigma_engine.engine import PySigmaDetector
    from normalization import canonical_matching_view
    from sigma_engine.mapping import apply_mapping

    rules_dir = Path(__file__).resolve().parents[1] / "sigma_engine" / "rules"
    det = PySigmaDetector(str(rules_dir), enforce=True)
    snap = det._snapshot
    n_rules = len(snap.compiled)
    print(f"rules compiled: {n_rules}")

    events = [dict(EVENT_SHAPES[i % 3]) for i in range(args.events)]

    seg_mapping, seg_table, seg_rules, seg_blackbox = [], [], [], []
    for ev in events:
        # ── 黑盒墙钟 ──
        t0 = time.perf_counter()
        det.detect(dict(ev))
        seg_blackbox.append((time.perf_counter() - t0) * 1000)

        # ── 分段复刻（与 _detect_with_snapshot 同序） ──
        t0 = time.perf_counter()
        mapped = apply_mapping(canonical_matching_view(dict(ev)))
        t1 = time.perf_counter()
        conn = sqlite3.connect(":memory:")
        det._ensure_table(list(mapped.keys()), mapped, conn=conn)
        t2 = time.perf_counter()
        cur = conn.cursor()
        for _meta, sql in snap.compiled:
            cur.execute(sql).fetchone()
        t3 = time.perf_counter()
        conn.close()
        seg_mapping.append((t1 - t0) * 1000)
        seg_table.append((t2 - t1) * 1000)
        seg_rules.append((t3 - t2) * 1000)

    def _row(name, xs):
        xs.sort()
        print(f"{name:12s} mean={statistics.mean(xs):7.3f}ms  "
              f"p50={xs[len(xs)//2]:7.3f}  p95={xs[int(len(xs)*0.95)]:7.3f}  "
              f"min={xs[0]:7.3f}  max={xs[-1]:7.3f}")

    print(f"\nper-event segment breakdown (n={args.events}, rules={n_rules}):")
    _row("mapping", seg_mapping)
    _row("table", seg_table)
    _row("rules", seg_rules)
    total = [a + b + c for a, b, c in zip(seg_mapping, seg_table, seg_rules)]
    _row("sum(3seg)", total)
    _row("blackbox", seg_blackbox)

    mb, mr = statistics.mean(seg_table), statistics.mean(seg_rules)
    mm = statistics.mean(seg_mapping)
    grand = mm + mb + mr
    print(f"\nshare: mapping={mm/grand:5.1%}  table={mb/grand:5.1%}  rules={mr/grand:5.1%}")
    print(f"implied single-process ceiling ≈ {1000 / grand:.1f} eps "
          f"(measured 42.46ms in PERF round ⇒ compare)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
