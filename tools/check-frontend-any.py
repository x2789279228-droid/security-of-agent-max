# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""前端类型棘轮门禁 (W2-2, 2026-10-29)。

规则: `fetchJSON<any` 在 api.ts 的出现数只许下降不许上升 —— 当前上限
139(stats/logsEvents 已类型化)。给端点补了类型后请把上限同步调低。

附带检查:
  - `new EventSource` 只许出现在 lib/api.ts(共享 SSE 工厂) —— 防止页面
    再私建无重连的 EventSource(复审 P1-13 的复发守卫)。
"""
from __future__ import annotations

import glob
import io
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.normpath(os.path.join(HERE, ".."))
API_TS = os.path.join(REPO, "frontend", "src", "lib", "api.ts")

#: 棘轮上限 — 只许调低。历史: 2026-10-29 从 141 起步, stats/logsEvents 已类型化。
FETCH_ANY_LIMIT = 139

sys.stdout.reconfigure(encoding="utf-8")


def main() -> int:
    src = io.open(API_TS, encoding="utf-8").read()
    n = len(re.findall(r"fetchJSON<any", src))
    failures = []
    if n > FETCH_ANY_LIMIT:
        failures.append(
            f"api.ts 的 fetchJSON<any> 有 {n} 处, 超过棘轮上限 {FETCH_ANY_LIMIT} "
            "— 禁止新增未类型化端点; 补类型后请调低上限"
        )

    stray_es = []
    for p in glob.glob(os.path.join(REPO, "frontend", "src", "**", "*.ts*"), recursive=True):
        rel = os.path.relpath(p, os.path.join(REPO, "frontend", "src")).replace("\\", "/")
        if rel == "lib/api.ts":
            continue
        try:
            body = io.open(p, encoding="utf-8").read()
        except OSError:
            continue
        if "new EventSource" in body:
            stray_es.append(rel)
    if stray_es:
        failures.append(
            f"new EventSource 出现在共享工厂之外: {stray_es} — 页面必须走 lib/eventStream 单例"
        )

    if failures:
        print("FAIL: 前端类型棘轮")
        for f in failures:
            print("  -", f)
        return 1
    print(f"OK: fetchJSON<any>={n}(上限 {FETCH_ANY_LIMIT}), EventSource 单点持有")
    return 0


if __name__ == "__main__":
    sys.exit(main())
