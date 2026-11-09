# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""README 数字门禁 (R5 / 复审 P1-6 防复发)。

README 里手写的统计数字(规则数/测试数/组件数)与实测比对, 漂移即失败。
历史教训: 路线4 提交加了 9 条规则没回写 README, "150 条"实际 159 条。

实测口径:
  - Sigma 规则: rules/*.yml + rules_community_active/*.yml 文件数
  - 测试: backend 下 `pytest --collect-only -q` 末行(较慢, --fast 跳过)
  - 组件: frontend/src/components/**/*.tsx
"""
from __future__ import annotations

import glob
import io
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.normpath(os.path.join(HERE, ".."))
BACKEND = os.path.join(REPO, "backend")

sys.stdout.reconfigure(encoding="utf-8")


def count_rules() -> tuple[int, int, int]:
    own = len(glob.glob(os.path.join(BACKEND, "sigma_engine", "rules", "*.yml")))
    comm = len(glob.glob(os.path.join(BACKEND, "sigma_engine", "rules_community_active", "*.yml")))
    return own, comm, own + comm


def count_components() -> int:
    return len(glob.glob(os.path.join(REPO, "frontend", "src", "components", "**", "*.tsx"), recursive=True))


def count_tests() -> int | None:
    try:
        r = subprocess.run(
            [sys.executable, "-m", "pytest", "--collect-only", "-q"],
            cwd=BACKEND, capture_output=True, text=True, timeout=240,
        )
        m = re.search(r"(\d+) tests? collected", r.stdout)
        return int(m.group(1)) if m else None
    except Exception:
        return None


def main() -> int:
    fast = "--fast" in sys.argv
    src = io.open(os.path.join(REPO, "README.md"), encoding="utf-8").read()
    failures = []

    own, comm, total_rules = count_rules()
    m = re.findall(r"(\d+) 条规则", src)
    claimed = {int(x) for x in m}
    if claimed and total_rules not in claimed:
        failures.append(f"规则数: README 宣称 {sorted(claimed)}, 实测 {total_rules} (自研 {own} + 社区 {comm})")

    comps = count_components()
    m = re.findall(r"(\d+) 组件", src)
    claimed_c = {int(x) for x in m}
    if claimed_c and comps not in claimed_c:
        failures.append(f"组件数: README 宣称 {sorted(claimed_c)}, 实测 {comps}")

    if not fast:
        n_tests = count_tests()
        if n_tests is not None:
            m = re.findall(r"(\d+) 项后?端?测试", src)
            claimed_t = {int(x) for x in m}
            if claimed_t and n_tests not in claimed_t:
                failures.append(f"测试数: README 宣称 {sorted(claimed_t)}, 实测 collected={n_tests}")

    # 复现命令守卫: backend/ 无 __init__.py, python -m backend.* 必然 ImportError
    if re.search(r"python -m backend\.eval_datasets", src):
        failures.append("复现命令: 发现 'python -m backend.eval_datasets.*' — backend 无 __init__.py, 应为 'cd backend && python -m eval_datasets.*'")

    if failures:
        print("FAIL: README 数字与实测漂移:")
        for f in failures:
            print("  -", f)
        return 1
    print("OK: README 数字与实测一致(规则=%d, 组件=%d%s)" % (
        total_rules, comps, ", 测试快查已跳过" if fast else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
