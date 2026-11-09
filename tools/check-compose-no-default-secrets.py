# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""compose 密码默认值门禁 (R3 / 复审 P1-14 防复发)。

规则: docker-compose*.yml 中, 变量名含 PASSWORD/PASSWD/SECRET/KEY/PWD 的
环境引用不允许写 `:-默认值` 形式的非空回退 —— 必须用 `:?must be set`
fail-closed, 或 `:-}`(空回退, 表示"未配置即关闭功能")。

允许(白名单, 逐条理由):
  - `:-}` 空回退: 功能开关语义, 缺省即不启用, 不构成弱口令。
  - 示例占位(仅 *.example 文件)不在扫描范围。

背景: 2026-10-29 复审发现 base compose 三处 `${TEMPORAL_PASSWORD:-temporal_dev_pwd}`
等默认口令回退, prod overlay 未覆盖 → 生产叠加后仍可用默认口令登录。
"""
from __future__ import annotations

import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.normpath(os.path.join(HERE, ".."))

# 变量名命中这些词即视为敏感凭据
SECRET_VAR_PAT = re.compile(r"(PASSWORD|PASSWD|SECRET|_KEY\b|API_KEY|_PWD\b)", re.I)
# ${VAR:-nonempty} 非空默认值回退
DEFAULT_FALLBACK_PAT = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*):-([^}]*)\}")

COMPOSE_FILES = [
    "docker-compose.yml",
    "docker-compose.prod.yml",
    "docker-compose.ha.yml",
    "docker-compose.dev.yml",
]


def main() -> int:
    violations = []
    for name in COMPOSE_FILES:
        path = os.path.join(REPO, name)
        if not os.path.exists(path):
            continue
        with open(path, encoding="utf-8") as f:
            for lineno, line in enumerate(f, 1):
                for m in DEFAULT_FALLBACK_PAT.finditer(line):
                    var, fallback = m.group(1), m.group(2)
                    if SECRET_VAR_PAT.search(var) and fallback.strip():
                        violations.append((name, lineno, var, fallback.strip()[:40]))
                    elif SECRET_VAR_PAT.search(var) and not fallback.strip():
                        pass  # 空回退 = 功能开关语义, 允许
                    elif fallback.strip() and var.endswith("_PASSWORD"):
                        violations.append((name, lineno, var, fallback.strip()[:40]))

    if violations:
        print("FAIL: compose 存在带非空默认值的凭据回退(必须改 :? fail-closed):")
        for f, ln, var, fb in violations:
            print("  %s:%d  ${%s:-%s}" % (f, ln, var, fb))
        print("\n共 %d 处。修复: ${%s:?%s must be set}" % (len(violations), "VAR", "VAR"))
        return 1

    print("OK: compose 凭据变量无非空默认回退(%d 个文件检查通过)" % len(COMPOSE_FILES))
    return 0


if __name__ == "__main__":
    sys.exit(main())
