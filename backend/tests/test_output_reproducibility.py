# -*- coding: utf-8 -*-
"""检测/统计输出必须**跨进程可复现**（整改报告 §9.58）。

## 背景

Python 的 str 哈希**每进程随机化**（`PYTHONHASHSEED`）→
`list(set(...))` 的顺序**每次启动都不同**。本轮在生产代码里扫出 6 处：

| 模块 | 位置 | 输出 |
|---|---|---|
| `sigma_detector.py` | `analyze()` / `stats()` | `attack_types` |
| `sigma_engine/engine.py` | `detect()` / `stats()` | `attack_types` |
| `tool_registry.py` | 关联分组 | `types` |
| `self_play/overlay.py` | `detect()` | `attack_types` |

内容稳定、**顺序不稳定** → 同一份数据的 API 响应/统计**逐字节不可复现**
（整改方案 §十三「异常检测：…**重放结果可复现**」）。

## 本守卫盯什么

1. **行为**：统计里的集合型列表必须**已排序**（非空转：测试环境有 16 条规则）；
2. **决定性**：两个**不同 `PYTHONHASHSEED`** 的子进程 → 同一份输出的
   JSON 必须**逐字节相同**；
3. **结构**：这四个模块里不得再出现**未排序**的集合转列表。
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND))

#: 扫过的那四个模块（集合转列表只允许出现在**已排序**的写法里）
SCANNED = [
    "sigma_detector.py",
    "sigma_engine/engine.py",
    "tool_registry.py",
    "self_play/overlay.py",
]

PROBE = (
    "import json, sigma_detector;"
    "print(json.dumps(sigma_detector.sigma_detector.stats(), sort_keys=True, default=str))"
)


class TestTheOutputsAreSorted:
    def test_the_sigma_stats_attack_types_is_sorted(self):
        """**行为**断言：统计里的集合型列表必须已排序（非空转：环境里有 16 条规则）。"""
        import sigma_detector
        st = sigma_detector.sigma_detector.stats()
        types = list(st.get("attack_types") or [])
        assert types, "规则库是空的 —— 这条断言会变成空断言，先确认环境"
        assert types == sorted(types), f"attack_types 未排序：{types}"

    def test_no_unsorted_set_to_list_in_the_scanned_modules(self):
        """**结构**规则：这四个模块里不得再有未排序的集合转列表。"""
        offenders = []
        for rel in SCANNED:
            src = (BACKEND / rel).read_text(encoding="utf-8")
            for i, line in enumerate(src.splitlines(), 1):
                stripped = line.strip()
                if stripped.startswith("#"):
                    continue
                if "list(set(" in stripped or "list({" in stripped:
                    offenders.append("%s:%d %s" % (rel, i, stripped[:90]))
        assert not offenders, (
            "集合转列表必须**排序**（否则跨进程不可复现，§9.58）：\n  "
            + "\n  ".join(offenders))


class TestTheReproducibilityAcrossProcesses:
    def test_two_hash_seeds_give_byte_identical_output(self):
        """**决定性**：两个不同 `PYTHONHASHSEED` 的进程 → 输出必须逐字节相同。

        这是本节的核心性质：**同一份数据，两个进程，结果一致**。
        """
        outs = []
        for seed in ("0", "12345"):
            env = dict(os.environ)
            env["PYTHONHASHSEED"] = seed
            env["PYTHONIOENCODING"] = "utf-8"
            env["SHARED_MEMORY_SKIP_DOTENV"] = "1"
            r = subprocess.run(
                [sys.executable, "-c", PROBE], cwd=str(BACKEND), env=env,
                capture_output=True, text=True, timeout=300,
                encoding="utf-8", errors="replace")
            assert r.returncode == 0, f"探针失败：\n{r.stdout}\n{r.stderr}"
            outs.append((r.stdout or "").strip())
        assert outs[0], "探针没有输出"
        assert outs[0] == outs[1], (
            "两个不同 PYTHONHASHSEED 的进程给出了**不同**的输出 → "
            "结果跨进程不可复现（§9.58）")
        payload = json.loads(outs[0])
        types = list(payload.get("attack_types") or [])
        assert types, "规则库是空的 —— 这条断言会变成空断言，先确认环境"
        assert types == sorted(types), types


def pytest_main():
    import pytest
    return pytest.main([__file__, "-q"])


if __name__ == "__main__":       # pragma: no cover
    raise SystemExit(pytest_main())
