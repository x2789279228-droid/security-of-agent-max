# -*- coding: utf-8 -*-
"""规则库的三态必须是**真的三态**，且加载诊断必须能回答「高风险规则不可用没有」
（整改方案 §六.2，§9.40）。

## 缺陷（实测复现）

### A. 部分规则未加载时 `run_mode` 仍然是 "normal"

§六.2 原文：

> - normal：pySigma 规则按预期加载和运行。
> - degraded：启用了 Legacy 兜底**或部分规则未加载**，并明确记录原因。
> - unavailable：没有任何可用的合规检测路径。

修复前的判据是 `mode = "normal" if self._compiled else (...)` ——
只看「有没有编译出规则」，**不看有没有规则没加载上**。

实测：2 个规则文件、1 个 YAML 语法错误 →

```
run_mode        = normal        ← 应该是 degraded
compiled_count  = 1
load_errors     = [{'phase': 'parse', 'file': 'b.yml', ...}]   ← 明明记着失败
```

后果：运维（和 `routers/audit.py` 的 API 消费者）看到 "normal" 就以为规则库完好，
实际上**有一半规则没加载**。

### B. `load_errors` 里没有 severity → 「高风险规则不可用」不可判定

§六.2 的最后一句：

> **高风险规则不可用时，应触发告警和明确的分析不完整状态。**

而 `load_errors` 的每一条只有
`phase / file / rule_id / rule_name / error_code / error` —— **没有 severity**。
于是「一条 critical 规则没加载」和「一条 low 规则没加载」在数据上**长得一样**，
「高风险规则不可用」这件事**根本无法判定**。

## 本守卫盯什么

1. 三态真的分得开：全好 → normal；有坏有好 → degraded；一个都没有 → unavailable；
2. degraded 时**说得出原因**（`degraded_reasons`）；
3. `load_errors` 每条都带 `severity` 键 ——
   规则**已知**时是**真实级别**，**未知**时是显式的 `"unknown"`
   （「显式的不知道」与「忘了记这个键」必须能区分开）；
4. 检测结果**不受影响**（纯披露）。

⚠ 判据用**行为**（`stats()` 的实际取值），不用源码文本。
"""
from __future__ import annotations

import os
import sys

import pytest

os.environ.setdefault("SHARED_MEMORY_SKIP_DOTENV", "1")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sigma_engine.engine import PySigmaDetector  # noqa: E402

GOOD_RULE = """
title: Good Rule
id: 66666666-0000-0000-0000-000000000001
status: experimental
description: good
logsource:
  category: webserver
detection:
  keywords:
    - "UNION SELECT"
  condition: keywords
level: {lvl}
"""

#: YAML 语法错误 → 整个文件读不出来 → 里面的规则**级别未知**
BROKEN_YAML = "title: [unclosed\n  detection: {{{\n"

#: 语法合法但**条件写不出来**（pySigma 校验失败）→ 规则**已知** → 级别可取
INVALID_RULE = """
title: No Criteria Rule
id: 66666666-0000-0000-0000-000000000002
status: experimental
description: probe
logsource:
  category: webserver
detection:
  condition: selection
level: critical
"""


def _mk_detector(tmp_path, files: dict):
    d = tmp_path / "rules"
    d.mkdir(parents=True, exist_ok=True)
    for name, text in files.items():
        (d / name).write_text(text, encoding="utf-8")
    return PySigmaDetector(str(d), enforce=True)


def _base_event(**over):
    ev = {
        "event": "WEB_ATTACK",
        "url": "http://x/search?q=1",
        "message": "GET /search",
        "src_ip": "10.0.0.9",
        "dst_ip": "10.0.0.5",
        "protocol": "http",
        "severity": "medium",
        "details": "",
        "http.url": "http://x/search?q=1",
        "cs-uri-query": "q=1",
    }
    ev.update(over)
    return ev


class TestTheThreeStatesAreReallyThree:
    def test_a_healthy_library_is_normal(self, tmp_path):
        det = _mk_detector(tmp_path, {"ok.yml": GOOD_RULE.format(lvl="high")})
        st = det.stats()
        assert st["run_mode"] == "normal", st
        assert st["degraded_reasons"] == [], st
        assert st["load_errors"] == [], st

    def test_a_partially_loaded_library_is_degraded(self, tmp_path):
        """【核心性质】1 好 1 坏 → **degraded**，不是 normal。

        修复前这里是 "normal" —— 而同一个 `st` 里的 `load_errors`
        明明记着那个失败。
        """
        det = _mk_detector(tmp_path, {
            "ok.yml": GOOD_RULE.format(lvl="high"),
            "bad.yml": BROKEN_YAML,
        })
        st = det.stats()
        assert st["load_errors"], "前提失效：没有加载错误，下面就无从判断"
        assert st["run_mode"] == "degraded", (
            f"部分规则未加载却报 {st['run_mode']!r} —— "
            "运维看到 normal 就以为规则库完好")
        assert st["degraded_reasons"], (
            "降级了却说不出原因 —— §六.2 要求「明确记录原因」")
        assert "load_errors" in st["degraded_reasons"], st["degraded_reasons"]

    def test_a_library_with_nothing_usable_is_unavailable(self, tmp_path):
        det = _mk_detector(tmp_path, {"bad.yml": BROKEN_YAML})
        st = det.stats()
        assert st["run_mode"] == "unavailable", st
        assert st["compiled_count"] == 0, st

    def test_an_empty_rules_directory_is_unavailable(self, tmp_path):
        d = tmp_path / "rules"
        d.mkdir(parents=True, exist_ok=True)
        det = PySigmaDetector(str(d), enforce=True)
        st = det.stats()
        assert st["run_mode"] == "unavailable", st
        assert st["degraded_reasons"] == [], st


class TestTheLoadDiagnosticsCanAnswerTheHighRiskQuestion:
    def test_every_load_error_carries_a_severity_key(self, tmp_path):
        """每条 load_error 都带 `severity` 键。

        缺这个键 = 「忘了记」；有但值是 `"unknown"` = 「确实不知道」。
        两者必须能区分开。
        """
        det = _mk_detector(tmp_path, {
            "ok.yml": GOOD_RULE.format(lvl="high"),
            "bad.yml": BROKEN_YAML,
        })
        st = det.stats()
        assert st["load_errors"], "前提失效：没有加载错误"
        for e in st["load_errors"]:
            assert "severity" in e, (
                f"load_error 没有 severity 键 —— 「高风险规则不可用」不可判定: {e}")

    def test_a_known_rule_reports_its_real_severity(self, tmp_path):
        """规则**已知**时（pySigma 校验失败）→ severity 是**真实级别**。

        修复前 load_errors 里根本没有 severity，
        「一条 critical 没加载」与「一条 low 没加载」完全一样。
        """
        det = _mk_detector(tmp_path, {
            "ok.yml": GOOD_RULE.format(lvl="high"),
            "invalid.yml": INVALID_RULE,
        })
        st = det.stats()
        validate_errors = [e for e in st["load_errors"] if e.get("phase") == "validate"]
        assert validate_errors, (
            f"前提失效：没有 validate 阶段的错误（load_errors={st['load_errors']}）")
        sev = validate_errors[0]["severity"]
        assert sev == "critical", (
            f"已知的 critical 规则没加载，severity 却报 {sev!r} —— "
            "「高风险规则不可用」无法判定")

    def test_an_unknown_rule_reports_unknown_explicitly(self, tmp_path):
        """规则**未知**时（文件解析失败）→ severity 是显式的 `"unknown"`。"""
        det = _mk_detector(tmp_path, {
            "ok.yml": GOOD_RULE.format(lvl="high"),
            "bad.yml": BROKEN_YAML,
        })
        st = det.stats()
        parse_errors = [e for e in st["load_errors"] if e.get("phase") == "parse"]
        assert parse_errors, (
            f"前提失效：没有 parse 阶段的错误（load_errors={st['load_errors']}）")
        assert parse_errors[0]["severity"] == "unknown", parse_errors[0]


class TestTheDetectionIsUnaffected:
    def test_a_healthy_rule_still_hits_when_another_file_is_broken(self, tmp_path):
        """回归：这次修复是**纯披露** —— 好规则照常命中。"""
        det = _mk_detector(tmp_path, {
            "ok.yml": GOOD_RULE.format(lvl="high"),
            "bad.yml": BROKEN_YAML,
        })
        hits = det.detect(_base_event(url="http://x/?q=UNION SELECT"))
        assert hits, "部分规则未加载时，好规则也不命中了 —— 修复改动了检测语义"
        assert hits[0].rule_id == "66666666-0000-0000-0000-000000000001", hits[0].rule_id
        miss = det.detect(_base_event(url="http://x/?q=benign"))
        assert not miss, "良性事件被误报"


if __name__ == "__main__":       # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
