"""J 清零（2026-10-30）：跨语言 op 语义对齐契约钉。

Python ``sigma_detector._check_aggregation`` 与 Flink
``SigmaThresholdAggregationJob.ThresholdWindowFunction.thresholdMet``
必须遵守**同一份比较契约**：
  '>' → 严格大于；'>=' → 大于等于；'=='/'=' → 等于；
  认不出的 op → 回退 '>='（保持旧 Flink 硬编码兼容）。
修复前 Python default 回退 '>' 而 Flink 回退 '>=' —— 同一未知 op 规则
在 HTTP 直连路径与 Kafka/Flink 路径告警时点不同。
Java 侧真执行由 test_sigma_aggregation_action_chain 的窗口层覆盖
（本文件钉 Python 侧 + 双侧契约文本一致性的静态核对）。
"""
import re
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import sigma_detector


def _met(op: str, count: int, threshold: int) -> bool:
    """直接驱动 Python 侧聚合比较逻辑（复用生产代码的判定分支）。"""
    from collections import deque
    det = sigma_detector.SigmaDetector.__new__(sigma_detector.SigmaDetector)
    rule = sigma_detector.SigmaRule(
        rule_id="T-OP", name="op-contract", description="contract pin",
        severity="high", attack_type="test", confidence="high",
        action_recommend="alert", conditions={})
    rule.aggregation = {"func": "count", "field": "src_ip", "op": op,
                        "threshold": threshold, "timeframe": "5m"}
    det._agg_windows = {"T-OP": {"g": deque()}}
    det._parse_timeframe = lambda tf: 300
    import time as _t
    # _check_aggregation 会先 append 当前事件再计数 —— 预填 count-1 条
    now = _t.time()
    det._agg_windows["T-OP"]["g"] = deque((now, 1) for _ in range(count - 1))
    return det._check_aggregation(rule, {"src_ip": "g"})


def test_python_side_contract_matches_java_threshold_met():
    """逐 op 对齐 Java thresholdMet 的四分支(default 含在内)。"""
    # '>' 严格大于: 第 threshold 条不告, 第 threshold+1 条告
    assert _met(">", 5, 5) is False
    assert _met(">", 6, 5) is True
    # '>=': 第 threshold 条即告
    assert _met(">=", 5, 5) is True
    assert _met(">=", 4, 5) is False
    # '==' 与 '=' 等价
    assert _met("==", 5, 5) is True
    assert _met("==", 6, 5) is False
    assert _met("=", 5, 5) is True
    # 未知 op → '>='(与 Java default 一致 —— 修复前 Python 是 '>')
    assert _met("<", 5, 5) is True      # default >= → 5>=5 True
    assert _met("<=", 4, 5) is False    # default >= → 4>=5 False
    assert _met("gt", 5, 5) is True
    # 空 op → '>='
    assert _met("", 5, 5) is True


def test_java_threshold_met_source_contract_unmodified():
    """静态契约核对: Java 侧 default 分支仍是 '>=' 且含 '=' 分支。

    防止未来单侧改动再次引入分歧 —— 双侧契约文本各自的关键行都在场。
    """
    java = (Path(__file__).resolve().parent.parent.parent
            / "flink-jobs" / "src" / "main" / "java" / "com" / "soc" / "job"
            / "SigmaThresholdAggregationJob.java").read_text(encoding="utf-8")
    m = re.search(
        r"static boolean thresholdMet.*?case \"<\":\s*break;", java, re.S)
    body = m.group(0) if m else java
    assert "case \">\":  return count > threshold;" in body
    assert "case \">=\": return count >= threshold;" in body
    assert 'case "=":  return count == threshold;' in body
    # default 回退必须与 Python 侧一致 '>='
    assert re.search(r"default:\s+return count >= threshold;", body)
