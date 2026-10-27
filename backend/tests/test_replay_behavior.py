# -*- coding: utf-8 -*-
"""路线 6(2026-10-27)回归: 行为层公开数据集回放(registry + 适配器 + 阈值扫描)。

钉住四件事:
  1. 适配器解析(CIC 列映射 / CTU Background 排除);
  2. CIC fixture 的可行区间非空且含默认阈值 0.60(检出语义活了);
  3. 扫描单调性(阈值升 → TPR/FPR 不升);
  4. CTU 信标 fixture 的诚实结果: 实体相对基线对"首见实体的稳态信标"
     结构性失明 —— known_gap 登记, 需补 beacon 周期性/全局频率维度。
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

os.environ.setdefault("SHARED_MEMORY_SKIP_DOTENV", "1")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from eval_datasets import replay_behavior_public as rb  # noqa: E402

FIXTURES = Path(rb.__file__).parent / "fixtures"


def test_registry_and_adapters_parse():
    assert set(rb.DATASETS) == {"cicids2017", "ctu13"}
    cic = rb.load_cicids2017(FIXTURES / "cicids2017_sample.csv")
    assert all(e["event_id"].startswith("cic-") for e in cic), "event_id 缺失 = 基线被幂等吞掉"
    mal = [e for e in cic if e["_label"] == "malicious"]
    assert len(mal) == 20 and all(e["_family"] == "SSH-PATATOR" for e in mal)
    ctu = rb.load_ctu13(FIXTURES / "ctu13_sample.binetflow.csv")
    assert all(not e["src_ip"].startswith("Background") for e in ctu)
    assert sum(1 for e in ctu if e["_label"] == "malicious") == 30
    assert all(e["event_id"].startswith("ctu-") for e in ctu)


def test_cic_fixture_feasible_interval_contains_default():
    res = rb.run_dataset("cicids2017", FIXTURES / "cicids2017_sample.csv")
    assert res["feasible_interval"]["thresholds"], "可行区间为空 = 检出语义断了"
    assert min(res["feasible_interval"]["thresholds"]) <= 0.60 <= max(
        res["feasible_interval"]["thresholds"]), "默认阈值 0.60 必须落在可行区间内"
    at_default = next(p for p in res["per_threshold"] if p["threshold"] == 0.60)
    assert at_default["tpr"] >= 0.6 and at_default["fpr"] <= 0.05
    # 攻击分数整体高于良性(可分性)
    assert res["per_threshold"][-1]["tp"] == 0 or res["per_threshold"][0]["tp"] >= res["per_threshold"][-1]["tp"]


def test_sweep_monotonicity():
    res = rb.run_dataset("cicids2017", FIXTURES / "cicids2017_sample.csv")
    tprs = [p["tpr"] for p in res["per_threshold"]]
    fprs = [p["fpr"] for p in res["per_threshold"]]
    assert all(tprs[i] >= tprs[i + 1] for i in range(len(tprs) - 1)), "TPR 随阈值升不升 = 口径坏了"
    assert all(fprs[i] >= fprs[i + 1] for i in range(len(fprs) - 1)), "FPR 随阈值升不降 = 口径坏了"


def test_ctu_beacon_gap_is_registered_honestly(tmp_path):
    """首见实体的稳态信标: 实体相对基线的结构性盲区 —— 必须显式登记,
    不允许为了绿数字去调 fixture。"""
    res = rb.run_dataset("ctu13", FIXTURES / "ctu13_sample.binetflow.csv")
    assert res["feasible_interval"]["thresholds"] == []
    assert "缺口" in res["feasible_interval"]["conclusion"]
    md = rb.render_markdown(res)
    assert "流级口径" in md and "runbook" in md
    sys_argv = ["prog", "--dataset", "ctu13", "--out", str(tmp_path)]
    old = sys.argv
    sys.argv = sys_argv
    try:
        assert rb.main() == 0
    finally:
        sys.argv = old
    assert (tmp_path / "REPLAY-BEHAVIOR-ctu13-result.json").exists()
