# -*- coding: utf-8 -*-
"""路线 1(2026-10-27)回归: Atomic 覆盖对账器 + runner 安全闸。

钉住四件事:
  1. 对账匹配口径(技术强证据 / 主机+时间窗兜底 / 窗外不算);
  2. 漏检必须能被表达(AC: 漏检 run 100% 登记);
  3. runner 三道安全闸(plan 默认 / --execute-local / VM 自我声明 + 生产标记);
  4. remote 模式只生成脚本不执行。
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

os.environ.setdefault("SHARED_MEMORY_SKIP_DOTENV", "1")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "tools"))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import atomic_runner as runner  # noqa: E402
from eval_datasets import evaluate_attack_coverage as cov  # noqa: E402

FIXTURES = Path(cov.__file__).parent / "fixtures"
ROOT = Path(__file__).resolve().parent.parent.parent


def test_coverage_fixture_match_kinds_and_missed(tmp_path):
    gt = cov.load_ground_truth(FIXTURES / "atomic_ground_truth.jsonl")
    alerts = json.loads((FIXTURES / "atomic_alerts_export.json").read_text(encoding="utf-8"))
    res = cov.evaluate(gt, alerts)
    assert res["runs_n"] == 7
    assert res["techniques_detected"] == 6, "T1505 fixture run 必须是漏检样例"
    assert res["missed"] == ["run-7-T1505"]
    assert res["coverage"] == round(6 / 7, 4)
    # 强证据/兜底分开可辨
    kinds = {t: set(v["match_kinds"]) for t, v in res["per_technique"].items()}
    assert "technique" in kinds["T1059"] and "host+window" in kinds["T1059"]
    assert "host+window" in kinds["T1046"], "无技术标签的告警走主机+窗口兜底"
    # 漏检语义: 无技术命中且无窗口重叠(T1505 在任何告警里都没出现)
    md = cov.render_markdown(res, "fixture")
    assert "❌ T1505" in md and "自欺" in md  # 诚实口径声明在报告里
    # 端到端落盘
    sys.argv = ["prog", "--ground-truth", str(FIXTURES / "atomic_ground_truth.jsonl"),
                "--alerts", str(FIXTURES / "atomic_alerts_export.json"),
                "--out", str(tmp_path)]
    assert cov.main() == 0
    assert (tmp_path / "ATTACK-COVERAGE-result.json").exists()


def test_runner_plan_mode_is_inert(tmp_path, capsys):
    manifest = ROOT / "tools" / "atomic" / "manifest.json"
    sys.argv = ["prog", "--manifest", str(manifest), "--mode", "plan",
                "--out", str(tmp_path)]
    assert runner.main() == 0
    out = capsys.readouterr().out
    assert "plan 模式不执行" in out
    assert list(tmp_path.iterdir()) == [], "plan 模式不得产出任何执行痕迹"


def test_runner_local_requires_explicit_consent(tmp_path, monkeypatch):
    manifest = ROOT / "tools" / "atomic" / "manifest.json"
    # 闸 1: 缺 --execute-local
    sys.argv = ["prog", "--manifest", str(manifest), "--mode", "local",
                "--out", str(tmp_path)]
    assert runner.main() == 4
    # 闸 2: 有 --execute-local 但缺 VM 自我声明
    monkeypatch.delenv(runner._VM_MARKER_ENV, raising=False)
    sys.argv = ["prog", "--manifest", str(manifest), "--mode", "local",
                "--execute-local", "--out", str(tmp_path)]
    assert runner.main() == 4


def test_runner_remote_generates_script_only(tmp_path, capsys):
    manifest = ROOT / "tools" / "atomic" / "manifest.json"
    sys.argv = ["prog", "--manifest", str(manifest), "--mode", "remote",
                "--out", str(tmp_path)]
    assert runner.main() == 0
    ps1 = tmp_path / "invoke-atomics.ps1"
    text = ps1.read_text(encoding="utf-8-sig")
    assert "Invoke-AtomicTest" in text, "remote 产物必须是官方模块调用"
    assert "仅在测试虚机执行" in text
    # remote 模式不得直接执行: 产物里没有本地 subprocess/Start-Process cmd 直跑
    assert "ground-truth.jsonl" in text
