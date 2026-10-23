# -*- coding: utf-8 -*-
"""反弱化门禁对**未跟踪测试文件**的覆盖（整改报告 §9.65 / §9.41 盲区）。

## 背景

整改方案 §十三「全量回归」行把验收标准写成：

> 全量测试通过，并且原有测试没有通过删除断言或放宽安全要求来人为变绿。

`tools/assert-no-assert-weakening.py` 负责判这后半句，但它的比对来源是
`git diff --name-only <base>` —— **只列已跟踪文件**。未跟踪的新测试文件
没有 git 基线可比 → 它们的断言若被削弱，CI 照样绿。

实测规模（2026-10-20）：**123 个未跟踪测试文件、3942 条断言**全在射程之外。

## 本轮做法

* `tools/guard_assert_baseline.json` 记每个未跟踪测试文件的
  **断言清单 sha256** + 断言条数；
* 门禁比对：断言**变了** → 报 `UNTRACKED_CHANGED` 并**判红**（人工核对）；
* `--update-baseline` 重新生成基线。

⚠ 诚实的边界：基线只有摘要，**判不出「弱化」，只能报「变了」**。
与已跟踪路径的自动判定不等价，但至少**从「不可见」变成「必须被看见」**。
"""
from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

BACKEND = Path(__file__).resolve().parent.parent
REPO = BACKEND.parent
TOOL = REPO / "tools" / "assert-no-assert-weakening.py"
BASELINE = REPO / "tools" / "guard_assert_baseline.json"


def _load_gate():
    """按路径加载门禁（文件名带连字符，不能按模块名 import）。"""
    spec = importlib.util.spec_from_file_location(
        "assert_no_weakening_gate", TOOL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def gate():
    return _load_gate()


class TestTheGateItself:
    def test_the_classifier_selfcheck_passes(self, gate):
        """门禁的**自检**必须通过（否则它给出的任何结论都不可信）。"""
        problems = gate.selfcheck()
        assert not problems, problems

    def test_the_gate_runs_and_reaches_a_conclusion(self):
        """跑一次门禁：要么给结论（0/1），要么明确「本次没有结论」（2）。

        绝不能是「崩溃却看起来像通过」。
        """
        r = subprocess.run(
            [sys.executable, str(TOOL), "--repo", str(REPO)],
            cwd=str(REPO), capture_output=True, text=True,
            timeout=300, encoding="utf-8", errors="replace")
        assert r.returncode in (0, 1), (
            f"门禁退出码 {r.returncode}（2 = 本次没有结论，"
            f"其它 = 崩溃）：\n{r.stdout[-1500:]}\n{r.stderr[-800:]}")


class TestTheBaseline:
    def test_the_baseline_file_exists_and_is_valid(self):
        assert BASELINE.exists(), (
            f"缺少断言基线 {BASELINE.name} —— 未跟踪测试文件的断言变更就没人管")
        data = json.loads(BASELINE.read_text(encoding="utf-8"))
        assert isinstance(data, dict) and data, "基线为空或格式不对"
        for rel, rec in list(data.items())[:5]:
            assert isinstance(rec, dict), rel
            assert len(str(rec.get("sha256", ""))) == 64, rel
            assert isinstance(rec.get("asserts"), int), rel

    def test_the_baseline_covers_the_untracked_test_files(self, gate):
        """每个**有断言**的未跟踪测试文件都必须在基线里。

        新建守卫文件后本条会红 —— 那是**有意的**：基线必须被显式更新，
        而不是悄悄失效。
        """
        untracked = gate._untracked_test_files(REPO)
        assert untracked is not None, "无法枚举未跟踪测试文件"
        baseline = gate.load_baseline(str(BASELINE))
        assert baseline is not None, "基线读不到"
        missing = []
        for rel in untracked:
            rec = baseline.get(rel)
            if rec is None:
                missing.append(rel)
        assert not missing, (
            "这些未跟踪测试文件**不在基线里**（它们的断言变更将无人管）：\n  "
            + "\n  ".join(missing[:15])
            + "\n  → 跑 `python tools/assert-no-assert-weakening.py --update-baseline`")

    def test_the_current_tree_matches_the_baseline(self, gate):
        """当前工作区必须与基线一致（断言一改就会红 → 强制复核）。"""
        untracked = gate._untracked_test_files(REPO)
        baseline = gate.load_baseline(str(BASELINE))
        changed, _not_in, _detail, _total = gate.compare_untracked_asserts(
            str(REPO), untracked, baseline)
        assert not changed, (
            "这些未跟踪测试文件的断言已变更（未跟踪文件没有 git 基线可比，"
            "门禁只能报「变了」而判不了「弱化了」）：\n  "
            + "\n  ".join(f"{rel}  {before} → {now} 条" for rel, now, before in changed[:15])
            + "\n  → 人工核对后跑 `python tools/assert-no-assert-weakening.py --update-baseline`")


class TestTheChangeDetection:
    """**决定性**：断言变更必须被抓到；只改注释**不得**误报。"""

    def test_an_assertion_change_is_detected(self, gate, tmp_path):
        target = tmp_path / "test_demo.py"
        strong = "def t():\n    assert x == 1\n"
        weak = "def t():\n    assert x is not None\n"
        target.write_text(strong, encoding="utf-8")
        baseline = {"test_demo.py": {
            "sha256": gate.assert_digest(strong), "asserts": 1}}
        changed, not_in, detail, total = gate.compare_untracked_asserts(
            str(tmp_path), ["test_demo.py"], baseline)
        assert changed == [], "未改动却被判成变更 —— 判据坏了"
        # 把强断言换成弱断言
        target.write_text(weak, encoding="utf-8")
        changed, not_in, detail, total = gate.compare_untracked_asserts(
            str(tmp_path), ["test_demo.py"], baseline)
        assert changed, "断言被改弱却没被抓到 —— 门禁的覆盖仍然有洞"
        assert changed[0][0] == "test_demo.py"
        assert changed[0][2] == 1, changed

    def test_a_comment_only_change_is_not_flagged(self, gate, tmp_path):
        """只改注释**不得**触发复核（否则每次改注释都要走一遍基线更新）。"""
        target = tmp_path / "test_demo.py"
        plain = "def t():\n    assert x == 1\n"
        commented = "def t():\n    # 说明：x 应当等于 1\n    assert x == 1\n"
        target.write_text(plain, encoding="utf-8")
        baseline = {"test_demo.py": {
            "sha256": gate.assert_digest(plain), "asserts": 1}}
        target.write_text(commented, encoding="utf-8")
        changed, _n, _d, _t = gate.compare_untracked_asserts(
            str(tmp_path), ["test_demo.py"], baseline)
        assert changed == [], "只改注释被判成断言变更 —— 假阳性会让人忽略这个门禁"

    def test_a_new_file_is_reported_as_not_in_the_baseline(self, gate, tmp_path):
        """基线里没有的新文件 → 报「未纳入基线」，**不**报「变更」。"""
        target = tmp_path / "test_new.py"
        target.write_text("def t():\n    assert x == 1\n", encoding="utf-8")
        changed, not_in, _d, _t = gate.compare_untracked_asserts(
            str(tmp_path), ["test_new.py"], {})
        assert changed == [], changed
        assert [r for r, _n in not_in] == ["test_new.py"], not_in


if __name__ == "__main__":       # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
