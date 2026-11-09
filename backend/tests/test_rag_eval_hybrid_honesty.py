# -*- coding: utf-8 -*-
"""R11: hybrid 评测宣称与代码现实一致 (P1-5)。

修复前: 文档(EXTERNAL-INTEL-UPGRADE §2)把 `--mode hybrid` 列为"用户环境 AC",
CLI 文案暗示"起了真实栈就能跑" —— 实际代码没有任何 hybrid 实现分支, 无条件
退出码 3。AC 在代码上不可达成。

锁定: hybrid 分支存在且如实输出"未实现"(不再误导), lexical 主路径不受影响。
"""
from __future__ import annotations

import os
import sys

import pytest

os.environ.setdefault("SHARED_MEMORY_SKIP_DOTENV", "1")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

MOD = "eval_datasets.evaluate_rag"


def test_hybrid_branch_reports_unimplemented(capsys):
    import importlib

    mod = importlib.import_module(MOD)
    rc = mod.main(["--mode", "hybrid"])
    assert rc == 3
    err = capsys.readouterr().err
    assert "未实现" in err, f"hybrid 文案必须如实声明未实现: {err!r}"
    assert "需要真实检索栈" not in err, "不得再暗示'起了栈就能跑'"


def test_lexical_mode_still_runs():
    """词法层主路径不受影响 — 评测真实产出指标。"""
    import importlib

    mod = importlib.import_module(MOD)
    rc = mod.main([])  # 默认 --mode lexical, fixture 语料
    assert rc == 0


def test_doc_claim_matches_cli():
    """文档 AC 描述不得再把 --mode hybrid 写成可达成项。"""
    import io
    import pathlib

    doc = pathlib.Path(__file__).resolve().parents[2] / (
        "docs/upgrade/EXTERNAL-INTEL-UPGRADE-2026-10-27.md")
    src = io.open(doc, encoding="utf-8").read()
    # R5 行必须包含"尚未实现"口径
    r5_rows = [ln for ln in src.splitlines() if "R5 ATT&CK+RAG" in ln]
    assert r5_rows, "文档中找不到 R5 行"
    assert any("尚未实现" in ln for ln in r5_rows), \
        "R5 的 AC 必须如实标注 hybrid 未实现"
