# -*- coding: utf-8 -*-
"""R11: hybrid 评测宣称与代码现实一致 (P1-5)。

修复前: 文档(EXTERNAL-INTEL-UPGRADE §2)把 `--mode hybrid` 列为"用户环境 AC",
CLI 文案暗示"起了真实栈就能跑" —— 实际代码没有任何 hybrid 实现分支, 无条件
退出码 3。AC 在代码上不可达成。

2026-11-09 阶段4C: hybrid 已实现为真栈实跑(rag.retriever 实查黄金集)。
锁定口径随之升级: 栈未就绪 → 退出码 4 + runbook(不伪造数字),
lexical 主路径不受影响, 文档 R5 与 CLI 现实一致。
"""
from __future__ import annotations

import os
import sys

import pytest

os.environ.setdefault("SHARED_MEMORY_SKIP_DOTENV", "1")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

MOD = "eval_datasets.evaluate_rag"


def test_hybrid_branch_requires_real_stack(capsys):
    import importlib

    mod = importlib.import_module(MOD)
    rc = mod.main(["--mode", "hybrid"])
    # 测试环境无 Qdrant/embedding 真实栈 → 预检拒绝, 退出码 4
    assert rc == 4
    err = capsys.readouterr().err
    assert "未就绪" in err or "未配置" in err, f"hybrid 文案必须如实说明栈缺失: {err!r}"
    assert "runbook" in err.lower(), "必须给出起栈路径"


def test_lexical_mode_still_runs():
    """词法层主路径不受影响 — 评测真实产出指标。"""
    import importlib

    mod = importlib.import_module(MOD)
    rc = mod.main([])  # 默认 --mode lexical, fixture 语料
    assert rc == 0


def test_doc_claim_matches_cli():
    """文档 AC 描述与 hybrid 实现状态一致(2026-11-09: 已实现真栈实跑)。"""
    import io
    import pathlib

    doc = pathlib.Path(__file__).resolve().parents[2] / (
        "docs/upgrade/EXTERNAL-INTEL-UPGRADE-2026-10-27.md")
    src = io.open(doc, encoding="utf-8").read()
    r5_rows = [ln for ln in src.splitlines() if "R5 ATT&CK+RAG" in ln]
    assert r5_rows, "文档中找不到 R5 行"
    assert any("已实现" in ln for ln in r5_rows), \
        "R5 的 AC 必须与 hybrid 已实现的现实一致"
