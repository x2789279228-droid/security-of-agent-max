# -*- coding: utf-8 -*-
"""路线 5(2026-10-27)回归: RAG 评测可复现性守卫。

旧"RAG 评估"的教训: 30 条自造语料 + 64 维模拟向量 + 脚本未入库 = 不可复现。
本守卫钉住: 语料/黄金集完整性、评测确定性、指标回归底线、hybrid 诚实失败。
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

os.environ.setdefault("SHARED_MEMORY_SKIP_DOTENV", "1")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from eval_datasets import evaluate_rag as er  # noqa: E402

FIXTURES = Path(er.__file__).parent / "fixtures"
CORPUS = er.load_corpus(FIXTURES / "rag_corpus.jsonl")
GOLDEN = er.load_golden(FIXTURES / "rag_golden_queries.json")


def test_corpus_and_golden_integrity():
    ids = [c["id"] for c in CORPUS]
    assert len(CORPUS) >= 55, "语料缩水 —— 检索基线覆盖面下降, 需重估"
    assert len(ids) == len(set(ids)), "语料 id 重复"
    assert len(GOLDEN) >= 50, "黄金查询少于 50 条 —— 不可复现宣称修不回来"
    valid_cat = {"technique", "mitigation", "platform", "intel", "ops"}
    missing = {r for q in GOLDEN for r in q["relevant"]} - set(ids)
    assert not missing, f"黄金集引用不存在的 chunk: {sorted(missing)}"
    cats = {q["category"] for q in GOLDEN}
    assert cats <= valid_cat, f"非法意图分类: {cats - valid_cat}"
    # 语料分类均衡性: 技术面与缓解面都不能是空壳
    corpus_cats = {c["category"] for c in CORPUS}
    assert {"technique", "mitigation", "platform", "intel", "ops"} <= corpus_cats


def test_evaluation_deterministic_and_above_floor(tmp_path):
    rank1 = er.build_ranker(CORPUS)
    rank2 = er.build_ranker(CORPUS)
    res1 = er.evaluate(CORPUS, GOLDEN, rank1)
    res2 = er.evaluate(CORPUS, GOLDEN, rank2)
    # 确定性: 同输入同数字(排序并列按 id 破平)
    for k in ("mrr", "recall_at_5", "recall_at_10"):
        assert res1[k] == res2[k], f"评测器不确定: {k} 两轮不等"
    # 回归底线: 词法层在已版本化语料上的性能门槛
    assert res1["mrr"] >= 0.85, f"MRR 跌破 0.85({res1['mrr']}) —— 切词或排序回归"
    assert res1["recall_at_5"] >= 0.9, (
        f"recall@5 跌破 0.9({res1['recall_at_5']}) —— 查询集或语料被改坏"
    )
    # 端到端落盘
    out = tmp_path / "rag"
    rc = er.main.__wrapped__ if hasattr(er.main, "__wrapped__") else None
    sys_argv = ["prog", "--corpus", str(FIXTURES / "rag_corpus.jsonl"),
                "--golden", str(FIXTURES / "rag_golden_queries.json"),
                "--out", str(out)]
    old = sys.argv
    sys.argv = sys_argv
    try:
        assert er.main() == 0
    finally:
        sys.argv = old
    report = json.loads((out / "RAG-EVAL-result.json").read_text(encoding="utf-8"))
    assert report["mrr"] == res1["mrr"]
    md = (out / "RAG-EVAL.md").read_text(encoding="utf-8")
    assert "回归基线语义" in md, "报告必须保留诚实定性声明"


def test_hybrid_mode_fails_honestly(tmp_path, capsys):
    """无真实检索栈时 hybrid 必须退出码 3 明说, 绝不伪造数字。"""
    old = sys.argv
    sys.argv = ["prog", "--mode", "hybrid", "--out", str(tmp_path)]
    try:
        rc = er.main()
    finally:
        sys.argv = old
    assert rc == 3
    err = capsys.readouterr().err
    # R11: 文案升级为如实口径 —— "未实现"(预留扩展位), 不再暗示"起了真实栈就能跑"
    assert "未实现" in err
    assert "需要真实检索栈" not in err
