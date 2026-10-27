"""evaluate_rag.py — RAG 词法层检索质量评测(B5 路线 5)。

修掉的宣称缺口(2026-10-27): 旧"RAG 评估"(docs/rag-eval-2026-09-05.md)用
30 条自造语料 + 64 维模拟向量 + 未入库脚本 —— 不可复现, 数字不承重。

本评测器的诚实口径:
  - 语料与黄金集**提交入库**(fixtures/rag_corpus.jsonl 60 chunks +
    fixtures/rag_golden_queries.json 60 查询), 任何人在仓库根一条命令复现;
  - lexical 模式用平台**自己的** rag.lexical.tokenize 切词(评的就是平台
    真实词法层) + 标准 BM25 排序, 零网络/零 embedding API/确定性;
  - hybrid 模式需真实检索栈(PG+Qdrant+embedding 服务), 本环境不可用时
    退出码 3 并打印 runbook —— 不伪造数字;
  - 报告保留改前改后: 语料/查询集版本变化时旧结果 JSON 保留为 *-pre-*.json。

用法:
    python -m eval_datasets.evaluate_rag --out ../docs/benchmark
    python -m eval_datasets.evaluate_rag --mode hybrid   # 需真实检索栈
"""
from __future__ import annotations

import argparse
import collections
import json
import math
import sys
import time
from pathlib import Path

_K1 = 1.5
_B = 0.75
_TOP_K = 10


def load_corpus(path: Path) -> list[dict]:
    rows = []
    for ln in path.read_text(encoding="utf-8").splitlines():
        if ln.strip():
            rows.append(json.loads(ln))
    return rows


def load_golden(path: Path) -> list[dict]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return data["queries"]


def build_ranker(corpus: list[dict]):
    """BM25 索引: 用平台自己的 rag.lexical.tokenize 切词(评测对象就是它)。"""
    from rag.lexical import tokenize

    doc_tokens: list[list[str]] = []
    for c in corpus:
        # 标题记 2 遍(标题词权重), 内容 1 遍
        toks = tokenize(c["title"]) * 2 + tokenize(c["content"])
        doc_tokens.append(toks)
    n_docs = len(doc_tokens)
    avgdl = sum(len(t) for t in doc_tokens) / max(n_docs, 1)
    df: collections.Counter = collections.Counter()
    for toks in doc_tokens:
        df.update(set(toks))

    def score(query: str) -> list[tuple[str, float]]:
        q_tokens = tokenize(query)
        if not q_tokens:
            return []
        scores: list[tuple[str, float]] = []
        for c, toks in zip(corpus, doc_tokens):
            tf = collections.Counter(toks)
            s = 0.0
            for t in q_tokens:
                if t not in tf:
                    continue
                idf = math.log(1 + (n_docs - df[t] + 0.5) / (df[t] + 0.5))
                s += idf * tf[t] * (_K1 + 1) / (
                    tf[t] + _K1 * (1 - _B + _B * len(toks) / avgdl)
                )
            scores.append((c["id"], s))
        scores.sort(key=lambda x: (-x[1], x[0]))  # 确定性: 分数并列按 id
        return scores

    return score


def evaluate(corpus: list[dict], golden: list[dict], rank_fn) -> dict:
    corpus_ids = {c["id"] for c in corpus}
    per_query = []
    rr_sum = 0.0
    hit5 = hit10 = 0
    per_cat = collections.defaultdict(lambda: {"n": 0, "rr": 0.0, "hit5": 0, "hit10": 0})
    t0 = time.perf_counter()
    for q in golden:
        relevant = [rid for rid in q["relevant"] if rid in corpus_ids]
        ranked = [cid for cid, _ in rank_fn(q["query"])][: _TOP_K]
        first_rank = next(
            (i + 1 for i, cid in enumerate(ranked) if cid in relevant), None
        )
        rr = (1.0 / first_rank) if first_rank else 0.0
        r5 = any(cid in relevant for cid in ranked[:5])
        r10 = any(cid in relevant for cid in ranked[:10])
        rr_sum += rr
        hit5 += int(r5)
        hit10 += int(r10)
        cat = per_cat[q["category"]]
        cat["n"] += 1
        cat["rr"] += rr
        cat["hit5"] += int(r5)
        cat["hit10"] += int(r10)
        per_query.append({
            "id": q["id"], "query": q["query"], "category": q["category"],
            "mrr_rr": round(rr, 4), "top5_hit": r5, "ranked_top5": ranked[:5],
            "relevant": relevant,
        })
    n = len(golden) or 1
    elapsed = time.perf_counter() - t0
    return {
        "mode": "lexical_bm25",
        "corpus_n": len(corpus),
        "queries_n": len(golden),
        "mrr": round(rr_sum / n, 4),
        "recall_at_5": round(hit5 / n, 4),
        "recall_at_10": round(hit10 / n, 4),
        "elapsed_ms": round(elapsed * 1000, 1),
        "per_category": {
            cat: {
                "n": v["n"],
                "mrr": round(v["rr"] / v["n"], 4) if v["n"] else None,
                "recall_at_5": round(v["hit5"] / v["n"], 4) if v["n"] else None,
                "recall_at_10": round(v["hit10"] / v["n"], 4) if v["n"] else None,
            }
            for cat, v in sorted(per_cat.items())
        },
        "queries": per_query,
    }


def render_markdown(res: dict, note_lines: list[str]) -> str:
    lines = [
        "# RAG 检索质量评测 — 词法层基线(可复现)", "",
        f"- 语料: {res['corpus_n']} chunks (fixtures/rag_corpus.jsonl, 提交入库)",
        f"- 黄金集: {res['queries_n']} 条查询 (fixtures/rag_golden_queries.json, 四类意图)",
        f"- 排序器: 平台 rag.lexical.tokenize + BM25(k1=1.5,b=0.75), 确定性",
        f"- 指标: **MRR={res['mrr']}** / recall@5={res['recall_at_5']} /"
        f" recall@10={res['recall_at_10']} ({res['elapsed_ms']}ms)",
        "",
        "> 口径声明: 本报告评的是**词法召回层**的可复现基线 —— hybrid/embedding",
        "> 模式复用同一黄金集, 需真实检索栈(PG+Qdrant+embedding 服务), 运行命令",
        "> 见文末。数字变化 = 语料/查询集/排序器之一变化, 三者全部版本化入库。",
        ">",
        "> 诚实定性: 60-doc 语料上的高 MRR 是**回归基线语义**(钉住切词/索引",
        "> 不回归), 不是检索能力上限 —— 与旧评估 30 条自造语料 MRR=100 的区别",
        "> 在于: 本基线可复现、可对账、失败样本逐条列出, 且明确不是能力声明。",
        "",
        "## 分意图指标", "",
        "| 意图 | n | MRR | recall@5 | recall@10 |",
        "|---|---|---|---|---|",
    ]
    for cat, v in res["per_category"].items():
        lines.append(f"| {cat} | {v['n']} | {v['mrr']} | {v['recall_at_5']} | {v['recall_at_10']} |")
    failed = [q for q in res["queries"] if not q["top5_hit"]]
    lines += ["", f"## top5 未命中({len(failed)} 条 — 改语料/改切词的依据)", "",
              "| 查询 | 相关 chunk | top5 实际 |", "|---|---|---|"]
    for q in failed[:15]:
        lines.append(f"| {q['id']}: {q['query']} | {','.join(q['relevant'])} | {','.join(q['ranked_top5'])} |")
    lines += ["", "## 复现与升级路径", ""] + note_lines
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--corpus", default=str(Path(__file__).parent / "fixtures" / "rag_corpus.jsonl"))
    ap.add_argument("--golden", default=str(Path(__file__).parent / "fixtures" / "rag_golden_queries.json"))
    ap.add_argument("--out", default="", help="写 RAG-EVAL.{md,-result.json} 的目录")
    ap.add_argument("--mode", default="lexical", choices=["lexical", "hybrid"])
    args = ap.parse_args()

    if args.mode == "hybrid":
        # 诚实失败: 真实检索栈不可用时明说, 不退化为模拟向量伪造数字
        # (旧评估的教训: 64 维模拟向量产出的 MRR=100 是过拟合噪声)。
        print(
            "[hybrid] 需要真实检索栈(PG+Qdrant+embedding 服务)。\n"
            "runbook: 1) docker compose up -d  2) 导入 rag_corpus.jsonl 入 knowledge_base\n"
            "         3) 以 rag.retriever 实跑本黄金集 —— 评测器接口不变。",
            file=sys.stderr,
        )
        return 3

    corpus = load_corpus(Path(args.corpus))
    golden = load_golden(Path(args.golden))
    ids = [c["id"] for c in corpus]
    if len(ids) != len(set(ids)):
        print("语料 id 重复", file=sys.stderr)
        return 2
    missing = {rid for q in golden for rid in q["relevant"]} - set(ids)
    if missing:
        print(f"黄金集引用了不存在的 chunk: {sorted(missing)}", file=sys.stderr)
        return 2

    rank_fn = build_ranker(corpus)
    res = evaluate(corpus, golden, rank_fn)
    notes = [
        "- 复现: `python -m eval_datasets.evaluate_rag --out ../docs/benchmark`",
        "- 升级 hybrid: 按上 runbook 起真实栈后 `--mode hybrid` 并保留 lexical 结果对照",
        "- 改语料/查询集必须: 更新 fixtures 版本号 + 旧结果存 *-pre-*.json + 本报告重跑",
    ]
    md = render_markdown(res, notes)
    if args.out:
        out = Path(args.out)
        out.mkdir(parents=True, exist_ok=True)
        (out / "RAG-EVAL-result.json").write_text(
            json.dumps(res, ensure_ascii=False, indent=2), encoding="utf-8")
        (out / "RAG-EVAL.md").write_text(md, encoding="utf-8")
        print(f"报告已写 {out}/RAG-EVAL.{{md,-result.json}}")
    print(json.dumps({k: v for k, v in res.items() if k != "queries"}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
