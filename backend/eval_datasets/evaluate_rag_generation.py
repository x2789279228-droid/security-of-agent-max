"""evaluate_rag_generation.py — RAG 生成侧忠实度评测(2026-11-09 阶段4C)。

补掉的宣称缺口: 词法层 RAG-EVAL 只评检索(MRR/recall), **检索增强是否提升
生成质量**此前无任何生成侧证据。本评测器把"检索→生成→忠实度打分"整链路
拉通出真实数字:

  1. 检索: 复用 evaluate_rag 的 BM25 ranker(平台 rag.lexical.tokenize)取 top5 证据
  2. 生成: 平台 LLMClient(真实网关) 按与 Copilot 同风格的"仅凭证据作答"提示词回答
  3. 打分: 复用 faithfulness_gate.compute_faithfulness(生产同款断言-证据比对,
     含编造实体/无证据主张/结论相反三类失败拆解) —— 评的就是线上同一套闸

诚实口径:
  - 需要 LLM API key(与生产同一把); 无 key → 退出码 4, 不伪造数字
  - 指标: faithfulness 均值 / abstain 率(证据不足时应当拒答) / 失败类型分布
  - 语料/黄金集与 RAG-EVAL 同源, fingerprint 入报告
  - 检索层用 BM25(与 lexical 基线同层): 本评测回答的是"生成是否忠实于检索",
    hybrid 栈另见 evaluate_rag --mode hybrid

用法:
    python -m eval_datasets.evaluate_rag_generation --limit 20 --out ../docs/benchmark
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import re
import sys
from pathlib import Path

_ABSTAIN_RE = re.compile(r"无法(根据|基于|从).{0,6}(证据|资料|文档)|证据不足|未提供足够|不能确定")
_TOP_K = 5


def _llm_client():
    from summary_compression import LLMClient
    return LLMClient()


async def _answer_one(llm, query: str, evidence_texts: list[str]) -> str:
    """仅凭证据作答 —— system prompt 入库模板(prompts 守卫口径)。"""
    from prompts import render
    evidence_block = "\n\n".join(
        f"[证据{i + 1}] {t[:800]}" for i, t in enumerate(evidence_texts)
    )
    system = render("rag_eval_answer_system").strip()
    user = f"证据:\n{evidence_block}\n\n问题: {query}"
    return await llm.chat(
        [{"role": "system", "content": system}, {"role": "user", "content": user}],
        temperature=0.1,
    )


def evaluate_generation(corpus, golden, limit, llm) -> dict:
    import asyncio
    from eval_datasets.evaluate_rag import build_ranker
    from faithfulness_gate import compute_faithfulness

    rank_fn = build_ranker(corpus)
    by_id = {c["id"]: c for c in corpus}

    rows = []
    abstain_n = 0
    faith_sum = 0.0
    failure_totals = {"invalid_reference": 0, "unsupported_claim": 0, "wrong_conclusion": 0}
    for q in golden[:limit]:
        ranked = [cid for cid, _ in rank_fn(q["query"])][:_TOP_K]
        evidence_texts = [f"{by_id[cid]['title']}。{by_id[cid]['content']}" for cid in ranked]
        answer = asyncio.run(_answer_one(llm, q["query"], evidence_texts))
        is_abstain = bool(_ABSTAIN_RE.search(answer or ""))
        abstain_n += int(is_abstain)
        verdict = compute_faithfulness(
            answer,
            [{"content": t} for t in evidence_texts],
            query=q["query"],
        )
        faith_sum += verdict["faithfulness"]
        for k in failure_totals:
            failure_totals[k] += int((verdict.get("failure_breakdown") or {}).get(k, 0))
        rows.append({
            "id": q["id"], "query": q["query"], "category": q["category"],
            "answer": (answer or "")[:300],
            "abstain": is_abstain,
            "faithfulness": round(verdict["faithfulness"], 4),
            "claim_count": verdict["claim_count"],
            "unsupported_count": verdict["unsupported_count"],
            "evidence_ids": ranked,
        })

    n = len(rows) or 1
    return {
        "mode": "generation_faithfulness",
        "retrieval": "bm25_top5(与 lexical 基线同层)",
        "queries_n": len(rows),
        "faithfulness_mean": round(faith_sum / n, 4),
        "abstain_rate": round(abstain_n / n, 4),
        "failure_totals": failure_totals,
        "llm_model": getattr(llm, "model", ""),
        "queries": rows,
    }


def render_markdown(res: dict) -> str:
    lines = [
        "# RAG 生成侧忠实度评测 — 检索增强是否让生成可信", "",
        f"- 查询数: {res['queries_n']}(黄金集前 N, 同 RAG-EVAL 语料)",
        f"- 链路: BM25 top5 证据 → 平台 LLMClient({res['llm_model']}) 仅凭证据作答"
        f" → faithfulness_gate.compute_faithfulness(生产同款闸)",
        f"- 指标: **faithfulness={res['faithfulness_mean']}** /"
        f" abstain 率={res['abstain_rate']} /"
        f" 失败分布={res['failure_totals']}",
        "",
        "> 口径: 评的是「生成是否忠实于检索到的证据」—— 编造实体/无证据主张/",
        "> 结论相反由 faithfulness_gate 逐断言判定(与线上 Copilot 同一实现)。",
        "> abstain 是**正确行为**的证据: 黄金集含证据不足类问题时, 高 abstain",
        "> 率+高 faithfulness = 系统不编造。LLM 换代/提示词变化都须重跑本评测。",
        "",
        "## 逐查询明细(top 20)", "",
        "| 查询 | abstain | faithfulness | 无证据主张 | 回答摘录 |",
        "|---|---|---|---|---|",
    ]
    for r in res["queries"][:20]:
        snippet = (r["answer"] or "").replace("|", "\\|").replace("\n", " ")[:60]
        lines.append(
            f"| {r['id']}: {r['query'][:28]} | {r['abstain']} | {r['faithfulness']}"
            f" | {r['unsupported_count']} | {snippet} |"
        )
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--corpus", default=str(Path(__file__).parent / "fixtures" / "rag_corpus.jsonl"))
    ap.add_argument("--golden", default=str(Path(__file__).parent / "fixtures" / "rag_golden_queries.json"))
    ap.add_argument("--limit", type=int, default=20, help="评测查询数(控制 LLM 成本)")
    ap.add_argument("--out", default="")
    args = ap.parse_args(argv)

    from config import settings
    if not settings.llm_api_key:
        print("[gen-eval] 需要 LLM API key(SHARED_MEMORY_LLM_API_KEY) — 不伪造数字", file=sys.stderr)
        return 4

    from eval_datasets.evaluate_rag import load_corpus, load_golden
    corpus = load_corpus(Path(args.corpus))
    golden = load_golden(Path(args.golden))

    llm = _llm_client()
    res = evaluate_generation(corpus, golden, args.limit, llm)

    def _fp(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()[:12]
    res["version"] = {
        "evaluated_at": datetime.date.today().isoformat(),
        "corpus_fingerprint": _fp(Path(args.corpus)),
        "golden_fingerprint": _fp(Path(args.golden)),
        "evaluator": "generation_faithfulness_v1",
    }

    if args.out:
        out = Path(args.out)
        out.mkdir(parents=True, exist_ok=True)
        (out / "RAG-GEN-EVAL-result.json").write_text(
            json.dumps(res, ensure_ascii=False, indent=2), encoding="utf-8")
        (out / "RAG-GEN-EVAL.md").write_text(render_markdown(res), encoding="utf-8")
        print(f"报告已写 {out}/RAG-GEN-EVAL.{{md,-result.json}}")
    print(json.dumps({k: v for k, v in res.items() if k != "queries"}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
