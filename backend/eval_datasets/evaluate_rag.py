"""evaluate_rag.py — RAG 词法层检索质量评测(B5 路线 5)。

修掉的宣称缺口(2026-10-27): 旧"RAG 评估"(docs/rag-eval-2026-09-05.md)用
30 条自造语料 + 64 维模拟向量 + 未入库脚本 —— 不可复现, 数字不承重。

本评测器的诚实口径:
  - 语料与黄金集**提交入库**(fixtures/rag_corpus.jsonl 60 chunks +
    fixtures/rag_golden_queries.json 60 查询), 任何人在仓库根一条命令复现;
  - lexical 模式用平台**自己的** rag.lexical.tokenize 切词(评的就是平台
    真实词法层) + 标准 BM25 排序, 零网络/零 embedding API/确定性;
  - hybrid 模式是**预留扩展位, 尚未实现**(R11, 2026-10-29): 退出码 3 并
    如实说明 —— 不伪造数字, 也不宣称"起了真实栈就能跑";
  - 报告保留改前改后: 语料/查询集版本变化时旧结果 JSON 保留为 *-pre-*.json。

用法:
    python -m eval_datasets.evaluate_rag --out ../docs/benchmark
"""
from __future__ import annotations

import argparse
import collections
import json
import hashlib
import datetime
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
        "- 排序器: 平台 rag.lexical.tokenize + BM25(k1=1.5,b=0.75), 确定性",
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


async def _hybrid_rank_all(corpus: list[dict], golden: list[dict]) -> "dict[str, list[tuple[str, float]]]":
    """起真实栈跑混合检索: rag.retriever.Retriever(dense+BM25+RRF) 实查黄金集。

    返回 query→[(chunk_id, score)]; chunk_id 取检索结果的 chunk 编号或内容指纹
    (与 fixtures 语料 id 对齐的逻辑: 优先用 result 自带 id, 否则按标题精确匹配)。
    语料不在知识库时先经 KnowledgeBaseManager.add_document 自动入库(source 标记
    rag-eval-corpus, 幂等: 同名文档已存在则跳过)。
    """
    import asyncio

    from rag.knowledge_base import KnowledgeBaseManager
    from rag.retriever import Retriever
    from models import async_session

    title_to_id = {c["title"]: c["id"] for c in corpus}

    async with async_session() as session:
        kb = KnowledgeBaseManager()
        stats = await kb.get_stats(session)
        # 幂等入库: 每个 chunk 一篇文档(标题做去重键)
        existing = {d.get("title") for d in (await kb.search_documents(session, query="", limit=1000) or [])} \
            if stats.get("total_documents", 0) else set()
        for c in corpus:
            if c["title"] in existing:
                continue
            await kb.add_document(
                session,
                title=c["title"],
                content=c["content"],
                source="rag-eval-corpus",
                auto_approve=True,
            )
        await session.commit()

    retriever = Retriever()
    rankings: dict[str, list[tuple[str, float]]] = {}
    for q in golden:
        async with async_session() as session:
            result = await retriever.retrieve(
                session, query=q["query"], top_k=_TOP_K, skip_llm=True,
            )
        ranked: list[tuple[str, float]] = []
        for ch in result.chunks[:_TOP_K]:
            cid = str(ch.get("id") or ch.get("chunk_id") or "")
            if cid not in {c["id"] for c in corpus}:
                cid = title_to_id.get(str(ch.get("title") or ""), cid)
            ranked.append((cid, float(ch.get("score") or 0.0)))
        rankings[q["query"]] = ranked
        # 真实栈限速: 避免压垮 embedding 服务
        await asyncio.sleep(0.2)
    return rankings


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--corpus", default=str(Path(__file__).parent / "fixtures" / "rag_corpus.jsonl"))
    ap.add_argument("--golden", default=str(Path(__file__).parent / "fixtures" / "rag_golden_queries.json"))
    ap.add_argument("--out", default="", help="写 RAG-EVAL.{md,-result.json} 的目录")
    ap.add_argument("--mode", default="lexical", choices=["lexical", "hybrid"])
    args = ap.parse_args(argv)

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

    if args.mode == "hybrid":
        # 阶段4C(2026-11-09): hybrid 分支落地为真实现 —— 起真实栈
        # (PG+Qdrant+embedding)以 rag.retriever 实跑黄金集, 与 lexical 对照。
        # 前置任一不满足 → 退出码 4 + runbook, 不退化为模拟向量伪造数字。
        import asyncio
        import httpx
        from config import settings

        async def _qdrant_health(url: str) -> "str | None":
            try:
                async with httpx.AsyncClient(timeout=3) as hc:
                    r = await hc.get(url.rstrip("/") + "/healthz")
                    if r.status_code >= 400:
                        return f"Qdrant 健康检查失败: HTTP {r.status_code}"
                    return None
            except Exception as e:  # noqa: BLE001 — 不可达原因统一上报
                return f"Qdrant 不可达({url}): {type(e).__name__}"

        problems = []
        if not settings.qdrant_url:
            problems.append("SHARED_MEMORY_QDRANT_URL 未配置")
        else:
            err = asyncio.run(_qdrant_health(settings.qdrant_url))
            if err:
                problems.append(err)
        if not settings.embedding_api_key:
            problems.append("SHARED_MEMORY_EMBEDDING_API_KEY 未配置")
        if problems:
            print(
                "[hybrid] 真实栈未就绪, 不伪造数字。缺:\n  - " + "\n  - ".join(problems) +
                "\nrunbook: docker compose up -d postgres qdrant backend → 确认 .env 的"
                " QDRANT_URL/EMBEDDING_API_KEY → 重跑本命令。",
                file=sys.stderr,
            )
            return 4
        try:
            rankings = asyncio.run(_hybrid_rank_all(corpus, golden))
        except Exception as e:  # noqa: BLE001 — 栈侧故障必须可见, 不静默退化
            print(f"[hybrid] 真实栈执行失败: {type(e).__name__}: {e}", file=sys.stderr)
            return 5
        # 预计算排名回填给同一 evaluate() —— 指标口径与 lexical 完全一致
        rank_fn = lambda query: rankings.get(query, [])  # noqa: E731
        res = evaluate(corpus, golden, rank_fn)
        res["mode"] = "hybrid_real_stack"
        res["version"] = {
            "evaluated_at": datetime.date.today().isoformat(),
            "corpus_fingerprint": hashlib.sha256(Path(args.corpus).read_bytes()).hexdigest()[:12],
            "golden_fingerprint": hashlib.sha256(Path(args.golden).read_bytes()).hexdigest()[:12],
            "evaluator": "hybrid_rrf_v1(rag.retriever 实跑)",
        }
        notes = [
            "- 复现: 起真实栈(docker compose up -d postgres qdrant backend)后"
            " `python -m eval_datasets.evaluate_rag --mode hybrid --out ../docs/benchmark`",
            "- 与 lexical 基线同黄金集对照: MRR/recall 差值即混合检索(dense+BM25+RRF)的净增益",
            "- 改语料/查询集必须: 更新 fixtures 版本号 + 旧结果存 *-pre-*.json + 本报告重跑",
        ]
        md = render_markdown(res, notes)
        md = md.replace("# RAG 检索质量评测 — 词法层基线(可复现)",
                        "# RAG 检索质量评测 — 混合检索(真实栈实跑)")
        if args.out:
            out = Path(args.out)
            out.mkdir(parents=True, exist_ok=True)
            tag = "-hybrid"
            (out / f"RAG-EVAL{tag}-result.json").write_text(
                json.dumps(res, ensure_ascii=False, indent=2), encoding="utf-8")
            (out / f"RAG-EVAL{tag}.md").write_text(md, encoding="utf-8")
            print(f"报告已写 {out}/RAG-EVAL{tag}.{{md,-result.json}}")
        print(json.dumps({k: v for k, v in res.items() if k != "queries"}, ensure_ascii=False))
        return 0

    # ── lexical 模式(默认): 确定性词法基线 ──
    rank_fn = build_ranker(corpus)
    res = evaluate(corpus, golden, rank_fn)

    # E5(2026-10-30): 版本化指纹 —— 检索质量数字从此可归因到具体语料/查询集/评估器版本
    # (改任一 fingerprint, 结果即不可比; 报告头部自动携带)
    def _fp(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()[:12]
    res["version"] = {
        "evaluated_at": datetime.date.today().isoformat(),
        "corpus_fingerprint": _fp(Path(__file__).parent / "fixtures" / "rag_corpus.jsonl"),
        "golden_fingerprint": _fp(Path(__file__).parent / "fixtures" / "rag_golden_queries.json"),
        "evaluator": "lexical_bm25_v1",
        "note": "fingerprint 变化即结果不可比; 旧结果须存 *-pre-*.json",
    }

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
