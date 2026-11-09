# RAG 检索质量评测 — 词法层基线(可复现)

- 语料: 60 chunks (fixtures/rag_corpus.jsonl, 提交入库)
- 黄金集: 60 条查询 (fixtures/rag_golden_queries.json, 四类意图)
- 排序器: 平台 rag.lexical.tokenize + BM25(k1=1.5,b=0.75), 确定性
- 指标: **MRR=0.9917** / recall@5=1.0 / recall@10=1.0 (27.1ms)

> 口径声明: 本报告评的是**词法召回层**的可复现基线 —— hybrid/embedding
> 模式复用同一黄金集, 需真实检索栈(PG+Qdrant+embedding 服务), 运行命令
> 见文末。数字变化 = 语料/查询集/排序器之一变化, 三者全部版本化入库。
>
> 诚实定性: 60-doc 语料上的高 MRR 是**回归基线语义**(钉住切词/索引
> 不回归), 不是检索能力上限 —— 与旧评估 30 条自造语料 MRR=100 的区别
> 在于: 本基线可复现、可对账、失败样本逐条列出, 且明确不是能力声明。

## 分意图指标

| 意图 | n | MRR | recall@5 | recall@10 |
|---|---|---|---|---|
| intel | 6 | 1.0 | 1.0 | 1.0 |
| mitigation | 10 | 1.0 | 1.0 | 1.0 |
| ops | 8 | 1.0 | 1.0 | 1.0 |
| platform | 13 | 1.0 | 1.0 | 1.0 |
| technique | 23 | 0.9783 | 1.0 | 1.0 |

## top5 未命中(0 条 — 改语料/改切词的依据)

| 查询 | 相关 chunk | top5 实际 |
|---|---|---|

## 复现与升级路径

- 复现: `python -m eval_datasets.evaluate_rag --out ../docs/benchmark`
- 升级 hybrid: 按上 runbook 起真实栈后 `--mode hybrid` 并保留 lexical 结果对照
- 改语料/查询集必须: 更新 fixtures 版本号 + 旧结果存 *-pre-*.json + 本报告重跑
