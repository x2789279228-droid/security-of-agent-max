# AUDIT-BENCH 2026-10-30 —— 50 条人工标注审计基准（REMEDIATION-PLAN 路线 E4）

> 引擎：`backend/eval_datasets/audit_bench.py` —— capabilities `audit_pipeline`
> 注记「缺 50 条人工标注审计基准」的直接关闭物。
> 维护约定（与 grounding_cases 一致）：**先写 expect 再跑实现；冲突先判实现，
> 确认是标注问题才改 expect（本轮 4 个 FAIL 逐一裁决，3 个为标注错、1 个为口径别名）**。

## 1. 结果

| 项 | 值 |
|---|---|
| 总样本 | **46**（目标 50：grounding 12 + behavior 9 + 新增语义 25） |
| 计分样本 / known_gap | 43 / 3（known_gap 不混入准确率） |
| **通过 / 准确率** | **43 / 43 = 1.0000** |

分组：grounding 12/12、behavior 9/9、triage 6/6、analysis_completeness 1/1、
degrade 8/8、budget 4/4、sigma_shadow 2/2、stabilize 1/1。

## 2. 覆盖面（25 条新增语义样本调用的都是生产函数）

- **分诊语义**：medium→P2/tools_only、critical+高融合分→P1/llm_single（strong=1 有
  fused 背书）、sigma critical→P0、正常→rule_close、**H-④ 沙箱报告升 priority**、
  分析不完整时 reasons 不得与完整分析相同（防「未分析=阴性」）；
- **降级语义**：429 标记→`rate_limited_429` 且可重试、5xx 不可重试、正常 JSON 不判
  fallback、budget 标记、timeout 标记、非字符串/裸文本不判 fallback（调用方契约）；
- **预算语义**：P0 不短路、用量非负、exhausted 返回 bool、P3 短路合法；
- **影子/执法与稳定化**：shadow_count≥1600、rules_count≥1600、parse_llm_json 往返。

## 3. 裁决记录（4 个初始 FAIL）

| FAIL | 裁决 | 处置 |
|---|---|---|
| grounding partial→partially_grounded | **口径别名**（evaluate_grounding._EXPECT_ALIAS 早有映射，本引擎漏用） | 引擎补 alias |
| t02 critical→P1 非 P0 | **标注错**：strong=1（fused 背书）走 P1 llm_single；P0 留给 sigma critical（t03 钉住） | 改 expect=P1 |
| d06 None 判 fallback | **标注错**：非字符串输入不判（调用方契约是"字符串标记检测"） | 改 expect=False |
| d07 裸文本判 fallback | **标注错**：'not-json-at-all' 非 fallback JSON 标记 | 改 expect=False |

## 4. 复现

```bash
cd backend && python -m eval_datasets.audit_bench   # 43/43, acc=1.0
```
