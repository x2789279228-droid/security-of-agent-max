# 检测评估基线（2026-10-21）

> 命令：`cd backend && python -m eval_datasets.evaluate_detection`
> 环境：Windows / Python 3.11.9 / 本机运行
> 数据集：**合成标定集**（`backend/eval_datasets/detection_cases.py`），不是生产流量。
> 结论：只能用于“实现与标注是否一致”的回归，不能外推生产误报率/召回率。

## 1. Sigma

| 指标 | 值 |
|---|---|
| TP / FP / TN / FN | 8 / 0 / 10 / 0 |
| Precision / Recall / F1 | 1.000 / 1.000 / 1.000 |
| FPR / FNR | 0.000 / 0.000 |

按证据来源拆分：

| 来源 | n | 真值 | TP | FP | Precision | Recall |
|---|---:|---|---:|---:|---|---|
| raw_indicator | 6 | 恶意 | 4 | 0 | 1.000 | 1.000 |
| event_type_only | 4 | 恶意 | 4 | 0 | 1.000 | 1.000 |
| lookalike | 5 | 良性 | 0 | 0 | n/a | n/a |
| benign | 5 | 良性 | 0 | 0 | n/a | n/a |

关键事实（不能省略）：

- 8 个真阳性中，**来自原始指标的只有 50%**；另外 50% 只是复述上游 `event_type`。
- `raw_indicator` 组有 2 条是 `partial_only`（SIG-P-04、SIG-P-05），不计入 P/R。
- 标定集 FP=0，因此各基准率下 Precision 都显示 1.000；**这是样本集性质，不是生产性质**。

## 2. 异常检测

| 用例 | 期望 | 实际 | 分数 |
|---|---|---|---|
| ANO-P-01 | detected | detected | 0.7143 |
| ANO-P-02 | detected | not_detected | 0.4357 |
| ANO-P-03 | detected | not_detected | 0.4957 |
| ANO-N-01 | not_detected | not_detected | 0.0000 |
| ANO-N-02 | not_detected | not_detected | 0.1714 |
| ANO-I-01/02/03 | inconclusive | inconclusive | 0.4957 / 0.4357 / 0.0000 |

- 应检出 3 条，实际 1 条；另有 3 条结构性不可判。
- 阈值扫描：召回上界 0.4357，负类下界 0.1714，不可判下界 0.4957。
- **完整可行区间 = 空集**（0.4957 ≥ 0.4357）→ 缺口不是阈值问题。
- 结论：当前特征/权重无法把 3 条正样本与负样本/不可判样本分开；需要补特征或改宣称。

## 3. 关联引擎

| 指标 | 值 |
|---|---|
| TP / FP / TN / FN | 2 / 0 / 6 / 0 |
| Precision / Recall / F1 | 1.000 / 1.000 / 1.000 |

样本量只有 8 条，且是合成用例；不能据此宣称真实攻击链关联能力。

## 4. 结论边界

1. 本基线**不代表生产检测质量**。
2. Sigma 的“完美指标”有一半来自上游分类器复述，不能作为 Sigma 自身增量检出能力的证明。
3. 异常检测的可行阈值区间为空，是当前最明确的检测能力缺口。
4. 下一步（M3）：
   - 建 ≥200 条版本化标注集（带 `manifest.json`、来源、标注人、内容哈希、分层）；
   - 把评估接入 CI，产出 JSON + Markdown 并做 before/after；
   - 异常检测补目标基数、失败率、资产重要性等特征，目标是可行阈值区间非空；
   - Sigma 以 `raw_indicator` 层 Recall ≥0.8 @ FPR ≤0.05 为验收。
