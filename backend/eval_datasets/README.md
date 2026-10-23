# 评估数据集

> **重要**：当前 `detection_cases.py` / `behavior_cases.py` / `grounding_cases.py`
> 都是**合成标定集**，用于验证“实现与标注是否一致”，**不代表生产流量分布**。
> 绝对误报率/召回率不可外推；任何对外材料都必须带这句限定。

## 运行

```bash
cd backend
python -m eval_datasets.evaluate_detection      # Sigma / 异常 / 关联
python -m eval_datasets.evaluate_behavior       # AI 工具调用行为
python -m eval_datasets.evaluate_grounding      # 证据溯源
```

`evaluate_detection --json` 输出机器可读结果（含数据集版本与内容哈希），
适合 CI artifact 与 before/after 对比。

## 当前基线（2026-10-21）

完整报告见 `docs/upgrade/EVAL-BASELINE-2026-10-21.md`。摘要：

- Sigma：TP=8 / FP=0 / TN=10 / FN=0；但 8 个 TP 里只有 50% 来自原始指标。
- 异常：应检出 3 条，实际 1 条；完整可行阈值区间为空集。
- 关联：TP=2 / FP=0 / TN=6 / FN=0（仅 8 条合成用例）。

## 维护规则

1. **不要为了变绿改标注**。改用例必须同步更新报告，并说明理由。
2. 新增用例要带 `evidence_kind` / `attack_type` 分层；否则无法判断增量能力。
3. 版本化：每次大规模改动用例，更新 `dataset_info()` 里的 `version`。
4. 真实生产标注集应放在独立目录（如 `eval_datasets/production_v1/`），
   带来源、标注人、脱敏说明，不与合成集混用。
