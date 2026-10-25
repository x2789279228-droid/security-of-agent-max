# 对抗变体检出保持率(签名层)

- 总体保持率: **0.438**(算子: url_encode, double_encode, partial_encode, case_flip)

| 家族 | 基线命中 | url_encode | double_encode | partial_encode | case_flip | 保持率 |
|---|---|---|---|---|---|---|
| traversal | ✓ | ✗ | ✓ | ✗ | ✓ | 0.5 |
| traversal_encoded | ✓ | ✓ | ✗ | ✓ | ✓ | 0.75 |
| xss | ✓ | ✗ | ✗ | ✗ | ✓ | 0.25 |
| es_unauth | ✓ | ✗ | ✗ | ✓ | ✓ | 0.5 |
| env_probe | ✓ | ✗ | ✗ | ✓ | ✓ | 0.5 |
| git_probe | ✓ | ✗ | ✗ | ✓ | ✓ | 0.5 |
| actuator | ✓ | ✗ | ✗ | ✗ | ✓ | 0.25 |
| webshell_cmd | ✓ | ✗ | ✗ | ✗ | ✓ | 0.25 |

## 怎么读

- 基线未命中的家族是评测器自身的对齐问题(见 note), 不计入引擎评价;
- 保持率低的算子 = 该编码形态需要 ingest 侧规范化(与 REPLAY 报告的
  双重编码发现一致), 修复面在接入管道而非逐条规则;
- 本表只覆盖签名层; 行为层(anomaly)与链层(correlation)的对抗评估
  由 self_play 红蓝自博弈承担(其课程化变体见 self_play/ 模块)。
