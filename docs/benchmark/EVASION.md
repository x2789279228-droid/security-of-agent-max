# 对抗变体检出保持率(签名层)

- 总体保持率: **1.0**(算子: url_encode, double_encode, partial_encode, case_flip)

- 规范化前基线(2026-10-25 之前, 见 EVASION-result-pre-normalization.json): **0.438** → 接入 `normalization.canonical_matching_view` 后 **1.0**(升级证据: docs/upgrade/evidence/DETECTION-NORMALIZATION-2026-10-25.md)

| 家族 | 基线命中 | url_encode | double_encode | partial_encode | case_flip | 保持率 |
|---|---|---|---|---|---|---|
| traversal | ✓ | ✓ | ✓ | ✓ | ✓ | 1.0 |
| traversal_encoded | ✓ | ✓ | ✓ | ✓ | ✓ | 1.0 |
| xss | ✓ | ✓ | ✓ | ✓ | ✓ | 1.0 |
| es_unauth | ✓ | ✓ | ✓ | ✓ | ✓ | 1.0 |
| env_probe | ✓ | ✓ | ✓ | ✓ | ✓ | 1.0 |
| git_probe | ✓ | ✓ | ✓ | ✓ | ✓ | 1.0 |
| actuator | ✓ | ✓ | ✓ | ✓ | ✓ | 1.0 |
| webshell_cmd | ✓ | ✓ | ✓ | ✓ | ✓ | 1.0 |

## 改前改后(同口径同向量)

| 家族 | 改前保持率 | 改后保持率 |
|---|---|---|
| traversal | 0.5 | 1.0 |
| traversal_encoded | 0.75 | 1.0 |
| xss | 0.25 | 1.0 |
| es_unauth | 0.5 | 1.0 |
| env_probe | 0.5 | 1.0 |
| git_probe | 0.5 | 1.0 |
| actuator | 0.25 | 1.0 |
| webshell_cmd | 0.25 | 1.0 |

## 怎么读

- 基线未命中的家族是评测器自身的对齐问题(见 note), 不计入引擎评价;
- 保持率低的算子 = 该编码形态需要 ingest 侧规范化(与 REPLAY 报告的
  双重编码发现一致), 修复面在接入管道而非逐条规则;
- 2026-10-25 起 `normalization.canonical_matching_view` 接入引擎匹配
  视图(受限多轮解码+反斜杠归一+缺省 dst 补齐), 编码算子不再是规避通道;
- 本表只覆盖签名层; 行为层(anomaly)与链层(correlation)的对抗评估
  由 self_play 红蓝自博弈承担(其课程化变体见 self_play/ 模块)。
