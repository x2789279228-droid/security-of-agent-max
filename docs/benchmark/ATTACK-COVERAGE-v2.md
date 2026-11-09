# ATTACK-COVERAGE-v2 —— 规则侧 ATT&CK 静态覆盖（REMEDIATION-PLAN 路线 B4，2026-10-30）

> 口径说明：本报告是**规则库静态覆盖**（加载规则 tags 中的 ATT&CK technique 去重数），
> 与既有 [ATTACK-COVERAGE.md](ATTACK-COVERAGE.md)（Atomic 实跑 × 告警对账，需 ground truth）
> 是两个互补口径：静态覆盖回答"规则面铺到哪些技术"，实跑对账回答"铺到的是否真检出"。
> 对比基线：`git HEAD`（B2 导入前，139 条社区 + 20 自研）vs 当前（1675 条，见
> [RULE-IMPORT-2026-10-30.md](RULE-IMPORT-2026-10-30.md)）。
> 计数口径：`attack.tXXXX[.YYY]` tag 去重；major = TXXXX 归并，full = 含子技术。

## 结果

| 口径 | B2 前（HEAD） | B2 后（当前） | 倍率 |
|---|---|---|---|
| major techniques | 21 | **141** | **6.7×**（目标 ≥2×） |
| full techniques（含子技术） | 27 | **284** | 10.5× |
| 旧覆盖保留 | — | 21/21 全保留 | 无覆盖回退 |

新增覆盖的 major technique 例：T1001 / T1003 / T1005 / T1007 / T1012 / T1014 / T1016 /
T1021 / T1027 / T1033 …（凭证访问、发现、防御逃逸、C2 等此前规则面为 0 的战术）。

## 边界（如实）

1. 静态覆盖 ≠ 检出能力：命中证据与误报门禁见 [RULE-PROMOTION 报告](RULE-PROMOTION-2026-10-30.md)
   （B3 回测，影子→执法的唯一通道）；进程面规则等待 E1 真实 Sysmon 语料回测后才具备转正资格。
2. 绝大多数新增覆盖来自影子规则（1650/1675）——覆盖矩阵描述的是**平台规则面**，
   执法面由 B3 按证据逐步扩大。

## 复现

```bash
# 见本报告同目录脚本逻辑：git ls-tree -r HEAD 两个规则目录 → 解析 tags 去重
python - <<'EOF'
# 与正文同口径：TAG_RE=^attack\.t\d{4}(\.\d{3})?$，major=去子技术
EOF
```
