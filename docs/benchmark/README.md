# 检测能力量化报告集(B1-B4)

> 生成方式全部可复现: 命令在各报告头部/对应模块 docstring。
> 数据面: 合成标定集(detection_cases, 工程正确性)+ 公开数据集
> CSIC-2010(外部 ground truth, 能力量化)+ 对抗变体(签名韧性)。

| 报告 | 回答的问题 | 生成命令(backend/ 下) |
|---|---|---|
| [REPLAY-CSIC-2010.md](REPLAY-CSIC-2010.md) | 对公开真实攻击数据的召回/误报? | `python -m eval_datasets.replay_public_datasets --root ../tools/datasets-cache --out ../docs/benchmark` |
| [ABLATION.md](ABLATION.md) | 多层堆叠每层带来什么? | `python -m eval_datasets.ablation --out ../docs/benchmark` |
| [EVASION.md](EVASION.md) | 签名层对抗编码规避的韧性? | `python -m eval_datasets.evasion_retention --out ../docs/benchmark` |

## 一页结论(2026-10-25 实测)

- **规则库 150 条**(12 内置 SIG + 8 自研 SIG-013..020 + 5 手适配 + 125 影子批量),
  全编译 0 错误;合成标定集 Precision=1.0 / FP=0。
- **CSIC-2010 公开数据集**: 良性 5000 样本 **0 误报**;签名可测子集召回
  34.5%(原始=规范化 —— 现有规则已含关键编码变体);SQLi 由影子层接住
  (19/156, 晋升候选);其余 ~80% 异常类为纯行为异常, 属异常检测器工作面。
- **分层消融**: 执行层/异常检测/关联引擎在各自工作面接近满分;
  SOAR 决策层 5/8 确认检出落地为可执行决策(auto 2 + approval 3),
  3 类 web 攻击无 taxonomy 叶子与专属策略 —— 已登记为策略库缺口。
- **对抗保持率 0.438**: 大小写翻转 100% 保持;完整 URL 编码 0/8 ——
  修复面在 ingest 解码规范化(roadmap), 不在逐条规则。

## 数据/源码获取

- SigmaHQ 源: `tools/.sigmahq-cache/`(见 `tools/import_sigmahq.py` 头注释)
- CSIC-2010: `tools/datasets-cache/`(GitLab FING 镜像, 三个 txt)
- 两者均已 gitignore, 不随仓库分发(许可与体积原因)
