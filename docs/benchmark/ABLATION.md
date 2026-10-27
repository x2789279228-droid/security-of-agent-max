# 分层消融 — 各检测层的边际贡献(合成标定口径)

| 层 | 工作面/数据集 | 指标 |
|---|---|---|
| L1 Sigma 执行层(非影子) | sigma_cases(合成标定) | P=1.0 R=1.0 F1=1.0 (TP=8 FP=0 FN=0) |
| L2 社区影子层(125 条) | csic_sample.jsonl(公开数据集夹具) | 补充证据 0 / 良性侧影子误报 0 |
| L3 统计异常检测 | anomaly_cases(行为面) | P=1.0 R=1.0 F1=1.0 (TP=3 FP=0 FN=0) TN=2 (排除: inconclusive 3 + known_gap 0) |
| L4 关联引擎(11 链) | correlation_cases(链级) | P=1.0 R=1.0 F1=1.0 (TP=2 FP=0 FN=0) |
| L5 SOAR 决策层 | L1 确认检出 × taxonomy × 真实策略引擎 | 决策分布 {'auto_execute': 2, 'needs_approval': 6, 'uncertain': 0, 'no_action': 0, 'uncovered_type': 0}, 均 9.6ms/次 |

## 怎么读这张表

- **L2 的确认口径与 L1 相同** —— 影子层不改变确认检出, 它的价值是在真实公开数据(CSIC)上提供补充证据与晋升候选(全量口径见 REPLAY 报告:签名子集召回 34.7%, 其中 SQLi 全部由影子层接住);
- **L3 的口径(2026-10-25 两步修正)**: 第一步修评估器 —— 修复前本函数用 Sigma 的 malicious/benign 词表数 anomaly_cases 的 detected/not_detected 样本, 词表不匹配 → TP/FP/FN 恒 0, "接近满分"是空值假象; 正类=detected, 负类=not_detected, inconclusive(结构不可判)排除出二分类并单列。 第二步修检测器 —— ANO-P-02/03 双双低于阈值的缺口由 severity_shift 基线相对证据维度关闭(§七.2), 本表现在是测量面全量口径: TP=3 FP=0 FN=0; L4 关联引擎在链面满分 —— 多层堆叠的理由不变: 单层视角必然漏掉其它面的攻击;
- **L5 的 UNCERTAIN 兜底是设计**: 执行层检出的攻击类型若无专属策略,落入 5 分钟短封+高优告警的不确定模板, 而不是放行或乱封;
- LLM 审计层的贡献不在本表: 无 key 时它退化为规则收口(无区分度),其价值由 grounding 评测(事实性/溯源)单独量化。

## 边界

- 全部为合成标定数据, 绝对值不可外推到生产; 真实流量面见 REPLAY 报告;
- L3 的两条标定缺口(ANO-P-02/03)已由 severity_shift 证据维度关闭 (2026-10-25b, 演进史见 tests/test_anomaly_threshold_feasibility docstring); 真实行为面评估仍需生产基线数据, 见升级证据文档的范围边界;
- 消融刻度是"层", 不是"多智能体角色" —— 四层 Agent 流水线的
  内部消融(拆 Decompiler/Reviewer)需要 LLM 在环, 属后续工作。
