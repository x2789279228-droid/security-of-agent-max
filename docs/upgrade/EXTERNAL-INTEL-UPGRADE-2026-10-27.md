# 外部能力增强方案 — 执行报告（2026-10-27/28）

> 六条路线的**落地状态总账**。原方案与 AC 见本文件 §2；沙箱（开发机，无外网）
> 完成 = 代码+测试+fixture+评测器全绿；用户环境 AC = 需要真实网络/虚机/数据集
> 的验收步骤，全部有**一条命令的 runbook**。

## 1. 一句话总结

六条路线全部实现并提交；评测报告新增四份（RAG-EVAL / REPLAY-PCAP /
ATTACK-COVERAGE / REPLAY-BEHAVIOR-*）；实测数字：SigmaHQ 解锁 116→125、
CIC 行为层可行区间 0.40~0.60（默认阈值在内）、pcap 对账全绿、RAG 词法基线
MRR=0.9917（回归基线语义）。**四个"宣称缺口"变成"有报告、有测试、有 runbook
的交付物"**。

## 2. 六路线状态总账

| 路线 | 提交 | 沙箱完成 | 用户环境 AC（runbook） |
|---|---|---|---|
| R3 情报全家桶+富化 | `2146d30` | 4 源方言（Feodo/OpenPhish/URLhaus/KEV）+ enricher 双链接线 + 11 测试 | `bash tools/seed-free-intel-feeds.sh`（有网环境拉真实源, 证据截图） |
| R5 ATT&CK+RAG | `966745f` | evaluate_rag + 60 语料/60 黄金集入库可复现 + technique 告警面透传 + 9 测试 | `cd backend && python -m eval_datasets.evaluate_rag`（词法层, 已实测）；**hybrid 已实现为真栈实跑（2026-11-09 阶段4C：rag.retriever 实查黄金集，栈未就绪退出码 4 + runbook, 不伪造数字）**；ATT&CK bundle 导入 runbook |
| R2 Suricata+pcap | `898875f` | 连接器复活（默认落库处理器）+ app 启动分支 + compose 回放服务 + 评测器 + 5 测试 | MTA pcap 下载 → `soc-suricata-replay` → 评测器（runbook 见模块 docstring） |
| R1 Atomic | `95e436a` | runner 三模式三道安全闸 + 覆盖对账器 + 8 技术 manifest + 4 测试 | 按 `docs/upgrade/ATOMIC-REDTEAM-RUNBOOK.md` 在测试 VM 执行（检出 ≥60% AC） |
| R4 字段扩展 | `0c74228` | dns_query/file_hash 四层贯通（含 Avro/Java 契约）+ **实测 116→125** | 第二批 Sysmon 字段（依赖 R1 真实数据源）→ 目标 ≥400 |
| R6 行为层回放 | `a6b772c` | registry + 双数据集适配器 + 阈值扫描 + **CIC 可行区间 0.40~0.60** + 4 测试 | 全量 CIC/CTU 数据集下载回放（runbook 见模块 docstring） |

## 3. 实测数字（非沙箱内可得部分全部如实标注）

- **SigmaHQ**: field_compatible 116→**125**（+9 dns 影子规则，编译 125/125），
  manifest 2026-10-28；吞吐 profile 37.9ms/事件与 PERF 基线同量级（无退化）。
- **RAG**: MRR=0.9917 / recall@5=1.0（60-doc 语料，明确声明为回归基线而非能力
  上限——与旧"30 条自造语料 MRR=100 且不可复现"的本质区别是可对账）。
- **pcap 回放**: fixture 6 alert → 5 接受 + 1 去重，三方对账全绿。
- **行为层**: CIC 多日基线+暴破 → 可行区间 0.40~0.60；CTU 稳态信标+首见实体
  → 区间为空 = **实体相对基线的结构性盲区**（已知缺口，需 beacon 周期性维度/
  全局频率层——这是行动项不是失败）。
- **ATT&CK 覆盖**: fixture 7 runs（含 1 漏检样例）6/7=86%，漏检逐条登记机制
  已钉死；真实 VM 检出率待执行。

## 4. 过程中顺手修掉的真实缺陷

1. `intel_enricher` 死代码 → 双链接线（消费断点闭环）。
2. `ids_connector` D 级死代码（告警凭空消失）→ 默认落库处理器复活。
3. `sigma_detector.detect()` 构造 `DetectionResult` 时**从不填充**
   mitre/shadow 字段（只在 matched_fields 里藏着，顶层消费方全拿 None）
   → 两类位置都写。
4. 幂等重放会吞掉行为层基线学习（无 event_id 时）→ 适配器显式生成唯一
   event_id，语义教训写进模块 docstring。
5. 跨运行时契约纪律当场生效：schema 加字段第一版漏了 Avro/Java，
   `test_schema_compat` 的目录对齐测试当场转红。

## 5. 新增 known_gap（诚实登记）

- 新实体冷启动封顶限制"首见实体攻击"的检出（实体相对基线的固有语义）；
- CTU 稳态信标 + 首见实体 = 结构性失明 → **行动项：beacon 周期性维度/
  Flink 全局频率层接入**（评测结论"区间为空"在此是正确答案）；
- Windows/Sysmon 类 SigmaHQ 规则（约 250+ 条解锁面）等待 R1 真实数据源。

## 6. 复现索引

| 交付物 | 命令 |
|---|---|
| 情报接线+富化 | `bash tools/seed-free-intel-feeds.sh`（需网） |
| ATT&CK 知识库导入 | `POST /api/rag/import/mitre`（admin；源=官方 attack-stix-data bundle，mitre_importer.py 内置） |
| RAG 词法基线 | `python -m eval_datasets.evaluate_rag --out ../docs/benchmark` |
| pcap 回放 | `python -m eval_datasets.replay_pcap_suricata --out ../docs/benchmark` |
| ATT&CK 覆盖 | `python -m eval_datasets.evaluate_attack_coverage --ground-truth <gt> --alerts <export> --out ../docs/benchmark` |
| 行为层回放 | `python -m eval_datasets.replay_behavior_public --dataset cicids2017 --out ../docs/benchmark` |
| SigmaHQ 重导入 | `python tools/import_sigmahq.py [--dry-run]` |
