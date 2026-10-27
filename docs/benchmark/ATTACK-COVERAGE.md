# ATT&CK 覆盖评测 — Atomic Red Team 真实行为检出

- 执行 run: 7 / 技术: 7
- 平台告警: 10
- **技术覆盖: 6/7 (86%)**
- 漏检 run: 1 条(每条都要登记 known_gap + 候选规则)
- fixture: 7 runs(含 1 漏检样例) / 10 alerts

| 技术 | run 数 | 检出 | 匹配方式 |
|---|---|---|---|
| ✅ T1046 | 1 | 1 | host+window |
| ✅ T1053 | 1 | 1 | host+window |
| ✅ T1059 | 1 | 1 | host+window,technique |
| ✅ T1071 | 1 | 1 | host+window,technique |
| ✅ T1087 | 1 | 1 | host+window |
| ✅ T1110 | 1 | 1 | host+window,technique |
| ❌ T1505 | 1 | 0 | - |

## 口径声明

- 技术=强证据(平台提取的 ATT&CK 标签)；主机+时间窗=行为面兜底
  (±60s/±600s 容差)，防'没检出来但时间对得上就算中'的自欺；
- 覆盖率只统计**首批已执行**技术 —— 是当前检测面的事实清单，
  不是能力上限声明；扩面靠路线 4 的字段解锁与影子规则晋升；
- 真实数据 runbook: docs/upgrade/ATOMIC-REDTEAM-RUNBOOK.md。
