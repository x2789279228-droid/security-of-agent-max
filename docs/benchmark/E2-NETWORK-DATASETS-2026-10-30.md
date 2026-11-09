# E2 公开网络数据集回放（REMEDIATION-PLAN 路线 E2，2026-10-30）

> 引擎：`backend/eval_datasets/replay_network_public.py`（UNSW-NB15 + CIC-IDS2018 flows 适配器）
> + `replay_edr_public.py`（CIC-IDS2018 EVTX 面，E1 管线复用）
> 语料缓存：`tools/datasets-cache/{unsw_nb15, cicids2018}/`
> 规则面：1675 条（shadow 1650）。红线口径：只写实测；形态边界如实标注。

## 1. 数据集与获取口径（如实）

| 数据集 | 来源 | 规模 | 获取口径 |
|---|---|---|---|
| UNSW-NB15（镜像） | GitHub `InitRoot/UNSW_NB15`（10MB zip） | 257,673 行（train+test），二分类 label | **官方在 SharePoint 需人工下载**（探测 404/超时）——镜像为特征编码 CSV：proto/service/state 为编码值、**无 IP/端口/URL 文本**，已登记 |
| CIC-IDS2018 flows | AWS Open Data `cse-cic-ids2018` S3（匿名可拉） | Thursday-01-03 渗透日 331,125 行（Benign 238,037 / Infilteration 93,063）+ 其余 9 日未拉（352MB-4GB/日） | CICFlowMeter 数值特征向量：有 Dst Port/Protocol，**无 URL/UA 文本** |
| CIC-IDS2018 EVTX | 同上 Original Network Traffic and Log data | 15 台受害机 413 个 .evtx（渗透攻击期全量） | **Windows 核心事件日志，非 Sysmon schema**（见 §3） |

## 2. 回放结果（抽样全量：各 30,000/类；EVTX 42 文件抽样≈1/10，625,699 条）

| 语料 | 类别 | n | 命中事件 | 触发规则 | eps |
|---|---|---|---|---|---|
| UNSW-NB15 | benign | 30,000 | 0 | 0 | 47.7 |
| UNSW-NB15 | malicious | 30,000 | 0 | 0 | 48.2 |
| CIC-IDS2018 flows | benign | 30,000 | 0 | 0 | 46.8 |
| CIC-IDS2018 flows | malicious | 30,000 | **35** | **2**（SIG-017 端口类×28 / SIG-006×7，自研） | 46.1 |
| CIC-IDS2018 EVTX | 攻击期全量 | 625,699 | 0 | 0 | ~121 |

解析面：EVTX 625,699/625,699 = **100%**（sysmon_parser 对非 Sysmon 的 Windows 核心日志同样全量解析）；flows/UNSW CSV 全量入链。

## 3. 形态边界（本批最重要的诚实结论）

1. **特征向量语料（UNSW 镜像 / CICFlowMeter）对 Sigma URL/UA 类规则零命中是数据形态事实**——规则匹配文本字段，语料只有数值特征。CIC flows 的 35 个命中全部来自自研端口类规则（SIG-017）消费 Dst Port —— 这是该语料与规则面的真实交集。**1641 条 hq 影子规则在两个特征向量语料上均零命中、零误报。**
2. **CIC-IDS2018 原始 EVTX 是 Windows 核心事件日志，不是 Sysmon**（EventID 分布 16/7040/6/44/43…，EID1 极少且无 Image/CommandLine 字段）——`process_creation` 规则面（1262 条）按 schema 事实不命中。**EVTX-ATTACK-SAMPLES（E1）仍是唯一 Sysmon-schema 攻击语料。**
3. **对 B3 ≥300 的含义（如实）**：攻击侧证据燃料仍集中于 E1 语料（135 条规则已获命中证据）；E2 未新增 hq 规则攻击证据。**转正的真正阻塞在良性侧**——需要「良性 + Sysmon schema + ≥24h」语料（真机基线），攻击/良性两侧对齐后一次 `--apply`。

## 4. 复现

```bash
cd backend
python -m eval_datasets.replay_network_public --dataset unsw_nb15 --root ../tools/datasets-cache
python -m eval_datasets.replay_network_public --dataset cicids2018_flows --root ../tools/datasets-cache
python -m eval_datasets.replay_edr_public --root ../tools/datasets-cache/cicids2018/sample-evtx
```
