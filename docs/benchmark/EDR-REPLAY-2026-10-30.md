# EDR-REPLAY 2026-10-30 —— EVTX-ATTACK-SAMPLES 全量回放（REMEDIATION-PLAN 路线 E1）

> 数据：[EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES)（MIT，真实攻击机全量事件流）
> 278 个 .evtx（270 个有效回放，8 个在跳过目录）→ python-evtx 逐条 XML →
> `SysmonParser.parse()`（本批修复后）→ `apply_mapping` → 1675 条规则引擎检测。
> 引擎：`backend/eval_datasets/replay_edr_public.py`（`--per-file-cap 3000`）。
> 耗时：784.6s 单进程。**这是平台首次在真实 Windows/Sysmon 攻击数据上的全量回放。**

## 1. 总账

| 指标 | 数值 |
|---|---|
| 回放文件 | 270（按 ATT&CK 战术目录组织） |
| 事件记录 | **36,564** |
| 解析成功率 | **36,564/36,564 = 100%**（含 Security 事件与 Sysmon 全 EventID 面） |
| 检测错误 | 0 |
| 命中事件 | **268** |
| 触发规则数（去重） | **135** —— **头部命中全部来自 B2 新导入的 hq 影子规则**（C-1422×24 / C-879×18 / C-1485×16 / C-1602×16 / C-959×14…），即 **B3 转正的攻击命中证据燃料已产出** |

## 2. 分战术命中表（节选，全量见同名 JSON）

| 战术 | 文件 | 记录 | 命中事件 | 触发规则数 |
|---|---|---|---|---|
| Privilege Escalation | 65 | 1,139 | 66 | 36 |
| Execution | 34 | 541 | 63 | 46 |
| Credential Access | 38 | 29,852 | 43 | 20 |
| Persistence | 22 | 411 | 35 | 16 |
| Lateral Movement | 47 | 1,288 | 32 | 27 |
| Defense Evasion | 35 | 429 | 24 | 16 |
| Command and Control | 6 | 1,969 | 1 | 1 |

**technique 标注口径（诚实）**：该数据集仅 3 个文件名内嵌技术编号（T1098/T1186/T1178），
其余 267 个的 technique 元数据在仓库 README/网站而非文件名 —— 本表按**战术目录**粒度呈现，
不猜测具体技术；如需 per-technique 精细对账，后续用其官方元数据表补标注。

## 3. 本批关掉的 capabilities `edr` 两个待修（均有单测钉死）

| 待修 | 修复 | 测试 |
|---|---|---|
| 事件时间提取 | XML `TimeCreated@SystemTime` / JSON `SystemTime` → `to_dict().timestamp`（修复前完全不提取，下游只能拿入库时刻）；顺带补 `System/Computer` 提取 | `tests/test_sysmon_parser_e1_fixes.py` 5 项 |
| 跨源关联键 | 修复前 `computer:process_name:event_id` —— EventID 是**事件类型**（所有进程创建都是 1），同机同类型事件全部误关联；改为 **ProcessGuid**（每进程全局唯一，EID1/EID3 跨类型同键），无 Guid 源降级 `computer:pid:process_name` | 同上（含同 Guid 跨事件类型关联、不同进程不同键两个语义用例） |

## 4. 良性 Sysmon 基线的诚实边界（B3 红线相关）

本数据集是**攻击期全量事件流**（含攻击机上的正常进程活动）——不能当良性 FP 语料，
用它算"FP=0"是伪证据。因此：

- 攻击命中证据（本报告 135 条规则）✅ 已产出；
- **良性门禁未满足**：24h 真机 Sysmon 基线未采集（需真机/长时部署，非本机可完成）；
- 按红线，**1262 条 process_creation 规则仍不转正**（缺 FP=0 的良性证据）；
  良性基线到位后：`backtest_promotion.py` 扩 `--edr-root`（攻击证据）+ 良性 Sysmon 语料（FP 门禁）
  一次 `--apply` 完成转正 —— 证据两侧都已就绪一半以上。

## 5. 复现

```bash
cd backend
python -m eval_datasets.replay_edr_public \
  --root ../tools/datasets-cache/evtx-attack-samples/EVTX-ATTACK-SAMPLES-master \
  --per-file-cap 3000 --out ../docs/benchmark/EDR-REPLAY-2026-10-30.json
```
