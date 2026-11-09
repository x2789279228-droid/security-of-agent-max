# RULE-IMPORT 2026-10-30 —— SigmaHQ 全量影子导入（REMEDIATION-PLAN 路线 B2）

> 命令：`python tools/import_sigmahq.py --backend-dir backend`
> 源：SigmaHQ master（codeload tarball，`tools/.sigmahq-cache/`，DRL 1.1 许可，出处保留在每条规则的 license/author 字段与 manifest）
> 红线口径：本报告只写实测数字；转正（执法模式）一律走 B3 回测（FP=0 硬门禁），本批**全部影子**。

## 1. 导入账目（工具实测输出）

| 阶段 | 数量 | 说明 |
|---|---|---|
| 扫描 | 3208 | rules/{web,proxy,network,windows,linux} + rules-emerging-threats（后两者为本批新增扫描面；proxy/emerging 目录在 SigmaHQ 新版已并入 web，`is_dir` 守卫优雅跳过） |
| 字段兼容 | 1641 | B1 第二批字段解锁（EventID/Image/CommandLine/ParentImage/User/TargetFilename/TargetObject…） |
| 剔除：类别外 | 1187 | powershell 等无平台数据源的 logsource 类别（正确剔除 = 恒不命中的死重） |
| 剔除：字段缺失 | 288 | 检测字段不在 COMPAT_FIELDS（无源可命中） |
| 剔除：不兼容 | 83 | `|re` 修饰符（自研 SQLite 后端无 REGEXP）/ 空字符串字面量（稀疏事件全量误报，实测教训） |
| 标题去重 | 9 | 与手适配 c_00x 同名规则跳过（避免影子/执行双份污染 precision） |
| pySigma 编译门禁 | **1641 通过 / 0 失败** | 逐条编译、失败定位到文件 |
| 写入 | **1641 条 hq_\*（全部 x-soc-shadow=true）** | manifest：`backend/sigma_engine/SIGMAHQ_MANIFEST.json`（imported_at/total_scanned/field_compatible/compiled_ok/written 版本化） |

## 2. 加载与命中验收（引擎实测）

| 项 | 数值 |
|---|---|
| 引擎加载总数 | **1675** = 20 自研(rules/) + 1641 hq(影子) + 9 c_00x(影子) + 5 web_*(旧执法，前批次遗留) —— 对比导入前 159 条，**10.5×** |
| shadow_count / enforcement | **1650 / 25**（det.stats() 实测） |
| 影子命中 spot-check | 事件（EventID=1, Image=powershell.exe 全路径, CommandLine 含 `-enc <base64>`, ParentImage=cmd.exe）→ 命中 **C-1098 "Suspicious Execution of Powershell with Base64"**，返回带 `[SHADOW]` 标记、action=alert（只告警不执行）—— 影子语义端到端正确 |
| 良性 sysmon 形态事件 | hits=0（cmd/whoami 无误报） |
| 引擎加载耗时（启动） | ~9.1s（1675 条编译；生产为常驻进程，摊销） |

## 3. 导入暴露并修复的两个性能/正确性缺陷（当天闭环）

| # | 缺陷（实测形态） | 修复 |
|---|---|---|
| 1 | **列撞名崩溃**：mapping 产出 `User`（SigmaHQ 检测字段）与引擎标准列 `user` 在 SQLite 大小写不敏感语义下 duplicate column → `sigma_exec_schema_invalid` 整次检测崩溃 | `_ensure_table` 大小写不敏感去重（保留标准名形态）+ 取值不敏感回退（User/user 同逻辑字段不丢值） |
| 2 | **千列 DDL 拖垮检测**：全量 field_index 补齐让每事件 DROP/CREATE/INSERT 背上千列 —— web 形态事件 **7.48ms(150 规则基线) → 496ms(1675 规则)**，sysmon 形态首跑 9.5s | **A4 惰性 schema（提前落地）**：编译期按规则提取 `sql_cols`（SQL 引用列全集，含 IS NULL 形态），检测期先按 Wave 1-3 预筛判活、只为存活规则建列；任一规则缺 sql_cols → 保守回退全量列（不许因惰性引入漏报） |

修复后实测（同一进程 1675 规则）：

| 事件形态 | 修复前 | 修复后 |
|---|---|---|
| web 形态 | 496.3 ms | **34.3 ms** |
| sysmon 攻击形态 | 9461.8 ms(首跑) | **240 ms** |
| 命中等价性 | — | 惰性 vs 保守全量列 A/B 同命中（无漏报）；Q2 私库隔离等 6 项引擎守卫全绿 |

> 注：web 形态 34ms 仍高于 150 规则时代的 7.48ms —— 差额来自新解锁的 web/proxy 类存活规则的真实执行（数量增加是导入的目的），单进程 ceiling 重标定归 A7/PERF-2。

## 4. 已知限制（如实登记）

1. **3 条规则触发 SQLite 表达式深度上限**（C-412/C-416/C-1405，"Expression tree is too large (maximum depth 1000)"——超长 IN 列表规则）。引擎逐条捕获并计入 rule_errors（不崩、留痕、计为不命中）；B3 转正时这几条直接排除，或后续为其做列表分片。
2. 引擎启动编译耗时 ~9s：常驻进程无碍；多进程（A3）每 worker 各付一次。
3. 本批全部影子：precision/召回回测（CSIC 良性 FP=0 硬门禁 + EVTX/E1 攻击命中证据）是转正唯一通道（B3）。

## 5. 复现

```bash
# 拉源(或用 tools/.sigmahq-cache 既有快照)
curl -sL -o tools/.sigmahq-cache/sigma.tar.gz \
  https://codeload.github.com/SigmaHQ/sigma/tar.gz/refs/heads/master
tar -xzf tools/.sigmahq-cache/sigma.tar.gz -C tools/.sigmahq-cache --wildcards \
  "sigma-master/rules/web" "sigma-master/rules/network" "sigma-master/rules/windows" "sigma-master/rules/linux"
# 导入(幂等: 清掉旧 hq_* 后全量重写)
python tools/import_sigmahq.py --backend-dir backend
# 验收
cd backend && python -c "
from sigma_engine.engine import PySigmaDetector
d = PySigmaDetector('sigma_engine/rules', enforce=False)
print(d.stats())"
```
