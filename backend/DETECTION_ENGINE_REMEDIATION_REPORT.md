# 检测引擎整改验收报告

- 依据：`DETECTION_ENGINE_REVIEW.md`（VERDICT: FAIL，6×P0 / 34×P1 / 22×P2 / 11×P3）
  与《整改方案：从 P0 缺陷修复到完整验收》
- 日期：2026-10-18
- 范围：提交 A ~ F 共 6 个批次
- **结论：6 个批次的代码整改与回归验证已完成，全量测试 2042 passed / 0 failed。
  「量化评估」维度已补齐并据其结果修复了 Sigma 的 3 条良性误报（FPR 0.300 → 0.000）；
  该修复引出的封禁链路断裂（6 层）已逐层修复；Flink 作业不仅**真编译通过**，
  其窗口逻辑也已**在进程外真执行**，且这套验证**在 CI 里会真的跑**
  （新增 flink-verification job + 跳过核对，§三.4）；
  Kafka 输入的畸形/超限载荷处理已补齐，并因此挖出并修掉两个真缺陷
  （畸形 JSON 可掀翻消费循环、超大载荷可卡死分区 offset，§三.3）；
  §九.2 点名的 G² 四个覆盖维度此前一条都没有，本轮补齐 42 例；
  §九.1 / §十一.2 的「记录统计后端、依赖版本与检验参数」此前未落地，
  本轮补齐 10 例（§2.5）；跨 schema 版本混流此前从未被执行过，
  本轮补齐 17 例（§三.6）；
  §十一 P2 的 7 类检测指标已全部落地或明确覆盖（§7）。
  但标定集仍是合成的，Flink 作业从未在集群上跑过，另有 4 项结论仍属待验证。**
  详见 §三「待验证」与 §四「量化评估」与 §七「§十一 P2 指标盘点」。

> **2026-10-19 晚间复验更新（§九）**：本轮把「已修复」逐条改成**行为实测** ——
> 对每条被声称已修的性质写能证伪它的探针，再注入真缺陷确认守卫会红。
> 产出 **38 处**新发现：**一条会按墙钟自己引爆的 P0 守卫**（§9.1）、
> **§十三 黄金样本集的时间锚点污染**（§9.2）、
> **§十三 要求的误报率/漏报率在两个三分类评估器上缺失**（§9.3）、
> **负类标签写死导致关联/异常家族误报率算不出来**（§9.4）、
> **一条从未真正验证过的测试**（§9.7，测试库隔离）、
> **Sigma 规则执行错误通道的并发串扰**（§9.10 —— **P0 缺陷在并发下复活**）、
> **畸形字段类型让整条异常分析路径崩溃**（§9.11 —— §七.3 末条从未落地）、
> **全局统计不幂等 → 重复消费改变后续事件的评分**（§9.12）、
> **去重键撞车 → 第五维对无 id 事件结构性失效**（§9.13）、
> **沙箱「结果回取半边」生产零调用**（§9.14，登记）、
> **§六 验收标准「单条 Critical 规则执行异常 → 追踪错误并阻止错误收口」的端到端验收**（§9.15），
> **一条依赖实时 DNS 的单元测试 + 补上「防 DNS 变更绕过」这条从未被测过的安全性质**（§9.16），
> 以及 **一处「判别力为零」的过强表述更正 + 把它钉成守卫**（§9.17）、
> **§三.2 因果识别条件的端到端验收 + 补上一条从未有过的回归**（§9.18），
> **§三.3 方向冲突的端到端验收 + 补上另一条从未有过的回归**（§9.19），
> **§六 DDL 字段名标识符转义的端到端验收 + 补上第三条从未有过的回归**（§9.20），
> **沙箱重定向目标未重新校验 → SSRF + 凭据外泄**（§9.21，**真缺陷，已修**），
> **「缺失 task_id ⇒ 提交失败」此前零回归**（§9.22，覆盖缺口，已补）、
> **相似度「显示值 vs 判定值」契约此前零回归**（§9.23，覆盖缺口，已补），
> 以及 **特征集「限长」缺口：两半空洞成立、一半是死指标**（§9.24，登记 + 待决项 22），
> **§七「每千条事件误报量」此前根本没报**（§9.25，已补 + 3 条守卫），
> **§十三「全量回归」行首次实测：找到并修掉一处被弱化的断言**
> （§9.26 —— 并把这次人工审计固化成 CI 门禁 `tools/assert-no-assert-weakening.py`），
> **工单审批「通过后执行响应动作」是假的**（§9.36 —— 死代码 + 注释与实现不一致，
> 而系统里有**两套并行审批机制**；→ 待决项 25），
> 以及 **「多少个指标没人看」有两个互相矛盾的口径**（§9.37 —— 报告写 45、
> 登记表是 43，差在 2 个 Histogram 基础指标上；已改为以可重算的守卫口径为准），
> **Sigma 快照连接的释放判据是「代数」不是「引用」**（§9.39 —— §六 第 5 条
> 「旧快照只在不再被执行任务引用时释放」**没有落地**，而机制的 docstring
> 却声称自己实现了它；已改成引用计数租约并补 11 条守卫），
> **规则库的「三态」其实只有两态**（§9.40 —— §六.2 要求「部分规则未加载」
> 必须是 `degraded`，而实现只看「有没有编译出规则」，于是「1 好 1 坏」报
> `normal`；且 `load_errors` 没有 `severity`，「高风险规则不可用」不可判定），
> 以及 **反弱化门禁的覆盖盲区**（§9.41 —— 门禁用 `git diff --name-only`
> 取文件，**只含已跟踪**的；实测 **103 个未跟踪的测试文件、2935 条断言**
> 在它的射程之外，而原来的输出看起来像「全查过了」），
> 以及 **因果调整集的组合族不完整**（§9.42 —— §三.1「检查**所有**符合理论
> 条件的候选调整集」只落地了一半：候选**池**全了，候选**组合**没全；
> 实测存在合法调整集时仍报「不可识别」，**漏报**方向），
> 以及 **MCP 工具把「模拟执行」报成「成功」**（§9.46 —— 6 个执行器全是模拟实现，
> 却返回 `status: success` +「已封禁 …」/「扫描完成 … **发现0个漏洞**」；
> 而这条路径是**活的**（`POST /api/audit/guard/call`，需 JWT 鉴权），
> `rate_limit` / `vulnerability_scan` 会被**直接放行**并真的落到模拟器 → **谎报成功**）。
> 以及 **TLS 挂起会话在缓冲区溢出时被静默丢弃**（§9.43 —— 同一模块里
> 「超时」路径会落库+计数，「溢出」路径却直接 `pop` 掉：C2 检测的证据
> 在**高峰期**无声消失，而 `stats` 还**没有消费方**；已改成照样落库+计数+指标），
> 以及 **22 个活跃叶子模块零测试覆盖**（§9.44 —— §十三「全量回归」行的隐含前提
> 「测试能覆盖到生产路径」实测**不成立**：193 个活跃模块里 22 个（170 KB）
> 在 `tests/` 里**连名字都没出现过**，含 `response_engine/ttl_manager.py`
> （响应动作 TTL）、`protocol_parser/tls_parser.py`（C2 会话证据的来源）、
> `phishing_guard/drill_manager.py`；已把清单显式登记并用双向相等守卫钉住
> —— §9.45 又从这份清单里挑出 `response_engine/transport.py` 并**给它补了测试**，
> 于是它已从清单中消失），
> 以及 **Windows 响应动作被平台自己的白名单全拦下**（§9.45 —— `response_registry` 调 `ssh_transport.run()` 时**没传 platform**，
> 于是用默认的 linux 规则去查 windows 命令 → **每一个** Windows 响应动作
> 都必然被拒；auto 模式下**静默降级为桩**，且拒绝原因被换成
> 「需要 SSH_HOST 配置」——把运维引向完全错误的方向）。
> §九 新增的守卫全部逐条注入验红；晚间共加 **469 条**（Q5 2 + 畸形字段类型 4
> + 重放幂等 2 + 去重键撞车 3 + 沙箱回取缺口 4 + partial 到融合层 1 + DNS 语义 3
> + 黄金样本区分度 3 + 因果识别条件 6 + 因果方向冲突 5 + DDL 标识符转义 5
> + 重定向复检 8 + 缺失 task_id 8 + 相似度契约 3 + 特征集限长 2
> + 每千条误报 3 + HTTP 载荷键集合 14 + 失败路径键集合 1
> + 检测延迟与冷启动分档 17 + 规模/窗口矩阵 14 + 陈旧边 5
> + 状态词表一致性 7 + 共享事件标记 5 + 失败阶段结构化 6
> + 自动派单结果计数 7 + 告警发布结果计数 9 + 工单审批结果计数 9
> + 快照租约 11 + 规则库三态 8 + 调整集枚举 13 + TLS 驱逐可见性 9
> + 活跃模块零覆盖 6 + 响应链路平台转发 14 + MCP 工具诚实性 12
> + 参数契约一致性 9 + 注册表隔离 6 + .env 隔离开关 6
> + 学习闭环聚类顺序无关性 10 + embedding 降级产物契约 12
> + grounding 闸门诚实性 7 + 幂等检查可见性 9
> + 自动解封机制可见性 6 + 资产保护范围可见性 6
> + 响应动作审计失败可见性 6 + 响应策略加载失败可见性 7
> + 信誉先验失败可见性 4 + 输出跨进程可复现 3 + 集合序确定性 15
> + 异常阈值可行性 11 + 告警 webhook URL 边界 16
> + 遏制适配器标识符注入 16 + 审计 URL 密钥脱敏 14
> + 沙箱 URL 样本指纹 11 + 既有 strict-xfail 前提守卫同步 2
> + 门禁覆盖盲区基线 8
> + 行为阈值余量与域约束 21
> + 配置项 falsy 陷阱与评估器基线同源 19
> + 限流命名空间耦合 12
> + 限流两个缺陷的耦合约束 6）。
> **这个总数是明细逐项相加的结果** —— 原先写的「48 / 64 / 85」三个数
> 与各自明细都**对不上**（48 漏了「重定向复检 8」，64 少算 8，85 沿用了旧合计），
> 已按明细重算；明细项本身可逐个核（见 §9.26.7 的教训）。
> 其中 §9.10 那条的插桩点特意放在 **SQL 执行层**，
> 以便同一支测试能同时判定「旧行为红 / 新行为绿」。
> 当前全量回归 **`2776 passed, 18 skipped, 55 xfailed, 0 failed`**（415.55s，2026-10-20；
> 第 **50** 次全量、第 **34** 次零失败）。
> 第 49 次（`2773 passed / 0 failed`，400.03s）是 §9.69 守卫补强**之前**的基线。
> 上一轮（第 **44** 次，403.74s）有 1 条失败：
> `test_case_automation.py::TestAutoDispatch::test_audit_pipeline_path_creates_case` ——
> **既有的时序脆弱用例**（单独重跑通过 ✓、重复 12 次失败 2 次 ≈17%，
> 与已登记的 `async-timing-tests-flake-under-load` 一致）⇒ **不是本轮回归**。
> 再上一轮的 **`2716 passed / 0 failed`**（400.55s，第 43 次全量、第 29 次零失败）
> 是 §9.66 改动**之前**的基线。
> ⚠ 但**不能据此认为待决项 17 已消失**：同一份工作区本轮跑了 43 次全量，
> **29 次 0 failed、12 次 1 failed**（**9 次**是待决项 17 那一条，
> **1 次**是 §9.47 的全局单例污染、**1 次**是 §9.44 的零覆盖清单未同步、
> **1 次**是 §9.51 新增状态词未登记进 §十一.2 的词表守卫
> —— 后三次**本轮已修**，且它们的红色**位置**与待决项 17 不同）——
> 实测**单独跑也会失败 2/6**，与「是否全量跑」无关（§9.26.7）。
> ⚠ 另有 **2 次**不是 1 failed：第 38 次（3 failed）与第 40 次（2 failed）——
> 那两次的红色**全部由本轮自己的改动造成**（§9.63 的契约更正 2 条 +
> §9.64 的既有 strict-xfail 前提守卫形态 2 条），**均已修复并复验**；
> 记在这里是因为「零失败」的统计不该只算对自己有利的那些次。
> ⚠ 唯一会间歇失败的 `tests/test_case_automation.py::TestAutoDispatch::test_audit_pipeline_path_creates_case`
> 是**已登记**的待决项 17（测试库 StaticPool 单连接脏读，§9.7）。
> **⚠ 更正（2026-10-19 深夜，§9.26.7）**：本行原先写着
> 「本轮实测**单独跑 6/6 通过**、全量跑时可能失败」——
> **这句话经本轮实测是错的：单独跑也会失败。**
> 实测（每种组合跑 6 次）：
>
> | 组合 | 失败次数 |
> |---|---|
> | `test_case_automation.py` **单跑** | **2 / 6** |
> | + `test_http_dict_contract.py`（本轮新建） | 0 / 6 |
> | + `test_ingest_pipeline.py`（既有） | 2 / 6 |
> | + `test_review_anomaly.py`（既有） | 2 / 6 |
>
> 即**是否全量跑与它无关**。机制：`auto_create_case` 的 fire-and-forget
> `create_task` 与测试的轮询会话**共用 StaticPool 的同一条连接** →
> 后台任务未提交的 INSERT 可能被轮询会话的回滚丢弃 → 随后的 UPDATE
> 影响 0 行（`case_manager.py:787` 记 `auto-dispatch failed`）→ case 丢失 →
> 断言失败。**生产不受影响**（postgresql + asyncpg，真实连接池，
> 建单与派单在**同一事务**里）。本轮**未触碰** `tests/conftest.py` 与
> DB 会话层 —— 三条修复路线已实测均不可行（§9.7），仍作**待决项 17** 上交。
> 待决项累计 **51 项**（本轮新增的 17~37 共 21 项逐条列在 §9.8，§9.59.10 新增 38~40、§9.60.7 新增 41、§9.61.8 新增 42~43、§9.62.8 新增 44~45、§9.63.6 新增 46、§9.64.7 新增 47、§9.65.6 新增 48、§9.66.8 新增 49、§9.67.7 新增 50、§9.68.8 新增 51 共 14 项；更早的 1~16 分散登记在 §6.2 与 §7.1.x 各节 —— ⚠ 那部分**没有单一口径的台账**，且 12~16 号在报告里查不到，见 §9.37.5）。

---

## 一、验收维度逐条结论

文档 §十三 列出 8 个验收维度。下表逐条给出结论与**证据位置**。
「已验证」= 有对应回归测试且当前全绿；「待验证」= 本机环境不具备验证条件。

> **用例计数是快照，不是活数字。** 表里每个「N 例」都是写下的那一刻的实测值，
> 后续加用例就会过期。2026-10-19 做了一次**全量核对**（把报告里 32 个测试文件的
> 计数断言逐条与 `pytest --collect-only` 的实际收集数比对），发现 9 处过期并已更正；
> 其中 6 处是本轮新增守卫导致，3 处（`test_causal_chain` / `test_metric_wiring_guard` /
> `test_review_contract_fusion`）**早于本轮就已经失真**。
> 核对脚本的形态是「提取断言 → 逐条比对 → 打印不一致」，可重复执行；
> 它刻意**没有**做成常驻回归测试 —— 32 次 `--collect-only` 的代价远大于收益。
> **2026-10-19 晚间再核一次**：本轮新增/修改了 5 个测试文件后重跑该核对，
> 报告里 24 个文件的计数断言与实际收集数（177 个文件 / 2400 条）**逐条一致**。
>
> **2026-10-19 深夜再核一次**：核对脚本的正则原来只允许
> 「文件名 + 空白/星号 + 数字 + 例」，于是
> 「`tests/test_detection_latency_metric.py`（**17 例**）」这种**中文全角括号**的写法**根本匹配不上** ——
> 那条断言等于**没进检查范围**。正则加宽到 `[^0-9A-Za-z]{0,6}` 后，
> 覆盖从 25 个文件升到 **44 个文件**（实际收集 **187 个文件 / 2525 条**），
> 并当场查出 **2 处真过期**（`test_eval_metric_completeness.py` 的「7 例」实为 13、
> `test_http_dict_contract.py` 的「13 例」实为 14）—— 均已更正。
> 另有 2 处「不一致」是脚本取了**历史旧值**（报告写的是「由 9 例扩到 13 例」，
> 正确）—— 属脚本的「取首次出现」规则，不是报告错。

| 验收维度 | 结论 | 证据 |
|---|---|---|
| 检测状态语义 | ✅ 已验证（**消费侧有例外**） | `detection_contract.py` 五态契约；**§十一.2「状态词表保持一致」已固化成门禁**（扫描范围自动推导 + 显式登记表 + 登记表反向检查 + 4 条前提守卫，实测检测链路上非规范且未登记的状态词 **0 处**，见 §9.31）；⚠️ **2026-10-20 深夜**：§二 验收要求 3 的「**在哪个阶段**失败」此前只以 `error_message` 的方括号前缀存在、`error_summary()` 根本没输出该字段（尽管它的 docstring 承诺了）—— 已提成**结构化字段** `phase` 并加守卫，见 §9.33；`tests/test_review_contract_fusion.py` 28 例；Sigma 单规则失败不再静默变 `not_detected`，且**到融合层**仍被标 partial、禁止按阴性收口（§9.15）；因果 verdict 五态互斥。⚠️ 状态传播的**数据层**已闭合，但承载它的两个指标在仪表盘/告警里零出现 —— 见 §7.1.15。⚠️ 关联引擎此前是**唯一**还在报二态的（模式匹配全崩时上报 `not_detected`，与真实阴性同形），本轮已修 —— 见 §2.5.1 |
| 安全入口 | ✅ 已验证 | `tests/test_review_sandbox_security.py` **87 例**（含 URL / task_id 拒绝用例、状态映射、报告缺失≠clean、以及越界 CAPE 评分的显式契约；原「22 例」的说法早于多轮补齐）。⚠️ **2026-10-19 晚间补**：URL 校验组此前依赖**实时 DNS**（结论由环境决定），已改为离线可跑，并补上「DNS 解析到私网 IP 必须被拒」这条从未被测过的安全性质 —— 见 §9.16 |
| 账号入口 | ⚠️ **未验证：闸门从未实现** | `/api/auth/register` 无条件在 `app.py:432-438` 的 `_PUBLIC_PATHS` 里，不需凭证；`routers/auth.py:115-172` 无任何开关判断；`.env.example:45` 出货的 `SHARED_MEMORY_ALLOW_SELF_REGISTRATION=false` 是空操作，`config.py` 无该字段、全仓零读点。**无提权**（role 硬编码 `viewer`）、admin 用户名被拒、限流 best-effort（Redis 挂了就失效）。守卫 `tests/test_self_registration_gate.py`（5 passed / 3 strict xfail）。**影响面已在 §7.1.12 补齐：管理员不受影响，但前端有完整自助注册入口**。见 §7.1.12 |
| Sigma 正确性 | ✅ 已验证 | `tests/test_review_sigma_detector.py` **36 例** + `tests/test_sigma_snapshot_lease.py` **11 例**（本轮新增）+ `tests/test_sigma_rule_library_states.py` **8 例**（本轮新增）；每次检测独立 `sqlite3.connect(":memory:")`；`stats()` 暴露 `run_mode` / `load_errors` / `compiled_count`；**恶意字段名不得破坏建表**（§9.20，此前零回归）。⚠️ **单条规则执行失败原先在并发下会被洗成完整阴性**（错误通道走实例属性，跨线程串扰），本轮已修 —— 见 §9.10。⚠️ **2026-10-20 凌晨**：§六 第 5 条「旧快照只在不再被执行任务引用时释放」**没有落地** —— 释放判据是**代数**（延迟一代）而不是引用，持有 retired 快照的执行任务在两次 reload 后拿到的是**已关闭的连接**；已改成引用计数租约，见 §9.39。⚠️ **同晚**：§六.2 的规则库「三态」其实**只有两态** —— 「部分规则未加载」也报 `normal`，且 `load_errors` 没有 `severity` → 「高风险规则不可用」不可判定；已修，见 §9.40 |
| Flink 作业 | ✅ 已编译 + ✅ **窗口逻辑已真执行** / ⚠️ **未在集群运行** | `mvn compile` BUILD SUCCESS（15 源文件），回归 `test_flink_jobs_compile`；另用进程外 harness 驱动**真实** `ThresholdWindowFunction` 跑真实载荷，17 条断言（阈值方向、`threshold=0` 不退化、窗口内取最严、跨语言字段契约），见 §三.4 |
| 异常检测 | ✅ 已验证 | `tests/test_review_anomaly.py` **25 例** + `tests/test_anomaly_rarity.py` 9 例 + `tests/test_anomaly_timezone_fallback.py` **11 例** + `tests/test_anomaly_replay_determinism.py` **41 例**（重放一致性 / 冷启动的主力守卫，**此前报告从未提过这个文件**）（本轮新增：时区回退静默 + 载荷上报谎报，见 §2.4.1；**畸形字段类型导致分析路径崩溃**，见 §9.11；**重复投递改变后续事件评分**，见 §9.12；**去重键撞车使第五维结构性失效**，见 §9.13） |
| 关联引擎 | ✅ 已验证 | `tests/test_review_correlation.py` 39 例（含总跨度、chain_id 稳定性、去重确定性）+ `tests/test_correlation_partial_contract.py` **15 例**（本轮新增：模式匹配异常不得被编码成真实阴性，见 §2.5.1）；⚠️ **2026-10-20 深夜**：共享事件标记（`shared_event_ids`）**从未送到下游** —— 引擎算好了但两个序列化点都丢了，§八「下游不得把同一事件算成两份证据」因此**无法执行**（今天前端没有跨链累加，所以是潜在风险而非已发生的错误数字），已修并加静态守卫（将来新增出口也会被抓到），见 §9.32 |
| 因果推断 | ✅ 已验证（离线） | `tests/test_causal_chain.py` 11 例 + `tests/test_causal_api.py` 2 例 + `tests/test_causal_provenance.py` 10 例 + `tests/test_causal_path_gate.py` **13 例**（本轮新增：`path_ok` 未真正闸住 `causal_support` §2.5.2、前端五种判定被压成一个词 §2.5.3）+ `tests/test_causal_identification.py` **6 例**（本轮新增：§三.2「不可识别时不得输出 ACE」此前**完全没有回归**，见 §9.18）+ `tests/test_causal_consensus_conflict.py` **5 例**（本轮新增：§三.3「A→B 与 B→A 不得同时输出」此前**完全没有回归**，见 §9.19）+ `tests/test_causal_adjust_candidate_completeness.py` **13 例**（本轮新增：§三.1「检查**所有**符合理论条件的候选调整集」只落地了一半 —— 候选**池**全了但候选**组合**没全，实测存在合法调整集时仍报「不可识别」，漏报方向，见 §9.42）；前端护栏 `frontend/scripts/securityUxFixes.test.ts` 第 4 组 5 例（CI 会跑） |
| 零日与聚类 | ⚠️ **规则已验证，但生产未接线** | 沙箱提交/轮询/状态机已验证（22 例）；沙箱状态词表完整（8 态 + verdict_capable/inconclusive 分列）。**但 `behavior_analyzer.analyze()` 与 `variant_cluster.*` 在生产代码里零调用方** —— 报告拿到后没有任何东西解读它，`variant_cluster.stats` 恒为全零。见 §7.1.4。⚠️ **2026-10-20 深夜**：变种聚类的「陈旧边」已修 —— 同一 hash 被不同特征覆盖时旧边残留，**增量构建 ≠ 全量重建**，会把 Jaccard=0 的两个样本判成同族（§十.2 的「同样本集合」要求），见 §9.30。⚠️ **2026-10-19 晚间补**：沙箱的**「结果回取半边」**（poll / wait / fetch_report / get_task_status）生产零调用 —— 提交进去的任务永远拿不到结果，`SandboxTask` 恒为 `pending`（与 §7.1.9 的「写回那半边」合起来才是完整缺口），见 §9.14 |

> **⚠ 这张表有一条全局限定条件，必须一起读（本轮查证，见 §7.1.5）**
>
> 上表的「已验证」指的是**规则正确**：契约对不对、边界条件守不守得住、
> 会不会静默降级。这**不等于**该能力在生产里被执行过。
>
> 全仓 AST 普查发现 **20 块能力在生产代码里零调用**（`behavior_analyzer`、
> 整个 `threat_intel`、`session_reconstruct` 三件套、三个处置适配器、
> `traffic_profiler` / `peer_group`、`suricata_connector`、`mitm_proxy`、
> `llm_correlation`、`red_agent` 等）。
>
> 对这些能力，「已验证」的正确读法是：
> **「实现是对的，但没人调它」** —— 拿它当验收依据是不成立的，
> 前提必须是接线。§7.1.4 已据此把「零日与聚类」从 ✅ 改为 ⚠；
> 新增 `tests/test_dormant_modules_guard.py`（7 passed / 22 xfailed）
> 把这 20 块逐个登记，**接线即转红**。
>
> **⚠ 2026-10-20 凌晨补一条相反方向的限定**：上面说的是「实现了但没人调」；
> 这次查的是**「有人调、但测试够不着」** ——
> 全仓 AST 普查发现 **22 个**被**包外**生产代码引用的**叶子**模块，
> 在 `tests/` 里**连名字都没出现过**（合计 170 KB），含
> `response_engine/ttl_manager.py`（响应动作 TTL）、
> `protocol_parser/tls_parser.py`（C2 会话证据的来源）、
> `phishing_guard/drill_manager.py`、`rag/seeder.py`（44 KB）。
> §9.43 挖出的「C2 证据在高峰期被静默丢弃」就藏在其中一个模块里。
> **这份清单已经在缩短**：§9.45 从里面挑出 `response_engine/transport.py`
> （响应动作的执行通道）并给它补了 14 条守卫 → 它已从清单中消失。
> ⚠ 另有 8 个 `routers/` 下的 HTTP 入口同样没被 import，
> 但它们很可能已被**端点级测试**覆盖 → **不**据此下结论。
> 扫描器已入库（`tools/scan-active-zero-coverage.py`），清单用
> `tests/test_active_module_coverage_gap.py`（5 例）**双向相等**钉住 ——
> 补了测试要同步登记，新增缺口也要登记。详见 §9.44。
>
> **该清单已产生第二个用户可见后果**：能力看板「威胁情报」那块
> 的 count 读的是休眠路径的自增点，而活着的 IOC 匹配写在另一个计数器上，
> 于是**恒显示「已启用 · 0 条」**。见 §7.1.6。
| 量化评估 | ⚠️ **部分达标** | 已建标定集与评估器并产出 P/R/FPR/PPV（§四）；据其结果修掉 Sigma 3 条良性误报（FPR 0.300 → 0.000）。但**这是合成标定集，不是生产黄金样本**；生产流量基线仍未测。⚠️ 两套黄金样本**观测到的**误报/漏报恒为 0（12/9 条全对）→ 测不出真实误差率；但数据集**有区分度**（恒判主类别的平凡检测器会错 7/12、6/9），已用守卫钉住 —— 见 §9.17；**§七 要求的「每千条事件误报量」此前根本没报**，本轮补上（`false_positives_per_1k_benign` 与按基准率分档的 `false_positives_per_1k`）—— 见 §9.25 |
| 全量回归 | ✅ 已验证 | 最新一次：**`2716 passed, 18 skipped, 55 xfailed, 0 failed`**（400.55s，2026-10-20；第 43 次全量、第 29 次零失败）。⚠️ 同一份工作区本轮 43 次全量里 **12 次出现 1 failed**（**9 次**是待决项 17；**1 次**是 §9.47 的全局单例污染、**1 次**是 §9.44 的零覆盖清单未同步、**1 次**是 §9.51 新增状态词未登记 —— 后三次本轮已修）。⚠️ **「原有测试没有通过删除断言或放宽安全要求来人为变绿」这一条此前无人判** —— 本轮首次逐 hunk 审计 18 个被改测试文件，查出 **1 条真弱化**（键集合等式被改成子集断言）并已修复，且已固化成 CI 门禁 `tools/assert-no-assert-weakening.py`（自带 7 个已知答案自检）—— 见 §9.26。⚠️ 唯一会失败的是已登记的待决项 17（**单独跑也会失败 2/6**，非全量专属）—— 见 §9.26.7。`xfailed` 全部是 **strict xfail 缺口标记**，刻意可见而非隐藏，逐条登记在各 §7.1.x 小节（休眠能力、配置开关、情报落库、沙箱任务死胡同、签名持久化、公开注册闸门、`.env.example` 元规则、指标消费面、API 契约、DLQ 接线）。**全部 strict xfail 均配 `raises=AssertionError`**（见 §12.5），确保「守卫在崩」不会被记成「缺口仍在」。本轮新增：标定回归 detection 27 + grounding 35 + **behavior 46**（§4.4/§4.7/§4.8）+ CI 门禁 13（§6.6）+ 指标消费守卫 4（§7.1.15）+ API 契约守卫 6（§7.1.16）+ **关联部分失败契约 15（§2.5.1）** + **因果 path_ok 闸 13（§2.5.2/§2.5.3）** + **Kafka 字段范围缺口守卫 20（§7.1.19）** + **时区回退守卫 11（§2.4.1）** |

> ⚠ **复现全量回归前必须先把 Maven 放进 PATH**，否则会静默少跑 18 条：
>
> ```powershell
> $env:PATH = (Join-Path $env:TEMP 'flinkbuild\apache-maven-3.9.9\bin') + ';' + $env:PATH
> ```
>
> 不加这一行，`test_sigma_aggregation_action_chain.py` 里的 17 条窗口层真执行
> 断言 + 1 条真编译会以「未安装 Maven，跳过」全部 skip，而 pytest 的退出码
> **仍然是 0** —— 报告上写着「0 failed」，实际少跑了 18 条真执行断言。
> 这与本轮修的 `inc_intel_ioc` 是同一类缺陷：**量具读数与「一切正常」同形**
> （详见 §6.3.1）。CI 侧已由 `flink-verification` job +
> `tools/assert-junit-no-skip.py` 核对 JUnit XML 来覆盖。
> ⚠️ 本轮又查出该脚本把 xfail 与 skip 混为一谈并已修复，详见 §6.6。
>
> 本机踩到的具体情形：便携 Maven 曾被 `%TEMP%` 清理掉，只剩 `maven.zip`，
> 重新 `Expand-Archive` 即可恢复（`~/.m2/repository` 的 666 个 jar 未丢）。

---

## 二、已验证：各批次的实测数据

### 2.1 提交 A — 统一检测契约与融合层 fail-open

- 新增 `detection_contract.py`：`DetectionStatus` 五态
  （`detected` / `not_detected` / `inconclusive` / `error` / `partial`）、
  `AnalysisStatus.build()`、`combine_status()`。
- 实测状态合并语义：`(error, detected) → partial`、
  `(inconclusive, not_detected) → inconclusive`、`(error, error) → error`。
- 融合层不再 fail-open：critical Sigma 命中 + anomaly 失败 → 仍 P0 / 走 LLM 分析。
- `audit_triage.py` 新增 `elif analysis_incomplete:` 分支，**禁止** `LANE_RULE_CLOSE`。

### 2.2 提交 B — 沙箱安全入口与任务状态机

- 8 个任务状态常量，`VERDICT_CAPABLE_STATUSES = {completed}`。
- `sample_hash` 现在随 outcome 返回并按 `_by_hash` 索引回连（修复前算了就丢）。
- `_extract_task_id()` 缺失即 `failed/missing_task_id`（修复前 `str(None)` → 字面量 `"None"`）。

### 2.3 提交 C — Sigma 引擎

- 不可变快照 + `_publish_snapshot()` + **按引用**释放 retired 连接
  （`_ConnLease` 引用计数；修复前是**代数**判据 —— 两次 reload 后
  在途执行任务拿到的仍是**已关闭的**连接，见 §9.39）。
- `detect()` 每次检测一个**私有** in-memory 连接（不做全局锁）。
- `_quote_ident()` 转义标识符内双引号。
- 规则库三态（§六.2）：`normal` / `degraded` / `unavailable`，
  并新增 `degraded_reasons` 说明**为什么**降级 ——
  修复前「部分规则未加载」也报 `normal`（§9.40）。
- `load_errors` 每条都带 `severity`：规则已知时是**真实级别**，
  未知时是显式的 `"unknown"` —— 没有它，「高风险规则不可用」不可判定。
- 稳定规则 ID：`x-soc-id` → Sigma 稳定 id → 内容指纹 `SIG-<sha1[:10]>`，
  冲突按 `id#1` / `id#2` 确定性消歧。
- `KEYWORD_FIELDS` 由 6 个扩到 30+，新增 `NUMERIC_FIELDS`；
  `convert_condition_val_num` 改为 `CAST(field AS REAL) = literal` 数值相等。
- 规则执行错误与**本轮检测绑定返回**（`_detect_with_errors()`），
  不再走实例属性通道 —— 原通道在并发下会把失败洗成完整阴性，见 §9.10。

### 2.4 提交 D — 异常检测（本轮改动最大）

| 问题 | 修复前 | 修复后 |
|---|---|---|
| 重复方法定义 | 新 `analyze()` 写完后旧副本**又定义在后面**，生产路径一直在跑旧代码 | 截断删除，旧副本清零（34451 → 30397 字节，`async def analyze` 计数 = 1） |
| 冷启动误报（新引入后自查发现） | 「剔除 + 重新归一」使新实体只剩 `severity_prior` 时被归一成 **1.0 分直接告警** | 证据维度分母恒为 `EVIDENCE_TOTAL`，上下文只加成；无证据时封顶 `COLD_START_SCORE_CAP=0.59 < 阈值` |
| 滚动窗口时均口径 | `window_total / 24.0` 是**日均**：稳态 50 条/小时算出「均值 350」，σ 恒 0，**7 倍真实突增完全看不见** | 用实际跨度小时数做分母（上限 `window_days×24`） |
| 基线年龄灵敏度 | 触发 3σ 所需突增：1 天 21 / 7 天 54 / 30 天 112 / 60 天 158（**越老越安全**） | 实测 22 / 22 / 22 / 22，**与年龄无关**；7 倍突增 → σ = 10.0 |
| 旧基线（无 `recent`） | 滚动桶为空 → `hour_total` 恒 0 → σ 恒 0（**静默全量漏报**） | 新增 `_legacy_sigma()` 回退口径；无可比较基准时返回 `None` |
| rarity 标度 | `1 - ratio*100`，魔法数 100 → 10:1 不平衡判 0 | `1 - ratio/uniform`；10:1 → 0.82，100:1 → 0.98 |
| rarity 标度（中途方案） | 对数写法 `1+log10(uniform/ratio)` 在该分支恒 ≥ 1，**永远夹到 1.0**，连续区间不可达 | 已弃用，改线性相对口径 |
| 样本不足 | 返回 `0.0`，与「确定无偏离」同值 | 返回 `None`，并记入 `inconclusive_dimensions` |
| 重放 | 6 次重放得 4 种分数，`is_anomaly` 翻转 | 分数稳定，`reasons` 留 `replay:baseline_not_updated` 痕迹 |
| 窗口淘汰基准 | 用事件时间戳做 cutoff → 发旧时间戳可让过期桶**无限续命** | 改用墙上时钟 |

#### 2.4.1 §四：时区解析的**回退路径**静默，且载荷在撒谎（本轮修复）

P0-4 的主体修得是对的：默认时区 `Asia/Shanghai`、用**事件自身时间戳**
（`event_dt.astimezone(self.tz)`）、时区可配置。
本轮核 §四 第 6 条「建立边界用例」时发现**同一修复的尾部漏洞**：
时区解析有三条回退路径，其中一条**既不告警、又让载荷写出与实际计算不符的时区名**。

##### 实测（修复前）

| 场景 | `_resolve_tz` 返回 | 日志 |
|---|---|---|
| `Asia/Shanghai`（本机 tzdata 齐全） | `Asia/Shanghai` | 无（正常） |
| 未知名 `Mars/Olympus` | `UTC` | **有** WARNING |
| **`_HAS_ZONEINFO = False`** | **`UTC`** | **无 —— 完全静默** |

修复前的代码是 `if not _HAS_ZONEINFO or not name: return timezone.utc`，
把「zoneinfo 不可用」和「时区名为空」两条路径并成一行，都没有日志。
而第一条回退到的**正是 §四 要消灭的服务器 UTC 钟点**：

> 缺 `tzdata` 的机器（Windows、精简 Linux 镜像）上，配好的 `Asia/Shanghai`
> 根本不生效，北京白天上班被判「非活跃时段 +0.4」、北京凌晨拿不到加分 ——
> **P0-4 缺陷本身原样复活，而且一行日志都没有**。

实测复现：同一事件（北京 10:00 = UTC 02:00）在回退后取到的小时是 **2** 而不是 10。

##### 更糟的一层：载荷在撒谎

结果载荷原本无条件写 `"timezone": self.timezone_name`（配置值），
而实际打分用的是 `self.tz`。在上述场景下它会写出
`"timezone": "Asia/Shanghai"`，实际按 UTC 打分 ——
排查时序评分异常的人看到这行会认为时区语义正确，从而找错方向。

这与 §6.3.1 的 `inc_intel_ioc` 是同一个家族：
**量具读数与「一切正常」同形**，只不过这里更糟 ——
它不是缺失，而是**主动写了一个错误的值**。

##### 改法

1. `_resolve_tz` 的 `not _HAS_ZONEINFO` 分支补 WARNING，与未知时区名那条对齐；
2. 载荷改用 `timezone_audit()`，同时给三个字段：
   `timezone`（**实际生效的**）、`timezone_configured`（配置值，即使没生效）、
   `timezone_fallback`（两者是否不一致，运维告警入口）。

`["timezone"]` 这个键全仓**零消费方**（已全仓搜过），
所以改它的值不破坏任何调用点；它同时也是「字段在、没人读」的又一例。

##### 一次注入抓出「守卫没连到它保护的东西」

第一版守卫 8 例，全绿。但注入把两处 `**self.timezone_audit()`
换回 `"timezone": self.timezone_name,`（命中 2）之后，
**8 条依然全绿** —— 因为它们直接调 `timezone_audit()` 这个方法，
而那个方法本身仍然是正确的。

> **方法对、接线错**，而测试只测了方法。守卫没有连到它声称保护的东西。

补了 `TestThePayloadItselfTellsTheTruth` 三条：跑真实的 `analyze()`，
检查真正写进 `report.analysis_window` 的内容。补完后重做注入：

| 注入 | 转红 |
|---|---|
| A：载荷改回上报配置值 | **3 条** |
| B：删掉 `not _HAS_ZONEINFO` 的 WARNING | **1 条** |

守卫文件 `tests/test_anomaly_timezone_fallback.py` 共 **11 例**，
两次注入按字节还原，sha256 `14cf580867431dd7` 一致；
该文件是 CRLF（926 CRLF / 0 混合），行尾保持不变。

##### 顺带记一笔

`test_the_fallback_actually_changes_scoring` 第一版把对照组也建在
`no_zoneinfo` fixture 的 monkeypatch 作用域内，于是**第二个 detector
同样回退到 UTC**，对照断言变成同义反复。已改成直接用
`ZoneInfo("Asia/Shanghai")` 作对照，不经过任何回退路径 ——
对照组一旦也走被测代码路径，它就不再是对照。

异常检测相关回归 57 例全绿；全量回归
**`2241 passed, 1 deselected, 53 xfailed, 0 failed`**（145.17s，exit 0），
相对上一轮的 2230 正好 **+11**，与本节新增的 11 条用例逐位对齐。

### 2.5 提交 E — 关联与因果

**因果（compare.py）** verdict 改为文档 §三.1 的五级判定顺序：

```
data_available → identifiable → statistical_support → path_ok
```

实测：修复前 `data=None` 也能拿到 `causal_support`；现在返回 `insufficient_data`。

**因果（do_calculus.py）** 修复前 `extra` 候选集过滤条件
（`not in preferred and is_confounder(n)`）**互斥，该分支恒空** ——
只有先验声明的 2 个混杂变量可能被调整。实测：合成 U（未观测混杂）+ Z（可观测）
场景下，修复前空调整集给出 +0.2783 并标 `identifiable=True`；现在自动选出
`z=['HOUR_NIGHT']`，ACE = **0.6653**（真值 ≈ 0.55）。声明未观测混杂后
诚实返回 `not_identifiable / unobserved_confounding`，不输出 ACE。
每次识别结果落库 `graph_version`（边序无关指纹）+ `assumptions`。

**因果（ges.py）** `"undirected": []` 硬编码改为按 v-结构判定 compelled；
`consensus()` 消掉 A→B 与 B→A 同时输出的矛盾；每条边带
`orientation` / `orientation_source` / `identifiability`。

#### §9.42 因果调整集枚举：组合族不完整 → **存在合法集却报不可识别**（本轮新增）

- §三.1「检查**所有**符合理论条件的候选调整集」此前只落地了一半：
  候选**池**变成全部可观测变量了，但候选**组合**只有五族，
  「先验混杂的子集 + 其它变量的多个」这一族一个都没生成过。
  实测（三条独立后门）：修前 `backdoor_set` 返回 `None` → 判「不可识别」，
  而合法集 `[HOUR_NIGHT, N1, N2]` 确实存在 —— **漏报方向**。
- 修法：补全组合（第二梯队），**接在原有五族之后** →
  顺序即优先级 → **既有判定一条都不变**，只有原本「弃权」的情况才变。
- 枚举改成**惰性**：命中即停，实测 **0.366 → 0.186 ms/次**（反而更快）。
- 顺带披露候选池被 `MAX_ADJUST_POOL` 静默截断的变量数。

#### §九.2 点名的 G² 覆盖维度 —— 本轮补齐（本轮新增）

整改方案 §九.2 原文：

> G² 相关测试应覆盖**低频稀疏数据、不同条件集大小、不同自由度和边缘概率**，
> 并检查**输出图的骨架与方向状态**是否符合预期。

逐条核对后：**这四项此前一条都没有**。原有因果测试 8 条里，
与 G² 相关的只有骨架一条。所以这是**未兑现的要求**，不是「已验证但没写清楚」。

新增 `tests/test_g2_statistical_coverage.py` 42 例：

| 文档要求 | 用例 | 钉住的行为 |
|---|---|---|
| 不同自由度 | df 1~8 逐点对照 scipy、df 单调性、条件集使 df>1 | 修复前的 erfc 兜底只在 df=1 正确 |
| 低频稀疏数据 | 事件从未发生 → NaN + `all_strata_degenerate`；事件出现过 → 照常算 p | 两个方向都要钉：稀疏 ≠ 不可判定 |
| 边缘概率 | 0.5 / 0.25 / 0.05 三档，完全等价的变量必须显著 | 偏斜不得突然退化成 NaN |
| 不同条件集大小 | `max_cond` 0~3 扫参 | 骨架只能变稀、不能凭空长边；真边在每档都存活 |
| 骨架与方向状态 | 定向/未定向互斥、两者覆盖全部骨架、collider 可定向 | 见下 |
| §九.2「不要保留改变 p 值的备用实现」 | df 1~40 × 8 个统计量对照 scipy（<1e-9）+ **反向证明** | 见下 |

三点值得单独说：

1. **兜底验证从手工升级为回归**。无 scipy 的 χ² 兜底此前只做过一次性
   手工比对（560 点），手工验证留不下回归 —— 下次有人改
   `_gammaincc`，没有任何测试会红。现在固化成逐点对照，并加了
   **反向证明**：断言我们的兜底**不等于** df=1 的 erfc 公式，
   且那个 erfc 公式确实与 scipy 有显著偏差（否则这条断言本身失去意义）。

2. **无 scipy 与有 scipy 必须给出同一张图**。§九.2 原始抱怨是
   「安装与不安装 SciPy 时学出的图不一致」，现在用端到端对照钉住
   （骨架与定向边集合逐项相等）。

3. **一条断言写错过，值得记下来**。我最初写「真实链 A→B→C 必须被定向」，
   实测 `directed=[]`。查证后确认：**这不是缺陷，是 PC 的教科书行为** ——
   没有 collider 时 {A→B→C, A←B←C, A←B→C} 属于同一个 Markov 等价类，
   数据根本无法区分。**强行定向才是缺陷**，因为那会让下游把猜出来的方向
   当成有数据支持的因果结论（正是 §九.3 禁止的）。
   现在正向断言「链必须留作未定向」，并补一条 collider 用例证明
   **有依据时确实能定向** —— 否则第一条会退化成「永远不定向」。

另外顺带发现 §十一 的 `stats.untestable_pairs` 之外，
`g2_pvalue` 的 `tally` 出参已把不可判定拆成
`same_var` / `too_few_rows` / `all_strata_degenerate` 三类 ——
样本不足与分层退化是两种运维问题，合成一个数字就找不到方向。
本次新增用例把这三类分别钉住（`test_too_few_rows_is_counted_separately` 等）。

#### §九.1 / §十一.2 的「记录统计后端」—— 本轮补齐（此前完全未落地）

两份文档各写了一次同一件事：

> 统一并记录统计后端、依赖版本和检验参数。
> 记录实际算法版本、统计后端和规则版本，确保结果可追溯。

核对结果：**此前完全没有落地**。`learn_from_matrix()` 的返回里没有
统计后端、没有依赖版本，`max_cond` 甚至**不是参数**（固定走默认值，
既无法记录也无法在调用侧复现同一张图）。

为什么这不是整洁问题：修复前的 χ² 兜底对任意 df 都套用 df=1 的公式，
它**改变 p 值**。也就是说同一份数据，在装了 scipy 和没装 scipy 的机器上
可能学出不同的图 —— 而两张图在输出里长得一模一样，没有任何痕迹能解释差异。
「结果可追溯」在这里是字面意义上的空话。

已落地：
- `pc.stat_backend()` → `{"chi2": ..., "scipy_version": ...}`，
  进 `pc_learn(...)["stats"]`；
- `pc.test_parameters(alpha, max_cond)` → 进同一个 stats；
- `learn_from_matrix(..., max_cond=...)` 变成真参数，返回新增
  `provenance`（算法列表 + χ² 后端 + scipy 版本 + alpha + max_cond）。

新增 `tests/test_causal_provenance.py` 10 例，其中最关键的是
`test_pc_stats_backend_flips_with_the_backend`：切到兜底后端后
`chi2` 字段**必须跟着变**。只断言「字段存在」不够 ——
一个恒为常量、从不反映真实后端的字段，会让两张来路不同的图看起来同样可信，
正好毁掉这条记录存在的全部意义。

> 验红时我一度用「摘掉记录再跑测试」的方式确认，抓到 7 条变红
> （`test_learn_result_carries_provenance` 等）。恢复过程里出了事故，
> 详见本轮交付说明。

**因果（pc.py）** `g2_pvalue` 在算不出来时返回 **NaN** 而非 `1.0` ——
修复前「样本不足」被当成「检验通过独立」，骨架被静默删空。
无 scipy 的兜底公式（`_gammaincc`）与 `scipy.stats.chi2.sf` 对比：
df ∈ {1,2,3,5,8,13,40} × 7 个统计量，**最大绝对误差 3.2e-15**。

**关联（correlation_engine.py）**

| 问题 | 修复前 | 修复后 |
|---|---|---|
| 跳步 | `allow_skip_missing` 默认 True → 任意步骤可跳；`lateral_movement` 无横向移动事件也命中 | 默认 False，只允许跳 `skippable` 声明的步骤；`skippable` 配置现在**真的**有区分度 |
| 时间窗口 | 只有相邻间隔上限 → 每步 29 分钟的链可跨越近 1 小时 | 11 个模式 + hub 模式均声明 `max_chain_duration_minutes`，且**严于** `gap×(步数-1)`（否则约束永不独立生效） |
| chain_id | 取「输入顺序第一条」事件 id → 插入一条无关 DNS_QUERY 就换 ID | `stable_chain_id()`：匹配事件 ID 排序指纹，与顺序无关 |
| 去重 | 只按 `len(events)` 排序，并列项随输入序翻转；共享事件被静默重复归属 | 显式排序键（事件数→完整性→置信度→chain_id），且**不改调用方列表**；共享事件写进 `shared_event_ids` |
| 模式退化 | 完全不可见 | `AttackChain.skipped_steps` / `required_steps` / `partial` |
| 被拒链 | 所有 `return None` 同一条静默路径 | `reject_reasons` 分项计数（`too_few_events` / `min_match_not_reached` / `adjacent_gap_exceeded` / `chain_duration_exceeded`） |

#### 2.5.1 §八：模式匹配异常被编码成真实阴性（本轮修复）

上表把关联引擎的六项都列成已修，但整改方案 §八 验收段还写了**一条**没人做的：

> 「另外，你报告指出 `correlation_engine.analyze()` 的部分模式异常会被日志后
> 继续吞掉。该行为应纳入统一检测契约：存在模式匹配错误时，必须标记本次分析
> 为部分失败，不能直接当成没有攻击链。」

核对结果：**确实没做**。而且它的性质不是「可观测性不足」，是 §二 的 P0 契约违规。

##### 修复前实测（不是推断）

`analyze()` 上报给 `record_detection` 的状态：

| 场景 | 修复前 | 修复后 |
|---|---|---|
| 基线：一切正常、无攻击 | `not_detected` | `not_detected` |
| **全部 11 个模式匹配器抛异常** | **`not_detected`** | **`error`** |
| 仅枢纽主机关联抛异常 | `not_detected` | `partial` |

第一行和第二行**逐位相同**。也就是说在 `soc_detection_outcomes_total` 这张
时间序列上，「匹配器全部崩溃」与「这段时间确实没有攻击」完全无法区分 ——
这正是 §二 明令禁止的「检测失败被编码成真实阴性」，
也和 §6.3.1 的 `inc_intel_ioc`（面板恒显示「已启用 · 0 条」）是同一个家族：
**量具读数与「一切正常」同形**。

枢纽主机那条更彻底：修复前它 `except` 里**只写日志**，连 `reject_reasons`
都不写，结果对象与干净路径**逐位相同** —— 跨源 Kill Chain 这条路径整个消失，
在任何字段里都看不出来。

##### 一个必须避开的命名陷阱

`AttackChain.partial` 早就存在，含义是「命中的这条链**本身跳了步**」
（模式退化，链的属性）。而这里是「引擎这次**没跑完**」（分析的属性）。
两个 partial 混用会让下游分不清该重跑分析还是该复查模式。

所以新字段刻意叫 `pattern_errors` / `hub_error`，**不叫 partial**，
并用一条守卫（`test_correlation_result_has_no_field_named_partial`）
把「不许再出现叫 partial 的字段」钉死。

##### 状态规则沿用 `detection_contract`，不自造

`detection_contract.py` 里五态词表、`INCOMPLETE_STATUSES`、`combine_status`
早就齐全，`anomaly_detector.py:679` 也已经在报真实 status —— 关联引擎是
最后一个还用二态的。所以本轮**复用**而非新造：

| 条件 | status |
|---|---|
| 有命中、无失败 | `detected` |
| 有命中、有失败 | `partial`（保留有效结果 + 标注不完整，对齐 `combine_status`） |
| 无命中、无失败 | `not_detected` |
| 无命中、**全部**模式失败 | `error` |
| 无命中、仅部分模式失败 | `partial` |

枢纽主机失败**单独**判为 `partial` 而不是 `error`：11 个模式都已给出完整阴性
证据，此时声称「一点证据都没有」是虚假的。

##### 计数语义也修了

`reject_reasons["pattern_error"]` 按（源 IP × 模式）累加 —— 1 个源跑 11 次
就是 11，10 个源跑同一个坏模式就是 110，读起来像「110 个模式坏了」。
新增 `pattern_errors` 记**去重后的坏模式数**，两个数字语义不同、都保留
（`test_many_source_ips_do_not_inflate_pattern_errors` 钉住：
3 个源 IP 下 `pattern_errors` 仍必须是 1，而 `reject_reasons` 应为 3）。

##### 没动 `ops.py`

`routers/ops.py` 是仓库既有的整文件 CRLF，必须保留。新字段全部放进
`CorrelationResult.observability` 字典里，而 `ops.py:1268` 本来就
`"observability": result.observability` —— **端点自动带上新字段，一个字节都不用碰**。

##### 验红

新增 `tests/test_correlation_partial_contract.py`（**15 例**）。
三次注入，按字节还原 + sha256 校验（`ceb7eb6a2305773f`）：

| 注入 | 转红 |
|---|---|
| A：`record_detection` 退回二态 | **6 条**（所有断言上报状态的用例） |
| B：枢纽异常退回「只写日志」 | **3 条**（`TestHubFailureLeavesATrace` 整组） |
| C：不再记录坏掉的 pattern_key | **6 条**（`pattern_errors` 恒为 0 的后果） |

其中注入 A 有一处值得记：6 条里**不包括** `test_clean_run_stays_not_detected`
与 `test_clean_run_with_a_hit_stays_detected` —— 回归用例在缺陷存在时仍必须全绿，
否则就成了「必须一直坏着才能过」的伪守卫。

全量回归：**`2197 passed, 1 deselected, 53 xfailed, 0 failed`**（146.53s，exit 0）。
相对上一轮的 2182 正好 **+15**，与本节新增的 15 条用例逐位对齐。

#### 2.5.2 §三.1：`path_ok` 没有真正闸住 `causal_support`（本轮修复）

整改方案 §三.1 给出的判定伪代码是**五级**，最后两级写得很死：

```python
elif not statistical_support: verdict = "insufficient_causal_evidence"
elif path_ok:                 verdict = "causal_support"
else:                         verdict = "unknown"
```

核对结果：`_decide_verdict` 的签名里**根本没有 `path_ok`**。
它被 `annotate_chain` 算出来、写进 `causal_path_ok` 字段，
却**完全不参与判定** —— 伪代码的最后两行整个丢了。

##### 修复前实测

构造：学到的图里只保留 `PORT_SCAN → C2_BEACON` 的**直达边**，
于是 `PORT_SCAN → BRUTE_FORCE` 与 `BRUTE_FORCE → C2_BEACON`
两段相邻步骤**在图上都不可达**（`path_ok = False`）；
而 `intervene(PORT_SCAN, C2_BEACON)` 完全可识别、ACE = **0.5955**。

| | 修复前 | 修复后 |
|---|---|---|
| `causal_path_ok` | False | False |
| `ace` | 0.5955 | 0.5955 |
| **`causal_verdict`** | **`causal_support`** | **`unknown`** |

因果图明确**不支持**这条攻击序列，下游却被告知「有因果支持」，
还附着一个漂亮的 ACE 数值 —— **结论的强度超过了数据真正支持的范围**。
这与 §九.3「不要把先验/推测当成由数据识别出来的方向」是同一类错误。

对照组（图上是完整链条）前后都仍是 `causal_support`，本修复不误伤。

##### 顺带发现一条恒真断言

`test_causal_chain.py` 里有一行：

```python
assert annotated["causal_path_ok"] in (True, False)
```

注释写着「图上可达也必须照实记录」，但 `in (True, False)` 对任何布尔值都成立 ——
**这条断言永远不可能失败**，等于没有断言。
已改成一条真能失败的不变式：`path_ok=True` 必须对应空的 `causal_missing_edges`，
`path_ok=False` 必须记录到缺边。

这也说明本轮为什么必须有 §四.8 那类**前提守卫**：`causal_path_ok` 的
「唯一消费者」就是这条恒真断言，字段有人写、有人「读」，但没人真的读。

##### `path_ok` 设为必填，而不是给默认值

如果写成 `path_ok: bool = True`，那么任何**忘记传它**的调用点都会静默放行 ——
正是这里要修的那个失效形态本身。验红证明了这一点：

| 注入 | 转红 |
|---|---|
| A：删掉 `if not path_ok: return "unknown"` | **2 条** |
| B：把 `path_ok` 改成**有默认值 True** | **1 条** |

注入 B 那一轮最说明问题：给默认值之后，**8 条行为用例全绿**，
只有签名守卫（`test_decide_verdict_refuses_to_run_without_path_ok`）转红。
也就是说这条闸在行为层面**测不出来**，只能在签名层面守住。

##### 验红与回归

新增 `tests/test_causal_path_gate.py`（**9 例**），两次注入按字节还原 +
sha256 校验（`d02f2698c992149c`）。关键一条是
`test_the_test_premise_holds`：它断言被测场景真的处在
「`identifiable=True` 且 ACE 显著」的状态 —— 否则 verdict 之所以不是
`causal_support`，可能只是因为 `identifiable=False`，
那条用例就测不到 `path_ok`，会变成永远绿的摆设。

因果相关回归 54 例全绿（`test_causal_chain` / `test_causal_api` /
`test_causal_provenance` / `test_review_contract_fusion` / 本轮新增文件）。

#### 2.5.3 §三.1 末段：前端把五种判定压成了三种（本轮修复）

§三.1 的最后一句是另一条独立要求：

> 「还应当确保前端和下游融合逻辑区分 `causal_support`、`not_identifiable`、
> `insufficient_data` 和 `unknown`，不能把这些结果统一映射成一个真假值。」

核对结果：**没做**。`SecurityAudit.tsx` 修复前是一个三支三元表达式：

```tsx
{c.causal_verdict === 'causal_support' ? '因果支持'
 : c.causal_verdict === 'spurious' ? '伪相关' : '未知'}
```

两个问题叠在一起：

| 问题 | 后果 |
|---|---|
| `spurious` **不在后端 `VERDICTS` 里**（后端只有 `causal_support` / `insufficient_causal_evidence` / `not_identifiable` / `insufficient_data` / `unknown`） | 永远不成立的**死分支**。界面让人以为存在「伪相关」这种结论，其实后端从不产出 |
| 其余四种全部落进 `'未知'` | `insufficient_data`（没数据）、`not_identifiable`（识别假设不满足）、`insufficient_causal_evidence`（ACE 不显著）、`unknown`（图不支持这条序列）**界面上完全同形** |

第二条与 §2.5.2 叠加后更糟：`path_ok` 闸修好之后，`unknown` 现在会真实地
表示「这条攻击序列在因果图上不成立」，而它与「根本没有数据」显示成同一个词 ——
运维看到「未知」时无法区分「数据没采到」和「图否证了这个攻击序列」，
而这两种情况的处置完全不同。

##### 改法

改成显式映射表，五个取值各有各的标签；表里没有的取值**直接显示原值**，
宁可难看也不谎报成「未知」：

```tsx
const CAUSAL_VERDICT_LABEL: Record<string, string> = {
  causal_support: '因果支持',
  insufficient_causal_evidence: '因果证据不足',
  not_identifiable: '不可识别',
  insufficient_data: '数据不足',
  unknown: '无法判定',
}
// 渲染处
{CAUSAL_VERDICT_LABEL[c.causal_verdict] ?? c.causal_verdict}
```

##### 跨语言守卫

这条如果只靠 code review，下次有人「顺手简化」成三元表达式就回去了。
`tests/test_causal_path_gate.py::TestFrontendDistinguishesEveryVerdict` 4 例
直接解析 `SecurityAudit.tsx` 的源码，与后端 `VERDICTS` 对账：

- 后端每个 verdict 都必须有前端标签（缺一个就转红）
- 前端标签表**不得有多余键**（多出来的就是死分支，同样是错）
- 五个标签必须**互不相同**（相同就等于又压回去了）
- 必须保留 `?? c.causal_verdict` 兜底

注入验红：从标签表删掉两项（制造「四种压成一个词」的原始形态）
→ **2 条转红**（Python 侧对账守卫）与 **3 条转红**（CI 真正会跑的 TS 护栏），
还原 sha256 `17cc5c2a02c0bb37` 逐字节一致。

> 这次注入第一次**静默没命中**：源文件是 CRLF 而我用了 LF 模式，
> 替换数 0。命中数守卫（`if ($hits -ne 1) { throw }`）当场中止，
> 源文件未被改动 —— 这正是「注入必须校验唯一命中」的理由。

##### 双份守卫，各管一段

| 守卫 | 位置 | 谁会跑 |
|---|---|---|
| TS 护栏 5 条 | `frontend/scripts/securityUxFixes.test.ts`「修复 4」 | **CI `frontend-check` job 真的会跑**（`node --test`） |
| Python 对账 4 条 | `tests/test_causal_path_gate.py::TestFrontendDistinguishesEveryVerdict` | 后端全量回归 |

两边都验过红。前端那 5 条实测 **16 passed / 0 failed**（既有 11 + 新增 5）。

后端全量回归：**`2210 passed, 1 deselected, 53 xfailed, 0 failed`**（146.06s，exit 0）。
相对 §2.5.2 那一轮的 2206 正好 **+4**，与本节新增的 4 条 Python 对账守卫对齐
（另 5 条 TS 护栏不计入后端套件）。

### 2.6 提交 F — 变种聚类与可观测性

实测（`VariantCluster`）：

| 问题 | 修复前 | 修复后 |
|---|---|---|
| 空特征 | `jaccard({}, {}) = 1.0` → 两条毫无可比特征的样本「100% 相似」 | 返回 **NaN**（不可判定），所有 `>= 阈值` 比较为 False |
| 畸形 IOC | `ioc.get("value","")` → `"net:"` 占位 token，所有畸形样本互为高相似 | 逐个校验，非法值进 `invalid_tokens`；实测 `hBAD` 有效特征只剩 `['sig:s1','sig:s2']`，且**不与正常家族同簇** |
| 顺序依赖 | 只与簇代表（最早加入的样本）比较 | 相似图**连通分量**；3 样本的 6 种排列实测簇号与分量完全一致 |
| 静默截断 | `samples[:20]` | `samples_truncated` + `total_samples`；另补 `min_similarity` / `mean_similarity` / `linkage`（单链接易链式漂移，内聚度用来发现低内聚簇） |
| 显示精度 | 只给 `round(sim,3)` → 0.4996 显示成 0.500 却未命中 | 同时给未取整 `similarity` 与 `similarity_display`，并标 `truncated` / `total_matches` |
| 重复/空 hash | 空 hash 全挤在 `""` 一个键上 | 无 hash 时用内容哈希兜底；重复提交单独计数 |

**可观测性（§十一）**：沙箱连接器 `observability()` 按终态分项计数 +
`dangling_tasks`；关联 `CorrelationResult.observability` 区分
`chains_matched` / `chains_partial` / `chains_overlapping` / `reject_reasons`；
聚类 `stats` 给出 `samples_without_features` / `duplicate_submissions`；
异常检测 `AnomalyReport` 带 `inconclusive_dimensions` / `baseline_samples` /
`event_time_source`；Sigma `stats()` 带 `run_mode` / `load_errors` /
`compiled_count`；PC 带 `stats.untestable_pairs` 与
`stats.undecidable`（`same_var` / `too_few_rows` / `all_strata_degenerate` /
`df_computed` / `df_degenerate` 分项）。

---

## 三、待验证（本机环境不具备条件）

以下 6 项**不得**按「已通过」计入验收。文档 §十三 末尾已点名其中 3 项，
其余为本轮修复过程中发现的环境级问题。

1. **真实数据库上的因果链表现**
   本机无 PostgreSQL，`events_to_matrix` 的真实字段分布、
   `pc_skeleton` 在真实稀疏度下的 `untestable_pairs` 比例、
   GES 与 PC 在真实数据上的骨架一致率均未测。

2. **真实 CAPE/Cuckoo 的任务状态**
   本机无沙箱实例。`map_cape_status()` 的状态词表只覆盖文档中列举的
   常见取值，真实实例可能返回未收录的状态词 —— 那种情况会落到
   `unknown` 而不是 `failed`，**需要用真实实例枚举一次状态词表**。
   60s / 30s 硬超时未实测。

3. **Kafka 输入的复杂字段校验（本轮已大部分关闭）**
   ~~畸形 payload~~ —— **已关闭，并因此挖出两个真缺陷**。
   查这条时发现 `_decode_kafka_value`（决定「一条消息算不算有效事件」的
   唯一判据）此前**零测试覆盖**：现有 `_ack_record` 用例传的都是已解析好的
   dict，等于「解码这一步本身」从未被执行过。

   补测试时实测出两类输入会**绕过** `except json.JSONDecodeError`：

   | 输入 | 抛出的异常 | 为什么不是 JSONDecodeError |
   |---|---|---|
   | 深度嵌套 JSON（`[`×10 万） | `RecursionError` | C 扫描器直接爆栈 |
   | 超长整数字面量（5000 位） | 裸 `ValueError` | Python 3.11+ 的 int 转换上限 |

   后果比「一条消息处理失败」严重得多：两者都会穿出 `_decode_kafka_value`
   → 穿出 `_ack_record`，而 `_settle_fetch` 调用点**只有
   `except asyncio.CancelledError`**，最终落到消费循环顶层的
   `except Exception: logger.error("consumer crashed")` ——
   **一条畸形消息就能让整个 topic 的消费循环退出**，日志只有一行，
   看起来与网络抖动无异。

   已修：`except RecursionError` 与 `except ValueError`（必须排在
   `JSONDecodeError` 之后，它是 `ValueError` 的子类）。
   顺带把空载荷的原因从「Expecting value: line 1 column 1」
   改成 `empty kafka payload`，与 `raw is None` 分支对齐。
   新增 `tests/test_kafka_decode_paths.py` 22 例；已用「只摘掉两个新
   `except`」的方式验证修复前为红（**6 failed**，异常类型正是
   `RecursionError` 与 `ValueError`，其余 16 条仍绿）。

   ⚠️ 顺着这条查下去，发现 DLQ 侧有一个**更严重、且输入即可触发**的洞，
   本轮一并修了：

   `persist_dlq_failure` 对超过 `MAX_DLQ_BYTES`（512 KB）的载荷原本
   **一律返回 `persisted=False`**。看起来是稳妥的保护，实际后果是：

   ```
   写入失败 → 调用方保留 offset → 这条 offset 永远提交不了
            → 分区水位卡死在这条消息上
            → 它后面所有消息被处理但无法提交，重启后从头再来
   ```

   **任何人往 topic 投一条 >512 KB 的畸形消息，就能让该分区的 offset
   永远不再推进** —— 一个输入即可触发的 DoS，而且日志上只表现为
   「DLQ 写入失败」，与磁盘故障无法区分。

   为什么此前没人发现：现有 `test_dlq_security.py` 测的是解密失败、
   字段注入、重放幂等，全部用几百字节的小载荷。
   **512 KB 这个上限从未被触发过，包括那条会返回 `payload_too_large`
   的分支。**

   取舍：**丢证据好过卡住整条链路。**
   - 原始字节超限 → 保留前 64 KB（畸形 JSON 的断点通常在头部），
     并把**真实长度**写进 `_dlq_raw_bytes_original`（按错误的字节数去
     捞原文是排障时最容易被骗的地方）；
   - 事件体本身超限 → `shrink_to_fit` 递归压缩，**只丢体积不丢键名**
     （必须递归：真实事件里撑爆上限的常是 `rawData` 这类嵌套结构，
     只处理字符串的话一字节都裁不掉）；
   - `payload_complete` 这一列**早就接好了** —— 重放路径读它、
     `not payload_complete` 就拒绝重放；但写入侧**恒写 True**，
     于是「记录里其实少了东西」永远不会被下游发现。现在裁剪时置 False，
     于是：记录落库（offset 能推进），但重放被挡住 ——
     重放一份被截断的消息，等于把残缺证据当成完整事件重新投回链路。

   新增 `tests/test_dlq_oversize.py` 13 例，已用「摘掉修复」的方式
   验证修复前为红（**4 failed**，红的正是接线那几条；
   纯函数助手的单测仍绿 —— 分层正确）。

   ⚠️ **仍未关闭的一项**：
   - ~~跨 schema 版本混流~~ —— **本轮已关闭**，见 §三.6。

4. **Flink 聚合作业未在集群上运行过**（本轮已部分关闭，见 §4.3.1）
   ~~作业未编译~~ —— **已关闭**：装了 Maven 3.9.9 + JDK 21 后，
   `mvn -B -DskipTests compile` 在 `flink-jobs/` 下 BUILD SUCCESS，
   15 个源文件全部编译通过（含本轮改动的
   `SigmaThresholdAggregationJob` 及其两个嵌套类），
   已固化为回归 `test_flink_jobs_compile`。

   ~~窗口逻辑未经执行~~ —— **本轮已关闭**：新增进程外 harness
   （`flink-jobs/src/test/java/com/soc/job/SigmaWindowHarness.java` +
   同包 shim `SigmaWindowTestContexts.java`），用**真实 Java 进程**驱动
   **真实的** `ThresholdWindowFunction.process`，喂**真实载荷**。
   17 条断言覆盖：阈值比较方向（含反向证明）、`threshold=0` 不退化、
   窗口内取最严动作/严重度（且与到达顺序无关）、输出字段齐全、
   以及 **Python 生产者 → Java 消费者**的跨语言契约
   （载荷由 `_agg_payload` 真产出）。这些断言已逐条验证在修复前的
   Java 代码上**是红的**（`git stash` 回退到 HEAD 后 24 failed）。

   **仍未关闭的只剩集群语义**：5m/1m 滑动窗口的边界分配、同 key 并发、
   水位线推进、处理时间 vs 事件时间的选择，都需要真实 Flink 运行时。
   这一条要紧，因为本轮修复把封禁决定权交给了聚合层。

   **「在 CI 上生效」这一层也是本轮才发现的**：加完 harness 才注意到，
   `backend-test` job **没有装 JDK/Maven**，`~/.m2` 是空的 ——
   `test_flink_jobs_compile` 与上面 17 条断言在 CI 上会**全部静默 skip**，
   而 pytest 的退出码在「全部通过」与「全部跳过」两种情况下**都是 0**。
   `flink-build` job 虽装了 Maven，但它是独立 job，缓存不共享给 pytest。

   也就是说：一个只在本地跑过一次的验证，在 CI 上是个恒绿的门禁。
   这与本仓库 `mcp-arg-injection`（`|| echo` 吞退出码）和
   `security-scan`（`continue-on-error: true`）当初踩的是同一个坑。

   已修：
   - 新增 `flink-verification` job：`setup-java` + `setup-python` +
     预热 Maven 缓存（含 `maven-dependency-plugin`，冷缓存下导出 classpath
     会解析不到），然后跑聚合测试并产出 JUnit XML。
   - 新增 `tools/assert-junit-no-skip.py`：跑完 pytest 回头核对 XML ——
     有**真跳过**（`type="pytest.skip"`）就失败，执行条数低于门槛也失败
     （否则删掉测试能让门禁变绿）。
     **本轮修正**：第一版把 `<skipped>` 一视同仁，把 53 条 xfail 也算成跳过，
     接到主套件上会恒红。见 §6.6。
   - 新增 `backend/tests/test_ci_flink_gate.py` 9 条守卫：盯 CI 配置本身，
     并**测断言脚本自己的逻辑**（全跳过必须红、XML 损坏必须红、
     两种 JUnit 根布局都要能读）。已实测：把核对脚本从 ci.yml 删掉，
     守卫立刻变红。
   - 顺带清掉 6 个此前遗留、删不掉的临时探针文件
     （`_review_probe_*` / `_tmp_*`），本次经 `mavis-trash.js` 移入回收站。

5. **量具与运行环境（本轮已部分关闭）**
   ~~χ² 兜底分支从未在缺 scipy 的环境执行过~~ —— 已关闭：把 `_chi2`
   置为 `None` 后逐点验证，df 1~40 × 14 个统计量共 560 点，
   与 `scipy.stats.chi2.sf` 最大绝对误差 **3.775e-15**；
   端点行为也核对过（`df≤0 → NaN`、`stat=0 → 1.0`、`stat=inf → 0.0`）。

   仍未关闭：`_legacy_sigma` 只在旧 Redis 基线上生效，新部署走不到，
   它的实际命中率无法观测；`EVIDENCE_DIMENSIONS` 权重与各模式
   `max_chain_duration_minutes` 是本轮新设的**工程判断**，
   目前只有合成标定集支撑（§四）。

6. **A 类黄金样本（生产）** —— 合成标定集已建（§四），
   但**生产黄金样本与真实流量基线仍未测**。

### 3.6 跨 schema 版本混流 —— 已关闭（本轮新增 §三.6 内容见下）

滚动升级期间生产者和消费者不可能同时切换，一个批里必然同时存在
旧格式、新格式、甚至主版本不符的消息。此前这件事**从未被执行过**：
`test_schema_compat.py` 的 24 例测的是 registry/catalog 在孤立状态下的行为，
消费路径的用例则每条都传同一个格式的良构 dict，
而且**从不断言「一条成功处理的消息」确实到达了业务 handler**。

新增 `tests/test_schema_version_mixed_stream.py` 17 例，走真实的
`_ack_record` / `_process_message` 分流与真实的 `version_errors`
（只把 jsonschema 校验器换成 None，因为它依赖 catalog 里的 schema 文件）：

| 钉住的行为 | 结果 |
|---|---|
| 版本策略整张表（未声明/次版本旧/一致/超前 → 接受；主版本不符/非法 → 拒绝） | ✅ |
| 混流批次：3 好 1 坏 → 好的**确实到达 handler**，坏的进 DLQ | ✅ |
| 一条坏消息不能连累同批好消息 | ✅ |
| 合法消息不得被静默丢弃（单独一条钉，兜底用） | ✅ |
| DLQ 写失败 → 那条 offset 不推进 | ✅ |
| 跨格式的 `resolve()` 标识稳定（否则幂等去重失效） | ✅ |

**一个查证后确认「不是缺陷」的发现**，值得单独记：

我最初断言「信封与扁平消息解出的业务载荷应当一致」，实测**不一致** ——
handler 收到的是整个信封（`eventType="security.event"`，业务字段嵌在 `payload` 里），
而 `kafka_consumer.py` 里**没有任何 handler 调用 `unwrap()`**。
一度以为是挖到了大缺陷，继续查证后确认**不是**：

1. `stamp_identity` 的文档写明「在扁平消息上补可选身份字段，**不改写成信封**」；
2. `wrap()` 在**生产代码里零调用**（只有单测用）。

所以线上消息全是扁平的，业务 handler 直接 `event.get("eventType")` 是对的。

但这确实是个**潜在陷阱**：校验层（`schema_registry.unwrap`）与标识层
（`resolve`）都已支持信封，唯独业务 handler 层没有。哪天有人把 `wrap()`
接进生产者，信封就会真的上链路 —— schema 校验照过、event_id 照常解析，
**只有业务 handler 悄悄收到一个空壳信封**，每个字段取到 `None` 或
`"security.event"`。这种退化**不报任何错**。

因此把它钉成显式不变量，而不是留给将来踩：

- `test_no_production_code_wraps_messages_into_envelopes` ——
  生产代码里出现 `wrap()` 调用即失败，并提示必须同时改 handler
  （用词边界 `\bwrap\(`，否则 `unwrap(` 会被误判成违规，这条我踩过一次）；
- `test_stamp_identity_does_not_convert_flat_to_envelope` ——
  身份盖章不得把扁平消息包成信封；
- `test_envelope_reaches_handler_unwrapped_is_not_implemented` ——
  把当前断层**显式记录**下来：哪天这条变了，就是动手改 handler 的信号。

---

## 四、量化评估结果

新增 `eval_datasets/detection_cases.py`（21 条 Sigma + 8 条异常 +
8 条关联标定样本）+ `eval_datasets/evaluate_detection.py`（评估器）+
`tests/test_p3_detection_calibration.py`（**29 例**回归），
沿用既有 `behavior_cases` / `grounding_cases` 的约定。

### 4.1 标定集指标

| 检测器 | TP | FP | TN | FN | 候选(排除) | Precision | Recall | FPR |
|---|---|---|---|---|---|---|---|---|
| Sigma | 8 | 0 | 10 | 0 | 2 | 1.000 | 1.000 | 0.000 |
| 关联引擎 | 2 | 0 | 6 | 0 | 0 | 1.000 | 1.000 | 0.000 |
| 异常检测 | 1 | 0 | 2 | 2 | 3 | 1.000 | 0.333 | 0.000 |

「候选(排除)」= `suspicious`（有信号但证据不足以定结论）与 `inconclusive`
（结构性不可判），**既不计 TP 也不计 TN/FN**。这正是整改方案 §二的核心要求。
把它们算成阴性会虚高特异度，算成漏报会虚高漏报率 —— 两个方向的失真
都会让指标失去决策价值。

⚠️ 这里有一处**必须与真实现对齐**的口径：候选一旦从 `_binary()` 的
统计总体里排除，所有派生统计都必须用同一总体。否则同一份报告里
两个总分的分母不一样，而这种漂移不会报错、只会让数字悄悄失真。
本轮就抓到过一处：`precision_by_prevalence()` 自己数混淆矩阵时用的是
`expect != "malicious"`，把候选当成了阴性。现已改为**委托给
`_binary()`**，并由 `test_binary_excludes_suspicious_from_both_sides`
钉住两者同分母。

#### 这张表与 `--json` 对不上过一次：预过滤把 3 条 inconclusive 吞了

核对方式：把本表每一行与 `python -m eval_datasets.evaluate_detection --json`
的实际输出逐项比对。Sigma、关联引擎两行一致，**异常检测那行不一致** ——
表里 `候选(排除) = 3`，而 `--json` 发出的 `excluded_suspicious = 0`。

原因：异常检测的 JSON 出口写的是

```python
"detected_recall": _binary(
    [r for r in anomaly_rows if r["expect"] in ("detected", "not_detected")],
    "detected", negative_label="not_detected"),
```

那层**预过滤**在 `_binary` 之前就把 3 条 `inconclusive` 行删掉了；
而文本渲染是**单独统计**的，报 3。同一份报告的两种输出格式，
对「候选(排除)」给出不同的数，**两边都不报错**。
更糟的是预过滤让 `excluded_suspicious` 变成一个恒为 0 的死字段 ——
「第三类有没有被如实记账」从此在指标上再也看不出来。

删掉预过滤，让 `_binary` 自己排除（它本来就会），两条路径口径统一，
本表三行与 `--json` 逐项一致。

**第一版守卫抓不到它。** 守卫原本直接调 `_binary(run_anomaly(), ...)`，
于是测的是 `_binary` 的行为，而缺陷在**调用点** —— 注入预过滤后 7 条全绿。
改写成跑 `main(["--json"])`、读回真正发出去的数据后才验红（2 条）。

> **判据必须走被消费的那条路径。** 直接调被测函数、绕过它的调用方，
> 守卫会忠实地验证一个**没有人走**的分支。
> 与 §十.2 的「只比较簇代表」、§七.1 的「对照组不可比」同族：
> 测的东西对，但没测在被用的那个东西上。

守卫：`tests/test_eval_metric_completeness.py::TestExcludedRowsAreCountedNotPreFiltered`
（2 例），注入预过滤验红，按字节还原。

### 4.2 关于「精确率随基准率崩塌」——以及为什么现在表里全是 1.000

修复 Sigma 误报后，标定集 `FP=0`，于是**所有基准率下的 Precision 都是
1.000**。这张表现在看起来像「精确率不随基准率下降」，但那是
**样本集恰好没有误报**的性质，不是检测器的性质。必须把两件事分开说：

| 攻击占比 | Precision（当前 FP=0） | Precision（反事实 FPR=0.30，即修复前） |
|---|---|---|
| 50%（标定集实测） | 1.000 | 0.769 |
| 10% | 1.000 | 0.270 |
| **1%** | 1.000 | **0.033** |
| 0.1% | 1.000 | 0.003 |

右列不是「旧数据」，是**同样的 Recall=1.000 下换用修复前的 FPR** 解析算出的
值。它说明这条缺陷在生产上的真实代价：FPR=0.30 时，1% 基准率下
每次告警只有 3.3% 的概率是真的。

左列也不能当成保证。下表用同一公式给出「生产上若 FPR 不是 0」的结果
（Recall=1.000、基准率 1%），可以看到精确率对 FPR 极度敏感：

| 生产实测 FPR | 1% 基准率下的 Precision |
|---|---|
| 0.001 | 0.910 |
| 0.01 | 0.503 |
| 0.05 | 0.168 |
| 0.30 | 0.033 |

**误报率 FPR = FP/(FP+TN) 与基准率无关**（定义使然，分子分母都在良性类内部），
随基准率变的是精确率。生产环境攻击占比通常低于 1%，
所以只报标定集实测 PPV 会**系统性地高估**实际可用性。

> 本节这条「必须把两件事分开说」的区分，2026-10-19 在 §9.9 又用到了 ——
> 而那里曾把它写成「判别力为零」，是**过强**表述，已更正并钉成守卫（§9.17）。

⚠️ 这条纠正了评估器第一版的两个错误：一是把标题写成「误报率随基准率变化」，
三档输出完全相同却顶着该标题 —— 真数字套着假标题；二是 NPV 的分母误用
误报率，算出 NPV > 1 这种不可能的值。两条分别由
`test_false_positive_rate_is_invariant_to_prevalence` 与
`test_npv_never_exceeds_one` 钉死。

「精确率随基准率下降」这个关系本身由
`test_precision_declines_when_false_positives_exist` 用合成行单独验证
（TP=4 FN=1 FP=5 TN=5 → 手算 0.615 / 0.151），**不依赖标定集当前
恰好有没有误报** —— 否则 FP 修成 0 之后，这条性质就没人守了。

### 4.3 缺口 1：Sigma 裸子串误报 —— 已修复

上一版登记的 3 条良性误报**已全部消除**，FPR 从 **0.300 降到 0.000**。
修复分两层，第二层才是根因：

| 层 | 问题 | 修法 | 证据 |
|---|---|---|---|
| 表层判据过宽 | SIG-002/005 用裸子串 `/api/status`、`/export` 做 URL 判据，任何含该子串的正常请求都命中 | 移除该判据，保留 `sel_event` 的 OR 路径，检出能力不受影响 | SIG-N-01/02 现为 `not_detected`，0 命中 |
| **根因：证据不足却下执行动作** | SIG-001/007 声明 `x-soc-aggregation`（`count(src_ip)>5 in 5m`）—— **规则作者自己承认单事件证据不足**，但单事件阶段仍产出 `action_recommend=block_ip` | 带 `x-soc-aggregation` 的规则命中一律降级为 `partial`：描述加 `[PENDING-AGG]` 标记，动作从执行类降为 `alert` | SIG-N-03 实测 `severity=high` + **`action=alert`** |

第二层才是关键。只修判据是治标：只要「规则声明需要聚合」和
「单事件阶段照发封禁动作」这两件事同时存在，下一条规则还会再犯。
判据换完之后，剩下的误报恰恰是**规则自己知道证据不足**的那部分 ——
它们必须以「候选」而非「结论」的身份出现。

降级后的行为（真引擎直接实测，非评估器过滤后）：

| 用例 | 场景 | status | severity | 动作 |
|---|---|---|---|---|
| SIG-N-03 | 员工正常访问 `/admin/login` | `partial` | high | **`alert`**（待 SIG-001 窗口确认） |
| SIG-P-01 | 路径遍历攻击 | `detected` | critical | `block_ip`（保留） |

真正的攻击没有被降级：SIG-P-01/02/03/06/07/09 仍带 `block_ip`。

### 4.3.1 降级引出的连带缺陷：封禁动作在聚合链路上整条断掉

上一版报告在这里写了一句「真正的 block 由聚合窗口（Flink）阈值触发后产生」。
写的时候这句话**并不成立**。逐层追查后发现聚合链路有 **6 层**，
其中 4 层各自独立地把封禁能力丢掉了。这正是本次修复自身引入的回归，
必须一起修掉，否则等于用「消除误报」换来了「暴力破解不再封 IP」。

| 层 | 文件 | 修复前 | 后果 |
|---|---|---|---|
| 1 单事件判定 | `sigma_engine/engine.py` | 降级为 `alert`（本轮修） | 良性登录不再被封 ✅ |
| 1b **接线** | `engine.py::detect` | 存在，但**无任何断言覆盖** | 见下 |
| 2 候选载荷 | `engine.py::_agg_payload` | 只有 `src_ip/rule_id/threshold/timestamp` | 规则声明的 `block_ip` **出不去** |
| 3 Kafka 白名单 | `kafka_producer.py::publish_sigma_hit` | 按白名单重建 dict，未列键静默丢弃 | 即使上游塞了也到不了 Flink |
| 4 Flink 窗口 | `SigmaThresholdAggregationJob.java` | `severity` **硬编码 `"high"`**，无 `alertType`、无 `confidence` | 规则意图被改写；告警回落成 `ANOMALY` |
| 5 告警消费 | `kafka_consumer.py::_handle_alert` | **硬编码 `allow_blocking=True`** | 无论声明什么动作都放行封禁 |
| 6 策略匹配 | 同上 | 只读 `anomalyScore` 算置信度 | 聚合告警无此字段 → **confidence=0.0 → NO_ACTION** |

### 第 6 层：前五层全修对了，链路依然不封禁

这一层值得单独记，因为它是**前一轮修完之后才发现的** ——
修完第 5 层时链路看着是通的，报告里也确实写了「链路已通」。
实际拿真策略引擎一跑：

```
confidence=0.0（聚合告警无 anomalyScore）
  → 策略「暴力破解自动阻断」要求 min_confidence=0.5
  → MatchStatus.NO_ACTION, actions=[]
  → allow_blocking 判对了也永远不封禁

confidence=0.9 → MATCHED, policy='暴力破解自动阻断', actions=['block_ip','send_alert']
```

**结论：链路上每多一层，就多一次「字段在这条边界上被丢掉」的机会。**
上一轮我把「四层都带了动作字段」当成了链路修通，其实只验到字段有没有被
传输，没验到**传输过去之后有没有人真正用它**。

置信度刻度没有自造：复用 `audit_triage._fused_confidence` 与
`ingest_pipeline` 里已有的 `{"high":0.85,"medium":0.65,"low":0.45}`
（提为 `SIGMA_CONFIDENCE_NUM`）。同一条 Sigma 证据在审计链路和聚合链路
必须用同一把尺，否则两条处置路径的门槛对不上。认不出的取值一律落到
**最低档 0.45** —— 往低了落最坏是不处置，往高了落则一条拼错的规则
就能凭空获得封禁资格。

### 第 1b 层：上一轮测试自己留的洞

上一轮新增的 31 条断言测的全是 `_agg_payload` **这个纯函数**，
没有任何一条证明 `detect()` 会调用它。把
`if requires_agg: self._schedule_publish_agg(...)` 整段删掉，
31 条断言**照样全绿**，而候选再也发不出去。

这是「测函数」与「测接线」的区别：前者保证函数对，后者保证它被调到。
已补两条断言，并实测确认输入确实命中（SIG-001 命中且被发布；
SIG-003 命中但**不**被发布 —— 反向约束同样非空跑）。

### 第 4 层另外两条独立缺陷

- **`threshold=0` 会退化成单事件告警**。原条件 `count >= threshold` 在
  阈值为 0 时恒真 —— 任何一条候选都立刻出告警，恰好是本作业存在的意义
  所反对的。已加 `threshold > 0` 前置。
- **同窗口内动作取任意一条**。规则可被 `learn_loop` 在线改
  `action_recommend`，窗口内新旧动作可能并存，取任意一条会让处置结果
  依赖消息到达顺序。已改为取最严（`worseAction` / `worseSeverity`）。

#### 第 4 层怎么才算真的验过：进程外 harness

上面两条缺陷（`threshold=0` 退化、取任意一条）在源码字符串断言下
**全都是绿的** —— 只要 `worseAction` 这个名字还在文件里，
`assert "worseAction" in src` 就通过，哪怕它被改成了「取最后一条」。
比较写反、字段没 put 出去、两个 Python 侧的字符串对不上 Java 侧的键，
同理一条都抓不住。

所以本轮加了进程外 harness：

| 文件 | 作用 |
|---|---|
| `flink-jobs/src/test/java/com/soc/job/SigmaWindowHarness.java` | 从 stdin 读 NDJSON 载荷 → 调**真实的** `ThresholdWindowFunction.process` → stdout 输出告警 JSON |
| `flink-jobs/src/test/java/org/apache/flink/.../functions/SigmaWindowTestContexts.java` | 构造 Flink 运行时**自己用的** `InternalProcessWindowContext` |

17 条断言里有两条值得单说：

- **`test_threshold_comparison_is_not_reversed`** —— 用 `count=3 / threshold=10`
  断言**不**告警。方向写反成 `count <= threshold` 时，正向用例
  （count == threshold 告警）仍可能通过，只有这条会红。
- **`test_python_producer_payload_reaches_java_intact`** —— 载荷不是手写的，
  是 `PySigmaDetector._agg_payload(...)` 的**真实输出**。两端任何一边
  改键名（`action_recommend` ↔ `action`），两边单测都还绿，
  只有这条会看到默认值而不是声明值。

**验红方式**：`git stash push` 把 `SigmaThresholdAggregationJob.java`
回退到 HEAD（修复前）后重跑，**24 failed**，其中 12 条是上面这些新断言。
恢复后 76 例全绿。

#### 一个附带结论：Flink 的 `ProcessWindowFunction.Context` 无法从外部子类化

写 harness 时踩到的，记下来免得下一个人再查一遍：

`Context` 是 Flink 的**内部类**，字节码里有 `this$0` 和
`Context(ProcessWindowFunction)` 外部实例构造器，但这个构造器
**对 javac 不可见** —— `javap -p` 看得到，javac 的 ClassSymbol 上只剩
隐式无参构造器。于是两种写法都编译不过：

- `super(host)` → 「需要: 没有参数」
- 不写 `super` → 「需要包含 ProcessWindowFunction.Context 的封闭实例」

用最小复现排除了所有看似相关的因素：与宿主是否泛型无关（纯 Java 泛型
版本通过）、与是否同包无关、Context 是内层类还是静态嵌套类无关。
最后落到 Flink 自己的具体实现 `InternalProcessWindowContext`
（`WindowOperator` 运行时用的就是它），它的构造器是**包私有**的 ——
把一个工厂类放进 Flink 那个包里即可访问。

顺带一提：这也说明为什么 harness 值得用 Flink 的真 Context 而不是
自己伪造一个 —— 伪造版漏实现某个方法时，会把「harness 能跑」
伪装成「窗口在集群上能跑」。

修复后链路的正确形态：

```
单事件阶段   证据不足 → partial + alert（禁止处置）
     ↓ 发布候选（携带规则声明的 block_ip/severity/attack_type/confidence=0.85）
Flink 窗口   count ≥ threshold 且 threshold > 0 → 出聚合告警
     ↓ 告警带 alertType=SIGMA_AGGREGATE + action_recommend + confidence
消费端       allow_blocking = (action ∈ ENFORCEMENT_ACTIONS)
             confidence = anomalyScore or confidence → 0.85
响应引擎     策略「暴力破解自动阻断」匹配 → block_ip + send_alert
```

消费端的三条口径（见 `kafka_consumer._allow_blocking_for`）：

1. **显式声明了动作** → 以动作为准（`block_ip` 允许，`alert`/`require_confirmation` 不允许）
2. **没声明动作**（CEP、行为基线等其它告警源）→ 保持既有行为 `True`，
   本次改动不改变其它链路的处置
3. **判不出来**（`ENFORCEMENT_ACTIONS` 导入失败）→ `False`，fail-safe：
   无法确认规则声明了执行动作时宁可少封也不误封。**不能 fail-open** ——
   那意味着一次依赖故障就全量打开封禁

口径 1 与 2 必须分开：`alert.get("action_recommend") or ""` 会把
「字段缺失」和「声明为空」都变成空串，两者合并后一句空声明就会放行封禁。
因此用 `in` 判存在、`strip()` 判内容。

新增回归 `tests/test_sigma_aggregation_action_chain.py` 共 **76 例**，
对链路上每一层各钉一条断言。其中：

- 第 6 层配了一条**反向证明** `test_aggregation_alert_without_confidence_matches_nothing`
  —— 没有它，「能封禁」可能是因为别的什么宽松改动，而不是真的修好了置信度
- 对 Java 的断言现在有**真编译**（`test_flink_jobs_compile`）与
  **进程外真执行**（4c 节 17 条）两层兜底；源码字符串断言降级为
  定位「少了哪个字段」的补充手段
- 逐条用 `git show HEAD:` 取旧版源码验证过**修复前确实为红**；
  窗口层那 17 条另用 `git stash` 整体回退验证（24 failed）

登记方式：`KNOWN_GAPS['sigma_bare_substring_false_positives']` 条目
**已移除**，替换为两条反向回归断言 ——
`test_benign_cases_never_produce_confirmed_detection`（良性样本不得报阳）与
`test_benign_cases_never_carry_enforcement_action`（良性样本不得携带执行类动作，
无论是否产生候选）。第二条比第一条严格，是本轮修复的核心不变式。

### 4.4 缺口 2：异常检测阈值 0.60 高于标定集的召回下限 —— 仍未修复

ANO-P-02（罕见类型 + critical）得分 0.4357、ANO-P-03（凌晨 + 罕见类型）
得分 0.4957，均低于阈值 0.60 → 漏检。

> ⚠️ **本节原先写「阈值扫描显示能覆盖全部应检出样本的区间是 [0.0, 0.4]」，
> 这句话是错的，本轮已更正。**

#### 本轮查出的真缺陷：网格量化值被当成了精确边界

`sweep_anomaly_threshold(rows, step=0.05)` 是在 **0.05 的网格**上找
「完美落点」，只会报出**小于真实约束的最后一个网格点**。
真正约束人的是「必须靠分数命中（而非靠 sigma>3）的最低应检出得分」，
记作 `m`，可行区间是 **`[0, m)`**。

标定集实测：

```
ANO-P-01  0.7143  ← 不是约束
ANO-P-02  0.4357  ← m，约束在这里
ANO-P-03  0.4957
网格上界  0.40    ← 0.05 网格里 < 0.4357 的最后一点
```

所以**召回下界**是 **`[0, 0.4357)`**，而报告写成了 `[0.0, 0.4]`。
（⚠ 2026-10-20 §9.60 更正：它只是**召回下界**，不是可行区间 ——
补齐另两类约束后完整可行区间为**空集**，见本节结论后的更正块。）

**这不是小数点问题，是决策依据被量化了**：照「≤0.4」去调阈值，
会比必要值**多降 0.0357**，而多降的部分直接变成额外的误报面。

> 与整改方案 §十 批评变种聚类的
> 「`round(sim,3)` 把 0.4996 显示成 0.500，隐藏实际阈值差异」
> 是同一类缺陷 —— 只是这次发生在**报告自己的结论依据**上。
> 一个把自身决策边界量化掉的报告，比一个报错更难发现。

#### 修复

`eval_datasets/evaluate_detection.py` 的扫描当时同时输出两者：

```
精确可行区间 = [0, 0.4357)   ← 右端是**开**的，由最低的应检出得分决定
网格(步长 0.05)上完美落点 = [0.0] ~ [0.4]
⚠ 网格上界 0.4 比精确上界低 0.0357 —— 照网格值调阈值会多降这么多，
  多出来的部分直接变成额外误报面
```

> ⚠ **2026-10-20 §9.60 更正**：上面那段是**当时**的输出。
> 现在它已被改掉 —— 「精确可行区间」这个叫法本身是错的
>（那只是**召回下界**），工具现在的输出是：

```
召回下界 = [0, 0.4357)   ← 只约束「不漏掉应检出样本」，**不是**可行区间
负类下界   = 0.1714   ← 阈值必须 ≥ 它，否则已知正常样本变误报
不可判下界 = 0.4957   ← 阈值低于它，「结构性不可判」的样本会被报成 detected
⚠ 完整可行区间 = **空集**（下界 0.4957 ≥ 上界 0.4357）——
  **没有任何阈值**能同时满足三条约束 ⇒ 缺口不是阈值问题
```

回归 `tests/test_p3_detection_calibration.py` 由 22 例扩到 **27 例**，
新增 5 条：精确上界必须等于「必须靠分数命中」的最低应检出得分；
区间右端是**开**的（判定是 `score > t`，取等号就漏）；
靠 `sigma>3` 命中的正样本**不构成上界**；`known_gap` 行不参与约束；
以及一条前提守卫把标定集上的量化差额 `0.0357` **钉死** ——
哪天差额变了，报告里引用的数字会被强制同步。

**验红**：把 `exact_upper_bound` 改成取网格值，5 条全部转红，还原 sha256 一致。

#### 结论（未变，只是依据更准）

阈值 0.60 高于标定集的召回下限，缺口仍然存在。
而 ANO-N-02（应判正常）得分仅 0.1714，**远低于 0.4357**，
所以把阈值降到精确上界以内不会引入误报。

> ⚠ **2026-10-20 §9.60 更正（本段结论**方向未变，但依据不完整**）**：
> 上面那句「降到上界以内不会引入误报」**只看了负类**。
> 负类那条判断本身是对的（实测：`t > 0.1714` 时负类永不误报），
> 但标定集里还有第三类 —— `expect="inconclusive"`（全新源 IP，
> 统计维度**结构上**不可判），它**不参与**阈值扫描，而它的得分
> 是 **0.4957 / 0.4357** —— **与两条应检出样本完全相同**。
>
> 于是把阈值降到 `[0, 0.4357)` 会把这两条**结构性不可判**的样本
> 判成 `detected`（新源 IP + critical + 凌晨 → 报「已检出」）。
>
> 补齐全部三类约束后的**完整可行区间 = [0.4957, 0.4357) = 空集**：
> **没有任何阈值**能让标定集完全自洽。
> ⇒ 结论升级为：**这个缺口不是阈值问题**，靠调阈值补不上，
> 必须走整改方案 §七.2 的重设计（新证据维度 + 独立冷启动规则）。
> 详见 §9.60（含逐档体检表与 4 处注入验红）。

本轮**依然没有**擅自调阈值 —— 标定集是合成的，
整改方案 §七.2 明确要求「用有标签的样本做离线评估」，
调参必须等生产黄金样本。
缺口登记在 `KNOWN_GAPS`，`tests/test_p3_detection_calibration.py:196`
的 `test_anomaly_threshold_gap_is_registered` 会持续盯住。

### 4.5 Sigma 到底贡献了多少独立检出

8 个真阳性中：

- **50% 来自原始指标**（URL 载荷、端口等，不依赖上游分类器）
- 50% 仅复述上游 `event_type`

结论：**Sigma 确实有独立于上游分类器的增量检出能力**（raw_indicator
可判定样本 4/4 全中），不是纯粹的回声。但 11 条规则里有 8 条的判据
含 `event|contains`，若上游把事件标成 `C2_BEACON`，Sigma 必然命中 ——
这部分不是独立证据。

⚠️ raw_indicator 命中率 4/4 这个数看着漂亮，但要连着分母口径一起读：
该组共 6 条样本，其中 2 条（SIG-P-04/05，SSH 异常连接）标为 `suspicious`
—— 规则声明需窗口内计数达阈值，单事件阶段本就无法定论，因此**不进分母**。
若把它们算成阴性，命中率会从 1.000 掉到 0.667，然后就会有人跑去「修」Sigma ——
而 Sigma 一行都没错，是评估口径把「还没判定」当成了「判成阴性」。
该口径由 `test_no_regression_below_threshold` 同时钉住分子与分母。

### 4.6 本节数据的适用边界

标定集是**合成的**，用于比较实现与标注的一致性。它可以回答
「阈值相对标定集偏高还是偏低」「规则会不会误伤 lookalike」，
**不能**回答「生产误报率是多少」。后者需要真实流量基线。

### 4.7 Grounding 评估器：同一缺陷的第二个实例

与 §4.4 同源（网格量化值被当成精确边界），但**这一处更难发现**：
本标定集的精确上界恰好落在网格点上，所以「余量」这个表面数字改动前后完全一样。
真正变的是另外两件事。

#### 精确边界是什么

判定是 `score >= g_t`（`evaluate_grounding.py:167`），所以 grounded 阈值的精确约束是：

- 干净样本要留在 grounded → `g_t <= min_grounded`（**闭**上界）
- 越界样本不能被当成 grounded → `g_t > max_bad_without_hard_fail`（**开**下界）

实测 `min_grounded = 0.9000`、`max_bad_without_hard_fail = 0.7000`、裕度 `0.2000`。

> ⚠️ **这组数字在 §九.2 修掉黄金样本集的时间锚点之前是 `0.8000 / 0.6000`。**
> 原因是 `grounding_cases.py` 把事件时间硬编码成绝对日期，锚点越过
> 24 小时 TTL 后**全部 13 个用例的 freshness 一起掉到 0**，每条
> `grounding_score` 被扣 0.10。判定结果（accuracy / confusion /
> hard_fail_coverage）恰好没被这一平移改变，但**诊断数值被改了**。
> 本节末尾「诚实的边界」那一小节因此重写过，见 §9.2 与下文。

#### 缺陷 1：下界被网格抬高，合法区间被说成非法

`sweep_thresholds` 在 `step=0.01` 的网格上枚举 `(g_t, p_t)`，只报「网格上完全满足的组合」。
实测网格落点是 `[0.61, 0.80]`，于是修复前的渲染把下界说成 **0.61**。
但真实要求只是「严格大于 0.60」—— 区间 `(0.60, 0.61]` 完全合法，却被工具判为不可用。

损失方向是**白严**：合法阈值被误报成非法，人会被推去调一个不需要调的阈值。
这类错误比漏报更隐蔽，因为它看起来像「工具很保守」。

#### 缺陷 2：「已越出数据支持区间」用网格上界判，会**误报**

修复前的越界告警条件是 `cur_g > max(gs)`，`max(gs)` 是网格落点里最大的那个。
只要真实 `min_grounded` 不落在网格点上，这个判据就是错的，而且错在
**「误报越界」**这一侧：

| | 值 |
|---|---|
| 真实精确上界 `min_grounded` | 0.8034 |
| 当前阈值 `cur_g` | 0.802（在支持区间**内**） |
| 网格上界 `max(gs)` | 0.80 |
| 旧判据 `0.802 > 0.80` | **真** → 误报「已越出」 |

这条告警的语义是「提高阈值会开始误杀干净断言」，读的人据此会把阈值**调低** ——
也就是说，一个纯粹的**呈现**缺陷会直接推动一个**方向错误**的阈值变更。
这正是 §4.4 说的「损失有方向，不是对称误差」。

`test_out_of_range_check_uses_the_exact_upper_bound` 用合成数据把这条钉住：
`monkeypatch` 把阈值设成 0.802、干净样本 0.8034、网格步长 0.01，
断言渲染输出里**不得**出现「已越出数据支持区间」。

另外补上了**下界方向**的告警分支——修复前只检查上界。
阈值掉到 `max_bad_without_hard_fail` 以下时，越界样本会被直接当成 grounded，
而这条路径此前没有任何提示。

#### 改法

`sweep_thresholds` 返回值新增 `exact_lower_exclusive` / `exact_upper_inclusive`，
直接取自 `report.separation`，**不经过网格**。渲染实测输出：

```
  当前阈值 grounded≥0.8 / partial≥0.4
  当前阈值落在完全满足区间内  = True
  精确可行区间 = (0.7000, 0.9000]   ← 下端**开**（越界样本不得被当成 grounded）、上端**闭**（干净样本要留在 grounded）
  ★ 当前 grounded=0.8 距精确上界 0.9000 还有 0.1000 余量
  网格(步长 0.01)上完美落点 = [0.71, 0.90]   ← 网格量化值，边界以精确值为准
  在该区间内 partial 阈值上界      = 0.70（网格值）
  ⚠ 网格下界 0.71 与精确下界 0.7000 不一致（差 +0.0100）—— 网格比真实约束更严
```

网格落点仍然输出（它有诊断价值：能看出离最近的网格线有多远），
但明确标注为网格值；网格与精确值不一致时**主动报残差**，
而不是让人自己猜哪个是真值。

#### 诚实的边界：这一节的结论曾被自己的夹具骗过一次

**原文（已作废，留档以便对照）**：

> `min_grounded` 实测正好是 `0.8`，落在 0.01 网格上，所以网格上界与精确上界相等，
> 余量仍是 `0.0000`。**如果报告写成「余量从 0.00 修正为 0.20」，那是编的。**
> 这次修的是**判据来源**与**下界语义**，不是本数据集上的表面数字。

当时的推理是：「余量没变」⇒ 修的是判据不是数字⇒ 这个数据集上看不出差别。
**这个推理的前提本身是错的。** §九.2 查出 `grounding_cases.py` 把事件时间硬编码成
绝对日期，锚点越过 24 小时 TTL 后全部用例 freshness → 0，每条 `grounding_score`
被扣 0.10。修掉之后：

| | 污染态（当时发布） | 修正后（当前） |
|---|---|---|
| `min_grounded` | 0.8000 | **0.9000** |
| 精确可行区间 | (0.6000, 0.8000] | **(0.7000, 0.9000]** |
| 当前阈值距上界的余量 | **0.0000** | **0.1000** |
| `margin_without_hard_fail` | 0.2000 | 0.2000（未变） |

真正致命的不是数字平移，而是**它恰好把最紧的那个干净样本推到了阈值上**：
`min_grounded` 从 0.9 掉到 0.8，而当前阈值正好是 0.8，于是余量归零、
「网格上界 == 精确上界」这个本数据集独有的巧合被制造了出来。
当时的结论——「这个数据集上看不出判据修复的效果」——其实是在描述
**夹具缺陷的症状**，却被当成了数据集的性质。

> **「表面数字没变」不是「修复没生效」的证据。**
> 它至少有两个同样自洽的解释：(a) 修的是判据不是数字；(b) 夹具/数据本身有偏差。
> 在 (a)/(b) 无法区分时，结论应当写成「本数据集不足以区分」，
> 而不是「修的是判据不是数字」。

> **「某个值恰好等于某个阈值」这类巧合，要先怀疑自己的输入，再写进结论。**
> 巧合不会自己出现在数据里 —— 它通常是某个偏移量与阈值的差。

缺陷会在标定集一换、`min_grounded` 一不落在网格点时立刻显形；
标定集本来就要换（§4.6：当前是合成集，生产定标必须换真实基线）。
现在 `min_grounded = 0.9` 仍落在 0.01 网格上，所以「网格值 == 精确值」这一点
依然成立 —— **但这次它是真的，而不是偏移量的巧合**。

#### 验红

`tests/test_p3_grounding_calibration.py` 由 31 → **35 例**，新增 `TestExactThresholdBounds` 4 条。
两次注入，按字节还原 + sha256 校验（`a078ad052b96e387`）：

> ⚠️ 上面这个 sha256 记录的是**当时**的工作区状态。`evaluate_grounding.py`
> 在 §九.3 又被改动（`per_class` 补 `tn` / `false_positive_rate` /
> `false_negative_rate`），当前哈希已不同；用例数 35 未变。

| 注入 | 结果 |
|---|---|
| 把越界判断改回用网格上界 | **1 条转红** |
| 移除 `exact_lower_exclusive` / `exact_upper_inclusive` 两字段 | **4 条全红** |

第二次特别重要：**只移除字段、不动判据**，4 条仍全部转红，
说明这些用例盯的是「结论对不对」，不是「实现长什么样」。

全量回归：`2172 passed, 1 deselected, 53 xfailed, 0 failed`（153.56s，exit 0）。

### 4.8 Behavior 评估器：同一族的第三例，外加一个前两处没有的缺陷

`evaluate_behavior.py` 是「网格值当精确边界」的第三处。
但它比前两处多带一样东西：**扫描域从未对外声明**。

#### 缺陷 3：sweep 静默跳过了 81% 的组合

三嵌套循环（`evaluate_behavior.py:304-312`）用 `continue` 跳过
`confirm_t < warn_t` 与 `deny_t < confirm_t` 的组合。实测：

| | 值 |
|---|---|
| 网格全组合 | 21³ = **9261** |
| 进入枚举域 | **1771**（19%） |
| 其中可行 | **1408** |

**跳过本身是对的** —— confirm 低于 warn 语义上讲不通。
问题在于旧渲染把受限域上的投影直接印成

```
  完全满足的 warn 区间     = [0.00, 0.80]
  完全满足的 confirm 区间  = [0.05, 0.80]
  完全满足的 deny 区间     = [0.05, 0.95]
```

读者无从知道存在这条序约束。后果是可量化的：三行投影交叉可得 **5168** 个三元组，
其中 **3760 个根本不在搜索域内**。

#### 缺陷 4：三个「区间」是边缘投影，不是可行域

`warn 投影 = [0.00, 0.80]` 的含义是「**存在** confirm/deny 取值使这个 warn 可行」，
不是「warn 取区间内任意值都可行」。两者在报告里长得一模一样。

#### 缺陷 5：旧工具从没回答过「我能不能单独调这一个阈值」

这是最实的一条。新增 `exact_conditional_bounds`：固定其余两个阈值在当前值，
只动这一个，算出**精确**可行区间。实测输出：

```
  ── 精确可行区间（其余两阈值固定在当前值）──────────────────────────
    warn     当前 0.6000 → [0.0000, 0.8000]   余量 上 +0.2000 / 下 -0.6000
    confirm  当前 0.8000 → [0.6000, 0.8000]   余量 上 +0.0000 / 下 -0.2000
    deny     当前 0.9500 → [0.8000, 0.9500]   余量 上 +0.0000 / 下 -0.1500

> ⚠️ **本行于 §9.66 更正。** 原文是 `[0.0000, 1.0000]` / `[0.0000, 0.8000]` /
> `[0.0000, 0.9500]`。原值**越出了评估器自己声明的搜索域**
> `warn <= confirm <= deny`：warn=1.0 时 confirm=0.8 被越过，
> confirm=0.0 时被 warn=0.6 越过，deny=0.0 时被 confirm=0.8 越过。
> ⇒ 那三个「余量」有一部分是**调不出来的**。
> 详见 §9.66。
```

**confirm 与 deny 的上侧余量都是 +0.0000** —— 当前阈值正卡在精确上界上，
在现有标定集下**一点都调不上去**；warn 则有 +0.20 的空间。
旧工具只说「当前阈值落在完全满足区间内 = True」，从不给余量。

> ⚠️ **「+0.40 的空间」于 §9.66 更正为「+0.20」**，并**降级**为「不可调出」：
> 原值里 warn 的 0.8~1.0 那一段越过了 confirm 门槛。
> 另：§9.66 进一步查清「上侧余量为 0」的**成因**不是合成集稀疏，
> 而是**维度分是离散常量、且阈值恰好等于某个常量**
> （confirm=0.8 = `_score_caller` 的常量 0.8；deny=0.95 = 常量 0.95）。
> ⇒ **扩样本并不能放宽上界**（实测：加 0.90/0.95/1.00 的 confirm 样本、
> 加 0.97/1.00 的 deny 样本，上界纹丝不动）。

同时注意 warn 的**投影**上界 0.80 与**精确**上界 1.00 相差 0.20：
投影被序关系挤压了。这正好说明两者不能互换。

#### 为什么这个「精确」不是又一次量化

三个阈值只经由 `score >= t` 与 `max_dim >= t` 起作用，
可行性关于每一维都是**分段常数**的，断点只落在数据值上。
所以只需在「断点本身」与「相邻断点的严格中点」上取值即可覆盖全轴 ——
段内恒定，中点代表整段，而相邻浮点中点严格落在两者之间。
这是**穷举断点**，不是又一次网格近似。

#### 一条必须写下来的否定结论：这里**不给残差**

§4.4 与 §4.7 都能给残差，因为那里的网格值与精确值是**同一个量**的近似。
这里不行：网格投影回答「∃ 其余两维可行」，精确区间回答「其余两维固定」。
两者相减没有意义。渲染里因此显式写了「不给残差」，
并用一条用例钉住这个决定本身，防止后来者看到那组数字手痒补一行「差 +0.20」。

#### 我自己写错了一句，已改

第一版渲染里我写了「三个投影不是独立区间，不能当盒子用」。
**实测是错的**：盒子 ∩ 序约束恰好等于可行集（1408 = 1408，集合相等）。
已改成准确表述 —— 问题不在盒子，而在**序约束从未声明**。

这与 §4.7 里「这个数据集上余量没变」是同一类提醒：
**呈现缺陷的修复本身也可能是错的，必须实测。**

#### 验红

`tests/test_p3_behavior_calibration.py` **36 → 46 例**（新增 3 个测试类 / 10 条）。
（⚠️ §9.66 契约改写后该文件为 **48 例** —— 此处保留当时的数字作为历史记述。）
三次注入，按字节还原 + sha256 校验（`15a1444991f43605`）：

| 注入 | 转红 |
|---|---|
| A：把精确边界退回 0.05 网格 | **1 条** —— `test_bounds_are_exact_on_an_offgrid_dataset`，报 `0.8 == 0.8034` |
| B：恢复旧渲染文案「完全满足的 warn 区间」 | **1 条** —— `test_render_declares_domain_and_labels_projections_as_grid` |
| C：谎称未跳过任何组合（`n_enumerated = 9261`） | **2 条** —— `TestSweepDomainIsDeclared` 整组 |

注入 A 那一轮暴露了一件事：**真实标定集上三个边界恰好都落在网格点上**
（0.0 / 0.8 / 0.95 / 1.0 全是 0.05 网格值），
所以只用真实数据写的用例**无法区分「精确」与「又一次网格」**。
为此补了合成用例，把上界放到 0.8034（离网格点 0.80 差 0.0034），这条才有鉴别力。

这是 §4.7 那条「这个数据集上数字没变」的同族教训：
**守卫必须落在能分辨出差异的那组数据上，否则它只是一致性检查。**

全量回归：**`2182 passed, 1 deselected, 53 xfailed, 0 failed`**（157.32s，exit 0）。
相对上一轮的 2172 正好 **+10**，与本节新增的 10 条用例逐位对齐。

---

## 五、「没有人为变绿」的自查

文档 §十三 要求「原有测试没有通过删除断言或放宽安全要求来人为变绿」。
本轮对 4 个审查测试文件的改动、以及晚间**新增的 4 个测试文件**，全部记录在案：

| 文件 | 改动性质 |
|---|---|
| `test_review_sigma_detector.py` | 29 例断言由「冻结缺陷行为」改为「修复后行为成立」，docstring 保留「修复前是什么」；**2026-10-19 晚间再 +7 例（Q5 2 例 + Q6 标识符转义 5 例）**，现 36 例 |
| `test_review_anomaly.py` | **全文重写**：16 例由固化缺陷行为改为修复后行为，并新增 6 例此前不存在的用例（总跨度/幂等/证据上下文分离）。**2026-10-19 晚间再 +9 例**，现 25 例：新增「畸形字段类型」4 例（§9.11）、「重放幂等」2 例（§9.12）、「去重键撞车」3 例（§9.13），docstring 均写明「修复前是什么」与实测数字 |
| `test_review_contract_fusion.py` | 26 → 22 例，全部改为 `[FIXED]` 断言；**2026-10-19 晚间再 +1 例（Q16：单条规则失败到融合层）**，现 28 例 |
| `test_review_sandbox_security.py` | **2026-10-19 晚间**：把一条**依赖实时 DNS** 的用例改为离线可跑（结论不再由环境决定），并新增 3 条**打桩**用例 —— 其中一条补上「DNS 解析到私网 IP 必须被拒」这条从未被测过的安全性质（§9.16）；再新增 8 例**重定向复检**（§9.21）。前一项**生产行为未改**（DNS 失败 fail closed 本来就是对的），后一项**改了生产行为**（跨主机/元数据/loopback 重定向不再跟随） |
| `test_eval_metric_completeness.py` | **2026-10-19 晚间 +3 例**（§9.17）：黄金样本集**不得退化成单一类别** —— 「恒判主类别的平凡检测器能拿满分」才是真正的「判别力为零」；同时校验评估器读到的类别分布与黄金样本表同源 |
| `test_causal_identification.py`（新建） | **2026-10-19 晚间新建，6 例**（§9.18）：§三.2「不可识别时不得输出已识别的 ACE」此前**一条回归都没有**。含正向对照（可观测混杂时仍要给出 ACE） |
| `test_causal_consensus_conflict.py`（新建） | **2026-10-19 晚间新建，5 例**（§9.19）：§三.3「A→B 与 B→A 不得同时输出」此前**一条回归都没有** |
| `test_sandbox_result_retrieval_gap.py`（新建） | **2026-10-19 晚间新建，3 passed / 1 strict xfail**（§9.14）：钉住「沙箱结果回取半边生产零调用」这个已知缺口；XPASS(strict) 即转红，强制回来更新报告 |
| `test_review_correlation.py` | 25 例，7 条由固化缺陷行为改为修复后行为，新增 3 例（总跨度、chain_id 稳定性、去重顺序无关） |
| `test_anomaly_rarity.py`（生产测试） | 5 条断言因整改口径变更而更新：魔法数 100 的标定值、样本不足返回 0.0。**更新方向是收紧（0.0 → None）不是放宽**，并保留 #9 分母修复的回归用例 |
| `test_causal_chain.py`（生产测试） | `spurious` verdict 枚举 → 改为否定式断言「绝不等于 causal_support」，比原断言更强 |
| `test_causal_api.py`（生产测试） | `unknown` → `insufficient_data`，按文档 §三.1 的五态语义 |

本轮新增断言 9 条，改写断言 14 条，
其中 3 条是**先写失败再修**（滚动窗口时均口径、证据/上下文分离、chain_id 稳定性）。

> **⚠ 更正（2026-10-19 深夜，§9.26）：**本节原先写着
> 「**没有任何一条断言被删除或放宽。**」——
> **这句话经本轮实测是错的。**
>
> 原文是一句**全称判断**（覆盖整个 `tests/`），
> 而它真正需要的是一个**审计过的结论**。
>
> 本轮首次对工作区相对 `HEAD` 的全部 **18 个被改测试文件**做了逐 hunk 审计
> （16 条被删断言逐条读真实 diff 判定），结果：
>
> | 结论 | 条数 | 说明 |
> |---|---|---|
> | 真加强或语义修正 | **15** | 例如 `test_inc_metrics.py` 把绝对值 `== 1.0` 改成**前后差值 == 1.0**（原写法依赖进程级顺序，全量跑会间歇红） |
> | **真弱化** | **1** | `test_ingest_pipeline.py` 的键集合等式被改成子集断言 —— **已在本轮修复**（§9.26.1 / §9.26.2） |
>
> 那一条弱化**不是本轮引入的**（来自接手时就在工作区的那批未提交改动），
> 但「本轮没有引入」**不等于**「仓库里没有」——
> 而且更关键的是：**此前没有任何工具会发现它**。
> 本轮已把这次人工审计固化成 CI 门禁 `tools/assert-no-assert-weakening.py`（§9.26.3）。

> **2026-10-19 晚间补充（§九）**：本轮另有**两处**判据改写，如实记录：
> `test_q2_3_detection_needs_no_global_lock` 的判据由「只看 `detect()` 的源码」
> 改为「收齐**整条检测执行路径**的源码再判」。
> 触发原因是它**误报**：拆开 `detect()` 后建连接搬进了辅助方法，
> 而**性质并没有变**（每轮仍自建独立连接、路径上仍无全局锁）。
> 按「为变绿而放宽安全要求」处理是不对的，所以改的是判据、不是性质；
> 并用**两次注入**当场证明该守卫仍有分辨力（真回归仍会红）。详见 §9.10.6。
>
> 另一处是 `test_q12_2_public_http_https_allowed`：**结论由环境决定**的用例
> 改为离线可跑，并补上「DNS 解析到私网 IP 必须被拒」这条从未被测过的性质
> （§9.16）。**生产行为未动** —— 改的是测试，不是「为了变绿而放宽安全要求」。

---

## 六、遗留待办

### 6.1 临时探针文件 —— 已清理（本轮）

早前登记的「删除被安全策略拦截、需手动清理」已解决：
`mavis-trash.cmd` 本身被中文路径打坏（cmd.exe 按 ACP 936 读 UTF-8 脚本，
里面的路径被解成乱码），而顶层 `rm -- ...` 又会以「不可调用」被直接拒绝。

绕过办法是直接调它的纯 Node 实现
`node D:\浏览器下载\.minimax\bin\mavis-trash.js <paths...>`。
6 个文件已移入回收站（可恢复）：

```
backend/_review_probe_sigma_id.py
backend/_review_probe_anomaly.py
backend/tests/_tmp_write_probe.py
backend/tests/_tmp_write_probe2.py
backend/tools/_tmp_probe_unbounded.py
backend/tools/_tmp_revert_probe.py
```

顺带修掉 `tools/generate_test_feed.py:78` 遗留的一处 U+FFFD；
全仓扫描后仅剩 `docs/upgrade-proposals/_minimax_daylight_ledger_qa.md`
一处**有意**展示该字符的 QA 台账，不是损坏。

### 6.2 建议的下一步（按优先级）

1. **用生产黄金样本复测**（§4.6）。当前所有数字都来自合成标定集。
   拿到真实流量后重跑 `python -m eval_datasets.evaluate_detection`，
   重点看 1% 基准率下的 Precision，以及 Sigma 在真实 URL 分布上的 FPR ——
   当前 FPR=0.000 只说明**这 21 条样本里没有误报**，不说明规则库在真实
   URL 分布上不会误伤。§4.2 的敏感性表已给出量化预期。
2. **据标定结果决定异常检测阈值**（§4.4 / §9.60）。
   ⚠ **本条已更正（2026-10-20）**：`[0, 0.4357)` 是**召回下界**
   （只约束「不漏掉应检出样本」），**不是可行区间**。
   补齐负类与「结构性不可判」两类约束后，**完整可行区间是空集**
   （下界 0.4957 ≥ 上界 0.4357）—— 逐档体检显示**没有任何阈值**
   能让标定集完全自洽。
   ⇒ **先别动阈值**：降下去会把「全新源 IP + critical + 凌晨」
   这类**结构性不可判**的样本报成已检出。
   要补召回缺口，得先做整改方案 §七.2 的重设计（新证据维度 +
   独立冷启动规则），且需要**有标签的样本**做离线评估。
   **不要照网格值 0.4 调** —— 那是 0.05 扫描网格量化出来的，
   比召回下界低 0.0357（§4.4 已详述）。
3. **据标定结果决定 grounding 与行为档位阈值**（§4.7 / §4.8）。
   这两个评估器此前都把网格落点当成精确边界，本轮已改正并给出精确值：

   | 阈值 | 精确可行区间 | 当前值 | 上侧余量 |
   |---|---|---|---|
   | grounding `grounded` | `(0.7000, 0.9000]` | 0.8 | **+0.1000** |
   | behavior `warn` | `[0.0000, 0.8000]` | 0.6 | +0.2000 |
   | behavior `confirm` | `[0.6000, 0.8000]` | 0.8 | **+0.0000** |
   | behavior `deny` | `[0.8000, 0.9500]` | 0.95 | **+0.0000** |

   > ⚠️ **本表于 §9.66 更正。** 原值 `[0.0000, 1.0000]` / `[0.0000, 0.8000]` /
   > `[0.0000, 0.9500]` 越出了评估器自己声明的域 `warn <= confirm <= deny`。
   > 另：这三个「余量」**不能**被读成「有 0.20 的调节空间」——
   > 实测三个阈值在各自域内区间上**都不改变任何一条样本的处置档位**
   > （维度分是离散常量）。详见 §9.66。

   > ⚠️ grounding 那一行在 §九.2 修掉黄金样本集时间锚点**之前**是
   > `(0.6000, 0.8000]` / 余量 **+0.0000**。当时「上侧余量为 0」被写进
   > 结论「三个阈值的上侧余量都是 0」——现在看，那个 0 是夹具污染
   > （freshness −0.10）恰好把最紧的干净样本压到当前阈值上的**巧合**，
   > 不是标定集的性质。修好后 grounding 实际有 0.10 的上侧余量，
   > 真正调不上去的是 behavior 的 confirm / deny 两个阈值。
   >
   > **「某阈值的余量恰好是 0」在写进结论之前，应先怀疑输入，而不是直接归因于数据集。**

   behavior 的 confirm / deny 两个阈值上侧余量仍为 0 —— 在现有**合成**标定集下
   它们一点都调不上去。但这**不等于**「阈值该降」：合成集代表不了生产分布（§4.6）。
   需要扩真实标注样本才能给出可用的定标区间；
   在那之前，任何调阈动作都是在过拟合 9 条计入样本。

   > ⚠️ **本段于 §9.66 补正一处前提**：上面那句「扩真实标注样本才能给出可用的
   > 定标区间」，**对上侧余量不成立** —— 扩样本**不能**放宽上界（实测见 §9.66）。
   > 真正卡住上侧的是**维度分常量与阈值同值**这个结构事实。
   > 扩样本仍然是必要的，但目的不是「把上界推上去」，
   > 而是「让下界与生产分布对齐」以及「暴露更多未见的矛盾」。

   守卫：`test_p3_grounding_calibration.py` 35 例、
   `test_p3_behavior_calibration.py` 48 例（§9.66 契约改写 2 条后），均做过注入验红。
4. **Flink 聚合作业的运行验证**（§4.3.1）—— **「编译」与「窗口逻辑执行」本轮已关闭**。
   装了 Maven 3.9.9 + JDK 21 后，`mvn -B -DskipTests compile` 在 `flink-jobs/`
   下 **BUILD SUCCESS**，15 个源文件全部编译通过，产出
   `SigmaThresholdAggregationJob{,$SigmaHit,$ThresholdWindowFunction}.class`。
   已固化为回归 `test_flink_jobs_compile`。
   随后又用进程外 harness 把**真实的窗口函数**在真实 JVM 里跑起来，
   17 条断言钉住阈值方向、最严归并、字段透传与跨语言契约（§三.4）。

   **仍未关闭：作业从未在真实 Flink 集群上运行过。** 编译与进程外执行
   证明的是**窗口函数本身的逻辑**，不是窗口算子的运行语义 ——
   5m/1m 滑动窗口的边界行为、同 key 并发、水位线、
   处理时间 vs 事件时间，仍需集群实测。
5. **补聚合链路的端到端联调**（§4.3.1）。Python 侧（单事件 → 载荷 → 白名单 →
   消费端 → 策略匹配）已逐层验证，第 6 层有端到端断言证明能匹配到
   `暴力破解自动阻断` 策略。但「6 次登录失败 → 窗口出告警 → 响应引擎下发封禁」
   这条真实链路**没有跑过**，因为需要 Kafka + Flink 集群。
6. **确认 Flink 作业的部署顺序**。backend 会往 `security-sigma-hit`
   发候选，而该作业是 `submit-jobs.sh` 默认提交的第三个作业。若部署时
   作业尚未启动，候选会堆积在 topic 里无人消费 —— 而单事件阶段又已经
   禁止处置，结果是**既不封也不告警**。上线前需确认启动顺序与 topic 保留策略。

   **本轮已把可验证的那一环做掉（§6.5）**：跨语言 topic 契约守卫，
   16 例，且**刻意不依赖 Maven/JDK**，不会像那 18 条真编译断言一样静默跳过。
   另修正本条的风险描述 —— 原写法暗示「积压会无限堆积」并不准确，
   真实边界见 §6.5.2。

7. 用真实 CAPE 实例枚举一次任务状态词表，补全 `map_cape_status()`。
8. 在**真的没有 scipy** 的环境跑一次因果链。
   （本轮已把 `_chi2` 置 None 逐点验证：df 1~40 × 14 个统计量共 560 点，
   最大误差 3.775e-15，df≤0 返回 NaN、stat=0 返回 1.0、stat=inf 返回 0.0
   —— 这条可以从待验证清单里划掉。）
9. 若已有真实 PostgreSQL，补测 `events_to_matrix` 与 `pc_skeleton`
   在真实稀疏度下的 `untestable_pairs` 比例 —— 若该比例很高，
   说明 PC 的骨架会因「无法判定」而偏稠密，需要重新评估 α 或采样密度。
10. **给检测引擎补告警与面板**（§7.1.15）。本轮新增的
    `soc_detection_outcomes_total` / `soc_detection_seconds` 在仪表盘与告警里
    零出现，66 个指标里 **44 个**处于「被产出但仓库内无 Prometheus 消费面」
    （守卫口径，与 `UNWATCHED` 登记表**逐项相等**；报告早期用的原始引用并集口径是 45，
    差在 2 个 Histogram 基础指标上 —— 见 §9.37）。
    **需要用户拍板**：新增告警会产生值班呼叫，属运维行为变更；
    44 个指标的接线优先级也取决于运维实际关心什么。
    守卫 `tests/test_metric_consumer_guard.py`（4 passed / 2 strict xfail）已就位，
    一旦接线，`UNWATCHED` 登记表会立刻转红提醒同步。
11. **处置前端两条必然失败的请求**（§7.1.16）。`opsFeedbackList`
    （GET `/api/feedback`，后端只有 POST → 405）与 `opsFeedbackReview`
    （POST `/api/feedback/{id}/review`，后端无路由 → 404）。
    二者前端均无调用方，线上无感；**需用户决策**：删除这两个客户端方法，
    还是补后端 `GET /feedback` 与 `POST /feedback/{id}/review`。
    守卫 `tests/test_api_contract_guard.py`（4 passed / 1 strict xfail）已就位，
    处置后必须同时销号，否则 xfail XPASS 与登记过期两条会同时转红。
12. **给 DLQ 接 UI 入口**（§7.1.17）。DLQ 四个端点（列表 / 详情 /
    **replay** / dry-run）后端齐全，`frontend/src` 零调用，全仓唯一引用是
    `http_guards.py` 的限流点名表。死信重放是 DLQ 存在的理由，
    却是运维唯一做不了的操作。与 §7.1.5 休眠能力清单同源，
    **需用户决策接线优先级**。
    守卫已把这件事钉成 strict xfail，并留了前提守卫：
    一旦 DLQ 出现新消费方，结论会主动要求重估而不是静默过期。
13. **把反假门禁接到主测试套件**（§6.6）。`ci.yml:66` 的 `backend-test` job
    只跑 `pytest --cov-fail-under=20`，**没有** `--junitxml`、
    也没有 skip 断言 —— 也就是说 §6.5 批评的「pytest 全跳过也退出 0」
    那个坑，在主套件上完全没有防护。

    本轮已把工具备好并实测通过（本机全套 2212 条用例）：

    ```bash
    python -m pytest tests -q --junitxml=full.xml
    python tools/assert-junit-no-skip.py full.xml \
        --min-tests 2000 \
        --allow-skip-file test_sigma_aggregation_action_chain \
        --max-xfail 53
    ```

    豁免那 18 条是必须的：`backend-test` 不装 Maven，它们必然跳过；
    而那 18 条由 `flink-verification` job 用「0 跳过 + ≥60 条」严格校验，
    两边合起来是完整的。**未直接改 CI 的原因**：CI 环境与本机不同
    （无 `.env`、不 deselect 那条时序脆弱用例），我无法在这里端到端验证，
    改合并门禁属部署面变更，留给用户拍板。
14. **决定 Kafka 权威 schema 是否收紧取值范围**（§7.1.19）。
    `schemas/security_event.schema.json` 在 `description` 里写了
    `confidence [0,100]` / `timestamp 2020~2030` / `message 最长 500 字符`，
    但**没有对应的 `minimum` / `maximum` / `maxLength` 关键字**，
    实测越界值全部放行（`confidence=500`、`timestamp=-1`、10 万字符 message）。

    **本轮刻意没有直接收紧**：那是契约变更，会让真实生产方开始被拒，
    而本机不知道真实取值范围（confidence 是 0~100 还是 0~1？timestamp
    会不会被用 `-1` 当哨兵？仓库里无证据）。误拒与漏报同级，且这种改动
    不会让任何东西变红 —— 只会让真实流量悄悄进不了 DLQ。

    **需用户决策**：收紧与否，以及三个字段各取什么范围。
    守卫 `tests/test_kafka_field_range_gap.py`（20 例，普通断言非 xfail）
    已把「缺口当前存在」钉死 —— 一旦加了范围约束就会转红，强制更新登记。

### 6.3 §十一.2 死代码处置 —— 13 个零引用符号逐个查证（本轮）

整改方案 §十一.2 要求「删除或实现长期无人调用的死代码」。
做法：扫 backend 顶层 668 个 def/class，对全仓 789 个文本文件做引用统计，
得到 13 个**零引用**符号。逐个查证后按三类处置 —— 其中**两个是真缺陷**。

#### 6.3.1 真缺陷：指标声明了却无人自增，读数结构性恒为 0

| 符号 | 缺陷 |
|---|---|
| `metrics.inc_intel_ioc` | `routers/capabilities.py:20` 正是用 `soc_intel_ioc_*` 给 `/api/capabilities/status` 的 `threat_intel.count` 赋值，而该计数器**零自增点** → 面板恒显示「已启用、0 条」 |
| `metrics.inc_capture_packet` | `soc_capture_packets_total` 在 `/metrics` 暴露给 Grafana，同样零自增点 |

危害不是「少了个数字」，而是 **0 与「没事件」完全同形**：
采集链路整个断了，看板读数却与一切正常无法区分。

已接线（`threat_intel/stix_taxii.py::poll_feed`、`traffic_capture/capture_engine.py`）：

- `poll_feed` 是 taxii / misp / csv / stix_bundle 四种源的**唯一**汇聚点，
  计数打在这里，`source` 标签取 feed 的 `name`（与 IOC 自带的 `source` 同源）。
- `_on_packet_scapy` 是全仓唯一的包摄入收敛点 —— AF_PACKET / DPDK 后端
  在 `capture_engine.py` 里是**占位实现**（只 `sleep`，不摄入包），
  故这一处覆盖全部真实抓包流量。埋点单独 `try` 包住：
  绝不能连带跳过下面的 handler 派发。

回归 `backend/tests/test_dead_code_remediation.py`（12 例）。
其中最关键的一条是**端到端**而非只看计数器：

```python
text = generate_latest().decode()
total = _parse_metric_values(text, "soc_intel_ioc_")   # capabilities.py 自己的解析器
assert total >= 3
```

前端看的是 `_parse_metric_values` 的输出，不是 REGISTRY 的原始样本 ——
只断言计数器自增，证明不了前端那个数字会动。

**修复前实测 7 failed / 5 passed**（红的正是两条接线 + 端到端那条）。

> **⚠ 结论纠正（本轮后续查证，见 §7.1.5）：本节的修复只消除了 0 的**一个**成因，
> 面板在生产里仍然会显示 0。**
>
> `poll_feed` 所在的 `threat_intel/stix_taxii.py` 本身在生产代码里**零导入** ——
> 整个 `threat_intel` 包是休眠的，没有任何生产路径会去拉情报。
>
> 所以准确的表述是：**「即使有人接上情报拉取，计数也会动」**，
> 而不是「面板现在会显示真实条数」。
>
> 这正是「两段都有测试 ≠ 中间那段被测过」的另一种形态：
> `test_dead_code_remediation.py` 的端到端断言直接调 `poll_feed`，
> 它证明的是**计数点本身正确**，证明不了**计数点会被执行到**。
> 前者绿，后者红，而且两者可以同时成立。
>
> 之所以当时没能发现：`poll_feed` 恰好是「四种源的唯一汇聚点」，
> 这个性质让「选对计数点」看起来已经等价于「计数会动」。
> 选点正确与可达是两件事。

#### 6.3.2 一个「看起来该接线、接了反而改结论」的坑

`veto_gates.has_admitted_threat_claims` 零引用，名字读起来正是
`apply_confirmation_gate(has_admitted_claims=...)` 该用的东西。

**本轮试着接了，然后回退了。** 原因：

- 生产判定用的是 `len(threat_claims) > 0`。两者在生产路径上**恒等** ——
  `ChunkVerdict.threat_claims` 必由 `strip_ungrounded_claims` 写入，
  而它只收 `ADMITTED_VERDICTS`；executor:917 的异常分支 `threat_claims` 为空，
  两种写法也一致。所以接线**不修任何缺陷**。
- 但它判的是「`grounding_verdict` 注解在不在」，**不是 grounding 本身**。
  接上后，一个「带真实 `evidence_ids` + `evidence_quotes`、只是没带注解」的
  claim 会被判为无据 —— **有证据的威胁被降级成 `insufficient_evidence` 并强制人审**。
- 全量回归立刻暴露：`test_p1a_evidence_and_recheck` 与
  `test_p1b_terminal_state` 共 **3 条既有用例转红**（结论被改写）。
  `test_silence_is_not_contradiction` 的断言是
  `assert res.verdict != "insufficient_evidence"` —— 复核沉默场景直接失效。

结论：**这不是死代码清理，是 P0-1 的语义收紧决策**，不能顺手带上。
已回退接线，并在 `has_admitted_threat_claims` 的 docstring 里写明
「不要接到确认闸入参上」及其理由 —— 保留它是因为**名字正是会诱人接线的因素**，
删掉反而抹掉这个警示。差异本身由 `test_verdict_check_diverges_from_production_count_on_unannotated_claims`
钉住；真正的行为守卫是上面那条既有用例。

#### 6.3.3 已删除（3 个）

| 符号 | 删除理由 |
|---|---|
| `retry_policy.map_gather_result` | 函数体就是 `return item`（恒等），但 docstring 声称「还原成值或异常」——**一个撒谎的死函数**，比没有更糟 |
| `otel_setup._tracer` | HTTP 中间件与 `pipeline_tracer.py` 本就直接调 `otel_trace.get_tracer()` 且各带不同 tracer 名，这是从未用到的第三份写法。删除后同步修正模块 docstring（原文写「提供 get_tracer()」，已不成立） |
| `trace_context.span_id_to_bytes` | 零引用。连带清掉因此变成未用的 `import os` 与 `_SPAN_ID_RE` —— 删一半会**制造新的死代码** |

#### 6.3.4 查证后确认不是缺陷，保留（6 个）

| 符号 | 判定依据 |
|---|---|
| `trace_hook.register_trace_recorder` | 覆盖钩子。模块末尾 line 162 已把 `_recorder` 初始化为 `_lazy_recorder`，`emit_trace` 照常落 AgentTrace —— 不是「轨迹静默丢失」 |
| `auth.TokenPayload` | 疑似 FastAPI/Pydantic 模型 |
| `ingest_pipeline.PersistItem`、`memory_tree.CorrelationGroup` | dataclass |

> **⚠ 本节原有第 4 条已于 §7.1.10 更正为缺陷，原判定撤回。**
> 原判据是「`models.ToolSignature`、`models.ToolAnomaly` 是 SQLAlchemy 模型，
> 零引用是 ORM 常态，删会掉表」。
> 「零引用是 ORM 常态」在本仓库**不成立** —— 全仓 50 个 ORM 模型里
> **46 个有生产写入方、48 个有生产读取方**，零读零写的只有这 2 个。
>
> 它们不是「ORM 常态」，而是**持久化脚手架铺了四层（表 / 配置 / 构造器钩子 /
> 保留期）、唯独缺写入那一层**的真实缺口：
> `BehaviorDetector(persist=...)` 是死参数，`self._dirty` 只写不清不读，
> `tool_signature_log_retention_days` 零读点。
> 详见 **§7.1.10**，守卫 `tests/test_tool_signature_persistence_gap.py`。

`event_identity.prepare_event` 保留：它是 `ensure_identity` + `resolve` 的
三行组合，两者都在生产使用，不属于「长期无人调用的死代码」。

### 6.4 §十一.2「运维决策状态词表保持一致」——查证与修复（本轮）

#### 6.4.1 全仓词表扫描

AST 扫出 33 个模块级状态型词表常量，逐一比对后发现**同一个事件上有三套都叫
`status` 的词表**，分处不同存储：

| 位置 | 词表 | 用途 |
|---|---|---|
| `SecurityEvent.status`（DB 列） | `new \| acknowledged \| investigating \| resolved \| closed \| false_positive` | 案件生命周期 |
| 分析状态（Redis 缓存） | `completed \| failed \| fallback \| pending \| running \| skipped` | 审核流水线 |
| `raw_data._audit_llm.status` | `completed \| failed \| fallback` | 审计载荷 |

**逐个查证读方后确认：未发现读混。** `case_manager` / `feedback_loop` /
`rule_manager` / `learn_loop.harvest` 读的都是 DB 列且只用案件词汇；
`routers/ops.py` 读的是 `_audit_llm.status` 且只用分析词汇。
`event_store.update(status=...)` 虽然签名上接受任意值，
但全仓无调用方传 `status=`。据实记录为**命名隐患而非缺陷**，未做改动。

严重度另有 4 套并存的口径（`veto_gates.SEVERITY_ORDER` 5 级含 info、
`sigma_engine.SEVERITY_ORDER` 4 级无 info、`evaluate_detection.SEVERITY_RANK`
4 级无 info、Capec 的 `very high/very low` 五级制）。它们分属不同子系统，
未见交叉消费，本轮只登记不统一。

沙箱侧 `zeroday_detect/sandbox_status.py` 的词表经查证**是完整的**：
`timeout` / `unavailable` 都在 `ALL_TASK_STATUSES` 里 —— 它们不在
`_CAPE_STATUS_MAP` 是正确的，因为那两者是客户端条件而非 CAPE 返回值。

#### 6.4.2 真缺陷：终态事件被永远显示成「分析进行中」

`routers/ops.py::observability_thought_chain`（admin 运维监控页）的状态推导：

```python
status = "running"            # ← 无条件默认
if evt:
    st = (audit or {}).get("status") or ""
    if st in ("completed", "failed", "fallback"): status = st
    elif getattr(evt, "analyzed", False) and audit: status = "completed"
    elif raw.get("_audit_llm_error"): status = "failed"
# 三者都不命中 → 保持 "running"
```

缺口：`evt.analyzed=True` 但 `raw_data` 里没有 `_audit_llm` 时，三个分支全不命中。

**这不是假设**：`_mark_analyzed` 只在 `if db_evt and not db_evt.analyzed`
时才写 `_audit_llm`（`log_ingestion.py:648`），对**已分析过**的事件是空操作。
于是「重复处理 / 载荷写入失败」都会留下 `analyzed=True + 无载荷` 的组合。
`_audit_llm: {}` 走同一条路径（`audit or {}` 把空字典一并归一掉）。

后果：分析早已终结，监控页却一直显示「分析进行中」，**永不收敛**。
运维会一直等一个已经结束的审核 —— 比报错更糟。

修复：抽出 `_derive_chain_status()`，把 `running` 收窄为「确实尚未标记
`analyzed`」这一种情形，已终结却拿不到状态的一支改吐 `unknown`
（与 running 可区分、且不渲染成空白）。既有语义原样保留 ——
审计载荷存在但状态非终态时仍归 `completed`，由
`test_audit_payload_without_terminal_status_still_falls_back_to_completed` 钉住。

回归 `backend/tests/test_ops_chain_status.py` 10 例，
**修复前 3 failed / 7 passed**（红的正是缺口那三条，
其余 7 条钉住既有语义未被改动）。测试走**真实端点函数**，
只替换 `event_store.get_by_id` 与 `thought_events.snapshot` 的 IO ——
不打在 `ops_router` 模块属性上，因为端点在函数体内 `from event_store import`，
打模块属性不生效（第一次就这么踩了）。

另加 `test_emitted_status_always_from_the_declared_vocabulary`：
遍历 7 种事件形态，断言端点只吐
`{running, completed, failed, fallback, unknown}` 里的值。

### 6.5 跨语言 Kafka topic 契约守卫（本轮新增，对应 §6.2 第 6 条）

#### 6.5.0 附带核实：CI 的「反假门禁」本身双向可用（本轮）

§6.2 第 6 条末尾声称「CI 侧由 `flink-verification` job +
`tools/assert-junit-no-skip.py` 覆盖」。本轮**实测了这个门禁本身**，
而不只是确认文件存在 —— 一个从没被执行过的门禁和一个不存在的门禁，
在仓库里长得一模一样。

`ci.yml:155` 的 `flink-verification` job 确实存在，装了 JDK+Maven，
预热 `~/.m2`（窗口 harness 用 `mvn -o` 离线跑），最后
`ci.yml:198` 用 JUnit XML 反过来断言「0 条跳过且执行数 ≥ 60」。

**两个方向都跑了：**

| 环境 | pytest | `assert-junit-no-skip.py --min-tests 60` |
|---|---|---|
| PATH 含 Maven 3.9.9 | `76 passed, 0 skipped`，**exit 0** | **exit 0**：`76 条用例真实执行，0 跳过` |
| PATH 无 Maven | `58 passed, 18 skipped`，**exit 0** ← pytest 不区分 | **exit 1**：逐条列出 18 个跳过的用例 |

> **左列第二行就是整个设计的意义**：pytest 在「全部跳过」时**退出码仍是 0**，
> 只看 pytest 的 CI 门禁会把 18 条真编译/真执行断言的缺席放过去。
> 右列证明 `assert-junit-no-skip.py` 拦得住，且**逐条点名**是哪些，
> 不是只报一个总数。
>
> 同时确认 `--min-tests 60` 这个阈值**可达到**（实测 76 条），
> 不是一条永远红的假门禁 —— 阈值定得高但实际跑不到，和没设是一回事。

#### 6.5.1 为什么两侧各自一份字面量是个隐患

backend 与 flink-jobs 各自持有一批**互不相关的 topic 字面量**：

| 位置 | 形式 |
|---|---|
| `flink-jobs/.../util/KafkaConfig.java` | `TOPIC_*` 常量 |
| `backend/config.py` | `kafka_topic_*` 配置项 |
| `backend/kafka_consumer.py:74` | 模块级 `DLQ_TOPIC` |

**当前 10 个共享 topic 全部一致**，所以本节是**回归守卫，不是缺陷修复** ——
如实说明，避免把它记成一次「修了个 bug」。

但不一致的后果是**完全静默**的：producer 把消息发到一个没人消费的 topic，
消费端那个 topic 永远空，**没有任何报错**。以 `security-sigma-hit` 为例，
三件事叠加即「既不封，也不告警，且看不出原因」：

1. backend 只在候选命中时往该 topic 发（`kafka_producer.py:195`）；
2. 唯一消费者是 `SigmaThresholdAggregationJob`，是 `submit-jobs.sh` 里
   **第三个**提交的作业；
3. 聚合告警不回写 → 无策略匹配 → 不告警，而单事件阶段本就禁止处置。

#### 6.5.2 修正风险描述：积压不是无限堆积

原 §6.2 第 6 条写「候选会堆积在 topic 里无人消费」，措辞暗示无限增长，
**这不准确**。`SigmaThresholdAggregationJob.java:104` 用的是
`OffsetsInitializer.earliest()`，因此作业一旦启动就会**从头消费**，
积压可自愈。真实边界是：

* **自愈条件**：作业启动前消息未被 retention 清除。
* **真正不可逆的窗口**：broker 保留期先到、消息已过期 —— 那段攻击事件
  **永久丢失**，且没有任何补偿。
* **仍然存在、且本轮修不掉的**：作业长期未启动期间，backend 侧**只有发送
  计数、没有消费可见性**。「聚合告警变少」既可能是「没攻击」也可能是
  「作业挂了」，两者读数同形。

最后一条要动 `stats()` 并新增停滞检测指标，属于新增功能，
本轮只登记，未实施。

#### 6.5.3 守卫设计与验红

新增 `tests/test_flink_topic_contract.py` **16 例**：

| 用例 | 守什么 |
|---|---|
| `test_sigma_hit_topic_matches_across_languages` | 本次重点：聚合候选 topic 两侧同名 |
| `test_all_shared_topics_match`（10 参数化） | 10 个共享 topic 逐一比对 |
| `test_dlq_topic_matches` | DLQ 走模块常量而非 settings |
| `test_every_java_topic_has_an_explicit_decision` | **防漂移核心**：新增 `TOPIC_*` 必须逼出一次明确表态 |
| `test_declared_java_only_topics_still_exist` | 反向检查：`JAVA_ONLY` 不得有过期登记 |
| `test_every_java_only_entry_has_a_reason` | 孤儿常量登记必须写原因，空串等于没登记 |
| `test_sigma_job_consumes_the_shared_constant` | 消费端不许内联字面量（避免契约被复制到第三个文件） |

**刻意不依赖 Maven / JDK。** `test_sigma_aggregation_action_chain.py` 的 18 条
真编译断言在 PATH 无 Maven 时会静默跳过（退出码仍是 0）—— 跑没跑都绿的守卫
等于没有。topic 名字是纯文本字面量，正则即可读出。

**验红**：把 `TOPIC_SIGMA_HIT` 改成貌似合理的笔误
`security-sigma-hits` → **2 failed**，精确报出两侧值与差一个字符；
还原后 `git diff` 无差异、16 passed。实测确认守卫生效，
而不只是「当前恰好一致所以是绿的」。

---

### 6.6 ⚠ 真实修复：`assert-junit-no-skip.py` 把 xfail 当成 skip（本轮）

§6.5.0 验证那个反假门禁「可用」的时候，顺手把它接到主套件上试了一次，
**当场翻车**。

#### 缺陷

pytest 的 JUnit XML 里，**xfail 和 skip 都写成 `<skipped>` 元素**，
只靠 `type` 属性区分：

```xml
<skipped type="pytest.xfail" message="已知缺口：..."/>   ← 已登记的缺口
<skipped type="pytest.skip"  message="未安装 Maven..."/> ← 根本没在验
```

而这个脚本第一版写的是：

```python
skipped = root.findall(".//skipped")     # 两者一视同仁
```

实测主套件：71 条 `<skipped>` = **18 条真 skip + 53 条 xfail**。
照第一版判据，这 53 条已登记的已知缺口会被报成
「有 53 条用例被跳过 —— 这条门禁没有在验任何东西」。

**这不是误报，是恒红。** 门禁一旦恒红，就等于没有门禁 —— 和
§6.5 开头批评的那个「只跑 pytest」的 CI 步骤是同一种失效，只是方向相反。

> 它在 `flink-verification` job 上一直没出事，
> **只是因为那个文件恰好一条 xfail 都没有**（实测 0）。
> 不是判据对，是运气好。
>
> 这正是本会话反复强调的那条：**「在当前条件下没出事」不等于「判据正确」**。

#### 修复

`tools/assert-junit-no-skip.py` 按 `type` 分流，并新增两个能力：

| 能力 | 用途 |
|---|---|
| xfail 与 skip 分开计数 | 「已知的、被人盯着的缺口」和「因为环境缺失所以没在验」不再同形 |
| `--allow-skip-file` | 允许某个已知文件的跳过（该文件由另一个 job 用完整工具链校验） |
| `--max-xfail` | 钉住 xfail 账本规模，防止「用 xfail 悄悄带过新问题」 |

#### 实测（五个方向，全跑过）

| 场景 | 结果 |
|---|---|
| 全套，无豁免 | **exit 1**，准确报出 18 条，并注明「53 条 xfail 不计入」 |
| 全套 + `--allow-skip-file test_sigma_aggregation_action_chain` | **exit 0**：`2212 条真实执行，18 条跳过（豁免），53 条已知缺口` |
| 全套 + 豁免 + `--max-xfail 52` | **exit 1**：xfail 53 超限 |
| flink 文件，无 Maven，无豁免 | **exit 1**（严格性未退化） |
| flink 文件，有 Maven，无豁免 | **exit 0**：76 条真实执行，0 跳过，0 xfail |

> `--allow-skip-file` **不是万能钥匙**：回归里专门有一条断言，
> 把同一批跳过换个文件归属就必须报出来（`test_guard_allow_skip_file_only_exempts_that_file`）。

#### 回归

`backend/tests/test_ci_flink_gate.py` 由 9 例扩到 **13 例**，新增 4 条：

- `test_guard_does_not_count_xfail_as_a_skip` —— 全 xfail 的运行必须判通过
- `test_guard_still_flags_real_skips_alongside_xfails` —— 两者混存时真 skip 仍要报
- `test_guard_allow_skip_file_only_exempts_that_file` —— 豁免必须按文件粒度
- `test_guard_max_xfail_pins_the_known_gap_surface` —— xfail 账本可钉

**验红**：把 `if kind == "pytest.xfail":` 改回 `if False:` 注入缺陷，
上述 4 条中 **2 条转红**，还原 sha256 一致。

> 顺带修掉一个因签名变更而破裂的既有用例
> （`test_guard_reads_both_junit_layouts` 断言 `analyze()` 返回 2 元组）。
> 这不是「让测试变绿」的改动，是跟着实现一起改的断言。

#### 量具校准：本机为什么不能直接信 `exit=-1`

测这五条时，前两条一度显示 `exit=-1`。那**不是门禁的行为**，
是 PowerShell 的 `Select-Object -First` 掐断了管道、
把还没跑完 `sys.exit()` 的 native 进程杀掉。
把输出收进变量重测：

```
A) 全套 无豁免        exit=1
D) flink 无 Maven     exit=1
B) 全套 + 豁免        exit=0
```

> 靠退出码判成败的命令，输出**不要接 `Select-Object -First`**。
> 量具谎报「失败」和谎报「成功」一样致命。

## 七、§十一 P2：统一检测指标盘点与计划

整改方案 §十一 P2 的要求是「最好在本轮结束前**形成明确计划**」。
本节是逐条实测后的盘点 —— 数字来自实际调用各引擎的 `stats()` /
`observability` 取到的字段，**不是 grep 推测**。

### 7.1 逐条覆盖情况

> **本节 19 条普查结论（§7.1.1 ~ §7.1.19）全部有专门守卫在持续复测**，
> 因此它们**不会**像本文档其它章节的数字那样静默过期。2026-10-19 逐节核对了
> 「每条是否引用了 tests/test_*.py」，结果是 19/19 命中。
>
> 守卫的形态值得说清楚 —— 以 §7.1.11 的 `test_config_switch_wiring.py` 为例，
> 它是**三重**而不是单一断言：
>
> | 层 | 作用 |
> |---|---|
> | **活扫** | 每次运行都重新扫 `Settings` 字段与读点，「37 个读不出来」是扫出来的而非写死 |
> | **绊线** | `len(fields) == 329` —— `config.py` 一改就红，并提示「请重新跑全量普查并更新报告」 |
> | **分辨力前提守卫** | 断言「≥250 个字段有活读点」，防止「37 个读不出来」与「扫描器什么都没匹配上」同形 |
> | **已知答案抽检** | `KNOWN_ZERO_READ` / `KNOWN_DORMANT_ONLY` / `KNOWN_LIVE` 逐个核对，强制三类区分开 |
>
> **所以：哪些数字需要人工核对？** 本文档 §一、§四、§六、§九 里的**数字快照**
> （用例计数、阈值区间、混淆矩阵、待决项条数）。这些没有守卫在复测，
> 每次加用例或改实现都可能让它们过期 —— 2026-10-19 那次核对发现的 10 处过期
> 全部来自这一类。§7.1 各条则不需要。

| §十一 要求的指标 | 覆盖 | 实际字段 |
|---|---|---|
| 成功/命中/未命中/**部分失败**/执行错误 | ✅ **本轮补齐** | `soc_detection_outcomes_total{detector,outcome}` 五态分列（§7.2） |
| 各检测器耗时分布 | ✅ **本轮补齐** | `soc_detection_seconds{detector}` Histogram（§7.2） |
| 规则编译失败和跳过规则数 | ✅ | `load_errors` / `skipped_rules` / `compiled_count` / `run_mode` |
| 异常检测基线样本量和**基线版本** | ✅ **本轮补齐** | `AnomalyReport.baseline_samples` + `baseline_version`（单调代数，跨重启持久化） |
| 关联链匹配数、被拒绝的链及原因 | ✅ **本轮接线（原为过度声明）** | `chains_matched` / `chains_partial` / `chains_overlapping` / `reject_reasons`；本轮补上 `/api/security/chains` 的返回，修复前该属性零消费方（§7.1.3） |
| 因果检验的自由度、稀疏度、未定向边数 | ✅ **本轮补齐** | `pc.stats.undecidable`（原因拆分：`too_few_rows` / `all_strata_degenerate` / `df_degenerate`）+ `undirected_edges` / `directed_edges` |
| 沙箱提交失败、超时和悬空任务数 | ✅ | `by_status` / `by_failure_reason` / `dangling_tasks` / `verdict_capable` / `not_verdict_capable` |
| 聚类无有效特征数、样本重复率、**特征截断数** | ✅ **本轮补齐** | `samples_without_features` / `duplicate_submissions` / `truncated_features` + `truncated_features_ratio` |

> **这张表统计的是「指标是否被产出」，不是「产出它的能力是否被执行」。**
> 后者是另一层，全仓有 20 块能力在生产里零调用，见 §7.1.5。
> 举例：本表说「沙箱 `by_status` ✅ 已覆盖」是对的（提交/轮询确实在跑），
> 但同一条链下游的 `behavior_analyzer` 与 `variant_cluster` 是休眠的 —— 见 §7.1.4。

「部分失败」这条特别值得记：整改方案 §二要求把 partial 与阴性分开，
而 §十一 又要求「不能把这些状态压成一个 not_detected 计数」。

> ⚠ **本节原先写着「跨事件的累计口径还没建 —— 现在没法回答
> 「过去一小时有多少事件因为证据不足没下结论」」，这句话是错的，已更正。**
> 它与同一节表格里的「部分失败 ✅ 本轮补齐」自相矛盾，而且**方向反了**：
> 累计口径恰恰是有的。

**实测（本轮）**：跑真实 `PySigmaDetector` 过标定集，3 个待聚合用例
（`SIG-P-04` / `SIG-P-05` / `SIG-N-03`）全部 `status='partial'`，
`soc_detection_outcomes_total{detector="sigma",outcome="partial"}` 恰好 **3.0**，
`not_detected` 9.0、`detected` 8.0。
所以这个问题**现在就能回答**：

```
rate(soc_detection_outcomes_total{detector="sigma",outcome="partial"}[1h])
```

### 7.1.1 补上「引擎 → 计数器」那一段的端到端覆盖（本轮新增）

这条错误能长期留在报告里，是因为**没有任何测试会问这个问题**：

| 已有测试 | 覆盖范围 |
|---|---|
| `test_detection_metrics.py` | 直接调 `record_detection()` + 替换 registry —— 测的是**计数器本身**（clamp / 白名单 / 不被合并） |
| `test_p3_detection_calibration.py` | 测的是**引擎本身**（`status == "partial"`、`pending_aggregation` 非空） |
| **中间那段** | ❌ 无人测 |

即「真实检测调用 → 引擎算 status → `record_detection` → 五态计数器」这一段
没有任何覆盖。中间脱节时（引擎改了 status 名、包装层忘透传、计数器被换掉），
上面两个测试**照样全绿**，而面板上的五态分布**全是错的**。

新增 `tests/test_detection_metrics_end_to_end.py` **4 例**，直接跑真实引擎：

| 用例 | 守什么 |
|---|---|
| `test_calibration_set_actually_contains_every_state_it_claims` | 前提守卫：标定集必须真产出 partial，否则端到端断言**空跑恒绿** |
| `test_partial_status_reaches_the_counter_end_to_end` | 真实引擎产出的 partial 必须累加进 partial 桶 |
| `test_partial_is_not_absorbed_into_not_detected` | partial 必须单列，「没结论」不得被记成「阴性」 |
| `test_every_call_lands_in_exactly_one_bucket` | 五桶之和 == 调用数；任何白名单外 status 会被 `clamp_label` **静默**记成 error |

**验红**：把 `sigma_engine/engine.py` 传给计数器的 status 写死成
`"not_detected"`（模拟「引擎改了 status 名、包装层忘透传」）→
新守卫 **2 failed**，而 `test_detection_metrics.py` 与
`test_p3_detection_calibration.py` **全绿** —— 这正是那段盲区的直接证明。
还原后 4 passed。

教训与 §7.4 那条同源：**「两边分别都有测试」不等于「中间那段被测过」**。
链路型指标必须有一条真跑全链的用例，否则断点会长期无人发现。

### 7.1.2 指标骨干接线守卫：把「声明了却无人自增」变成回归（本轮新增）

§7.1 点名的「悬空任务数」「执行错误」等指标，本轮做了一次全量接线核查
（`metrics.py` + `core_metrics.py` 全部 `inc_/note_/record_/set_` 写入器，
逐个统计生产调用点）。

**结论：除本轮已修的两个之外，全部接线**，`UNWIRED` 表为空。这是查证后
确认的否定结论，不是「没查」。

新增 `tests/test_metric_wiring_guard.py` **8 例**：

| 用例 | 守什么 |
|---|---|
| `test_scan_actually_found_writers` | 前提守卫：扫描器要真扫到东西（≥30 个），否则后续断言空跑 |
| `test_every_metric_writer_is_called_in_production` | 任何写入器在生产代码零调用点即红 |
| `test_internal_callers_count_as_wired` | 防止扫描口径退回「排除定义文件」 |
| `test_unwired_allowlist_has_no_stale_entries` | 双向检查登记表不过期、不多登记 |
| `test_every_unwired_entry_states_a_reason_and_action` | 登记必须写理由，空串等于静默白名单 |
| `test_the_two_accidentally_unwired_metrics_are_now_wired` | 定向回归：那两个指标确实接上线了 |

**验红**：把 `poll_feed` 里的 `inc_intel_ioc` 调用临时摘除 →
**2 failed**，报出「零调用点」并指出后果是
`capabilities.status 的 threat_intel.count 恒为 0`。还原后 18 passed
（与死代码处置那 12 例合跑）。

#### 写这类扫描器时的固有陷阱（本轮踩了两次）

第一版扫描口径把「正在被扫描的那个文件」整体排除（理由：避免自引用计数），
结果连续误报三个：

* `note_dlq_open` ← 被 `record_dlq_persisted` 调用（同在 `core_metrics.py`）
* `record_unexpected_drop` ← 被 `set_lifecycle_leftover` / `note_eventbus_drop` 调用
* `set_eventbus_subscribers` ← 被 `/metrics` 抓取处理器调用（同在 `metrics.py`）

**排除被扫描文件 = 连它自己的内部调用点一起漏掉。**
第三例尤其典型：`set_eventbus_subscribers` 与 `refresh_db_pool_gauges`
是**拉取时设置**的 gauge，只在 `/metrics` 处理器里调用，这是设计如此，
按「零调用」判就是纯误报。

正确口径：**内部调用也算接线**，只判「调用次数为 0」。
本文件最终就按这个口径写，并把这条要求固化成
`test_internal_callers_count_as_wired`，防止将来有人「顺手清理」
时把口径改回去。

> 推广：写「找出未接线的 X」这类扫描器时，**先确认被扫描对象自身
> 会不会调用它**。零引用的结论只有在「不含自身调用」时才是结论；
> 否则要先排除内部调用，再谈未接线。

### 7.1.3 「字段存在」不等于「有人看」——关联链 observability 零消费方（本轮新增）

§7.1 里那 8 行「实际字段」本轮逐条**实测取值**（不是 grep），
结果 6 行属实、1 行发现过度声明。

**过度声明的那一行**：

| §7.1 的承诺 | 实测 |
|---|---|
| 关联链匹配数、被拒绝的链及原因 ✅ `chains_matched` / `chains_partial` / `chains_overlapping` / `reject_reasons` | 字段**算得出**，但**全仓零消费方** |

`CorrelationResult.observability`（`correlation_engine.py:331`）的 docstring
写得很清楚它为什么存在：

> `chains_matched=0` 有两种完全不同的原因：这段时间真的没有攻击，
> 或者模式已经退化到永远匹配不上。把两者压成一个数字，仪表盘就再也帮不上排障。

但运维侧唯一的入口 `/api/security/chains`（`routers/ops.py::list_chains`）
返回 `chains` / `temporal_groups` / `total_events_analyzed`，
**唯独没有 observability**。（`total_events_analyzed` 被手工复制进了响应，
说明作者意识到要暴露点什么，只是漏了主体部分。）

**后果很具体**：运维在界面上看到 `chains: []` 时，
无法区分「这段时间确实没有攻击」与「CEP 模式退化到永远匹配不上」
—— 而这两种情况在界面上长得一模一样，正是这个属性要解决的问题。
§十一.1 原文「评估误关联和模式退化」因此**没有真正落地**。

已修：响应加入 `"observability": result.observability`，
**直接复用属性而非手工拼字段** —— 手工再拼一份的话，
日后 `observability` 增删字段时端点会悄悄落后，那恰恰是本缺陷的成因。
`test_observability_is_the_real_property_not_a_copy` 钉住这一点。

回归 `tests/test_correlation_observability_exposed.py` 5 例，
**修复前 4 failed / 1 passed**（唯一绿的是「既有字段未丢失」）。

#### 为什么这类缺陷特别难发现

| 环节 | 状态 |
|---|---|
| 字段存在 | ✅ |
| 有 docstring 讲清用途 | ✅ |
| 计算逻辑有测试覆盖 | ✅ `test_review_correlation.py` |
| 验收报告把它列为已覆盖项 | ✅ §7.1 |
| **有人读它** | ❌ |

**生产者写对了，不等于有人看。** 已有测试全部在断言「`observability`
算得对不对」，没有任何一条断言「有人读它」。
这与本轮 `inc_intel_ioc` 那类缺陷同源：**产出面完整，消费面为空**。

推广：给任何字段/接口声称「可观测」之前，
必须去**消费方**确认它真的被读到，而不只是看生产者有没有把它算出来。
本轮的两次撞坑（`inc_intel_ioc` 无人自增、`observability` 无人读取）
是同一个 bug 类的两个面：**写入端与读取端必须各自验证**。

### 7.1.4 ⚠ 重大发现：零日链后半段**在生产里从未被调用**（本轮新增）

沿着 §7.1.3 的「消费面」继续查，撞上一个远比前两项严重的问题。

| 组件 | 生产调用方 |
|---|---|
| `sandbox_connector`（提交 / 轮询 / 状态机） | ✅ `routers/edr_intel.py:206-229` 的 `POST /sandbox/submit`。**轮询与状态机在连接器内部**（`sandbox_connector.py:417` / `:501`）—— ⚠ 本行原写 `:237`，**该行号不存在**，见 §7.1.9 |
| **`behavior_analyzer.analyze()`** | ❌ **零生产调用方**（只有测试） |
| **`variant_cluster.add_sample()` / `find_similar()` / `get_cluster_info()` / `get_unclustered()` / `label_cluster()`** | ❌ **零生产调用方**（只有测试） |
| （`variant_cluster` 的纯函数 `jaccard_similarity`） | ✅ 被 `learn_loop/models_cluster.py` 生产导入 —— **但那是另一件事**，见 §7.1.5 |

扫描口径：AST 扫全 backend、排除 `tests/`；**排除零日包自身**
（定义都在包里，包内自调用不构成「链接到生产」）。

**后果**：沙箱确实跑起来了 —— 事件提交、`task_id` 拿到、状态机记录，
报告 `payload` 也确实挂在 `SandboxOutcome.report` 上
（`sandbox_connector.py:414`）。

**但拿到报告之后，没有任何东西去解读它。**
没有 `clean` / `suspicious` / `malicious` 判定被产出，
没有任何样本进入家族聚类，`variant_cluster.stats` 永远是全零。

于是：

* 整改方案 §十.2 点名的 6 条聚类缺陷（空集合相似度 1.0、畸形 IOC 占位
  token、簇划分顺序依赖、`sigs[:20]` 静默截断、`round(sim,3)` 隐藏阈值差异、
  `cluster_id` 内容寻址）—— **规则全都正确，但规则从未被执行**；
* §十三「零日与聚类」这条验收维度的「无有效特征不等于高相似度」
  等性质**成立但无意义**：前提是分析真的跑过，而它没跑。

这是本轮发现里**唯一改变验收结论**的一条，已据此改写 §一。

#### 3.0b 2026-10-19 复核：仍成立，且断点在**第一环**而不是「缺消费者」

复核口径与原扫描一致（AST 扫全 backend、排除 `tests/`、排除零日包自身），
`behavior_analyzer.analyze()` 与 `variant_cluster.*` 的生产调用方**仍是 0**。

本轮补到一层更精确的事实：`zeroday_detect/llm_behavior.py` 提供
`should_trigger_llm(analysis_result)`（`:31`）与 `llm_interpret_behavior(...)`（`:39`），
它的模块说明写着「在 `behavior_analyzer` 产出分析结果后…」——
也就是说，**下游消费者是写好了的**。

但实测这两个函数在生产代码里**同样零调用方**（全仓命中只有 `llm_behavior.py` 自身；
`phishing_guard/llm_dimension.py` 里那个同名 `enrich_with_llm` 是另一条不相干的链路）。

于是断链位置可以精确表述：

> **不是「消费者缺失」，而是「生产者没接线」** ——
> `behavior_analyzer.analyze()` 无人调用 → `should_trigger_llm()` / `llm_interpret_behavior()`
> 永远拿不到输入 → 零日链后半段整体不可达。
> 这决定了修复的最小面：接线点在**第一环**，不需要新建消费者。

另两条相关普查同日复核，仍然成立：
`threat_iocs`（§7.1.8）生产侧只有模型定义 + 读表函数 + 文档字符串，**无任何写入方**；
`test_api_contract_guard.py`（§7.1.16）6 passed / 2 xfailed，断链仍是原来那两条。

#### 3.1 为什么用 strict xfail 钉住，而不是直接断言或直接修

这个缺口「还没修」，不该由一次扫描顺手替用户拍板接线。
但它也绝不能只躺在报告里。用 `@pytest.mark.xfail(strict=True)`：

* 现在 → 标记为**预期失败**，持续出现在回归输出里；
* 将来有人接线让它真的通过 → **XPASS 且 strict → 整条转红**，
  强制摘掉标记、改掉报告结论。

于是这个缺口**无法被静默遗忘**：修好了必须回来改文档。

新增 `tests/test_zeroday_wiring_gap.py`：4 条 strict xfail + 1 条前提守卫。
**验红**：在 `routers/edr_intel.py` 注入一个真实的生产调用点 →
4 条**全部 XPASS(strict) 转红**，前提守卫转为 skip 并提示
「请摘掉标记并更新 §十三 结论」；移除后恢复 1 passed / 4 xfailed。

#### 3.2 扫描器自身的坑：按方法名匹配会把同名对象算进来

第一版按 `Call(func.attr == "analyze")` 匹配，结果把
`anomaly_detector.analyze()`、`IntelEnricher.analyze()`、
`_AnomalyStub(0.42).analyze()` 全算成了零日分析器的调用方 ——
strict xfail 立刻 XPASS 转红，直接把假阳性暴露出来。

改成**导入感知**：先做导入绑定分析，只认真正从 `zeroday_detect.*`
导出的单例/类，再在其上匹配方法调用。

> 这是本轮第三次在扫描器上翻车（前两次：排除被扫描文件、词边界）。
> 规律一致：**扫描器的匹配精度决定结论的可信度**，
> 写完扫描器必须先注入一个已知答案验它的鉴别力，
> 否则「扫描结果是空的」分不清是真没找到，还是根本没匹配上。

#### 3.3 接线的设计问题（本轮不替用户决定）

1. **内存无上界**：`variant_cluster._samples` 只增不减，单例是进程级的。
2. **全量重建**：`add_sample` 每次调 `_reindex()` → `_components()`
   遍历全部样本，N 个样本累计 **O(N²)**。
3. **何时喂**：`_finish()` 是唯一收敛点，但该路径上的 `SandboxOutcome`
   **没有** `sample_hash`（`sandbox_connector.py:413-415`），
   而 `add_sample` 靠它做键。
4. **家族标注策略**：谁调 `label_cluster`、什么时候标。

这几条需要先定再接线。**不要为了让它变绿就在 `_finish` 里随手加一行。**

### 7.1.5 把「零生产调用方」推广到全仓：33 个休眠模块的系统性登记（本轮新增）

§7.1.4 那个发现是手工 grep 出来的 —— 那就意味着**同类问题很可能不止一处**。
把同一件事自动化：AST 扫 backend 全仓，统计每个模块有没有**生产导入方**，
得到 **33 个零导入模块**，逐个查证并分类。

| 类别 | 数量 | 含义 |
|---|---|---|
| `entrypoint` | 3 | `app.py`、`self_play/__main__.py`、`temporal/worker.py` —— 进程入口，天然无人 import，正常 |
| `script` | 9 | 迁移 / 训练 / 演示 / 规则工具脚本，正常 |
| **`dormant`** | **20** | **文档声称有、生产从不调用的能力 —— 与 §7.1.4 同类，是缺口** |

20 个 `dormant` 模块按能力域分：

| 能力域 | 模块 |
|---|---|
| 零日与聚类 | `zeroday_detect/{behavior_analyzer,llm_behavior}.py` |
| 威胁情报 | `threat_intel/{stix_taxii,intel_enricher,llm_context}.py` |
| 会话重建 | `session_reconstruct/{timeline,http_linker,tcp_reassembler}.py` |
| 响应处置 | `response_engine/containment/{host,directory,mail}_adapter.py` |
| 流量基线 | `traffic_baseline/{traffic_profiler,peer_group}.py` |
| IDS 接入 | `ids_connector/suricata_connector.py` |
| 加密流量 | `encrypted_traffic/mitm_proxy.py` |
| EDR 融合 | `edr_fusion/llm_correlation.py` |
| Agent | `agents/audit_single.py` |
| 模型参数 | `hierarchical_attention.py`、`optimized_params.py` |
| 自博弈 | `self_play/store.py` |

**这改变的是量级判断，不是新增缺陷。** §7.1.4 之前，
报告的措辞是「零日链有缺口」；现在能说的是：
**整个 backend 有 20 块能力在生产里从未被执行过**，
其中任何一块都不能拿「规则已验证」当验收依据。

#### 4.1 守卫把这件事变成回归：`tests/test_dormant_modules_guard.py`

新增 **7 passed / 22 xfailed**，四组用例：

1. **扫描器自检**（2 条）——`phishing_guard.email_detector` 必须**不**在休眠集，
   `zeroday_detect.behavior_analyzer` 必须**在**。
   扫描结果为空时，分不清是真没找到还是没匹配上，所以用已知答案钉精度。
2. **分类表完整性**（2 条）——任何休眠模块必须登记类别与理由；理由空串等于静默白名单。
3. **反向检查**（1 条）——登记为整文件休眠的模块若已有人导入，登记过期，强制重归类。
4. **strict xfail**（21 条 = 20 个 `dormant` + 1 个 `partial`）——接线即 XPASS 转红。
   `alias` 类**不配** xfail，理由见 4.5。

> 成本控制（实测，非估算）：`_importers()` 是 O(文件数 × 模块数)，
> 第一版 22 条 strict xfail 各自重扫一次，这个文件单独跑要 **23.08 秒**，
> 占全量回归的 20%。给 `_importers()` 加 `lru_cache` 后实测 **4.6 秒**
> （其中模块级扫描 setup ~1.1s，能力级扫描 3 次各 ~0.85s），
> 同一次全量回归从 142.43s 降到 118.50s。
>
> **守卫贵到没人愿意跑，就等于没有守卫** —— 性能问题在这里也是正确性问题。

#### 4.2 这个守卫当场抓出了我自己的登记错误：`partial` 这一类

第一版把 `zeroday_detect/variant_cluster.py` 登记成整文件休眠，
守卫生效判它「登记已过期」。查下去发现是**登记粒度错了**：

```
learn_loop/models_cluster.py:22   from zeroday_detect.variant_cluster import jaccard_similarity
```

活的是纯函数 `jaccard_similarity`（`learn_loop` 拿它聚类**模型**），
死的是 `VariantCluster` 这个聚类**恶意样本**的能力（生产零引用）。
而 `learn_loop` 本身是活的（`routers/ops.py:921`、`scheduler.py:469,580`）。

两个后果都很实际：

* 写成整文件休眠，会让人以为**整文件可删** —— 删掉 `jaccard_similarity`
  就打断了 `learn_loop` 的生产链路；
* 模块级的 strict xfail 是**假信号** —— 哪天有人为了任何理由 import 了这个模块
  （哪怕只为那个活着的纯函数），xfail 就 XPASS 转绿，
  等于宣布「零日聚类已接线」。**能力接线与模块接线是两件事。**

于是新增第四类 `partial`，并为它单独写**能力级扫描**
（按符号找引用方，**排除定义文件自身** —— `variant_cluster.py:438` 有
`variant_cluster = VariantCluster()`，那是自引用，不是接线），
配一组阳性/阴性自检 + 1 条 strict xfail。

**§7.1.4 的结论没有被推翻**：`VariantCluster` 类在生产里确实零引用，
只是「模块休眠」这个描述不准确 —— 准确说法是「文件活着，聚类能力死」。

#### 4.3 验红：注入一个真实生产调用点

新建 `backend/_tmp_probe_wiring.py`：

```python
from zeroday_detect.variant_cluster import VariantCluster
_CLUSTER = VariantCluster()
```

**三处同时转红**，互不重复：

| 用例 | 现象 |
|---|---|
| `test_every_dormant_module_is_explicitly_classified` | 抓到未登记模块 `_tmp_probe_wiring.py` |
| `test_capability_scanner_reports_a_symbol_that_is_dead` | 精确点名引用方 `_tmp_probe_wiring.py` |
| `test_partially_dormant_capability_is_reachable_from_production` | **XPASS(strict) 转红** |

移除探针后恢复 `7 passed / 22 xfailed`。

> 这是本轮第四次在扫描器上翻车。前三次（排除被扫描文件、`GES` 无词边界、
> 按方法名匹配同名对象）都是**精度不足导致假阳性**；
> 这次相反，是**粒度太粗导致假阴性** —— 模块级判据看不见能力级缺口。
>
> 推广：**判据的粒度要匹配被声称的性质。**
> 声称「这个能力没接线」时，判据必须落在**能力**上；
> 落在文件或模块上，会被「同一个文件里恰好还有别的东西是活的」骗过。

#### 4.4 一个如实登记、未修的口径边界

「零导入」**不等于**「不可达」：若模块 A 零导入、模块 B 只被 A 导入，
B 在这套扫描里不算休眠（有导入方），但 B 同样到不了生产。

本轮 33 个模块里**没有出现这种链**（休眠模块之间互不导入，已逐个核过导入图），
所以结论不受影响。但这不是扫描器保证的，是**这一批文件碰巧的性质** ——
换一批就需要改成从入口出发的可达性分析。已写进守卫的 docstring。

#### 4.5 守卫第二次抓出我自己的登记错误：把已接线的能力说成了缺口

把 20 个 `dormant` 按「同包内有没有活着的兄弟模块」分类，想搞清楚
哪些是「产品实际在用的另一套实现」：

```
【A】同包内有活着的兄弟模块（过期的/并行的另一套）: 14
    edr_fusion.llm_correlation  ← 同包 edr_adapter / sysmon_parser / winevent_parser 都活着
    traffic_baseline.{traffic_profiler, peer_group}  ← 同包 seasonal / llm_anomaly 活着
    encrypted_traffic.mitm_proxy  ← 同包 ja3_fingerprint / session_collector 活着
    ...
【B】整包休眠（包里一个活的都没有）: 7
    session_reconstruct.*（3）  ids_connector.suricata_connector
    hierarchical_attention  optimized_params  red_agent
```

`red_agent` 落在【B】看着很刺眼 —— 同名的 `self_play.red_agent` 是**活的**，
疑似重复实现。读了一下，是**想错了**：

```python
# backend/red_agent.py —— 全文 8 行
\"\"\"红队 Agent 入口(提案对接点)。

实现位于 self_play.red_agent。蓝队即现有 Decomposer→Executor→Reviewer 流水线,
由 self_play.orchestrator 驱动对抗循环。
\"\"\"
from self_play.red_agent import RedAgent
```

它是个**刻意的再导出门面**，不是重复实现。
所以 **RED Agent 能力是接线的** —— 走 `self_play.red_agent`，
顶层这个文件只是没人用的对外入口。

我原来的登记把它列成 `dormant`（能力缺口），是**把一条已接线的能力说成了缺口**。
而且给它配的 strict xfail 是个**必炸的假信号** ——
有人 import 一下这个别名就会 XPASS，等于宣布「RED Agent 未接线」。

于是新增第五类 `alias`（零导入的再导出门面，实现已接线，**不配 xfail**）。
判据是三条同时成立：**文件极小 + 只做再导出 + 真正的实现在别处且已接线**。
21 → 20。

按行数把 20 个全扫了一遍确认是单独一例：
`red_agent` 8 行，下一个是 `optimized_params` 77 行（配置加载器），其余 84～440 行。

> **推广**：**「零引用」和「没接线」是两个不同的结论**，
> 中间隔着「零引用但只是别名」「零引用但能力在别处已接线」这类情况。
> 前者可以据以删代码，后者据以删代码**会打断别人**。
> 同 §6.3.2 那个坑一样 —— 先证明自己看到的那个东西**到底是什么**。

### 7.1.6 能力看板的 count 在数一个死计数器，而活的那条路写在别处（本轮新增）

§7.1.5 的休眠清单给出一个直接可查的推论：
**凡是自增点落在休眠模块里的指标，生产读数必然恒 0。**

逐块核了 `/api/capabilities/status` 的五块能力
（`inc_*` 包装函数 → 全仓调用点）：

| 能力 | 自增函数 | 生产自增点 | 可达 |
|---|---|---|---|
| ndr | `inc_ndr_flow` | `traffic_capture/flow_aggregator.py:225` | ✅ |
| edr | `inc_edr_event` | `edr_fusion/edr_adapter.py:126,136` | ✅ |
| **threat_intel** | `inc_intel_ioc` | `threat_intel/stix_taxii.py:75` | ❌ **休眠模块内** |
| zeroday | `inc_sandbox_submission` | `zeroday_detect/sandbox_connector.py:252,283` | ✅ |
| phishing | `inc_phishing_detection` | `phishing_guard/scoring.py:100` | ✅ |

**五块里只有 threat_intel 的 count 结构性恒 0。**
这与 §6.3.1 的纠正是同一根因，但这里还有**第二层，更扎手**。

#### 5.1 真正扎手的地方：活路径写在了另一个计数器上

`ioc_matcher` 是**活的** —— `app.py:288` 在 `intel_enabled` 为真时导入它
并 `await refresh_cache()`。它命中时调 `inc_ioc_match()`
（`ioc_matcher.py:182`），自增的是 **`soc_ioc_matches_total`**。

而看板（`routers/capabilities.py:20`）读的是 `soc_intel_ioc_`，
即**拉取量**，不是**命中量**。于是：

> 威胁情报能力确实在工作（IOC 匹配在命中），
> 看板读的是一个死计数器，于是**恒显示「已启用 · 0 条」**。

前端 `CapabilitiesDashboard.tsx:14` 把这一块渲染成
`{label:'威胁情报', desc:'IOC / MISP / TAXII'}`，
第 28 行还把五块 count 求和当页面顶部「事件累计」——
于是一个**恒偏低的总数**被展示成权威数字。

这是 §7.1.3「字段存在 ≠ 有人看」的**读方向**版本：
上一轮是「值算出来了没人读」，这个是「**值有人写了，读的人挑错了源**」。

#### 5.2 为什么不直接改：这是语义决策

那块 count 到底该表达什么，两种读法都说得通：

* **算拉取量** → 语义是「摄入了多少情报」，但拉取侧本身休眠；
* **算命中量** → 语义是「处理了多少事件」，与另外四块的「事件累计」一致，
  但会丢掉「摄入了多少」这一维。

擅自选一个就是替用户改产品口径，所以用 **strict xfail** 钉住缺口：
`tests/test_capability_tile_counts.py`（**2 passed / 1 strict xfail**）。

接线 `threat_intel/stix_taxii.py` 或改看板读数，两条路都能让**这条用例**转绿。

> **⚠ 但本节原先写「接线 `stix_taxii`（一并解掉 §7.1.4 / §6.3.1 的休眠）
> 即可」是错的，已更正 —— 见 §7.1.8。**
>
> `poll_feed` **只 return 不落库**，所以即便把拉取侧接上线，
> `ioc_matcher` 依然读到空表，**IOC 匹配在生产里仍然一次都不会命中**。
>
> 这条用例衡量的是「看板读数」，不是「能力可用」。两者在这里恰好脱钩。

**验红**：把 `_CAPABILITIES` 里 threat_intel 的前缀临时改成
`soc_ioc_matches_` → **XPASS(strict) 立刻转红**，两条前提守卫保持绿；
`git checkout` 回滚后恢复 2 passed / 1 xfailed。

#### 5.3 前提守卫拦下了一次「恒绿」的假通过

两条前提守卫（必须常绿）不是凑数：

1. `match()` 命中后 `soc_ioc_matches_total` 必须 +1 —— 证明活路径确实在发信号；
2. 两个计数器确实不是同一个 —— 这是「读错源」的前提。

写第一条时踩了个坑：`IocMatcher.match` 是 **`async def`**，
漏了 `await` 时 `hits` 是个协程对象，而**协程对象恒为真**，
`assert hits` 于是恒绿、整条前提守卫白写。必须 `asyncio.run(...)` 真跑。

> 这是「前提守卫不可省」的又一个实例，而且它拦下的不是业务缺陷，
> 是**守卫自己**的失效 —— 没有它，缺口那条会带着一个假绿的前提通过，
> 看起来仍然「有效」。

#### 5.4 连带发现：一条既有测试断言的是绝对值，靠「恰好第一个跑」成立

加上 `test_capability_tile_counts.py` 之后，全量回归红了：

```
FAILED tests/test_capability_tile_counts.py::test_ioc_match_path_really_increments_the_live_counter
```

第一反应是「我新增的测试有问题」。**复现后结论相反** ——
单跑 `test_inc_metrics.py` 是 `3 passed`，
只要前面有别的用例动过 `soc_ioc_matches_total` 就红：

```python
# tests/test_inc_metrics.py:37（改前）
assert "soc_ioc_matches_total 1.0" in out
```

这条断言真正要表达的是「`inc_ioc_match()` 让计数器**恰好 +1**」，
但写成绝对值之后，它实际要求的是「这个进程级计数器从没被别的东西碰过」。
Prometheus 计数器是**进程级全局**的，于是它只在「本文件恰好第一个跑到」时成立。

同一函数里**五条断言全是这个毛病**（`soc_ndr_flows` / `soc_edr_events` /
`soc_sandbox_submissions` / `soc_ioc_matches` / `soc_phishing_detections` /
`soc_tls_sessions`），只是本轮恰好只有 `soc_ioc_matches` 被踩到。

讽刺的是，**项目自己的 `test_dead_code_remediation.py` 里就写着这条规矩**：

> Prometheus 计数器是进程级全局的，测试之间会累积。
> 因此一律取「测试前后差值」，绝不直接断言绝对值 —— 否则单跑绿、全量跑红。

已按该规矩修好，拆成两半、**一样都不放宽**：

* **格式**（指标名 + label 在 `/metrics` 文本里长什么样）—— 仍在文本上断言；
* **数值**（自增恰好 1）—— 取前后差值。

**验红**（两半各验一次，确认没被改成恒真）：

| 注入的违例 | 结果 |
|---|---|
| `inc_edr_event("winevent")`（标签写错） | 🔴 `soc_edr_events_total{source="sysmon"} 没出现在 /metrics 文本里` |
| 注释掉 `inc_tls_session()`（漏自增） | 🔴 `soc_tls_sessions_total 应恰好 +1，实际 0.0 -> 0.0` |

label 写错照样红、函数不自增照样红 —— 原来的鉴别力全部保留。

**修的过程中我自己引入过一处同型脆弱性，一并记下**：
差值检查最初把 series 写成裸指标名 `soc_ndr_flows_total`，
而正则里 label 组是可选的 —— 它会匹配到「第一条带 label 的子线」，
匹配到哪条取决于标签值的输出顺序。
**那是把一个顺序依赖换成了另一个顺序依赖。**

反证（构造 udp 在前、tcp 在后的 exposition 文本实测）：

```
[OK  ] soc_ndr_flows_total{protocol="tcp"} -> 3.0   写全 label，正确
[反证] 裸 soc_ndr_flows_total                 -> 7.0   挑了 udp 而非 tcp
```

已把六条 series 全部写全 label，与子线顺序无关。

> **推广（补一句）**：修「顺序依赖」这类问题时，
> 要检查新写法**是不是只是把依赖换了个位置**。
> 「原来依赖执行顺序 → 现在依赖标签排序」不算修好。

#### 5.5 第二层根因：我的夹具一直在靠「环境缺一块」而假绿

修好 `test_inc_metrics.py` 之后，全量**仍然红**，而且红的还是同一条前提守卫。
**只解释第一层是不够的** —— 停下来查了第二层。

`IocMatcher.match()` 开头有自动刷新：

```python
# threat_intel/ioc_matcher.py:133
# 自动刷新缓存
if time.time() - self._last_refresh > self._refresh_interval:
    await self.refresh_cache(session)
```

新建实例的 `_last_refresh = 0.0`，所以**第一次 `match()` 必定触发刷新**，
而 `refresh_cache` 会用 DB 里的内容**覆盖 `_cache`** ——
测试刚塞进去的夹具被抹掉。

于是出现了一个很难看的局面：

| 运行方式 | DB 状态 | 结果 |
|---|---|---|
| 单跑本文件 | 恰好不可用（`no such table: threat_iocs`） | 刷新失败被吞 → **夹具幸存 → 假绿** |
| 全量 | 前面的用例把表建好了 | 刷新成功 → **夹具被抹 → 转红** |

> **假绿的原因是环境缺一块，而不是测试写对了。**
> 夹具的存活依赖了一个与被测性质无关的环境偶然。

修法是造一个**已预热**的匹配器（设 `_last_refresh = time.time()`），
这也正是 `app.py:289` 线上启动后的状态。

**顺带修了一个更隐蔽的问题**：那条 strict xfail 原本也用同样的夹具。
若夹具被抹掉，`assert hits` 会先失败，xfail 于是
「因为错误的原因」被判为已知缺口 —— **缺口被登记成了已知，但理由是假的**。
现在把 `assert hits` 的失败信息改成明确区分这两种情况。

**验证**（用 `--runxfail` 让 xfail 变成普通失败，看它到底为什么失败）：

```
AssertionError: IOC 确实命中了（1 条），但看板 threat_intel 的 count 仍是 0
              —— 用户看到的是「已启用 · 0 条」
```

确认 xfail 是因为「看板读数没跟着动」，
**而不是**因为「夹具被自动刷新抹掉」。

> **推广**：`assert fixture_生效` 这类前提断言，
> 只证明「测试跑到了某一行」，不证明「失败的是你想的那件事」。
> 想确认 xfail/strict xfail 登记得对不对，就用 `--runxfail` 看它**实际**失败在哪一行 ——
> 理由错了的「已知缺口」比没有登记更危险，它会让缺口以错误的成因被长期接受。

#### 5.6 把结论从「发现一处」升级成「查了 62 个，只有这一处」

上面 5.1 的结论是从五块能力里查出来的。要说「这是唯一一处」，
得把 backend 全部 62 个 Prometheus 计数器都过一遍：

```
扫描器自检通过（5 个已知活的 + 1 个已知死的，判定全部符合预期）
计数器总数: 62
  A 生产自增点全在休眠模块内（读数必然恒 0）: 1
  B 有活的自增点:                              61
  C 零自增点:                                  0

=== A. 读数必然恒 0 的计数器 ===
  INTEL_IOC  (soc_intel_ioc_total)
      threat_intel/stix_taxii.py:75: inc_intel_ioc(...)
```

即：**`INTEL_IOC` 是 62 个里唯一一个读数必然恒 0 的**，
其余 61 个都有活的自增点，其余四块能力看板的数字都会动。

#### 5.7 这个扫描器改了三版，前两版都给出错答案 —— 全记在这里

| 版本 | 口径 | 结果 | 错在哪 |
|---|---|---|---|
| v1 | 只认 `inc_*` 包装函数，且**排除** `metrics.py`/`core_metrics.py` | 报出 **6 个**「零调用点」 | 漏 `metrics.py:289` `EVENTBUS_SUBSCRIBERS.set()`、`metrics.py:302` `DB_POOL_CHECKEDOUT…set()`；且 Gauge 常**直接** `.set()`/`.labels().inc()`（`core_metrics.py:403/406/527/536`），根本没有包装函数 |
| v2 | 定义文件里的直接使用**也算**调用点 | 报出 **0 个**死指标（假全清） | `metrics.py` 内 `INTEL_IOC.labels(...)` 那行是**包装函数自己的实现**，被当成独立调用点，于是「所有自增点都在休眠模块内」判假 —— **把唯一的真死指标洗白了** |
| **v3** | 调用点 = 包装函数调用（**含**定义文件内互相调用）∪ 定义文件**之外**的直接变量使用 | **1 个**（正确） | —— |

v2 那版最危险：它报的是「一切正常」，**比报错更难被发现**。

最终判据（实测过 6 个量在定义文件里的直接使用**全部在函数体内**，
是包装函数实现而非独立调用点）：

* **调用点** = 包装函数调用点（`metrics.py` 内部的互相调用也算）
  ∪ 定义文件**之外**的直接变量使用（`.set()` / `.labels().inc()`）；
* **死指标** = 调用点非空，且**全部**落在休眠模块内。

> **推广**：**判「没人调用」比判「有人调用」难**，因为要把两类路径都覆盖 ——
> 经包装函数的，和直接操作指标的。而把某一类算重或算漏，
> 都会系统性地偏到「一切正常」那一侧。
>
> 所以这个扫描器**带了已知答案自检**（6 个已知判定，不过就 `raise SystemExit(2)` 拒绝输出）：
> 前两版如果没有这道闸，v2 的假全清会被直接当成结论写进报告。

### 7.1.7 §7.1.5 的休眠清单，让**门面 README** 当场被抓（本轮新增）

休眠清单的价值不止于内部认知 —— 它可以直接拿去核对**用户读得见的东西**。
拿 README 的「NDR / EDR / Threat Intel / 反钓鱼」能力表逐行对照：

| README 行 | 被当作已交付能力列出的休眠模块 |
|---|---|
| 146 行为异常分析 | `behavior_analyzer` / `llm_behavior` /（`variant_cluster` 聚类能力） |
| 152 加密流量 | `mitm_proxy` |
| 155 流量基线 | `peer_group` |
| 156 EDR 融合 | `llm_correlation` |
| 157 IDS 对接 | `suricata_connector` |
| 158 威胁情报 | `stix_taxii` / `intel_enricher` / `llm_context` |

**7 个**。同一张表还引用了 **32 个确实活着的模块**
（`phishing_guard/*`、`capture_engine`、`flow_aggregator`、
`ioc_matcher`、`reputation`、`cross_correlator` …）—— 这个对照就是前提守卫，
证明解析器认得出活模块，否则「全部合规」和「什么都没匹配上」长得一样。

这是 §7.4/§7.5（文档承诺与实现不一致）的**用户可见版本**：
之前修的都是 docstring 和 `variant_cluster` 的注释，
而 README 是仓库的门面，读者据此判断系统具备什么。

#### 7.1.7.1 处置：标注，不删除

这些模块的**代码是对的**（有测试、规则正确）。
删掉会让将来接线时无从对照 —— §十一.2 的处置原则本来就是
「不一致必须被显式声明」而非「不一致必须消失」。

已给 7 个模块加上 `⚠未接线` 标记 + 一段图例（说明标记含义、指向守卫文件），
并新增 `tests/test_readme_capability_claims.py`（**7 passed**）守住两件事：

* 休眠模块**必须**带标记（新睡的模块不许悄悄混进能力表）；
* 活着的模块**不许**带标记（接线后标记要摘掉，否则标记本身变成新的谎言）。

#### 7.1.7.2 顺带核实：`mitm_enabled` 是一个只能空转的开关

> **⚠ 本节的三个数字已于 §7.1.11 全量普查后更正。原口径只扫了「布尔开关」一个子集，
> 且只数到 28 个（实际 54 个），把抽样结论当成了全量结论。**
>
> | 本节原写 | §7.1.11 实测 |
> |---|---|
> | 28 个 `config.py` 布尔开关 | **54 个** |
> | 读点全部落在休眠模块的**只有 1 个**（`mitm_enabled`） | **3 个**：另加 `forensic_include_dump`（`host_adapter.py:338`）、`misp_verify_ssl`（`stix_taxii.py:42,157`） |
> | 其余 27 个都有活读点 | 49 个有活读点 + **2 个零读点**（`kafka_flink_secondary_llm`、`audit_p1_use_temporal`） |
>
> 把范围从「布尔」扩到全部 329 个字段后，B 类（读点全在休眠模块内）从 1 个变成 **20 个**，
> 且含 **TAXII / MISP / MITM 三组凭据** —— 运维填了密钥也不会有任何事发生。
> 详见 **§7.1.11**，守卫 `tests/test_config_switch_wiring.py`。

原口径下（仅布尔开关）的结论本身仍然成立：`mitm_enabled` 的读点都在
`encrypted_traffic/mitm_proxy.py` 里，即**把它设成 true 什么也不会发生**。

特别澄清一个我原本的怀疑：`llm_intel_enabled` / `llm_sandbox_enabled` /
`llm_edr_enabled` **不是**空转的 —— `llm_enhancer.py`（活模块）也在读它们做预算路由。

`.env.example:261` 出货了 `SHARED_MEMORY_MITM_ENABLED`，未标注它当前无效。

> 严重性按**「README 是否承诺」**分档：
> `mitm_proxy` 这类既在 README 能力表里、又有 `.env` 开关的，排在最前；
> 纯库内模块（如 `hierarchical_attention`）排在最后。

#### 7.1.7.3 这个守卫自己出了两次错，都是靠验红动作抓出来的

写完直接绿了，但**绿不代表它在检查东西**。两次注入各抓出一个问题：

| 注入的违例 | 第一版结果 | 根因 |
|---|---|---|
| 摘掉 `peer_group` 的标记 | ✅ 转红 | —（这条本来就对） |
| 给活着的 `tls_metadata` 加过期标记 | ❌ **不红** | ① 遍历 `_dormant_refs_in()`（只返回休眠模块）再判 `not in DORMANT_STEMS` —— **恒假，整条断言永不失败** |

修①之后**还是不红**，继续查，发现更深一层：

裸名正则写成 `\(([a-z_][a-z0-9_]*)\)`，要求模块名**紧跟 `)`**。
可一旦加上标记就变成 `(tls_metadata ⚠未接线)` —— **这个模块对解析器彻底隐形**。
也就是说：写测试时表格还没标记（能工作），加完标记后解析器反而瞎了，
那条检查是**因为看不见**才绿的，不是因为检查过。

改成 `\(([a-z_][a-z0-9_]*)[^)]*\)`（允许后接标注）后，两个注入**同时转红**。

顺带修了一个连带误报：`_marked()` 的 30 字符窗口会跨到**下一个**模块，
把紧挨在被标记模块之前的活模块（`session_collector` / `seasonal` / `reputation`）
也算成带标记。窗口改为**在下一个 `(` 处截断**。

> **推广（本轮最值得记的一条）**：
> **解析规则可能依赖「原文没被改过」——而改动正是你自己做的。**
> 这次是先写测试、后加标记，于是测试在加标记后静默退化成了瞎子，
> 而且**越是「我正确地做了改进」，越不会去怀疑改进让守卫失效了**。
>
> 所以：**守卫自己改过判定逻辑或输入格式之后，必须把验红动作重跑一遍**，
> 不能沿用改动之前那次「验过红」的结论。

> **推广**：「单跑绿、全量红」的第一嫌疑人永远是**被测对象之外的状态**，
> 而第二嫌疑人是**新测试的隔离性**—— 但这次两者都不是。
> 真正的原因是既有测试把自己的通过建立在「没人碰过这个全局量」上。
>
> 新增一个会碰全局状态的测试，等于**替所有依赖该状态未被触碰的测试踩了一脚**。
> 遇到这种情况要查的是既有测试，不是把自己的新测试改弱了事。

### 7.1.8 情报能力链**缺了一整段**：没有任何东西往 `threat_iocs` 写 IOC（本轮新增）

§7.1.5 登记 `threat_intel/stix_taxii.py` 为休眠时，把它归成了
「一个没被调用的模块」。继续往下查发现：**它就算被调用也不解决问题**。

```
TAXII/MISP ──poll_feed──> IOC 列表 ──落库──> threat_iocs 表 ──ioc_matcher──> 事件匹配
                            ✅ 实现存在        ❌ 这一段根本不存在        ⚠ 读到空表
```

逐段核实（多路交叉）：

| 环节 | 状态 | 证据 |
|---|---|---|
| `TaxiiClient.poll_feed` 拉取 | ❌ 生产零调用方 | 全仓（排除 tests）只有 `stix_taxii.py` 自己的 docstring 提到它 |
| **落库** | ❌ **完全不存在** | `stix_taxii.py` 全文只有 4 处 `session`，**全是 `aiohttp.ClientSession`**（HTTP 客户端），零持久化；`poll_feed` 的签名就是 `-> list[dict]`，纯返回 |
| `ioc_matcher` 匹配 | ✅ **函数确实被调用**（`routers/edr_intel.py:156` 的 `POST /intel/match`、`threat_intel/reputation.py:106,148`），但**永远读到空表** | `ioc_matcher.py:85` `select(ThreatIoc).where(is_active==True)` |

`threat_iocs` 这个表名在全仓（排除 tests / .git / node_modules / target）
只出现在三处：`models.py:666` 建表定义、`ioc_matcher.py` 的 SELECT、
`init.sql:294-320` 的 DDL 与索引。**零 INSERT。**
`ThreatIoc(` 构造器调用在全仓也是 **0 次**（唯一的出现是 `models.py:664` 的类定义）。

#### 8.0 三层用户可见面 —— 这才是本条最要紧的部分

查的过程中发现：**`threat_intel` 的整条数据层是「DDL + 读 API + 前端页面」，
但每一层都没有写入方。** 不是「某个模块没接线」，是整条链路上游**从未被实现**。

| 层 | 已有的东西 | 谁写 | 运行时表现 |
|---|---|---|---|
| `threat_intel_feeds` 表 | `init.sql:322` DDL + `models.py:687` ORM + `GET /intel/feeds` | **无**（无 POST、无 seed、无迁移） | 列表恒为空 |
| `last_poll_at` / `_status` / `_count` | `models.py:698-700`，默认 `idle` / `0` / `null` | **无**（轮询器不存在） | 恒为默认值 |
| `threat_iocs` 表 | DDL + ORM + `GET /intel/iocs` + `POST /intel/match` | **无**（`poll_feed` 只 return） | `hits` 恒为 `[]` |
| 前端 | `Intel.tsx:31` 拉 `/intel/feeds`，`:143-145` 展示 `last_poll_status` | — | **每个数字都是冻结的** |

`ThreatIntelFeed` 模型专门留了 `poll_interval_min` / `last_poll_status` /
`last_poll_at` / `last_poll_count` 四个字段 —— 说明**轮询的设计意图是有的**，
但全仓没有任何代码写它们（只有 `routers/edr_intel.py:138-141` 读出来显示）。

> **这是最隐蔽的一种失效形态**：代码在跑（`POST /intel/match` 有真实调用方）、
> 接口能通（返回结构良好的 JSON）、页面能开（`Intel.tsx` 能拉数据），
> **只是每一个数字都是默认值**，看板上没有任何「报错」或「未配置」信号。
>
> 与 §7.1.6 的「恒 0」同族，但这里**连那个恒 0 的计数器样本都不会出现**
> —— `poll_feed` 不跑，所以 `soc_intel_ioc_total` 压根不会被创建。

#### 8.1 为什么这比「休眠」严重 —— 它推翻了我自己报告里的一句话

休眠是「一段没接线」，补上即可。但这里是**一段根本不存在**。

本报告 §7.1.6 原先写过：「接线 `threat_intel/stix_taxii.py`
（解 §7.1.4 / §6.3.1 的休眠）」—— **这句话是错的**，
已就地标注更正。按它去接线的人，会得到一个会动的计数器、
一份跑通的测试，和一个**仍然不产出任何命中**的匹配器。

差别很实际：

| | 休眠（没接线） | 缺一环（不存在） |
|---|---|---|
| 症状 | 该跑的没跑 | 跑了也不出结果 |
| 补救 | 接线 | **先要定设计**：落库归谁？重复 IOC 怎么 upsert？`is_active`/`expires_at` 谁维护？ |
| 能否只靠接线解决 | 能 | **不能** |

#### 8.2 守卫：`tests/test_threat_intel_pipeline_gap.py`（**7 passed / 1 strict xfail**）

四条前提守卫（必须常绿）+ 一条 strict xfail：

* 前提①`ioc_matcher` 确实**读**这张表 —— 否则「没人写」可能只是「没人读」；
* 前提②`poll_feed` 确实**不**落库 —— 一旦有人加了落库，
  「缺一环」的说法过时，本文件与本节都要改（守卫会提示改成什么）；
* 前提③`last_poll_*` 全仓没有写入方 —— 「轮询器从未实现」的独立佐证；
* 前提④前端 `Intel.tsx` 确实还在展示这个冻结字段 —— 它决定本缺口的严重性；
* **strict xfail**：全仓必须存在一个把 IOC 写进 `threat_iocs` 的生产路径。

每条前提都写明「若哪天转红意味着什么」—— 它们不是装饰，
是让结论**可被推翻**的抓手：任一条转红，就该重新评估整节结论。

**验红**：新建一个 `ThreatIoc(...)` 实例化的临时模块 → **XPASS(strict) 转红**，
守卫随即恢复。`--runxfail` 确认失败理由正确
（是「找不到写入方」，不是夹具问题）。

#### 8.3 这个守卫的第一版判据是错的，被 strict xfail 顶了出来

第一版用**文件级启发式**：「文件提到 `ThreatIoc` 且出现 `add(`/`commit(`」
就算写入方。它把 `routers/edr_intel.py` 判成了写入方 ——
但该文件第 105~110 行是用 `ThreatIoc` 做 **SELECT**（读），
第 227~228 行的 `session.add(record)` 加的是**另一个模型**。

`strict=True` 的 xfail 立刻 XPASS 转红，把假阳性顶出来。

改成**构造器级**判据（ORM 插入的必要前提）：直接 `INSERT INTO threat_iocs`，
或实例化 `ThreatIoc(...)`（含 SQLAlchemy 2.0 的 `insert(ThreatIoc)`）。
实测：全仓 `ThreatIoc(` 只有类定义本身，零实例化 —— 判据既准确又更严格。

> **推广**：「某模型/表被写入了」不能靠**文件级**关键词判断 ——
> 同一个文件里完全可以「用 A 模型读、用 B 模型写」。
> 必须落到**语句级或构造器级**：有没有实例化那个对象、有没有对那张表 INSERT。

### 7.1.9 同一形态的第二个实例：沙箱任务记录是一条**死胡同**（本轮新增）

§7.1.8 暴露出「入口接线了、但数据层没人写」的形态。既然它出现了，
就该问一句：**别处是不是也有？**

查沙箱链，答案是有，而且几乎是镜像：

```
POST /api/sandbox/submit
   ├─ sandbox.submit_url(url)            ✅ 真实提交给 CAPE/Cuckoo
   └─ SandboxTask(status="pending")      ✅ 写入 DB —— 到此为止
                      ⋮（沙箱异步分析完成）
   ├─ sandbox_connector._finish()        ✅ 拿到报告，只在内存（line 501-518）
   └─ ？                                  ❌ 零回调 / 零事件 / 零持久化桥
                      ↓
GET /api/sandbox/tasks → status 恒 "pending"
                        verdict / score / behavior_summary /
                        mitre_techniques / network_iocs 恒为空
```

**证据**：

* `SandboxTask` 在生产代码里只有 **7 处**出现：类定义、2 个 import、
  1 处 SELECT、1 处 WHERE 过滤、1 次构造、1 条 docstring。
  **没有任何 UPDATE 路径**；原始 SQL 也搜不到（`UPDATE ... sandbox` 零命中）。
* `routers/edr_intel.py` 全文 **229 行**，路由到 `POST /sandbox/submit` 结束 ——
  **不存在轮询协程**。
  （§7.1.4 曾把「轮询」标在 `routers/edr_intel.py:237`，**该行号并不存在**，
  本轮更正。沙箱的状态机确实有，但在 `sandbox_connector` 内部，
  与这张 DB 表之间没有任何桥。）
* `sandbox_connector.py` 全文**零** `callback` / `on_complete` / `event_bus` /
  `publish` / `subscribe` / `notify` 出口 —— `_finish()` 拿到报告后无处可送。

> **2026-10-19 晚间补充**：本节钉的是**写回**那半边（「有没有代码把结果写回
> `SandboxTask`」）。**回取**那半边（「有没有代码去轮询 / 取回结果」）
> 由 §9.14 单独普查并单独钉住 —— 两半边都没有，才构成「提交进去就悬空」。

#### 9.1 两个实例的对照 —— 所以这是形态，不是偶然

| | Intel（§7.1.8） | 沙箱（本节） |
|---|---|---|
| 写入方 | **完全没有** | 有，但**只写一次** |
| 读接口冻结在 | `last_poll_status="idle"` | `status="pending"` |
| 前端行为 | **显示**冻结值（`idle`） | **隐藏**空字段，只留永久 `pending` |
| 危险度 | 看板数字误导 | 略低：前端防御性（`{t.verdict && ...}`、`{t.score > 0 && ...}`），不会谎报「clean / 0 分」 |

共同点：**完整搭好的 UI + API，建立在一层永远不会被完成的数据上。**

沙箱这条危险度略低，但症状同样无法自解释 ——
用户看到「永远是 pending」，**无法区分「正在排队」和「从没有被处理过」**。

#### 9.2 守卫：`tests/test_sandbox_task_dead_end.py`（**5 passed / 1 strict xfail**）

四条前提守卫 + 一条 strict xfail + 一条反向检查，
每条都写明「若哪天转红意味着什么」。

**验红**（注入 `record.status = "completed"`）→ **XPASS(strict) 转红**；
撤除后恢复 5 passed / 1 xfailed。

#### 9.3 这个守卫写错了**断言方向**——它永远不会报警

验红时注入了一行 `record.status = "completed"`，守卫**没有转红**。
手工复现证明检测逻辑是对的，是 pytest 报了 XFAIL。查下去才发现：

`strict=True` 的 xfail 语义是

* **缺口修好** → 测试应当**通过** → XPASS(strict) → 转红，强制摘标记；
* **缺口还在** → 测试**失败** → XFAIL。

而我把正文写成了 `assert False, "出现了 .status = 赋值"` ——
**方向反了**：缺口修好时它**失败**，被当成「预期的失败」记成 XFAIL。
于是这条守卫**看起来一直正常，实际永远不报警**。

正确写法是正向断言 `assert updaters, "<缺口描述>"`。

> **推广（这一条最值得带走）**：
> **strict xfail 的正文必须是正向断言** ——
> 「期望的能力存在」时通过，「不存在」时失败。
>
> 写反了不会报错、不会红、不会被发现，它只是**安静地变成一个永不报警的摆设**。
> 而验红是唯一能发现它的动作 —— 这也是为什么每个守卫都必须真的注入一次违例。
>
> 推广到别处：**任何「缺口标记」的断言方向都要单独验一次**。
> 判断方法很简单 —— 注入修复后，它必须**转红**；不转红就说明方向反了。

### 7.1.10 把「偶然发现」系统化：全仓 50 个 ORM 模型扫一遍（本轮新增）

§7.1.8（`threat_iocs`）和 §7.1.9（`SandboxTask`）都是**偶然**撞见的。
偶然发现的问题是：不知道还有没有第三个、第四个。
本节把查法变成可复跑的扫描器（`%TEMP%\scan_models_without_writers.py`），
然后**扫描器自己先翻了四次车**，其中一次制造了两个假缺口。

#### 10.0 扫描器的四次修正 —— 每次都是**假结论**

| 版本 | 缺陷 | 造成的假结论 |
|---|---|---|
| v1 | 只认 `session.add(`，不认 ORM 构造 | 漏掉「构造后 add」和「构造即插入」 |
| v2 | 只认字面 `Model(` | 漏 `from models import PipelineSpan as PipelineSpanModel`（`pipeline_tracer.py:422`），把 `pipeline_spans` 误判成零写入 |
| v2 | 自检集合把 `SandboxTask` 当「零写入」样本 | 它其实有一次构造写入、只是从不被更新 —— 与「零写入」不同类 |
| **v3** | **`app.py` 带 UTF-8 BOM，`ast.parse` 抛 `SyntaxError`，而代码里写的是 `except SyntaxError: tree = None`** | **`NetworkFlow`（19 个读取点）和 `PcapFile` 被判成「零写入方」** |

v3 这条最值得说，因为它**同时是量具缺陷和结论缺陷**：

`dbg_parse_failures.py` 实测 —— 全仓 299 个生产 `.py` 里**只有 `app.py` 一个**带 BOM，
解析失败 0 个、真的语法错误 0 个。也就是说：

> **A 类里那两个错误结论，100% 来自这一个文件。**

#### 10.1 偏置方向是**不对称**的 —— 所以这类缺陷比报错危险

「解析失败 → 记为零写入」这条降级路径的偏置方向是**恒定**的：
它总是把一个文件推向「没人写」→ 推向「这是个缺口」。

也就是说：**量具坏了会凭空制造缺口，而不会掩盖缺口。**
一个会静默降级的扫描器，它的 A 类结论**不可信**，而且不可信的方向是**更多、更严重**的缺口。

> **推广：判据静默降级时，先问「这条降级把结果推向哪个方向」。**
> 推向「一切正常」的风险大家都会想到；
> 推向「更多问题」的那种，往往没人设防 —— 因为它看起来像「查得更严了」。
>
> 同族教训：§7.1.6 的读死计数器（§7.1.4 的看板 count）也是同一个方向 ——
> **量具谎报的问题，系统性地比真实问题更严重。**

修法两处：(a) 解析前 `text.lstrip("\ufeff")`；(b) **解析失败不再静默降级**，
改为收集进 `parse_failures` 并纳入自检闸门。

#### 10.2 修正后的结论（全仓 50 个 ORM 模型）

| 类别 | 数量 | 模型 |
|---|---|---|
| **A. 有生产读取方、零生产写入方** | **2** | `ThreatIoc`、`ThreatIntelFeed`（即 §7.1.8 已记录的那两个） |
| **B. 既无写入也无读取** | **2** | `ToolSignature`、`ToolAnomaly` ← 本节 10.3 |
| C. 有生产写入方 | **46** | 含 `NetworkFlow`、`PcapFile`、`ToolCallLog`、`PipelineSpan`、`BaselineSnapshot`（SQL） … |

对照的另一侧：**48 个模型有生产读取方**（零读取的只有 `ToolAnomaly` / `ToolSignature`）。
所以「零引用是 ORM 常态」在本仓库尤其站不住 —— 50 个里 **48 个有人读、46 个有人写**。

> 这一行的数字是被**核过的**：初稿写的是「46 个有写入方、46 个有读取方」，
> 而读取方那个 46 是顺手写的、未实测。`verify_report_numbers.py` 复核后是 **48**。
> （复核脚本第一版还漏了原始 SQL `INSERT INTO <表名>` 那一路判据，
> 把 `scheduler.py:171` 用 SQL 写 `BaselineSnapshot` 判成零写入，写入方一度算成 45 ——
> 与 `scan_models_without_writers.py` v2 的别名缺陷同族：**漏掉一种写入形态**。）

#### 10.3 `tool_signatures` / `tool_anomalies`：持久化脚手架铺了四层，只差写入

两张表在 schema 里完整存在（`models.py:1013/1024` + `init.sql:649/658`，含两个索引），
但**零生产写入方、零生产读取方**。

**持久化在四个层面都铺好了，唯独缺写入那一层：**

| 层 | 位置 | 状态 |
|---|---|---|
| 表 | `models.py:1013/1024`、`init.sql:649/658` | ✅ 完整（含索引） |
| 配置 | `config.py:294-302` 共 9 个开关，`.env.example:114-122` 逐个出货 | ✅ 完整 |
| 构造器钩子 | `behavior_detector.py:154` `persist: bool = False`、`:172` `self.persist = ...`、`:173` `self._dirty: set`、`:462` `self._dirty.add(...)` | ⚠ 铺好但**从未被消费** |
| 保留期 | `tool_signature_log_retention_days: int = 180` | ⚠ 出货了，**零读点** |
| **写入** | —— | ❌ **不存在** |

量出来的三处「铺好但没接线」：

* **`self.persist` 存进去之后再没有被读过** —— 全文件仅 `:154`（定义）和 `:172`（赋值）两处。
* **`self._dirty` 只 `.add()` / `.clear()`，从不被读** —— 一个给持久化循环用的脏表，没有消费者。
* **全仓唯一的生产实例化 `guard_server.py:89` 是裸的 `BehaviorDetector()`** ——
  连 `persist` 都没传。而全仓**没有任何一处** `BehaviorDetector(..., persist=True)`
  （唯一出现的 `persist=True` 字面量在本守卫自己的断言字符串里）：
  测试里的实例化要么写死 `persist=False`，要么省略走默认值 `False`。

#### 10.4 严重级别：这不是「面板坏了」

`ToolSignaturePanel.tsx` 调的 4 个端点**都在**，而且**都不读这两张表**：

| 前端调用 | 后端端点 | 实际数据源 |
|---|---|---|
| `api.guardStatus()` | `routers/audit.py:52` | `mcp_guard.detector` + `log.stats()` |
| `api.guardSignatures()` | `routers/audit.py:147` | `det.list_signatures()` → `self._signatures`（进程内 dict，`behavior_detector.py:159`） |
| `api.guardAnomalies(40)` | `routers/audit.py:155` | `det.recent_anomalies()` → `self._anomalies`（进程内 deque，`:166`） |
| `api.guardCall(...)` | `http_guards.py:/api/guard/call` | 内存 + 审批队列 |

**面板正常工作**，只是它展示的东西活不过一次重启。
把这条写成「用户可见故障」会是夸大 —— 所以它被钉成前提守卫①。

真实代价是**可用性**：签名要 `tool_signature_min_samples: int = 30` 个样本才 ready，
每次重启后每个 `(tool, caller)` 都要重新学；而偏离历史受 `_ANOMALY_MAX` 的 deque 上限截断。

#### 10.5 与 §7.1.9 的**关键区别**：冷启动是诚实的

| | §7.1.9 `SandboxTask` | 本节 MCP Guard |
|---|---|---|
| 现象 | 永远 pending | 冷启动窗口内无基线 |
| 是否谎报「干净」 | 前端用 `t.verdict && ...` 防御性渲染，不谎报，但**也不提示在等** | 后端**主动**标注 `cold_start=True`、`anomaly_score=None`、`action="logged"`、`reasons=["学习中 (0/30)"]` |
| 失效形态 | 用户以为在跑，其实没在跑 | 用户被明确告知「我还在学」 |

代码路径：`behavior_detector.py:306` 的 `if not dims:` 冷启动分支。
重启后 `_signatures` 为空 ⇒ `dims` 全空 ⇒ 走该分支。

**这个区别必须写进守卫**，否则下一轮审计很可能把它和 §7.1.9 归成一类、给出夸大的评级。
所以前提守卫②是**运行时**断言（真新建一个 detector、真调 `observe_pre_exec`），
而不是 grep。

`observe_pre_exec` 的 docstring 写明「失败返回 None（fail-open）」，
`mode` 支持 `shadow/confirm/enforce/deny`，冷启动窗口的 fail-open 是**显式设计**，
不是缺陷 —— 这一点也要写明，否则会被当成又一个「默认放行」的问题重复上报。

#### 10.6 守卫：`tests/test_tool_signature_persistence_gap.py`（**5 passed / 3 strict xfail**）

| 守卫 | 作用 |
|---|---|
| 前提①面板端点读内存而非空表 | 严重级别分界线；端点改读表即转红，要求重估 |
| 前提②**冷启动诚实**（运行时断言） | 防止「重启后静默失效」被误当成同一个问题 |
| 前提③`tool_call_log` 确实落库（对照组） | 防止更宽的误判「mcp_guard 从不碰 DB」 |
| 前提④detector 容器是进程内结构 | 与 grep 模型名互相独立的物证 |
| 对照组：另外 8 个签名开关仍有读点 | 防止过度归因成「签名配置整体空转」 |
| **xfail①**两张表有生产写入方 | 接线即转红 |
| **xfail②**`persist` 真的控制持久化 | 三处静默失败点任一修好即转红 |
| **xfail③**`log_retention_days` 有读点 | 接了落库却不清表 = 无界增长 |

**三条 xfail 全部验红**（注入修复 → XPASS(strict) 转红），注入文件按 sha256 校验还原：

| 注入 | 结果 |
|---|---|
| `ToolSignature(id=1)` 实例化 | `XPASS(strict) 转红` |
| 加 `flush()` 读 `_dirty` + 读 `self.persist` + 生产传 `persist=True` | `XPASS(strict) 转红` |
| 给 `log_retention_days` 加读点 | `XPASS(strict) 转红` |

还原后 4 个被注入文件的 **sha256 逐个与注入前一致**（含行尾），
`git diff` 确认剩余改动均为本会话早前的 P0 修复，非本次残留。

#### 10.7 附带发现：`network_flows` / `pcap_files` 是**条件写入**，不是零写入

`app.py:219-236` 与 `:240-244` 确实有 `_persist_flow` / `_persist_pcap_meta`
两个回调，`session.add(NetworkFlow(...))` / `session.add(PcapFile(...))` 都在。

但它们被 `app.py:214` 的 `if settings.capture_enabled:` 门控，而
`config.py:351` `capture_enabled: bool = False` —— **默认关闭**，
`.env.example:257` 也出货了 `SHARED_MEMORY_CAPTURE_ENABLED=false`。

所以准确表述是**「有写入方、默认关闭」**，不是「零写入方」。
`/api/ndr/flows`（`routers/ndr.py:18`）在默认部署下恒为空，
但抓包本身是侵入式开销，默认关是合理设计 —— 记为边界条件，不记为缺口。
（另：前端 `api.ts` 全文无 `ndr` / `flows` 引用，NDR 目前是纯 API 面，无 UI 消费。）

#### 10.8 更正报告里一句经不起查的话

报告 §6.3.4「查证后确认不是缺陷」曾把这两个模型列为**非缺陷**，
判定依据是「SQLAlchemy 模型，零引用是 ORM 常态，删会掉表」。

**「零引用是 ORM 常态」在本仓库不成立** —— 全仓 50 个模型里 **46 个有生产写入方、
48 个有生产读取方**，零读零写的只有这 2 个。把它归为「ORM 常态」是用一句未经核实的话
把一个真实缺口解释掉了。

「删会掉表」这半句是对的（所以处置应是**接线，或明确删除并同步改文档**），
但**不能用「这是常态」替代「查过没有」**。

§6.3.4 的原判定已就地标注撤回（标题由「7 个」改为「6 个」，
并在表下加了更正块），两处结论现在一致。

### 7.1.11 配置开关接线普查：329 个字段里 37 个读不出来（本轮新增）

§7.1.7 撞见 `mitm_enabled`、§7.1.10 撞见 `tool_signature_log_retention_days` ——
两次都是**窄口径**（一个只扫布尔开关、一个只扫签名相关）。
本节把口径系统化到 `config.py` 的**全部 329 个** `Settings` 字段。

#### 11.0 扫描器要防的三个陷阱

| 陷阱 | 后果 | 处理 |
|---|---|---|
| **定义行不是读点** | `config.py` 里那行 `xxx: bool = False` 自己被算成「有人读」 | 排除 `config.py` |
| **裸名匹配会误判** | 若代码用 `getattr(settings, k)` 传变量 k，裸 `\bkey\b` 会把 329 个键全算成有读点 | 只认三种形态：`.<key>` 属性访问、`["']<key>["']` 环境变量名、`getattr(settings, "<key>", …)` 的**字段名裸字符串** |
| **`model_dump()` 整体读取** | 逐字段判零会把全表误判成死开关 | 先探测 `settings.(model_dump\|dict\|json)(` —— 实测**零命中**，故本口径成立 |

> ⚠ 上表第二行的「两种形态」是初版口径，**漏了第三种** ——
> `security_crypto.py:26` 的 `getattr(settings, "control_hmac_key", "")`
> 里字段名以**裸字符串**出现，既无前导点也不是环境变量名，
> 初版把它判成零读点，由 §7.1.13 的自检闸门拦下。

#### 11.0.1 补充检验：读点还有没有**第四种形态**

§7.1.14 指出「判据只覆盖我想到的写法」是本轮最常见的错误，
所以这里专门回头查了本节口径是否还漏别的读法：

* **动态构造的环境变量名** —— 全仓只有一处 `os.environ.get(name)` 传变量
  （`kafka_consumer.py:81` 的 `_env_int(name, fallback)`），
  但它的 docstring 写明「**旧的无前缀环境变量**优先于 settings，
  避免改掉已经在跑的覆盖」—— 是有意保留的兼容路径，且**不带 `SHARED_MEMORY_` 前缀**，
  与本节的分析口径无关。
* **`SHARED_MEMORY_ENV_NAME`** —— `app.py:407` 直接 `os.environ.get` 读，
  同时 `config.py:113` 有 `env_name: str = "dev"` 字段兜底，**是活的**。

结论：A/B 两类的判定在这两类读法下都成立，未被推翻。
这与 §7.1.13 的过滤规则问题是**同一族的判据粒度问题**：
结论建立在「枚举出的形态」上，枚举不全就会漏 —— 只是这次查完确认没漏。

#### 11.1 自检闸门抓到我自己的分类错误

第一版把 `mitm_enabled` 写进「已知零读点」样本，自检立刻失败并拒绝输出：
它其实**有 1 个读点**（`mitm_proxy.py:40`），只是那个模块从不被导入。

> **「零读点」和「读点全在休眠模块」是两个不同的问题，必须分开记：**
> 前者是连读的代码都没有；后者代码里明明写着有人在读，
> 但那几行**从不被执行** —— 后者更隐蔽，因为代码审查看上去一切正常。

#### 11.2 结果

| 类别 | 数量 | 占比 |
|---|---|---|
| **A. 零读点** | **17** | 没有任何生产代码读它 —— 设成什么都不会发生 |
| **B. 读点全在休眠模块内** | **20** | 读了，但读它的那几行代码从不被执行 |
| C. 有活读点（对照组） | 292 | —— |

A 类 17 个：`audit_max_rounds_standard`、`audit_p1_use_temporal`、`forensic_dump_max_mb`、
`fw_ssh_user_readonly`、`ingest_store_batch_flush_ms`、`intel_poll_interval`、
`kafka_flink_secondary_llm`、`kafka_topic_flows`、`kafka_topic_pcap_meta`、`kafka_topic_tls`、
`llm_enhancer_concurrency`、`log_batch_interval`、`response_ssh_key`、
`self_play_decoy_ratio`、`self_play_default_rounds`、`tool_exec_default_timeout_ms`、
`tool_signature_log_retention_days`。

B 类 20 个按能力域聚成 5 组，每组对应 §7.1.5 的一块休眠模块：

| 组 | 开关 | 休眠模块 |
|---|---|---|
| TAXII | `taxii_url` / `taxii_user` / `taxii_password` | `threat_intel/stix_taxii.py` |
| MISP | `misp_url` / `misp_api_key` / `misp_verify_ssl` | `threat_intel/stix_taxii.py` |
| MITM | `mitm_enabled` / `mitm_listen_port` / `mitm_ca_key` / `mitm_ca_cert` | `encrypted_traffic/mitm_proxy.py` |
| 邮件处置 | `graph_tenant` / `graph_client_id` / `graph_client_secret` | `response_engine/containment/mail_adapter.py` |
| 主机 / 目录处置 + 取证 | `kill_process_max_matches` / `forensic_include_dump` / `forensic_snapshot_timeout_s` / `ldap_url` / `ldap_bind_dn` / `ldap_bind_password` / `ldap_base_dn` | `host_adapter.py` / `directory_adapter.py` |

#### 11.3 出货覆盖：**14 个「填了也不会生效」**

`.env.example` 共出货 150 个 `SHARED_MEMORY_*` 键，其中：

* **A 类出货 4 个**：`self_play_decoy_ratio`、`self_play_default_rounds`、
  `intel_poll_interval`（§7.1.8 已记录）、`tool_signature_log_retention_days`（§7.1.10 已记录）
* **B 类出货 10 个**：`taxii_url` / `taxii_user` / **`taxii_password`** /
  `misp_url` / **`misp_api_key`** / `misp_verify_ssl` /
  `mitm_enabled`（§7.1.7 已记录）/ `mitm_listen_port` / **`mitm_ca_key`** / `mitm_ca_cert`

> **出货了却无效，比内部死配置严重一级** —— 它是对运维的承诺落空。
> 而 `graph_client_secret` / `ldap_bind_password` 这两个凭据**反而没出货**，
> 说明连「这里需要配密钥」都没告知，进一步印证那几块能力确实没接线。

#### 11.4 `self_play` 那两个开关为什么会死 —— 不是随机的

`routers/self_play.py::_cfg_from_req` 里，**所有**请求字段都遵循
「请求优先、回落 `settings`」，只有两个例外：

```python
"inject":              req.inject if req.inject else bool(settings.self_play_inject),        # 有回落
"wait_audit":          req.wait_audit if req.wait_audit else bool(settings.self_play_wait_audit),  # 有回落
"diverse_env":         bool(req.diverse_env) or bool(getattr(settings, "self_play_diverse_env", False)),  # 有回落
"background_traffic":  bool(req.background_traffic) or bool(getattr(settings, "self_play_background_traffic", False)),  # 有回落
"decoy_ratio":         req.decoy_ratio,   # ← 没有回落，取死值 Field(0.2)
"rounds":              req.rounds,        # ← 没有回落，取死值 Field(8)
```

而零读点的 `self_play_*` 开关**恰好就是这两个**，且请求字段默认值与配置默认值
**完全一致**（`0.2` / `8`）—— 不是巧合，是同一处漏改。

后果是可测的：把 `settings.self_play_decoy_ratio` 设成 `0.9`，
`_cfg_from_req` 产出的仍是 `0.2`。**前提守卫④用运行时实证钉住这一点**
（同一个函数里带回落的 `wait_audit` 作为对照组，确保不是我的理解过时了）。

这与 §7.1.6 同形：**值有人写了，读的人挑错了源**。
配置层写了值，请求层用另一个硬编码源，两边看起来都「对」。

#### 11.5 `audit_p1_use_temporal`：注释描述了一个开关能控制的行为

```
scheduler.py:728   # 仅 P0 agent 走 Temporal; P1 (audit_p1_use_temporal=False) 降级 llm_single
scheduler.py:729   go_temporal = temporal_lane and tier == "P0"
```

`:729` 是**硬编码**的。注释里那个括号中的开关名，全仓**只有注释里这一处**，
没有任何一行代码读它 —— 即 P1 是否走 Temporal 完全不可配置，
`SHARED_MEMORY_AUDIT_P1_USE_TEMPORAL=true` 什么也不会发生。

同样形态：**注释是承诺，代码没兑现**，且注释写得足够具体，
读代码的人会以为它是可配的。

#### 11.6 守卫：`tests/test_config_switch_wiring.py`（**4 passed / 4 strict xfail**）

四条前提守卫 + 四条 strict xfail。前提守卫里最重要的是**对照组**：
断言「有活读点的字段 ≥ 250 个」，以及三个已知答案（零读点 / 仅休眠读点 / 活读点）
逐个核对 —— 否则「37 个读不出来」和「扫描器什么都没匹配上」长得一样。

`_readers()` 加了 `functools.lru_cache`：要给 329 个字段各扫一遍全仓，
6 个测试各调一次就是 6 倍开销。实测 **40.5s → 10.7s**。

**四条 xfail 全部验红**（注入修复 → XPASS(strict) 转红），还原后 sha256 一致：

| 注入 | 结果 |
|---|---|
| 把 37 个死开关一次性全部接线到活模块（`routers/edr_intel.py`） | **3 条 XPASS(strict) 转红** + 前提守卫同时报「已知答案已变」 |
| 给 `scheduler.py` 的 `go_temporal` 加上真实读取 `audit_p1_use_temporal` | **1 条 XPASS(strict) 转红** |

> 前三条 xfail 的断言是 `assert not dead`，**全量翻转才转绿**。
> 所以验红必须一次注入全部键 —— 单点注入不会 XPASS，
> 会让验红「看起来失败」。这一点在写验红脚本前就该想到，
> 否则很容易误判成「守卫方向写反了」。

### 7.1.12 ⚠ 公开注册闸门从未实现：`.env.example` 出货了它，测试守住了它的存在（本轮新增）

这是本轮**严重级别最高**的一条，而且它的发现方式本身值得记：
**§7.1.11 扫「Settings 字段有没有读点」，本节是反过来扫「`.env.example` 的键
对不对得上 Settings 字段」** —— 两个方向问的问题不一样。

#### 12.0 事实链

| 层 | 状态 |
|---|---|
| 审计文档 | `docs/AUDIT-2026-10-03-修复实施计划.md:18` 列为待修：现状「**无（永远开）⚠️**」→ 目标 `False`；`:139` 写明实施方案「在 `config.py` 加 `allow_self_registration: bool = False`」 |
| `.env.example:45` | ✅ **已出货** `SHARED_MEMORY_ALLOW_SELF_REGISTRATION=false` |
| `config.py` | ❌ **没有这个字段** |
| 生产代码读点 | ❌ **全仓零读点**（`.env.example` 之外，唯一出现在既有测试的字符串常量里） |
| 端点 | `routers/auth.py:115-172` 注册处理函数**全程没有任何开关判断** |
| 公开性 | `app.py:432-438` `_PUBLIC_PATHS` **无条件**包含 `/api/auth/register` |

即：**那次安全修复只做了一半** —— `.env` 侧做了，`config.py` 侧和执行侧从未做。

#### 12.0b 2026-10-19 复核：事实链仍成立，但**影响面比原先写的更大**（待决项 21）

四条子论断逐条复核，**全部仍成立**（`.env.example:45` 仍出货 / `config.py` 仍无字段 /
全仓读点仍只在测试文件里 / `_PUBLIC_PATHS` 仍含该端点）。
本轮新增查证到两个事实，它们**直接决定这个决定该怎么下**：

| 新查证 | 位置 | 对决策的意义 |
|---|---|---|
| **管理员登录与自注册无关** | `routers/auth.py:78-85` 用 `settings.admin_user` / `admin_password`（`.env.example:23` 出货 `SHARED_MEMORY_ADMIN_PASSWORD`）直接校验 | 关闭自注册**不会**把管理员锁在外面 —— 原先担心的运维风险**不存在** |
| **前端有完整自助注册入口** | `frontend/src/.../RegisterForm.tsx` + `LoginForm.tsx:100-101` 的「去注册」链接 + `/register` 路由 | 关闭它**不是**纯安全收紧，而是**改变 onboarding 模型**；只改后端会让用户点「去注册」后撞 403 |

端点现有的三道缓解（决定它是「中危」而非「高危」）：
`routers/auth.py:158` role 硬编码 `viewer`（无提权）、`:133-134` admin 用户名被拒、
`:136-151` 限流 **best-effort** —— Redis 不可用时 `except Exception: pass`，
**限流静默失效**。

**所以这不是一个可以单方面关掉的开关。** 完整改动需要同时覆盖：
后端 `config.py` 字段 + 端点判断、前端隐藏「去注册」入口并给出明确文案、
把 `tests/test_self_registration_gate.py` 的 3 条 **strict xfail** 转正
（strict xfail 在缺口被补上时会 XPASS 转红，这是它作为「待关闭项清单」的设计意图）。
是否做、以什么默认值做（默认关 / 默认开但强制显式确认），属产品决策 —— 见 §9.8 的待决项。

#### 12.1 为什么这条比 §7.1.11 的 37 个开关严重

三个原因叠加，缺一不可：

1. **它在公开端点上。** 不需要任何凭证即可调用。
2. **`false` 出货了，但它是空操作。** 运维照 `.env.example` 配了，会**真的相信注册已关闭**。
   这比不出货更糟 —— 不出货只是缺信息，出货了是**错误的确认**。
3. **已有测试给它盖章。** `tests/test_security_fixes_2026_10_03.py:362`
   `test_env_example_documents_security_defaults` 断言该键在 `.env.example` 里 ——
   **该测试当前是绿的**。

> 第 3 点是本轮见过的最隐蔽的失效形态：
> **同一个安全修复，一半有测试、一半没有，而绿的那一半正好是让人以为整件事做完了的那一半。**
> 它守的是「这个键被写进了 `.env.example`」，不是「这个键生效」。
> 修复的文档侧有测试背书，执行侧一片空白 —— 两者加起来等于「已修复」的假象。

#### 12.2 严重级别要说准：**没有提权**

不要夸大，也不要含糊：

* `routers/auth.py:158` `create_user(..., role="viewer")` —— role **硬编码**，注册出的账号拿不到任何提权；
* `:133-134` 显式拒绝占用内置 admin 用户名；
* `:137-151` 有按 IP 限流（20 次/小时）。

真实影响是**公开端点上的无界账号创建**，不是权限提升。

但有一处必须单独指出：限流是 **best-effort** ——

```python
except Exception:
    pass          # routers/auth.py:150-151
```

Redis 不可用时限流**整个失效**，且不报错、不告警。
所以「有限流」只能写成「Redis 可用时有限流」，**不能列为缓解措施**。
这条已钉成前提守卫⑤：哪天改成 fail-closed，严重级别要下调。

#### 12.3 同一张表里另外三项都做完了 —— 这把失败精确定位到一项

那张表共四项待修。逐项核实（`check_audit4_items.py`）：

| 配置项 | `config.py` 有字段 | 生产读点 | 结论 |
|---|---|---|---|
| `execution_mode` | ✅ | 14 处 | ✅ 已落地 |
| `control_hmac_key` | ✅ | 1 处（`security_crypto.py:26`） | ✅ 已落地，且已改 **fail-closed** |
| `llm_budget_unlimited` | ✅ | 2 处（`llm_enhancer.py:73`、`summary_compression.py:140`） | ✅ 已落地 |
| **`allow_self_registration`** | ❌ **无** | **0** | ❌ **半修复** |

所以不能写成「那份计划被整体忽略」——**三项做对了，只有一项停在 `.env` 那一侧**。
这条对比本身就说明：这不是执行不力，而是**某一步被漏掉了**，且漏掉的那一步没人发现。

`control_hmac_key` 那条尤其值得对照 —— `security_crypto.py` 的 docstring 记着
它当年修的是什么：**两个密钥都为空时回退到源码里的公开常量
`b"dev-hmac-unconfigured"`**，于是任何人读过源码就能伪造审批签名。
修法是 fail-closed（缺密钥即抛异常）。

而且它的 docstring 还记了**同一种测试失效**：

> 「`test_control_plane_security.py` 的 autouse fixture 只 pin 了 TTL、
> 从未 pin 或断言密钥存在，因此签名与验签双方都回退到同一常量、结果一致，
> **测试永远绿**。」

> **这是同一个失效模式的第二次出现，而且是同一份代码里的先例。**
>
> 本仓库有一种反复出现的写法：**给「配置的文档面」写测试，
> 而不给「配置的执行面」写测试**。
> 文档面（`.env` 出货、key 存在、默认值写着）容易断言，于是有了绿测试；
> 执行面（端点是否真的拒绝）没人断言，于是缺口长年不被发现。
>
> 判断方法：**看到一个守着 `.env.example` 的测试，要问它有没有同时守执行面。**
> 没有的话，它守的是「我们打算修」，不是「我们修了」。

#### 12.4 守卫：`tests/test_self_registration_gate.py`（**5 passed / 3 strict xfail**）

**5 条前提守卫全部围绕严重级别**：①端点确实公开 ②role 确实硬编码 `viewer`
③admin 用户名确实被拒 ④`.env.example` 确实出货且值为 `false` ⑤限流确实 best-effort。
任何一条变化都会让本节的严重级别需要重估 —— 这是把「不要夸大」写成可执行的检查。

3 条 strict xfail 覆盖三个独立缺口：`config.py` 缺字段 / 端点不读开关 /
既有安全测试守错了对象。

**三条全部验红**，且按 sha256 校验还原（含行尾，`config.py` 是 CRLF 文件，
注入时匹配行尾，未产生混用）：

| 注入 | 结果 |
|---|---|
| C1：`config.py` 加字段 **+** 注册端点加闸门 | 2 条 XPASS(strict) 转红 |
| C2：**只**加 `config.py` 字段 | 1 条 XPASS(strict) 转红（验证两条 xfail 各自独立） |
| C3：让既有安全测试同时校验 `config.py` | 1 条 XPASS(strict) 转红 |

#### 12.5 顺带修掉一个**系统性**隐患：`xfail` 会吞掉守卫自己的崩溃

C3 第一版**没转红**。查下去是两层叠加：

1. 我那条正则括号不配对（`re.error`）；
2. **`pytest.mark.xfail` 在未指定 `raises=` 时会捕获任何异常** ——
   不只是 `AssertionError`，还包括 `KeyError` / `TypeError` / `re.error`。

于是这条守卫连着几轮都在报「缺口仍在」，而它其实**每次都在崩** ——
**崩溃与「正确检测到缺口」在输出上完全同形**。

**判据**：`raises=AssertionError`。加上之后，任何非断言的异常会**直接判失败**，
守卫的崩溃从此可见。

这不是个别问题，也不止本会话新建的守卫。**全仓普查后逐个补齐**：

| 轮次 | 范围 | 补齐处数 |
|---|---|---|
| 第一轮 | 本会话新建的 7 个守卫文件 | 12 处 |
| 第二轮（全仓复审） | `test_zeroday_wiring_gap.py`、`test_acceptance_g9_spec_gaps.py`、`test_acceptance_g4_llm_egress.py`、`test_acceptance_g5_executor_budget.py`、`test_acceptance_g7_integration_faults.py` | 6 处 |

最终：**25 个 strict xfail 标记块，25 个都配了 `raises=AssertionError`**，
未覆盖的文件为 0。

补齐后全量回归 `2147 passed / 49 xfailed`（**这是该次补齐当时的快照值**，
非最终值 —— 最终回归数字见 §一 验收表），
**与补齐前逐位相同** ——
这本身就是校验：**没有任何一条 xfail 靠「异常」而非「断言」在 xfail**。
若补完出现转红，说明那条 xfail 原本靠异常撑着，必须单独查。

复审脚本只改 `@pytest.mark.xfail(...)` **标记块内部**；
docstring 与散文里提到的 `strict=True` 一律不动
（`test_sandbox_task_dead_end.py:202`、`test_zeroday_wiring_gap.py:40` 都是散文，不是标记）。

> **推广（本轮最值得带走的一条）**：
> `xfail` 不指定 `raises=` 时，**它无法区分「测试正确地失败了」和「测试自己炸了」**。
> 而 strict 只加严了「通过时必须转红」，对**失败得对不对**毫无约束。
>
> 这与 §7.1.10 的 BOM 静默降级是同一个家族：
> **量具的失效形态和量具的正常输出长得一样。**
>
> 补 `raises=AssertionError` 是一行成本；不补的代价是
> 「守卫在报缺口」可能是**它在崩**，而没有任何信号告诉你。

### 7.1.13 把「测试守错了对象」也系统化：13 个被守键里 6 个不生效（本轮新增）

§7.1.12 的发现方式是撞见的：一条绿测试守着 `.env.example` 的键，
而那个键在生产里零读点。本节把查法系统化。

#### 13.0 判据

「这个键被**文档面测试**守着」的准确口径：

* 某个 `test_*` 函数体**代码**（AST 字符串常量）里出现 `SHARED_MEMORY_*`；
* 且该键**真的在 `.env.example` 里**。

「文档面被守、但**实际不生效**」分两类（§7.1.11 已立的口径，不能混）：

| 类别 | 数量 | 键 |
|---|---|---|
| **A. 生产零读点** | 3 | `ALLOW_SELF_REGISTRATION`、`SELF_PLAY_DECOY_RATIO`、`SELF_PLAY_DEFAULT_ROUNDS` |
| **A2. 读点全在休眠模块内** | 3 | `MISP_API_KEY`、`MITM_ENABLED`、`TAXII_PASSWORD` |
| B. 确有**活**读点（对照组） | 7 | `JWT_SECRET`、`ADMIN_PASSWORD`、`DATABASE_URL`、`EMBEDDING_API_KEY`、`LLM_API_KEY`、`CONTROL_HMAC_KEY`、`EXECUTION_MODE` |

**6 / 13 = 46%**。也就是说：凡是有人为它写过绿测试的键，近一半是无效的。

B 类那 7 个尤其值得看 —— 它们全是最敏感的键（JWT 密钥、管理员口令、
数据库连接串、模型 API Key），**全部是活的**。所以这不是「`.env.example` 整体不可信」，
而是「**写了什么**决定它可不可信」。

#### 13.1 扫描器自己翻了三次车（每次都改变结论）

| 版本 | 缺陷 | 造成的假结论 |
|---|---|---|
| v1 | 抓整个函数体**文本**，含 docstring | 把说明文字里的占位符 `SHARED_MEMORY_*` 当成真键；再去掉前缀得单字母 `x`，`\.x\b` 在 `causal_chain/compare.py` 匹配到 11 处 —— 占位符被归进「有活读点」的对照组 |
| v1 | 读点判据只有两种形态 | 漏了第三种：`getattr(settings, "control_hmac_key", "")`（**字段名以裸字符串出现**，既无前导点也不是环境变量名），把 `CONTROL_HMAC_KEY` 判成零读点 |
| v2 | 分不清「有读点」与「有**活**读点」 | 把 3 个读点全在休眠模块的键放进对照组，结论直接误导 |

另外两条**加过滤器时的教训**：

* 先试「候选键的字段名必须在 Settings 里或被 `os.environ` 读过」——
  **结果把 `ALLOW_SELF_REGISTRATION` 一起滤掉了**，而它正是要找的那一类
  （不在 Settings、无生产读点）。**把结论的核心滤掉了。**
* 正确判据回到前提本身：**候选键必须真的出现在 `.env.example` 里**。
  占位符不会出现在那里，不需要额外启发式。

还有一条**假阴性**：v2 加了「函数体里必须出现 `.env.example`」这条看似合理的过滤，
结果把本文件 §7.1.11 的 `test_env_example_parses_and_ships_the_keys_we_care_about`
剔除了 —— 它的函数体只调 `_shipped_keys()`，`.env.example` 只在 docstring 里。
**前提守卫被当成无关测试剔除，分母从 13 缩到 8。**

> **推广**：
> **过滤规则会同时滤掉「噪声」和「你正要找的东西」，而后者是无声的。**
> 每加一条过滤器，必须问「它会不会把目标本身滤掉」。
> 本条是靠「前提守卫被剔除 → 分母变了 → 前提守卫自己转红」才发现的 ——
> **计数类前提守卫的真正作用，是让口径变更自己报警。**

#### 13.2 元规则守卫：`tests/test_config_switch_wiring.py` 内新增

不逐条列那 6 个键（逐条列只能守住当前这批），而是写成**元规则**：

> 凡是断言「某键必须出现在 `.env.example`」的测试，都必须同时有
> (a) 生产代码在**活模块**里真的读它，或 (b) 一个把它登记为缺口的守卫。

任何人新增一条 `.env.example` 断言都会被立刻要求配执行面验证。

#### 13.3 它**不接受半修复** —— 这是验红时才暴露的性质

第一次验红只往活模块注入 `_inj13_settings.<key>` 引用，**没转红**。
查下去发现：`_readers()` 是**以 `config.py` 的 Settings 字段为键**去扫的，
而 `allow_self_registration` 不是字段 → 它的读点恒为 0，
无论代码里写没写那个引用。

这其实是**正确的性质**，不是缺陷：§7.1.12 的修复本来就要求两件事同时做 ——
`config.py` 加字段 **+** 生产代码读它。只做一件不构成修复。
**元规则不接受半修复，正是它该有的行为。**

| 注入 | 结果 |
|---|---|
| 只加 `config.py` 字段 | **0 条 XPASS** —— 拒绝半修复（并有前提守卫报字段数变化） |
| 加字段 **+** 6 个键全部接线 | **元规则 XPASS(strict) 转红** + 2 条前提守卫同时报「已知答案已变」（字段数 329→330、`mitm_enabled` 不再是仅休眠读点） |

还原后 `config.py` / `edr_intel.py` 的 **sha256 与注入前一致**，无混用行尾
（两个文件都是 CRLF，注入时匹配行尾）。

### 7.1.14 指标接线普查：**0 个从未写入**，唯一失效的就是已知那个（本轮新增）

前面几轮（§7.1.10 模型表 / §7.1.11 配置开关 / §7.1.13 `.env.example`）都发现了成片缺口。
指标这一面扫完是**否定结论** —— 但这个否定结论本身要验证过才算数。

#### 14.0 结果：66 个指标，四条写入路径

| 类别 | 数量 | 含义 |
|---|---|---|
| **live** | 59 | 包装函数在活模块被调用 |
| **mounted** | 2 | 写入器是**类方法**，由 `app.py:640 add_middleware(MetricsMiddleware)` 挂载后被框架调用 |
| **dormant_only** | **1** | `soc_intel_ioc_total` —— 唯一调用点在休眠模块 `stix_taxii.py:75`（即 §7.1.6 已记录） |
| **declared_only** | **0** | 声明了却压根没有写入路径 |

> **该面唯一一个失效指标就是 §7.1.6 已经登记的那个，没有第二个。**
> 这是 §7「§十一 P2 的 7 类检测指标已全部落地」那条结论的独立复核，
> 且是用一条与 §7 完全不同口径的判据得到的。

#### 14.1 扫描器翻了**五次**车 —— 五次都被自检闸门当场拦下

| 版本 | 缺陷 | 造成的假结论 |
|---|---|---|
| v1 | 行级正则 `labels\([^)]*\)` 匹配跨行调用失败 | **17 个核心指标被判成 declared_only**（`DETECTION_OUTCOMES.labels(\n...\n).inc()` 跨了 3 行） |
| v1 | 标签参数硬取 `args[1]` | docstring 占了那个位置，所有 `core_metrics.py` 指标都被记成「无标签」 |
| v1 | 操作正则要求 var 后有**两个**点 | `VAR.inc()` 只有一个点 → 全部判成零读点 |
| v2 | 只认 `Name(...)` 调用 | `_m.set_mttr_seconds(...)` 是**属性调用** → 4 个已手工核实的活指标被判成死的 |
| v2 | 整体排除定义模块 | `metrics.py:392` 模块级 `set_eventbus_subscribers(...)` 被漏掉 |
| v3 | `Counter` 不分来源 | **`collections.Counter` 被当成 Prometheus 指标**（`learn_loop/models_cluster.py:118-119` 的 `types = Counter(<genexpr>)`），产生 2 个假指标；短名 `types` 又在全仓匹配出无关命中 |
| v3 | 不认方法型写入路径 | `MetricsMiddleware.__call__` 写的两个 HTTP 指标被判成 declared_only |

> **七次修正，六次都是同一类错误：判据只覆盖了「我想到的那种写法」。**
>
> 这与 §7.1.13 的「过滤规则会滤掉目标」是镜像：
> 那边是**多加**一条规则把目标滤掉，这边是**少写**一种形态把目标漏掉。
> 两者都不会报错 —— 只会在数字上体现。
>
> **两次都是自检闸门拦下的，不是事后看出来的。**
> 尤其是 v3 的 `collections.Counter`：它让一个**真实存在的**文件
> 贡献了两个「指标」，看起来像多了缺口，实际是多了假缺口 ——
> **假缺口与真缺口在报告上长得一模一样。**

#### 14.2 新增的第四条写入路径：`mounted`

这一条是 v3 才发现的：**写入器可以是类方法，由框架挂载后调用，
代码里没有任何直接调用点**。

```
app.py:640   app.add_middleware(MetricsMiddleware)
metrics.py:407  class MetricsMiddleware:
metrics.py:413      async def __call__(self, scope, receive, send):
metrics.py:430-431      HTTP_REQUESTS.labels(...).inc()
                          HTTP_DURATION.labels(...).observe(...)
```

若不识别这一类，`soc_http_requests_total` / `soc_http_request_duration_seconds`
会被判成「声明了从不写入」——**而它们是全仓最基础的两个 HTTP 指标**。

> 这条对前面几轮的口径有反推作用：
> **§7.1.11 的配置开关扫描只认「属性访问 / `getattr` / `os.environ`」三种读点形态，
> 没有考虑「由框架在运行时读取」这一类**。
> 虽然配置项没有「挂载」这种用法（那是代码结构特有的），
> 但这次至少说明：**每换一个面，都要重新问一遍「写入/读取还可能是什么形态」。**

#### 14.3 守卫：`tests/test_metric_wiring_guard.py`（**8 passed**）

既有的 `_public_writers` 只收「`tree.body` 里以 `inc_/note_/record_/set_` 开头的
**模块级函数**」，所以两类它看不见：

* 指标被声明了，但**压根没有写入器函数**；
* 写入器是**类方法**（`__call__`）。

本轮补的就是第一条：`test_every_declared_metric_has_at_least_one_write_path`
—— **声明了就必须有写入路径，哪怕那个写入方只在休眠模块里**（后者由 §7.1.5 另行管，
不重复判罚）。

另加前提守卫 `test_metric_declaration_extraction_finds_the_known_metrics`，
其中专门断言 **`collections.Counter` 不许被收进来**（v3 踩过的坑）。

**两条都验红**（注入即转红），还原后 sha256 一致：

| 注入 | 结果 |
|---|---|
| C1：加一个无写入点的 `Counter` | `test_every_declared_metric_has_at_least_one_write_path` 转红 |
| C2：名字解析退回 v1 口径 | 前提守卫**与**主守卫**同时**转红 |

> **正因为 `declared_only` 现在是 0，才需要这条守卫** ——
> 否则下一个新加的指标可以毫无阻力地带着一个永远为 0 的读数进仓库。

### 7.1.15 指标的消费面：`declared_only` 是 0，消费侧却漏了 42 个（本轮新增）

§7.1.14 查的是「声明了有没有人写」。本节查另一半：**写出来了，有没有人看**。

**两件事必须分开**，因为它们的失效形态完全相反：

| 层 | 问题 | 症状 | 谁在守 |
|---|---|---|---|
| 产出侧 | 声明了没人写 | 读数**恒为 0** | §7.1.6、§7.1.14 |
| 消费侧 | 写了没人看 | 读数**正常变化，但没有任何面板/告警** | 本节 |

§7.1.6 的 `soc_intel_ioc_total` 属于前者。**本节全部属于后者。**

#### 实测

扫 `config/grafana/provisioning/dashboards/*.json`（2 个仪表盘、22 条 PromQL、
22 个唯一指标名）与 `config/prometheus/alerts.yml`（9 条规则、9 个指标名），
与全仓 62 个声明指标对撞：

| 项 | 数 |
|---|---|
| 声明指标（AST 扫 `metrics.py` + `core_metrics.py`） | **62**（与 §7.1.14 独立复核一致） |
| 仪表盘引用的指标 | 22 |
| 告警规则引用的指标 | 9 |
| **仪表盘 / 告警都引用的并集** | **20** |
| **在仓库可验证的 Prometheus 消费面上零出现** | **42 / 62（68%）**（原始引用并集口径） |
| ⚠ **更正（§9.37.4）** | **守卫口径为 40 / 62** —— 仪表盘查 Histogram 的 `_bucket`
派生序列时**基础指标名并不出现在原始引用里**，原始并集口径因此**高估**了 2 个缺口 |

**先说好消息（否定结论，同样要记）**：仪表盘与告警引用的
**31 个指标名全部能对到真实声明**，没有「死面板」也没有「永不触发的告警」。
这一条此前无守卫，已由本轮新增的
`test_every_dashboard_metric_is_declared_in_python` 与
`test_every_alert_rule_metric_is_declared_in_python` 固化。

**坏消息在别处**，而且刺眼之处在于：**本轮整改自己新增的两个指标，
一个只有测试在读，另一个全仓零引用。**

| 指标 | 声明 | 仪表盘 | 告警 | 其它引用 |
|---|---|---|---|---|
| `soc_detection_outcomes_total` | `core_metrics.py:227` | ❌ | ❌ | 仅 `tests/test_detection_metrics_end_to_end.py:15,45` |
| `soc_detection_seconds` | `core_metrics.py:221` | ❌ | ❌ | **无，全仓零引用** |

后果具体到 §十一.1 的原话：「监控不能只记录最终检测分数，还应记录
检测依据不足、运行错误和真实阴性各自的数量」——

- **数据层**：做到了。五态分列的计数器在写，耗时 Histogram 在分布。
- **运维可见性层**：从未发生。`alerts.yml` 的 9 条规则只覆盖
  队列丢弃 / DLQ 积压 / 关闭遗留任务 / Kafka 积压，**没有一条覆盖检测引擎**。

于是 Sigma 引擎开始批量报错这件事，数据完整地落在了 TSDB 里，
而**没有任何一块屏幕会亮**。这不是「少个面板」，这是本轮整改的核心成果
（P0-1 状态传播）在运维侧断掉的最后一环。

> ⚠️ **`alerts.yml` 自身是好的**：9 条规则引用的指标全部存在，
> `prometheus.yml:9-10` 的 `rule_files` 确实加载了它，
> `docker-compose.yml:633` 也确实把文件挂进了容器。
> 「声明了但没人加载」这一层已被排除 —— 缺的不是加载，是**规则本身没写**。

#### 口径边界（必须写清，否则会把结论说过头）

「零消费」只声称到**仓库内可验证的 Prometheus 消费面**：

- `config/grafana/provisioning/dashboards/*.json` —— 被 provision 的仪表盘
- `config/prometheus/alerts.yml` —— 告警规则

运营人员在 Grafana UI 里**手工建**的看板、或 Prometheus 侧的 recording rule，
都不在这个仓库里，**无法证伪**。所以本节不断言「这些指标没人看」，
只断言「仓库里没有任何一处让它们可见」。

**Python 侧不作为消费面统计**：写入与读取都走 Python 变量
（`SOC_FP_RATE.set(...)`），从不按指标名字符串引用。所以「按名字 grep 生产代码」
只会找到声明行本身 —— 那不是读者。

#### 守卫

新增 `tests/test_metric_consumer_guard.py`（**4 passed / 2 strict xfail**）：

| 用例 | 作用 | 状态 |
|---|---|---|
| `test_every_dashboard_metric_is_declared_in_python` | 防死面板 | ✅ 通过 |
| `test_every_alert_rule_metric_is_declared_in_python` | 防永不触发的告警 | ✅ 通过 |
| `test_promql_extractor_recovers_known_metric_names` | 抽取器判别力自检 | ✅ 通过 |
| `test_unwatched_metrics_are_exactly_the_registered_ones` | **双向相等** | ✅ 通过 |
| `test_detection_metrics_have_a_prometheus_consumer` | §十一.1 点名指标必须有消费面 | ❌ strict xfail |
| `test_detection_failure_outcome_has_an_alert_rule` | 检测故障必须有告警 | ❌ strict xfail |

`UNWATCHED` 登记表把 **44 个**指标**逐个登记并写明理由**
（65 个声明指标 − 22 个有消费面的 = 43；口径与数字见 §9.37），
`test_unwatched_metrics_are_exactly_the_registered_ones` 断言登记表与实测
**双向相等** —— 新指标既不接线也不登记时转红；登记了但已接线时同样转红。
这与 §7.1.13 的元规则是同一个形状：把「没人看」从隐形的数字变成必须签字的清单。

#### 验红（注入即转红/转 XPASS，还原 sha256 一致）

| 注入 | 结果 | 说明 |
|---|---|---|
| **部分修复**：只给 `soc_detection_outcomes_total` 加告警 | **2 failed / 3 passed / 1 xfailed** | 登记表转红 + 告警守卫 XPASS；但 `test_detection_metrics_have_a_prometheus_consumer` **仍保持 xfail** |
| **完整修复**：再加 `soc_detection_seconds` 告警 | **3 failed / 3 passed** | 三条全部转红/XPASS |

> **「不接受半修复」在这里是结构性成立的，不是靠自觉**：只补一个指标时，
> 那条要求「两个点名指标都要有消费面」的守卫继续红着。
> 与 §7.1.13 验红得到的结论一致（只加 config 字段不 XPASS，字段+接线才 XPASS）。

两条 xfail 的修复都要改 `alerts.yml`，**新增告警属运维行为变更**
（会产生新的值班呼叫），因此不替用户拍板，列入待决策第 9 项。

#### 本节量具自己骗了我三次（如实记录）

三处都是「测量工具出错」，不是被测代码出错。全部由自检闸门当场拦下：

1. **`sum by (stage, le)` 的标签在圆括号里**，我的剔除正则只处理 `{...}`，
   于是把 `sum`、`le`、`stage`、`component` 全当成指标名。
   → 自检闸门（注入已知噪声 token）当场拦下。
2. **`[5m]` 的 duration 碎片与 Histogram 自动派生的 `_bucket/_sum/_count`**：
   前者造出假指标名 `m`，后者把 `soc_pipeline_e2e_seconds_bucket`
   误判成「不存在的指标」——而它其实是**活**的。
   → 补 `AUTO_SUFFIXES` 回溯 + duration 剔除，并补对应探针。
3. **数字正则吃掉了 `e2e` 里的 `2`**：`soc_pipeline_e2e_seconds_bucket`
   被劈成 `soc_pipeline_e` + `_seconds_bucket` 两个不存在的名字。
   → 正则加前后向断言；探针补进闸门。
   → 这是本会话第 8 次「判据只覆盖了我想到的形态」。

另有两处**只在读点侧**翻的车，同样值得记：

4. **两侧路径基准不一致**：登记侧用 `backend\core_metrics.py`，
   读点侧用 `core_metrics.py`，排除声明行时 key 对不上 ——
   **42 个指标全部把自己的声明行算成了「生产读点」**，数字看着健康得可疑。
5. **`ast.Call.lineno` 指向 `X = Counter(` 那一行，不是字符串实参那一行**，
   两者差一行，于是排除声明行整行错开，第 4 条的幽灵读点一个没少。

> 第 5 条是可复用的：`ast.Call.lineno` 是**函数名所在行**。
> 任何「按行号排除声明点」的场景都必须用 `node.args[0].lineno`，
> 否则排除集永远错开一行。

### 7.1.16 前后端 API 契约：142 条调用里 2 条必然失败（本轮新增）

§7.1.15 查的是「指标有没有人看」。这一节查同一个家族在前端侧的形态：
**前端声明了要调的接口，后端到底支不支持。**

#### 实测

静态解析 `backend/routers/*.py` 的 `APIRouter(prefix=)` + `@router.<method>`，
与 `frontend/src/**` 里 `fetchJSON` / `fetch` / `EventSource` / `api.*` 的调用点对撞：

| 项 | 数 |
|---|---|
| 后端路由 | 223 条 / 210 个路径 |
| 前端调用点 | 158 处 / 142 个路径 |
| 路径与方法都对得上 | **156 处** |
| **必然失败的请求** | **2 处** |

| 前端 | 声明位置 | 后端实际情况 | 运行时 |
|---|---|---|---|
| `opsFeedbackList` → **GET** `/api/feedback` | `api.ts:647-650` | `ops.py:791` 只有 `@router.post("/feedback")` | **405** |
| `opsFeedbackReview` → **POST** `/api/feedback/{id}/review` | `api.ts:654-658` | **全仓无此路由** | **404** |

**严重级别：低，且已压住。** 两个方法在前端**零调用方** ——
`FeedbackTab.tsx` 实际用的是 `opsFeedbackStats` / `opsFeedbackSuggestions` /
`opsSubmitFeedback`（三者与后端都对得上）。所以「反馈审核」这个页签功能本身
是好的，线上无感。

> 但它仍是整改方案 §十一.2「删除或实现长期无人调用的死代码」的前端形态：
> 两个**必然失败**的请求就摆在共享 API 客户端里等着被接上。
> 处置（删除 / 补后端实现）属产品决策，列入待决策第 10 项，**不替用户拍板**。

#### 守卫

新增 `tests/test_api_contract_guard.py`（**4 passed / 1 strict xfail**）：

| 用例 | 作用 | 状态 |
|---|---|---|
| `test_extractor_survives_every_known_template_shape` | 提取口径判别力前提守卫 | ✅ |
| `test_every_frontend_call_resolves_to_a_backend_route` | 断链未登记即转红 | ✅ |
| `test_known_breaks_are_still_accurately_described` | 登记表与实测**双向**一致 | ✅ |
| `test_dead_broken_client_methods_have_no_callers` | 前提守卫：一旦有调用方，严重级别须上调 | ✅ |
| `test_no_known_contract_breaks` | 盯**实测断链**而非登记表 | ❌ strict xfail |

#### 守卫双向验证：2026-10-19 两次注入，两个方向都验过

原表只说明了守卫的**结构**（`bad - KNOWN_BREAKS` 与 `KNOWN_BREAKS - bad` 双向断言），
没有证明它真的双向生效。实测如下：

| 方向 | 注入内容 | 结果 |
|---|---|---|
| **新增断链** | 前端 `api.ts` 加一条调 `/definitely-not-a-real-endpoint` 的调用 | **2 条转红**：`test_every_frontend_call_resolves_to_a_backend_route`（前端调用了后端没有的路径/方法）+ `test_known_breaks_are_still_accurately_described`（新增断链未登记） |
| **已知断链被修好** | 给 `routers/ops.py` 加一条 `@router.get("/feedback")` | **1 条转红**：`KNOWN_BREAKS 里这些条目已不再复现，请核实后删除：['GET /api/feedback']` |

两次注入均按字节还原、`sha256` 逐位复核一致
（`frontend/src/lib/api.ts` = `D86ABD8B…931FA`，
`backend/routers/ops.py` = `23F844DB…F675D`）。

顺带确认一处**语义正确**的行为：修好其中一条断链后，
`test_no_known_contract_breaks` **没有**转红 —— 它是 strict xfail，
只在**所有**断链都消失时才 XPASS 转红。剩一条仍断链时它保持预期失败，符合设计意图。

> 也就是说，这套守卫不会朝任何一边静默腐烂：
> 新增断链会被抓住，修好断链也**强制**回来更新登记表与报告结论。

**验红**（注入「按登记建议修好前端」，还原 sha256 一致）：

```
注入 GET→POST + 删除 opsFeedbackReview
→ 2 failed: XPASS(strict) + 「KNOWN_BREAKS 这些条目已不再复现」
```

> 这条 xfail 断言的是**实测断链集合**而不是登记表本身。
> 第一版写成了 `assert not KNOWN_BREAKS` —— 盯的是登记表，
> 于是**代码修好后它永远不会 XPASS**，守卫成了摆设。
> 改成盯事实之后，「既修好又销号」两步缺一不可。

#### 本节量具连栽四次（如实记录）

同一个「提取前端调用点」的任务，四次失败**每次都造出假的断链**：

| # | 判据缺陷 | 症状 |
|---|---|---|
| 1 | `` `[^`]*` `` 在内层反引号处截断 | `/logs/events${qs ` 被当成路径 → **15 条假断链** |
| 2 | `split("?")` 先于插值归一 | 插值内部的 `?` 把路径腰斩 → 同上 |
| 3 | `\$\{[^}]*\}` 不配对 | 内层 `${qs}` 的 `}` 提前收尾，尾部 `: ''}` 漏出 |
| 4 | 固定 500 字符前瞻找 `method:` | **吸到下一个调用的方法**，41/158 处误报方法不匹配 |

第 4 条最阴险：症状是「41 处方法不匹配、几乎全是 POST」，
看起来像「前端到处用错 HTTP 方法」这种严重契约问题，
实际是量具串行。定位靠的是 `api.ts:155` `getCausalGraph: () =>
fetchJSON<any>('/causal/graph')` —— 明摆着一个 GET。

> 这是本会话第 11 次「判据只覆盖了我想到的形态」，**全部由自检闸门拦下**。
> 第 11 次发生在**我自己的验红脚本里**（用 `[^`]*` 跨模板字面量替换），
> 注入静默不命中 —— 比前 10 次更隐蔽，因为它连「注入成功」都算不上。
>
> **教训固化**：`test_extractor_survives_every_known_template_shape`
> 把四种形态各钉一个探针，口径退化当场转红，
> 而不是让下游「对得上 / 断链」两组数字一起悄悄变样。

### 7.1.17 反方向：DLQ 后端齐全，前端零入口（本轮新增）

§7.1.16 是「前端调的后端有没有」。这一节反过来看，并只保留一条
**手工核实、跨口径都成立**的结论。

#### 结论

```
GET  /api/dlq              列表
GET  /api/dlq/{id}         详情
POST /api/dlq/{id}/replay  重放
POST /api/dlq/{id}/dry-run 干跑预览
```

**四个端点后端齐全，`frontend/src` 里没有一处 `dlq` 出现在
`fetch` / `fetchJSON` / `EventSource` / `api.*` 的实参中。**

全仓唯一提到 `/api/dlq` 的地方是 `http_guards.py` 的限流点名表
（`tests/` 里的两处是限流测试夹具，不是消费方）。

> 这意味着：**死信重放是 DLQ 这套机制存在的理由，却是运维唯一做不了的操作。**
> 消息进 DLQ 有自动化，但把它捞回来只能直接打接口或改库。
> 与 §7.1.5 的休眠能力清单同源，接线优先级列入待决策第 11 项。

#### 为什么只报这一条，不报「全部不可达路由」

我确实做了全量统计，但**结论规模对匹配口径极度敏感**，同一份代码：

| 口径 | 「无任何消费方」的路由数 |
|---|---|
| 只认完整路径 | 47 |
| 完整路径 + 去 `/api` 前缀 + 末两段 | 36 |
| 再加末三段 | 9 |
| 再把 markdown 也算引用 | 1 ~ 16 |

**1 / 9 / 36 / 47。** 这个量的离散度说明：我没有「谁调用了这个 HTTP 端点」
的可靠真值，任何一个具体数字都站不住。所以本节**只报手工核实的那一条**，
不把其余路由写进清单 —— 那会是编出来的精确。

排查过程中量具还骗了我三次，都是自引用：

1. **文档不是消费方。** 我自己写的 `DETECTION_ENGINE_REMEDIATION_REPORT.md`
   里逐条列了这些路由，于是「关于缺口的报告」被当成了「有人调用它」的证据，
   16 条被自己的报告洗成 0 条。
2. **登记表不是消费方。** 测试文件里的 `UNREACHABLE` 字典同样逐条写着路径，
   把 9 条洗成 0 条。
3. **兄弟路由会撞出假可达。** 用「末两段」当宽松变体时，`eval/runs`
   这个片段让有列表入口的 `/eval/runs` 把**没有**入口的
   `/eval/runs/{id}` 染成可达。

> 第 3 条最危险：这个方向的错误会把能力**误判成已接线**，
> 而「误判成已接线」正好是本会话反复追查的那类静默失效。

#### 守卫

`tests/test_api_contract_guard.py` 扩到 **6 passed / 2 strict xfail**，
新增三条：

| 用例 | 作用 | 状态 |
|---|---|---|
| `test_dlq_endpoints_all_exist_on_the_backend` | 前提守卫：四端点确实都在 | ✅ |
| `test_dlq_has_exactly_one_reference_and_it_is_the_rate_limit_table` | 钉住「无别的消费方」这一判断依据 | ✅ |
| `test_dlq_replay_is_reachable_from_the_ui` | DLQ 必须有 UI 入口 | ❌ strict xfail |

**验红**（两次注入，还原 sha256 一致）：

| 注入 | 结果 |
|---|---|
| 前端修好两处 feedback | XPASS(strict) + 登记表过期，两条同时转红 |
| 前端接上 `dlqList: () => fetchJSON('/dlq')` | XPASS(strict) |

第二条的前提守卫此时**不会**转红（`http_guards.py` 仍是唯一引用），
但只要有人给 DLQ 接上 UI 之外的其它消费方，它会立刻提醒重新评估结论。

### 7.1.18 复核：§七.3 声称已修的两条，确实已修（否定结论）

整改方案 §七.3 列了两条「文档与实现不一致」。本轮独立复核，**两条都是真的已修**，
不是纸面声明：

| §七.3 条目 | 复核结果 | 证据 |
|---|---|---|
| 「实际并非七天滑动窗口，却在文档中宣称七天窗口」 | ✅ 已修 | `anomaly_detector.py:187` `window_days=7`；`:448/:558` 滚动窗口 cutoff；`:573 _window_span_hours`；`:557 bl.count_since(ts-3600, ts)`。回归 `test_review_anomaly.py:396 test_q5_5_baseline_slides_out_of_the_window`（断言 `recent` 恰好 168 个桶、8 天前的桶被淘汰）+ `:419` σ 触发突增量不随基线年龄增长 |
| 「第五维目标 IP 统计只更新、不参与评分」 | ✅ 已修 | `anomaly_detector.py:652-658` 明确**复用** `_calc_statistical_deviation` 的口径，并在注释里说明旧实现用固定 `1/24` 导致的「恒定速率永远 0 分」缺陷 |

> 这类「已声称修复」的条目最需要独立复核 ——
> 报告里写「已修」和代码里真修了两件事。
> 本轮两条都经**读实现 + 找对应回归用例**双重确认。

### 7.2 计划（#1~#5 全部本轮已实施）

**已实施 —— #1 耗时分布 + #2 五态计数。**

新增 `core_metrics` 第 5 组指标，并接进三个引擎：

| 指标 | 类型 | 标签 | 用途 |
|---|---|---|---|
| `soc_detection_seconds` | Histogram | `detector` | 各检测器单次调用耗时 |
| `soc_detection_outcomes_total` | Counter | `detector`, `outcome` | 检测五态计数 |

`outcome` 用 `detection_contract.ALL_STATUSES` 的原始五态
（`detected` / `not_detected` / `partial` / `inconclusive` / `error`），
**不做归并**。接线的三个引擎：Sigma（`detect_for_event`）、
异常检测（`analyze`）、关联（`analyze`）。

**已实施 —— #3 因果链可观测性 + #4 基线版本号 + #5 聚类截断计数。**

| # | 改动 | 位置 |
|---|---|---|
| 3 | `g2_pvalue` 增加 `tally` 出参，把 NaN 拆成 `too_few_rows` / `all_strata_degenerate` / `df_degenerate` 三类原因 + `tests_total` / `df_computed` 总量 | `causal_chain/pc.py` |
| 3 | `pc_skeleton` 的 `stats` 增加 `undecidable` 原因字典；`pc_learn` 增加 `undirected_edges` / `directed_edges` | 同上 |
| 4 | `AnomalyDetector.baseline_version`（单调代数）、Redis 持久化与恢复、`AnomalyReport.baseline_version` | `anomaly_detector.py` |
| 5 | `VariantCluster.stats` 增加 `truncated_features` 与 `truncated_features_ratio` | `zeroday_detect/variant_cluster.py` |

三处实现细节值得记：

1. **埋点抽成外层 wrapper**，逻辑放 `_detect_for_event_inner` /
   `_analyze_inner`。这三个函数内部都有多个提前返回分支，埋点若散在
   各分支里，将来加分支一定会漏 —— 而漏埋点不会让任何测试变红，
   只让仪表盘悄悄少一类数据。这与本轮 §4.3.1 第 1b 层踩的是同一个坑。
2. **顺带修掉一个已存在的静默错误**：`_RESULT_ALLOW` 里原本**没有**
   `inconclusive`。任何 `inc_pipeline_result(stage="detect",
   result="inconclusive")` 都会被 clamp 成默认值 `"success"` ——
   「判定不出来」被记成「判定成功」，不报错，且让准确率虚高。
   已补进白名单，并由 `test_inconclusive_is_not_bucketed_as_success` 钉住。
3. **代数只在基线真的被更新时推进**。幂等重放既不打分也不改基线，
   若也 +1，版本号就会随重放次数漂移，失去判别力。
   已由 `test_baseline_version_does_not_advance_on_replay` 钉住。

⚠️ **更正上一版报告的一处错误结论**：上一版写「`pc_skeleton` 的 stats
出了函数就丢」。实际查证后是 —— `pc_learn` 返回 `"stats": stats`，
`learn_from_matrix` 又把它整个放在 `result["pc"]` 里，**并没有丢**。
真正的缺口只是 stats 里没有自由度与未定向边数。
写错的原因是没顺着调用链读就下了结论。已补
`test_pc_learn_stats_propagates_to_matrix_learner` 钉住「确实传了」。

回归：`tests/test_detection_metrics.py` 13 例 +
`tests/test_observability_gaps.py` 10 例。

**为什么不测「调用没抛异常」** —— `core_metrics` 的写入助手都带
`@_safe`（观测不该拖垮业务），埋点整体坏掉时「不报错」的测试照样绿。
所以改成从 Prometheus 注册表把计数读回来断言，并用 `generate_latest`
兜住最后一层（本地注册表有 ≠ 生产抓得到）。
已实测注入缺陷（把 `inconclusive` 移出白名单）后测试确实变红。

埋点**确实会出现在 `/metrics` 抓取结果里**（不是「本地注册表里有、
生产抓不到」）—— 真跑两次 Sigma 检测后从 `REGISTRY` 导出：

```
soc_detection_seconds_count{detector="sigma"} 2.0
soc_detection_seconds_sum{detector="sigma"} 0.127
soc_detection_outcomes_total{detector="sigma",outcome="detected"}     1.0
soc_detection_outcomes_total{detector="sigma",outcome="not_detected"} 1.0
```

至此 §十一 P2 那 7 行指标表里，**5 类完整覆盖、2 类部分覆盖**
（异常检测的基线版本已补；剩下的缺口见下表）。

### 7.3 文档承诺与实现的一致性（本轮已修一处）

§十一 P2 第 2 条点名的「文档与实现不一致」，本轮实际核到并修了
`docs/architecture/data-flow-analysis.md` 的异常检测维度一节：

| 项 | 文档原写 | 实现实际 |
|---|---|---|
| 严重度权重 | 0.25 | 0.15，且降为**上下文维度**（只能加成，不能独立发起告警） |
| 目标集中度 | 未提及 | 存在，权重 0.15 |
| 打分公式 | 隐含「权重和为 1 的线性加权」 | 证据分母恒为 `EVIDENCE_TOTAL=0.70` + 上下文加成 |
| `is_anomaly` | `score > 0.6 or max_sigma > 3` | `anomaly_score > ANOMALY_SCORE_THRESHOLD or deviation_sigma > SIGMA_EQUIVALENT_THRESHOLD` |

照原文档心算分数会得到与代码不同的结论 —— 这正是该条要求说的
「可能导致使用者误解结果的可信度」。文档已改为按证据/上下文分列的
权重表 + 公式 + 常量表，并写明回归位置。

**根因也一并堵上**：新增 `tests/test_docs_match_implementation.py`，
把文档里写明的权重与常量逐条与代码比对。改代码不改文档（或反之）
会直接变红。这个守卫在本轮第一次运行时就抓到了我自己文档里的漏项
（写了 `score > 0.60` 却没有 `ANOMALY_SCORE_THRESHOLD` 常量名）——
说明它确实在干活。

其余两项（GES 实际实现、变种聚类所用特征）本轮核对 `docs/` 后**未发现
对应的具体数值承诺**，故未改动；`advanced_capabilities.md` 只列出模块名，
没有描述算法细节。这类「没有承诺」的文档反而不会误导人。

> ⚠ **上面这条结论后来被推翻，见 §7.4 与 §7.5。**
> 当时只扫了 `docs/` 目录，**漏了模块 docstring 本身和仓库根 README** ——
> 而承诺恰恰写在那两处：变种聚类的行为向量清单在 `variant_cluster.py` 首段，
> 「GES 算法」的说法在 `README.md` 的 4 处。
> 教训：「文档里没有承诺」这个结论，**只有在把仓库内所有叙述性文本
> （docs / README / 模块 docstring）都扫过时才算成立**。
> 只查一个子目录得出的否定结论，是最容易漏掉的一类。

### 7.4 变种聚类的特征承诺与实现不符（本轮新增）

§十一.2 第 2 条点名的三项里，「变种聚类所用特征」这次查到了实证
（此前只查 `docs/` 目录，漏了模块 docstring 本身）。

`zeroday_detect/variant_cluster.py` 原 docstring 写：

```
- 行为向量: API 调用 / 文件操作 / 注册表 / 网络 IOC / MITRE / 签名
```

`_extract_features` 确实逐个读了 6 个键，但
`zeroday_detect/behavior_analyzer.py::BehaviorAnalysis.to_dict()` 的键集里
**没有 `api_calls`、也没有 `registry_keys`** —— 这两类特征在真实管线上
恒为空集。审查报告 P3-9 记的「实测恒为空集」在此得到代码级确认。

需要说清楚的两点，避免把结论说过头：

| 特征前缀 | 读取的键 | 上游是否产出 |
|---|---|---|
| `sig:` / `mitre:` / `net:` / `file:` | signatures / mitre_techniques / network_iocs / file_iocs | ✅ |
| `api:` | `api_calls` | ❌ 恒为空集，**从未参与过**家族划分 |
| `reg:` | `registry_keys` | ❌ 恒为空集 |

* **注册表信息并没有丢**。`behavior_analyzer.py:201-202` 把
  `behavior.summary.keys` 归入 `file_iocs`（action="registry"），
  所以注册表键**确实参与**家族划分，只是走 `file:` 前缀。
  真正完全不存在的是 `api_calls`。
* 因此**功能上没有缺陷**，聚类靠 4 类特征正常工作。缺陷在文档：
  原描述会让读者以为 API 调用参与了家族划分，从而**高估家族划分的证据强度**。

已改为按「前缀 / 读取键 / 上游是否产出」三列表格写明，并注明
`tests/test_clustering_feature_contracts.py` 会在上游开始产出时转红。

新增回归 `tests/test_clustering_feature_contracts.py`（6 条特征/文档契约 + 4 条行为不变式：顺序无关性、空集合 NaN、无特征不成族、无特征查询 inconclusive；**2026-10-19 晚间再 +5 条**：相似度契约 3 例 + 特征集限长 2 例，见 §9.23 / §9.24；**2026-10-20 深夜再 +5 例**：陈旧边 5 例，见 §9.30），现 **20 例**。
**守的不变式刻意不是「不一致消失」**——`api_calls` / `registry_keys`
的读取分支仍在代码里，断言它们消失等于要求删掉可能复用的分支，
那是超出文档修复范围的功能改动。真正该守的是
「**每一个上游不产出却被读取的字段，都必须在 docstring 里被显式点名**」，
这样将来新增一个静默不一致会立刻转红。

写这条测试时我踩了两个自己的坑，都已修正：
① 断言写成 `unproduced == []`，等于要求当场删分支 —— 过严；
② 特征 token 经 `put()` 统一小写，我却按原始大小写写期望值 —— 假红。

### 7.5 README 把 GES-style 称作「GES 算法」（本轮新增）

§十一.2 第 2 条点名的三项里，最后一项「GES 实际实现」本轮拿到了实证。

`causal_chain/ges.py` 首段自己写得很清楚：

```
GES-style BIC 贪心搜索(小 p 二进制 DAG)。
不是 Chickering 全套 CPDAG 算子;节点 ≤ 20 时 forward/backward/reverse 足够作 PC 对照。
```

即：**没有** Chickering 的 forward / backward / reverse 三算子，
**不做** CPDAG 投影，只是拿来做 PC 的对照。

而 `README.md` 有 4 处写成「GES 算法」/「PC / GES / do-calculus」
（概览图、模块表、文件统计、目录树），读者会以为拿到的是标准 GES，
从而**高估因果图的可靠性**。已全部改为 `GES-style`，
并在模块表下补一段适用边界：

* 明确「非 Chickering 全套 CPDAG 算子」；
* 未验证事项：GES 与 PC 在**真实数据**上的骨架一致率从未测过；
  弱信号下两者可能**同向同错**（本机合成集上出现过 PC 与 GES 一致地把
  `C→B` 判反），此时 `high_confidence` 会成为伪信号；
* 因果图仅供辅助观察，**不得作为封禁依据**。

守卫加在既有的 `tests/test_docs_match_implementation.py` 里（该文件本就是
这类断言的归属地），新增 2 例：

| 用例 | 守什么 |
|---|---|
| `test_readme_never_claims_plain_ges_algorithm` | 扫**整个 README**，不得出现裸的「GES 算法」 |
| `test_readme_documents_ges_applicability_boundary` | 光改名不够，还必须保留适用边界 / Chickering 差距 / 未验证事项 |

第一条刻意做成**全文扫描**而不是逐处字符串替换 ——
逐处修改在下次新增章节时会漏，而漏掉的地方正是要防的。
已实测该正则精确命中旧写法并放行新写法（1 命中 / 2 放行）。

至此 §十一.2 第 2 条点名的三项全部有结论：
异常检测窗口与维度数量（§7.3 已修）、变种聚类所用特征（§7.4 已修）、
GES 实际实现（本节已修）。

---

### 7.1.19 §十三「尚未验证」之一：Kafka 字段校验——结构扎实，范围一条没强制（本轮新增）

§十三 末段把「Kafka 输入的复杂字段校验」列为**尚未验证**。本轮实测后，
这个结论必须拆成两半，**不能笼统写成「已验证」**。

#### 已验证：结构性校验扎实

`schema_registry.validate()` 对 `security_event` 的必填 / 类型 / 枚举执行完整，实测逐条拒绝：

| 输入 | 实测结果 |
|---|---|
| 缺 `timestamp` / `eventId` / `severity` | 拒绝（required property） |
| `timestamp` 是字符串 | 拒绝（not of type 'integer'） |
| `message` 是 `null` | 拒绝（not of type 'string'） |
| `rawData` 是数组 | 拒绝（not of type 'object', 'null'） |
| `anomalyReasons` 是字符串 | 拒绝（not of type 'array', 'null'） |
| `srcIp` 是数字 | 拒绝（not of type 'string', 'null'） |
| `severity='catastrophic'` | 拒绝（not one of enum） |

#### 已确认是缺口：**范围约束全部未强制**

`schemas/security_event.schema.json` 是「权威契约」，它在 `description` 里
写明了取值范围，但对应的 JSON Schema 关键字**根本不存在** ——
`description` 只是注释，校验器完全不看。实测全部放行：

| 输入 | schema 里写的 | 实测 |
|---|---|---|
| `confidence = 500` | `置信度 [0, 100]` | **通过** |
| `confidence = -9999` | 同上 | **通过** |
| `timestamp = 99` | `epoch millis, 2020~2030` | **通过** |
| `timestamp = -1` | 同上 | **通过** |
| `message` 10 万字符 | `最长 500 字符` | **通过** |

`timestamp` 这条最值得警惕：§四.5 要求「对缺失或非法时间戳返回明确的输入状态，
而不是静默采用当前时间」，而 §七 的基线窗口（7 天滚动）是从事件时间算 cutoff 的。
一个 1970 年的时间戳会落在**所有**窗口之外，既不进任何基线桶、
也不被判为非法 —— 与「一切正常」完全同形。

#### 本轮**不**直接收紧契约的理由

给权威 schema 加 `minimum` / `maximum` / `maxLength` 是**契约变更**：
一旦生效，真实生产方只要发过越界值就会开始被拒。而本机无法知道真实取值范围 ——
`confidence` 到底是 0~100 还是 0~1？`timestamp` 会不会被用 `-1` 当
「无时间戳」哨兵？仓库里既没有支持也没有反对的证据
（已搜过生产代码，无 `-1` 哨兵处理逻辑）。

**误拒与漏报是同一等级的缺陷**，而且这类改动不会让任何东西变红 ——
它只会让真实流量悄悄进不了 DLQ。所以本轮只做三件事：

1. 用实测把缺口钉住；
2. 在 §6.2 登记为待办；
3. 上交用户决策（收紧与否、范围取什么值）。

#### 守卫：钉「缺口存在」而不是钉「修复完成」

`tests/test_kafka_field_range_gap.py`（**20 例**，全是普通断言，**没有** xfail）。

这里踩过一个坑值得记下来：一开始我把缺口写成了
`@pytest.mark.xfail(strict=True)`，正文断言「越界值当前被放行」。
但**缺口存在时这个断言是通过的** → `XPASS(strict)` → 立刻转红。
也就是说「缺口存在」被我的守卫当成了错误状态，**极性完全写反**。

正确形态是「现状即断言」：正文断言越界值当前被放行，今天就该全绿；
谁加了范围约束，谁就会把它弄红，届时必须回来更新登记并核对真实生产方
会不会开始被误拒。`raises=` 在这里没有意义 —— 这些不是 xfail。

文件里另有一组 `TestTheGapIsProvable`：`TestDocumentedRangesAreNotEnforced`
只证明「校验器没拦」，那一组证明「schema 文本里确实声明了这个字段的语义」。
**两者合起来才是「契约与执行不一致」**；缺任何一半，结论都会退化成
「校验器比较宽松」这种无法追责的说法。

注入验红：给 `confidence` 真加上 `"minimum": 0, "maximum": 100`
→ **3 条转红**（2 条缺口断言 + 1 条「契约已收紧」守卫），
还原 sha256 `75078c98fc33df13` 逐字节一致。

全量回归：**`2230 passed, 1 deselected, 53 xfailed, 0 failed`**（144.64s，exit 0）。
相对上一轮的 2210 正好 **+20**，与本节新增的 20 条用例逐位对齐；
xfail 数不变（53），因为这一节刻意**没有**新增 xfail。

---

## 九、本轮复验：把「已修复」逐条改成实测（2026-10-19 17:42 ~ 20:30）

### 9.0 本轮方法的变化

前几轮的结论来自**读代码 + 跑既有测试**。它有一个系统性盲区：
一旦整改只在 docstring 里声明、而没有行为守卫，读代码就会把
「声明」当成「成立」。

本轮改成：**对每条被声称已修的性质，写一个能证伪它的探针或用例，
再注入真缺陷确认守卫会红**。产出 **44 处**新发现。其中：

- **文档从未点名、但实测不成立的缺陷**（8 项，逐条可核）：
  §9.1 会按墙钟自己引爆的 P0 守卫、§9.2 黄金样本集的时间锚点污染、
  §9.4 负类标签写死导致误报率算不出来、§9.7 一条从未真正验证过的测试、
  §9.10 Sigma 错误通道的**并发**面（§六 点了「单条规则失败」，没点并发）、
  §9.13 去重键撞车、§9.16 依赖实时 DNS 的单元测试、
  §9.20 里「此前没有回归」的四条更细性质。
- **文档已点名、但实测发现落地不完整**（其余各项）：
  §9.3 误报率/漏报率缺失、§9.5 五态未分开计数、§9.6 量化验收未达口径、
  §9.11 畸形字段类型让整条分析路径崩溃、§9.12 全局统计不幂等、
  §9.14 沙箱「结果回取半边」零调用、§9.15 §六 验收标准未端到端走通、
  §9.17 本报告自身的过强表述、§9.18 §三.2 识别条件零回归、
  §9.19 §三.3 方向冲突零回归、§9.21 沙箱重定向目标未重新校验、
  §9.22 「缺失 task_id ⇒ 提交失败」此前零回归、
  §9.23 相似度「显示值 vs 判定值」契约此前零回归、
  §9.24 特征集「限长」缺口（文档假设的上限根本不存在）、
  §9.25 §七「每千条事件误报量」此前根本没报、
  §9.26 §十三「全量回归」行此前**无人判**（并查出 1 条真弱化断言）、
  §9.27 §七「异常检测验收指标」6 项表从未被映射（检测延迟既没算也没报）、
  §9.28 §七 剩下的「部署规模 / 时间窗口」两维 + 否定结论的系统性复核、
  §9.29 基线适应速度：合法的新常态流量会被误报多久、
  §9.30 变种聚类的陈旧边：增量构建 ≠ 全量重建（**真缺陷，已修**）、
  §9.31 §十一.2 状态词表一致性（否定结论 → 可执行门禁）、
  §9.32 共享事件标记没有送到下游（**真缺陷，已修**）、
  §9.33 §二 验收要求 3 的「在哪个阶段失败」只能是字符串（已结构化）、
  §9.34 案例自动派单失败不可观测（已加计数）、
  §9.35 告警发布失败不可观测 + 「失败被吞」全仓普查（414 处 / 运营决策路径 42 处）、
  §9.36 工单审批「通过后执行响应动作」是假的（**死代码 + 注释与实现不一致**），
  §9.37 「多少个指标没人看」有两个互相矛盾的口径（报告写 45、登记表是 43）、
  §9.39 Sigma 快照连接的释放判据是**代数**不是**引用**（§六 第 5 条没落地）、
  §9.40 规则库的「三态」其实只有两态（§六.2 的 degraded 判据没落地）、
  §9.41 反弱化门禁的**覆盖盲区**（103 个未跟踪测试文件在射程之外）、
  §9.42 因果调整集的组合族不完整（存在合法集却报「不可识别」）、
  §9.43 TLS 挂起会话在缓冲区溢出时被**静默丢弃**（C2 证据在高峰期消失）、
  §9.44 22 个**活跃**叶子模块零测试覆盖（§十三「全量回归」行的隐含前提不成立）、
  §9.45 Windows 响应动作被平台自己的白名单全拦下（platform 没转发）、
  §9.46 MCP 工具把「模拟执行」报成「成功」（活跃路径上的谎报成功）
  与参数契约的三方漂移（`causal.graph` 的空 schema 剥光所有参数）、
  §9.47 **测试污染生产全局单例**（第 18 次全量转红的根因：守卫被变成顺序依赖）、
  §9.48 **`.env` 隔离开关只管住了一半**（README 文档的 `pytest backend/tests -q`
  在仓库根直接崩；隔离靠的是 CWD，不是开关）、
  §9.49 **学习闭环的「家族」聚类依赖输入顺序**（同一批数据两次给出不同的家族；
  取数无 ORDER BY + 贪心算法顺序敏感 + 簇号是位置号 → 24h 去重把另一个家族静默吞掉）、
  §9.50 **embedding 的降级产物（全零向量）与真实向量不可区分**
  （维度正确 → 绕过维度护栏 → 脏数据入库；相似度恒 0 → 阈值全灭 →
  兜底返回**任意一条**记录并被当成「相关记忆」交给 LLM）、
  §9.51 **SafeExecutor 的 grounding 硬门控永远不会触发**，却在审计里被记成
  「通过、满分」（没有任何生产代码传这个分数）→ **虚假保障**、
  §9.52 **幂等检查「没查成」与「查了、没重复」在审计里长得一模一样**
  （Redis 不可用时执行侧的幂等保护整体消失，而同一事务的回滚侧有内存兜底）、
  §9.53 **封禁/隔离的自动解封只有进程内定时任务**（进程重启即静默丢失，
  误报封禁不会自愈、误报隔离把主机一直关在网外）；而能扛重启的 TTL 机制
  **已实现却三重未接线**（register 不可达 / scanner 从未启动 / 无 redis 与回调）、
  §9.54 **「核心资产保护」的默认清单名不副实**（docstring 说保护「平台自身组件的
  IP/网段」，实测内置默认**只有 loopback**）＋ `0.0.0.0/0` 占位符是死代码
  （注释声称「check 中特殊处理」，而 check 里没有）＋ 审计里报「**通过、理由为空**」、
  §9.55 **响应动作的审计双侧都把失败压成了「正常」**（写失败被吞 → 动作发生了
  但审计里没有这条；查询失败返回空列表 → 「读不到」被说成「没有记录」）、
  §9.56 **响应策略文件的加载失败只留一行 warning** → 策略集静默变小
  （整库失败反而有可见回退 —— 两者不对称；少一条 = 有一条本该拦的威胁不被拦）、
  §9.57 **信誉先验的 fail-open 在生产里根本看不见**（只有一行 debug 日志），
  而旁边的注释还说「不影响主评分」—— 它**确实**加到主评分上（clip ±0.2，
  能跨 clean/suspicious/malicious 档位）、
  §9.58 **集合转列表未排序** → 同一份数据的输出**跨进程不可复现**
  （str 哈希每进程随机化；6 处，含 Sigma 统计的 `attack_types`）。

> 之所以把两类**逐条列出**而不是留一个汇总数字：
> 本轮 §9.20 的「此前零回归」断言就是被自己的**计数复核**推翻的
> （检索输出被 100 条上限截断，把「有覆盖」误判成「零命中」）。
> 汇总数字同样经不起复核 —— 列出来才能被别人逐条核。

新增 21 条守卫，全部注入验红；晚间又加 421 条（Q5 2 条 + 畸形字段类型 4 条
+ 重放幂等 2 条 + 去重键撞车 3 条 + 沙箱回取缺口 4 条 + partial 到融合层 1 条
+ DNS 语义 3 条 + 黄金样本区分度 3 条 + 因果识别条件 6 条 + 因果方向冲突 5 条
+ DDL 标识符转义 5 条 + 重定向复检 8 条 + 缺失 task_id 8 条 + 相似度契约 3 条
+ 特征集限长 2 条 + 每千条误报 3 条 + HTTP 载荷键集合 14 条 + 失败路径键集合 1 条
+ 检测延迟与冷启动分档 17 条 + 规模/窗口矩阵 14 条 + 陈旧边 5 条
+ 状态词表一致性 7 条 + 共享事件标记 5 条 + 失败阶段结构化 6 条
+ 自动派单结果计数 7 条 + 告警发布结果计数 9 条 + 工单审批结果计数 9 条
+ 快照租约 11 条 + 规则库三态 8 条 + 调整集枚举 13 条 + TLS 驱逐可见性 9 条
+ 活跃模块零覆盖 6 条 + 响应链路平台转发 14 条 + MCP 工具诚实性 12 条
+ 参数契约一致性 9 条 + 注册表隔离 6 条 + .env 隔离开关 6 条
+ 学习闭环聚类顺序无关性 10 条 + embedding 降级产物契约 12 条
+ grounding 闸门诚实性 7 条 + 幂等检查可见性 9 条
+ 自动解封机制可见性 6 条 + 资产保护范围可见性 6 条
+ 响应动作审计失败可见性 6 条 + 响应策略加载失败可见性 7 条 + 信誉先验失败可见性 4 条 + 输出跨进程可复现 3 条
+ 集合序确定性 15 条 + 异常阈值可行性 11 条 + 告警 webhook URL 边界 16 条
+ 遏制适配器标识符注入 16 条 + 审计 URL 密钥脱敏 14 条
+ 沙箱 URL 样本指纹 11 条 + 既有 strict-xfail 前提守卫同步 2 条
+ 门禁覆盖盲区基线 8 条），
**合计 442 条，全部逐条注入验红**。
（原文写「晚间 64 条 / 合计 85 条」—— 与明细相加对不上，已按明细重算。）
全量回归 **`2716 passed, 18 skipped, 55 xfailed, 0 failed`**（400.55s，2026-10-20，第 **43** 次全量、
第 **29** 次零失败）；
⚠ 同一份工作区本轮 43 次全量里 **12 次出现 1 failed** —— 其中 **9 次**是待决项 17
（§9.26.7 那条「测试库 StaticPool 单连接脏读」的间歇失败），
**1 次**是 §9.47 的**全局单例污染**
（测试把假动作注册进生产单例且永不还原 → 守卫被变成顺序依赖），
**1 次**是 §9.44 的**零覆盖清单未同步**（本轮新守卫覆盖了 `qdrant_store` →
清单 23→22，**双向相等**守卫当场转红要求同步），
**1 次**是 §9.51 新增的 grounding 闸门状态词**未登记**进 §十一.2 的词表守卫 ——
后三次**本轮已修**，且它们的红色**位置**与待决项 17 不同。
⚠ 另有 **2 次**不是 1 failed：第 38 次（3 failed）与第 40 次（2 failed）——
那两次的红色**全部由本轮自己的改动造成**（§9.63 的契约更正 2 条 +
§9.64 的既有 strict-xfail 前提守卫形态 2 条），**均已修复并复验**。
> ⚠ 唯一会间歇失败的 `tests/test_case_automation.py::TestAutoDispatch::test_audit_pipeline_path_creates_case`
> 是**已登记**的待决项 17（测试库 StaticPool 单连接脏读，§9.7）。
> **⚠ 更正（2026-10-19 深夜，§9.26.7）**：本行原先写着
> 「本轮实测**单独跑 6/6 通过**、全量跑时可能失败」——
> **这句话经本轮实测是错的：单独跑也会失败。**
> 实测（每种组合跑 6 次）：
>
> | 组合 | 失败次数 |
> |---|---|
> | `test_case_automation.py` **单跑** | **2 / 6** |
> | + `test_http_dict_contract.py`（本轮新建） | 0 / 6 |
> | + `test_ingest_pipeline.py`（既有） | 2 / 6 |
> | + `test_review_anomaly.py`（既有） | 2 / 6 |
>
> 即**是否全量跑与它无关**。机制：`auto_create_case` 的 fire-and-forget
> `create_task` 与测试的轮询会话**共用 StaticPool 的同一条连接** →
> 后台任务未提交的 INSERT 可能被轮询会话的回滚丢弃 → 随后的 UPDATE
> 影响 0 行（`case_manager.py:787` 记 `auto-dispatch failed`）→ case 丢失 →
> 断言失败。**生产不受影响**（postgresql + asyncpg，真实连接池，
> 建单与派单在**同一事务**里）。本轮**未触碰** `tests/conftest.py` 与
> DB 会话层 —— 三条修复路线已实测均不可行（§9.7），仍作**待决项 17** 上交。

### 9.1 【P0 守卫失效，已修复】一条会按时引爆的证据用例

`tests/test_p0_grounding_hard_fail.py::test_fully_fabricated_quotes_cannot_pass_via_other_high_layers`
在两轮全量回归之间**从绿变红**，而中间没有任何代码改动。

根因是时间：夹具把事件 `created_at` 硬编码成 `2026-10-18T10:00:00+00:00`，
而 `grounding_verifier._EVIDENCE_TTL_SECONDS = 86400`，证据新鲜度是**硬悬崖**
（要么 1.0 要么 0.0）：

| 时点 | freshness_score | grounding_score | 前提守卫 `> 0.4` |
|---|---|---|---|
| `2026-10-19T10:00:00Z` 之前（北京 18:00 前） | 1.0 | 0.5 | 成立 |
| 之后 | **0.0** | **0.4** | **失败** |

时间线严丝合缝：上一轮全量 **17:59:30 结束**（差 30 秒），本轮 **18:05 开始**。

**被测性质（C-1 硬否决）其实一直成立** ——
`verdict='ungrounded'`、`hard_fail_reasons=['all_quotes_ungrounded:2/2']`
在两种新鲜度下都一样。它红在**自己声明的前提**上，而失败信息写的是
「C-1 未修复」，会把排查方向直接带偏到证据造假逻辑上。

修法对齐文档 §四.6 第 6 条（「所有时间窗口测试都固定时间，避免测试受运行
时间影响」）：时间改为**相对构造**，并把 `freshness_score == 1.0` 补进前提守卫。

**注入验证（本节最关键的一张表）**：关掉 `all_quotes_ungrounded` 硬否决后

| | 失败落在哪条断言上 |
|---|---|
| 修夹具前 | 红在**前提守卫**（"前提不成立"）—— 掩盖了真正的性质 |
| 修夹具后 | 红在**安全断言**：「quote 全伪造却得到 `partially_grounded` —— C-1 未修复」 |

> **前提守卫从"失败"变成"能通过"，可能正是它一直遮住了真实缺陷。**
> 修夹具不是让测试变绿，是让它第一次能报出真正的问题。

### 9.2 【已修复】§十三 黄金样本集的时间锚点污染

把 8.1 的隐患推广到全仓：扫出 6 个含硬编码绝对时间戳的候选，逐一定性，
4 个安全（`evidence_ids=[]` 使 freshness 恒 1；纯解析测试；过去时刻的 SLA
只会越来越 breach；纯透传字段）。**1 个是真炸弹**：

`eval_datasets/grounding_cases.py` 的 13 个用例，每个事件都写死
`2026-10-18T00:00:00+00:00`，锚点已过期 34.3 小时。对照实验
（同一套用例，只刷新时间）：

| 指标 | 硬编码（已过期） | 刷新后 | 一致 |
|---|---|---|---|
| accuracy / confusion / hard_fail_coverage | 1.0 / 混淆矩阵 / 6-7 | 同 | ✅ |
| **separation.min_grounded** | **0.8** | **0.9** | ❌ |
| **separation.known_gap_max_score** | **0.8** | **0.9** | ❌ |

**判定质量没有被污染**（−0.10 是均匀平移，没有让任何用例跨档位，margin 仍是 0.2）。
真正的问题是**同一套黄金集在 TTL 过期前后报出的诊断数值不同**，这与本仓库
其它数据集自己写明的意图「固定值 = 可复现」相矛盾。

关键区分（已写进代码注释）：

> **固定锚点适合「窗口边界」**（`detection_cases` / `behavior_cases` 就是这么
> 用的，那是对的）；**不适合任何按「现在」度量的 TTL / 新鲜度 / 过期判定**。

修后两条路径给出**逐项相同**的结果，`min_grounded` 回到真实的 0.9。

### 9.3 【已修复】§十三 要求的误报率/漏报率，在两个三分类评估器上缺失

文档 §十三 验收要求「分别报告各类检测器的 Precision、Recall、**误报率与漏报率**」。
逐个查（全文计数 `false_positive_rate` / `fpr` / `specificity` 均为 **0**）：

| 评估器 | 标签空间 | P/R/F1 | 误报率 / 漏报率 |
|---|---|---|---|
| `evaluate_detection.py` | 二分类 | ✅ | ✅ |
| `evaluate_grounding.py` | 三分类 | ✅ | ❌ **缺** |
| `evaluate_behavior.py` | 三分类 | ✅ | ❌ **缺** |

按 one-vs-rest 补齐，分母口径与 `evaluate_detection.py` 文档里写明的坑保持一致
（`TN = 计入准确率的样本数 − tp − fp − fn`，用 `counted` 排除 known_gap ——
算成 TN 会虚高特异度，算成 FN 会虚高漏报率）。

守卫：`tests/test_eval_metric_completeness.py`（**13 例**：5 例 FPR/FNR + 2 例候选计数口径
+ 黄金样本区分度 3（§9.17）+ 每千条误报 3（§9.25））。
**这里踩过一个坑必须记下**：两套黄金样本分别只有 12 / 9 条计入样本且**全部判对**，
实测 FPR/FNR 全为 0。若只在真实数据上断言「这些率存在且落在 0~1 之间」，
守卫永远不会红。所以改用**已知答案的人工混淆矩阵**钉死每个数字。

注入「分母为 0 时返回 0.0 而不是 None」（最危险的语义错误：0.0 会被读成
「没有误报」）→ **2 条转红**；还原后 5 passed。

### 9.4 【已修复】负类标签写死 → 关联/异常家族的误报率**根本算不出来**

跑 `evaluate_detection` 时，`excluded_suspicious` 这个计数器暴露了问题：

| 家族 | tp | fp | **tn** | fn | **excluded_suspicious** | 误报率 |
|---|---|---|---|---|---|---|
| sigma | 8 | 0 | **10** | 0 | 2 | 0.0 ✅ |
| correlation | 2 | 0 | **0** | 0 | **6** | **null** ❌ |
| anomaly | 1 | 0 | **0** | 2 | **2** | **null** ❌ |

根因：`_binary` 里写死了单一常量 `_NEGATIVE_LABEL = "benign"`，但三个家族的
负类标签**根本不同**：

```
Sigma      正类 malicious   负类 benign          → 默认值恰好正确
异常检测    正类 detected    负类 not_detected   → 负样本被当候选排除
关联引擎    正类 chain       负类 no_chain       → 负样本被当候选排除
```

**最严重的不是"少报一个指标"**：关联引擎当时报
`accuracy = (2+0)/2 = 1.0` —— 一个**一条负样本都没有**的总体报了 100% 准确率，
且结构上无法表达任何误报。评估器自己那句警告「本标定集 FP=0……这是样本集
没有误报的性质」对这两个家族是**错的**：它们的 FP=0 是被结构性排除出来的。

（§2.x 那条注释早就警告过「与 `_binary` 的排除规则脱节，同一份报告里两个总分
的分母就不一样了」—— 这条 bug 正是该警告描述的那一类。）

修后：anomaly `tn` 0→2、误报率 null→0.0、accuracy 0.333→**0.6**（诚实的分母）；
correlation `tn` 0→6、误报率 null→0.0；sigma 不变。

守卫：`tests/test_p3_detection_calibration.py`（共 **29 例**）+2 例，其中一条专门把
「漏传负类标签」的后果钉成可观测数字。注入退回写死的标签 → **2 条转红**
（且复现出**完全相同的原始数字** `tn=0 / excluded=2 / fpr=None`）。

### 9.5 【已验证】§十一 核心要求：五态经真实路径实测分开计数

文档 §十一 的关键句：「如果这些状态最终都被压成一个 `not_detected` 计数，
那么新增多少仪表盘也无法真正帮助排障。」

换掉注册表、跑**真实**的 `analyze()` 路径，把 `soc_detection_outcomes_total`
读回来：

```
detector=anomaly  outcome=detected      count=117
detector=anomaly  outcome=inconclusive  count=130
detector=anomaly  outcome=not_detected  count=205
```

三行独立计数，`inconclusive` 未被压进 `not_detected`。守卫
`tests/test_detection_metrics.py` +2 例（跑真实 `analyze()` 而非直接调
`record_detection`）。注入「`analyze()` 把 inconclusive 提前判成 not_detected」
→ **3 条转红**（含既有的 `test_anomaly_records_timing_and_outcome`，
所以不能声称"此前无人守"；新守卫补的是更强且此前没有的性质：
**三行独立且计数互不相同** —— 同一份报告里三个相同的计数只说明有人写了三行，
不说明它们对应不同结局）。

### 9.6 【已验证】§七.1 / §二 / §十.2 / §五 的量化验收

| 维度 | 实测结论 |
|---|---|
| §七.1 基线年龄不得钝化灵敏度 | 速率恒定下，基线 1/7/30/60 天触发 3σ 所需突增量 = **6/5/5/5**，60 天仅 **0.83×**（文档点名的旧行为是 **7.50×**）。滚动桶饱和在 168（=7×24），证明窗口生效。守卫 2 例（含空断言守卫）注入验红 |
| §二 三态区分 | 成熟+正常 `not_detected`/可收口=True；成熟+突增 `detected`；新实体首波 `inconclusive`/禁止收口。且 `analysis_incomplete` 会 priority +20 并**禁止 `rule_close`** |
| §十.2 变种聚类 | 60 种输入顺序下簇划分与 `cluster_id` 逐位一致；空集合相似度 = `nan`；无有效特征样本各自成单点簇 |
| §五.1/§五.2 沙箱 | 11 条 URL/task_id 边界全过（`file:`/`gopher:`/`ftp:`、loopback、私有段、`169.254.169.254`、`[::1]`、`localhost`、`../../v1/admin`、换行、空串）；`analyze(None/{}/"str"/[])` 全为 `unavailable` 而非 clean |

### 9.7 【上报】测试库隔离缺陷 —— 一条**从未真正验证过**的测试

`tests/test_case_automation.py::test_audit_pipeline_path_creates_case`
是长期 flaky（约 75% 失败）。本轮查明：**它一次都没有验证过所声称的路径**。

根因在测试库配置，不在被测代码：`sqlite+aiosqlite:///:memory:` 被 SQLAlchemy
判为内存库并选用 **StaticPool**，全进程所有 Session 共用**同一条 DBAPI 连接**；
SQLite 的 BEGIN/COMMIT/ROLLBACK 是**连接级**而非事务对象级的，于是
任一 Session `close()` 发出的 ROLLBACK 会连带丢弃**别的** Session 未提交的写入。

连接级事件时序（`sqlalchemy.event` 监听 `before_cursor_execute`/`commit`/`rollback`）：

```
005 INSERT security_cases        ← flush
006 SELECT-CASES                 ← 读者命中窗口 → 测试"通过"（**脏读**）
007 ROLLBACK                     ← 别的 Session 抹掉 INSERT
009 COMMIT                       ← _create_case_from_event 的 commit 照样成功
010 UPDATE security_cases        ← 0 rows matched → StaleDataError
```

8 轮实测：`auto-dispatch failed` 恰好打印 8 次，**没有任何一轮真正 COMMIT 过
那条 case 行**。OK 与 MISS 的唯一差别，是读者的 SELECT 有没有落进
INSERT 与 ROLLBACK 之间那个窗口。更毒的是 `_create_case_from_event` 在 commit
之后照打 `[Case] Auto-created` —— **日志自述成功，数据不存在**。

生产路径（`postgresql+asyncpg` + QueuePool，每 Session 独立连接）**不受影响**，
这是测试可信度问题而非线上数据丢失。

**三条修复路线全部被证据否决**（已按字节回滚 `tests/conftest.py`，
sha256 `ED0A1E03A11722D74C0DEDB10F70D2558CB515AEA37C1375FA88B624024BD970` 复核一致）：

| 方案 | 实测结果 |
|---|---|
| shared-cache 内存库 `?mode=memory&cache=shared` | 表级锁且无 WAL → 并发写直接 `database table is locked`，**比原状更糟** |
| 文件型 SQLite + 默认 QueuePool | 目标用例 12/12 正确通过，但全量 **124 failed + 33 errors** |
| 文件型 SQLite + `NullPool` | 每次签出新建连接，全量 **>7min 未完成** |

**在用户决策前，该用例的绿灯不作为验收证据**；
`case_manager` 的 Kafka 入口建单/派单路径目前**未经有效验证**。

### 9.8 本轮新增的待决项（17 ~ 28）

| # | 事项 | 证据 |
|---|---|---|
| 17 | 是否投资修测试库隔离 | §9.7 |
| 18 | 异常阈值 0.60 在标定集上落在**召回下界**之外：3 条应检出只中 1 条（得分 0.4357 / 0.4957），扫描给出召回下界 **[0, 0.4357)**、网格落点 [0.0, 0.4]，且报「当前值落在网格区间内 = False」。⚠ **2026-10-20 §9.60 更正**：那个区间不是可行区间 —— 补齐负类（0.1714）与「结构性不可判」（0.4957）两类约束后，**完整可行区间为空集**，任何阈值都补不上这个缺口（逐档体检：降阈值会把不可判样本翻成 detected）。文档 §七.2 明确警告不要靠降阈解决；真实代价需生产流量重测 | §4.4 / §9.60 |
| 19 | 有限的越界 CAPE 分数（>10）是否记入 `input_errors`：`inf` 会被截断**并**记录，99 会被截断**且不记录**。但 `analyze()` 里任何非空 `input_errors` 都短路成 `error`+`score=None` ⇒ 补错误码等于把 `malicious` 翻成 `error` = **关掉检测**。属检测方向的收紧，登记为决策 | `behavior_analyzer.py:63` |
| 20 | 行为（零日）检测器的 verdict 未接入五态指标：`_DETECTOR_ALLOW` 允许 8 个检测器，实测只有 `anomaly`/`correlation`/`sigma` 三个调用 `record_detection`。`behavior` 的词表（clean/suspicious/malicious/unavailable/error）与五态高度对应却无处上报；`suspicious` 归 `inconclusive` 还是 `partial`、`unavailable` 是否进白名单，属语义决策 | §9.5 |
| 21 | **公开注册闸门要不要真的关掉**（本报告严重级别最高的一条）。四条子论断 2026-10-19 复核**仍全部成立**。本轮新查到两件决定性的事：① 管理员登录走 `settings.admin_user`/`admin_password`（`routers/auth.py:78-85`，`.env.example:23` 出货），**关掉自注册不会把管理员锁在外面** —— 原先担心的运维风险不存在；② 前端有完整自助注册入口（`RegisterForm.tsx` + `LoginForm.tsx:100-101` 的「去注册」+ `/register` 路由），**只改后端会让用户点「去注册」后撞 403**。完整改动需同时覆盖：后端 `config.py` 字段 + 端点判断、前端隐藏入口并给明确文案、把 `tests/test_self_registration_gate.py` 的 3 条 **strict xfail** 转正。默认关 / 默认开但强制显式确认，属产品决策 | §7.1.12 |
| 22 | **变种聚类的特征集要不要加上限**（新登记，见 §9.24）。文档 §十.2 假设「若必须限长，标记不完整并防止仅凭截断后的集合得出强结论」；但当前实现**根本不截断** → 那两半**空洞成立**，而 `SampleFeatures.features_truncated` 在**生产代码里零赋值**（唯一赋值在测试里手工设置）→ `stats["truncated_features"]` **结构性恒为 0**，是死计数器。真正缺的是文档假设的**上限本身**：特征集大小无界。补上限会**改变聚类结果**，方向可能是**漏报**（超大特征集被截断后的相似度分布会变），属设计决策 → 单方面改会踩「误拒与漏报同级」的线 | §9.24 |
| 23 | **异常得分在速率突增维度上饱和，要不要改打分口径**（新登记，见 §9.28.3）。实测 `dim = min(1.0, dev_sigma / 5.0)`，而 σ 在 3× 及以上就撞上夹紧上限 `10.0` → **1.5× 与 6× 突增的得分完全相同（0.774）** —— 得分在这个维度上**没有分辨率**。另测到「**短窗口让老实体得分更低**」（168 小时老实体改用 1 天窗口：基线样本量 168→24，得分 0.597→0.567，方向是**漏报**）。放宽夹紧或改用非线性 σ→分映射都会改变**所有**既有分数（§9.3 的扫描区间也会跟着动），属**检测方向**的改动 → 不单方面做 | §9.28 |
| 24 | **合法的新常态流量会被误报至少 8 小时，要不要缓解**（新登记，见 §9.29）。实测：实体从 50 条/小时换到 100 条/小时后，基线在 **8 小时时还没认下、12 小时时已认下**（矩阵阶梯 {1,2,4,8,12,24,48}h 所限，实际落在 8~12 小时之间），这期间新常态流量**持续**被报成异常（100 条/小时 → 每天 1000+ 条误报）。且触发误报的是 **`sigma > 3` 旁路**（得分 0.572 ≤ 阈值 0.60，但 σ=3.59 > 3）—— **调阈值消不掉这批误报**。缓解手段（换常态检测 / 慢启动抑制 / 手动重置基线）每一种都动判定逻辑 → 属检测方向，不单方面做 | §9.29 |
| 28 | **MCP 工具路径要不要接到真正干活的响应引擎**（新登记，见 §9.46）。现状：`mcp_guard/tool_registry.py` 的 6 个执行器**全是模拟实现**，而真正干活的响应动作在 `response_engine/response_registry.py`（SSH/防火墙/QoS）—— **MCP 路径根本够不着它**。本轮只做了诚实性修复（模拟就报 `status="simulated"`）。接线的**前置障碍**是参数契约**四方声明不一致**（见 §9.46.5）：MCP 面给 LLM 的是 `ip`/`host`/`rate`，转换器是 `ip`/`hostname`/`target`，动作注册表与动作签名是 `src_ip`/`host_ip`/`bandwidth_kbps`。所以「以哪份声明为准」是**契约决策**，不能顺手代拍 → 不单方面做 | §9.46 |
| 27 | **宿主机遏制路径（`containment/host_adapter.py`）的命令形态要不要改成编码形态**（新登记，见 §9.45.6）。实测：该模块把**原始 PowerShell 脚本**交给 `ssh_transport.run()`，而 windows 白名单只放行编码形态（WIN-004）、`GLOBAL_FORBIDDEN` 又拦下脚本里的 `;` / `|` → **每一次调用都被拒**（`success=False`，如实上报，不会谎报成功）。修法是像 `response_registry._ps_cmd()` 那样**先编码**再送 —— 但那样 `GLOBAL_FORBIDDEN` 就**看不见脚本内容**了（安全面变化）。缓解事实：这些脚本由适配器**自己构造**，输入只有已校验的 PID / SHA-256 摘要 / 过 `reject_path` 的路径 → 风险有界。但「注入过滤器是否还看得见内容」是**安全设计**问题 → 不单方面做 | §9.45 |
| 26 | **因果候选池的上限 `MAX_ADJUST_POOL=12` 要不要提到图节点上限**（新登记，见 §9.42）。实测：可观测变量 18 个时，候选池只装得下 14 个，**2 个变量被静默丢掉**；被丢掉的变量若正好在后门路径上，该因果效应仍会被判成「不可识别」。本轮已把截断数随结论落库（`assumptions.adjust_pool_truncated`）—— 原因不再不可见，但缺口本身还在。提到 `MAX_NODES=20`（图节点上限）会让候选组合数从 1471 涨到约 4048（最坏耗时 0.60 → 约 1.7 ms/次），属**性能/完备性**的取舍，且会改变「不可识别」的判定范围 → 不单方面做 | §9.42 |
| 37 | **信誉先验读取失败时要不要回退到内存缓存**（新登记，见 §9.57）。实测：`_get_prior_delta` 失败时返回 0.0（docstring 明确声明 fail-open，方向没错），但**只留一行 debug 日志** → 生产默认 INFO 下看不见；而 delta **确实**加到主评分上（clip ±`learn_loop_prior_clip`=±0.2，能跨 clean/suspicious/malicious 档位）→ 一次 DB 抖动就让「重复攻击者」的信誉分少一个先验修正、可能降档，而**旁边的注释还写着「不影响主评分」**（在撒谎）。本轮已把降级**改成可见且可数**（warning + `soc_reputation_prior_lookup_failed_total`）并改正注释，**行为不变**。剩下的是：缓存里就有上次加载的先验，**回退**会把评分改回去，而方向取决于 delta 的符号（正 → 检出更多；负「常误报」→ 检出更少）→ **属业务判断**，不单方面做 | §9.57 |
| 36 | **「核心资产保护」的内置默认清单要不要真的覆盖平台自身组件网段**（新登记，见 §9.54）。实测：`asset_whitelist` 的模块 docstring 声称内置默认保护「平台自身组件的 IP/网段」，而**内置清单只有 `127.0.0.0/8`（loopback）一条** → 平台自己的 DB/缓存/Kafka **不在**保护范围内（**文档承诺落空**，整改方案 §十一.2）；业务资产靠 `SHARED_MEMORY_PROTECTED_ASSETS` 配置，而**出货的 compose 里没有设它**（全仓只有说明文字里出现过）。本轮只把**保护范围**写进审计（`protected_count` + `scope=empty/builtin_only/configured`）并删掉 `0.0.0.0/0` 死占位符（其注释「check 中特殊处理」在撒谎，而 check 里没有）。补内置清单属**扩大保护范围**的决策（会改变哪些 IP 被拦）→ 不单方面做 | §9.54 |
| 35 | **能扛重启的 TTL 机制要不要接线**（新登记，见 §9.53）。现状：在用的是**进程内**的 `asyncio.create_task(_auto_rollback(...))` → 进程重启 / 发布 / 崩溃会**静默丢失**这次自动解封（连日志都没有）→ 误报封禁不会自愈，误报**主机隔离**会把机器一直关在网外（in+out 双向 DROP）；而**能扛重启**的 `response_engine/ttl_manager.py`（Redis 持久化 TTL + 后台扫描器）**已实现但三重未接线**（`register` 的调用不可达、因为**没人传** `_ttl_seconds`/`_rule_id`；`start_scanner` 从未启动；`set_redis`/`set_rollback_callback` 无调用方），且**没有**任何定时对账会清理残留规则（`rollback_all` 只能管理员手工点）。本轮只把机制与局限**写进动作结果**并计数（`soc_response_auto_unblock_scheduled_total`）。接线需要四件事同时做（动作传 TTL 参数、启动时 set_redis/set_rollback_callback、启动 scanner、一条按 rule_id 回滚的回调）→ 属**接线决策**（新增后台扫描器 + Redis 写入 + 启动钩子），不单方面做 | §9.53 |
| 34 | **响应动作的「执行幂等」要不要像「回滚幂等」那样补内存兜底**（新登记，见 §9.52）。实测：**同一事务的两侧不对称** —— 回滚侧 `RollbackStore` 是「内存为主、Redis 兜底」（Redis 故障时保护仍在），**执行侧** `SafeExecutor._idempotency_check` 是**纯 Redis** → Redis 故障时幂等保护**整体消失**（Kafka 重放会重复执行动作：重复防火墙规则/通知/工单），且**标记**也写不进去。本轮已把「没查成」与「查了、没重复」**分开记**（`state="unavailable"` + 单独计数），**拦截行为不变**。补内存兜底属**收紧型**改动：① Redis 故障时同进程重复会被拦下（可能误拒「同一事件的合法二次执行」）；② 内存标记的存活期与 Redis 的 24h TTL **不等价**（进程活得更久就拦得更久）→ 缺省语义属**业务定义**，不单方面做 | §9.52 |
| 33 | **SafeExecutor 的 grounding 硬门控要不要真的接上**（新登记，见 §9.51）。实测：这道闸门**永远不会触发** —— `grounding_score` 在整个 `response_engine` 包里只出现在闸门自己（没有任何生产代码传它），而动作函数也不转发 `**kwargs`；**审计里却记成「通过、满分」**。本轮已把「没评估过」与「评估通过」**分开记**（`state="not_evaluated"` + `passed=None`）并单独计数（`soc_response_grounding_gate_total`），**拦截行为不变**。剩下的是**要不要接线**：非审计来源的响应（Kafka 告警 / EDR 融合）**根本没有 grounding 分数**，若按缺省拒绝，整个响应能力会瘫；而给不同来源定不同的缺省语义是**业务定义** → 收紧型改动，不单方面做 | §9.51 |
| 32 | **`embed()` 的失败返回要不要从「全零向量」改成 `None`**（新登记，见 §9.50）。现状：失败时返回**维度正确但全零**的向量 → 与真实向量不可区分（`if v` 惯例拦不住、维度护栏拦不住）。本轮已在**三个存储/检索口**各加一道闸（判定口统一为 `is_degraded_vector`），把「脏数据入库」与「兜底返回任意一条」两个实际危害堵住了；但**契约本身**仍不一致 —— 同一类的 `embed_batch()` 对同一失败返回的是 **None**。改成 `None` 需要动 8 个调用方（`agents/agent_a|b|c`（传 None 给 `store_memory` 本就支持）、`rag/retriever.py:78/104`、`tool_registry.py:628`、`routers/rag.py:142/278`、`migrate_pgvector_to_qdrant.py:111`），属**接口语义变更**；漏改一处会从「静默降级」变成「TypeError」。另有一处相关缺口：LLM 看到的 `vector.search` 结果仍是空列表，分不清「没有相关记忆」与「检索不可用」，修它要改工具返回形态（list → dict），同样是契约变更 → 本轮**只做不改变契约就能堵住的部分** | §9.50 |
| 31 | **学习闭环的「家族」定义要不要从「贪心/leader」改成「相似链连通分量」**（新登记，见 §9.49）。两份实现**回答同一个业务问题**却给出两套答案：`zeroday_detect/variant_cluster.py` 用**单链接**（相似链连通分量，并显式给出「内聚度」以暴露链式漂移），`learn_loop/models_cluster.py` 用**贪心/leader**（只比簇代表，且簇代表是成员并集、会长大）。整改方案 §十.2 明确说「对于簇划分，我建议先确定业务定义：一个家族究竟要求所有成员彼此相似，还是只需要通过相似链连接？……不要仅仅因为现有文档写着 DBSCAN，就将实现机械替换成 DBSCAN」→ 那是**业务定义**，不是 bug。本轮只把**顺序无关性**与**簇号内容寻址**做掉（不动算法），两种定义的差别仍在 → 不单方面做 | §9.49 |
| 29 | **生产全局单例 `response_registry` 要不要改成依赖注入**（新登记，见 §9.47）。本轮已让它**可以被独立构造**（`_init_registry(registry=None)`），从而能在不碰全局单例的前提下测出「生产动作集」；但 `routers/response.py`、各执行器、TTL 管理等**仍直接用全局单例** → 全局被谁注册过仍会影响行为。彻底改成注入式（应用启动时构造、向下传递）会牵动十数个调用点，属**结构改造**；而全局单例本身不是缺陷（生产里只有一处构造）→ 本轮只把「可测量性」和「污染可被发现」做掉，不擅自重构 | §9.47 |
| 30 | **仓库根 `.env` 里那 16 个「非本服务」的键怎么处理**（新登记，见 §9.48）。实测：仓库根 `.env` 是**多服务共用**的配置（postgres / redis / kafka / kafka-ui / grafana / misp 都在里面），后端只认 `SHARED_MEMORY_` 前缀的键 → pydantic-settings 把那 16 个键当成 extra ⇒ 从仓库根裸跑就崩（收集期 16 条 `extra_forbidden`）。三个选项：(a) 把非本服务的键**移出**这份 `.env`（各服务各管各的）；(b) 后端读 `.env` 时**只取带前缀的键**（需定制 settings source；直接改 `extra="ignore"` 会让**配置拼写错误被静默忽略** —— 那是**放宽**，不采纳）；(c) 保持现状（开关打开时已不读 `.env`，§9.48 已修；开关关闭时从仓库根裸跑仍会崩）。本轮**只做 (c) 里代码能做的部分**，不动用户机器上的 `.env` | §9.48 |
| 25 | **工单审批通过后到底要不要真的执行响应动作**（新登记，见 §9.36）。`_execute_approved_actions` 的名字与 docstring 都写着「执行响应动作」，实际**一个动作都不执行**（只把案例状态改成 `responding`）—— 系统里因此有**两套并行的审批机制**：内存态 `approval_queue`（进程重启即丢，但通过后**真的**执行动作）vs 数据库态 `WorkOrder.approval_status`（持久、运维实际操作的是它，但通过后**不执行**任何动作）。**接上**可能与内存票路径**重复执行**；**不接上**则运维点「批准」后系统什么都不做 —— 在安全运营里同样是危险的静默。两边后果都不轻，且都超出「修一个 bug」的范围 → 本轮只做安全的三件事（删死代码、改正 docstring、加三态计数），**不擅自接** | §9.36 |


### 9.9 本轮没有推进的部分（诚实登记）

- **Flink 仍未在真实集群运行**；本轮无新证据。
- **§十三 的量化基线仍是合成标定集**：§9.3 补齐了指标，但两套黄金样本
  计入样本分别只有 12 / 9 条且**全部判对** → **观测到的**误报率/漏报率恒为 0。
  要让 §十三 测出真实流量上的误差率，需要含真实误报/漏报的黄金样本，属数据缺口。
- ⚠ **更正本报告此前的一句过强表述**：上面这条曾被写成「指标形式完整，
  **判别力为零**」。**这是错的** —— 2026-10-19 实测推翻了它：
  - 数据集**有区分度**：grounding 集的混淆矩阵是 grounded 5/5、
    partially_grounded 1/1、ungrounded 6/7，一个**恒判 grounded 的平凡检测器
    会错 7/12**（只对 5 条）；behavior 集的 9 条计入样本分属 logged/confirm/deny
    三类各 3 条，恒判 logged 同样会错 6/9。
  - 阈值本身在真正做决定：grounding 扫描的**分离裕度 0.2000**
    （干净样本最低 0.9000 vs 未硬否决的越界样本最高 0.7000），
    且 7 条应判非 grounded 里有 **1 条纯靠分数阈值**判定（其余 6 条靠硬否决）。
  - behavior 集另有 **2 条已登记的 known_gap**（`new_payload_same_length` /
    `new_target_same_class`）被排除在准确率外 —— 它们是「已知检测不到」的
    **真实缺口**，不是样本缺失。
  - 真正成立的限制只有一条：**观测误差为 0**，所以这批样本测不出真实误差率
    —— 是**样本集**的问题（合成、偏易、规模小），不是**指标**的问题。
- 累计待决项 **48 项**（§9.8 表列出本轮新增的 17~37 共 21 项，§9.59.10 新增 38~40、§9.60.7 新增 41、§9.61.8 新增 42~43、§9.62.8 新增 44~45、§9.63.6 新增 46、§9.64.7 新增 47、§9.65.6 新增 48 共 11 项；更早的 1~16 分散在 §6.2 与 §7.1.x 各节 —— ⚠ 那部分的编号有两套且互相冲突，12~16 号查不到，见 §9.37.5）。

### 9.10 【已修复·本轮新增】Sigma 规则执行错误通道的并发串扰 —— P0 缺陷在并发下复活

#### 9.10.1 现象

「单条规则 SQL 执行失败被上报为 `partial`」这条性质，单线程下上一轮已经修好并有守卫
（§2.3、`test_q4_2_per_rule_sql_error_is_reported_as_partial`）。
本轮发现它**在并发下不成立**：

```
线程 A（规则必然报错）        status=not_detected  rules_evaluated=1  rules_failed=0
线程 B（同一条规则正常执行）  status=detected      rules_evaluated=1  rules_failed=0
```

A 那一轮的规则**真的报错了** —— 日志里能看到
`[Sigma] rule execution failed rule_id=PROBE-001 error=no such column: bad_col` ——
但最终载荷里 `rules_failed=0`、`status_errors=[]`、`status=not_detected`。
**P0 缺陷「单条规则 SQL 执行失败被当作完整阴性」原样复活。**

#### 9.10.2 根因：错误通道是实例级共享状态，而它跨了两次独立调用

上一轮修 §六 那条缺陷的方式是：把失败记进 `self._last_rule_errors`，
由 `detect_for_event()` 据此产出 `partial`。问题出在这条通道的**位置**：

| 位置（修复前） | 内容 |
|---|---|
| `engine.py:435` | `self._last_rule_errors = []` —— 每次 `detect()` 重置 |
| `engine.py:447` | `self._last_rule_errors.append({...})` —— 记录本轮失败 |
| `engine.py:705` | `errs = list(self._last_rule_errors)` —— `_detect_for_event_inner()` 读取 |

**写与读分属两次独立调用**（`detect()` 返回之后才读），中间还隔着一次函数返回；
而 `self._last_rule_errors` 是**跨线程共享**的实例属性：

* 线程 A 在自己的 `detect()` 里记下失败（写进列表对象 L1）；
* 线程 B 的 `detect()` 执行到重置那行，把属性**重新绑定**到新列表 L2 ——
  L1 连同 A 的失败一起被丢弃；
* 线程 A 随后读到的是 L2（空）→ `errs=[]` → 整轮被当成完整阴性。

这与 §六 的另一条验收标准「**并发不同事件时，检测结果相互独立**」直接冲突：
上一轮把 SQLite 连接做成了每轮独占（Q2 那一族守卫守的就是它），
但**错误通道没有跟着搬进执行上下文**。

生产上并非纯理论：`ingest_pipeline.py:368` 在 async 函数里**同步**调用
`detect_for_event()`，而 FastAPI 的同步端点在线程池中执行，
另有 `ops_loop` / `case_manager` 的后台线程。

#### 9.10.3 第二处同形态缺陷：早退路径绕过了重置

`self._last_rule_errors` 只在 `detect()` 的 `try` 块内重置，
而 `detect()` 有两条早退路径位于 `try` 之前：

* `if not compiled: return self._legacy_detect(event)`（无已编译规则）
* `if not cols: return []`（事件一个字段都没有）

这两条路径不重置 → 上一轮的失败会被**下一轮原样继承**。实测：

```
第 1 轮（规则失败）                       : status=partial  rules_failed=1
第 2 轮（空事件，一条规则都没执行）      : status=partial  rules_failed=1
```

第 2 轮报告了一条**它自己从未执行过**的规则失败 ——
§二 要求「融合层能够记录是哪个检测器、哪个版本、**在哪个阶段**失败」，阶段被记错了。

#### 9.10.4 修复：错误与本轮检测绑定返回

把错误从「实例属性通道」改成「**随本轮返回值一起交回**」：

* 新增 `_detect_with_errors(event) -> (hits, rule_errors)`；
  `rule_errors` 是**函数局部变量**，跨线程、跨调用都不可能串扰。
* `detect()` 变成薄封装，仍把本轮错误写回 `self._last_rule_errors` **仅供调试**，
  并在注释里写明「它**不是**判定依据」。
* `_detect_for_event_inner()` 改为 `hits, errs = self._detect_with_errors(log_data)`，
  **不再读实例属性**。
* 两条早退路径各自返回 `([], [])`，顺带修掉 9.10.3。

#### 9.10.5 守卫与验红

新增 `tests/test_review_sigma_detector.py::TestQ5RuleErrorChannelIsolation`（2 例）：

| 用例 | 守住什么 |
|---|---|
| `test_q5_1_concurrent_detection_does_not_swallow_a_rule_failure` | 并发检测不得吞掉另一轮的规则失败 |
| `test_q5_2_stale_rule_errors_do_not_leak_into_the_next_detection` | 上一轮的错误不得泄漏到下一轮 |

**插桩点的选择本身是一个结论**：编排点没有落在 `detect()` /
`_detect_with_errors()` 这类内部方法名上，而是落在 **SQLite 自定义函数**（SQL 执行层）——
新旧实现都必经 SQL 执行，所以同一支测试能同时判定「旧行为红 / 新行为绿」。
若插桩落在内部方法名上，换个实现就失效，那样的守卫**测不出回归**。

验红（把 `engine.py` 字节级还原成修复前版本，逆向重建的 sha256
`e7622e2dc9a0b59ec72c15b6ae225f112c0944e27f5c3c2734fdfc730f2fe1e1`
与修复前基线**逐位一致**）：

```
注入旧行为 → 2 failed
  Q5.1  AssertionError: 线程 A 的单条规则执行失败被并发检测吞掉：
         {'status': ..., 'status_errors': [], 'rules_failed': 0, ...}
  Q5.2  AssertionError: 上一轮的规则失败泄漏到了本轮（本次一条规则都没执行）：
         {'status': 'partial', 'status_errors': [{...'no such column: probe_missing'}],
          'rules_failed': 1}
还原修复 → 2 passed
```

#### 9.10.6 顺带修掉一条守卫的**判据失配**（不是性质被破坏）

拆开 `detect()` 之后，既有守卫 `test_q2_3_detection_needs_no_global_lock` 立刻变红：

```
AssertionError: detect() 不再自建连接 —— 隔离已失效，请更新结论
```

它的判据是 `inspect.getsource(PySigmaDetector.detect)` 里找 `sqlite3.connect`。
但**性质并没有变**：每次检测仍然自建独立连接、检测路径上仍然没有全局锁
（实测路径 = `detect` → `_detect_with_errors` → `_ensure_table` / `_quote_ident` /
`_mk_result` / `_agg_payload` / `_schedule_publish_agg` / `_legacy_detect`，
其中 `self._lock` 出现 **0** 次、`sqlite3.connect` 出现 **1** 次）。

按「为变绿而放宽安全要求」处理是不对的。改法是**把判据对准性质本身**：
沿 `self.xxx(...)` 调用把**整条检测执行路径**的源码收齐再判。
重构搬家不再误报，而真回归仍会红 —— 这一点用两次注入当场验过：

| 注入 | 结果 |
|---|---|
| 在检测路径上加 `with self._lock:` | **红** ✓ |
| 把 `sqlite3.connect(":memory:")` 换成 `self._conn` | **红** ✓ |

（两次注入后均按字节还原，sha256 复核一致。）

#### 9.10.7 扫过的邻近面（否定结论）

* **legacy 兜底引擎没有同形态缺陷**：`SigmaDetector` 的实例状态只有 `rules`
  与 `_last_cleanup`（清理节流时间戳），没有「本次调用的错误」通道。
* **全仓没有第二处同形态通道**：扫 `self._last_errors` / `self._current_*`
  等命名形态，除已修的 `_last_rule_errors` 外无命中。
* **本轮没有改变检测口径**：阈值、规则语义、聚合判定、动作建议一律未动；
  改的只是「错误怎么回到调用方」。

### 9.11 【已修复·本轮新增】畸形字段类型让整条异常分析路径崩溃 —— §七.3 末条从未落地

#### 9.11.1 现象

整改方案 §七.3「统一分数边界和时间语义」列了 5 条，最后一条是：

> 「输入中的 src_ip 等字段类型异常，可能导致统计数据结构操作失败的问题。」

本轮按这条逐项核查（前 4 条都已实装：样本不足返回 `None`、
`mean==0` 分支不再绕过 `min(sigma, 10.0)`、时序改用事件时间 + 配置时区、
窗口改成真滚动窗口），**最后一条从未落地**。实测（2026-10-19）：

```
src_ip 是 list  → TypeError: unhashable type: 'list'
src_ip 是 dict  → TypeError: unhashable type: 'dict'
dst_ip 是 list  → TypeError: unhashable type: 'list'
event   是 dict → TypeError: unhashable type: 'dict'
```

三种崩法（都因为把**原始事件字段直接当 dict 键**用）：

| 位置 | 用法 |
|---|---|
| `anomaly_detector.py:889` | `self.baselines["src_ip"].get(src_ip)` |
| `anomaly_detector.py:668` | `self.baselines[entity_type].get(entity_key)`（`dst_ip` 经 `_calc_target_concentration` 进来） |
| `anomaly_detector.py:565` | `bl.event_types.add(event_type)`（`event_type` 经 `_update_baseline` 进来） |

#### 9.11.2 为什么这条不是「小事」

`analyze()` 抛异常，在生产上被 `ingest_pipeline._run_anomaly()` 的 `except`
兜成 `DetectorError` → 该事件的状态变成 `error`。方向上是**安全**的
（不是误判成阴性），但代价是：

1. **可被上游触发**。`src_ip` / `dst_ip` / `event` 都是日志载荷里的字段 ——
   一个把 `src_ip` 写成数组的日志源（或能被请求体影响的接入层），
   就能让该源的事件**整条不可判定**。这是可用性面，不是理论问题。
2. **不留痕**。报告里没有任何痕迹说明「这条事件不可判定是因为
   **字段类型坏了**」，读的人只会看到「样本不足」。

#### 9.11.3 修复：规范化 + 显式披露 + 不入分布

新增 `AnomalyDetector._entity_key(value) -> (key, usable)`，把三个字段
统一规范化成**可哈希**的实体键，并单独标出「不可解释」的值：

| 输入 | 键 | usable | 理由 |
|---|---|---|---|
| `None` / `str` / `int` / `float` / `bool` | 原样 | ✅ | 都可哈希，行为不变 |
| `list` / `tuple` 且**恰好一个元素** | 该元素递归 | ✅ | `["10.0.0.1"]` 与 `"10.0.0.1"` 必须是**同一个实体** |
| 多元素序列 / `dict` / `set` / 自定义对象 | `""` | ❌ | 无法解释成一个实体 |

对 `usable=False` 的值：

* 该维度按 **inconclusive** 处理（不是当成正常值，也不是当成阴性）；
* 实体**不入基线**（基线是「这个实体长什么样」，读不懂的值建出来的也是读不懂的）；
* 事件类型**不进全局分布** —— 这一条方向很重要：
  畸形类型若进了 `global_event_types`，它的占比近乎 0，
  `_calc_event_rarity` 会判成「从未见过」→ `rarity=1.0` → **每条畸形事件都误报**；
* 报告留痕 `ingest:invalid_src_ip_type` / `ingest:invalid_dst_ip_type` /
  `ingest:invalid_event_type`（沿用既有的 `ingest:` 前缀 = 纯披露，
  不改分、不进 `veto_gates._STRONG_SIGNAL_REASONS`）。

#### 9.11.4 守卫与验红

新增 `tests/test_review_anomaly.py::TestMalformedFieldTypeRobustness`（4 例）：

| 用例 | 守住什么 |
|---|---|
| `test_mf_1_malformed_field_types_do_not_crash_the_analysis` | 畸形类型不得让分析路径崩溃；必须标 inconclusive 且留痕 |
| `test_mf_2_malformed_event_type_stays_out_of_the_global_distribution` | 畸形事件类型不得进全局分布（防的是**误报**方向） |
| `test_mf_3_single_element_list_is_the_same_entity` | 单元素列表与标量不得分裂成两个基线 |
| `test_mf_4_malformed_values_create_no_baseline_entities` | 不可解释的值不得建出基线实体 |

验红（`anomaly_detector.py` 字节级还原成修复前版本，逆向重建的 sha256
`4e291af1ee2c2f729bb34ac402671ab063e8c3bad147206110fb8c5a4ed5127f`
与修复前基线**逐位一致**）：

```
注入旧行为 → 4 failed
  TypeError: unhashable type: 'dict'
  anomaly_detector.py:889: TypeError
还原修复 → 4 passed
```

#### 9.11.5 守卫生效过程中我自己写错过一次断言（如实记录）

`test_mf_4` 的第一版断言是「三个实体类型的基线键集合都必须为空」。
它红了 —— 但**不是代码错了，是我的断言错了**：
`BASE` 事件里**合法**的 `src_ip="10.0.0.1"` 本来就该建出基线，
另外 4 个畸形用例只覆盖了 `dst_ip` / `event`，`src_ip` 仍是合法的。

改成「占位键 `""` 不得进基线」+「畸形 `dst_ip` 不得建出任何实体」后通过。
**教训**：断言写错和代码写坏的失效形态一样（都是红），
必须先分辨是哪一种，再决定改哪边 —— 否则就会「改代码去迁就一个错的断言」。

#### 9.11.6 邻近面（否定结论）

* **没有改检测口径**：阈值、权重、维度集合、稀有度公式、
  冷启动策略一律未动；改的只是「读不懂的字段怎么办」。
* **合法输入的路径逐位不变**：`_entity_key` 对 `str` / `int` / `float` / `bool` /
  `None` 原样返回，对单元素序列取元素 —— 这两类覆盖了现有全部生产取值。
* **同族扫描**：全仓扫 `self.baselines[...]` / `global_event_types[...]` /
  `event_types.add(...)` 三类「拿事件字段当键」的用法，
  本文件内已全部收口到 `_entity_key`；未发现第二处同类崩溃点。

### 9.12 【已修复·本轮新增】全局统计不幂等 → 重复消费改变后续事件的评分

#### 9.12.1 现象

整改方案 §七.1 明写：

> 「如果平台允许重复消息，基线更新还应当对事件 ID 幂等。
>   同一条事件重复投递多次，不能因为重复消费改变后续事件的评分。」

**前半句实现了，后半句没有。** 实体基线早就按 `event_id` 幂等
（每个实体一个 `bl.seen_ids`），但**全局统计**是无条件自增的：

```python
self.global_hourly_counts[hour] += 1          # ← 没有幂等闸门
self.global_event_types[event_type] += 1       # ← 同上
```

而全局统计决定 **rarity 维度**，rarity 直接进最终加权分。实测（2026-10-19）：
灌 45 条事件后**重投同一条事件 20 次**（Kafka 至少一次投递的常态）：

| 指标 | 期望 | 实测（修复前） |
|---|---|---|
| `global_total` 增量 | +0 | **+21** |
| `global_event_types['BENIGN']` 增量 | +0 | **+20** |
| 后续事件的 rarity | 不变 | 0.7778 → **0.8182** |
| 后续事件的总分 | 不变 | 0.2222 → **0.2338** |

反方向更危险：重投一条**罕见**事件会把它自己的占比推高、rarity 被拉低 ——
攻击事件因此变得「不罕见」。这是**漏报**方向。

#### 9.12.2 修复

全局统计是**事件级**的（每小时多少条、每种类型多少条），所以幂等也必须按
**事件级**判定。判据复用**已随基线持久化到 Redis 的实体级 `seen_ids`**
（不新增状态面）：任一实体说「这条事件我见过」就算重投。

* `counted_type` = 事件类型实体更新的返回值（该实体每次都有 `f"{eid_key}:type"` 键）；
* `is_replay = (src_ip and not counted) or (event_type_ok and not counted_type)`；
* 全局计数只在 `not is_replay` 时自增；
* 报告留痕 `replay:global_stats_not_updated`（`replay:` 前缀 = 纯披露，
  不进 `veto_gates._STRONG_SIGNAL_REASONS`）。

#### 9.12.3 守卫与验红

新增 `tests/test_review_anomaly.py::TestReplayIdempotency`（2 例）：

| 用例 | 守住什么 |
|---|---|
| `test_rp_1_replaying_the_same_event_does_not_change_global_stats` | 重投不得改变全局统计 |
| `test_rp_2_replays_do_not_change_the_score_of_later_events` | **对照实验**：两个内容相同的检测器，一个被重投 20 次 → 后续事件的分数/维度/状态必须逐位相同 |

验红（字节级还原到修复前，逆向重建 sha256 `e4998fca…` 与基线逐位一致）：

```
注入旧行为 → 2 failed
  AssertionError: 重复消费改变了后续事件的评分：0.2418 vs 0.2222
还原修复 → 2 passed
```

#### 9.12.4 §十三 评估数字未受影响（实测）

修复前后各跑一次 `python -m eval_datasets.evaluate_detection --json`，
把输出**摊平成 560 个标量**逐项比对：**逐项完全相同**。
原因很直接：评估集的事件 id 互不相同，撞车与重投都没发生。

---

### 9.13 【已修复·本轮新增】去重键撞车 → 第五维对无 id 事件**结构性失效**

#### 9.13.1 现象

这是做 §9.12 时被**既有测试**撞出来的（`test_q6_1` 突然变红），
追下去发现的是一个**先前就存在、此前无人发现**的缺陷。

`_update_baseline` 的三个调用点把去重键写成了：

```python
src_ip     → event_id = eid_key
dst_ip     → event_id = f"{eid_key}:dst"
event_type → event_id = f"{eid_key}:type"
```

而没有 `event_id` 时 `eid_key` 是 **int 0** → 两个后缀键都变成**真值**字符串
`"0:dst"` / `"0:type"`。于是**所有**无 id 事件共享同一个去重键，
每个实体只计进**第一条**事件：

| 灌入 30 条 | src_ip | dst_ip | event_type |
|---|---|---|---|
| 无 event_id | 30 ✓ | **1** ✗ | **1** ✗ |
| 互不相同的 event_id | 30 ✓ | 30 ✓ | 30 ✓ |
| 同一个 event_id 重复 30 次（重投） | 1 ✓ | 1 ✓ | 1 ✓ |

#### 9.13.2 后果：第五维的 21.4% 权重**结构性失效**（漏报方向）

`dst_ip` 基线只记进 1 条 → `_calc_statistical_deviation("dst_ip", ...)` 的
样本量不足（`COLD_START_MIN_SAMPLES = 5`）→ 第五维
`target_concentration` **恒为 inconclusive** → 它
`0.15 / EVIDENCE_TOTAL(0.70) = 0.2143` 的有效权重在无 id 事件上**完全失效**。

而评分分母是**固定**的 `EVIDENCE_TOTAL`（这是有意的：防止冷启动被归一成 1.0 分），
于是每条无 id 事件的分数被**系统性压低最多 0.2143**。

注入验红时的实测输出把这一点摆得很清楚：

```
dimensions        = {'statistical_deviation': 0.0}          ← 少了第五维
effective_weights = {'statistical_deviation': 0.5}           ← 少了 0.2143
inconclusive      = ['rarity', 'target_concentration']
```

**为什么此前没有任何测试发现**：既有用例要么用唯一 id（不撞车），
要么用 `seed_rolling()` 直接改 `bl.recent`（**绕过** `_update_baseline`）。

#### 9.13.3 修复

后缀本来就是**多余**的：每个实体类型有**各自**的 `seen_ids` 集合
（`self.baselines["dst_ip"]` 与 `self.baselines["src_ip"]` 不共享对象），
根本不需要靠后缀隔开命名空间 —— 反而正是后缀制造了撞车。

改法：去重键就是**事件 id 本身**（`eid_key`）。
无 id 时 `eid_key` 是 0 → `if event_id:` 为假 → **不去重**（如实：没有标识
就没有幂等的依据）→ 事件正常累进基线。

#### 9.13.4 守卫与验红

新增 `tests/test_review_anomaly.py::TestDedupKeyCollision`（3 例）：

| 用例 | 守住什么 |
|---|---|
| `test_dk_1_events_without_event_id_accumulate_the_baseline` | 无 id 事件必须正常累进基线 |
| `test_dk_2_replays_still_do_not_accumulate` | **另一半**：只修撞车不修幂等，等于把重投也放进来 |
| `test_dk_3_fifth_dimension_is_not_structurally_dead` | 检测层后果：第五维不得对无 id 事件恒为 inconclusive |

验红（字节级还原到修复前，逆向重建 sha256 `e4998fca…` 与基线逐位一致）：

```
注入旧行为 → 2 failed, 1 passed
  dk_1  AssertionError: dst_ip 基线只记进 1 条（期望 30）—— 去重键互相撞车了
  dk_3  AssertionError: 第五维对无 id 事件不可判定
        （inconclusive=['rarity', 'target_concentration']）
还原修复 → 3 passed
```

`dk_2` 在注入下**仍然绿** —— 它守的是「重投仍然要去重」，
而本次注入只回退了去重键修复、没回退幂等修复。这符合预期，
如实标注：它验证的是**另一条**性质。

#### 9.13.5 §十三 评估数字未受影响（实测）

同 §9.12.4：修复前后 `evaluate_detection --json` 摊平 560 项逐项比对，
**逐项完全相同**。评估集的事件 id 互不相同，撞车从未发生。

---
### 9.14 【登记】沙箱的「结果回取半边」在生产代码里零调用

#### 9.14.1 事实

`sandbox_connector` 有一整半边能力在生产里**没有任何调用方**。
下表是 AST 普查（生产 .py 310 个 / 测试 .py 179 个，排除实现模块本身）：

| 能力 | 生产调用方（模块外） |
|---|---|
| `submit_url` | **有**：`routers/edr_intel.py`（`POST /sandbox/submit`） |
| `submit_file` / `submit_file_outcome` | **0** |
| `auto_submit_check` | **0** |
| `poll_outcome` | **0** |
| `wait_outcome` / `wait_for_completion` | **0** |
| `fetch_report_outcome` / `get_report` | **0** |
| `get_task_status` | **0** |
| `lookup_by_hash` | **0** |

于是生产上的实际形态是：

```
POST /api/sandbox/submit
   └─ sandbox.submit_url(url)              ✅ 真实提交给 CAPE/Cuckoo
   └─ SandboxTask(status="pending")        ✅ 写入 DB
                    ⋮
   └─ poll_outcome / fetch_report_outcome  ❌ 生产零调用
                    ↓
   SandboxTask 永远停在 "pending"，verdict / score / behavior_summary 恒为空
```

这与 §7.1.9 已登记的「写回那半边没有」是**两半边**：
那个守卫钉的是「有没有代码把结果写回 `SandboxTask`」，
本条钉的是「有没有代码去**取**结果」—— 两半边都没有，才构成「提交进去就悬空」。

另外 `lookup_by_hash` 零生产调用 → 整改方案 §十.1 要求的
「明确相同样本重复提交的策略，避免无意创建大量重复任务」
**能力已实现但未接线**。

#### 9.14.2 新增守卫

`tests/test_sandbox_result_retrieval_gap.py`（3 passed / 1 strict xfail）：

* `test_scanner_finds_both_bare_and_attribute_calls` —— 扫描器的前提守卫；
* `test_submit_half_is_wired_so_the_gap_is_precise` —— 写入半边**有**入口，
  缺口因此是精确的（不是「整个模块都没接」）；
* `test_implementation_module_is_excluded_but_still_contains_internal_calls`
  —— 排除规则的前提守卫；
* `test_result_retrieval_has_a_production_caller` —— **strict xfail** 钉住缺口。

#### 9.14.3 这条守卫我连写错两版，都是**注入验证**当场抓出来的（如实记录）

第一版断言写成 `assert not hits`，并把**实现模块自身**也算进调用方：

* **洞 1 · 排除缺失**：连接器内部本来就有
  `get_task_status → self.poll_outcome(...)`、
  `get_report → self.fetch_report_outcome(...)`、
  `wait_outcome → self.poll_outcome(...)` 等 **5 处**内部调用。
  把实现算成消费者 → `hits` **永远非空** → strict xfail **永远转不了红**
  → 这条守卫**结构性失效**（注入真缺陷也照样绿）。
* **洞 2 · 极性写反**：`strict=True` 的 xfail 期望用例**失败**，
  所以必须写成「**必须找得到**调用方」；写成 `assert not hits` 会把极性整个反过来。

两处都是**注入后 pytest 仍然报 "1 xfailed"** 才暴露的 ——
这正是「守卫绿不等于守卫有效」的又一例：这次不是判据太宽，
而是判据**永远不可能触发**。

顺带记一笔**普查工具自己也翻车**：第一版普查脚本用
「符号前必须有 `.` 或 `(`」的正则，**漏掉了裸函数调用**
（`inc_sandbox_submission("file")`），
差点把「沙箱提交指标无人自增」写成结论 —— 实际它在生产里是自增的。
改用 AST 后结论才成立。这也是为什么本文件里
「扫描器的前提守卫」是**一条独立用例**而不是注释。

#### 9.14.4 注入验证结果

| 状态 | pytest | 判定 |
|---|---|---|
| 未注入 | `3 passed, 1 xfailed` | 绿（xfail 成立） |
| 注入真实回取调用（`routers/edr_intel.py` 加 `await sandbox.poll_outcome(task_id)`） | `2 failed`（XPASS(strict) + 前提守卫） | **红** ✓ |
| 还原 | `3 passed, 1 xfailed` | 绿，sha256 复核一致 |

#### 9.14.5 为什么只登记、不修

补上回取路径需要真实设计决策：谁负责轮询（router 协程 / scheduler /
连接器内部）？失败重试与超时怎么落？凭据怎么传？
这与 §7.1.4 的零日链接线同型，**不该由一次审计代拍**。
所以用 strict xfail 钉住：一旦有人接上，XPASS(strict) 立刻转红，
强制回来改本文件与报告 §9.14。


### 9.15 【已验证·本轮新增】§六 验收标准：单条 Critical 规则执行异常 → 追踪错误并阻止错误收口

#### 9.15.1 为什么单列一条（这是一个**否定结论**）

整改方案 §六 的验收标准原文：

> 「单条规则 SQL 执行失败被当作 hit=False → 单独记录规则执行错误，
>   整轮标记为 partial 或 error，**不能返回完整阴性**」
> 验收：「**注入单条 Critical 规则执行异常，系统能够追踪错误并阻止错误收口**」

这条性质在**引擎侧**有守卫（`test_q4_2_per_rule_sql_error_is_reported_as_partial`），
在**融合层**却从未被端到端走过 —— 因为既有融合层测试（Q14/Q15）全部用
「引擎整体抛异常」→ status=**error**，
而「单条规则失败、引擎其余部分照常运行」是 **partial** —— 另一支。

这正是 §9.10 那条修复的落脚点：**错误通道修好了，但融合层若不认 `partial`，
那条修复就是空转**，事件仍会按阴性收口。所以必须单独钉住。

#### 9.15.2 实测（2026-10-19）

把一条 **critical** 规则（SIG-003「路径遍历攻击」）的 SQL 换成必然报错的
`SELECT * FROM no_such_table_...`，走**真实融合路径** `ingest_pipeline.detect()`：

```
sigma 载荷:
   status        = partial
   rules_failed  = 1
   error_code    = rule_exec_failed:1
   status_errors = [{'rule_id': 'SIG-003', 'severity': 'critical',
                     'error_code': 'OperationalError:rule_exec', ...}]
融合层:
   analysis_status        = partial
   analysis_complete      = False
   can_close_as_negative  = False
   detector_errors        = [{'detector': 'sigma', 'detector_version': 'pysigma-1.0',
                              'status': 'partial', 'error_code': 'rule_exec_failed:1', ...}]
```

**结论：性质成立。** 并且 `detector_errors` 里带了
「哪个检测器 / 哪个版本 / 哪个阶段 / 哪条规则」——正是 §二.2 验收 3 要求的四项。

#### 9.15.3 新增守卫

`tests/test_review_contract_fusion.py::TestQ16PartialRuleFailureReachesFusion`（1 例）。

**异常侧被钉成干净阴性**（stub 成 `not_detected`）是有意的：
这样「单条规则失败」就是**唯一**的不干净信号，
`can_close_as_negative is False` 才真的在测规则失败，
而不是被异常引擎的冷启动 `inconclusive` 顺带盖住。

#### 9.15.4 注入验证（两次，分别打在两条不同的断言上）

| 注入 | 红的断言 | 含义 |
|---|---|---|
| 融合层把 `partial` 当成 `not_detected` | **「单条规则执行失败却仍可按阴性收口 —— §六『不能返回完整阴性』未成立」** | 安全向：失败被当成可收口 |
| 把 `partial` 从 `FAILED_STATUSES` 摘掉 | `analysis_status == "partial"` | 状态口径 |

两次都按字节还原（sha256 复核一致），还原后守卫绿。

**断言顺序是刻意排的**：把「不可收口」排在「状态」之前 ——
否则最危险的注入只会报「状态不对」，
而真正要盯的那条（**错误被当成可收口**）根本轮不到触发。
这个顺序问题也是靠上面两次注入的报错位置发现的。

---

### 9.16 【已修复·本轮新增】一条依赖**实时 DNS** 的单元测试 + 补上「防 DNS 变更绕过」的覆盖

#### 9.16.1 现象

全量回归时 `tests/test_review_sandbox_security.py::TestUrlValidation::test_q12_2_public_http_https_allowed`
**间歇失败**（单独跑通过）。这不是 flaky 用例的已知项，是本轮**第一次**出现。

根因：`validate_submittable_url()` 的 `resolve_dns` 默认 **True**，
内部会真的做一次 `socket.getaddrinfo(host, ...)`。而该用例直接拿真实域名
`example.com` 去断言「公网 http/https 放行」——

```
DNS 正常   → 放行 → 绿
DNS 抖动   → UrlRejected("dns_resolve_failed") → 红
```

也就是说：**这条单元测试的结论由环境决定，而不是由被测代码决定。**
在离线 CI、被墙网络、或 DNS 抖动的机器上，它会莫名其妙地红。

#### 9.16.2 顺带查出：一条**从未被测过**的安全性质

整改方案 §五.2 明确要求：

> 「对域名解析后的 IP 与重定向后的目标重新做限制，避免 DNS 变更和重定向绕过」

而测试里**没有任何一条**覆盖「DNS 解析到私网 IP 必须被拒」——
全仓 `tests/` 搜 `getaddrinfo` 零命中。也就是说，
「防 DNS 变更绕过」这条安全性质**只有实现、没有回归**。

#### 9.16.3 处置

**没有改生产行为** —— 「DNS 解析失败 → 拒绝（fail closed）」本来就是对的
（查不到 ≠ 安全），生产路径继续依赖 DNS 解析是有意为之；
且它对拒绝的处理是优雅的（记日志 + `inc_sandbox_submission("url_rejected")`
+ 返回 `ST_FAILED` / `url_rejected:dns_resolve_failed`）。

改的是**测试**：

| 用例 | 改法 |
|---|---|
| `test_q12_2_public_http_https_allowed` | 「公网 http/https 放行」改用 `resolve_dns=False` —— 断言的仍是 scheme / 控制字符 / userinfo / 元数据主机等语义，**不依赖外网** |
| `test_q12_2b_dns_resolved_public_ip_is_allowed`（新） | 打桩 `getaddrinfo` 返回公网 IP → 放行 |
| `test_q12_2c_dns_resolved_private_ip_is_rejected`（新） | 打桩返回私网 IP → **拒绝**（补上 §五.2 那条从未被测过的性质） |
| `test_q12_2d_dns_failure_fails_closed`（新） | 打桩抛 `gaierror` → **拒绝**（fail closed） |

三条新用例全部**打桩**，离线可跑。

#### 9.16.4 验红

| 动作 | 结果 |
|---|---|
| 把 `socket.getaddrinfo` 打成失败（模拟断网）跑整个 URL 校验组 | **22 passed**（改之前这一组会红）✓ |
| 注入「DNS 解析到私网 IP 不再拒绝」 | `q12_2c` **红**：`DID NOT RAISE UrlRejected` ✓ |
| 注入「DNS 失败时放行（fail open）」 | `q12_2d` **红**：`DID NOT RAISE UrlRejected` ✓ |
| 还原 | 22 passed，sha256 复核一致 ✓ |

#### 9.16.5 全仓扫描结论

全仓 `tests/` 搜 `getaddrinfo` / `gethostbyname` / `urlopen` / `requests.get` /
`httpx.` —— **只有这一条**真的依赖实时网络；
其余的 `example.com` 都只是 mock 数据里的字符串，httpx 都是打桩的。

### 9.17 【更正·本轮新增】「判别力为零」是**过强**表述 —— 已更正并钉成守卫

#### 9.17.1 发现自己写错了一句

§9.9 原本写着：

> 「两套黄金样本 12/9 条且全部判对，误报率恒 0 —— 指标形式完整，**判别力为零**。」

本轮实跑两个评估器核对时，发现**这句话是错的**：

```
grounding 混淆矩阵（行=标注，列=实现）
                grounded  partially_grounded  ungrounded
grounded               5           0           0
partially_grounded     0           1           0
ungrounded             1           0           6      ← 这一条是已登记的 known_gap

behavior  11 条中计入 9 条：logged 3 / confirm 3 / deny 3
```

**数据集有区分度**：一个恒判 `grounded` 的**平凡检测器**在 grounding 集上
只对 5 条、**错 7/12**；恒判 `logged` 的在 behavior 集上**错 6/9**。
所以「判别力为零」把两件事混为一谈了：

| | 成立吗 |
|---|---|
| **观测到的**误报率/漏报率恒为 0（12/9 条全对） | ✅ 成立 |
| 指标/数据集**没有区分能力** | ❌ **不成立** |

#### 9.17.2 补上的三条支持证据

1. **阈值本身在真正做决定**：grounding 扫描的分离裕度 **0.2000**
   （干净样本最低 0.9000 vs 未硬否决的越界样本最高 0.7000），
   且 7 条应判非 grounded 里有 **1 条纯靠分数阈值**判定（其余 6 条靠硬否决）。
2. **behavior 集的 2 条 known_gap**（`new_payload_same_length` /
   `new_target_same_class`）被排除在准确率外 —— 它们是「已知检测不到」的
   **真实缺口**，不是样本缺失。
3. **类别分布非退化**（见下）。

真正成立的限制只有一条：**观测误差为 0** → 这批样本**测不出真实流量上的误差率**
（样本合成、偏易、规模小）—— 是**样本集**的问题，不是**指标**的问题。

#### 9.17.3 把它钉成守卫

新增 `tests/test_eval_metric_completeness.py::TestGoldenSetsStillHaveDiscriminatingPower`（3 例）：

| 用例 | 守住什么 |
|---|---|
| `test_grounding_golden_set_is_not_degenerate` | grounding 集不得退化成单一类别；最大类别不得占满 |
| `test_behavior_golden_set_is_not_degenerate` | 同上（behavior） |
| `test_evaluator_class_counts_agree_with_the_golden_sets` | 评估器读到的类别分布必须与黄金样本表**同源** |

「退化成单一类别」才是**判别力为零**的真实形态：一旦所有期望标签相同，
任何检测器都能拿 100%，误报率/漏报率就再也测不出东西。
这条现在由守卫守住，**数据集退化会立刻变红**。

#### 9.17.4 验红

| 注入 | 结果 |
|---|---|
| grounding 集过滤成只剩 `expect == "grounded"` | **红**：`grounding 集退化成单一类别：{'grounded': 5}` ✓ |
| behavior 集过滤成只剩 `expect == "logged"` | **红**：`behavior 集退化成单一类别：{'logged': 3}` ✓ |
| 还原 | 3 passed，sha256 复核一致 ✓ |

#### 9.17.5 附带：顺序无关性

本轮所有新增用例都会改**全局** `sd.sigma_detector` 的 `_snapshot`（Q16 与 Q5），
所以专门跑了一次**带 pytest-randomly 的随机顺序**全量回归：

```
2328 passed, 18 skipped, 54 xfailed, 0 failed
```

与固定顺序（`-p no:randomly`）结果一致 —— 新用例不依赖执行顺序，
也不把全局状态泄漏给后续用例（Q16 用 `try/finally` 还原快照）。

### 9.18 【已验证·本轮新增】§三.2 因果识别条件：性质成立，但**此前没有任何回归**

#### 9.18.1 性质成立（实测）

整改方案 §三.2 的验收标准原文：

> 「不可识别时，不能输出已识别的 ACE」
> 「明确区分 observed_variables、已声明的潜变量以及未知混杂假设」
> 「修复 extra 候选调整集恒为空的过滤逻辑，检查所有符合理论条件的候选调整集」

实测（2026-10-19，`causal_chain/do_calculus.py`）：

| 场景 | 结果 |
|---|---|
| 图里有 H→X / H→Y，但 H **不可观测** | `identifiable=False`、`reason="no_backdoor"`、**无 `ace` 字段** ✓ |
| 把 H 纳入 `names`（可观测） | `identifiable=True`、`z=["H"]`、`ace=0.1909` ✓ |
| 调用方**声明**潜混杂 `unobserved_confounders=["H"]` | `identifiable=False`、`reason="unobserved_confounding"`、假设字段如实记为 `no_unobserved_confounding=False` ✓ |
| 候选调整集（extra 分支） | `[[], ['W1'], ['W2'], ['W3'], ['W1','W2'], ['W1','W3'], ['W2','W3']]` —— **不再恒为空** ✓ |
| `x == y` / 变量不在 `names` | `same_variable` / `unknown_variable`，均无 ACE ✓ |

关键机制：图里保留了 H 的边 → `G_Xbar` 下 X 与 Y **不 d-分离** → 空集不合法
→ 没有**可观测**候选能挡住它 → `backdoor_set` 返回 `None` → 不可识别。
**引擎是从图里自己看出「有未观测混杂」的**，不是靠调用方声明才知道。

#### 9.18.2 但这一组性质**此前一条回归都没有**

全仓 `tests/` 搜 `no_backdoor` / `unobserved_confounding` → **零命中**。
既有 `test_causal_chain.py` / `test_causal_path_gate.py` 覆盖的是
`compare.py` 的判定顺序（§三.1）与 `path_ok` 闸门，
**没有一条**断言「不可识别时不得输出 ACE」—— 而那正是 §三.2 点名的 P0。

`test_causal_chain.py:102` 那句 `if q.get("identifiable") and q.get("ace") is not None:`
是**条件分支里的**检查，不是守卫：不可识别时它整段被跳过。

#### 9.18.3 新增守卫

`tests/test_causal_identification.py`（6 例）：

| 用例 | 守住什么 |
|---|---|
| `test_unobserved_confounder_in_graph_blocks_identification` | **最要害的一条**：不可识别且**不得输出 ACE / P(Y\|do(X))** |
| `test_observable_confounder_is_adjusted_and_yields_an_ace` | 正向对照：别把好案例也堵死 |
| `test_declared_latent_confounder_overrides_the_assumption` | 声明的潜混杂必须推翻假设，且假设字段如实落库 |
| `test_candidate_pool_contains_non_prior_variables` | extra 分支不再恒为空；且**空集必须保留** |
| `test_unknown_or_same_variable_is_not_identifiable`（2 例） | 变量缺失 / x==y 的守卫 |

#### 9.18.4 验红

注入方式：把 `backdoor_set` 的「找不到满足后门准则的候选 → `None`」
改回旧行为的「→ `[]`（空集永远是合法调整集）」——
**这正是 §三.2 描述的老缺陷**（空调整集被当成「不存在后门路径」）。

```
注入旧行为 → RED
  AssertionError: 未观测混杂 H 在图里，却判成可识别：{...}
还原 → 6 passed，sha256 复核一致
```

---

### 9.19 【已验证·本轮新增】§三.3 方向冲突：性质成立，但**此前也没有任何回归**

#### 9.19.1 性质成立（实测）

整改方案 §三.3 原文：

> 「同时需要修复 GES 输出中可能同时存在 A → B 和 B → A 的矛盾方向」
> 验收：「强数据证据与领域先验冲突时，保留冲突信息」

实测（2026-10-19，`causal_chain/ges.py::consensus()`）：

| 场景 | 结果 |
|---|---|
| PC 说 A→B、GES 说 B→A | 输出**只有一条**，`orientation="undirected"`、`orientation_source="conflict"`、`confidence="undirected_or_conflict"`、`identifiability="not_identified"`、`conflict_candidates=[["A","B"],["B","A"]]`、`direction_conflicts=[["A","B"]]` ✓ |
| 两算法同向 | `orientation="directed"`、`orientation_source="data_invariant"`、`identifiability="identified"`、`confidence="high_confidence"` ✓ |
| GES 侧该边**可逆**（在 `undirected` 里）且两算法同向 | `orientation_source="score_search"`、`identifiability="not_identified"` ✓ |
| 骨架不一致 | **不**标成 conflict（那是「算法没共识」，不是「方向矛盾」）✓ |

顺带厘清一个容易看错的结构：GES 的 `directed` 是它找到的 DAG 的**全部**边，
而 `undirected` 是其中**可逆**的子集 —— 两者**有交集**，
所以 `score_search` 分支是可达的（GES 把可逆边也放进了 `directed`）。

#### 9.19.2 但这一组性质**此前也没有回归**

`consensus()` 在生产被 `causal_chain/learn.py:104` 调用，
但全仓 `tests/` 搜 `consensus(` / `conflict_candidates` → **零命中**
（`test_rag_hybrid.py` 里的 `test_fusion_prefers_consensus` 是 RAG 融合的
另一个同名概念，与因果方向冲突无关）。

后果：§三.3 点名的「不得同时输出 A→B 与 B→A」这条 P0 性质，
**修了但没锁** —— 任何一次重构都可能悄悄把它改回去而无人察觉。

#### 9.19.3 新增守卫

`tests/test_causal_consensus_conflict.py`（5 例）：

| 用例 | 守住什么 |
|---|---|
| `test_opposite_directions_do_not_both_appear_as_directed` | **最要害的一条**：不得同时输出两个相反方向 |
| `test_conflict_is_marked_and_candidates_are_preserved` | 冲突必须被**标出来**，并保留两个候选方向 |
| `test_agreeing_direction_stays_data_invariant` | 正向对照：同向时仍标成数据识别 |
| `test_score_only_edge_is_not_claimed_as_data_derived` | 搜索顺序决定的方向不得冒充数据识别 |
| `test_skeleton_disagreement_is_not_a_direction_conflict` | 骨架不一致 ≠ 方向矛盾 |

#### 9.19.4 验红

注入方式：把 `consensus()` 的冲突过滤分支 `if sk in conflicts:` 短路掉 ——
**这正是 §三.3 描述的老缺陷**（`for a, b in sorted(pc_dir | ges_dir)` 直接遍历并集）。

```
注入旧行为 → RED
  AssertionError: 同时输出了两个互相矛盾的方向：[('A', 'B'), ('B', 'A')]
还原 → 5 passed，sha256 复核一致
```

#### 9.19.5 本轮新增守卫的一次自曝（守卫生效前它自己先错了）

`test_score_only_edge_is_not_claimed_as_data_derived` 的**第一版前提写错了**：
我把 GES 的「可逆边」当成不会进 `directed`，于是造出一个
「GES 只有 undirected、PC 有 directed」的组合 —— 结果 `confidence` 落在
`oriented_by_one` 而不是 `high_confidence`，`score_search` 分支压根没走到，
用例红。

追下去才发现真实结构（GES 的 `directed` 含**全部** DAG 边，`undirected` 是
其中可逆的**子集**，两者有交集），改正前提后即绿。
**判据写错和代码写坏的失效形态一样（都是红）** —— 必须先分辨是哪一种。

---

---

### 9.20 【已验证·本轮新增】§六 DDL 字段名标识符转义：核心早有回归，但四条更细的性质没有

#### 9.20.1 性质成立（实测）

整改方案 §六 的一行与它的验收标准：

> 「DDL 字段名直接通过 f-string 拼接 → 优先将外部字段映射成可信的内部列名；
>   否则严格校验和引用 SQL 标识符，值继续采用参数绑定」
> 验收：「**恶意字段名不能破坏建表**，异常不会无保护地泄漏到 API」

实测（2026-10-19，`sigma_engine/engine.py::_quote_ident` + `_ensure_table`）：

| 字段名 | 结果 |
|---|---|
| `evil"col` | 建表成功，命中 0 条 ✓ |
| `x"; DROP TABLE events; --` | 建表成功，命中 0 条 ✓ |
| `a"b"c` | 建表成功，命中 0 条 ✓ |
| `col" , "injected" TEXT, "x` | 建表成功，命中 0 条 ✓ |
| `"; DELETE FROM events; --` | 建表成功，命中 0 条 ✓ |

建出来的列名**原样保留**（被正确转义，而不是被截断或改写），
**没有凭空多出名为 `injected` 的列**（注入串惰性），`events` 表仍有 1 行。

#### 9.20.2 覆盖情况：核心早有回归，缺的是四条更细的性质

既有 `test_q1_10_field_name_injection_is_escaped` **已经**覆盖核心：
不抛异常 + `_quote_ident('a"b') == '"a""b"'` + 不影响正常事件检测。

此前**没有**回归的是另外四条：

| 性质 | 为什么值得单独守 |
|---|---|
| 列名必须**原样保留** | 转义成 `""` 之外的处理（截断/改名）同样能「建表成功」，但语义已经错了 |
| 注入串**惰性** | 不得凭空多出列、表也不得被删 —— 这才是「不生效」的完整含义 |
| 值**仍走参数绑定** | 值里的引号不得影响 schema 或数据 |
| 建表真失败时异常必须**被包成**带 `sigma_exec_schema_invalid` 的 RuntimeError | 「异常不会无保护地泄漏到 API」这半条此前没人守 |

#### 9.20.3 新增守卫

`tests/test_review_sigma_detector.py::TestQ6IdentifierQuoting`（5 例）：
`test_malicious_field_name_does_not_break_detection` /
`test_malicious_field_name_is_preserved_verbatim` /
`test_injection_string_is_inert` /
`test_values_still_go_through_parameter_binding` /
`test_schema_failure_is_wrapped_not_leaked`。

#### 9.20.4 验红

注入方式：把 `_quote_ident` 退回修复前的**不转义**写法
（`'"' + str(name) + '"'`）—— 这正是 §六 描述的老缺陷。

```
注入旧行为 → RED
  AssertionError: 字段名 'evil"col' 让检测路径抛异常
                  RuntimeError: sigma_exec_schema_invalid: near ".": syntax error
还原 → 5 passed，sha256 复核一致
```

#### 9.20.5 本轮的第三次「判据先红」与一次**测量错误**（如实记录）

**其一**：`test_values_still_go_through_parameter_binding` 的**第一版断言**写的是
「表里的列**只有**事件自带的那些」—— 结果红。
追下去才发现 `_ensure_table` 总会**额外**预建一批标准字段
（`body` / `bytes` / `cookie` / `cs-uri-query` …），表里本来就有 50+ 列。
改正断言为「事件自带的列名原样在表里 + 行数正确 + 值原样存回」后即绿。

**其二（更严重）**：写这一节时我曾断言「全仓 `tests/` 搜 `_quote_ident`
→ **零命中**，此前没有任何回归」—— **这是错的**：
`test_q1_10` 早就覆盖了核心。错因是**检索输出被 100 条上限截断**，
后面的行没看见，于是把「有覆盖」误判成「零命中」。

改用**逐行计数扫描**（不依赖 grep、不会被上限截断）后真相大白：

| 本报告的「此前零回归」结论 | 计数复核结果 |
|---|---|
| §9.18 因果识别条件 | ✅ 成立（命中只在新文件里） |
| §9.19 因果方向冲突 | ✅ 成立（命中只在新文件里） |
| §9.20 DDL 标识符转义 | ❌ **不成立**（`test_q1_10` 早已覆盖核心） |

> **否定结论（「零命中」「没有覆盖」）必须用不会被截断的扫描来下。**
> 检索工具的输出上限，是把「有」误判成「无」的常见来源 ——
> 而且这类错误在**测试**上尤其危险：它会让你以为「补了守卫」，
> 实际补的是重复品。

#### 9.20.6 顺带做的**系统性覆盖扫描**（§九.1 方法的规模化应用）

把整改文档的验收标准逐条对应到测试里，用**逐行计数扫描**（不截断）
跑了一遍 38 条标准 → 只有 2 条零命中：

| 零命中 | 人工判定 |
|---|---|
| §二 状态必须区分真实阴性/不可判定/执行失败 | **正则太窄**，实际由 `test_q14_2` 等覆盖 ✓ |
| §五 重定向后重新校验 | **真的没覆盖** → 查出 §9.21 这条**真缺陷** |

其余 36 条标准均有对应回归。扫描脚本与结果留在
`%TEMP%/scan_doc_coverage.py`（可重复执行）。

**第二批**（§五.1 的 7 态 / §十.1 与 §十.2 的逐条 / §十一 的指标与词表 /
§十三 的验收维度，共 45 条）同样用计数扫描跑了一遍 → **只有 1 条零命中**：
「§十.1 提交成功必须返回有效的外部 task_id」→
查下去发现实现是对的（`_extract_task_id` 取不到就返回 `""` → 提交失败），
但**没有任何测试断言它** → 补出 §9.22。

也就是说：整改文档的验收标准到这里已经**逐条**有回归或有明确登记。


### 9.21 【已修复·本轮新增】沙箱重定向目标没有重新校验 → SSRF + 凭据外泄

#### 9.21.1 现象（真缺陷，不是覆盖缺口）

整改方案 §五.2 的两条要求：

> 「对域名解析后的 IP 与**重定向后的目标**重新做限制，
>   避免 DNS 变更和重定向绕过」
> 「对外部 API 请求**禁用非预期重定向**，使用固定服务端点」

实现里**前半句做到了**（`allow_redirects=False` → 不自动跟随，每一跳手动处理），
但**「重新做限制」只做了一半**：`_safe_redirect_target()` 只挡
**scheme 混淆**与**控制字符**。实测（修复前，2026-10-19）：

| 重定向目标 | 期望 | 修复前实际 |
|---|---|---|
| `http://169.254.169.254/latest/meta-data/` | 拒 | **放行** ❌ |
| `http://metadata.google.internal/computeMetadata/v1/` | 拒 | **放行** ❌ |
| `http://127.0.0.1:6379/_INFO` | 拒 | **放行** ❌ |
| `http://evil.example.com/steal` | 拒 | **放行** ❌ |
| `file:///etc/passwd` | 拒 | 拒绝 ✓ |
| 含控制字符的 Location | 拒 | **放行** ❌ |

**后果**：平台会带着 `self._headers()` 里的 **Bearer 沙箱 API key**
去请求那些地址 —— 典型 SSRF + **凭据外泄**。
跨主机那一项尤其致命：沙箱 API 若（被攻陷、或反射用户输入地）回一个
`Location: http://evil.example.com/steal`，平台就把 key 送了出去。

**另一处更隐蔽**：控制字符那道检查查的是 `urljoin` **之后**的串，
而 `urljoin` 会把控制字符**剥掉** —— 所以那道检查**等于没有**。

#### 9.21.2 修法（三条）

1. **原始** Location 里就不能有控制字符（`urljoin` 剥掉 → 事后查等于没查）；
2. 重定向目标必须**留在配置的沙箱端点主机上**
   （「固定服务端点」/「禁用非预期重定向」）—— 否则凭据会被带到别的域；
3. 目标本身重新过一遍 `validate_submittable_url`
   （`allow_private=True`：沙箱端点本身是内网服务；
   但 **loopback 与云元数据在任何模式下都禁**）。

#### 9.21.3 守卫与验红

新增 `tests/test_review_sandbox_security.py::TestRedirectTargetRevalidation`（8 例：
5 个参数化 + 控制字符 + 空 Location + 同主机相对重定向的正向对照）。

| 注入 | 结果 |
|---|---|
| 把 `_safe_redirect_target` 退回修复前版本 | **7 条红**（`DID NOT RAISE UrlRejected`）✓ |
| 还原 | 8 passed，sha256 复核一致 ✓ |

#### 9.21.4 ⚠ 唯一的行为变化（要如实说）

**跨主机重定向不再被跟随**。如果你的沙箱 API 真的会重定向到**另一个主机**
（例如前面挂了 LB、或 API 与最终端点不同域），这条会让它失败。
按文档「使用固定服务端点」，正确做法是**把 `sandbox_api_url` 直接配成最终端点**。

同一主机的正常重定向（相对路径、http→https 同主机）**不受影响** ——
正向对照用例已钉住。

其余变化（云元数据 / loopback / 跨主机 / 控制字符 / 空 Location）
全是**收紧安全边界**，不改变任何一条检测结论。


### 9.22 【已补·本轮新增】「缺失 task_id ⇒ 提交失败」：性质成立，但**此前零回归**

#### 9.22.1 性质成立（实测）

整改方案 §十.1 原文：

> 「提交成功必须返回有效的外部任务 ID；**缺失 ID 应当视为提交失败**」

`zeroday_detect/sandbox_connector.py::_extract_task_id()` 取不到可用 id 时返回 `""`，
调用方随即返回 `ST_FAILED` + `error_code="missing_task_id"` —— 行为**正确**。

而修复前的写法是 `str(result.get("task_id", ...))`：
`None` 会变成字面量字符串 `"None"`，**真值检查放行** →
落库成 `SandboxTask(status="pending")` 的**永久悬空任务**（再也不会被推进）。

#### 9.22.2 但这一条此前**没有任何回归**

全仓 `tests/` 搜 `missing_task_id` → **零命中**。
既有测试覆盖了「非法 URL 被拒」「task_id 路径注入」「空样本」，
却**没有**覆盖「沙箱返回 200 但没有可用 task_id」这一条 ——
而它正是模块 docstring 自称已修、也是**悬空任务**的唯一来源。

#### 9.22.3 新增守卫

`tests/test_review_sandbox_security.py::TestMissingTaskIdIsSubmissionFailure`（8 例）：
6 个参数化（`{"task_id": None}` / `{"task_id": ""}` / `{"task_id": "   "}` /
`{}` / `{"task_ids": []}` / `{"other": "x"}`）+ 2 个正向对照
（有可用 id → `ST_PENDING`；`task_ids` 列表取第一个可用项）。

> ⚠ 用例里的 URL 特意用 **IP 字面量**而不是域名：域名会触发
> `validate_submittable_url` 的实时 DNS 解析 → 结论由环境决定
> —— 那正是本轮刚在 §9.16 修掉的坑，**不能再犯一次**。

#### 9.22.4 验红

注入方式：把 `_extract_task_id` 退回修复前的写法
（`str(payload.get("task_id", "missing"))` —— `None` → 真值字符串 `"None"` 放行）。

```
注入旧行为 → RED（11 条失败）
  AssertionError: assert 'pending' == 'failed'
还原 → 8 passed，sha256 复核一致
```


### 9.23 【已补·本轮新增】相似度的「显示值 vs 判定值」契约：性质成立，但**此前零回归**

#### 9.23.1 性质成立

整改方案 §十.2 的一行：

> 「`round(sim, 3)` 隐藏实际阈值差异 → **显示精度与原始判定值一致**，
>   避免把 0.4996 显示成 0.500 却判为『相似』」

现在的契约（`zeroday_detect/variant_cluster.py::find_similar`）：

| 字段 | 含义 |
|---|---|
| `similarity` | **未取整的判定值** |
| `similarity_display` | 仅用于展示的 3 位小数 |
| `meets_threshold` | 由**原值**与阈值比较得出 |

`jaccard_similarity()` 本身也返回原值（`intersection / union`，不取整）。

#### 9.23.2 但这一条此前**没有任何回归**

全仓 `tests/` 搜 `similarity_display` / `meets_threshold` → **零命中**。
也就是说：「把 0.4996 显示成 0.500 却判为不相似」这类误读，
在实现里已经修好了，但**没有任何一条用例锁住它**。

#### 9.23.3 新增守卫

`tests/test_clustering_feature_contracts.py::TestSimilarityReportingContract`（3 例）：

| 用例 | 守住什么 |
|---|---|
| `test_similarity_value_is_not_rounded` | 判定值必须是**原值** —— 直接用文档举的 0.4996（1249/2500）当例子，并断言它 `!= round(sim, 3)` |
| `test_find_similar_reports_raw_similarity_and_a_separate_display` | `similarity` 是原值（2/3）、`similarity_display` 是 "0.667"，两者分开 |
| `test_meets_threshold_agrees_with_the_raw_value` | `meets_threshold` 必须由**原值**决定（多个阈值下逐一核对） |

#### 9.23.4 验红

注入方式：把 `find_similar` 的 `"similarity"` 退回 `round(sim, 3)`（修复前形态）。

```
注入旧行为 → RED
  AssertionError: assert 0.667 == (2 / 3)
还原 → 3 passed，sha256 复核一致
```

#### 9.23.5 本轮守卫生效前的又一次「前提先错」

第一版断言写的是「`res[0]` 是目标样本」—— 结果红。
追下去才发现 `find_similar` 会把**查询样本自身**也列进去（相似度 1.0 排第一），
必须按 `sample_hash` 定位目标条目。

这是本轮**第三次**出现「判据写错 vs 代码写坏」分辨不清的情况
（另两次：§9.20 的 `_ensure_table` 标准字段集、§9.16 的 `_ensure_table` 列数）。
每次都是靠「先分辨是哪一种，再决定改哪边」，而不是直接改代码去迁就断言。

---

### 9.24 【登记·本轮新增】特征集「限长」：文档的两半**空洞成立**，另一半是**死指标**

#### 9.24.1 文档原文

§十.2 的一行：

> 「`sigs[:20]` 丢失后续差异 → 避免静默截断；**若必须限长，标记不完整**
>   并**防止仅凭截断后的集合得出强结论**」

这一行其实是**三个要求**。逐条核对当前实现：

| 要求 | 当前状态 |
|---|---|
| 「避免静默截断」 | ✅ **成立** —— `_extract_features()` 现在**完全不截断**，30 个签名全部进特征集 |
| 「若必须限长，标记不完整」 | ⚠️ **标记在，但永远为假** —— 见下 |
| 「防止仅凭截断后的集合得出强结论」 | ✅ **空洞成立**（因为根本不截断，没有「截断后的集合」可言） |

#### 9.24.2 计数扫描的结论：`features_truncated` 在生产里**零赋值**

用逐行计数扫描（不截断）扫全仓：

```
生产代码里的 features_truncated
  [读取] zeroday_detect/variant_cluster.py:125  features_truncated: bool = False
  [读取] zeroday_detect/variant_cluster.py:418  truncated = sum(... getattr(f, "features_truncated", False))
生产侧**赋值**处数: 0
生产侧读取处数: 3

测试代码里的 features_truncated
  [赋值] tests/test_observability_gaps.py:256  feats.features_truncated = True
```

**唯一的赋值在测试里手工设置** —— 于是
`stats["truncated_features"]` 在生产里**结构性恒为 0**：
§十一 要求的「聚类…**特征截断数**」是一条**死计数器**
（与 §6.3.1 的 `inc_intel_ioc`、§7.1.6 的 `threat_intel.count` 同族）。

而它恒为 0 的原因很朴素：**当前实现根本没有上限**，
所以「截断」这个事件不会发生，标记自然永远为假。

#### 9.24.3 真正缺的是文档假设的那个**上限**

文档写「**若必须限长**」—— 暗示特征集**应该**有上限。
但 `_extract_features()` 把 `signatures` / `api_calls` / `registry_keys` /
`mitre_ids` / `network_hosts` / `files_written` **全部**塞进特征集，
**没有任何条数上限**。所以：

* 特征集大小只受**输入报告大小**约束（沙箱报告本身有界）→ 现实风险不高；
* 但「若必须限长」这个前提**不存在**，文档那一整套「标记 + 防止强结论」
  的机制**没有落在实处**。

#### 9.24.4 为什么**不**单方面加上限

加上限会**改变聚类结果**：被截断的样本与别人的 Jaccard 分布会变，
方向可能是**漏报**（一个签名极多的真实变种被截短后不再与同族样本相似）。
按「误拒与漏报同级」的原则，这类改动不该由一次审计代拍 → **登记为待决项 22**。

#### 9.24.5 新增守卫（1 passed / 1 strict xfail）

`tests/test_clustering_feature_contracts.py::TestFeatureSetIsNotSilentlyTruncated`：

* `test_signatures_are_not_silently_truncated_at_twenty`（**通过**）——
  30 个签名必须全部进特征集，把老缺陷「`sigs[:20]` 静默截断」**锁死**；
* `test_feature_set_is_bounded_and_marked_when_truncated`（**strict xfail**）——
  「特征集必须有上限且被截断时必须打标记」。
  现状下它失败（没有上限）→ xfail 成立；**一旦有人补上限，XPASS(strict) 立刻转红**，
  强制回来改本文件与报告。

> 顺带记一个本轮见过的同类形态：`test_observability_gaps.py:256`
> **手工把标志置真**来测汇总逻辑 —— 它测的是**汇总**，
> 不是**生产路径**（生产路径上那一步根本不存在）。
> 与 §9.17「守卫必须走被消费的那条路径」同族。

---

### 9.25 【已补·本轮新增】§七「异常检测验收指标」里的「每千条事件误报量」此前**根本没报**

#### 9.25.1 文档原文

§七 的「异常检测验收指标」要求至少报告 6 项，其中一项是：

> 每千条事件误报量　|　直观衡量实际运营负担

#### 9.25.2 实测（修复前）：这一项**没有任何字段承载**

`eval_datasets/evaluate_detection.py` 报了
`precision` / `recall` / `f1` / `false_positive_rate` /
`false_negative_rate` / `accuracy` —— **唯独没有「每千条事件误报量」**。

`false_positive_rate` 是个**比例**（0~1）。运维看它得不到
「每千条会响几次」这个能直接对应工作量的数 ——
而这一项恰恰是文档明确点名要的。

#### 9.25.3 修复：补两个**口径不同**的字段

| 字段 | 公式 | 含义 | 随基准率变？ |
|---|---|---|---|
| `false_positives_per_1k_benign` | `FPR × 1000` | **每千条良性事件**的误报数 | ❌ 不变（类条件量） |
| `false_positives_per_1k`（`prevalence.by_prevalence` 各档） | `1000 × (1-p) × FPR` | **每千条摄入事件**的误报数 | ✅ 变（这才是运营负担） |

两个数**不能互相替代**：FPR 不随基准率变，但「每千条事件误报量」随基准率变。
报告里同时给，读者才知道自己看的是哪一个。
文本报告的基准率分档表新增「**每千条误报**」列。

#### 9.25.4 实测输出（合成标定集）

| 检测器 | TP | FP | TN | FN | 另计 | FPR | `…per_1k_benign` | 各基准率档 `…per_1k` |
|---|---|---|---|---|---|---|---|---|
| Sigma | 8 | 0 | 10 | 0 | 2 条 excluded_suspicious | 0.000 | **0.0** | 50% / 10% / 1% / 0.1% 四档**全为 0.0** |
| 异常检测 | 1 | 0 | 2 | 2 | 3 条 inconclusive | 0.000 | **0.0** | — |
| 关联引擎 | 2 | 0 | 6 | 0 | 0 | 0.000 | **0.0** | — |

> **⚠ 这三个 0 不代表「没有误报负担」。**
> 标定集 `FP=0`，所以两个指标**恒为 0** ——
> 这是「**样本集没有误报**」的性质，
> 与「生产每千条 0 条误报」**不是一回事**。
> 必须用真实流量重测才能回答运营负担问题。
> 这条警告必须留在报告里，否则读者会把 `0.0` 读成「运营负担为零」。

#### 9.25.5 新增守卫（3 例）

`tests/test_eval_metric_completeness.py::TestFalsePositivesPerThousandIsReported`：

* `test_binary_reports_per_1k_benign` —— 二分类口径必须报 `FPR × 1000`；
* `test_per_1k_is_none_when_its_own_denominator_is_empty` —— 分母为空时给 `None`，
  **不给 0**（`0` 等于宣称「测出零误报」，而实际是「没测到」）；
* `test_prevalence_table_reports_the_operational_burden` —— 基准率分档表必须报
  `1000 × (1-p) × FPR`。

注入验红：把 `false_positives_per_1k_benign` 字段删掉 → **3 条全红**。

> 顺带记一个口径决定：为什么分母为空时给 `None` 而不是 `0` ——
> 与 §9.10 那条「错误通道不能靠默认值掩盖」同源：
> **「没测到」和「测到是 0」必须能被区分开**。

### 9.26 【已修复·本轮新增】§十三「全量回归」行首次实测：找到并修掉一处**被弱化的断言**，并把它固化成 CI 门禁

#### 9.26.1 文档原文

§十三「全量回归」行：

> 全量测试通过，并且原有测试没有通过删除断言或放宽安全要求来人为变绿

前半句（测试全绿）任何 CI 都能自动判；
**后半句此前没有任何工具在判**。

#### 9.26.2 逐 hunk 审计（首次实测）

方法：工作区相对 `HEAD` 有 **18 个**测试文件被改过 →
逐 hunk 取出被删/新增的断言行 → **逐条读真实 diff** 判定
（行级 diff 会把「重写」和「弱化」混在一起，必须读原文）。

结果：**16 条被删断言**里，**15 条是真加强或语义修正**，**1 条是真弱化**。

真弱化的那一条 —— `tests/test_ingest_pipeline.py::test_run_one_return_keys_match_facade`：

```diff
-        assert set(http_dict.keys()) == {
-            "status", "event_id", "event_type", "severity", "anomaly", "sigma",
-        }
+        assert {
+            "status", "event_id", "event_type", "severity", "anomaly", "sigma",
+        }.issubset(http_dict.keys())
```

子集断言**丢掉了「不得出现意外键」这一条**。
而 `RunResult` 有 10 个字段，其中 **7 个**
（`detect_ms` / `persist_ms` / `dispatch_ms` / `detector_errors` /
`error_class` / `error_code` / `idempotent`）
**本就不该**出现在 HTTP 兼容载荷里 ——
键集合契约就是拦住这件事的那道闸。

> 另外 15 条里有两条值得单独记：
>
> * `test_inc_metrics.py` 的 5 条绝对值断言 `== 1.0` 被改成**前后差值 == 1.0** ——
>   那是**加强**：原写法要求「这个进程级计数器从没被别的东西碰过」，
>   单跑绿、全量里只要前面有别的用例动过同一个计数器就红
>   （2026-10-18 由 `test_capability_tile_counts.py` 踩到过）。
> * `test_any_fallback_guard.py` 的 `assert calls[0][0] == "block_ip"`
>   被改成 `assert calls == []` + 审批工单断言 ——
>   那条的**方向是收紧的**：原断言之所以一直通过，
>   是因为 conftest 没固定 `RESPONSE_POLICIES_DIR`，
>   YAML 策略加载失败、回退到**代码内置兜底策略**（那条没有审批要求），
>   于是 `block_ip` 被「自动执行」——
>   **它一直在验证降级路径，从未验证真实策略。**
>
> 这两条都**不是**「为变绿而放宽安全要求」。

#### 9.26.3 修复

* 复原为**精确键集合**断言（并把新增的 `eventId` 计入）；
  `tests/test_ingest_pipeline.py` 因此 **11 → 12 例**。
* 补 `test_run_one_failure_path_expands_the_key_set_exactly`（1 例）：
  失败路径必须**恰好**多出 `process_status` / `retryable` / `error`，
  且 `error_class` / `error_code` **不得**进载荷。
* 新建 `tests/test_http_dict_contract.py`（**14 例**）：钉住 `as_http_dict()` 的**精确**键集合
  （成功 / 带 eventId / 空 eventId 被省掉 / 失败 / 空 error 被省掉 /
  内部字段不泄漏 / 四种 `process_status` 各自登记），
  外加**前提守卫**「三种形态的键集合必须互不相同」——
  少了这条，某天有人把条件判断删成「总是全给」时，
  「精确等式」会因为期望值没跟着改而**照样绿**。

**注入验红（3 处，逐条点名跑对应性质的用例）：**

| 注入 | 点名后红掉的用例 |
|---|---|
| `detect_ms` 进了 HTTP 载荷 | `test_internal_only_fields_never_leak` |
| `eventId` 条件失效（空串也进载荷） | `test_empty_event_id_is_omitted_not_emitted_as_blank` |
| 失败路径条件失效（success 也带出 `process_status`） | `test_success_process_status_is_never_emitted` |

三次都红了，且**红的就是对应性质自己的那条用例**
（不是别的用例先红把结论遮住 ——
第一版验证脚本带 `-x`，在首个失败处就停了，**报不出「是不是这条性质抓到的」**，
已改成「点名跑 + 全量跑」两遍）。
还原按字节 + sha256 校验一致。

#### 9.26.4 把这次人工审计固化成 CI 门禁

新增 `tools/assert-no-assert-weakening.py`
（与既有的 `tools/assert-junit-no-skip.py` 同级），
并接入 `.github/workflows/ci.yml` 的 `backend-test` job
（该 job 的 `checkout` 需 `fetch-depth: 0` ——
浅克隆拿不到 `origin/<base>`，`merge-base` 会失败）。

判据只覆盖**能明确识别的弱化**，不猜语义：

| 弱化签名 | 例子 |
|---|---|
| 集合相等 → 子集 | `assert set(x) == {…}` → `assert {…}.issubset(x)` |
| 相等 → 存在性 | `assert x == 1` → `assert x is not None` / 裸 `assert x` |
| 精确长度 → 下界 | `assert len(x) == 3` → `assert len(x) >= 1` |
| 成员 → 存在性 | `assert a in b` → `assert a is not None` |
| 期望异常 → 取消 | `with pytest.raises(E):` 被删且同函数内没有新的 `pytest.raises` |

判不准的一律归 `REPLACED`，**列进「需人工核对」清单，不自动判红** ——
**误报会让人开始忽略这个门禁，那比没有门禁更糟**。

三类结论：`WEAKENED` / `DELETED` **判红**；
`REPLACED` / `TEST_REMOVED` / `MOVED` 只列出。

**门禁自己带 7 个已知答案自检**：
4 个已知弱化必须判成 `WEAKENED`，3 个已知加强必须判成 `REPLACED`。
自检不过 → **退出码 2**，明确报「分类器自己坏了」，
**不给出「通过」结论**（崩了 ≠ 查过了）。

**注入验红（3 处）：** 集合相等→子集 / 相等→存在性 / 期望异常→取消 ——
三处都被判成 `WEAKENED`、退出码 1，还原后 sha256 一致。

#### 9.26.5 自曝：这个门禁的判据被我自己推翻过三次

**第一次：逐 hunk 比对漏判。** 注入的弱化长这样：

```
assert set(http_dict.keys()) == {      ← 被删
# 中间隔了十来行注释
assert {                                ← 新增（被 -U0 切进另一个 hunk）
}.issubset(http_dict.keys())
```

`git diff -U0` 把这两处切成了**两个 hunk** →
「被删的强断言」和「新增的弱断言」永远碰不到一起 →
判成「有替代断言」，放过去了。

> **教训：弱化和它的替代形态完全可能被无关改动隔开。**
> 比对单位必须是**文件**（再按**函数**归组），不是 hunk。

**第二次：自检自己走错了路径。** 自检用例把**原始行**直接当语句传进去，
而真实路径要先按**括号配平**切分逻辑语句 ——
于是自检在测一条**不存在的路径**。
改法：自检走**与真实路径同一套**的切分。

**第三次：崩溃与检测同码。** 工具自身抛异常时退出码也是 `1`，
而 `1` 在这个工具里表示「发现了弱化」 ——
**一次崩溃会被读成一次检测**。
已改为：崩溃走退出码 `2`，并打印「本次运行**没有结论**」。
同族的还有一条：基线 ref 不存在时也走 `2`，
因为「**查不到基线 ≠ 没有弱化**」。

#### 9.26.6 门禁的边界（写清楚，免得被当成万能）

* **只能发现相对基线被改弱的断言。**
  **新增代码里的弱化没有基线可比** ——
  本轮有一处注入打在**新增**测试函数里，门禁就抓不到（已如实记在注入记录里）。
* 只判**形式弱化**。「把 `== 1` 改成 `== 2`」是数值放宽，判不出来
  （归 `REPLACED`，进人工核对清单）。
* `TEST_REMOVED`（整个测试函数被删**或被改名**）与
  `DELETED`（同函数内断言被删且无替代）**分开报** ——
  删测试是另一类决策，不与「弱化」混为一谈。
* 判据按**表达式**匹配而不是按整行文本 ——
  整行比对会把「一条加强 + 一条无关」误判成「什么都没变」。

#### 9.26.7 顺带更正两处**本报告自己**的过期结论

**（一）「单独跑 6/6 通过」是错的。**

§九 的头部与 §9.9 都写着：`test_audit_pipeline_path_creates_case`
「本轮实测**单独跑 6/6 通过**、全量跑时可能失败」。

本轮实测（每种组合跑 6 次）：

| 组合 | 失败次数 |
|---|---|
| `test_case_automation.py` **单跑** | **2 / 6** |
| + `test_http_dict_contract.py`（本轮新建） | 0 / 6 |
| + `test_ingest_pipeline.py`（既有） | 2 / 6 |
| + `test_review_anomaly.py`（既有） | 2 / 6 |

**单独跑也会红**，与「是否全量跑」无关。
所以那句话描述的因果（「全量跑时可能失败」）**方向就不对** ——
它把一个**在任何组合下都可能发生**的间歇失败，
说成了「只有全量跑才会犯」。

> 顺带记一个本轮踩过的坑：**单次观察不构成因果**。
> 我第一次看到「加上我的新文件就红」时，直接下了「是我的文件引入的」；
> 紧接着用**同样的命令**再跑一次却全绿。
> 于是又下了「那是间歇、与我无关」的结论 —— **两次都判错了**，
> 因为两次都只有 **1 个样本**。
> 真正的判据是**多次重复**：每种组合各跑 6 次，才看得出
> 「单跑 2/6、加我的文件 0/6、加既有两个文件各 2/6」——
> 我的新文件**并没有**提高失败率，而「单跑也会失败」这个事实
> 只有多次重复才看得出来。
>
> 这是「全量跑偶尔红、单独跑总是绿 → 先怀疑外部依赖」那条的**加强版**：
> **「单独跑总是绿」本身也要多次重复才能成立。**

机制（已定位，非猜测）：

```
auto_create_case 的 fire-and-forget create_task
  └─ 与测试的轮询会话【共用 StaticPool 的同一条连接】
       └─ 后台任务未提交的 INSERT 可能被轮询会话的回滚丢弃
            └─ 随后的 UPDATE 影响 0 行
                 └─ case_manager.py:787 记 "auto-dispatch failed"
                      └─ case 不存在 → 断言 "应自动建 case" 失败
```

**生产不受影响**：postgresql + asyncpg，真实连接池，
建单与派单在**同一事务**里（`log_ingestion.py:109-112` 同一个 `case_session`）。
这是**测试库隔离**问题（待决项 17），三条修复路线已实测均不可行（§9.7），
本轮**未触碰** `tests/conftest.py` 与 DB 会话层。

**（二）计数核对脚本自己的正则漏了一种写法。**

核对脚本原来用「文件名 + 空白/星号 + 数字 + 例」提取断言，
于是「`tests/xxx.py`（**14 例**）」这种**中文全角括号**的写法
**根本匹配不上** —— 那条断言等于**没进检查范围**。

把分隔符放宽成 `[^0-9A-Za-z]{0,6}` 后，覆盖从 25 个文件升到 **44 个文件**
（实际收集 **187 个文件 / 2525 条**），并当场查出 **2 处真过期**：

| 文件 | 报告原写 | 实际 | 处理 |
|---|---|---|---|
| `test_eval_metric_completeness.py` | 7 例 | **13 例** | 已更正 |
| `test_http_dict_contract.py` | 13 例 | **14 例** | 已更正 |

另有 2 处「不一致」是脚本取了**历史旧值**
（报告写的是「由 9 例扩到 **13 例**」，本身正确）——
属脚本「取首次出现」的规则，不是报告错。

> **这与本会话早前那次「检索输出上限把『有』误判成『无』」是同一族**：
> **否定/肯定结论的覆盖面，取决于检索表达式本身。**
> 换一个分隔符写法，结论就从「核过了」变成「没核过」——
> 而两者在输出里长得一模一样。

#### 9.26.8 §五 的说法随之更正

§五 原文「**没有任何一条断言被删除或放宽。**」已更正为**审计过的逐条结论**
（15 条真加强 / 1 条真弱化且已修复），并在 §五 里写明：
「本轮没有引入」**不等于**「仓库里没有」——
原话是一句**全称判断**，而它需要的是一个**审计过的结论**。

---

### 9.27 【已补·本轮新增】§七「异常检测验收指标」的 6 项表**从未被映射**，其中「检测延迟」**既没算也没报**

#### 9.27.1 文档原文

§七 的「异常检测验收指标」：

> 至少按新实体、成熟实体、不同部署规模、不同时间窗口分别报告：
>
> | 指标 | 目的 |
> |---|---|
> | Recall | 真实异常中有多少被发现 |
> | False Positive Rate | 正常事件被错误告警的比例 |
> | 每千条事件误报量 | 直观衡量实际运营负担 |
> | 检测延迟 | 从异常出现到被识别的时间 |
> | 冷启动检测表现 | 检查新 IP 或新资产不会系统性失明 |
> | 重放一致性 | 固定事件与基线快照时，结果是否可复现 |
>
> 这比单纯确保输出分数落在 0–1 之间更重要。

#### 9.27.2 实测：这张表**从未被映射过**，第 4 项在实现里根本不存在

报告此前只覆盖了 §四「量化评估结果」，**没有**这张表。逐条核对实现：

| 指标 | 修复前状态 |
|---|---|
| Recall | ✅ `detected_recall.recall` |
| False Positive Rate | ✅ `false_positive_rate` |
| 每千条事件误报量 | ❌ **根本没报** → §9.25 已补 |
| **检测延迟** | ❌ **既没算也没报** → 本节已补 |
| 冷启动检测表现 | ⚠ 机制齐（`COLD_START_MIN_SAMPLES=5` / `COLD_START_SCORE_CAP=0.59` / `error_code="cold_start_no_evidence"`），但**没被单独报告** → 本节已补分档 |
| 重放一致性 | ✅ `tests/test_anomaly_replay_determinism.py`（**41 例**）—— 但这个文件**报告里从未提过** |

#### 9.27.3 「检测延迟」为什么**能**算，而代码注释说「根本算不出来」

`anomaly_detector.py` 的注释里原写着：

> §十三 要求的「检测延迟 = 从异常出现到被识别的时间」
> 在本模块**根本算不出来**，因为没有起点。

**这句话过强了。** 实测：

* `analyze()` 里三个时间**本来就在同一个作用域**：
  `analysis_ts = time.time()`（分析时刻）、
  `now_ts`（事件时间，事件自带时间戳时）、
  `received_ts`（接收时间，事件自带时）。
* 「**异常出现** → 识别」的起点是**事件时间** ——
  事件自带时间戳时它是有的。
* 真正**没有**起点的是「**到达** → 识别」这一段：
  实测**全仓生产代码里没有任何一处写入接收时间字段**，
  `received_at` 恒为 `None`。

两段必须**分开**算、分开报。混成一条就会把「不知道」读成「很快」。

#### 9.27.4 改动（**纯披露**，不碰任何判定）

`anomaly_detector.py`：

* 新增 `detection_latency_seconds`（事件时间 → 分析时刻）与
  `ingest_latency_seconds`（接收时间 → 分析时刻），
  写进**既有的** `analysis_window` 通道
  （不新建只有测试看得见的通路）；
* 事件时间缺失时 `detection_latency_seconds = None` ——
  **不用墙钟顶替**：那条分支里 `now_ts = time.time()`，相减会得到 ~0，
  等于**谎报「延迟 0 秒」**，而真实情况是「不知道这条事件什么时候发生」。

`eval_datasets/evaluate_detection.py`：

* 每条异常行带上两个字段；
* 新增 `latency_summary()`：可算/不可算条数 + min/中位/max；
  分母是**进入二分类统计的样本数**，一条都算不出来时给 `None` 而不是 `0`；
* 新增 `cold_start_breakdown()`：按**基线样本量**与
  `COLD_START_MIN_SAMPLES` 的关系分「成熟实体 / 新实体·冷启动」两档，
  并把新实体档里「被判成 `not_detected`」的样本**点名列出**
  （那是**结构性失明** = 漏报，不是「不可判定」）；
* JSON 出口加 `anomaly.latency` 与 `anomaly.cold_start` 块；文本报告各加一段。

**没有碰**：`status` / `score` / `dimensions` / `effective_weights` / `reasons`。
（`reasons` 喂 `veto_gates._STRONG_SIGNAL_REASONS`，
指标名进去就可能被当成强信号 → 判定被改。）

#### 9.27.5 实测输出

```
检测延迟（事件时间→分析时刻）：7 条可算，1 条不可算
  实测 min=35427.568s 中位=36867.957s max=67828.056s

按基线是否成立分档（§七 要求「按新实体、成熟实体…分别报告」）：
  成熟实体（基线 ≥ 5 样本）：5 条，检出 1，不可判 0，阴性 4
  新实体 / 冷启动（基线 < 5 样本）：3 条，检出 0，不可判 3，阴性 0
  ✅ 新实体档没有出现「判成 not_detected」——新 IP 不会被系统性当成阴性
```

不可算的那 1 条正是 **ANO-I-02**（事件无时间戳）—— 与「缺就是缺」一致。

> ⚠ **这些数字在标定集上不是链路延迟。**
> 标定集的事件时间锚在**固定基准** `BASE_DT`（2026-10-19 02:00 +08:00），
> 于是「分析时刻 − 事件时间」量到的是
> **标定集锚点到本次运行时刻的年龄**。
> 这里报它只有一个目的：**证明这条指标真的被算出来了**。
> **真实延迟必须从生产流量测** —— 登记为待验证项。

新实体档的结果值得单独记一句：**3 条全部判 inconclusive、0 条被当成阴性**。
这正是「冷启动检测表现」这条指标想要的结论 ——
新 IP 不会被系统性当成「干净」；
但它同时说明**新实体永远拿不到 `detected`**（这是待决项 18 的另一面：
阈值 `ANOMALY_SCORE_THRESHOLD=0.60` 落在标定集**召回下界**外，
网格上界 0.4 比召回下界 0.4357 还低；
⚠ 而 §9.60 已证明**降阈值补不上** —— 完整可行区间是空集）。

#### 9.27.6 仍未覆盖的两维（**登记为待补**，不装作已覆盖）

§七 要求「至少按新实体、成熟实体、**不同部署规模**、**不同时间窗口**分别报告」。

| 维度 | 状态 |
|---|---|
| 新实体 / 成熟实体 | ✅ 本轮补上分档 |
| **不同部署规模** | ✅ **§9.28 补上**（3 档规模 × 3 档窗口的矩阵） |
| **不同时间窗口** | ✅ **§9.28 补上**（同矩阵的列维度） |

这两维要补就得**扩充标定集**（造不同规模/窗口的基线），
属于数据工作而非代码工作 → 与 §十三 的「真实黄金样本」缺口一起登记。

#### 9.27.7 新增守卫（17 例）

`tests/test_detection_latency_metric.py`（**17 例**）：

* `TestDetectionLatencyIsComputed`（5 例）——
  延迟 = 事件时间→分析时刻的差；事件时间缺失时为 **None 而非 0**；
  **前提守卫**：把墙钟钉在远离事件时间处，延迟必须随之变化
  （否则某天改成 `analysis_ts - time.time()`，它会恒为 0 而**照样绿**）；
  接收时间在/不在时 `ingest_latency_seconds` 的两个走向；
  两段延迟互不串扰。
* `TestTheMetricIsPureDisclosure`（3 例）——
  `reasons` 里不得出现 latency（`reasons` 喂 veto gates）；
  带/不带 `received_at` 时判定**逐项相同**；
  指标必须走**既有的** `analysis_window` 通道（→ `DetectionResult` → HTTP 载荷）。
* `TestEvaluatorReportsTheLatency`（3 例）——
  评估器每行都带字段；`可算 + 不可算 == 总条数`；
  **不可算的那条必须就是 ANO-I-02**（无时间戳那条），不是随机的；
  一条都算不出来时 min/中位/max 必须是 `None` 而非 `0`。
* `TestColdStartIsReportedSeparately`（5 例）——
  两档必须把样本**分完**；新实体档**不得**出现 `not_detected`
  （这是「冷启动检测表现」的可执行形式）；真出现时必须**点名**列出；
  分档门槛必须用**生产常量** `COLD_START_MIN_SAMPLES`，不得在评估器里另写一个数；
  未覆盖的两维必须在输出里**点名**。

**注入验红（3 处，逐条点名）**：

| 注入 | 点名后红掉的用例 |
|---|---|
| 延迟取自墙钟而不是事件时间 | `test_the_latency_tracks_the_event_time_not_the_wall_clock` |
| 事件时间缺失时给 0 而不是 None | `test_latency_is_none_when_the_event_time_is_missing` |
| 指标没写进 `analysis_window` | `test_the_metric_is_published_through_the_existing_channel` |

三次都红了，且红的就是**对应性质自己的那条用例**；还原后 sha256 一致。

#### 9.27.8 顺带更正两处过期/缺失

* §四 开头写「`tests/test_p3_detection_calibration.py`（**22 例**回归）」——
  实为 **29 例**（报告自己在 §9.3 写的就是 29）。已更正。
* `tests/test_anomaly_replay_determinism.py`（**41 例**）——
  它正是 §七「重放一致性」与「冷启动检测表现」两项的主力守卫，
  但**报告此前从未提到这个文件**。已补进 §一 的异常检测行与计数核对范围。

---

### 9.28 【已补·本轮新增】§七 剩下的两维（部署规模 / 时间窗口）补齐 + 否定结论的系统性复核

#### 9.28.1 上轮登记的缺口

§9.27.6 登记了 §七 要求的四个维度里**还没覆盖**的两维：

| 维度 | §9.27 时的状态 |
|---|---|
| 新实体 / 成熟实体 | ✅ §9.27 补上分档 |
| **不同部署规模** | ❌ 标定集没有按部署规模分层的样本 |
| **不同时间窗口** | ❌ 标定集没有按窗口长度分层的样本 |

本节把这两维补上。**做法是另起一套测量，不动既有标定集** ——
§9.3 的阈值扫描（**召回下界** `[0, 0.4357)`，不是可行区间 —— 见 §9.60）
来自既有 8 条标定集，
两处测量互不污染。

#### 9.28.2 新增 `eval_datasets/evaluate_scale_window.py`

矩阵 = **部署规模（行）× 时间窗口（列）**：

| 行（部署规模） | 基线 | | 列（时间窗口） |
|---|---|---|---|
| `young_12h_x20` | 12 小时 × 20 条/小时 | | `1d` / `7d` / `30d` |
| `steady_24h_x50` | 24 小时 × 50 条/小时 | | |
| `aged_168h_x10` | 168 小时 × 10 条/小时 | | |

每格扫一串突增倍数（`1.2 / 1.5 / 2 / 3 / 4 / 6`×），报出
**是否检出 / 得分 / σ / 基线样本量**，并给出**最小可检突增倍数**。

**必须钉住时钟**：窗口淘汰用的是**墙钟**
（`anomaly_detector._update_baseline` 的
`cutoff = time.time() - window_days * 86400`），
而矩阵锚在固定历史时刻 —— 不钉住时钟的话，
同一份代码在不同时间跑会淘汰掉不同的桶，矩阵就**不可复现**。
（与 `tests/test_anomaly_replay_determinism.py` 的做法一致。）

#### 9.28.3 实测结果（可复现）

```
规模                           窗口 1d        窗口 7d        窗口 30d
young_12h_x20     1.2x ✓0.730  1.5x ✓0.774  2x..6x ✓0.774
steady_24h_x50    1.2x ✓0.774  1.5x..6x ✓0.774
aged_168h_x10     1.2x ✓0.567  1.5x ✓0.690  2x..6x ✓0.774
                  1.2x ✓0.597  1.5x ✓0.731          （7d / 30d）
```

三条结论：

**（一）速率突增维度上，异常得分会饱和。**
`dim = min(1.0, dev_sigma / 5.0)`，而 σ 在 3× 及以上就撞上夹紧上限 `10.0` ——
于是 **1.5× 与 6× 突增的得分完全相同（0.774）**。
得分在这个维度上**没有分辨率**：
读者看到 0.774 无法知道这是 2 倍还是 6 倍。
（判定用的是 `score > 阈值 or sigma > 3` 的**或**语义，
所以 1.2× 也能检出 —— 得分 0.567 < 阈值 0.60，但 σ > 3。）

**（二）⚠ 真发现：短窗口会让**老实体**的得分变低 —— 方向是漏报。**

同一个 168 小时老实体、同一个 1.2 倍突增：

| 窗口 | 基线样本量 | 得分 |
|---|---|---|
| **1d** | **24**（168 小时的老基线被砍到只剩 1 天） | **0.567** |
| 7d / 30d | 168 | **0.597** |

原因：窗口比基线年龄短 → 老基线被淘汰 → 统计维度的证据变弱 → 得分变低
→ **更容易漏报**。这是**配置选择的后果**，不是缺陷：
但它意味着「把窗口调短」这个看似无害的运维操作会**缩小漏报面**，
必须让人知道。

**（三）部署规模维度：低速率实体更难被察觉。**
`aged_168h_x10`（10 条/小时）在 1.2× 突增下得分 0.567~0.597，
而 `young_12h_x20`（20 条/小时）是 0.730 —— 同样倍率，低速率实体的 σ 更小
（σ ∝ √速率）。

#### 9.28.4 新增守卫（9 例 → §9.29 又加 5 例，现 **14 例**）

`tests/test_scale_window_matrix.py`（**14 例**；其中 9 例属本节，5 例见 §9.29.6）：

* `TestMatrixCoversTheTwoDimensions`（2 例）—— 3 规模 × 3 窗口 = 9 个组合
  全部测到，每格跑满突增阶梯；每格必须带齐测量字段。
* `TestTheWindowDimensionIsReal`（3 例）——
  **窗口维度必须真的影响什么**（1 天窗口必须把 168 小时老基线砍掉，
  否则这一维只是装饰，报告成「已覆盖」是骗人）；
  短窗口得分更低（本轮实测，方向是漏报）；
  窗口比基线年龄还长时**不该**有差别。
* `TestTheMatrixIsReproducible`（2 例）—— 两次跑结果必须逐项相同；
  `pinned_clock` 退出后必须还原 `time.time`。
* `TestTheMatrixDoesNotContaminateTheCalibrationSet`（2 例）——
  既有标定集仍必须 8 条；§9.3 的扫描上界仍必须是 `0.4357`、`current = 0.6`、
  `current_is_perfect = False`。

**注入验红（3 处，逐条点名）**：

| 注入 | 点名后红掉的用例 |
|---|---|
| 窗口不裁剪老基线（一律用 30 天） | `test_a_short_window_prunes_an_aged_baseline` |
| 每次矩阵运行用不同的时钟 | `test_two_runs_give_identical_results` |
| 污染既有标定集（`run_anomaly` 多返回一条） | `test_the_main_evaluator_still_has_eight_anomaly_cases` |

三次都红了，红的就是**对应性质自己的那条用例**；还原后 sha256 一致。

> **注入自证的一个坑（这轮踩到）**：第一版 J2 用 `random()` 给时钟加抖动，
> 结果「没转红」—— 但那是**运气**：两次矩阵恰好算出了相同结果。
> **注入若依赖随机量，「没转红」就不能当证据。**
> 改成确定性注入（每次矩阵运行时钟偏移一小时）后立刻转红。
>
> 与 §9.26.5 那条「自检自己走错路径」同族：
> 注入自证的**证据链**本身也要经得起检验。

#### 9.28.5 顺带做的一件事：把报告里**剩余的否定结论**逐条复核

§9.20 的教训是「否定结论必须用不截断的扫描来下」。
本轮把报告里**剩下的**「此前零命中」类否定结论逐条用
`git grep -c`（给出每文件精确命中行数，不截断）复核，
**且扫的是基线 `HEAD` 的 `tests/`**（101 个文件）——
「此前零回归」说的是**修复之前**没有用例覆盖它。

| 报告里的否定结论 | 复核结果 |
|---|---|
| §9.16.2「DNS 解析到私网 IP 必须被拒」此前无覆盖 | ✅ 成立（`getaddrinfo` 0 命中） |
| §9.18.2「不可识别时不得输出 ACE」此前无回归 | ✅ 成立（`no_backdoor` / `unobserved_confounding` / `backdoor_set` 全 0） |
| §9.19.2「A→B 与 B→A 不得同时输出」此前无回归 | ✅ 成立（`conflict_candidates` 0 命中） |
| §9.22.2「缺失 task_id ⇒ 提交失败」此前无回归 | ✅ 成立（`missing_task_id` / `validate_task_id` 全 0） |
| §9.23.2「相似度显示值 vs 判定值」此前无回归 | ✅ 成立（`similarity_display` / `meets_threshold` 全 0） |

> **第一遍复核报了一处「违例」**：§9.19.2 的模式 `consensus(` 命中 1 次
> —— 但那命中的是 `test_rag_hybrid.py::test_fusion_prefers_consensus`，
> 是 **RAG 的同名方法**，与 `causal_chain/ges.py::consensus` 毫无关系。
> **这正是报告 §7.1.5 自己记过的坑**（按方法名匹配会把同名对象算进来）。
> 收紧模式后归零。
>
> 教训：**否定结论的「不成立」也可能只是模式写得太宽** ——
> 两种错误（漏报与误报）都要单独处理，不能只盯着一种。

#### 9.28.6 仍未解决 / 仍需你拍板的

* **本节的三条结论都来自合成基线**，量的是「配置组合下的表现」，
  **不是生产误报率** —— 真实指标仍需真实流量（§三「待验证」）。
* **窗口维度的「适应速度」**：✅ **§9.29 补上**（有趋势基线的适应矩阵）。
* **得分饱和**（结论一）要不要改，是**打分口径**的取舍：
  放宽 `dim` 的夹紧或改用非线性的 σ→分映射都会改变所有既有分数，
  属于**检测方向**的改动 → 不单方面做，登记为**待决项 23**。

---

### 9.29 【已补·本轮新增】基线**适应速度**：合法的新常态流量会被误报多久

#### 9.29.1 上轮登记的缺口

§9.28.6 登记：

> **窗口维度的「适应速度」没测**：矩阵用的是**均匀速率**基线，
> 于是窗口只改变**基线样本量**，不改变检出结果。
> 要测出适应速度需要**有趋势**的基线（实体先安静后繁忙），本轮未做。

本节把它做掉。

#### 9.29.2 场景

实体先处在旧常态（50 条/小时 × 12 小时），Δ 小时前**换到新常态**
（100 条/小时），然后探一条**新常态**的流量。

探针是**合法**的流量 —— 被报成 `detected` 就是**误报**。
问的是：换常态之后要过多久，基线才把新常态认下来？

实现：`eval_datasets/evaluate_scale_window.py` 新增
`run_adaptation_matrix()`（Δ ∈ {1,2,4,8,12,24,48} 小时 × 窗口 {1,7,30}d）。

#### 9.29.3 实测结果

```
换常态后经过      窗口 1d        窗口 7d        窗口 30d
1 小时        误报 0.774      误报 0.774      误报 0.774
2 小时        误报 0.774      误报 0.774      误报 0.774
4 小时        误报 0.738      误报 0.738      误报 0.738
8 小时        误报 0.572      误报 0.572      误报 0.572
12 小时       已适应 0.472     已适应 0.472     已适应 0.472
24 小时       已适应 0.060     已适应 0.321     已适应 0.321
48 小时       已适应 0.060     已适应 0.211     已适应 0.211
```

#### 9.29.4 三条结论

**（一）合法的新常态流量会被误报至少 8 小时。**
矩阵阶梯是 {1, 2, 4, 8, 12, 24, 48} 小时：
**8 小时时仍在被报成异常，12 小时时已不再被报** ——
所以真实适应时间落在 **8 ~ 12 小时之间**（阶梯粒度所限，不能再精确）。
这段时间里新常态的流量**持续**被报成异常 ——
**这是纯误报**，而且量不小（100 条/小时 → 这 8~12 小时就是 800~1200 条误报）。

**（二）⚠ 触发误报的是「σ>3 旁路」，不是得分超阈值。**
判定规则是 `score > 阈值 or sigma > 3` 的**或**语义。
Δ=8 小时那格：得分 **0.572 ≤ 阈值 0.60**（没过），
但 σ = **3.59 > 3.0** → **旁路**把它报成了异常。

这条决定着「调阈值能不能消掉这批误报」——**不能**：
得分本来就没超阈值。这与待决项 18（阈值 0.60 落在可行区间外）
是**两件不同的事**，不能混为一谈。

**（三）窗口越长，基线越难忘掉旧常态 —— 但判定上看不出来。**
Δ=24 小时时：

| 窗口 | 保留的基线 | σ | 得分 |
|---|---|---|---|
| **1d** | 24h **全是**新常态（旧常态被整个切掉） | **0.0** | **0.060** |
| 7d / 30d | 仍留着 12h 旧常态 | 1.83 | 0.321 |

得分差了**五倍多**，但两者的最终判定**都是「不报」** ——
**差异被阈值吃掉了**。这正是待决项 23（得分在突增维度上饱和）
的另一个面向：**得分的分辨率不足以把配置差异传到判定上**。

#### 9.29.5 自曝：本轮真犯了一个 bug，被前提守卫抓住

第一版把桶映射写反了：

```python
# 错的：hours_since_switch = total_hours - h  算的是「距最老桶多久」
rate = (ADAPT_NEW_RATE if hours_since_switch >= delta_hours else ADAPT_OLD_RATE)
```

结果「旧常态」反而占据了**最近**的历史，于是矩阵显示
「换常态 1 小时就适应」——与直觉完全相反。

抓住它的不是任何复杂判据，是一条**前提守卫**：

> **换常态才 1 小时，基线几乎全是旧常态，探针必须被报成异常。**

修好后重写场景即转绿。这条守卫现在固定在
`test_one_hour_after_the_switch_the_new_regime_must_be_flagged`，
并用**注入**（把映射写回去）验证过它会红。

> 与 §9.28.4 那条「注入自证要用确定性」同族：
> **前提守卫的价值在于它能在场景写反时立刻喊出来**，
> 而复杂判据往往在场景写反时照样「通过」。

#### 9.29.6 新增守卫（14 例，`tests/test_scale_window_matrix.py`）

在 §9.28 的 9 例之上新增 5 例（`TestAdaptationSpeedIsMeasured`）：

* `test_one_hour_after_the_switch_the_new_regime_must_be_flagged` ——
  **前提守卫**（见 §9.29.5）；
* `test_the_score_falls_as_the_new_regime_settles_in` ——
  得分随 Δ **单调下降**（反了就说明场景又反了）；
* `test_a_short_window_forgets_the_old_regime_sooner` ——
  1d 窗口在 Δ=24h 时 σ 必须为 0（旧常态被整个切掉），
  7d 窗口必须仍 > 0，且短窗口得分更低；
* `test_the_false_positive_is_triggered_by_the_sigma_bypass` ——
  必须存在「得分没过阈值、却因 σ>3 被报成异常」的格子；
* `test_the_legitimate_new_regime_eventually_stops_being_flagged` ——
  最终必须能适应（否则基线永远学不会新常态）。

**注入验红（3 处，逐条点名）**：

| 注入 | 点名后红掉的用例 |
|---|---|
| 桶映射写反（本轮真犯的） | `test_one_hour_after_the_switch_the_new_regime_must_be_flagged` |
| 窗口不截断（一律 30 天） | `test_a_short_window_forgets_the_old_regime_sooner` |
| σ 旁路分类恒为 False | `test_the_false_positive_is_triggered_by_the_sigma_bypass` |

三次都红了，红的就是**对应性质自己的那条用例**；还原后 sha256 一致。

> **成本**：这个守卫文件单独跑 **28.8 秒**（两个 module 级 fixture
> 各跑一遍矩阵：54 格 + 21 格）。占全量回归约 **9%**。
> 记在这里是因为「**守卫贵到没人愿意跑，就等于没有守卫**」——
> 这个代价目前可接受，但若再扩矩阵必须先测成本。

#### 9.29.7 仍需你拍板的

**（一）新常态误报至少 8 小时（实际 8~12 小时），要不要缓解？**
这是**误报**方向，改法有几种（换常态检测、慢启动抑制、要求运维手动重置基线），
每一种都会动判定逻辑 → 属检测方向 → **不单方面做**，
登记为**待决项 24**。

**（二）σ 旁路该不该保留？**
`score > 阈值 or sigma > 3` 的**或**语义让「得分没过阈值」的事件
仍然被报成异常。这是 §9.29.4 结论（二）的成因。
把 σ 旁路改成「仅当得分也在同一量级时才生效」之类的收紧，
会减少误报但也会减少真阳性 → 与待决项 23 同族，一起上交。

---

### 9.30 【已修复·本轮新增】变种聚类的「陈旧边」：增量构建 ≠ 全量重建

#### 9.30.1 文档原文（§十.2 的三条验证要求）

> 最终需要验证：相同样本集合仅改变输入顺序，不会产生不可解释的簇变化；
> 无效或空特征不会人为形成同一家族；相似度、簇 ID 和原始样本均可以追踪。

第 2 条（空特征）此前已覆盖，第 3 条见 §9.23。
本节查的是第 1 条 —— 以及它的一个**更隐蔽的变体**。

#### 9.30.2 先复核：纯顺序变化**已成立**，且已有守卫

独立实测（5 个样本、**120 种插入顺序**全部跑一遍）：

```
与基准不同的排列数 = 0
基准 components = [['hA', 'hB'], ['hC'], ['hD', 'hE']]
```

顺序无关性**成立**，机制是双层保障：
`_components()` 把遍历起点/成员/分量顺序全部排序，
`_cluster_id_for()` 取 `min(hashes)`（内容寻址）。

而且这一条**已有行为守卫**：
`tests/test_clustering_feature_contracts.py::test_partition_and_cluster_ids_do_not_depend_on_input_order`
（连它的灵敏度都实测记录过：只拆一层仍绿，两层同时拆才红）。

**所以本节发现的不是「顺序依赖」** —— 顺序无关性是真的。
发现的是它的**另一个变体**。

#### 9.30.3 真缺陷：同一 hash 被不同特征覆盖时，**旧边残留**

`add_sample(analysis, sample_hash="")` 允许调用方**显式**指定 hash ——
此时 hash **不再由特征派生**（只有不传时才走 `_content_hash(analysis)`），
于是**同一个 hash 可以带不同特征被提交多次**。

修复前的 `add_sample` 只做两件事：覆盖特征、记一次重复计数。
**按旧特征算出来的边没有被清掉。**

实测（修复前）：

```
dup(V2) 与 X 的 Jaccard = 0.0
全量重建（按最终特征）      : [['X'], ['dup']]
增量构建（V1→V2 覆盖）      : [['X', 'dup']]     ← 不一致

增量构建把 Jaccard=0 的两个样本判成同族：True
```

两个后果：

1. **错误的家族归属**：当前特征毫无重叠（Jaccard=0）的两个样本，
   仍被报成同一个变种家族。
2. **同样本集合给出两种结果**：按**最终状态**看，
   这批样本的集合是确定的（dup 的特征是 V2、X 的特征是 alpha），
   但**增量构建**与**全量重建**给出**不同的簇划分** ——
   而 §十.2 要求的恰恰是「相同样本集合……不会产生不可解释的簇变化」。

**影响面**：`variant_cluster` 的聚类能力**生产零调用方**（§7.1.4），
所以今天没有生产影响；但这是文档点名的验收项，且模块是交付物。

#### 9.30.4 修复

`zeroday_detect/variant_cluster.py::add_sample`：覆盖特征时**先清掉该样本的旧边**
（对称地清：既删 `_adj[sh]`，也从每个邻居的集合里删掉 `sh`），再按当前特征重建。

**正常情形是空操作**：同样本重复提交、特征相同时，
清掉的边会被同一段逻辑重新算回来。守卫把这条也钉住了。

#### 9.30.5 新增守卫（5 例）

`tests/test_clustering_feature_contracts.py::TestOverwrittenSamplesDoNotLeaveStaleEdges`：

* `test_the_old_edge_is_removed_when_features_are_overwritten` ——
  覆盖特征后旧边必须消失（核心性质）；
* `test_incremental_build_matches_a_fresh_build` ——
  **同样本集合**，增量构建与全量重建必须一致；
* `test_a_duplicate_with_identical_features_keeps_its_cluster` ——
  正常重复提交不能被改坏；
* `test_the_duplicate_counter_still_counts` ——
  记账不能被修复顺手删掉；
* `test_samples_with_zero_overlap_never_share_a_cluster` ——
  用户可见的性质：家族归属必须由**当前**特征支撑。

**注入验红（3 处，逐条点名）**：

| 注入 | 点名后红掉的用例 |
|---|---|
| 覆盖特征时完全不清边 | `test_the_old_edge_is_removed_when_features_are_overwritten` |
| 只清 `_adj[sh]`、不清**反向边** | 同上（**只清单向也会被抓到**） |
| 重复提交计数被删 | `test_the_duplicate_counter_still_counts` |

三次都红了，红的就是**对应性质自己的那条用例**；还原后 sha256 一致。

> 第二个注入值得单说：清边时**只清自己那一侧**看起来是「清了一半」，
> 但症状与「完全不清」**一模一样** ——
> 因为邻接表是**双向**的，反向边留在邻居那边，
> BFS 照样能从邻居走到 `sh`。
> 守卫能同时抓住这两种，说明它抓的是**结果**（簇划分）而不是**写法**。

#### 9.30.6 自曝：我第一次把场景测错了

第一版探针里我写了「`dup(V1),X` 与 `dup(V2),X` 结果不同 ⇒ 顺序依赖」。
**这个结论是错的** —— 那两组的**特征版本**不同（不是顺序不同），
各自的结果其实都是**正确**的。

真正要测的是「**同一个 hash 在同一实例里被两种特征各提交一次**」，
形如 `dup(V1), X, dup(V2)`。

> 与 §9.29.5 那条同族：**场景写反时，任何复杂判据都可能给出「看起来对」的结论**。
> 抓住它的办法还是那条**前提守卫**：
> 「最终特征下 Jaccard=0 的两个样本，不该同族」——
> 这句话不需要任何背景知识就能判断对错。

#### 9.30.7 与既有守卫的关系

| 性质 | 覆盖者 |
|---|---|
| 纯顺序变化 → 簇划分不变 | `test_partition_and_cluster_ids_do_not_depend_on_input_order`（既有） |
| 同样本集合 → 增量构建 == 全量重建 | `test_incremental_build_matches_a_fresh_build`（**本轮新增**） |
| 空特征不成族 | `test_featureless_sample_...`（既有，见 §9.24 前后） |
| 相似度/簇 ID 可追踪 | §9.23（既有） |

**四条** §十.2 的要求现在**都有行为守卫**。

---

### 9.31 【已补·本轮新增】§十一.2「所有用于运维决策的状态词表保持一致」：否定结论固化成门禁

#### 9.31.1 文档原文（§十一.2 第 4 条）

> - 所有用于运维决策的状态词表保持一致。

§十一.2 把它列在「清理和明确文档承诺」里 —— 也就是说，
它当时是一句**承诺**，不是一条**不变式**。

#### 9.31.2 实测：检测状态词表**是一致的**（否定结论）

扫描口径（比「手挑模块清单」可靠）：
**检测状态词表的消费方 = 导入/引用 `detection_contract` 的模块**
（实测 **10 个**），
在这些模块的「状态槽位」上收集全部字符串字面量。

结果：

| 类别 | 命中 |
|---|---|
| 规范词表（`ALL_STATUSES` 五态） | **26 处** |
| 属于**别的**词表（已登记） | **2 处** |
| **非规范且未登记** | **0 处** |

那 2 处「别的词表」是：

| 值 | 位置 | 它是哪套词表 |
|---|---|---|
| `review_queued` | `ingest_pipeline.py:265` | **HTTP 兼容字段**（`RunResult.status`）—— 不是检测结论 |
| `fallback` | `ingest_pipeline.py:810` | **审计跟踪状态**（`_mark_analyzed` 的 status 槽位，与 `quality='shed'` 配对） |

所以：**检测链路上没有词表漂移**。

#### 9.31.3 但否定结论**必须被钉住**，否则下一次改动就悄悄漂了

一句「现在是一致的」在没有守卫的情况下等于**没有结论** ——
下一个人写 `status="clean"` 时，没有任何东西会红。

所以本节新增 `tests/test_detection_status_vocabulary.py`（**7 例**），
把这条一致性变成**可执行的不变式**：

* **扫描范围自动推导** —— 不手挑模块清单，而是「谁引用了
  `detection_contract` 谁就是消费方」。新增一个消费方模块会被自动纳入。
* **登记表显式** —— 非规范词必须登记**它属于哪套词表**，
  登记理由为空串 = 静默白名单。
* **登记表反向检查** —— 登记的每个词**必须真的在代码里出现**。
  只进不出的登记表会积攒一堆早已不用的词，最后失去意义。

#### 9.31.4 前提守卫（否则本守卫可能恒绿）

| 前提守卫 | 挡的是什么 |
|---|---|
| 检测链路不为空且含 `detection_contract.py` | 扫描范围推导坏了 → 空转 |
| 扫描必须抓到规范词表里的字面量（抓到 0 个 = 扫描器坏了） | AST 形态漏了 → 扫不到东西 |
| **已知答案自检**：往合成代码里塞非规范词，扫描器必须报出来 | 扫描器自己恒绿（槽位名写错等） |
| 规范词表必须与 `detection_contract.ALL_STATUSES` 一致 | 有人加了第 6 个状态而没改登记表 |

#### 9.31.5 注入验红（3 处，逐条点名）

| 注入 | 点名后红掉的用例 |
|---|---|
| 往检测链路塞一个非规范状态词（`status="totally_bogus_status"`） | `test_every_status_literal_in_the_detection_chain_is_registered` |
| 登记一个**代码里不存在**的词 | `test_the_registry_is_not_stale` |
| **把扫描器本身弄坏**（槽位名改名） | `test_the_scanner_finds_canonical_status_literals` |

三次都红了，红的就是**对应性质自己的那条用例**；还原后 sha256 一致。

第三条注入值得单说：它证明**前提守卫本身有效** ——
扫描器坏掉时，守卫不是「什么都没扫到所以通过」，而是**明确报红**。

#### 9.31.6 自曝：第一次的 J2 注入**打错了地方**

第一版 J2 写成「删掉一个仍在使用的登记项」，期望抓「登记过期」。
结果**目标用例是绿的**，而**主守卫**红了。

原因：删掉登记项后，那个词变成「**未登记**」（该由主守卫抓），
而不是「**过期**」（登记了但代码里已不存在）。
两个是不同的性质，我把它们搞混了。

改成「登记一个代码里根本不存在的词」后，过期守卫才正确转红。

> 与 §9.29.5 / §9.30.6 同族：**注入必须针对守卫**实际断言的那条性质**，
> 而不是相邻的性质 —— 症状相似不代表判据相同。

---

### 9.32 【已修复·本轮新增】共享事件标记**从未送到下游** —— §八 的「下游不得重复计数」无法执行

#### 9.32.1 文档原文（§八 第 3 条的后半段）

> 但下游汇总时，必须避免同一事件仅因为出现在两条链里就被重复计算成两份独立证据。

前提是引擎给出「这条链与别的链共享了哪些事件」这个信息。

#### 9.32.2 引擎**已经算好了**，但两个序列化点都把它丢了

引擎侧一切正常：

* `AttackChain.shared_event_ids` / `overlaps_other_chain` 由 `_dedup_chains()` 填；
* 它的 docstring 明写着理由：
  > 改成把共享事件**标注出来**（`shared_event_ids`），
  > 让下游知道自己不能按链累加。
* `CorrelationResult.observability` 里有 `chains_overlapping` 计数；
* `tests/test_review_correlation.py` 的 Q8 系列**覆盖了它的计算**。

**但它没有出现在任何一个出口**：

| 序列化点 | 面向谁 | 有 `shared_event_ids` 吗 |
|---|---|---|
| `routers/ops.py::list_chains` | 运维界面（`/api/security/chains`） | ❌ |
| `tool_registry.py::_correlation_chains` | LLM（`correlation.chains` 工具载荷） | ❌ |

于是那句「让下游知道自己不能按链累加」是**空头支票**：
下游**根本看不到**这个标记，重复计数的风险**无法规避**，
只能靠下游自己想到 —— 而文档把这条要求写给了引擎这一侧。

#### 9.32.3 为什么这类缺陷特别难发现

* 字段**存在**、**有 docstring**、**有测试覆盖其计算**；
* 验收报告 §2.5 还把它列成了已覆盖项；
* 但**没有任何一条断言「有人读它」**。

**生产者写对了，不等于有人看。**
与本轮 `test_correlation_observability_exposed.py` 记的
「`observability` 零消费方」是**同一个形态** ——
只是这次零消费方的是「共享事件」而不是「observability 块」。

#### 9.32.4 修复（**纯披露**，不动任何判定）

两个序列化点各加两个字段：

```python
"shared_event_ids": list(getattr(c, "shared_event_ids", []) or []),
"overlaps_other_chain": bool(getattr(c, "overlaps_other_chain", False)),
```

`getattr` 兜底：测试替身/历史对象可能没有这些字段
（`routers/ops.py` 里 `actor` 字段已经是这个写法）。

**没有碰**：`status` / `confidence` / `event_ids` / 任何判定逻辑。
新增字段不破坏既有响应契约。

#### 9.32.5 新增守卫（5 例）

`tests/test_shared_event_marker.py`（**5 例**）：

* `TestTheMarkerReachesDownstream`（2 例）——
  **运行时**：API 响应与工具载荷都必须真的带上标记（**带值**，不只是有 key）。
* `TestEveryChainSerializationCarriesTheMarker`（2 例）——
  **静态**：全仓任何「序列化一条链」的字典字面量（判据：有 `chain_id` 键）
  都必须带这两个字段 → **将来新增的出口也会被抓到**；
  外加一条**前提守卫**：扫描器必须真的找得到已知的序列化点（否则它恒绿）。
* `TestTheEngineReallyProducesTheMarker`（1 例）——
  标记不是摆设：两条链共享一个事件时，它必须真的被填上。

**注入验红（3 处，逐条点名）**：

| 注入 | 点名后红掉的用例 |
|---|---|
| API 序列化丢掉标记 | `test_the_api_payload_carries_the_shared_event_marker` |
| 工具载荷丢掉标记 | `test_the_tool_payload_carries_the_shared_event_marker` |
| **新增一个不带标记的链序列化点** | `test_every_chain_serialization_carries_the_shared_event_marker` |

第三条最有价值：它证明静态守卫**能抓到将来新增的出口**，
而不只是盯住今天这两个。

#### 9.32.6 边界：今天的重复计数是**潜在的**，不是已发生的

实测前端（`frontend/src/pages/SecurityAudit.tsx` 的攻击链页签）
只逐条列出 `c.event_ids`，**没有**跨链累加；
`agents/agent_executor.py::_extract_chain_info` 把链事件收进
`chain_ids` 这个 **set**（天然去重）。

所以：**今天没有下游在重复计数**。
这条缺陷的实际后果是「文档点名要求的能力**不可用**」，
而不是「已经在产生错误数字」。

> 这个区分要写清楚：把它说成「正在重复计数」是**过强**的表述。
> 与 §9.17 那次（「判别力为零」实为「观测误差为 0」）同族 ——
> **过强的表述会让修复的紧迫性看起来比实际更高**。

#### 9.32.7 顺带：§八 剩下那条「缺失时间戳」也核了

文档 §八 第 2 条还写了：

> 缺失时间戳应产生明确的异常或不完整状态，而不是隐式填充。

实测（2026-10-20）：引擎的时间锚点是 DB 的 `SecurityEvent.created_at`，
而查询层带 `SecurityEvent.created_at >= cutoff` ——
**`created_at` 为 NULL 的行根本进不来**（SQL 里 `NULL >= cutoff` 不成立）。

所以「隐式填充」这件事**不存在**（引擎不填任何时间戳）。
但**「明确的异常或不完整状态」也不存在** ——
被时间窗过滤掉的行不留任何痕迹。

⚠ 但这在本实现里**不可达**：`SecurityEvent.created_at` 虽然没写
`nullable=False`（SQLAlchemy 默认允许 NULL），
但所有写入路径都经 SQLAlchemy 的 Python 侧 default 赋值。
**唯一可能产生 NULL 的路径是裸 SQL 插入或历史迁移未回填**，
而这两条都不在生产写入链路上。

→ 登记为**观察项**（不是缺陷）：若将来出现裸 SQL 写入路径，
需要给 `created_at` 加 `nullable=False` 或在引擎侧显式拒绝无时间戳事件。
本轮**不擅自改**（改列的可空性属于 schema 变更）。

---

### 9.33 【已修复·本轮新增】§二 验收要求 3 的「在哪个阶段失败」只能靠**解析消息**拿到

#### 9.33.1 文档原文（§二 验收要求 3）

> 对任意单一检测器注入异常，融合层都能够记录是哪个检测器、
> 哪个版本、**在哪个阶段**失败。

三项里前两项有**结构化字段**（`detector` / `detector_version`），
第三项**没有**。

#### 9.33.2 实测：阶段只以 `error_message` 的方括号前缀存在

| 位置 | 有 phase 吗 |
|---|---|
| `DetectionResult` 数据类 | ❌ **没有 phase 字段** |
| `AnalysisStatus.error_summary()` | ❌ 返回的字典里**没有 phase** |
| `DetectionResult.from_error(..., phase=...)` | ⚠️ 会把 phase 塞进消息前缀，但**生产零调用方** |
| `ingest_pipeline` 构造 DetectionResult 时 | ⚠️ 写成 `f"[{err.phase}] {err.message}"` —— **塞进消息** |

而 `error_summary()` 的 docstring 明写着：

> 「可落库 / 可上报的失败明细：**哪个检测器、哪个版本、哪个阶段**。」

**docstring 承诺的三个字段里，第三个不在输出里。**

#### 9.33.3 既有守卫用的是**子串匹配**

`tests/test_review_contract_fusion.py::test_q14_5b_detector_version_and_phase_are_recorded`：

```python
assert "detect" in err["error_message"], err["error_message"]
```

这是**子串匹配**：消息里出现 "detect" 就算过 ——
措辞、别的检测器名、错误类型名都可能含这个词
（`RuntimeError` 里没有，但 `detect_for_event`、`_audit_pipeline` 之类有）。

所以这条守卫**证明的是「消息里有这个字」**，不是「阶段被结构化记录了」。

#### 9.33.4 后果

下游要回答「在哪个阶段失败」只能**解析字符串**；
消息格式一改（哪怕只是去掉方括号），阶段信息就**静默**丢失，
而**没有任何东西会红**。

#### 9.33.5 修复（**纯增量**）

* `DetectionResult` 增加 `phase: str = ""`；
* `from_error` 把 phase 传进字段（**消息里的前缀保持不变**，向后兼容）；
* `error_summary()` / `to_dict()` 输出 `phase`；
* `ingest_pipeline` 构造 DetectionResult 时把 `DetectorError.phase` 传进去。

**没有碰**：任何既有字段的值、任何判定逻辑、消息格式。

#### 9.33.6 新增守卫（6 例）

`tests/test_detection_error_phase_field.py`（**6 例**）：

* `test_the_real_path_records_the_phase_structurally` ——
  真实路径（注入异常引擎挂掉）产出的失败明细里必须有**非空且已登记**的 phase；
* `test_the_phase_does_not_depend_on_parsing_the_message` ——
  把消息里的方括号前缀抠掉，阶段仍然拿得到；
* `test_the_structured_phase_is_not_derived_from_the_message` ——
  ⚠ **反向判据**：消息里写着 "detect"、字段却写着 "persist" 时**以字段为准**。
  这条挡住「实现退化成从消息里正则抠」——
  那种实现会让「消息被改写 → 阶段静默变错」；
* `test_from_error_puts_the_phase_in_the_field`；
* `TestTheMessagePrefixIsKept`（2 例）——
  消息里的方括号前缀**保持不变**（向后兼容），既有字段一个都不少。

**注入验红（3 处，逐条点名）**：

| 注入 | 点名后红掉的用例 |
|---|---|
| `ingest_pipeline` 不传 phase（退回「只藏在消息里」） | `test_the_real_path_records_the_phase_structurally` |
| `error_summary()` 不输出 phase | 同上 |
| phase 改成**从消息里正则抠**（退化实现） | `test_the_structured_phase_is_not_derived_from_the_message` |

三次都红了，红的就是**对应性质自己的那条用例**；还原后 sha256 一致。

#### 9.33.7 边界（写清楚，免得读成「阶段信息已经完备」）

实测（2026-10-20）：`DetectorError.phase` **只被读、从未被赋过非默认值** ——
生产上所有检测器错误都发生在 `detect` 阶段，所以这个字段今天是**常量 "detect"**。

而且 **persist / dispatch 阶段的失败根本没有 phase**：
它们走 `RunResult.error` / `error_code`，与 `DetectorError` 是两条路。

所以这条修复的准确描述是：
**「阶段」这个概念第一次有了结构化载体，并且能被守卫钉住**；
至于「每个阶段的失败都带自己的阶段」，那是**另一件事**
（需要 persist/dispatch 的失败也走同一套结构）→ 登记为**观察项**，
本轮**不擅自改**（那会动 `RunResult` 的形状与错误路径）。

> 与 §9.17 同族的表述纪律：
> 这条是「**可验证性**的缺口」，不是「生产上正在记错阶段」——
> 因为今天的值本来就是对的（恒为 "detect"）。
> 把它说成「阶段记错了」是**过强**的表述。

---

### 9.34 【已补·本轮新增】案例自动派单失败**不可观测**：案例建好了却没人派单

#### 9.34.1 怎么查到的：复核待决项 17 的归因

待决项 17 说的是「测试库隔离」，而它的症状是：

```
[Case] auto-dispatch failed: UPDATE statement on table 'security_cases'
expected to update 1 row(s); 0 were matched.
```

我先复核了「生产代码有没有漏 commit」这个怀疑：
`auto_create_case` 在 `await session.commit()` **之后**才调 `_maybe_auto_dispatch`
（`case_manager.py:727` → `:734`），**同一 session、已提交** ——
所以**不是**漏 commit，生产路径是对的。

那 UPDATE 为什么影响 0 行？`update_status` 里
`session.get(SecurityCase, case_id)` **取到了行**（否则会返回「案例不存在」而不是抛异常），
说明**行在 SELECT 之后消失了**。
生产用独立连接，行不会这样消失；测试用 StaticPool 的**同一条连接**，
测试会话的回滚会把后台任务未提交的 INSERT 一起带走 ——
**待决项 17 的归因成立**，本轮不动它。

但顺着这条线查下去发现了一个**生产侧**的问题。

#### 9.34.2 缺陷：失败只有一行 warning 日志

`case_manager._maybe_auto_dispatch` 的失败路径：

```python
except Exception as e:
    logger.warning(f"[Case] auto-dispatch failed: {e}")
    return False
```

后果（生产侧）：

* 案例**已经建好并提交**，但**没有工单**、没有派单、没人被叫醒；
* 案例停在 `open`，在指标上与「本来就不需要派单」**完全同形**；
* 唯一痕迹是一行日志 —— **没有任何计数**。

而且它的返回值本身把两件事混成同一个 `False`：
「优先级不够、不需要派单」与「**派单失败了**」。

这与整改方案 §十一.1 的
「成功、命中、未命中、部分失败、**执行错误计数**」是同一族要求，
也是本轮反复出现的那个形态：**故障不能长得像正常**。

#### 9.34.3 改动（**纯观测**，不改行为）

* `core_metrics.py`：新增 `soc_case_auto_dispatch_total{result=ok|skipped|failed}`
  与 `record_case_auto_dispatch()`；
* `case_manager.py`：三个出口各记一次 ——
  成功 → `ok`、不需要派单 → `skipped`、**异常 → `failed`**。

`failed` 与 `skipped` **必须分开**：
只有前者需要人介入（案例建好了却没人派单）。

#### 9.34.4 新指标被既有门禁当场抓住（这是门禁设计的功劳）

新指标一落地，`tests/test_metric_consumer_guard.py` 就转红了：

> 实测多出: `['soc_case_auto_dispatch_total']`
> 新指标必须二选一：接进仪表盘/告警，或在 `UNWATCHED` 里写明理由。

**这正是那条守卫存在的理由**（§7.1.15 记的就是
「新指标既不接线也不登记时无处可藏」）。

处置：**登记，不接告警**。理由是接告警会产生**值班呼叫**，
属运维行为变更 —— 报告 §7.1.15 明写「**需要用户拍板**」。
按既有做法（此前 42 个指标同样处理）先登记并写明理由。

报告里「62 个指标 / 40 个无消费面」（**守卫口径**，见 §9.37.4）相应改为 **63 / 41**。

#### 9.34.5 新增守卫（7 例）

`tests/test_case_auto_dispatch_metric.py`（**7 例**）：

* `TestTheThreeOutcomesAreCounted`（4 例）——
  三个出口各记一次；**`failed` 与 `skipped` 必须是不同的计数**；
* `TestTheMetricIsReallyVisible`（3 例）——
  指标**真的**出现在 /metrics 文本里（从**默认注册表**导出，
  验证的是「真实 /metrics 里真的有这一行」——
  声明了却没注册 = 没有任何面板能看见它）；
  标签白名单正好三个值；未知取值必须 clamp 到**保守**的一侧（`failed`），
  而不是悄悄变成「成功」。

**注入验红（3 处，逐条点名）**：

| 注入 | 点名后红掉的用例 |
|---|---|
| 失败路径不记 `failed` | `test_a_failed_dispatch_is_counted_as_failed` |
| 失败路径记成 `skipped`（两者混成一个标签） | `test_failed_and_skipped_are_different_counters` |
| 白名单漏掉 `failed`（失败被**误标**成别的） | 同上（5 条红） |

三次都红了，红的就是**对应性质自己的那条用例**；还原后 sha256 一致。

#### 9.34.6 边界

* 这个指标解决的是**「不可见」**，不是**「不发生」**：
  派单失败依然会发生，计数只是让它**可被看见**。
  「失败后要不要自动补偿（重试/降级/直接告警）」属**运维行为决策** → 上交。
* 生产上这条路径的**实际失败率未知** ——
  修复前没有计数，所以**历史失败次数无法回溯**。
  指标从本次上线后才开始有数。

---

### 9.35 【已补·本轮新增】告警发布失败**不可观测** + 「失败被吞」的全仓普查

#### 9.35.1 先把 §9.34 的形态系统化

§9.34 命中的形态是：**自动化动作失败 → `except Exception` → 只记日志
→ 没有指标 → 失败与「不需要做」在指标上同形**。

本轮不再一个一个碰，而是**全仓扫**（脚本已入库：
`tools/scan-swallowed-failures.py`，可重复执行）：

口径：排除 `tests/`；只看 `except Exception` / `except BaseException`
这类**宽异常**；判定「有计数」= handler 体内出现指标调用；
同时标出「handler 直接返回一个假值」（None / False / [] / {}）——
那是最隐蔽的一类：**调用方无法区分「失败」与「没有该做」**。

| 结果 | 数量 |
|---|---|
| 宽异常 handler 里「只记日志、无计数」的总数 | **414** |
| 其中落在**运营决策路径**（派单 / 告警 / 封禁 / 建单 / 工单 / 入队…） | **42** |

**这是一个规模问题，不是一条缺陷。** 本轮只修最严重的两处
（§9.34 案例自动派单、本节告警发布），
其余登记为**待补清单**（见 §9.35.5），不假装一次改完。

#### 9.35.2 本轮修的第二处：告警发布失败 = **告警彻底消失**

`kafka_producer.publish_alert` 的四种失败模式**全部不可见**：

| 失败模式 | 修复前 |
|---|---|
| producer 未启动 | `return`，无痕迹 |
| schema 校验拒收 | `logger.warning` + `return`，无计数 |
| 盖章 / 加密抛异常 | `logger.warning` + `return`，无计数 |
| **broker 发送失败** | `_send_bounded` 返回 False，**返回值被丢掉** |

最后一条最隐蔽：`_send_bounded` 明确返回 bool（成功 True / 失败 False），
而 `publish_alert` 直接 `await` 它、**不接返回值** ——
连调用方都不知道这条告警没发出去。

**最有说服力的是一处不对称**：原始事件路径 `produce_raw` 的同类拒收
**是有计数的**（`record_ingest("kafka", "validation_failed", reason="schema")`），
而**告警路径一个指标都没有** ——
也就是说：**丢告警比丢原始事件更难被发现**
（原始事件丢了还能靠 DLQ 找，告警丢了就没人知道了）。

#### 9.35.3 改动（纯观测，不改行为）

* `core_metrics.py`：新增 `soc_kafka_alert_publish_total{result=ok|not_started|schema_rejected|error|send_failed}`；
* `kafka_producer.publish_alert`：五个出口各记一次，并**接住** `_send_bounded` 的返回值。

新指标同样被 `tests/test_metric_consumer_guard.py` 的**双向相等**守卫当场抓住
（「新指标必须二选一：接进仪表盘/告警，或在 `UNWATCHED` 里写明理由」）。
处置仍是**登记，不接告警** —— 接告警会产生值班呼叫，属运维行为变更，需用户拍板。
报告里「63 个指标 / 41 个无消费面」（**守卫口径**，见 §9.37.4）相应改为 **64 / 42**。

#### 9.35.4 新增守卫（9 例）

`tests/test_kafka_alert_publish_metric.py`（**9 例**）：

* `TestAlertPublishOutcomesAreCounted`（6 例）——
  五个出口各记一次；**broker 发送失败必须被看见**（核心）；
  **四种失败互不相同**；
* `TestTheMetricIsReallyVisible`（3 例）——
  指标真的出现在 /metrics 文本里；白名单正好五个值；
  未知取值 clamp 到**保守**的一侧（`error`），不悄悄变成「成功」。

**注入验红（3 处，逐条点名）**：

| 注入 | 点名后红掉的用例 |
|---|---|
| 不接 `_send_bounded` 的返回值（退回修复前） | `test_a_failed_send_is_counted_as_send_failed` |
| 无论成败都记 `ok` | `test_the_four_failure_modes_are_distinguishable` |
| 去掉「未启动」的计数 | `test_a_not_started_producer_is_counted` |

三次都红了，红的就是**对应性质自己的那条用例**；还原后 sha256 一致。

> **写这条守卫时自己踩了两个坑，都记在这里**：
> ① 第一版没替换 `schema_registry.validate` → 真实校验器要求 `alertId`，
> 把最小 payload 拒掉，于是每条用例都走 schema 分支，
> 「ok / send_failed」两条**测的是别的东西**；
> ② `boom` 用例把 `stamp_identity` 换成抛异常的版本后**没复原**，
> 导致后面的「发送失败」也被记成 error。
>
> 与本会话那条「守卫必须走被消费的那条路径」同族：
> **夹具不干净 → 守卫测的不是它声称测的东西。**

#### 9.35.5 剩下的 40 处运营决策路径失败（登记为待补清单）

普查出的 42 处里，本轮修了 2 处（§9.34 自动派单、本节告警发布）。
剩下 40 处按严重度分档登记，**逐条可核**（脚本可重跑）：

| 档 | 形态 | 代表位置 |
|---|---|---|
| **高** | 失败**完全不可见**（返回值被丢掉 / 直接 `return`） | `kafka_consumer._handle_alert` / `_handle_behavior_alert`、`ingest_pipeline.dispatch`、`work_order_service._execute_approved_actions`、`response_engine.ssh_firewall.block_ip` / `isolate_host` |
| **中** | 失败**对调用方可见**但无计数 | `case_manager.update_status` / `assign` / `set_disposition`、`work_order_service.approve` / `reject` / `check_sla_breaches`、`kafka_producer.publish_audit_result` / `publish_sigma_hit` |
| **低** | 尽力而为的清理/旁路，吞掉无妨 | `audit_trail` 的哈希链回退、`vector_store._client_or_none`、`self_play` 的 LLM 兜底 |

「高」档是**告警/封禁/派单**这类动作 —— 失败时运维侧可能**完全不知情**。
本轮不一次性改 40 处（每处都要单独判断「失败要不要上报、报给谁」），
但清单已**逐条可复跑**，不是一句「还有很多」。

> 处置原则与 §9.34 一致：**先让失败可见，再谈要不要自动补偿**。
> 「失败后要不要重试/降级/直接告警」属**运维行为决策** → 上交，不单方面做。

---

### 9.36 【已补·本轮新增】工单审批「通过后执行响应动作」是**假的** —— 死代码 + 注释与实现不一致

#### 9.36.1 怎么查到的

§9.35 的「失败被吞」普查把 `work_order_service._execute_approved_actions`
标进了「高」档（返回值被丢掉）。顺着它读下去，发现的不是计数问题，
而是**更根本的一条**：

* 函数名 `_execute_approved_actions`（执行已批准的动作）；
* docstring 写着「审批通过后执行响应动作」；
* 函数体里取了一个 `get_orchestrator()`，**从头到尾没用过**（死代码），
  只把案例状态改成 `responding`。

也就是说：**名字、注释、调用点三处都让人以为「审批通过会执行响应动作」，
实际一个动作都不执行。**

#### 9.36.2 系统里有**两套并行的审批机制**

| 机制 | 载体 | 进程重启后 | 通过后**真的执行动作**吗 |
|---|---|---|---|
| 内存态审批票 | `human_approval.approval_queue` | **丢** | **是**（`response_executor.execute_actions`） |
| 数据库态工单审批 | `WorkOrder.approval_status` | 持久 | **否** |

运维在界面上实际操作的是**后者**（工单审批），
而真正会执行响应动作的是**前者**（内存票）。
两条路径各有各的审批人、审批入口和状态字段。

> **注释与实现不一致，本身就是缺陷的一种，而且是最难发现的一种** ——
> 读代码的人会把 docstring 当成事实，审计的人也会。
> §十一.2 说的「删除或实现长期无人调用的死代码」正是这一类。

#### 9.36.3 为什么本轮**不**把执行接上

「工单审批通过后要不要真的执行响应动作」是**产品语义决策**，不是缺陷修复：

* **接上**就可能与内存票路径**重复执行**（同一威胁、两条路径各执行一次）；
* **不接上**意味着运维点了「批准」之后系统**什么都不做** ——
  这在安全运营里同样是危险的静默。

两边的后果都不轻，且都超出「修一个 bug」的范围 → 登记为**待决项 25** 上交。

#### 9.36.4 改动（**不改行为**）

* `work_order_service._execute_approved_actions`：**删掉死代码**（取来不用的
  `get_orchestrator()`）、**改正 docstring**（明写「⚠ **它不执行任何响应动作。**」
  并说清真正的执行路径在哪）、**改为返回 bool**
  （此前无返回值 → 推进失败完全不可见）；
* `work_order_service.approve`：三个出口各记一次 ——
  成功 → `approved`、**推进失败 → `failed`**、不需要推进 → `skipped`；
* `core_metrics.py`：新增 `soc_work_order_approve_total{result=approved|skipped|failed}`
  与 `record_work_order_approve()`。

`failed` 与 `approved` **必须分开**：
审批**已经写进数据库**了，但推进步骤抛异常 —— 只看 `approved` 会以为一切正常。

#### 9.36.5 新指标被既有门禁当场抓住

同 §9.34 / §9.35：落地后 `tests/test_metric_consumer_guard.py` 转红
（「新指标必须二选一：接进仪表盘/告警，或在 `UNWATCHED` 里写明理由」）。
处置仍是**登记，不接告警**（接告警会产生值班呼叫，属运维行为变更，需你拍板）。
报告里「64 个指标 / 42 个无消费面」相应改为 **65 / 43**（守卫口径，见 §9.37.4）。

#### 9.36.6 新增守卫（9 例）

`tests/test_work_order_approve_metric.py`（**9 例**）：

* `TestTheApprovalOutcomesAreCounted`（4 例）——
  三个出口各记一次；**「审批写进库了但推进失败」必须记成 `failed` 而不是 `approved`**
  （该用例直接用一个会抛异常的 `session.get` 替身来触发它）；
* `TestTheDeadCodeStaysDead`（3 例）——
  ① 死代码不得回来；② docstring 必须说清「不执行任何响应动作」；
  ③ helper 必须返回 bool；
* `TestTheMetricIsReallyVisible`（2 例）——
  指标**真的**出现在 /metrics 文本里（从**默认注册表**导出，
  验证的是「真实 /metrics 里真的有这一行」）；标签白名单正好三个值。

⚠ **判据必须看代码不看文本**：docstring 里为了说明这件事**会提到** `get_orchestrator()`
—— 用 `in src` 判定会误报（守卫第一版就栽在这里）。所以走 **AST**，只看函数体里的**调用**。

#### 9.36.7 注入验红（4 处，逐条点名）

| 注入 | 点名后红掉的用例 |
|---|---|
| 失败路径不记 `failed`（记成 `approved`） | `test_a_failed_post_approval_step_is_counted_as_failed` |
| 死代码回来（重新取 `get_orchestrator()`） | `test_the_post_approval_helper_does_not_fetch_the_orchestrator`（+2 条连带） |
| docstring 不再声明「不执行任何响应动作」 | `test_the_docstring_says_it_does_not_execute_actions` |
| helper 不再返回 bool | `test_the_helper_returns_a_bool`（+1 条连带） |

四次都红了，红的就是**对应性质自己的那条用例**；
每处还原后 sha256 一致（`15b030ba7b901b4d…`），最终还原校验通过。
注入按**字节**做、用 `shutil.copyfile` 还原（**不用 git** ——
`git stash` 会把 LF 文件整体改写成 CRLF）。

#### 9.36.8 边界

* 本轮**没有**让工单审批真的执行响应动作 —— 那是待决项 25。
* 死代码删除**不改变任何行为**（那个对象取来就没用过），
  但**可读性上的风险已经消除**：后来人不会再以为这里会执行动作。
* 生产上这条路径的**实际失败率未知** —— 修复前没有计数，历史失败次数无法回溯。

---

### 9.37 【已更正·本轮新增】「多少个指标没人看」有两个**互相矛盾**的口径 —— 报告写 45，登记表是 43

#### 9.37.1 现象

写 §9.36 时要更新报告里的指标计数，发现对不上：

* 报告正文（§6.2 第 10 项、§7.1.14、§7.1.15）写「**65 个指标 / 45 个**处于
  『被产出但仓库内无 Prometheus 消费面』」；
* 而守卫 `tests/test_metric_consumer_guard.py` 的 `UNWATCHED` 登记表**只有 43 条**。

两者都**自洽**，差 2 条。而报告自己的规矩是
「**汇总数字必须能由明细重算出来**」—— 现在这个数**重算不出来**。

#### 9.37.2 根因：两个口径

| 口径 | 算法 | 落在声明里的 | 65 个里无消费面的 |
|---|---|---|---|
| **原始引用并集**（报告 §7.1.15 用的） | 仪表盘 PromQL + 告警 expr 里的**原始指标名**并集 | **20** | **45** |
| **守卫口径**（`prom_consumed()`） | 并集之上再**回溯** Histogram/Summary 的自动派生序列（`_bucket`/`_sum`/`_count`/`_created`）的基础指标名 | **22** | **43** |

实测（`declared=65`、`dash=22`、`alert=9`、原始并集=22、`prom_consumed()=24`）：

```
原始并集口径   无消费面 = 45
守卫口径       无消费面 = 43
UNWATCHED 登记         = 43   ← 守卫口径
```

#### 9.37.3 差异恰好落在 2 个 Histogram 基础指标上

```
soc_pipeline_e2e_seconds      ← 仪表盘只查它的 _bucket 派生序列
soc_pipeline_stage_seconds    ← 同上
```

原始并集里**看不到基础指标名**（PromQL 写的是 `soc_pipeline_e2e_seconds_bucket`），
于是这两个**有人看**的 Histogram 被算成了「没人看」。

> 方向很重要：这是**高估**缺口 —— 把「有人看」说成「没人看」。
> 与 §9.17 那条（把「判别力为零」说过强）同族，但这次是**数字**而不是文字，
> 所以更不容易被人一眼看出来。

#### 9.37.4 处置：以守卫口径（**43**）为准

两条理由：

1. **它有明细可对**：`UNWATCHED` 登记表**逐条登记**了 44 个指标及理由，
   且守卫断言**双向相等** —— 汇总数字能由明细重算。
2. **它语义更准**：查 `_bucket` 就是消费了那个 Histogram。

连带更正（把 §9.34 / §9.35 的增量链也换成守卫口径，
保证「加一个指标就 +1」这件事**可验证**）：

| 阶段 | 原始并集口径（报告原写） | **守卫口径（现用）** |
|---|---|---|
| 基线（62 个指标） | 42 | **40** |
| §9.34 加 `soc_case_auto_dispatch_total` | 43 | **41** |
| §9.35 加 `soc_kafka_alert_publish_total` | 44 | **42** |
| §9.36 加 `soc_work_order_approve_total` | 45 | **43** |

§7.1.15 那张原始测量表（当时 62 个指标）也按守卫口径补注：
原始并集 20/42，守卫口径 **22/40**。

守卫文件里两处过期数字也一并更正（docstring 的「62 个声明指标里只有 20 个」
与 xfail reason 的「62 个声明指标里 42 个」）—— **理由字符串里写错数字，
比正文写错更隐蔽**：它会跟着 xfail 一起被读成「这是已知的、已核对的」。

#### 9.37.5 顺带发现：待决项**有两套互相冲突的编号**，12~16 号在报告里查不到

§6.2 的「建议的下一步」清单编号 **1~14**，而 §7.1.x 各节用「待决策第 N 项」登记，
两者**差 1**，且指向**同一批**决策：

| 决策 | §6.2 清单编号 | §7.1.x 登记编号 |
|---|---|---|
| 给检测引擎补告警与面板 | 第 **10** 项（§6.2） | 待决策第 **9** 项（§7.1.15） |
| 处置前端两条必然失败的请求 | 第 **11** 项 | 待决策第 **10** 项（§7.1.16） |
| 给 DLQ 接 UI 入口 | 第 **12** 项 | 待决策第 **11** 项（§7.1.17） |

更要紧的是：**12~16 这五个编号在整份报告里没有按编号出现过** ——
§9.8 的表从 **17** 起，于是「待决项累计 N 项」这个数字
**无法由任何一张明细表重算**。

> 教训与 §9.37.1 同源：**汇总数字必须能由明细重算出来**，
> 而「明细在哪儿」本身就是明细的一部分。
> 一份有 25 条待办、却查不到其中 5 条编号的报告，
> 用户没法判断自己是漏看了哪一条。
>
> **本轮不重排编号**（那会牵动全篇引用），只把这件事**显式记下来**，
> 并让 §9.8 的表成为 17~25 的**单一权威来源**。

---

### 9.38 【已更正·本轮新增】把两处汇总数字**真的重算一遍** —— 都用代码里的实测数，不用报告里的转述

§9.37 暴露了一个习惯性风险：报告里的汇总数字是**上一轮抄下来的**，
而明细会随本轮的改动一起长。于是「合计」与「明细」会慢慢分家。

本轮把两处关键汇总数字**从代码重算**，并把方法固化成可复跑的一次核对。

#### 9.38.1 守卫条数：147 → 156，合计 168 → 177

做法：对报告 §9.0 的明细逐条**定位到具体的守卫文件**，
用 `pytest --collect-only` 取**真实收集数**（不是 `def test_` 的个数 ——
参数化会让两者不等），再与报告声称的条数对撞。

| 条目 | 报告声称 | pytest 实测 | 结论 |
|---|---|---|---|
| HTTP 载荷键集合 + 失败路径键集合 | 14 + 1 | **14 passed**（10 函数 + 4 参数化） | ✅ |
| 检测延迟与冷启动分档 | 17 | **17** | ✅ |
| 规模/窗口矩阵 | 14 | **14** | ✅ |
| 状态词表一致性 | 7 | **7** | ✅ |
| 共享事件标记 | 5 | **5** | ✅ |
| 失败阶段结构化 | 6 | **6** | ✅ |
| 自动派单结果计数 | 7 | **7** | ✅ |
| 告警发布结果计数 | 9 | **9** | ✅ |
| 工单审批结果计数（本轮新增） | 9 | **9** | ✅ |
| 陈旧边 | 5 | 文件共 20（含此前既有用例） | ✅ 新增 5 条 |

> ⚠ **一个必须写下来的测量事故**：我第一版用 AST 数 `def test_*`，
> 于是「HTTP 载荷键集合」数出 **11**、用 `--collect-only` 数出 **10** ——
> 两者**都错**（前者漏了参数化，后者我的过滤条件把以 `]` 结尾的
> 参数化用例整条滤掉了）。**pytest 自己报的 `14 passed` 才是判据。**
>
> 与 §4.7 / §4.8 那两处「同一个缺陷的第二个、第三个实例」同族：
> **判据和被测对象必须用同一个量纲**，否则量具自己会骗人。

明细相加：原 147（✅ 与报告一致）**+ 本轮 9 = 156**；合计 21 + 156 = **177**。

#### 9.38.2 「产出 N 处新发现」：报告声称 34，它自己的清单只点名了 33 条

这个差是**本来就有**的，不是本轮造成的：
§9.0 声称 34 处，而两条「逐条列出」的清单里只点了 33 个 §9.x。

按可重算的口径（§9.1~§9.37 扣掉纯记账的 §9.8 待决项表与 §9.9 诚实登记）：

```
§9.1 ~ §9.37  = 37 个小节
扣掉 §9.8 / §9.9 = 35 个「发现」
```

本轮补上 §9.36 / §9.37 两条后，**35 既是实际数，也能由清单逐条点名** ——
两个口径第一次对上了。

#### 9.38.3 教训

> **汇总数字必须能由明细重算出来**，而「明细在哪儿」本身就是明细的一部分。
>
> 更具体地说：**转述的数字会腐烂，指向代码的数字不会。**
> 报告里的「147 条」当初是对的，但它是**抄**来的 ——
> 抄的东西不会因为代码变了而变。
>
> 做法：凡是「N 个 X」这种汇总，**要么给出能复跑的对撞方法**，
> 要么就别写这个数。
> 本轮起，守卫条数的对撞方法随报告一起给出（pytest `--collect-only`），
> 下一个人可以直接复跑，不必信我。

#### 9.38.4 本轮没有推进的部分

* 这只解决了**报告自身**的两处记账，没有动 §9.37.5 说的
  **待决项 1~16 缺台账**的问题（12~16 号仍查不到）——
  那是**另一件事**，需要把 §6.2 与 §7.1.x 的编号体系统一，牵动全篇引用。

---

### 9.39 【已修复·本轮新增】Sigma 快照连接的释放判据是**代数**不是**引用** —— §六 第 5 条没有落地

#### 9.39.1 文档原文

整改方案 §六 在「一个实现上的重要建议」里给了五条实现建议，第 5 条是：

> 5. 旧快照只在不再被执行任务引用时释放。

§六 的验收表里，对 `reload()` 那一行的验收标准是：

> 并发检测与热更新同时运行，不会出现旧连接被关闭导致的检测失败

#### 9.39.2 缺陷：释放判据是**代数**

修复前的实现（`sigma_engine/engine.py`）：

```python
def _drain_retired(self) -> None:
    if len(self._retired_conns) > 1:
        stale, self._retired_conns = self._retired_conns[:-1], [self._retired_conns[-1]]
        for c in stale:
            c.close()
```

「延迟一代」听起来像在解决这个问题，但它仍然是**代数**：
与「有没有执行任务还在用这一代快照」**毫无关系**。

实测（修复前；抓一个快照引用后连续 reload）：

```
reload #1 -> generation=2, _retired_conns=1
   snap1.conn: 可用
reload #2 -> generation=3, _retired_conns=1
   snap1.conn: 已关闭/不可用: ProgrammingError: Cannot operate on a closed database.
```

而机制自己的 docstring 写的是：

> 不在 `_publish_snapshot` 内立即 close —— 那会关掉可能仍被在途 detect
> 引用的连接（整改方案 §六「旧快照只在不再被执行任务引用时释放」）。

**它声称自己实现了它没有实现的东西。**

#### 9.39.3 今天为什么没出事（严重级别要说准）

`detect()` 走的是**每次检测一个私有 `:memory:` 连接**（§六 第 4 条的真正隔离），
**从不持有快照连接**。

也就是说：**第 4 条的隔离设计顺带掩盖了第 5 条的缺失** ——
安全性来自「另一个设计」，不是来自释放机制本身。

所以这条**不是**「线上正在丢检测」，而是「**要求没有落地 + 注释在说谎**」：
严重级别是**隐患**，不是**正在发生的故障**。说成后者会夸大紧迫性（§9.17 同族）。

#### 9.39.4 修复：把释放判据改成**引用**

引入 `_ConnLease`（引用计数凭证）：

* 快照携带一个 lease；
* 执行任务捕获快照时 `acquire()`，结束时 `release()`；
* 退休的 lease 只有在**引用归零**时才关连接；
* **宽限一代**的原有行为保留（刚退休的那一代先不关），
  但它现在只是**附加条件**，不再是唯一判据 ——「不再被引用」才是必要条件。

顺带修掉一个**竞态**：检测路径原来在 `_detect_with_errors` 里读 `self._snapshot`，
现在把快照**显式传**给 `_detect_with_snapshot(snap, event)` ——
否则「捕获快照」与「拿租约」可能落在两代上，租约保护的就不是实际在用的那一代。

> 行为影响：**检测结果一条不变**。
> 每事件私有连接、独立规则集、错误与本轮绑定 —— 都没动。
> 变的只是「旧连接什么时候关」。

#### 9.39.4.1 自曝：这个修复**自己引入了一个竞态**

第一版 `_ConnLease.acquire()` 在租约已关闭时抛
`RuntimeError("sigma_snapshot_conn_closed")`。写完才想到这条路径：

```
线程 A: snap = self._snapshot        → 拿到 snap1
线程 B: 连续两次 reload()            → snap1 退休、宽限期过、连接被关
线程 A: snap.lease.acquire()         → 租约已关闭 → 抛异常
```

也就是说，**我把一个原本无害的时序变成了检测崩溃**。

为什么无害：检测路径**不使用**快照连接（走每事件私有的 `:memory:` 连接），
快照的 `compiled` 又是不可变 tuple ——
「租约没拿到保护」**不影响检测结果的正确性**。

改法：`acquire()` 在已关闭的租约上**不抛错**，只是拿不到保护。
并补一条守卫把这条性质钉住。

> 这条自曝本身就是「竞态类改动必须把**时序**写出来」的例证：
> 我在写实现时只想着「谁持有就保护谁」，
> 没想「持有这个动作本身**也可能**落在退休之后」。

#### 9.39.5 新增守卫（10 例）

`tests/test_sigma_snapshot_lease.py`（**11 例**）：

| 组 | 例数 | 作用 |
|---|---|---|
| `TestTheLeaseIsThePrecondition` | 3 | **前提守卫**：快照带租约、租约持有的是同一个连接、新租约引用数为 0 —— 否则下面全部恒绿 |
| `TestTheReleaseIsByReference` | 5 | ① 被引用的快照多次 reload 后连接**仍可用**；② 最后一个引用释放后**必须**关闭；③ 无人引用的旧代**仍要**按宽限期回收（防泄漏）；④ 宽限一代的原有行为保留；⑤ **已被回收的租约再 `acquire()` 不抛错**（§9.39.4.1 那个竞态） |
| `TestTheDetectionPathActuallyHoldsALease` | 3 | 检测执行期间**确实**持有租约、结束后**确实**释放、检测结果不受影响 |

第 ② 与第 ③ 是一对**反向**判据：
只钉「不提前关」而不钉「该关的要关」，守卫会放过一个把连接永远留着的实现。

#### 9.39.6 注入验红（7 处，含两组「只修一半」）

| 注入 | 期望 | 实测红掉的用例 |
|---|---|---|
| J1a 只改 drain 循环 | **不红** | — |
| J1c 只改 lease 自身那一层 | **不红** | — |
| **J1b 两层同时改（= 忠实还原原缺陷）** | **红** | `test_a_referenced_snapshot_survives_repeated_reloads`、`test_the_connection_closes_when_the_last_reference_is_released` |
| J2 检测路径不再拿租约 | 红 | `test_the_detection_holds_a_lease_while_it_runs` |
| J3 检测路径不释放租约 | 红 | `test_the_lease_is_released_after_the_detection` |
| J4 释放引用后永不关闭 | 红 | `test_the_connection_closes_when_the_last_reference_is_released` |
| J5 快照不再携带租约 | 红 | 10 条（含 3 条前提守卫） |

**J1a / J1c 不红，这本身就是结论。**

修复把同一个不变量守在了**两层**（drain 循环的引用检查 + lease 自身的引用检查），
所以**单点注入打不穿**。第一版注入只改 drain 循环，**没转红** ——
当时差点被当成「守卫无效」。

> 这正是「注入自证要**同时试「完全不修」和「只修一半」**」那条判据的实例：
> **「只修一半」不转红，说明守卫钉的是最终结果，不是实现动作。**
> 要忠实还原原缺陷，必须**两层同时打**（J1b）—— 那一针才转红，
> 且红的正是核心性质自己的那条用例。

每处还原后 sha256 一致（`abd8d628e85551eb…`），最终还原校验通过。

#### 9.39.7 边界

* 本轮**没有**改任何检测判定 —— 规则语义、命中与否、错误通道全部不变。
* 「宽限一代」保留是有意的：发布快照的同一瞬间把在途任务断掉，
  比晚一点回收更糟。
* 快照的共享连接在生产路径上**几乎没人用**（detect 走私有连接）——
  本轮**不删**它：它同时是既有测试的注入点，
  而「持有它的人」正是这条租约要保护的对象；
  删掉它会把本条从「隐患」变成「无物可保护」。
* 本轮**没有**为「共享连接要不要彻底删掉」单独立待决项 ——
  它不是**正确性**问题（生产路径不依赖它），是**清理**问题；
  清理的收益（少一个空内存库）远小于它把本条变成「无物可保护」的代价。

---

### 9.40 【已修复·本轮新增】规则库的「三态」其实只有两态 —— §六.2 的 `degraded` 判据没落地

#### 9.40.1 文档原文（§六.2）

整改方案 §六.2「Legacy 兜底需要有明确的降级状态」：

> 建议规则库建立三种运行状态：
> - normal：pySigma 规则按预期加载和运行。
> - degraded：启用了 Legacy 兜底**或部分规则未加载**，并明确记录原因。
> - unavailable：没有任何可用的合规检测路径。
> ...
> **高风险规则不可用时，应触发告警和明确的分析不完整状态。**

代码里三态**确实存在**（`stats()["run_mode"]`），
但判据与文档对不上 —— 而且是**两处**对不上。

#### 9.40.2 缺陷 A：部分规则未加载时 `run_mode` 仍然是 "normal"

修复前的判据：

```python
mode = "normal" if self._compiled else (
    "degraded" if self._legacy is not None else "unavailable")
```

只看「有没有编译出规则」，**不看有没有规则没加载上**。

实测（2 个规则文件、1 个 YAML 语法错误）：

```
run_mode        = normal        ← 应该是 degraded
compiled_count  = 1
load_errors     = [{'phase': 'parse', 'file': 'b.yml', ...}]   ← 明明记着失败
```

后果：运维（以及 `routers/audit.py:33` 对外透出 `stats()` 的 API 消费者）
看到 "normal" 就以为规则库完好，实际上**有一半规则没加载**。
文档要求的「明确记录原因」做到了（`load_errors`），
但「**降级状态**」没有 —— 两半只落了一半。

> 最扎眼的是：既有测试 `test_review_sigma_detector.py:248-258` 用的**正是这个场景**
> （一个 `ok.yml` + 一个 `bad.yml`），而且它**断言 `run_mode == "normal"`** ——
> **一条把缺陷当契约钉住的断言。**
> 同一个 `st` 里 `load_errors` 明明记着失败，断言却说「正常」。

#### 9.40.3 缺陷 B：`load_errors` 里没有 severity → 「高风险规则不可用」不可判定

`load_errors` 的每一条只有
`phase / file / rule_id / rule_name / error_code / error` —— **没有 severity**。

于是「一条 critical 规则没加载」和「一条 low 规则没加载」在数据上**完全一样**，
文档那句「**高风险规则不可用时**，应触发告警」在数据上**根本无法判定** ——
连「哪些是高风险」这个信息都拿不到。

#### 9.40.4 改动（**纯披露**，不动任何判定）

`run_mode` 判据：

```python
degraded_reasons: list = []
if self._load_errors:
    degraded_reasons.append("load_errors")
if self._skipped_rule_names():
    degraded_reasons.append("skipped_rules")
if not self._compiled:
    mode = "degraded" if self._legacy is not None else "unavailable"
elif degraded_reasons:
    mode = "degraded"
else:
    mode = "normal"
```

并新增 `degraded_reasons` 字段：**降级了要说得出为什么**。
两个分支（`normal` / `unavailable`）都带这个键，为空数组。

`load_errors` 每条都带 `severity`：

| 阶段 | 规则是否已知 | `severity` |
|---|---|---|
| `validate` | **已知**（已解析出来） | **真实级别**（如 `critical`） |
| `compile` | **已知**（`meta` 里已有） | **真实级别** |
| `read` / `parse` / `init` / `reload` | **未知** | 显式的 `"unknown"` |

> **「显式的 `unknown`」与「忘了记这个键」必须能区分开**：
> 前者是一个结论，后者是一个疏漏。
> 所以键**永远存在**；不知道的时候写 `"unknown"`，而不是不写。

⚠ **纯披露**：`run_mode` 与 `load_errors` **没有任何生产消费方**
（全仓只有 `engine.py` 生产、`tests/` 断言、`routers/audit.py` 原样透出），
**没有任何代码按 `run_mode` 分支** —— 所以这次改动**不改变任何检测判定**。
新增的 `degraded_reasons` 同理。

#### 9.40.5 顺带更正一条**把缺陷当契约**的既有断言

`tests/test_review_sigma_detector.py:258`：

```python
-        assert st["run_mode"] == "normal", st
+        assert st["run_mode"] == "degraded", st
+        assert st["degraded_reasons"], st
```

**这是「更正 + 加强」，不是放宽**：

* 修复前断言的是「有坏规则也算正常」；
* 修复后断言的是「有坏规则**必须**报降级**且说得出原因**」。

两条断言在「有坏规则」这个场景下**互斥** ——
所以它不可能是放宽：**改完之后能通过这条断言的实现更少、要求更高。**

本轮**没有**删除任何断言，**没有**放宽任何安全要求。

#### 9.40.6 新增守卫（8 例）

`tests/test_sigma_rule_library_states.py`（**8 例**）：

| 组 | 例数 | 作用 |
|---|---|---|
| `TestTheThreeStatesAreReallyThree` | 4 | 全好 → `normal`；**1 好 1 坏 → `degraded`**（核心性质）；一个都没有 → `unavailable`；空目录 → `unavailable` |
| `TestTheLoadDiagnosticsCanAnswerTheHighRiskQuestion` | 3 | 每条 load_error 都带 `severity` 键；**已知规则报真实级别**；未知规则报显式 `"unknown"` |
| `TestTheDetectionIsUnaffected` | 1 | 回归：部分规则未加载时，好规则照常命中、良性事件不误报（证明是纯披露） |

第 2 组的两条是**配对**判据：
只钉「已知规则报真实级别」而不钉「每条都有这个键」，
守卫会放过一个把已知规则也写成 `unknown` 的实现。

#### 9.40.7 注入验红（4 处，逐条点名）

| 注入 | 红掉的用例 |
|---|---|
| `run_mode` 判据改回「只看有没有编译出规则」 | `test_a_partially_loaded_library_is_degraded` |
| 不再计算 `degraded_reasons`（降级说不出原因） | `test_a_partially_loaded_library_is_degraded` |
| 已知规则也报 `unknown`（「高风险」不可判定） | `test_a_known_rule_reports_its_real_severity` |
| load_error 干脆不带 `severity` 键（忘了记） | `test_every_load_error_carries_a_severity_key`、`test_an_unknown_rule_reports_unknown_explicitly` |

四处都红了，红的就是**对应性质自己的那条用例**；
每处还原后 sha256 一致，最终还原校验通过。

#### 9.40.8 边界

* 本轮**没有**接告警 —— 文档那句「高风险规则不可用时应触发告警」
  现在**具备了判定所需的数据**（`severity`），但**接告警会产生值班呼叫**，
  属运维行为变更，需你拍板 → 与 §9.34 / §9.35 同等处置（先让事实可见）。
* 本轮**没有**改 Legacy 兜底本身的语义（它仍然只在前缀规则可用时启用）——
  §六.2 对 Legacy 的要求是「不能假装它与完整的 pySigma 规则库等价」，
  而 `run_mode` 的 `degraded` + `degraded_reasons` 已经把这个差别**显式化**了。

---

### 9.41 【已补·本轮新增】反弱化门禁的**覆盖盲区**：103 个未跟踪的测试文件、2935 条断言在射程之外

#### 9.41.1 怎么发现的

§9.40 改了一条既有断言（`run_mode == "normal"` → `"degraded"`），
改完顺手跑 CI 里的反假门禁 `tools/assert-no-assert-weakening.py` ——
它**没报**我的改动。

一开始以为是自己读错了分类规则。查下去才发现：
`test_review_sigma_detector.py` 根本**不在 git 里**
（`git status --porcelain` 显示 `??`）。

#### 9.41.2 盲区的机制

门禁取「改动的测试文件」用的是：

```python
code, changed, _ = git(repo, "diff", "--name-only", args.base, "--")
```

`git diff --name-only <base>` **只列已跟踪（tracked）**的文件。
**未跟踪（`git ??`）的新测试文件没有基线可比 → 完全不在覆盖范围内。**

而本轮及前几轮**新建的守卫文件几乎全是 `??`** ——
也就是说「本轮新增的 216 条守卫」**一条都不在门禁射程内**。

实测（改后的门禁输出）：

```
::warning:: 覆盖边界：另有 103 个**未跟踪**的测试文件（git ??）**不在本门禁覆盖范围内**
    规模：这些文件里共有 **2935 条断言**。
```

后果很具体：**这些文件里的断言若被削弱，门禁看不见，CI 照样绿。**

#### 9.41.3 为什么原来的输出看起来是「全查过了」

门禁原本的输出是：

```
[assert-no-assert-weakening] 基线 HEAD，改动的测试文件 18 个
[assert-no-assert-weakening] 结论：REPLACED=14, TEST_REMOVED=2
```

「18 个」听起来像一个**有边界的**数字，
而「结论：REPLACED=14, TEST_REMOVED=2」看起来像**已经覆盖到位**。
**盲区是隐形的** —— 这正是它危险的地方：
门禁在跑、结论是「通过」、而绝大多数测试文件它**根本没见过**。

#### 9.41.4 处置：把边界显式化（**不改退出码**）

* 枚举**未跟踪**的测试文件，报告数量 + 它们一共含多少条断言；
* 枚举失败时**判退出码 2**（与「检测到弱化」区分开）——
  把「不知道」说成「0 个」会让盲区**再次隐形**；
* **不改退出码**：未跟踪文件没有基线，判红就是**恒红**，
  而恒红的门禁会被忽略 —— 那比没有门禁更糟。

> 这与 §9.35 那条「失败被吞要系统扫描」同族：
> **盲区要能被看见、能被数出来** ——
> 否则「门禁在跑」这件事本身就是一种误导。

#### 9.41.5 边界

* 真正的修法是**把新测试文件纳入 git 跟踪** —— 那样门禁才会比对它们。
  本轮**不**代你 `git add`（那是仓库状态变更），只把缺口**显式化**。
* 本轮新增的 11 + 8 + 13 + 9 + 5 + 14 条守卫文件目前都在盲区里；
  它们本身的**注入验红**已逐条做过（§9.39.6 / §9.40.7），
  所以「被人弱化」这个风险目前**未发生** ——
  但门禁**不会**替你发现它。

---

### 9.42 【已修复·本轮新增】因果调整集的**组合族不完整** → 存在合法调整集却报「不可识别」

#### 9.42.1 文档原文（§三.1）

> 修复 extra 候选调整集恒为空的过滤逻辑，**检查所有符合理论条件的候选调整集**。

这一条**只落地了一半**：

* 「extra 分支恒为空」早已修好 —— 候选**池**变成了全部可观测变量
  （`do_calculus.py` 模块 docstring 记着这个修复）；
* 但候选**组合**仍然只有五族：

```python
add(conf)                       # 先验混杂全带
add([])                         # 空集
for c in conf: add([c])         # 单个先验混杂
for n in others: add([n]); add(conf + [n])   # 单个其它变量 / 先验全带+单个其它
for a, b in combinations(others, 2): add([a, b])   # 其它变量两两组合
```

于是**「先验混杂的子集 + 其它变量的多个」这一族一个都没生成过**：
`[c, n]`、`[c, n1, n2]`、`[c1, c2, n1, n2]`、`[n1, n2, n3]` …

#### 9.42.2 实测：存在合法调整集，却报成「不可识别」

构造三条**互相独立**的后门路径（一条过先验混杂、两条过其它变量）：

```
图: HOUR_NIGHT → PORT_SCAN, HOUR_NIGHT → C2_BEACON,
    N1 → PORT_SCAN, N1 → C2_BEACON,
    N2 → PORT_SCAN, N2 → C2_BEACON

backdoor_set 返回 : None            ← 报成「不可识别」
穷举得到的合法集  : [['HOUR_NIGHT', 'N1', 'N2'], ['DST_HUB', 'HOUR_NIGHT', 'N1', 'N2']]
```

单调任何一个都堵不住另外两条，必须 `{c, n1, n2}` 一起调 ——
而这一族**从来没被生成过**。

后果：`intervene()` 返回 `identifiable=False` → `causal_verdict = not_identifiable`。
**效果其实可识别，却被判成不可识别** —— **漏报**方向。

> 候选枚举的覆盖度实测：16 个可观测变量时，
> 池内大小 ≤ 4 的合规候选共 **1471** 个，修复前只生成 **94** 个（**6.4%**）。

#### 9.42.3 修法：补全组合，但**接在原有五族之后**

> 顺序即优先级。

把「池内大小 ≤ `MAX_ADJUST_SET` 的**全部**剩余子集」作为**第二梯队**接在后面，
于是：

* 第一梯队能命中的**仍然先命中** → **既有判定一条都不变**；
* 只有原本**弃权**（`None`）的情况才会变 → 变成**有依据**的可识别。

实测五个对照案例（单条后门 / 两条后门 / 无后门 / 对撞点 / 混杂+其它）
**选出的调整集完全一致**：

| 案例 | 修前 | 修后 |
|---|---|---|
| 单条后门（先验混杂） | `['DST_HUB','HOUR_NIGHT']` | 同左 |
| 单条后门（其它变量） | `['N1']` | 同左 |
| 两条后门（混杂+其它） | `['DST_HUB','HOUR_NIGHT','N1']` | 同左 |
| 无后门（X→Y 直连） | `['DST_HUB','HOUR_NIGHT']` | 同左 |
| 对撞点 M | `['DST_HUB','HOUR_NIGHT']` | 同左 |

**方向说明**：这次改动只会把「弃权」变成「有依据的结论」，
**不会**把任何既有结论改成更强的断言 ——
新增的候选仍必须满足后门准则，不编造任何统计结论（§九）。

#### 9.42.4 顺带把成本问题解决了：枚举改**惰性**

补全后候选数可达 1471，而 `backdoor_set` 其实只需要**第一个**满足准则的集。
第一版实现把 1471 个候选**全部物化**成 list → 实测 **1.996 ms/次**（×6.5）。

改成惰性生成（`_iter_candidate_adjust_sets`）后：

| 版本 | 耗时 |
|---|---|
| 修复前（物化 94 个） | 0.366 ms/次 |
| 补全但仍物化 | 1.996 ms/次 |
| **补全 + 惰性（现用）** | **0.186 ms/次（×0.5，反而更快）** |

> 补全枚举**没有**带来性能负担 —— 代价来自**物化**而不是**搜索**。
> 这与 §9.38 那条「判据要用对工具」同源：
> **同一个算法，惰性与物化的实现成本可以差一个数量级。**

#### 9.42.5 顺带披露：候选池的**静默截断**

`MAX_ADJUST_POOL = 12` 会把排在前面的可观测变量**悄悄丢掉**。
被丢掉的变量若正好在后门路径上 → 同样报成「不可识别」，
而原因在数据上**完全不可见**。

按 §9.24 的判据（「避免静默截断；若必须限长，标记不完整」），
截断数现在随 `assumptions.adjust_pool_truncated` 一起落库：

```
可观测变量  6 个 → adjust_pool_truncated = 0
可观测变量 16 个 → adjust_pool_truncated = 0
可观测变量 18 个 → adjust_pool_truncated = 2   ← 图节点上限 MAX_NODES=20 时会触发
```

#### 9.42.6 新增守卫（13 例）

`tests/test_causal_adjust_candidate_completeness.py`（**13 例**）：

| 组 | 例数 | 作用 |
|---|---|---|
| `TestTheSearchFindsAValidSetWhenOneExists` | 3 | **核心性质**：三条独立后门 → 可识别；**前提守卫**（三条后门真的互相独立、修前实现真的在这个案例上失败） |
| `TestTheEnumerationIsExhaustive` | 3 | 池内大小 ≤ `MAX_ADJUST_SET` 的**全部**子集都在候选里；空集仍保留；**原有五族仍排在补全组合之前** |
| `TestTheExistingVerdictsAreUnchanged` | 5 | 五个对照案例选出的调整集**与修前逐条一致**（参数化） |
| `TestThePoolTruncationIsDisclosed` | 2 | 截断数披露正确；没截断时是 0 |

第 1 组的**两条前提守卫**很重要：
没有它们，「核心性质」可能是因为「图退化成了一条后门」而绿，
或者是因为「修前本来就能识别」而绿。

#### 9.42.7 注入验红（4 处，逐条点名）

| 注入 | 红掉的用例 |
|---|---|
| 去掉第二梯队（组合不补全） | `test_three_independent_backdoors_are_identified`、`test_every_pool_subset_of_allowed_size_is_generated`、`test_the_legacy_families_still_come_first` |
| 把空集提到先验混杂之前（顺序即优先级被破坏） | `test_the_same_adjustment_set_is_still_chosen[无后门…]`、`…[对撞点…]` |
| 不披露候选池截断数 | `test_the_truncation_count_is_reported`、`test_no_truncation_reports_zero` |
| 把空调整集过滤掉 | `test_every_pool_subset_of_allowed_size_is_generated`、`test_the_empty_set_is_still_generated` |

四处都红了，红的就是**对应性质自己的那条用例**；
每处还原后 sha256 一致，最终还原校验通过。

#### 9.42.8 边界

* 本轮**没有**动 `MAX_ADJUST_POOL` 的取值 —— 它是**上限**，改了会改变搜索规模；
  现在改成**披露**截断数（§9.42.5），要不要把上限提到图节点上限（`MAX_NODES=20`）
  属**性能/完备性**的取舍 → **登记为待决项 26**。
* 本轮**没有**动 `intervene` 的估计逻辑（分层估计、ACE 计算）——
  变的只是「找不找得到合法调整集」。
* 既有因果判定**一条都没变**（§9.42.3 的五个对照案例）。

---

### 9.43 【已修复·本轮新增】TLS 挂起会话在缓冲区溢出时被**静默丢弃** —— C2 证据在高峰期消失

#### 9.43.1 怎么发现的

做 §9.42 时顺手扫了「核心检测模块里的**集合截断**」，
用的是 AST（只认 `[:N]` 形式的切片，排除字符串切片），
结果在一堆显示层截断里捞到一条**形态很正**的：

`encrypted_traffic/session_collector.py` 里有**两条**「丢掉一个挂起会话」的路径，
行为完全不一致：

| 路径 | 修复前 | 结果 |
|---|---|---|
| 超时 `_sweep_expired` | `stats["expired"] += 1` + `await self._flush(key)` | **落库 + 计数** ✓ |
| 溢出 `_evict_oldest` | `self._pending.pop(oldest, None)` | **直接丢掉** ✗ |

同一个模块、同一个动作（丢掉一条挂起会话），
一条路径记得落库并计数，另一条**什么都不留**。

#### 9.43.2 实测：证据静默消失，且**不可见**

```
=== 路径 1：挂起会话超时 ===
   _flush 被调用 : [('10.0.0.9', '10.0.0.2', 443)]
   stats         : {'sessions': 0, 'expired': 1, 'pending': 1}
   >>> 超时的会话**落库了**，且 expired 计数 +1 ✓

=== 路径 2：缓冲区满（>= _MAX_PENDING）===
   填满后 pending = 2000 （上限 2000）
   _flush 被调用 : []          ← 没落库
   落库记录      : []          ← 没落库
   被驱逐的 key 还在 pending 里吗？ False
   stats         : {'sessions': 0, 'expired': 0, 'pending': 2000}
   >>> 溢出路径：会话**被静默丢弃** —— 不落库、不计数、不打日志 ✗
```

被驱逐的会话**不进 `tls_sessions`、不评分、不触发 LLM 语义判定** ——
C2 检测的证据**静默消失**。

而且它恰好发生在**流量最高**的时候（>2000 个并发挂起握手），
也就是攻击最可能发生的时候。

更糟的是**看不见**：`stats` 全仓**零消费方**（实测），
所以即使只加一个本地计数也仍然不可见。

#### 9.43.3 这条路径是**活的**（严重级别）

`app.py:267-272`：

```python
from encrypted_traffic.session_collector import tls_session_collector
...
dissector.on_message(tls_session_collector.on_message)
```

即 `capture_enabled` 时它就接在流量采集链路上 ——
**不是** §7.1.4 那种休眠模块。

同时发现：**`TlsSessionCollector` 此前一个测试都没有** ——
`tests/` 里 `test_inc_ndr.py` 覆盖的是 TLS 元数据层，
会话**关联器**（决定哪些握手变成评分/落库/LLM 会话的那一层）**零覆盖**。

#### 9.43.4 修法：与超时路径**对齐**

1. 被驱逐的那一条**照样 flush 落库**（SNI/JA3 仍有价值）；
2. `stats["evicted"]` 计数；
3. 新增 `soc_tls_session_evicted_total` 指标 ——
   `stats` 没有消费方，只加本地计数仍然不可见。

**不会造成写放大**：被驱逐的会话本来也会在 `_SESSION_TIMEOUT` 之后被 flush，
驱逐只是把 flush **提前**，落库总数不变。
（守卫里有专门的「不写放大」用例钉住这一点。）

新指标同样按 §9.34 / §9.35 的做法**登记进 `UNWATCHED`、不接告警** ——
接告警会产生值班呼叫，属运维行为变更，需你拍板。
指标计数因此从 65/43 变为 **66/44**。

#### 9.43.5 新增守卫（9 例）

`tests/test_tls_session_evict_visibility.py`（**9 例**）：

| 组 | 例数 | 作用 |
|---|---|---|
| `TestTheEvictedSessionIsNotLost` | 4 | 核心性质：被驱逐的会话**必须落库**；本地计数 +1；指标自增；**反向**：没驱逐就不许计数 |
| `TestTheTimeoutPathIsUnchanged` | 1 | 超时路径**不受影响**（这次修复不能改坏既有行为） |
| `TestTheTwoDropPathsAreSymmetric` | 2 | 两条丢弃路径**对称**（都有落库 + 计数）；**不写放大**（一次驱逐只多做 1 次 flush） |
| `TestThePremises` | 2 | 前提守卫：上限真实可达；**这条路径确实在 `app.py` 里接线**（否则严重级别要重估） |

第 4 组的「反向判据」很关键：只钉「驱逐会计数」而不钉「不驱逐不计数」，
守卫会放过一个无条件计数的实现。

#### 9.43.6 注入验红（4 处，逐条点名）

| 注入 | 红掉的用例 |
|---|---|
| 驱逐改回直接丢弃（不落库） | `test_the_evicted_session_is_flushed`、`test_both_paths_flush_and_count`、`test_the_eviction_does_not_add_flushes` |
| 不记本地计数 | `test_the_eviction_is_counted`、`test_both_paths_flush_and_count` |
| 不进指标 | `test_the_eviction_is_visible_in_the_metric` |
| 超时路径不计数（对称性被破坏） | `test_an_expired_session_is_still_flushed_and_counted`、`test_both_paths_flush_and_count` |

四处都红了，红的就是**对应性质自己的那条用例**；
每处还原后 sha256 一致（`b6598b54fde08719…`），最终还原校验通过。

> 这次注入过程里踩了一个**操作坑**，如实记录：
> pytest 刚跑完的那一瞬写回文件报 `OSError: [Errno 22] Invalid argument`
> （文件锁/antivirus），**还原没写成功 → 注入留在了工作区**。
> 是靠「最终 sha256 校验」当场发现的，随后从备份强制还原。
> **注入脚本的写回必须带重试，且必须以最终 sha256 校验收尾** ——
> 否则「验红」本身会把工作区弄脏。

#### 9.43.7 边界

* 本轮**没有**改 `_MAX_PENDING` 的取值（2000）——
  它是内存保护上限，改了是**容量/性能**决策。
  现在改成了**背压信号**（指标可见），要不要提高上限 → 与待决项 26 同族，
  属**容量取舍**，不单方面做。
* 本轮**没有**给这个模块补齐**全部**测试覆盖 ——
  新守卫只覆盖「两条丢弃路径」这一族；
  握手三消息的关联逻辑（ClientHello/ServerHello/Certificate 的配对与乱序）
  仍然没有回归，属**待补**（登记在此，不假装已覆盖）。

---

### 9.44 【已补·本轮新增】§十三「全量回归」行的隐含前提**不成立** —— 22 个**活跃**叶子模块零测试覆盖（170 KB）

#### 9.44.1 怎么发现的

§9.43 在 `encrypted_traffic/session_collector.py` 里挖出「C2 证据被静默丢弃」，
而那个模块**此前一条测试都没有**。
顺着这个线索，把问题从「一个模块没测试」抬到「**有多少个活跃模块没测试**」。

§7.1.5 已经扫过**休眠**模块（33 个）；本轮扫的是**活跃**模块的零覆盖面。

#### 9.44.2 实测

```
backend 模块总数        : 508
测试文件数              : 197
解析失败的文件数        : 0        ← **必须为 0**（见 §9.44.3）
被**包外**生产代码引用的模块数: 193
其中**零测试覆盖**的    : 22        （非入口层的叶子模块，合计 170 KB）
入口层同样没被 import 的: 8        （HTTP 入口，静态判据结构性失效）
```

「零覆盖」的判据：全仓 `tests/` 里既没有 import 它，
也没有任何测试文件在**代码**里引用它的标识符 —— 两项都用 **AST** 判，
不用文本（grep 会把 docstring 里的提及算进去）。

这 22 个模块里有：

| 模块 | 为什么它重要 |
|---|---|
| `response_engine/ttl_manager.py` | 响应动作 TTL —— 零覆盖，且**生产里从未被调用**（`register` 不可达 / scanner 从未启动 / 无 redis 与回调，§9.53） |
| `protocol_parser/tls_parser.py` / `dissector.py` | **C2 会话证据的来源** |
| `phishing_guard/drill_manager.py` | 钓鱼演练编排（演练触发的是**真实响应动作**） |
| `traffic_capture/pcap_store.py` | PCAP 落盘（流量证据） |
| `rag/seeder.py`（44 KB） | 检索链的大件 |
| `stabilizer/stabilizer.py` / `json_repair.py` | 输入稳定化（**且整条管线没有生产调用方**，见 §9.44.5） |
| `memory_tree.py`（11 KB） | 记忆树 |
| `protocol_parser/{http,dns,smb}_parser.py` | 其余协议解析 |
| `rag/context_builder.py` / `traffic_capture/flow_aggregator.py` | RAG 上下文 / 流量聚合 |
| 其余 7 个 | 资产历史 / 上下文流 / 依赖健康 / 评估服务 / 阶段事件 / 统计计数 / 用户存储 |

> §十三 的「全量回归」验收行写的是「全量测试通过」——
> 而**全量测试压根看不见这 170 KB 的生产代码**。
> 这不是「测试没过」，是「**测试够不着**」。

#### 9.44.3 这个扫描器自己踩了**五次**坑（如实记录）

| 版本 | 缺陷 | 造成的假结论 |
|---|---|---|
| v1 | 只认「import 的模块路径」，认不出 `from pkg import mod` | **45** 个（误报 21 个，包括 `mcp_guard/permission_manager.py`、`response_engine/policy_store.py`） |
| v1.1 | 认出了 `from pkg import mod`，但**别名**把原名遮住（`from mcp_guard import permission_manager as pm` 只记了 `pm`） | 靠**已知答案自检**抓到的 |
| v2 | 「活跃」没区分**包内 / 包外**引用 —— 模块被**自己包内**的兄弟 import 也算「活」 | 结论**虚高**（整体休眠的包，其内部文件全被算成活跃） |
| v3 | 用 `utf-8` 解码 → **带 BOM 的 `app.py` 解析失败被静默跳过** | **最隐蔽的一个**：`app.py` 恰恰是 `protocol_parser.dissector` 等模块**唯一的包外引用方** → 结论失真 |
| v3.1 | 包的 `__init__.py` 模块名**多切了 3 个字符**（`rag/__init__.py` → `""`、`asset/__init__.py` → `"as"`） | 空模块名混进清单 |

最终口径（v4）：

* **活跃** = 被**包外**生产代码引用；
* **零覆盖** = 非入口层的叶子模块，且 `tests/` 里连它的名字都没出现过；
* `routers/` 下的 HTTP 入口**单列** —— 它们通常由**端点级测试**覆盖，
  而测试文件从不 import 路由模块 → 静态判据对它们**结构性失效**，
  混进结论会**系统性地误导**；
* **解析失败的文件数必须为 0** —— 失败的文件被静默跳过，
  它的 import 全部不可见 → 结论虚高。

**五次都是自检抓到的，不是事后看出来的** ——
所以这个扫描器带了 8 条**已知答案自检**
（`tools/scan-active-zero-coverage.py::SELFCHECK`）
外加一条「解析失败数必须为 0」的守卫。

> 工具已入库：`tools/scan-active-zero-coverage.py`（可复跑，带 `--json` 出口）。

#### 9.44.4 处置：把缺口**显式登记**并双向钉住

本轮**不**试图一次性补 22 个模块的测试（那是几天的工程量，且需要真实依赖）。
做法与 §7.1.5 / §7.1.13 一致：**把缺口变成必须签字的清单**。

* `tools/scan-active-zero-coverage.py` —— 扫描器入库，范围**自动推导**；
* `tests/test_active_module_coverage_gap.py`（**6 例**）——
  实测清单与**显式登记表**（22 条，每条写明理由）**双向相等**：
  * 新增一个没被覆盖的活跃模块 → 转红（缺口不能悄悄扩大）；
  * 给某个模块补了测试 → **也**转红（必须同步登记表）；
  * 每条都必须写理由（不能只列名字）；
  * **安全关键**的 5 条必须**在**登记表里（不能被悄悄删掉）；
  * 扫描器的 8 条已知答案自检必须通过；
  * **解析失败的文件数必须为 0**（§9.44.3 的 v3 那个坑）；
  * 扫描结果**与当前工作目录无关**（否则 CI 与本机会给出不同答案）。

#### 9.44.5 注入验红（3 处，逐条点名）

这次的注入对象是**守卫自己的登记表** —— 要验证的是「登记表被改坏时守卫会不会转红」。

| 注入 | 红掉的用例 |
|---|---|
| 从登记表里删掉一条**安全关键**的 | `test_the_measured_list_equals_the_registry`、`test_the_security_critical_ones_are_still_registered` |
| 从登记表里删掉一条**普通**的 | `test_the_measured_list_equals_the_registry` |
| 某条没写理由 | `test_every_registered_entry_has_a_reason` |

三处都红了，红的就是**对应性质自己的那条用例**；
每处还原后 sha256 一致，最终还原校验通过。

#### 9.44.6 边界

* 本轮**没有**补这 22 个模块的测试 —— 那是**工程量决策**，不是缺陷修复；
  清单已登记并钉住，**优先级**已按「安全关键 / 检索链大件 / 其余」排好。
* 清单里 `encrypted_traffic.session_collector` **不在**了 ——
  它被 §9.43 的新守卫覆盖了。修复前它**在**这份清单里（它正是 §9.43 的藏身处）。
* 清单里 `qdrant_store` **也不在**了 —— 它被 §9.50 的降级产物守卫覆盖了
  （那正是「降级产物入库」那条路的所在）。修复前它**在**这份清单里，
  清单因此从 **23 → 22**、**188 KB → 170 KB**；
  双向相等守卫在第 21 次全量回归里**当场转红**要求同步 —— 这正是它该做的事。
* 判据是「**没有测试引用**」，不是「测试质量差」——
  有测试但没测到关键路径的模块，这份清单**看不见**。
  「零覆盖」是这份清单能回答的问题；「覆盖够不够」是另一个问题。
* 判据是**静态**的：它回答「测试里连名字都没出现过」，
  **不**回答「行为有没有被测到」——这是两个问题，别混。
* **入口层单列**：8 个 `routers/` 模块同样没被 import，
  但它们很可能已被**端点级测试**覆盖 → 本节**不**据它们下结论。
* **这份清单会变短，而且是被守卫逼着变短的**：§9.45 给
  `response_engine/transport.py` 补了 14 条守卫 → 它从清单里消失 →
  双向相等守卫当场转红 → 登记表必须同步。
  **「登记表与实测不一致」本身就是一条告警** ——
  它说明有人在补测试（好）或者在删登记（坏），而清单本身没跟上。

---

### 9.45 【已修复·本轮新增】Windows 响应动作被平台**自己的白名单**全拦下 —— `platform` 没转发

#### 9.45.1 怎么发现的

§9.44 挖出了一份「活跃模块零测试覆盖」清单，
其中就有 `response_engine/transport.py` —— **响应动作的实际下发通道**。
零覆盖意味着里面藏着什么都不会有人发现。
（补完这一节的测试后，它已经从 §9.44 的清单里消失 ——
双向相等守卫当场转红，登记表是同步过的。）

于是一个一个读。第一个读的是 `transport.py`，没看出问题；
但顺着调用方往回读，在 `response_registry.py` 里看到了。

#### 9.45.2 缺陷：第二道白名单检查用错了平台

链条：

```
response_registry._block_ip → cmd = _ps_cmd(script)（已 Base64 编码）
  → _exec(cmd, action, platform="windows")
    → safe_executor.execute(command=cmd, platform="windows")
      → command_whitelist.check(cmd, "windows")     ← WIN-004 放行 ✓
    → _live_fn(command)
      → ssh_transport.run(command, powershell=use_powershell)
           ⚠ **没有传 platform** → run() 用它自己的默认值 platform="linux"
      → command_whitelist.check(command, "linux")   ← **必然不匹配** ✗
```

修复前的那一行：

```python
# response_registry.py
result = await ssh_transport.run(command, powershell=use_powershell)
```

而 `transport.run()` 的签名是
`run(command, timeout=30, powershell=True, platform="linux")` ——
**`platform` 默认 "linux"**。

linux 规则里**没有任何一条**能匹配 `powershell ... -EncodedCommand <b64>` →
**每一个** Windows 响应动作都被白名单拒绝。

实测（修复前）：

```
=== 第一道检查：safe_executor 用 platform='windows' ===
   windows        → allowed=True  rule=WIN-004

=== 第二道检查：transport.run() 用 platform='linux'（调用方没传！）===
   linux          → allowed=False rule=-   命令不在白名单中 (platform=linux)

=== 直接调 ssh_transport.run(cmd, powershell=True) ===
   success      = False
   error        = '命令白名单拒绝: 命令不在白名单中 (platform=linux)'
   blocked_by   = 'command_whitelist'
```

#### 9.45.3 后果：静默降级为桩，且**诊断被引向错误方向**

`response_transport_mode` 默认 **`"auto"`**（`config.py:72`），
而 `auto` 模式下 `transport.run()` 失败 → `_live_fn` 走 else 分支 → **桩回退**：

```
logger.warning(f"[SSH/{platform}] {action} failed, fallback to stub: {result['stderr'][:100]}")
```

而白名单拒绝时 `result["stderr"]` 是**空串** → 这行日志里原因是**空的**；
`_stub_fallback` 自己的日志又写死了另一句：

```
[STUB] block_ip would execute: {'src_ip': '1.2.3.4'} (SSH transport requires RESPONSE_SSH_HOST config)
```

**SSH 明明配好了**（否则 `_live_fn` 根本不会走到 `transport.run()`），
真正的卡点是「命令白名单拒绝」——
但运维看到的提示是「需要配置 RESPONSE_SSH_HOST」，
**会被引到一个根本没问题的方向上去**。

影响面：`response_registry` 的**全部**动作
（`block_ip` / `isolate_host` / `rate_limit` / `remove_rate_limit` /
`kill_session` / `send_alert` / 桌面通知）都走 `_exec(cmd, ...)`，
而 `_exec` 的 `platform` 默认就是 `"windows"` → **无一例外**。

> 好消息：桩回退的结果带 `_stub: True` 且**没有** `success` 键，
> 所以它**不会谎报成功**。问题在「不执行」+「原因被说错」。

#### 9.45.4 修法：三处，全是「少走弯路」

1. **转发 `platform`** —— 白名单本来就按平台参数化，这里传对即可；
2. **`powershell=False`** —— 命令**已经是** `_ps_cmd()` 产出的最终形态
   （`powershell -NoProfile ... -EncodedCommand <b64>`），
   再让 transport 编码一次会变成**双层** powershell ——
   **内层脚本的 `exit N` 会被外层吞掉，失败的动作会被报成 success**。
   单层时，远端执行的就是**被白名单校验过的那条命令**（逐字相同）。
3. **失败原因必须可见** —— 白名单拒绝时 `stderr` 是空串，
   改用 `result.get("error")`；**桩回退也必须把真实原因带回结果**
   （`_stub_fallback(reason=...)`），而不是写死一句关于 SSH 配置的猜测。

实测（修复后，端到端，mock 掉 ssh 子进程）：

```
=== 修复后的调用形态：run(cmd, powershell=False, platform='windows') ===
   success   = True
   真正下发到远端的命令：
   powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand JABuAGEAbQBlACAAPQAgACIAUgBFA...
   >>> 下发的就是被白名单校验过的那条命令（未二次编码）: True
   >>> 双层 powershell（被误编码）: False

=== 对照：修复前的形态 ===
   success   = False
   error     = 命令白名单拒绝: 命令不在白名单中 (platform=linux)
   到达 SSH 了吗: False
```

#### 9.45.5 新增守卫（14 例）

`tests/test_response_transport_platform.py`（**14 例**）：

| 组 | 例数 | 作用 |
|---|---|---|
| `TestTheWindowsCommandReachesTheHost` | 3 | 核心性质：按 windows 规则放行；**真的到达 SSH**；下发的命令与被校验的**逐字相同** |
| `TestThePlatformMustMatch` | 2 | **反向**：同一条命令按 linux 规则**必须**被拒；**修复前的调用形态必须到不了 SSH** |
| `TestTheCallerMustForwardThePlatform` | 3 | 调用方**必须**转发 platform（用捕获实际调用判定，不用源码文本）；**不得二次编码**；executor 收到的 platform 也是 windows |
| `TestTheLinuxPathIsUnaffected` | 2 | linux 路径不受影响 |
| `TestTheFailureReasonIsVisible` | 2 | 白名单拒绝时 `error` 非空；**桩回退必须带原因** |
| `TestThePremises` | 2 | 前提守卫：默认模式是 `auto`（会静默降级的那条）；**至少 5 个动作**走 `_exec`（影响面结论的前提） |

第 2 组的「反向判据」很关键：只钉「能放行」而不钉「错平台必须拒」，
守卫会放过一个「把检查放松了」的实现。

#### 9.45.6 自曝：这个修复**自己还漏了一处**，被守卫当场抓住

第一版修复只改了**日志**（用 `result.get("error")`），
没改**桩回退的结果**。新写的守卫跑出一个红：

```
AssertionError: 桩回退**没有带任何原因** —— 调用方无从判断是白名单拒了还是 SSH 没配：
{'action': 'block_ip', 'mode': 'stub', 'src_ip': '1.2.3.4', '_stub': True}
```

补完之后才真正闭合：**桩回退不执行任何动作，但它必须说清为什么没执行。**

#### 9.45.7 同一形态的**第二个实例**（只登记，不改）→ 待决项 27

`response_engine/containment/host_adapter.py`（宿主机遏制：kill_process /
quarantine_file …）传的是**原始 PowerShell 脚本**，不是编码形态：

```
── digest 分支
   windows 规则：allowed=False rule=GLOBAL
   原因：命令包含禁止子串: ';'
   GLOBAL_FORBIDDEN 命中：[';', '|']

── pid 分支
   windows 规则：allowed=False rule=GLOBAL
   原因：命令包含禁止子串: ';'
```

即：**每一次 `ssh_transport.run()` 都会被拒**。
与 §9.45.3 不同的是，它**如实上报 `success=False`**（不会静默降级），严重级别低一档。

**但本轮不改它**，因为修法有**安全面**变化：
要让它过白名单，就得像 `response_registry._ps_cmd()` 那样**先编码** ——
而编码之后 `GLOBAL_FORBIDDEN` 就**看不见脚本内容**了
（注入检测从「看得见」变成「看不见」）。

缓解事实：这些脚本由适配器**自己构造**，输入只有
已校验的 PID / SHA-256 摘要 / 过 `reject_path` 的路径 → 风险有界。
但「注入过滤器还看不看得见内容」是**安全设计**问题 → 登记为**待决项 27**。

#### 9.45.8 注入验红（3 处，逐条点名）

| 注入 | 红掉的用例 |
|---|---|
| 不再把 `platform` 转发给 transport（还原原缺陷） | `test_live_fn_forwards_the_platform` |
| 让 transport 二次编码（双层 powershell） | `test_live_fn_does_not_double_encode` |
| 桩回退不带原因 | `test_the_failure_result_carries_the_reason_to_the_caller` |

三处都红了，红的就是**对应性质自己的那条用例**；
每处还原后 sha256 一致（`5e60ec9f092c5e76…`），最终还原校验通过。

#### 9.45.9 边界

* 本轮**没有**改白名单规则本身 —— 问题是**调用方传错了参数**，
  规则按平台生效是对的（反向用例已钉住）。
* 本轮**没有**让 `host_adapter` 那条路径恢复（见 §9.45.7 / 待决项 27）。
* 本轮**没有**验证「命令真的在远端生效」——
  那需要一台真的 Windows 宿主机（§三 的「待验证」清单），
  本轮验到的是「命令通过了平台白名单并以**被校验过的形态**下发」。

---

### 9.46 【已修复·本轮新增】MCP 工具把「模拟执行」报成「成功」—— 活跃路径上的**谎报成功**

#### 9.46.1 怎么发现的

§9.44 的零覆盖清单把 `mcp_guard/` 之外的几处也照了进来，
顺着 `security_guard/sequence_guard.py` 往下读到 `mcp_guard/tool_registry.py` ——
那里的 6 个执行器**全是模拟实现**（作者自己的 docstring 写着
「模拟防火墙封禁IP」「模拟EDR主机隔离」…），但它们返回：

```python
{"status": "success", "action": "block_ip",
 "detail": f"已封禁 {ip}，时长 {duration} 秒", "device": "firewall"}
```

#### 9.46.2 这条路径是**活的**

```
POST /api/audit/guard/call        （routers/audit.py:202，需 JWT 鉴权）
  → guard_server.call_tool()       （4 层检查：注册 / RBAC / 参数 / 策略）
    → _finish()：`decision.status == "allow"` → `self.registry.execute(...)`
      → mcp_guard/tool_registry.py 的 **_exec_block_ip 等模拟执行器**
        → {"status": "success", "detail": "已封禁 1.2.3.4…"}
```

`settings.mcp_guard_enabled` 默认 **True**（`config.py:289`），
所以这不是休眠路径 —— 与 §7.1.4 的休眠纪律不同，严重级别按**活跃**算。

> **影响面要说准**：全仓搜 `call_tool` 的调用点，**生产入口只有那一个 API 端点**；
> **LLM agent 不走这条链**（`agents/agent_executor.py` 走的是
> 主 `tool_registry.execute`，那是审计查询面，另一套实现）。
> 所以爆炸半径限于「有人直接调这个端点」，
> 而不是「每个 LLM 工具调用都会谎报」。

#### 9.46.3 实测：哪些会被**直接放行**并真的落到模拟器

| 工具 | 风险 | 决策 | 修复前 |
|---|---|---|---|
| `rate_limit` | MEDIUM | **allow** | **谎报成功** |
| `vulnerability_scan` | LOW | **allow** | **谎报成功** |
| `block_ip` | HIGH | require_confirmation | 不执行 |
| `terminate_process` | HIGH | require_confirmation | 不执行 |
| `isolate_host` | CRITICAL | require_confirmation | 不执行 |

（高风险的三个虽然不执行，但 `mcp_guard/approval_queue.py::approve`
**没有生产调用方** —— 只有测试在调 —— 所以那条路也走不通。）

`vulnerability_scan` 那种最恶劣：它声称**做了一次安全扫描**
并给出「**发现 0 个漏洞**」的结论 —— 一个**从没跑过**的扫描。
运维看到「扫描完成，发现0个漏洞」会**放心地**不处理这个目标。

而**真正**干活的响应动作在 `response_engine/response_registry.py`
（SSH / 防火墙 / QoS）—— **MCP 路径根本够不着它**（两条链没有交汇）。

#### 9.46.4 修法：纯诚实性

模拟就是模拟，**不许报成功**。六个执行器统一走一个收口：

```python
{
  "status": "simulated",
  "executed": False,
  "simulated": True,
  "action": "rate_limit",
  "detail": "[模拟] 对 1.2.3.4 设置速率限制: 100 req/s（**未实际下发**）",
  "device": "firewall",
}
```

实测（修复后）：

```
rate_limit        {'status': 'simulated', 'executed': False, 'simulated': True, ...}
vulnerability_scan {'status': 'simulated', 'executed': False, 'simulated': True, ...}
```

**没有**把 MCP 路径接到真干活的响应引擎 —— 那是**接线决策**（见 §9.46.5）。

#### 9.46.4.1 连带更正了**三条既有断言**（如实记）

改完之后全量回归报了 3 个失败 —— 都是既有测试断言了
`execution["status"] == "success"`。逐条查了它们的**主体**：

| 用例 | 主体 | 那条断言的**真实作用** |
|---|---|---|
| `test_caller_identity_is_not_spoofable` | 请求体里的 `caller` 不得被采纳 | 「确认调用真的到达了工具」的代理（作者自己在注释里写着「执行结果由 mock 工具返回」） |
| `test_detector_crash_fail_open_in_deny_mode` | 检测器崩了 → fail-open，不阻断 | 「没被拦住」的代理 |
| `test_detector_exception_fail_open_eval` | 同上 | 同上 |

**没有一条的主体是「status 必须是 success」** —— 它们只是借它来表达
「调用到达了执行器」。而 MCP 的执行器**是模拟实现**，
它原先把模拟执行报成 success —— **那正是 §9.46 修掉的谎报**。
留着那条断言，等于**把谎报钉成契约**。

改法：断言「调用确实到达了执行器」——用 `action`（比 `status` 更能说明
**哪个**工具跑了 → **并不放宽**），并额外钉住「不许报 success」：

```python
assert resp.get("execution", {}).get("action") == "alert_only"
assert resp["execution"]["status"] != "success", (
    "模拟执行器不许报成功（§9.46）")
```
> **净效果是断言更准、更严**：旧断言无法区分「真执行成功」与「模拟报成功」；
> 新断言能区分。**没有**删任何断言，**没有**放宽任何安全要求。

#### 9.46.5 顺带查出来的问题：**参数契约有四方声明**

同一个工具的参数，在**四个地方**各有一份声明，而它们**互相不一致**：

| 工具 | MCP 面（给 LLM） | 转换器 `PARAM_SCHEMAS` | 动作注册表 `params_schema` | 动作签名 |
|---|---|---|---|---|
| `block_ip` | `ip`, `duration` | `ip`, `duration`, `reason` | `src_ip`, `reason`, `duration_minutes` | ✓ 与左边一致 |
| `isolate_host` | `host`, `isolation_type` | `hostname`, `isolation_type`, `reason` | `host_ip`, `reason`, `extra_ips`, `duration_minutes` | ✓ |
| `rate_limit` | `ip`, `rate` | `target`, `rate`, `duration`, `unit`, `reason` | `src_ip`, `bandwidth_kbps`, `reason` | ✓ |
| `alert_only` | `title`, `message` | `title`, `severity`, `description`, `recipients` | (注册名是 `send_alert`) | `_send_alert(title, message, severity, …)` |

所以：**MCP 面告诉 LLM 用 `ip`，而动作要的是 `src_ip`**
（v4.1 重构把动作参数改名时，MCP 面与转换器都没跟上）。
而转换器那一份是**第三套**（`target` / `hostname`），且它一旦被启用
（目前**没有生产调用方**，整条 `stabilizer` 管线是休眠的），
会把动作真正要的 `src_ip` 当「未知字段」**剥掉**。

`causal.graph` 的 schema 是**空的** `{}` → 转换器会把**所有**参数
当未知字段剥掉，而必填校验因为 schema 为空而**通过** →
**静默地以空参调用**。

「以哪份声明为准」是**契约决策** → 登记为**待决项 28**（与「要不要接线」是同一件事的两面）。

#### 9.46.5.1 把三方差异**数清楚**（不是三个名字，是三组数）

```
响应引擎注册的动作            : 12 个
  block_ip, isolate_host, rate_limit, dns_sinkhole, kill_session,
  send_alert, kill_process, quarantine_file, clean_persistence,
  disable_account, forensic_snapshot, recall_email

MCP 面给 LLM 的工具            : 6 个
  alert_only, block_ip, isolate_host, rate_limit,
  terminate_process, vulnerability_scan

转换器 PARAM_SCHEMAS 的键      : 17 个（含全部 6 个 MCP 工具 ✓）

MCP 面有、响应引擎**没有**     : 3 个
  → alert_only / terminate_process / vulnerability_scan
  → **即使把 MCP 路径接到响应引擎，这三个也「无动作可调」**

响应引擎有、转换器**没有**     : 9 个
  → clean_persistence / disable_account / dns_sinkhole /
    forensic_snapshot / kill_process / kill_session /
    quarantine_file / recall_email / send_alert
  → 转换器不认识这 9 个**真实存在**的响应动作
```

还有一处**最阴**的（§9.46.9）：`causal.graph` 的 schema 是**空的** `{}`
→ 转换器把**所有**参数当「未知字段」剥掉，
而必填校验因为 schema 为空而**通过** → **静默地以空参被调用**。

#### 9.46.6 新增守卫（12 例）

`tests/test_mcp_tool_honesty.py`（**12 例**）：

| 组 | 例数 | 作用 |
|---|---|---|
| `TestNoSimulatedToolMayClaimSuccess` | 3 | **核心性质**：每个执行器都**不得**返回 `status == "success"`；必须带 `executed: False` + `simulated: True`；detail 必须说明**未实际下发** |
| `TestTheEndToEndPathDoesNotClaimSuccess` | 7 | 端到端走 Guard 链：被放行的工具返回的 `execution` 不能是 success；**审计记录**的 `exec_status` 同样不能是 success；高风险工具**仍然**要求人工确认（这次修复没碰策略） |
| `TestThePremises` | 2 | 前提守卫：这些执行器**确实是模拟**（docstring 写着「模拟」）→ 所以「报 simulated」是**准确**的；这条路径**是活的**（`mcp_guard_enabled` 默认 True + 有 API 端点） |

第 2 组把「审计记录」单独列一条，是因为
**能力看板与审计回放读的是记录而不是返回值** ——
记录说成功，谎报就成立了。

#### 9.46.7 注入验红（3 处，逐条点名）

| 注入 | 红掉的用例 |
|---|---|
| 恢复成报 `success`（还原原缺陷） | `test_no_executor_reports_success` + 4 条端到端用例（`rate_limit` / `vulnerability_scan` 各两条） |
| 去掉 `executed` 标记 | `test_every_executor_marks_itself_as_not_executed` + 2 条端到端用例 |
| detail 不再说明未实际下发 | `test_the_detail_says_it_was_not_dispatched` |

三处都红了，红的就是**对应性质自己的那条用例**；
每处还原后 sha256 一致（`81df1d5f03d0afcb…`），最终还原校验通过。

#### 9.46.8 边界

* 本轮**没有**把 MCP 路径接到真干活的响应引擎（待决项 28）。
* 本轮**没有**统一四方参数声明（同一件待决项）。
* 本轮**没有**改 MCP 的策略层（高风险工具仍然要求人工确认）——
  这次只修「模拟报成功」这一处诚实性问题。
* `vulnerability_scan` 修复后返回「[模拟] 漏洞扫描: 目标=…（未实际下发）」——
  它**不再**声称「发现0个漏洞」。**没有漏洞结论**，因为**根本没有扫描**。

---

### 9.46.9 【已修复·本轮新增】`causal.graph` 的**空 schema 剥光所有参数** + 三方漂移的精确数字

#### 9.46.9.1 缺陷：空 schema = 「没有声明任何字段」，却被当「所有字段都是未知的」

`stabilizer/param_coercer.py::PARAM_SCHEMAS["causal.graph"] = {}` —— **空 schema**。

而 `coerce()` 的第三步是「剥离未知字段」：

```python
known_fields = set(schema.keys())            # ← 空 schema → 空集合
unknown = [k for k in list(result.keys()) if k not in known_fields]
for k in unknown:
    result.pop(k)                            # ← 全部剥掉
```

第四步的必填校验对空 schema **不做任何检查** → **通过**。
于是工具**静默地以空参被调用** —— 没有任何错误信号。

实测（修复前）：

```
── causal.graph
   输入 : {'entity': '1.2.3.4', 'depth': 3}
   输出 : {}
   被剥掉的字段: ['entity', 'depth']
```

修复后：

```
   输出 : {'entity': '1.2.3.4', 'depth': 3}
   被剥掉的字段: 无
```

#### 9.46.9.2 修法

**空 schema = 「没有声明任何字段」** ⇒ 不能据此判定别的字段都是「未知」
⇒ 不剥离（与「工具未注册」的处理一致：原样返回，不动它）。

> **非空 schema 的「剥离未知字段」是防参数走私的安全措施**
> （不让调用方夹带 `cmd` 之类），**没有**放松 ——
> 守卫里专门有一条反向用例钉住它。

#### 9.46.9.3 新增守卫（9 例）

`tests/test_param_coercer_contract.py`（**9 例**）：

| 组 | 例数 | 作用 |
|---|---|---|
| `TestTheEmptySchemaMustNotStripEverything` | 3 | **核心性质**：空 schema **保留**全部参数；**反向**：非空 schema **仍然**剥离未知字段（防参数走私）；未注册工具原样返回 |
| `TestTheThreeDeclarationsDriftIsPinned` | 4 | 三方漂移的**具体清单**必须与登记一致（双向）：MCP 面 3 个「无对应动作」、响应引擎 9 个「转换器不认识」、3 个同名工具的字段名差异 |
| `TestThePremises` | 2 | MCP 面那份**就是**给 LLM 看的；动作注册表的 `params_schema` 与动作签名**一致**（它是唯一自洽的一份） |

第 2 组的作用是：漂移在「以哪份为准」被决定之前**不会继续扩大**，
而一旦有人修好，守卫会要求同步更新登记（否则转红）。

#### 9.46.9.4 注入验红（2 处，逐条点名）

| 注入 | 红掉的用例 |
|---|---|
| 空 schema 又开始剥光参数（还原原缺陷） | `test_an_empty_schema_keeps_the_parameters` |
| 完全不剥离未知字段（放松防参数走私） | `test_a_nonempty_schema_still_strips_unknown_fields` |

两处都红了，红的就是**对应性质自己的那条用例**；
每处还原后 sha256 一致（`f683d1ff319e067f…`），最终还原校验通过。

#### 9.46.9.5 边界

* 本轮**没有**统一三方声明（待决项 28）——
  守卫只是把漂移**钉住**，不让它继续扩大。
* 本轮**没有**给 `stabilizer` 管线接线（它整条**休眠**，
  `stabilize()` 只出现在自己的 docstring 里）——
  所以这次修复当前**没有生产影响**，属于「接线前必须先对」的准备工作。
* 本轮**没有**动 `MAX_ADJUST_SET` / `MAX_ADJUST_POOL`。

### 9.47 【已修复·本轮新增】测试污染**生产全局单例** → 守卫被变成顺序依赖（第 18 次全量回归转红的根因）

#### 9.47.1 现象

第 18 次全量回归**转红**（此前 17 次里 12 次零失败）：

```
1 failed, 2542 passed, 18 skipped, 55 xfailed, 3 warnings in 341.35s (0:05:41)
FAILED tests/test_param_coercer_contract.py::TestTheThreeDeclarationsDriftIsPinned::test_the_registry_only_tools_are_pinned
```

红的**不是**待决项 17 那条间歇失败，而是 §9.46.9 刚写的参数契约守卫。
单独跑那个文件：**9/9 全绿**。

> 「单独跑绿、全量跑红」= **顺序依赖**。这类红的红点与真实缺陷**毫无关系**，
> 它本身就是缺陷 —— 一条会因「谁先跑」而变色的守卫，等于没有守卫。

#### 9.47.2 根因（实测）

`tests/test_rollback_idempotent.py` 在**模块顶层**（import 期即执行，第 108~115 行）
把两个假动作注册进了**生产对象**：

```python
response_registry.register(
    "fake_pr2_block", _fake_exec, description="test only",
    severity="low", rollback_fn=_fake_rollback,
)
response_registry.register(
    "fake_pr2_gone", _fake_exec, description="test only",
    severity="low", rollback_fn=_fake_rollback_not_found,
)
```

`response_registry` 是 `response_engine/response_registry.py:173` 的**模块级全局单例**。
pytest 在**收集期**导入**所有**测试模块 → 污染在任何用例跑之前就已生效 →
所有依赖「生产动作集」的守卫都被污染。

实测（手工重现污染后测量）：

| 测量 | 干净 | 被污染 |
|---|---|---|
| 全局单例动作数 | 12 | **14** |
| 守卫实测的 `REGISTRY_ONLY` 集合 | 9 | **11** |
| 多出来的 | — | `fake_pr2_block` / `fake_pr2_gone` |

所以那条守卫的断言（`measured == REGISTRY_ONLY`）从 9 项变成 11 项 → 转红。
断言**本身没写错**（它是故意写死的：漂移被修好就该红），
坏的是**测量面** —— 它读的是「当前进程状态」，而进程状态会被别的测试改掉。

#### 9.47.3 影响面（不止「测试不干净」）

1. **全局单例是生产对象**：`routers/response.py:361` 的动作清单接口读的就是它
   → 测试环境下该 API 会把 `fake_pr2_*` 列进「可用响应动作」。
2. **注册表是安全边界**：`ResponseRegistry.execute()` 按名字取执行函数
   → 任何能往里注册东西的代码都扩大了「可被调用的动作」这一攻击面。
3. **守卫变成顺序依赖**：本轮就因此把第 18 次全量跑**染红**，
   而且红点与真实缺陷无关 —— 排障成本全部转嫁给「看报告的人」。

#### 9.47.4 修法（三处，方向不同）

**(1) 生产侧：让「生产动作集」可以被独立构造**

`response_engine/response_registry.py::_init_registry` 原来只往全局单例注册。
改成可传入独立实例：

```python
def _init_registry(registry=None):
    """把内置动作注册到 registry（默认 = 模块级全局单例）。"""
    registry = registry if registry is not None else response_registry
```

调用点（模块底部 `_init_registry()`）**不变**，生产行为**完全不变**；
新增的能力是：可以在**不碰全局单例**的前提下构造一份干净的生产动作集。

**(2) 测试侧：顶层注册 → fixture 注册 + teardown 精确还原**

`tests/test_rollback_idempotent.py` 的注册搬进 `fake_actions` fixture，
teardown 把 `_actions` / `_exec_fns` / `_rollback_fns` **三个字典逐项还原**
（不是简单 `del` 两个键 —— 那样会误删别的测试注册的东西）。

注册**仍然**落在全局单例上：`ResponseExecutor.rollback_batch` 走
`response_registry._rollback_fns`，必须是全局对象。

**(3) 守卫：测量面从「全局单例」换成「干净注册表」**

`tests/test_param_coercer_contract.py` 的 `_registry()` 改为构造独立注册表；
`tests/test_response_registry_isolation.py`（新建 6 条）**专门盯隔离性**。

#### 9.47.5 守卫（6 条）

| 组 | 例数 | 作用 |
|---|---|---|
| `TestTheProductionActionSetIsDeterministic` | 4 | 干净注册表 == 显式声明的 12 个（双向）；每个动作都有执行函数（注册了没实现 = 假功能）；**构造干净注册表不得动到全局**（比对动作定义对象的**身份**）；重复初始化幂等 |
| `TestTheGlobalSingletonIsNotPolluted` | 2 | **金丝雀**：全局单例里出现任何非生产动作 → 转红；「快照-还原」能**逐项**还原 |

生产动作集（12 个）现由**两处独立测量**互为对照：干净注册表 + 全局单例。

#### 9.47.6 注入验红（3 处，逐条点名）

| 注入 | 红掉的用例 |
|---|---|
| I1 `_init_registry` 无视传入的 registry（注册流向全局） | `test_building_a_clean_registry_does_not_touch_the_global`（+ `test_the_clean_registry_has_exactly_the_declared_actions`） |
| I2 containment 注册流向全局（干净集只剩 6 个） | `test_the_clean_registry_has_exactly_the_declared_actions` |
| I3 全局单例被多注册一个动作 | `test_the_global_singleton_holds_exactly_the_production_actions`（+ `test_the_pollution_can_be_undone_exactly`） |

三处都红了，红的都是**对应性质自己的那条用例**；每处还原后 sha256 一致
（`06a5e23e18e0320a…`），整轮结束 sha256 与基线一致。

#### 9.47.7 自曝两处（本轮自己抓到的）

1. **守卫的第一版判据写弱了**：
   「构造干净注册表不碰全局」最初只比**动作名集合** ——
   而重注册是**幂等**的，名字集合一模一样 →
   这条**永远抓不到**「注册流向了全局」。
   改成比对动作定义对象的**身份**（`id`）才抓得住。
2. **注入脚本第一轮带 `-x`** → 第一个失败就停 →
   「命中期望用例」判据看起来不成立（I1 红在了另一条上）。
   去掉 `-x` 后三处都按预期命中各自的用例。

> 这两处的共同点：**判据的强度要对着「修复前的真实缺陷」验**，
> 而不是对着「我以为的缺陷形态」写。

#### 9.47.8 边界

* 本轮**没有**把全局单例改成依赖注入（`routers/response.py`、
  `response_engine/__init__.py` 等仍用全局）→ 登记为**待决项 29**。
* 本轮**没有**给 `ResponseRegistry` 加 `unregister()` ——
  还原逻辑放在**测试侧**（逐项还原三个字典），
  避免为了测试给生产加一个没人用的 API（「选项存在不等于它生效」的同族坑）。
* 待决项 17（测试库隔离，间歇失败）**仍在**，本节处理的是另一类失败。

### 9.48 【已修复·本轮新增】`.env` 隔离开关只管住了一半 → README 文档的测试命令在仓库根直接崩

#### 9.48.1 现象

README「测试矩阵」里写的是：

```
| 后端单元/集成 | `pytest backend/tests -q` | ... |
```

**从仓库根执行**。实测（在修复前）：

```
$ cd <仓库根> && python -m pytest backend/tests/test_param_coercer_contract.py -q
E   pydantic_core._pydantic_core.ValidationError: 16 validation errors for Settings
E   image_tag        Extra inputs are not permitted
E   postgres_password Extra inputs are not permitted
    ...
EXIT=4
```

**收集期**就崩，16 个字段全是「后端根本不认识的键」。
而且 `tests/conftest.py:27` **已经设了** `SHARED_MEMORY_SKIP_DOTENV=1` —— 开关**没挡住**。

#### 9.48.2 机制（读源码读到 pydantic-settings 2.13.1）

`config.py` 有**两条**读 `.env` 的通道，此前**只有一条**被开关把守：

| # | 通道 | 读哪个 `.env` | 开关管得住吗 |
|---|---|---|---|
| 1 | `_load_project_root_env()`（手工灌 `os.environ`） | **项目根** `.env` | ✅ 管得住（2026-10-03 加的） |
| 2 | `class Config: env_file = ".env"`（pydantic-settings 自己的 dotenv 源） | **CWD** 的 `.env` | ❌ **此前无条件** |

pydantic-settings 2.13.1 `sources/providers/dotenv.py:107-140` 的关键三行：

```python
for env_name, env_value in self.env_vars.items():
    if not env_value or env_name in data or (self.env_prefix and env_name in self.settings_cls.model_fields):
        continue
    ...
    if not env_used:
        if is_extra_allowed and env_name.startswith(self.env_prefix):
            data[normalized_env_name] = env_value
        else:
            data[env_name] = env_value        # ← 未声明的键被当成 extra 塞进数据
```

`extra="forbid"` ⇒ `data` 里的任何未声明键 ⇒ `ValidationError`。
**`env_prefix` 只影响「取值」，不影响「多余键的判定」** ——
这就是为什么仓库根 `.env` 里那 16 个「别的服务的」键（kafka-ui / grafana / misp）
会把后端**炸**掉：后端只认 `SHARED_MEMORY_` 前缀的键。

合成实验（证明开关挡不住通道 2）：

| 场景 | 开关 | 结果 |
|---|---|---|
| `.env` 含 `SHARED_MEMORY_JWT_SECRET=from-dotenv` | 开 | `jwt_secret = from-dotenv` —— **照样读进来了** |
| `.env` 含 `image_tag=dev`（未声明） | 开 | `ValidationError: Extra inputs are not permitted` |
| `.env` 含 `image_tag=dev`（未声明） | 关 | 同上 |
| `.env` 只含 `SHARED_MEMORY_JWT_SECRET` | 开/关 | 通过（未声明键才是崩因） |

#### 9.48.3 真实影响：隔离是**巧合**，不是机制

* 仓库根**有** `.env`（5 KB / 97 个可解析键），`backend/.env` **不存在**。
* 所以「测试读不到开发者的真 `.env`」这件事，**靠的是 CWD，不是开关**。
* 后果分两半：
  * 今天这一半是**响亮地崩**（收集期 exit 4）——
    报错是 16 条「不认识的设置」，把人指向完全错误的方向；
  * **更糟的那一半**：一旦 `.env` 的键都是合法的，
    **任何以仓库根为 CWD 启动的进程**都会把真实密钥读进 `Settings`，
    而开关显示「已隔离」—— 那是**假安全感**，不是隔离。
* **生产（docker）不受影响**：`backend/Dockerfile` 是 `WORKDIR /app` + 构建上下文 `./backend`
  → 容器里没有 `.env`；CI 也是 `working-directory: backend`。
* **根目录的其它脚本不受影响**：`log_simulator.py` / `demo_e2e.py` 不 import `config`。

#### 9.48.4 修法

`config.py` 加**模块级**单一事实来源：

```python
_SKIP_DOTENV = os.environ.get("SHARED_MEMORY_SKIP_DOTENV", "").strip() in (
    "1", "true", "TRUE", "yes"
)
```

```python
class Config:
    env_file = None if _SKIP_DOTENV else ".env"
    env_prefix = "SHARED_MEMORY_"
```

手工 loader 也复用同一个常量（`_load_project_root_env()` 里的 `if _SKIP_DOTENV: return`）。

**开关关闭时行为完全不变**（生产语义没动）；开关打开时**一个 `.env` 都不读**
（两条通道同时关）。

修后实测：README 文档的命令在**仓库根**执行 → `15 passed`（修复前 exit 4）。

#### 9.48.5 守卫（6 条）

| 组 | 例数 | 作用 |
|---|---|---|
| `TestTheSwitchReallyControlsTheDotenvChannel` | 5 | 开关开 ⇒ `.env` 的**内容**进不来 Settings；开关开 ⇒ 未声明的键**不**再变成 extra；**反向**：开关关 ⇒ dotenv 通道**仍然活着**（修不得顺手把生产读 `.env` 的能力关掉 —— 那是**放宽**不是修复）；开关开 ⇒ 手工 loader **不注入**任何键；**核心一对**：同一份 `.env`，只差一个开关 —— 关则崩、开则不崩 |
| `TestTheDocumentedPathIsNotBlocked` | 1 | README 文档的路径（**仓库根**执行）不再被仓库根的 `.env` 堵死 |

判据全部用**行为**（子进程真实 `import config` 的结果），不用源码文本。

#### 9.48.6 注入验红（3 处，逐条点名）

| 注入 | 红掉的用例 |
|---|---|
| J1 dotenv 源不再服从开关（回到无条件 `.env`） | `test_with_the_switch_on_the_file_content_does_not_reach_settings` 等 **5** 条 |
| J2 dotenv 源被整个关掉（生产读不到 `.env` 了 —— 放宽不是修复） | `test_with_the_switch_off_the_dotenv_channel_is_still_alive`（+ 同文件那一对） |
| J3 手工 loader 不再服从开关（`os.environ` 注入通道泄漏） | `test_with_the_switch_on_the_manual_loader_injects_nothing` |

三处都红了；每处还原后 sha256 一致（`5bbaadbc8bfc8b1b…`），整轮结束与基线一致。

#### 9.48.7 自曝：守卫的第一版**永远不会红**

J3 第一次注入时**没红**。查下来的原因是守卫自己写错了：

* 守卫第一版让子进程**继承父进程的全部 `os.environ`**；
* 而父进程（pytest）自己 import 过 `config` —— 在 J3 状态下 loader 生效，
  已经把 **97 个键**（含 `POSTGRES_PASSWORD` / `GRAFANA_ADMIN_PASSWORD` /
  `MISP_*_PASSWORD` 等）灌进了父进程的 `os.environ`；
* loader 的语义是「**不覆盖已存在的键**」→ 子进程里它**什么也不注入**
  → 差集**恒为空** → 这条检查**永远不可能红**。

也就是说：**守卫测的正是「有没有被注入」，而它测的环境已经被注入过了。**
改法：子进程改用**最小环境**（只继承 `SYSTEMROOT` / `PATH` / `TEMP` 等 11 个），
J3 立刻被抓到。

> 判据的**前提**必须被验证 —— 前提不成立时，检查不是「弱」，是**空转**。
> 这与 §9.44「扫描器自己错了五次」是同一条纪律：
> **量具要先自证。**

#### 9.48.8 边界

* 本轮**没有**动仓库根那份 `.env` 本身（它是**用户机器上的文件**，不在版本库里）——
  那 16 个「非本服务」的键仍在 → 开关关闭时从仓库根裸跑仍会崩
  → 登记为**待决项 30**。
* 本轮**没有**放宽 `extra="forbid"`：配置键写错时**响亮地失败**是对的，
  静默忽略才是危险的。
* 本轮**没有**改 CI（CI 本来就在 `working-directory: backend` 下跑，安全）。

### 9.49 【已修复·本轮新增】学习闭环的「家族」聚类**依赖输入顺序** → 同一批数据两次给出不同的家族

#### 9.49.1 怎么发现的

回到整改方案 §十.2 逐条核对，发现有一条**明确写了验收方法**的性质，
在**第二份实现**上不成立：

> 「只比较簇代表，结果依赖插入顺序 | 明确采用的聚类策略，并通过**样本排列测试**
> 验证稳定性」
> 「最终需要验证：相同样本集合仅改变输入顺序，不会产生不可解释的簇变化」

`zeroday_detect/variant_cluster.py`（恶意样本家族）已按**连通分量 + 内容寻址簇号**修好，
并列测试在 `tests/test_clustering_feature_contracts.py`。
但 `learn_loop/models_cluster.py`（**学习闭环**的 FP/漏报家族聚类）是**另一份实现**，
仍是「只比簇代表 + 位置号」。

> 两份实现**回答的是同一个业务问题**（「什么叫一个家族」），
> 却给出了**两套不同答案** —— 而答案差的那一套正好在**活跃路径**上。

#### 9.49.2 缺陷（实测）

贪心算法把新样本只与**簇代表**比，而簇代表是**已并入成员的并集**（会长大）→ 顺序敏感。

实测（3 个人工构造的事件：`sim(A,B)=2/3`、`sim(B,C)=1/2`、`sim(A,C)=1/4`，阈值 0.5）：

| 输入顺序 | 修复前 | 修复后 |
|---|---|---|
| `[A,B,C]` | 1 个簇（size 3） | 1 个簇（size 3） |
| `[A,C,B]` | **2 个簇**（size 2 + size 1） | 1 个簇（size 3） |
| `[C,B,A]` / `[B,A,C]` | 1 个簇 | 1 个簇 |

簇 id → 成员的**映射**同样不稳定（修复前：`[A,C,B]` 下 `learn_cluster_0` 的成员是 `{1,2}`，
`[A,B,C]` 下是 `{1,2,3}`）。

#### 9.49.3 这条路径是**活的**（不是休眠模块）

| 环节 | 位置 |
|---|---|
| 调度 | `scheduler.py:86` → `_learn_loop` → 每日 **02:15 UTC** 跑 `run_cycle(trigger="daily")`（`learn_loop_enabled` 默认 **True**） |
| 手动触发 | `routers/ops.py:916` `POST /api/ops/learn-loop/run`（管理员） |
| 聚类 | `orchestrator.py:_step_clusters` → `build_clusters` |
| 产出 | `propose.py:151` → `label_cluster` 动作（`HUMAN_ONLY_TYPES`）→ 落成 `LearningAction` 行，`target_id = cluster_id` |

#### 9.49.4 取数侧也缺一环

`orchestrator.py:114-116` 的查询**没有 ORDER BY**：

```python
events = (await session.execute(
    select(SecurityEvent).where(SecurityEvent.id.in_(want_ids))
)).scalars().all()
```

`IN (...)` **不保证**返回顺序 → 同一批事件两次查询的顺序可能不同。
（收割侧 `_harvest_feedback` 有 `order_by(created_at.desc())`，
但 **created_at 并列时顺序未定义** —— 批量写入的反馈记录很容易同刻。）

#### 9.49.5 后果：位置号会让 24h 去重把**另一个家族**静默吞掉

`propose.py:49` 的去重键 = `f"{action_type}:{target_id}"` = `label_cluster:{cluster_id}`；
`orchestrator.py:251` 的 `existing_keys` 来自 DB 的**近 24h** 已提议键。

簇号是**位置号**（`learn_cluster_{idx}`）→ 今天的 `learn_cluster_0` 与昨天的
`learn_cluster_0` **可能根本不是同一个家族** → 新家族的提议被**静默去重掉**，
人工打标**永远轮不到它**。而 `label_cluster` 落不到自动应用
（`apply.py` 里它落到 `not_implemented_pending_human`）→ 没有人会发现这件事。

#### 9.49.6 修法（四处，方向不同）

1. **确定性全序**（`models_cluster.py`）：聚类前按 `(id, 特征集, 成员身份串)` 排序
   → 簇划分成为「事件**集合**」的函数，而不是「到达顺序」的函数。
   ⚠ **聚类算法本身没动**（仍是贪心 / leader）——
   「家族」的定义（全链接 vs 相似链）是**业务定义**，不单方面代拍 → **待决项 31**。
2. **簇号内容寻址**（`models_cluster.py`）：`_cluster_id_for(成员身份串)`
   → 不同家族**不撞号**；别的家族插到前面也**不改变**本家族的号。
3. **非数字 id 不再炸**（`models_cluster.py`）：`int(e.get("id"))` → `_int_or_none`
   （转不了就跳过，不抛）→ **一个坏 id 不再带走整次聚类**
   （此前只能由 `orchestrator` 记 `partial` 并丢掉**全部**簇）。
4. **取数显式定序**（`orchestrator.py`）：`_step_clusters` 与 `_step_sequences`
   的查询都补 `.order_by(SecurityEvent.id)`（纵深防御）。

#### 9.49.7 守卫（10 条）

| 组 | 例数 | 作用 |
|---|---|---|
| `TestTheClusteringIsOrderIndependent` | 3 | **排列测试**：同一批样本的**所有排列** → 同一划分、同一簇号；钉住那个**具体的**反例 |
| `TestTheClusterIdIsContentAddressed` | 3 | 同一家族**在别的家族排前面时**簇号不变；两个家族不撞号；加入无关家族不改变另一个簇的号 |
| `TestTheClusteringIsRobust` | 2 | 非数字 id 不再带走整次聚类；**没有 id** 的事件也要能聚类 |
| `TestTheProductionPathIsDeterministic` | 1 | 取数必须**显式定序**（AST 结构性检查） |
| `TestTheReverseCriterion` | 1 | **反向判据**：相似事件**仍然**要能并成一个簇（不许把修复做成「都不聚」） |

#### 9.49.8 注入验红（4 处，逐条点名）

| 注入 | 红掉的用例 |
|---|---|
| K1 去掉确定性排序（恢复到达顺序） | `test_every_permutation_gives_the_same_partition`（+ 簇号那条 + 反例那条） |
| K2 恢复位置型簇号 | `test_a_family_keeps_its_id_when_another_family_sorts_before_it` |
| K3 恢复会抛异常的 `int(id)` | `test_a_non_numeric_id_does_not_destroy_the_whole_clustering` |
| K4 取数去掉 ORDER BY | `test_the_event_queries_have_an_explicit_order_by` |

四处都红了，红的都是**对应性质自己的那条用例**；每处还原后 sha256 一致
（`0d1be994f3dfe911…` / `89548ed5f4f64662…`），整轮结束与基线一致。

#### 9.49.9 自曝：K2 第一次注入**没红** —— 守卫写得太弱

把簇号换回位置号后，守卫 10 条**全绿**。

原因：确定性排序让**位置号**在**单次调用**内也稳定
→ 「两个家族不撞号」「加入无关家族不改变另一个簇的号」这些**单次调用**的判据
**全都**不受影响。病根在**跨调用**：别的家族插到**前面**就会把 X 挤到别的号上。

补了一条**能真正分辨**的用例（Y 家族的 id 0 排在 X 之前）→ K2 当场变红。

> 这是本轮第二次出现「判据测的不是要测的性质」
>（第一次是 §9.47 的「构造干净注册表不碰全局」只比了动作名集合）。
> **判据的强度要对着「修复前的真实缺陷」验**，
> 而不是对着「我以为的缺陷形态」写 —— 位置号在单次调用里**看不出问题**。

#### 9.49.10 边界

* 本轮**没有**改聚类算法（家族定义见**待决项 31**）。
* 簇号格式从 `learn_cluster_{idx}` 变成 `learn_cluster_{12位sha1}` ——
  这是**对外可见**的格式变化（`LearningAction.target_id` 与 payload）。
  影响：DB 里**历史**的 `label_cluster:learn_cluster_N` 键与新键不再相等
  → 改簇后的**第一轮**会**重新提议**一遍全部簇（一次性噪声；
  `label_cluster` 是人工动作，不会自动落地）。
* `event_ids` 仍只收**能转 int** 的 id（保持类型一致）；
  生产路径的 `SecurityEvent.id` 恒为 int，不受影响。
* 本轮**没有**动 `zeroday_detect/variant_cluster.py`（它已经是连通分量 + 内容寻址）。

### 9.50 【已修复·本轮新增】embedding 的**降级产物**（全零向量）与真实向量不可区分 → 脏数据入库 + 假阳性检索

#### 9.50.1 怎么发现的

整改方案 §十一 有一条要求：

> 「监控不能只记录最终检测分数，还应记录检测依据不足、运行错误和真实阴性
> 各自的数量。**如果这些状态最终都被压成一个 not_detected 计数**，
> 那么新增多少仪表盘也无法真正帮助排障。」

带着这个去找「**失败被压成一个正常值**」的地方，在 `summary_compression.py`
的 `EmbeddingClient.embed()` 里找到了：失败时返回 `[0.0] * embedding_dim`。

#### 9.50.2 缺陷（实测）

降级产物**维度正确、内容全零** → 与真实向量**不可区分**：

| 特征 | 真实向量 | 降级产物 |
|---|---|---|
| 长度 | = `embedding_dim` | **= `embedding_dim`**（一样） |
| `bool(vec)` | True | **True**（一样）→ `if v` 拦不住 |
| 维度护栏 | 通过 | **通过** |
| 内容 | 有信息 | 全零 |

**危害一：脏数据入库**（实测）。`vector_store.store_memory()` 的维度护栏只查**长度**
→ 零向量长度正确 → 直接放行：

```
[1] store_memory(零向量): mem.id=1 embedding=len=768 全零=True
    -> 零向量被存进库了? True
```

（`rag/seeder.py:1125` 其实**早就有**零向量识别 ——「API 失败或返回零向量(降级产物)
→ 视为失败, 不存脏数据」—— **同一个判断只在一个地方实现了**。）

**危害二：假阳性检索**（实测）。`vector_store._search_pgvector` 的兜底
`return filtered if filtered else rows[:1]`：零向量查询时所有余弦相似度**恒为 0**
（`cosine_sim` 对零范数返回 0.0）→ 阈值过滤后必然为空 → 兜底返回**任意一条**：

```
零向量与各条记忆的余弦相似度: [(1, 0.0), (2, 0.0)]
阈值(0.75)过滤后: []
-> 兜底 `filtered if filtered else rows[:1]` 返回: (1, '降级产物记忆')
```

那条记忆与查询**毫无关系**，却会被 `tool_registry` 的 `vector.search` 工具
当成「相关记忆」交给 LLM → **LLM 上下文里混进一条不相关记忆**。

**危害三：同一个类的两个 API 对「失败」表达不一致** ——
`embed()` 返回全零向量，`embed_batch()` 对同一失败返回 **None**。

#### 9.50.3 修法：判定口唯一 + 三个存储/检索口各自把关

**(1) 判定口唯一**（`summary_compression.py`，生产方定义自己的降级产物）：

```python
def is_degraded_vector(vec, eps: float = 1e-5) -> bool:
    """降级产物判定：None / 空 / 全零（每个分量的绝对值都 <= eps）。"""
```

阈值 `1e-5` 与 `rag/seeder.py` 原有口径**一致**（`_ZERO_EPS`）。

**(2) 三个口各自把关**（每个存储/检索口守自己的门）：

| 口 | 位置 | 修法 |
|---|---|---|
| 记忆入库 | `vector_store.store_memory` | 降级产物 → `embedding=None`（**不写向量**，内容仍留库，词法仍可用） |
| 记忆检索 | `vector_store.search_similar` | 降级产物查询 → **直接返回空**（**不得**走到后端） |
| 知识库写入 | `qdrant_store.upsert_chunk` | 降级产物 → **跳过写入**（闸门放在 SDK import **之前**：它是纯输入检查，不该依赖 `qdrant_client` 是否安装） |
| 知识库入库 | `routers/rag.py` | 降级产物 → `embedding=None` + 不进 Qdrant 批次（内容仍入库，词法仍可用） |

**(3) 局部实现收敛**：`rag/seeder.py` 原本那份**局部**零向量判定 → 改用同一个函数。

#### 9.50.4 守卫（12 条）

| 组 | 例数 | 作用 |
|---|---|---|
| `TestTheJudgmentPoint` | 6 | None/空/全零/极小向量 → 降级；**反向判据**：真实向量（含「部分分量为 0」的）**不得**被误判；前提守卫：全零向量**拦不住** `if v` 惯例 |
| `TestTheStoreSide` | 2 | 降级产物**不写进库**；**反向判据**：正常向量照写（别把闸门做成「全都不写」） |
| `TestTheSearchSide` | 2 | 降级产物查询 → 空；**不得走到后端**（后端的兜底会返回任意一条） |
| `TestTheQdrantWriteSide` | 1 | Qdrant 写入口也拒收降级产物（保护**所有**调用方） |
| `TestTheSingleSourceOfTruth` | 1 | seeder 必须用共享判定（局部实现不得复现） |

#### 9.50.5 注入验红（5 处，逐条点名）

| 注入 | 红掉的用例 |
|---|---|
| M1 去掉入库闸门 | `test_store_memory_refuses_the_degradation_product` |
| M2 去掉检索闸门 | `test_search_similar_returns_empty_for_the_degradation_product` + `test_search_similar_never_reaches_the_backends` |
| M3 seeder 退回局部判定 | `test_the_seeder_uses_the_shared_judgment` |
| M4 判定口失效（全零向量不再判为降级） | 7 条（含判定口自身 + 入库 + 检索 + Qdrant） |
| M5 去掉 Qdrant 写入口闸门 | `test_upsert_chunk_skips_the_degradation_product` |

五处都红了，红的都是**对应性质自己的那条用例**；每处还原后 sha256 一致
（`c75287c80c5db7a3…` / `ef585e459866a48f…` / `ed089932c1779d21…` /
`c2aab573d1920839…`），整轮结束四个文件与基线一致。

#### 9.50.6 边界

* 本轮**没有**改 `embed()` 的公开契约（仍返回零向量）——
  改契约要动 8 个调用方，属于**接口语义变更**，不单方面做 → **待决项 32**。
* 由此仍存一处**已知缺口**：LLM 看到的 `vector.search` 结果仍是「空列表」，
  分不清「没有相关记忆」与「检索根本不可用」——
  trace（`AgentTrace`）里**有** `status="degraded"/"error"` 的记录 ✅，
  但**调用方**拿不到信号。修它要改工具的返回形态（list → dict）→ 同样属契约变更。
* 本轮**没有**动知识库检索那条路：它有**词法通道**兜底
  （`rag/retriever.py` 的 hybrid 融合在 dense 为空时仍走 BM25），
  实测**任意一条**的兜底只出现在记忆路径（`vector_store._search_pgvector`）。
* **连带**：本轮的新守卫 import 了 `qdrant_store` → 它不再属于「零覆盖」→
  §9.44 的**双向相等**守卫在第 21 次全量回归里**当场转红**要求同步登记表
  （清单 23 → 22、188 KB → 170 KB，见 §9.44.6）。
  这正是那条守卫存在的意义：**给谁补了测试，登记表就得跟着变**。

### 9.51 【已修复·本轮新增】SafeExecutor 的 grounding 硬门控**永远不会触发**，却在审计里被记成「通过、满分」

#### 9.51.1 怎么发现的

按 §9.50 的形态（「失败被压成一个正常值」）去扫**安全闸门**，
在 `response_engine/safe_executor.py` 的检查链第 ⓪ 步找到一道写着
「无证据支撑的审计结论不允许触发响应动作」的硬门控：

```python
grounding_score = params.get("grounding_score", 1.0)
if grounding_score < 0.4:
    ... BLOCKED ...
audit["checks"]["grounding"] = {"passed": True, "score": grounding_score}
```

三个实测事实（2026-10-20）：

1. **没有任何生产代码传它** —— 整个 `response_engine` 包里，
   `grounding_score` **只出现在闸门自己**（`safe_executor.py:116`）；
2. **就算传了也会在半路丢掉** —— 动作函数（`_block_ip` 等）**不转发 `**kwargs`**，
   `grounding_score` 到不了闸门；
3. **没有任何测试覆盖它** —— `tests/` 里找不到让这道闸门触发的用例。

于是：这道闸门**永远不会触发**，而它写进审计的是
`{"passed": True, "score": 1.0}` —— **`grounding_score` 的缺省值 1.0（最宽松）**，
于是**一道从没跑过的检查，在审计里被记成「通过、满分」**。

> 这是**虚假保障**：读审计的人以为「无证据不许响应」由 SafeExecutor 保证，
> 而实际上那一刻**什么都没保证**。

#### 9.51.2 别误读：平台**并非**没有这道保护

活的那道是 `veto_gates.evaluate_auto_response_gate`（`veto_gates.py:1054`），
它检查 `threat_detected` / `verdict` / `confidence` 与一组阻断因子
（`needs_human_review` / `response_blocked` / `schema_invalid` /
CAD 断路器 / `supervision_failed`）—— 证据不足的结论会带
`needs_human_review=True` → 被它拦住 ✅。

所以本节的结论**不是**「平台缺保护」，而是：

* 有一道**重复的、写着 P0 硬门控、实际从来没跑过**的检查；
* 它给出的**虚假保障**（审计里报绿）比没有它更危险。

#### 9.51.3 修法：只改**诚实性**，不改拦截行为

**(1) 闸门三态化**（`safe_executor.py`）：

| 情形 | 审计记录 |
|---|---|
| 给了分数且通过 | `{"passed": True, "state": "evaluated_pass", "score": 0.9}` |
| 给了分数且不通过 | `{"passed": False, "state": "evaluated_block", "score": 0.1}` → **仍然拦截** |
| **没给分数** | `{"passed": None, "state": "not_evaluated", "score": None, "reason": "…本闸门未评估…"}` |

畸形分数（非数字）按「未评估」处理，不得变成「通过」，也不得让动作抛异常。

> **词表统一**：审计里的 `state` 与指标标签用**同一套**三个值
> （`evaluated_pass` / `evaluated_block` / `not_evaluated`）——
> 同一个概念两套说法就是词表漂移（§9.49 的教训），而 §十一.2 要求
> 「所有用于运维决策的状态词表保持一致」→ 三个值已登记进
> `tests/test_detection_status_vocabulary.py` 的 `REGISTERED_OTHER`。

**(2) 单独计数**（§十一.1：「依据不足」必须与「真实阴性」分开计数）：
新增 `soc_response_grounding_gate_total{state=evaluated_pass|evaluated_block|not_evaluated}`，
并登记进 `test_metric_consumer_guard.py` 的 `UNWATCHED`（**不接告警** ——
接告警会产生值班呼叫，属运维行为变更，需用户拍板，§7.1.15）。

**(3) 不改变拦截行为**：没给分数时**仍然放行**（与修复前一致）——
把它接上属**收紧型**改动，见 §9.51.5。

#### 9.51.4 守卫（7 条）

| 组 | 例数 | 作用 |
|---|---|---|
| `TestTheAuditMustNotClaimAPassWhenNothingWasEvaluated` | 2 | 没评估过 → `state="not_evaluated"` + `passed is None`；**反向判据**：动作**仍然执行**（本轮只改诚实性） |
| `TestTheGateWorksWhenItIsActuallyFed` | 3 | 给了分数就**真评估**：低分被拦、高分通过、畸形分数按未评估处理 |
| `TestTheNotEvaluatedStateIsCounted` | 1 | `not_evaluated` 状态被计数（§十一.1） |
| `TestTheWiringFactIsPinned` | 1 | **事实钉住**：`response_engine` 包里 `grounding_score` 只允许出现在闸门自己 —— 一旦有人把它接上，本守卫转红，要求同步更新**待决项 33** 与报告结论 |

#### 9.51.5 注入验红（3 处，逐条点名）

| 注入 | 红掉的用例 |
|---|---|
| N1 没评估过也记成「通过、满分」 | `test_without_a_score_the_audit_says_not_evaluated`（+ 畸形分数那条 + 计数那条） |
| N2 给了分数也不评估 | `test_a_low_score_is_evaluated_and_blocks` |
| N3 `not_evaluated` 不计数 | `test_the_counter_records_the_state` |

三处都红了，红的都是**对应性质自己的那条用例**；还原后 sha256 一致
（`c6e1b803658abca3…`）。

#### 9.51.6 边界与待决项

* 本轮**没有**把闸门接上 → **待决项 33**：接上属**收紧型**改动 ——
  非审计来源的响应（Kafka 告警 / EDR 融合）**根本没有 grounding 分数**，
  若按缺省拒绝，整个响应能力会瘫；而给不同来源定不同的缺省语义，
  是**业务定义**（与 §9.49 的「家族定义」同类）→ 不单方面做。
* 本轮**没有**删掉这道闸门：它是**有效**的检查（给了分数就真拦），
  删掉会丢掉「将来接线」的能力；现在它至少**如实说自己没评估**。
* 本轮**没有**动活的那道闸门（`veto_gates.evaluate_auto_response_gate`）。

### 9.52 【已修复·本轮新增】幂等检查「**没查成**」与「查了、没重复」在审计里长得一模一样

#### 9.52.1 怎么发现的

§9.51 修完 grounding 闸门后，按 §9.49 的纪律把 `SafeExecutor` 的**整条检查链**
逐项过一遍，找「**这道检查当时有没有跑**」这个问题。链上五项：

| 检查 | 跑不了时会怎样 | 会不会「看起来通过了」 |
|---|---|---|
| ⓪ grounding | 已在 §9.51 修（三态化） | — |
| ① 命令白名单 | 异常**直接上抛**（无 try/except） | ❌ 不会（动作不执行） |
| ② 参数强校验 | 同上 | ❌ 不会 |
| ③ 核心资产保护 | 同上；无目标 IP 时**不写入** `checks` | ❌ 不会（键是**缺席**，不是通过） |
| ④ **幂等检查** | Redis 未配置 / 调用出错 → `return False` | ✅ **会** |

第 ④ 项修复前只返回 bool，于是这两种情形**返回同一个值** `False`：

* 「查了，Redis 里没有这条 → 不是重复」；
* 「**根本没查成**」—— `self._redis is None`（Redis 未配置）或 `redis.exists()` 抛异常。

审计里写的是 `audit["checks"]["idempotency"] = {"hit": False}`
→ **看不出这道检查当时有没有跑**。

#### 9.52.2 后果：同一事务的两侧，Redis 故障时的**不对称**

| 侧 | 实现 | Redis 故障时 |
|---|---|---|
| **回滚幂等**（`RollbackStore`） | **内存为主、Redis 兜底**（docstring 明写「Redis 写入失败只降级为纯内存模式」） | ✅ 保护**仍在** |
| **执行幂等**（`SafeExecutor._idempotency_check`） | **纯 Redis** | ❌ 保护**整体消失** |

后果：Redis 故障期间，**同一事件**（Kafka 重放 / 24h 内的重投递）的响应动作
会被**执行多次** → 重复的防火墙规则、重复的通知、重复的工单。
而且 `_idempotency_mark` 也是纯 Redis → 标记也写不进去 →
**下一次重放连「标记」都没有**。

#### 9.52.3 修法：只改**诚实性**，不改拦截行为

**(1) 幂等检查三态化** → `(hit, state)`，`state ∈ {evaluated, unavailable}`：

| 情形 | 审计记录 |
|---|---|
| Redis 正常、命中重复 | `{"hit": True, "state": "evaluated"}` → 动作**跳过** |
| Redis 正常、不是重复 | `{"hit": False, "state": "evaluated"}` → 动作**执行** |
| **Redis 不可用 / 出错** | `{"hit": False, "state": "unavailable", "reason": "幂等检查**未执行**；此刻这道保护不生效"}` |

**(2) 标记结果如实记**：`_idempotency_mark` 现在返回**是否真的标记上了**；
标记写失败 → 审计里 `marked: False` + 「下一次重放不会被幂等拦下」。

**(3) 单独计数**：`soc_response_idempotency_check_total{state=evaluated_hit|evaluated_miss|unavailable}`，
登记进 `test_metric_consumer_guard.py` 的 `UNWATCHED`（**不接告警**）。

**(4) 不改变拦截行为**：Redis 不可用时动作**照常执行**（与修复前一致）。

#### 9.52.4 守卫（9 条）

| 组 | 例数 | 作用 |
|---|---|---|
| `TestTheUnavailableStateMustNotLookLikeACleanCheck` | 3 | Redis 未配置 / 调用出错 → `state="unavailable"` + 有理由；**反向判据**：动作**仍然执行** |
| `TestTheEvaluatedState` | 2 | 查了 → `state="evaluated"`；命中跳过、没命中执行 |
| `TestTheMarkResultIsRecorded` | 2 | 标记写失败 → `marked=False` + 理由；写成功 → `marked=True` |
| `TestTheCounter` | 1 | `unavailable` 状态被单独计数 |
| `TestTheAsymmetryIsVisible` | 1 | **前提守卫**：回滚侧在 Redis 不可用时**仍有**保护（内存兜底），执行侧没有 —— 这个不对称必须被看见 |

#### 9.52.5 注入验红（3 处，逐条点名）

| 注入 | 红掉的用例 |
|---|---|
| P1 没查成也记成 `evaluated` | `test_without_redis_the_audit_says_unavailable`（+ Redis 报错那条 + 计数那条 + 不对称那条） |
| P2 标记结果不记进审计 | `test_a_failed_mark_is_recorded`（+ 标记成功那条等） |
| P3 `unavailable` 不计数 | `test_the_unavailable_state_is_counted` |

三处都红了，红的都是**对应性质自己的那条用例**；还原后 sha256 一致
（`6b21d976b9e6…`）。

#### 9.52.6 边界与待决项

* 本轮**没有**给执行侧补内存兜底 → **待决项 34**：
  补内存兜底属**收紧型**改动（Redis 故障时同进程重复会被拦下），
  且内存标记的存活期与 Redis 的 24h TTL 不等价（进程活得更久就拦得更久）
  → 缺省语义属**业务定义**，不单方面做。
* 本轮**没有**动回滚侧（它本来就有内存兜底 ✅）。
* 本轮**没有**改「Redis 不可用时动作照常执行」这一行为（只把状态写清楚）。

### 9.53 【已修复·本轮新增】封禁/隔离的「自动解封」只有**进程内**的定时任务 —— 进程重启就没了；而**能扛重启**的 TTL 机制已实现却**从未接线**

#### 9.53.1 怎么发现的

`response_engine/ttl_manager.py` 早就在 §9.44 的零覆盖清单里
（理由写着「响应动作 TTL —— 过期后是否仍会执行，无回归」）。
这一轮按 §9.49 的纪律去挖清单里的模块 → 挖出三件**互相咬合**的事。

#### 9.53.2 三个实测事实

**(1) 在用的是「进程内定时任务」**

```python
asyncio.create_task(_auto_rollback(fw_rule_id, duration_minutes * 60, ...))
# _auto_rollback: await asyncio.sleep(delay_seconds) → ssh_firewall.rollback(rule_id)
```

它是 `asyncio.sleep` + 回滚，**只活在当前进程的内存里** →
进程重启 / 发布 / 崩溃都会**静默丢失**这次解封
（`_auto_rollback` 里的 `except Exception` 连 `CancelledError` 都接不住，
退出时**连一行日志都不会有**）→ 规则**一直留存**：

* 误报的**封禁**不会自愈（该 60 分钟自动解封，结果一直封着）；
* 误报的**主机隔离**更严重 —— `isolate_host` 是 in+out **双向 DROP**，
  机器会一直被关在网外。

**(2) 能扛重启的机制**（`ttl_manager`：Redis 持久化 TTL + 后台扫描器）
**已实现，但三重未接线**：

| 入口 | 状态 |
|---|---|
| `ttl_manager.register(...)` | `safe_executor` 第 ⑧ 步**调用**它，但条件是 `ttl_seconds > 0 and rule_id` —— 而**没有任何生产代码**传 `_ttl_seconds` / `_rule_id`（全仓只有 `response_registry._exec` 里的两处 `fields.pop`）→ **不可达** |
| `ttl_manager.start_scanner()` | **从未被调用**（docstring 说「在 app startup 中调用」—— 它没有） |
| `set_redis(...)` / `set_rollback_callback(...)` | **没有调用方** → 即使可达也跑不起来 |

**(3) 没有别的机制会清理残留规则** —— `ssh_firewall.rollback_all` 只能由管理员
**手工**点 `POST /firewall/rollback-all`，没有定时对账。

#### 9.53.3 修法：只加**可见性**，不改行为

**(1) 动作结果写明机制与局限**（`block_ip` / `isolate_host`）：

```python
"auto_unblock": {
    "scheduled": True,
    "mechanism": "in_process_task",
    "restart_survives": False,
    "duration_minutes": 60,
    "rule_ids": "FW-RULE-12345",
    "note": "自动解封是**进程内**的定时任务；进程重启 / 发布 / 崩溃会导致这次"
            "自动解封**静默丢失**（规则将一直留存）—— 整改报告 §9.53；"
            "能扛重启的 TTL 机制（response_engine/ttl_manager.py）已实现但未接线（待决项 35）",
}
```

这段信息跟着动作结果落进 `response_logs` → 运维看得到
「这次封禁靠的是**扛不住重启**的机制」。

**(2) 计数**：`soc_response_auto_unblock_scheduled_total{action=block_ip|isolate_host}`
→ 「有多少条封禁正依赖那个机制」=「一次发布会让多少条封禁失去自动解封」。
登记进 `test_metric_consumer_guard.py` 的 `UNWATCHED`（**不接告警**）。

**(3) 不改变行为**：调度照旧（`asyncio.create_task` 仍在），
没被调度时 `auto_unblock.scheduled=False`。

#### 9.53.4 守卫（6 条）

| 组 | 例数 | 作用 |
|---|---|---|
| `TestTheMechanismIsVisible` | 4 | 信息内容（机制=进程内任务、扛不住重启、有说明）；没调度 → `scheduled=False`；**live 路径**的结果里必须带 `auto_unblock`；**反向判据**：调度**仍然发生** |
| `TestTheCounter` | 1 | 调度次数可数 |
| `TestTheWiringFactIsPinned` | 1 | **事实钉住**：`set_redis` / `set_rollback_callback` / `start_scanner` **无生产调用方**，且**没人传** `_ttl_seconds` / `_rule_id`（→ `register` 不可达）—— 一旦有人接线，守卫转红，要求同步**待决项 35** 与报告结论 |

#### 9.53.5 注入验红（3 处，逐条点名）

| 注入 | 红掉的用例 |
|---|---|
| Q1 结果里不写机制与局限 | `test_the_block_result_carries_the_info`（+ 计数那条） |
| Q2 不再调度自动解封 | `test_the_unblock_is_still_scheduled` |
| Q3 调度不计数 | `test_the_scheduling_is_counted` |

三处都红了，红的都是**对应性质自己的那条用例**；还原后 sha256 一致
（`a97059d7f8af…`）。

#### 9.53.6 边界与待决项

* 本轮**没有**接线 `ttl_manager` → **待决项 35**：
  接线需要四件事同时做（动作传 `_ttl_seconds`/`_rule_id`、启动时
  `set_redis` / `set_rollback_callback`、启动 `start_scanner`、
  以及一条「按 rule_id 回滚」的回调），属**接线决策**（新增后台扫描器 +
  Redis 写入 + 启动钩子）→ 不单方面做。
* 本轮**没有**改自动解封的**行为**（仍然是进程内任务）。
* 本轮**没有**动 `ssh_firewall.rollback_all`（管理员手工入口，保持原样）。
* 顺带更正 §9.44 登记表里 `response_engine/ttl_manager.py` 的理由：
  它不只是「零覆盖」，而是**生产里从未被调用**（§9.53）。

### 9.54 【已修复·本轮新增】「核心资产保护」的**默认清单名不副实**，而它在审计里报「通过、理由为空」

#### 9.54.1 怎么发现的

接着 §9.53 的线（安全机制存在但**没生效**），把 `SafeExecutor` 检查链里剩下的
第 ③ 项「核心资产保护」也过一遍 → 三个事实。

#### 9.54.2 三个实测事实

**(1) 默认清单名不副实**

`response_engine/asset_whitelist.py` 的模块 docstring 写着：

> 「白名单来源（优先级从高到低）: 1. **内置默认保护（平台自身组件的 IP/网段）**」

实测内置清单**只有一条**：

```python
_BUILTIN_PROTECTED = [
    ("127.0.0.0/8", "loopback", "builtin"),
    ("0.0.0.0/0", "default-route-placeholder", "builtin"),  # 仅用于占位，check 中特殊处理
]
```

→ 平台自己的 DB / 缓存 / Kafka **不在**保护范围内 → **文档承诺落空**
（整改方案 §十一.2「文档只承诺当前真正实现的算法与约束」）。

**(2) `0.0.0.0/0` 占位符是死代码，而它的注释在撒谎**

注释写「仅用于占位，**check 中特殊处理**」—— 但：

* `initialize()` 里 `if "placeholder" in label: continue` → **直接跳过**它；
* `check()` 里**从头到尾没有任何** 0.0.0.0/0 的特殊处理。

也就是说，那条注释是维护者判断「check 里有没有处理」的**唯一依据**，
而它**指向一个不存在的处理**。

**(3) 审计里的「假通过、理由为空」**

`check()` 在「没命中」时返回 `(False, "")` → 审计里写的是：

```python
audit["checks"]["asset_whitelist"] = {"passed": not is_protected, "reason": asset_reason}
# → {"passed": True, "reason": ""}
```

**理由是空串** —— 从审计上**分不出**「没命中受保护清单」与
「清单里根本没有可保护的东西」（默认就是后者：只有 loopback）。
这正是 §9.50/§9.51/§9.52 那一族：**没跑成/没保护到任何东西的检查，
被记成一次干净的通过**。

#### 9.54.3 修法

**(1) 删死代码 + 改掉撒谎的注释**（§9.36 的先例）：`0.0.0.0/0` 占位符已删除，
注释改为如实说明（它被删了、为什么被删、默认范围只有 loopback）。

**(2) 审计条目三要素**（`safe_executor.py`）：

```python
audit["checks"]["asset_whitelist"] = {
    "passed": not is_protected,
    "state": "evaluated",
    "reason": asset_reason or f"未命中受保护清单（当前清单 {N} 条，范围 {scope}）",
    "protected_count": N,          # 这道检查当时覆盖了多大范围
    "scope": scope,                # empty / builtin_only / configured
}
```

→ 运维看得到「这次检查只覆盖了 1 条内置 loopback，没有配置任何业务资产」。

**(3) 不改变保护行为**：哪些 IP 受保护**一个字没改**。

#### 9.54.4 守卫（6 条）

| 组 | 例数 | 作用 |
|---|---|---|
| `TestTheBuiltinScopeIsPinned` | 2 | **事实钉住**：内置默认**只有 loopback**；`0.0.0.0/0` 占位符**已不在**内置清单里（判据看**导入后的真实清单**，不看文件文本 —— 说明性注释里合法地提到「这条被删了」是文档、不是缺陷） |
| `TestTheAuditShowsTheScope` | 3 | 理由**非空**；审计里带 `protected_count` + `scope`；配了业务资产 → `scope="configured"` |
| `TestTheReverseCriterion` | 1 | **反向判据**：受保护 IP **仍然被拦**（保护行为没改） |

#### 9.54.5 注入验红（3 处，逐条点名）

| 注入 | 红掉的用例 |
|---|---|
| R1 审计里的理由回到空串 | `test_the_reason_is_not_empty_when_not_protected` |
| R2 占位符回到内置清单 | `test_the_placeholder_is_gone` |
| R3 默认内置清单被扩充（待决项 36 的接线场景） | `test_the_builtin_default_is_only_loopback`（+ 理由那条） |

三处都红了，红的都是**对应性质自己的那条用例**；还原后 sha256 一致
（`fb255f0a9368…` / `c52061ff6f6f…`）。

#### 9.54.6 边界与待决项

* 本轮**没有**扩充内置默认清单 → **待决项 36**：
  「内置默认保护要不要真的覆盖**平台自身组件**的 IP/网段」
  （docstring 这么承诺过，实现没做到；补上属于**扩大保护范围**的决策，
  会改变哪些 IP 被拦 → 不单方面做）。业务资产目前靠
  `SHARED_MEMORY_PROTECTED_ASSETS` 配置 —— 而**出货的 compose 里没有设它**
  （实测全仓 `PROTECTED_ASSETS` 只出现在 `asset_whitelist.py` 的说明里）。
* 本轮**没有**改保护行为（哪些 IP 受保护完全不变）。
* 本轮**没有**动 `docker-compose`（补 `PROTECTED_ASSETS` 属部署配置变更）。

### 9.55 【已修复·本轮新增】响应动作的**审计双侧**都把失败压成了「正常」

#### 9.55.1 怎么发现的

接着 §9.50~§9.54 那一族（「失败被压成一个正常值」），
用 §9.50 写的那个扫描器（找「except 里返回空值、而正常路径返回非空结构」）
在**响应动作的审计**上命中三处。

#### 9.55.2 三个实测事实

| 位置 | 旧行为 | 后果 |
|---|---|---|
| `log_threat` 写失败 | `logger.warning` → 吞 | 动作照常发生，但「**谁触发的**」在审计里**没有**了 |
| `log_action` 写失败 | `logger.warning` → 吞 | 动作**执行了**，审计里**没有**这条（审计缺口） |
| `query_logs` 查失败 | `return []` | 运维看到**空列表** = 「**没有响应动作记录**」，而真相是「**查不出来**」 |

第三条是**假阴性**：它把「读不到审计」说成「没做过处置」。
端点 `GET /response/logs` 直接把空列表返回给调用方（`routers/response.py:623`），
没有任何「查询失败」的信号。

#### 9.55.3 修法

**写侧**：失败 → 返回 `False`（调用方能知道）+ 计数 + **error 级**日志
（原来只有 `warning`，在告警级别上等于「发生过一件小事」）。

**读侧**：失败 → 计数 + error 级日志 + **上抛**；端点把它转成
**`HTTPException(503, "响应动作审计查询失败: …")`** →
运维看到的是「查不出来」，**不是**「没有记录」。

**计数**：`soc_response_audit_failed_total{phase=threat|action|query}`
→ 三种审计失败都可数（§十一.1：运行错误要单独计数，
「如果这些状态最终都被压成一个计数，那么新增多少仪表盘也无法真正帮助排障」）。
登记进 `test_metric_consumer_guard.py` 的 `UNWATCHED`（**不接告警**）。

> ⚠ **可见的行为变化**：查询失败时 `/response/logs` 从 `200 []` 变成 **503**。
> 这是**有意的**：「没有记录」与「读不到记录」在安全产品里不能混同
> （整改方案 §十一.1 / §十三「响应动作可追踪」）。

#### 9.55.4 守卫（6 条）

| 组 | 例数 | 作用 |
|---|---|---|
| `TestTheWriteSideReportsFailure` | 3 | 写失败 → 返回 `False` + 被计数；**反向判据**：成功写入返回 `True` |
| `TestTheReadSideDoesNotFakeAnEmptyResult` | 3 | 查询失败 → **上抛**（不是空列表）；**反向判据**：成功查询照常返回记录；端点把失败转成 **503** |

#### 9.55.5 注入验红（3 处，逐条点名）

| 注入 | 红掉的用例 |
|---|---|
| S1 写失败又变回静默吞掉 | `test_log_action_returns_false_on_failure` |
| S2 查询失败又变回返回空列表 | `test_query_logs_raises_instead_of_returning_empty` |
| S3 端点不再把失败转成 503 | `test_the_endpoint_turns_the_failure_into_503` |

三处都红了，红的都是**对应性质自己的那条用例**；还原后 sha256 一致
（`eac79b9c1f81…` / `782ffd6d19ce…`）。

#### 9.55.6 边界

* 本轮**没有**把「审计没落库」写进动作结果（`response_orchestrator` 调
  `log_action` 时**忽略**了返回值）→ 缺口当前只能从**计数与 error 日志**看到。
  要写进结果就得改 orchestrator 的返回结构（下游会看到新字段）→ 留作后续。
* 本轮**没有**动 `log_threat` / `log_action` 的**成功路径**行为。
* 本轮**没有**给「审计失败」接告警（会产生值班呼叫，属运维行为变更，§7.1.15）。

### 9.56 【已修复·本轮新增】响应**策略文件**的加载失败只留一行 warning → 策略集静默变小

#### 9.56.1 怎么发现的

接着 §9.40（Sigma 侧把「规则库不可用」修成 `degraded`）的同构问题，
去看**响应策略**这一侧 —— 那边没有对应的降级状态。

#### 9.56.2 缺陷（实测）

`response_engine/policy_store.py::load_all` 对每个文件：

* 解析失败 / 不是映射 → `logger.warning` + **跳过**；
* 校验不过 → `logger.warning` + **跳过**。

→ **策略集静默变小**：一条有语法错的策略文件 = 那条策略**根本不存在**，
而它本该拦住的威胁因此**不被拦** —— 却没有任何「降级」信号。

**不对称的是**：**整库**加载失败反而有可见回退 ——
`response_policies.reload()` 里 `rows=[]` → 回退代码种子 → `source="code"`
（且 API 会把 `source` 露出来）。也就是说：
「21 条策略里坏了 1 条」比「21 条全坏了」**更难发现**。

#### 9.56.3 修法

**(1) 单一入口 + 失败清单**（`policy_store.py`）：

```python
def load_all_with_errors(policies_dir) -> tuple[list[dict], list[dict]]:
    """→ (可用策略, 失败清单)；失败项：{path, reason: parse|invalid, detail}"""

def load_all(policies_dir) -> list[dict]:   # 签名与行为**不变**
    policies, _failures = load_all_with_errors(policies_dir)
    return policies
```

**(2) 引擎记住失败**（`response_policies.py`）：`self._load_errors`，
且日志改成 **error 级**并**点名是哪几个文件**：
`[ResponsePolicy] N 个策略文件加载失败（其余 M 条已加载）: path:reason …`。

**(3) 端点把失败清单一起返回**（`routers/response.py`）：
`POST /response/policies/reload` 的响应从
`{status, count, source}` 变成 `{status, count, source, failed, load_errors[]}`
→ 运维点「重载」就能看到**少了哪几条**。
（这是**新增字段**，不改已有字段 → 向后兼容 ✅）

**(4) 计数**：`soc_response_policy_load_failed_total{reason=parse|invalid|load_failed}`
→ 「有几条响应规则此刻根本没生效」可数。登记进 `UNWATCHED`（**不接告警**）。

#### 9.56.4 守卫（7 条）

| 组 | 例数 | 作用 |
|---|---|---|
| `TestTheFileLevelFailuresAreReported` | 4 | 语法坏掉的文件 → 被记录（reason=parse/invalid）；**反向判据**：健康目录**没有**失败；`load_all` 签名与行为**不变** |
| `TestTheEngineAndTheEndpointSeeTheFailures` | 3 | 引擎记进 `_load_errors`；重载端点返回失败清单；失败被计数 |

#### 9.56.5 注入验红（3 处，逐条点名）

| 注入 | 红掉的用例 |
|---|---|
| T1 不再记录文件级失败 | `test_a_broken_file_is_reported`（+ 引擎/端点/计数三条） |
| T2 引擎不再记录 `_load_errors` | `test_the_engine_records_the_load_errors`（+ 端点那条） |
| T3 端点不再返回失败清单 | `test_the_reload_endpoint_returns_the_failures` |

三处都红了，红的都是**对应性质自己的那条用例**；还原后 sha256 一致
（`1a4d1090858f…` / `ddffd40c734d…` / `43970a0c6227…`）。

#### 9.56.6 边界

* 本轮**没有**改变「策略文件坏了就跳过」这个**行为**（仍然跳过）——
  改它（fail-closed：坏一条就不响应）属**收紧型**改动 → 未单方面做。
  本轮只保证「跳过了**看得见**」。
* 本轮**没有**给策略加载失败接告警（会产生值班呼叫，属运维行为变更，§7.1.15）。
* 本轮**没有**动「整库失败 → code defaults 回退」这条**已有**的可见降级。
* 顺带核实：`response_engine/containment/store.py`（遏制记录表）**没有任何生产调用方**
  → 属 §7.1.5 已登记的**休眠能力**，不是本节的静默失败。

### 9.57 【已修复·本轮新增】信誉先验的 fail-open 在生产里**根本看不见**，而注释还说「不影响主评分」

#### 9.57.1 怎么发现的

继续用 §9.50 那个扫描器（找「except 里返回空值、而正常路径返回非空结构」）
扫**威胁情报**这一侧，命中 `threat_intel/reputation.py::_get_prior_delta`：
docstring 明写「任何失败返回 0.0(fail-open)」—— 方向对（fail-open 是显式声明的），
但**失败时只留一行 `logger.debug`** → 生产默认 INFO → **这次降级等于没记录**。

#### 9.57.2 而它并不是无害的

`_get_prior_delta` 的返回值**直接加到信誉分上**：

```python
delta = await _get_prior_delta("ip", ip, session)
score = min(1.0, max(0.0, min(score, 1.0) + delta))   # ← 就在主评分里
result.level = self._classify(result.score)             # clean/suspicious/malicious
```

`delta` 的 clip 幅度 = `learn_loop_prior_clip` = **±0.2** → 它能**跨档位**。

而**旁边的注释在撒谎**：

```python
# learn_loop 有界先验(TP/FP 反馈 → delta): fail-open, 不影响主评分
```

「**不影响主评分**」—— 与上面那行代码直接矛盾。

⇒ 一次 DB 抖动 → 「重复攻击者」的信誉分**少掉一个先验修正** → 可能从
`malicious` 掉到 `suspicious` → **处置降级**，而日志级别是 debug（生产看不见）、
没有计数、没有其它信号。

#### 9.57.3 修法

**(1) 失败可见且可数**：`logger.debug` → **`logger.warning`**（点名「评分少一个先验修正」）
+ 新增 `soc_reputation_prior_lookup_failed_total`
→ 「有多少次检测的评分少掉了一个先验修正」可数。
登记进 `test_metric_consumer_guard.py` 的 `UNWATCHED`（**不接告警**）。

**(2) 改掉那句撒谎的注释**（ip 与 domain 两处）→ 改成如实描述：
delta **会**加到主评分上，clip ±`learn_loop_prior_clip`，所以 fail-open 的代价是
「评分少一个先验修正」。

#### 9.57.4 守卫（4 条）

| 组 | 例数 | 作用 |
|---|---|---|
| `TestTheFailureIsVisible` | 2 | 失败被计数；失败被 **warning** 级记录（**不是 debug** —— 生产默认 INFO，debug 等于没记录） |
| `TestThePremise` | 2 | **前提守卫**：delta **确实**影响主评分（所以旧注释是错的）；源码里**不再**声称「不影响主评分」 |

> 判据里那条文本检查写得比较克制：那句错话**只允许**出现在带更正标记的行里
> —— 说明性注释里**合法地引用**旧话是文档、不是缺陷（§9.54 同款教训，
> 本轮第二次被自己的守卫抓）。

#### 9.57.5 注入验红（3 处，逐条点名）

| 注入 | 红掉的用例 |
|---|---|
| U1 失败时回到 debug 级日志 | `test_the_failure_is_logged_at_warning_level`（+ 计数那条） |
| U2 不计数 | `test_the_failure_is_counted` |
| U3 恢复那句不准确的注释 | `test_the_source_no_longer_claims_the_prior_does_not_affect_the_score` |

三处都红了，红的都是**对应性质自己的那条用例**；还原后 sha256 一致
（`5f964f6556f1…`）。

#### 9.57.6 边界与待决项

* 本轮**没有**改 fail-open 的**行为**（仍然返回 0.0）→ **待决项 37**：
  「先验读取失败时要不要回退到**内存缓存**」——
  缓存里就有上次加载的先验，回退会把评分**改回去**；
  而方向取决于 delta 的符号（正 delta → 评分升 → 检出更多；
  负 delta（常误报）→ 评分降 → 检出更少）→ **属业务判断**，不单方面做。
* 本轮**没有**动信誉分的算法与 clip 幅度。
* 本轮**没有**给先验读取失败接告警（会产生值班呼叫，属运维行为变更，§7.1.15）。

### 9.58 【已修复·本轮新增】集合转列表未排序 → 同一份数据的输出**跨进程不可复现**

#### 9.58.1 怎么发现的

顺着 §9.50 那个「失败被压成正常值」的思路换了一条轴线：
找**「同一份数据在两次运行给出不同结果」**的写法。
具体做法：写了个 AST 扫描器找「集合迭代顺序参与结果」的地方
（`for x in <set>` 且体内有 `break`/`return`/`max`/`min`；`min(set)`/`max(set)`；
`list(set(...))`）。

Python 的 str 哈希**每进程随机化**（`PYTHONHASHSEED`）→
凡是把集合迭代出来的**顺序**进了输出，结果就**每次启动都不同**。

#### 9.58.2 实测：6 处

| 模块 | 位置 | 输出字段 |
|---|---|---|
| `sigma_detector.py` | `analyze()` / `stats()` | `attack_types` |
| `sigma_engine/engine.py` | `detect()` / `stats()` | `attack_types` |
| `tool_registry.py` | 关联分组 | `types` |
| `self_play/overlay.py` | `detect()` | `attack_types` |

实测哈希随机化确实生效（同一组字符串，四个种子给出四种顺序），
而 `stats()["attack_types"]` 在修复前就是**未排序**的集合序 →
**同一份规则库，两个进程 → 两份不同的 JSON**。

这与整改方案 §十三「异常检测：…**重放结果可复现**」直接冲突：
结果里的**集合**是稳定的（内容不变），但**顺序**不是 →
逐字节比对会得到「结果变了」的假信号。

#### 9.58.3 修法

6 处 `list(set(...))` → **`sorted({...})`**：内容**一个不少**、顺序**确定**。

**先核实过没有消费方依赖「第一个元素」**：
`attack_types[0]` / `attack_types.index(...)` / `for at in attack_types` 全仓**零命中** ✅
→ 排序不改变任何既有语义（原先那个「第一个」本来就是任意的）。

#### 9.58.4 守卫（3 条）

| 组 | 例数 | 作用 |
|---|---|---|
| `TestTheOutputsAreSorted` | 2 | **行为**：统计里的集合型列表必须**已排序**（非空转：环境里 16 条规则、11 个类型）；**结构**：这四个模块里不得再有未排序的集合转列表 |
| `TestTheReproducibilityAcrossProcesses` | 1 | **决定性**：两个**不同 `PYTHONHASHSEED`** 的子进程 → 同一份输出的 JSON 必须**逐字节相同** |

#### 9.58.5 注入验红（3 处，逐条点名）

| 注入 | 红掉的用例 |
|---|---|
| V1 **活动实现**（`sigma_engine/engine.py`）的 stats 退回未排序 | `test_the_sigma_stats_attack_types_is_sorted` + `test_no_unsorted_set_to_list_in_the_scanned_modules` + **`test_two_hash_seeds_give_byte_identical_output`** |
| V1b 旧实现（`sigma_detector.py`）的 stats 退回未排序 | `test_no_unsorted_set_to_list_in_the_scanned_modules` |
| V2 关联分组的 types 退回未排序 | `test_no_unsorted_set_to_list_in_the_scanned_modules` |

> ⚠ **第一次注入打偏了**（如实记）：最初 V1 打在 `sigma_detector.py` 的 `stats()` 上，
> 守卫**只**红了结构那条，「两个哈希种子输出不同」那条**没红** ——
> 查下来是 `sigma_detector.sigma_detector` 实际**委托**给
> `sigma_engine/engine.py::PySigmaDetector`（本环境有 pySigma）→
> 注入打在了**未被使用**的那份实现上（**同类副本**的坑，§9.49 同款）。
> 改打活动实现后，决定性那条立刻转红 ✅。
>
> 顺带说明：这条注入经历也证明「决定性判据」**不是空断言** ——
> 它确实能区分「排序」与「未排序」。

#### 9.58.6 边界

* 本轮**没有**改变任何集合的**内容**（只改顺序）。
* 本轮**没有**处理「dict 的插入顺序」类问题（dict 顺序是确定的，不受哈希随机化影响）。
* 本轮**没有**全仓普查所有 `set` 的用法 —— 扫描器给的 6 处是**已定位**的
  「集合转列表」点；其它把集合当**无序集合**用的地方（只做成员判断）不受影响。

### 9.59 【已修复·本轮新增】集合→列表：**全仓**普查 —— §9.58 的扫描是**抽样**，同族还有 6 处真缺陷，3 处连**内容**都不确定

#### 9.59.1 起点：§9.58 自己写下的边界声明

§9.58.6「边界」里明写着：

> 本轮**没有**全仓普查所有 `set` 的用法 —— 扫描器给的 6 处是**已定位**的
> 「集合转列表」点。

那句声明是对的，而它同时也是本节的**起点**。回头看 §9.58 的扫描器
（`tests/test_output_reproducibility.py::test_no_unsorted_set_to_list_in_the_scanned_modules`），
它有两个限制：

1. **只扫 4 个模块**（`sigma_detector.py` / `sigma_engine/engine.py` /
   `tool_registry.py` / `self_play/overlay.py`）；
2. **只认字面形态** —— 判据是源码里有没有 `list(set(` 或 `list({`。

第 2 条是致命的：**集合最常见的来源不是字面量，而是一个变量**。
`list(bl.event_types)`（`bl` 是函数参数）这种写法**一个字面量都没有**，
于是它整条从扫描里溜掉了 —— 而它恰好出现在 §9.58 标记为「已修好」的
`tool_registry.py` 里（§9.58 修的是同一文件里的**另一处** `list(set(...))`）。

> **这是「同类副本」坑的第四个变体**：§9.49 是「同一份实现有另一个副本」，
> §9.58 是「同一条规则有另一个实例」，这一条是「**同一次扫描，判据形态不同
> → 漏掉整类写法**」。**扫描器本身必须先被验证它能抓到目标形态** ——
> 而 §9.58 的扫描器**没有**被这样验证过。

#### 9.59.2 扫描器：从「字面形态」到「五种数据流形态」

本轮把扫描器重写成**按数据流形态**判定，共三版：

| 版本 | 判据 | 全仓命中 |
|---|---|---|
| v1 | 局部变量被赋成集合（推导 / `set()` / set 字面量） | 5 处 / 4 文件 |
| v2 | + 参数标注 `set`、**跨模块**的 `set` 属性（按属性名匹配）、`dict[str, set]` 的值 | 11 处 / 5 文件 |
| v3（修复后） | 同 v2 + 路径归一 + **解析失败显式化** | **7 处，全部为否定结论** |

**v2 的第 3 条是这一节的关键**：集合可以是**别的模块里声明的 dataclass 属性**
（`AttackChain.src_ips: set`），扫描器必须**跨模块**按属性名收集。
只在本文件里找 set 属性的话，`routers/ops.py` 里的 `list(c.src_ips)`
就看不见 —— 而那正是 §9.59 缺陷 D6 的一半。

**扫描器解析失败必须变成显式数字**：本轮扫到 2 个带 BOM 的文件
（`app.py` / `tools/__init__.py`）会让 `ast.parse` 直接抛
`invalid non-printable character U+FEFF`。扫描器改用 `utf-8-sig` 读，
并把「解析失败的文件数」**显式报出来**，不静默跳过 ——
否则「扫过了 0 个文件」和「扫过了 400 个文件」在输出上完全同形。

**必须登记的盲区**（静态扫描**必然**有盲区，这是本节的方法论核心）：

* 集合经**函数返回值**先赋给局部变量、再转 list（v2 规则只覆盖 `list(f())` 直接形态）；
* 集合经**字典值**再取下标（只认 `dict[str, set]` 这种标注，认不出运行期构造的 dict）；
* 集合经**对象属性**但该属性名不与任何 `set` 标注同名；
* 集合经**容器嵌套**（`list(d[k])` 而 `d` 是 `defaultdict`）。

⇒ **静态扫描不可能是完备的** ⇒ 守卫必须配一层**决定性**判据（跑真实生产路径，
比两个哈希种子的输出），静态扫描只当**兜底网**。

#### 9.59.3 实测：两处**内容**层面的不确定性（不是顺序）

决定性探针：同一份输入，三个不同 `PYTHONHASHSEED` 的子进程，各自跑**真实生产路径**
（`_update_baseline` / `_save_baselines_to_redis` / `_match_pattern` /
`_entity_linking` / `_decompose_supplement` / `_chain_payload` /
`_baseline_snapshot_payload` / `_anomaly_baseline`），比输出。

| 生产输出 | seed=0 | seed=12345 | seed=777 |
|---|---|---|---|
| 补审计划**选中**的 3 个 IP | `10.0.0.1, 10.0.0.6, 10.0.0.2` | `10.0.0.2, 10.0.0.6, 10.0.0.1` | `10.0.0.1, 10.0.0.5, 10.0.0.4` |
| 攻击链的 `src_ips` | `10.0.0.1, 10.0.0.2, 10.0.0.3` | `10.0.0.3, 10.0.0.2, 10.0.0.1` | `10.0.0.1, 10.0.0.3, 10.0.0.2` |
| 实体关联的 `src_ips` | 同上 | 同上 | 同上 |

**第一行是本节最重的一条**：seed=0 选的是 `{1, 6, 2}`，seed=777 选的是 `{1, 5, 4}` ——
**集合本身都不同**，不只是顺序不同。含义很直接：

> 同一次补审，在 A 进程里查 `10.0.0.{1,2,6}`、在 B 进程里查 `10.0.0.{1,4,5}`。
> **补审覆盖到谁，是一枚骰子** —— 而补审的存在意义就是「把上次漏掉的威胁查回来」。

第二、三行是 API 响应层的不可复现（§十三「重放结果可复现」）。

#### 9.59.4 缺陷清单（6 处）

| # | 位置 | 修复前的写法 | 性质 | 后果 |
|---|---|---|---|---|
| **D1** | `anomaly_detector.py` `seen_ids` 淘汰 | `set(list(bl.seen_ids)[-2500:])` | **内容**不确定 | `seen_ids` 是**重放幂等账本**：哪条事件 id 被淘汰，决定它下次重投算不算重复消费。字符串哈希每进程随机 → 同一串事件在两个进程里得到不同的账本 → 基线与评分随之漂移（§7.2「重放一致性」） |
| **D2** | `anomaly_detector.py` Redis 落库快照 | `list(bl.event_types)` / `list(bl.seen_ids)[-5000:]` | 顺序不确定 | 同一份基线在两个进程里落出**逐字节不同**的 JSON |
| **D3** | `scheduler.py` 落库快照（`baseline_snapshots` 表） | `list(bl.event_types)` | 顺序不确定 | 快照失去「逐字节比对」能力 → 基线趋势比对无从谈起 |
| **D4** | `tool_registry.py` MCP 工具 `anomaly_baseline` | `list(bl.event_types)` | 顺序不确定 | 这是**给 LLM 看的**载荷：同一段事实换一种排列 |
| **D5** | `agents/agent_decomposer.py` IP 上限 | `list(target_ips)[:3]` | **内容**不确定 **+ 截断不留痕** | ① 查哪 3 个 IP 随进程变；② 截断**一个字都没记** —— 同一个函数里 `event_ids` 侧明明写了 `param_truncations`，IP 侧被漏掉（**自相矛盾**） |
| **D6** | `correlation_engine.py` + `routers/ops.py` | `list(srcs)` / `list(c.src_ips)` / `list(c.dst_ips)` | 顺序不确定 | 攻击链与实体关联的 API 响应跨进程不可复现 |

D1 的机制值得单说：**集合没有顺序**，`list(...) [-2500:]` 取到的是
**任意** 2500 个，而不是代码作者以为的「最近的 2500 个」。
原注释只写「有界，防止无限增长」—— 那个意图本身是对的，
错的是「用无序集合假装它有序」。

#### 9.59.5 修法

| # | 改法 | 语义变化 |
|---|---|---|
| D1 | `set(sorted(bl.seen_ids)[-2500:])` | **有**：原先保留「任意 2500 个」，现在保留「字典序最大的 2500 个」。两者都不表达「最近」，但后者**可复现** → 策略选择上交（**待决项 38**） |
| D2 | `sorted(bl.event_types)` / `sorted(bl.seen_ids)[-5000:]` | 无（只改顺序） |
| D3 | `sorted(bl.event_types)` | 无 |
| D4 | `sorted(bl.event_types)` | 无 |
| D5 | `sorted(target_ips)[:3]` + **新增** `param_truncations` 记录（`field="src_ips"`、`requested`/`used`/`limit`） | ① 选取从「任意 3 个」变成「**字典序**前 3 个」（策略上交，**待决项 39**）；② 截断**从不留痕 → 留痕**（可见性，**只增不改**拦截行为） |
| D6 | `sorted(srcs)` / `sorted(c.src_ips)` / `sorted(c.dst_ips)` | 无（只改顺序） |

**两处「抽取式」重构**（行为等价，只搬家）：为了让「载荷可复现」这条性质
**可测**，把载荷构造从端点/调度函数里抽成模块级函数：

* `routers/ops.py::_chain_payload(c)` —— 原 `list_chains` 里的字典推导；
* `scheduler.py::_baseline_snapshot_payload(bl)` —— 原 `_snapshot_baselines` 里的 `json.dumps({...})`。

端点要 DB 会话，守卫测不了；抽出来之后守卫能**直接调用生产代码**。
不抽的话，守卫只能测「我自己在测试里重写一遍的排序」—— 那等于把缺陷抄了一遍，
判据永远绿。

**一处「一致性收尾」（明确不是缺陷）**：`"event_ids": list(target_ids)` → `sorted(target_ids)`。
`target_ids` 的元素是**整数**，整数哈希不随机 → 跨进程**本就稳定**，
它不是 §9.59 家族的真缺陷。改它只有一个理由：同一个函数下面两行的
`description` 用的是 `sorted(target_ids)`，**「计划里写的」与「参数里传的」
应当是同一个顺序**。这一条**不计入缺陷数**。

#### 9.59.6 守卫（15 条，四层）

新建 `backend/tests/test_set_order_determinism.py`：

| 层 | 例数 | 作用 |
|---|---|---|
| `TestTheTwoHashSeedsAgree` | 2 | **决定性**：3 个不同 `PYTHONHASHSEED` 的子进程 → 同一份**生产输出**必须逐字节相同；**自证**：探针的每个字段都必须有内容（防空转），且实体快照必须**真的落库了** |
| `TestTheBehavior` | 9 | 幂等账本保留集合 / Redis 快照（`event_types` + `seen_ids`）/ 落库快照 / MCP 输出 / 实体关联 / 链载荷（**顺序** + **内容不丢**）/ IP 选择 / 截断留痕 / 未截断时**不**留痕 |
| `TestTheStructuralRegistry` | 2 | **结构**：全仓 AST 扫描 → 每个命中必须在登记表里（附否定结论理由），新命中即红；登记表不得有**陈旧条目**（代码改了但登记没改 → 命中数对不上，真正的漏网被淹没） |
| `TestTheNegativeConclusions` | 1 | **否定结论**：`PYTHONHASHSEED` 只随机化 str/bytes，整数集合的迭代顺序**跨进程稳定** → `causal_chain/pc.py` 那 4 处**不必修**（钉住它，免得将来把「不必修」当缺陷乱改） |

登记表（`REGISTERED_NEGATIVES`）逐条写明理由 —— 它的用途不是「放过」，
而是**逼人把话说清楚**：新增一个命中而没登记 → 守卫变红 → 必须裁决
「它是缺陷（修）」还是「它是否定结论（登记理由）」。

#### 9.59.7 注入验红（9 处，逐条点名）

| 注入 | 红掉的用例 |
|---|---|
| X1 幂等账本淘汰回到未排序 | `test_the_idempotency_ledger_keeps_a_deterministic_subset` + **`test_the_production_outputs_are_byte_identical`** |
| X2 Redis 快照的 `event_types` 回到未排序 | `test_the_redis_snapshot_is_sorted` + **决定性** |
| X3 Redis 快照的 `seen_ids` 回到未排序 | `test_the_redis_snapshot_is_sorted` + **决定性** |
| X4 补审计划的 IP 选择回到集合前 3 | `test_the_plan_selects_the_ips_deterministically` + **决定性** |
| X5 去掉 IP 侧的截断留痕 | `test_the_ip_truncation_is_recorded` |
| X6 实体关联的 `src_ips` 回到未排序 | `test_the_entity_links_are_sorted` + **决定性** |
| X7 攻击链载荷的 `src_ips` 回到未排序 | `test_the_chain_payload_ips_are_sorted` + **决定性** |
| X8 落库快照的 `event_types` 回到未排序 | `test_the_db_snapshot_payload_is_sorted` + **决定性** |
| X9 MCP 工具输出的 `event_types` 回到未排序 | `test_the_mcp_tool_output_is_sorted` + **决定性** |

每处还原后 sha256 与基线**逐位相同**。

#### 9.59.8 否定结论（4 类，必须登记 —— 否则将来会被当成「没修干净」）

| 位置 | 为什么**不是**缺陷 |
|---|---|
| `case_manager.py:898` `list(session_ids)` | 是 `IN (...)` 的参数：SQL 的 `IN` 不看顺序，集合化只是为了可哈希 |
| `causal_chain/do_calculus.py:138` `list(zset)` | `zset` 的遍历只做**集合并 / pop / discard**，与顺序无关（实测：两个哈希种子下 `d_separated` 结果完全相同） |
| `causal_chain/pc.py` ×4 `list(directed/undirected/both)` | 元素是**整数**：整数哈希不随机 → 跨进程稳定（实测两个种子输出逐字节相同） |
| `correlation_engine.py:484` `list(self.matched_patterns)` | 字段本身就是**已排序的 list**（生产方 `sorted(...)`），此处只是防御性拷贝 |

#### 9.59.9 写这一节时自己踩的四个坑（如实记录）

1. **判据空转（最严重）**：守卫第一版用 2023 年的时间戳建基线 →
   `last_seen` 落在 `cutoff` 之前 → 实体被**剪掉** → **快照根本没落库** →
   「顺序」这条判据落在「压根不存在的那份数据」上，两个进程的输出都只有
   全局键 → **恒等**。
   改成**将来的**固定时间戳（`2100-01-01`）才真正落到那份快照上。
   ⇒ **「判据的采集环境必须与被测事实同源」**：被测事实是「落库的快照」，
   而采集环境里那个实体已经被剪掉了。
2. **假红**：登记表用 `/` 写路径，扫描器在 Windows 上返回 `\` → 6 条否定结论
   全部对不上 → 守卫红了一堆**全是假的**。已统一为 `/`。
3. **判据靠运气**：行为断言第一版只用 3 个 IP（`10.0.0.1/2/3`）。
   3 个元素的集合其迭代顺序**偶然**等于升序的概率是 **1/6** ——
   于是「把 `sorted()` 退回 `list()`」这个真缺陷注入进去后，
   行为那条**靠运气通过了**，只有跨进程那条抓到它。
   ⇒ 判据必须**稳定地**红：已加厚到 12 个元素（偶然概率 ≈ 1/12!）。
4. **断言写错，不是代码错**：我按**数值序**写期望（`10.0.0.2` 在 `10.0.0.10` 之前），
   而生产代码是**字典序**（字符串比较，`10.0.0.10` 排在 `10.0.0.2` 之前）。
   已把期望改成 `sorted(IPS12)`，并在代码与守卫里写明「字典序是**已声明**的策略」。

#### 9.59.10 边界与待决项

* 本轮**没有**改任何集合的**内容**（只改顺序），除 D1 的淘汰子集（见待决项 38）
  与 D5 的 IP 选取（见待决项 39）。
* 本轮**没有**改变任何**拦截/告警行为** —— 本节全部是**确定性与可见性**改动。
* 本轮**没有**处理「dict 的插入顺序」类问题（dict 顺序是确定的，不受哈希随机化影响）。
* **待决项 38**：幂等账本（`seen_ids`）的淘汰策略该是**字典序最大**还是
  **按插入序保留最近的 2500 个**？本轮只保证「**确定**」，不承诺哪种更合理 ——
  后者要额外维护一个有序结构（并改 Redis 快照格式），属**数据结构决策**，
  不单方面做。两种策略在 >5000 条事件的实体上会保留不同的 id 集合。
* **待决项 39**：补审计划的 IP 上限（3 个）该按**字典序**取，还是按
  **数值序**（`ipaddress` 序，`10.0.0.2` 在 `10.0.0.10` 之前），
  还是按**严重度/时间**取？本轮用字典序（最简单、无失败模式、可复现），
  但它对运维来说看着别扭。取值策略属**业务定义**，不单方面做。
* **待决项 40**（本节新增的第三条，登记用）：静态扫描**必然**有盲区
  （§9.59.2 列了 4 类）。是否要再补一层「运行时集合序探针」
  （在生产代码的关键出口埋点，检测到未排序的集合就告警）？
  本轮**没有**做 —— 那会增加生产路径的开销，属**运行时行为变更**，不单方面做。

### 9.60 【已修复·本轮新增】异常检测的「精确可行区间 `[0, 0.4357)`」其实是**召回下界** —— 完整可行区间是**空集**，缺口根本不是阈值问题

#### 9.60.1 起点：一个**看起来**已经算精确了的结论

§4.4 早就把「网格落点 ≠ 精确边界」修好了（那是个真缺陷）：阈值扫描现在
同时输出「网格上界 0.4」与「精确上界 0.4357」，报告 §4.4 / §6.2 /
待决项 18 / §9.28.2 引用的都是后者，并把它叫做「**精确可行区间** `[0, 0.4357)`」。

本轮回头核对这段时注意到一件此前没人提的事：**同一个工具的 `note` 写着**

> 扫描只约束「不漏掉应检出样本」；不把 inconclusive 算成阴性，
> 所以这是一个召回下限，不是完整的最优阈值

而它的**渲染输出**把同一个数印成「精确可行区间」。

> **工具自己跟自己矛盾**，而下游（§6.2 的行动项「把阈值降到 0.4357 以内」）
> 照着那行字去调阈值。**一个被自己标注为「不是可行区间」的数，
> 却在报告里被叫做可行区间。**

#### 9.60.2 缺的那一条约束：「结构性不可判」的样本

`sweep_anomaly_threshold` 只检查一件事：**不漏掉应检出样本**。
于是标定集里的第三类样本 —— `expect="inconclusive"`（全新源 IP，
统计维度**结构上**不可判）—— **完全不参与**判定。

而它们的得分并不低。实测（2026-10-20，标定集 8 条）：

| 样本 | 标注 | 得分 | 说明 |
|---|---|---|---|
| ANO-P-02 | detected | **0.4357** | 罕见类型 + critical（当前漏检） |
| ANO-P-03 | detected | **0.4957** | 凌晨 + 罕见类型（当前漏检） |
| ANO-N-01 | not_detected | 0.0000 | 稳态实体，速率与基线一致 |
| ANO-N-02 | not_detected | **0.1714** | 有基线、正常工作时段的常见事件 |
| ANO-I-01 | **inconclusive** | **0.4957** | 全新源 IP + critical + 凌晨 |
| ANO-I-02 | **inconclusive** | **0.4357** | 全新源 IP，且事件无时间戳 |
| ANO-I-03 | inconclusive | 0.0000 | 基线只有 2 个小时桶（冷启动） |

**两条「不可判」的得分与两条「应检出」完全相同**（0.4957 / 0.4357）——
因为它们拿到的是同一组上下文维度（severity + 时段）+ 同一个罕见度维度，
差别只在「统计维度拿不到」。

于是 §6.2 行动项 2 的原话（「把阈值降到精确上界 `[0, 0.4357)` 以内」）会把
这两条**结构性不可判**的样本判成 `detected`：
新源 IP + critical + 凌晨 → 报「已检出」。

#### 9.60.3 决定性实测：逐档体检

（`sweep_anomaly_threshold` 修好后新增的 `threshold_mismatch_table`，
网格步长 0.05，判据与真检测器一致：`score > t or sigma > 3`）

| 阈值 | 漏检（应检出未中） | 误报（负类被中） | 不可判被翻成 detected | 不一致 |
|---|---|---|---|---|
| 0.00 ~ 0.15 | — | ANO-N-02 | ANO-I-01, ANO-I-02 | 3 |
| 0.20 ~ 0.40 | — | — | **ANO-I-01, ANO-I-02** | **2** |
| 0.45 | ANO-P-02 | — | ANO-I-01 | 2 |
| **0.60（当前）** | **ANO-P-02, ANO-P-03** | — | — | **2** |
| 0.65 ~ 1.00 | ANO-P-02, ANO-P-03 | — | — | 2 |

**没有任何一档**能让标定集完全自洽：

* `t ≥ 0.45`：漏掉正样本（当前缺口）；
* `0.20 ≤ t < 0.4357`：漏检修好了，但两条「结构性不可判」被翻成 `detected`；
* `t < 0.20`：负类也出现误报。

⇒ **完整可行区间 = [0.4957, 0.4357) = 空集**。

这条结论是**解析**的（下界 ≥ 上界），不是网格采样的副产品 ——
守卫里两条断言各钉一个：网格版（密集 0.01 步长，101 档）与解析版。

#### 9.60.4 修法

**改的是「决策依据」，不是检测行为。** 本轮**没有**动 `ANOMALY_SCORE_THRESHOLD`
（0.60 保持不变），**没有**动任何评分公式，**没有**动任何拦截行为。

1. `eval_datasets/evaluate_detection.py::sweep_anomaly_threshold` 补齐约束：
   * `false_positive_lower_bound` = 负类最高分（0.1714）—— 阈值必须 ≥ 它；
   * `inconclusive_lower_bound` = 不可判类最高分（0.4957）—— 阈值低于它，
     不可判样本会被报成 `detected`；
   * `complete_lower_bound` = 两者取大；
   * `complete_feasible` / `complete_feasible_interval` / `feasible_thresholds`；
   * `threshold_mismatch_table`：逐档体检表。
   **既有键全部保持原样**（`exact_upper_bound` / `grid_upper` /
   `perfect_thresholds` / `current_is_perfect`），既有守卫不受影响 ✅。
2. 渲染输出改名并补全：
   「精确可行区间 = [0, 0.4357)」→「**召回下界** = [0, 0.4357)」，
   另加负类下界 / 不可判下界 / **完整可行区间 = 空集** 三行。
3. `note` 改写：说清楚它是召回下界，并指向 `complete_feasible`。
4. `eval_datasets/evaluate_scale_window.py` 的注释同步改口径
   （它原本写「§9.3 的阈值扫描（精确可行区间 `[0, 0.4357)`）」）。
5. 报告 §4.4 / §6.2 / 待决项 18 / §9.28.2 四处引用同步更正 ——
   **同一个被量化的错误结论会顺着文档与代码注释传播**，本轮实测它已经扩散到 5 处。

> **同仓库的对照组**：`eval_datasets/evaluate_grounding.py` 与
> `evaluate_behavior.py` **早就做对了** —— 它们算的是带**双端**的精确可行区间
> （`exact_lower_exclusive` / `exact_upper_inclusive`），并专门写了注释说明
> 「网格投影 ≠ 精确边界」。只有检测评估器一直停在「单边上界」。
> ⇒ 这不是「没人想到」，是**同一件事在一个工具里做了、在另一个工具里没做**。

#### 9.60.5 守卫（11 条，`tests/test_anomaly_threshold_feasibility.py`）

| 组 | 例数 | 作用 |
|---|---|---|
| `TestNoThresholdWorks` | 4 | **决定性**：密集网格（101 档）上**独立重算**不一致集合 → 每个阈值都至少 1 条不一致（**不采信工具自己的表** —— 采信它就成了自证）；空集是**解析**结论（下界 ≥ 上界） |
| `TestTheOutputDoesNotOverclaim` | 3 | 渲染输出**不得**把召回下界印成「可行区间」；`note` 必须自称召回下界并指向权威字段；同族评估器（`evaluate_scale_window.py`）用同一措辞（**正向**断言，避免被「合法引用旧话」误伤） |
| `TestTheNegativeConclusions` | 3 | 负类单独看时 `t > 0.1714` 永不误报（**原句对负类为真**，它错在只看负类）；负类样本量只有 **n=2**（事实钉住）；不可判类**不计入**负类 |
| `TestTheProductionFactIsPinned` | 1 | 生产事实：`is_anomaly` **不因**证据维度不可判而否决（→ 待决项 41） |

#### 9.60.6 注入验红（4 处，逐条点名）

| 注入 | 红掉的用例 |
|---|---|
| Y1 扫描不再算「不可判类下界」（回到只算召回下界） | `test_the_complete_feasible_interval_is_empty` + `test_the_three_bounds_are_pinned` + `test_the_empty_interval_is_analytical_not_sampled` + `test_the_inconclusive_class_is_not_counted_as_a_negative` |
| Y2 渲染把「召回下界」又印成「精确可行区间」 | `test_the_rendered_output_does_not_call_it_a_feasible_interval` |
| Y3 `note` 回到旧说法 | `test_the_sweep_note_says_it_is_a_recall_bound` |
| Y4 同族注释里「召回下界」被改回「精确可行区间」 | `test_the_sibling_evaluator_uses_the_same_wording` |

四处都红了，红的都是**对应性质自己的那条用例**；还原后 sha256 一致。

#### 9.60.7 边界与待决项

* 本轮**没有**动 `ANOMALY_SCORE_THRESHOLD`（仍 0.60）、**没有**动评分公式、
  **没有**动任何拦截/告警行为 —— 改的全是**决策依据**与**口径**。
* 本轮**没有**把「不可判类下界」变成一条**硬约束**（即没有让工具因为它
  就拒绝出数）—— 它是**约束**，是否成立取决于冷启动规则的设计 → **待决项 41**。
* 本轮**没有**登记新的 `KNOWN_GAPS` 条目：原条目
  `anomaly_threshold_above_recall_floor` 仍然成立（漏检集合未变），
  但它的**性质**变了 —— 由「阈值调一下就能补」升级为「**阈值怎么调都补不上**」。
* **待决项 41**（本节新增）：整改方案 §七.2 要求
  「对缺乏历史数据的新实体，单独采用经过评估的冷启动规则」——
  **当前实现没有这条规则**：`is_anomaly` 不因证据维度不可判而否决，
  不可判只是被**记下来**（`inconclusive_dimensions`），
  不参与否决（守卫 `TestTheProductionFactIsPinned` 已把这条事实钉住）。
  要不要改成「存在不可判维度时 `is_anomaly` 不得成立」或
  「把 status 改成 `partial`」属**收紧型**改动 —— 方向上会**减少**检出
  （新实体攻击正是靠罕见度+严重度+时段被抓住的），**不单方面做**。
  配套的「冷启动规则」本身需要**有标签的样本**做离线评估，
  与 §4.4 那个缺口是**同一个**数据依赖。

### 9.61 【已修复·本轮新增】同一个平台、两个面：沙箱拦 SSRF，**告警 webhook 却不拦** —— 而且动作参数在审计里**全都不见**

#### 9.61.1 起点：一次「全仓外呼点」普查

整改方案 §五 给沙箱入口定了完整的 URL 安全边界（只允许 http/https；
拒绝 loopback / link-local / 私有地址 / 云元数据地址；重定向目标重新校验；
task_id 只接受明确格式）。那是 §9.21 / §9.22 修的。

本轮按 §9.59 的方法论做了一次**全仓外呼点普查**（AST 版扫出 136 处候选，
其中绝大多数是 ORM 的 `session.get(Model, id)` 假阳性；源码级收窄后 61 处候选
→ 逐条裁决后剩 **20 余处真外呼点**），问的问题是：

> **平台还有第二个「接受用户给的 URL 并去请求它」的面吗？那套限制接上了吗？**

逐条裁决的结果：

| 外呼点 | URL 来源 | 结论 |
|---|---|---|
| `zeroday_detect/sandbox_connector.py` | 用户提交 | ✅ **已有限制**（§9.21/§9.22） |
| `encrypted_traffic/mitm_proxy.py:193`（`urlopen`） | **硬编码**的回环地址 | ✅ 否定结论 |
| `routers/kafka.py`、`routers/ops.py`（tempo） | 配置/服务名 | ✅ 否定结论 |
| `schema_registry.py`、`rag/*_importer.py`、`threat_intel/stix_taxii.py`、`rag/reranker.py` | 配置/运维参数 | ✅ 否定结论 |
| **`response_engine/response_registry.py::_send_webhook`** | **动作参数（调用方给）** | ❌ **无任何校验** |

#### 9.61.2 缺陷 D2：告警 webhook 的 URL 完全没有限制

`webhook_url` 是整个响应注册表里**唯一**的 URL 参数（实测：全仓扫描
`webhook_url` 只出现在这一处），而它**完全不校验** →

```python
async with httpx.AsyncClient(timeout=10) as client:
    resp = await client.post(webhook_url, json=payload)
```

**到达路径（实测）**：

1. `send_alert` 的 severity 是 **low**（不是 critical）→ 手动执行端点
   「CRITICAL 不许手动直执行」那道闸**不拦**它；
2. `POST /response/execute?action_name=send_alert` 要 **operator** 角色
   （不是 admin），而它 JSON body 里的 `params` 是**原样透传**给动作的
   （`routers/response.py:417-435`）→ `webhook_url` 直接落到动作参数；
3. SecurityGuard 的意图矩阵**每一档**都放行 `send_alert`（含 low/info）；
4. → 平台向任意 URL 发 POST，并把 `status_code` 带回给调用方
   （**内网探测 oracle**）。

**决定性实测（修复前）**：本地起一个 HTTP 监听器，让 `send_alert` 指过去：

```
1) 平台是否真的向 loopback 发了请求: 是 ❗
   收到: path=/internal-only body={"title":"t","message":"m","severity":"high",...}
   执行结果: success=1 failed=0 detail=[{'mode': 'webhook', 'success': True, 'status_code': 200}]

2) validate_submittable_url('http://127.0.0.1:13222/internal-only') → 拒绝: UrlRejected: loopback_not_allowed: 127.0.0.1
2) validate_submittable_url('http://169.254.169.254/latest/meta-data/') → 拒绝: UrlRejected: cloud_metadata_blocked
2) validate_submittable_url('file:///etc/passwd') → 拒绝: UrlRejected: scheme_not_allowed: file
```

> **同一平台、同一套 URL、两个面：沙箱那一面拒绝，告警这一面照发。**
> 平台**早就有**该用的校验器（`zeroday_detect.sandbox_status.validate_submittable_url`，
> §9.21 打磨过、有 DNS 复检），只是**没接到这个面上**。

（`httpx` 的 `follow_redirects` 默认是 `False` → 沙箱那边踩过的
「重定向绕过」在这个面上**不成立**；这与沙箱用 aiohttp 不同。）

#### 9.61.3 缺陷 D1：动作的**实际参数**在审计里全都不见

`response_engine/response_orchestrator.py::action_rows_from_batch` 写进
响应日志的 `action_params` 只有三个键：

```python
"action_params": {
    "execution_mode": mode,
    "verified": inner.get("verified"),
    "error": item.error or inner.get("error") or "",
},
```

`webhook_url` / `src_ip` / `duration_minutes` / `host_ip` … **一个都没有**。
（参数只存在于**回滚存储**里 —— 那是回滚用的，不是审计面。）

后果与 D2 叠加：operator 让平台向内网某地址发请求，**审计里查不到那个地址**。
实测（修复前）：

```
3) 响应日志行的 action_params = {"execution_mode": "webhook", "verified": null, "error": ""}
   里面有 webhook_url 吗: 没有 ❗
```

这属于 §9.34 / §9.35 那一族（「动作发生了，但审计里没有这条」）的**变体**：
不是「没有这条记录」，而是「**记录在，但少了最关键的那一半**」。

#### 9.61.4 缺陷 D3：`dingtalk` / `wework` 渠道**从未实现**，却在文档与 schema 里宣传

`_send_alert` 的 docstring 写着四个渠道（webhook / eventlog / dingtalk / wework），
`params_schema` 写着 `通知渠道(webhook/dingtalk/wechat)` ——
而实现里**只有** webhook / eventlog / display。配成 `dingtalk` 的策略
走的是 `else` 分支：

```python
logger.warning(f"[ALERT] Unknown channel={channel}, falling back to log")
return {"action": "send_alert", "mode": "stub", ...}     # 没有 success、没有 error
```

→ 告警**静默丢失**（只留一行 warning），结构化日志里只有 `success=False` + **空**的 error
（原因同样只在那行 warning 里）。

#### 9.61.5 修法

| # | 改法 | 性质 |
|---|---|---|
| D2 | `_send_webhook` 发请求前过 `_check_webhook_url()`（**复用**平台既有的 `validate_submittable_url`，口径与沙箱一致）：只允许 http/https；**loopback / link-local / 保留段 / 组播 / 云元数据一律拒绝**（`allow_private=True` 只放开 RFC1918 私有段 —— 那是内网告警接收方的正常形态）；域名解析后的 IP 复检；**解析失败不阻断**（此时请求本身也会失败，结果相同）但留 warning；校验器不可用 → **fail-closed**（不发送） | 应用平台**既有**不变式（沙箱那侧的注释写明「loopback 与云元数据在任何模式下都禁」），**不改变**正常部署形态 → 不是收紧型决策 |
| D1 | `ActionResult` 增加 `params` 字段（执行器填**脱敏后**的实参）→ `action_rows_from_batch` 写进 `action_params["params"]`（**嵌套**一层，避免动作参数自带 `error`/`execution_mode` 这类键名覆盖审计元字段）。脱敏规则：敏感键（password/secret/token/credential/apikey/…）的值 → `***`，**键名保留**（「它带了 password 参数」本身就是信息）；超长值截断 | 纯**可见性**，不改变任何行为 |
| D3 | 未实现的渠道 → **明确失败**（`success=False` + `error="unsupported_channel: <channel>"`）+ error 级日志；docstring 与 `params_schema` 如实化（只列实现了的三个渠道，并补上此前漏写的 `webhook_url`） | 诚实化 + 可见性 |

**没有做的事**：没有实现钉钉/企业微信（属产品决策，**待决项 43**）；
没有改任何动作的**执行**行为（除了被 URL 校验拦下的那些 webhook）；
没有改 `send_alert` 的 severity / 护栏矩阵 / 角色要求。

#### 9.61.6 守卫（16 条，`tests/test_response_webhook_url_guard.py`）

| 组 | 例数 | 作用 |
|---|---|---|
| `TestTheLoopbackIsRejected` | 8 | **决定性（网络层）**：loopback 目标**收不到任何请求**（监听器里没有记录才是证据）；**决定性（调用层）**：禁止目标**根本不会走到 HTTP 调用**；6 个禁止目标各自给出**正确的**拒绝原因（loopback / link-local / 云元数据 / 非 http(s) / IPv6 loopback） |
| `TestTheLegitTargetStillWorks` | 3 | **反向**（防过度收紧）：私有地址、公网 https 目标**放行**；合法目标**确实走到了 HTTP 调用**（用记录器断言调用发生了） |
| `TestTheAuditSeesTheTarget` | 3 | 动作参数进 `action_params` 且**不挤掉**既有字段；敏感键脱敏（值 `***`、键名保留、超长截断）；**端到端**：执行器 → `ActionResult` → 日志行，参数一路都在 |
| `TestTheUnsupportedChannelFailsLoudly` | 2 | 未实现的渠道**明确失败**并给出原因；`params_schema` **不得**宣传未实现的渠道 |

> **为什么「合法目标收到请求」不在网络层断言**：本机（Windows + 私有
> profile 防火墙）连**自己的私有 IP**都会被拦（实测 `httpx.ReadTimeout`），
> 而 loopback 又恰好是被禁的那一类 → 网络层没有「既合法又可达」的本地目标。
> 正向证明改在**调用层**（HTTP 客户端是否被调用）；网络层的**负向**证明
> （loopback 收不到）仍是真网络证据。

#### 9.61.7 注入验红（6 处，逐条点名）

| 注入 | 红掉的用例 |
|---|---|
| Z1 webhook 不再做 URL 校验 | `test_the_request_never_reaches_a_loopback_listener` + `test_a_forbidden_target_never_reaches_the_http_client` |
| Z2 响应日志不再带动作参数 | `test_the_action_params_reach_the_response_log` |
| Z3 敏感参数不再脱敏 | `test_sensitive_params_are_redacted` |
| Z4 未实现的渠道回到静默降级 | `test_an_unimplemented_channel_fails_with_a_reason` |
| Z5 `params_schema` 又开始宣传未实现的渠道 | `test_the_schema_does_not_advertise_unimplemented_channels` |
| Z6 执行器不再把参数挂到 `ActionResult` 上 | `test_the_executor_carries_the_params_all_the_way` |

六处都红了，红的都是**对应性质自己的那条用例**；还原后 sha256 一致。

> ⚠ **第一次注入验红时 Z6 没红**（如实记）：守卫最初那条断言是
> **自己造**一个带参数的 `ActionResult` 再喂给 `action_rows_from_batch` ——
> 于是「**执行器压根没把参数挂到结果上**」这个真缺陷**测不出来**。
> 判据只覆盖了「我想到的那种写法」。已补一条**端到端**用例
> （走真实执行器），Z6 随即转红。
> ⇒ 与 §9.59 那条「判据要对着修复前的真实缺陷写」同源：
> **接线处**最容易漏 —— 函数本身对，**没接上**。

#### 9.61.8 边界与待决项

* 本轮**没有**实现钉钉/企业微信渠道 → **待决项 43**：
  「`dingtalk` / `wework` 两个渠道**要不要真的实现**」——
  此前它们只在 docstring 与 `params_schema` 里存在，**代码里从来没有**。
  实现是产品决策（要接哪家的机器人、要不要带签名/加签），不单方面做；
  本轮只做**如实化 + 明确失败**（不再静默丢告警）。
* 本轮**没有**改私有地址的默认放行 → **待决项 42**：
  「告警 webhook 的**私有地址**（RFC1918）默认放行还是默认拒绝 +
  要不要独立授权/例外开关」——
  本轮默认**放行**（与沙箱 `allow_private=True` 同一口径），
  因为内网告警接收方是**正常部署形态**，默认拒绝会打断所有现有部署；
  但文档 §五 对沙箱的说法是「默认拒绝……如果确有内部 URL 分析需求，
  需要**独立授权、明确例外**和隔离环境」—— 告警通道是否也该走
  「独立授权」这条路，属**业务/运维决策**，不单方面做。
  （同一条待决项还含一个小问题：**DNS 解析失败时是否阻断**。
  本轮选「不阻断但留痕」，理由：此时 HTTP 请求本身也会失败，结果相同。）
* 本轮**没有**改 `send_alert` 的 severity、护栏矩阵、角色要求，
  **没有**加新的指标，**没有**改任何动作的执行语义。
* 本轮**没有**把 URL 校验接到**其它**接受 URL 的面（配置类外呼已逐条裁决为
  否定结论）；**将来**若新增「用户可填 URL」的面，必须接同一套校验 ——
  这条已由本守卫的结构（`validate_submittable_url` 是平台唯一口径）间接保证。
* **一个可解释的副作用**：`zeroday_detect/sandbox_status.py` 此前只被
  沙箱自己引用；本轮 `response_engine/response_registry.py` 也引用了它
  （URL 安全策略的**唯一**实现所在）→ 它成了「被包外生产代码引用的模块」，
  §9.44 的**活跃模块**数 192 → **193**（零覆盖清单仍是 22 条：
  它本来就有测试）。

### 9.62 【已修复·本轮新增】外部可控标识符进入**查询表达式 / URL 路径**：Graph 与 LDAP 两个面**没有**防护，主机适配器有

#### 9.62.1 起点：把 §9.61 的方法论用到第二个能力上

§9.61 的判据是「安全边界要按**能力**普查，不是按**模块**」。本轮把它用到
**第二个能力**上：**外部可控的标识符被拼进查询表达式 / URL 路径**。

整改方案 §五 对沙箱的 `task_id` 说过：「只接受明确的标识符格式，拒绝路径
分隔符、`..` 和其他路径控制字符，避免将用户输入直接拼接进请求 URL」
（§9.22 已实现为 `validate_task_id`）。

于是问同一个问题：**平台还有哪些面把外部可控标识符拼进了查询表达式或 URL 路径？**

| 适配器 | 面 | 防护 |
|---|---|---|
| `host_adapter.py` | PowerShell 命令 / 文件路径 | ✅ **有**：`reject_path` 拒 `..` 与系统目录；引号用 `replace(chr(39), '')` 剥离 |
| `mail_adapter.py` | Microsoft Graph（OData 过滤器 + URL 路径） | ❌ **无** |
| `directory_adapter.py` | LDAP/AD 过滤器 | ❌ **无** |

⇒ **同一平台、同一类能力，防护只接在了一个面上**（与 §9.61 同形）。

#### 9.62.2 缺陷 D1：Graph 的 OData 过滤器可被**改写**（删掉别人的邮件）

`recall_email`（撤回钓鱼邮件，severity=high，category=mail）把
`internet_message_id` **原样**拼进 Graph 的 `$filter`：

```python
filt = quote(f"internetMessageId eq '{mid}'", safe="")
```

`quote()` 只保护 **URL 语法**；Graph 收到 URL 后会**先解码**再交给 OData
解析器 —— 于是值里的 `'` 仍然会闭合字面量、改写表达式。

**决定性实测（修复前）**（本地起 HTTP 桩，抓平台真正会发出的 URL）：

```
[GET] https://graph.microsoft.com/v1.0/users/.../messages?$filter=internetMessageId%20eq%20%27msg-1%27%20or%20contains%28subject%2C%27x%27%29%20or%20%27a%27%3D%27a%27
   → Graph 看到的 $filter = "internetMessageId eq 'msg-1' or contains(subject,'x') or 'a'='a'"
   → 注入成立? 是 ❗（OData 表达式被改写）
```

后果：过滤器不再只匹配那一封邮件 → `items[0]` 可能是**别人的邮件** → 平台把它
`move` 到 `recoverableitemsdeletions`（**删掉别人的邮件**）。
**这条安全动作本身变成了删除任意邮件的原语。**

可达性：`internet_message_id` 既可由动作参数给（`/response/execute`，
operator 角色），**也可由威胁上下文注入**（`response_executor._execute_one`
从 `threat_info` 取）→ 事件里的字段即可影响它。

#### 9.62.3 缺陷 D2：Graph 的 URL 路径可被**穿越**（带着应用 token 落到别人的邮箱）

```python
filt = ...
search = await client.get(f"https://graph.microsoft.com/v1.0/users/{quote(user)}/messages?$filter={filt}", headers=headers)
```

`quote()` 的默认 **`safe='/'`** —— **不转义 `/`**；而 `.` 本来就不在转义范围里。
于是 `mailbox="../../users/victim@corp.com"` 原样进入 URL 路径：

```
   → 解码后路径 = /v1.0/users/../../users/victim@corp.com/messages
   → 规范化后   = /users/victim@corp.com/messages
   → 路径穿越成立? 是 ❗（请求落到另一个用户的邮箱路径）
```

请求带着 **应用自己的 Graph token**（client_credentials + `.default` 作用域）
→ 越权访问**另一个用户**的邮箱。

#### 9.62.4 缺陷 D3：LDAP 过滤器可被**改写**（禁用了另一个账户）

```python
filt = f"(|(sAMAccountName={acct})(userPrincipalName={acct}))"
```

`acct` **原样**拼进 LDAP 过滤器 → `acct = "x)(objectClass=*"` 把子句数从 2
变成 4，其中一个是 `objectClass=*`（匹配**所有**对象）→ 平台禁用了
**另一个**账户 —— 而审批单上写的是攻击者给的那个。

`disable_account` 是 **critical** 动作（要走审批），受保护账户的复查仍在
（`is_protected_account(acct, dn=found_dn)`，用**找到的** DN 再查一次），
所以爆炸半径被限制在「非受保护账户」—— 但「审批单说的是 A、平台禁的是 B」
本身就是**越权 + 审计失真**。

可达性同 D1：`account` 既可由动作参数给，也可由**威胁上下文**注入
（`response_executor._execute_one` 从 `threat_info.get("user_name")` 取）→ 事件里的
字段即可影响它。

#### 9.62.5 修法

| # | 改法 | 性质 |
|---|---|---|
| D1 | 新增 `_odata_escape()`：OData v4 ABNF 的单引号**翻倍**（`'` → `''`）；过滤器构造抽成 `_odata_filter()` | 用**协议规定的**转义，合法 id **原样通过** → 不是收紧 |
| D2 | 新增 `_graph_path_segment()`：拒绝路径分隔符 / `..` / 控制字符，并用 `quote(raw, safe="")`（`safe=""` 才不保留 `/`）；Graph 自己返回的 message id 走 `_graph_opaque_id()`：**只校验不改写**（它的字符集由 Graph 决定，含 base64 的 `/` `+`，重编码反而可能打到错误路径） | 合法 UPN / `me` 原样通过 → 不是收紧 |
| D3 | 新增 `escape_ldap_filter()`（RFC 4515 的 6 个字符，`\XX` 形式，与 `ldap3.utils.conv.escape_filter_chars` 同一套规则，但**自带一份** → 不装 ldap3 的环境也能测，行为只有一条）；过滤器构造抽成 `build_ldap_filter()` | 合法账户名原样通过 → 不是收紧 |

**为什么 LDAP 的转义自己实现而不用 ldap3 的**：本环境**没装 ldap3**（活路径本来
就不可达），用官方函数就**测不到**；自带一份还能让「不装依赖的环境」与
「装了的环境」行为一致。规则本身是 RFC 4515，两边等价。

#### 9.62.6 守卫（16 条，`tests/test_containment_identifier_injection.py`）

| 组 | 例数 | 作用 |
|---|---|---|
| `TestTheGraphODataFilter` | 3 | **决定性**：无论 mid 是什么，过滤器**结构**恒为「一个字符串字面量」（值里的 `'` 必须成对转义）；**端到端**：恶意 mid 发出的 `$filter` 仍只有一个字面量；**反向**：合法 Graph id 原样通过 |
| `TestTheGraphPath` | 8 | 6 个穿越形态（`../`、`..\`、`a/b`、`a\b`、`..`、NUL）必须被拒；合法 UPN 与 `me` 通过；**端到端**：恶意 mailbox **根本不会**产生 Graph 消息请求 |
| `TestTheLdapFilter` | 4 | **决定性**：过滤器的**子句数**恒为 2（结构不变式）；合法账户名原样通过；转义规则符合 RFC 4515；转义后的值里没有裸结构字符 |
| `TestTheNegativeConclusion` | 1 | **否定结论**：`host_adapter.reject_path` 确实拒 `..` / 系统目录 / 空路径 → 钉住「那一面**不必修**」 |

#### 9.62.7 注入验红（3 处，逐条点名）

| 注入 | 红掉的用例 |
|---|---|
| X1 Graph 的 OData 转义被去掉 | `test_the_filter_always_has_exactly_one_literal` + `test_the_odata_injection_never_reaches_graph` |
| X2 Graph 的路径段校验被去掉（回到 `quote` 默认 `safe='/'`） | `test_the_traversal_mailbox_is_rejected`（6 个参数化用例）+ `test_the_recall_never_reaches_graph_for_a_malicious_mailbox` |
| X3 LDAP 的过滤器值转义被去掉 | `test_the_filter_structure_is_invariant` + `test_the_escaping_follows_rfc4515` + `test_the_escaped_value_has_no_structure_characters` |

三处都红了，红的都是**对应性质自己的那条用例**；还原后 sha256 一致。

> ⚠ **判据第一版写错了一处**（如实记）：LDAP 那条曾要求「剥掉转义序列后剩下的
> 值必须**是空的**」—— 那等于要求「值里不能有任何字符」，而 RFC 4515 里
> `'` **本就没有**特殊含义（过滤器语言的结构字符是 `( ) | & ! = < > ~ :`
> 与 `* \ ( ) NUL /`）→ 那个判据既**过严**又不贴切。
> 已改成**子句数不变式**（最外层 `(|...)` 里恒为 2 个子句）——
> 那才是「结构」的可测形式。

#### 9.62.8 边界与待决项

* 本轮**没有**改任何动作的**正常路径**行为：合法 UPN / Graph id / 账户名
  都原样通过（守卫有**反向**判据钉住）。
* 本轮**没有**给 LDAP 活路径做端到端实测（本环境**没装 ldap3**，
  `disable_account` 的活路径本来就不可达）→ 判据落在**过滤器构造**这一层，
  而构造用的就是活路径**同一行**代码。
* 本轮**没有**动 `host_adapter`（它**有**防护）→ 钉成否定结论。
* 本轮**没有**给 `internet_message_id` / `account` 加**严格白名单** →
  **待决项 44**：「`mailbox` 要不要**严格白名单**（只允许 UPN / `me` / GUID），
  还是维持『只拒路径分隔符与控制字符』的最小规则」——
  白名单更严，但会拒掉少数合法的目录服务标识（如 `DOMAIN\User` 之外的写法）；
  本轮取最小规则（零误拒），**收紧型**决策不单方面做。
* **待决项 45**：「标识符策略要不要**统一到一处**」——
  现在分散在 `zeroday_detect.sandbox_status.validate_task_id`（沙箱）
  与本轮新增的 `mail_adapter._graph_path_segment` /
  `directory_adapter.escape_ldap_filter` 三处。抽成平台统一的
  「标识符策略」模块，对**下一个**「用户可控标识符进 URL」的面更有用
  （§9.61/§9.62 两次都栽在「防护只接在一个面上」）；
  但那是**重构决策**（要动沙箱那侧的既有实现与测试），不单方面做。

### 9.63 【已修复·本轮新增】**我 §9.61 那个改动扩大出来的暴露面**：审计与日志现在含 webhook 密钥，而 `/response/logs` 对**任何**登录用户开放

#### 9.63.1 起点：一次「OS 命令 / SSH 面」普查，和一处**自曝**

本轮先做了一次「**外部可控输入 → OS 命令**」的普查（§9.62 的方法论），
结论是**这个面基本是干净的**（下表），于是转而去盯 §9.61 那个改动的**副作用**。

| 面 | 防护 | 结论 |
|---|---|---|
| `host_adapter.py`（PowerShell / 文件路径） | `reject_path` 拒 `..` 与系统目录；引号用 `replace(chr(39), '')` 剥离 | ✅ 否定结论 |
| `ssh_firewall.py`（iptables） | `_normalize_ip` 严格 `ipaddress` 校验 + `command_whitelist` + `asset_whitelist` | ✅ 否定结论 |
| `command_whitelist.py` | 规则是**整条锚定**的正则（`^...$`）+ `GLOBAL_FORBIDDEN`（`;` `&&` `|` `>` `` ` `` `$(` …） | ✅ 否定结论 |
| Windows 通道（`transport.py`） | 脚本走 **Base64 编码**（`powershell -EncodedCommand <b64>`） | ✅ 注入不可能 |
| SSH 的**目标主机** | `transport.run()` **没有 host 参数** → 目标是**配置项**，不是用户输入 | ✅ 否定结论 |
| `nmap` 真实扫描 | `ssh_firewall.vulnerability_scan` 的 `target` **未校验**，但白名单只放行**裸 IPv4**；且该方法**无生产调用方**（MCP 那个是模拟的） | ✅ 否定结论（休眠能力） |

> 顺带钉住的**否定结论**：沙箱的 `task_id` / `sample_hash` 已按文档 §十 修好
> （`_extract_task_id` 取不到就返回空串，不再产出字面量 `"None"`；`sample_hash`
> 随 outcome 返回）→ 不再是缺陷。

**自曝**：§9.61 把动作的**实际参数**写进了响应日志。那是对的（审计要能回答
「这个动作对什么做了什么」），但——

#### 9.63.2 缺陷：告警 webhook 的 URL **通常内嵌密钥**

| 渠道 | URL 形态 |
|---|---|
| Slack | `https://hooks.slack.com/services/T00/B00/<SECRET>` |
| 钉钉 | `https://oapi.dingtalk.com/robot/send?access_token=<SECRET>` |
| 企业微信 | `https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=<SECRET>` |

而响应日志的查询端点 `GET /response/logs` 只要
`Depends(get_current_user)` —— **任何登录用户**（连角色都不要求）：

```python
@router.get("/response/logs")
async def query_response_logs(
    ...
    user: UserInfo = Depends(get_current_user),
):
```

⇒ §9.61 之后，**告警通道的钥匙落进了全体登录用户可读的审计表**。
拿到钥匙的人可以往 SOC 的告警通道里**注入任意消息**（告警注入），
若接收侧接了自动化 workflows，危害更大。

> 这条是**我自己上一轮的改动扩大出来的暴露面** —— §9.61 把参数写进审计时
> 只想着「审计要看得见动作的目标」，没想着「目标里可能带着凭据」。
> **把可见性和保密性一起考虑，才算把审计做对。**

#### 9.63.3 修法：URL 一律记成「可关联但不含密钥」的形态

新增 `response_engine/response_registry.py::redact_url_for_log(url)`：

```
https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=SUPERSECRET
  → https://qyapi.weixin.qq.com/cgi-bin/…#sha256:3f2a9c1b7d04
```

* 保留 `scheme://host[:port]/<路径首段>` —— 足够回答「发到哪台机器、哪条通道」；
* 加完整 URL 的 `sha256[:12]` —— **同一个目标在不同日志里仍可关联**（不需要看到密钥）；
* **查询串与 userinfo 一律丢弃**（`?key=` / `?access_token=` / `user:pass@`）。

三个使用点：

| 位置 | 原来 | 现在 |
|---|---|---|
| 响应日志的 `action_params["params"]` | URL 原样 | `redact_url_for_log(...)`（在 `redact_action_params` 里按「值像 URL」判定） |
| 应用日志「Webhook sent to …」 | URL 原样 | 脱敏 |
| 被安全校验拒绝时的**结果**里的 `url` 字段 | URL 原样 | 脱敏 |

> 第三处容易漏：拒绝路径**根本没发请求**，但 URL 照样进了
> `action_result` → 一样落进审计。

#### 9.63.4 守卫（14 条，`tests/test_response_audit_secret_redaction.py`）

| 组 | 例数 | 作用 |
|---|---|---|
| `TestTheAuditDoesNotLeakTheSecret` | 6 | 4 种「URL 内嵌密钥」形态（企业微信查询串 / 钉钉查询串 / Slack 路径段 / **userinfo**）脱敏后不得含密钥；**端到端**：审计行里不得含密钥；查询串整体丢弃 |
| `TestTheLogsDoNotLeakTheSecret` | 2 | 发送成功那行日志、被拒绝那行日志与**结果**里都不得含密钥 |
| `TestTheCorrelationIsPreserved` | 3 | 同一 URL 的脱敏结果**稳定**；不同 URL 的结果**可区分**；**主机仍可见**（别把审计变成一串 `***`） |
| `TestTheOtherParamsAreNotOverRedacted` | 3 | 非 URL 的参数照旧可见；敏感键仍被 `***`；普通字符串不被改形状 |

#### 9.63.5 注入验红（3 处，逐条点名）

| 注入 | 红掉的用例 |
|---|---|
| Z1 审计里的 URL 不再脱敏 | `test_the_audit_row_has_no_secret` |
| Z2 发送成功那行日志不再脱敏 | `test_the_send_log_has_no_secret` |
| Z3 被拒绝时结果里的 URL 不再脱敏 | `test_the_rejection_log_has_no_secret` |

三处都红了，红的都是**对应性质自己的那条用例**；还原后 sha256 一致。

#### 9.63.5.1 ⚠ 本节**改了自己上一轮的两条断言** —— 契约本身是错的

§9.61 的守卫里有两条断言要求「响应日志 / 执行结果里出现**原样的**
`webhook_url`」。本节修好后，这两条**当场转红**（第 38 次全量：3 failed，
其中 2 条就是它们）。

按惯例先问「该性质在改动之后还应该成立吗」：

* 「审计要能回答『这个动作对什么做了什么』」→ **仍然成立** ✅
  （脱敏形态仍含主机 + 路径首段 + 哈希，仍能定位目标）；
* 「审计里必须出现**原样的** webhook_url」→ **不再成立**，而且
  **它本身就是要修的缺陷** ❌ —— 那条断言**强制**了「密钥进审计」。

⇒ 所以这不是「把断言改松以求变绿」，而是**把契约换成更强的形式**：

```python
# 旧（强制泄漏）：
assert got.get("webhook_url") == params["webhook_url"]
# 新（更强）：
assert recorded, "审计里没有动作的目标"
assert "alerts.example.com" in recorded, "目标认不出来了"
assert secret not in recorded, "密钥落进审计行了"
```

即：既要**看得见目标**，又要**看不见密钥** —— 后者比旧断言**更严**。

> ⚠ **门禁可见性**：这两个文件是本轮**新建**的（未被 git 跟踪），
> 而反弱化门禁 `tools/assert-no-assert-weakening.py` 只比对**已跟踪**文件
> （§9.41 登记的盲区）→ 这次断言变更**门禁看不见**。
> 本轮**不**代为 `git add`（那是仓库状态变更），只把这件事**显式化**。


#### 9.63.6 边界与待决项

* 本轮**没有**改任何动作的执行行为（只改「写进审计/日志的形态」）。
* 本轮**没有**动 `/response/logs` 的角色门槛 → **待决项 46**：
  「响应动作审计要不要提高角色门槛」—— 现在**任何登录用户**都能读，
  而响应日志含 `src_ip` / `threat_info` / 动作参数 / 动作结果；
  提高到 operator/auditor 属**收紧型**（会挡住前端低权限用户的排查视图），
  且要与前端的权限模型一起看 → 不单方面做。
  本轮只把**最敏感的那一项**（URL 里的密钥）从源头去掉。
* 本轮**没有**改 §9.61 的「动作参数进审计」这件事本身 —— 那是**对的**
  （参数只存在于回滚存储里的时代，审计根本答不出「动作对什么做了什么」）。
  本轮把它补成「**参数进审计，但凭据不进**」。

### 9.64 【已修复·本轮新增】URL 提交路径**没有样本指纹** —— 文档 §十.1 明文要求的「用 SHA-256 关联沙箱任务」在**活路径**上未落地

#### 9.64.1 起点：文档 §十.1 的一条明文要求

整改方案 §十.1 写得很具体：

> 使用 SHA-256 对应的真实样本标识关联沙箱任务，持久化 sample_hash、
> 外部 task_id、提交时间、当前状态、最近错误和报告引用。

§十三 的验收行也写着：「零日与聚类：…**任务与样本可以追踪**」。

**照着这条要求去核，发现两半路径的待遇完全不同：**

| 提交方式 | `outcome.sample_hash` | `_by_hash`（可回连） | 落库 `SandboxTask.sample_hash` |
|---|---|---|---|
| **文件**（`submit_file_outcome`） | ✅ 有 | ✅ 有 | ❌（见下） |
| **URL**（`submit_url_outcome`） | ❌ **没有** | ❌ **没有** | ❌ **没有** |

⇒ **文件路径早就修好了**（上一轮：「`sha256` 修复前算了就丢」——那是
`submit_file_outcome` 的事），**URL 路径从头到尾没有指纹**。

而 URL 提交正是**活的**生产入口（`routers/edr_intel.py:206`
`POST /sandbox/submit`）→ 沙箱任务**落库了**，却**回连不到样本**。

更刺眼的是：`SandboxTask.sample_hash` 这一列**建了索引**
（`models.py:716`，`index=True`）—— 显然就是为「按指纹回连」准备的，
而它**永远是空的**。

#### 9.64.2 为什么「只有文件路径有」不是偶然

`submit_file_outcome` 里有这么一行：

```python
sample_hash = sample_hash or hashlib.sha256(bytes(file_bytes)).hexdigest()
```

`submit_url_outcome` 里**没有对应的一行**。也就是说：**指纹这件事
在 URL 路径上从来没被实现过**，不是「后来被改坏的」。

#### 9.64.3 修法

1. `zeroday_detect/sandbox_connector.py::submit_url_outcome`：
   算 `sha256(url.strip().encode("utf-8"))` → 放进 outcome；
   **失败路径同样带**（被 URL 校验拒 / 提交失败 / 拿不到 task_id）——
   否则「失败的提交」在样本维度上彻底不可追（文件路径的既有行为 ✓）。
2. `routers/edr_intel.py::POST /sandbox/submit`：
   改用 `submit_url_outcome()`（旧的 `submit_url()` **只回传 task_id**，
   指纹会在这一步丢掉）→ 把 `sample_hash` 写进 `SandboxTask` 记录
   → 并在响应里回给调用方（运维能直接拿指纹去对账）。

#### 9.64.4 守卫（11 条，`tests/test_sandbox_sample_traceability.py`）

| 组 | 例数 | 作用 |
|---|---|---|
| `TestTheUrlSubmissionCarriesTheHash` | 3 | outcome 必须带 64 位十六进制指纹；**必须等于 URL 的 SHA-256**；同一 URL 稳定、不同 URL 不撞 |
| `TestTheFailurePathsAlsoCarryTheHash` | 3 | 被拒 / 提交失败 / 拿不到 task_id 时**也要**留指纹 |
| `TestTheHashIsLookupable` | 2 | `lookup_by_hash` 能按指纹找回这次提交；`tracked_samples` 计数包含它 |
| `TestTheRecordIsWired` | 2 | **接线**（AST）：落库记录必须带 `sample_hash=`；端点必须用 `submit_url_outcome`（不得有 `submit_url(...)` 调用） |
| `TestTheFilePathIsUnaffected` | 1 | **反向**：文件路径的指纹行为不受影响 |

#### 9.64.5 注入验红（3 处，逐条点名）

| 注入 | 红掉的用例 |
|---|---|
| Y1 URL 提交的 outcome 不再带样本指纹 | `test_the_outcome_carries_the_sample_hash` + `test_the_hash_is_the_sha256_of_the_url` + `test_the_hash_is_stable_and_distinct` + `test_lookup_by_hash_finds_the_submission` + `test_tracked_samples_counts_it` |
| Y2 落库记录不再写 `sample_hash` | `test_the_router_writes_the_sample_hash` |
| Y3 端点回到 `submit_url()`（指纹会丢） | `test_the_router_uses_the_outcome_api` |

三处都红了，红的都是**对应性质自己的那条用例**；还原后 sha256 一致。

#### 9.64.6 自曝两处

1. **判据第一版**用正则找 `submit_url(` —— 结果它**匹配到了我自己
   写在注释里的那句话**（「旧的 submit_url() 只回传 task_id」）→ 假红。
   > 这正是「文本型判据要克制：说明性注释里合法引用旧话是文档、不是缺陷」
   > 那条的又一次实例。已改成 **AST** 判定：正则不认识注释，AST 认识。

2. **我 §9.64 的改动打破了两条既有的 strict xfail 前提守卫**
   （`test_sandbox_result_retrieval_gap.py`）：
   * `test_scanner_finds_both_bare_and_attribute_calls` —— 它的**例子**
     写的是 `sandbox.submit_url(...)`，而端点已换成 `submit_url_outcome(...)`
     → 前提守卫**假红**；
   * `test_submit_half_is_wired_so_the_gap_is_precise` —— 符号集里没有
     `submit_url_outcome` → 「写入半边有入口」这个**前提**被判成不成立。

   ⇒ 按守卫自己的提示（「缺口形态变了，本文件的登记需要改写」）更新：
   * `SUBMIT_SYMBOLS` **两种接法都认**（`submit_url` + `submit_url_outcome`）
     → 前提守卫不再因一次无关的接线升级而误判；
   * 例子改成当前真实接线，并注明「若端点又换了接法，请同步本文件与
     验收报告 §9.14/§9.64」。

   ⚠ **缺口本身没变**：strict xfail 仍是 xfail（回取半边仍零调用）✓，
   变的只是「写入半边用哪个 API 接入」这一**形态**。
   反弱化门禁对本文件的改动**无告警**（`REPLACED=16` 未变 —— 改的是
   符号集与示例，不是断言强度）。

#### 9.64.7 边界与待决项

* 本轮**没有**碰沙箱的「结果回取半边」与「结果写回 `SandboxTask`」——
  那两半**已由 strict xfail 守卫登记**（§7.1.9 / §9.14：谁负责轮询、
  凭据怎么传、失败重试与超时怎么落，属**设计决策**）。
  ⇒ 本轮只补上「**任务 ↔ 样本**」这一半：任务记录现在**带指纹**了，
  等「结果写回」那半落地时，指纹就是天然的关联键。
* 本轮**没有**动沙箱的自动提交路径（`auto_submit_check` / `auto_submit_outcome`
  **无生产调用方** → 休眠能力，登记为否定结论）。
* **待决项 47**：「**同一样本**的判定口径」——
  本轮用 URL **原样**的 SHA-256（简单、可复现、与文件路径的
  「字节的 SHA-256」同构），但同一 URL 的大小写差异、尾斜杠、默认端口
  都会得到**不同**指纹 → 去重提示会漏。
  要不要改成**规范化后**（大小写/尾斜杠/默认端口归一）再算？
  规范化会让指纹**不再等于**「提交内容的原样摘要」，两者取舍不同 →
  属**业务定义**，不单方面做。
* 本轮**没有**改沙箱的 URL 安全边界（§五.2 那套）—— 那是 §9.21/§9.22 的活。

### 9.65 【已修复·本轮新增】反弱化门禁的**覆盖盲区**：123 个未跟踪测试文件、3942 条断言全在射程之外 —— 现在「断言一改就必须被看见」

#### 9.65.1 起点：整改方案 §十三「全量回归」行的后半句

§十三 那一行的验收标准是：

> 全量测试通过，**并且原有测试没有通过删除断言或放宽安全要求来人为变绿**。

前半句任何 CI 都能自动判；后半句由 `tools/assert-no-assert-weakening.py`
（§9.26 建的门禁）负责。它做得很扎实：5 类弱化签名、7 个已知答案自检、
按文件（再按函数）归组比对。

**但它的比对来源是 `git diff --name-only <base>` —— 只列已跟踪文件。**

§9.41 已经把这件事登记为「覆盖盲区」并给了处置建议（把新测试文件纳入
git 跟踪），但一直没做。本轮先把**规模**量出来（2026-10-20）：

```
未跟踪测试文件: 123 个
断言总数      : 3942 条
```

⇒ **这些文件里的断言若被削弱，CI 照样绿** —— 而它们恰恰是**本轮新增**的
（§9.26 之后每一轮都在加守卫）。盲区随着工作量**一起变大**。

#### 9.65.2 为什么不直接 `git add`

`git add` 是**仓库状态变更**，§9.41 已经明确「本轮不代你 `git add`」。
但「不代你改仓库状态」不等于「什么都不做」—— 本轮的做法是**不改 git 索引**
也能把盲区关上一半。

#### 9.65.3 做法：断言清单的**基线摘要**

新增 `tools/guard_assert_baseline.json`（**18.9 KB**）：

```json
"backend/tests/test_set_order_determinism.py": {"sha256": "…", "asserts": 34}
```

* 基线记的是**断言清单**的 sha256，**不是整文件**：
  * 注释 / docstring 改动**不触发**复核（断言没变）；
  * 断言**一改**，摘要必变 → 一定会被看见。
* 门禁比对：摘要变了 → 报 `UNTRACKED_CHANGED` 并**判红**（退出码 1），
  提示「人工核对；确认无误后跑 `--update-baseline`」。
* `--update-baseline` 重新生成基线。

**为什么摘要而不是全文**：全文清单要 **220 KB**（3942 条断言），
放进仓库会淹没真实 diff；摘要只要 18.9 KB ✓。

**诚实的边界**（必须写清）：

> 基线只有摘要，**判不出「弱化」，只能报「变了」** ——
> 与已跟踪路径的自动判定**不等价**。
> 但至少这个面**从「不可见」变成「必须被看见」**。

#### 9.65.4 守卫（8 条，`tests/test_assert_weakening_gate_coverage.py`）

| 组 | 例数 | 作用 |
|---|---|---|
| `TestTheGateItself` | 2 | 门禁的**自检**必须通过（否则它给出的任何结论都不可信）；跑一次门禁必须落在 0/1/2 之内（**崩溃不能看起来像通过**） |
| `TestTheBaseline` | 3 | 基线文件存在且格式合法；**每个有断言的未跟踪测试文件都必须在基线里**（新建守卫后本条会红 → 基线必须被**显式**更新，而不是悄悄失效）；当前工作区必须与基线一致 |
| `TestTheChangeDetection` | 3 | **决定性**：断言被改弱**必须**被抓到；只改注释**不得**误报（假阳性会让人忽略这个门禁）；新文件报「未纳入基线」而**不是**「变更」 |

#### 9.65.5 注入验红（2 处，**端到端**跑真门禁）

| 注入 | 期望 | 实测 |
|---|---|---|
| Z1 把一个**未跟踪**守卫文件里的断言改弱（`assert out, …` → `assert True, …`） | 门禁 **rc=1** 且点名该文件 | ✅ rc=1，输出含 `UNTRACKED_CHANGED` |
| Z2 同一文件**只改注释** | 门禁 **rc=0**（不得误报） | ✅ rc=0 |

两处还原后 sha256 一致。

> 这一次验红与以往不同：以往是「把生产代码改坏 → 守卫应变红」，
> 这次是「把**门禁自己的覆盖对象**改坏 → 门禁本身要能察觉」——
> **门禁自己也需要被验红**（它的自检只覆盖分类器，不覆盖覆盖边界）。

#### 9.65.6 边界与待决项

* 本轮**没有**改 git 索引（不 `git add`、不 `git stash`）→ 仓库状态不变 ✓。
* 本轮**没有**把「变更即复核」说成「自动判定弱化」—— 摘要判不出弱化，
  报告与门禁输出都写明了这一点 ✓。
* 本轮**没有**动已跟踪路径的判定逻辑（5 类弱化签名、7 个已知答案自检原样保留）✓。
* **待决项 48**：「新测试文件要不要**纳入 git 跟踪**」——
  这是**彻底解法**（纳入后 `git diff` 就能比对，门禁的自动判定也能覆盖它们），
  属**仓库状态决策**，不单方面做。本轮只做到「变更即复核」这一层。
* 顺带说明：基线文件本身也是**未跟踪**的新文件（`tools/` 下），
  它的变更同样不进 `git diff` ⇒ 它的评审要靠人眼（`git status` 能看见 `??`）。
  一旦这些文件被纳入跟踪，它就会进入常规 diff 评审 ✓。

### 9.66 【已修复·本轮新增】行为检测阈值的「余量恰好 0」：成因是**离散常量与阈值同值**，而原评估器**没施加它自己声明的序约束**

#### 9.66.1 起点：§9.2 的那条纪律，用在 behavior 上

§9.2 修 grounding 时留下一条纪律：

> **「某阈值的余量恰好是 0」在写进结论之前，应先怀疑输入，而不是直接归因于数据集。**

grounding 那次的答案是「夹具污染」（时间锚点越过 24h TTL，freshness −0.10
恰好把最紧的干净样本压到当前阈值上）⇒ 修掉后余量变成 +0.10。

behavior 那边当时记的是：

> behavior 的 confirm / deny 两个阈值上侧余量仍为 0 …… 需要扩真实标注样本才能给出
> 可用的定标区间。

本轮对 behavior 用同一条纪律，得到**第三种**答案 ——
既不是「夹具污染」，也不是「数据集稀疏」。

#### 9.66.2 实测一：维度分是**离散常量**，且阈值与常量**同值**

AST 扫描生产打分函数，得到维度分的常量取值集合：

```
_score_seq    : [0, 0.8, 0.95, 1.0]              （另有 0.02 / 0.35 两个比较常量）
_score_caller : [0.0, 0.55, 0.7, 0.75, 0.8, 0.85, 0.9, 1]
score_params  : [0.01, 0.05, 0.65, 0.7, 0.8, 0.9, 0.95, 1.0]
score_time    : [0.002, 0.08, 0.35, 0.7, 0.85, 1]
合并常量集     = [0.002, 0.01, 0.02, 0.05, 0.08, 0.35, 0.55, 0.65, 0.7,
                  0.75, 0.8, 0.85, 0.9, 0.95, 1.0]
```

**`DEFAULT_CONFIRM = 0.8` 与 `DEFAULT_DENY = 0.95` 都在这个集合里。**

判据是 `max_dim >= t`，而 `max_dim` 只会取那几个常量值 ⇒
**阈值一旦等于某个常量，该常量对应的整类信号就恰好卡在阈值上，
往上挪一丁点就整类失效。**

上界因此有一个**可独立重算的代数式**（实测吻合）：

```
confirm 上界 = min over confirm 族样本的 max(score, max_dim)
              = min(0.8, 0.85, 0.95) = 0.80   ← 由 non_exact_tool_match 钉住
              （该样本 score=0.2 / max_dim=0.8，max_dim 来自
                _score_caller 对 tool_match_method != "exact" 的常量 0.8）
deny    上界 = min over deny 族样本的 max(score, max_dim)
              = min(0.95, 0.95, 1.0) = 0.95   ← 由 new_ip_class_public 钉住
              （max_dim=0.95 来自 score_params 对「基线未见的 IP 类别」的常量 0.95）
```

**⇒「扩样本能不能放宽上界」的实测答案：不能。**

| 加入的同族样本（均与当前实现一致） | confirm 上界 | deny 上界 |
|---|---|---|
| 空（基线） | 0.80 | 0.95 |
| + confirm 族 max_dim=0.90 | 0.80 | 0.95 |
| + confirm 族 max_dim=0.95 | 0.80 | 0.95 |
| + confirm 族 max_dim=1.00 | 0.80 | 0.95 |
| + deny 族 max_dim=0.97 | 0.80 | 0.95 |
| + deny 族 max_dim=1.00 | 0.80 | 0.95 |

上界是 `min`，**加样本只能让 min 更小或不变，永远不会变大**。

⇒ §6.2 那句「需要扩真实标注样本才能给出可用的定标区间」，
**对上侧余量不成立**。扩样本仍然必要，但目的不是「把上界推上去」。

#### 9.66.3 实测二（真缺陷）：「精确可行区间」**没有**施加该工具自己声明的序约束

`sweep_thresholds` 明确声明并**强制执行**了搜索域：

```python
"domain": "warn <= confirm <= deny",
"domain_note": "越过该序关系的组合不参与扫描，也不计入下列投影",
```

它用 `continue` 跳过 confirm < warn 与 deny < confirm 的组合。

但 `exact_conditional_bounds` 这条路径**不施加同一个域** ⇒
它报出的区间里混进了**该工具自己声明为不可搜索**的配置：

| 阈值 | 修复前报出 | 对应三元组 | 越过了 |
|---|---|---|---|
| warn 上界 | 1.0000 | (1.0, 0.8, 0.95) | confirm |
| confirm 下界 | 0.0000 | (0.6, 0.0, 0.95) | warn |
| deny 下界 | 0.0000 | (0.6, 0.8, 0.0) | confirm |

⇒ 报出的「余量」有一部分是**调不出来的**：
运维照着把 warn 调到 0.9，会得到一个 **confirm 低于 warn** 的阈值组合
（而 `sweep_thresholds` 自己说这种组合「语义上讲不通」）。

**修复后**（其余两阈值固定在当前值 0.6 / 0.8 / 0.95）：

```
    warn     当前 0.6000 → [0.0000, 0.8000]   余量 上 +0.2000 / 下 -0.6000
    confirm  当前 0.8000 → [0.6000, 0.8000]   余量 上 +0.0000 / 下 -0.2000
    deny     当前 0.9500 → [0.8000, 0.9500]   余量 上 +0.0000 / 下 -0.1500
```

⚠️ **下界余量的语义变了**：域内下界不是「标定集允许的下界」，
而是「**域**允许的下界」—— 它由 `confirm >= warn` 这条**语义**约束决定，
与样本无关。所以要读作「**不能**调到低于 X，否则语义上讲不通」，
而不是「数据只支持到 X」。这一点已在渲染层与报告里写明。

> **修复过程中我自己踩了一个同类坑，并当场修掉**：
> 施加域约束后，`confirm` 的域内下界一度报成 **0.8** 而非 0.6。
> 原因：域约束的边界（另一个阈值的当前值）**不在断点集里** ——
> 扫描跳过边界、退而报出更窄的区间。
> ⇒ 断点集必须并入 `set(cur)`（域边界）。
> 这与 §9.4/§9.7 的「断点枚举」是同一条纪律：**枚举的分段边界，
> 必须与判定实际变化的边界一致**。
> 注入 Z2 专门钉这一条。

#### 9.66.4 实测三：「可行区间宽」≠「旋钮有用」

区间宽度只保证「标定集仍然全对」，**不**保证「行为真的变了」——
而后者才是运维问「我能调这个旋钮吗」时真正要的答案。

新增量具 `knob_effectiveness()`，在域内区间上逐点重算每条样本的处置档位。
实测（域内区间，各取 401 点）：

| 阈值 | 域内区间 | 改变处置档位的取值点 | 改变 is_anomaly 的取值点 | 结论 |
|---|---|---|---|---|
| warn | [0.0000, 0.8000] | **0** | 1 | 整段无效旋钮（处置档位无变化） |
| confirm | [0.6000, 0.8000] | **0** | 0 | ★ 整段无效旋钮 |
| deny | [0.8000, 0.9500] | **0** | 0 | ★ 整段无效旋钮 |

**三个阈值在各自域内区间上，都不改变任何一条样本的处置档位。**
（三者的 `inert` 实测**全为 True**；warn 与另两个的差别只在于
  `is_anomaly` 在端点 0.0 上还翻了一次 —— 而那不改变任何处置后果。）
原因还是离散常量：样本的 score / max_dim 落在
0.0 / 0.2 / 0.8 / 0.85 / 0.95 / 1.0 这些**固定值**上，
阈值在相邻取值之间移动**不改变任何 `>=` 的结果**。

⇒ **「余量 +0.4000」这类数字不能被读成「有 0.40 的调节空间」。**

⚠️ `inert` 的判据**只认处置档位**，不认 `is_anomaly`：
实测 warn 区间内唯一的 is_anomaly 翻转点在 **warn=0.0** 这个**端点**上
（三条 logged 样本的 is_anomaly 变 True），但它们的 `action` 仍是 `logged`
—— 档位判定在 is_anomaly 为真之后还要过 confirm/deny 门限。
这是**端点假象**：取值点恰在 0.0 边界上，再往前一步就回退。
拿 is_anomaly 充数会把「整段无效旋钮」误判成「有效果」⇒ 注入 Z3 钉这一条。

#### 9.66.5 修复清单

1. **`eval_datasets/evaluate_behavior.py`**
   * 新增 `_within_domain()` / `_feasible_in_domain()`，
     `exact_conditional_bounds` 改用后者 —— **两条路径现在用同一个域**；
   * 断点集并入 `set(cur)`（域边界必须参与分段，见 §9.66.3 的自坑）；
   * 返回值新增 `domain` / `unconstrained_lower` / `unconstrained_upper`
     （+ 各自的 `_closed`），原始值保留供追溯但**不算可运维区间**；
   * 新增 `knob_effectiveness()`（旋钮有效性量具）；
   * 渲染层新增「域约束」声明、「不可运维」标注、
     「下界由域约束决定」的说明、「旋钮有效性」一节；
   * **4 处硬编码的 `0.8` 全部改为引用生产常量**。
2. **`mcp_guard/behavior_detector.py`**（**行为零变更**）
   * 抽出 `STRONG_DIM_THRESHOLD = 0.8`（单维强信号门限）
     与 `SEVERITY_HIGH_SCORE = 0.8`（severity 分档门限）；
   * 两者历史上都是字面量 0.8，数值又与 `DEFAULT_CONFIRM=0.8` 相同 ⇒
     「改 confirm 阈值」看起来像「也改了 strong 门限」，
     而实际上 strong 门限**不跟随任何配置项**。
     **分名命名是为了让这件事看得见，不是为了改行为。**
3. **`tests/test_p3_behavior_calibration.py`** —— **契约改写（2 条）**
   * `test_bounds_are_wider_than_the_grid_projection` →
     `test_bounds_respect_the_declared_domain` +
     `test_unconstrained_values_are_kept_for_traceability` +
     `test_grid_projection_still_differs_from_the_conditional_slice`。
     原断言把「未施加域约束的上界（warn=1.0）」当成正确答案钉住了 ——
     而那是**该工具自己声明为不可搜索**的配置。
     改写后的契约**更强**：不是「精确区间比投影宽」，
     而是「精确区间的每一条边都必须在声明域内」。
   * `test_bounds_are_exact_on_an_offgrid_dataset` 的取值来源改为
     `unconstrained_upper`（0.8034 的鉴别力保留），
     同时**新增**断言「域内上界必须 ≠ 0.8034」⇒ 证明域约束真的生效。
   * `test_endpoints_sit_on_data_breakpoints` 的允许断点集**扩大**一项
     （并入域边界），并写明理由。

> ⚠️ **按 §9.63 的纪律记录**：上面第 3 项属于**契约更正**，不是「把断言改松以求变绿」。
> 被替换掉的旧断言**强制了一个缺陷**（把越域值当正确答案），
> 新断言在**原意图之外**还多了约束（域内性 + 鉴别力仍在）⇒ 更强，不是更松。

#### 9.66.6 守卫（21 条，`tests/test_p3_behavior_threshold_headroom.py`）

| 组 | 例数 | 作用 |
|---|---|---|
| `TestDimensionScoresAreDiscreteConstants` | 3 | 维度分常量集**确实**含 confirm=0.8 / deny=0.95；上界**等于**族内 `min(max(score,max_dim))`（可独立重算的结构不变式）；**加同族样本不能放宽上界** |
| `TestDomainConstraintIsApplied` | 5 | 精确区间每条边都在域内；与 sweep **同一个**域；域边界是断点（confirm 下界 = warn 当前值）；越域值被标为不可运维；**反向证明**：去掉域约束后区间立刻含越域点 |
| `TestKnobEffectiveness` | 3 | 三个阈值在域内区间上**都不改变任何处置档位**；`inert` 只看处置档位（不看 is_anomaly）；有效性建立在**域内**区间上 |
| `TestStrongThresholdHasOneSource` | 5 | 生产导出常量；生产判分处**引用常量而非字面量**；评估器**不得自带一份 0.8**；strong 门限**没有**配置项（缺口登记）；strong **不跟随** confirm 阈值（默认 confirm=0.8 → confirm；调到 0.9 → is_anomaly=True 却 action=logged） |
| `TestRenderStatesTheNewSemantics` | 5 | 渲染声明域约束；标注越域值不可运维；说明下界来自域约束；展示旋钮有效性；**不得**把宽区间说成可用余量 |

另有既有的 `test_p3_behavior_calibration.py` **46 → 48 例**同步
（§9.66 契约改写：1 条拆成 3 条，净增 2 条；断言条数 55 → 55 **未减少**）。

#### 9.66.7 注入验红（8 处，**端到端**跑真守卫）

| 注入 | 期望 | 实测 |
|---|---|---|
| Z1 移除 `exact_conditional_bounds` 的域约束 | 守卫红 | ✅ rc=1，3 条红（域内性 / 域边界 / 越域标注） |
| Z2 断点集漏掉域边界（去掉 `set(cur)`） | 守卫红 | ✅ rc=1，`confirm.lower` 0.8 ≠ 期望 0.6 |
| Z3 `inert` 判据退回「is_anomaly 也算有效」 | 守卫红 | ✅ rc=1，2 条红 |
| Z4 评估器自带一份 strong 门限字面量 0.8 | 守卫红 | ✅ rc=1（AST 扫描命中） |
| Z5 生产侧 strong 门限换回字面量 0.8 | 守卫红 | ✅ rc=1，「单一真源已断」 |
| Z6 旋钮有效性被伪造成「区间宽即有效」 | 守卫红 | ✅ rc=1，`action_changes` 0 → 1 |
| Z7 渲染层删除域约束说明 | 守卫红 | ✅ rc=1 |
| Z8 域内守卫反向（越域也算可行） | 守卫红 | ✅ rc=1，3 条红 |

8/8 全部成功变红；还原后 sha256 逐一复核一致，`INJECTED` 残留 = 0。

> Z4 首次运行**锚点命中 0 次**被脚本拦下（锚点写错，不是守卫失效）——
> 修正锚点后变红。这正是「锚点唯一命中」这条纪律的作用：
> 锚点写错时**宁可不注入**，也不能注入到一个不确定的位置。

#### 9.66.8 边界与待决项

* 本轮**没有**改任何检测行为：维度分公式、权重、阈值默认值、
  `mode` 语义、`escalate_decision` 全部原样 ⇒ 只是**给既有常量命名**
  并**让评估器施加它自己声明的域**。
* 本轮**没有**动 `config.py` 的任何字段（未新增旋钮）。
* 本轮**没有**把「余量为 0」改成「余量为正」—— 上侧余量**仍然是 0**，
  这是**真实的**结构事实（常量与阈值同值）。本轮改的是
  「这个 0 的**成因解释**」与「另外两个阈值报出的越域余量」。
* **待决项 49**：「`strong` 单维门限要不要成为可配置旋钮」——
  实测后果已钉住：把 confirm 阈值调到 0.9 后，单维 0.85 的样本
  `is_anomaly=True` 却 `action=logged`（**记为异常但不做任何处置**）。
  这是「strong 门限与 confirm 阈值各走各的」的直接后果。
  修它有两条路：(a) 让 strong 跟随 confirm；
  (b) 给 strong 单独配一个旋钮。
  **两条都会改变处置语义**（(a) 在 confirm 调低时会**收紧**、
  调高时会**放宽**）⇒ 属行为变更，不单方面做，本轮只把后果钉住并上交。
* 本轮**没有**把「旋钮无效」当成缺陷去修：整段无效是
  **离散常量 + 9 条样本**的必然结果，要它变有效需要**更多样本**或
  **改维度分的连续性**（后者是检测行为变更）⇒ 不在本轮范围。
* **本轮自己制造了一次回归失败，如实登记**（第 44 次全量）：
  我改了未跟踪文件 `test_p3_behavior_calibration.py` 的断言
  （契约改写，条数 55 → **55，未减少**），反弱化门禁按 §9.65 的
  「变更即复核」如实报红（`UNTRACKED_CHANGED`）——
  **这正是那道门禁该做的事**。但我**先跑了全量、后更新基线**，
  于是全量里 `test_assert_weakening_gate_coverage.py` 的 2 条
  （`test_the_baseline_covers_the_untracked_test_files` /
  `test_the_current_tree_matches_the_baseline`）变红。
  ⇒ 复核后单独重跑该文件：8 条全绿 ✓；基线更新后再跑全量：零失败 ✓。
  **教训**：「变更即复核」型门禁要求**先更新基线、再跑全量**，
  顺序反了会得到一次**自伤**的失败 —— 与 §9.63/§9.64 记录的
  「本轮自己的改动造成失败」同族，但成因不同（这次是**顺序**问题）。
* **本轮又更正了 §9.66.4 表格的一处表述**（自己写的）：
  原文把 warn 标成「有效果（仅 is_anomaly）」，但 `inert` 的判据是**处置档位** ——
  warn 的 `inert` 实测为 **True**。准确表述是「**三个阈值的处置档位都整段无效**」，
  warn 的差别只在于 `is_anomaly` 在端点 0.0 上还翻了一次（不改变处置后果）。
  ⇒ 这条更正是**收紧**表述（把「有效果」降为「整段无效」），不是放宽。
* 断言基线同步更新：`tools/guard_assert_baseline.json`
  **125 个未跟踪测试文件 / 19.1 KB**（新增本轮的
  `test_p3_behavior_threshold_headroom.py`），
  LF / 无 BOM / 无 U+FFFD，sha `565cf50fd16b7baa`。
  门禁复核：`REPLACED=16, TEST_REMOVED=2`，**无 WEAKENED / DELETED**，rc=0 ✓。
* **第 45 次全量回归：`2739 passed, 18 skipped, 55 xfailed, 0 failed`**（398.52s）—— **零失败**。
  紧邻的上一轮（第 44 次，403.74s）有 1 条失败：
  `tests/test_case_automation.py::TestAutoDispatch::test_audit_pipeline_path_creates_case`
  是**既有的时序脆弱用例**（已登记，见 memory `async-timing-tests-flake-under-load`）：
  它把 `_audit_pipeline_inner` 替换成 no-op，**根本不执行审计链路的任何代码**，
  失败概率与被测改动无关。判定方法照旧：**单独重跑通过 ✓**、
  **重复跑 12 次失败 2 次（≈17%）** —— 抖动率与已登记的历史数据一致。
  ⇒ **不是本轮回归** ✓。

  > 50 次统计更新：34 次 0 failed、14 次 1 failed、**1 次 2 failed**
  > （第 44 次：基线未更新导致门禁覆盖守卫 2 条红 —— 本轮自伤，已修复）、
  > **1 次 3 failed**（第 38 次）—— 后两项都是**本轮自己的改动造成**的，
  > 已修复复验，报告里如实登记。
  > ⚠️ 另有 2 次 1 failed 是**基线时序**造成的（第 44 次后半程、第 46 次：
  > 都是「先跑全量、后更新基线」）—— **同一个坑连犯两次**，已写入记忆。

### 9.67 【已修复·本轮新增】配置项的 falsy 陷阱：运维把阈值配成 **0**，生产却拿到默认值 —— 而评估器的「当前阈值」与生产**脱钩**

#### 9.67.1 起点：§9.66 顺带牵出的两个「同一件事写了两遍」

§9.66 把「余量 0」的成因查清之后，回头看那条链上的每一环，
发现**同一个阈值在三个地方各写了一份**：

| 位置 | 内容 | 读不读 config |
|---|---|---|
| `config.py` | `tool_signature_warn_threshold: float = 0.6` 等四项声明 | — |
| `mcp_guard/behavior_detector.py` | `getattr(s, "tool_signature_warn_threshold", 0.6) or 0.6` | 读 |
| `eval_datasets/evaluate_behavior.py` | `DEFAULT_WARN = 0.6` / `DEFAULT_CONFIRM = 0.8` / `DEFAULT_DENY = 0.95` | **不读** |

三份的**默认值恰好一致**（0.6 / 0.8 / 0.95），
所以在默认配置下**看不出来** —— 这正是它能活到现在的原因。
一旦运维改了配置，两条裂口立刻显形。

#### 9.67.2 缺陷 1：`X or default` 把**合法的 0** 当成「没配」

四个阈值/样本数都写成这个形态：

```python
return float(getattr(s, "tool_signature_warn_threshold", 0.6) or 0.6) if s else 0.6
```

`or` 的语义是「**falsy 就取右边**」—— 而 `0.0` 正是 falsy。

**实测（2026-10-20）**：

| 配置项 | settings 实际读到 | 生产实际拿到 | |
|---|---|---|---|
| `tool_signature_warn_threshold` | 0.0 | **0.6** | ❌ 0 被吞 |
| `tool_signature_confirm_threshold` | 0.0 | **0.8** | ❌ 0 被吞 |
| `tool_signature_deny_threshold` | 0.0 | **0.95** | ❌ 0 被吞 |
| `tool_signature_min_samples` | 0 | **30** | ❌ 0 被吞 |

⇒ **运维配了 0（语义 = 一切都触发），生产跑的是默认值。**
且**没有任何日志提示** —— 配置改了却看不到效果，且查不出原因。

`0` 对这四个字段是**合法且有意义**的取值，不能被静默吞掉。
正确的兜底条件是「**没配**」（None / 属性不存在），不是「值为 0」。

> **「0」的准确语义（实测，别照字面想）**：
> 探针用「完全落在基线内的正常调用」，四个组合的实测结果是
>
> | warn | confirm | is_anomaly | action |
> |---|---|---|---|
> | 0.6 | 0.8 | False | logged |
> | **0.0** | 0.8 | **True** | logged |
> | 0.6 | **0.0** | False | logged |
> | **0.0** | **0.0** | **True** | **confirm** |
>
> ⇒ `is_anomaly` 由 **warn**（与 strong 门限）决定，**confirm 只在
> is_anomaly 已为真时才起作用**。
> 所以「配 confirm=0」单独用**不会**让一切都被确认；
> 真正的「一切都要确认」是 `warn=0` **且** `confirm=0`。
> **关键点不变**：旧实现把运维配的 0 静默改成默认值 ⇒
> 意图被忽略且**无任何提示**；修复后 0 按字面生效，
> 具体语义由运维自己组合决定。
>
> 非 0 取值**完全不受影响**（实测 0.3 / 0.6 / 0.8 / 0.95 / 1.0 逐个核对 ✓）。

**修法**：抽出共享 helper `_config_number(settings, name, default, caster)`，
用 `is None` 判定「没配」；四个读取方法全部走它（单一真源）。
**行为影响：只影响「配 0」这一种情况**（原来被静默改写成默认，现在按配置生效），
其余取值完全不变。

#### 9.67.3 缺陷 2：评估器的「当前阈值」与生产**脱钩**

`evaluate_behavior.py` 把三个阈值写死成 `DEFAULT_*` 常量，**不读 config**。

**实测**：把 confirm 配成 0.9、warn 配成 0.5、deny 配成 0.97 后：

```
生产实际用的: warn=0.5 confirm=0.9 deny=0.97
评估器扫的:   warn=0.6 confirm=0.8 deny=0.95      ← 旧基线
```

后果有两层：

1. **报告里那张「余量」表整体过期** ——
   运维改过阈值之后，「上侧余量 +0.0000」是相对于**生产并不在用的** 0.8 算的。
2. **更硬的一条**：`_assert_reimplementation_matches`（§4.8 建立的
   「档位重实现必须与真检测器逐条一致」纪律）会**直接抛错**：

   ```
   AssertionError: 档位重实现与真检测器不一致：off_hours_only score=0.1275
   max_dim=0.85 mode=confirm 真实现=logged 重实现=confirm
   ```

   ⇒ 评估器扫的不是生产正在跑的那套阈值。**它要么报错、要么报旧基线的数字**，
   两条都不是运维要的东西。

**修法**：新增 `current_thresholds()` —— 从**生产模块**读当前实际在用的三个阈值
（`BehaviorDetector.warn_threshold()/confirm_threshold()/deny_threshold()`），
评估器里**所有**「当前值」语义一律走它（9 处使用点：
`single_dim_trigger_share` / `normalization_sensitivity` /
`_assert_reimplementation_matches` / `sweep_thresholds.current` /
`exact_conditional_bounds` / `knob_effectiveness`）。

`DEFAULT_WARN/CONFIRM/DENY` **保留**，但语义收窄为「**出厂默认值**」
（标定集所依据的基线），文档里写明它**不是**「生产当前正在用的值」。

**修复后的行为**（实测，运维把 confirm 配成 0.9 时）：

```
warn     当前 0.5 → ★★ 当前值本身不可行，无可行区间可言
confirm  当前 0.9 → ★★ 当前值本身不可行，无可行区间可言
deny     当前 0.97 → ★★ 当前值本身不可行，无可行区间可言
```

⇒ 工具**如实说「当前值不可行」**，而不是印一个来自旧基线的区间。
这在语义上也是对的：标定集的标注是在 0.6/0.8/0.95 下写的，
生产改了阈值之后，标定集与生产**已经不同源** —— 工具必须报出来。

#### 9.67.4 一条更宽的普查：全仓这个形态有多少？

AST 扫描全仓，三个**逐步收窄**的口径（数字可由
`%TEMP%` 里的普查脚本复算）：

| 口径 | 命中 | 说明 |
|---|---|---|
| ① `getattr(X, name, D) or D`（D 为字面量） | **255 处** | 全仓任意对象的这个形态 |
| ② X 是 settings-like **且** name 是 `config.Settings` 的真实字段（共 329 个） | **116 处** | 真正的「读配置项」 |
| ③ ②中数值型**且**字段名表达阈值/上限/速率/时长/次数（0 有业务语义） | **82 处** | 如 `rate_limit_per_minute`、`llm_rate_per_minute`、`audit_max_rounds_deep`、`kafka_retry_max_attempts`、`audit_workers`、`stuck_audit_reap_minutes` … |

> 口径 ① 的数字**随工作区变化**（§9.67 把 behavior 的 4 处 `or` 换成了
> `_config_number`，同时新增了 1 处 helper 内的 `getattr`）⇒ 写 255 是
> **以本轮定稿时的工作区为准**。口径 ②③ 不受此影响（它们按真实配置项算）。

> ⚠️ 口径必须写清，否则数字会被不同扫描方式带偏
> （本轮初稿写的 231 / 120 / 50 是**混了口径**的中间值，已更正）。

**本轮没有全仓改**。理由：

* 这些项里，**配 0 的语义各不相同**（有的 0 = 禁用、有的 0 = 无限、
  有的 0 = 无上限、有的 0 明显无意义）——
  一刀切成 `is None` 会让某些项的 0 从「禁用」变成「生效」，属**行为变更**；
* 而 `X or D` 这个形态本身在**多数**项上是**正确的**兜底
  （路径/密钥/URL 类配置配 0 本就该当没配）。

⇒ 按「收紧型/行为变更不单方面做」的纪律，本轮只修**实测确认后果的那一处**
（behavior 四阈值：0 有明确语义 = 「一切命中」），其余登记为待决项 50。

#### 9.67.5 守卫（19 条，`tests/test_config_zero_threshold_preserved.py`）

| 组 | 例数 | 作用 |
|---|---|---|
| `TestZeroIsNotSwallowed` | 9 | 四个阈值「配 0」时**必须**拿到 0；未配时仍退回默认；兜底判据必须是 `is None` 而非 truthiness；四个读取方法里**不得**再有 `or` 兜底；四个方法都走**同一个** helper（逻辑不分叉） |
| `TestEvaluatorBaselineComesFromProduction` | 6 | 评估器当前阈值 == 生产当前阈值；**改 config 后仍跟随**；评估器**不得**用 `DEFAULT_*` 充当当前值（AST 扫三元组形态）；`sweep.current` 必须是生产当前值；`DEFAULT_*` 的「出厂默认值」语义与 config 声明一致 |
| `TestHonestReportingWhenProductionChanged` | 2 | 生产改阈值致当前点不可行时，**必须**报 `feasible_at_current=False` 而不是 0 宽度区间；渲染**必须**印「★★ 当前值本身不可行」 |

> ⚠️ **写守卫时踩到的坑，已写进文件头**：`config.settings` 是**模块级单例**，
> 而 conftest 有一个 autouse fixture 会在每个用例后**复位全局状态与 settings**。
> ⇒ 想测「不同配置下的行为」**不能**靠 `importlib.reload`
> （reload 出来的对象会被 fixture 复位掉，症状是「单独跑脚本对、
> 在 pytest 里全错」），必须**直接改 settings 对象上的字段**（`monkeypatch.setattr`）。
> 这个坑排查时花了几轮，值得记下来。

#### 9.67.6 注入验红（6 处，**端到端**跑真守卫）

| 注入 | 期望 | 实测 |
|---|---|---|
| Z1 生产阈值读取退回 `or` 兜底（吞掉合法的 0） | 守卫红 | ✅ rc=1，4 条红 |
| Z2 兜底判据从 `is None` 改回 truthiness | 守卫红 | ✅ rc=1 |
| Z3 评估器基线退回硬编码 `DEFAULT_*` | 守卫红 | ✅ rc=1，2 条红 |
| Z4 `current_thresholds()` 改成返回硬编码常量 | 守卫红 | ✅ rc=1，2 条红 |
| Z5 不可行当前值被报成 0 宽度区间（谎报） | 守卫红 | ✅ rc=1 |
| Z6 阈值读取方法不走共享 helper（逻辑分叉） | 守卫红 | ✅ rc=1，2 条红 |

6/6 全部成功变红；还原后 sha256 逐一复核一致，`INJECTED` 残留 = 0。

#### 9.67.7 边界与待决项

* 本轮**没有**改任何检测行为：维度分、权重、`mode` 语义、
  `escalate_decision` 全部原样。
* 本轮**没有**改 `config.py` 的任何字段声明。
* 本轮**没有**动默认阈值（0.6 / 0.8 / 0.95 三处默认值仍一致）。
* 本轮**没有**全仓替换 `X or D` 形态（理由见 §9.67.4）。
* **本轮第二次踩到同一个基线时序坑，如实登记**：
  新增守卫文件 `test_config_zero_threshold_preserved.py` 之后，我**又**是
  先跑全量、后更新基线 ⇒ 全量里
  `test_assert_weakening_gate_coverage.py::test_the_baseline_covers_the_untracked_test_files`
  变红（该文件不在基线里）。
  ⇒ 门禁的 warning 其实**已经点名**了它：
  「另有 **1 个未纳入基线**（新文件）：没有基线可比，其断言变更本门禁判不出来
  …… → 跑 --update-baseline 把它们纳入基线」。
  **这条 warning 就在输出里，只是我先跑了全量。**
  ⇒ 与 §9.66.8 记的是**同一个坑、第二次犯** —— 说明「先更新基线、再跑全量」
  这条纪律需要**流程化**（见下）。
  复核：该文件单独重跑 8 条全绿 ✓；基线更新后再跑全量：零失败 ✓。
* 断言基线同步更新：`tools/guard_assert_baseline.json`
  **126 个未跟踪测试文件**（新增本轮的 `test_config_zero_threshold_preserved.py`），
  LF / 无 BOM / 无 U+FFFD。
  门禁复核：`REPLACED=16, TEST_REMOVED=2`，**无 WEAKENED / DELETED**，rc=0 ✓。
* **第 47 次全量回归：`2758 passed, 18 skipped, 55 xfailed, 0 failed`**（396.59s）—— **零失败**。
  （第 46 次有 1 条失败，是上面记的**基线时序**自伤，不是回归。）
* **第 48 次全量回归：`2767 passed, 18 skipped, 55 xfailed, 0 failed`**（405.30s）—— **零失败**。
  ⇒ 断言基线**先更新**再跑的全量（吸取 §9.66.8 / §9.67.7 两次时序自伤的教训）✓
* **第 50 次全量回归：`2776 passed, 18 skipped, 55 xfailed, 0 failed`**（415.55s）—— **零失败**。
* **待决项 50**：「`getattr(settings, X, D) or D` 这个形态要不要全仓替换」
  —— 全仓 **254 处**该形态；其中读的是**真实配置项**的 **116 处**，
  再收窄到「0 有明确业务语义」的是 **82 处**（见 §9.67.4 的口径表）。
  关键在于**逐项判定「配 0 的语义」**：
  `0 = 禁用` 的项，改成 `is None` 会让它**从禁用变成生效**（行为变更）；
  `0 = 无限制` 的项，改成 `is None` 是修正；
  路径/密钥类项，`or` 兜底**本来就是对的**。
  ⇒ 这需要**逐项过一遍语义**，不是一次机械替换 —— 属需要决策的改动，
  本轮只普查、只修实测确认后果的那一处，其余上交。
* **待决项 49**（§9.66.8 登记的 strong 门限旋钮）**不受本轮影响**。

### 9.68 【已定位·未修复·本轮新增】限流的**一个旋钮管全部命名空间**：配 std 配额 0 会**连带关掉**所有限流，而其中包括 `/api/response/execute` 这类**会改动生产状态**的端点

> ⚠️ **本节的「strict 桶」表述于 §9.69.1 更正**：限流其实有**三个**命名空间（`crit` / `strict` / `std`），那 32 个强制限流前缀**全部**是 `crit`，而配额函数只识别 `strict` ⇒ `crit` 落回 std 的 120/分。

> ⚠️ **本节没有改任何限流行为** —— 两条修法都会**改变限流强度**（收紧），
> 属需要决策的改动（待决项 51）。本轮做的是：把耦合**测出来**、
> 用守卫**钉住当前事实**、并**上交决策**。
> 与 §9.66 / §9.67（那两节是「已修复」）不同 —— 这里**没有代码修复**。

#### 9.68.1 起点：§9.67 的「`X or D` 吞掉合法的 0」要不要全仓推

§9.67 修完 behavior 四阈值后，留了一个尾巴：
「`getattr(settings, X, D) or D` 这个形态要不要全仓替换」——
当时只做了普查（254 / 116 / 82 三档），没有逐处判定**实际后果**。

本轮把这件事做完。

#### 9.68.2 普查与逐处判定

| 口径 | 命中 |
|---|---|
| ① `getattr(X, name, D) or D`（D 为字面量） | **254 处** |
| ② X 是 settings-like **且** name 是 `config.Settings` 的真实字段（329 个） | **116 处** |
| ③ ②中数值型**且**字段名表达阈值/上限/速率/时长/次数 | **82 处** |

**逐处实测后的结论：②③里绝大多数不是缺陷**，理由分三类：

1. **兜底恰好等于 0/空串 ⇒ `or` 恰好无害**（实测）：
   * `llm_rate_per_minute`：兜底 0，配 0 → 实际 0（**0 = 不限流**，运维意图被保留 ✓）
   * `stuck_audit_reap_minutes`：兜底 0，配 0 → 实际 0（**0 = 不回收** ✓）
   * `llm_reasoning_effort` / `database_url` / `dns_sinkhole_ipv4|6`：
     空串是合法的「不指定」，被吞成空串 ✓
2. **属性齐全 ⇒ 兜底分支走不到**（实测）：`settings` 是完整的 pydantic
   `Settings` 实例，**329 个字段全都在**。所以「兜底 ≠ 声明」目前**不是活缺陷**，
   而是**潜在缺陷**（settings 被换成测试替身 / 裁剪过的配置源时才会显形）。
   实测 21 处「兜底 ≠ config 声明」，但正常运行时取不到。
3. **timeout 类**：0 = 不超时 / 无意义。

> ⚠️ **这三类都不是「无需登记」** —— 它们是「**已逐处判定过**」的否定结论。
> 下次有人再看到这 116 处，不需要重新普查。

#### 9.68.3 ★ 真缺陷：豁免条件只由 **std 那个旋钮**决定

`app.py:537`（限流中间件）：

```python
if settings.rate_limit_per_minute <= 0:
    return await call_next(request)      # ← 整体绕过，**含所有命名空间**
```

`http_guards.rate_limit_quota` 的两个命名空间：

| 命名空间 | 配额来源 | 默认 | 覆盖的端点 |
|---|---|---|---|
| `std` | `rate_limit_per_minute` | 120/分 | 普通流量 **+ 32 个 `crit` 端点**（见下） |
| `strict` | `rate_limit_strict_per_minute` | 10/分 | **1 个**端点（`/api/dlq/replay`） |

**⚠️ 本段于 §9.69.1 更正**：`RATE_LIMIT_FORCED` 的 32 个前缀里，
**全部**被判成 `crit` 命名空间（实测逐个跑 `_forced_namespace` 确认），
而 `rate_limit_quota` **只识别 `strict`** ⇒ `crit` 落回 std 的 120/分。
也就是说：**`/api/response/execute` 这类高危动作端点拿到的不是 10/分，而是和普通流量一样的 120/分**。

那 32 个前缀里包括（实测列举）：

```
/api/response/execute      /api/response/rollback     /api/response/clear-cooldowns
/api/firewall/connect       /api/firewall/rollback-all /api/guard/call
/api/guard/calls/flush      /api/logs/ingest           /api/logs/analyze
/api/rules                  /api/learn-loop/run        /api/cad/circuit-breaker/reset
/api/security/review        /api/causal/learn          /api/cep/replay   …
```

**这些是真正会改动生产状态的接口**（下发响应动作、连防火墙、跑审计、
改规则、触发学习闭环）。

**实测（2026-10-20）**：

| 运维配法 | 运维意图 | 实际效果 |
|---|---|---|
| `std=0, strict=10` | **只放开 std** | **全部请求不限流**（所有命名空间被连带绕过） |
| `std=0, strict=0` | 两个都放开 | 全部请求不限流 ✓（但 strict=0 本也被 `or 10` 吞成 10） |
| `std=-1, strict=-1` | 两个都不限流 | 全部请求不限流 ✓（**唯一能用的写法**） |

⇒ **strict 的 10 次/分钟形同虚设**（配额层算出来是 10，但中间件在它之前
就 `return` 了 ⇒ 那行代码根本走不到）。
⇒ 限流强度**下降**，**没有任何日志提示**。

#### 9.68.4 ★ 真缺陷（同一处）：配 `strict=0` 会被 `or 10` 静默改回 10

```python
return int(getattr(settings, "rate_limit_strict_per_minute", 10) or 10)
```

`or 10` 把合法的 0 当成「没配」⇒ **想单独关掉 strict 限流做不到**。

⇒ 合起来：**运维的直觉「0 = 关掉」在限流这两处都不成立**，
而 `config.py` 里这两个字段**既没有 description、声明行也没有注释** ——
运维从配置界面根本无从得知。

#### 9.68.5 为什么本轮不改

两条修法都**改变限流强度**（收紧）：

* **(a)** 豁免条件改成「两个命名空间都 <= 0 才整体放行」
  * ⇒ 配 `std=0` 时 strict 仍受 10 次/分钟保护（**限流强度上升**）
  * ⇒ 副作用：想两个都放开必须显式配 `strict=0`（当前也有效 ✓）
* **(b)** 保持现状，配 `std<=0` 且 `strict>0` 时**告警**
  * ⇒ 不改行为，但要新增日志/告警通道

⇒ 属**收紧型 / 行为变更**，按纪律不单方面做。
本轮只做：把耦合**暴露出来**（守卫钉住当前事实）+ 上交决策（待决项 51）。

#### 9.68.6 守卫（12 条，`tests/test_rate_limit_namespace_coupling.py`）

| 组 | 例数 | 作用 |
|---|---|---|
| `TestTheStrictBucketIsWiredToHighRiskEndpoints` | 1 | 强制限流表**确实**包含 `/api/response/execute` 等会改动生产状态的端点（前提）；强制限流端点数 ≥ 20 |
| `TestTheExemptionIsDrivenByTheStdKnobOnly` | 3 | 豁免条件**确实**只读 std 旋钮（源码级）；豁免行**不含** strict；豁免点在配额取用点**之前** |
| `TestStrictZeroIsSilentlyRewritten` | 2 | 配 strict=0 ⇒ 实际得到 **10**；根因是 `or 10` 这个形态 |
| `TestTheDocumentedWayToDisableRateLimiting` | 1 | 登记「负数」是当前唯一能真正关掉限流的写法（给运维一条**能用的**路径） |
| `TestTheNamespaceTaxonomy` | 3 | 三个命名空间 `crit`/`strict`/`std` 都真实存在；**`crit` 落回 std 的 120/分**（配额函数只识别 `strict`）；`strict`（10/分）**只**覆盖 `/api/dlq/replay` 一个端点 |
| `TestConfigDoesNotDocumentTheSemantics` | 2 | 两个限流字段**没有** description；声明行**也没有**行末注释（互补的两条，因为行末注释不进 pydantic 的 description） |

> ⚠️ **这些断言钉的是「当前事实」，不是「正确行为」。**
> 将来按方案 (a) 或 (b) 修好之后，本文件会**变红** ——
> 那正是「需要更新登记 + 重新评估待决项 51」的信号，不是回归。

#### 9.68.7 注入验红（5 处，**端到端**跑真守卫）

| 注入 | 期望 | 实测 |
|---|---|---|
| Z1 豁免条件同时看两个旋钮（= 耦合已解） | 守卫红 | ✅ rc=1 |
| Z2 strict 配额不再吞 0（`or 10` → `is None` 判定） | 守卫红 | ✅ rc=1，2 条红 |
| Z3 豁免条件里的 std 旋钮被换掉 | 守卫红 | ✅ rc=1，2 条红 |
| Z4 高危端点被移出强制限流表 | 守卫红 | ✅ rc=1 |
| Z5 config 的限流字段补上行末说明 | 守卫红 | ✅ rc=1 |

5/5 全部成功变红；还原后 sha256 逐一复核一致，`INJECTED` 残留 = 0。

> **Z1/Z2 是「往修好的方向注入」** —— 守卫的职责是「当前事实被改了就红」，
> 所以修好时它**应该**红。这不是守卫与修复作对，而是**登记的语义**：
> 本文件登记的是「耦合**存在**」，修好 ⇒ 登记失效 ⇒ 必须更新。
>
> ⚠️ 注入脚本踩到的一个坑，已修：**`app.py` / `config.py` 是 CRLF 文件**，
> 用 LF 锚点替换会**整篇改写行尾**（把 656 个 CRLF 变成 0 个）⇒
> 锚点反而命中 0 次。现在注入脚本按**目标文件原行尾**写回。

#### 9.68.8 边界与待决项

* 本轮**没有**改任何限流行为、任何配置项声明、任何检测逻辑。
* 本轮**没有**动 `app.py` / `http_guards.py` / `config.py`（它们只被**注入**
  用于验红，已按字节还原 + sha256 复核）。
* 本轮**没有**把「116 处 `or D`」全仓改掉 —— 逐处实测后，
  它们要么**恰好无害**、要么**只在 settings 被替换时才显形**（潜在缺陷），
  唯一确认的活缺陷是限流这一处，且其修法**改变限流强度** ⇒ 上交。
* **待决项 51**：「限流的两个命名空间耦合怎么修」
  —— 方案 (a) 收紧豁免条件 / 方案 (b) 保持现状但告警。
  两条都需要你定：**(a) 会让「只放开 std」的运维发现 strict 仍在限流**
  （这其实是他们配 `strict=10` 的本意，但会让「配了 0 却没完全放开」变成常态）；
  **(b) 不改行为，但需要新增告警通道**（限流被静默关掉这件事该让人知道）。
  另可考虑 (c)：给两个命名空间**各自独立**的豁免开关，代价是新增两个配置项。

### 9.69 【已定位·未修复·本轮新增】限流的两个缺陷是**耦合**的 —— 只修一个都会把限流强度推向**错误方向**

#### 9.69.1 起点：§9.68 留下的问题是「能不能拆开修」

§9.68 查出限流这处有**两个**缺陷（都在同一个面上）：

* **A**：`app.py:537` 的豁免条件只看 **std** 那个旋钮
  ⇒ 配 `rate_limit_per_minute=0` 会**连带绕过所有命名空间**。
* **B**：`http_guards.rate_limit_quota` 里的 `or 10`
  ⇒ 配 `rate_limit_strict_per_minute=0` 会被静默改回 10。

§9.68 把两条都登记成待决项 51 的选项。但**没说清它们能不能拆开修** ——
而这恰恰是决策的关键前提。

#### 9.69.2 限流判定的三行结构

```python
if settings.rate_limit_per_minute <= 0:      # L537 豁免（**只看 std**）
    return await call_next(request)
...
limit = _rate_limit_quota(namespace)          # L551 取配额（std / strict 分流）
if len(_rate_limit_store[rate_key]) >= limit: # L552 超限 → 429
```

★ **L537 只看 std 那个旋钮 ⇒ 其它命名空间没有自己的「关掉」通道。**

#### 9.69.3 实测：天真修 B 会造成**平台级阻断**

若只把 B 修好（`or 10` → 「保留 0」），则 `limit=0`，
而 `len(hits) >= 0` **恒真** ⇒ 无论窗口内有没有请求，一律 429。

**实测**（`limit=0` 时）：

| 窗口内已有请求数 | 结果 |
|---|---|
| 0 | ❌ 429 全部拒绝 |
| 1 | ❌ 429 全部拒绝 |
| 5 | ❌ 429 全部拒绝 |

⇒ 走 strict 桶的端点（`/api/dlq/replay`）**全部 429** ——
该端点是「重放死信」的高危写动作，**被平台级阻断**。
（⚠️ §9.69.1 更正：此前这里写的是「strict 桶的 32 个端点」——
  实际那 32 个是 `crit`，落回 std 配额；strict 只覆盖 1 个端点。）

#### 9.69.4 结论：两个缺陷**必须一起**决定

| 只修哪个 | 后果 |
|---|---|
| 只修 B（`or 10` → 保留 0） | strict 桶**全拒**（该端点被平台级阻断）—— 限流强度**反向**上升 |
| 只修 A（豁免同时看两个旋钮） | strict 恢复限流 ✓，但运维**仍无法单独关掉** strict（`or 10` 吞 0）—— 灵活性**不足** |
| 两个一起修 | 语义自洽：`0` 在两层含义统一，`-1` 仍是唯一的「整体关掉」 |

⇒ **只修一个都会把限流强度推向错误方向**（一个是意外全拒，一个是无法单独关闭）。
⇒ 这就是待决项 51 必须**一起**决定、不能拆成两个独立小改动的原因。

#### 9.69.5 顺带查清的一件事：「0」在限流里是**歧义值**

同一个 `0`，在两层上得到**相反**的结论：

| 层 | 位置 | 对 0 的处理 |
|---|---|---|
| 中间件层 | `app.py:537` | `rate_limit_per_minute <= 0` ⇒ **整体放行（不限流）** |
| 配额层 | `http_guards:262` | `or 10` ⇒ **改回 10（限流）** |

⇒ **运维当前唯一能真正「两个都不限流」的写法是负数**
（`rate_limit_per_minute=-1` 且 `rate_limit_strict_per_minute=-1`）：
中间件的 `<= 0` 直接放行，配额层根本走不到。
配 0 则是「std 不限流 + strict 名义 10/分（但被绕过）」。

⇒ 这一条已写进 §9.68 的守卫（`TestTheDocumentedWayToDisableRateLimiting`），
给运维一条**能用的**路径，而不是让他们以为 0 就是「关掉」。

#### 9.69.6 守卫（6 条，`tests/test_rate_limit_decision_coupling.py`）

| 组 | 例数 | 作用 |
|---|---|---|
| `TestTheRateLimitDecisionShape` | 3 | 限流判定的**三步顺序**（豁免 → 取配额 → 比较）不得变；比较是 `>= limit`；**limit=0 ⇒ 恒真**（=全部拒绝，不是不限流） |
| `TestOnlyNegativeValuesDisableRateLimiting` | 2 | **负数**是当前唯一能真正关掉限流的写法；0 在两层上**语义相反**（歧义值） |
| `TestTheHighRiskEndpointsAreStillForced` | 1 | 强制限流表**必须**仍含高危动作端点（前提守卫） |

#### 9.69.7 注入验红（5 处，**端到端**跑真守卫）

| 注入 | 期望 | 实测 |
|---|---|---|
| Z1 限流比较从 `>= limit` 改成 `> limit` | 守卫红 | ✅ rc=1，2 条红 |
| Z2 豁免点被移到取配额之后（顺序颠倒） | 守卫红 | ✅ rc=1 |
| Z3 strict 配额层不再吞 0（`or 10` → 保留 0） | 守卫红 | ✅ rc=1 |
| Z4 高危端点被移出强制限流表 | 守卫红 | ✅ rc=1 |
| Z5 配额比较被换成 `>= max(1, limit)`（0 的语义被改写） | 守卫红 | ✅ rc=1，2 条红 |

5/5 全部成功变红；还原后 sha256 逐一复核一致，`INJECTED` 残留 = 0。

#### 9.69.8 边界与待决项

* 本轮**没有**改任何限流行为、任何配置项、任何检测逻辑。
* 本轮**没有**动 `app.py` / `http_guards.py`（它们只被**注入**用于验红，
  已按字节还原 + sha256 复核）。
* **待决项 51 补充一条约束**（见 §9.68.8 的选项表）：
  **不能拆开修**。只修 `or 10` 会让走 strict 桶的端点全拒（平台级阻断），
  只修豁免条件则运维仍无法单独关掉 strict。
  ⇒ 三个选项 (a)/(b)/(c) 都是**整体**方案，选哪个都请以「两个缺陷一起解决」为前提。

#### 9.69.1 ★ 事实更正：我此前把 `strict` 桶的覆盖**说大了 32 倍**

写完 §9.69 的前三节后，我复查了一遍命名空间本身，
发现**一个此前完全没查的事实**：限流其实有**三个**命名空间，不是两个。

`http_guards.py:158` 的注释写着「namespace 仅允许低基数标签：**crit / strict**」，
而 `RATE_LIMIT_FORCED_NESTED` 里也确实有 `crit`：

```python
RATE_LIMIT_FORCED_NESTED = (
    ("/api/dlq", "dry-run", ("POST",), "crit"),
    ("/api/dlq", "replay",  ("POST",), "strict"),
)
```

**实测（把 `RATE_LIMIT_FORCED` 的 32 个前缀逐个跑 `_forced_namespace`）**：

| 命名空间 | 前缀数 | `rate_limit_quota` 返回 |
|---|---|---|
| `crit` | **32** | **120/分**（落回 std！） |
| `strict` | **1**（`/api/dlq/replay`） | 10/分 |
| std（普通流量） | — | 120/分 |

**⇒ §9.68 / §9.69 前三节写的「strict 桶覆盖 32 个高危端点」是错的。**
那 32 个端点（`/api/response/execute`、`/api/firewall/connect`、`/api/guard/call`、
`/api/logs/ingest`、`/api/rules` …）实际是 **`crit`** 命名空间，
而 `rate_limit_quota` **只识别 `strict`** ⇒ `crit` 落回 std 的 120/分。

#### 9.69.2 这个更正把结论推向**两个方向**

**方向一：不是缺陷，是「命名造成的可发现性缺口」。**

`RATE_LIMIT_FORCED` 的作用（见 `_forced_namespace` 与 `rate_limit_decision` 的注释）是
**「不让这些端点被白名单豁免」**（`强制限流 > 豁免(None) > 全局默认(std)` 的优先级），
**不是**「给它们更低的配额」。

实测印证：32 个 `crit` 前缀**确实**被点名进限流桶、不被白名单豁免 ✓ ——
「点名限流」这件事是做到的。

但命名（`crit` / `strict`）让人以为 `crit` 有更低的配额，
而实际上**「不可逆高危动作」与「普通流量」共用同一个 120/分**。
⇒ 这是**可发现性缺口**，不是行为缺陷 ⇒ 登记，不改。

**方向二：真正被影响的是 `strict` 那个配置项。**

`rate_limit_strict_per_minute`（10/分）实际只覆盖 **1 个**端点：
`/api/dlq/replay`（重放死信，高危写动作）。

⇒ 回到 §9.68 的缺陷 B：配 `strict=0` 被 `or 10` 吞掉
⇒ **运维想让 `/api/dlq/replay` 无限流都做不到**。
而这一个端点恰恰是「重放死信」的高危写动作。

⇒ 也让 §9.68 的缺陷 A（豁免只看 std）**影响面更大**：
配 `std=0` 时，**所有**命名空间（含 32 个 `crit` 高危端点）**一起**失去限流 ——
不是「只影响 strict 桶」，而是**全部**。

#### 9.69.3 三处更正（已落到 §9.68 / §9.69 正文）

| 位置 | 原文（错） | 改为 |
|---|---|---|
| §9.68.3 命名空间表 | strict 覆盖「**32 个**强制限流端点」 | strict 覆盖「**1 个**端点（`/api/dlq/replay`）」；std 覆盖「普通流量 **+ 32 个 `crit` 端点**」 |
| §9.68.3 端点列举 | 「`RATE_LIMIT_FORCED` 的 32 个端点里包括…」 | 加更正块：那 32 个**全部**是 `crit`，落回 120/分 |
| §9.69.3 结论句 | 「strict 桶的 **32 个**端点…全部 429」 | 「走 strict 桶的端点（`/api/dlq/replay`）全部 429」 |

⚠️ **这个更正不影响任何结论的方向**，但影响**影响面的表述**：
「配 std=0 会连带关掉 strict 限流」这句话**方向对**（确实会连带关掉），
只是**范围更大**（不是 1 个端点，是**全部 32 个 crit 高危端点 + 普通流量**）。

#### 9.69.4 守卫补充（6 → 12 条）

`tests/test_rate_limit_namespace_coupling.py` 增补 3 条（`TestTheNamespaceTaxonomy`），把**命名空间的三层结构**钉住：

| 新增例 | 作用 |
|---|---|
| `test_the_three_namespaces_exist` | `crit` / `strict` / `std` 三个标签都真实存在（`RATE_LIMIT_FORCED_NESTED` 里确实有 `crit`） |
| `test_crit_falls_back_to_the_std_quota` | **`crit` 落回 std 的 120/分** —— `rate_limit_quota` 只识别 `strict` |
| `test_the_strict_namespace_covers_exactly_one_endpoint` | `strict`（10/分）**只**覆盖 `/api/dlq/replay` 一个端点 |

⚠️ 这三条钉的是**当前事实**。若将来给 `crit` 配上独立配额（`rate_limit_crit_per_minute`），
它们会**变红** —— 那正是需要更新登记（并重新评估待决项 51）的信号。
