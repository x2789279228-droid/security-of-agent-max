# 项目质量解构与分模块评分（2026-10-24）

> 范围：`源代码/` 全仓（后端 13.1 万行 Python / 前端 2.9 万行 / Flink 3.6 千行 Java / 18.7 万行总）
> 方法：① 主审逐 commit 读 diff + 实跑门禁；② 4 路并行只读审查（响应引擎+审计链路 / 检测+接入 / AI编排 / 契约+CI+前端）；③ 主审对 4 条高危结论**独立复现**（探针脚本跑在临时目录，未改任何项目文件）
> 基线：`98d4c44..1396052`（14 commit，479 文件，+115,123/-4,768）+ 工作区未提交改动（35 文件，+606/-626）

---

## 0. 一句话结论

**这个项目已经从「演示级原型」进入「可审计的工程系统」区间，但证据仍然落后于代码。**
工程纪律（门禁自带判别力自检、契约单一权威、能力登记表三档诚实标注）明显高于同类竞赛项目；
但**四条被声称"已修复"的高危问题中有三条未闭环**，另有约 1700 行名义实现（零生产调用方），
且**当前 CI 实为红色**（leak-gate 因文档里一行脱敏示例被判泄露）。

| 维度 | 评分 | 依据摘要 |
|---|---|---|
| 工程纪律与可审计性 | **8.5** | 13 个 CI job 有效 12、恒绿 0；多数门禁自带"已知答案自检"；断言弱化门禁用 AST+分类器而非 grep |
| 功能真实性 | **6.5** | 多智能体编排/RAG/自博弈是**真实现**；但零日链 1492 行、IDS 206 行、后端告警产出侧均零调用方 |
| 生产就绪度 | **5.5** | 4 条高危未闭环；真机演练缺失；契约响应侧全空；schema 三源未收敛 |
| **加权总分** | **7.0 / 10** | 从"能演示"到"敢交付"还差一轮真机闭环 |

---

## 1. 主审实跑结果（不采信文档，独立复现）

| 检查项 | 结果 | 与文档声称是否一致 |
|---|---|---|
| 后端全量 pytest | **2860 passed / 19 skipped / 48 xfailed**，244.8s，exit 0 | ✅ 一致 |
| 覆盖率（`--cov=.`） | **65%**（43,998 语句 / 15,281 覆盖） | ⚠ 文档说"约 64%"，实测 65%；CI 门禁 55%，余量 10pp |
| Schema 兼容门禁 | `python tools/check-schema-compat.py` → exit 0 | ✅ 一致 |
| 前端生产构建 | `tsc + vite` 通过，4.36s | ✅ 一致 |
| OpenAPI 产物 | `openapi.json` 与代码 sha256 一致；**226/226 个 200 响应 schema 为空**，211 paths / 36 component | ✅ 一致（这是硬伤，非误报） |
| 断言弱化门禁 | 12/13 job 有效，**恒绿 0 个**；`grep -c` 修复属实 | ✅ 一致 |
| 19 个 skip | 全部是环境依赖（Maven 18 + testcontainers 1），**不掩盖逻辑缺陷** | ✅ 优于预期 |
| 48 个 xfailed | 当前 **0 个 XPASS**（台账准确）；但 `pytest.ini` 未设 `xfail_strict` | ⚠ 台账准确，但未来会静默腐烂 |
| `.env` 泄露 | 从未被 git 跟踪；历史密钥扫描命中 0；`.dockerignore` 已排除 | ✅ 安全（但工作区 `.env` 含真实 LLM key，zip 分发需注意） |
| `capabilities.yaml` | 16 项能力：**3 verified / 12 experimental / 1 disabled** | ✅ 诚实度罕见地高 |

**关于断言基线 566→10 行**：我核实这是**正确的收缩**，不是门禁失效 —— 基线只覆盖**未跟踪**测试文件（已跟踪的走更弱的 git-diff 路径判定），原 141 条基线文件现已全部被 git 跟踪（235/237），剩 2 个新文件与新基线精确对应。

---

## 2. 分模块评分

| # | 功能模块 | LOC | 评分 | 定性 |
|---|---|---|---|---|
| 1 | 响应引擎（执行安全） | 7,658 | **6.5** | 抽象分层正确，但"预览对所有动作生效"未闭环、幂等有并发缺陷 |
| 2 | 审计与可靠性链路 | ~4,000 | **7.0** | 五层降级有层次，但存在"队列整体过期消失"的致命项 |
| 3 | 检测引擎 | ~11,000 | **7.0** | Sigma/异常/攻击链/因果是**真实现**；零日链、钓鱼测试为空壳 |
| 4 | 接入与事件管道 | ~5,000 | **7.0** | 连续水位提交 + DLQ 先落库再 ack 是同类少见的成熟度 |
| 5 | AI / 多智能体编排 | ~16,000 | **7.0** | **全项目最强的一层**：真编排、真向量检索、真对抗闭环 |
| 6 | 契约与 API 层 | 5,645 | **6.0** | 门禁有效，但响应侧契约完全空转、TS 生成链是死链 |
| 7 | 前端 | 28,720 | **6.0** | 可用但错误处理不透明（18 处空 catch、301 处 any） |
| 8 | Flink 流计算 | 3,776 | **7.0** | 事件时间 + EXACTLY_ONCE 方向对，但 base compose 泄露默认 key |
| 9 | CI/CD 与部署 | — | **7.0** | 门禁密度罕见地高、几乎无假绿；当前 CI 实红 |
| 10 | 测试有效性（横切） | 46,651 | **8.0** | 明显优于同类；能抓到真回归，也有真门禁自检 |

**加权总分 7.0 / 10**（按 LOC 与风险加权）

---

## 3. 我独立复现的 4 条高危缺陷（附探针结论）

### 🔴 H1 — `execution_mode=dry_run` 下 webhook **真实外发**（推翻整改声明）

- `backend/config.py:358` — `execution_mode: str = "dry_run"` 是**默认值**
- `backend/response_engine/response_registry.py:125-153` — `registry.execute()` **无任何模式检查**，直接调 handler
- `backend/response_engine/response_registry.py:1152-1163` — `_send_alert` 只查 `preview_mode` **ContextVar**，**不查 `config.execution_mode`**
- 本次改动的注释写着"预览模式必须对**所有**动作生效"，但 `send_alert` 是注册表里**唯一不过 `_exec`/`_execution_mode()`** 的动作

**实测**（`settings.execution_mode=dry_run`、`preview_mode` 未置位）：
```
preview_mode=False  url=http://192.168.31.10/hook   外发=1 -> mode=webhook / success=True
preview_mode=True   url=http://192.168.31.10/hook   外发=0 -> mode=dry_run
```
⇒ **平台默认安全模式下，告警 webhook 仍会打到外部地址。**
修法：`_send_alert` 首行改用 `_execution_mode()`（含 config 读取），而不是 `preview_mode.get()`。

### 🔴 H2 — `ssh_firewall.rollback` **部分删除失败仍报 success**（三态判定未闭环）

- `backend/response_engine/ssh_firewall.py:508` — `if deleted:` **先于** `:520` 的 `if delete_errors:` 返回
- 即：只要有**任意一条**删除成功，就走 success 分支，**错误被吞**，`errors` 字段不出现

**实测**（探针让 8 条删成功、7 条删失败）：
```
status: success | deleted: 1 | errors字段未出现 | active_rule: revoked
```
⇒ 残留隔离规则 + `_active_rules` 被误标 `revoked`（后续再也无法定位该规则）+ TTL 索引被删 → **永久残留**。
修法：先收集 `delete_errors`，有错误即 `status=error` + 不置 `revoked` + 保留 TTL 索引。

### 🔴 H3 — `cleanup_db` 用 `datetime` 比较 `Float` 列（**本次整改新引入的缺陷**）

- `backend/models.py` — `ApprovalTicketRecord.created_at` 列类型是 **`Float`**
- `backend/response_engine/human_approval.py:224` — 本次改动把 cutoff 从 `time.time()`（float）改成 `datetime.now(timezone.utc) - timedelta(...)`
- 注释写"created_at 是 DateTime 列"——**与模型不符**

**实测**（SQLite）：
```
created_at=1.0        的行 → 被删
created_at=99999999999 的行 → 也被删   （未来时间戳照删）
剩余: ['pending']
```
⇒ SQLite 下**每次启动删光全部终态审批工单**；PG 下直接类型报错 → 生产清理彻底失效。
修法：模型列改 `DateTime(timezone=True)` 并迁移数据，或 cutoff 改回 float 且比较两侧同型。

### 🔴 H4 — `audit_pq` 给**整个 ZSET** 设 TTL → 队列静默整体消失

- `backend/audit_pq.py:115` — `pipe.expire(PQ_KEY, max(60, int(ttl_s) * 2))`

Redis 的 key 级 TTL 作用于**整个 ZSET**，不是单个成员。⇒ 队列约 30 分钟后 ZSET 到期，
**全部未处理审计任务整体消失**：无死信、无 drop 指标、Redis key 过期不触发任何回调。
与「审计永不丢失」的核心主张直接冲突。
修法：去掉 ZSET 级 TTL，改为逐条清理幽灵成员 + 落死信 + 计指标。

### 🟠 H5 — CI leak-gate **当前必红**（独立复核确认）

```
$ git log --all -p | grep -cE 'BEGIN (OPENSSH |RSA |EC |DSA )?PRIVATE KEY'
1
```
命中 1 行，来自 commit `a9f5af1` 的 `docs/AUDIT-2026-10-03-全量功能审计报告.md`——
**是描述审计发现的脱敏示例文字，不是真实密钥**。但 `grep -c` 的修复本身是对的，
现在门禁会因这一行报红。⇒ **「CI 全绿」目前不成立。** 修法：文档行加白名单或改写措辞。

---

## 4. 名义实现清单（代码在、但生产路径不经过）

| 模块 | 规模 | 证据 | 影响 |
|---|---|---|---|
| `zeroday_detect` 后半段 | 1,492 行 | `behavior_analyzer.analyze()` / `variant_cluster.*` 全仓零调用 | 沙箱报告拿到后无人解读，无 clean/suspicious/malicious 判定 |
| `ids_connector` | 206 行 | `suricata_connector.py` 全仓零引用 | Suricata EVE JSON 接入通道**根本不存在** |
| `kafka_producer.publish_alert` | — | 全仓无生产调用方（仅自身+测试） | 后端告警产出侧空转；`security-alerts` 仅 Flink 生产，该函数内的 schema 校验在生产中**从不执行** |
| `event_store` 归档 | — | 声称 parquet 温存 / s3 冷存，实际只有 `mkdir` | 事件长期留存能力不存在 |
| `phishing_guard` 测试 | 2,463 行仅 1 个测试文件 | `assert all(...)` 对空列表真空真、`assert hasattr(...) or ... or v is not None` 恒真 | 7 个钓鱼检测器**零行为断言** |
| `cross_correlator` 横向移动 | — | `:215` 只判 `dst_ip` 非空，**从不比较 `dst_ip == logon.computer_name`**；confidence 硬编码 0.75（可达阻断门槛） | 笛卡尔积误报 |

---

## 5. 本次大改动的真实价值（该给的肯定）

1. **Sigma 契约修复修的是一条真实的生产级断裂。** 改动前 Flink 聚合告警只发 6 个字段，缺 `alertId`/`message`/`anomalyScore`/`timestamp` 这 4 个 schema 必填项 ⇒ 消费端 `kafka_consumer.py:1201` 校验失败直接进 DLQ ⇒ **每一条 Sigma 聚合告警都会被拒收**，整条「Sigma→聚合→`block_ip` 自动封禁」链在生产上从未闭环。这是本轮最有价值的一处修改。
2. **CI 4 项修复经实测全部属实**：PR 用 merge-base / push 用 before SHA（缺基线即 exit 1 拒自比）、api-contract job 补装后端依赖、API smoke 断言登录 200 + 错误密码 401、私钥扫描改 `grep -c`（`grep|head` 在 pipefail 下 SIGPIPE 恒绿）。
3. **一批可靠性整改真闭环**：TTL 回滚失败保留索引让扫描器重试、`distributed_lock` release 用 Lua compare-and-delete、审批先落库再执行（失败 503）+ 停机排空 write-behind、审计 PQ 损坏 payload 单独捕获记死信不再宽 except、死信只有终态才写 `replayed_at`。
4. **`schema_compat.py --register` 前置 `run_gate`** —— 此前注册完全跳过门禁，等于把不兼容 schema 直接发布到 Registry。
5. **工程纪律的三个亮点**（同类竞赛项目少见）：① 断言弱化门禁用 AST + 强弱分类器 + **7 个已知答案自检**，自检不过退出码 2 区分"工具坏了"和"发现弱化"；② `capabilities.yaml` 用 verified/experimental/disabled 三档**诚实标注**，16 项里只有 3 项敢标 verified；③ `test_ci_flink_gate.py` 用合成 JUnit XML 反例证明门禁在"全跳过/套件消失/XML 损坏"时都会红。

---

## 6. 行动优先级

### P0（本周，直接影响"敢不敢交付"）
1. 修 H1：`send_alert` 改走 `_execution_mode()`，补一条"settings=dry_run 时 webhook 不得外发"的**行为**测试。
2. 修 H3：`ApprovalTicketRecord.created_at` 类型与 cutoff 对齐（这是本次改动引入的回归，优先级最高）。
3. 修 H5：leak-gate 文档行白名单 → 让 CI 恢复绿。
4. 修 H2：rollback 先收集错误再判定。

### P1（两周）
5. 修 H4：去掉 PQ 的 ZSET 级 TTL。
6. `_send_alert` / `_exec` 的模式判定收敛为**单一强制点**（当前逐动作手写守卫，天然会漏，webhook 就是漏的那个）。
7. 幂等占位与完成标记**分离**（或 release 用 Lua CAS）—— 当前 `_idempotency_release` 无条件 DELETE，会误删他人写的完成标记。
8. `ioc_ingest` 改 SAVEPOINT/逐行 rollback（当前 PG 事务 aborted 后整批丢失，且 `stats["inserted"]` 统计的是未提交的插入）。

### P2（一个月，对外可信度）
9. **接线或删除** `zeroday_detect` 后半段、`ids_connector`、`publish_alert` —— 1700+ 行名义实现是最大的信任负债。
10. 修 `cross_correlator` 主机比对（把 confidence 从常量改为由匹配强度推导）。
11. `phishing_guard` 补行为断言（现有断言对空列表真空真）。
12. OpenAPI 响应加 `response_model`（226/226 空 schema ⇒ TS 生成链目前只是仪式）；前端改用 `types/api-generated.ts`（当前零引用）。
13. schema 三源收敛：`docker-compose.yml:52` 仍挂载 `init.sql`（29 表）而 ORM 有 52 表，`create_all(checkfirst)` 不修正既有表 ⇒ `init.sql` 对这 29 表实际有优先权。
14. `pytest.ini` 加 `xfail_strict = true`（当前 0 个 XPASS，台账是准的，但缺 XPASS 会让台账静默过期）。
15. 覆盖率门禁从 55% 提到 65%（实测值）+ 关键模块单独下限。

---

## 7. 本次评估未覆盖（诚实声明）

- **Flink JVM 真编译未在本机复现**（环境无 Maven）；`test_sigma_aggregation_action_chain.py` 的 18 个 skip 正是因此产生。CI 有对应 job。
- **未连真实 Kafka / PostgreSQL / Redis**：offset 提交、DLQ 落库、Redis 原子占位、跨重启幂等等路径均为离线静态与单测验证。**Redis 测试替身不支持 `nx`/`eval`/`expire` ⇒ 原子占位、Lua 原子弹出、队列 TTL 这三条最关键的可靠性保证在本地从未被真实验证。**
- 未运行前端 E2E、压测、备份恢复演练。
- 本次评估**全程只读**：未修改、创建或删除任何项目文件；探针脚本写在系统临时目录。
