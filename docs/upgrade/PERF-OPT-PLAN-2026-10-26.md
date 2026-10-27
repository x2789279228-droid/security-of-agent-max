# 压测后优化/升级计划（PERF-OPT-2026-10-26）· 已对照代码逐项核实

> **依据**：`docs/benchmark/PERF-2026-10-26.md`（第一轮端到端压测 + 故障注入）
> **核实状态**：2026-10-26 三路代码核查完成（异常检测接线 / 回滚与闸门 / 消费管线与扩容条件），
> 本版将初版的假设替换为**已验证根因**（文件:行号可查）。
> **原则**：延续"没有证据不算完成"——每个 Wave 退出必须有可复现数字；
> 容量优化**不得**回退 B1/B2/B3 基线（FP=0/36000、EVASION=1.0、L3 可行区间），
> 回归门禁由 `tests/test_normalization.py` 等守卫钉住。

---

## 0. 核实结论：修正认知的四条（含对 PERF 报告的两处勘误）

1. **异常检测 100% inconclusive 根因（已验证，非假设）**：
   `COLD_START_MIN_SAMPLES=5` 作用在 `len(bl.recent)` = **不同小时桶数**（`anomaly_detector.py:771-773`，
   桶合并 `:649-660`）——15 分钟突发流量任何实体最多 1-2 个桶 → statistical_deviation /
   target_concentration / severity_shift 恒缺席；叠加聚合规则"任一维度 inconclusive ⇒
   整体 inconclusive"（`:1229-1235`）→ **100% 是必然结果，与事件量无关**。
   rarity 其实可判定（8 类威胁轮转，n_types≈8）但救不了整体状态。
   勘误（对 PERF 报告）：报告解读"阈值区间内但真实分布落在区间外"不准确——
   不是分布问题，是**成熟度门槛的计量口径 + 聚合规则**的结构问题。
   H1（实例churn）证伪：全仓生产代码只有模块级单例一处构造；
   H2（字段丢失）机制存在但本压测未触发（event/type/severity/ts 端到端保真）。
2. **回滚断链根因（精确到行）**：`execute_actions` 落库的是**未注入 src_ip 的原始 params**
   （`response_executor.py:347/332`；`:375-376` 的注入发生在本地副本不回写）→
   `rollback_batch` 逆向调 `_unblock_ip()` 缺必填参 TypeError（iptables 从未被触碰）；
   策略批次必含的 `send_alert` 是 `reversible=False` 无 rollback_fn（`response_registry.py:1550-1565`）
   → 被计为 **failed 而非 skipped**。TTL 能删是因为走 `ttl_rollback(rule_id)` 直连
   `ssh_firewall.rollback`，不依赖 rollback_store 的 params。
3. **HTTP p50 2s 主因勘误**：不是报告写的"同步等 broker ack 的在途窗口"，
   而是 **Sigma 检测（42.46ms/事件，裸同步调用）阻塞共享事件循环**——
   12 audit worker + 9 消费循环 + FastAPI 全在一个 asyncio loop（`ingest_pipeline.py:368`
   无 to_thread/run_in_executor）。引擎本身线程安全（每事件私有 `:memory:` 连接 +
   租约锁，`engine.py:708-710`）→ `asyncio.to_thread` 包一层是零风险第一步。
   ack 窗口（`kafka_produce_gate=32` + acks=all）是次级因素。
4. **背压闸门事实**：admission 闸门默认发 **503**（`config.http_overload_status`，
   `capacity.py:387-396` → `note_pressure` → `audit_queue_ratio` = 内存队列/2000）；
   压测观察到的 429×2407 来自 **rate-limit 中间件 crit 桶**，不是 admission 闸门。
   `KAFKA_LAG` Gauge 已存在（`kafka_consumer.py:769-800` 刷新）但**无任何闸门读它**。
   PQ 不对称（enqueue 2242 / dequeue 7）是**结构性**的：PQ 是 Temporal 满载时
   P0/P1 LLM 车道的溢出池（`log_ingestion.py:575-593`），drain 是慢速 scheduler 循环
   （0.2s/批 20，agent 满时 break，`scheduler.py:718-862`）——非计量 bug。

---

## Wave 0 — 正确性缺陷（1-2 人日，与 Wave 1-1/1-2 并行）

| # | 问题 | 方案（已核实） | 退出标准 |
|---|---|---|---|
| 0-1 | 回滚断链 | rollback record 改存**执行时有效 params**（含注入的 src_ip，建议同时存 rule_id 以便直连 `ssh_firewall.rollback(rule_id)`）；不可逆动作按 `reversible` 标志计 **skipped** 不计 failed；containment 记录 `rollback_token` 字段语义澄清（FW-RULE id ≠ batch token） | live 演练 block→batch rollback→`iptables -L` 无残留；send_alert 计 skipped |
| 0-2 | 异常检测 100% inconclusive | **已执行（2026-10-26）**，范围按代码核查结果收敛为安全子集：<br>✅ **B 聚合降级（已落地）**：新增 `ENTITY_EVIDENCE_DIMENSIONS = {statistical_deviation, severity_shift}`（**src 侧**；`target_concentration` 刻意排除——它是 dst 侧维度，算作实体证据会让新攻击者踩着受害者基线拿干净阴性，`test_anomaly_partial_evidence.py` 首触用例钉住）。至少一个 src 实体证据可用 → 按证据判定（not_detected/detected），其余不可判维度逐维披露（reasons `partial_evidence:` 留痕 + error_code `partial_evidence_disclosure`）；全新实体仍整体 inconclusive，q6_3 防误报语义保持。<br>❌ **A 撤销（同义反复陷阱）**：事件数口径成熟度会让单桶实体拿到 σ≡0 的"确定性阴性"——`_window_span_hours` 下限 1.0 使 `hour_total==hourly_mean` 恒真，那是零信息，发阴性即谎报。桶数门槛 5 保持。<br>⛔ **冷启动规则（升级为待决项 41 的正式决策请求）**：q6_3 用 `critical+ATTACK_BRUTEFORCE` 新实体场景，任何冷启动升级规则都会击穿它；短窗首触流量（压测 15 分钟全首触）的 100% inconclusive 是 **q6_3 纪律下的正确输出**，唯一改变路径是 §七.3 冷启动规则（新实体+high/critical+罕见类型→升级），需独立 FP 评估后拍板。<br>✅ **附带修复：fixture 时间炸弹**——标定集锚定 2026-10-19，`_update_baseline` 的 7 天墙钟窗口淘汰在锚点满 7 天后开始掉桶（10-26 实测 P1/P02/P03 分数漂移）。`run_anomaly` 现以 `pinned_clock(锚点+13h)` 钉钟（权威实现上移 evaluate_detection，scale_window 复用），评测从此不随挂钟漂移。 | 单测 `test_anomaly_partial_evidence.py` 3 项全绿；异常全簇 210 项全绿；标定集 8 条 status/分数与钉钟前完全一致 |
| 0-3 | capabilities 诚实性 | `behavior_anomaly` 拆为 verified(合成标定面) / experimental(真实流量)，引 PERF 为证 | 能力页与 PERF 数字一致 |
| 0-4 | 审计通道治理 | 确认"内存队列为主、PQ=溢出池"语义写进文档；`scheduler.py:745-752` agent-full break 条件修/参数化；建立三角闭合计量（入 = 出 + 深度Δ + 死信） | 任一通道三角闭合；指标可作背压信号 |

## Wave 1 — 容量：检测消费侧追平接入侧（3-5 人日）

> **执行状态（2026-10-26）**：1-1/1-2/1-3 已完成；1-4（批量执行）按 profile 结论**降级为可选**——
> 实测建表仅占 2.3%，批量摊薄建表的收益上限 ~2%，远低于预期，CPU 大头在逐规则查询。

| # | 任务 | 要点（已核实的前置条件） | 退出标准 | 实测 |
|---|---|---|---|---|
| 1-1 | Profile 分段计时 | ✅ 完成。`backend/tools/profile_sigma_detect.py`（可复现入册）：**规则 SQL 执行占 97%+**（13.4ms），建表 2.3%，mapping 0.2% —— 定向结论：批量摊薄建表无意义，预筛/削减查询次数才是主杠杆 | 分段表进报告 | ✅ |
| 1-2 | **`asyncio.to_thread` 卸载 Sigma**（已完成） | `ingest_pipeline._run_sigma` 包 `asyncio.to_thread`（引擎每事件私有连接+租约锁，线程安全前提已具备）。解除唯一事件循环被 40ms 级同步段卡死——HTTP p50 与消费 eps 解耦的第一步 | 行为无回归 | ✅ 全量测试绿 |
| 1-3 | 规则预筛索引 | ✅ 完成。编译期按段（UNION ALL 前）提取 presence-必须列存 `meta["req_col_sets"]`；检测期"每段至少缺一个必须列→段死，全段死→跳过"。安全性：正向谓词 NULL 非 TRUE；`IS NULL` 列（如 C-013 的 cs-referer）缺席即命中条件→必须剔除；保守默认=不跳。**等价性**：混合事件集 170 条双跑 0 mismatch（含 sigma_cases/EVASION 向量/CSIC fixture/良性） | eps ≥1.5× | ✅ 压测形态（无 url）**13.05→7.48ms = 1.74×，ceiling 77→134 eps**；混合 url 面 +9% |
| 1-4 | 批量执行 | **降级可选**：建表占 2.3%，摊薄收益上限低；且 1-3 已把无 url 事件的规则面砍到 ~127→更少查询。若压测复测仍不达标再启动 | （视数字） | — |
| 1-5 | 多进程消费 | 前置已就绪：3 分区/key 随机/连续水位/PG 幂等/Redis 认领锁。障碍处置：固定 container_name/端口、17 scheduler 循环无 leader、进程内闸门×N、audit_spill 本地文件、claim fail-open | 2 进程 ≈2×（±15%） | 待压测复测后决定 |
| 1-6 | 回归门禁 | ✅ EVASION 保持率 **1.0**（8 家族全绿）；ABLATION 重生成一致；标定集 L1 P=1.0/FP=0；105 项检测簇测试全绿 | 三基线不回退 | ✅ |

**Profile 数字对比**（150 规则，清洁环境）：修复前黑盒 ~14-15ms（ceiling ~70 eps，压测形态 77 eps）→
预筛后压测形态 7.48ms（**134 eps**）。PERF 压测实测 42.46ms 与清洁值的 ~3× 差距 = 事件循环饿死 +
2 核 CPU 争抢放大（勘误 1 的量化佐证）；to_thread + 预筛 + 下轮压测复测给出真实生产数字。

## Wave 2 — 背压对准（1-2 人日）

| # | 任务 | 要点 | 退出标准 |
|---|---|---|---|
| 2-1 | 复合压力信号 | `capacity.note_pressure` 扩展为 max(内存队列比, f(KAFKA_LAG), PQ 深度)；**`kafka_fetch_paused` 保持绑处理队列**（停拉会加深 lag，不绑 lag） | 重跑 P2：lag 越阈后过载响应（503/429 按 `http_overload_status`）必须出现、恢复后停止 |
| 2-2 | 阈值标定 | 阈值 = Wave 1 实测容量 × 60s 允许积压；守卫钉口径 | 公式与实测依据进文档 |
| 2-3 | 排空 SLO 重定基线 | `积压条数/实测消费速率` 替换"60s 归零" | 新 SLO 进 deployment.md 并实测达标 |
| 2-4 | 8h 内存浸泡 | 232→511 MiB 单点快照不定论 | 8h RSS 增长 <10% 或定性归属 |

## Wave 3 — 架构验证补全（2-3 人日 + 挂机）

| # | 任务 | 要点 | 退出标准 |
|---|---|---|---|
| 3-1 | Flink 直灌剖面 | Kafka→raw 真实过 LogValidationJob→validated→enriched | Flink 层吞吐/延迟数字 |
| 3-2 | 双路径架构决策 | 数据驱动：A 归一走 raw（一致性好、多一跳）vs B 承认 Python 主路径（文档改写） | 决策记录进 docs/upgrade，文档=事实 |
| 3-3 | 补 4 项故障注入 | broker kill（full profile）/ LLM 429 mock / kill api（审批 write-behind，M1 真机验证项）/ 无 key 全链路 | 四项各有恢复数字 |
| 3-4 | 剖面标准化 | 稳态 ≥30 min + 10 min 恢复 | 完整收敛曲线 |
| 3-5 | preflight-check.sh | 固化 8 阻断项修法 + 事务可见性自检（写 1 条→read_committed 读到） | 新环境一键自检 |

## 执行顺序与红线

```
Wave 0 ──→ Wave 2（2-1 依赖 0-4 的对称计量）
  │
  └──→ Wave 1-1/1-2（并行启动）→ 1-3 → 1-4 →（1-5 视数字）→ Wave 3
```

合计 ≈7-12 人日 + 挂机。红线：B1/B2/B3 三基线不回退（守卫+评测双保险）；
"不丢事件"账目闭合口径（入队=落库+幂等吸收）作为每次注入后的对账标准。
