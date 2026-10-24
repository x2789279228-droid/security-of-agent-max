# 生产化 Profile 方案 — 数据接入与流处理（笔记本可跑）

日期：2026-10-24 · 关联：`PROJECT-QUALITY-REVIEW-2026-10-24` 缺口表、`P0-FIXLOG-2026-10-24`

## 0. 设计原则

**机制等价于生产，规模等比缩小（production-shaped, laptop-sized）**。
副本数、堆内存、并行度按笔记本预算压缩；RF/minISR、checkpoint/savepoint、SCRAM+TLS、
disk buffer、指标与告警这些**机制**一项不少。每个生产特性都对应一个可在 5 分钟内
演示的故障演练，而不是 PPT 特性。

## 1. Profile 布局

| Profile | Kafka | 用途 | 内存增量 |
|---|---|---|---|
| **full**（默认，`.env` 的 `COMPOSE_PROFILES=full`） | `kafka-1/2/3` KRaft 集群，RF=3 / minISR=2，每 broker 堆 768MB | 生产机制演示 + 日常开发 | ~2.3GB |
| **lite** | 现有单 broker `kafka`（RF=1） | 8GB 内存机器兜底 | 0 |

切换（两处必须同时改）：

```bash
# .env
COMPOSE_PROFILES=lite
KAFKA_BOOTSTRAP_SERVERS=kafka:9092
```

## 2. Kafka：3-broker KRaft（full）

- **拓扑**：`kafka-1/2/3` 混合节点（broker+controller），单机三进程；controller quorum
  `1@kafka-1:9095,2@kafka-2:9095,3@kafka-3:9095`；CLUSTER_ID 与 lite 一致。
- **生产语义**：业务 topic 由 `kafka-init` 以 `RF=3, min.insync.replicas=2` 创建；
  `__transaction_state RF=3/minISR=2`（Flink EXACTLY_ONCE 前提）；producer 侧 `acks=all`。
- **监听**：`PLAINTEXT:9092`（容器网内管理面）+ `SASL_SSL:9093`（数据面，SCRAM-SHA-512）。
  证书 SAN 覆盖 `kafka-1/2/3/kafka/localhost`（`tools/gen-kafka-certs.sh` 已更新，**需重新生成**）。
- **kafka-init**（full 一次性）：创建 `soc-app`（backend/Flink/exporter 数据面账号）与
  `KAFKA_LOG_SOURCE_USER`（外部日志源），然后跑 `init-kafka-topics.sh`。幂等可重跑。
- **已知取舍**（文档化）：inter-broker 与管理面走容器网内 PLAINTEXT；生产替换为
  SASL_SSL inter-broker + 独立 controller 节点。观测面（kafka_exporter / kafka-ui）与
  管理面同信任边界。

## 3. 客户端安全接线（全链路同一份配置）

- **backend**：`config.py` 新增 `kafka_security_protocol/sasl_*/ssl_*`；
  `kafka_security.aiokafka_security_kwargs()` 是**唯一出口**，5 个连接点
  （主 producer、DLQ producer、3 类 consumer）全部 `**` 展开。
  默认 `PLAINTEXT` 返回 `{}` —— 行为与历史版本完全一致。
- **Flink**：`KafkaConfig.clientSecurityProps()`（env 驱动），三个核心作业的
  全部 `KafkaSource`（`setProperties`）与 `KafkaSink`（`setKafkaProducerConfig`）
  已接线；PEM CA 经 `KAFKA_SSL_CA_FILE` 内联进 `ssl.truststore.type=PEM`，免维护 JKS。
- **演示**：`.env` 置 `KAFKA_SECURITY_PROTOCOL=SASL_SSL` + `KAFKA_APP_PASSWORD` 后
  `docker compose up -d`：无凭据客户端连 9093 被拒（TimeoutException/认证失败），
  backend/Flink 正常收发，抓包 9093 为密文。

## 4. 可观测（把已配置的真正接上）

Prometheus/Grafana 此前已在栈内，本轮补齐 Kafka 侧：

- `kafka-exporter`（full）→ Prometheus job `soc-kafka`。
- **新增告警组**（`config/prometheus/alerts.yml`）：
  - `soc-kafka-cluster`：broker<3、under-replicated>0、ISR<minISR、消费组 lag>5000；
  - `soc-flink-stream`：checkpoint 失败、运行作业<3、重复事件占比>50%。
- **新增面板**（自动 provisioning，开箱即出）：
  - `SOC Kafka 集群`：broker 存活、under-replicated、ISR by topic、消费组 lag、写入速率、log size；
  - `SOC Flink 流处理管道 (SLO)`：作业数、checkpoint 失败/耗时/大小（SLO<30s）、
    作业吞吐、反压/忙碌、data_quality（valid/duplicate/schema_fail/auth_fail）、消费循环存活。

## 5. 容灾演练：`demo/production-drill.sh`

账本 → 混沌 → 对账：

1. 按 batch 灌 `TOTAL_EVENTS` 条（默认 200），每条带唯一 `drill <ts> seq=<n>` 盖章；
2. 并行注入故障：杀 broker-2（RF=3 无感）→ 复活（ISR 自愈）→ 杀 TM-1 → 重启 backend；
3. 按 seq 对账：`missing=0, dupes=0` 才通过（幂等 eventId + EXACTLY_ONCE + checkpoint 恢复共同兜底）。

```bash
bash demo/production-drill.sh                     # 完整演练
SKIP_BROKER=1 TOTAL_EVENTS=50 bash demo/production-drill.sh   # 快速冒烟
```

故障窗口内被容量门禁拒绝的 batch 返回 503/207（not_durable 语义，**接受即持久**），
属预期行为，不进入对账分母。

## 6. 验证记录

- `docker compose config --quiet`：full / lite 两 profile 均通过；
- Flink 15 个源文件 `javac` 编译通过（含安全接线）；
- backend 相关测试套件全绿（含网关/契约守卫）；`ruff`、schema 门禁通过；
- `init-kafka-topics.sh` / `init-kafka-cluster.sh` / `production-drill.sh` `bash -n` 通过。

## 7. 部署/升级注意

1. **重新生成证书**（SAN 新增 kafka-1/2/3）：`bash tools/gen-kafka-certs.sh`；
2. `.env` 增加 `COMPOSE_PROFILES=full`、`KAFKA_BOOTSTRAP_SERVERS`、
   `KAFKA_APP_USER/KAFKA_APP_PASSWORD`（见 `.env.example`）；
3. 首次启动顺序：`docker compose up -d kafka-1 kafka-2 kafka-3` → healthy →
   `kafka-init` 自动建账号/建 topic → 其余服务正常起；
4. **旧数据卷**：lite 的 `kafka_data` 与 full 的 `kafka_data_1/2/3` 互不迁移
   （演示环境可弃；生产用镜像迁移工具，见 Kafka `mirror-maker` 文档）。

## 10. 第二批落地（2026-10-24 续）

### 10.1 Vector 边缘代理（edge profile）

- `config/vector/vector.toml`：HTTP(8686) 接入 → VRL 字段白名单+盖章（产出与
  `_enqueue_ingest` 同构的 wrapper，`body.eventId` 幂等键）→ Kafka(security-events-ingest)；
- **disk buffer**：`buffer.type=disk`（256MB、满时背压、zstd、重试退避上限 60s），
  缓冲卷 `vector_data` 持久化，容器重建不丢；
- 启用：`COMPOSE_PROFILES=full,edge` → `docker compose up -d vector`；
- 演示：`demo/vector-buffer-demo.sh` —— 停全部 broker → 向 Vector 灌 60 条（全 200，
  落盘缓冲；对照组直连网关 503 not_durable）→ 拉起 Kafka → 自动排干 → 按盖章对账全到齐。

### 10.2 Flink JM 高可用（overlay：docker-compose.ha.yml）

- standalone HA：ZooKeeper 选主 + HA 元数据存共享卷 `flink_state`（双 JM 同挂）；
  `high-availability.cluster-id=soc-cluster`，TM 经 ZK 发现在位 JM；
- 用法：`docker compose -f docker-compose.yml -f docker-compose.ha.yml up -d`；
  内存增量 ~1.5GB（ZK ~400MB + 备 JM ~1GB）；
- 演示：杀在位 JM → 备 JM 接管，作业从 HA 存储的最近 checkpoint 恢复；
- 生产路径（K8s Flink Operator + fabric8 HA）在文档中作为已知边界陈述。

### 10.3 零丢失升级脚本（tools/flink-savepoint.sh）

- 对运行中的核心作业逐个经 JM REST 触发 savepoint（flush），轮询完成并输出
  恢复路径；与 P0-6 的 `FLINK_RESTORE_SAVEPOINT` 恢复提交闭环；
- 升级流程：`bash tools/flink-savepoint.sh` → 停旧作业 →
  `FLINK_RESTORE_SAVEPOINT=<路径> ./submit-jobs.sh` → 从 savepoint 续跑，零丢失零重复。

### 10.4 夜间检测回测（.github/workflows/nightly-backtest.yml）

- 每日 UTC 18:00（北京 02:00）+ 手动触发；
- 门禁：`test_p3_detection_calibration.py` 口径守卫（良性样本不携执行动作、
  已登记缺口不回退、待聚合候选不算确定性检出）——规则/引擎回归当晚变红；
- 报告：`evaluate_detection.py --json`（per-rule precision/recall、阈值扫描、
  攻击链检出）存 artifact 90 天 + job summary，支撑"规则变更 PR 附回测结果"。

## 11. 第二轮评审修复（2026-10-24，验收意见落地）

### 必修（§四，8/8）

| # | 问题 | 修复 |
|---|---|---|
| 1 | 默认启动无 Kafka | README 快速启动改为 `docker compose --profile full up -d --build` 并说明 profile 语义 |
| 2 | full 外部 SASL_SSL advertised=容器名 | kafka-N 增加独立 **EXTERNAL** 监听（9094，SASL_SSL），advertised=`${KAFKA_PUBLIC_HOST}:9094`，宿主端口仅 broker-1 映射；管理面 PLAINTEXT 改 127.0.0.1:9095 |
| 3 | EDR/Suricata 漏安全参数 | 两条消费链路补 `**aiokafka_security_kwargs()`；新增 `test_kafka_security_wiring.py`（AST 扫描全部构造点 + 钉住 7 个连接点数量 + PLAINTEXT 零行为/SASL_SSL 凭据断言）——顺带抓出并修掉 `check_hostname`/`CERT_NONE` 设置顺序 bug |
| 4 | ZK healthcheck 坏 | `exec 3<>/dev/tcp/...; printf ruok >&3; cat <&3`（写 socket 再读回） |
| 5 | kafka-init 竞态 | backend / flink-jobmanager / job-submitter 增加 `depends_on: kafka-init: service_completed_successfully (required:false)` |
| 6 | 15 slots 无余量 | `parallelism.default: 3`（9/15 槽，杀任一 TM 剩 10 槽仍可全部重启；HA overlay 同步） |
| 7 | Flink 指标名错 | 从 flink-runtime 1.20.5 jar 核实为 `numRunningJobs`，告警与面板已更正 |
| 8 | alerts 1 分区 | `security-alerts` 分区参数化为 3（`KAFKA_ALERT_PARTITIONS`），与 parallelism 对齐 |

### 残留（§五，除算法重设计/Avro serde 外全处理）

- **sigma 秒级时间戳**：`_agg_payload` 发布前 ×1000；Java `SigmaHit.fromString` 同步归一（harness 测试钉住）
- **窗口分配器测试**：新增 `RuleTimeframeHarness` + `test_sigma_window_assigner.py`（宽度/slide/对齐/覆盖/缺省回退/字符串与毫秒等价/秒归一，7 条真执行断言，本机已跑通）
- **聚合分组键**：候选新增 `group_key`（规则声明的 aggregation.field 取值），keyBy 改 `groupKey#ruleId#ruleVersion` —— 热更新不混窗、非 src_ip 分组语义正确
- **同源告警风暴**：ThresholdWindowFunction 增加事件时间 cooldown（=slide，同 key 一个 slide 只发首条；harness 直调时状态不可用 → fail-open）
- **SIG-007 语义**：规则注释对齐实际行为（单事件=pending，第 2 条处置；拆结论型规则的路径写明）
- **audit_pq 整队 TTL**：删除 ZSET 整体 expire；payload TTL 改 4× 安全网；pop 侧对过期任务**显式 dead_letter("expired")** 后继续取下一个
- **Flink 消费幂等**：enriched/audit-queue 两个 handler 检查 `stored.idempotent`，replay 不重复挂记忆树/发 SSE/重复提交 Audit-LLM
- **sigma 发布可观测**：producer 未启动/发送失败/任务异常全部打点（`record_ingest source=sigma candidate_dropped`）+ warning 日志
- **SourceReputation 死代码**：从拓扑移除（validRate≡1 恒 trusted，输出无下游）
- **sigma-hit schema 绑定**：`sigma_hit.schema.json` 进 catalog 双副本 + fallback map；`publish_sigma_hit` 发送前按契约自检（warning-only，不丢候选）
- **savepoint 脚本**：解析全部改 jq（容器内无 python）
- **drill 账本**：只记 ACK 批次的 seq，被 503/207 拒绝的批次不入对账分母
- **prod overlay**：`kafka` → `kafka-1`，生产保留 EXTERNAL 9094、关闭本机调试端口

### 仍开放（登记为已知边界）

异常评分统计缺陷（Welford 口径/冷启动）、Avro 运行时 serde、logsource 路由、
告警生命周期/确定性 alertKey 折叠、每源 ACL/mTLS、K8s Operator。

## 11. 明确不做的（生产后项）

K8s/Flink Operator（autoscale 与 JM HA 的生产路径）、Kafka 分层存储、Vault secrets、
真实多机、OCSF 全量映射（当前为演示类别映射）。以上在答辩中作为"已知边界"主动陈述。
