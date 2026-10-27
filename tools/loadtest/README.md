# 第三方压测 · 运行手册（守望 SOC）

攻击机（Kali）→ 平台（`host.docker.internal:8001`）的第三方压测准备与执行。
本目录**不含**已发起的压测；执行入口是 `run-kali-loadtest.ps1`。

---

## 1. 组件现状（2026-10-26 实测）

| 组件 | 状态 | 证据 |
|---|---|---|
| LLM `MiniMax-M2.7` | ✅ 可用 | 裸调 `POST /v1/chat/completions` 200 / 1.33s；平台自身 `summary.llm.chat()` → `1+1=2。` / 4.2s |
| Embedding `embo-01` | ✅ 可用 | 裸调 `POST /v1/embeddings` 200 / 1.04s，1536 维单位向量；平台自身 `embedder.embed()` 0.59s |
| `/api/health` | ✅ | `{"llm":"MiniMax-M2.7","embedding":"embo-01","kafka":"enabled"}` |
| 攻击机 `kali-pentest` | ✅ 可用 | `kalilinux/kali-rolling`；nmap 7.991 / hydra 9.7 / python3 3.14 / curl / jq / socat / nc |
| 攻击机 → 平台 | ✅ 可达 | `host.docker.internal` = 192.168.65.254；`/api/health` 7ms；11 个平台端口 nmap 全 open |
| Flink 作业 | ✅ 3 个 RUNNING | LogValidation / SigmaThresholdAggregation / AnomalyDetection |
| HTTP 接入 → PostgreSQL | ✅ | 冒烟 60 条 100% 落库，p50 109ms / p95 134ms |

---

## 2. 怎么跑

```powershell
# 冒烟：60 条 @ 6/s，先确认"真的入库"
.\run-kali-loadtest.ps1 -Mode smoke -Total 60 -Rate 6

# 复现 9/10 基线：3000 条 @ 2/s（与 attack-perf-large-scale-2026-09-10.md 同口径）
.\run-kali-loadtest.ps1 -Mode baseline

# 加压：10000 条 @ 10/s
.\run-kali-loadtest.ps1 -Mode stress
```

脚本自动完成：现铸 JWT → 确保攻击容器在跑 → 攻击机内注入 → 回查 PG 真实落库 → 出 JSON 报告到
仓库根 `.tmp_kali-loadtest/`（已被 `.gitignore` 的 `.tmp_*` 规则忽略）。

**结论看 `landed_rows`，不看 `sent_ok`。** 请求全 200 但入库 0 行的情况真实发生过（见下）。

---

## 3. 踩过的坑（都已修，但要知道）

### 3.1 `event_id` 前缀撞唯一索引 → 请求全成功、入库 0 行

`security_events.event_id` 上有 `uq_security_events_event_id` 唯一索引。
`tools/attack-large-scale-2026-09-10.py` 原本把 `event_id` 写死成 `large-scale-20260910-{seq}`，
第二次跑同一脚本 ⇒ 全部撞库 ⇒ 幂等去重。

实测：重跑 20 条，**`sent_ok=20, fail=0`，落库 0 行**。

已修：该脚本新增 `--id-prefix`（默认仍是原值，向后兼容），编排器每次运行自动换前缀。

### 3.2 psql 取数读到空行 ⇒ 量具报 0

`psql -t`（对齐模式）在结果后会多吐一行空行。`Select-Object -Last 1` 取到的是那行空行，
`int('')` = 0。**平台入库 60 行，报告写 0 行。**

已修：改用 `-t -A` 且只认纯数字行。

### 3.3 PowerShell 5.1 往原生命令管道写文本会带 BOM

SQL 走 stdin → psql 报 `syntax error at or near '﻿select'`。SQL 必须走 `-c`。

### 3.4 `.ps1` 含中文必须存成 UTF-8 **带 BOM**

否则 PowerShell 5.1 按 ANSI 读 → 语法错误。同仓库 `tools/security-tray.ps1` 带 BOM，
`tools/enable-rerank.ps1` / `tools/install-service.ps1` 没带（同样是潜在雷）。

### 3.5 JWT 会过期

有效期约 2 小时（实测 111 分钟）。编排器每次现铸，**不要**把 token 写进文件长期复用。

---

## 4. 已知堵点（压测前必须知道，否则量出来的是"平台自己崩了"）

> 2026-10-26 更新：§4.1 / §4.2 / §4.3 / §4.5 四个堵点已代码级修复（见各节顶部
> 的 ✅ 说明），下面保留修复前的问题记录作为对照。压测口径以修复后行为为准。

### 4.1 Kafka 生产者运行期未生效 ⇒ 压测打不到 Kafka/Flink 链路

> **✅ 已修复（2026-10-26 审计 #1）**：① 生产者首启失败不再永久失效 ——
> 新增监督循环指数退避重试（`kafka_producer_restart_initial_s/max_s`，与消费者对齐）；
> ② `kafka_enabled=true` 但生产者未就绪时 ingest 返回 **503 `not_durable`**，
> 不再静默回退 200 直写 —— 压测看到非 202 即链路有问题，口径不再失真；
> ③ `/api/health` 的 `kafka` 字段改读生产者存活（`enabled/degraded/disabled`），
> `/api/health/dependencies` 补 kafka 探针；④ compose 的
> `SHARED_MEMORY_KAFKA_BOOTSTRAP` 不再被 `KAFKA_BOOTSTRAP_SERVERS` 遮蔽，
> lite 栈（`kafka:9092`）配置能正确进容器。验收：ingest 202 占比 100% +
> `security-events-ingest` offset 增长。

修复前记录：`POST /api/logs/ingest` 返回 **200 `review_queued`**（同步直写 PG 路径），
而不是 Kafka 模式的 202 `queued`。`security-events-ingest` 三个分区末端 offset 恒为 `0`，
说明**后端一条都没往 Kafka 投**。

⚠️ `/api/health` 仍报 `"kafka":"enabled"` —— 它读的是**配置项** `kafka_enabled`，
不是生产者存活状态。**别拿这个字段当 Kafka 通路的健康信号。**

⇒ 后果：本压测目前量的是 **HTTP → PG 直连路径**，不是 Kafka + Flink 流水线。
与 9/10 报告（202 `queued`）口径不同，横向对比要注明。

### 4.2 消费者分区被 43 条历史事件永久卡死

> **✅ 已修复（2026-10-26 审计 #2）**：① 后端 `security_event/envelope/alert_event`
> 三个 JSON Schema 的可空字段与 Avro 全面对齐放宽（`parentEventId/schemaVersion/
> producer/correlationId/occurredAt/timeSpanMs` → 可空），存量 43 条重启消费者后
> 直接通过校验入库；② Flink `SecurityEvent` 加 `@JsonInclude(NON_NULL)` 不再输出
> null 键（治本 + 消息瘦身，含 2 个序列化单测）；③ `schema_compat` 门禁不再剥
> null —— "Avro 可空 / JSON 纯类型"漂移会被 CI 抓住（本次靠它又抓出 5 个同型漂移）。

问题记录：`security-events-enriched`（offset 0/0/12/14/17）里的 Flink 产出事件带
`"parentEventId": null`，而 `backend/schemas/security_event.schema.json` 要求该字段是 `string`：

```
[Schema] topic=security-events-enriched 事件校验失败 (1 项):
  ['parentEventId']: None is not of type 'string'
```

**契约漂移**：Flink Avro（`flink-jobs/schemas/security-event.avsc:24`）声明的是
`["null","string"] default null`，后端 JSON 契约却写成 `"type": "string"`；
同族可选字段 `srcIp` / `dstIp` / `protocol` / `traceId` 都是可空的，只有它不是。

### 4.3 DLQ 在当前配置下结构性不可用 ⇒ offset 保留 ⇒ 无限重试

> **✅ 已修复（2026-10-26 审计 #3）**：无密钥部署（disabled 态）DLQ 允许
> **明文降级落库** —— 负载以 `PLAIN:` 前缀 JSON 存入 `payload_ciphertext` 列，
> `persisted=True` → offset 正常推进，毒丸可在 DLQ 页审计/重放。密钥**损坏**
> （broken）仍 fail-closed；启用加密后明文 DLQ 记录拒开（`plaintext_bypass`）。
> 结合 #2 的契约修复，存量 43 条不再进 DLQ。加密按决策**暂不启用**
> （启用需 Flink 侧配套加密，否则 plaintext_bypass 拒收全部明文事件）。

问题记录：`.env` 的 `SHARED_MEMORY_FIELD_ENCRYPTION_KEY` **为空** ⇒ 字段加密处于 `disabled`。
`field_cipher.seal_payload()` 在非 `enabled` 态返回 `None` ⇒
`dlq_store.py:314` 返回 `cipher_unavailable` ⇒ DLQ 写不进去 ⇒ **offset 保留**
⇒ 消费者每 30 秒重读同 3 个事件，永不推进（`dlq_records` 表至今 0 行）。

而且**开密钥也救不了**：加密一旦 `enabled`，明文 Flink 事件会被 `plaintext_bypass` 拒绝
（`_decrypt_field` 对明文敏感字段直接抛错）。⇒ 现状下 DLQ 两条路都堵。

### 4.4 Kafka lag 指标对"完全卡死"是瞎的

`soc_kafka_consumer_lag{topic="security-events-enriched"} = 0.0`，
而该 group 的 `CURRENT-OFFSET` 是 `-`（一条都没提交）。
⇒ **lag=0 不代表健康**。判断消费是否推进要看
`kafka-consumer-groups --describe` 的 `CURRENT-OFFSET`，不能只看 Prometheus。

### 4.5 `soc-firewall` 不存在

> **✅ 已修复（2026-10-26 审计 #4）**：① compose 新增 `soc-firewall` service
> （`profile=firewall`，alpine + iptables + sshd，NET_ADMIN，仅内网）——
> `docker compose --profile firewall up -d --build soc-firewall`；
> ② `containment_records` 死表已接线：block_ip 的 mock/live 成功路径落台账
> （dry_run/idempotent_skip 不入账），回滚/解封成功翻 `rolled_back`
> （见 `backend/tests/test_containment_ledger.py`）；
> ③ `.env` 增 `SHARED_MEMORY_FW_SSH_ALLOW_UNKNOWN_HOST=true`（靶场容器无预置
> known_hosts；生产改用 known_hosts 白名单）。live 演示三件套：起容器 +
> `SHARED_MEMORY_EXECUTION_MODE=live` + 上述开关。

问题记录：`.env` 里 `SHARED_MEMORY_FW_SSH_HOST=soc-firewall`，但 `docker-compose.yml` 里**没有这个 service**
（compose 只有 `suricata` / `cape` / `misp` 等）。⇒ `block_ip` 封禁链路无目标，
`containment_records` 至今 0 行。

---

## 5. 授权边界

沿用 `tools/kali_sim_perf.py` 的自述约束：
**不做** hydra 口令爆破 / sqlmap / msf / 任何利用 payload；
只做平台自身端口的 TCP connect 扫描 + 安全日志描述注入。
目标与攻击机均为自建实验环境，符合 `docs/competition-materials/02-合规声明.md`。
