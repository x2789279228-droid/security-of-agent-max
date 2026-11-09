# WAVE3-1-FLINK-DIRECT 2026-10-30 —— Flink 直灌剖面（PERF-2 空缺补齐）

> 注入器：`tools/flink-direct-inject.py`（schema 合法事件直灌 `security-logs-raw`：
> apiKey 白名单内 + 必填 eventType/severity/message + IPv4 + 毫秒时间戳 + 分区轮转）
> 环境：运行中 lite 栈（单 broker + Flink JM/1×TM + 3 作业 RUNNING）
> 命令：6000 条 → `security-logs-raw`，produced 135.9s（**44/s**，acks=all+逐条 send_and_wait，
> 生产者侧上限而非 Flink 上限）
> 红线：全部实测；新发现瓶颈如实登记。

## 1. 核心结论：Flink 主流水线全程跟上，瓶颈在 Python 消费侧

| 层 | 消费组 | 注入窗口结束时 lag | 说明 |
|---|---|---|---|
| raw→validated | `log-validation-job` | **0**（分区 0: 2000/2000, 分区 2: 4000/4000） | LogValidationJob 校验+认证+去重全量跟上 |
| validated→enriched | `anomaly-detection-job` | **3/分区**（瞬态，秒级归零） | 异常评分+CEP 跟上 |
| sigma-hit→聚合 | `sigma-threshold-agg-job` | **0**（两分区 3514/3514, 3385/3385） | Sigma 阈值聚合跟上 |
| **enriched→PG（Python）** | `soc-backend-enriched` | **3544 并持续 6 分钟不动** | **停摆——本剖面的核心新发现** |

**Flink 层吞吐（44/s 持续注入下 lag≈0）不是瓶颈**——这关闭了 PERF-2 的
"Flink 主流水线吞吐本轮未测"空缺：Flink 在该注入速率下实时消化全部 6000 条。

## 2. 新发现（如实登记）：enriched 消费者 Redis 连接池耗尽停摆

- **现象**：初始 2.5 分钟摄入 3,583/6,000（≈24/s 有效含审计），随后
  `soc-backend-enriched` lag 卡 3,544 六分钟不推进；
- **根因**（backend 日志实证）：`redis.exceptions.MaxConnectionsError: Too many
  connections`（redis-py 客户端连接池上限击穿；Redis 服务端 connected_clients=141，
  服务端 maxclients=10000 未到——是**客户端池**配置瓶颈，非服务端）；
  `Task exception was never retrieved` —— 后台任务的池耗尽异常无人接管，
  消费循环静默死亡且监督循环未拉起；
- **恢复验证**：重启 backend 后 lag 3544→2941→1649→838（90s 内 ≈18-27/s 排空速度）；
  重放消息命中**幂等跳过完全生效**（"已存在，跳过重复入库"日志连续；PG
  event_id 唯一性 5,553/5,553 distinct = 零重复）；
- **可观测性注**：A5 批的集群 lag Gauge **正确看见了这次停摆**
  （`[Kafka-Lag] High consumer lag: security-events-enriched: 3491` 告警连续输出）——
  背压复合信号的"看得见"目标在真实故障中验证。

## 3. 账目（对账口径）

| 项 | 值 |
|---|---|
| 注入 → raw | 6,000（eventId 前缀 w31a-，分区 0:2000/1:8/2:4000） |
| rejected / duplicate | 0 / 0（schema 全部合法、无重复注入） |
| enriched topic 总产出 | 6,123 偏移（含历史存量；本批 6,000 条经异常评分富化，`_anomalyScore`/`_anomalyReasons`/traceparent 齐备——事件形态抽验 w31a-005999） |
| sigma-hit（Python 检测→Flink 聚合支线） | 10,873 偏移（含历史）；alerts topic +753 |
| PG 落库（w31a 前缀） | **5,553 / 6,000**（重启排空前；剩余 838 条处于消费者排空/幂等跳过区间——重启后日志显示持续跳过处理中，非丢失：enriched topic 保留 5 天可重放） |

## 4. 后续动作（登记）

1. **Redis 客户端池扩容/复用**（排查 sliding_window/llm_cache/distributed_lock 多客户端
   实例化点，收敛为共享池或提高 max_connections）——新登记 P1；
2. 消费循环监督：`Task exception was never retrieved` 说明某异步任务异常路径未接入
   重启监督（kafka_consumer 重试循环的一个分支缺口）——与 PERF-2 §4 已知断点合并追踪；
3. Flink 层更高压力（>44/s 需并行生产者/linger 调优）留下一轮——本剖面生产者侧已饱和。

## 5. 复现

```bash
MSYS_NO_PATHCONV=1 docker run --rm --network soc_default \
  -v "<repo>/tools/flink-direct-inject.py:/inject.py:ro" \
  soc-backend:latest python /inject.py 6000 w31a
# 逐组 lag: docker exec soc-kafka /usr/bin/kafka-consumer-groups \
#   --bootstrap-server localhost:9092 --describe --group <log-validation-job|anomaly-detection-job|sigma-threshold-agg-job|soc-backend-enriched>
```

---

## 6. P1 修复验证（2026-10-30 深夜追加）

### 修复内容（`tests/test_redis_pool_w31.py` 4 项单测钉住）

| 修复 | 位置 | 内容 |
|---|---|---|
| A. 池扩容 | `config.py` 新增 `redis_pool_max_connections=500`；`sliding_window.RedisBackend.connect` 与 `temporal/worker.py` 两处 `from_url` 显式传入（此前吃 redis-py 默认 **100**） | 单测：from_url 捕获参数断言 max_connections=settings 值 + socket_timeout=None 语义保留 |
| B. 异常回收 | `event_store._publish_invalidate` 的裸 `create_task` 挂 `_on_invalidate_done` done 回调（异常记日志+core_metrics 计数） | 单测：广播协程抛错后被消化，不再产生 unretrieved task |

### 重放验证（6000 条新前缀 w31b，同注入器同速率 135.6s @44/s）

| 指标 | 修复前（w31a） | 修复后（w31b） |
|---|---|---|
| MaxConnectionsError | 数百条 + "Task exception was never retrieved" 刷屏 | **0**（25+ 分钟持续负载） |
| 消费者硬停摆 | 是（lag 冻结 6 分钟，需重启恢复） | **否**：loop alive=1、偏移持续单调前进（enriched p0: 790→2071→…）、处理连续（幂等跳过 ~200/min 全部被吸收） |
| 数据安全 | 重启后幂等零重复 | 同样零重复（PG distinct=rows） |

### 修正后的结论（第二层真相，如实）

池耗尽是**放大器**而非唯一根因。修复后仍观察到的慢排空（~3 eps）是
**审计车道背压的设计语义**：`_handle_enriched` 每事件入审计队列 →
audit-queue 积压（本轮 1,333）→ `kafka_fetch_paused` 停拉 + 偏移保留 →
enriched lag 高位缓降。这与 PERF-2 的单 worker 8.4-8.6 eps 属同一吞吐界
（当前被 audit backlog 进一步压低）。**消费者不再死、不丢数据**
（topic 保留 5 天、幂等吸收重放、偏移水位前进），P1 的"静默死亡"缺陷已消除；
吞吐提升属于 A3 多 worker 扩展（已验证 2.08×）与审计车道优化的范畴，不与本 P1 混算。

### 残余发现（诚实边界，非本 P1 范畴）

重放后半段观察：审计车道饱和（backlog ~1,333）时，enriched 消费者的**偏移提交水位
冻结**（消费循环活着、持续幂等重读 ~200/min，但 tracker 不推进 commit）——
即 `offsets_retained` 语义在审计积压下的表现。数据安全不受影响
（幂等吸收重放 + topic 保留 5 天，audit 车道排空后水位自然恢复推进），
但 lag gauge 会持续高位 —— 这与 A5 复合信号语义一致（它看到的是真实积压）。
**后续项**：审计车道排空速率与 worker 扩展的联动（A3 多 worker 已证 2.08×），
以及 `_handle_enriched` 在 audit 满载时的 not-ok 标记是否应区分"拒绝"与"延后"
（当前都导致水位保留）。登记为下一轮观察项，不与已消除的 P1（静默死亡）混算。
