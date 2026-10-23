# M2 证据：不丢事件（第一批）

> 日期：2026-10-21
> 范围：告警消费异常、Temporal 忠实度闸、Redis PQ 丢失可见性、Kafka 事务隔离、Schema 主通道
> 结论级别：**测试级 + 全量回归**；真实 Kafka/Flink 故障演练仍待做。

## 1. 变更

| 问题 | 修复 |
|---|---|
| `_handle_alert` / `_handle_behavior_alert` 吞异常后 offset 仍提交 | 改为 `logger.exception` + `raise`，进入统一重试/DLQ 路径 |
| Temporal 忠实度闸 `except: response_blocked=False` | 抽出 `_faithfulness_gate_fail_closed`，异常 → `response_blocked=True` + `needs_human_review=True` |
| Kafka 消费端默认 `read_uncommitted` | 三个 `AIOKafkaConsumer` 全部 `isolation_level="read_committed"` |
| 生产端重试可能重复 | `enable_idempotence=True` |
| Redis PQ payload 过期后 `pop_highest` 静默返回 None | 新增 `soc_audit_pq_lost_total{reason}`、错误日志；`pop_matching` 同时清理幽灵成员 |
| Python 权威检测主通道无 schema | `security-events-ingest` 加入 catalog + fallback map |
| 案例自动派单 flaky（UPDATE 0 rows） | 测试环境同步执行案例聚合；连跑 20 次稳定；生产仍异步 |
| Redis PQ `zpopmin` + `get` + `del` 非原子 | 新增 Lua 原子弹出（`_POP_LUA`）；fake/旧客户端回退旧路径 |
| spill `drop_event` 截断重写、崩溃全丢 | 改为追加墓碑行 + fsync；超过 1MB 才 compact，compact 用临时文件 + `os.replace` |

## 2. 测试

```bash
cd backend
python -m pytest tests/test_m2_no_silent_loss.py tests/test_audit_spill_tombstone.py -q
# 11 passed
```

覆盖：
- 告警/行为告警响应异常必须冒泡；
- Temporal 忠实度闸异常必须 fail-closed；
- `soc_audit_pq_lost_total` 在 payload 丢失时 +1；
- Redis PQ 原子弹出（Lua）；
- Kafka 消费者 `read_committed`（3 处）；
- 生产端 `enable_idempotence=True`；
- `security-events-ingest` 有真实校验；
- spill 墓碑追加 / 重新入队 / compact / 坏行跳过。

## 3. 全量回归

**2816 passed, 18 skipped, 48 xfailed**，427.05s，退出码 0。

## 4. 尚未验证

1. 真实 Kafka broker 下 `read_committed` + Flink 事务 abort 的端到端验证。
2. 真实 Redis PQ TTL 过期 + `SocAuditPqLost` 告警触发。
3. 真实 Temporal server 的 activity 重试/忠实度闸异常演练。
4. spill 文件“截断即全丢”仍是待修项（`audit_spill.replace_records` 全量重写）。
5. `pop_matching` 的 `zrange` + `get` + `zrem` 仍非原子；需 Lua 化。

## 5. 下一步

1. 用本地 Kafka + Redis + Flink 跑一次“杀消费者 → 重启 → 对账”演练。
2. Redis PQ 改 Lua 原子 pop；spill 改 append-only。
3. 补 `soc_audit_pq_lost_total` 的演示脚本与告警截图。
