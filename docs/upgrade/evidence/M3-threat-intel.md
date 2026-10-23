# M3 证据：威胁情报 IOC 链路接线

> 日期：2026-10-21
> 范围：IOC 落库、情报源拉取、过期过滤、缓存刷新
> 结论级别：**SQLite + fake feed 测试**；真实 MISP/TAXII 拉取仍待演练。

## 1. 缺口与修复

审计结论：`poll_feed` 只返回 list，全仓 `ThreatIoc(...)` 零实例化 →
`ioc_matcher` 永远读空表，IOC 匹配一次都不会命中。

修复：

| 文件 | 变更 |
|---|---|
| `backend/threat_intel/ioc_ingest.py` | **新增**：`store_iocs`（校验/规范化/upsert/默认 30 天过期）+ `poll_feed_and_store` |
| `backend/threat_intel/ioc_matcher.py` | 加载时过滤 `expires_at`（NULL 视为长期有效） |
| `backend/routers/edr_intel.py` | 新增 `POST /api/intel/iocs`、`POST /api/intel/feeds`、`POST /api/intel/feeds/{id}/poll` |
| `backend/scheduler.py` | `intel_enabled=true` 时启动 feed 轮询循环，按各 feed 的 `poll_interval_min` 拉取 |
| `backend/models.py` | 修正 `ThreatIoc.tags` 用 `MutableListJSON`（原 `MutableJSON` 拒绝 list） |
| `backend/tests/test_ioc_ingest.py` | 落库/去重/过期/匹配/端点/轮询 |
| `backend/tests/test_threat_intel_pipeline_gap.py` | strict xfail 转为正向断言：生产写入路径存在 |
| `backend/tests/test_dormant_modules_guard.py` | 移除 `stix_taxii` dormant 登记 |
| `backend/capabilities.yaml` | threat_intel → experimental |

## 2. 设计决策

- **拉取与落库分离**：`poll_feed` 仍是纯函数；落库由调用方显式调用，
  避免把 DB session 塞进网络客户端。
- **upsert 键**：`(ioc_type, ioc_value)`；保留 `first_seen`，刷新 `last_seen`。
- **过期**：默认 30 天；已过期条目直接跳过，不写库；匹配时再次过滤。
- **刷新**：导入/轮询成功后立即 `ioc_matcher.refresh_cache(session)`。

## 3. 测试

```bash
cd backend
python -m pytest tests/test_ioc_ingest.py tests/test_threat_intel_pipeline_gap.py -q
# 10 passed
```

覆盖：
- 插入 + 同批去重；
- upsert 保留 `first_seen`；
- 过期/非法 IOC 不落库；
- 落库后 `IocMatcher.match` 命中；过期 IOC 不命中；
- `POST /api/intel/iocs` 写库并刷新缓存；
- `POST /api/intel/feeds/{id}/poll` 更新 `last_poll_*` 并写 IOC；
- scheduler 只轮询到期的 feed，未到 `poll_interval_min` 不重复拉取。

## 4. 尚未验证

1. 真实 MISP / TAXII 服务的证书、分页、增量 `added_after`。
2. 大规模 IOC（10 万+）的缓存刷新耗时与内存。
3. 并发导入同一 IOC 的 upsert 竞态（当前依赖唯一查询，非数据库唯一约束）。
4. 过期 IOC 的定时清理（当前只在加载时过滤，不删除行）。

## 5. 下一步

1. 给 `threat_iocs` 加 `(ioc_type, ioc_value)` 唯一索引 + `ON CONFLICT`，消除并发竞态。
2. 增加 `POST /intel/feeds/{id}/poll` 的调度器（按 `poll_interval_min`）。
3. 用本地 MISP 容器跑一次真实拉取，补证据。
