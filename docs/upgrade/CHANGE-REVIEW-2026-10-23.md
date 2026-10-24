# 改动质量审查（2026-10-23）

> 审查范围：`98d4c44..1396052`（14 个 commit，479 个文件，+115,123 / -4,768）
> 方式：三路并行静态审查（后端运行时 / Flink+契约+CI / 前端+API 契约）＋ 本机门禁实跑
> 结论：**方向正确、质量明显提升；但“测试绿”仍不等于“生产可信”，且有若干门禁是假绿，已在本轮修复。**

## 1. 本机实跑结果

| 门禁 | 结果 |
|---|---|
| 后端全量 pytest | **2860 passed, 19 skipped, 48 xfailed**，215.9s，退出码 0 |
| Schema 门禁 | `check-schema-compat.py` 通过（对齐/兼容/fixtures） |
| 前端生产构建 | `npm run build` 通过（tsc + vite） |
| API 契约产物 | 审查确认 `openapi.json` 与 `app.openapi()` 一致；`api-generated.ts` 与重新生成结果一致 |
| 断言弱化门禁 | 通过（基线已更新，含 2 个未跟踪新测试文件） |
| Flink 编译 | 本机无 Maven，未跑；CI job 存在 |

## 2. 做得好的地方

- **安全默认值**：`execution_mode=dry_run`、注册默认关闭、SSH known_hosts fail-closed、审批 HMAC 不允许回退 `jwt_secret`、空 JWT 密钥返回 503。
- **响应链路**：SafeExecutor 的 grounding/白名单/资产/幂等/post-validate/TTL 链是真实代码，不是装饰；本轮又把 HIGH/CRITICAL 手动直执行收回 403。
- **可靠性方向**：连续水位提交、DLQ 先落库再 ack、PQ 原子弹出、spill 墓碑、Flink EXACTLY_ONCE/事件时间，方向都对。
- **契约工程**：JSON Schema 单一权威、CI 逐字段对齐、fixtures 两侧字节一致、OpenAPI→TS 生成链，是同类项目里少见的完整度。
- **可观测性**：request-id/结构化日志、OTel trace、10 条告警规则、KPI 快照，基础扎实。

## 3. 本轮已修复的高风险问题

| # | 问题 | 修复 |
|---|---|---|
| 1 | 预览模式只覆盖 block/isolate/sinkhole，kill_session/rate_limit/告警 webhook 仍真实执行 | `_exec` 统一传 `mode_override`；containment 三个 adapter 检查 `preview_mode`；`_send_alert` 预览直接返回 |
| 2 | TTL 自动解封把“SSH 全失败”当成功，删除索引 → 规则永久残留 | `ssh_firewall.rollback` 区分查询失败/删除失败/幂等成功；TTL/recover 失败保留索引 |
| 3 | 执行幂等是 check-then-act，并发重复执行；手动解封后 24h 内再攻击被 skip | `SET NX` 原子占位 + 失败释放；解封/恢复清除目标幂等键；duration=0 只做 5 分钟去重 |
| 4 | 审批先返回后异步落库，崩溃后 DB 仍 pending → 二次审批重复执行 | 审批接口 `await persist_ticket` 后才执行；persist 失败 503；停机排空 write-behind |
| 5 | dead-letter replay 对 worker_not_started/overflow/error 也标已重放 | 只有终态才写 `replayed_at`，其余保留重试 |
| 6 | Redis PQ 损坏 payload 被宽 except 吞掉并回退弹出别的任务 | 单独捕获 JSONDecodeError，计数 `payload_corrupt` 并记死信 |
| 7 | ioc_ingest 规范化异常拖垮整批；无唯一约束 | 单条 try/except；`ThreatIoc.tags` 改 MutableList；过期过滤 |
| 8 | distributed_lock release 不校验 token | Lua compare-and-delete；fallback 校验 token |
| 9 | Sigma 聚合告警缺 alertId/message/anomalyScore/timestamp，alertType 不在 schema | Flink job 补齐契约字段；schema/Avro/baseline 增加 `SIGMA_AGGREGATE` |
| 10 | api-contract CI job 未装后端依赖，永远 ModuleNotFound | 增加 `pip install -r backend/requirements.lock` |
| 11 | publish 只依赖 schema-gate，测试红也能发镜像 | 新增 `quality-gate`（pytest + frontend build），publish 依赖它 |
| 12 | PG 集成测试在 async 用例里调 `command.upgrade` → nested event loop | `asyncio.to_thread(command.upgrade, ...)` |
| 13 | 新 Kafka topic（sigma-hit/ingest/behavior-alerts）未创建 | `init-kafka-topics.sh` 补齐并 `set -euo pipefail` |
| 14 | 断言门禁在 push 时用 HEAD 自比，恒绿 | PR 用 merge-base 且缺失即失败；push 用 before SHA；缺失即失败 |
| 15 | leak-gate 用 `grep | head`，pipefail 下 SIGPIPE 误判 | 改 `grep -c` 计数 |
| 16 | API smoke 接受 401 登录失败 | 断言登录 200 + 错误密码 401 |
| 17 | schema `--register` 跳过门禁 | 注册前先跑 `run_gate` |
| 18 | SSE 重连未清 watchdog，interval 累积；cursor_reset 不清 dedup | 重连/重开清 interval；reset 清 `seenKeys` |
| 19 | 能力页错误态下仍显示“暂无数据” | 加 `!error` 条件与 `role="alert"` |
| 20 | Webhook 异常文本带完整 URL/token 落 ResponseLog | 新增 `redact_text_for_log`，错误/结果统一脱敏 |
| 21 | `auto_migrate=False` 的旧数据卷带病启动 | 新增 `assert_schema_current()`，PG 缺表/列直接拒绝启动 |
| 22 | learn_loop/审批清理用例的微秒边界 flake | 测试注入 window_end；cleanup_db 用 datetime 边界并含等号 |

## 4. 仍需处理（按风险排序）

| 风险 | 说明 | 建议 |
|---|---|---|
| **真机演练仍缺** | SSH 封禁/隔离、Redis TTL 跨重启、PG 迁移都只有 fake/单测/SQLite | 用本地 soc-firewall 容器 + 真实 Redis 做一次 10 分钟演练并留证据 |
| **`/metrics` 公开** | `_PUBLIC_PATHS` 含 `/metrics`，8001 对外时暴露内部计数 | 仅私网/本机或 service token；或 nginx 层限制 |
| **迁移遗留重复 event_id** | baseline 的 `CREATE UNIQUE INDEX security_events(event_id)` 在旧数据有重复时会失败 | 迁移前跑一次重复检测/清理脚本 |
| **API 契约只保护路径** | 226/226 个 200 响应 schema 为空；TS 生成物未被 src 引用 | 给关键响应加 model；前端逐步改用 generated 类型 |
| **PG 集成可静默 skip** | 无 Docker 时整文件 skip，CI 未断言“至少跑 N 条” | 加 `--junitxml` + `assert-junit-no-skip.py --min-tests 3` |
| **主 pytest 无 skip 门禁** | 仅 Flink 窗口测试有 JUnit skip 断言 | 主套件加 allow-skip-file + 最小测试数 |
| **Webhook SSRF TOCTOU** | 校验时解析一次，httpx 请求时再解析 | 固定解析结果/连接 IP，或限制出站代理 |
| **audit_worker 事件循环阻塞** | 每个任务成功都同步 `fsync`/compact spill | 放 `asyncio.to_thread`，或改批量/异步写 |
| **distributed_lock token 进程级** | 同进程多个锁共享 token；release 只比较值 | 每次 acquire 生成 token 并存 map |
| **审批“已批准未执行”恢复** | restore 只加载 PENDING；崩溃在 persist 与 execute 之间会漏执行 | 增加 `executed_at` 并在启动时重放未执行 approved |
| **演示默认密钥** | compose 默认 `soc-*-2024` 仍可用于 spoof | 默认 compose 也要求显式注入，或标注“仅演示” |
| **覆盖率门禁 55%** | 实测约 64%，55% 只是地板 | 按 CI 实测值逐月 +2%，并设关键模块下限 |

## 5. 质量评级

| 维度 | 评级 | 依据 |
|---|---|---|
| 架构方向 | **A-** | 响应安全、契约单一权威、可观测性三条主线正确 |
| 安全默认值 | **A-** | 默认 dry_run/注册关闭/SSH fail-closed/审批 HMAC，已明显优于审计前 |
| 可靠性设计 | **B+** | 连续水位/DLQ/PQ/幂等/TTL 都有，但真机演练与部分原子性仍缺 |
| 测试有效性 | **B** | 2860 条全绿，但仍有源码 grep 型测试、skip/xfail 门禁未覆盖主套件 |
| 生产就绪度 | **B-** | 缺真机演练、备份恢复、`/metrics` 收口、旧库迁移预案 |
| 可维护性 | **B** | 大文件仍多（kafka_consumer 2k+、log_ingestion 1.4k），但重复实现已在收敛 |

**总评：从“演示级原型”进入了“可审计的工程系统”区间。** 当前最大的问题不是代码写得差，而是**证据还没有跟上代码**：很多“已实现”仍只有 mock 级证明。下一步应优先补真机演练和 CI 门禁的真实性，而不是继续加功能。
