# 生产就绪度审查报告与加固方案(2026-10-24)

> 审查方式:4 个并行深审(数据管道/审计链路、响应引擎、检测引擎/智能体、API/部署/前端),
> 覆盖 backend 全部模块群、compose 部署、CI、前端结构。本报告为第一轮审查结论与第二轮执行方案,
> 执行后每项均有对应提交与测试佐证。

## 总体评价

工程化程度远超典型学生项目:fail-closed 默认、审计哈希链、DLQ 先落库后 ack、MCP 四层 Guard、
契约/泄漏 CI 门禁等均真实生效。但离生产仍有实质差距,集中在三类问题:

1. **结果上报链路的"失败报成功"缝隙**(桩回退被记成功、SSH stderr 为空时 fail-open);
2. **监督与闸门自身失效**(audit worker 被卡死回收器静默杀光、`await` 同步方法崩溃、哈希链不校验链接);
3. **密钥纪律与默认回退**(git 跟踪文件中的真实口令、compose 默认演示 API key 推翻 fail-closed)。

## P0(必须修复 — 数据丢失/安全漏洞/崩溃)

| # | 位置 | 问题 | 修复方案 |
|---|------|------|---------|
| P0-1 | `backend/audit_worker.py:486` | stuck reaper 取消 job task 后 `CancelledError` 穿透 `_run_job`→`_loop`,worker 协程永久退出且无监督,审计池静默缩到 0 | `_run_job` 内区分内外取消(3.11 `Task.cancelling()`),内部取消转为普通失败;补回归测试 |
| P0-2 | `backend/response_engine/response_registry.py:143,425` | `_stub_fallback` 返回无 `success` 键,`execute()` 只判 `is False` → 桩回退被记为执行成功,策略冷却/审计全部失真 | 桩显式 `success=False`;`execute()` 对 `_stub` 结果判失败 |
| P0-3 | `backend/response_engine/ssh_firewall.py:284` | `_exec` 仅在 `rc!=0 且 stderr 非空` 时抛错 → 命令失败但 stderr 为空被当成功;sudo 密码提示被误判 | 以 `rc!=0` 为准抛错;sudo 改 `-n` 非交互,密码提示立即失败 |
| P0-4 | `backend/agents/agent_cad.py:136` | `await circuit_breaker.record_na(...)`,但 `record_na` 是同步方法 → `await None` 必抛 TypeError,最常见车道(单源告警)整轮审计崩 | 去掉 `await` 调同步方法(测试均为同步调用,保持接口不变) |
| P0-5 | `tools/monitor-2026-09-10.py:60` | 真实 PG 口令硬编码于 git 跟踪文件,且 `.env` 仍用同一口令 — 凭据视为已泄露 | 脚本改读环境变量;文档强制要求轮换全部共享口令与 API Key |

## P1(生产事故风险 — 按模块)

### 响应引擎
- 审批轮询永不超时(PENDING 无人迁移 EXPIRED,轮询任务无限累积)→ 轮询内自判过期并落库
- `AUTO_EXECUTED` 状态改在 submit 落库调度之后、且不再重持久化 → 重启后二次执行;先定状态再 submit
- 回滚按行号删除有竞态可删错规则 → 改按 `-m comment --comment <rule_id>` 匹配删除
- 规则台账纯内存,重启成孤儿规则 → 台账落 Redis 持久索引
- `kill_session` 的 user 拼进 `-match` 正则未转义,`user=".*"` 可杀全主机进程 → `regex.escape`
- `unsinkhole_domain`/`disable_account` 同步 SSH/LDAP 跑在事件循环 → 包 `asyncio.to_thread`
- critical 动作 `disable_account` 回滚(启用)恒失败却标 `reversible=True` → 如实标注
- `rollback_store.record()` 存原始 params(webhook token 明文进 Redis 7 天)→ 复用脱敏
- webhook 完整 URL(含 token)写日志两处 → 套 `redact_url_for_log`
- `asyncio.wait_for` 超时后 SSH 线程仍可能已写入规则,却报失败并释放幂等锁 → 超时语义改为"结果未知",不释放幂等占位

### 数据管道与审计
- 审计哈希链 `verify_chain` 不比对相邻链接,删行不可检出 → 逐行比对 `prev_hash`
- fallback 缓冲 flush 无锁,并发双 flush 致哈希链分叉 → `asyncio.Lock`
- CEP 消费者 value_deserializer 内 `json.loads`,毒丸消息致无限崩溃循环 → 走 `_decode_kafka_value`+DLQ
- poll 批内原地退避 sleep 最长 50×60s 触发 rebalance 风暴 → 临时失败立即让出,重试走内存调度
- `get_by_upstream_id` 缺字段致幂等命中路径 `already_audited` 失效 → 补齐映射
- DLQ 落库 SELECT-then-INSERT → `ON CONFLICT DO UPDATE`;`purge_expired` 逐行删 → 批量
- worker 无事件循环时 `submit` 返回 "direct" 假成功、死信重放当终态 → 无循环时入 fallback

### 检测引擎与智能体
- CAD `_persist` 读-改-写无 CAS,跨进程熔断状态可被陈旧副本回滚 → `WHERE version=:v` 乐观锁
- Sigma 多 selection 规则只编译第一条 SQL,其余静默丢弃(系统性漏报)→ UNION ALL 合并
- 聚合候选:ISO8601 时间戳解析崩溃静默丢失;跨线程 `create_task` 不安全 → `run_coroutine_threadsafe`+容错解析
- EDR 横向移动"目标 IP 匹配"只做空值检查不做相等比较,笛卡尔积假告警工厂 → 真实匹配
- feedback_loop 降级分母混入 miss/suggestion,5 条反馈即可自动降级 → 分母改 fp+tp 并加覆盖条件

### API 与部署
- compose 默认回退演示 API key,推翻 fail-closed → `${VALID_API_KEYS:?必填}`
- 限流 key 无条件信任 X-Forwarded-For,轮换 XFF 绕过全部限流 → 仅 `trust_proxy=true` 时采用
- 登录爆破保护 Redis 异常 fail-open → 退回内存计数并告警
- chat/audit-run/analyze 等无角色检查,低权账号可烧穿 LLM 预算 → `RequireRole("operator")`
- compose 除 rerank 外全部服务无资源限制;prod kafka-ui 0.0.0.0 暴露 → 补 limits/收端口

### 高价值 P2(一并执行)
- 随机 rule_id 碰撞(300 条即 50%)→ `secrets`;SSH 重连不关旧连接;审计 before/after 脱敏;
  `audit_dead_letters` 汇总日志打印真实成功数;`entrypoint.sh` root 目录必然失败;
  healthcheck 命令行暴露 redis 口令 → `REDISCLI_AUTH`;`case_manager.try_auto_resolve` 过期分支无视 pending 审批;
  `ttl_manager` 回滚无认领退避;`transfer.py` kill 后不 wait;`case_manager` session 锁泄漏。

## 执行顺序

批次 A(P0)→ B(响应引擎)→ C(管道审计)→ D(检测)→ E(API/部署)→ F(P2 快赢),
每批次后跑相关测试子集,最后全量测试 + ruff + 提交。

## 遗留风险(需人工介入,不在代码修复范围)

1. **凭据轮换**:.env 中 SHARED_MEMORY_ADMIN_PASSWORD 与 LLM API Key 均视为已泄露,须在真实环境轮换;
   git 历史中的旧口令建议 filter-repo 清理。
2. Sigma 每事件建内存 SQLite 的架构选型(热路径 O(规则数) SQL)建议后续预编译谓词/常驻连接;
   异常基线多进程合并写、限流计数器 Redis 化,均为架构级改造,本轮先做局部加固与文档标注。

## 执行记录(2026-10-24,同日完成)

### 批次 A — P0 全部修复
- P0-1 `audit_worker._run_job`: 用 `Task.cancelling()` 区分内外取消, stuck reaper 取消 job 不再杀死 worker(附语义注释)
- P0-2 `response_registry`: `_stub_fallback` 显式 `success=False`; `execute()` 对 `_stub` 结果一律判失败
- P0-3 `ssh_firewall._exec`: 以 rc 为准抛错(stderr 为空的失败不再被当成功); sudo 改 `-n` 非交互
- P0-4 `agent_cad`: 去掉对同步 `record_na` 的 `await`(单源告警车道崩溃修复)
- P0-5 `tools/monitor-2026-09-10.py`: 明文口令改环境变量读取, 缺失时明确报错

### 批次 B — 响应引擎 P1
- 审批轮询自判过期并落库(无人审批工单不再无限轮询)
- `AUTO_EXECUTED` 状态变更后重落库(消除重启后二次执行竞态)
- 回滚改按匹配删除(`-s/-d + comment`), 消除行号竞态; 纯 comment 删除入白名单兜底(LX-006/012 扩展)
- `get_active_rules_async` 合并 Redis TTL 索引(重启后孤儿规则可见可回滚); unblock/restore/防火墙状态端点切换
- `kill_session` 用户匹配改 `-eq` 精确比较(正则注入杀全进程)
- `unsinkhole_domain`/LDAP `disable/enable_account` 移入 `asyncio.to_thread`; enable 实现真实 LDAP 写路径(reversible 名副其实)
- 回滚记录与 safe_executor 审计参数统一 `redact_action_params` 脱敏
- webhook 日志三处脱敏; `wait_for` 超时上报 `outcome=unknown` 且 SafeExecutor 保留幂等占位锁
- `_connect_once` 重连先关旧连接(fd 泄漏); rule_id/isolation_id 改 secrets 10 位(防碰撞)

### 批次 C — 管道与审计 P1
- `verify_chain` 增加相邻链接比对(删行/重排可检出); fallback flush 加锁(防哈希链分叉)
- CEP 消费者去 value_deserializer, 毒丸消息走 DLQ(不再无限崩溃循环)
- 重试退避受批预算约束(≤ max_poll_interval/2), 防踢组风暴
- `get_by_upstream_id` 补齐字段映射(幂等命中不再重复入审计队列)
- DLQ 并发写撞唯一约束改为重试走 UPDATE; `purge_expired` 批量删除
- worker 无循环分支不再返回假成功 "direct"; 死信重放口径与日志计数修正

### 批次 D — 检测引擎 P1
- CAD `_persist` 改 CAS(version 谓词), 冲突重载权威副本(熔断状态不再被陈旧副本回滚)
- Sigma 多 SQL 合并 UNION ALL(多 selection 规则不再漏报); ISO8601 时间戳容错解析; 聚合发布跨线程 `run_coroutine_threadsafe`
- EDR 横向移动按行为者匹配(src_ip 相等 + 预索引), 并修复 `raw_data`/`user`/`event_name` 三处 AttributeError(该规则此前从未跑通)
- feedback_loop 降级判定分母改 fp+tp(5 条反馈不再触发自动降级)

### 批次 E — API 与部署 P1
- compose 演示 API key 默认回退改为必填(`:?`), dev/ha 与 prod 对齐 fail-closed
- 限流 key 仅 `trust_proxy=true` 时信任 XFF
- 登录爆破保护 Redis 故障退回进程内计数(fail-open 消除); admin 口令常量时间比较
- `/chat`、`/chat/stream`、`/audit-llm/run`、`/logs/analyze` 加 `RequireRole("operator")`
- 27 个服务补 mem_limit/cpus; prod kafka-ui 改绑 127.0.0.1; redis healthcheck 改 REDISCLI_AUTH; entrypoint /root/.ssh 分支修权限语义

### 批次 F — P2 快赢
- TTL 回滚: `zrem` 原子认领 + 指数退避 + 尝试上限告警
- sigma store 原子写(tmp+rename) + 真实版本号回写; case_manager 锁回收与 stale 分支不越过待审工单
- transport kill 后 wait + 文档纠正; geoip Reader 单例 + asn 字段不再张冠李戴; suricata topic 可配置
- correlation 回溯加 LIMIT; grounding 混合行为不再硬否决(只判同实体字段互斥矛盾), 删除自增 ID 跳跃误判
- Settings 字段守卫测试同步(338→345, 含前一轮 Kafka 安全化 6 字段)

### 架构级遗留(已文档化, 不在本轮范围)
- Sigma 每事件内存 SQLite → 规则预编译谓词
- 异常基线/限流计数/JTI 吊销的多进程 Redis 化
- TAXII 分页 / MISP 增量 / ioc_ingest 批量 upsert / ioc_matcher 单飞刷新
- 凭据轮换与 git 历史清理(人工操作)
