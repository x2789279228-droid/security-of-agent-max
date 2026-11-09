# M1 证据：响应安全闭环（第一批）

> 日期：2026-10-21；**F2 live 演练补录：2026-10-30（见 §6）**
> 范围：安全默认值、响应边界、审批、SSH、主机遏制、TTL、注册闸门、admit 字段、能力登记表
> 结论级别：测试级（fake SSH/Redis）+ 全量回归；**live 级（真实 SSH 靶机 + 真实 Redis）已于 2026-10-30 完成第 4 节 1–3 项演练，见 §6**。

## 1. 代码变更

| 文件 | 变更 |
|---|---|
| `backend/config.py` | `execution_mode` 默认 `dry_run`；新增 `fw_ssh_known_hosts`、`fw_ssh_allow_unknown_host`、`response_ssh_known_hosts`、`response_ssh_allow_unknown_host`、`allow_self_registration`（默认 False） |
| `backend/response_engine/execution_modes.py` | `ExecutionModeRouter` 默认 `dry_run`（失败关闭） |
| `backend/app.py` | lifespan 初始化 `safe_executor`、注入 Redis、启动 `ttl_manager` 扫描器与回滚回调 |
| `backend/response_engine/response_registry.py` | `block_ip` / `isolate_host` / `dns_sinkhole` 统一经 `SafeExecutor`；TTL 优先 Redis，Redis 不可用才回退进程内并标注“不扛重启”；`grounding_score` 转发；`_auto_unblock_info` 区分机制 |
| `backend/response_engine/safe_executor.py` | 新增 `verify_fn` / `idempotency_key` / `idempotency_ttl` / `mode_override` / `skip_whitelist_reason` |
| `backend/response_engine/ssh_firewall.py` | `RejectPolicy` + 必需 known_hosts；`block_ip`/`isolate_host` 支持预生成 rule_id；新增 `run_verify_command` |
| `backend/response_engine/transport.py` | `StrictHostKeyChecking=yes`；known_hosts 缺失默认拒绝；PowerShell **先编码再查白名单** |
| `backend/response_engine/ttl_manager.py` | 回滚失败不再删除索引（保留重试）；payload 丢失仍按 rule_id 回滚 |
| `backend/routers/response.py` | HIGH 与 CRITICAL 都不允许手动直执行（此前只拦 critical，block_ip 可绕过审批） |
| `backend/response_engine/containment/host_adapter.py` | 配置缺失时默认 `dry_run` |
| `backend/threat_intel/stix_taxii.py` | 修正 MISP `ssl_ctx` 反转 |
| `backend/routers/auth.py` | 自助注册默认关闭，关闭时 403 |
| `backend/audit_triage.py` | `admit()` 保留 `analysis_status` / `analysis_complete` / `strong_count` |
| `backend/kafka_consumer.py` | 告警响应编排异常不再吞掉；三类消费者 `read_committed` |
| `backend/kafka_producer.py` | `enable_idempotence=True` |
| `backend/audit_pq.py` / `metrics.py` | payload 丢失计数 `soc_audit_pq_lost_total` + 错误日志 |
| `backend/schema_registry.py` / `contracts/catalog.json` | `security-events-ingest` 纳入 schema 校验 |
| `backend/capabilities.yaml` / `capabilities_registry.py` / `routers/capabilities.py` | 能力登记表：verified / experimental / disabled + 证据 + 最后验证日期 |
| `frontend/src/pages/CapabilitiesDashboard.tsx` | 展示三档状态、证据路径、运行开关 |
| `docker-compose.prod.yml` | 显式 pin `SHARED_MEMORY_EXECUTION_MODE=${...:-dry_run}`、`ENV_NAME=prod` |
| `config/prometheus/alerts.yml` | 新增 `SocAuditPqLost` 告警 |

## 2. 新增/更新测试

| 文件 | 覆盖 |
|---|---|
| `tests/test_m1_security_defaults.py` | 默认 dry_run、router 默认、prod compose pin、启动接线、MISP、SSH、注册、admit、ingest schema |
| `tests/test_m1_response_boundary.py` | block_ip 全检查链 + 幂等 + Redis TTL；dry_run 不触达 live；isolate/sinkhole 审计链；低 grounding 拦截 |
| `tests/test_response_execute_guard.py` | high/critical 手动直执行 403；medium 手动执行留痕 |
| `tests/test_response_transport_platform.py` | 主机遏制脚本编码后过白名单并到达 SSH |
| `tests/test_m2_no_silent_loss.py` | 告警异常冒泡、Temporal 忠实度闸 fail-closed、PQ 丢失计数、Kafka 事务/幂等 |
| `tests/test_capabilities_registry.py` | 能力状态合法、verified 有证据、旧 id 保留 |
| `tests/test_self_registration_gate.py` | strict xfail 转为正向断言 |
| `tests/test_active_module_coverage_gap.py` | 移除 `ttl_manager` 零覆盖登记 |
| `tests/test_response_grounding_gate_honesty.py` | 接线守卫改为“已被响应路径喂分数” |
| `tests/conftest.py` | 测试环境 `env_name=test`，案例聚合同步执行，消除 `:memory:` 单连接竞争 |

## 3. 实测结果

### 3.1 全量回归

```bash
cd backend
python -m pytest tests -q -p no:cacheprovider
```

结果：**2816 passed, 18 skipped, 48 xfailed**，耗时 **427.05s**，退出码 0。

### 3.2 关键行为

- `block_ip` 的 `audit.checks` 同时包含 `whitelist` / `params` / `asset_whitelist` / `idempotency` / `execution_mode` / `post_validation` / `ttl`。
- 同一 IP + 时长重复调用：第二次 `mode=idempotent_skip`，fake firewall 的 `block_ip` 只被调用 1 次。
- Redis TTL 可用：`ttl_registered=True`、`auto_unblock.mechanism=redis_ttl`、`restart_survives=True`。
- Redis 不可用：回退 `in_process_task`，`restart_survives=False`，并写 warning。
- `grounding_score=0.1`：在 ⓪ 闸门被拦截，fake firewall 零调用。
- `dns_sinkhole`：`audit.checks.whitelist.skipped=True`，理由记录为“常量模板 + 入口强校验”。
- `block_ip` / `isolate_host` / `dns_sinkhole` 手动直执行均 403；`rate_limit` 可执行并写 ResponseLog/AuditTrail。
- 主机遏制 3 条 PowerShell 脚本（kill/quarantine/clean）全部通过白名单并到达 SSH。
- 告警响应编排抛异常：`_handle_alert` / `_handle_behavior_alert` 均向上抛出，不再提交 offset。
- `security-events-ingest` 已进入 `TOPIC_SCHEMA_MAP`，垃圾载荷返回 5 条校验错误。
- 案例聚合 flaky 用例连跑 20 次全绿（此前 1/10 复现 UPDATE 0 rows）。

## 4. 尚未验证（必须保留为待办）

1. ~~**真实 soc-firewall 的 live 封禁/隔离**~~：✅ 2026-10-30 完成，见 §6 演练 A。
2. ~~**真实 Redis TTL 跨进程重启**~~：✅ 2026-10-30 完成，见 §6 演练 B。
3. ~~**post-validator 在真实 iptables 上的输出**~~：✅ 2026-10-30 完成（block 返回 `verified=true`，来自真实 `iptables -L` 解析），见 §6。
4. **主机遏制的真实 Windows 目标**：当前验证到“命令编码 + 白名单 + 到达 SSH”，未执行真实 PowerShell。
5. **审批队列的持久化**：`human_approval` 仍是进程内存态，重启丢失。
   （注：审批的 write-behind 落库与 approve 前先持久化已在 2026-10-27 路线收口，此处指工单全量持久化。）

## 5. 下一步

1. ~~搭一个本地 Linux SSH 靶机 + Redis，完成第 4 节 1–3 的 live 演练~~ ✅ 2026-10-30 完成（复用运行中栈的 `soc-firewall` 靶机 + `shared-memory-redis`，无需新搭）。
2. M2 剩余：Redis PQ 原子 pop、spill 追加写、Temporal 版本机制。
3. M3：版本化标注集 + CI 评估报告。
4. M4：dormant 二选一 + 默认 compose 收敛。

## 6. F2 live 演练（2026-10-30）—— 真实 SSH 靶机 + 真实 Redis

> 环境：运行中全栈（`shared-memory-backend`，`SHARED_MEMORY_EXECUTION_MODE=live`，
> `FW_SSH_HOST=soc-firewall`）+ `soc-firewall` 靶机容器（Alpine，sshd+iptables，
> `FIREWALL_ROOT_PASSWORD` 凭据）+ `shared-memory-redis`。
> 方式：`docker exec` 独立进程直驱 `response_executor`（组件级 live），
> 跨进程形态正是生产重启/多 worker 的真实条件。
> 依据：REMEDIATION-PLAN-2026-10-30 路线 F2。

### 6.1 演练 A：block → 真实 DROP → 跨进程回滚 → 零残留

| 步骤 | 实测（时间本地 UTC+8） |
|---|---|
| 基线 | `iptables -L INPUT` 空；containment 存量 216 条 |
| block（exec 进程①） | `EXEC succeeded=1`，`mode=ssh_firewall_paramiko`，`rule_id=FW-RULE-1429485173`，**`verified=true`（post-validator 解析真实 iptables 输出，关闭第 4 节待办 3）**；回滚记录落 Redis（TTL 604800s=7 天） |
| 实拍 | `iptables -L INPUT -n`：`DROP 203.0.113.66 … /* FW-RULE-1429485173 */` |
| 回滚（exec 进程②，跨进程） | 首轮暴露 3 个缺陷（见 6.2），修复后复跑：`ROLLBACK succeeded=1`，`deleted_count=1` |
| 终态 | `iptables -L INPUT` **零残留**；containment #217 → `rolled_back` |

另证：fail-closed 语义真实生效 —— 回滚进程未接 `safe_executor` Redis 时，
live 封禁被 `idempotency_unavailable` 拒绝（§9.52），iptables 未被触碰。

### 6.2 演练 A 发现并修复的 3 个真实缺陷（全部当天闭环）

| # | 缺陷（实测形态） | 修复 | 测试 |
|---|---|---|---|
| 1 | `_unblock_ip` src_ip 分支：封禁进程退出后合并视图（内存台账+本进程 TTL 索引）缺记录 → 循环零命中 `deleted_count=0`，冗余 `rule_id` 未用于直连扫描 → **规则残留** | 视图零命中且带 `rule_id` 时直连 `ssh_firewall.rollback(rule_id)`（扫描真实 iptables 注释，不依赖任何进程状态） | `test_rollback_cross_process_fix.py` |
| 2 | `response_registry.rollback` 包装无条件 `success=True`（不抛异常即成功）→ `deleted_count=0` 被计成回滚成功（**虚报**），且 `mark_rolled` 幂等标记被错误打下，后续真实回滚被"already rolled back"短路 | 包装层与 execute 的 P0-2 语义对齐：inner 自报 `success=False` → 外层 False | 同上 |
| 3 | `_unblock_ip` 与 `ttl_rollback` 均不保证 SSH 已配置/连接（封禁路径有 `_ensure_firewall_connected`，解封没有）→ 任何非 app 进程（重启后的扫描器/运维脚本）解封卡在主机密钥 fail-closed 或“SSH 未连接” | 两处入口统一先 `_ensure_firewall_connected()` | 同上 |

修复验证：3 项新测试 + 回滚面 34 项 + TTL 面 18 项全绿；修复文件同步进容器后，
**用现场遗留的真实规则复跑回滚成功删除**（`deleted_count=1`、零残留、台账对账）。

### 6.3 演练 B：TTL 双路径（跨进程回收 + 重启自动解封，真实 Redis）

| 路径 | 实测 |
|---|---|
| B1 跨进程回收 | exec 进程③封禁 `203.0.113.77`（TTL 60s，注册 `soc:ttl:index`）；到期时旧代码 app 扫描器回收 FAILED（缺陷 3）→ **app 重启吃进修复后代码**，00:20:17 扫描器 `Recovery: FW-RULE-0207373284 key lost → 立即回滚`，`rolled back: 1 lines ['iptables:INPUT']` |
| B2 重启存活 | 00:19:46 封禁 `203.0.113.88`（TTL 180s）→ 00:19:50 `docker restart shared-memory-backend`（扫描器 stopped→restarted）→ 00:22:49 到期，`Auto-rollback: OK` |
| 终态 | `iptables -S INPUT | grep DROP` = **0**；containment #218/#219 均 `rolled_back`；TTL 索引仅剩演练 A 的 60min 条目（规则已手工删，到期幂等回收） |

### 6.4 结论

- 第 4 节待办 1–3 全部关闭；`response_engine` 的 live 级证据从 fake 升级为真实 SSH+Redis。
- `capabilities.yaml` 中 `response_engine` 的“待真机 SSH + Redis TTL 演练后升 verified”条件**已满足**
  （升级动作与证据链接由 REMEDIATION-PLAN 路线 F 统一收口时执行）。
- 遗留：第 4 节待办 4（真实 Windows PowerShell 目标）与 5（审批工单全量持久化）仍开放。
