# 守望平台 · 全面升级计划（2026-10-21）

> **依据**：`docs/AUDIT-2026-10-21-全量代码审计报告.md`
> **目标**：竞赛交付 + 可信演示。把平台从“功能很多”升级为“每条宣称都能现场证明”。
> **已拍板**：NDR / TLS / EDR 保留；Qdrant 不删；Temporal 以进程内路径为权威，Temporal 作为可选加速器。
> **验收原则**：每一项改造必须有“失败测试 → 修复 → 通过测试 / 可复现脚本 / 报告”三件套；没有证据不算完成。

---

## 0. 结论与边界

- 不重写、不拆微服务、不引新消息总线/新向量库、不再加 Agent 模块。
- 8 万行不是问题；问题是重复实现、未接线、能力宣称与运行事实不一致。
- 升级主线：**收口（一条路径一个权威实现）→ 加固（安全与可靠性）→ 减负（删/降级未验证能力）→ 可验证（评估与演示）**。
- 默认 compose 从 27 个服务收敛到 12 个 core，其余用 profile 保留；NDR/TLS/EDR 作为受支持的 lab profile，不删除。

---

## 1. 目标形态

| 维度 | 现在 | 升级后 |
|---|---|---|
| 默认服务 | 27 个，6 个 healthcheck，0 个 networks | 12 个 core + `ndr` / `lab` / `search` / `workflow` 可选 profile |
| 后端进程 | API + 后台任务混跑 | api / audit-worker / responder 三进程，responder 独占 SSH 凭据 |
| 检测语义 | Flink 与 Python 两套异常检测，语义冲突 | 一份 `contracts/detection-policy.yaml` 事实源；Flink 产候选，Python 审计裁决 |
| 审批 | `mcp_guard` 死队列 + `human_approval` 真队列 | 一套 HMAC + digest + TTL + 防重放 |
| 记忆 | 记忆树 + 向量记忆，均无 TTL | 一套记忆服务，带 TTL / 撤销 / 租户字段 |
| 向量 | pgvector + Qdrant 双写，删除不同步 | 保留 Qdrant；修删除同步 + 对账任务；pgvector 为降级路径 |
| 响应执行 | 三条高危动作直连 ssh_firewall | 所有高危动作经 SafeExecutor（白名单/幂等/post-validate/TTL） |
| 能力宣称 | 30+ 模块 / 21 dormant | 10 verified + 5 experimental + 0 unaccounted；每项带证据 |
| 验收 | “代码存在” | 测试 + 脚本 + 报告，可复现 |

---

## 2. 里程碑

| 里程碑 | 内容 | 相对工作量 | 退出条件 |
|---|---|---|---|
| **M0 基线冻结** | 分支/tag、产物清理、基线复跑、25 个 P0 状态表 | 2–3 人日 | `BASELINE.md` 可复现；工作区状态明确；能力清单冻结 |
| **M1 响应安全闭环** | 高危动作入 SafeExecutor、默认 dry_run、审批/SSH/TTL/主机遏制 | 10–12 人日 | operator 直连封禁 403；admin 审批后可执行；篡改被拒；重启后 TTL 仍生效 |
| **M2 不丢事件** | Kafka offset/DLQ、Redis PQ、admit 字段、Temporal fail-closed、自动派单事务 | 8–10 人日 | 1,000 条已知 ID 事件重启对账 100%，静默丢失 0 |
| **M3 可度量检测** | 200+ 标注集、CI 评估、异常重标定、Sigma op/版本、情报落库 | 12–15 人日 | `EVAL-REPORT.md`：分层 P/R/F1、FPR、非空阈值区间、数据集哈希 |
| **M4 收口减负** | dormant 二选一、删死代码、合并重复路径、能力注册表、compose profile | 8–10 人日 | dormant 0 或全部登记；默认服务 ≤12；文档与代码一致 |
| **M5 演示与体验** | 告警→建案→审批→处置→复盘、错误态/虚拟化、Demo Mode、5 分钟脚本 | 10–12 人日 | `demo/run_demo.ps1` 一条命令跑通，无手工步骤 |
| **M6 门禁与运维** | 覆盖率棘轮、发布门禁、healthcheck/networks/limits、备份、Alertmanager | 6–8 人日 | 故意回归 CI 变红；恢复演练有数字 |

合计约 56–70 人日；不设硬期限，每个里程碑结束必须可演示。

### 当前进度（2026-10-21）

| 项 | 状态 | 证据 |
|---|---|---|
| 安全默认值 / dry_run | ✅ 完成 | `evidence/M1-response-safety.md` |
| 高危动作入 SafeExecutor | ✅ 完成（测试级） | `tests/test_m1_response_boundary.py` |
| 审批闸门（HIGH/CRITICAL 手动直执行 403） | ✅ 完成 | `tests/test_response_execute_guard.py` |
| SSH 主机密钥 / known_hosts | ✅ 完成（测试级） | `tests/test_m1_security_defaults.py` |
| 主机遏制 PowerShell 编码 | ✅ 完成（测试级） | `tests/test_response_transport_platform.py` |
| TTL 接线（Redis + 回滚回调） | ✅ 完成（fake Redis） | `tests/test_m1_response_boundary.py` |
| 告警异常不吞 / Temporal fail-closed | ✅ 完成 | `evidence/M2-reliability.md` |
| Kafka read_committed / 幂等生产 | ✅ 完成（静态+单测） | `tests/test_m2_no_silent_loss.py` |
| Redis PQ 丢失可见性 | ✅ 完成（单测） | `tests/test_m2_no_silent_loss.py` |
| `security-events-ingest` schema | ✅ 完成 | `tests/test_m1_security_defaults.py` |
| 能力登记表 + 前端状态 | ✅ 完成 | `backend/capabilities.yaml` / `tests/test_capabilities_registry.py` |
| 案例自动派单 flaky | ✅ 测试稳定 20/20 | `tests/test_case_automation.py` |
| 威胁情报 IOC 落库 + 拉取端点 | ✅ 完成（fake feed） | `evidence/M3-threat-intel.md` |
| 评估基线 + 数据集哈希 + CI artifact | ✅ 完成 | `EVAL-BASELINE-2026-10-21.md` |
| 真机 SSH / Redis 重启演练 | ⏳ 待做 | — |
| Redis PQ Lua 原子化 / spill append-only | ✅ 完成（单测） | `tests/test_m2_no_silent_loss.py` / `test_audit_spill_tombstone.py` |
| 200+ 真实标注集 / 异常重标定 | ⏳ 待做 | — |
| dormant 二选一 / compose 收敛 | ⏳ 部分完成 | 已删 3D 与 hierarchical 三件套 |
| 5 分钟演示脚本 | ✅ 完成（待联调） | `demo/run_demo.ps1` / `demo/README.md` |

---

## 3. 工作流 A：响应安全（最高优先）

### A1 高危动作统一走 SafeExecutor

- 位置：`backend/response_engine/response_registry.py:288,473-648`，`safe_executor.py`。
- 动作：`block_ip` / `isolate_host` / `dns_sinkhole` 不再直连 `ssh_firewall`；构造规范命令，经 `safe_executor.execute()`，保留真实 `live_fn`。
- 必带：命令白名单、参数校验、资产保护、Redis 幂等、post-validator、TTL 注册。
- 幂等键与 TTL 规则 ID 解耦：同一 IP + 时长在 TTL 窗口内重复请求应命中幂等；TTL 标记随封禁时长过期。
- 验收：`tests/security/test_response_boundary.py` 枚举所有 `subprocess/paramiko/exec_command` 到达点，断言只能经 SafeExecutor；重复 `block_ip` 不产生重复 iptables 规则。

### A2 默认 dry_run

- `backend/config.py:338` 默认 `dry_run`。
- `docker-compose.prod.yml` 显式 pin `SHARED_MEMORY_EXECUTION_MODE=${SHARED_MEMORY_EXECUTION_MODE:-dry_run}`。
- 启动时打印明确横幅：当前模式、是否允许真实执行。
- `.env.demo.example` 提供 `live` 显式示例。
- 验收：默认配置下 `_execution_mode()` 返回 `dry_run`；prod compose 含显式键；CI 断言默认值。

### A3 审批收口

- `requires_approval` 必须真正阻断，而不是只打日志。
- 统一到 `response_engine/human_approval`（HMAC + actions digest + TTL + 防重放）。
- `mcp_guard/approval_queue` 要么接入 approve/deny，要么删除并在文档中说明。
- 验收：篡改 actions 后审批被拒；未审批的高危动作返回 403；审批票据重启后不误放行。

### A4 SSH 主机密钥

- `ssh_firewall.py:167` `AutoAddPolicy` → `RejectPolicy`。
- `known_hosts` 必需；`/dev/null` 退化改为启动失败。
- `transport.py` 的 `StrictHostKeyChecking=accept-new` 改为 `yes`，并强制 `UserKnownHostsFile` 存在。
- 验收：未知主机密钥时连接被拒；缺失 known_hosts 时启动失败并给出操作指引。

### A5 主机侧遏制

- 修 PowerShell `EncodedCommand` 与白名单的衔接；`kill_process` / `quarantine_file` / `clean_persistence` 活路径必须可执行。
- post-validator 检查 `KILLED_COUNT` / `QUARANTINED` 等标记；“无验证器”与“验证通过”分开记录。
- 验收：用本地 Linux/Windows 目标或 fake SSH server 跑通 5 条活路径；测试覆盖活路径，而不只 mock/unconfigured。

### A6 TTL 接线

- 启动 `ttl_manager` scanner，注入 Redis 与 rollback callback。
- 移除/降级进程内 `asyncio.create_task` 自动解封。
- 验收：封禁后重启 responder，到期仍自动解封；Redis 不可用时明确 fail-closed 或显式告警。

### A7 小修复

- MISP `ssl_ctx = None if not verify else False` 逻辑反转。
- 公开注册默认关闭，env 显式开启；首个管理员用启动脚本/CLI 创建。
- `/metrics` 默认仅私网/本机或 service token 可访问。
- 审计链缺 HMAC 密钥/DB 读失败时 fail-closed；响应执行与 post-validation 入链。

---

## 4. 工作流 B：不丢事件

- **B1 Kafka**：`_handle_alert` / `_handle_behavior_alert` 异常 → DLQ 或保留 offset；消费端 `isolation_level="read_committed"`；生产端 `enable_idempotence=True`；两个告警 Sink 改 EXACTLY_ONCE。
- **B2 Redis PQ**：payload 过期导致 `pop_highest` 返回 None 时计指标、写日志、告警；Lua 原子 pop；spill 改 append-only。
- **B3 `admit()`**：保留 `analysis_status` / `analysis_complete` / `strong_count`。
- **B4 Temporal**：忠实度闸异常 → `response_blocked=True`；进程内与 Temporal 的非 LLM 信号集一致；Activity 幂等键。
- **B5 自动派单**：工单创建与状态迁移同事务或显式补偿；把 flaky 用例变成回归用例。
- **B6 契约与 trace**：5 个无 schema topic 补 catalog；前端类型从 JSON Schema 生成；`trace_id` 统一 32 hex。

**验收**：`tools/reconcile_events.py` 灌 1,000 条已知 ID → 杀 backend/Redis → 重启 → DB+DLQ=1000，静默丢失=0。

---

## 5. 工作流 C：可度量检测

- **C1 标注集**：`backend/eval_datasets/v2/`，≥200 条，`manifest.json` 带来源、标注人、内容哈希、分层；合成数据必须标注。
- **C2 CI 评估**：`evaluate_detection` / `evaluate_grounding` / `evaluate_behavior` 接入 CI，产出 JSON + Markdown，支持 before/after。
- **C3 异常检测**：阈值入 config；补目标基数、失败率、资产重要性特征；以“可行阈值区间非空”为硬验收；若不可分，降级为“优先级排序”并改文档。
- **C4 Sigma**：`op` 运算符进跨语言载荷；Flink 按 `op` 比较；`rule_version` 真正产出；用真实样本验证。
- **C5 威胁情报**：补生产代码写 `threat_iocs`；`expires_at` 过滤、去重、撤销；IOC 命中才可作为强信号。
- **C6 审计基准**：50 条带期望结论/证据的审计用例；度量 grounding 通过率、幻觉率、误报率；LLM 录制回放保证演示确定性。

**验收目标（可按基线校准）**：Sigma 原始指标层 Recall ≥0.8 @ FPR ≤0.05；异常阈值区间非空；审计 grounding ≥0.8、幻觉 ≤0.1。

---

## 6. 工作流 D：收口减负

| 保留并加固 | 降为 optional / lab | 删除或退休 |
|---|---|---|
| 接入/Kafka/Flink 校验、Sigma 聚合、4 阶段审计、响应引擎、案例/工单/复盘、RAG、Self-Play、MCP Guard、情报、可观测性 | NDR（Suricata/PCAP/协议解析）、EDR、CAPE 沙箱、MISP/TAXII、Temporal、bge-rerank | `hierarchical_attention` / `train_hierarchical` / `optimized_params`、`stabilizer` 全管线、`components/hero` + three 依赖、`mcp_guard` 死审批队列、`mitm_proxy` |

- 新增 `capabilities.yaml`：`id / name / status / evidence / last_verified / demo`；Capabilities 页只读它。
- `status` 只允许 `verified` / `experimental` / `disabled`；`verified` 必须有证据链接和最后验证日期。
- NDR/TLS/EDR 进入 `ndr` profile，保留并补 PCAP 级测试；未验证前标记 `experimental`，不进入默认演示。

---

## 7. 工作流 E：演示与体验

- 5 分钟故事线：端口扫描 → 暴力破解 → 审计四阶段 → 建案 → 审批封禁 → post-validate → TTL 解封 → 复盘。
- “从告警直接建案”，自动携带 `event_id` / `session_id`，不再手填。
- 统一 loading / empty / error 三态；Logs 接虚拟化；severity 五档配色。
- `DEMO_MODE`：确定性种子、独立 schema/前缀、一键 reset，不污染生产数据。
- 删除 3D 死代码与 three 依赖。

---

## 8. 工作流 F：工程门禁与运维

- 覆盖率门禁从 20% 提到实测基线，并对安全关键模块设单模块下限。
- 吞异常 / 零覆盖 / dormant 三个扫描器接入 CI，基线棘轮只降不升。
- `publish.yml` 依赖全部关键 job。
- core 服务补 healthcheck；加 `networks`；加资源上限；prod `SHARED_MEMORY_ENV_NAME=prod`；`FIELD_ENCRYPTION_KEY` 缺失即启动失败；`TEMPORAL_PASSWORD` 改 `:?`。
- 备份/恢复脚本 + 一次恢复演练；Alertmanager + 6 条 SLO 告警。

---

## 9. 能力矩阵（初稿）

| 能力 | 当前状态 | 目标 | 证据 |
|---|---|---|---|
| 日志接入 / Kafka 消费 | verified | 保持 | 对账脚本 |
| Flink 校验 / Sigma 聚合 | experimental | verified | 跨语言测试 + 真实样本 |
| 4 阶段 LLM 审计 | experimental | verified | 50 条审计基准 |
| 响应引擎（审批/封禁/隔离） | experimental | verified | 响应边界测试 + 演示脚本 |
| 案例 / 工单 / 复盘 | verified | 保持 | 生命周期测试 |
| RAG 混合检索 | experimental | verified | 版本化检索评估 |
| Self-Play | experimental | verified（隔离后） | 对局导出 + 隔离证明 |
| MCP Guard / 工具行为签名 | experimental | verified | 越权/注入测试 |
| 威胁情报 | disabled → experimental | verified | IOC 落库 + 命中测试 |
| 可观测性 / trace | verified | 保持 | trace 对账脚本 |
| NDR / TLS / EDR | disabled → experimental | experimental（lab profile） | PCAP 级测试 |
| 沙箱 / CAPE | disabled | experimental（lab profile） | 样本提交回放 |
| Temporal | experimental | optional | fail-closed + 版本测试 |

---

## 10. 明确不做

- 不拆微服务、不上 K8s、不引新消息总线/新向量库。
- 不再加 Agent 模块；不再用“模块数量”当成果指标。
- 不允许 `force=True` 绕过晋升门。
- 不再维持 pgvector + Qdrant 双写而不对账；保留 Qdrant，但必须修删除同步与一致性任务。
- 不保留 three.js 3D 死代码。

---

## 11. 执行约定

- 每个修复先写失败测试/探针；无法复现的审计项降级为文档问题，不写“已修”。
- 每个里程碑结束提交一份 `docs/upgrade/evidence/Mx-*.md`，包含命令、输出、截图/日志。
- 工作区冻结后再开始跨模块改动；当前未提交改动较多，提交策略需单独确认。
- 变更只动与目标直接相关的文件；不做顺手重构。
