# 修复方案与验收标准（对应 AUDIT-2026-10-29-缺陷复审清单）

编号规则：R×对应复审清单的 P0/P1；附带覆盖的 P2 在同条目内注明。每条遵循统一验收原则：

> **验收总原则（对所有条目生效）**
> 1. 每个修复必须附带"修复前失败、修复后通过"的自动化测试（红→绿），测试名在本表登记，不允许只改代码不加测试。
> 2. "扫描/统计"类修复必须带**空结果自检**（产出为空 ≠ 通过，需显式区分"扫描了且为零"与"没扫到东西"）。
> 3. "宣称"类修复必须落到可执行断言（`test_readme_capability_claims.py` 扩展或新门禁脚本），不依赖人工记忆回写。
> 4. 全部完成后跑一遍总验收清单（文末 §总验收），任何一项不过即不视为完成。

---

## 批次 A：分钟级修复（先行合入，单独成 commit）

### R1（P1-3）情报第 4 源 kev_json 无法注册
**方案**：`backend/routers/edr_intel.py:203` 白名单元组补 `"kev_json"`。同步检查 `edr_intel.py` 内 feed_type 的其它枚举点（如 GET 列表过滤、poll 端点）是否共用同一常量——若是散落字面量，抽成模块级 `_ALLOWED_FEED_TYPES` 常量，四处引用，防止下次再加源又漏。
**验收标准**：
- [ ] 新增 `backend/tests/test_intel_feed_registration.py::test_register_kev_json_feed`：admin POST `/api/intel/feeds` body `feed_type="kev_json"` → 201；修复前为 400。
- [ ] 端到端：本地起 backend 后 `bash tools/seed-free-intel-feeds.sh` 完整跑完**不中途退出**（`set -euo pipefail` 下退出码 0），`GET /api/intel/feeds` 返回 4 条 active feed（feodo/openphish/urlhaus/cisa-kev）。
- [ ] cisa-kev poll 一次后 `GET /api/intel/iocs?source=cisa-kev` 返回非空（KEV 目录至少 1 条）。

### R2（P0-1）CI 静态扫描恒空产出（假门禁）
**方案**：`tools/scan-swallowed-failures.py:26` 改 `REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "backend")`；脚本末尾加自检：扫描文件数为 0 时打印原因并以退出码 2 失败。`ci.yml` "Static risk scans" 步骤同时检查 `scan-active-zero-coverage.py` 是否已有同类自检，没有则补齐。
**验收标准**：
- [ ] 在干净 Linux 环境（或 `bash -c "python tools/scan-swallowed-failures.py"` 于仓库根，路径含空格/中文可正常解析）运行：扫描文件数 > 300，正常退出 0。
- [ ] 破坏性自测：临时把 REPO 指向不存在目录 → 退出码 2 且 stderr 有明确信息（证明自检生效），恢复后通过。
- [ ] CI "Static risk scans" 步骤 artifact `swallowed-failures.txt` 非空（内容行数 > 0），且该步在任何 PR 上跑的是真实路径（可在 PR 里临时 `pwd && ls backend | head` 验证后移除）。

### R3（P1-14）compose 3 处默认密码回退
**方案**：`docker-compose.yml:921`、`:944`、`:1124` 的 `${VAR:-default}` 全部改 `${VAR:?must be set}`，与 postgres/redis 风格统一。
**验收标准**：
- [ ] 不注入环境变量执行 `docker compose -f docker-compose.yml -f docker-compose.prod.yml config` → 因 `TEMPORAL_PASSWORD`/`SHARED_MEMORY_FW_SSH_PASSWORD` 缺失而报错退出（fail-closed）；注入后 config 成功。
- [ ] 新增 `tools/check-compose-no-default-secrets.py`（grep `:-` 默认值模式出现在 *_PASSWORD/_PWD/_KEY 变量上即失败）挂入 CI static-analysis 步骤；自测：向 compose 临时插回一个默认密码 → 脚本退出 1。

### R4（P2）scheduler 两处 commit 失败静默
**方案**：`backend/scheduler.py:487-492`、`:522-528` 的 `except Exception: pass` 改为 `logger.error("[case-sla] commit failed: %s", exc, exc_info=True)` 并 `await session.rollback()`。
**验收标准**：
- [ ] 新增测试：mock session.commit 抛异常 → 调用对应函数 → 断言 `caplog` 中出现 ERROR 级 "commit failed" 且函数不抛出（降级不中断调度循环）。
- [ ] 全量测试后 `grep -n "except Exception: pass" backend/scheduler.py` 为 0 处。

### R5（P1 一并）README 复现命令与数字失准
**方案**：
1. `README.md:561` 改为 `cd backend && python -m eval_datasets.evaluate_detection`（与 ci.yml:106-108 实际用法一致）。
2. 数字修正：规则 150→159（影子 125→139）、测试 3084/252→以门禁输出为准、组件 71→75、端点数改为 openapi 口径（"226 operations"）。
3. 新增 `tools/check-readme-numbers.py`：解析 README 中的规则数/测试数/组件数，与实测（`ls backend/sigma_engine/rules*`、`pytest --collect-only -q | tail -1`、`find frontend/src/components -name "*.tsx" | wc -l`）比对，漂移即退出 1；挂入 CI（排在 backend-test 之后复用其环境，或独立轻量 job）。
**验收标准**：
- [ ] 人工复现：按 README"快速开始"逐条粘贴执行，评测命令不再 ImportError。
- [ ] `python tools/check-readme-numbers.py` 当前退出 0；临时把 README 规则数改回 150 → 退出 1（防漂移自测）。
- [ ] CI 新增数字门禁 job 且绿。

---

## 批次 B：半天级修复

### R6（P1-9）优雅停机不清理 5 个采集引擎
**方案**：`backend/lifecycle.py` `shutdown_platform()` 在 `drain.begin()` 之后、Kafka drain 之前插入引擎收尾段（顺序有意：先停采集入口，再刷存储，最后走既有 DB/Redis 收尾）：
```python
# 1) 停采集入口（不再产生新事件）
for name, mod, attr in (("capture_engine", "traffic_capture.capture_engine", "capture_engine"),
                        ("suricata_connector", "ids_connector.suricata_connector", "suricata_connector"),
                        ("edr_adapter", "edr_fusion.edr_adapter", "edr_adapter")):
    ...  # getattr(mod, attr).stop()，各自 try/except 记 error 不中断
# 2) 刷存储（pcap_store.stop() 关闭当前文件并补落 pcap_files 元数据；flow_aggregator.stop() 落在途流）
```
每个 stop 包 try/except 与现有风格一致；若某引擎未启用（`capture_enabled=false`）其 stop 应为幂等 no-op（实现时确认各 stop() 已幂等，不幂等则加 `if self._running` 守卫）。
**验收标准**：
- [ ] 新增 `backend/tests/test_shutdown_stops_engines.py`：monkeypatch 5 个引擎单例为 AsyncMock，调 `shutdown_platform()`，断言 5 个 `.stop()` 均被 await，且调用顺序在 `dispose_engines` 之前。
- [ ] 冒烟（手工，登记步骤）：`capture_enabled=true` 起 backend → 注入若干包 → `kill -TERM` → 检查 ①进程正常退出（无 hang）②`pcap_files` 表存在 stop 之后时间戳的完整记录 ③对应 pcap 文件句柄已关闭（容器内 `lsof` 无残留）。
- [ ] 全仓 grep 确认 `app.py` 启动的每个长任务引擎（5 个）在 lifecycle 中都有对应 stop；在 lifecycle.py 头部 docstring 的停机顺序清单中补第 0 步。

### R7（P2）bcrypt 阻塞事件循环
**方案**：`backend/user_store.py` 的 `verify_password`/`hash_password` 改 `async def` + `await asyncio.to_thread(bcrypt.checkpw, ...)`；调用点 `routers/auth.py:128`、注册路径同步加 await。或者保守方案：仅 `routers/auth.py` 内包 `to_thread`，user_store 保持同步。选前者（接口层面根治），改动点 grep `verify_password|hash_password` 全部调用处。
**验收标准**：
- [ ] 新增 `backend/tests/test_auth_no_event_loop_block.py`：用一个已完成 future + `asyncio.wait_for(..., timeout=0.5)` 包住 login 请求处理（或在 loop 上挂低优先级探测任务），断言 bcrypt 期间探测任务仍被调度（事件循环未被同步阻塞 ≥200ms）。
- [ ] 既有登录/注册测试全绿（3124 基线上无回归）。

### R8（P2）audit_pq.pop_matching 损坏 payload 静默滞留
**方案**：`backend/audit_pq.py:374-377` 对齐 `pop_highest` 的处理：`json.loads` 失败 → `zrem` 该成员 + `inc_audit_pq_lost("payload_corrupt")` + `_dead_letter(...)` + continue。
**验收标准**：
- [ ] 新增测试：向 ZSET 塞 1 个损坏 payload + 2 个正常任务 → `pop_matching` 后断言 ①返回 2 个正常任务 ②ZSET 长度为 0（幽灵成员被清除）③dead_letter 里出现该损坏成员 ④`audit_pq_lost_total{reason="payload_corrupt"}` +1。
- [ ] 修复前该测试在"ZSET 长度为 0"断言处失败（红→绿留痕）。

### R9（P2）Suricata 消费循环无重试
**方案**：`backend/ids_connector/suricata_connector.py:222-258` 消费循环外面包 `while self._running:` + `except Exception: logger.error + 指数退避(1s→30s 封顶) + continue`，与 `kafka_consumer.py:423-458` 的监督重启模式对齐；退避期间 `_running=False` 时立即退出。
**验收标准**：
- [ ] 新增测试：mock aiokafka 消费者第一次 `getmany` 抛 ConnectionError → 断言循环没有退出（`_running` 仍 True 且再次尝试），第 2 次恢复正常后告警继续产出。
- [ ] 对照测试：连续 N 次异常后退避时长不超过 30s 封顶（用虚拟时钟断言）。

### R10（P2）suricata-replay 不建 eve-out 目录
**方案**：`docker-compose.yml` `soc-suricata-replay` 服务命令前置 `mkdir -p /pcaps/eve-out`；`|| true` 改为 `|| echo "[replay] WARN: eve copy failed: $f" >&2`（保留非致命但可见）。
**验收标准**：
- [ ] 手工：删掉宿主 `./pcaps/eve-out` → `docker compose run --rm soc-suricata-replay`（或按 REPLAY-PCAP.md 步骤）→ 目录自动创建且 eve.json 落盘成功。
- [ ] 若 cp 失败，容器 stdout 出现 WARN 行（不再无声）。

### R11（P1-5）RAG hybrid 评测宣称与现实不符
**方案**（二选一，默认选 a，答辩前完成）：
a. **降级宣称**：`docs/upgrade/EXTERNAL-INTEL-UPGRADE-2026-10-27.md` §2 R5 与 `evaluate_rag.py:176-185` 的提示文案改为如实口径："hybrid 模式尚未实现，当前 AC 以 dense+rerank 为准"；`--mode hybrid` 保留退出码 3 但文案删掉"需要真实检索栈"的误导（改为"未实现"）。
b. **实现**：hybrid 分支真实调用 `rag/retriever.py` 的 hybrid 检索（若已具备）跑同一评测集。
**验收标准**：
- [ ] 选 a：文档与 CLI 输出不再含"需要真实检索栈即可运行"的暗示；`grep -rn "mode hybrid" docs/upgrade/` 全部标注"未实现"。
- [ ] 选 b：`cd backend && python -m eval_datasets.evaluate_rag --mode hybrid`（真实栈）产出带 precision/recall 的报告 JSON 且退出码 0；新增回归测试断言 hybrid 分支不再 `return 3`。
- [ ] `test_readme_capability_claims.py` 增加断言：capabilities.yaml 中 RAG 评测的 AC 描述与 `evaluate_rag.py` 支持的 mode 集合一致（解析两边比对）。

---

## 批次 C：一天级修复

### R12（P1-6/7/8 + P2）demo 系统隔离四件套
**方案**：
1. **IOC 隔离**：`backend/threat_intel/ioc_matcher.py:86-92` `_load_from_db` 增加 `ThreatIoc.source != "demo-seed"` 过滤（富化匹配永不命中演示 IOC；`GET /api/intel/iocs` 列表查询不动，展示层已有过滤）。
2. **KPI 可回滚**：`demo_seed.py` 增加登记表（新表 `demo_seeded_artifacts(kind, key, created_at)` 或复用于 `_seed_kpi` 前把将覆盖的 `(snapshot_date)` 记入登记）；`_seed_kpi` 只 upsert 登记过的日期；`/seed/clear`（:371-405）按登记删除 `kpi_snapshots` 对应行 + 清登记。若不想动表结构，替代方案：`_seed_kpi` 改为只在快照**不存在**的日期写入（绝不覆盖已有真实快照），clear 删除 demo 期间新增的行——选登记表方案，语义更干净。
3. **流量通路**：`demo/run-demo.sh:78` 把 ：67 已取得的 admin JWT 传给模拟器 `--token "$TOKEN"`；`log_simulator.py` continuous 模式无 token 时**启动即报错退出**（fail-fast，不再静默 403）；`:326` 的 `DEFAULT_API_KEY` 删除或仅作 `--api-key` 缺省并在 help 里注明"需在 SHARED_MEMORY_SOURCE_API_KEYS 注册"。
4. **ingest 认证语义扶正**：`backend/routers/logs.py` `_authenticate_source`：配置了 `SHARED_MEMORY_SOURCE_API_KEYS` 时，无 key 与坏 key 一律 401/403（fail-closed，删除"匿名放行"分支）；未配置且 `environment=prod` 时拒绝所有 HTTP ingest（Kafka 通道不受影响）；未配置且非 prod 时放行 + 一次性 warning。
5. **服务端演示开关**：`config.py` 加 `demo_mode: bool = False`；`app.py:710,728` 仅 `settings.demo_mode` 时 `include_router(demo_seed_router)`；compose 加 `SHARED_MEMORY_DEMO_MODE` 透传；`demo_start.bat`/run-demo.sh 设置该变量。
**验收标准**：
- [ ] 新增 `backend/tests/test_demo_isolation.py`：①seed 后 `_load_from_db` 结果不含 demo-seed 源；②对含 `23.129.64.33` 的真实事件调 `enrich_event` → intel 命中断言为空；③seed→clear 后 `kpi_snapshots` 恢复 seed 前状态（对比行数与内容哈希）；④`demo_mode=False` 时 `POST /api/demo/seed` → 404。
- [ ] 新增 `backend/tests/test_ingest_auth_semantics.py` 认证矩阵：{无key, 坏key, 好key} × {keys已配置, 未配置+dev, 未配置+prod} → 断言 {401, 403, 202} / {202+warn, 202+warn} / {401, 401, 401}。
- [ ] 端到端（runbook 登记）：`bash demo/run-demo.sh` 全程跑通——traffic 容器日志出现连续 HTTP 202（`docker logs demo-traffic | grep -c 202` ≥ 60/min 对应 interval），`/api/stats` 事件计数持续增长；关掉 `SHARED_MEMORY_DEMO_MODE` 重启后 `/api/demo/*` 全部 404。
- [ ] `grep -rn "soc-simulator-2024" . --include="*.py"` 仅剩 help 文案或为 0；`log_simulator.py --mode continuous` 无 token 时退出码非 0 且 stderr 明确提示。

### R13（P1-1）Windows 白名单空壳
**方案**：`backend/response_engine/command_whitelist.py` WIN-004 改两级校验：①外层保留编码形态正则（快速通道）；②新增解码层——`base64.b64decode` 后按**脚本模板指纹**匹配：每个会产生 PowerShell 动作的响应策略在 `host_adapter.py` 生成脚本时同步登记模板（变量占位参数化后的规范化 SHA256，或"前缀+骨架正则"），白名单校验解码内容必须命中已登记模板之一；解码失败/未命中 → 拒绝。模板登记表放 `response_engine/ps_templates.py`，`GLOBAL_FORBIDDEN` 同时作用于解码后文本。
**验收标准**：
- [ ] 新增 `backend/tests/test_windows_whitelist_decoded.py`：①随机/构造恶意脚本（`Remove-Item C:\ -Recurse`、下载执行、`iex(...)`）base64 编码后 → `check(platform="windows")` 拒绝且 reason 含 `decoded_mismatch`（修复前这些全部通过——红→绿留痕）；②4 个内置动作（kill_process/quarantine_file/clean_persistence/forensic_snapshot）的合法生成脚本 → 放行；③模板外的合法运维脚本（如手工编写的良性 PowerShell）→ 拒绝（fail-closed 语义确认）。
- [ ] 属性测试（hypothesis 或循环 1000 随机 payload）：解码文本含 GLOBAL_FORBIDDEN 任一符号 → 必拒绝。
- [ ] `host_adapter.py` 新增动作若未登记模板，单测有一条守卫断言（枚举所有 `powershell=True` 动作 ↔ 模板表键一致，防未来新增动作漏登记）。

### R14（P1-2）情报链路 SSRF + 本地文件读 + 凭证外带
**方案**：
1. 把 `backend/zeroday_detect/sandbox_status.py:225-283` 的 `validate_submittable_url` + `_ip_rejection` + `_host_to_ips` 上提为共享模块 `backend/net_guard.py`（sandbox_status 改为 re-export 保持兼容），threat_intel 与 sandbox 同源。
2. `stix_taxii.py`：①`_import_csv_http`（:300-317）与 `_fetch_text`（:207-229）入口先过 `validate_submittable_url(url)`（情报源是公网服务，`allow_private=False` 即默认）；②`httpx.AsyncClient(follow_redirects=False)`，手动逐跳循环：每跳重过校验器，跨 host 跳转时剥离 Authorization 头，最多 5 跳；③流式下载 + `aiter_bytes` 累计计数，超过 `_MAX_FEED_BYTES` 中止（不再先整包入内存）。
3. `_import_csv`（:190-205）：本地 csv 路径限定白名单目录（`settings.intel_local_feed_dir`，默认 `<data>/feeds/`，compose 挂载显式卷），且 `Path.resolve()` 后必须位于该目录内；白名单目录外 → 拒绝并提示改用 csv_http。
4. `_poll_taxii/_poll_misp`（:94/:143）同样走 1 的校验。
**验收标准**：
- [ ] 新增 `backend/tests/test_intel_fetch_net_guard.py`：①feed url `http://169.254.169.254/`、`http://10.0.0.1/x`、`http://127.0.0.1/` → 注册被拒（400/422，poll 亦然）；②feed_type=csv url=`../../.env` 与 `/etc/passwd` → 拒绝；③mock httpx 302 跳 `http://192.168.1.1/` → 拒绝；④302 跳其它公网 host → 第二跳请求头断言**不含** Authorization；⑤超 10MB 的响应在 ~10MB 处中止（断言读取字节数 < 11MB）。
- [ ] 回归：4 个真实免费源（批次 R1 之后）在改造后仍能拉取成功（集成冒烟脚本 `tools/smoke-free-intel.sh`，登记到 runbook）。
- [ ] `grep -n "follow_redirects=True" backend/threat_intel/` 为 0。

### R15（P1-12 + P1-13）前端 Logs 性能 + Home SSE
**方案**：
1. Logs（`frontend/src/pages/Logs.tsx`）：①REST"加载更多"路径（:150）加 `slice(0, 500)` 与 SSE 路径同口径；②表格改 react-window 虚拟化（复用 Monitor 的实现模式），行组件 memo 化，入场动画从逐行 FLIP 改为仅对新插入行做一次性 CSS 动画（`layout` 属性移除）。
2. Home（`frontend/src/pages/Home.tsx:99-113`）：删除私建 EventSource，改用 `lib/eventStream.ts` 单例订阅 `security_event`/`audit_complete`（参照 Monitor.tsx 接法），连接状态交给 StatusBar 统一展示。
**验收标准**：
- [ ] `cd frontend && npx tsc --noEmit` 0 错误；`npm run build` 成功。
- [ ] 性能验收（Playwright 或手工，登记步骤与数字）：注入 2000 条事件后 Logs 页 DOM 中表格行节点 ≤ 30；连续点"加载更多" 5 次，缓冲维持 500 上限并出现"已达缓冲上限"提示；Chrome Performance 录制 10s 滚动无 long task > 200ms。
- [ ] Home SSE：起前端 + 杀 backend 再重启 → 首页计数在重连后**继续增长**（修复前冻结）；断网 10s 恢复 → 状态条出现过 DEGRADED→LIVE 迁移。
- [ ] `grep -n "new EventSource" frontend/src/pages/` 为 0（唯一 SSE 入口在 eventStream.ts）。

### R16（P1-10）案例 event_ids 无界 + N+1
**方案**：
1. `backend/case_manager.py:811-815`：`_add_event_to_case` 加上限常量 `_MAX_EVENTS_PER_CASE = 500`，超限后不再 append（记录一次性 warning 指引看 event_archive），并在 Case 模型加 `events_capped: bool` 标记（前端展示"已截断"角标）。
2. `:225-233` 策略 0 增加 session 聚合时间窗（如 30 分钟无新事件即关闭 case，与现有 SLA 扫描复用同一实现思路）。
3. `post_mortem_service.py:171-178` 删除本地 N+1 复制，改调 `case_manager.get_case_timeline`（:533-538 批查版）；`case_manager.py:284-292、:322-325` 两处逐 id get 改 `id.in_()` 批查。
**验收标准**：
- [ ] 新增 `backend/tests/test_case_aggregation_bounds.py`：①同一 session 注入 600 事件 → case.event_ids 长度 == 500 且 `events_capped=True`；②30+ 分钟（虚拟时钟）无后续事件的 session case 被时间窗关闭。
- [ ] SQL 断言：`get_case_timeline` 路径在 100-event case 上 SELECT 次数 == 1（用 SQLAlchemy 事件计数或 echo capture），修复前为 100。
- [ ] 既有案例流转测试全绿；post_mortem 产出与改造前对同一 case 的 timeline 内容一致（快照对比测试）。

---

## 批次 D：结构性修复（1-3 天/项）

### R17（P0-2）测试污染治理
**方案**：
1. **策略目录隔离**：`backend/tests/conftest.py` 增加会话级 fixture：启动时把 `response_engine/policies/*.yml` 复制到 `tmp_path_factory` 目录，monkeypatch 策略加载根路径指向副本（policy_engine 的目录来源改为可注入参数/环境变量 `SOC_POLICY_DIR`，生产默认原路径）。learn_loop 回滚问题当年因"行为不一致"放弃——本次要求：跑 `pytest -k learn_loop` 单独绿 + 全量绿双验证，不一致则修 learn_loop 测试本身。
2. **`_reset_globals` fail-fast**（conftest.py:111-145）：6 个复位块的 `except Exception: pass` 改为收集错误，任一失败 `pytest.fail("global reset failed: ...")`（保留逐块执行，最后统一上报）。
3. **剩余 5 个 `_cache` 直戳测试**：按 e3b388f 模式改"新实例化"——`test_capability_tile_counts.py`、`test_event_store_cache.py`、`test_inc_threat_intel.py`、`test_intel_enrichment.py`、`test_llm_cache_and_embedding.py`；确需全局态的（如 event_store LRU 有界断言）改用 fixture 内 `pytest.MonkeyPatch.setattr` 自动还原，禁止裸 `_cache.pop/clear`。
4. **字母序 workaround**（conftest.py:86-96）：登记为已知债务，建 issue；Python 3.12 升级前必须解决（本次不在范围，但在 conftest 注释中写明到期条件）。
**验收标准**：
- [ ] **核心验收**：干净 clone → `git status` 记录基线 → `cd backend && python -m pytest -q` 全量跑完 → `git status` 与基线**完全一致**（policies/*.yml 内容与 mtime 不变；`git diff --stat` 为空）。
- [ ] 全量与单跑双绿：`pytest -k "learn_loop or response_policy or update_rule"` 单跑绿，随后全量跑也绿（顺序不再影响结果）。
- [ ] 破坏性自测：临时在 `_reset_globals` 某块注入 raise → 测试会话以 "global reset failed" 失败（证明 fail-fast 生效），恢复后全绿。
- [ ] `grep -rn "_cache\.\(pop\|clear\)" backend/tests/` 为 0（或仅剩带 MonkeyPatch 还原的用法并逐处注明）。

### R18（P1-11）OpenAPI 生成类型接线
**方案**：`frontend/src/lib/api.ts` 全量替换 `fetchJSON<any>` 为 `fetchJSON<components['schemas']['XxxResponse']>`（从 `types/api-generated.ts` 导入 `components` 类型）；`/stats` 等复合端点先在 `frontend/src/types/stats.ts` 定义窄接口并让各页共享（Monitor/Home/BattleScreen 四处解构点统一引用）。替换分三步合入：①stats 高频端点 ②告警/事件端点 ③其余。CI 增加门禁脚本 `tools/check-frontend-any.ts`（统计 `fetchJSON<any` 出现次数，阈值 0，逐步收紧）。
**验收标准**：
- [ ] `grep -c "fetchJSON<any" frontend/src/lib/api.ts` == 0；`: any` 总数较基线 123 下降 ≥ 40（stats/事件域清零）。
- [ ] 故意把 api-generated.ts 中某字段改名 → `npx tsc --noEmit` 报错（证明契约链真正生效，红→绿验证）。
- [ ] `npm run gen:api && npx tsc --noEmit` 在 CI 顺序执行且绿；check-frontend-any 门禁挂入 frontend-check job。

### R19（P2）simulate 旁路审批分级
**方案**：`backend/routers/response.py:127-150` simulate 请求体强制 `allow_blocking=False`（服务端写死，不收客户端字段）；或 threat_info 注入前显式 `"allow_blocking": False`。同时 `response_orchestrator.py:257-259` 的缺省回落从 `True` 改 `False`（缺省不阻断——fail-safe 语义），仅 `/api/response/execute` 显式审批通过后才传 True。全仓 grep `allow_blocking` 确认调用面。
**验收标准**：
- [ ] 新增 `backend/tests/test_simulate_no_live_blocking.py`：`execution_mode=live` 下 POST `/api/response/simulate`（threat_type 命中 POL-TRAVERSAL, src_ip=1.2.3.4）→ 断言 ①无 iptables/ssh 调用（mock firewall 断言 not called）②返回的动作列表中阻断类标记 `simulated`。
- [ ] 正向回归：走 `/api/response/execute` + admin 审批的 block_ip 用例仍能执行（既有 `test_response_execute_guard.py` 全绿）。
- [ ] `grep -n 'get("allow_blocking", True)' backend/` 为 0。

### R20（P2 择要打包）可靠性小项清账
**方案与验收（逐项一行）**：
- MCP Guard fail-open（`guard_server.py:318-336`）：对齐 audit 侧——`tool_signature_mode=deny` 时检测器异常 → 拒绝执行并返回 degraded。验收：单测 mock 检测器 raise → 断言 execute 未被调用。
- 审计→响应裸 create_task（`log_ingestion.py:1298`）：改走 `capacity.schedule_bounded` 并登记引用集。验收：grep 该行无裸 create_task；压测 1000 并发告警时响应编排并发 ≤ http_background_max（单测断言信号量占用）。
- Redis 滑窗 TTL（`sliding_window.py:203,244-259`）：rpush/写淘汰键时顺带 `expire(key, window_ttl*4)`。验收：单测断言两键 TTL > 0。
- ioc_matcher 惊群+无界（`ioc_matcher.py:79-92,139-140`）：`asyncio.Lock` 包刷新 + `_load_from_db` 加 `LIMIT`（如 50000）+ 超限 warning。验收：并发 50 请求触发过期 → 断言 DB 查询只发生 1 次（mock 计数）。
- 富化 cancel 毒化 session（`intel_enricher.py:181-192`）：`wait_for` 内改用独立短生命周期 session（或 enrich 内部自管 session），调用方 session 不进 cancel 范围。验收：单测让 enrich 内部第一条 SQL 挂起→超时→断言外层 session 仍可正常 execute。
- JWT `?token=`（`app.py:555-562` + Dockerfile）：uvicorn 启动加 `--no-access-log`（自研中间件已在记路径级访问日志）或 SSE 改 `Authorization` 头 + 一次性 ticket 降级路径。验收：起服务带 `?token=` 请求 → 容器日志 grep 不到该 token。
- 前端死代码 13 文件（~1,402 行）：删除清单见复审清单 P2-1（TopNav/LearnLoopTab/ShiftOrbit/BrandPanel/RegisterForm/PipelineStrip/Chip/DutyTape/GlassPanel/SplittingText/StatusDot/SurfacePanel/TiltCard/useTilt）。验收：删除后 `tsc --noEmit` 0 错误 + build 成功 + `grep -rn "TopNav" frontend/src` 为 0。
- `query`→dns_query 门禁（`log_ingestion.py:141`）：别名 `query` 仅当事件 `event_type in {"dns","network.dns"}` 或 source 属 DNS 类时归一。验收：注入含 `query` 字段的 sql_audit 事件 → sigma 匹配断言不命中 `hq_net_dns_*` 规则；DNS 事件仍命中（既有路线4测试全绿）。
- sigma 哈希混淆（`mapping.py:46-80`）：按字段名与算法前缀匹配（`sha256*`→sha256 目标，md5→md5），不再一对全写。验收：单测 md5 值只出现在 md5 目标字段。
- Tempo 硬编码 3 处（`routers/kafka.py:134`、`ops.py:301,355`）：改 `settings.tempo_url`。验收：grep `http://tempo:3200` 为 0；.env.example 补变量。

---

## §总验收（全部批次完成后的 Definition of Done）

| # | 验收项 | 判定方式 |
|---|---|---|
| 1 | CI 全绿 | ci.yml 14 job + 新增（数字门禁/any 门禁/compose 密码门禁）全绿，无 skip |
| 2 | 全量测试 | `cd backend && python -m pytest -q` 3124+ 用例全绿，`--cov-fail-under=55` 通过（实测应 ≥64%，建议顺势收紧到 60） |
| 3 | 测试零污染 | 干净 clone 跑全量后 `git status` 与基线一致（R17 核心验收） |
| 4 | 前端 | `npx tsc --noEmit` 0 错误；`npm run build` 成功；`fetchJSON<any`==0；`new EventSource` 仅 eventStream.ts 一处 |
| 5 | 假门禁清零 | 两个 risk-scan 空结果自检生效；repo 内无"恒绿不可能失败"的扫描步骤（清单化核对 ci.yml 每个步骤的失败模式） |
| 6 | 情报链路 | seed 脚本 4 源全通 + smoke-free-intel.sh 绿 + SSRF 测试矩阵绿 |
| 7 | 演示链路 | run-demo.sh 端到端：流量 202 持续、KPI 可回滚、demo_mode 关闭后 404；demo_start.bat 冒烟一遍 |
| 8 | 停机冒烟 | SIGTERM 后 5 引擎 stop 日志齐、pcap_files 有终记录、进程 30s 内退出 |
| 9 | 文档对账 | check-readme-numbers.py 绿；EXTERNAL-INTEL-UPGRADE/ATOMIC-RUNBOOK 与代码口径一致（R11/R1 对应段落人工复核签字） |
| 10 | 红线回归 | 既有 security_guard/response_engine veto/veto_gates/agent_live_ticks 等核心测试全绿（闸门收紧无回归） |

## 实施顺序与依赖

```
批次A（R1-R5，先行独立合入）
   └→ 批次B（R6-R11）           R14 依赖 R1（4源先通才能回归）
        └→ 批次C（R12-R16）      R12 依赖 R7 同文件区（auth）无冲突即可并行
             └→ 批次D（R17-R20） R18 建议单独 PR（触碰文件多但机械）
```
- 每条 R× 一个独立 commit，commit message 引用复审清单编号（如 `fix(intel): R1 kev_json 白名单`），保证可回溯。
- R13（Windows 白名单）与 R19（simulate 分级）改动响应引擎核心，合入后必须重跑 `test_veto_gates.py`、`test_response_execute_guard.py`、`test_agent_live_ticks.py` 三套红线。
- 批次 C 的 R12 涉及 compose 新变量 `SHARED_MEMORY_DEMO_MODE`，`.env.example` 与 README 快速开始同步补文档（一并纳入 R5 的数字门禁不覆盖的手工项）。
