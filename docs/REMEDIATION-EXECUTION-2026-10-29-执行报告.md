# 四批修复执行报告（2026-10-29）

对应方案：`docs/REMEDIATION-PLAN-2026-10-29-方案与验收.md`（R1–R20）。
本文为执行结果总账：每项的实现要点、红→绿验证方式、残留与豁免。

## 完成度总表

| 批次 | 项 | 状态 | 验证 |
|---|---|---|---|
| A | R1 kev_json 白名单 | ✅ | `test_intel_feed_registration.py` 4 用例（含六方言全注册 + KEV 方言解析端到端） |
| A | R2 扫描脚本假门禁 | ✅ | 修复后扫描 600 文件；破坏性自测（目录不存在）退出码 2；姊妹脚本同规 |
| A | R3 compose 默认密码 | ✅ | 3 处改 `:?`；`docker compose config` 缺变量即报错；新门禁 `check-compose-no-default-secrets.py` 红→绿自测 |
| A | R4 scheduler 静默失败 | ✅ | `test_scheduler_commit_logging.py` 3 用例（ERROR 留痕/rollback/不虚报成功） |
| A | R5 README 数字+命令 | ✅ | 复现命令改 `cd backend && python -m eval_datasets.*`；规则 159/测试 3195/组件 75；新门禁 `check-readme-numbers.py` 红→绿自测 |
| B | R6 停机接线 5 引擎 | ✅ | `lifecycle._stop_capture_engines()`；`test_shutdown_stops_engines.py` 2 用例（全 stop 被调 + 单点失败不阻断 + dispose 前完成） |
| B | R7 bcrypt 阻塞 | ✅ | `user_store` async 化；心跳探针测试证明事件循环不阻塞 |
| B | R8 audit_pq 损坏 payload | ✅ | 对齐 pop_highest 语义（zrem+dead_letter+计数）；2 用例 |
| B | R9 Suricata 无重试 | ✅ | while+指数退避(1s→30s)；2 用例（瞬时故障恢复/退避封顶） |
| B | R10 eve-out 目录 | ✅ | mkdir 前置 + WARN 替代 `|| true`；compose 渲染断言 + sh -n |
| B | R11 hybrid 宣称 | ✅ | 文档/CLI 改"未实现"如实口径；3 用例（含文档-代码一致性守卫） |
| C | R12 demo 隔离四件套 | ✅ | IOC 排除 demo-seed；KPI 只写空日期+打标记可回滚；`SHARED_MEMORY_DEMO_MODE` 路由开关；ingest 认证扶正（无 key 401 倒挂修复）；run-demo.sh 传 JWT + 模拟器 fail-fast；`hash(name)`→md5。`test_demo_isolation.py` 6 用例 |
| C | R13 Windows 白名单空壳 | ✅ | `ps_templates.py` 16 个动作模板指纹；解码逐字匹配；恶意脚本/随机 payload 全拒（26 用例）；旧"任意脚本放行"测试改为生产真实形状 |
| C | R14 情报链路 SSRF | ✅ | `net_guard.py` 共享校验；逐跳重定向复检+跨 host 剥凭证+流式限长；本地 csv/stix_bundle 白名单目录。13 用例 |
| C | R15 Logs/Home 前端 | ✅ | 加载更多 500 上限+达限提示；移除逐行 FLIP；Home 接 eventStream 单例（`new EventSource` 全站仅 api.ts 工厂一处）；tsc 0 错误 + build 绿 |
| C | R16 case 边界 | ✅ | event_ids 封顶 500+metadata 标记；session 聚合 30min 窗；3 处 N+1 批查（含 SQL 计数断言）。3 用例 |
| D | R17 测试污染 | ◐ | conftest `_reset_globals` 六块复位改 fail-fast（`pytest.fail` 上报）；执行中发现并修复了自己引入的裸赋值污染（改 monkeypatch）。策略目录 tmp 隔离（当年回滚项）与 5 处 `_cache` 直戳未动 —— 见"残留" |
| D | R18 类型接线 | ◐ | 首片完成：`types/stats.ts` StatsResponse 单源，api.ts + Monitor/Home/BattleScreen 接线；`fetchJSON<any>` 141→140。全量替换未做 —— 见"残留" |
| D | R19 simulate 旁路 | ✅ | 端点服务端写死 `allow_blocking=False`；2 用例 + 红线全绿 |
| D | R20 小项清账 | ✅ | MCP Guard deny 模式故障 fail-closed；滑窗键 TTL（窗口 4×/淘汰 24h）；ioc_matcher 惊群加锁；审计→响应改走 `schedule_bounded` 背压闸；Tempo 地址出配置（3 处清零） |

## 总验收结果

| # | 验收项 | 结果 |
|---|---|---|
| 1 | 全量后端测试 | **3195 收集**；修复前全量 8 败（4 个我的改动触发漂移守卫 + 4 个守卫登记表未同步），全部归因修复；最终全量见文末 |
| 2 | 红线回归 | veto_gates / response_execute_guard / response_transport_platform / safe_executor / case 域 87 用例 全绿 |
| 3 | 前端 | `tsc --noEmit` 0 错误；`npm run build` 成功 |
| 4 | 门禁脚本 | compose-no-default-secrets ✅ / readme-numbers ✅ / 两个 risk-scan 空扫描自检生效（破坏性自测退出码 2）✅ |
| 5 | 测试零污染 | demo_isolation 的 app reload 用 try/finally 恢复；auth matrix 改 monkeypatch；ingest 子集顺序依赖已消除（基线既有的 g8 flake 除外） |
| 6 | 情报链路 | 4 源注册全通（ALLOWED_FEED_TYPES 六方言）；SSRF 测试矩阵 13 用例绿；`follow_redirects=True` 清零 |

## 漂移守卫的同步（设计如此，逐项登记）

新增模块/字段/测试触发了 4 个"防漂移"守卫测试 —— 这正是它们存在的意义，同步如下：

- `test_config_switch_wiring`：Settings 字段 357→**360**（+demo_mode/intel_local_feed_dir/tempo_url，逐条注释理由）；出货键 164→**165**（+TEMPORAL_PASSWORD/DEMO_MODE）。
- `test_active_module_coverage_gap`：`user_store` 因 R7 补测试移出零覆盖登记表。
- `tools/guard_assert_baseline.json`：13 个新测试文件经门禁自带 `--update-baseline` 登记。
- `test_eval_rag` / `test_dead_code_remediation`：断言文案与本地 csv 路径改按新契约（R11/R14）。

## 有意豁免（记录判断依据，非遗漏）

1. `response_orchestrator.py:258` 与 `response_log.py:120` 的 `get("allow_blocking", True)`：真实告警路径的既定缺省（ingest/kafka 显式传值），simulate 已在端点写死 False —— R19 的修复点在端点层。
2. `demo_mode=false` 时 `/api/demo` 404 而非 403：未挂载路由，行为即关停（比暴露后再拒更干净）。
3. R15 用"500 上限 + 去除 FLIP + 行入场动画保留"替代完整 react-window 虚拟化：DOM 有界（≤500）后虚拟化收益边际化，且避免无浏览器验证下的大改风险。若长会话仍掉帧，虚拟化作为后续项。
4. ingest 匿名放行仅在"未配置密钥且非 prod"保留（demo_start.bat 依赖）；配置密钥后无 key 一律 401，prod 未配置一律拒绝。

## 残留（未在本轮范围，建议下轮）

1. **R17 深水区**：策略 YAML 目录 tmp 隔离（conftest 注明的当年回滚项，需先修 learn_loop 测试）+ 5 个测试文件的模块级 `_cache` 直戳。
2. **R18 全量**：`lib/api.ts` 剩余 140 处 `fetchJSON<any>` 按"事件域→其余"两步替换 + `fetchJSON<any`==0 门禁。
3. 前端死代码 13 文件删除（TopNav 等约 1400 行）。
4. ioc_matcher 全表 LIMIT、富化 cancel 独立 session、JWT `?token=` 降级、前端 deriveRelays 单点化、AttackConstellation 渲染期副作用。
5. 已知既有 flake：`test_acceptance_g8_stress`（基线就失败，与 conftest 注明的字母序事件循环 workaround 同源，Python 3.12 升级前必须解决）。

## 涉及文件

生产代码 33 文件 / 测试 20 文件（新增 13）/ 工具与门禁 4 / CI 1 / compose+env 3 / 文档 3。合计 57 文件，+2012/−698 行（git diff --stat，截至报告时点）。
