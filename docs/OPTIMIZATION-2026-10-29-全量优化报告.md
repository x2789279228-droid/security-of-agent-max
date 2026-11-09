# 全量优化执行报告（2026-10-29）

目标：健壮性 / 可用性 / 代码质量三线推进。承接《REMEDIATION-EXECUTION-2026-10-29》的残留清单并扩展至复审清单未修 P2/P3。

## Wave 1 — 后端健壮性（6 项全部完成）

| 项 | 内容 | 验证 |
|---|---|---|
| 事件循环地雷根治 | 生产 3 处（audit_trail/source_registry/transport）+ 测试 3 处隐式 `get_event_loop()` 全部改 `get_running_loop()`/`asyncio.run()`；conftest 的字母序 workaround **移除**（保留拆除记录注释） | 经典污染对（audit_cache+inc_edr+ingest_wrapper+g8+dead_code）38 用例全绿；**历史 flake test_acceptance_g8_stress 在全量顺序下首次通过**；Python 3.14 升级障碍消除 |
| 策略 YAML 测试隔离（P0-2 残留，两年未修） | conftest 改为**会话级单一副本**（当年回滚因用了每测试独立 tmp；本次语义与共享仓库目录一致） | 策略域 142 用例全绿；`git status` 对 policies/*.yml 与 taxonomy.yml **零污染** |
| 单例缓存测试治理 | `summary.llm._response_cache` 两处 `.clear()` → `monkeypatch` 换新 dict（自动还原）；**审计误报修正**：event_store/capability_tile/inc_threat_intel 三文件实为局部新实例，非污染源（已注记） | llm_cache 5 用例绿 |
| ioc_matcher 上限 | `_load_from_db` 加 `ORDER BY last_seen DESC LIMIT 50000` + 超限告警 | demo_isolation+intel_enrichment 18 用例绿 |
| 富化 cancel 隔离 | `enrich_event_if_enabled` 的 `wait_for` 协程强制开独立短生命周期 session（超时 cancel 不再可能毒化调用方共享 session） | 同上 |
| jti 有界 + JWT 日志 | `_user_jtis` 每用户 64 上限（超限丢旧）；backend Dockerfile `--no-access-log`（自研中间件仅记 path，SSE `?token=` 不再落容器日志） | auth 域 29 用例绿 |
| 四项语义修正 | ① 登录时序侧信道：用户不存在时跑同 cost 哑 bcrypt，两分支耗时一致；② http_parser 遍历正则补 `%2e%2e%5c`/`..%2f`/`%2e./`/`%c0%ae`；③ `query`→dns_query 加 DNS 语境门禁（事件类型/DNS 专属键/域名形态三判据，SQL/HTTP 日志不再误入）；④ sigma 哈希按算法路由（键名或 hex 长度 64/40/32 → 对应目标字段，不再一对全写） | 新增 test_dns_query_gating 5 用例 + mapping/sigma 183 用例 + login/bruteforce 9 用例全绿 |

## Wave 2 — 前端质量（全部完成）

| 项 | 内容 | 验证 |
|---|---|---|
| 死代码清除 | 13 组件 + useTilt 共 **14 文件删除**（TopNav/LearnLoopTab/ShiftOrbit/BrandPanel/RegisterForm/PipelineStrip/Chip/DutyTape/GlassPanel/SplittingText/StatusDot/SurfacePanel/TiltCard/useTilt；删除前逐一复核零 import，含"边改边死"的 TopNav） | tsc 0 错误 |
| 类型棘轮 | `logsEvents` 类型化为共享 `SecurityLog[]`（fetchJSON\<any\> 141→139）；新门禁 `check-frontend-any.py`：any 只许降不许升（上限 139）+ `new EventSource` 单点持有（api.ts 工厂外禁现）挂入 CI frontend-check | 破坏性自测红→绿 |
| Monitor 过滤缓存 | 搜索的 `JSON.stringify` 结果按事件 id 缓存（4096 条 LRU 式清空）——修复前每次 flush 对 500 条全量序列化（高压 ~20 次/s 的 CPU 热点） | tsc/build 绿 |
| deriveRelays 单点化 | `deriveRelaysMemo` 模块级 memo：同一 buffer 引用只派生一次，Monitor/AgentRelayStrip/ActiveRelayCards 三处消费共享（原 3×O(500)/flush） | tsc/build 绿 |
| AttackConstellation 三项 | ① 节点外观参数改 **key 种子确定性 PRNG**（mulberry32，StrictMode 双渲染一致，删除渲染期 Math.random 脆弱模式）；② `edgeFxRef` 2000 上限裁剪至 500（对照 settledRef 纪律）；③ rAF 隐藏/移出视口**停表**（不再每帧空转自调度），visibility/intersection 回调重启，卸载时 cancelAnimationFrame | tsc/build 绿 |

## Wave 3 — 可用性（全部完成）

- **healthcheck**：backend（python urllib 探 `/api/health`，公开路径零依赖）、frontend（busybox wget）、temporal-worker（进程存活）→ compose 健康探测 6→**9 服务**（含既有 kafka/pg/redis 等）；`docker compose config` 渲染断言通过。
- **镜像钉版**：`nginx:alpine`→`nginx:1.27-alpine`；infinity 的 latest 显式注明"生产必须 INFINITY_IMAGE 钉 tag"（不猜上游 tag 名）；cape 保持"演示勿启用"注释。
- **INDEX.md 死链**：指向被 gitignore 的 `security_audit_report.md` 改为文字说明。
- **ruff 覆盖 tools/**：`--isolated --select E9,F,UP`（语法/未定义名/未用导入），修 7 处未用导入后挂入 CI——tools 目录此前零 lint 零测试（硬编码路径假门禁的温床）。

## 总验收（全部通过）

| 验收项 | 结果 |
|---|---|
| 后端全量 | **3121 passed / 0 failed**（3200 collected，34 skipped + 47 xfailed；9 分 26 秒）——含历史 flake g8 在全量顺序下通过 |
| 前端 | tsc 0 错误；`npm run build` ✓；lint 0 errors（65 warnings 既有） |
| 门禁全绿 | compose-no-default-secrets / readme-numbers（规则 159、组件 63、测试 3200）/ frontend-any 棘轮 / 两个 risk-scan 空扫描自检 / tools-ruff |
| 测试零污染 | 策略 YAML 工作区零改动（会话副本）；断言基线 14 个未跟踪测试文件已登记 |
| 漂移守卫同步 | Settings 字段数断言与组件数/测试数 README 已随动 |

## 量化

- 变更：93 文件，+2287/−2186（含上一轮四批修复，均为未提交工作区状态）。
- 前端组件 75→63（-14 死文件）；`fetchJSON<any>` 141→139 且棘轮锁定。
- 测试 3195→3200（+5 dns 门禁；删 0）。
- compose 健康探测 6→9 服务；uvicorn access log 不再含 JWT。

## 残留（下轮）

1. api.ts 剩余 139 处 `fetchJSON<any>` 按棘轮逐步归零（每归一处调低上限）。
2. `/metrics` 无认证、EDR ingest/audit-llm 流水线的角色细分（复审 P3-5/6）。
3. MCP 审批工单 TTL/持久化（P3-7）；flink/temporal 全家 healthcheck。
4. `focusStore` 脉冲致 Logs 整页重渲染（需行级 memo 拆分，动 Logs 表格结构，建议与虚拟化一并做）。
5. deploy.yml `if: false` 未启用（启用时需实跑 scp/ssh 序列验证）。
