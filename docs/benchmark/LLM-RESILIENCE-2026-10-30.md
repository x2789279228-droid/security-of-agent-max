# LLM-RESILIENCE 2026-10-30 —— G 路线：LLM 依赖韧性故障注入矩阵

> 测试：`backend/tests/test_llm_resilience_matrix.py`（10 项，全部通过）
> 现场数据：A3 批次实测的 LLM 供应商 429 风暴（2026-10-30 live 栈）
> 架构事实（如实）：平台是**降级语义**——故障不切换备模型（无 llm_backup 热切换），
> 而是返回结构化 fallback 标记（`agents/llm_fallback.py` 判定）+ 可重试事件重新入队
> + tier 分级短路；缓存命中在预算/上游闸门**之前**，故障期不被饿死。

## 1. 五类故障矩阵（mock 注入 httpx 层，逐项断言终态/重试语义/时延上界/调用数）

| 故障 | 处理路径 | 终态（fallback JSON） | retryable | 上游调用数 | 时延上界（断言） |
|---|---|---|---|---|---|
| **429 限流** | 1 次短重试（尊重 Retry-After，默认窗 1s）后放弃 | `rate_limited_429` | **True**（可重新入队） | 2（首发+1 重试，不无限打） | < 1s |
| **超时** | `httpx.TimeoutException` 直捕，不重试（P2-E-2） | `llm_request_timeout` | True | 1 | < 5s（分段超时：connect 快速失败，不受 90s read 拖累） |
| **无效 key（401）** | 通用异常路径：3 次指数退避+全抖动重试后兜底 | `LLM调用失败` fallback | False（兜底） | 3-4 | 退避可控（测试注入 0.01s 步长） |
| **断网（ConnectError）** | 同上 3 次退避 | 同上 | False | ≥3 | 同上 |
| **模型下线（404）** | 同上（非 5xx 快速路径） | 同上 | False | ≥3 | 同上 |
| （附）**上游 5xx** | **不重试立即放弃**（防重发打死刚恢复的上游） | `upstream_5xx` | False | 1 | 立即 |

## 2. 防护闸门（故障前的三道本地闸，零上游成本）

| 闸 | 触发 | 行为 | 测试 |
|---|---|---|---|
| 无 key | `llm_api_key` 空 | `LLM未配置` fallback，**0 次上游调用** | ✅ |
| 预算尽 | `cost_tracker.is_over_budget` | `预算已用尽` fallback；**P0 tier 不短路**（分级保留高优） | ✅（tier 短路语义：预算尽→P2 短路/P0 放行；预算余→全放行） |
| 本地槽/限流 | llm_limiter | `llm_slot_timeout`/`llm_rate_limited`，retryable | （limiter 既有测试覆盖） |

## 3. 缓存路径（故障期间的零成本命中）

- 成功响应缓存后**同 prompt 第二次零上游调用**（Redis 主源 + 本地 dict 快速路径）✅
- **上游已 429 时缓存仍可达**：缓存查询在预算/上游闸之前——门禁不饿死缓存（故障期免费命中）✅

## 4. 现场数据：2026-10-30 live 栈 429 风暴（A3 批次实测）

- 供应商（MiniMax API）在持续审计负载下进入 429 风暴：`httpx 429 Too Many Requests` 连续出现，
  重试链`LLM rate-limited (429), short retry`；
- **影响面实测**：leader 审计车道跌至 **1-2 eps**（正常 8.4+），并把双 worker 吞吐测量污染成
  0.67×（后经配对复测澄清为测量污染，健康条件 2.08×，见 REMEDIATION-PLAN A3 行）；
- **韧性表现**：风暴期间 **spill→`security-audit-overflow`→重启回灌零丢失**（账目闭合 PG 精确）、
  embedding 失败退化为全零向量并显式告警"检索不可用"（不静默假数据）、平台不停摆；
- 运维结论：429 是**共享配额资源**——多 worker 不增加 LLM 吞吐，反而加剧风暴；风暴期
  P0/P1 依赖 `retryable` 重新入队消化，P2/P3 走 tools_only 车道不受影响。

## 5. 复现

```bash
cd backend && python -m pytest tests/test_llm_resilience_matrix.py -q   # 10 passed
```
