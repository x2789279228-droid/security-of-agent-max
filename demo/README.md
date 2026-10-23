# 5 分钟演示脚本

> 目标：用一条命令注入确定性攻击场景，然后按固定路线展示
> **接入 → 审计 → 建案 → 审批 → 响应 → 复盘 → 能力证据**。

## 前置

```powershell
# 1) 启动核心栈（默认 dry_run，不会真实封禁）
docker compose up -d

# 2) 打开前端（prod 覆盖是 3001；dev 覆盖是 3004）
#    后端 API 默认 http://localhost:8001
```

## 运行

```powershell
# 注入场景并打印验证清单
.\demo\run_demo.ps1

# 同时打开浏览器
.\demo\run_demo.ps1 -OpenBrowser
```

脚本会调用 `tools/generate_test_feed.py --inject`，生成：

- 暴力破解：同源 24 连败 + 1 成功；
- C2 beacon：失陷内网主机 → 外部 C2；
- Web 攻击：命令注入 / WebShell；
- 良性噪声：验证不会误封。

## 演示路线

| 步骤 | 页面 | 看什么 |
|---|---|---|
| 1 | Monitor | 实时事件带出现注入事件 |
| 2 | SecurityAudit | 输入脚本输出的 Session ID，查看 Decomposer→ToolBuilder→Executor→Reviewer 四阶段、证据与判定 |
| 3 | Operations → 案例/工单 | 高/严重事件自动建案并派生 disposition 工单 |
| 4 | Response | 手动 `block_ip` 返回 **403**（HIGH 必须审批）；审批通过后才执行；回滚幂等 |
| 5 | Operations → 复盘 | 事件时间线、误报反馈、规则建议 |
| 6 | Capabilities | verified / experimental / disabled 三档 + 证据路径 + 最后验证日期 |

## 真实响应（仅限隔离靶场）

默认 `SHARED_MEMORY_EXECUTION_MODE=dry_run`。只有在隔离靶场才显式开启：

```bash
SHARED_MEMORY_EXECUTION_MODE=live
SHARED_MEMORY_FW_SSH_HOST=<靶机>
SHARED_MEMORY_FW_SSH_USER=<用户>
SHARED_MEMORY_FW_SSH_KNOWN_HOSTS=/tmp/ssh/known_hosts   # 必须预置
```

**不要**在生产打开 `*_ALLOW_UNKNOWN_HOST`。演示前先在一台一次性靶机上验证
TTL 自动解封与回滚。

## 讲解要点（可信度）

- 这不是“功能列表”：每一步都有对应测试或证据文档（`docs/upgrade/evidence/`）。
- Sigma 指标是**合成标定集**，报告里明确写了 50% 真阳性来自上游分类器复述；
  不把合成集数字冒充生产数据。
- 异常检测当前可行阈值区间为空，Capabilities 里标为 `experimental`；
  不宣称“已解决”。
- 响应默认 dry_run；HIGH/CRITICAL 手动直执行 403；审批、幂等、post-validate、
  TTL 都有测试。
