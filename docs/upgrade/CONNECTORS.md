# CONNECTORS —— 开放生态连接器登记（REMEDIATION-PLAN 路线 I，2026-10-30）

> 定位：四类**零设备**连接器的接线方式与验证状态。每条给出接入命令与验收路径。
> 红线：状态列只写实测；容器化验证在本机完成，真机/Wazuh 集群部署留部署环境。

## I-1 通用 Webhook 连接器（入向 + 出向）

**入向**（外部系统推事件）：平台既有 `POST /api/logs/ingest`（X-API-Key + JWT 双轨，
R12 fail-closed）就是 webhook 入口 —— 无需新代码。验收：`curl -X POST .../api/logs/ingest -H "X-API-Key: <key>"` → 202 + PG 落行（A3 批 8 轮账目闭合已证）。

**出向**（响应动作回调）：`response_engine/transport` 已有 webhook 通道
（`send_alert` 动作 + URL 脱敏审计，整改报告 §9.63）。
验收路径：`POST /api/response/execute?action_name=send_alert&src_ip=...`（medium 级免审批）。

## I-2 osquery 接入（免费真实端点遥测）

osquery 容器（`kolide/osqueryd`）分布式查询结果 JSON 经 I-1 入向推送：

```bash
# 一次性查询示例（容器内）
docker run --rm kolide/osqueryi --json "SELECT pid,name,path FROM processes"
# 周期推送（osqueryd 配置 schedule + webhook logger 插件 → /api/logs/ingest）
```

**状态：设计接线（osquery 容器镜像未在本机拉取验证）**——入向通道本身已验证（同 I-1）。

## I-3 Wazuh 告警对接（开源 XDR 互操作）

Wazuh manager 容器（`wazuh/wazuh-manager`，免费）+ integrator 自定义 webhook
（`/var/ossec/etc/ossec.conf` 的 `<integration><hook_url>` 指向 I-1）。
Wazuh 告警 JSON（syscheck/rootcheck/sysmon 采集面）→ 平台 ingest → Sigma 链。

**状态：设计接线**——Wazuh manager 镜像 ~1GB，本批未拉取（部署环境验证项）。
互操作价值：Wazuh 的 3000 规则检出经平台 ingest 后与 1675 条 Sigma 面**并联分诊**
（P2 tools_only lane，无 LLM 成本）。

## I-4 Shuffle SOAR 双向

- Shuffle webhook trigger → 平台 `POST /api/response/approvals/{id}/approve`
  （admin RBAC + HMAC sig，2026-10-27 已接线）→ Shuffle 侧执行编排后的动作；
- 平台 `send_alert` → Shuffle webhook receiver（I-1 出向）。

**状态：协议面就绪（两端 webhook URL 均为标准 POST/JSON）**；编排剧本属部署侧内容。

## 验收总表

| 连接器 | 通道 | 本机实测 | 部署环境 |
|---|---|---|---|
| Webhook 入向 | /api/logs/ingest | ✅（A3 批 8 轮账目闭合） | — |
| Webhook 出向 | send_alert + transport | ✅（测试套件+审计脱敏） | — |
| osquery | I-1 入向复用 | ◐ 通道✅ / 镜像未拉 | 拉取+schedule 配置 |
| Wazuh | integrator→I-1 | ◐ 协议就绪 | manager 部署+hook 配置 |
| Shuffle | 审批 approve + send_alert | ◐ 协议就绪 | 剧本编排 |
