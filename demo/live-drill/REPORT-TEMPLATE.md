# live 真机演练报告 — <日期与编号>

> 归档位置:`docs/drill/DRILL-LIVE-<日期>.md`(连同 `evidence/<ts>/` 一起归档)。
> 本报告是 SOAR 响应能力 capabilities.yaml 升 verified 的配套证据。

## 1. 环境与拓扑

| 项 | 值 |
|---|---|
| 演练日期 | |
| 攻击机(攻击源 IP) | |
| 目标机 IP / OS | |
| 平台部署位置 | 云服务器 / 本机 compose |
| 平台版本 commit | |
| execution_mode | live(启动日志截图附后) |
| 封禁通道账号 | soc-fw(仅 iptables 免密 sudo) |

拓扑图:(贴 `demo/live-drill/README.md` 拓扑或自绘)

## 2. 演练时间线(以 evidence/<ts>/report.md 为准誊抄)

| 时刻 | 事件 | 证据 |
|---|---|---|
| T0 | 攻击开始(SSH 爆破 8 次) | attack.json |
| T1 | 平台收到首条原始 "Failed password" 事件 | events_seen.json |
| T2 | SIG-012 聚合命中 → 策略匹配 POL-DRILL-BRUTE | response_action.json |
| T3 | iptables DROP 下发到目标机(rule_id FW-RULE-xxxxx) | firewall_rules.json |
| T4 | 攻击源 3×TCP 探测全部超时(**金证据**) | probe_blocked.json |
| T5 | TTL 3min 到期,规则自动移除 | probe_after_ttl.json |
| T6 | 攻击源恢复连通(ok_count=3) | probe_after_ttl.json |

关键时延:T0→T1 = ___s(采集) / T1→T2 = ___s(检出) / T2→T3 = ___s(下发) / T3→T5 = ___s(TTL)

## 3. 检出独立性说明(防"循环论证"追问)

本次检出的锚点是 **SIG-012 对原始 syslog 文本的聚合匹配**
(`message contains "Failed password"` + src_ip 计数阈值),
与 syslog-adapter 的 BRUTE_FORCE 预分类相互独立:即使关闭适配器分类,
Sigma 聚合路径仍独立产生告警与响应。对照:
`backend/eval_datasets/detection_cases.py` 的 evidence_kind 设计
(raw_indicator vs event_type_only),本演练属于前者。

## 4. 人机协同(答辩演示点)

- 自动路径:POL-DRILL-BRUTE `auto_execute: true`,medium 以下自动执行;
- 审批路径:高危动作(block_ip 为 high)在手动直执行时被平台 403 拒绝
  (`routers/response.py`,"HIGH 不允许手动直执行"),必须走
  `/api/response/approvals` 队列由 admin 审批 —— 现场演示一次拒绝 + 一次审批通过;
- 回滚:按 rule_id 精确回滚(单测覆盖)+ TTL 自动解封(本次演练 T5 实证)。

## 5. 结论

- [ ] 封禁真实生效(攻击源视角连通性前后对比)
- [ ] 自动解封真实生效(TTL)
- [ ] 全程审计哈希链可导出(`audit_trail` 表快照附后)
- [ ] Grafana 时序截图(响应动作计数、封禁窗口)
- [ ] 录屏(3-5 分钟:攻击→检出→封禁→讲解→解封)

签署:演练人 ___ 日期 ___
