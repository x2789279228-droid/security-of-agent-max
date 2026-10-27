# Suricata pcap 回放评测 — 真实 IDS 流量进平台

- 场景数: 1；三方对账: ✅ 全部一致

| 场景 | eve 行 | alert 行 | 接受 | 去重 | 平台事件 | 检出 |
|---|---|---|---|---|---|---|
| fixture-mixed-web-c2 | 10 | 6 | 5 | 1 | 5 | ✅ |

## 场景明细

### fixture-mixed-web-c2 (hand-authored EVE fixture (Suricata 8 官方 EVE schema))

- 期望类别: ['attempted-admin', 'command-and-control', 'web-application-attack']
- 观测类别: ['attempted-admin', 'command-and-control', 'web-application-attack']
- 事件类型分布: {'alert': 6, 'dns': 1, 'tls': 1, 'http': 1, 'flow': 1}
- 平台 techniques: 无
- sigma 命中规则: 无

## 口径声明

- IDS 告警类别级证据 = Suricata ET 规则本身；平台价值在: 接入不丢
  (三方对账)、与 sigma/ATT&CK 提取同链路、事件落库可查。
- 真实 pcap runbook 见模块 docstring；本报告 fixture 版用于钉住
  对账与映射语义，真实数据替换 eve 文件即可复用同一评测器。
