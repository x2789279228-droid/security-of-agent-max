# live 真机攻防演练套件

> 目的:把 SOAR 响应链从"代码存在、默认 dry_run"变成**有完整证据链的真机事实**
> ——真实 SSH 爆破 → SIG-012 原始文本聚合检出 → live iptables 封禁攻击源 →
> TTL 自动解封,全程探测数据与平台动作留痕归档。
> 这是 capabilities.yaml 中响应类能力从 experimental 升 verified 的证据来源。

## 拓扑

```
┌──────────────┐   SSH 爆破(真实认证失败)   ┌──────────────────┐
│  攻击机 VM    │ ────────────────────────→ │  目标机 VM         │
│  (运行本套件) │      tcp/22               │  sshd + rsyslog   │
└──────┬───────┘                           │  iptables         │
       │ [被 DROP 后探测全断]               └────────┬─────────┘
       │                                            │ auth.log UDP/514
       │            ┌──────────────────┐            ▼
       │            │ 平台 (docker)     │ ←─ syslog-adapter.py
       └────────────│ SIG-012→策略→SOAR │
       查询 API/证据 │ block_ip 经 SSH  │ ──── SSH(soc-fw 账号) ───→ 目标机 iptables
                    └──────────────────┘
```

角色分工:
- **攻击机**(Kali/任意 Linux,python3.9+):运行 `run_live_drill.py` 与 `attacker-bruteforce.py`
- **目标机**(Linux):被保护对象,跑一次 `target-setup.sh`
- **平台**:docker compose 全栈(云服务器或本机),`.env` 打开 live

## 授权边界(答辩会被问,必须能答)

- 目标机与攻击机均为**自己名下的实验虚拟机**,网络自建自管;
- 攻击内容仅为**SSH 口令认证失败**(单线程、固定错误口令、秒级间隔),无利用 payload;
- 对应 `docs/competition-materials/02-合规声明.md` 的自建实验环境条款;
- `run_live_drill.py` 内置硬断言:目标必须 RFC1918 私网,公网目标需显式
  `DRILL_ALLOW_PUBLIC=1` 且另附书面授权 —— 防止脚本被误用出实验室。

## 目标机凭证

平台封禁通道通过 SSH 登录目标机执行 iptables(`ssh_firewall.py` 只放行
iptables 系命令,且仅对它们加 sudo)。两步:

1. 目标机上已由 `target-setup.sh` 创建受限账号 `soc-fw`(仅 iptables 免密 sudo);
2. 平台 `.env` 配置(私钥方式,推荐):
   ```
   SHARED_MEMORY_FW_SSH_HOST=<目标机IP>
   SHARED_MEMORY_FW_SSH_USER=soc-fw
   SHARED_MEMORY_FW_SSH_KEY=/run/secrets/fw_key        # 容器内路径,挂载私钥
   SHARED_MEMORY_EXECUTION_MODE=live
   ```
   首次连接前把目标机 host key 写入信任文件或临时设
   `SHARED_MEMORY_FW_SSH_ALLOW_UNKNOWN_HOST=true`(仅演练机,答辩环境建议关闭)。

## 运行步骤

```bash
# 0) 目标机(一次性):
PLATFORM_IP=<平台IP> bash target-setup.sh

# 1) 平台侧启动 syslog-adapter(收 UDP 514 → 平台):
python3 tools/syslog-adapter.py --soc http://127.0.0.1:8001 --port 514

# 2) 平台 .env 打开 live 并重启 backend,确认启动日志出现
#    "[Response] execution_mode=live —— 真实封禁/隔离已启用"

# 3) 攻击机:
export SOC_BASE=http://<平台IP>:8001 SOC_USER=admin SOC_PASS=***
export DRILL_TARGET=<目标机IP>
python3 run_live_drill.py
```

脚本自动完成:preflight(mode=live/fw 连通/baseline 可达)→ 临时启用
`POL-DRILL-BRUTE`(TTL 3min,结束自动复位,含失败路径)→ 真实爆破 →
轮询平台事件与响应动作 → 封禁中 3×TCP 探测(必须全断)→ 防火墙规则留痕 →
等 TTL 自动解封复测 → 证据落 `evidence/<ts>/`(探测 JSON、事件、动作、
防火墙规则、report.md)。

`--skip-attack`:爆破由攻击机手动执行(如需录屏演示攻击过程),编排器只观测取证。

## 演示时长控制

TTL 由 `POL-DRILL-BRUTE` 定为 3 分钟:封禁 → 现场讲解审计链/看 Grafana →
约 3 分钟后自动解封,节奏正好。生产策略 `POL-BRUTE-FORCE` 仍是 30 分钟,
演练结束策略自动复位,**禁止把 POL-DRILL-BRUTE 提交为 enabled: true**。

## 证据 → 答辩叙事对照

| 证据文件 | 回答的问题 |
|---|---|
| probe_baseline / probe_blocked / probe_after_ttl | "封禁是真的吗?" 前通后断后通 |
| events_seen.json(原始 Failed password 文本) | "检出是不是自己触发自己?" SIG-012 直接匹配原始日志 |
| response_action.json + 审计哈希链 | "自动封禁谁批的? 可追溯吗?" |
| firewall_rules.json(FW-RULE-xxxxx 注释) | "规则可精确定位/回滚吗?" |
| report.md 时间线 | 检出时延/封禁时延/TTL 时长,量化 SLA |
