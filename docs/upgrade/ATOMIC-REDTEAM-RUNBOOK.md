# Atomic Red Team 检出对账 Runbook（路线 1）

> 目标：把"检测是复述模拟器标签"修成"检测面对真实攻击行为"。
> 每执行一个 Atomic，平台收到的是**真实系统事件**（Sysmon 进程/网络/注册表），
> 检出与否由 `evaluate_attack_coverage.py` 对账——这是答辩时"检测还是复述"
> 问题的直接证据。

## 0. 安全纪律（不可妥协）

1. **只在测试虚机执行**。runner 写死了三道闸：默认 plan 模式、
   `--execute-local` 显式开关、`ATOMIC_I_AM_ON_A_TEST_VM=yes` 环境变量
   自我声明 + 生产形态 .env 标记检测。
2. **执行前必须做 VM 快照**——首批 Atomic 包含计划任务/账户创建等真实改动。
3. **零外网 C2**：首批 8 个技术全部走本地/内网资源（127.0.0.1 / 内置命令），
   不需要也禁止连接真实 C2。

## 1. 测试 VM 准备（一次性）

```
Windows 10/Server 2019+ 虚机（4C8G 足够）
├─ Sysmon：下载 Sysmon 15.x，配 SwiftOnSecurity sysmon-config
│    sysmon -accepteula -i sysmonconfig-export.xml
├─ 采集：二选一
│    a) Winlogbeat → Kafka(edr-sysmon topic) —— 推荐生产形态
│    b) 仓库自带 tools/windows-log-collector.ps1 + /api/edr/ingest
├─ 账户：管理员 + 一个普通账户（T1136 用）
└─ 模块：Install-Module invoke-atomicredteam -Scope CurrentUser
         （remote 模式脚本依赖；local 模式可不用）
```

验收：Sysmon 服务运行中；`/api/edr_intel` 融合视图能看到 VM 的一条登录事件。

## 2. 执行三模式

```bash
# ① plan（默认，零风险）：打印执行计划
python tools/atomic-runner.py --manifest tools/atomic/manifest.json

# ② remote（推荐）：生成 invoke-atomics.ps1，人工拷到 VM 执行
python tools/atomic-runner.py --manifest tools/atomic/manifest.json \
    --mode remote --out ./atomic-out
#   VM 上: .\invoke-atomics.ps1  → 产出 ground-truth.jsonl 拷回平台侧

# ③ local（仅测试 VM，双保险开关）：
set ATOMIC_I_AM_ON_A_TEST_VM=yes
python tools/atomic-runner.py --manifest tools/atomic/manifest.json \
    --mode local --execute-local --out ./atomic-out
```

## 3. 对账

```bash
# 平台侧导出告警（时间窗覆盖执行期），然后：
python -m eval_datasets.evaluate_attack_coverage \
    --ground-truth ./atomic-out/ground-truth.jsonl \
    --alerts ./atomic-out/alerts-export.json \
    --out ../docs/benchmark --source-note "TEST-VM 2026-xx-xx 首批8技术"
```

- **技术命中**（强证据）：平台事件 techniques 字段含对应 T 编号；
- **主机+时间窗命中**（兜底）：无技术标签但主机与时间窗吻合
  （+60s/-600s 容差）——**这是弱证据，报告里分开列**，不能当强证据吹；
- 每个漏检 run 必须登记：known_gap → 候选规则 → 进路线 4 影子池。

## 4. 验收基线

- 首批 8 技术 100% 在融合视图产生 EDR 事件（接入面）；
- **≥60% 技术被平台确认检出**（技术命中或主机窗口命中）；
- 漏检 100% 登记 gap（检出率低的解释权在自己手里）；
- VM 快照回滚验证一次。

## 5. 扩面方向

- MITRE Caldera 编排多步链（当前 8 个单技术 → 链式攻击）；
- C2 类 Atomic 配本地 listener（Python http.server 即可）；
- 检出缺口对接 learn_loop 候选规则生命周期。
