#!/bin/bash
# ════════════════════════════════════════════════════════════════
# live 演练 — 目标机初始化 (在被保护 Linux VM 上以 root 运行一次)
#
# 做四件事:
#   1. 允许平台管理 IP 永不受封禁影响 (防自锁, 必须最先做)
#   2. 创建受限响应账号 soc-fw: 仅免密 sudo iptables/ip6tables
#      (平台 command_whitelist 只放行 iptables 系命令 + ssh_firewall
#       只对 iptables 前缀加 sudo —— 双向最小权限)
#   3. 配置 rsyslog 把 auth 日志转发到平台 syslog-adapter (UDP 514)
#   4. 自检: 模拟一条 Failed password 日志, 验证转发链路
#
# 用法:
#   PLATFORM_IP=10.0.0.10 ADAPTER_IP=10.0.0.10 bash target-setup.sh
#   # PLATFORM_IP: 平台后端所在 IP (容器宿主机), 同时是 iptables 白名单对象
#   # ADAPTER_IP:  syslog-adapter 监听 IP (通常与 PLATFORM_IP 相同)
# ════════════════════════════════════════════════════════════════
set -euo pipefail

PLATFORM_IP="${PLATFORM_IP:?必须设置 PLATFORM_IP (平台后端 IP)}"
ADAPTER_IP="${ADAPTER_IP:-$PLATFORM_IP}"
FW_USER="${FW_USER:-soc-fw}"

say() { echo "[target-setup] $*"; }

[ "$(id -u)" = "0" ] || { echo "必须以 root 运行"; exit 1; }

# ── 1. 平台管理 IP 白名单 (防自锁: 平台 SSH 管理通道永不被封) ──
say "白名单平台管理 IP ${PLATFORM_IP} (INPUT #1)"
iptables -I INPUT 1 -s "${PLATFORM_IP}" -j ACCEPT -m comment --comment 'SOC-MGMT-WHITELIST'
command -v ip6tables >/dev/null && ip6tables -I INPUT 1 -s "${PLATFORM_IP}" -j ACCEPT -m comment --comment 'SOC-MGMT-WHITELIST' || true

# ── 2. 受限响应账号 ──
say "创建响应账号 ${FW_USER} (仅 iptables 免密 sudo)"
id "${FW_USER}" &>/dev/null || useradd -m -s /bin/bash "${FW_USER}"
IPT_P="$(command -v iptables)"; IPT6_P="$(command -v ip6tables || true)"
cat > "/etc/sudoers.d/soc-fw" <<EOF
${FW_USER} ALL=(root) NOPASSWD: ${IPT_P}
${FW_USER} ALL=(root) NOPASSWD: /usr/sbin/iptables
${FW_USER} ALL=(root) NOPASSWD: /usr/sbin/ip6tables
EOF
chmod 440 "/etc/sudoers.d/soc-fw"
visudo -c >/dev/null || { echo "sudoers 语法错误, 回滚"; rm -f "/etc/sudoers.d/soc-fw"; exit 1; }

# ── 3. rsyslog 转发 auth 日志 ──
say "配置 rsyslog → udp:${ADAPTER_IP}:514"
mkdir -p /etc/rsyslog.d
cat > /etc/rsyslog.d/60-soc-forward.conf <<EOF
# SOC live-drill: auth 相关日志全部转发平台 syslog-adapter
auth.*,authpriv.* @${ADAPTER_IP}:514
EOF
systemctl restart rsyslog 2>/dev/null || service rsyslog restart || { echo "rsyslog 重启失败"; exit 1; }

# ── 4. 链路自检 ──
say "注入一条测试日志验证转发 (logger -p authpriv)"
logger -p authpriv.notice "soc-drill selftest $(date +%s) - 链路自检, 非攻击"
sleep 1
say "完成。后续在平台侧执行 preflight.sh 验证端到端可见。"
say "注意: 平台 SSH 封禁通道将用 ${FW_USER} 登录本机, 需要配置公钥或口令"
say "      (见 README.md『目标机凭证』一节; 不要使用 root 直接登录)"
