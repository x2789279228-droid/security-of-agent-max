#!/bin/sh
# soc-firewall 入口: 配置 root 密码 + sshd + iptables 可用性自检。
# 密码经 compose 注入, 与 backend 的 SHARED_MEMORY_FW_SSH_PASSWORD 对齐。
set -eu

: "${FIREWALL_ROOT_PASSWORD:=***REMOVED-LEAKED-SECRET***}"
echo "root:${FIREWALL_ROOT_PASSWORD}" | chpasswd

# 靶场专用: root 密码登录(容器仅在内网, compose 不映射 22 到宿主)
cat > /etc/ssh/sshd_config <<'EOF'
Port 22
ListenAddress 0.0.0.0
PermitRootLogin yes
PasswordAuthentication yes
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
UsePAM no
Subsystem sftp internal-sftp
EOF

ssh-keygen -A
/usr/sbin/sshd

# FW_USE_SUDO=true 时 backend 会在命令前加 sudo; root 免密直通
echo "root ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/root-nopasswd
chmod 440 /etc/sudoers.d/root-nopasswd

if iptables -L -n >/dev/null 2>&1; then
    echo "[soc-firewall] iptables OK, sshd ready on :22"
else
    echo "[soc-firewall] WARN: iptables unavailable — compose 需 cap_add: [NET_ADMIN]" >&2
fi

# 前台保活; iptables 规则由 backend 经 SSH 动态增删
exec tail -f /dev/null
