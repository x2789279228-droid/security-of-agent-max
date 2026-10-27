# soc-firewall: block_ip/SSH 封禁链路的真实靶标(alpine + iptables + sshd)。
# 2026-10-25 审计 #4: FW_SSH_HOST 一直指向这个不存在的 service, 封禁链路无目标。
# 仅限 compose 内网靶场 —— root 密码认证 + NET_ADMIN, 不得映射宿主端口或暴露公网。
FROM alpine:3.20

RUN apk add --no-cache iptables ip6tables openssh-server sudo bash \
    && mkdir -p /var/run/sshd

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22

ENTRYPOINT ["/entrypoint.sh"]
