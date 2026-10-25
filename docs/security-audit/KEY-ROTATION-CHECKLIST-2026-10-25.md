# 凭证轮换检查单 — 2026-10-25

> 依据:`docs/AUDIT-2026-10-03-全量功能审计报告.md`。2026-10-03 前分发的交付 zip
> 内含真实凭证,按"分发即泄露"原则全部视为已泄露。**轮换是人工动作**(需登录外部
> 控制台),本清单把它变成可勾选、可验证的步骤。全部勾完前,不建议向外部人员
> 分发任何新交付包。

## 优先级 P0 — 直接可登录生产面的凭证

- [ ] **MiniMax LLM API Key**(`.env: SHARED_MEMORY_LLM_API_KEY`)
  1. 登录 MiniMax 开放平台 → API Key 管理 → 撤销旧 key → 签发新 key
  2. 更新演示机 `.env`(仅演示机本地,不进 git)
  3. 验证:平台发起一次真实 LLM 审计,`/metrics` 中 LLM 请求计数 +1
  4. 旧 key 撤销后用旧 key 调用应返回 401(留截图进答辩证据包"密钥治理"页)

- [ ] **Embedding API Key**(`.env: SHARED_MEMORY_EMBEDDING_API_KEY`)同上流程

- [ ] **JWT Secret**(`.env: SHARED_MEMORY_JWT_SECRET`)
  - 换成 `openssl rand -hex 32` 生成的新值;轮换后所有旧 token 失效(预期行为)
  - 验证:轮换前签发的 JWT 访问 `/api/logs` 应 401

- [ ] **防火墙 SSH 私钥**(`config/ssh/firewall_key`,zip 中已泄露)
  ```bash
  # 在响应目标机上:
  rm ~/.ssh/authorized_keys 中旧公钥行
  ssh-keygen -t ed25519 -b 521 -f config/ssh/firewall_key_v2   # 新密钥对
  # 公钥入 target 机 authorized_keys,私钥路径更新到 .env SHARED_MEMORY_FW_SSH_KEY
  ```
  - 验证:新私钥可 SSH 目标机;旧私钥被拒(Permission denied (publickey))

## 优先级 P1 — 服务间凭证

- [ ] **Kafka 全信任链**(ca-key.pem / broker-key.pem / client-key.pem / *.p12,zip 已泄露)
  - 用 compose 内 cert 生成流程重签三件套;同步 SCRAM 口令
  - 验证:`docker compose exec kafka kafka-topics --list` 用新 client 证书成功
- [ ] **PostgreSQL / Redis / Grafana / MISP 口令**(POSTGRES_PASSWORD 等)
  - compose 修改后 `docker compose up -d` 重建;验证健康检查全绿
- [ ] **Flink Dashboard 明文口令**(flink-credentials.txt / flink.htpasswd)

## 优先级 P2 — 流程防再犯

- [ ] 分发一律走 `bash tools/release.sh <dir> --zip`(净化+自检),禁止手工 zip
- [ ] CI leak-gate 已升级为完整 PEM 块扫描(`tools/scan-private-key-history.py`),
      新增密钥类文件名规则时需同步 `tools/release.sh` 的 SECRET_PATTERNS

## 完成判据

以上 P0 全部勾选且验证通过后,在本文件顶部追加一行:
`轮换完成于 <日期>,执行人 <姓名>,验证截图见 docs/drill/evidence/`
