#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
# 发布净化脚本 — 防止密钥随交付包外泄
# ═══════════════════════════════════════════════════════════════════
#
# 为什么需要这个脚本
# ------------------
# .gitignore 正确忽略了 .env / certs/ / config/ssh/，git 也没有跟踪它们。
# 但【打包分发】走的是 zip/tar，不读 .gitignore ——
# 2026-10-03 审计发现 shared-memory-platform.zip 内含:
#   .env (5097B, 全部 API Key) / certs/kafka/*-key.pem + *.p12 (Kafka 全信任链私钥)
#   config/ssh/firewall_key (OpenSSH 私钥) / config/nginx/flink-credentials.txt (明文口令)
# 这些凭证一旦随包分发即视为已泄露，必须轮换。
#
# 用法
# ----
#   bash tools/release.sh <输出目录>            # 净化后的目录
#   bash tools/release.sh <输出目录> --zip      # 顺便打 zip
#   bash tools/release.sh --check <归档文件>    # 只校验某个归档是否含密钥（CI 用）
#
# 退出码: 0=干净  1=检出密钥（发布中止）

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# ── 必须排除的路径（相对 REPO_ROOT）──
EXCLUDE_PATHS=(
  ".git"
  ".pytest_cache"
  ".reasonix"
  ".idea"
  ".vite"
  "backend/__pycache__"
  "backend/.pytest_cache"
  "frontend/node_modules"
  "frontend/dist"
  ".env"
  ".env.*"              # .env.demo / .env.eval-bak 等派生副本
  "certs"
  "config/ssh"
  "config/nginx/flink-credentials.txt"
  "config/nginx/flink.htpasswd"
  "config/kafka/kafka_jaas.conf"
)

# ── 绝不允许进入发布包的文件模式 ──
# 与 CI 的 leak-gate job 保持一致；新增规则请同时改两处。
SECRET_PATTERNS='(^|/)\.env($|\.)|(^|/)certs/|\.pem$|\.p12$|\.jks$|id_rsa|firewall_key|htpasswd$|flink-credentials|-creds$|known_hosts$'

# ── 白名单：命中模式但可以安全分发的条目 ──
# *.example 是刻意提交到版本库的文档模板（.env.example / .env.demo.example），
# 其中的值为占位符或非敏感配置（collection 名、阈值、网卡名、用户名等），
# 不含任何真实凭证。已逐条核对确认。
ALLOW_PATTERNS='\.example$|\.example\.[a-z]+$|/config/suricata/\.gitkeep$'

log()  { printf '  %s\n' "$*"; }
fail() { printf '\n[FAIL] %s\n' "$*" >&2; exit 1; }

# 从 stdin 读路径列表，输出"命中秘密模式但不在白名单"的条目
filter_hits() {
  grep -E "$SECRET_PATTERNS" | grep -Ev "$ALLOW_PATTERNS" || true
}

# ═══════════════════════════════════
# 模式 1: 校验一个已存在的归档/目录
# ═══════════════════════════════════
check_path() {
  local target="$1"
  [ -e "$target" ] || fail "路径不存在: $target"

  if [ -d "$target" ]; then
    log "扫描目录: $target"
    local hits
    hits="$(find "$target" -type f -print | sed "s|^$target/||" | filter_hits)"
  else
    log "扫描归档: $target"
    local hits
    # 兼容 zip；tar 用 tar -tzf
    local listing
    if [[ "$target" == *.zip ]]; then
      listing="$(unzip -Z1 "$target" 2>/dev/null || true)"
    else
      listing="$(tar -tzf "$target" 2>/dev/null || true)"
    fi
    [ -n "$listing" ] || fail "无法列出归档内容（需要 unzip 或 tar）: $target"
    hits="$(printf '%s\n' "$listing" | filter_hits)"
  fi

  if [ -n "$hits" ]; then
    printf '\n[FAIL] 归档/目录中检出疑似密钥条目:\n' >&2
    printf '%s\n' "$hits" | sed 's/^/    /' >&2
    printf '\n请确认这些文件确属运行时生成物（不应进版本库），并改用 tools/release.sh 生成发布包。\n' >&2
    printf '已分发的包必须视为已泄露 —— 请轮换对应凭证。\n' >&2
    exit 1
  fi
  log "未检出密钥条目 — 干净。"
}

# ═══════════════════════════════════
# 模式 2: 生成净化后的发布目录
# ═══════════════════════════════════
stage_clean() {
  local out="$1"
  [ -n "$out" ] || fail "用法: bash tools/release.sh <输出目录> [--zip]"

  case "$out" in
    "$REPO_ROOT"|"$REPO_ROOT"/*) fail "输出目录不能位于仓库内部: $out" ;;
  esac

  log "仓库根: $REPO_ROOT"
  log "输出到: $out"
  rm -rf "$out"
  mkdir -p "$out"

  # 复制全部内容后删除敏感路径。
  # 不用 rsync --exclude 是为了兼容无 rsync 的环境（CI 容器 / Git Bash）。
  log "复制中…"
  ( cd "$REPO_ROOT" && tar -cf - \
      --exclude-from=<(printf '%s\n' "${EXCLUDE_PATHS[@]}") \
      --exclude='*/__pycache__' \
      --exclude='*.pyc' \
      --exclude='.env' --exclude='.env.*' \
      . ) | ( cd "$out" && tar -xf - )

  # tar --exclude 对目录形态（如 ./certs）匹配不稳，这里再做一次显式清理
  for p in "${EXCLUDE_PATHS[@]}"; do
    [ -e "$out/$p" ] && rm -rf "$out/$p" && log "  排除 $p"
  done
  find "$out" -name '*.pem' -o -name '*.p12' -o -name '*.jks' 2>/dev/null | while read -r f; do
    log "  排除 (密钥文件) ${f#$out/}"; rm -f "$f"
  done

  log "净化完成。最终自检…"
  check_path "$out"

  local size
  size="$(du -sh "$out" 2>/dev/null | cut -f1)"
  log "发布目录就绪: $out ($size)"
}

# ═══════════════════════════════════
# 入口
# ═══════════════════════════════════
case "${1:-}" in
  --check)
    [ -n "${2:-}" ] || fail "用法: bash tools/release.sh --check <归档或目录>"
    check_path "$2"
    ;;
  -h|--help|"")
    sed -n '2,30p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    ;;
  *)
    stage_clean "$1"
    if [ "${2:-}" = "--zip" ]; then
      log "打包 zip…"
      ( cd "$(dirname "$1")" && zip -qr "$(basename "$1").zip" "$(basename "$1")" )
      check_path "$1.zip"
      log "发布包: $1.zip"
    fi
    ;;
esac
