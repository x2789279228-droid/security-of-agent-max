#!/bin/bash
# ════════════════════════════════════════════════════════════════
# 答辩演示总控 (C1) — 一条命令进入演出状态
#
# 流程: 起全栈(lite) → 等健康 → preflight 自检 → 灌演示种子 →
#       起持续攻击流量(log_simulator) → 打印大屏/监控入口
#
# 用法:
#   bash demo/run-demo.sh                 # 全流程
#   SKIP_PREFLIGHT=1 bash demo/run-demo.sh   # 跳过自检(赶时间彩排)
#   TRAFFIC_EPS=60 bash demo/run-demo.sh     # 调低演示流量
#
# 前置: Docker Desktop 引擎已就绪 (答辩机开机第一件事, 等鲸鱼图标变绿)
# 停演: bash demo/run-demo.sh stop
# ════════════════════════════════════════════════════════════════
set -uo pipefail
cd "$(dirname "$0")/.."

BACKEND="${BACKEND:-http://127.0.0.1:8001}"
FRONTEND="${FRONTEND:-http://127.0.0.1:8080}"
TRAFFIC_EPS="${TRAFFIC_EPS:-40}"

say()  { echo "[demo $(date +%H:%M:%S)] $*"; }
fail() { say "❌ $*"; exit 1; }

# compose 项目名: 仓库路径含中文, compose 无法从目录名推导 → 显式 -p soc
COMPOSE="docker compose -p ${COMPOSE_PROJECT:-soc}"

if [ "${1:-}" = "stop" ]; then
  say "停止演示流量与栈..."
  docker rm -f demo-traffic 2>/dev/null || true
  ${COMPOSE} --profile lite down
  say "已停止。"
  exit 0
fi

command -v docker >/dev/null 2>&1 || fail "需要 docker"
docker info >/dev/null 2>&1 || fail "Docker 引擎未就绪 —— 先开 Docker Desktop, 等鲸鱼图标变绿"

# ── 1. 起栈 (lite profile, 8GB 内存兜底) ──
say "=== 1/5 起全栈 (lite) ==="
${COMPOSE} --profile lite up -d || fail "compose up 失败"

# ── 2. 等健康 (最多 3 分钟) ──
say "=== 2/5 等后端健康 (最多 180s) ==="
ok=""
for i in $(seq 1 36); do
  if curl -sf "${BACKEND}/health" >/dev/null 2>&1 || curl -sf "${BACKEND}/api/health" >/dev/null 2>&1; then
    ok=1; break
  fi
  sleep 5
done
[ -n "$ok" ] || fail "backend 180s 未健康 — 跑 bash tools/preflight-check.sh 定位"

# ── 3. preflight 自检 (静态+运行时, 失败即停) ──
if [ "${SKIP_PREFLIGHT:-0}" != "1" ]; then
  say "=== 3/5 preflight 自检 ==="
  bash tools/preflight-check.sh || fail "自检未过 — 现场不要开始演示 (修法见 PERF 报告 8 阻断项表)"
else
  say "=== 3/5 跳过 preflight (SKIP_PREFLIGHT=1) ==="
fi

# ── 4. 演示种子 (案件/IOC/沙箱/工单 静态数据) ──
say "=== 4/5 灌演示种子 ==="
PW="$(grep -E '^SHARED_MEMORY_ADMIN_PASSWORD=' .env | tail -1 | cut -d= -f2- | tr -d '\r')"
TOK="$(curl -s -X POST "${BACKEND}/api/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"admin\",\"password\":\"${PW}\"}" | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')"
[ -n "$TOK" ] || fail "登录失败 — 校对 .env SHARED_MEMORY_ADMIN_PASSWORD"
curl -sf -X POST "${BACKEND}/api/demo/seed" -H "Authorization: Bearer ${TOK}" >/dev/null \
  && say "种子已灌 (demo_seed)" || say "⚠️ demo/seed 失败 — 后端需以 SHARED_MEMORY_DEMO_MODE=true 启动(R12 起演示路由按需挂载)"

# ── 5. 持续攻击流量 (后台容器, 多地域源 IP 池) ──
say "=== 5/5 起持续攻击流量 (≈${TRAFFIC_EPS} eps, 多地域源) ==="
INTERVAL="$(awk "BEGIN{printf \"%.4f\", 1/${TRAFFIC_EPS}}")"
docker rm -f demo-traffic 2>/dev/null || true
# R12: 传 JWT(匿名接入已 fail-closed); 不再全吞输出 — 启动失败时打印容器日志尾部
if [ -z "${TOK}" ]; then
  say "⚠️ 未取得 admin JWT — 演示流量无法通过数据源认证, 跳过流量注入"
else
  docker run -d --name demo-traffic --network host \
    -v "$(pwd):/workspace" -w /workspace python:3.11-slim \
    python log_simulator.py --mode continuous --interval "${INTERVAL}" \
    --api "${BACKEND}" --token "${TOK}" >/dev/null 2>&1 \
    && say "流量容器已起 (demo-traffic, interval=${INTERVAL}s)" \
    || { say "⚠️ 流量容器启动失败 — 最近日志:"; docker logs --tail 20 demo-traffic 2>&1 || true; }
fi

say ""
say "═══════════════ 演出就绪 ═══════════════"
say "大屏(kiosk):   ${FRONTEND}/screen"
say "监控页:        ${FRONTEND}/monitor"
say "六幕剧本:      ${FRONTEND}/demo"
say "账本/地图/agent 实况已随 SSE 自动上墙 (ledger / attack_geo / agent_tick)"
say "停演:          bash demo/run-demo.sh stop"
say "════════════════════════════════════════"
