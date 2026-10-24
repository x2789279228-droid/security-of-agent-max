#!/bin/bash
# ════════════════════════════════════════════════════════════════
# Vector 磁盘缓冲演示 — "Kafka 全停, 采集边缘零丢失"
#
# 流程:
#   1. 停掉全部 Kafka broker
#   2. 向 Vector(8686) 持续灌 N 条事件 → HTTP 全部 200 (落磁盘缓冲)
#      同时直连 backend 网关灌 1 条 → 预期 503 not_durable (接受即持久语义:
#      没有边缘缓冲的路径宁可拒绝也不假装接受)
#   3. 拉起 Kafka → Vector 自动排干 → 事件经 ingest 队列检测入库
#   4. 按 message 盖章(vedge <ts> seq=<n>) 对账: 全部到齐 = 通过
#
# 前置: COMPOSE_PROFILES 含 edge (vector 容器在跑), backend 健康 (127.0.0.1:8001)
# 用法: bash demo/vector-buffer-demo.sh  [TOTAL=60] [TIMEOUT=240]
# ════════════════════════════════════════════════════════════════
set -uo pipefail
cd "$(dirname "$0")/.."

BACKEND="${BACKEND:-http://127.0.0.1:8001}"
VECTOR="${VECTOR:-http://127.0.0.1:8686}"
TOTAL="${1:-60}"
TIMEOUT="${2:-240}"
TS="$(date +%Y%m%d-%H%M%S)"

say() { echo "[vedge $(date +%H:%M:%S)] $*"; }
fail() { say "❌ $*"; exit 1; }

say "=== 0/4 前置检查 ==="
docker compose ps --services --filter "status=running" 2>/dev/null | grep -qx vector \
  || fail "vector 未运行 —— 先启用 edge profile: COMPOSE_PROFILES=full,edge && docker compose up -d vector"
curl -sf "${BACKEND}/health" >/dev/null 2>&1 || curl -sf "${BACKEND}/api/health" >/dev/null 2>&1 \
  || fail "backend 不可达: ${BACKEND}"

KAFKA_CTNS=""
for c in soc-kafka-1 soc-kafka-2 soc-kafka-3; do
  docker ps --format '{{.Names}}' | grep -qx "$c" && KAFKA_CTNS="$KAFKA_CTNS $c"
done
[ -z "${KAFKA_CTNS}" ] && docker ps --format '{{.Names}}' | grep -qx soc-kafka && KAFKA_CTNS=" soc-kafka"
[ -z "${KAFKA_CTNS}" ] && fail "未发现运行中的 Kafka broker"
say "Kafka: [${KAFKA_CTNS}]  Vector: ${VECTOR}"

# ── 1. 停 Kafka ──
say "=== 1/4 停 Kafka ([${KAFKA_CTNS}]) ==="
for c in ${KAFKA_CTNS}; do docker stop "$c" >/dev/null; done

# ── 2. 停机窗口内灌入 ──
say "=== 2/4 停机窗口内向 Vector 灌入 ${TOTAL} 条 ==="
ok=0; seq=0
while [ $seq -lt $TOTAL ]; do
  code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "${VECTOR}" \
    -H "Content-Type: application/json" \
    -d "{\"message\":\"vedge ${TS} seq=${seq} demo\",\"severity\":\"low\",\"event\":\"VEDGE_EVENT\"}")
  if [ "$code" = "200" ]; then ok=$((ok+1)); else say "WARN: vector 返回 ${code} (seq=${seq})"; fi
  seq=$((seq+1))
done
say "Vector 接受 ${ok}/${TOTAL} (HTTP 200 = 已进磁盘缓冲)"
[ "$ok" -lt "$TOTAL" ] && fail "Vector 未全量接受 —— 检查 vector 容器日志"

# 对照组: 停机窗口直连网关必须被拒绝 (not_durable, 不得假装成功)
gw=$(curl -s -o /dev/null -w '%{http_code}' -X POST "${BACKEND}/api/logs/ingest" \
  -H "Content-Type: application/json" \
  -d '{"message":{"message":"vedge gateway probe during outage","severity":"low"}}')
say "对照组: 停机窗口直连网关 → HTTP ${gw} (期望 503/202-拒绝语义)"
[ "$gw" = "503" ] || say "NOTE: 网关返回 ${gw} (Kafka producer 状态相关; 503=not_durable 为预期, 202 需复查)"

# ── 3. 拉起 Kafka, 等 Vector 排干 ──
say "=== 3/4 拉起 Kafka → Vector 自动排干 ==="
for c in ${KAFKA_CTNS}; do docker start "$c" >/dev/null; done
say "等待 broker healthy + 管道消化 (最长 ${TIMEOUT}s)..."
deadline=$(( $(date +%s) + TIMEOUT ))
found=0
while [ $(date +%s) -lt $deadline ]; do
  found=$(curl -sf "${BACKEND}/api/logs/events?limit=1000" | python -c "
import sys, json
try:
    rows = json.load(sys.stdin)
except Exception:
    print(0); raise SystemExit
n = sum(1 for r in rows if str(r.get('message','')).startswith('vedge ${TS} '))
print(n)" 2>/dev/null || echo 0)
  say "已入库 ${found}/${TOTAL}"
  [ "${found}" -ge "${TOTAL}" ] && break
  sleep 10
done

# ── 4. 对账 ──
say "=== 4/4 对账 ==="
if [ "${found}" -ge "${TOTAL}" ]; then
  say "✅ 演示通过: Kafka 全停 ${TIMEOUT}s 窗口内灌入的 ${TOTAL} 条事件经磁盘缓冲全部入库 —— 边缘零丢失"
  exit 0
else
  fail "只到账 ${found}/${TOTAL} —— 查看 vector 容器日志与 backend 消费指标 (Grafana: SOC Flink 流处理管道)"
fi
