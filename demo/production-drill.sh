#!/bin/bash
# ════════════════════════════════════════════════════════════════
# 生产化容灾演练 (production drill) — 账本 → 混沌 → 对账
#
# 演示"机制等价于生产、规模等比缩小"的核心承诺: 依次注入故障,
# 全程持续灌事件, 结束后按 eventId 对账 —— 零丢失、零重复。
#
# 用法:
#   bash demo/production-drill.sh              # 完整演练 (需 full profile)
#   SKIP_BROKER=1 SKIP_TM=1 ... bash demo/...  # 跳过某类故障
#   TOTAL_EVENTS=300 bash demo/...             # 调整灌入量
#
# 前置: docker compose (COMPOSE_PROFILES=full) 全栈已启动, backend 健康 (127.0.0.1:8001)
# 输出: demo/.drill/ledger-<ts>.jsonl (账本) + 对账结论; 退出码非 0 = 丢数据
# ════════════════════════════════════════════════════════════════
set -uo pipefail
cd "$(dirname "$0")/.."

BACKEND="${BACKEND:-http://127.0.0.1:8001}"
TOTAL_EVENTS="${TOTAL_EVENTS:-200}"
BATCH_SIZE="${BATCH_SIZE:-20}"
CHAOS_WAIT="${CHAOS_WAIT:-45}"          # 每次故障后的恢复观察窗口 (秒)
DRILL_DIR="demo/.drill"
TS="$(date +%Y%m%d-%H%M%S)"
LEDGER="${DRILL_DIR}/ledger-${TS}.jsonl"
RESULT="${DRILL_DIR}/result-${TS}.txt"
mkdir -p "${DRILL_DIR}"

say()  { echo "[drill $(date +%H:%M:%S)] $*"; }
fail() { say "❌ $*"; echo "FAIL: $*" >> "${RESULT}"; exit 1; }

compose() { docker compose "$@"; }
svc_up()  { compose ps --services --filter "status=running" 2>/dev/null | grep -qx "$1"; }

# ── 0. 前置检查 ──
say "=== 0/5 前置检查 ==="
command -v docker >/dev/null || fail "需要 docker"
curl -sf "${BACKEND}/health" >/dev/null 2>&1 || curl -sf "${BACKEND}/api/health" >/dev/null 2>&1 \
  || fail "backend 不可达: ${BACKEND} (compose 全栈是否已启动?)"
if svc_up kafka-1; then PROFILE=full; KAFKA_SVCS="kafka-1 kafka-2 kafka-3";
elif svc_up kafka;    then PROFILE=lite; KAFKA_SVCS="kafka";
else fail "Kafka 未运行 (full: kafka-1/2/3, lite: kafka)"; fi
say "profile=${PROFILE} kafka=[${KAFKA_SVCS}] backend=${BACKEND}"

# ── 1. 灌账本事件 (后台持续, 与混沌并行) ──
say "=== 1/5 灌入 ${TOTAL_EVENTS} 条事件 (batch=${BATCH_SIZE}) ==="
producer_pid=""
produce_loop() {
  local sent=0
  while [ "${sent}" -lt "${TOTAL_EVENTS}" ]; do
    local n=$(( BATCH_SIZE < TOTAL_EVENTS - sent ? BATCH_SIZE : TOTAL_EVENTS - sent ))
    local logs="[" i=0
    while [ $i -lt $n ]; do
      [ $i -gt 0 ] && logs+=","
      # eventId 留空由网关盖章 —— 对账键从响应取
      logs+="{\"message\":\"drill ${TS} seq=$((sent+i)) <b>xss</b>\",\"severity\":\"low\",\"event\":\"DRILL_EVENT\"}"
      i=$((i+1))
    done
    logs+="]"
    # 账本语义 (评审 §五.13 修复): 只记录**被 ACK 批次**的 seq ——
    # 故障窗口内被 503/207 拒绝的批次属"未接受即未持久", 不进对账分母。
    if curl -sf -X POST "${BACKEND}/api/logs/ingest/batch" \
      -H "Content-Type: application/json" \
      -d "{\"logs\": ${logs}, \"session_id\": \"drill-${TS}\"}" > /tmp/drill-batch.json 2>/dev/null; then
      local j=0
      while [ $j -lt $n ]; do echo $((sent+j)) >> "${LEDGER}"; j=$((j+1)); done
    else
      say "WARN: batch [${sent}..$((sent+n-1))] 被拒 (not_durable, 不入对账分母)"
    fi
    sent=$((sent+n))
    sleep 0.3
  done
}
: > "${LEDGER}"
produce_loop & producer_pid=$!
say "灌入进程 pid=${producer_pid}"

# ── 2. 混沌注入 ──
say "=== 2/5 混沌注入 (每个故障后观察 ${CHAOS_WAIT}s) ==="
chaos() {
  local name="$1"; shift
  say "--- 混沌: ${name} ---"
  "$@"
  sleep "${CHAOS_WAIT}"
}

if [ "${SKIP_BROKER:-0}" != "1" ] && [ "${PROFILE}" = "full" ]; then
  chaos "杀 broker-2 (RF=3/minISR=2 应无感)" docker stop soc-kafka-2
  chaos "复活 broker-2 (ISR 自愈)"           docker start soc-kafka-2
fi
if [ "${SKIP_TM:-0}" != "1" ]; then
  chaos "杀 TaskManager-1 (作业自动重启)"     docker stop soc-flink-taskmanager-1
  chaos "复活 TaskManager-1"                  docker start soc-flink-taskmanager-1
fi
if [ "${SKIP_BACKEND_RESTART:-0}" != "1" ]; then
  chaos "重启 backend (幂等 eventId 兜底)"    compose restart backend
fi
# broker 全停 + 冷启动 (disk-buffer 语义在 batch 拒绝处体现: not_durable 不接受)
if [ "${SKIP_KAFKA_ALL:-1}" = "0" ]; then
  for s in ${KAFKA_SVCS}; do docker stop "soc-${s}" 2>/dev/null; done
  for s in ${KAFKA_SVCS}; do docker start "soc-${s}" 2>/dev/null; done
  sleep "${CHAOS_WAIT}"
fi

# ── 3. 等灌入结束 + 管道排干 ──
say "=== 3/5 等待灌入结束与管道排干 ==="
wait "${producer_pid}" || true
say "账本行数: $(wc -l < "${LEDGER}")"
say "等待 ${CHAOS_WAIT}s 让 Flink/审计链路消化队列..."
sleep "${CHAOS_WAIT}"

# ── 4. 对账 ──
say "=== 4/5 对账 (ACK 账本 → backend 存储) ==="
# 分母 = 账本里**被 ACK 批次**的 seq (评审 §五.13 修复): 被拒批次属
# "未接受即未持久", 不计为丢失。
python - "${LEDGER}" "${BACKEND}" "${TS}" <<'PY'
import json, sys, urllib.request

ledger_path, backend, ts = sys.argv[1], sys.argv[2], sys.argv[3]
expected = set()
for ln in open(ledger_path, encoding="utf-8"):
    ln = ln.strip()
    if ln.isdigit():
        expected.add(int(ln))
total = len(expected)
print(f"acked(ledger)={total}")

# 全量翻页拉取已存储事件, 按 message 里的 drill 序号对账:
#   message = "drill <ts> seq=<n>" —— 注入时唯一, 存储后原样保留
stored_seq = {}
after = 0
while True:
    with urllib.request.urlopen(
            f"{backend}/api/logs/events?limit=1000&after_id={after}") as r:
        rows = json.load(r)
    if not rows:
        break
    for row in rows:
        # message 首部: "drill <ts> seq=<n> ..." (注入时盖章, 网关只清洗标签不改前缀)
        msg = str(row.get("message") or "")
        if not msg.startswith(f"drill {ts} seq="):
            continue
        try:
            seq = int(msg.split()[2].split("=", 1)[1])
        except (IndexError, ValueError):
            continue
        stored_seq[seq] = stored_seq.get(seq, 0) + 1
    after = max(x["id"] for x in rows)
    if len(rows) < 1000:
        break

got = set(stored_seq)
missing = sorted(expected - got)
dupes = {k: v for k, v in stored_seq.items() if v > 1}
print(f"expected={total} stored={len(stored_seq)} missing={len(missing)} dupes={len(dupes)}")
if missing:
    print("missing seq sample:", missing[:10])
if dupes:
    print("dup seq sample:", list(dupes.items())[:10])
sys.exit(0 if not missing and not dupes else 1)
PY
RECONCILE_RC=$?
say "对账退出码: ${RECONCILE_RC} (0=零丢失零重复)"

# ── 5. 结论 ──
say "=== 5/5 结论 ==="
{
  echo "ts=${TS} profile=${PROFILE} total=${TOTAL_EVENTS}"
  echo "ledger=${LEDGER}"
} >> "${RESULT}"
if [ "${RECONCILE_RC}" = "0" ]; then
  say "✅ 演练通过: 故障注入期间零丢失、零重复 ( eventId 幂等 + Flink EXACTLY_ONCE + checkpoint 恢复 )"
  exit 0
else
  fail "对账不一致 —— 检查 Grafana(soc-flink-pipeline/soc-kafka-cluster) 与 backend 日志定位丢失窗口"
fi
