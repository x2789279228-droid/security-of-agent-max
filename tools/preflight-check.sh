#!/bin/bash
# ════════════════════════════════════════════════════════════════
# 答辩现场一键自检 (preflight check) — PERF-2026-10-26 阻断项固化
#
# 依据: docs/benchmark/PERF-2026-10-26.md「改前基线: 8 个阻断项」+
#       docs/upgrade/PERF-OPT-PLAN-2026-10-26.md Wave 3-5。
# 目标: 新环境 / 答辩机开机后一条命令验证"链路真的通"——
#       8 个阻断项的静态防线逐项在位, 且 Kafka 事务可见性
#       (写 1 条 → read_committed 读到)实测闭合。
#
# 用法:
#   bash tools/preflight-check.sh            # 全量检查 (静态 + 运行时)
#   bash tools/preflight-check.sh --static   # 只查静态防线 (无需 docker/栈)
#   bash tools/preflight-check.sh --fix      # 检查 + 机械修复可修项
#                                            #   (CRLF、.env 两键)
#
# 退出码: 0 = 全部 PASS/WARN; 1 = 存在 FAIL (现场不要开始演示)
# 产物:  tools/.preflight/report-<ts>.txt (本次检查回执)
# ════════════════════════════════════════════════════════════════
set -uo pipefail

# ── CRLF 自免疫: 仓库无 .gitattributes, checkout 可能被 CRLF 化
#    (阻断项 3 的病根)。检出自身带 \r 时经 sed 净化后重执行。
#    CR 检测必须走 Python 二进制读: Git Bash 下 (a) argv 里的裸 CR
#    会被 MSYS 序列化吞掉, (b) grep 以文本模式读文件, CR 在读取层
#    就被剥掉 —— 两条路都让 grep 的 CR 模式永远匹配不到 (实测钉死,
#    "空模式 grep -c 全部行"的假阳性就是这条坑的产物)。
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if command -v python >/dev/null 2>&1 && \
   python -c "import sys;sys.exit(1 if b'\r' not in open(sys.argv[1],'rb').read() else 0)" \
     "${BASH_SOURCE[0]}" 2>/dev/null; then
  exec bash <(sed 's/\r$//' "${BASH_SOURCE[0]}") "$@"
fi
cd "$REPO_DIR"

# CR 检测助手: $@ = 文件路径 → 输出含 CR 的文件 (Python 二进制读)
_PREFLIGHT_PY="${TMPDIR:-/tmp}/preflight-crlf-$$.py"
trap 'rm -f "$_PREFLIGHT_PY"' EXIT
cat > "${_PREFLIGHT_PY}" <<'PYEOF'
import sys
for p in sys.argv[1:]:
    try:
        with open(p, "rb") as fh:
            if b"\r" in fh.read():
                print(p)
    except OSError:
        pass
PYEOF
detect_crlf() { python "${_PREFLIGHT_PY}" "$@" 2>/dev/null; }

FIX=0
STATIC_ONLY=0
for arg in "$@"; do
  case "$arg" in
    --fix)    FIX=1 ;;
    --static) STATIC_ONLY=1 ;;
    *) echo "未知参数: $arg (支持 --fix / --static)"; exit 2 ;;
  esac
done

BACKEND="${BACKEND:-http://127.0.0.1:8001}"
ENV_FILE=".env"
TS="$(date +%Y%m%d-%H%M%S)"
REPORT_DIR="tools/.preflight"
REPORT="${REPORT_DIR}/report-${TS}.txt"
mkdir -p "${REPORT_DIR}"

PASS_N=0; FAIL_N=0; WARN_N=0
say()  { echo "[preflight $(date +%H:%M:%S)] $*" | tee -a "${REPORT}"; }
ok()   { PASS_N=$((PASS_N+1)); echo "  ✅ $*" | tee -a "${REPORT}"; }
bad()  { FAIL_N=$((FAIL_N+1)); echo "  ❌ $*" | tee -a "${REPORT}"; }
warn() { WARN_N=$((WARN_N+1)); echo "  ⚠️  $*" | tee -a "${REPORT}"; }

# 从 .env 读键 (取最后一次出现, 忽略注释行)
envget() {
  [ -f "${ENV_FILE}" ] || return 1
  grep -E "^${1}=" "${ENV_FILE}" | tail -1 | cut -d= -f2- | tr -d '\r'
}

say "=== 「守望」答辩现场自检 @ ${REPO_DIR} ==="

# ════════════════ 静态防线 ════════════════
say "--- S. 静态防线 (阻断项修法固化) ---"

# 阻断项 1: alembic fileConfig 顶掉 root logger → 迁移后宿主日志全灭
if grep -q "_saved_handlers" backend/migrations/env.py 2>/dev/null; then
  ok "S1 alembic root-logger 还原在位 (backend/migrations/env.py)"
else
  bad "S1 backend/migrations/env.py 缺 root-logger 还原 (阻断项 1 复发: 迁移后所有 INFO 日志消失)"
fi

# 阻断项 2: .env 缺 KAFKA_BOOTSTRAP_SERVERS / profile 不匹配
PROFILE="$(envget COMPOSE_PROFILES || echo lite)"
if [ "${PROFILE}" = "full" ]; then
  EXPECT_KAFKA_CTR="soc-kafka-1"
  EXPECT_BOOTSTRAP="kafka-1:9092,kafka-2:9092,kafka-3:9092"
else
  PROFILE="lite"
  EXPECT_KAFKA_CTR="soc-kafka"
  EXPECT_BOOTSTRAP="kafka:9092"
fi
ACTUAL_BOOTSTRAP="$(envget KAFKA_BOOTSTRAP_SERVERS || echo '')"
if [ "${ACTUAL_BOOTSTRAP}" = "${EXPECT_BOOTSTRAP}" ]; then
  ok "S2 .env: COMPOSE_PROFILES=${PROFILE} ↔ KAFKA_BOOTSTRAP_SERVERS 一致"
elif [ -n "${ACTUAL_BOOTSTRAP}" ]; then
  if [ "${FIX}" = "1" ]; then
    sed -i "s|^KAFKA_BOOTSTRAP_SERVERS=.*|KAFKA_BOOTSTRAP_SERVERS=${EXPECT_BOOTSTRAP}|" "${ENV_FILE}" \
      && ok "S2 已修复: KAFKA_BOOTSTRAP_SERVERS → ${EXPECT_BOOTSTRAP} (与 ${PROFILE} 一致)"
  else
    bad "S2 .env: KAFKA_BOOTSTRAP_SERVERS=${ACTUAL_BOOTSTRAP} 与 ${PROFILE} 不匹配 (期望 ${EXPECT_BOOTSTRAP}); 修法见阻断项 2 / --fix"
  fi
else
  if [ "${FIX}" = "1" ]; then
    printf 'KAFKA_BOOTSTRAP_SERVERS=%s\n' "${EXPECT_BOOTSTRAP}" >> "${ENV_FILE}" \
      && ok "S2 已补: KAFKA_BOOTSTRAP_SERVERS=${EXPECT_BOOTSTRAP}"
  else
    bad "S2 .env 缺 KAFKA_BOOTSTRAP_SERVERS (阻断项 2: Flink/SR 指向不存在的 broker, 作业 FAILING 循环); --fix 可补"
  fi
fi

# 阻断项 3: flink-jobs/*.sh CRLF → 容器内 /bin/bash^M exit 126
CRLF_SH="$(detect_crlf $(find flink-jobs -maxdepth 1 -name '*.sh'))"
if [ -z "${CRLF_SH}" ]; then
  ok "S3 flink-jobs/*.sh 无 CRLF"
else
  if [ "${FIX}" = "1" ]; then
    find flink-jobs -maxdepth 1 -name '*.sh' -exec sed -i 's/\r$//' {} + \
      && ok "S3 已净化 CRLF: $(echo "${CRLF_SH}" | tr '\n' ' ')"
  else
    bad "S3 CRLF 感染: ${CRLF_SH} (阻断项 3: job-submitter exit 126 崩溃循环, 作业一个都提交不了); --fix 可修"
  fi
fi
# 仓库其它 .sh 的 CRLF 只提示不强修 (宿主 Git Bash 可容忍, 容器内不可)
OTHER_CRLF="$(detect_crlf $(find demo tools -maxdepth 2 -name '*.sh' -not -path 'tools/preflight-check.sh') | head -5)"
if [ -n "${OTHER_CRLF}" ]; then
  warn "S3b 其它脚本含 CRLF (容器内执行会踩阻断项 3 同款): ${OTHER_CRLF}"
fi

# 阻断项 4: checkpointing 必须进镜像 config.yaml (客户端 config.yaml 无效)
# 阻断项 3 防线: Dockerfile 内 sed 净化
if grep -q 's/\\r\$//' flink-jobs/Dockerfile 2>/dev/null; then
  ok "S4a flink-jobs/Dockerfile CRLF 净化防线在位"
else
  bad "S4a flink-jobs/Dockerfile 缺 sed CRLF 净化 (镜像重建成后阻断项 3 复发)"
fi
if grep -q "checkpointing:" flink-jobs/Dockerfile 2>/dev/null; then
  ok "S4b checkpointing 进镜像 (Dockerfile 内嵌 config, EXACTLY_ONCE 事务能提交)"
else
  bad "S4b 镜像侧 config 缺 checkpointing (阻断项 4: 事务永不提交, read_committed 一条都读不到)"
fi

# 阻断项 6/7: compose 接线 (EXECUTION_MODE 双服务 + FLINK_PARALLELISM)
for svc_key in "SHARED_MEMORY_EXECUTION_MODE" "FLINK_PARALLELISM"; do
  N=$(grep -c "${svc_key}:" docker-compose.yml 2>/dev/null || echo 0)
  if [ "${svc_key}" = "SHARED_MEMORY_EXECUTION_MODE" ]; then
    if [ "${N}" -ge 2 ]; then
      ok "S5a compose 接线 SHARED_MEMORY_EXECUTION_MODE ×${N} (backend + temporal-worker)"
    else
      bad "S5a compose 只有 ${N} 处 SHARED_MEMORY_EXECUTION_MODE (阻断项 6: .env 配 live 不生效, 永远 dry_run)"
    fi
  else
    if [ "${N}" -ge 1 ]; then
      ok "S5b compose 接线 FLINK_PARALLELISM (阻断项 7: 否则 15 槽只用 3 槽)"
    else
      bad "S5b compose 缺 FLINK_PARALLELISM (阻断项 7)"
    fi
  fi
done

if [ "${STATIC_ONLY}" = "1" ]; then
  say "--- 静态检查结束 (--static): PASS=${PASS_N} FAIL=${FAIL_N} WARN=${WARN_N} ---"
  [ "${FAIL_N}" -eq 0 ] || exit 1
  exit 0
fi

# ════════════════ 运行时 ════════════════
say "--- R. 运行时 (栈在位 + 事务可见性) ---"

command -v docker >/dev/null 2>&1 || { bad "R0 docker 不可用"; exit 1; }
docker info >/dev/null 2>&1 || { bad "R0 docker daemon 未启动"; exit 1; }

kctr() {  # kafka 容器名 (lite→soc-kafka; full→soc-kafka-1)
  docker ps --format '{{.Names}}' | grep -qx "${EXPECT_KAFKA_CTR}" && echo "${EXPECT_KAFKA_CTR}" || \
  docker ps --format '{{.Names}}' | grep -E '^soc-kafka(-1)?$' | head -1
}

# R1 核心容器在位 + backend 健康
MISSING=""
for c in "${EXPECT_KAFKA_CTR}" shared-memory-pg shared-memory-backend; do
  docker ps --format '{{.Names}}' | grep -qx "${c}" || MISSING="${MISSING} ${c}"
done
if [ -z "${MISSING}" ]; then
  ok "R1 核心容器在位 (kafka=${EXPECT_KAFKA_CTR} / pg / backend)"
else
  bad "R1 容器缺失:${MISSING} (compose 栈是否已启动?)"
fi
if curl -sf "${BACKEND}/health" >/dev/null 2>&1 || curl -sf "${BACKEND}/api/health" >/dev/null 2>&1; then
  ok "R1b backend 健康: ${BACKEND}"
else
  bad "R1b backend 不可达: ${BACKEND}"
fi

KC="$(kctr || true)"
# Kafka CLI 名称: cp-kafka 容器里是无扩展名符号链接 (kafka-topics),
# 其它镜像 (bitnami/apache) 是 .sh —— 运行时解析一次, 全脚本统一走 kcli()
KCLI_SUFFIX=""
if [ -n "${KC}" ] && ! docker exec "${KC}" bash -c 'command -v kafka-topics' >/dev/null 2>&1; then
  KCLI_SUFFIX=".sh"
fi
kcli() { docker exec "${KC}" "kafka-$1${KCLI_SUFFIX}" "${@:2}"; }

if [ -z "${KC}" ]; then
  say "  (kafka 容器不在位, R2-R5 跳过)"
  bad "R2-R5 跳过: 无 kafka 容器"
else
  # R2 topic 在位
  if kcli topics --bootstrap-server localhost:9092 --list 2>/dev/null \
      | grep -qx "security-events-ingest"; then
    ok "R2 topic security-events-ingest 在位"
  else
    warn "R2 缺 security-events-ingest (跑 tools/init-kafka-topics.sh)"
  fi

  # R3 checkpoint 卷属主 (阻断项 5: root 属主 → checkpoint 存储创建失败 → 作业 FAILED)
  TM="$(docker ps --format '{{.Names}}' | grep '^soc-flink-taskmanager' | head -1 || true)"
  if [ -n "${TM}" ] && docker exec "${TM}" test -d /var/flink-state 2>/dev/null; then
    OWNER="$(docker exec -u 0 "${TM}" stat -c '%U' /var/flink-state 2>/dev/null || echo '?')"
    if [ "${OWNER}" = "flink" ]; then
      ok "R3 checkpoint 卷属主 flink (${TM})"
    else
      bad "R3 checkpoint 卷属主=${OWNER} (阻断项 5: 修法 docker exec -u 0 chown flink:flink)"
    fi
  else
    warn "R3 无运行中 taskmanager 或无 /var/flink-state (Flink 侧未启动?)"
  fi

  # R4 未决事务扫描 (阻断项 8 的现存形态: 事务卡 Ongoing → read_committed 永久不可见)
  TXOUT="$(kcli transactions --bootstrap-server localhost:9092 list 2>/dev/null || true)"
  if [ -n "${TXOUT}" ]; then
    NOW_MS="$(date +%s%3N)"
    STUCK="$(echo "${TXOUT}" | grep '"state":"Ongoing"' | while read -r line; do
      ST="$(echo "${line}" | sed -n 's/.*"startTimestamp":\([0-9]*\).*/\1/p')"
      [ -n "${ST}" ] || continue
      AGE=$(( (NOW_MS - ST) / 1000 ))
      [ "${AGE}" -gt 300 ] && echo "${line}"
    done | head -3)"
    if [ -z "${STUCK}" ]; then
      ok "R4 无超 5 分钟的 Ongoing 事务"
    else
      bad "R4 存在长期未决事务 (阻断项 8 形态, 数据对 read_committed 不可见):"
      echo "${STUCK}" | sed 's/^/      /' | tee -a "${REPORT}"
    fi
  else
    warn "R4 kafka-transactions.sh 无输出 (工具缺失或版本差异, 人工确认)"
  fi

  # R5 事务可见性自检 (核心): 写 1 条 → read_committed 消费者读到
  TOPIC="preflight-txn-visibility"
  PAYLOAD="preflight-$(date +%s)"
  kcli topics --bootstrap-server localhost:9092 --create --if-not-exists \
    --topic "${TOPIC}" --partitions 1 --replication-factor 1 \
    --config retention.ms=600000 >/dev/null 2>&1
  if echo "${PAYLOAD}" | docker exec -i "${KC}" "kafka-console-producer${KCLI_SUFFIX}" \
      --bootstrap-server localhost:9092 --topic "${TOPIC}" >/dev/null 2>&1; then
    GOT="$(docker exec "${KC}" timeout 25 "kafka-console-consumer${KCLI_SUFFIX}" \
      --bootstrap-server localhost:9092 --topic "${TOPIC}" --from-beginning \
      --max-messages 1 --isolation-level read_committed --timeout-ms 20000 2>/dev/null | tail -1)"
    if [ "${GOT}" = "${PAYLOAD}" ]; then
      ok "R5 事务可见性闭合: 写 1 条 → read_committed 读到 (${PAYLOAD})"
    else
      bad "R5 read_committed 读不到刚写的消息 (阻断项 4/8 事故形态: 事务未提交或卡死)"
    fi
  else
    bad "R5 生产探针失败 (写入都不通, 链路断裂)"
  fi

  # R6 PG 可查 + 消费组 lag 可读
  if docker exec shared-memory-pg psql -U admin -d shared_memory -t -A -c "select 1" 2>/dev/null | grep -q 1; then
    ok "R6 PG 可查 (admin@shared_memory)"
  else
    bad "R6 PG 查询失败"
  fi
  LAGLINE="$(kcli consumer-groups --bootstrap-server localhost:9092 \
    --describe --group soc-backend-ingestpy 2>/dev/null | tail -n +2 | head -3 || true)"
  if [ -n "${LAGLINE}" ]; then
    TOTAL_LAG="$(echo "${LAGLINE}" | awk '{s+=$(NF-2)} END {print s+0}')"
    ok "R6 消费组 soc-backend-ingestpy 可读 (当前 lag=${TOTAL_LAG})"
  else
    warn "R6 消费组 soc-backend-ingestpy 无记录 (消费侧未起, 演示前需起 backend)"
  fi
fi

# R7 认证可用 (演示与大压工具都走 JWT)
PW="$(envget SHARED_MEMORY_ADMIN_PASSWORD || echo '')"
if [ -n "${PW}" ]; then
  CODE="$(curl -s -o /dev/null -w '%{http_code}' -X POST "${BACKEND}/api/auth/login" \
    -H 'Content-Type: application/json' \
    -d "{\"username\":\"admin\",\"password\":\"${PW}\"}" 2>/dev/null || echo 000)"
  if [ "${CODE}" = "200" ]; then
    ok "R7 JWT 登录可用 (admin)"
  else
    bad "R7 登录失败 http=${CODE} (校对 .env SHARED_MEMORY_ADMIN_PASSWORD)"
  fi
else
  warn "R7 .env 无 SHARED_MEMORY_ADMIN_PASSWORD, 登录检查跳过"
fi

# ════════════════ 汇总 ════════════════
say "--- 汇总: PASS=${PASS_N} FAIL=${FAIL_N} WARN=${WARN_N} → ${REPORT} ---"
if [ "${FAIL_N}" -gt 0 ]; then
  say "❌ 现场不要开始演示: ${FAIL_N} 项 FAIL。修法索引: docs/benchmark/PERF-2026-10-26.md「改前基线」8 项表。"
  exit 1
fi
say "✅ 自检通过 — 静态防线在位, 事务可见性闭合。祝答辩顺利。"
exit 0
