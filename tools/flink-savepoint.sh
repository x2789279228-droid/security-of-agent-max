#!/bin/bash
# ════════════════════════════════════════════════════════════════
# Flink Savepoint 助手 — "零丢失升级"的第一步
#
# 对运行中的核心作业逐个触发 savepoint (JM REST), 轮询完成并输出
# 可直接用于恢复提交的路径:
#
#   FLINK_RESTORE_SAVEPOINT=<输出的路径> ./submit-jobs.sh
#
# 用法:
#   bash tools/flink-savepoint.sh                # 全部运行中的核心作业
#   JM_CONTAINER=soc-flink-jobmanager-standby bash tools/flink-savepoint.sh
#   ONLY=LogValidationJob bash tools/flink-savepoint.sh
#
# 前提: flink_state 卷挂载在 JM 上 (compose 已配), state.savepoints.dir
#       指向 file:///var/flink-state/savepoints —— REST 不传 target-directory
#       时使用集群默认, 输出路径两个 JM 都可见。
# ════════════════════════════════════════════════════════════════
set -uo pipefail

JM_CONTAINER="${JM_CONTAINER:-soc-flink-jobmanager}"
JM_REST="${JM_REST:-http://localhost:8081}"
CORE_JOBS='LogValidationJob|AnomalyDetectionJob|SigmaThresholdAggregationJob'
ONLY="${ONLY:-}"
POLL_MAX="${POLL_MAX:-180}"     # 单作业 savepoint 完成上限 (秒)

say() { echo "[savepoint $(date +%H:%M:%S)] $*"; }

rest() {
    # REST 调用统一走容器内 curl (JM REST 未映射宿主)
    docker exec "${JM_CONTAINER}" curl -sf -m 10 -X "$1" "${JM_REST}$2" \
        ${3:+-d "$3"} -H "Content-Type: application/json"
}

# 解析用 jq (flink-jobs 镜像只装了 curl+jq, 没有 python)
mapfile -t JOBS < <(rest GET "/jobs/overview" 2>/dev/null \
    | jq -r '.jobs[] | select(.state == "RUNNING") | "\(.jid)\t\(.name)"' 2>/dev/null || true)

if [ "${#JOBS[@]}" = "0" ]; then
    say "未发现运行中的作业 (JM=${JM_CONTAINER})"; exit 1
fi

rc=0
declare -a RESULTS
for row in "${JOBS[@]}"; do
    jid="${row%%$'\t'*}"
    name="${row#*$'\t'}"
    if [ -n "${ONLY}" ] && [[ "${name}" != *"${ONLY}"* ]]; then continue; fi
    if ! [[ "${name}" =~ (${CORE_JOBS}) ]]; then
        say "跳过非核心作业: ${name}"; continue
    fi

    say "触发 savepoint: ${name} (${jid})"
    resp="$(rest POST "/jobs/${jid}/savepoints" '{"flush": true}' 2>/dev/null)" || {
        say "❌ 触发失败: ${name}"; rc=1; RESULTS+=("FAIL ${name}"); continue; }

    reqid="$(echo "${resp}" | jq -r '."request-id" // empty' 2>/dev/null)"
    [ -z "${reqid}" ] && { say "❌ 响应无 request-id: ${resp}"; rc=1; continue; }

    waited=0; location=""
    while [ "${waited}" -lt "${POLL_MAX}" ]; do
        status="$(rest GET "/jobs/${jid}/savepoints/${reqid}" 2>/dev/null)" || true
        done_flag="$(echo "${status}" | jq -r '
            if .completed then
                "DONE\t" + (.operation.location // "") + "\t"
                    + ((.operation.failure_cause // "") | tostring)
            else "WAIT" end' 2>/dev/null || echo "")"
        if [[ "${done_flag}" == DONE* ]]; then
            location="$(echo "${done_flag}" | cut -f2)"
            cause="$(echo "${done_flag}" | cut -f3)"
            if [ -n "${location}" ]; then
                say "✅ ${name}: ${location}"
                RESULTS+=("OK ${name} ${location}")
            else
                say "❌ ${name} savepoint 失败: ${cause}"; rc=1
                RESULTS+=("FAIL ${name} ${cause}")
            fi
            break
        fi
        sleep 5; waited=$((waited + 5))
    done
    [ "${waited}" -ge "${POLL_MAX}" ] && { say "❌ ${name} 超时 (>${POLL_MAX}s)"; rc=1; RESULTS+=("TIMEOUT ${name}"); }
done

say ""
say "════ 汇总 (恢复用法) ════"
for r in "${RESULTS[@]:-}"; do
    [ -n "$r" ] && echo "  $r"
done
if [ "${rc}" = "0" ]; then
    say "升级/重启: 对每个作业用其 savepoint 路径"
    say "  FLINK_RESTORE_SAVEPOINT=<路径> FLINK_ALLOW_NON_RESTORED_STATE=1 ./submit-jobs.sh"
    say "  (compose: .env 里设 FLINK_RESTORE_SAVEPOINT 后重启 flink-job-submitter)"
fi
exit "${rc}"
