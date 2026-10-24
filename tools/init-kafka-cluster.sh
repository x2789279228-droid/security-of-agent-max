#!/bin/bash
# ── Kafka 集群初始化 (生产化 full profile, 一次性) ──
# 在 3-broker KRaft 集群 healthy 后执行:
#   1) 创建 SCRAM-SHA-512 服务账号 (soc-app / 日志源 / kafka_exporter)
#   2) 按 KAFKA_TOPIC_RF / KAFKA_MIN_ISR 创建全部业务 topic (RF=3, minISR=2)
# 由 docker-compose 的 kafka-init 服务在 full profile 下自动执行;
# 手动重跑幂等 (kafka-configs alter 与 --if-not-exists 都是幂等操作)。
set -euo pipefail

BOOTSTRAP="${KAFKA_BOOTSTRAP_SERVERS:-kafka-1:9092}"
# 用户管理/建 topic 走容器内网 PLAINTEXT(9092); 客户端数据面才走 SASL_SSL
ADMIN_BOOTSTRAP="${KAFKA_ADMIN_BOOTSTRAP:-kafka-1:9092}"

KAFKA_CONFIGS="kafka-configs --bootstrap-server ${ADMIN_BOOTSTRAP}"

create_user() {
    local name="$1" pass="$2"
    if [ -z "${name}" ] || [ -z "${pass}" ]; then
        echo "跳过用户创建: ${name:-<empty>} (凭据未配置)"
        return 0
    fi
    echo "创建/更新 SCRAM 账号: ${name}"
    ${KAFKA_CONFIGS} --alter --entity-type users --entity-name "${name}" \
        --add-config "SCRAM-SHA-512=[iterations=8192,password=${pass}]"
}

echo "=== 1/2 SCRAM 服务账号 ==="
# 应用账号: backend / Flink / kafka_exporter 共用 (数据面 SASL_SSL)
create_user "${KAFKA_APP_USER:-soc-app}" "${KAFKA_APP_PASSWORD:-}"
# 外部日志源账号 (与 .env 的 KAFKA_LOG_SOURCE_* 同名)
create_user "${KAFKA_LOG_SOURCE_USER:-}" "${KAFKA_LOG_SOURCE_PASSWORD:-}"

echo ""
echo "=== 2/2 业务 topic (RF=${KAFKA_TOPIC_RF:-3} minISR=${KAFKA_MIN_ISR:-2}) ==="
export KAFKA_TOPIC_RF KAFKA_MIN_ISR
export BOOTSTRAP
bash "$(dirname "$0")/init-kafka-topics.sh" "${BOOTSTRAP}"

echo ""
echo "=== Kafka 集群初始化完成 ==="
echo "数据面: SASL_SSL://${KAFKA_APP_USER:-soc-app}@<broker>:9093 (CA: certs/kafka/ca-cert.pem)"
