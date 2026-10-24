#!/bin/bash
set -euo pipefail
# Kafka Topic 差异化保留策略初始化
#
# 推荐在 Kafka 容器内执行 (宿主机没有 kafka CLI):
#   docker compose exec -T kafka bash < tools/init-kafka-topics.sh
# 或在装有 kafka CLI 的主机上:
#   bash tools/init-kafka-topics.sh [bootstrap-server]
# 默认 bootstrap: localhost:9092 (容器内 PLAINTEXT 监听)

# 生产化: RF/minISR 经 env 注入 (full profile: RF=3 minISR=2; lite: 1/1)
KAFKA_TOPIC_RF="${KAFKA_TOPIC_RF:-1}"
KAFKA_MIN_ISR="${KAFKA_MIN_ISR:-1}"
BOOTSTRAP="${1:-${KAFKA_BOOTSTRAP_SERVERS:-localhost:9092}}"
KAFKA_CONFIGS="kafka-configs --bootstrap-server $BOOTSTRAP"
KAFKA_TOPICS="kafka-topics --bootstrap-server $BOOTSTRAP"

echo "=== Kafka Topic 初始化 (bootstrap=$BOOTSTRAP) ==="

# 等待 Kafka 就绪
until $KAFKA_TOPICS --list >/dev/null 2>&1; do
  echo "等待 Kafka 就绪..."
  sleep 3
done

# ── 创建 Topic（如不存在）并设置差异化保留策略 ──

# 原始日志: 保留 3 天（数据量大，快速过期）
$KAFKA_TOPICS --create --if-not-exists --topic security-logs-raw --partitions 3 --replication-factor "${KAFKA_TOPIC_RF}"
$KAFKA_CONFIGS --alter --topic security-logs-raw \
  --add-config retention.ms=259200000,retention.bytes=536870912,cleanup.policy=delete,min.insync.replicas=${KAFKA_MIN_ISR}

# 已验证日志: 保留 5 天
$KAFKA_TOPICS --create --if-not-exists --topic security-logs-validated --partitions 3 --replication-factor "${KAFKA_TOPIC_RF}"
$KAFKA_CONFIGS --alter --topic security-logs-validated \
  --add-config retention.ms=432000000,retention.bytes=536870912,cleanup.policy=delete,min.insync.replicas=${KAFKA_MIN_ISR}

# 被拒绝日志: 保留 14 天（审计需要，量小）
$KAFKA_TOPICS --create --if-not-exists --topic security-logs-rejected --partitions 1 --replication-factor "${KAFKA_TOPIC_RF}"
$KAFKA_CONFIGS --alter --topic security-logs-rejected \
  --add-config retention.ms=1209600000,cleanup.policy=delete,min.insync.replicas=${KAFKA_MIN_ISR}

# 重复事件 (60s 窗口去重命中, P0-4): 保留 7 天。
# 与 rejected 分流 —— "重复"不是数据质量问题, 混在一起会污染按拒绝原因告警的口径。
$KAFKA_TOPICS --create --if-not-exists --topic security-logs-duplicate --partitions 3 --replication-factor "${KAFKA_TOPIC_RF}"
$KAFKA_CONFIGS --alter --topic security-logs-duplicate \
  --add-config retention.ms=604800000,cleanup.policy=delete,min.insync.replicas=${KAFKA_MIN_ISR}

# 富化事件: 保留 7 天
$KAFKA_TOPICS --create --if-not-exists --topic security-events-enriched --partitions 3 --replication-factor "${KAFKA_TOPIC_RF}"
$KAFKA_CONFIGS --alter --topic security-events-enriched \
  --add-config retention.ms=604800000,retention.bytes=1073741824,cleanup.policy=delete,min.insync.replicas=${KAFKA_MIN_ISR}

# Python 权威检测主通道 (gateway → Python ingest worker): 保留 7 天
$KAFKA_TOPICS --create --if-not-exists --topic security-events-ingest --partitions 3 --replication-factor "${KAFKA_TOPIC_RF}"
$KAFKA_CONFIGS --alter --topic security-events-ingest \
  --add-config retention.ms=604800000,retention.bytes=1073741824,cleanup.policy=delete,min.insync.replicas=${KAFKA_MIN_ISR}

# Sigma 单事件命中候选 (Python → SigmaThresholdAggregationJob): 保留 7 天
$KAFKA_TOPICS --create --if-not-exists --topic security-sigma-hit --partitions 3 --replication-factor "${KAFKA_TOPIC_RF}"
$KAFKA_CONFIGS --alter --topic security-sigma-hit \
  --add-config retention.ms=604800000,cleanup.policy=delete,min.insync.replicas=${KAFKA_MIN_ISR}

# Flink 行为基线告警: 保留 30 天
$KAFKA_TOPICS --create --if-not-exists --topic security-behavior-alerts --partitions 1 --replication-factor "${KAFKA_TOPIC_RF}"
$KAFKA_CONFIGS --alter --topic security-behavior-alerts \
  --add-config retention.ms=2592000000,cleanup.policy=delete,min.insync.replicas=${KAFKA_MIN_ISR}

# 告警: 保留 30 天（关键安全数据，长期保留）
$KAFKA_TOPICS --create --if-not-exists --topic security-alerts --partitions ${KAFKA_ALERT_PARTITIONS:-3} --replication-factor "${KAFKA_TOPIC_RF}"
$KAFKA_CONFIGS --alter --topic security-alerts \
  --add-config retention.ms=2592000000,cleanup.policy=delete,min.insync.replicas=${KAFKA_MIN_ISR}

# 审计队列: 保留 7 天
$KAFKA_TOPICS --create --if-not-exists --topic security-audit-queue --partitions 2 --replication-factor "${KAFKA_TOPIC_RF}"
$KAFKA_CONFIGS --alter --topic security-audit-queue \
  --add-config retention.ms=604800000,cleanup.policy=delete,min.insync.replicas=${KAFKA_MIN_ISR}

# P0/P1 审计溢出(内存队列满且 Redis PQ 失败): 保留 7 天, Python 回灌 worker
$KAFKA_TOPICS --create --if-not-exists --topic security-audit-overflow --partitions 2 --replication-factor "${KAFKA_TOPIC_RF}"
$KAFKA_CONFIGS --alter --topic security-audit-overflow \
  --add-config retention.ms=604800000,cleanup.policy=delete,min.insync.replicas=${KAFKA_MIN_ISR}

# 审计结果: 保留 30 天（合规要求）
$KAFKA_TOPICS --create --if-not-exists --topic security-audit-results --partitions 2 --replication-factor "${KAFKA_TOPIC_RF}"
$KAFKA_CONFIGS --alter --topic security-audit-results \
  --add-config retention.ms=2592000000,cleanup.policy=delete,min.insync.replicas=${KAFKA_MIN_ISR}

# 死信队列: 保留 30 天（故障排查需要）
$KAFKA_TOPICS --create --if-not-exists --topic security-logs-dlq --partitions 1 --replication-factor "${KAFKA_TOPIC_RF}"
$KAFKA_CONFIGS --alter --topic security-logs-dlq \
  --add-config retention.ms=2592000000,cleanup.policy=delete,min.insync.replicas=${KAFKA_MIN_ISR}

# 延迟重试（仅 kafka_retry_ordering=unordered 使用；strict 默认不往这里发）
$KAFKA_TOPICS --create --if-not-exists --topic security-logs-retry --partitions 3 --replication-factor "${KAFKA_TOPIC_RF}"
$KAFKA_CONFIGS --alter --topic security-logs-retry \
  --add-config retention.ms=604800000,cleanup.policy=delete,min.insync.replicas=${KAFKA_MIN_ISR}

# CEP 部分匹配预警: 保留 7 天（后端 kafka_consumer 消费）
$KAFKA_TOPICS --create --if-not-exists --topic security-cep-partial --partitions 1 --replication-factor "${KAFKA_TOPIC_RF}"
$KAFKA_CONFIGS --alter --topic security-cep-partial \
  --add-config retention.ms=604800000,cleanup.policy=delete,min.insync.replicas=${KAFKA_MIN_ISR}

# CEP 模式定义下发: 保留 30 天（配置类消息）
$KAFKA_TOPICS --create --if-not-exists --topic security-cep-patterns --partitions 1 --replication-factor "${KAFKA_TOPIC_RF}"
$KAFKA_CONFIGS --alter --topic security-cep-patterns \
  --add-config retention.ms=2592000000,cleanup.policy=compact,min.insync.replicas=${KAFKA_MIN_ISR}

# ── NDR 扩展 Topic ──

# 网络流: 保留 7 天（高吞吐）
$KAFKA_TOPICS --create --if-not-exists --topic ndr-flows --partitions 3 --replication-factor "${KAFKA_TOPIC_RF}"
$KAFKA_CONFIGS --alter --topic ndr-flows \
  --add-config retention.ms=604800000,retention.bytes=1073741824,cleanup.policy=delete,min.insync.replicas=${KAFKA_MIN_ISR}

# 流聚合结果 (FlowAggregationJob 输出): 保留 7 天
$KAFKA_TOPICS --create --if-not-exists --topic ndr-flows-aggregated --partitions 2 --replication-factor "${KAFKA_TOPIC_RF}"
$KAFKA_CONFIGS --alter --topic ndr-flows-aggregated \
  --add-config retention.ms=604800000,cleanup.policy=delete,min.insync.replicas=${KAFKA_MIN_ISR}

# TLS 会话: 保留 7 天
$KAFKA_TOPICS --create --if-not-exists --topic ndr-tls-sessions --partitions 2 --replication-factor "${KAFKA_TOPIC_RF}"
$KAFKA_CONFIGS --alter --topic ndr-tls-sessions \
  --add-config retention.ms=604800000,cleanup.policy=delete,min.insync.replicas=${KAFKA_MIN_ISR}

# TLS 指纹富化 (TlsFingerprintJob 输出): 保留 7 天
$KAFKA_TOPICS --create --if-not-exists --topic ndr-tls-enriched --partitions 2 --replication-factor "${KAFKA_TOPIC_RF}"
$KAFKA_CONFIGS --alter --topic ndr-tls-enriched \
  --add-config retention.ms=604800000,cleanup.policy=delete,min.insync.replicas=${KAFKA_MIN_ISR}

# PCAP 元数据: 保留 30 天（量小）
$KAFKA_TOPICS --create --if-not-exists --topic ndr-pcap-meta --partitions 1 --replication-factor "${KAFKA_TOPIC_RF}"
$KAFKA_CONFIGS --alter --topic ndr-pcap-meta \
  --add-config retention.ms=2592000000,cleanup.policy=delete,min.insync.replicas=${KAFKA_MIN_ISR}

# EDR Sysmon: 保留 7 天
$KAFKA_TOPICS --create --if-not-exists --topic edr-sysmon --partitions 2 --replication-factor "${KAFKA_TOPIC_RF}"
$KAFKA_CONFIGS --alter --topic edr-sysmon \
  --add-config retention.ms=604800000,retention.bytes=536870912,cleanup.policy=delete,min.insync.replicas=${KAFKA_MIN_ISR}

# EDR Windows Event Log: 保留 7 天
$KAFKA_TOPICS --create --if-not-exists --topic edr-winevent --partitions 2 --replication-factor "${KAFKA_TOPIC_RF}"
$KAFKA_CONFIGS --alter --topic edr-winevent \
  --add-config retention.ms=604800000,retention.bytes=536870912,cleanup.policy=delete,min.insync.replicas=${KAFKA_MIN_ISR}

# Suricata EVE JSON: 保留 3 天（高吞吐）
$KAFKA_TOPICS --create --if-not-exists --topic suricata-eve --partitions 3 --replication-factor "${KAFKA_TOPIC_RF}"
$KAFKA_CONFIGS --alter --topic suricata-eve \
  --add-config retention.ms=259200000,retention.bytes=536870912,cleanup.policy=delete,min.insync.replicas=${KAFKA_MIN_ISR}

echo ""
echo "=== Topic 保留策略 ==="
echo "  security-logs-raw:          3 天  (512MB)"
echo "  security-logs-validated:    5 天  (512MB)"
echo "  security-logs-rejected:    14 天"
echo "  security-logs-duplicate:    7 天"
echo "  security-events-enriched:   7 天  (1GB)"
echo "  security-events-ingest:     7 天  (1GB)"
echo "  security-sigma-hit:         7 天"
echo "  security-behavior-alerts:  30 天"
echo "  security-alerts:           30 天"
echo "  security-audit-queue:       7 天"
echo "  security-audit-results:    30 天"
echo "  security-logs-dlq:         30 天"
echo "  security-cep-partial:       7 天"
echo "  security-cep-patterns:     30 天  (compact)"
echo "  ndr-flows / -aggregated:    7 天"
echo "  ndr-tls-sessions / -enriched: 7 天"
echo "  ndr-pcap-meta:             30 天"
echo ""
echo "=== 完成 ==="
