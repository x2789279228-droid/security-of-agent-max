package com.soc.util;

import org.apache.kafka.common.serialization.StringDeserializer;
import org.apache.kafka.common.serialization.StringSerializer;

import java.util.Properties;

/**
 * Kafka 配置工具类
 * 集中管理所有 Kafka Topic 名称和连接配置
 */
public class KafkaConfig {

    private static final org.slf4j.Logger LOG =
            org.slf4j.LoggerFactory.getLogger(KafkaConfig.class);

    // ==================== Kafka Topic 定义 ====================

    /** 原始安全日志 - 所有来源的日志统一入口 */
    public static final String TOPIC_RAW_LOGS = "security-logs-raw";

    /** 已验证日志 - 经过 Schema 校验和来源认证 */
    public static final String TOPIC_VALIDATED_LOGS = "security-logs-validated";

    /** 被拒绝日志 - 校验失败或认证不通过的日志 */
    public static final String TOPIC_REJECTED_LOGS = "security-logs-rejected";

    /**
     * 重复事件 - 60 秒窗口去重命中 (P0-4)。
     * "重复"不是数据质量问题, 混进 rejected 会污染按拒绝原因告警的口径;
     * 独立 topic 后去重率/漏报可单独观测, 合法重复(如防火墙重复 deny)可回放。
     */
    public static final String TOPIC_DUPLICATE_LOGS = "security-logs-duplicate";

    /** 已富化事件 - 附带异常评分的事件 */
    public static final String TOPIC_ENRICHED_EVENTS = "security-events-enriched";

    /** 安全告警 - 高优先级告警 */
    public static final String TOPIC_ALERTS = "security-alerts";

    /** 审计队列 - 等待 LLM 审计的事件 */
    public static final String TOPIC_AUDIT_QUEUE = "security-audit-queue";

    /** 死信队列 - 处理失败的消息 */
    public static final String TOPIC_DLQ = "security-logs-dlq";

    /** CEP 部分匹配 - 攻击链中间状态（可视化用）*/
    public static final String TOPIC_CEP_PARTIAL = "security-cep-partial";

    /** CEP 模式配置 - Broadcast 热更新通道 */
    public static final String TOPIC_CEP_PATTERNS = "security-cep-patterns";

    /** Sigma 聚合候选 - pySigma 单事件命中带聚合聚合规则(如 SIG-001/007)的事件; Flink 阈值窗口消费 */
    public static final String TOPIC_SIGMA_HIT = "security-sigma-hit";

    /** NDR 流聚合结果 - FlowAggregationJob 输出 */
    public static final String TOPIC_FLOWS_AGGREGATED = "ndr-flows-aggregated";

    /** 行为基线告警 - BehaviorAnomalyJob 输出，绕过厂商 threat_type */
    public static final String TOPIC_BEHAVIOR_ALERTS = "security-behavior-alerts";

    // ==================== Kafka 连接配置 ====================

    /** Kafka Bootstrap 服务器地址，支持环境变量覆盖 */
    public static final String KAFKA_BOOTSTRAP;

    // ── 安全连接（生产化: 内部链路 SASL_SSL; 默认 PLAINTEXT 保持演示兼容）──
    // compose 经环境变量注入; 三个核心作业的 KafkaSource/KafkaSink 必须经
    // securityProps() 应用同一份配置, 与 backend 的 kafka_security.py 同源。
    public static final String SECURITY_PROTOCOL = envOrDefault("KAFKA_SECURITY_PROTOCOL", "PLAINTEXT");
    public static final String SASL_MECHANISM = envOrDefault("KAFKA_SASL_MECHANISM", "SCRAM-SHA-512");
    public static final String SASL_USERNAME = envOrDefault("KAFKA_SASL_USERNAME", "");
    public static final String SASL_PASSWORD = envOrDefault("KAFKA_SASL_PASSWORD", "");
    /** 自签名 CA 的 PEM 文件（容器内路径）; 空表示用 JVM 默认信任库 */
    public static final String SSL_CA_FILE = envOrDefault("KAFKA_SSL_CA_FILE", "");
    /** 证书 SAN 与 bootstrap 主机名一致时可保持默认 https; 演示自签可置空 */
    public static final String SSL_ENDPOINT_ID = envOrDefault("KAFKA_SSL_ENDPOINT_IDENTIFICATION_ALGORITHM", "");

    static {
        String env = System.getenv("KAFKA_BOOTSTRAP");
        KAFKA_BOOTSTRAP = (env != null && !env.isEmpty()) ? env : "localhost:9092";
    }

    private static String envOrDefault(String name, String def) {
        String v = System.getenv(name);
        return (v != null && !v.isEmpty()) ? v : def;
    }

    /**
     * 客户端安全属性（source/sink 通用）。
     * PLAINTEXT（默认）返回仅含 bootstrap 的 Properties —— 行为与历史版本一致;
     * SASL_SSL 时附带 SCRAM 认证与 TLS 信任配置。
     */
    public static java.util.Properties clientSecurityProps() {
        java.util.Properties props = new java.util.Properties();
        props.setProperty("bootstrap.servers", KAFKA_BOOTSTRAP);
        if ("PLAINTEXT".equalsIgnoreCase(SECURITY_PROTOCOL)) {
            return props;
        }
        props.setProperty("security.protocol", SECURITY_PROTOCOL);
        if (SECURITY_PROTOCOL.contains("SASL")) {
            props.setProperty("sasl.mechanism", SASL_MECHANISM);
            boolean scram = SASL_MECHANISM.startsWith("SCRAM");
            String module = scram
                    ? "org.apache.kafka.common.security.scram.ScramLoginModule"
                    : "org.apache.kafka.common.security.plain.PlainLoginModule";
            props.setProperty("sasl.jaas.config",
                    module + " required username=\"" + SASL_USERNAME
                            + "\" password=\"" + SASL_PASSWORD + "\";");
        }
        if (SECURITY_PROTOCOL.contains("SSL")) {
            // 自签演示证书: endpoint 校验默认关(KAFKA_SSL_ENDPOINT_IDENTIFICATION_ALGORITHM 可覆盖)
            props.setProperty("ssl.endpoint.identification.algorithm", SSL_ENDPOINT_ID);
            String pem = readPemFile(SSL_CA_FILE);
            if (!pem.isEmpty()) {
                // kafka-clients 3.x 支持内联 PEM 信任库 —— 免维护 JKS/PKCS12
                props.setProperty("ssl.truststore.type", "PEM");
                props.setProperty("ssl.truststore.certificates", pem);
            } else if (!SSL_CA_FILE.isEmpty()) {
                LOG.error("KAFKA_SSL_CA_FILE={} 存在但读取为空 — TLS 握手将失败", SSL_CA_FILE);
            }
        }
        return props;
    }

    private static String readPemFile(String path) {
        if (path == null || path.isEmpty()) {
            return "";
        }
        try {
            byte[] bytes = java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(path));
            return new String(bytes, java.nio.charset.StandardCharsets.UTF_8).trim();
        } catch (Exception e) {
            LOG.warn("read CA pem failed: {} ({})", path, e.getMessage());
            return "";
        }
    }

    /**
     * 获取 Kafka Bootstrap 服务器地址
     *
     * @return bootstrap servers 字符串
     */
    public static String getBootstrapServers() {
        return KAFKA_BOOTSTRAP;
    }

    /**
     * 获取 Kafka 消费者配置
     *
     * @param groupId 消费者组 ID
     * @return 消费者 Properties
     */
    public static Properties getConsumerProperties(String groupId) {
        Properties props = new Properties();
        props.setProperty("bootstrap.servers", KAFKA_BOOTSTRAP);
        props.setProperty("group.id", groupId);
        props.setProperty("key.deserializer", StringDeserializer.class.getName());
        props.setProperty("value.deserializer", StringDeserializer.class.getName());
        // 从最早的消息开始消费（演示环境）
        props.setProperty("auto.offset.reset", "earliest");
        // 安全配置与 KafkaSource/Sink 同源 (PLAINTEXT 时为空操作)
        for (java.util.Map.Entry<Object, Object> e : clientSecurityProps().entrySet()) {
            props.setProperty(String.valueOf(e.getKey()), String.valueOf(e.getValue()));
        }
        return props;
    }

    /**
     * 获取 Kafka 生产者配置
     *
     * @return 生产者 Properties
     */
    public static Properties getProducerProperties() {
        Properties props = new Properties();
        props.setProperty("bootstrap.servers", KAFKA_BOOTSTRAP);
        props.setProperty("key.serializer", StringSerializer.class.getName());
        props.setProperty("value.serializer", StringSerializer.class.getName());
        return props;
    }

    private KafkaConfig() {
        // 工具类，禁止实例化
    }
}
