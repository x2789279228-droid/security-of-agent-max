package com.soc.model;

import org.apache.flink.shaded.jackson2.com.fasterxml.jackson.databind.JsonNode;
import org.apache.flink.shaded.jackson2.com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * enriched 事件序列化契约: 可选字段未赋值时不得输出 null 键。
 *
 * 2026-10-25 审计: 裸 ObjectMapper 默认输出 null 字段, 每条 enriched 事件
 * 都带 "parentEventId": null, 被后端 JSON Schema(当时为纯 string)全量拒收,
 * 消费者组被毒丸永久卡死。SecurityEvent 现标 @JsonInclude(NON_NULL),
 * 本测试用与 AnomalyDetectionJob 相同的裸 mapper 钉死该行为。
 */
public class SecurityEventSerializationTest {

    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    public void nullOptionalFieldsAreOmitted() throws Exception {
        SecurityEvent event = new SecurityEvent(
                "evt-1", "src-1", "key-1", "BRUTE_FORCE", "high",
                null, null, null, "failed login", 0.9, null, 1730000000000L);

        JsonNode node = mapper.readTree(mapper.writeValueAsString(event));

        assertFalse(node.has("parentEventId"), "parentEventId 为 null 不得出现在 enriched JSON");
        assertFalse(node.has("srcIp"));
        assertFalse(node.has("dstIp"));
        assertFalse(node.has("traceId"));
        assertFalse(node.has("schemaVersion"));
        assertFalse(node.has("producer"));
        assertFalse(node.has("correlationId"));
        assertFalse(node.has("occurredAt"));
    }

    @Test
    public void assignedFieldsAreKept() throws Exception {
        SecurityEvent event = new SecurityEvent(
                "evt-2", "src-2", "key-2", "PORT_SCAN", "medium",
                "10.0.0.8", "10.0.0.42", "tcp", "scan", 0.7, null, 1730000000001L);
        event.setParentEventId("evt-parent-9");
        event.setTraceId("trace-abc");

        JsonNode node = mapper.readTree(mapper.writeValueAsString(event));

        assertTrue(node.hasNonNull("parentEventId"));
        assertTrue(node.hasNonNull("srcIp"));
        assertTrue(node.hasNonNull("traceId"));
        // 必填四件套 + primitive 字段永远在
        assertTrue(node.hasNonNull("eventId"));
        assertTrue(node.hasNonNull("eventType"));
        assertTrue(node.hasNonNull("severity"));
        assertTrue(node.hasNonNull("message"));
        assertTrue(node.has("timestamp"));
    }
}
