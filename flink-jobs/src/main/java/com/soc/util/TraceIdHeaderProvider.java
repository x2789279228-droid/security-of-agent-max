package com.soc.util;

import org.apache.flink.shaded.jackson2.com.fasterxml.jackson.databind.JsonNode;
import org.apache.flink.shaded.jackson2.com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.flink.connector.kafka.sink.HeaderProvider;
import org.apache.kafka.common.header.Headers;
import org.apache.kafka.common.header.internals.RecordHeaders;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.UUID;

/**
 * 为 Kafka 消息写入标准 W3C trace 头 — 全链路追踪关键一环。
 *
 * 配合 KafkaRecordSerializationSchema.builder().setHeaderProvider(...) 使用:
 * 值序列化保持 JSON (SimpleStringSchema), 同时写入:
 *   - event_id:        稳定业务事件 ID（与 JSON eventId 一致，重试不得更换）
 *   - correlation_id:  同一项业务处理的关联标识
 *   - parent_event_id: 派生事件的来源 event_id（若有）
 *   - traceparent:     W3C 标准格式 (00-traceid-spanid-flags)
 *   - trace_id:        旧版兼容头 (traceid 原文)
 * 使下游 (Python kafka_consumer 等) 能按统一约定提取身份与 trace。
 */
public class TraceIdHeaderProvider implements HeaderProvider<String> {

    private transient ObjectMapper mapper;

    @Override
    public Headers getHeaders(String element) {
        RecordHeaders headers = new RecordHeaders();
        JsonNode node = parse(element);
        // 优先使用事件内已携带的标准 traceparent (Flink span 下发), 否则由 traceId 派生
        String traceparent = extractTraceparent(node);
        String traceId = "";
        if (traceparent.isEmpty()) {
            traceId = firstText(node, "traceId", "trace_id");
            traceparent = buildTraceparent(traceId);
        } else {
            String[] parts = traceparent.split("-");
            if (parts.length >= 2) {
                traceId = parts[1];
            }
        }
        String eventId = firstText(node, "eventId", "event_id", "alertId");
        String correlationId = firstText(node, "correlationId", "correlation_id");
        if (correlationId.isEmpty()) {
            correlationId = eventId;
        }
        String parentEventId = firstText(node, "parentEventId", "parent_event_id");
        if (!eventId.isEmpty()) {
            headers.add("event_id", eventId.getBytes(StandardCharsets.UTF_8));
        }
        if (!correlationId.isEmpty()) {
            headers.add("correlation_id", correlationId.getBytes(StandardCharsets.UTF_8));
        }
        if (!parentEventId.isEmpty()) {
            headers.add("parent_event_id", parentEventId.getBytes(StandardCharsets.UTF_8));
        }
        headers.add("trace_id", traceId.getBytes(StandardCharsets.UTF_8));
        headers.add("traceparent", traceparent.getBytes(StandardCharsets.UTF_8));
        return headers;
    }

    private JsonNode parse(String element) {
        try {
            if (mapper == null) {
                mapper = new ObjectMapper();
            }
            return mapper.readTree(element);
        } catch (Exception ignored) {
            return null;
        }
    }

    private String firstText(JsonNode node, String... fields) {
        if (node == null || !node.isObject()) {
            return "";
        }
        for (String field : fields) {
            if (node.hasNonNull(field)) {
                String value = node.get(field).asText("");
                if (value != null && !value.trim().isEmpty()) {
                    return value;
                }
            }
        }
        if (node.has("payload") && node.get("payload").isObject()) {
            JsonNode payload = node.get("payload");
            for (String field : fields) {
                if (payload.hasNonNull(field)) {
                    String value = payload.get(field).asText("");
                    if (value != null && !value.trim().isEmpty()) {
                        return value;
                    }
                }
            }
        }
        return "";
    }

    /** 从事件 JSON 提取上游 traceparent (rawData._traceparent 或顶层 traceparent) */
    private String extractTraceparent(JsonNode node) {
        if (node == null || !node.isObject()) {
            return "";
        }
        if (node.hasNonNull("traceparent")) {
            return node.get("traceparent").asText();
        }
        if (node.hasNonNull("rawData") && node.get("rawData").hasNonNull("_traceparent")) {
            return node.get("rawData").get("_traceparent").asText();
        }
        return "";
    }

    /** 由 traceId (可能带横线 UUID) 构造标准 W3C traceparent */
    private String buildTraceparent(String traceId) {
        String traceIdHex = normalizeTraceIdHex(traceId);
        String spanId = UUID.randomUUID().toString().replace("-", "").substring(0, 16);
        return "00-" + traceIdHex + "-" + spanId + "-01";
    }

    /** 规整为 32 hex; 非法输入用 MD5 确定性补齐 */
    private String normalizeTraceIdHex(String traceId) {
        String cleaned = (traceId == null ? "" : traceId).replace("-", "").toLowerCase();
        if (cleaned.matches("^[0-9a-f]{32}$")) {
            return cleaned;
        }
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] digest = md.digest(
                    (traceId == null ? "" : traceId).getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            return UUID.randomUUID().toString().replace("-", "");
        }
    }
}