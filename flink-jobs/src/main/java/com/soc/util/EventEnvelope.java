package com.soc.util;

import com.soc.model.AlertEvent;
import com.soc.model.SecurityEvent;
import org.apache.flink.shaded.jackson2.com.fasterxml.jackson.databind.JsonNode;
import org.apache.flink.shaded.jackson2.com.fasterxml.jackson.databind.ObjectMapper;

/**
 * 统一事件信封：兼容扁平历史消息。
 * 含 payload 对象且带 schemaVersion / eventId 时按信封拆开，否则整份当业务事件。
 */
public final class EventEnvelope {

    public static final String SCHEMA_VERSION = "1.0.0";
    public static final String PRODUCER_LOGVAL = "flink.LogValidationJob";
    public static final String PRODUCER_ANOMALY = "flink.AnomalyDetectionJob";

    private EventEnvelope() {
    }

    public static boolean isEnvelope(JsonNode root) {
        if (root == null || !root.isObject()) {
            return false;
        }
        JsonNode payload = root.get("payload");
        if (payload == null || !payload.isObject()) {
            return false;
        }
        return hasText(root, "schemaVersion")
                || hasText(root, "schema_version")
                || hasText(root, "eventId")
                || hasText(root, "event_id");
    }

    public static SecurityEvent parseSecurityEvent(ObjectMapper mapper, String json) throws Exception {
        JsonNode root = mapper.readTree(json);
        SecurityEvent event;
        if (isEnvelope(root)) {
            event = mapper.treeToValue(root.get("payload"), SecurityEvent.class);
            applyEnvelope(event, root);
        } else {
            event = mapper.treeToValue(root, SecurityEvent.class);
        }
        return event;
    }

    public static void stamp(SecurityEvent event, String producer) {
        if (event == null) {
            return;
        }
        if (isBlank(event.getSchemaVersion())) {
            event.setSchemaVersion(SCHEMA_VERSION);
        }
        if (isBlank(event.getProducer())) {
            event.setProducer(producer);
        }
        if (isBlank(event.getCorrelationId())) {
            event.setCorrelationId(event.getEventId());
        }
        if (event.getOccurredAt() == null) {
            long ts = event.getTimestamp() != 0 ? event.getTimestamp() : System.currentTimeMillis();
            event.setOccurredAt(ts);
        }
    }

    public static void stamp(AlertEvent alert, String producer) {
        if (alert == null) {
            return;
        }
        if (isBlank(alert.getSchemaVersion())) {
            alert.setSchemaVersion(SCHEMA_VERSION);
        }
        if (isBlank(alert.getProducer())) {
            alert.setProducer(producer);
        }
        if (isBlank(alert.getCorrelationId())) {
            String corr = alert.getParentEventId();
            if (isBlank(corr)) {
                corr = alert.getAlertId();
            }
            alert.setCorrelationId(corr);
        }
        if (alert.getOccurredAt() == null) {
            long ts = alert.getTimestamp() != 0 ? alert.getTimestamp() : System.currentTimeMillis();
            alert.setOccurredAt(ts);
        }
    }

    private static void applyEnvelope(SecurityEvent event, JsonNode root) {
        if (isBlank(event.getSchemaVersion())) {
            event.setSchemaVersion(text(root, "schemaVersion", "schema_version"));
        }
        if (isBlank(event.getProducer())) {
            event.setProducer(text(root, "producer"));
        }
        if (isBlank(event.getCorrelationId())) {
            event.setCorrelationId(text(root, "correlationId", "correlation_id"));
        }
        if (event.getOccurredAt() == null) {
            event.setOccurredAt(longVal(root, "occurredAt", "occurred_at"));
        }
        if (isBlank(event.getEventId())) {
            event.setEventId(text(root, "eventId", "event_id"));
        }
        if (isBlank(event.getParentEventId())) {
            event.setParentEventId(text(root, "parentEventId", "parent_event_id"));
        }
        if (isBlank(event.getTraceId()) && !isBlank(event.getCorrelationId())) {
            event.setTraceId(event.getCorrelationId());
        }
    }

    private static boolean hasText(JsonNode root, String field) {
        JsonNode node = root.get(field);
        return node != null && !node.isNull() && node.asText("").trim().length() > 0;
    }

    private static String text(JsonNode root, String... fields) {
        for (String field : fields) {
            JsonNode node = root.get(field);
            if (node != null && !node.isNull()) {
                String value = node.asText("");
                if (value != null && !value.trim().isEmpty()) {
                    return value;
                }
            }
        }
        return null;
    }

    private static Long longVal(JsonNode root, String... fields) {
        for (String field : fields) {
            JsonNode node = root.get(field);
            if (node != null && node.isNumber()) {
                return node.asLong();
            }
        }
        return null;
    }

    private static boolean isBlank(String value) {
        return value == null || value.trim().isEmpty();
    }
}
