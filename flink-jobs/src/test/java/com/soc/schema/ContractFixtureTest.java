package com.soc.schema;

import com.soc.model.AlertEvent;
import com.soc.model.SecurityEvent;
import com.soc.util.EventEnvelope;
import org.apache.flink.shaded.jackson2.com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * 与 Python contracts/fixtures 共用同一组样例。
 * 扁平历史消息、带版本字段的消息、信封包装都能反序列化。
 */
public class ContractFixtureTest {

    private final ObjectMapper mapper = new ObjectMapper();

    private String readFixture(String name) throws Exception {
        Path[] candidates = new Path[]{
                Paths.get("src/test/resources/fixtures", name),
                Paths.get("../contracts/fixtures", name),
                Paths.get("contracts/fixtures", name)
        };
        for (Path path : candidates) {
            if (Files.exists(path)) {
                return new String(Files.readAllBytes(path), StandardCharsets.UTF_8);
            }
        }
        throw new IllegalStateException("missing fixture " + name);
    }

    @Test
    public void legacyFlatEventParses() throws Exception {
        SecurityEvent event = EventEnvelope.parseSecurityEvent(
                mapper, readFixture("security_event.legacy.json"));
        assertEquals("PORT_SCAN", event.getEventType());
        assertEquals("medium", event.getSeverity());
        assertNotNull(event.getEventId());
        EventEnvelope.stamp(event, EventEnvelope.PRODUCER_LOGVAL);
        assertEquals(EventEnvelope.SCHEMA_VERSION, event.getSchemaVersion());
        assertEquals(EventEnvelope.PRODUCER_LOGVAL, event.getProducer());
    }

    @Test
    public void versionedEventParses() throws Exception {
        SecurityEvent event = EventEnvelope.parseSecurityEvent(
                mapper, readFixture("security_event.valid.json"));
        assertEquals("BRUTE_FORCE", event.getEventType());
        assertEquals("1.0.0", event.getSchemaVersion());
        assertEquals("corr-brute-1", event.getCorrelationId());
    }

    @Test
    public void envelopeUnwrapsPayload() throws Exception {
        SecurityEvent event = EventEnvelope.parseSecurityEvent(
                mapper, readFixture("security_event.envelope.json"));
        assertEquals("C2_BEACON", event.getEventType());
        assertEquals("1.0.0", event.getSchemaVersion());
        assertEquals("corr-envelope-1", event.getCorrelationId());
        assertEquals("contracts.fixture", event.getProducer());
    }

    @Test
    public void alertParsesAndStamps() throws Exception {
        AlertEvent alert = mapper.readValue(
                readFixture("alert_event.valid.json"), AlertEvent.class);
        assertEquals("ANOMALY", alert.getAlertType());
        assertEquals(0.86, alert.getAnomalyScore(), 0.0001);
        EventEnvelope.stamp(alert, EventEnvelope.PRODUCER_ANOMALY);
        assertEquals("1.0.0", alert.getSchemaVersion());
        assertEquals("corr-alert-1", alert.getCorrelationId());
    }
}
