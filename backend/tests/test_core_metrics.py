"""六组核心运营指标：低基数标签、结构化日志、告警触发。"""
import logging

from prometheus_client import generate_latest

import core_metrics as cm
from event_bus import EventBus


def _text() -> str:
    return generate_latest().decode()


def test_metric_labels_never_include_event_id():
    offenders = cm.assert_no_high_cardinality_labels()
    assert offenders == []


def test_clamp_reason_drops_uuid_and_numeric_ids():
    assert cm.clamp_reason("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee") == "other"
    assert cm.clamp_reason("12345678901") == "other"
    assert cm.clamp_reason("schema_invalid") == "schema_invalid"
    assert cm.clamp_reason("decode") == "decode"


def test_log_process_records_event_id_stage_result_reason_retry(caplog):
    caplog.set_level(logging.DEBUG)
    cm.log_process(
        logging.getLogger("soc.core_metrics"),
        event_id="evt-stable-1",
        stage="persist",
        result="fail",
        reason="timeout",
        retry_count=3,
    )
    assert "event.process" in caplog.text
    assert "event_id=evt-stable-1" in caplog.text
    assert "stage=persist" in caplog.text
    assert "result=fail" in caplog.text
    assert "reason=timeout" in caplog.text
    assert "retry=3" in caplog.text


def test_ingest_and_pipeline_helpers_export_names():
    cm.record_ingest("http", "queued")
    cm.record_ingest("http", "rejected", reason="overloaded")
    cm.record_ingest("kafka", "validation_failed", reason="schema")
    cm.observe_pipeline_e2e(0.12, "success")
    cm.observe_pipeline_stage("detect", 0.01, "success")
    cm.inc_pipeline_result("persist", "fail")
    cm.set_kafka_lag("security-events-ingest", 12, 4.5)
    text = _text()
    assert "soc_ingest_received_total" in text
    assert "soc_ingest_rejected_total" in text
    assert "soc_ingest_validation_failed_total" in text
    assert "soc_pipeline_e2e_seconds" in text
    assert "soc_pipeline_stage_seconds" in text
    assert "soc_pipeline_results_total" in text
    assert "soc_kafka_consumer_lag" in text
    assert "soc_kafka_oldest_lag_seconds" in text
    assert 'topic="security-events-ingest"' in text
    assert 'event_id="' not in text


def test_kafka_loop_alive_and_restart_export_low_cardinality_labels():
    cm.set_kafka_loop_alive("audit", True)
    cm.note_kafka_loop_restart("audit")
    cm.set_kafka_loop_alive("not-a-real-loop", True)
    text = _text()
    assert "soc_kafka_consumer_alive" in text
    assert "soc_kafka_consumer_restarts_total" in text
    assert 'loop="audit"' in text
    assert 'loop="other"' in text
    assert 'event_id="' not in text


def test_dlq_depth_and_wait_and_backlog_alert():
    cm._DLQ_OPEN.clear()
    cm.DLQ_DEPTH.set(0)
    cm.record_dlq_persisted("schema_invalid", wait_seconds=12, record_id=42, first_failed_epoch=1)
    assert 42 in cm._DLQ_OPEN
    text = _text()
    assert "soc_dlq_messages_total" in text
    assert "soc_dlq_depth" in text
    assert cm._ALERT_STATE["SocDlqBacklog"] == 1
    cm.note_dlq_closed(42)
    assert 42 not in cm._DLQ_OPEN
    assert cm._ALERT_STATE["SocDlqBacklog"] == 0


def test_eventbus_drop_and_disconnect_metrics():
    bus = EventBus(max_subscribers=4)
    bus._queue_max = 1
    bus._critical_queue_max = 1
    sub = bus.subscribe()
    assert sub is not None
    bus.publish("heartbeat", {"n": 1})
    bus.publish("heartbeat", {"n": 2})
    bus.publish("heartbeat", {"n": 3})
    text = _text()
    assert "soc_eventbus_drops_total" in text
    assert "soc_eventbus_queue_depth" in text
    bus.unsubscribe(sub)
    assert "soc_eventbus_disconnects_total" in _text()


def test_critical_drop_is_unexpected_and_fires_alert():
    cm.note_eventbus_drop("critical")
    text = _text()
    assert "soc_unexpected_drops_total" in text
    assert 'kind="eventbus_critical"' in text
    assert cm._ALERT_STATE["SocEventBusDrop"] == 1
    assert cm._ALERT_STATE["SocUnexpectedDrop"] == 1


def test_shutdown_leftover_and_volatile_lost_are_alerted():
    cm.record_shutdown_leftover("audit_worker", leftover=2, spilled=1, lost=1)
    text = _text()
    assert "soc_lifecycle_leftover_tasks" in text
    assert "soc_lifecycle_shutdown_leftover_total" in text
    assert cm._ALERT_STATE["SocShutdownLeftoverTasks"] == 1
    assert cm._ALERT_STATE["SocUnexpectedDrop"] == 1


def test_cache_helpers_hit_miss_expired():
    cm.record_cache("event_store", "hit")
    cm.record_cache("event_store", "miss")
    cm.record_cache("event_store", "expired")
    cm.record_cache_invalidate_failure("event_store")
    text = _text()
    assert "soc_cache_requests_total" in text
    assert "soc_cache_invalidate_failures_total" in text
    assert 'result="expired"' in text


def test_catchup_counter():
    cm.inc_eventbus_catchup(3)
    assert "soc_eventbus_catchup_events_total" in _text()
