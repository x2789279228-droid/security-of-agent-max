"""稳定 event_id 贯穿 HTTP / Kafka / DB / DLQ / SSE。"""
import asyncio

import pytest

from event_envelope import stamp_identity
from event_identity import (
    HEADER_CORRELATION_ID,
    HEADER_EVENT_ID,
    HEADER_PARENT_EVENT_ID,
    HEADER_TRACE_ID,
    apply_headers,
    bus_fields,
    derive_from,
    ensure_identity,
    get_event_id,
    identity_headers,
    is_stored_id,
    resolve,
)
from event_bus import positive_event_id


STABLE = "11111111-2222-4333-8444-555555555555"


def test_retry_keeps_same_event_id():
    first = ensure_identity({"event": "BRUTE_FORCE", "eventId": STABLE})
    second = ensure_identity(first)
    third = ensure_identity({"event_id": STABLE, "message": "retry"})
    assert first["eventId"] == STABLE
    assert second["eventId"] == STABLE
    assert third["eventId"] == STABLE
    assert first["correlationId"] == STABLE


def test_missing_event_id_is_minted_once():
    msg = {"event": "PORT_SCAN", "message": "scan"}
    stamped = ensure_identity(msg)
    eid = stamped["eventId"]
    assert eid
    assert ensure_identity(stamped)["eventId"] == eid
    assert stamped["correlationId"] == eid


def test_integer_event_id_is_stored_id_not_business_id():
    assert is_stored_id(12) is True
    assert is_stored_id("12") is True
    assert is_stored_id(STABLE) is False
    msg = ensure_identity({"event_id": 42, "event": "X"})
    assert msg["eventId"] != "42"
    assert msg["event_id"] == 42
    assert get_event_id(msg) == msg["eventId"]


def test_correlation_does_not_fall_back_to_trace_id():
    stamped = stamp_identity(
        {"eventId": STABLE, "traceId": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "event": "X"},
        producer="unit",
    )
    assert stamped["eventId"] == STABLE
    assert stamped["correlationId"] == STABLE
    assert stamped["traceId"] == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"


def test_derive_from_creates_parent_link():
    parent = ensure_identity({"eventId": STABLE, "correlationId": "corr-1"})
    child = derive_from(parent, extra={"alertType": "ANOMALY"}, producer="flink.alert")
    assert child["eventId"] != STABLE
    assert child["parentEventId"] == STABLE
    assert child["correlationId"] == "corr-1"
    assert ensure_identity(child)["eventId"] == child["eventId"]


def test_identity_headers_and_apply_do_not_overwrite_body():
    body = {"eventId": STABLE, "correlationId": "corr-1"}
    headers = identity_headers(body, trace_id="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
    names = {k: v.decode("utf-8") for k, v in headers}
    assert names[HEADER_EVENT_ID] == STABLE
    assert names[HEADER_CORRELATION_ID] == "corr-1"
    assert names[HEADER_TRACE_ID]

    merged = apply_headers(
        {"message": "plain"},
        [
            (HEADER_EVENT_ID, STABLE.encode()),
            (HEADER_PARENT_EVENT_ID, b"parent-9"),
        ],
    )
    assert merged["eventId"] == STABLE
    assert merged["parentEventId"] == "parent-9"
    kept = apply_headers({"eventId": "keep-me"}, [(HEADER_EVENT_ID, STABLE.encode())])
    assert kept["eventId"] == "keep-me"


def test_nested_body_and_headers_round_trip():
    wrapper = {
        "uuid": "old-transport",
        "body": {"eventId": STABLE, "event": "LOGIN"},
    }
    ident = resolve(wrapper)
    assert ident.event_id == STABLE
    filled = apply_headers(
        {"body": {"event": "LOGIN"}},
        [(HEADER_EVENT_ID, STABLE.encode())],
    )
    assert filled["eventId"] == STABLE
    assert filled["body"]["eventId"] == STABLE


def test_bus_fields_keep_integer_cursor():
    payload = bus_fields(
        stored_id=12,
        event={"eventId": STABLE, "correlationId": "corr-1"},
        trace_id="trace-z",
    )
    assert payload["event_id"] == 12
    assert payload["stored_id"] == 12
    assert payload["eventId"] == STABLE
    assert payload["correlationId"] == "corr-1"
    assert positive_event_id(payload) == 12
    assert positive_event_id({"eventId": STABLE}) is None


def test_dlq_event_id_from_headers():
    from dlq_store import event_id_of

    assert event_id_of({"message": "x"}, [(HEADER_EVENT_ID, STABLE.encode())]) == STABLE
    assert event_id_of({"eventId": STABLE, "event_id": 99}) == STABLE
    assert event_id_of({"id": 7}) == ""


@pytest.mark.asyncio
async def test_produce_raw_writes_event_id_header(monkeypatch):
    from capacity import reset_gates
    from kafka_producer import KafkaProducerWrapper

    reset_gates()
    sent = []

    class Producer:
        def send(self, topic, key, value, headers):
            sent.append({"key": key, "value": value, "headers": headers})
            loop = asyncio.get_running_loop()
            fut = loop.create_future()
            fut.set_result("ok")
            return fut

    wrapper = KafkaProducerWrapper()
    wrapper._started = True
    wrapper._producer = Producer()
    n = await wrapper.produce_raw_batch(
        [{
            "eventId": STABLE,
            "eventType": "BRUTE_FORCE",
            "severity": "high",
            "message": "brute",
            "timestamp": 1710000000000,
        }],
        topic="security-events-enriched",
        key_field="eventId",
    )
    assert n == 1
    names = {k: v.decode("utf-8") for k, v in sent[0]["headers"]}
    assert names[HEADER_EVENT_ID] == STABLE
    assert sent[0]["value"]["eventId"] == STABLE
    retry = stamp_identity(sent[0]["value"])
    assert retry["eventId"] == STABLE


@pytest.mark.asyncio
async def test_retry_envelope_keeps_payload_event_id():
    from kafka_consumer import KafkaConsumerManager, _business_key

    sent = []

    class Producer:
        async def send_and_wait(self, topic, key, value, headers=None):
            sent.append({"topic": topic, "key": key, "value": value, "headers": headers})

    mgr = KafkaConsumerManager()
    mgr._dlq_producer = Producer()
    payload = {"eventId": STABLE, "eventType": "PORT_SCAN"}
    ok = await mgr._send_to_retry_topic(
        "security-events-enriched", payload, "timeout", 1, partition=0, offset=9,
    )
    assert ok is True
    assert sent[0]["value"]["payload"]["eventId"] == STABLE
    assert sent[0]["value"]["eventId"] == STABLE
    names = {k: v.decode("utf-8") for k, v in sent[0]["headers"]}
    assert names[HEADER_EVENT_ID] == STABLE
    assert _business_key(payload) == STABLE


@pytest.mark.asyncio
async def test_store_uses_snake_case_event_id_and_keeps_it():
    from models import Base, SecurityEvent, async_session, engine
    from event_store import event_store
    from sqlalchemy import select, func

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)

    payload = {
        "event_id": STABLE,
        "event": "BRUTE_FORCE",
        "severity": "high",
        "message": "brute",
    }
    async with async_session() as s:
        first = await event_store.store(s, payload, "sess-id")
        second = await event_store.store(s, {"eventId": STABLE, "event": "BRUTE_FORCE", "severity": "high", "message": "retry"}, "sess-id")
        total = (await s.execute(select(func.count(SecurityEvent.id)))).scalar()
        assert total == 1
        assert first.id == second.id
        assert first.event_id == STABLE
        row = (await s.execute(select(SecurityEvent).where(SecurityEvent.event_id == STABLE))).scalar_one()
        assert row.event_id == STABLE
        assert (row.raw_data or {}).get("eventId") == STABLE
