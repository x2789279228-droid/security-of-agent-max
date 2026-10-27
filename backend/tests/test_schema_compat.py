"""统一 Schema 版本、信封、对齐门禁、Registry 409 处理。"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from event_envelope import (
    DEFAULT_SCHEMA_VERSION,
    is_envelope,
    stamp_identity,
    unwrap,
    version_errors,
    wrap,
)
from schema_compat import (
    compatibility_issues,
    find_repo_root,
    run_gate,
    schemas_equal,
)
from schema_registry import RegisterOutcome, SchemaRegistryClient, schema_registry


ROOT = find_repo_root()
FIXTURES = ROOT / "contracts" / "fixtures"


def _load(name: str) -> dict:
    with (FIXTURES / name).open(encoding="utf-8") as f:
        return json.load(f)


# ── 信封 ──────────────────────────────────────────────────────────


def test_legacy_message_is_not_envelope():
    legacy = _load("security_event.legacy.json")
    assert is_envelope(legacy) is False
    opened = unwrap(legacy)
    assert opened.wrapped is False
    assert opened.payload["eventType"] == "PORT_SCAN"
    assert schema_registry.validate("security-events-enriched", legacy) == []


def test_envelope_unwraps_and_validates_payload():
    msg = _load("security_event.envelope.json")
    assert is_envelope(msg) is True
    opened = unwrap(msg)
    assert opened.wrapped is True
    assert opened.payload["eventType"] == "C2_BEACON"
    assert opened.schema_version == "1.0.0"
    assert schema_registry.validate("security-events-enriched", msg) == []


def test_envelope_rejects_bad_payload():
    msg = wrap(
        {"eventId": "x", "eventType": "BRUTE_FORCE", "severity": "nope",
         "message": "m", "timestamp": 1750000000000},
        producer="test",
        occurred_at=1750000000000,
        event_id="x",
        event_type="security.event",
    )
    errors = schema_registry.validate("security-events-enriched", msg)
    assert errors


def test_wrap_roundtrip_fields():
    payload = _load("security_event.legacy.json")
    env = wrap(payload, producer="unit-test", correlation_id="c1")
    assert env["schemaVersion"] == DEFAULT_SCHEMA_VERSION
    assert env["producer"] == "unit-test"
    assert env["correlationId"] == "c1"
    assert env["payload"]["eventType"] == "PORT_SCAN"
    opened = unwrap(env)
    assert opened.payload["eventId"] == payload["eventId"]


def test_stamp_identity_does_not_wrap():
    legacy = _load("security_event.legacy.json")
    stamped = stamp_identity(legacy, producer="backend.test", correlation_id="t1")
    assert is_envelope(stamped) is False
    assert stamped["schemaVersion"] == DEFAULT_SCHEMA_VERSION
    assert stamped["producer"] == "backend.test"
    assert stamped["correlationId"] == "t1"
    assert "payload" not in stamped
    assert schema_registry.validate("security-events-enriched", stamped) == []


def test_major_version_mismatch_is_rejected():
    event = _load("security_event.valid.json")
    event["schemaVersion"] = "2.0.0"
    errors = schema_registry.validate("security-events-enriched", event)
    assert any("主版本" in e for e in errors)
    assert version_errors("2.0.0", "1.0.0")
    assert version_errors("1.4.0", "1.0.0") == []
    assert version_errors("", "1.0.0") == []


def test_snake_case_envelope_is_accepted():
    payload = _load("security_event.legacy.json")
    msg = {
        "event_id": payload["eventId"],
        "event_type": "security.event",
        "schema_version": "1.0.0",
        "occurred_at": payload["timestamp"],
        "producer": "unit",
        "correlation_id": "c-snake",
        "payload": payload,
    }
    assert is_envelope(msg) is True
    assert schema_registry.validate("security-audit-queue", msg) == []


# ── 兼容性检查器 ──────────────────────────────────────────────────


def _base_schema():
    return {
        "type": "object",
        "properties": {
            "eventId": {"type": "string"},
            "severity": {"type": "string", "enum": ["low", "high"]},
            "score": {"type": "number"},
        },
        "required": ["eventId"],
        "additionalProperties": True,
    }


def test_compat_optional_field_is_allowed():
    old = _base_schema()
    new = _base_schema()
    new["properties"]["producer"] = {"type": "string"}
    assert compatibility_issues(new, old, "FULL") == []


def test_compat_new_required_field_is_backward_break():
    old = _base_schema()
    new = _base_schema()
    new["properties"]["must"] = {"type": "string"}
    new["required"] = ["eventId", "must"]
    issues = compatibility_issues(new, old, "FULL")
    assert any("BACKWARD" in i and "must" in i for i in issues)


def test_compat_type_change_is_break():
    old = _base_schema()
    new = _base_schema()
    new["properties"]["score"] = {"type": "string"}
    issues = compatibility_issues(new, old, "FULL")
    assert any("score" in i for i in issues)


def test_compat_enum_add_breaks_old_consumer():
    old = _base_schema()
    new = _base_schema()
    new["properties"]["severity"]["enum"] = ["low", "high", "critical"]
    issues = compatibility_issues(new, old, "FULL")
    assert any("FORWARD" in i and "severity" in i for i in issues)


def test_compat_remove_required_breaks_old_consumer():
    old = _base_schema()
    old["required"] = ["eventId", "score"]
    old["properties"]["score"] = {"type": "number"}
    new = _base_schema()
    issues = compatibility_issues(new, old, "FULL")
    assert any("FORWARD" in i and "score" in i for i in issues)


def test_catalog_alignment_and_fixtures_pass():
    issues = run_gate(ROOT)
    assert issues == [], issues


# ── 可空性对齐(2026-10-25 parentEventId 漂移回归) ──────────────────


def test_avro_nullable_json_strict_is_alignment_break():
    """Avro 可空 + JSON 纯类型 = 消费端会拒收 null, 门禁必须报(旧实现剥 null 后失明)。"""
    from schema_compat import alignment_issues

    js = {
        "type": "object",
        "properties": {"parentEventId": {"type": "string"}},
        "required": [],
        "additionalProperties": True,
    }
    avro = {"fields": [{"name": "parentEventId", "type": ["null", "string"], "default": None}]}
    issues = alignment_issues(js, avro, None)
    assert any("parentEventId" in i and "可空" in i for i in issues), issues


def test_avro_nullable_json_nullable_passes():
    from schema_compat import alignment_issues

    js = {
        "type": "object",
        "properties": {"parentEventId": {"type": ["string", "null"]}},
        "required": [],
        "additionalProperties": True,
    }
    avro = {"fields": [{"name": "parentEventId", "type": ["null", "string"], "default": None}]}
    assert alignment_issues(js, avro, None) == []


def test_writer_nullable_reader_strict_is_forward_break():
    """JSON 演化把字段收紧为非空(旧 reader 视角)也必须被 FULL 模式抓住。"""
    old = _base_schema()
    new = _base_schema()
    new["properties"]["score"] = {"type": ["number", "null"]}
    issues = compatibility_issues(new, old, "FULL")
    assert any("FORWARD" in i and "score" in i for i in issues), issues


def test_security_event_accepts_null_optional_fields():
    """Flink 存量消息的可空字段漂移不得再毒丸化消费者。"""
    event = _load("security_event.legacy.json")
    for key, value in (
        ("parentEventId", None), ("schemaVersion", None),
        ("producer", None), ("correlationId", None), ("occurredAt", None),
    ):
        event[key] = value
    assert schema_registry.validate("security-events-enriched", event) == []


def test_python_and_flink_share_fixtures():
    java_dir = ROOT / "flink-jobs" / "src" / "test" / "resources" / "fixtures"
    for name in (
        "security_event.valid.json",
        "security_event.legacy.json",
        "security_event.envelope.json",
        "alert_event.valid.json",
    ):
        left = json.loads((FIXTURES / name).read_text(encoding="utf-8"))
        right = json.loads((java_dir / name).read_text(encoding="utf-8"))
        assert left == right, name


def test_source_does_not_treat_raw_409_as_success():
    text = (ROOT / "backend" / "schema_registry.py").read_text(encoding="utf-8")
    assert "status_code in (200, 201, 409)" not in text
    assert "_resolve_conflict" in text
    assert "duplicate_identical" in text


# ── Registry 409 ─────────────────────────────────────────────────


class _Resp:
    def __init__(self, status, payload=None, text=""):
        self.status_code = status
        self._payload = payload if payload is not None else {}
        self.text = text or json.dumps(self._payload)

    def json(self):
        return self._payload


class _FakeClient:
    def __init__(self):
        self.posts = []
        self.gets = []
        self.register_status = 200
        self.register_body = {"id": 7, "version": 1}
        self.lookup_status = 404
        self.lookup_body = {}
        self.latest_status = 200
        self.latest_body = {"id": 7, "version": 1, "schema": "{}"}

    async def post(self, url, json=None):
        self.posts.append((url, json))
        if url.endswith("/versions"):
            return _Resp(self.register_status, self.register_body, "conflict")
        return _Resp(self.lookup_status, self.lookup_body)

    async def get(self, url):
        self.gets.append(url)
        return _Resp(self.latest_status, self.latest_body)


def _client() -> SchemaRegistryClient:
    reg = SchemaRegistryClient()
    reg._registry_base = "http://registry.test"
    return reg


def test_register_200_is_success():
    fake = _FakeClient()
    reg = _client()
    schema = {"type": "object"}
    out = asyncio.run(reg.register_schema("security-alerts-value", schema, fake))
    assert out.ok is True
    assert out.idempotent is False
    assert out.status_code == 200


def test_register_409_identical_is_idempotent():
    schema = {"title": "T", "type": "object"}
    fake = _FakeClient()
    fake.register_status = 409
    fake.register_body = {"error_code": 409, "message": "incompatible"}
    fake.lookup_status = 200
    fake.lookup_body = {
        "id": 3,
        "version": 1,
        "schema": json.dumps(schema),
    }
    reg = _client()
    out = asyncio.run(reg.register_schema("security-alerts-value", schema, fake))
    assert out.ok is True
    assert out.idempotent is True
    assert out.reason == "duplicate_identical"


def test_register_409_different_content_fails():
    schema = {"title": "New", "type": "object"}
    fake = _FakeClient()
    fake.register_status = 409
    fake.register_body = {"error_code": 409, "message": "Schema being registered is incompatible"}
    fake.lookup_status = 404
    fake.latest_status = 200
    fake.latest_body = {
        "id": 9,
        "version": 2,
        "schema": json.dumps({"title": "Old", "type": "object"}),
    }
    reg = _client()
    out = asyncio.run(reg.register_schema("security-alerts-value", schema, fake))
    assert out.ok is False
    assert out.status_code == 409
    assert "schema_conflict" in out.reason
    assert out.version == 2


def test_register_409_without_existing_record_fails():
    fake = _FakeClient()
    fake.register_status = 409
    fake.lookup_status = 404
    fake.latest_status = 404
    fake.latest_body = {}
    reg = _client()
    out = asyncio.run(reg.register_schema("missing-value", {"type": "object"}, fake))
    assert out.ok is False
    assert out.status_code == 409


def test_register_all_records_conflicts():
    fake = _FakeClient()
    fake.register_status = 409
    fake.lookup_status = 404
    fake.latest_body = {"id": 1, "version": 1, "schema": json.dumps({"title": "other"})}
    reg = _client()
    results = asyncio.run(reg.register_all(fake))
    assert results
    assert all(isinstance(item, RegisterOutcome) for item in results)
    assert any(not item.ok for item in results)
    assert any(not item.ok for item in reg.last_register)


def test_schemas_equal_ignores_key_order():
    assert schemas_equal({"b": 1, "a": 2}, '{"a":2,"b":1}')


# ── 生产前校验 ───────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_produce_raw_rejects_invalid_mapped_topic(monkeypatch):
    from capacity import reset_gates
    from kafka_producer import KafkaProducerWrapper

    reset_gates()
    sent = []

    class Producer:
        def send(self, topic, key, value, headers):
            sent.append(value)
            loop = asyncio.get_running_loop()
            fut = loop.create_future()
            fut.set_result("ok")
            return fut

    wrapper = KafkaProducerWrapper()
    wrapper._started = True
    wrapper._producer = Producer()
    n = await wrapper.produce_raw_batch(
        [{"eventId": "1", "eventType": "X", "severity": "nope", "message": "m", "timestamp": 1}],
        topic="security-events-enriched",
        key_field="eventId",
    )
    assert n == 0
    assert sent == []


@pytest.mark.asyncio
async def test_produce_raw_accepts_valid_security_event():
    from capacity import reset_gates
    from kafka_producer import KafkaProducerWrapper

    reset_gates()
    sent = []

    class Producer:
        def send(self, topic, key, value, headers):
            sent.append(value)
            loop = asyncio.get_running_loop()
            fut = loop.create_future()
            fut.set_result("ok")
            return fut

    wrapper = KafkaProducerWrapper()
    wrapper._started = True
    wrapper._producer = Producer()
    event = _load("security_event.valid.json")
    n = await wrapper.produce_raw_batch(
        [event], topic="security-events-enriched", key_field="eventId"
    )
    assert n == 1
    assert sent[0]["schemaVersion"] == DEFAULT_SCHEMA_VERSION
    assert sent[0]["eventType"] == "BRUTE_FORCE"


def test_alert_fixture_validates():
    alert = _load("alert_event.valid.json")
    assert schema_registry.validate("security-alerts", alert) == []
    bad = dict(alert)
    bad["alertType"] = "NOPE"
    assert schema_registry.validate("security-alerts", bad)
