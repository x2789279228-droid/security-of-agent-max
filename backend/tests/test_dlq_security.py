"""DLQ 恢复索引和字段加密失败关闭。

密文解不开、密钥不可用、格式不对、敏感字段类型异常，都不得当成明文继续处理。
DLQ 写入未确认时，原 offset 不能提交。查询和重放不返回明文负载。
"""
import asyncio
import json
import os
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException

from auth import UserInfo
from field_cipher import FieldCipherRejected, field_cipher
from kafka_consumer import KafkaConsumerManager


def _run(coro):
    return asyncio.run(coro)


async def _create_tables():
    from models import Base, engine

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


def _use_key() -> str:
    from cryptography.fernet import Fernet

    key = Fernet.generate_key().decode()
    os.environ["SHARED_MEMORY_FIELD_ENCRYPTION_KEY"] = key
    field_cipher.reload()
    return key


def _clear_key():
    os.environ.pop("SHARED_MEMORY_FIELD_ENCRYPTION_KEY", None)
    field_cipher.reload()


@pytest.fixture(autouse=True)
def _restore_cipher_key():
    old = os.environ.get("SHARED_MEMORY_FIELD_ENCRYPTION_KEY")
    yield
    if old is None:
        os.environ.pop("SHARED_MEMORY_FIELD_ENCRYPTION_KEY", None)
    else:
        os.environ["SHARED_MEMORY_FIELD_ENCRYPTION_KEY"] = old
    field_cipher.reload()


def test_decrypt_failure_is_not_treated_as_plaintext():
    from cryptography.fernet import Fernet

    _use_key()
    other = Fernet(Fernet.generate_key())
    foreign = "ENC:" + other.encrypt(b"secret-value").decode()
    decision = field_cipher.open_message({"message": foreign, "eventId": "e"})
    assert decision.ok is False
    assert decision.code == "decrypt_failed"
    assert decision.message is None

    malformed = field_cipher.open_message({"message": "ENC:@@@@", "eventId": "e"})
    assert malformed.ok is False
    assert malformed.code == "ciphertext_malformed"

    with pytest.raises(FieldCipherRejected) as raised:
        field_cipher.decrypt_message({"srcIp": foreign})
    assert raised.value.code == "decrypt_failed"
    assert "secret-value" not in str(raised.value)


def test_missing_or_broken_key_does_not_accept_ciphertext():
    _clear_key()
    missing = field_cipher.open_message({"message": "ENC:gAAAAA-not-really", "eventId": "e"})
    assert missing.ok is False
    assert missing.code == "cipher_unavailable"
    assert field_cipher.open_message({"eventId": "e", "message": "plain"}).ok is True

    os.environ["SHARED_MEMORY_FIELD_ENCRYPTION_KEY"] = "not-a-fernet-key"
    field_cipher.reload()
    assert field_cipher.state == "broken"
    broken = field_cipher.open_message({"srcIp": "203.0.113.5"})
    assert broken.ok is False
    assert broken.code == "cipher_unavailable"
    assert field_cipher.open_message({"eventId": "only"}).ok is True
    with pytest.raises(FieldCipherRejected) as raised:
        field_cipher.encrypt_message({"eventId": "only"})
    assert raised.value.code == "cipher_unavailable"


def test_anomalous_and_plaintext_fields_cannot_bypass():
    _clear_key()
    nested = field_cipher.open_message({"message": {"text": "secret"}})
    assert nested.ok is False
    assert nested.code == "anomalous_field"

    _use_key()
    leaked = field_cipher.open_message({"source_key": "live-token", "body": {"event": "login"}})
    assert leaked.ok is False
    assert leaked.code == "plaintext_bypass"
    bypass = field_cipher.open_message({"rawData": {"srcIp": "203.0.113.8"}})
    assert bypass.ok is False
    assert bypass.code == "plaintext_bypass"
    camel = field_cipher.open_message({"rawData": {"srcIp": "ENC:@@@@"}})
    assert camel.ok is False
    assert camel.code == "ciphertext_malformed"

    plain = {"eventId": "e1", "message": "hello", "rawData": {"src_ip": "203.0.113.9"}}
    wire = field_cipher.encrypt_message(plain)
    assert wire["message"].startswith("ENC:")
    assert wire["rawData"]["src_ip"].startswith("ENC:")
    assert plain["message"] == "hello"
    opened = field_cipher.open_message(wire)
    assert opened.ok is True
    assert opened.message["message"] == "hello"
    assert opened.message["rawData"]["src_ip"] == "203.0.113.9"


def test_cipher_reject_does_not_reach_handler_and_blocks_commit_without_dlq():
    async def _case():
        await _create_tables()
        mgr = KafkaConsumerManager()
        mgr._running = True
        called = []

        async def handler(event, trace_id):
            called.append(event)

        class Msg:
            partition = 3
            offset = 11
            timestamp = 1700000000000
            headers = []
            value = b""

        _clear_key()
        rejected = await mgr._process_message(
            Msg(),
            {"eventId": "e-cipher", "message": "ENC:not-a-token"},
            "security-logs-rejected",
            "",
            handler,
            "rejected_consumed",
            "soc-backend-rejected",
        )
        assert rejected is False
        assert called == []
        assert mgr._stats["dlq_failed"] >= 1

        _use_key()
        sent = []

        class Prod:
            async def send_and_wait(self, topic, key=None, value=None, headers=None):
                sent.append(value)
                return {"offset": 1}

        mgr._dlq_producer = Prod()
        accepted = await mgr._process_message(
            Msg(),
            {"eventId": "e-cipher", "message": "ENC:not-a-token", "note": "super-secret-key"},
            "security-logs-rejected",
            "",
            handler,
            "rejected_consumed",
            "soc-backend-rejected",
        )
        assert accepted is True
        assert called == []
        dumped = json.dumps(sent[0], ensure_ascii=False)
        assert "super-secret-key" not in dumped
        assert "original_message" not in sent[0]
        assert sent[0]["error_code"] == "ciphertext_malformed"
        assert sent[0]["consumer_group"] == "soc-backend-rejected"
        assert sent[0]["original_partition"] == 3
        assert sent[0]["original_offset"] == 11

    _run(_case())


def test_recovery_filters_dry_run_and_replay_are_idempotent():
    async def _case():
        await _create_tables()
        _use_key()
        from dlq_store import dry_run, get_record, list_records, persist_dlq_failure, purge_expired
        from kafka_consumer import kafka_consumer_manager
        from models import AuditTrail, DlqRecord, async_session
        from routers.dlq import ReplayRequest, dry_run_dlq, list_dlq, replay_dlq
        from sqlalchemy import select

        wire = field_cipher.encrypt_message({
            "eventId": "evt-keep",
            "message": "hello-secret",
            "schemaVersion": "1",
        })
        other = field_cipher.encrypt_message({"eventId": "evt-other", "message": "other-secret"})
        first = await persist_dlq_failure(
            topic="security-logs-rejected",
            payload=wire,
            error="apiKey=hello-secret schema",
            retry_count=2,
            partition=0,
            offset=4,
            consumer_group="soc-backend-rejected",
            message_timestamp_ms=1700000000000,
            error_class="SchemaError",
            error_code="schema_invalid",
        )
        assert first.persisted is True
        assert "hello-secret" not in json.dumps(first.envelope)
        second = await persist_dlq_failure(
            topic="security-alerts",
            payload=other,
            error="bad",
            partition=1,
            offset=8,
            consumer_group="soc-backend-alerts",
            error_code="schema_invalid",
        )
        assert second.persisted is True

        found = await list_records(event_id="evt-keep", topic="security-logs-rejected")
        assert len(found) == 1
        assert await list_records(since=datetime.now(timezone.utc) + timedelta(days=1)) == []
        assert len(await list_records(
            event_id="evt-keep",
            since=datetime.now(timezone.utc) - timedelta(minutes=5),
            until=datetime.now(timezone.utc) + timedelta(minutes=5),
        )) == 1
        assert found[0]["attempt_count"] == 2
        assert found[0]["consumer_group"] == "soc-backend-rejected"
        assert found[0]["error_code"] == "schema_invalid"
        assert "payload_ciphertext" not in found[0]
        assert "hello-secret" not in json.dumps(found[0])

        preview = await dry_run(first.record_id)
        assert preview["replay_allowed"] is True
        assert preview["cipher_code"] == "ok"
        assert "message" in preview["field_names"]
        assert "hello-secret" not in json.dumps(preview)
        assert preview["replay_status"] == "pending"

        operator = UserInfo(username="op", role="operator")
        viewer = UserInfo(username="view", role="viewer")
        admin = UserInfo(username="ada", role="admin")
        with pytest.raises(HTTPException) as denied:
            await list_dlq(user=viewer, limit=10)
        assert denied.value.status_code == 403

        class _Req:
            class _Client:
                host = "127.0.0.1"
            client = _Client()
            headers = {"user-agent": "pytest"}

        async with async_session() as session:
            audited = await dry_run_dlq(first.record_id, _Req(), session, operator)
        assert audited["ok"] is True
        async with async_session() as session:
            trail = (await session.execute(
                select(AuditTrail).where(AuditTrail.action == "dlq.dry_run")
            )).scalars().all()
        assert any(row.target_id == str(first.record_id) for row in trail)

        async with async_session() as session:
            with pytest.raises(HTTPException) as forbidden:
                await replay_dlq(
                    first.record_id,
                    ReplayRequest(confirm=True, idempotency_key="k1"),
                    _Req(),
                    session,
                    operator,
                )
        assert forbidden.value.status_code == 403
        async with async_session() as session:
            denied = (await session.execute(
                select(AuditTrail).where(AuditTrail.action == "dlq.replay_denied")
            )).scalars().all()
        assert any(row.actor == "op" and row.target_id == str(first.record_id) for row in denied)

        sent = []

        class Prod:
            async def send_and_wait(self, topic, key=None, value=None, headers=None):
                sent.append({"topic": topic, "key": key, "value": value})
                return {"offset": 15}

        previous = kafka_consumer_manager._dlq_producer
        kafka_consumer_manager._dlq_producer = Prod()
        try:
            async with async_session() as session:
                replayed = await replay_dlq(
                    first.record_id,
                    ReplayRequest(confirm=True, idempotency_key="k1"),
                    _Req(),
                    session,
                    admin,
                )
            assert replayed["status"] == "replayed"
            assert replayed["idempotent"] is False
            assert replayed["event_id"] == "evt-keep"
            assert sent[0]["topic"] == "security-logs-rejected"
            assert sent[0]["value"]["eventId"] == "evt-keep"
            assert sent[0]["value"]["message"].startswith("ENC:")
            assert "hello-secret" not in json.dumps(sent[0]["value"])

            async with async_session() as session:
                again = await replay_dlq(
                    first.record_id,
                    ReplayRequest(confirm=True, idempotency_key="k1"),
                    _Req(),
                    session,
                    admin,
                )
            assert again["idempotent"] is True
            assert len(sent) == 1
            stored = await get_record(first.record_id)
            assert stored["replay_status"] == "replayed"
            assert stored["event_id"] == "evt-keep"
        finally:
            kafka_consumer_manager._dlq_producer = previous

        async with async_session() as session:
            row = await session.get(DlqRecord, second.record_id)
            row.last_failed_at = datetime.now(timezone.utc) - timedelta(days=40)
            await session.commit()
        removed = await purge_expired()
        assert removed >= 1
        assert await get_record(second.record_id) is None
        assert await get_record(first.record_id) is not None

    _run(_case())


def test_undecodable_replay_is_blocked_and_confirm_is_required():
    async def _case():
        await _create_tables()
        _use_key()
        from models import async_session
        from routers.dlq import ReplayRequest, replay_dlq
        from dlq_store import persist_dlq_failure

        saved = await persist_dlq_failure(
            topic="security-logs-rejected",
            payload={"eventId": ""},
            error="payload is not json",
            partition=2,
            offset=3,
            error_code="decode_error",
            raw_bytes=b"\xffnot-json",
        )
        assert saved.persisted is True
        admin = UserInfo(username="ada", role="admin")

        class _Req:
            class _Client:
                host = "127.0.0.1"
            client = _Client()
            headers = {"user-agent": "pytest"}

        async with async_session() as session:
            with pytest.raises(HTTPException) as missing:
                await replay_dlq(
                    saved.record_id,
                    ReplayRequest(confirm=False),
                    _Req(),
                    session,
                    admin,
                )
            assert missing.value.status_code == 400
            async with async_session() as session:
                with pytest.raises(HTTPException) as blocked:
                    await replay_dlq(
                        saved.record_id,
                        ReplayRequest(confirm=True),
                        _Req(),
                        session,
                        admin,
                    )
            assert blocked.value.status_code == 409

    _run(_case())


# ── 无密钥部署的明文降级(2026-10-25 审计 #3) ──────────────────────


def test_plaintext_fallback_when_cipher_disabled():
    """无密钥时 DLQ 必须能落库(PLAIN: 前缀明文), 否则 offset 永久卡死。"""
    async def _case():
        await _create_tables()
        _clear_key()
        from dlq_store import PLAIN_DLQ_PREFIX, dry_run, persist_dlq_failure
        from models import DlqRecord, async_session

        saved = await persist_dlq_failure(
            topic="security-events-enriched",
            payload={"eventId": "evt-plain", "eventType": "BRUTE_FORCE", "severity": "high",
                     "message": "boom", "timestamp": 1700000000000, "srcIp": "203.0.113.7"},
            error="['parentEventId']: None is not of type 'string'",
            partition=0,
            offset=42,
            error_code="schema_invalid",
        )
        assert saved.persisted is True, saved.reason

        async with async_session() as session:
            row = await session.get(DlqRecord, saved.record_id)
            assert row.payload_ciphertext.startswith(PLAIN_DLQ_PREFIX)
            stored = row.payload_ciphertext[len(PLAIN_DLQ_PREFIX):]
        assert json.loads(stored)["eventId"] == "evt-plain"

        # 明文记录在无密钥态可审计/可重放
        preview = await dry_run(saved.record_id)
        assert preview["ok"] is True
        assert "srcIp" in preview["field_names"]

        sent = []

        class Prod:
            async def send_and_wait(self, topic, key=None, value=None, headers=None):
                sent.append(value)
                return {"offset": 7}

        from kafka_consumer import kafka_consumer_manager
        previous = kafka_consumer_manager._dlq_producer
        kafka_consumer_manager._dlq_producer = Prod()
        try:
            from routers.dlq import ReplayRequest, replay_dlq
            from models import async_session as sess

            admin = UserInfo(username="ada", role="admin")

            class _Req:
                class _Client:
                    host = "127.0.0.1"
                client = _Client()
                headers = {"user-agent": "pytest"}

            async with sess() as session:
                replayed = await replay_dlq(
                    saved.record_id,
                    ReplayRequest(confirm=True),
                    _Req(),
                    session,
                    admin,
                )
            assert replayed["status"] == "replayed", replayed
            assert sent and sent[0]["eventId"] == "evt-plain"
        finally:
            kafka_consumer_manager._dlq_producer = previous

    _run(_case())


def test_open_sealed_plaintext_rejected_when_encryption_enabled():
    """启用加密后明文 DLQ 记录必须拒开(明文不得在有密钥环境流动)。"""
    from dlq_store import PLAIN_DLQ_PREFIX

    _clear_key()
    assert field_cipher.open_sealed(PLAIN_DLQ_PREFIX + '{"eventId":"e"}') == {"eventId": "e"}

    _use_key()
    with pytest.raises(FieldCipherRejected) as raised:
        field_cipher.open_sealed(PLAIN_DLQ_PREFIX + '{"eventId":"e"}')
    assert raised.value.code == "plaintext_bypass"

    os.environ["SHARED_MEMORY_FIELD_ENCRYPTION_KEY"] = "not-a-fernet-key"
    field_cipher.reload()
    with pytest.raises(FieldCipherRejected) as broken:
        field_cipher.open_sealed(PLAIN_DLQ_PREFIX + '{"eventId":"e"}')
    assert broken.value.code == "cipher_unavailable"
    _clear_key()


def test_broken_key_still_fails_closed_for_dlq_persist():
    """密钥损坏(非 disabled)时维持 fail-closed —— 明文降级只豁免「未配置密钥」。"""
    async def _case():
        await _create_tables()
        os.environ["SHARED_MEMORY_FIELD_ENCRYPTION_KEY"] = "not-a-fernet-key"
        field_cipher.reload()
        assert field_cipher.state == "broken"
        from dlq_store import persist_dlq_failure

        saved = await persist_dlq_failure(
            topic="security-events-enriched",
            payload={"eventId": "evt-broken", "srcIp": "203.0.113.7"},
            error="schema",
            partition=1,
            offset=9,
            error_code="schema_invalid",
        )
        assert saved.persisted is False
        assert saved.reason == "cipher_unavailable"

    _run(_case())
