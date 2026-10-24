"""死信的持久化索引和受控重放。

写入顺序：先把失败状态提交到数据库，再等 Kafka DLQ 的 acks=all。
任何一步失败，调用方都不得提交原消息的 offset。
原始负载只以整包密文保存。查询结果不包含这列。
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import and_, select
from sqlalchemy.exc import IntegrityError

from config import settings
from field_cipher import FieldCipherRejected, field_cipher

logger = logging.getLogger(__name__)

DLQ_ENVELOPE_VERSION = "dlq.v1"
MAX_DLQ_BYTES = 512 * 1024
#: 原始字节最多保留多少。超出部分只记长度，不入库。
MAX_DLQ_RAW_PREFIX = 64 * 1024
TRUNC_MARK = "…[truncated by DLQ size limit]"
REPLAY_CLAIM_S = 60

_ENC = re.compile(r"ENC:[A-Za-z0-9_\-]+=*")
_BEARER = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-+/=]+")
_SECRET_ASSIGN = re.compile(
    r"(?i)\b(api[_-]?key|password|passwd|secret|token|authorization)\b\s*[:=]\s*\S+"
)
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def sanitize_error(text: str, limit: int = 500) -> str:
    """错误文本可以进日志和 DLQ 索引。密钥、密文和 IP 不行。"""
    raw = str(text or "")
    raw = _ENC.sub("[redacted]", raw)
    raw = _BEARER.sub("bearer [redacted]", raw)
    raw = _SECRET_ASSIGN.sub(lambda m: f"{m.group(1)}=[redacted]", raw)
    raw = _IPV4.sub("[ip]", raw)
    raw = raw.replace("\r", " ").replace("\n", " ")
    return raw[:limit]


def _encode_body(body: dict) -> bytes:
    return json.dumps(body, ensure_ascii=False, sort_keys=True,
                      default=str).encode("utf-8")


def clamp_raw_blob(blob: bytes, limit: int = MAX_DLQ_RAW_PREFIX) -> tuple[bytes, int]:
    """把原始载荷裁到上限，返回 (保留的前缀, 原始长度)。

    ## 为什么不直接拒绝

    `persist_dlq_failure` 返回 False 时，调用方（`_send_to_dlq`）会**保留
    offset** —— 这是对的，因为「没落库就不能提交」。但如果超限一律拒绝，
    这条 offset 就**永远提交不了**：分区水位卡在这条消息上，它后面所有
    消息虽然被处理了却无法提交，重启后从头再来。

    也就是说，一条 >512KB 的畸形消息就能让整个分区停止推进 offset ——
    一个**输入即可触发**的 DoS，而且日志上只表现为 DLQ 写入失败。

    所以这里丢证据（只保留头部，畸形 JSON 的断点通常就在前面），
    但把「失败这件事」记下来。**丢证据好过卡住整条链路。**
    原消息仍在 broker 里按 retention 保留，原始长度会被记下来供排查。
    """
    if len(blob) <= limit:
        return blob, len(blob)
    return blob[:limit], len(blob)


def _enc(value) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      default=str).encode("utf-8")


def _shrink_value(value, budget: int, depth: int = 0):
    """返回一个不超过 ``budget`` 字节的同构值，只丢体积、不丢键。

    递归处理 dict / list 是必要的：真实安全事件里撑爆上限的常常不是
    顶层字符串，而是 ``rawData`` 这类嵌套结构里的某个大字段。
    只处理字符串的话，嵌套场景下会一字节都裁不掉。
    """
    if depth > 16:                      # 病态嵌套，再往下不值得
        return TRUNC_MARK
    if isinstance(value, str):
        if len(_enc(value)) <= budget:
            return value
        keep = max(1, len(value) // 2)
        while keep > 0:
            candidate = value[:keep] + TRUNC_MARK
            if len(_enc(candidate)) <= budget:
                return candidate
            keep //= 2
        return TRUNC_MARK
    if isinstance(value, dict):
        out = {}
        remaining = budget          # 预算在键之间**共享**，否则每个键都按
        for key, sub in value.items():   # 满额分配，N 个键就会放大成 N 倍
            key_cost = len(_enc(key)) + 6
            if remaining - key_cost <= 0:
                out[key] = TRUNC_MARK   # 留名不留值
                continue
            shrunk = _shrink_value(sub, max(1, remaining // 2), depth + 1)
            out[key] = shrunk
            remaining -= key_cost + len(_enc(shrunk))
        return out
    if isinstance(value, (list, tuple)):
        out_list = []
        remaining = budget
        for item in value:
            if remaining <= 0:
                break
            shrunk = _shrink_value(item, max(1, remaining // 2), depth + 1)
            out_list.append(shrunk)
            remaining -= len(_enc(shrunk))
        return out_list
    return value


def shrink_to_fit(body: dict, limit: int = MAX_DLQ_BYTES) -> dict:
    """把 body 压进 limit 字节，**保留所有键名**。

    DLQ 记录真正的价值是「哪个 topic/partition/offset 因为什么原因失败」，
    这些都在独立列里；body 只是补充证据。而排障时最需要的往往恰恰是
    字段名本身。所以只丢体积，不丢键。
    """
    shrunk = _shrink_value(body, limit)
    return shrunk if isinstance(shrunk, dict) else {"_truncated": shrunk}


def _iso(value: Optional[datetime]) -> Optional[str]:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.isoformat()


def parse_ts(value: str) -> Optional[datetime]:
    if not value:
        return None
    text = str(value).strip().replace("Z", "+00:00")
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def event_id_of(body: dict, headers=None) -> str:
    from event_identity import get_event_id, is_stored_id
    if not isinstance(body, dict) and not headers:
        return ""
    eid = get_event_id(body if isinstance(body, dict) else {}, headers)
    if eid:
        return eid[:128]
    if not isinstance(body, dict):
        return ""
    ident = body.get("id")
    if isinstance(ident, str) and ident and not is_stored_id(ident):
        return ident[:128]
    nested = body.get("body")
    if isinstance(nested, dict):
        return event_id_of(nested, headers)
    return ""


def _schema_version(body: dict) -> str:
    for key in ("schemaVersion", "schema_version"):
        val = body.get(key)
        if val not in (None, ""):
            return str(val)[:40]
    return ""


def _message_time(ms) -> Optional[datetime]:
    if ms in (None, ""):
        return None
    try:
        return datetime.fromtimestamp(int(ms) / 1000.0, tz=timezone.utc)
    except Exception:
        return None


def _infer_code(error: str, error_code: str) -> str:
    if error_code:
        return str(error_code)[:80]
    low = (error or "").lower()
    if "schema" in low:
        return "schema_invalid"
    if "json" in low or "utf-8" in low or "payload" in low:
        return "decode_error"
    return "permanent_failure"


@dataclass
class PersistResult:
    persisted: bool
    record_id: int = 0
    event_id: str = ""
    envelope: Optional[dict] = None
    reason: str = ""


def _public(row) -> dict:
    return {
        "id": row.id,
        "event_id": row.event_id or "",
        "eventId": row.event_id or "",
        "original_topic": row.original_topic,
        "original_partition": row.original_partition,
        "original_offset": row.original_offset,
        "consumer_group": row.consumer_group or "",
        "attempt_count": row.attempt_count,
        "first_failed_at": _iso(row.first_failed_at),
        "last_failed_at": _iso(row.last_failed_at),
        "error_class": row.error_class or "",
        "error_code": row.error_code or "",
        "sanitized_error": row.sanitized_error or "",
        "message_schema_version": row.message_schema_version or "",
        "schema_version": row.envelope_version or DLQ_ENVELOPE_VERSION,
        "message_timestamp": _iso(row.message_timestamp),
        "payload_sha256": row.payload_sha256 or "",
        "payload_complete": bool(row.payload_complete),
        "trace_id": row.trace_id or "",
        "kafka_dlq_acked": bool(row.kafka_dlq_acked),
        "replay_status": row.replay_status or "pending",
        "replayed_at": _iso(row.replayed_at),
        "replayed_by": row.replayed_by or "",
        "replay_idempotency_key": row.replay_idempotency_key or "",
    }


def _envelope(row, sealed: str) -> dict:
    return {
        "schema_version": DLQ_ENVELOPE_VERSION,
        "message_schema_version": row.message_schema_version or "",
        "event_id": row.event_id or "",
        "eventId": row.event_id or "",
        "original_topic": row.original_topic,
        "original_partition": row.original_partition,
        "original_offset": row.original_offset,
        "consumer_group": row.consumer_group or "",
        "attempt_count": row.attempt_count,
        "first_failed_at": _iso(row.first_failed_at),
        "last_failed_at": _iso(row.last_failed_at),
        "error_class": row.error_class or "",
        "error_code": row.error_code or "",
        "sanitized_error": row.sanitized_error or "",
        "message_timestamp": _iso(row.message_timestamp),
        "payload_sha256": row.payload_sha256 or "",
        "payload_ciphertext": sealed,
        "payload_complete": True,
        "trace_id": row.trace_id or "",
    }


async def persist_dlq_failure(
    *,
    topic: str,
    payload: dict,
    error: str,
    retry_count: int = 1,
    partition: Optional[int] = None,
    offset: Optional[int] = None,
    consumer_group: str = "",
    message_timestamp_ms=None,
    error_class: str = "",
    error_code: str = "",
    trace_id: str = "",
    raw_bytes: Optional[bytes] = None,
    headers=None,
) -> PersistResult:
    """把失败状态写入数据库。返回的 envelope 只含密文。失败时 persisted=False。"""
    from event_identity import apply_headers, resolve
    body = dict(payload) if isinstance(payload, dict) else {"eventId": ""}
    if headers:
        body = apply_headers(body, headers)
    body.pop("_raw", None)
    #: 载荷是否被完整保存。只要发生过裁剪就置 False —— 该列已被重放路径
    #: 读取（`not payload_complete` → 拒绝重放），此前写入侧恒写 True，
    #: 于是「记录里其实少了东西」这件事永远不会被下游发现。
    complete = True
    if raw_bytes is not None:
        if isinstance(raw_bytes, str):
            raw_bytes = raw_bytes.encode("utf-8", errors="replace")
        blob, original_len = clamp_raw_blob(bytes(raw_bytes))
        if original_len > len(blob):
            # 截断是为了让记录能落库，不是消息本来就小。
            # 排障时按这个长度去 broker 里捞原文。
            body["_dlq_raw_bytes_original"] = original_len
            complete = False
        body["_dlq_raw_b64"] = base64.b64encode(blob).decode("ascii")
        body["_dlq_undecodable"] = True
    if len(_encode_body(body)) > MAX_DLQ_BYTES:
        body = shrink_to_fit(body, MAX_DLQ_BYTES)
        complete = False
    canonical = _encode_body(body)
    if len(canonical) > MAX_DLQ_BYTES:
        # 兜底：非字符串的病态结构（极深的嵌套 dict/list）压不进上限。
        # 这时拒绝仍然是正确的 —— 它意味着这条记录连键名都存不下，
        # 与其写一条残缺记录，不如如实告诉调用方「没落库」。
        return PersistResult(False, reason="payload_too_large")
    sealed = field_cipher.seal_payload(body)
    if not sealed:
        return PersistResult(False, reason="cipher_unavailable")

    part = -1 if partition is None else int(partition)
    off = -1 if offset is None else int(offset)
    now = datetime.now(timezone.utc)
    ident = resolve(body, headers)
    eid = ident.event_id or event_id_of(body, headers)
    code = _infer_code(error, error_code)
    klass = (error_class or "PermanentFailure")[:80]
    cleaned = sanitize_error(error)
    digest = hashlib.sha256(canonical).hexdigest()
    schema_ver = _schema_version(body)
    group = (consumer_group or settings.kafka_consumer_group or "")[:200]
    tid = (trace_id or ident.trace_id or str(body.get("_trace_id") or ""))[:128]
    msg_time = _message_time(message_timestamp_ms)
    attempts = max(1, int(retry_count or 1))

    try:
        from models import DlqRecord, async_session

        async with async_session() as session:
            # P2: SELECT-then-INSERT 有并发窗口 — 两进程对同一 (topic,partition,offset)
            # 同时写失败时, 输家撞唯一约束。修复前 IntegrityError 直接外抛 →
            # persisted=False → offset 无谓保留一整轮; 现重试一次走 UPDATE 分支
            # (等价 upsert, 且兼容 SQLite 测试环境, 不用 PG 方言的 ON CONFLICT)。
            for _attempt in range(2):
                found = (await session.execute(
                    select(DlqRecord).where(
                        DlqRecord.original_topic == (topic or "")[:200],
                        DlqRecord.original_partition == part,
                        DlqRecord.original_offset == off,
                    )
                )).scalar_one_or_none()
                if found is None:
                    row = DlqRecord(
                        event_id=eid,
                        original_topic=(topic or "")[:200],
                        original_partition=part,
                        original_offset=off,
                        consumer_group=group,
                        attempt_count=attempts,
                        first_failed_at=now,
                        last_failed_at=now,
                        error_class=klass,
                        error_code=code,
                        sanitized_error=cleaned,
                        message_schema_version=schema_ver,
                        envelope_version=DLQ_ENVELOPE_VERSION,
                        message_timestamp=msg_time,
                        payload_ciphertext=sealed,
                        payload_sha256=digest,
                        payload_complete=complete,
                        trace_id=tid,
                        kafka_dlq_acked=False,
                        replay_status="pending",
                        created_at=now,
                    )
                    session.add(row)
                else:
                    row = found
                    row.event_id = eid or row.event_id
                    row.consumer_group = group or row.consumer_group
                    row.attempt_count = max(int(row.attempt_count or 0) + 1, attempts)
                    row.last_failed_at = now
                    row.error_class = klass
                    row.error_code = code
                    row.sanitized_error = cleaned
                    row.message_schema_version = schema_ver or row.message_schema_version
                    row.message_timestamp = msg_time or row.message_timestamp
                    row.payload_ciphertext = sealed
                    row.payload_sha256 = digest
                    row.payload_complete = complete
                    row.trace_id = tid or row.trace_id
                    row.kafka_dlq_acked = False
                try:
                    await session.commit()
                    break
                except IntegrityError:
                    await session.rollback()
                    if _attempt == 0:
                        continue  # 并发同键插入竞速输了 → 第二轮 SELECT 命中走 UPDATE
                    raise
            await session.refresh(row)
            try:
                from core_metrics import log_process, record_dlq_persisted
                wait = 0.0
                first_epoch = now.timestamp()
                if row.first_failed_at is not None:
                    first = row.first_failed_at
                    if first.tzinfo is None:
                        first = first.replace(tzinfo=timezone.utc)
                    first_epoch = first.timestamp()
                    wait = max(0.0, now.timestamp() - first_epoch)
                record_dlq_persisted(
                    code, wait, record_id=int(row.id), first_failed_epoch=first_epoch,
                )
                log_process(
                    logger, event_id=row.event_id or eid, stage="dlq",
                    result="dlq", reason=code, retry_count=int(row.attempt_count or attempts),
                )
            except Exception:
                pass
            return PersistResult(
                True,
                record_id=int(row.id),
                event_id=row.event_id or "",
                envelope=_envelope(row, sealed),
                reason="ok",
            )
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        logger.error("[DLQ] index persist failed: %s", type(exc).__name__)
        return PersistResult(False, reason="db_error")


async def mark_kafka_acked(record_id: int) -> None:
    if not record_id:
        return
    try:
        from models import DlqRecord, async_session

        async with async_session() as session:
            row = await session.get(DlqRecord, record_id)
            if row is None:
                return
            row.kafka_dlq_acked = True
            await session.commit()
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        logger.warning("[DLQ] kafka ack flag update failed: %s", type(exc).__name__)


async def list_records(
    *,
    event_id: str = "",
    topic: str = "",
    since: Optional[datetime] = None,
    until: Optional[datetime] = None,
    limit: int = 50,
) -> list[dict]:
    from models import DlqRecord, async_session

    size = min(max(int(limit or 50), 1), 200)
    conds = []
    if event_id:
        conds.append(DlqRecord.event_id == event_id[:128])
    if topic:
        conds.append(DlqRecord.original_topic == topic[:200])
    if since is not None:
        conds.append(DlqRecord.last_failed_at >= since)
    if until is not None:
        conds.append(DlqRecord.last_failed_at <= until)
    stmt = select(DlqRecord)
    if conds:
        stmt = stmt.where(and_(*conds))
    stmt = stmt.order_by(DlqRecord.last_failed_at.desc(), DlqRecord.id.desc()).limit(size)
    async with async_session() as session:
        rows = (await session.execute(stmt)).scalars().all()
        return [_public(row) for row in rows]


async def get_record(record_id: int) -> Optional[dict]:
    from models import DlqRecord, async_session

    async with async_session() as session:
        row = await session.get(DlqRecord, record_id)
        if row is None:
            return None
        return _public(row)


def _field_names(payload: dict) -> list[str]:
    return sorted(key for key in payload.keys() if not str(key).startswith("_"))


async def dry_run(record_id: int) -> Optional[dict]:
    """服务器侧打开密文并校验。不改重放状态，不返回字段值。"""
    from models import DlqRecord, async_session

    async with async_session() as session:
        row = await session.get(DlqRecord, record_id)
        if row is None:
            return None
        base = _public(row)
        topic = row.original_topic
        ciphertext = row.payload_ciphertext or ""
        complete = bool(row.payload_complete)
    base["would_publish_to"] = topic
    base["field_names"] = []
    base["schema_errors"] = []
    if not complete or not ciphertext:
        base.update(ok=False, cipher_code="payload_incomplete", replay_allowed=False)
        return base
    try:
        payload = field_cipher.open_sealed(ciphertext)
    except FieldCipherRejected as exc:
        base.update(ok=False, cipher_code=exc.code, replay_allowed=False)
        return base
    base["field_names"] = _field_names(payload)
    if payload.get("_dlq_undecodable"):
        base.update(ok=False, cipher_code="undecodable", replay_allowed=False)
        return base
    decision = field_cipher.open_message(payload)
    schema_errors: list[str] = []
    if decision.ok and decision.message is not None:
        from schema_registry import schema_registry

        schema_errors = [
            sanitize_error(item, 160)
            for item in schema_registry.validate(topic, decision.message)[:5]
        ]
    base.update(
        ok=bool(decision.ok) and not schema_errors,
        cipher_code=decision.code,
        schema_errors=schema_errors,
        replay_allowed=bool(decision.ok),
    )
    return base


async def replay_record(
    record_id: int,
    *,
    actor: str,
    idempotency_key: str = "",
    publisher=None,
) -> dict:
    """重放原始负载。已成功的记录直接返回上次结果，不再发第二次。"""
    from models import DlqRecord, async_session

    key = (idempotency_key or f"dlq-{record_id}")[:120]
    async with async_session() as session:
        row = await session.get(DlqRecord, record_id)
        if row is None:
            return {"status": "not_found"}
        if row.replay_status == "replayed" or (row.replay_result or {}).get("published"):
            previous = dict(row.replay_result or {})
            previous.update(status="replayed", idempotent=True, event_id=row.event_id or previous.get("event_id", ""))
            return previous
        if row.replay_status == "replaying" and row.replay_claimed_at is not None:
            claimed = row.replay_claimed_at
            if claimed.tzinfo is None:
                claimed = claimed.replace(tzinfo=timezone.utc)
            age = (datetime.now(timezone.utc) - claimed).total_seconds()
            if age < REPLAY_CLAIM_S:
                return {
                    "status": "in_progress",
                    "idempotent": True,
                    "event_id": row.event_id or "",
                    "idempotency_key": row.replay_idempotency_key or key,
                }
        if not row.payload_complete or not row.payload_ciphertext:
            return {"status": "blocked", "error_code": "payload_incomplete", "event_id": row.event_id or ""}
        try:
            payload = field_cipher.open_sealed(row.payload_ciphertext)
        except FieldCipherRejected as exc:
            return {"status": "blocked", "error_code": exc.code, "event_id": row.event_id or ""}
        if payload.get("_dlq_undecodable"):
            return {"status": "blocked", "error_code": "undecodable", "event_id": row.event_id or ""}
        decision = field_cipher.open_message(payload)
        if not decision.ok:
            return {"status": "blocked", "error_code": decision.code, "event_id": row.event_id or ""}
        topic = row.original_topic
        event_id = row.event_id or ""
        row.replay_status = "replaying"
        row.replay_idempotency_key = key
        row.replayed_by = (actor or "")[:100]
        row.replay_claimed_at = datetime.now(timezone.utc)
        await session.commit()
        row_id = int(row.id)

    send = publisher or kafka_replay_publisher
    published_offset = None
    try:
        published_offset = await send(topic, event_id, payload)
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        logger.error("[DLQ] replay publish failed: %s", type(exc).__name__)
        published_offset = None

    async with async_session() as session:
        row = await session.get(DlqRecord, row_id)
        if row is None:
            return {"status": "not_found"}
        if published_offset is None:
            row.replay_status = "replay_failed"
            row.replay_result = {
                "published": False,
                "idempotency_key": key,
                "event_id": event_id,
                "target_topic": topic,
            }
            await session.commit()
            return {
                "status": "publish_failed",
                "idempotent": False,
                "event_id": event_id,
                "target_topic": topic,
                "idempotency_key": key,
            }
        result = {
            "published": True,
            "idempotent": False,
            "event_id": event_id,
            "target_topic": topic,
            "target_offset": int(published_offset),
            "idempotency_key": key,
            "original_partition": row.original_partition,
            "original_offset": row.original_offset,
        }
        row.replay_status = "replayed"
        row.replayed_at = datetime.now(timezone.utc)
        row.replay_result = result
        await session.commit()
        try:
            from core_metrics import log_process, note_dlq_closed
            note_dlq_closed(int(row.id))
            log_process(
                logger, event_id=event_id, stage="dlq", result="success",
                reason="replayed",
            )
        except Exception:
            pass
        return {"status": "replayed", **result}


async def kafka_replay_publisher(topic: str, key: str, value: dict):
    from kafka_consumer import kafka_consumer_manager

    prod = getattr(kafka_consumer_manager, "_dlq_producer", None)
    if prod is None:
        return None
    meta = await prod.send_and_wait(topic, key=key or None, value=value)
    off = getattr(meta, "offset", None)
    if off is None and isinstance(meta, dict):
        off = meta.get("offset")
    if off is None:
        return None
    return int(off)


async def purge_expired(session=None) -> int:
    """删除超过保留期的索引。不把负载写进审计日志。"""
    days = int(getattr(settings, "dlq_retention_days", 30) or 0)
    if days <= 0:
        return 0
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    async def _run(active) -> int:
        from sqlalchemy import delete as sa_delete

        from models import DlqRecord

        # P2: 修复前逐行 `await active.delete(row)` — N+1 删除且整批先进内存,
        # 保留期到期的大批清理会长时间阻塞事件循环。一条 DELETE 批量完成。
        result = await active.execute(
            sa_delete(DlqRecord).where(DlqRecord.last_failed_at < cutoff)
        )
        await active.commit()
        return int(result.rowcount or 0)

    if session is not None:
        return await _run(session)
    from models import async_session

    async with async_session() as own:
        return await _run(own)
