"""
统一事件信封：跨系统传输的外层结构。

规范字段（camelCase，与 Flink/Kafka 一致）：
  eventId, eventType, schemaVersion, occurredAt, producer, correlationId, payload

历史消息是扁平业务结构，没有 payload 外包。消费端按
is_envelope() 判断：是信封则先校验外层再校验 payload；否则整份当 payload。
生产端默认只盖可选身份字段，不强制改写成信封。
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Optional

from event_identity import ensure_identity, get_event_id

DEFAULT_SCHEMA_VERSION = "1.0.0"
DEFAULT_PRODUCER = "backend"

_ENVELOPE_ALIASES = {
    "eventId": ("eventId", "event_id"),
    "eventType": ("eventType", "event_type"),
    "schemaVersion": ("schemaVersion", "schema_version"),
    "occurredAt": ("occurredAt", "occurred_at"),
    "producer": ("producer",),
    "correlationId": ("correlationId", "correlation_id"),
    "payload": ("payload",),
}


def _first(msg: dict, *keys: str):
    for key in keys:
        if key in msg and msg[key] not in (None, ""):
            return msg[key]
    return None


def envelope_get(msg: dict, canonical: str):
    return _first(msg, *_ENVELOPE_ALIASES.get(canonical, (canonical,)))


def is_envelope(msg: Any) -> bool:
    """含业务 payload 对象，以及 schemaVersion / eventId 之一，视为信封。"""
    if not isinstance(msg, dict):
        return False
    payload = envelope_get(msg, "payload")
    if not isinstance(payload, dict):
        return False
    has_version = envelope_get(msg, "schemaVersion") is not None
    has_id = envelope_get(msg, "eventId") is not None
    return has_version or has_id


@dataclass
class Unwrapped:
    payload: dict
    wrapped: bool
    event_id: str = ""
    event_type: str = ""
    schema_version: str = ""
    occurred_at: Optional[int] = None
    producer: str = ""
    correlation_id: str = ""


def unwrap(msg: Any) -> Unwrapped:
    """拆信封；历史扁平消息原样返回。"""
    if not isinstance(msg, dict):
        return Unwrapped(payload={}, wrapped=False)
    if is_envelope(msg):
        payload = dict(envelope_get(msg, "payload") or {})
        occurred = envelope_get(msg, "occurredAt")
        try:
            occurred_at = int(occurred) if occurred is not None else None
        except (TypeError, ValueError):
            occurred_at = None
        return Unwrapped(
            payload=payload,
            wrapped=True,
            event_id=str(envelope_get(msg, "eventId") or payload.get("eventId") or ""),
            event_type=str(envelope_get(msg, "eventType") or payload.get("eventType") or ""),
            schema_version=str(envelope_get(msg, "schemaVersion") or payload.get("schemaVersion") or ""),
            occurred_at=occurred_at,
            producer=str(envelope_get(msg, "producer") or payload.get("producer") or ""),
            correlation_id=str(
                envelope_get(msg, "correlationId")
                or payload.get("correlationId")
                or ""
            ),
        )
    version = _first(msg, "schemaVersion", "schema_version") or ""
    occurred = _first(msg, "occurredAt", "occurred_at", "timestamp")
    try:
        occurred_at = int(occurred) if occurred is not None else None
    except (TypeError, ValueError):
        occurred_at = None
    return Unwrapped(
        payload=msg,
        wrapped=False,
        event_id=str(_first(msg, "eventId", "event_id", "alertId") or ""),
        event_type=str(_first(msg, "eventType", "event_type", "event", "type") or ""),
        schema_version=str(version),
        occurred_at=occurred_at,
        producer=str(_first(msg, "producer") or ""),
        correlation_id=str(_first(msg, "correlationId", "correlation_id") or ""),
    )


def wrap(
    payload: dict,
    *,
    event_type: str = "",
    producer: str = DEFAULT_PRODUCER,
    schema_version: str = DEFAULT_SCHEMA_VERSION,
    correlation_id: str = "",
    event_id: str = "",
    occurred_at: Optional[int] = None,
) -> dict:
    """把业务内容包成规范信封。现有 topic 默认不走这条路径。"""
    body = dict(payload or {})
    eid = event_id or str(_first(body, "eventId", "event_id", "alertId") or "")
    etype = event_type or str(_first(body, "eventType", "event_type") or "unknown")
    corr = correlation_id or str(_first(body, "correlationId", "correlation_id", "eventId") or eid)
    ts = occurred_at
    if ts is None:
        raw_ts = _first(body, "occurredAt", "timestamp")
        try:
            ts = int(raw_ts) if raw_ts is not None else int(time.time() * 1000)
        except (TypeError, ValueError):
            ts = int(time.time() * 1000)
    return {
        "eventId": eid,
        "eventType": etype,
        "schemaVersion": schema_version,
        "occurredAt": ts,
        "producer": producer,
        "correlationId": corr,
        "payload": body,
    }


def stamp_identity(
    msg: dict,
    *,
    producer: str = DEFAULT_PRODUCER,
    schema_version: str = DEFAULT_SCHEMA_VERSION,
    correlation_id: str = "",
) -> dict:
    """在扁平消息上补可选身份字段，不改写成信封。已有 eventId 保留。"""
    if not isinstance(msg, dict):
        return msg
    out = ensure_identity(msg, producer=producer, correlation_id=correlation_id)
    if is_envelope(out):
        if envelope_get(out, "schemaVersion") is None:
            out["schemaVersion"] = schema_version
        if envelope_get(out, "producer") is None:
            out["producer"] = producer
        if envelope_get(out, "correlationId") is None:
            out["correlationId"] = correlation_id or str(
                envelope_get(out, "eventId") or get_event_id(out) or ""
            )
        if envelope_get(out, "occurredAt") is None:
            out["occurredAt"] = int(time.time() * 1000)
        inner = out.get("payload")
        if isinstance(inner, dict):
            out["payload"] = stamp_identity(
                inner,
                producer=producer,
                schema_version=schema_version,
                correlation_id=correlation_id or str(out.get("correlationId") or ""),
            )
        return out
    if not _first(out, "schemaVersion", "schema_version"):
        out["schemaVersion"] = schema_version
    if not _first(out, "producer"):
        out["producer"] = producer
    if not _first(out, "correlationId", "correlation_id"):
        out["correlationId"] = correlation_id or str(
            _first(out, "eventId", "alertId", "uuid") or ""
        )
    if _first(out, "occurredAt", "occurred_at") is None:
        ts = _first(out, "timestamp", "_ts")
        try:
            if ts is None:
                out["occurredAt"] = int(time.time() * 1000)
            else:
                ts_n = float(ts)
                out["occurredAt"] = int(ts_n if ts_n > 1e12 else ts_n * 1000)
        except (TypeError, ValueError):
            out["occurredAt"] = int(time.time() * 1000)
    return out


def parse_semver(value: str) -> Optional[tuple[int, int, int]]:
    if not value or not isinstance(value, str):
        return None
    text = value.strip().lstrip("v")
    parts = text.split(".")
    if not parts or not parts[0].isdigit():
        return None
    nums = []
    for item in (parts + ["0", "0"])[:3]:
        if not str(item).isdigit():
            return None
        nums.append(int(item))
    return nums[0], nums[1], nums[2]


def version_errors(declared: str, current: str) -> list[str]:
    """主版本不一致则拒绝。未声明版本视为与当前主版本兼容。"""
    if not declared:
        return []
    got = parse_semver(declared)
    want = parse_semver(current) or (1, 0, 0)
    if got is None:
        return [f"schema_version 非法: {declared}"]
    if got[0] != want[0]:
        return [f"schema_version 主版本 {got[0]} 与当前 {want[0]} 不兼容"]
    return []
