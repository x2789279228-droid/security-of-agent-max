"""四种标识的职责，以及稳定 event_id 如何贯穿链路。

event_id / eventId
    一条业务事件的稳定 ID。入口生成一次，重试、重放、DLQ 不得更换。
correlation_id / correlationId
    同一项业务处理的关联标识。原事件缺省等于 event_id；派生事件继承。
trace_id / traceId
    调用链追踪（W3C）。与业务 ID 分开。
parent_event_id / parentEventId
    派生事件指向来源业务事件。重试不是派生，不写这个字段。
stored_id
    数据库自增主键，仅落库后存在，给 API / SSE 游标用，不是业务 ID。
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any, Iterable, Optional

HEADER_EVENT_ID = "event_id"
HEADER_CORRELATION_ID = "correlation_id"
HEADER_TRACE_ID = "trace_id"
HEADER_PARENT_EVENT_ID = "parent_event_id"
HEADER_TRACEPARENT = "traceparent"

_EVENT_ID_KEYS = ("eventId", "event_id")
_CORR_KEYS = ("correlationId", "correlation_id")
_TRACE_KEYS = ("traceId", "trace_id", "_trace_id")
_PARENT_KEYS = ("parentEventId", "parent_event_id")


def _as_text(value: Any) -> str:
    if value is None or isinstance(value, bool):
        return ""
    if isinstance(value, bytes):
        try:
            value = value.decode("utf-8")
        except UnicodeDecodeError:
            return ""
    text = str(value).strip()
    return text


def is_stored_id(value: Any) -> bool:
    """数据库自增主键：整数，或较短的纯数字字符串。"""
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return value >= 0
    text = _as_text(value)
    return bool(text) and text.isdigit() and len(text) <= 12


def _first_text(msg: dict, keys: Iterable[str], *, allow_stored: bool = False) -> str:
    if not isinstance(msg, dict):
        return ""
    for key in keys:
        if key not in msg:
            continue
        raw = msg.get(key)
        if raw in (None, ""):
            continue
        if not allow_stored and is_stored_id(raw) and key in ("event_id", "id"):
            continue
        text = _as_text(raw)
        if text:
            return text[:128]
    return ""


def _nested_bodies(msg: dict) -> list[dict]:
    found = []
    for key in ("body", "payload"):
        inner = msg.get(key)
        if isinstance(inner, dict):
            found.append(inner)
    return found


@dataclass
class EventIdentity:
    event_id: str = ""
    correlation_id: str = ""
    trace_id: str = ""
    parent_event_id: str = ""
    stored_id: int = 0
    traceparent: str = ""

    def log_fields(self) -> str:
        parts = [f"event_id={self.event_id or '-'}"]
        if self.stored_id:
            parts.append(f"stored_id={self.stored_id}")
        if self.correlation_id:
            parts.append(f"correlation_id={self.correlation_id}")
        if self.trace_id:
            parts.append(f"trace_id={self.trace_id[:32]}")
        if self.parent_event_id:
            parts.append(f"parent_event_id={self.parent_event_id}")
        return " ".join(parts)


def stored_id_of(msg: Any) -> int:
    if not isinstance(msg, dict):
        return 0
    for key in ("stored_id", "event_id", "id"):
        raw = msg.get(key)
        if is_stored_id(raw):
            try:
                number = int(raw)
            except (TypeError, ValueError):
                continue
            if number > 0:
                return number
    return 0


def parse_kafka_headers(headers: Any) -> dict[str, str]:
    parsed: dict[str, str] = {}
    if not headers:
        return parsed
    items = headers
    if hasattr(headers, "items") and not isinstance(headers, (list, tuple)):
        try:
            items = list(headers.items())
        except Exception:
            items = headers
    for pair in items:
        try:
            key, value = pair[0], pair[1]
        except (TypeError, ValueError, IndexError):
            continue
        name = key.decode("utf-8") if isinstance(key, (bytes, bytearray)) else str(key)
        text = _as_text(value)
        if name and text and name not in parsed:
            parsed[name] = text[:256]
    return parsed


def resolve(msg: Any = None, headers: Any = None) -> EventIdentity:
    """从消息体、嵌套 body/payload、Kafka headers 解析身份。body 已有 event_id 时以 body 为准。"""
    body = msg if isinstance(msg, dict) else {}
    hdr = parse_kafka_headers(headers)
    nested = _nested_bodies(body)

    event_id = _first_text(body, _EVENT_ID_KEYS)
    if not event_id:
        for inner in nested:
            event_id = _first_text(inner, _EVENT_ID_KEYS)
            if event_id:
                break
    if not event_id:
        event_id = _first_text(body, ("alertId", "alert_id"))
    if not event_id:
        event_id = hdr.get(HEADER_EVENT_ID) or hdr.get("eventId") or ""

    correlation_id = _first_text(body, _CORR_KEYS)
    if not correlation_id:
        for inner in nested:
            correlation_id = _first_text(inner, _CORR_KEYS)
            if correlation_id:
                break
    if not correlation_id:
        correlation_id = hdr.get(HEADER_CORRELATION_ID) or hdr.get("correlationId") or ""

    trace_id = _first_text(body, _TRACE_KEYS)
    if not trace_id:
        for inner in nested:
            trace_id = _first_text(inner, _TRACE_KEYS)
            if trace_id:
                break
    if not trace_id:
        trace_id = hdr.get(HEADER_TRACE_ID) or hdr.get("traceId") or ""
    traceparent = _as_text(body.get("traceparent")) or hdr.get(HEADER_TRACEPARENT) or ""
    if not trace_id and traceparent:
        parts = traceparent.split("-")
        if len(parts) >= 2 and len(parts[1]) == 32:
            trace_id = parts[1]

    parent_event_id = _first_text(body, _PARENT_KEYS)
    if not parent_event_id:
        for inner in nested:
            parent_event_id = _first_text(inner, _PARENT_KEYS)
            if parent_event_id:
                break
    if not parent_event_id:
        parent_event_id = hdr.get(HEADER_PARENT_EVENT_ID) or hdr.get("parentEventId") or ""

    return EventIdentity(
        event_id=event_id[:128],
        correlation_id=correlation_id[:128],
        trace_id=trace_id[:128],
        parent_event_id=parent_event_id[:128],
        stored_id=stored_id_of(body),
        traceparent=traceparent[:128],
    )


def get_event_id(msg: Any = None, headers: Any = None) -> str:
    return resolve(msg, headers).event_id


def new_event_id() -> str:
    return str(uuid.uuid4())


def ensure_identity(
    msg: Any,
    *,
    headers: Any = None,
    producer: str = "",
    correlation_id: str = "",
    trace_id: str = "",
    parent_event_id: str = "",
    derived: bool = False,
) -> dict:
    """给消息盖上身份字段。已有 eventId 一律保留，重试不会换 ID。"""
    if not isinstance(msg, dict):
        msg = {}
    out = dict(msg)
    ident = resolve(out, headers)

    event_id = ident.event_id
    if derived or parent_event_id:
        parent = parent_event_id or ident.parent_event_id or ident.event_id
        if derived:
            event_id = ident.event_id if ident.event_id and ident.event_id != parent else new_event_id()
        else:
            event_id = ident.event_id or new_event_id()
        ident_parent = parent
    else:
        event_id = event_id or new_event_id()
        ident_parent = ident.parent_event_id

    corr = correlation_id or ident.correlation_id or event_id
    tid = trace_id or ident.trace_id
    if not tid:
        tid = event_id.replace("-", "")
        if len(tid) != 32:
            tid = uuid.uuid5(uuid.NAMESPACE_OID, event_id).hex

    out["eventId"] = event_id
    if not _first_text(out, ("event_id",)) and not is_stored_id(out.get("event_id")):
        out["event_id"] = event_id
    out["correlationId"] = corr
    out.setdefault("correlation_id", corr)
    out["traceId"] = out.get("traceId") or tid
    out.setdefault("trace_id", out.get("trace_id") or tid)
    out.setdefault("_trace_id", out.get("_trace_id") or tid)
    if ident_parent:
        out["parentEventId"] = ident_parent
        out.setdefault("parent_event_id", ident_parent)
    if producer and not out.get("producer"):
        out["producer"] = producer

    inner = out.get("body")
    if isinstance(inner, dict) and not get_event_id(inner):
        nested = dict(inner)
        nested["eventId"] = event_id
        nested.setdefault("correlationId", corr)
        nested.setdefault("traceId", tid)
        if ident_parent:
            nested.setdefault("parentEventId", ident_parent)
        out["body"] = nested
    payload = out.get("payload")
    if isinstance(payload, dict) and not get_event_id(payload):
        nested = dict(payload)
        nested["eventId"] = event_id
        nested.setdefault("correlationId", corr)
        nested.setdefault("traceId", tid)
        out["payload"] = nested
    return out


def derive_from(parent: Any, *, extra: Optional[dict] = None, producer: str = "") -> dict:
    """派生新事件：新 event_id，parent_event_id 指向原事件，correlation_id 继承。"""
    src = parent if isinstance(parent, dict) else {}
    parent_ident = resolve(src)
    parent_id = parent_ident.event_id or new_event_id()
    body = dict(extra or {})
    return ensure_identity(
        body,
        producer=producer,
        correlation_id=parent_ident.correlation_id or parent_id,
        trace_id=parent_ident.trace_id,
        parent_event_id=parent_id,
        derived=True,
    )


def identity_headers(msg: Any = None, *, trace_id: str = "", headers: Any = None) -> list[tuple[str, bytes]]:
    ident = resolve(msg, headers)
    event_id = ident.event_id
    tid = trace_id or ident.trace_id
    if not tid and event_id:
        tid = event_id.replace("-", "")
        if len(tid) != 32:
            tid = uuid.uuid5(uuid.NAMESPACE_OID, event_id).hex
    corr = ident.correlation_id or event_id
    pairs: list[tuple[str, bytes]] = []
    if event_id:
        pairs.append((HEADER_EVENT_ID, event_id.encode("utf-8")))
    if corr:
        pairs.append((HEADER_CORRELATION_ID, corr.encode("utf-8")))
    if tid:
        pairs.append((HEADER_TRACE_ID, tid.encode("utf-8")))
    if ident.parent_event_id:
        pairs.append((HEADER_PARENT_EVENT_ID, ident.parent_event_id.encode("utf-8")))
    if ident.traceparent:
        pairs.append((HEADER_TRACEPARENT, ident.traceparent.encode("utf-8")))
    return pairs


def apply_headers(msg: Any, headers: Any) -> dict:
    """消费端：headers 补到 body 上缺失的身份字段，不覆盖已有 eventId。"""
    body = dict(msg) if isinstance(msg, dict) else {}
    ident = resolve(body, headers)
    if ident.event_id and not _first_text(body, _EVENT_ID_KEYS):
        body["eventId"] = ident.event_id
    if ident.correlation_id and not _first_text(body, _CORR_KEYS):
        body["correlationId"] = ident.correlation_id
    if ident.trace_id and not _first_text(body, _TRACE_KEYS):
        body["traceId"] = ident.trace_id
        body["_trace_id"] = ident.trace_id
    if ident.parent_event_id and not _first_text(body, _PARENT_KEYS):
        body["parentEventId"] = ident.parent_event_id
    if ident.traceparent and not body.get("traceparent"):
        body["traceparent"] = ident.traceparent
    for nested_key in ("body", "payload"):
        inner = body.get(nested_key)
        if isinstance(inner, dict) and ident.event_id and not get_event_id(inner):
            nested = dict(inner)
            nested["eventId"] = ident.event_id
            if ident.correlation_id:
                nested.setdefault("correlationId", ident.correlation_id)
            if ident.trace_id:
                nested.setdefault("traceId", ident.trace_id)
            if ident.parent_event_id:
                nested.setdefault("parentEventId", ident.parent_event_id)
            body[nested_key] = nested
    return body


def prepare_event(
    msg: Any,
    *,
    headers: Any = None,
    producer: str = "",
    correlation_id: str = "",
    trace_id: str = "",
) -> tuple[dict, EventIdentity]:
    """入口盖章：返回带身份的消息体和解析结果。已有 eventId 原样保留。"""
    stamped = ensure_identity(
        msg,
        headers=headers,
        producer=producer,
        correlation_id=correlation_id,
        trace_id=trace_id,
    )
    return stamped, resolve(stamped, headers)


def bus_fields(*, stored_id: int = 0, event: Any = None, trace_id: str = "") -> dict:
    """SSE / 总线载荷：整数 event_id 仍是库主键游标，eventId 是稳定业务 ID。"""
    ident = resolve(event)
    out: dict[str, Any] = {}
    if stored_id:
        out["event_id"] = int(stored_id)
        out["stored_id"] = int(stored_id)
    if ident.event_id:
        out["eventId"] = ident.event_id
    corr = ident.correlation_id or ident.event_id
    if corr:
        out["correlationId"] = corr
        out["correlation_id"] = corr
    tid = trace_id or ident.trace_id
    if tid:
        out["trace_id"] = tid
        out["traceId"] = ident.trace_id or tid
    if ident.parent_event_id:
        out["parentEventId"] = ident.parent_event_id
        out["parent_event_id"] = ident.parent_event_id
    return out
