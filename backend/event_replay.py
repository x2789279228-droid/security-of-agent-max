"""
安全事件断线补查。

游标是 security_events.id（自增主键，进程重启后仍然有效）。
内存 seq 和 epoch.seq 不是游标：解析失败时记为 ignored，不拿去查库。

补查与实时的衔接由调用方保证：先订阅总线，再查库，再按事件 ID 丢掉重叠的实时副本。
"""
import json
import time
from datetime import datetime, timezone

from sqlalchemy import func, select

REPLAY_PAGE = 500
REPLAY_CAP = 2000
REFRESH_TAIL = 50
INITIAL_TAIL = 100


def resolve_resume_cursor(header: str | None, query: str | None) -> tuple[int, str]:
    """合并 Last-Event-ID 和查询参数。只接受十进制整数，取较大的一个。

    带点的 epoch.seq 会被忽略。两边都不是整数时返回 (0, "ignored")，
    调用方应把这次续传标成不完整，而不是当成从 0 开始的全新尾巴。
    """
    def parse(raw: str | None) -> int | None:
        if raw is None:
            return None
        text = str(raw).strip()
        if text.isdigit():
            return int(text)
        return None

    values = [n for n in (parse(header), parse(query)) if n is not None]
    raw_header = str(header or "").strip()
    raw_query = str(query or "").strip()
    if not values:
        if raw_header or raw_query:
            return 0, "ignored"
        return 0, "none"
    return max(values), "event_id"


def parse_refresh_ids(raw: str | None, limit: int = 32) -> list[int]:
    if not raw:
        return []
    found: list[int] = []
    for part in str(raw).split(","):
        text = part.strip()
        if not text.isdigit():
            continue
        number = int(text)
        if number > 0 and number not in found:
            found.append(number)
        if len(found) >= limit:
            break
    return found


def _ts(value) -> float:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.timestamp()
    return time.time()


def snapshot_dict(row) -> dict:
    raw = row.raw_data if isinstance(row.raw_data, dict) else {}
    audit = raw.get("_audit_llm") if isinstance(raw.get("_audit_llm"), dict) else {}
    return {
        "event_id": row.id,
        "event_type": row.event_type,
        "severity": row.severity,
        "src_ip": row.src_ip or "",
        "dst_ip": row.dst_ip or "",
        "message": (row.message or "")[:500],
        "analyzed": bool(row.analyzed),
        "anomaly_score": row.anomaly_score or 0.0,
        "session_id": row.session_id or "",
        "audit_verdict": str(audit.get("verdict") or "")[:200],
        "audit_severity": str(audit.get("severity") or "")[:20],
        "threat_detected": bool(audit.get("threat_detected")),
    }


def _frame(row, *, refresh: bool, high_water: int) -> tuple[dict, int]:
    body = snapshot_dict(row)
    body.update({
        "_cursor_kind": "event_id",
        "_event_id": row.id,
        "_replay": True,
        "_refresh": refresh,
        "_ts": _ts(row.created_at),
        "_lane": "critical",
        "_severity": str(row.severity or "info").lower(),
    })
    frame = {
        "event": "security_event",
        "data": json.dumps(body, ensure_ascii=False, default=str),
        "dedup": f"e:security_event:{row.id}",
    }
    # 刷新旧行不能把 SSE id 拨回去，否则浏览器的 Last-Event-ID 会倒退。
    if not refresh and row.id >= high_water:
        frame["id"] = str(row.id)
        high_water = row.id
    return frame, high_water


async def fetch_event_snapshot(event_id: int, *, include_response: bool = False) -> dict | None:
    from models import SecurityEvent, async_session

    async with async_session() as session:
        row = await session.get(SecurityEvent, int(event_id))
        if row is None:
            return None
        snap = snapshot_dict(row)
        if include_response:
            snap["responses"] = await _latest_responses(session, row.id)
        return snap


async def _latest_responses(session, event_id: int) -> list[dict]:
    try:
        from models import ResponseLog
    except Exception:
        return []
    stmt = (
        select(ResponseLog)
        .where(ResponseLog.event_id == event_id)
        .order_by(ResponseLog.id.desc())
        .limit(3)
    )
    rows = (await session.execute(stmt)).scalars().all()
    out = []
    for row in reversed(rows):
        out.append({
            "id": row.id,
            "action_name": row.action_name,
            "action_success": bool(row.action_success),
            "threat_type": row.threat_type,
            "threat_severity": row.threat_severity,
        })
    return out


async def load_sse_replay(after_id: int, refresh_ids: list[int] | None = None) -> tuple[list[dict], dict]:
    """先读持久化记录。调用方必须已经订阅总线，避免补查和实时之间出现空洞。

    after_id == 0：新连接，只给最近 INITIAL_TAIL 条，不回放全表。
    after_id > 当前最大 id：游标无法解释（旧的内存 seq 或库被重建），标记 cursor_reset。
    命中 REPLAY_CAP 仍落后于最大 id：complete=false，next_after_id 是已发出的最后一行。
    """
    from models import SecurityEvent, async_session

    after_id = max(0, int(after_id or 0))
    refresh_ids = list(refresh_ids or [])
    meta = {
        "complete": True,
        "cursor_reset": False,
        "max_event_id": 0,
        "next_after_id": None,
        "db_error": False,
    }
    if after_id == 0 and not refresh_ids:
        async with async_session() as session:
            max_id = int(await session.scalar(select(func.max(SecurityEvent.id))) or 0)
            tail = list(reversed((await session.execute(
                select(SecurityEvent)
                .order_by(SecurityEvent.id.desc())
                .limit(INITIAL_TAIL)
            )).scalars().all()))
        meta["max_event_id"] = max_id
        meta["initial_tail"] = True
        frames: list[dict] = []
        high_water = 0
        for row in tail:
            frame, high_water = _frame(row, refresh=False, high_water=high_water)
            frames.append(frame)
        if tail:
            meta["next_after_id"] = tail[-1].id
        return frames, meta

    async with async_session() as session:
        max_id = int(await session.scalar(select(func.max(SecurityEvent.id))) or 0)
        meta["max_event_id"] = max_id
        if after_id > max_id:
            meta["complete"] = False
            meta["cursor_reset"] = True
            meta["next_after_id"] = max_id
            return [], meta

        rows: list = []
        cursor = after_id
        while len(rows) < REPLAY_CAP:
            batch = (await session.execute(
                select(SecurityEvent)
                .where(SecurityEvent.id > cursor)
                .order_by(SecurityEvent.id.asc())
                .limit(REPLAY_PAGE)
            )).scalars().all()
            if not batch:
                break
            rows.extend(batch)
            cursor = batch[-1].id
            if len(batch) < REPLAY_PAGE:
                break

        refresh_rows = []
        if refresh_ids:
            refresh_rows = (await session.execute(
                select(SecurityEvent)
                .where(SecurityEvent.id.in_(refresh_ids[:32]))
                .order_by(SecurityEvent.id.asc())
            )).scalars().all()
        elif after_id > 0:
            # 审计/响应更新的是已有行，id 不会增大。重连时刷新游标之前最近的已分析行。
            refresh_rows = list(reversed((await session.execute(
                select(SecurityEvent)
                .where(SecurityEvent.id <= after_id, SecurityEvent.analyzed.is_(True))
                .order_by(SecurityEvent.id.desc())
                .limit(REFRESH_TAIL)
            )).scalars().all()))

    truncated = bool(rows) and rows[-1].id < max_id and len(rows) >= REPLAY_CAP
    meta["complete"] = not truncated
    if rows:
        meta["next_after_id"] = rows[-1].id
    elif not truncated:
        meta["next_after_id"] = after_id

    frames: list[dict] = []
    high_water = after_id
    seen_refresh: set[int] = set()
    for row in refresh_rows:
        if row.id in seen_refresh:
            continue
        seen_refresh.add(row.id)
        frame, high_water = _frame(row, refresh=True, high_water=high_water)
        frames.append(frame)
    for row in rows:
        frame, high_water = _frame(row, refresh=False, high_water=high_water)
        frames.append(frame)
    return frames, meta
