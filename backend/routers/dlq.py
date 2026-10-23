"""死信恢复接口。

查看和 dry-run：admin 或 operator。
真正重放：只有 admin，必须 confirm=true，并写入审计。
响应里没有原始负载，也没有密文。
"""
import logging
import threading

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from audit_trail import log_from_request
from auth import RequireRole, UserInfo, get_current_user
from dlq_store import dry_run, get_record, list_records, parse_ts, replay_record
from models import get_session

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/dlq", tags=["dlq"])

_VIEW_ROLES = ("admin", "operator")
# 进程内 replay 并发上限。频率由 HTTP strict 桶限制；这里挡住同秒多条重放打满 Kafka。
_REPLAY_CONCURRENCY = 2
_replay_slots = threading.BoundedSemaphore(_REPLAY_CONCURRENCY)


def _ensure(user: UserInfo, *roles: str) -> None:
    if getattr(user, "role", "") == "admin":
        return
    if getattr(user, "role", "") not in roles:
        raise HTTPException(status_code=403, detail=f"Requires one of roles: {sorted(roles)}")


class ReplayRequest(BaseModel):
    confirm: bool = False
    idempotency_key: str = Field(default="", max_length=120)


@router.get("")
async def list_dlq(
    event_id: str = "",
    topic: str = "",
    since: str = "",
    until: str = "",
    limit: int = Query(50, ge=1, le=200),
    user: UserInfo = Depends(RequireRole("admin", "operator")),
):
    _ensure(user, *_VIEW_ROLES)
    try:
        since_dt = parse_ts(since)
        until_dt = parse_ts(until)
    except ValueError:
        raise HTTPException(status_code=400, detail="since/until must be ISO-8601 timestamps")
    items = await list_records(
        event_id=event_id.strip(),
        topic=topic.strip(),
        since=since_dt,
        until=until_dt,
        limit=limit,
    )
    return {"items": items, "count": len(items)}


@router.get("/{record_id}")
async def get_dlq(
    record_id: int,
    user: UserInfo = Depends(RequireRole("admin", "operator")),
):
    _ensure(user, *_VIEW_ROLES)
    row = await get_record(record_id)
    if row is None:
        raise HTTPException(status_code=404, detail="dlq record not found")
    return row


@router.post("/{record_id}/dry-run")
async def dry_run_dlq(
    record_id: int,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: UserInfo = Depends(RequireRole("admin", "operator")),
):
    _ensure(user, *_VIEW_ROLES)
    result = await dry_run(record_id)
    if result is None:
        raise HTTPException(status_code=404, detail="dlq record not found")
    await log_from_request(
        session, request, user,
        action="dlq.dry_run",
        target_type="dlq",
        target_id=str(record_id),
        after={
            "event_id": result.get("event_id", ""),
            "ok": result.get("ok"),
            "cipher_code": result.get("cipher_code", ""),
            "replay_allowed": result.get("replay_allowed"),
            "original_topic": result.get("original_topic", ""),
        },
        reason="dry-run",
    )
    return result


@router.post("/{record_id}/replay")
async def replay_dlq(
    record_id: int,
    body: ReplayRequest,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: UserInfo = Depends(get_current_user),
):
    if getattr(user, "role", "") != "admin":
        await log_from_request(
            session, request, user,
            action="dlq.replay_denied",
            target_type="dlq",
            target_id=str(record_id),
            after={"role": getattr(user, "role", "")},
            reason="role",
        )
        raise HTTPException(status_code=403, detail="Requires role: admin")
    if body.confirm is not True:
        raise HTTPException(status_code=400, detail="confirm must be true")
    if not _replay_slots.acquire(blocking=False):
        raise HTTPException(status_code=429, detail="replay concurrency limit")
    try:
        result = await replay_record(
            record_id,
            actor=getattr(user, "username", "") or "",
            idempotency_key=body.idempotency_key,
        )
    finally:
        _replay_slots.release()
    await log_from_request(
        session, request, user,
        action="dlq.replay",
        target_type="dlq",
        target_id=str(record_id),
        after={
            "status": result.get("status", ""),
            "event_id": result.get("event_id", ""),
            "idempotent": bool(result.get("idempotent")),
            "error_code": result.get("error_code", ""),
            "target_topic": result.get("target_topic", ""),
            "target_offset": result.get("target_offset"),
            "idempotency_key": result.get("idempotency_key", ""),
        },
        reason="replay",
    )
    status = result.get("status")
    if status == "not_found":
        raise HTTPException(status_code=404, detail="dlq record not found")
    if status == "blocked":
        raise HTTPException(status_code=409, detail={"error_code": result.get("error_code", "")})
    if status == "in_progress":
        raise HTTPException(status_code=409, detail="replay already in progress")
    if status == "publish_failed":
        raise HTTPException(status_code=503, detail="replay was not acknowledged")
    return result
