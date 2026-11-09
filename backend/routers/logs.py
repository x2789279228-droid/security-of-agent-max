"""
日志接入与事件管理路由 — 日志注入/批量接入/审核状态/事件查询/记忆管理

端点前缀: /api
"""
import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from models import get_session, SecurityEvent, Memory
from auth import RequireRole, UserInfo, get_current_user
from audit_trail import log_from_request
from log_ingestion import log_ingestor
from event_identity import ensure_identity, get_event_id
from event_store import event_store
from source_registry import source_registry
from vector_store import vector_store


def _ingest_metric(result: str, *, source: str = "http", reason: str = "", n: int = 1) -> None:
    try:
        from core_metrics import record_ingest
        record_ingest(source, result, reason=reason, n=n)
    except Exception:
        pass

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["logs"])


# ── 请求模型 ──

class LogIngestRequest(BaseModel):
    message: str | dict
    session_id: str = ""

class LogBatchRequest(BaseModel):
    logs: list[str | dict]
    session_id: str = ""


# ── 日志接入端点 ──

import re as _re


# ---------- Kafka decoupling gateway helpers ----------
def _ingest_mode() -> str:
    """接入路径三态: kafka(producer 就绪) / kafka_unavailable(启用但未就绪) / http(兼容直写)。

    kafka_unavailable 时必须 503 拒收而不是静默回退直写 —— 否则压测/上游
    会把 HTTP→PG 直连当成 Kafka 流水线口径(2026-10-25 审计确认的失真)。
    """
    if not getattr(settings, "kafka_enabled", False):
        return "http"
    from kafka_producer import kafka_producer as _kp
    return "kafka" if _kp.is_active else "kafka_unavailable"


def _ingest_producer_active() -> bool:
    return _ingest_mode() == "kafka"


def _kafka_unavailable_response() -> JSONResponse:
    return JSONResponse(
        status_code=503,
        content={
            "status": "not_durable",
            "reason": "kafka_unavailable",
            "detail": "Kafka 模式已启用但生产者未就绪，拒收以保证投递承诺；稍后重试或切回直写模式",
        },
        headers={"Retry-After": "5"},
    )

def _peek_type(d: dict) -> str:
    return str(d.get("event") or d.get("type") or d.get("eventType") or "UNKNOWN")

def _peek_source(api_key: str) -> str:
    if api_key:
        src = source_registry.authenticate(api_key)
        if src and getattr(src, "name", ""):
            return src.name
    return "http-admin"


def _authenticate_source(request: Request) -> str:
    """单条/批量接入共用的数据源鉴权（P0-3/P0-5）。

    修复前 batch 接口只读 X-API-Key 就透传，从不调用
    source_registry.authenticate —— 无效/吊销的 key 也能整批写入。
    现在两个端点走同一条路径：带了 key 就必须有效（无效 → 403）；
    Kafka 模式下不带 key 记安全告警（与单条接口同语义）。
    """
    api_key = request.headers.get("X-API-Key", "")
    if api_key:
        source = source_registry.authenticate(api_key)
        if not source:
            _ingest_metric("rejected", reason="auth")
            raise HTTPException(403, "Invalid or revoked API key")
        return api_key
    # R12(复审 P1-8 认证倒挂扶正): 修复前"带无效 key 拒绝(403)、完全不带 key
    # 放行" —— 攻击者只要不发 header 就能绕过数据源认证。现在:
    #   - 已配置任何数据源密钥 → 无 key 一律 401(fail-closed);
    #   - 未配置密钥: prod 拒绝(与 source_registry 的 prod 口径一致),
    #     非 prod 放行 + 一次性 warning(演示/开发兼容, demo_start.bat 依赖)。
    if source_registry._sources:
        _ingest_metric("rejected", reason="auth")
        raise HTTPException(401, "API key required")
    env_name = (getattr(settings, "env_name", "dev") or "dev").lower()
    if env_name == "prod":
        _ingest_metric("rejected", reason="auth")
        raise HTTPException(401, "API key required (SOURCE_API_KEYS unconfigured in prod)")
    if not getattr(_authenticate_source, "_anon_warned", False):
        _authenticate_source._anon_warned = True
        logger.warning("[Security] HTTP ingest without API key allowed in dev (SOURCE_API_KEYS unconfigured) — prod rejects")
    return api_key

def _stamp_ingest_events(events: list) -> list[dict]:
    """入口盖章：已有 eventId 保留，缺失时生成一次。"""
    stamped = []
    for ev in events:
        body = ev if isinstance(ev, dict) else {}
        stamped.append(ensure_identity(body, producer="backend.http_ingest"))
    return stamped


async def _enqueue_ingest(session_id: str, api_key: str, events: list) -> int:
    from kafka_producer import kafka_producer as _kp
    messages = []
    for ev in events:
        body = ensure_identity(ev if isinstance(ev, dict) else {}, producer="backend.http_ingest")
        if isinstance(ev, dict):
            ev.update(body)
        eid = get_event_id(body)
        messages.append({
            "uuid": eid,
            "eventId": eid,
            "correlationId": body.get("correlationId") or eid,
            "type": "security_event",
            "session_id": session_id,
            "source_id": _peek_source(api_key),
            "source_key": api_key or "",
            "_ts": round(__import__("time").time(), 3),
            "body": body,
        })
    return await _kp.produce_raw_batch(
        messages, topic=settings.kafka_topic_ingest_process, key_field="uuid")

def _sanitize_value(v):
    """移除 HTML 标签, 防止存储型 XSS"""
    if isinstance(v, str):
        return _re.sub(r'<[^>]*>', '', v)
    return v


def _queued_status_code() -> int:
    return int(getattr(settings, "ingest_http_queued_status", 202) or 202)


def _overload_response(reason: str, **extra):
    from capacity import overload_retry_after, overload_status
    retry_after = overload_retry_after()
    body = {"status": "overloaded", "reason": reason, "retry_after": retry_after}
    body.update(extra)
    return JSONResponse(
        status_code=overload_status(),
        content=body,
        headers={"Retry-After": str(retry_after)},
    )


def _reject_if_body_too_large(request: Request) -> None:
    from capacity import body_too_large
    raw = request.headers.get("content-length")
    if raw and str(raw).isdigit() and body_too_large(int(raw)):
        _ingest_metric("rejected", reason="too_large")
        raise HTTPException(413, "Request body exceeds configured limit")


def _reject_if_batch_forbidden(count: int) -> None:
    from capacity import BatchRejected, ensure_batch_allowed
    try:
        ensure_batch_allowed(count)
    except BatchRejected as exc:
        _ingest_metric("rejected", reason="batch_too_large", n=max(1, int(exc.count or count or 1)))
        raise HTTPException(413, f"Batch size {exc.count} exceeds limit of {exc.limit}") from exc


async def _admit(direct: bool):
    from capacity import AdmissionDenied, admit_http
    try:
        await admit_http(direct=direct)
    except AdmissionDenied as exc:
        return _overload_response(exc.reason)
    return None


async def _session_unless_queued():
    """Kafka producer 活跃时网关不借 OLTP session (yield None), 否则透传 get_session。"""
    if _ingest_producer_active():
        yield None
        return
    from models import get_session
    async for s in get_session():
        yield s


@router.post("/logs/ingest")
async def ingest_log(
    req: LogIngestRequest,
    request: Request,
    session: AsyncSession = Depends(_session_unless_queued)
):
    """
    接入单条安全日志

    安全增强: 支持 X-API-Key 头认证。
    - Kafka 模式下: 入队 security-events-ingest 后立即返回 202 (不借 DB session)
    - HTTP 模式下: 建议携带 X-API-Key 头, 同步 ingest 后返回 200
    """
    # 数据源认证检查（与 batch 接口共用 _authenticate_source）
    api_key = _authenticate_source(request)

    from drain import drain
    if not drain.accepting:
        _ingest_metric("rejected", reason="draining")
        return JSONResponse(
            status_code=503,
            content={"status": "draining", "detail": "服务正在关闭，不再接受新任务"},
        )
    _reject_if_body_too_large(request)
    mode = _ingest_mode()
    if mode == "kafka_unavailable":
        _ingest_metric("rejected", reason="kafka_unavailable")
        return _kafka_unavailable_response()
    denied = await _admit(direct=(mode != "kafka"))
    if denied is not None:
        _ingest_metric("rejected", reason="overloaded")
        return denied

    session_id = req.session_id or str(uuid.uuid4())
    log_data = req.message if isinstance(req.message, dict) else json.loads(req.message)
    # 输入 sanitization: 移除 message 字段中的 HTML 标签
    if isinstance(log_data.get("message"), str):
        log_data["message"] = _sanitize_value(log_data["message"])
    log_data = ensure_identity(log_data, producer="backend.http_ingest")
    if mode == "kafka":
        produced = await _enqueue_ingest(session_id, api_key, [log_data])
        if produced != 1:
            _ingest_metric("rejected", reason="not_durable")
            return JSONResponse(
                status_code=503,
                content={
                    "session_id": session_id,
                    "status": "not_durable",
                    "produced": produced,
                    "count": 1,
                    "eventId": get_event_id(log_data),
                    "detail": "Kafka 未确认这条日志，未接受",
                },
            )
        _ingest_metric("queued")
        return JSONResponse(
            status_code=_queued_status_code(),
            content={"session_id": session_id, "status": "queued", "produced": produced,
                     "eventId": get_event_id(log_data),
                     "event_type": _peek_type(log_data),
                     "severity": log_data.get("severity", "info")},
        )

    from capacity import GateTimeout
    try:
        result = await log_ingestor.ingest(session, session_id, log_data)
    except GateTimeout as exc:
        _ingest_metric("rejected", reason="overloaded")
        return _overload_response(exc.gate)
    _ingest_metric("accepted")
    return {"session_id": session_id, **result}

@router.post("/logs/ingest/batch")
async def ingest_log_batch(
    req: LogBatchRequest,
    request: Request,
    session: AsyncSession = Depends(_session_unless_queued)
):
    """Fast Path: 批量接入安全日志"""
    # P0-3/P0-5: batch 接口与单条接口共用鉴权，且鉴权前置 ——
    # 修复前只透传 header，无效 key 也能整批写入 Kafka。
    api_key = _authenticate_source(request)
    from drain import drain
    if not drain.accepting:
        _ingest_metric("rejected", reason="draining", n=max(1, len(req.logs)))
        return JSONResponse(
            status_code=503,
            content={"status": "draining", "detail": "服务正在关闭，不再接受新任务"},
        )
    _reject_if_body_too_large(request)
    _reject_if_batch_forbidden(len(req.logs))
    mode = _ingest_mode()
    if mode == "kafka_unavailable":
        _ingest_metric("rejected", reason="kafka_unavailable", n=max(1, len(req.logs)))
        return _kafka_unavailable_response()
    denied = await _admit(direct=(mode != "kafka"))
    if denied is not None:
        _ingest_metric("rejected", reason="overloaded", n=max(1, len(req.logs)))
        return denied
    session_id = req.session_id or str(uuid.uuid4())
    parsed = [d if isinstance(d, dict) else json.loads(d) for d in req.logs]
    # 输入 sanitization
    for d in parsed:
        if isinstance(d.get("message"), str):
            d["message"] = _sanitize_value(d["message"])
    parsed = _stamp_ingest_events(parsed)
    if mode == "kafka":
        produced = await _enqueue_ingest(session_id, api_key, parsed)
        event_ids = [get_event_id(d) for d in parsed]
        if produced <= 0:
            _ingest_metric("rejected", reason="not_durable", n=max(1, len(parsed)))
            return JSONResponse(
                status_code=503,
                content={
                    "session_id": session_id,
                    "status": "not_durable",
                    "produced": produced,
                    "count": len(parsed),
                    "event_ids": event_ids,
                    "detail": "Kafka 未确认任何日志，未接受",
                },
            )
        if produced != len(parsed):
            failed = len(parsed) - produced
            _ingest_metric("queued", n=produced)
            _ingest_metric("rejected", reason="not_durable", n=max(1, failed))
            return JSONResponse(
                status_code=207,
                content={
                    "session_id": session_id,
                    "status": "partial",
                    "produced": produced,
                    "failed": failed,
                    "count": len(parsed),
                    "event_ids": event_ids,
                    "detail": "Kafka 只确认了部分日志，已确认的不必整批重放",
                },
            )
        _ingest_metric("queued", n=len(parsed))
        return JSONResponse(
            status_code=_queued_status_code(),
            content={"session_id": session_id, "status": "queued",
                     "produced": produced, "count": len(parsed),
                     "event_ids": event_ids},
        )

    from capacity import GateTimeout, IngestCapacityError
    try:
        result = await log_ingestor.ingest_batch(session, session_id, parsed)
    except IngestCapacityError as exc:
        _ingest_metric("rejected", reason="overloaded", n=max(1, len(parsed)))
        return _overload_response(exc.reason, accepted=exc.accepted, count=exc.total)
    except GateTimeout as exc:
        _ingest_metric("rejected", reason="overloaded", n=max(1, len(parsed)))
        return _overload_response(exc.gate)
    _ingest_metric("accepted", n=len(parsed))
    return {"session_id": session_id, **result}


# ── 攻击剧本一键注入（接入台专用，2026-11 传智杯 AI Web 改造）──────────────

async def _run_ingest_pipeline(
    parsed: list[dict],
    session_id: str,
    request: Request,
    session: AsyncSession,
    *,
    source: str,
):
    """剧本/手动注入共用的接入管道 —— 与 /logs/ingest/batch 同一套门禁与传输。

    返回 (JSONResponse | dict)：Kafka 路径 202/207/503；直写路径 dict 结果。
    调用方已通过 JWT 鉴权（operator 及以上），故不要求 X-API-Key ——
    调用者是登录的值班员而非外部数据源。
    """
    from drain import drain
    if not drain.accepting:
        return JSONResponse(status_code=503, content={
            "status": "draining", "detail": "服务正在关闭，不再接受新任务"})
    _reject_if_body_too_large(request)
    _reject_if_batch_forbidden(len(parsed))
    mode = _ingest_mode()
    if mode == "kafka_unavailable":
        return _kafka_unavailable_response()
    denied = await _admit(direct=(mode != "kafka"))
    if denied is not None:
        return denied

    if mode == "kafka":
        produced = await _enqueue_ingest(session_id, "", parsed)
        event_ids = [get_event_id(d) for d in parsed]
        if produced <= 0:
            _ingest_metric("rejected", reason="not_durable", n=len(parsed), source=source)
            return JSONResponse(status_code=503, content={
                "status": "not_durable", "produced": produced,
                "detail": "Kafka 未确认任何日志，未接受"})
        _ingest_metric("queued", n=len(parsed), source=source)
        return JSONResponse(status_code=_queued_status_code(), content={
            "session_id": session_id, "status": "queued",
            "produced": produced, "count": len(parsed), "event_ids": event_ids})

    from capacity import GateTimeout, IngestCapacityError
    try:
        result = await log_ingestor.ingest_batch(session, session_id, parsed)
    except IngestCapacityError as exc:
        return _overload_response(exc.reason, accepted=exc.accepted, count=exc.total)
    except GateTimeout as exc:
        return _overload_response(exc.gate)
    _ingest_metric("accepted", n=len(parsed), source=source)
    return {"session_id": session_id, **result}


def _merge_extra(result, extra: dict):
    """把剧本/手动元信息并进管道响应。

    必须重建 JSONResponse 而不是原地改 body —— Content-Length 在构造时
    已按原 body 写死，事后换更长的 body 会触发 h11
    "Too much data for declared Content-Length" 直接断连
    （nginx 记 202 但浏览器报 Failed to fetch，2026-11-07 E2E 实测）。
    """
    if isinstance(result, JSONResponse):
        payload = json.loads(result.body)
        payload.update(extra)
        return JSONResponse(status_code=result.status_code, content=payload)
    return {**result, **extra}


@router.get("/logs/scenarios")
async def list_scenarios(user: UserInfo = Depends(get_current_user)):
    """剧本目录（前端接入台卡片数据：名称/描述/事件数/severity 分布）。"""
    from log_scenarios import scenario_catalog
    return {"scenarios": scenario_catalog()}


@router.post("/logs/scenario/{name}")
async def ingest_scenario(
    name: str,
    request: Request,
    session: AsyncSession = Depends(_session_unless_queued),
    user: UserInfo = Depends(RequireRole("operator")),
):
    """一键注入攻击剧本。

    每条日志带 inject_source="scenario:<name>" 标记（明示演练来源，不伪装真实流量）。
    """
    from log_scenarios import SCENARIOS, build_scenario

    meta = SCENARIOS.get(name)
    if not meta:
        raise HTTPException(404, f"Unknown scenario: {name}")

    logs = build_scenario(name) or []
    if not logs:
        raise HTTPException(500, f"Scenario {name} generated no logs")
    for d in logs:
        if isinstance(d.get("message"), str):
            d["message"] = _sanitize_value(d["message"])
    parsed = _stamp_ingest_events(logs)

    session_id = str(uuid.uuid4())
    result = await _run_ingest_pipeline(parsed, session_id, request, session, source="scenario")
    return _merge_extra(result, {"scenario": name, "title": meta["title"]})


@router.post("/logs/manual")
async def ingest_manual(
    req: LogIngestRequest,
    request: Request,
    session: AsyncSession = Depends(_session_unless_queued),
    user: UserInfo = Depends(RequireRole("operator")),
):
    """值班员手动录入单条日志（接入台编辑器专用）。

    与外部数据源 /logs/ingest 的差别：JWT 鉴权（无需 X-API-Key），且日志带
    inject_source="manual:<username>" —— 平台上可审计到"谁手动录的"。
    """
    log_data = req.message if isinstance(req.message, dict) else json.loads(req.message)
    if not isinstance(log_data, dict):
        raise HTTPException(422, "message 必须是 JSON 对象")
    if isinstance(log_data.get("message"), str):
        log_data["message"] = _sanitize_value(log_data["message"])
    log_data["inject_source"] = f"manual:{user.username}"
    parsed = _stamp_ingest_events([log_data])

    session_id = req.session_id or str(uuid.uuid4())
    result = await _run_ingest_pipeline(
        parsed, session_id, request, session, source="manual")
    return _merge_extra(result, {"event_ids": [get_event_id(d) for d in parsed]})


@router.post("/logs/manual/batch")
async def ingest_manual_batch(
    req: LogBatchRequest,
    request: Request,
    session: AsyncSession = Depends(_session_unless_queued),
    user: UserInfo = Depends(RequireRole("operator")),
):
    """值班员批量录入（接入台文件上传专用）——口径同 /logs/manual，逐条打标。"""
    if not req.logs:
        raise HTTPException(422, "logs 不能为空")
    parsed = []
    for item in req.logs:
        d = item if isinstance(item, dict) else json.loads(item)
        if not isinstance(d, dict):
            raise HTTPException(422, "logs 每项必须是 JSON 对象")
        if isinstance(d.get("message"), str):
            d["message"] = _sanitize_value(d["message"])
        d["inject_source"] = f"manual:{user.username}"
        parsed.append(d)
    parsed = _stamp_ingest_events(parsed)

    session_id = req.session_id or str(uuid.uuid4())
    result = await _run_ingest_pipeline(
        parsed, session_id, request, session, source="manual")
    return _merge_extra(result, {"event_ids": [get_event_id(d) for d in parsed]})

@router.post("/logs/analyze")
async def trigger_analysis(
    session_id: str = Query(..., description="会话ID"),
    user: UserInfo = Depends(RequireRole("operator")),
):
    """手动触发未分析日志的批量分析"""
    from drain import drain
    from capacity import batch_fanout_gate
    if not drain.accepting:
        raise HTTPException(503, "服务正在关闭，不再接受新任务")
    denied = await _admit(direct=True)
    if denied is not None:
        return denied
    gate = batch_fanout_gate()
    if not await gate.try_acquire():
        return _overload_response("analysis_saturated")

    async def _run():
        try:
            await log_ingestor._run_batch_analysis(session_id)
        finally:
            await gate.release()

    try:
        asyncio.create_task(_run())
    except Exception:
        await gate.release()
        raise
    return {"status": "analysis_triggered", "session_id": session_id}

@router.get("/logs/status")
async def log_status(
    session_id: str = Query(..., description="会话ID"),
    session: AsyncSession = Depends(get_session)
):
    """查询日志接入状态"""
    return await log_ingestor.get_status(session, session_id)

@router.get("/logs/review")
async def review_status(
    session_id: str = Query(..., description="会话ID"),
    limit: int = Query(50, description="返回条数"),
    session: AsyncSession = Depends(get_session)
):
    """查询每条日志的审核状态"""
    stmt = (
        select(SecurityEvent)
        .where(SecurityEvent.session_id == session_id)
        .order_by(desc(SecurityEvent.created_at))
        .limit(limit)
    )
    result = await session.execute(stmt)
    rows = result.scalars().all()
    reviewed = sum(1 for r in rows if r.analyzed)
    return {
        "session_id": session_id,
        "total": len(rows),
        "reviewed": reviewed,
        "pending": len(rows) - reviewed,
        "events": [
            {
                "id": e.id,
                "event_type": e.event_type,
                "severity": e.severity,
                "message": e.message[:80],
                "analyzed": e.analyzed,
                # Audit-LLM 管道写入键为 _audit_llm（历史键 _review 兼容保留）
                "result": (e.raw_data or {}).get("_audit_llm")
                          or (e.raw_data or {}).get("_review", {}),
                "error": (e.raw_data or {}).get("_audit_llm_error", ""),
                "created_at": e.created_at.isoformat(),
            }
            for e in rows
        ],
    }

@router.get("/logs/stuck")
async def stuck_events(
    minutes: int = Query(5, description="超过多少分钟未分析视为卡住"),
    session: AsyncSession = Depends(get_session)
):
    """诊断: 查找卡在审核中的事件"""
    from datetime import timedelta
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=minutes)
    stmt = (
        select(SecurityEvent)
        .where(SecurityEvent.analyzed == False, SecurityEvent.created_at < cutoff)
        .order_by(SecurityEvent.created_at)
        .limit(100)
    )
    result = await session.execute(stmt)
    rows = result.scalars().all()
    return {
        "stuck_count": len(rows),
        "cutoff_minutes": minutes,
        "events": [
            {
                "id": e.id,
                "event_type": e.event_type,
                "severity": e.severity,
                "created_at": e.created_at.isoformat(),
                "has_error": bool((e.raw_data or {}).get("_audit_llm_error")),
                "error": (e.raw_data or {}).get("_audit_llm_error", ""),
            }
            for e in rows
        ],
    }

@router.post("/logs/reset-stuck")
async def reset_stuck(
    request: Request,
    minutes: int = Query(5, description="超过多少分钟未分析视为卡住"),
    session: AsyncSession = Depends(get_session),
    user: UserInfo = Depends(RequireRole("admin", "operator")),
):
    """将所有卡住的事件标记为已分析（含错误标记），释放管道 (管道状态变更限操作员以上)"""
    from datetime import timedelta
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=minutes)
    stmt = (
        select(SecurityEvent)
        .where(SecurityEvent.analyzed == False, SecurityEvent.created_at < cutoff)
    )
    result = await session.execute(stmt)
    rows = result.scalars().all()
    count = 0
    reset_ids = []
    for e in rows:
        e.analyzed = True
        raw = dict(e.raw_data or {})
        raw["_audit_llm_error"] = "reset_by_admin"
        audit = dict(raw.get("_audit_llm") or {})
        audit["status"] = "failed"
        audit["error"] = "reset_by_admin"
        audit["note"] = "stuck event reset by admin/scheduler"
        raw["_audit_llm"] = audit
        e.raw_data = raw
        reset_ids.append(e.id)
        count += 1
    await event_store.commit_then_invalidate(session, *reset_ids)
    await log_from_request(
        session, request, user, action="logs.reset_stuck",
        target_type="security_event", target_id="*",
        after={"reset_count": count, "minutes": minutes},
        reason="批量重置卡住事件的分析状态",
    )
    return {"reset_count": count}

@router.get("/logs/events")
async def list_events(
    session_id: str = Query("", description="会话ID"),
    severity: str = Query("", description="按严重度筛选"),
    limit: int = 50, offset: int = 0,
    after_id: int = Query(0, ge=0, description="只返回 id 大于该值的事件，按 id 升序，供断线补查"),
    session: AsyncSession = Depends(get_session)
):
    """查询已接入的安全事件。

    after_id > 0 时按主键升序返回更晚的行，这是 SSE 断线补查的同一游标。
    不带 after_id 时仍按创建时间倒序，避免打乱现有日志列表。
    """
    if after_id > 0:
        stmt = (
            select(SecurityEvent)
            .where(SecurityEvent.id > after_id)
            .order_by(SecurityEvent.id.asc())
        )
    else:
        stmt = select(SecurityEvent).order_by(desc(SecurityEvent.created_at))
    if session_id:
        stmt = stmt.where(SecurityEvent.session_id == session_id)
    if severity:
        stmt = stmt.where(SecurityEvent.severity == severity)
    stmt = stmt.limit(limit).offset(offset)
    result = await session.execute(stmt)
    rows = result.scalars().all()
    return [
        {
            "id": e.id, "session_id": e.session_id,
            "event_type": e.event_type, "severity": e.severity,
            "src_ip": e.src_ip, "dst_ip": e.dst_ip,
            "message": e.message, "analyzed": e.analyzed,
            "anomaly_score": e.anomaly_score or 0.0,
            "is_anomaly": bool((e.anomaly_score or 0.0) >= 0.6),
            "audit_quality": (
                ((e.raw_data or {}).get("_audit_llm") or {}).get("quality")
                or ("fallback" if ((e.raw_data or {}).get("_audit_llm") or {}).get("fallback") else (
                    "llm" if e.analyzed else None
                ))
            ),
            "created_at": e.created_at.isoformat(),
        }
        for e in rows
    ]


# ── 记忆管理端点 ──

@router.get("/memories")
async def list_memories(
    limit: int = 20, offset: int = 0,
    session: AsyncSession = Depends(get_session)
):
    stmt = select(Memory).order_by(desc(Memory.created_at)).limit(limit).offset(offset)
    result = await session.execute(stmt)
    rows = result.scalars().all()
    return [
        {
            "id": m.id, "agent_id": m.agent_id, "content": m.content[:200],
            "metadata": m.metadata_, "created_at": m.created_at.isoformat()
        }
        for m in rows
    ]

@router.delete("/memories/{memory_id}")
async def delete_memory(
    memory_id: int,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: UserInfo = Depends(RequireRole("operator")),
):
    ok = await vector_store.delete_memory(session, memory_id)
    if not ok:
        raise HTTPException(404, "Memory not found")
    await log_from_request(
        session, request, user, action="memory.delete",
        target_type="memory", target_id=str(memory_id),
    )
    return {"deleted": True}
