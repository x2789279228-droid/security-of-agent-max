"""
对话/记忆树/实时事件路由 — 聊天流水线/SSE 事件流/记忆树/统计

端点前缀: /api
"""
import asyncio
import json
import logging
import time
import uuid

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from sse_starlette.sse import EventSourceResponse

from config import settings
from models import get_session, Conversation, SecurityEvent, Memory, MemoryTreeNode
from sliding_window import sliding_window
from memory_tree import memory_tree
from context_stream import context_stream
from event_bus import BOOT_TS, dedup_key, event_bus, hydrate_notice, render_sse, should_skip_live
from event_replay import load_sse_replay, parse_refresh_ids, resolve_resume_cursor
from agents import AgentA, AgentB, AgentC

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["chat"])

# 旧流水线 Agent 实例（兼容旧端点）
agent_a = AgentA()
agent_b = AgentB()
agent_c = AgentC()


# ── 请求模型 ──

class ChatRequest(BaseModel):
    query: str
    session_id: str = ""


# ── SSE 实时事件流 ──

@router.get("/events/stream")
async def events_stream(request: Request):
    """SSE 实时事件流。

    存储决定安全事件是否存在，这里只负责提醒和断线补查。
    先订阅并开始缓冲实时事件，再按 SecurityEvent.id 从数据库补查，
    最后按事件 ID 丢掉补查与实时重叠的部分。
    界面状态不写 SSE id 行，避免污染浏览器的 Last-Event-ID。
    """
    sub = event_bus.subscribe()
    if sub is None:
        # 订阅槽满员：拒绝而非踢出老订阅者（踢出会造成客户端无法感知的僵尸流）
        return JSONResponse(
            status_code=503,
            headers={"Retry-After": "3"},
            content={
                "detail": "event stream subscriber slots full, retry later",
                "subscribers": event_bus.subscriber_count,
                "max": event_bus.max_subscribers,
            },
        )
    # 浏览器自动重连会带 Last-Event-ID；手动重建用同名查询参数。两者都是业务游标时取较大值。
    resume_from, cursor_note = resolve_resume_cursor(
        request.headers.get("last-event-id"),
        request.query_params.get("last_event_id"),
    )
    refresh_ids = parse_refresh_ids(request.query_params.get("refresh_ids"))

    async def generator():
        sent: set[str] = set()
        high_water = resume_from
        try:
            try:
                # 订阅已经建立。此后入库并 publish 的事件会留在 sub 里，补查不会把它漏掉。
                missed, meta = await load_sse_replay(resume_from, refresh_ids)
            except Exception as exc:
                logger.warning("SSE replay from security_events failed: %s", exc)
                missed, meta = [], {
                    "complete": False,
                    "cursor_reset": False,
                    "max_event_id": None,
                    "next_after_id": None,
                    "db_error": True,
                }
            if cursor_note == "ignored":
                meta["complete"] = False
            try:
                from core_metrics import inc_eventbus_catchup
                inc_eventbus_catchup(len(missed))
            except Exception:
                pass
            yield {"event": "connected", "data": json.dumps({
                "subscribers": event_bus.subscriber_count,
                "server_time": time.time(),
                "epoch": BOOT_TS,
                "cursor_kind": "event_id",
                "resumed": resume_from > 0,
                "resume_from": resume_from,
                "replayed": len(missed),
                "complete": bool(meta.get("complete")),
                "cursor_reset": bool(meta.get("cursor_reset")),
                "cursor_ignored": cursor_note == "ignored",
                "max_event_id": meta.get("max_event_id"),
                "next_after_id": meta.get("next_after_id"),
                "db_error": bool(meta.get("db_error")),
            })}
            for item in missed:
                dedup = item.get("dedup")
                if dedup:
                    sent.add(dedup)
                sse_id = item.get("id")
                if sse_id is not None and str(sse_id).isdigit():
                    high_water = max(high_water, int(sse_id))
                frame = {"event": item["event"], "data": item["data"]}
                if sse_id is not None:
                    frame["id"] = str(sse_id)
                yield frame
            while True:
                try:
                    evt = await asyncio.wait_for(sub.get(), timeout=15)
                    if should_skip_live(evt, resume_from, sent):
                        continue
                    evt = await hydrate_notice(evt)
                    sent.add(dedup_key(evt))
                    frame, high_water = render_sse(evt, high_water)
                    yield frame
                except asyncio.TimeoutError:
                    # ping 不写 id 行。缺口在载荷里，客户端据此重连续传，而不是比较内存 seq。
                    yield {
                        "event": "ping",
                        "data": json.dumps({
                            "ts": time.time(),
                            "epoch": BOOT_TS,
                            "cursor_kind": "event_id",
                            "missed_critical": sub.missed_critical,
                            "critical_lost": sub.critical_lost,
                            "refresh_ids": list(sub.gap_ids),
                        }),
                    }
        finally:
            event_bus.unsubscribe(sub)

    return EventSourceResponse(generator())

@router.get("/events/recent")
async def events_recent(
    limit: int = Query(50, ge=1, le=200),
    since_seq: int = Query(0, ge=0),
):
    """内存诊断窗口（进程内 seq）。安全事件补查使用 /logs/events?after_id=。"""
    return event_bus.recent(limit, since_seq=since_seq)


# ── 对话端点 ──

@router.post("/chat")
async def chat(req: ChatRequest, session: AsyncSession = Depends(get_session)):
    session_id = str(uuid.uuid4())

    await sliding_window.add_message(session_id, "user", "user", req.query)
    session_obj = Conversation(
        session_id=session_id, agent_id="user", role="user", content=req.query
    )
    session.add(session_obj)
    await session.commit()

    agent_ctx = {}
    analysis = await agent_a.process(session, req.query, session_id, agent_ctx)
    agent_ctx["analysis"] = analysis.get("result", "")
    decision = await agent_b.process(session, req.query, session_id, agent_ctx)
    agent_ctx["decision"] = decision.get("result", "")
    report = await agent_c.process(session, req.query, session_id, agent_ctx)

    return {
        "session_id": session_id,
        "pipeline": [analysis, decision, report],
    }

@router.post("/chat/stream")
async def chat_stream(req: ChatRequest, session: AsyncSession = Depends(get_session)):
    session_id = req.session_id or str(uuid.uuid4())

    await sliding_window.add_message(session_id, "user", "user", req.query)
    session_obj = Conversation(
        session_id=session_id, agent_id="user", role="user", content=req.query
    )
    session.add(session_obj)
    await session.commit()

    async def event_generator():
        agent_ctx = {}
        yield {"event": "session", "data": json.dumps({"session_id": session_id})}

        yield {"event": "agent_start", "data": json.dumps({"agent": "分析 Agent", "step": "analysis"})}
        analysis = await agent_a.process(session, req.query, session_id, agent_ctx)
        agent_ctx["analysis"] = analysis.get("result", "")
        yield {"event": "agent_done", "data": json.dumps({"agent": "分析 Agent", "result": analysis["result"]})}
        session.add(Conversation(session_id=session_id, agent_id="agent_a", role="assistant", content=analysis["result"]))

        yield {"event": "agent_start", "data": json.dumps({"agent": "决策 Agent", "step": "decision"})}
        decision = await agent_b.process(session, req.query, session_id, agent_ctx)
        agent_ctx["decision"] = decision.get("result", "")
        yield {"event": "agent_done", "data": json.dumps({"agent": "决策 Agent", "result": decision["result"]})}
        session.add(Conversation(session_id=session_id, agent_id="agent_b", role="assistant", content=decision["result"]))

        yield {"event": "agent_start", "data": json.dumps({"agent": "报告 Agent", "step": "report"})}
        report = await agent_c.process(session, req.query, session_id, agent_ctx)
        yield {"event": "agent_done", "data": json.dumps({"agent": "报告 Agent", "result": report["result"]})}
        session.add(Conversation(session_id=session_id, agent_id="agent_c", role="assistant", content=report["result"]))

        await session.commit()

        yield {"event": "done", "data": json.dumps({
            "pipeline": [analysis, decision, report],
        })}

    return EventSourceResponse(event_generator())


# ── 记忆树端点 ──

@router.get("/tree/stats")
async def tree_stats(
    session_id: str = Query(..., description="会话ID"),
    session: AsyncSession = Depends(get_session)
):
    """记忆树统计"""
    return await memory_tree.get_tree_stats(session, session_id)

@router.get("/tree/context")
async def tree_context(
    session_id: str = Query(..., description="会话ID"),
    query: str = Query("", description="查询内容"),
    max_tokens: int = Query(1000, description="最大token数"),
    session: AsyncSession = Depends(get_session)
):
    """从记忆树重建上下文"""
    ctx = await memory_tree.reconstruct_context(session, session_id, query, max_tokens)
    return {"session_id": session_id, "context": ctx, "node_count": len(ctx)}

@router.get("/tree/nodes")
async def tree_nodes(
    session_id: str = Query(..., description="会话ID"),
    limit: int = 50,
    session: AsyncSession = Depends(get_session)
):
    """查看记忆树节点"""
    stmt = (
        select(MemoryTreeNode)
        .where(MemoryTreeNode.session_id == session_id)
        .order_by(MemoryTreeNode.created_at)
        .limit(limit)
    )
    result = await session.execute(stmt)
    nodes = result.scalars().all()
    return [
        {
            "id": n.id, "parent_id": n.parent_id,
            "depth": n.depth, "node_type": n.node_type,
            "importance": n.importance, "route": n.compression_route,
            "summary": (n.summary or n.content or "")[:100],
            "created_at": n.created_at.isoformat(),
        }
        for n in nodes
    ]

@router.get("/tree/consolidate")
async def tree_consolidate(
    session_id: str = Query(..., description="会话ID"),
    session: AsyncSession = Depends(get_session)
):
    """获取记忆树统计（改造后记忆树为纯索引结构，无需手动合并）"""
    stats = await memory_tree.get_tree_stats(session, session_id)
    return {"status": "ok", "session_id": session_id, "stats": stats}


# ── 会话/窗口/上下文端点 ──

@router.get("/chat/history/{session_id}")
async def get_chat_history(session_id: str, session: AsyncSession = Depends(get_session)):
    stmt = select(Conversation).where(Conversation.session_id == session_id).order_by(Conversation.created_at)
    result = await session.execute(stmt)
    rows = result.scalars().all()
    return [
        {
            "id": c.id, "agent_id": c.agent_id, "role": c.role,
            "content": c.content, "created_at": c.created_at.isoformat(),
        }
        for c in rows
    ]

@router.get("/window/{session_id}")
async def get_window(session_id: str):
    items = await sliding_window.get_window(session_id)
    return {"session_id": session_id, "messages": items}

@router.get("/context/stream/{session_id}")
async def get_context_stream(session_id: str):
    """查看当前上下文流状态"""
    loaded = await context_stream.load(session_id)
    if not loaded:
        return {"session_id": session_id, "active": False, "fragments": []}
    return {
        "session_id": session_id,
        "active": True,
        "stats": context_stream.stats(),
        "fragments": [
            {
                "source": f.source,
                "importance": f.importance,
                "tokens": f.tokens,
                "preview": f.content[:80],
            }
            for f in context_stream.fragments
        ],
    }

@router.get("/summary/{session_id}")
async def get_summary(session_id: str):
    s = await sliding_window.get_summary(session_id)
    return {"session_id": session_id, "summary": s or ""}


# ── 全局统计 ──

# global stats (Monitor). Real-time approximate via Redis counters + low-freq COUNT reconcile.
STATS_RECONCILE_EVERY_S = float(__import__("os").environ.get("SHARED_MEMORY_STATS_RECONCILE_EVERY_S", "8.0"))
_cache_ts = 0.0
_cache_payload = None
_reconcile_lock = None

def _get_reconcile_lock():
    global _reconcile_lock
    if _reconcile_lock is None:
        import asyncio as _a
        _reconcile_lock = _a.Lock()
    return _reconcile_lock

def _stats_payload(total, pending, done, tree_total, tree_leaves,
                   mem_count, conv_count, redis_keys):
    return {
        "memories_count": mem_count,
        "conversations_count": conv_count,
        "security_events": total,
        "security_pending": pending,
        "tree_nodes": tree_total,
        "tree_leaves": tree_leaves,
        "redis_keys": redis_keys,
        "audit_llm": {"total": total, "completed": done, "pending": pending},
        "services": {
            "pgvector": "active",
            "redis": "active",
            "llm": settings.llm_model,
            "embedding": settings.embedding_model,
        },
    }

async def _stats_reconcile(session) -> dict:
    row = (await session.execute(
        select(
            select(func.count(Memory.id)).scalar_subquery(),
            select(func.count(Conversation.id)).scalar_subquery(),
            select(func.count(SecurityEvent.id)).scalar_subquery(),
            select(func.count(SecurityEvent.id)).where(
                SecurityEvent.analyzed == False
            ).scalar_subquery(),
            select(func.count(MemoryTreeNode.id)).scalar_subquery(),
            select(func.count(MemoryTreeNode.id)).where(
                MemoryTreeNode.node_type == "leaf"
            ).scalar_subquery(),
        )
    )).one()
    mem_count, conv_count, evt_total, evt_pending, tree_total, tree_leaves = row
    done = evt_total - evt_pending
    try:
        from stats_counter import reconcile
        await reconcile(evt_total, done, evt_pending)
    except Exception:
        pass
    redis_keys = 0
    try:
        redis_keys = await sliding_window.dbsize()
    except Exception:
        pass
    return _stats_payload(evt_total, evt_pending, done, tree_total, tree_leaves,
                          mem_count, conv_count, redis_keys)

@router.get("/stats")
async def stats(session: AsyncSession = Depends(get_session)):
    global _cache_ts, _cache_payload
    now = __import__("time").monotonic()
    async with _get_reconcile_lock():
        fresh = bool(_cache_payload) and (now - _cache_ts) < STATS_RECONCILE_EVERY_S
        if not fresh:
            payload = await _stats_reconcile(session)
            _cache_ts = now
            _cache_payload = dict(payload)
            return payload
        # real-time approximate overlay on last full-reconcile payload (keeps tree/redis)
        snap = None
        try:
            from stats_counter import snapshot
            snap = await snapshot()
        except Exception:
            snap = None
        if snap is not None:
            base = dict(_cache_payload)
            base["security_events"] = snap["total"]
            base["security_pending"] = snap["pending"]
            au = dict(base.get("audit_llm") or {})
            au.update({"total": snap["total"], "completed": snap["done"],
                       "pending": snap["pending"]})
            base["audit_llm"] = au
            return base
        # Redis counters unavailable -> return last reconcile truth (no extra COUNT cost)
        return dict(_cache_payload)