"""EDR 融合 / 威胁情报 / 沙箱检测 — 路由模块"""

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from models import get_session
from auth import get_current_user, RequireRole, UserInfo

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["edr-intel"])


# ════════════════════════════════════════════
# EDR 融合
# ════════════════════════════════════════════

# Sysmon EventID → 事件名 (前端 event_name 展示用)
SYSMON_EVENT_NAMES = {
    1: "ProcessCreate", 2: "FileCreateTime", 3: "NetworkConnect",
    5: "ProcessTerminate", 6: "DriverLoaded", 7: "ImageLoaded",
    8: "CreateRemoteThread", 10: "ProcessAccess", 11: "FileCreate",
    12: "RegistryObjectAddDel", 13: "RegistryValueSet", 15: "FileCreateStreamHash",
    20: "WmiEventConsumer", 22: "DnsQuery", 23: "FileDelete",
}

@router.get("/edr/events")
async def edr_list_events(
    limit: int = Query(100, le=500),
    source_type: str = "",
    severity: str = "",
    computer: str = "",
    session: AsyncSession = Depends(get_session),
    user: UserInfo = Depends(get_current_user),
):
    """查询 EDR 事件"""
    from models import EdrEvent
    q = select(EdrEvent).order_by(desc(EdrEvent.created_at)).limit(limit)
    if source_type:
        q = q.where(EdrEvent.source_type == source_type)
    if severity:
        q = q.where(EdrEvent.severity == severity)
    if computer:
        q = q.where(EdrEvent.computer_name.contains(computer))
    result = await session.execute(q)
    events = result.scalars().all()
    return [
        {
            "id": e.id, "source_type": e.source_type, "event_id": e.event_id,
            "event_name": (e.event_data or {}).get("event_name")
                or (SYSMON_EVENT_NAMES.get(e.event_id, "") if e.source_type == "sysmon" else ""),
            "computer_name": e.computer_name, "user_name": e.user_name,
            "process_name": e.process_name, "parent_process": e.parent_process,
            "command_line": e.command_line, "image_hash": e.image_hash,
            "src_ip": e.src_ip, "dst_ip": e.dst_ip, "dst_port": e.dst_port,
            "severity": e.severity, "mitre_technique": e.mitre_technique,
            "security_flags": (e.event_data or {}).get("security_flags", []),
            "created_at": e.created_at.isoformat() if e.created_at else None,
        }
        for e in events
    ]


@router.post("/edr/ingest")
async def edr_ingest(
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: UserInfo = Depends(get_current_user),
):
    """接入 EDR 事件（HTTP API）"""
    body = await request.json()
    from edr_fusion.edr_adapter import edr_adapter
    parsed = await edr_adapter.ingest(body)
    if not parsed:
        raise HTTPException(400, "无法解析 EDR 事件")
    event_id = await edr_adapter.persist(session, parsed)
    await session.commit()
    return {"status": "ok", "event_id": event_id}


@router.get("/edr/stats")
async def edr_stats(user: UserInfo = Depends(get_current_user)):
    """EDR 适配器统计"""
    from edr_fusion.edr_adapter import edr_adapter
    return edr_adapter.get_stats()


# ════════════════════════════════════════════
# 威胁情报
# ════════════════════════════════════════════

@router.get("/intel/iocs")
async def intel_list_iocs(
    limit: int = Query(100, le=500),
    ioc_type: str = "",
    threat_type: str = "",
    session: AsyncSession = Depends(get_session),
    user: UserInfo = Depends(get_current_user),
):
    """查询 IOC 列表"""
    from models import ThreatIoc
    q = select(ThreatIoc).where(ThreatIoc.is_active == True).order_by(desc(ThreatIoc.created_at)).limit(limit)
    if ioc_type:
        q = q.where(ThreatIoc.ioc_type == ioc_type)
    if threat_type:
        q = q.where(ThreatIoc.threat_type == threat_type)
    result = await session.execute(q)
    iocs = result.scalars().all()
    return [
        {
            "id": i.id, "ioc_type": i.ioc_type, "ioc_value": i.ioc_value,
            "threat_type": i.threat_type, "severity": i.severity,
            "confidence": i.confidence, "source": i.source,
            "is_active": i.is_active,
            "created_at": i.created_at.isoformat() if i.created_at else None,
        }
        for i in iocs
    ]


@router.get("/intel/feeds")
async def intel_list_feeds(
    session: AsyncSession = Depends(get_session),
    user: UserInfo = Depends(get_current_user),
):
    """查询情报源配置"""
    from models import ThreatIntelFeed
    result = await session.execute(select(ThreatIntelFeed))
    feeds = result.scalars().all()
    return [
        {
            "id": f.id, "name": f.name, "feed_type": f.feed_type,
            "url": f.url, "enabled": f.enabled,
            "poll_interval_min": f.poll_interval_min,
            "last_poll_status": f.last_poll_status,
            "last_poll_count": f.last_poll_count,
            "last_poll_at": f.last_poll_at.isoformat() if f.last_poll_at else None,
        }
        for f in feeds
    ]


@router.post("/intel/match")
async def intel_match(
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: UserInfo = Depends(get_current_user),
):
    """IOC 实时匹配"""
    body = await request.json()
    from threat_intel.ioc_matcher import ioc_matcher
    hits = await ioc_matcher.match(
        ip=body.get("ip", ""),
        domain=body.get("domain", ""),
        file_hash=body.get("file_hash", ""),
        url=body.get("url", ""),
        session=session,
    )
    return {"hits": [h.to_dict() for h in hits], "count": len(hits)}


@router.post("/intel/iocs")
async def intel_upsert_iocs(
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: UserInfo = Depends(RequireRole("admin")),
):
    """手工/脚本导入 IOC（写 `threat_iocs` 的唯一生产入口之一）。"""
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, "请求体必须是 JSON")
    entries = body.get("iocs") if isinstance(body, dict) else body
    if not isinstance(entries, list):
        raise HTTPException(400, "需要 iocs 数组")
    source = str(body.get("source") or "manual") if isinstance(body, dict) else "manual"
    from threat_intel.ioc_ingest import store_iocs
    from threat_intel.ioc_matcher import ioc_matcher

    stats = await store_iocs(session, entries, source=source)
    await session.commit()
    await ioc_matcher.refresh_cache(session)
    return {"status": "ok", **stats}


@router.post("/intel/feeds")
async def intel_create_feed(
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: UserInfo = Depends(RequireRole("admin")),
):
    """创建情报源配置（TAXII / MISP / CSV / STIX Bundle）。"""
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, "请求体必须是 JSON")
    feed_type = str(body.get("feed_type") or "").strip().lower()
    if feed_type not in ("taxii", "misp", "csv", "stix_bundle"):
        raise HTTPException(400, "feed_type 必须是 taxii|misp|csv|stix_bundle")
    from models import ThreatIntelFeed

    feed = ThreatIntelFeed(
        name=str(body.get("name") or feed_type)[:200],
        feed_type=feed_type,
        url=str(body.get("url") or "")[:1000],
        api_key=str(body.get("api_key") or "")[:500],
        collection=str(body.get("collection") or "")[:200],
        poll_interval_min=max(1, int(body.get("poll_interval_min") or 60)),
        enabled=bool(body.get("enabled", True)),
        config=dict(body.get("config") or {}),
    )
    session.add(feed)
    await session.commit()
    return {"status": "ok", "id": feed.id}


@router.post("/intel/feeds/{feed_id}/poll")
async def intel_poll_feed(
    feed_id: int,
    session: AsyncSession = Depends(get_session),
    user: UserInfo = Depends(RequireRole("admin")),
):
    """拉取一个情报源并落库；成功后立即刷新 IOC 匹配缓存。"""
    from models import ThreatIntelFeed
    feed = await session.get(ThreatIntelFeed, feed_id)
    if not feed:
        raise HTTPException(404, "情报源不存在")
    cfg = {
        "feed_type": feed.feed_type,
        "url": feed.url,
        "api_key": feed.api_key,
        "collection": feed.collection,
        "name": feed.name,
    }
    try:
        from threat_intel.ioc_ingest import poll_feed_and_store
        from threat_intel.ioc_matcher import ioc_matcher
        stats = await poll_feed_and_store(session, cfg)
        feed.last_poll_at = datetime.now(timezone.utc)
        feed.last_poll_status = "success"
        feed.last_poll_count = int(stats.get("inserted", 0)) + int(stats.get("updated", 0))
        await session.commit()
        await ioc_matcher.refresh_cache(session)
        return {"status": "ok", **stats}
    except Exception as e:
        feed.last_poll_at = datetime.now(timezone.utc)
        feed.last_poll_status = "error"
        await session.commit()
        logger.error("[Intel] poll feed %s failed: %s", feed_id, e)
        raise HTTPException(502, f"情报源拉取失败: {e}")


# ════════════════════════════════════════════
# 沙箱检测
# ════════════════════════════════════════════

@router.get("/sandbox/tasks")
async def sandbox_list_tasks(
    limit: int = Query(50, le=200),
    status: str = "",
    session: AsyncSession = Depends(get_session),
    user: UserInfo = Depends(get_current_user),
):
    """查询沙箱任务"""
    from models import SandboxTask
    q = select(SandboxTask).order_by(desc(SandboxTask.created_at)).limit(limit)
    if status:
        q = q.where(SandboxTask.status == status)
    result = await session.execute(q)
    tasks = result.scalars().all()
    return [
        {
            "id": t.id, "task_id": t.task_id, "sample_name": t.sample_name,
            "sample_type": t.sample_type, "sample_hash": t.sample_hash,
            "source": t.source, "status": t.status, "verdict": t.verdict,
            "score": t.score, "behavior_summary": t.behavior_summary,
            "mitre_techniques": t.mitre_techniques or [],
            "network_iocs": t.network_iocs or [],
            "submitted_at": t.submitted_at.isoformat() if t.submitted_at else None,
            "completed_at": t.completed_at.isoformat() if t.completed_at else None,
        }
        for t in tasks
    ]


@router.get("/sandbox/status")
async def sandbox_status(user: UserInfo = Depends(get_current_user)):
    """沙箱连接器状态"""
    from zeroday_detect.sandbox_connector import sandbox
    return sandbox.get_status()


@router.post("/sandbox/submit")
async def sandbox_submit(
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: UserInfo = Depends(RequireRole("admin", "operator")),
):
    """提交样本到沙箱（URL 方式）"""
    body = await request.json()
    url = body.get("url", "")
    if not url:
        raise HTTPException(400, "需要提供 url 参数")
    from zeroday_detect.sandbox_connector import sandbox
    # 用 outcome 版本：它带着**样本指纹**（整改方案 §十.1），
    # 旧的 submit_url() 只回传 task_id，指纹就丢了。
    outcome = await sandbox.submit_url_outcome(
        url, priority=body.get("priority", 1))
    if not outcome.task_id:
        raise HTTPException(
            503,
            "沙箱不可用或未启用"
            f"（{outcome.error_code or 'no_task_id'}）",
        )
    # 记录到数据库
    from models import SandboxTask
    record = SandboxTask(
        task_id=outcome.task_id, sample_name=url, sample_type="url",
        # 样本指纹：文档 §十.1「用 SHA-256 的真实样本标识关联沙箱任务」
        # —— 修复前这一列**永远是空的**（URL 路径压根没算指纹）。
        sample_hash=outcome.sample_hash,
        source="manual", status="pending", sandbox_type=settings.sandbox_type,
    )
    session.add(record)
    await session.commit()
    return {
        "task_id": outcome.task_id,
        "status": "submitted",
        "sample_hash": outcome.sample_hash,
    }
