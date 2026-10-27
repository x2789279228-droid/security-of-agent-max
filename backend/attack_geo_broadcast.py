"""
攻击态势广播 — 定时把「最近事件的攻击来源地理分布」推上 event_bus。

数据流: security_events 最近 N 条 (id 倒序, PK 索引, 无需 created_at 索引)
→ src_ip 去重聚合计数 → geo_ip.resolve_point (LRU, 重复 IP 免查)
→ 攻击点列表 (含事件类型样例) → SSE attack_geo 频道。

与 ledger_broadcast 同一设计: 大屏 kiosk 无 JWT, 态势图数据走 SSE
免鉴权通道; bulk 车道按 key 合并只留最新帧, 洪峰不刷屏。
受击方 (home) 默认湖南科技大学 (湘潭), 可用 SHARED_MEMORY_HOME_LAT/
SHARED_MEMORY_HOME_LON/SHARED_MEMORY_HOME_LABEL 覆盖。
"""
import asyncio
import logging
import time
from collections import Counter

logger = logging.getLogger(__name__)


def _cfg():
    import config
    s = config.settings
    return (
        max(2.0, float(s.attack_geo_interval_s)),
        max(50, int(s.attack_geo_window)),
        int(s.attack_geo_max_points),
        float(s.home_lat),
        float(s.home_lon),
        str(s.home_label),
    )


def _home() -> dict:
    _i, _w, _m, lat, lon, label = _cfg()
    return {"lat": lat, "lon": lon, "label": label}


async def _tick() -> None:
    """取最近 window 条事件的 src_ip, 解析地理并聚合成一帧。"""
    interval, window, max_points, *_ = _cfg()
    from geo_ip import resolve_point
    from event_bus import event_bus
    from models import SecurityEvent, async_session as db_session
    from sqlalchemy import select

    async with db_session() as session:
        rows = (await session.execute(
            select(
                SecurityEvent.id, SecurityEvent.src_ip,
                SecurityEvent.event_type, SecurityEvent.severity,
            ).order_by(SecurityEvent.id.desc()).limit(window)
        )).all()

    src_counter: Counter[str] = Counter()
    src_meta: dict[str, dict] = {}
    for _id, src_ip, event_type, severity in rows:
        if not src_ip:
            continue
        src_counter[src_ip] += 1
        meta = src_meta.setdefault(src_ip, {"last_type": event_type, "max_severity": severity})
        _SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        if _SEV_ORDER.get(severity, 0) > _SEV_ORDER.get(meta["max_severity"], 0):
            meta["max_severity"] = severity
        meta["last_type"] = event_type

    resolved = 0
    points: list[dict] = []
    for src_ip, count in src_counter.most_common(max_points * 3):
        if len(points) >= max_points:
            break
        pt = resolve_point(src_ip)
        if not pt:
            continue
        resolved += 1
        meta = src_meta.get(src_ip, {})
        points.append({
            **pt,
            "ip": src_ip,
            "count": count,
            "last_type": meta.get("last_type") or "",
            "max_severity": meta.get("max_severity") or "info",
        })

    event_bus.publish("attack_geo", {
        "home": _home(),
        "points": points,
        "window": window,
        "sampled_events": len(rows),
        "distinct_ips": len(src_counter),
        "resolved_points": resolved,
        "interval_s": interval,
        "ts": time.time(),
    })


async def run_forever() -> None:
    interval, window, *_ = _cfg()
    logger.info(f"Attack geo broadcast started (interval={interval:.1f}s, window={window})")
    while True:
        try:
            await _tick()
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.debug(f"attack geo broadcast failed: {e}")
        await asyncio.sleep(interval)


def start() -> None:
    """在 lifespan 中调用: 挂一个后台态势广播任务。失败只降级(无态势推送)。"""
    asyncio.get_running_loop().create_task(run_forever())
