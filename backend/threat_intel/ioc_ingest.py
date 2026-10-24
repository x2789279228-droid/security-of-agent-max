"""IOC 落库：把 TAXII / MISP / CSV / 手工导入的 IOC 写入 `threat_iocs`。

2026-10-21：此前 `poll_feed` 只返回 list，全仓没有 `ThreatIoc(...)` 实例化，
`ioc_matcher` 永远读到空表。本模块是**唯一写入口**：

  * 拉取方（`poll_feed`）保持纯函数，不碰数据库；
  * 持久化由调用方显式调用 `store_iocs` / `poll_feed_and_store`；
  * 同一 (ioc_type, ioc_value) 做 upsert，保留 first_seen，刷新 last_seen；
  * 过期时间默认 30 天；`ioc_matcher` 加载时过滤过期项。
"""
from __future__ import annotations

import ipaddress
import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from models import ThreatIoc

logger = logging.getLogger(__name__)

_ALLOWED_TYPES = {"ip", "domain", "url", "file_hash", "email", "cidr"}
_ALLOWED_SEVERITY = {"info", "low", "medium", "high", "critical"}
_DEFAULT_TTL_DAYS = 30


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_dt(value, default: datetime | None = None):
    if not value:
        return default
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    try:
        text = str(value).replace("Z", "+00:00")
        dt = datetime.fromisoformat(text)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return default


def _normalize(entry: dict, default_source: str) -> dict | None:
    ioc_type = str(entry.get("ioc_type") or "").strip().lower()
    value = str(entry.get("ioc_value") or "").strip()
    if ioc_type not in _ALLOWED_TYPES or not value:
        return None

    if ioc_type == "ip":
        try:
            value = str(ipaddress.ip_address(value))
        except ValueError:
            return None
    elif ioc_type == "cidr":
        try:
            value = str(ipaddress.ip_network(value, strict=False))
        except ValueError:
            return None
    else:
        # 匹配器按小写查询，落库也统一小写。
        value = value.lower()

    severity = str(entry.get("severity") or "medium").strip().lower()
    if severity not in _ALLOWED_SEVERITY:
        severity = "medium"
    try:
        confidence = float(entry.get("confidence") or 0.0)
    except (TypeError, ValueError):
        confidence = 0.0
    confidence = max(0.0, min(1.0, confidence))

    now = _now()
    expires_at = _parse_dt(entry.get("expires_at"), now + timedelta(days=_DEFAULT_TTL_DAYS))
    if expires_at <= now:
        # 拉取到的已经是过期情报：不落库，避免“写进去就永远命中”。
        return None

    return {
        "ioc_type": ioc_type,
        "ioc_value": value,
        "threat_type": str(entry.get("threat_type") or "").strip(),
        "severity": severity,
        "confidence": confidence,
        "source": str(entry.get("source") or default_source or "").strip()[:100],
        "stix_id": str(entry.get("stix_id") or "").strip()[:200],
        "mitre_attack_id": str(entry.get("mitre_attack_id") or "").strip()[:50],
        "first_seen": _parse_dt(entry.get("first_seen"), now),
        "last_seen": _parse_dt(entry.get("last_seen"), now),
        "expires_at": expires_at,
        "tags": list(entry.get("tags") or [])[:50],
        "context": dict(entry.get("context") or {}),
    }


async def store_iocs(session, entries: list[dict], source: str = "") -> dict:
    """Upsert IOC 列表。调用方负责 commit。

    返回 {inserted, updated, skipped, errors, total}。
    """
    stats = {"inserted": 0, "updated": 0, "skipped": 0, "errors": 0, "total": 0}
    seen: set[tuple[str, str]] = set()
    for entry in entries or []:
        stats["total"] += 1
        if not isinstance(entry, dict):
            stats["skipped"] += 1
            continue
        try:
            norm = _normalize(entry, source)
        except Exception as e:
            # 单条坏数据（tags/context 不是预期类型等）不能拖垮整批。
            logger.error("IOC 规范化失败 (%r): %s", entry, e)
            stats["errors"] += 1
            continue
        if not norm:
            stats["skipped"] += 1
            continue
        key = (norm["ioc_type"], norm["ioc_value"])
        if key in seen:
            stats["skipped"] += 1
            continue
        seen.add(key)

        try:
            row = (await session.execute(
                select(ThreatIoc).where(
                    ThreatIoc.ioc_type == norm["ioc_type"],
                    ThreatIoc.ioc_value == norm["ioc_value"],
                ).limit(1)
            )).scalar_one_or_none()
            if row is None:
                session.add(ThreatIoc(**norm))
                stats["inserted"] += 1
            else:
                row.threat_type = norm["threat_type"] or row.threat_type
                row.severity = norm["severity"]
                row.confidence = norm["confidence"]
                row.source = norm["source"] or row.source
                row.stix_id = norm["stix_id"] or row.stix_id
                row.mitre_attack_id = norm["mitre_attack_id"] or row.mitre_attack_id
                row.last_seen = norm["last_seen"]
                row.expires_at = norm["expires_at"]
                row.is_active = True
                row.tags = norm["tags"] or row.tags
                row.context = norm["context"] or row.context
                row.updated_at = _now()
                stats["updated"] += 1
        except Exception as e:
            logger.error("IOC 落库失败 (%s=%s): %s", norm["ioc_type"], norm["ioc_value"], e)
            stats["errors"] += 1

    logger.info(
        "IOC 落库: inserted=%d updated=%d skipped=%d errors=%d total=%d",
        stats["inserted"], stats["updated"], stats["skipped"], stats["errors"], stats["total"],
    )
    return stats


async def poll_feed_and_store(session, feed_config: dict) -> dict:
    """拉取 + 落库。保持 `poll_feed` 本身无数据库依赖。"""
    from .stix_taxii import taxii_client
    entries = await taxii_client.poll_feed(feed_config)
    source = str(feed_config.get("name") or feed_config.get("feed_type") or "")
    stats = await store_iocs(session, entries, source=source)
    stats["fetched"] = len(entries)
    return stats
