"""Audit verdict cache — reuse conclusions for the same signature.

Key: event_type | src_ip | dst_ip | sigma_rule_ids | severity | message_hash
2026-10-23 修复：旧 key（type|src_ip|rules|severity）缺 dst_ip 与 message，
同源不同目标的事件会互相串用审计结论（甚至结论里带着别的事件的证据）。
现在 dst_ip 与 message 哈希都参与 key；命中率下降是正确性的必要代价。
TTL: settings.audit_cache_ttl_s (default 600). Memory LRU + optional Redis.
"""
from __future__ import annotations

import hashlib
import json
import logging
import time
from collections import OrderedDict
from typing import Optional

logger = logging.getLogger(__name__)

_MEM: "OrderedDict[str, tuple[float, dict]]" = OrderedDict()
_MEM_MAX = 4096
_REDIS = None
_PREFIX = "soc:audit:cache:"


def set_redis(client) -> None:
    global _REDIS
    _REDIS = client


def cache_key(log_data: dict) -> str:
    sigma = log_data.get("_sigma") or {}
    rules = sigma.get("hits") or sigma.get("rule_ids") or []
    if isinstance(rules, list):
        rule_ids = ",".join(sorted(str(h.get("rule_id") or h) if isinstance(h, dict) else str(h) for h in rules))
    else:
        rule_ids = str(rules)
    et = str(log_data.get("threat_type") or log_data.get("event") or log_data.get("type") or "").upper()
    src = str(log_data.get("src_ip") or "")
    dst = str(log_data.get("dst_ip") or "")
    sev = str(log_data.get("severity") or "info").lower()
    msg = str(log_data.get("message") or log_data.get("msg") or "")
    msg_hash = hashlib.sha256(msg.encode("utf-8", "replace")).hexdigest()[:16]
    raw = f"{et}|{src}|{dst}|{rule_ids}|{sev}|{msg_hash}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def _ttl() -> int:
    try:
        from config import settings
        return max(30, int(getattr(settings, "audit_cache_ttl_s", 600) or 600))
    except Exception:
        return 600


async def get(log_data: dict) -> Optional[dict]:
    key = cache_key(log_data)
    now = time.time()
    hit = _MEM.get(key)
    expired = False
    if hit and hit[0] > now:
        _MEM.move_to_end(key)
        _cache_metric("hit")
        return dict(hit[1])
    if hit:
        _MEM.pop(key, None)
        _cache_metric("expired")
        expired = True
    if _REDIS is None:
        if not expired:
            _cache_metric("miss")
        return None
    try:
        raw = _REDIS.get(_PREFIX + key)
        if hasattr(raw, "__await__"):
            raw = await raw
        if raw is None:
            if not expired:
                _cache_metric("miss")
            return None
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8")
        payload = json.loads(raw)
        if isinstance(payload, dict):
            _MEM[key] = (now + _ttl(), payload)
            _cache_metric("hit")
            return dict(payload)
    except Exception as e:
        logger.debug("audit_cache get failed: %s", e)
        try:
            from core_metrics import record_cache_invalidate_failure
            record_cache_invalidate_failure("audit_cache")
        except Exception:
            pass
    if not expired:
        _cache_metric("miss")
    return None


async def put(log_data: dict, verdict: dict) -> None:
    if not isinstance(verdict, dict):
        return
    key = cache_key(log_data)
    ttl = _ttl()
    exp = time.time() + ttl
    slim = {
        "threat_detected": bool(verdict.get("threat_detected")),
        "confidence": float(verdict.get("confidence") or 0),
        "severity": verdict.get("severity") or log_data.get("severity") or "info",
        "verdict": verdict.get("verdict") or verdict.get("status") or "",
        "lane": "cache",
    }
    _MEM[key] = (exp, slim)
    _MEM.move_to_end(key)
    while len(_MEM) > _MEM_MAX:
        _MEM.popitem(last=False)
    if _REDIS is None:
        return
    try:
        res = _REDIS.set(_PREFIX + key, json.dumps(slim, ensure_ascii=False), ex=ttl)
        if hasattr(res, "__await__"):
            await res
    except Exception as e:
        logger.debug("audit_cache put failed: %s", e)


def _cache_metric(result: str) -> None:
    try:
        from core_metrics import record_cache
        record_cache("audit_cache", result)
    except Exception:
        pass


def inc_hit_metric() -> None:
    try:
        from metrics import inc_audit_cache_hit
        inc_audit_cache_hit()
    except Exception:
        pass
