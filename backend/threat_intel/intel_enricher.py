"""
intel_enricher.py — 事件情报富化

将 IOC 匹配和信誉评分结果附加到安全事件/网络流/TLS 会话上，
实现检测与情报的自动联动。

富化点:
  - SecurityEvent: src_ip / dst_ip 信誉 + IOC 命中
  - NetworkFlow: 五元组 IOC 匹配 + GeoIP
  - TlsSession: SNI 域名信誉 + JA3 情报
  - EdrEvent: 进程哈希 IOC + 外联 IP 信誉

用法(接入链统一入口):
    from threat_intel.intel_enricher import enrich_event_if_enabled
    event_dict = await enrich_event_if_enabled(event_dict)   # session 可省

富化开关: settings.intel_enrich_enabled(默认 False, 与情报拉取解耦)。
"""
import logging

from config import settings

logger = logging.getLogger(__name__)


class IntelEnricher:
    """事件情报富化器"""

    def __init__(self):
        # 富化开关与情报拉取(intel_enabled)解耦(2026-10-27): 富化只读 IOC
        # 缓存, 独立启停 —— 情报入库但不想让富化介入主链路时, 只关这个。
        # 动态读取(不缓存到 self), 测试可随时 monkeypatch。
        pass

    async def enrich_event(self, session, event: dict) -> dict:
        """富化安全事件"""
        if not settings.intel_enrich_enabled:
            return event

        from threat_intel.ioc_matcher import ioc_matcher
        from threat_intel.reputation import reputation_engine

        enrichment = {}

        # IP IOC + 信誉
        src_ip = event.get("src_ip", "")
        dst_ip = event.get("dst_ip", "")

        if src_ip:
            hits = await ioc_matcher.match(ip=src_ip, session=session)
            if hits:
                enrichment["src_ip_ioc"] = [h.to_dict() for h in hits]
            rep = await reputation_engine.score_ip(src_ip, session=session)
            enrichment["src_ip_reputation"] = rep.to_dict()

        if dst_ip:
            hits = await ioc_matcher.match(ip=dst_ip, session=session)
            if hits:
                enrichment["dst_ip_ioc"] = [h.to_dict() for h in hits]
            rep = await reputation_engine.score_ip(dst_ip, session=session)
            enrichment["dst_ip_reputation"] = rep.to_dict()

        # 域名 IOC
        domain = event.get("host", event.get("sni", ""))
        if domain:
            hits = await ioc_matcher.match(domain=domain, session=session)
            if hits:
                enrichment["domain_ioc"] = [h.to_dict() for h in hits]
            rep = await reputation_engine.score_domain(domain, session=session)
            enrichment["domain_reputation"] = rep.to_dict()

        # 哈希 IOC
        file_hash = event.get("image_hash", event.get("sample_hash", ""))
        if file_hash:
            hits = await ioc_matcher.match(file_hash=file_hash, session=session)
            if hits:
                enrichment["hash_ioc"] = [h.to_dict() for h in hits]

        # CVE/KEV: 事件携带 cve 字段(如 Sigma/SAR 解析出的漏洞利用)时,
        # 与 CISA KEV 目录精确比对 —— KEV 是"已知在野利用", 命中即提级。
        cve = str(event.get("cve") or event.get("cve_id") or "").strip()
        if cve:
            hits = await ioc_matcher.match(cve=cve, session=session)
            if hits:
                enrichment["cve_ioc"] = [h.to_dict() for h in hits]

        if enrichment:
            event.setdefault("raw_data", {})
            event["raw_data"]["threat_intel"] = enrichment

            # KEV 特权提级: 命中已知被利用漏洞 → 严重度升一档(封顶 critical)
            # 并落 kev_hit 标注(security_events.raw_data 可查 = 审计痕迹)。
            if enrichment.get("cve_ioc"):
                try:
                    from metrics import inc_intel_enrich_kev
                    inc_intel_enrich_kev()
                except Exception:
                    pass
                event["raw_data"]["threat_intel"]["kev_hit"] = True
                event["raw_data"]["threat_intel"]["kev_boost_reason"] = (
                    f"KEV hit: {cve}"
                )
                event["severity"] = _bump_severity(event.get("severity"))
                logger.info(
                    "KEV 命中提级: %s %s → %s",
                    event.get("event_type", ""), cve, event.get("severity"),
                )

            # 信誉提级(原逻辑保留): 综合信誉分够高且事件还是低档 → high
            max_score = max(
                (r.get("score", 0) for r in enrichment.values()
                 if isinstance(r, dict) and "score" in r),
                default=0,
            )
            if max_score >= 0.7 and event.get("severity") in ("info", "low"):
                event["severity"] = "high"
                logger.info(
                    "情报富化提升严重度: %s → high (score=%.2f)",
                    event.get("event_type", ""), max_score,
                )

            # H-①(2026-10-30 REMEDIATION-PLAN 路线 H): IOC 命中后的 LLM 威胁上下文
            # —— threat_intel/llm_context.py 从休眠接入生产。fail-open + 开关 +
            # 成本护栏(内部走 llm_enhancer → llm_limiter)。默认关闭。
            try:
                from config import settings as _cfg
                if getattr(_cfg, "intel_llm_context_enabled", False):
                    from threat_intel.llm_context import (
                        llm_summarize_threat_context,
                        should_trigger_llm,
                    )
                    _ioc_hits = []
                    for _k in ("src_ip_ioc", "dst_ip_ioc",
                               "domain_ioc", "hash_ioc", "cve_ioc"):
                        _ioc_hits.extend(enrichment.get(_k) or [])
                    if should_trigger_llm(_ioc_hits):
                        _ctx = await llm_summarize_threat_context(
                            event_type=str(event.get("event_type", "")
                                           or event.get("event", "")),
                            src_ip=str(src_ip or ""),
                            dst_ip=str(dst_ip or ""),
                            ioc_hits=_ioc_hits,
                            reputation_scores={
                                "src": enrichment.get("src_ip_reputation", {}),
                                "dst": enrichment.get("dst_ip_reputation", {}),
                            },
                        )
                        if _ctx:
                            event["raw_data"]["threat_intel"]["llm_context"] = _ctx
            except Exception as _e:
                logger.debug("llm_context wiring skipped: %s", _e)

        return event

    async def enrich_flow(self, session, flow: dict) -> dict:
        """富化网络流"""
        if not settings.intel_enrich_enabled:
            return flow

        from threat_intel.ioc_matcher import ioc_matcher

        hits = await ioc_matcher.match(
            ip=flow.get("dst_ip", ""),
            domain=flow.get("app_protocol", "") if flow.get("app_protocol") == "DNS" else "",
            session=session,
        )
        if hits:
            flow.setdefault("raw_data", {})
            flow["raw_data"]["ioc_hits"] = [h.to_dict() for h in hits]

        return flow


# ── 全局单例 ──
intel_enricher = IntelEnricher()


_SEVERITY_LADDER = ("info", "low", "medium", "high", "critical")


def _bump_severity(current: str) -> str:
    """严重度升一档, 封顶 critical; 未知值按 info 起步。"""
    try:
        idx = _SEVERITY_LADDER.index(str(current or "").lower())
    except ValueError:
        idx = 0
    return _SEVERITY_LADDER[min(idx + 1, len(_SEVERITY_LADDER) - 1)]


async def enrich_event_if_enabled(event: dict, *, session=None) -> dict:
    """两条接入链(Kafka enriched / HTTP ingest)的**统一富化入口**。

    契约(2026-10-27 路线 3):
      - 开关 ``settings.intel_enrich_enabled`` 默认 False —— 关闭时原样返回,
        接入主链路行为与富化上线前完全一致(全量测试零回归的保证);
      - fail-open: 任何异常或超时只计数, **永不**阻塞/丢弃原事件 ——
        富化是旁路增强, 不能成为新的丢数据点;
      - 超时 ``settings.intel_enrich_timeout_ms``(默认 800ms): matcher 走
        内存缓存本应微秒级, 超时只可能来自信誉引擎的 DB 回源 —— 掐断它。
    """
    import asyncio

    if not settings.intel_enrich_enabled:
        try:
            from metrics import inc_intel_enrich
            inc_intel_enrich("skipped")
        except Exception:
            pass
        return event

    async def _enrich_isolated():
        # W1-4: wait_for 超时会 cancel 内层协程 — 若共享调用方 session, cancel
        # 瞬间该 session 可能正处于 execute 中而被驱动标记失效, 调用方后续
        # 落库连环失败。富化强制独立短生命周期 session(缓存温时从不真正连接,
        # 仅缓存过期刷新时用一次), 与调用方数据面结构性解耦。
        from models import async_session as _as
        async with _as() as s:
            return await intel_enricher.enrich_event(s, event)

    try:
        enriched = await asyncio.wait_for(
            _enrich_isolated(),
            timeout=max(settings.intel_enrich_timeout_ms, 1) / 1000,
        )
    except asyncio.TimeoutError:
        logger.warning("情报富化超时(%dms), 放行原事件", settings.intel_enrich_timeout_ms)
        try:
            from metrics import inc_intel_enrich
            inc_intel_enrich("timeout")
        except Exception:
            pass
        return event
    except asyncio.CancelledError:
        raise
    except Exception:
        logger.warning("情报富化失败, 放行原事件", exc_info=True)
        try:
            from metrics import inc_intel_enrich
            inc_intel_enrich("failed")
        except Exception:
            pass
        return event

    hit = bool((event.get("raw_data") or {}).get("threat_intel"))
    try:
        from metrics import inc_intel_enrich
        inc_intel_enrich("enriched" if hit else "no_hit")
    except Exception:
        pass
    return enriched
