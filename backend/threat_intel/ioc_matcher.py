"""
ioc_matcher.py — IOC 实时匹配引擎

将安全事件中的 IP/域名/哈希/URL 与 threat_iocs 表进行实时匹配。
使用内存缓存 + Redis 加速，避免每次查询都命中 PostgreSQL。

匹配策略:
  - 精确匹配: IP / 哈希 / 域名
  - CIDR 匹配: IP 属于已知恶意网段
  - 域名通配: *.evil.com 匹配 sub.evil.com

用法:
    from threat_intel.ioc_matcher import ioc_matcher
    hits = await ioc_matcher.match(ip="1.2.3.4", domain="evil.com")
"""
import asyncio
import ipaddress
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

from config import settings

logger = logging.getLogger(__name__)


@dataclass
class IocHit:
    """IOC 命中结果"""
    ioc_type: str
    ioc_value: str
    threat_type: str = ""
    severity: str = "medium"
    confidence: float = 0.0
    source: str = ""
    context: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "ioc_type": self.ioc_type,
            "ioc_value": self.ioc_value,
            "threat_type": self.threat_type,
            "severity": self.severity,
            "confidence": self.confidence,
            "source": self.source,
            "context": self.context,
        }


class IocMatcher:
    """IOC 匹配引擎（内存缓存 + DB 回源）"""

    def __init__(self):
        self.threshold = settings.ioc_match_threshold
        # 内存缓存: {ioc_value: IocHit}
        self._cache: dict[str, IocHit] = {}
        self._cidr_cache: list[tuple[ipaddress.IPv4Network, IocHit]] = []
        self._domain_suffix: dict[str, IocHit] = {}  # .evil.com → hit
        self._last_refresh = 0.0
        self._refresh_lock = asyncio.Lock()
        self._refresh_interval = 300  # 5 分钟刷新

    async def refresh_cache(self, session=None):
        """从 PostgreSQL 刷新 IOC 缓存"""
        try:
            if session is None:
                from models import async_session
                async with async_session() as s:
                    await self._load_from_db(s)
            else:
                await self._load_from_db(session)
            self._last_refresh = time.time()
            logger.info(
                "IOC 缓存刷新: %d 精确 + %d CIDR + %d 域名后缀",
                len(self._cache), len(self._cidr_cache), len(self._domain_suffix),
            )
        except Exception as e:
            logger.error("IOC 缓存刷新失败: %s", e)

    async def _load_from_db(self, session):
        """从 threat_iocs 表加载活跃 IOC"""
        from sqlalchemy import select, or_
        from models import ThreatIoc

        # 过期 IOC 不得继续参与匹配；NULL 视为长期有效。
        now = datetime.now(timezone.utc)
        # W1-4(复审 P2): 上限防护 — MISP/TAXII 大体量源(数万~数十万指标)
        # 全量物化会把内存与 5 分钟一次的全表 SELECT 双重放大。
        _IOC_CACHE_LIMIT = 50_000
        result = await session.execute(
            select(ThreatIoc).where(
                ThreatIoc.is_active == True,
                or_(ThreatIoc.expires_at.is_(None), ThreatIoc.expires_at > now),
                # R12(复审 P1-6): 演示种子 IOC 永不参与真实事件富化 ——
                # 修复前 demo-seed 的 is_active=True 行直接进匹配缓存, 真实
                # 事件命中 23.129.64.33 等演示 IP 会产生假 critical 富化。
                # 展示层(/api/intel/iocs 列表)不受影响, 此处只隔离检测层。
                ThreatIoc.source != "demo-seed",
            ).order_by(ThreatIoc.last_seen.desc().nullslast()).limit(_IOC_CACHE_LIMIT)
        )
        iocs = result.scalars().all()
        if len(iocs) >= _IOC_CACHE_LIMIT:
            logger.warning(
                "IOC 缓存加载达上限 %d 条(按 last_seen 截断) — 请检查情报源体量"
                "或分源接入", _IOC_CACHE_LIMIT,
            )

        cache = {}
        cidr_cache = []
        domain_suffix = {}

        for ioc in iocs:
            hit = IocHit(
                ioc_type=ioc.ioc_type,
                ioc_value=ioc.ioc_value,
                threat_type=ioc.threat_type,
                severity=ioc.severity,
                confidence=ioc.confidence,
                source=ioc.source,
                context=ioc.context or {},
            )

            if ioc.ioc_type == "cidr":
                try:
                    net = ipaddress.ip_network(ioc.ioc_value, strict=False)
                    cidr_cache.append((net, hit))
                except ValueError:
                    pass
            elif ioc.ioc_type == "domain" and ioc.ioc_value.startswith("*."):
                domain_suffix[ioc.ioc_value[1:]] = hit  # .evil.com
            else:
                cache[ioc.ioc_value.lower()] = hit

        self._cache = cache
        self._cidr_cache = cidr_cache
        self._domain_suffix = domain_suffix

    async def match(
        self,
        ip: str = "",
        domain: str = "",
        file_hash: str = "",
        url: str = "",
        cve: str = "",
        ja3: str = "",
        session=None,
    ) -> list[IocHit]:
        """
        多字段 IOC 匹配

        返回所有命中的 IOC（可能多条）
        """
        # 自动刷新缓存
        if time.time() - self._last_refresh > self._refresh_interval:
            # R20(复审 P2): 缓存过期后每个并发请求都会各自触发全表加载(惊群)。
            # _last_refresh 在加载完成后才更新, 高并发窗口内重复劳动 + DB 压力。
            # asyncio.Lock 串行化: 第一个请求刷完, 其余直接用新缓存。
            async with self._refresh_lock:
                if time.time() - self._last_refresh > self._refresh_interval:
                    await self.refresh_cache(session)

        hits = []

        # IP 精确匹配
        if ip:
            hit = self._cache.get(ip.lower())
            if hit:
                hits.append(hit)
            else:
                # CIDR 匹配
                try:
                    addr = ipaddress.ip_address(ip)
                    for net, cidr_hit in self._cidr_cache:
                        if addr in net:
                            hits.append(cidr_hit)
                            break
                except ValueError:
                    pass

        # 域名匹配
        if domain:
            domain_lower = domain.lower()
            hit = self._cache.get(domain_lower)
            if hit:
                hits.append(hit)
            else:
                # 后缀匹配 (*.evil.com)
                for suffix, s_hit in self._domain_suffix.items():
                    if domain_lower.endswith(suffix):
                        hits.append(s_hit)
                        break

        # 哈希匹配
        if file_hash:
            hit = self._cache.get(file_hash.lower())
            if hit:
                hits.append(hit)

        # URL 匹配
        if url:
            hit = self._cache.get(url.lower())
            if hit:
                hits.append(hit)

        # CVE 精确匹配(CISA KEV): 值统一小写落库(大小写不敏感)
        if cve:
            hit = self._cache.get(cve.strip().lower())
            if hit:
                hits.append(hit)

        # JA3 指纹精确匹配(abuse.ch SSL Blacklist 等): 32 位小写 MD5 hex
        if ja3:
            hit = self._cache.get(ja3.strip().lower())
            if hit:
                hits.append(hit)

        if hits:
            try:
                from metrics import inc_ioc_match
                inc_ioc_match()
            except Exception:
                pass
        return hits

    @property
    def cache_size(self) -> int:
        return len(self._cache) + len(self._cidr_cache) + len(self._domain_suffix)


# ── 全局单例 ──
ioc_matcher = IocMatcher()
