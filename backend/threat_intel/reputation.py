"""
reputation.py — IP/域名信誉查询（多源聚合）

聚合多个信誉源对 IP/域名进行评分:
  - 本地 IOC 库命中
  - GeoIP 地理位置 (高风险国家/地区)
  - ASN 信誉 (已知恶意 ASN)
  - 被动 DNS 历史 (域名首次出现时间)
  - WHOIS 年龄 (新注册域名高风险)

用法:
    from threat_intel.reputation import reputation_engine
    score = await reputation_engine.score_ip("1.2.3.4")
    score = await reputation_engine.score_domain("evil.com")
"""
import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

# 高风险国家/地区 (常见攻击来源)
_HIGH_RISK_COUNTRIES = {"RU", "CN", "KP", "IR", "SY"}  # 可按需调整

# 已知恶意 ASN（示例，实际应从情报源更新）
_MALICIOUS_ASNS = set()

# ── learn_loop 信誉先验(有界 delta, 见 reputation_priors 表) ──
# 无 session 的信誉查询走模块缓存; apply 侧 upsert 后同步 set_prior_cache。
_PRIOR_CACHE: dict = {}  # {(target_type, target): delta}


def set_prior_cache(target_type: str, target: str, delta: float) -> None:
    """apply.update_reputation_prior 落地后同步模块缓存。"""
    _PRIOR_CACHE[(target_type or "ip", str(target))] = float(delta or 0.0)


async def load_priors_into_cache(session) -> None:
    """把 reputation_priors 全量载入模块缓存(orchestrator 周期结束刷新)。"""
    try:
        from sqlalchemy import select
        from models import ReputationPrior
        rows = (await session.execute(select(ReputationPrior))).scalars().all()
        _PRIOR_CACHE.clear()
        for r in rows:
            _PRIOR_CACHE[(r.target_type or "ip", r.target)] = float(r.delta or 0.0)
    except Exception as e:
        logger.warning(f"load_priors_into_cache failed: {e}")


def _record_prior_lookup_failed() -> None:
    """记录一次先验读取失败 → §9.57。指标不可用时静默忽略。"""
    try:
        from core_metrics import record_reputation_prior_lookup_failed
        record_reputation_prior_lookup_failed()
    except Exception:
        pass


async def _get_prior_delta(target_type: str, target: str, session=None) -> float:
    """读取有界先验 delta; 任何失败返回 0.0(fail-open)。"""
    try:
        if session is not None:
            from sqlalchemy import select
            from models import ReputationPrior
            row = (await session.execute(
                select(ReputationPrior).where(
                    ReputationPrior.target == target,
                    ReputationPrior.target_type == target_type,
                )
            )).scalars().first()
            if row is not None:
                return float(row.delta or 0.0)
            return 0.0
        return float(_PRIOR_CACHE.get((target_type, target), 0.0))
    except Exception as e:
        # 2026-10-20 修复（整改报告 §9.57）：原先这里是 **debug** 级日志 ——
        # 生产默认 INFO → **这次降级根本看不见**。
        # 而它不是无害的：delta 会**加到主评分上**（clip ±learn_loop_prior_clip），
        # 一次 DB 抖动就让「重复攻击者」的信誉分少掉一个先验修正，
        # 可能跨过 clean/suspicious/malicious 的档位 → 处置降级，而没人知道。
        logger.warning(
            "[Reputation] 先验 delta 读取失败(降级为 0，评分少一个先验修正): %s", e)
        _record_prior_lookup_failed()
        return 0.0


@dataclass
class ReputationScore:
    """信誉评分结果"""
    target: str = ""
    target_type: str = "ip"     # ip | domain
    score: float = 0.0          # 0-1, 越高越危险
    level: str = "clean"        # clean | suspicious | malicious
    factors: list = field(default_factory=list)
    geo: dict = field(default_factory=dict)
    ioc_hits: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "target_type": self.target_type,
            "score": round(self.score, 3),
            "level": self.level,
            "factors": self.factors,
            "geo": self.geo,
            "ioc_hits": [h.to_dict() if hasattr(h, "to_dict") else h for h in self.ioc_hits],
        }


class ReputationEngine:
    """多源信誉评分引擎"""

    async def score_ip(self, ip: str, session=None) -> ReputationScore:
        """IP 信誉评分"""
        result = ReputationScore(target=ip, target_type="ip")
        score = 0.0
        factors = []

        # 1. IOC 命中
        from threat_intel.ioc_matcher import ioc_matcher
        hits = await ioc_matcher.match(ip=ip, session=session)
        if hits:
            result.ioc_hits = hits
            max_sev = max(hits, key=lambda h: h.confidence)
            score += max_sev.confidence * 0.6
            factors.append(f"ioc_hit:{max_sev.threat_type}")

        # 2. GeoIP（需要 geoip2 库，可选）
        geo = self._lookup_geoip(ip)
        if geo:
            result.geo = geo
            if geo.get("country") in _HIGH_RISK_COUNTRIES:
                score += 0.15
                factors.append(f"high_risk_country:{geo['country']}")

        # 3. 私有 IP 不评分
        import ipaddress
        try:
            if ipaddress.ip_address(ip).is_private:
                return ReputationScore(target=ip, target_type="ip", level="internal")
        except ValueError:
            pass

        # learn_loop 有界先验(TP/FP 反馈 → delta)。
        # ⚠ 2026-10-20 更正（整改报告 §9.57）：原注释写「fail-open, 不影响主评分」——
        #   **不准确**：delta 就在下一行**加到主评分上**（clip ±learn_loop_prior_clip），
        #   所以「读取失败 → delta=0」会让评分**少掉**一个先验修正（可能跨档位）。
        #   降级现在**可见且可数**（warning + soc_reputation_prior_lookup_failed_total）。
        delta = await _get_prior_delta("ip", ip, session)
        score = min(1.0, max(0.0, min(score, 1.0) + delta))
        if delta:
            factors.append(f"learn_prior:{delta:+.3f}")

        result.score = score
        result.factors = factors
        result.level = self._classify(result.score)
        return result

    async def score_domain(self, domain: str, session=None) -> ReputationScore:
        """域名信誉评分"""
        result = ReputationScore(target=domain, target_type="domain")
        score = 0.0
        factors = []

        # 1. IOC 命中
        from threat_intel.ioc_matcher import ioc_matcher
        hits = await ioc_matcher.match(domain=domain, session=session)
        if hits:
            result.ioc_hits = hits
            max_sev = max(hits, key=lambda h: h.confidence)
            score += max_sev.confidence * 0.6
            factors.append(f"ioc_hit:{max_sev.threat_type}")

        # 2. 可疑 TLD
        suspicious_tlds = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".icu"}
        for tld in suspicious_tlds:
            if domain.endswith(tld):
                score += 0.1
                factors.append(f"suspicious_tld:{tld}")
                break

        # 3. 域名长度（DGA 检测启发式）
        name_part = domain.split(".")[0]
        if len(name_part) > 20:
            score += 0.1
            factors.append("long_domain_name")

        # 4. 数字/辅音比例（DGA 特征）
        if name_part:
            digits = sum(c.isdigit() for c in name_part)
            if digits / len(name_part) > 0.4:
                score += 0.15
                factors.append("high_digit_ratio")

        # learn_loop 有界先验(TP/FP 反馈 → delta)。⚠ 同上（§9.57）：
        #   delta **会**加到主评分上，读取失败会让评分少掉一个先验修正。
        delta = await _get_prior_delta("domain", domain, session)
        score = min(1.0, max(0.0, min(score, 1.0) + delta))
        if delta:
            factors.append(f"learn_prior:{delta:+.3f}")

        result.score = score
        result.factors = factors
        result.level = self._classify(result.score)
        return result

    _geoip_reader = None  # P2: 单例 — 修复前每个 IP 都重新打开一次 mmdb 文件
    _geoip_failed = False

    def _lookup_geoip(self, ip: str) -> Optional[dict]:
        """GeoIP 查询（可选依赖 geoip2）"""
        if self.__class__._geoip_failed:
            return None
        try:
            import geoip2.database
        except ImportError:
            # 可选依赖缺失 → 静默降级(不闩死: 测试可能注入 fake 模块)
            return None
        if self.__class__._geoip_reader is None:
            try:
                # 需要 MaxMind GeoLite2 数据库文件
                self.__class__._geoip_reader = geoip2.database.Reader(
                    "/data/geoip/GeoLite2-Country.mmdb")
            except Exception:
                self.__class__._geoip_failed = True
                return None
        try:
            response = self.__class__._geoip_reader.country(ip)
            return {
                "country": response.country.iso_code,
                "country_name": response.country.name,
                # P2: 修复前 asn 字段填的是 country.iso_code — 张冠李戴,
                # 下游按 ASN 聚合即错。Country 库不含 ASN, 如实留空。
                "asn": "",
            }
        except Exception:
            return None

    def _classify(self, score: float) -> str:
        if score >= 0.7:
            return "malicious"
        elif score >= 0.3:
            return "suspicious"
        return "clean"


# ── 全局单例 ──
reputation_engine = ReputationEngine()
