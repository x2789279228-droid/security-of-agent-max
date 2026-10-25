"""
stix_taxii.py — TAXII 2.1 客户端与 STIX Bundle 解析

支持:
  - TAXII 2.1 Server 发现与 Collection 枚举
  - 增量拉取 (since 参数)
  - STIX 2.1 Bundle 解析 → IOC 提取
  - MISP REST API 对接 (events/restSearch)
  - CSV / STIX Bundle 文件导入

用法:
    from threat_intel.stix_taxii import taxii_client
    iocs = await taxii_client.poll_feed(feed_config)
"""
import json
import logging
from typing import Optional

from config import settings

logger = logging.getLogger(__name__)

# feed 文本软上限: 免费源最大也就几百 KB, 10MB 足够容纳任何直出列表
_MAX_FEED_BYTES = 10_000_000

# STIX 2.1 IOC 类型映射
_STIX_IOC_MAP = {
    "ipv4-addr": "ip",
    "ipv6-addr": "ip",
    "domain-name": "domain",
    "url": "url",
    "file": "file_hash",
    "email-addr": "email",
}


class TaxiiClient:
    """TAXII 2.1 / MISP 情报拉取客户端"""

    def __init__(self):
        self.misp_url = settings.misp_url
        self.misp_api_key = settings.misp_api_key
        self.misp_verify_ssl = settings.misp_verify_ssl
        self.taxii_url = settings.taxii_url
        self.taxii_user = settings.taxii_user
        self.taxii_password = settings.taxii_password

    async def poll_feed(self, feed_config: dict) -> list[dict]:
        """
        根据 feed 配置拉取 IOC

        feed_config: {feed_type, url, api_key, collection, ...}
        返回: [{ioc_type, ioc_value, threat_type, severity, source, ...}]
        """
        feed_type = feed_config.get("feed_type", "taxii")

        if feed_type == "taxii":
            iocs = await self._poll_taxii(feed_config)
        elif feed_type == "misp":
            iocs = await self._poll_misp(feed_config)
        elif feed_type == "csv":
            iocs = await self._import_csv(feed_config)
        elif feed_type == "csv_http":
            iocs = await self._import_csv_http(feed_config)
        elif feed_type == "stix_bundle":
            iocs = await self._import_stix_bundle(feed_config)
        else:
            logger.warning("不支持的情报源类型: %s", feed_type)
            return []

        # §十一.2: 本函数是四种源的**唯一**汇聚点，计数打在这里。
        # 修复前 soc_intel_ioc_total 无任何自增点，而 capabilities.py 正用它给
        # /api/capabilities/status 的 threat_intel.count 赋值 → 面板恒显示
        # 「已启用、0 条」。0 看上去像「暂无数据」，与「情报源已挂」完全同形。
        # 标签取 feed 的 name，与 IOC 自带的 source 字段同源，便于按源下钻。
        try:
            from metrics import inc_intel_ioc
            inc_intel_ioc(str(feed_config.get("name") or feed_type), n=len(iocs))
        except Exception:
            logger.debug("情报 IOC 计数失败", exc_info=True)

        return iocs

    async def _poll_taxii(self, config: dict) -> list[dict]:
        """TAXII 2.1 拉取"""
        try:
            import aiohttp
        except ImportError:
            logger.error("aiohttp 未安装")
            return []

        url = config.get("url", self.taxii_url)
        collection = config.get("collection", "")
        since = config.get("since", "")

        if not url:
            return []

        headers = {"Accept": "application/taxii+json;version=2.1"}
        auth = None
        user = config.get("user", self.taxii_user)
        pwd = config.get("password", self.taxii_password)
        if user and pwd:
            auth = aiohttp.BasicAuth(user, pwd)

        iocs = []
        try:
            async with aiohttp.ClientSession(auth=auth) as session:
                # 获取 objects
                objects_url = f"{url.rstrip('/')}/collections/{collection}/objects/"
                params = {}
                if since:
                    params["added_after"] = since

                async with session.get(
                    objects_url, headers=headers, params=params,
                    timeout=aiohttp.ClientTimeout(total=60),
                ) as resp:
                    if resp.status != 200:
                        logger.warning("TAXII 拉取失败: HTTP %d", resp.status)
                        return []
                    data = await resp.json()

                    for obj in data.get("objects", []):
                        parsed = self._parse_stix_object(obj, config.get("name", "taxii"))
                        iocs.extend(parsed)

            logger.info("TAXII 拉取: %d 条 IOC", len(iocs))
        except Exception as e:
            logger.error("TAXII 拉取异常: %s", e)

        return iocs

    async def _poll_misp(self, config: dict) -> list[dict]:
        """MISP REST API 拉取"""
        try:
            import aiohttp
        except ImportError:
            return []

        url = config.get("url", self.misp_url)
        api_key = config.get("api_key", self.misp_api_key)
        if not url or not api_key:
            return []

        headers = {
            "Authorization": api_key,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

        iocs = []
        try:
            async with aiohttp.ClientSession() as session:
                body = {
                    "returnFormat": "json",
                    "last": "1d",
                    "published": True,
                }
                # aiohttp 语义：None=使用默认证书校验；False=关闭校验。
                # 因此 verify=True 时必须传 None，verify=False 时才传 False。
                ssl_ctx = None if self.misp_verify_ssl else False

                async with session.post(
                    f"{url.rstrip('/')}/attributes/restSearch",
                    headers=headers,
                    json=body,
                    ssl=ssl_ctx,
                    timeout=aiohttp.ClientTimeout(total=120),
                ) as resp:
                    if resp.status != 200:
                        logger.warning("MISP 拉取失败: HTTP %d", resp.status)
                        return []
                    data = await resp.json()

                    for attr in data.get("response", []):
                        a = attr.get("Attribute", attr)
                        ioc = self._misp_attr_to_ioc(a, config.get("name", "misp"))
                        if ioc:
                            iocs.append(ioc)

            logger.info("MISP 拉取: %d 条 IOC", len(iocs))
        except Exception as e:
            logger.error("MISP 拉取异常: %s", e)

        return iocs

    async def _import_csv(self, config: dict) -> list[dict]:
        """CSV 文件导入 (每行一个 IOC)"""
        import csv
        from pathlib import Path

        file_path = config.get("url", "")
        if not file_path or not Path(file_path).exists():
            return []

        iocs = []
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                iocs = self._parse_csv_text(f.read(), config)
        except Exception as e:
            logger.error("CSV 导入失败: %s", e)

        return iocs

    async def _fetch_text(self, url: str, api_key: str = "") -> str:
        """拉取远程情报文本 (免费 feed 直接给匿名 CSV / 纯文本)。

        独立成方法供测试 monkeypatch —— 解析逻辑与传输解耦。
        """
        import httpx

        headers = {
            "User-Agent": "SOC-Platform/1.0 (threat-intel feed poller)",
        }
        if api_key:
            headers["Authorization"] = f"Token {api_key}"
        async with httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
            resp = await client.get(url, headers=headers)
            resp.raise_for_status()
            text = resp.text
        if len(text) > _MAX_FEED_BYTES:
            logger.warning(
                "feed 响应超大(%d chars, url=%s), 截断到 %d",
                len(text), url[:100], _MAX_FEED_BYTES,
            )
            text = text[:_MAX_FEED_BYTES]
        return text

    def _parse_csv_text(self, text: str, config: dict) -> list[dict]:
        """把 feed 文本解析为规范 IOC 列表。

        支持两种格式(config["config"] 里配 dialect):
          csv(默认): 带表头 CSV —— abuse.ch Feodo ipblocklist 等
              列映射: value_column(默认 value) / type_column / fixed_type /
                      threat_column / fixed_threat / severity
          plain: 每行一个指标 —— OpenPhish feed.txt 等
              全部取 fixed_type(默认 url)作为类型
        `#` 开头视为注释行(abuse.ch 三个头注释块)。
        """
        import csv
        import io

        cfg = config.get("config") or {}
        fmt = str(cfg.get("format", "csv")).lower()
        comment = str(cfg.get("comment_prefix", "#"))
        source = str(config.get("name", "csv_http"))
        lines = [
            ln for ln in text.splitlines()
            if ln.strip() and not ln.lstrip().startswith(comment)
        ]
        if not lines:
            return []

        value_col = str(cfg.get("value_column", "value"))
        type_col = str(cfg.get("type_column", ""))
        fixed_type = str(cfg.get("fixed_type", "ip"))
        threat_col = str(cfg.get("threat_column", ""))
        fixed_threat = str(cfg.get("fixed_threat", ""))
        severity = str(cfg.get("severity", "medium"))

        iocs: list[dict] = []
        if fmt == "plain":
            for ln in lines:
                iocs.append({
                    "ioc_type": fixed_type,
                    "ioc_value": ln.strip(),
                    "threat_type": fixed_threat,
                    "severity": severity,
                    "source": source,
                })
            return iocs

        reader = csv.DictReader(io.StringIO("\n".join(lines)))
        for row in reader:
            # 列名回退链保持与旧本地 csv 路径兼容(value|ioc_value / type|ioc_type)
            value = str(
                row.get(value_col) or row.get("value") or row.get("ioc_value") or ""
            ).strip()
            if not value:
                continue
            ioc_type = str(
                (row.get(type_col) if type_col else None)
                or row.get("type") or row.get("ioc_type") or fixed_type
            ).strip()
            threat = str(
                (row.get(threat_col) if threat_col else None)
                or row.get("threat_type") or fixed_threat
            ).strip()
            iocs.append({
                "ioc_type": ioc_type or fixed_type,
                "ioc_value": value,
                "threat_type": threat,
                "severity": severity,
                "source": source,
            })
        return iocs

    async def _import_csv_http(self, config: dict) -> list[dict]:
        """HTTP 情报源导入 (免费 feed: abuse.ch Feodo / OpenPhish / OTX 导出)。

        2026-10-25 前平台只支持本地 csv 文件与 TAXII/MISP ——
        免费源处于"客户端就绪、没有一条真实情报"状态。本方法接通:
            threat_intel_feeds(feed_type='csv_http', url=..., config={dialect})
        → scheduler 轮询 → store_iocs 落库 → ioc_matcher 命中富化。
        """
        url = str(config.get("url", "")).strip()
        if not url.lower().startswith(("http://", "https://")):
            logger.warning("csv_http 源 url 非法: %s", url[:100])
            return []
        try:
            text = await self._fetch_text(url, api_key=str(config.get("api_key", "")))
        except Exception as e:
            logger.warning("feed 拉取失败 url=%s: %s", url[:100], e)
            return []
        return self._parse_csv_text(text, config)

    async def _import_stix_bundle(self, config: dict) -> list[dict]:
        """STIX Bundle JSON 文件导入"""
        from pathlib import Path

        file_path = config.get("url", "")
        if not file_path or not Path(file_path).exists():
            return []

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                bundle = json.load(f)

            iocs = []
            for obj in bundle.get("objects", []):
                parsed = self._parse_stix_object(obj, config.get("name", "stix"))
                iocs.extend(parsed)
            return iocs
        except Exception as e:
            logger.error("STIX Bundle 导入失败: %s", e)
            return []

    def _parse_stix_object(self, obj: dict, source: str) -> list[dict]:
        """解析单个 STIX 对象为 IOC"""
        iocs = []
        obj_type = obj.get("type", "")

        if obj_type == "indicator":
            # STIX Indicator — 从 pattern 中提取
            pattern = obj.get("pattern", "")
            labels = obj.get("labels", [])
            severity = "high" if "malicious-activity" in labels else "medium"

            # 简单 pattern 解析: [ipv4-addr:value = '1.2.3.4']
            import re
            for match in re.finditer(r"(\w[\w-]*):value\s*=\s*'([^']+)'", pattern):
                stix_type, value = match.groups()
                ioc_type = _STIX_IOC_MAP.get(stix_type, stix_type)
                iocs.append({
                    "ioc_type": ioc_type,
                    "ioc_value": value,
                    "threat_type": labels[0] if labels else "",
                    "severity": severity,
                    "confidence": obj.get("confidence", 50) / 100,
                    "source": source,
                    "stix_id": obj.get("id", ""),
                    "mitre_attack_id": "",
                })

        elif obj_type in _STIX_IOC_MAP:
            # 直接可观察对象
            ioc_type = _STIX_IOC_MAP[obj_type]
            value = obj.get("value", "")
            if obj_type == "file":
                hashes = obj.get("hashes", {})
                value = hashes.get("SHA-256", hashes.get("MD5", ""))
            if value:
                iocs.append({
                    "ioc_type": ioc_type,
                    "ioc_value": value,
                    "threat_type": "",
                    "severity": "medium",
                    "source": source,
                    "stix_id": obj.get("id", ""),
                })

        return iocs

    def _misp_attr_to_ioc(self, attr: dict, source: str) -> Optional[dict]:
        """MISP Attribute → IOC"""
        attr_type = attr.get("type", "")
        value = attr.get("value", "")
        if not value:
            return None

        type_map = {
            "ip-dst": "ip", "ip-src": "ip",
            "domain": "domain", "hostname": "domain",
            "url": "url", "link": "url",
            "md5": "file_hash", "sha1": "file_hash", "sha256": "file_hash",
            "email-src": "email", "email-dst": "email",
        }

        ioc_type = type_map.get(attr_type)
        if not ioc_type:
            return None

        return {
            "ioc_type": ioc_type,
            "ioc_value": value,
            "threat_type": attr.get("category", ""),
            "severity": "high" if attr.get("to_ids") else "medium",
            "confidence": 0.8,
            "source": source,
            "stix_id": "",
        }


# ── 全局单例 ──
taxii_client = TaxiiClient()
