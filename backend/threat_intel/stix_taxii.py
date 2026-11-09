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
import os
from typing import Optional

from config import settings

logger = logging.getLogger(__name__)

# feed 文本软上限: 免费源最大也就几百 KB, 10MB 足够容纳任何直出列表
_MAX_FEED_BYTES = 10_000_000

# 支持的 feed_type 全集 — 与 poll_feed 的分支一一对应，是唯一真相源；
# API 注册白名单(routers/edr_intel.py)从这里引用，防止解析侧与注册侧漂移。
ALLOWED_FEED_TYPES = ("taxii", "misp", "misp_feed", "csv", "csv_http", "kev_json", "json_api", "stix_bundle")

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
        elif feed_type == "kev_json":
            iocs = await self._import_kev_json(feed_config)
        elif feed_type == "json_api":
            iocs = await self._import_json_api(feed_config)
        elif feed_type == "misp_feed":
            iocs = await self._import_misp_feed(feed_config)
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
        # R14: TAXII 目标同样过 SSRF 校验(禁内网/云元数据)
        from net_guard import UrlRejected, validate_submittable_url
        try:
            validate_submittable_url(url)
        except UrlRejected as e:
            logger.warning("TAXII url 被拒: %s (%s)", str(url)[:100], e)
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
        # R14: MISP 目标同样过 SSRF 校验
        from net_guard import UrlRejected, validate_submittable_url
        try:
            validate_submittable_url(url)
        except UrlRejected as e:
            logger.warning("MISP url 被拒: %s (%s)", str(url)[:100], e)
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
        """CSV 本地文件导入 (每行一个 IOC)

        R14(复审 P1-2): 本地路径必须落在 settings.intel_local_feed_dir 白名单
        目录内(resolve 后前缀校验) —— 修复前 url 可为 `../../.env`、`/etc/passwd`
        等任意路径, 文件内容落库为 IOC 后可经 /api/intel/iocs 回显(任意文件读)。
        """
        from pathlib import Path

        from config import settings

        file_path = str(config.get("url", "")).strip()
        allow_dir = str(getattr(settings, "intel_local_feed_dir", "") or "").strip()
        if not allow_dir:
            logger.warning("本地 csv 导入被拒: 未配置 intel_local_feed_dir 白名单目录 "
                           "(如需本地导入请在 .env 配置, 或改用 csv_http)")
            return []
        try:
            p = Path(file_path).resolve()
            root = Path(allow_dir).resolve()
            if not str(p).startswith(str(root) + os.sep) and p != root:
                logger.warning("本地 csv 导入被拒: %s 不在白名单目录 %s 内", file_path[:120], allow_dir)
                return []
        except (OSError, ValueError) as e:
            logger.warning("本地 csv 路径解析失败: %s (%s)", file_path[:120], e)
            return []
        if not p.is_file():
            return []

        iocs = []
        try:
            with open(p, "r", encoding="utf-8") as f:
                iocs = self._parse_csv_text(f.read(), config)
        except Exception as e:
            logger.error("CSV 导入失败: %s", e)

        return iocs

    async def _fetch_text(self, url: str, api_key: str = "",
                          extra_headers: dict | None = None) -> str:
        """拉取远程情报文本 (免费 feed 直接给匿名 CSV / 纯文本)。

        R14(复审 P1-2) 出网安全语义:
          - 首跳与每个重定向跳都过 net_guard.validate_submittable_url
            (禁 loopback/私网/云元数据, 域名解析后复检);
          - follow_redirects=False + 手动逐跳: 跨 host 跳转剥离 Authorization
            (修复凭证随 30x 发给任意第三方), 最多 5 跳;
          - 流式读取, 累计超 _MAX_FEED_BYTES 即中止(修复"先整包入内存再限长")。
        独立成方法供测试 monkeypatch —— 解析逻辑与传输解耦。

        extra_headers (2026-10-30 D 第二批): 源特定 header（如 OTX 的
        `X-OTX-API-KEY`）；跨 host 重定向时与 Authorization 一起剥离。
        """
        import httpx

        from net_guard import UrlRejected, validate_submittable_url

        current = url
        headers_base = {
            "User-Agent": "SOC-Platform/1.0 (threat-intel feed poller)",
        }
        headers_base.update({str(k): str(v) for k, v in (extra_headers or {}).items()})
        # 域名形式的 feed host 本跳也先解析复检一次
        try:
            current = validate_submittable_url(current)
        except UrlRejected as e:
            raise ValueError(f"feed url rejected: {e}") from e

        async with httpx.AsyncClient(timeout=30, follow_redirects=False) as client:
            for _hop in range(5):
                headers = dict(headers_base)
                if api_key:
                    headers["Authorization"] = f"Token {api_key}"
                resp = await client.get(current, headers=headers)
                if resp.is_redirect:
                    loc = resp.headers.get("location", "")
                    if not loc:
                        break
                    import httpx as _hx
                    next_url = str(_hx.URL(current).join(loc))
                    try:
                        validate_submittable_url(next_url)
                    except UrlRejected as e:
                        raise ValueError(f"redirect target rejected: {e}") from e
                    # 跨 host 跳转不带凭证（含源特定 header —— 与 Authorization 同规）
                    if _hx.URL(next_url).host != _hx.URL(current).host:
                        api_key = ""
                        headers_base = {
                            "User-Agent": "SOC-Platform/1.0 (threat-intel feed poller)",
                        }
                    current = next_url
                    continue
                resp.raise_for_status()
                buf = bytearray()
                async for chunk in resp.aiter_bytes(64 * 1024):
                    buf.extend(chunk)
                    if len(buf) > _MAX_FEED_BYTES:
                        logger.warning(
                            "feed 响应超限(> %d bytes, url=%s), 提前中止",
                            _MAX_FEED_BYTES, url[:100],
                        )
                        break
                return bytes(buf).decode("utf-8", errors="replace")
        raise ValueError(f"feed 重定向跳数超限(>5): {url[:100]}")

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
            # 行内取首字段的分隔符（Spamhaus DROP: "1.2.4.0/22 ; SBL233779"）
            split_delim = str(cfg.get("split_delimiter", "")).strip()
            for ln in lines:
                value = ln.strip()
                if split_delim:
                    value = value.split(split_delim)[0].strip()
                if not value:
                    continue
                iocs.append({
                    "ioc_type": fixed_type,
                    "ioc_value": value,
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
        # R14: 仅 scheme 前缀检查 → 完整 SSRF 校验(禁私网/元数据/DNS 解析复检)
        from net_guard import UrlRejected, validate_submittable_url
        try:
            validate_submittable_url(url)
        except UrlRejected as e:
            logger.warning("csv_http 源 url 非法: %s (%s)", url[:100], e)
            return []
        try:
            text = await self._fetch_text(url, api_key=str(config.get("api_key", "")))
        except Exception as e:
            logger.warning("feed 拉取失败 url=%s: %s", url[:100], e)
            return []
        return self._parse_csv_text(text, config)

    # ── json_api 通用 JSON 情报源（REMEDIATION-PLAN-2026-10-30 路线 D）──
    #
    # 覆盖无标准格式的免费源（abuse.ch ThreatFox / MalwareBazaar、
    # ransomware.live 等）：dotted-path 取数 + 类型别名映射，全部配置化。
    #
    # config 示例（ThreatFox）:
    #   {"method": "POST", "body": {"query": "get_iocs", "days": 1},
    #    "items_path": "data", "value_path": "ioc", "type_path": "ioc_type",
    #    "type_map": {"ip:port": "ip", "domain": "domain", "url": "url"},
    #    "strip_port": true}
    # MalwareBazaar: {"method": "POST", "body": {"query": "get_taginfo", "tag": "..." },
    #    "items_path": "data", "value_path": "sha256_hash", "fixed_type": "file_hash"}
    _JSON_TYPE_ALIASES = {
        "ip": "ip", "ip:port": "ip", "ipv4": "ip", "ipv6": "ip",
        "domain": "domain", "hostname": "domain", "host": "domain",
        "url": "url", "uri": "url",
        "md5": "file_hash", "sha1": "file_hash", "sha256": "file_hash",
        "hash": "file_hash",
        "ja3": "ja3", "ja3_hash": "ja3", "ja3_digest": "ja3",
        "email": "email",
        "cidr": "cidr", "network": "cidr", "netmask": "cidr",
        "cve": "cve",
    }

    @staticmethod
    def _dig(obj, dotted: str):
        """按 'a.b.0.c' 点路径取值（支持列表下标）；取不到返回 None。"""
        cur = obj
        for part in str(dotted or "").split("."):
            if not part:
                continue
            if isinstance(cur, list):
                try:
                    cur = cur[int(part)]
                except (ValueError, IndexError):
                    return None
            elif isinstance(cur, dict):
                cur = cur.get(part)
            else:
                return None
            if cur is None:
                return None
        return cur

    def _parse_json_api(self, text: str, config: dict) -> list[dict]:
        cfg = config.get("config") or {}
        source = str(config.get("name", "json_api"))
        try:
            import json as _json
            payload = _json.loads(text)
        except Exception as e:
            logger.warning("json_api 响应不是合法 JSON (source=%s): %s", source, e)
            return []

        items = self._dig(payload, str(cfg.get("items_path", ""))) if cfg.get("items_path") else payload
        if not isinstance(items, list):
            logger.warning("json_api items_path 取到的不是列表 (source=%s)", source)
            return []

        value_path = str(cfg.get("value_path", "")).strip()
        if not value_path:
            logger.warning("json_api 缺 value_path (source=%s)", source)
            return []
        type_path = str(cfg.get("type_path", "")).strip()
        fixed_type = str(cfg.get("fixed_type", "")).strip().lower()
        type_map = dict(self._JSON_TYPE_ALIASES)
        type_map.update({str(k).lower(): str(v).lower()
                         for k, v in (cfg.get("type_map") or {}).items()})
        threat_path = str(cfg.get("threat_path", "")).strip()
        fixed_threat = str(cfg.get("fixed_threat", ""))
        severity = str(cfg.get("severity", "medium"))
        strip_port = bool(cfg.get("strip_port", False))

        iocs: list[dict] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            value = str(self._dig(item, value_path) or "").strip()
            if not value:
                continue
            ioc_type = ""
            if type_path:
                raw_type = str(self._dig(item, type_path) or "").strip().lower()
                ioc_type = type_map.get(raw_type, "")
            if not ioc_type:
                ioc_type = fixed_type
            if not ioc_type:
                continue
            # ThreatFox 的 "ip:port" 形态：剥端口取 host（仅当恰好一个冒号，
            # IPv6 字面量含多冒号不受影响；剥完由 ioc_ingest 归一化复验）
            if strip_port and ioc_type == "ip" and value.count(":") == 1:
                value = value.rsplit(":", 1)[0]
            threat = str(self._dig(item, threat_path) or "").strip() if threat_path else ""
            iocs.append({
                "ioc_type": ioc_type,
                "ioc_value": value,
                "threat_type": threat or fixed_threat,
                "severity": severity,
                "source": source,
            })
        return iocs

    async def _post_json_text(self, url: str, body: dict, headers: dict | None = None) -> str:
        """POST JSON 拉取（ThreatFox / MalwareBazaar 类 API）。

        与 _fetch_text 同一套出网安全语义：首跳+重定向逐跳过
        net_guard、跨 host 剥凭证、流式读取限 _MAX_FEED_BYTES。
        30x 目标降级为 GET（HTTP 语义），不复带请求体。
        """
        import httpx

        from net_guard import UrlRejected, validate_submittable_url

        try:
            current = validate_submittable_url(url)
        except UrlRejected as e:
            raise ValueError(f"feed url rejected: {e}") from e

        base_headers = {"User-Agent": "SOC-Platform/1.0 (threat-intel feed poller)"}
        base_headers.update({str(k): str(v) for k, v in (headers or {}).items()})

        async with httpx.AsyncClient(timeout=30, follow_redirects=False) as client:
            for _hop in range(5):
                resp = await client.post(current, json=dict(body or {}), headers=dict(base_headers))
                if resp.is_redirect:
                    loc = resp.headers.get("location", "")
                    if not loc:
                        break
                    next_url = str(httpx.URL(current).join(loc))
                    try:
                        validate_submittable_url(next_url)
                    except UrlRejected as e:
                        raise ValueError(f"redirect target rejected: {e}") from e
                    current = next_url
                    # 重定向目标走 GET（不复带请求体），语义与 _fetch_text 对齐
                    return await self._fetch_text(current)
                resp.raise_for_status()
                buf = bytearray()
                async for chunk in resp.aiter_bytes(64 * 1024):
                    buf.extend(chunk)
                    if len(buf) > _MAX_FEED_BYTES:
                        logger.warning(
                            "json_api 响应超限(> %d bytes, url=%s), 提前中止",
                            _MAX_FEED_BYTES, url[:100],
                        )
                        break
                return bytes(buf).decode("utf-8", errors="replace")
        raise ValueError(f"json_api 重定向跳数超限(>5): {url[:100]}")

    # MISP 属性类型 → 平台 IOC 类型(botvrij OSINT feed 实测普查)
    _MISP_TYPE_MAP = {
        "ip-src": "ip", "ip-dst": "ip", "ip-src|port": "ip", "ip-dst|port": "ip",
        "domain": "domain", "hostname": "domain", "domain|ip": "domain",
        "url": "url",
        "md5": "file_hash", "sha1": "file_hash", "sha256": "file_hash",
        "filename|md5": "file_hash", "filename|sha1": "file_hash",
        "filename|sha256": "file_hash",
        "ja3": "ja3",
    }

    async def _import_misp_feed(self, config: dict) -> list[dict]:
        """MISP feed 静态目录导入（D 第二批实拉通道，2026-10-30）。

        botvrij.eu OSINT feed 等以 **MISP feed 标准格式**（manifest.json +
        事件UUID.json）静态发布, 无需 MISP 服务器/API key —— 这是与
        feed_type=misp(REST API, 需 key)互补的免凭据真拉取通道。
        config: {"url": ".../feed-osint/", "config": {"max_events": 20}}
        """
        url = str(config.get("url", "")).strip().rstrip("/")
        cfg = config.get("config") or {}
        max_events = max(1, int(cfg.get("max_events", 20)))
        source = str(config.get("name", "misp_feed"))

        from net_guard import UrlRejected, validate_submittable_url
        try:
            validate_submittable_url(url)
        except UrlRejected as e:
            logger.warning("misp_feed 源 url 非法: %s (%s)", url[:100], e)
            return []

        try:
            manifest_raw = await self._fetch_text(f"{url}/manifest.json",
                                                  api_key=str(config.get("api_key", "")))
            manifest = json.loads(manifest_raw)
        except Exception as e:
            logger.warning("misp_feed manifest 拉取失败 url=%s: %s", url[:80], e)
            return []
        if not isinstance(manifest, dict) or not manifest:
            return []

        # manifest: uuid -> {timestamp, ...}; 取最新 max_events 个事件
        def _ts(entry):
            try:
                return int(entry.get("timestamp") or 0)
            except (TypeError, ValueError):
                return 0
        ordered = sorted(manifest.items(), key=lambda kv: _ts(kv[1]), reverse=True)

        iocs: list[dict] = []
        for uuid_, _meta in ordered[:max_events]:
            try:
                ev_raw = await self._fetch_text(f"{url}/{uuid_}.json",
                                                api_key=str(config.get("api_key", "")))
                ev = json.loads(ev_raw)
            except Exception as e:
                logger.debug("misp_feed event %s skipped: %s", uuid_, e)
                continue
            attrs = ((ev.get("Event") or {}).get("Attribute")) or []
            for a in attrs:
                ioc_type = self._MISP_TYPE_MAP.get(str(a.get("type") or ""))
                value = str(a.get("value") or "").strip()
                if not ioc_type or not value:
                    continue
                # 复合值取 IOC 部分(domain|ip → domain; ip|port 剥端口由归一化处理)
                if "|" in value and ioc_type in ("domain",):
                    value = value.split("|")[0]
                tags = []
                gal = (ev.get("Event") or {}).get("Galaxy") or []
                try:
                    tags.append(str((ev.get("Event") or {}).get("threat_actor_id") or ""))
                except Exception:
                    pass
                iocs.append({
                    "ioc_type": ioc_type,
                    "ioc_value": value,
                    "threat_type": str(a.get("category") or ""),
                    "severity": "medium",
                    "source": source,
                    "stix_id": uuid_,
                    "tags": [t for t in tags if t],
                })
        logger.info("misp_feed %s: %d events → %d IOCs", source, min(len(ordered), max_events), len(iocs))
        return iocs

    async def _import_json_api(self, config: dict) -> list[dict]:
        """通用 JSON API 情报源导入（REMEDIATION-PLAN 路线 D：免费源最大化）。"""
        url = str(config.get("url", "")).strip()
        from net_guard import UrlRejected, validate_submittable_url
        try:
            validate_submittable_url(url)
        except UrlRejected as e:
            logger.warning("json_api 源 url 非法: %s (%s)", url[:100], e)
            return []
        cfg = config.get("config") or {}
        try:
            if str(cfg.get("method", "GET")).upper() == "POST":
                text = await self._post_json_text(
                    url, dict(cfg.get("body") or {}),
                    headers=dict(cfg.get("headers") or {}),
                )
            else:
                # GET + 源特定 header（OTX 的 X-OTX-API-KEY 等，D 第二批）
                text = await self._fetch_text(
                    url, api_key=str(config.get("api_key", "")),
                    extra_headers=dict(cfg.get("headers") or {}),
                )
        except Exception as e:
            logger.warning("json_api 拉取失败 url=%s: %s", url[:100], e)
            return []
        return self._parse_json_api(text, config)

    async def _import_kev_json(self, config: dict) -> list[dict]:
        """CISA KEV(已知被利用漏洞目录)JSON 拉取与解析。

        KEV 是免费情报里信号密度最高的源: 每条都是**已被在野利用**的 CVE,
        命中即应提级(见 intel_enricher 的 KEV 特权逻辑), 而不是普通弱信号。
        结构(2026-10 官方 schema):
            {"title": ..., "catalogVersion": ..., "count": N,
             "vulnerabilities": [{"cveID": "CVE-2021-44228",
                                  "vendorProject": "Apache",
                                  "product": "Log4j2",
                                  "vulnerabilityName": "...",
                                  "dateAdded": "2021-12-10",
                                  "dueDate": "...",
                                  "knownRansomwareCampaignUse": "Known"| "Unknown",
                                  "cwes": ["CWE-502", ...], ...}]}
        """
        url = str(config.get("url", "")).strip()
        # R14: 完整 SSRF 校验(与 csv_http 同规)
        from net_guard import UrlRejected, validate_submittable_url
        try:
            validate_submittable_url(url)
        except UrlRejected as e:
            logger.warning("kev_json 源 url 非法: %s (%s)", url[:100], e)
            return []
        try:
            text = await self._fetch_text(url, api_key=str(config.get("api_key", "")))
        except Exception as e:
            logger.warning("KEV 拉取失败 url=%s: %s", url[:100], e)
            return []
        return self._parse_kev_json(text, config)

    def _parse_kev_json(self, text: str, config: dict) -> list[dict]:
        """KEV JSON → cve 类型 IOC 列表(解析与传输解耦, 供测试)。"""
        source = str(config.get("name", "cisa-kev"))
        cfg = config.get("config") or {}
        severity = str(cfg.get("severity", "critical"))
        try:
            catalog = json.loads(text)
        except json.JSONDecodeError as e:
            logger.error("KEV JSON 解析失败: %s", e)
            return []
        vulns = catalog.get("vulnerabilities")
        if not isinstance(vulns, list):
            logger.warning("KEV JSON 缺 vulnerabilities 数组, 拒绝解析")
            return []

        iocs: list[dict] = []
        for v in vulns:
            cve_id = str((v or {}).get("cveID") or "").strip()
            # 宽进严出: 形状不对的条目跳过而不是让整批失败
            if not cve_id.lower().startswith("cve-"):
                continue
            iocs.append({
                "ioc_type": "cve",
                "ioc_value": cve_id,
                "threat_type": str(v.get("vulnerabilityName") or ""),
                "severity": severity,
                "confidence": 0.95,
                "source": source,
                "context": {
                    "vendor": str(v.get("vendorProject") or ""),
                    "product": str(v.get("product") or ""),
                    "dateAdded": str(v.get("dateAdded") or ""),
                    "dueDate": str(v.get("dueDate") or ""),
                    "ransomware_use": str(v.get("knownRansomwareCampaignUse") or ""),
                },
            })
        return iocs

    async def _import_stix_bundle(self, config: dict) -> list[dict]:
        """STIX Bundle JSON 文件导入 — 本地路径受 intel_local_feed_dir 白名单约束(R14)"""
        from pathlib import Path

        from config import settings

        file_path = str(config.get("url", "")).strip()
        allow_dir = str(getattr(settings, "intel_local_feed_dir", "") or "").strip()
        if not allow_dir:
            logger.warning("本地 stix_bundle 导入被拒: 未配置 intel_local_feed_dir 白名单目录")
            return []
        try:
            p = Path(file_path).resolve()
            root = Path(allow_dir).resolve()
            if not str(p).startswith(str(root) + os.sep) and p != root:
                logger.warning("本地 stix_bundle 导入被拒: %s 不在白名单目录内", file_path[:120])
                return []
        except (OSError, ValueError) as e:
            logger.warning("stix_bundle 路径解析失败: %s (%s)", file_path[:120], e)
            return []
        if not p.is_file():
            return []

        try:
            with open(p, "r", encoding="utf-8") as f:
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
