"""
离线 IP 地理库 — ip2region v4 (xdb, Apache-2.0, 本地文件无外呼)。

数据: backend/geo_data/ip2region.xdb (~11MB, 全量离线, 绑定为官方
binding/python 的 vendored 副本, 见 backend/ip2region/LICENSE)。

为什么选 ip2region 而不是 GeoLite2: 免许可注册、国内 IP 精度到市、
单文件即用 —— 答辩机离线环境零依赖。

返回格式 (v4, 5 段): 国家|省/区域|市|ISP|国家码
  中国|浙江省|杭州市|阿里|CN
  United States|California|0|Google LLC|US
  Reserved|Reserved|Reserved|0|0        ← 内网/保留地址

坐标表: 省会/国家近似坐标, 仅用于态势图布点 —— 是演示可视化,
不是测绘数据; 精度到省会/首都足够。
"""
import functools
import logging
import threading
from pathlib import Path

logger = logging.getLogger(__name__)

_XDB_PATH = Path(__file__).parent / "geo_data" / "ip2region.xdb"

_lock = threading.Lock()
_searcher = None  # 延迟加载 (首次查询时把 xdb 整体读入内存, ~11MB)


def _get_searcher():
    global _searcher
    if _searcher is not None:
        return _searcher
    with _lock:
        if _searcher is not None:
            return _searcher
        try:
            from ip2region import searcher, util
            buf = _XDB_PATH.read_bytes()
            _searcher = searcher.new_with_buffer(util.IPv4, buf)
            logger.info(f"ip2region loaded ({_XDB_PATH.name}, {len(buf) // 1024 // 1024}MB, buffer mode)")
        except Exception as e:
            logger.warning(f"ip2region unavailable (geo enrich 降级为无坐标): {e}")
            _searcher = False  # False = 已尝试且失败, 不再重试
    return _searcher


# ── 坐标表: 中国省级行政区(省会近似) ──
# 键为 ip2region 省名去后缀的短名, 值 (lat, lon)
CN_PROVINCE_COORDS: dict[str, tuple[float, float]] = {
    "北京": (39.9, 116.4), "天津": (39.1, 117.2), "河北": (38.0, 114.5),
    "山西": (37.9, 112.5), "内蒙古": (40.8, 111.7), "辽宁": (41.8, 123.4),
    "吉林": (43.9, 125.3), "黑龙江": (45.8, 126.5), "上海": (31.2, 121.5),
    "江苏": (32.1, 118.8), "浙江": (30.3, 120.2), "安徽": (31.8, 117.3),
    "福建": (26.1, 119.3), "江西": (28.7, 115.9), "山东": (36.7, 117.1),
    "河南": (34.8, 113.6), "湖北": (30.6, 114.3), "湖南": (28.2, 112.9),
    "广东": (23.1, 113.3), "广西": (22.8, 108.3), "海南": (20.0, 110.3),
    "重庆": (29.6, 106.5), "四川": (30.7, 104.1), "贵州": (26.6, 106.7),
    "云南": (25.0, 102.7), "西藏": (29.7, 91.1), "陕西": (34.3, 108.9),
    "甘肃": (36.1, 103.8), "青海": (36.6, 101.8), "宁夏": (38.5, 106.3),
    "新疆": (43.8, 87.6), "台湾": (25.0, 121.5), "香港": (22.3, 114.2),
    "澳门": (22.2, 113.5),
}

# ── 坐标表: 常见境外来源国(首都/中心近似) ──
COUNTRY_COORDS: dict[str, tuple[float, float]] = {
    "united states": (39.0, -97.5), "russia": (55.8, 37.6),
    "netherlands": (52.4, 4.9), "germany": (50.1, 8.7),
    "france": (48.9, 2.4), "united kingdom": (51.5, -0.1),
    "brazil": (-15.8, -47.9), "india": (28.6, 77.2),
    "vietnam": (21.0, 105.8), "south korea": (37.6, 127.0),
    "japan": (35.7, 139.7), "singapore": (1.35, 103.8),
    "canada": (45.4, -75.7), "australia": (-35.3, 149.1),
    "ukraine": (50.5, 30.5), "iran": (35.7, 51.4),
    "turkey": (39.9, 32.9), "indonesia": (-6.2, 106.8),
    "malaysia": (3.1, 101.7), "thailand": (13.8, 100.5),
    "philippines": (14.6, 121.0), "poland": (52.2, 21.0),
    "bulgaria": (42.7, 23.3), "romania": (44.4, 26.1),
    "moldova": (47.0, 28.9), "seychelles": (-4.6, 55.5),
    "panama": (9.0, -79.5), "israel": (31.8, 35.2),
    "sweden": (59.3, 18.1), "switzerland": (46.9, 7.4),
    "italy": (41.9, 12.5), "spain": (40.4, -3.7),
    "mexico": (19.4, -99.1), "argentina": (-34.6, -58.4),
    "south africa": (-25.7, 28.2), "nigeria": (9.1, 7.4),
    "kazakhstan": (51.2, 71.4), "pakistan": (33.7, 73.1),
    "bangladesh": (23.8, 90.4), "hong kong": (22.3, 114.2),
    "korea": (37.6, 127.0), "columbia": (4.7, -74.1),
    "colombia": (4.7, -74.1), "belarus": (53.9, 27.6),
    "austria": (48.2, 16.4), "belgium": (50.9, 4.4),
    "denmark": (55.7, 12.6), "finland": (60.2, 24.9),
    "norway": (59.9, 10.8), "portugal": (38.7, -9.1),
    "ireland": (53.3, -6.3), "czech": (50.1, 14.4),
    "hungary": (47.5, 19.0), "greece": (38.0, 23.7),
    "egypt": (30.0, 31.2), "uae": (24.5, 54.4),
    "united arab emirates": (24.5, 54.4), "saudi arabia": (24.7, 46.7),
    "laos": (18.0, 102.6), "cambodia": (11.6, 104.9),
    "myanmar": (16.8, 96.2), "nepal": (27.7, 85.3),
    "sri lanka": (6.9, 79.9), "mongolia": (47.9, 106.9),
    "north korea": (39.0, 125.8), "kyrgyzstan": (42.9, 74.6),
    "tajikistan": (38.6, 68.8), "uzbekistan": (41.3, 69.2),
    "afghanistan": (34.5, 69.2), "iraq": (33.3, 44.4),
    "syria": (33.5, 36.3), "jordan": (31.9, 35.9),
    "venezuela": (10.5, -66.9), "chile": (-33.5, -70.7),
    "peru": (-12.0, -77.0), "ecuador": (-0.2, -78.5),
    "bolivia": (-16.5, -68.1), "paraguay": (-25.3, -57.6),
    "uruguay": (-34.9, -56.2), "kenya": (-1.3, 36.8),
    "ethiopia": (9.0, 38.7), "ghana": (5.6, -0.2),
    "morocco": (34.0, -6.8), "algeria": (36.8, 3.1),
    "tunisia": (36.8, 10.2), "libya": (32.9, 13.2),
}

# 国家码兜底 (ip2region 给了 code, 国家名没收录时用)
_COUNTRY_CODE_COORDS: dict[str, tuple[float, float]] = {
    "US": (39.0, -97.5), "RU": (55.8, 37.6), "NL": (52.4, 4.9),
    "DE": (50.1, 8.7), "FR": (48.9, 2.4), "GB": (51.5, -0.1),
    "BR": (-15.8, -47.9), "IN": (28.6, 77.2), "VN": (21.0, 105.8),
    "KR": (37.6, 127.0), "JP": (35.7, 139.7), "SG": (1.35, 103.8),
    "CA": (45.4, -75.7), "AU": (-35.3, 149.1), "UA": (50.5, 30.5),
    "IR": (35.7, 51.4), "TR": (39.9, 32.9), "ID": (-6.2, 106.8),
    "MY": (3.1, 101.7), "TH": (13.8, 100.5), "PH": (14.6, 121.0),
    "PL": (52.2, 21.0), "BG": (42.7, 23.3), "RO": (44.4, 26.1),
    "MD": (47.0, 28.9), "SC": (-4.6, 55.5), "PA": (9.0, -79.5),
    "IL": (31.8, 35.2), "SE": (59.3, 18.1), "CH": (46.9, 7.4),
    "IT": (41.9, 12.5), "ES": (40.4, -3.7), "MX": (19.4, -99.1),
    "AR": (-34.6, -58.4), "ZA": (-25.7, 28.2), "NG": (9.1, 7.4),
    "KZ": (51.2, 71.4), "PK": (33.7, 73.1), "BD": (23.8, 90.4),
    "HK": (22.3, 114.2), "TW": (25.0, 121.5), "MO": (22.2, 113.5),
}


def _short_province(name: str) -> str:
    """江苏省→江苏 / 香港特别行政区→香港 / 内蒙古自治区→内蒙古 / 台北市→台湾省原样。"""
    for suffix in ("特别行政区", "维吾尔自治区", "回族自治区", "壮族自治区", "自治区", "省", "市"):
        if name.endswith(suffix):
            return name[: -len(suffix)]
    return name


@functools.lru_cache(maxsize=8192)
def lookup(ip: str) -> dict | None:
    """IP → {country, province, city, isp, country_code}。

    内网/保留/无效/库不可用 → None。线程安全 (searcher.search 持锁)。
    """
    if not ip or ":" in ip:  # IPv6 由 v6 库另行处理, 本模块只做 IPv4
        return None
    s = _get_searcher()
    if not s:
        return None
    try:
        with _lock:
            raw = s.search(ip)
    except Exception:
        return None
    if not raw:
        return None
    parts = str(raw).split("|")
    if len(parts) < 5:
        return None
    country, province, city, isp, code = (p.strip() for p in parts[:5])
    if country in ("Reserved", "0", ""):  # 内网/保留地址不是"攻击来源"
        return None
    return {
        "country": country,
        "province": province if province not in ("0", "") else "",
        "city": city if city not in ("0", "") else "",
        "isp": isp if isp not in ("0", "") else "",
        "country_code": code if code not in ("0", "") else "",
    }


def resolve_point(ip: str) -> dict | None:
    """IP → 态势图布点 {lat, lon, label, country, province, country_code}。

    中国 → 省会坐标 (label=省); 境外 → 国家坐标 (label=国家)。
    坐标表未收录且无码 → None (诚实降级: 不猜坐标)。
    """
    geo = lookup(ip)
    if not geo:
        return None
    country = geo["country"]
    code = (geo["country_code"] or "").upper()
    if country == "中国" or code == "CN":
        short = _short_province(geo["province"] or "")
        coord = CN_PROVINCE_COORDS.get(short)
        if not coord:
            return None
        return {"lat": coord[0], "lon": coord[1], "label": geo["province"] or short,
                "country": "中国", "province": geo["province"], "country_code": "CN"}
    key = country.lower()
    coord = COUNTRY_COORDS.get(key) or _COUNTRY_CODE_COORDS.get(code)
    if not coord:
        return None
    return {"lat": coord[0], "lon": coord[1], "label": country,
            "country": country, "province": geo["province"], "country_code": code}
