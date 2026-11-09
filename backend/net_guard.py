"""
net_guard.py — 出网 URL 安全校验的共享入口 (R14 / 复审 P1-2)

平台此前只有沙箱与 webhook 两处接了 SSRF 校验(zeroday_detect.sandbox_status),
威胁情报拉取链路(TAXII/MISP/csv_http/KEV)完全绕过 —— admin 可配 feed 指向
内网/云元数据, 或借本地 csv 路径读任意文件。

实现策略: 校验逻辑单点留在 sandbox_status(既有 12 个测试盯它), 本模块作为
共享门面 re-export; 新调用方一律 `from net_guard import validate_submittable_url`,
不再各自 import sandbox_status(防止"又一个新链路忘了接")。重定向逐跳复检、
跨 host 剥凭证的执行语义见 stix_taxii._fetch_text 的实现约定。
"""
from zeroday_detect.sandbox_status import (  # noqa: F401
    ALLOWED_URL_SCHEMES,
    MAX_URL_LENGTH,
    UrlRejected,
    validate_submittable_url,
)

__all__ = [
    "ALLOWED_URL_SCHEMES",
    "MAX_URL_LENGTH",
    "UrlRejected",
    "validate_submittable_url",
]
