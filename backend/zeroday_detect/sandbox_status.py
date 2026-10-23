"""沙箱任务状态契约与外部输入安全校验。

来源：2026-10-18 检测引擎正确性审查 P0-5 / P0-6 / P1-27~P1-30，
整改方案 §五、§十。

**为什么需要这个模块**

修复前，`None` 同时表达四种完全不同的语义：
「任务尚无结果」「服务不可用」「请求超时」「分析完成且没发现威胁」。
后果实测：`behavior_analyzer.analyze(None)` 返回
`verdict="clean", score=0.0`，与真实干净样本**逐字段相同**。
「沙箱没给结果」被当成「样本安全」。

现在把语义拆开：

| 状态 | 含义 | 可否产出 verdict |
|---|---|---|
| `pending` | 任务已提交，尚未完成 | 否 |
| `running` | 分析进行中 | 否 |
| `completed` | 分析完成，有可解析报告 | 是 |
| `no_result` | 任务完成，但没有有效分析报告 | 否 |
| `unavailable` | 沙箱服务不可用 | 否 |
| `timeout` | 请求超时 | 否 |
| `failed` | 任务或报告解析失败 | 否 |
| `clean` / `suspicious` / `malicious` | 仅在报告有效且分析完成后使用 | 是 |

**安全边界**：`submit_url` 修复前对 URL 零校验，
`file:///etc/passwd`、`http://169.254.169.254/latest/meta-data/`、
`gopher://127.0.0.1:6379/_INFO` 全部原样转发给沙箱 agent。
`task_id` 修复前直接拼进请求路径，`../../v1/admin` 会被规约成
`/v1/admin` 并携带 Bearer 头打到 CAPE 的其他端点。
"""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlsplit

# ── 任务状态 ──

ST_PENDING = "pending"
ST_RUNNING = "running"
ST_COMPLETED = "completed"
ST_NO_RESULT = "no_result"
ST_UNAVAILABLE = "unavailable"
ST_TIMEOUT = "timeout"
ST_FAILED = "failed"
ST_UNKNOWN = "unknown"

ALL_TASK_STATUSES = frozenset({
    ST_PENDING, ST_RUNNING, ST_COMPLETED, ST_NO_RESULT,
    ST_UNAVAILABLE, ST_TIMEOUT, ST_FAILED, ST_UNKNOWN,
})

#: 这些状态下允许给出 clean/suspicious/malicious 判定
VERDICT_CAPABLE_STATUSES = frozenset({ST_COMPLETED})

#: 这些状态表示"没能得出结论"，不得当作阴性
INCONCLUSIVE_STATUSES = frozenset({
    ST_PENDING, ST_RUNNING, ST_NO_RESULT,
    ST_UNAVAILABLE, ST_TIMEOUT, ST_FAILED, ST_UNKNOWN,
})

#: CAPE/Cuckoo 原始状态 → 统一状态
_CAPE_STATUS_MAP = {
    "pending": ST_PENDING,
    "running": ST_RUNNING,
    "processing": ST_RUNNING,
    "starting": ST_RUNNING,
    "completed": ST_COMPLETED,
    "reported": ST_COMPLETED,
    "recovered": ST_COMPLETED,
    "failed_analysis": ST_FAILED,
    "failed_processing": ST_FAILED,
    "failed_reporting": ST_FAILED,
    "reported_but_not_exported": ST_COMPLETED,
}


def map_cape_status(raw: Optional[str]) -> str:
    """CAPE/Cuckoo 原始状态 → 统一状态（未知一律 unknown，绝不降级成 clean）。"""
    if not raw:
        return ST_UNKNOWN
    return _CAPE_STATUS_MAP.get(str(raw).strip().lower(), ST_UNKNOWN)


@dataclass
class SandboxOutcome:
    """一次沙箱交互的终态或可恢复中间态。

    修复后 `None` 不再出现在这条链路上：调用方要么拿到 outcome，
    要么拿到明确的异常。
    """

    status: str
    task_id: str = ""
    report: Optional[dict] = None
    error_code: str = ""
    error_message: str = ""
    sample_hash: str = ""
    external_task_id: str = ""
    completed_on: str = ""
    submitted_at: float = 0.0
    updated_at: float = 0.0
    raw_status: str = ""

    def __post_init__(self) -> None:
        if self.status not in ALL_TASK_STATUSES:
            raise ValueError(f"unknown sandbox status: {self.status!r}")

    @property
    def verdict_capable(self) -> bool:
        """是否可以给出恶意性判定。仅 completed 才可以。"""
        return self.status in VERDICT_CAPABLE_STATUSES

    @property
    def is_failure(self) -> bool:
        return self.status in (ST_UNAVAILABLE, ST_TIMEOUT, ST_FAILED)

    @property
    def terminal(self) -> bool:
        return self.status in (ST_COMPLETED, ST_NO_RESULT, ST_FAILED,
                               ST_UNAVAILABLE, ST_TIMEOUT)

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "raw_status": self.raw_status,
            "completed_on": self.completed_on,
            "task_id": self.task_id or self.external_task_id,
            "sample_hash": self.sample_hash,
            "external_task_id": self.external_task_id,
            "verdict_capable": self.verdict_capable,
            "terminal": self.terminal,
            "error_code": self.error_code,
            "error_message": self.error_message,
            "submitted_at": self.submitted_at,
            "updated_at": self.updated_at,
        }


# ── URL 安全校验 ──

ALLOWED_URL_SCHEMES = frozenset({"http", "https"})

#: 云厂商元数据端点（即使解析成公网 IP 也拒绝）
_CLOUD_METADATA_HOSTS = frozenset({
    "169.254.169.254",
    "metadata.google.internal",
    "metadata.goog",
    "100.100.100.200",
    "fd00:ec2::254",
})

MAX_URL_LENGTH = 2048

# CAPE/Cuckoo 任务 ID：字母数字、连字符、下划线，长度 1..128
_TASK_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")


class UrlRejected(ValueError):
    """URL 未通过安全校验。"""

    def __init__(self, reason: str, detail: str = ""):
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail


class TaskIdRejected(ValueError):
    """task_id 未通过格式校验。"""

    def __init__(self, reason: str, detail: str = ""):
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail


def _ip_rejection(ip: ipaddress._BaseAddress, *, allow_private: bool) -> Optional[str]:
    """返回禁止原因；允许则返回 None。

    `allow_private` **只**放松私有段（RFC1918 / CGNAT / ULA），
    loopback / link-local / 保留段 / 组播一律不放行 —— 内网沙箱自己就在
    私有网段里，开放这一项已经覆盖了「分析平台内部 URL」的需求，
    但放开 loopback 会让沙箱 agent 可达宿主机。
    """
    if ip.is_loopback:
        return "loopback_not_allowed"
    if ip.is_link_local:
        return "link_local_not_allowed"
    if ip.is_private and not allow_private:
        return "private_not_allowed"
    if ip.is_reserved or ip.is_multicast or ip.is_unspecified:
        return "reserved_or_multicast_not_allowed"
    return None


def _host_to_ips(host: str, port: int) -> list:
    """解析主机名（可能失败）。返回 ipaddress 对象列表。"""
    try:
        ipaddress.ip_address(host)
        return []
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, port or None, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError, OSError):
        return []
    out = []
    for info in infos:
        sockaddr = info[4]
        if not sockaddr:
            continue
        try:
            out.append(ipaddress.ip_address(sockaddr[0]))
        except ValueError:
            continue
    return out


def validate_submittable_url(
    url: str,
    *,
    allow_private: bool = False,
    resolve_dns: bool = True,
) -> str:
    """校验「可提交给沙箱分析」的 URL。

    修复前 `sandbox_connector.submit_url` 对 `:109` 完全不校验，
    任何字符串都会原样转发（实测 `file:///etc/passwd` 被沙箱接收）。
    现在按整改方案 §五.2 执行：
      - 只允许 http / https；
      - 默认拒绝 loopback / link-local / 私有地址 / 云元数据地址；
      - 域名解析后的 IP 重新校验（防 DNS 变更绕过）。

    修复后 aiohttp 会跟随重定向，因此**每次请求都要重新过一遍本函数**。

    Raises: UrlRejected
    Returns: 校验通过的原始 URL
    """
    if not url or not isinstance(url, str):
        raise UrlRejected("url_empty", repr(url))
    url = url.strip()
    if len(url) > MAX_URL_LENGTH:
        raise UrlRejected("url_too_long", f"{len(url)} > {MAX_URL_LENGTH}")

    parts = urlsplit(url)
    scheme = (parts.scheme or "").lower()
    if scheme not in ALLOWED_URL_SCHEMES:
        raise UrlRejected("scheme_not_allowed", scheme or "<empty>")
    if any(ch in url for ch in ("\n", "\r", "\t", " ")):
        raise UrlRejected("url_control_chars", repr(url[:64]))

    host = parts.hostname
    if not host:
        raise UrlRejected("host_missing", url[:64])
    host_l = host.lower()
    if host_l in _CLOUD_METADATA_HOSTS:
        raise UrlRejected("cloud_metadata_blocked", host_l)
    if parts.username or parts.password:
        raise UrlRejected("userinfo_not_allowed", host_l)

    try:
        ip = ipaddress.ip_address(host_l)
    except ValueError:
        ip = None
    if ip is not None:
        reason = _ip_rejection(ip, allow_private=allow_private)
        if reason:
            raise UrlRejected(reason, host_l)
    elif resolve_dns:
        ips = _host_to_ips(host_l, parts.port or (443 if scheme == "https" else 80))
        if not ips:
            raise UrlRejected("dns_resolve_failed", host_l)
        for ip in ips:
            reason = _ip_rejection(ip, allow_private=allow_private)
            if reason:
                raise UrlRejected(reason, f"{host_l} -> {ip}")
    return url


def validate_task_id(task_id: str) -> str:
    """校验沙箱 task_id 格式。

    修复前 task_id 被直接拼进请求路径：
        `../../v1/admin` → 服务端实收 `/v1/admin`（带 Bearer 头）
        `abc?admin=1`   → 注入查询串
        `x#frag`        → 截断
    现在只接受明确的标识符格式。

    Raises: TaskIdRejected
    """
    if not task_id or not isinstance(task_id, str):
        raise TaskIdRejected("task_id_empty", repr(task_id))
    tid = task_id.strip()
    if not _TASK_ID_RE.match(tid):
        raise TaskIdRejected("task_id_format_invalid", repr(task_id[:64]))
    return tid
