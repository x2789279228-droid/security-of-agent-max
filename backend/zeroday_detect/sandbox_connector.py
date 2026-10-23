"""
sandbox_connector.py — CAPE / Cuckoo 沙箱 REST API 对接

支持:
  - 文件/URL 提交分析
  - 任务状态轮询
  - 报告获取与解析
  - 高危告警自动提交

整改方案 §五 / §十（2026-10-18 检测引擎正确性审查 P0-5 / P0-6 / P1-27~P1-30）：

**1. 状态机取代 `None`**
修复前 `submit_* / get_task_status / get_report / wait_for_completion`
全部用 `None` 同时表达「任务尚无结果」「服务不可用」「超时」
「分析完成但没发现威胁」。现在统一返回 `SandboxOutcome`。

**2. URL / task_id 校验**
修复前 `submit_url` 对 `:109` 完全不校验，`file:///etc/passwd`、
`http://169.254.169.254/latest/meta-data/`、`gopher://127.0.0.1:6379/_INFO`
全部原样转发给沙箱 agent；`task_id="../../v1/admin"` 会把请求打到
CAPE 的其他端点且带 Bearer 头。

**3. 任务可追踪**
`sha256` 修复前算了就丢（`SandboxTask.sample_hash` 从未被赋值），
任务无法回连原始样本。现在随 outcome 返回并做去重提示。

用法:
    from zeroday_detect.sandbox_connector import sandbox
    outcome = await sandbox.submit_file_outcome(file_bytes, filename="malware.exe")
    status  = await sandbox.poll_outcome(outcome.task_id)
    report  = await sandbox.analyze_outcome(outcome.task_id)
"""
import asyncio
import hashlib
import logging
import random
import time
from typing import Optional

from config import settings

from zeroday_detect.sandbox_status import (
    ST_COMPLETED,
    ST_FAILED,
    ST_NO_RESULT,
    ST_PENDING,
    ST_TIMEOUT,
    ST_UNAVAILABLE,
    ST_UNKNOWN,
    SandboxOutcome,
    TaskIdRejected,
    UrlRejected,
    map_cape_status,
    validate_submittable_url,
    validate_task_id,
)

logger = logging.getLogger(__name__)

#: 可重试的 HTTP 状态（429 限流 / 5xx 瞬时故障）
RETRYABLE_STATUSES = frozenset({429, 500, 502, 503, 504})
MAX_ATTEMPTS = 3
BACKOFF_BASE_S = 0.4
BACKOFF_MAX_S = 4.0


class SandboxConnector:
    """CAPE / Cuckoo 沙箱连接器"""

    def __init__(self):
        self.enabled = settings.sandbox_enabled
        self.api_url = settings.sandbox_api_url.rstrip("/")
        self.api_key = settings.sandbox_api_key
        self.timeout = settings.sandbox_timeout
        self.auto_submit = settings.sandbox_auto_submit
        self.auto_threshold = settings.sandbox_auto_threshold
        self.sandbox_type = settings.sandbox_type
        #: 是否允许提交内网 URL（默认拒绝；开启需独立授权 + 隔离环境）
        self.allow_internal_url = bool(
            getattr(settings, "sandbox_allow_internal_url", False))
        #: 样本指纹 → 最近一次提交结果（便于去重与回连；不做永久去重策略）
        self._by_hash: dict[str, SandboxOutcome] = {}
        self.last_outcome: Optional[SandboxOutcome] = None
        # 可观测性分项计数（整改方案 §十一）
        self._status_counts: dict[str, int] = {}
        self._failure_reasons: dict[str, int] = {}
        self._dangling = 0

    def _headers(self) -> dict:
        h = {"Accept": "application/json"}
        if self.api_key:
            h["Authorization"] = f"Bearer {self.api_key}"
        return h

    # ── 底层 HTTP（有界重试 + 重定向逐跳复检）──────────────────

    async def _request(self, method: str, url: str, *, timeout_s: float,
                       data=None, expect_json: bool = True,
                       max_redirects: int = 3):
        """带有界退避重试的请求。

        Returns: (status_code, payload_or_None, error_code, error_message)
        重定向**不自动跟随**：每一跳都要重新过安全校验（整改方案 §五.2）。
        """
        import aiohttp

        current = url
        redirects = 0
        last_err = ("", "")
        for attempt in range(MAX_ATTEMPTS):
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.request(
                        method, current, data=data, headers=self._headers(),
                        timeout=aiohttp.ClientTimeout(total=timeout_s),
                        allow_redirects=False,
                    ) as resp:
                        if resp.status in (301, 302, 303, 307, 308):
                            if redirects >= max_redirects:
                                return (resp.status, None, "too_many_redirects",
                                        f"{redirects}+ redirects")
                            loc = resp.headers.get("Location", "")
                            current = self._safe_redirect_target(current, loc)
                            redirects += 1
                            continue
                        if resp.status == 200:
                            payload = await resp.json() if expect_json else await resp.text()
                            return (200, payload, "", "")
                        if resp.status in RETRYABLE_STATUSES and attempt < MAX_ATTEMPTS - 1:
                            body = ""
                            try:
                                body = (await resp.text())[:200]
                            except Exception:
                                pass
                            last_err = (f"http_{resp.status}", body)
                            await self._sleep_backoff(attempt)
                            continue
                        body = ""
                        try:
                            body = (await resp.text())[:200]
                        except Exception:
                            pass
                        return (resp.status, None, f"http_{resp.status}", body)
            except asyncio.TimeoutError as exc:
                last_err = ("timeout", str(exc))
                if attempt >= MAX_ATTEMPTS - 1:
                    return (0, None, "timeout", "request timeout")
                await self._sleep_backoff(attempt)
            except Exception as exc:  # 连接被拒 / DNS 失败 / TLS 错误
                last_err = (f"{type(exc).__name__}", str(exc)[:200])
                if attempt >= MAX_ATTEMPTS - 1:
                    break
                await self._sleep_backoff(attempt)
        return (0, None, last_err[0] or "unavailable", last_err[1] or "sandbox unavailable")

    @staticmethod
    async def _sleep_backoff(attempt: int) -> None:
        """有上限的指数退避 + 抖动（整改方案 §十.1）。"""
        delay = min(BACKOFF_BASE_S * (2 ** attempt), BACKOFF_MAX_S)
        await asyncio.sleep(delay * (0.5 + random.random()))

    def _safe_redirect_target(self, base: str, location: str) -> str:
        """重定向目标必须重新过一遍 URL 安全校验（整改方案 §五.2）。

        修复前这里只挡 **scheme 混淆** 与 **控制字符**，于是
        **云元数据 / loopback / 跨主机**的重定向目标全部放行 ——
        平台会带着 `self._headers()` 里的 **Bearer 沙箱 API key**
        去请求那些地址 = SSRF + 凭据外泄。

        实测（修复前）：
            http://169.254.169.254/latest/meta-data/  → 放行
            http://metadata.google.internal/...       → 放行
            http://127.0.0.1:6379/_INFO               → 放行
            http://evil.example.com/steal             → 放行
            file:///etc/passwd                        → 拒绝
            含控制字符的 Location                      → 放行（urljoin 把它剥掉了）

        现在按三条守：

        1. **原始** Location 里就不能有控制字符 ——
           `urljoin` 会把它们**剥掉**，事后检查归一化后的串等于没检查；
        2. 重定向目标必须**留在配置的沙箱端点主机上**
           （「固定服务端点」/「禁用非预期重定向」）——
           否则 Bearer 凭据会被带到别的域；
        3. 目标本身重新过一遍 `validate_submittable_url`
           （`allow_private=True`：沙箱端点本身是内网服务；
           但 **loopback 与云元数据在任何模式下都禁**）。
        """
        from urllib.parse import urljoin, urlsplit

        from zeroday_detect.sandbox_status import validate_submittable_url

        raw = location or ""
        if not raw.strip():
            raise UrlRejected("redirect_target_empty", raw[:64])
        # ① 原始 Location 里的控制字符（urljoin 会剥掉，事后查等于没查）
        if any(ch in raw for ch in ("\n", "\r", "\t")):
            raise UrlRejected("redirect_control_chars", raw[:64])

        target = urljoin(base, raw)
        # ② 必须留在配置的端点主机上
        base_host = (urlsplit(base).hostname or "").lower()
        target_host = (urlsplit(target).hostname or "").lower()
        if not target_host or target_host != base_host:
            raise UrlRejected("redirect_host_not_allowed",
                              target_host or target[:64])
        # ③ 目标重新过一遍 URL 安全校验（scheme / 控制字符 / userinfo /
        #    云元数据主机 / loopback / 元数据 IP）
        return validate_submittable_url(target, allow_private=True,
                                         resolve_dns=False)

    # ── 提交 ──────────────────────────────────────────────

    async def submit_file(
        self,
        file_bytes: bytes,
        filename: str = "sample.bin",
        package: str = "",
        priority: int = 1,
    ) -> Optional[str]:
        """提交文件到沙箱分析，返回 task_id（兼容旧接口）。"""
        outcome = await self.submit_file_outcome(
            file_bytes, filename=filename, package=package, priority=priority)
        return outcome.task_id or None

    async def submit_file_outcome(
        self,
        file_bytes: bytes,
        filename: str = "sample.bin",
        package: str = "",
        priority: int = 1,
        sample_hash: str = "",
    ) -> SandboxOutcome:
        """提交文件 → SandboxOutcome。

        `sample_hash` 缺失时按内容计算（修复前算了就丢，任务无法回连样本）。
        """
        if not self.enabled:
            return self._finish(SandboxOutcome(
                status=ST_UNAVAILABLE, error_code="sandbox_disabled",
                error_message="沙箱未启用"))
        if not isinstance(file_bytes, (bytes, bytearray)) or not file_bytes:
            return self._finish(SandboxOutcome(
                status=ST_FAILED, error_code="empty_sample",
                error_message="sample payload empty or not bytes"))

        sample_hash = sample_hash or hashlib.sha256(bytes(file_bytes)).hexdigest()
        now = time.time()
        try:
            import aiohttp
        except ImportError:
            return self._finish(SandboxOutcome(
                status=ST_UNAVAILABLE, sample_hash=sample_hash,
                error_code="aiohttp_missing", error_message="aiohttp 未安装"))

        data = aiohttp.FormData()
        data.add_field("file", bytes(file_bytes), filename=filename,
                       content_type="application/octet-stream")
        if package:
            data.add_field("package", package)
        data.add_field("priority", str(priority))
        data.add_field("timeout", str(self.timeout))

        status, payload, err_code, err_msg = await self._request(
            "POST", f"{self.api_url}/tasks/create/file",
            timeout_s=60, data=data)
        if status != 200 or not isinstance(payload, dict):
            return self._finish(SandboxOutcome(
                status=ST_UNAVAILABLE if status == 0 else ST_FAILED,
                sample_hash=sample_hash, submitted_at=now, updated_at=time.time(),
                error_code=err_code or "submit_failed", error_message=err_msg))

        task_id = self._extract_task_id(payload)
        if not task_id:
            # 修复前 `str(result.get("task_id", ...))` 会把 None 变成字面量
            # 字符串 "None"，通过 `if not task_id` 检查后落库成永久悬空任务。
            return self._finish(SandboxOutcome(
                status=ST_FAILED, sample_hash=sample_hash,
                submitted_at=now, updated_at=time.time(),
                error_code="missing_task_id",
                error_message=f"no usable task id in response: {str(payload)[:120]}"))

        logger.info("沙箱提交成功: %s → task_id=%s sha256=%s", filename, task_id,
                    sample_hash[:12])
        try:
            from metrics import inc_sandbox_submission
            inc_sandbox_submission("file")
        except Exception:
            pass
        return self._finish(SandboxOutcome(
            status=ST_PENDING, task_id=task_id, external_task_id=task_id,
            sample_hash=sample_hash, submitted_at=now, updated_at=time.time()))

    async def submit_url(self, url_to_analyze: str, priority: int = 1) -> Optional[str]:
        """提交 URL 到沙箱分析（兼容旧接口）。"""
        outcome = await self.submit_url_outcome(url_to_analyze, priority=priority)
        return outcome.task_id or None

    async def submit_url_outcome(self, url_to_analyze: str,
                                 priority: int = 1) -> SandboxOutcome:
        """提交 URL → SandboxOutcome。

        **安全边界（整改方案 §五.2）**：只允许 http/https，默认拒绝
        loopback / link-local / 私有地址 / 云元数据地址，域名解析后的 IP 重新校验。

        **样本指纹（整改方案 §十.1）**：URL 样本同样要有 SHA-256 ——
        「使用 SHA-256 对应的真实样本标识关联沙箱任务」是**文档明确
        要求**的，而修复前**只有文件路径**算指纹：
        URL 提交的 outcome 里没有 `sample_hash` → `_by_hash` 里没有它
        → `lookup_by_hash` 回连不到 → 落库的 `SandboxTask` 也没有。
        而 URL 提交正是**活的**生产入口。
        """
        sample_hash = hashlib.sha256(
            str(url_to_analyze or "").strip().encode("utf-8")
        ).hexdigest()
        if not self.enabled:
            return self._finish(SandboxOutcome(
                status=ST_UNAVAILABLE, error_code="sandbox_disabled",
                error_message="沙箱未启用", sample_hash=sample_hash))
        try:
            validate_submittable_url(
                url_to_analyze, allow_private=self.allow_internal_url)
        except UrlRejected as exc:
            logger.warning("沙箱 URL 被拒: reason=%s detail=%s",
                           exc.reason, exc.detail)
            try:
                from metrics import inc_sandbox_submission
                inc_sandbox_submission("url_rejected")
            except Exception:
                pass
            return self._finish(SandboxOutcome(
                status=ST_FAILED, error_code=f"url_rejected:{exc.reason}",
                error_message=exc.detail or exc.reason,
                sample_hash=sample_hash))

        try:
            import aiohttp
        except ImportError:
            return self._finish(SandboxOutcome(
                status=ST_UNAVAILABLE, error_code="aiohttp_missing",
                error_message="aiohttp 未安装", sample_hash=sample_hash))

        data = aiohttp.FormData()
        data.add_field("url", url_to_analyze)
        data.add_field("priority", str(priority))
        data.add_field("timeout", str(self.timeout))
        status, payload, err_code, err_msg = await self._request(
            "POST", f"{self.api_url}/tasks/create/url", timeout_s=30, data=data)
        if status != 200 or not isinstance(payload, dict):
            return self._finish(SandboxOutcome(
                status=ST_UNAVAILABLE if status == 0 else ST_FAILED,
                error_code=err_code or "submit_failed", error_message=err_msg,
                sample_hash=sample_hash))
        task_id = self._extract_task_id(payload)
        if not task_id:
            return self._finish(SandboxOutcome(
                status=ST_FAILED, error_code="missing_task_id",
                error_message=f"no usable task id in response: {str(payload)[:120]}",
                sample_hash=sample_hash))
        logger.info("URL 沙箱提交: %s → task_id=%s", url_to_analyze, task_id)
        return self._finish(SandboxOutcome(
            status=ST_PENDING, task_id=task_id, external_task_id=task_id,
            sample_hash=sample_hash,
            submitted_at=time.time(), updated_at=time.time()))

    @staticmethod
    def _extract_task_id(payload: dict) -> str:
        """从提交响应里取**真实**的 task id；取不到就是提交失败。"""
        raw = payload.get("task_id")
        if isinstance(raw, (str, int)) and str(raw).strip():
            return str(raw).strip()
        ids = payload.get("task_ids")
        if isinstance(ids, (list, tuple)) and ids:
            first = ids[0]
            if isinstance(first, (str, int)) and str(first).strip():
                return str(first).strip()
        return ""

    # ── 查询 ──────────────────────────────────────────────

    async def get_task_status(self, task_id: str) -> Optional[dict]:
        """查询任务状态（兼容旧接口）。

        `status` 保持**原始 CAPE 状态**（如 "reported"），既有调用方依赖它；
        新增 `outcome` 字段承载归一化后的统一状态。
        """
        outcome = await self.poll_outcome(task_id)
        if not outcome.task_id:
            return None
        return {
            "task_id": outcome.task_id,
            "status": outcome.raw_status or outcome.status,
            "outcome": outcome.status,
            "completed_on": outcome.completed_on,
            "error_code": outcome.error_code,
            "error_message": outcome.error_message,
        }

    async def poll_outcome(self, task_id: str) -> SandboxOutcome:
        """轮询任务状态 → SandboxOutcome（状态映射见 sandbox_status.map_cape_status）。"""
        try:
            safe_id = validate_task_id(task_id)
        except TaskIdRejected as exc:
            return self._finish(SandboxOutcome(
                status=ST_FAILED, task_id=str(task_id or ""),
                error_code=f"task_id_rejected:{exc.reason}",
                error_message=exc.detail or exc.reason))

        status, payload, err_code, err_msg = await self._request(
            "GET", f"{self.api_url}/tasks/view/{safe_id}", timeout_s=15)
        if status != 200 or not isinstance(payload, dict):
            # 修复前: HTTP 非 200 时一条日志都不打, 且与「任务失败」返回同一个 None
            level = logger.error if err_code not in ("timeout",) else logger.warning
            level("沙箱状态查询失败 task_id=%s code=%s msg=%s", safe_id,
                  err_code, err_msg)
            mapped = ST_TIMEOUT if err_code == "timeout" else (
                ST_UNAVAILABLE if status == 0 else ST_FAILED)
            return self._finish(SandboxOutcome(
                status=mapped, task_id=safe_id, updated_at=time.time(),
                error_code=err_code or "status_failed", error_message=err_msg))

        task = payload.get("task", payload)
        raw = str((task or {}).get("status", "") or "")
        mapped = map_cape_status(raw)
        return self._finish(SandboxOutcome(
            status=mapped, task_id=safe_id, raw_status=raw,
            completed_on=str((task or {}).get("completed_on", "") or ""),
            updated_at=time.time()))

    async def get_report(self, task_id: str) -> Optional[dict]:
        """获取分析报告（兼容旧接口：直接返回报告 dict）。"""
        outcome = await self.fetch_report_outcome(task_id)
        return outcome.report

    async def fetch_report_outcome(self, task_id: str) -> SandboxOutcome:
        """获取报告 → SandboxOutcome。

        报告缺失（200 但没有可用内容）→ `no_result`，**不是** clean。
        """
        try:
            safe_id = validate_task_id(task_id)
        except TaskIdRejected as exc:
            return self._finish(SandboxOutcome(
                status=ST_FAILED, task_id=str(task_id or ""),
                error_code=f"task_id_rejected:{exc.reason}",
                error_message=exc.detail or exc.reason))

        status, payload, err_code, err_msg = await self._request(
            "GET", f"{self.api_url}/tasks/report/{safe_id}", timeout_s=60)
        if status != 200:
            logger.error("沙箱报告获取失败 task_id=%s code=%s msg=%s",
                         safe_id, err_code, err_msg)
            mapped = ST_TIMEOUT if err_code == "timeout" else (
                ST_UNAVAILABLE if status == 0 else ST_NO_RESULT)
            return self._finish(SandboxOutcome(
                status=mapped, task_id=safe_id, updated_at=time.time(),
                error_code=err_code or "report_failed", error_message=err_msg))
        if not isinstance(payload, dict) or not payload:
            return self._finish(SandboxOutcome(
                status=ST_NO_RESULT, task_id=safe_id, updated_at=time.time(),
                error_code="empty_report", error_message="report payload empty"))
        return self._finish(SandboxOutcome(
            status=ST_COMPLETED, task_id=safe_id, report=payload,
            updated_at=time.time()))

    async def wait_for_completion(self, task_id: str, poll_interval: int = 10) -> Optional[dict]:
        """等待任务完成并返回报告（兼容旧接口）。"""
        outcome = await self.wait_outcome(task_id, poll_interval=poll_interval)
        return outcome.report

    async def wait_outcome(self, task_id: str,
                           poll_interval: int = 10) -> SandboxOutcome:
        """等待任务完成 → SandboxOutcome。

        修复前：`poll_interval=0` 时 `elapsed += 0` → **永不退出**；
        `elapsed` 按迭代计数而非墙钟，单次请求耗时会让实际等待远超
        `timeout + 60`。现在用 `time.monotonic()` 做真实截止时间。
        """
        if poll_interval <= 0:
            return self._finish(SandboxOutcome(
                status=ST_FAILED, task_id=str(task_id or ""),
                error_code="invalid_poll_interval",
                error_message="poll_interval must be > 0"))
        deadline = time.monotonic() + self.timeout + 60
        while True:
            polled = await self.poll_outcome(task_id)
            if polled.status in (ST_UNAVAILABLE, ST_TIMEOUT, ST_FAILED):
                # 首次轮询失败即放弃整次分析 —— 但现在是**显式的 unavailable**，
                # 调用方能区分「沙箱挂了」与「分析完成且干净」。
                return polled
            if polled.status == ST_COMPLETED:
                return await self.fetch_report_outcome(task_id)
            if polled.status in (ST_NO_RESULT, ST_UNKNOWN):
                return polled
            if time.monotonic() >= deadline:
                logger.warning("沙箱任务超时: %s", task_id)
                return self._finish(SandboxOutcome(
                    status=ST_TIMEOUT, task_id=polled.task_id,
                    raw_status=polled.raw_status, updated_at=time.time(),
                    error_code="deadline_exceeded",
                    error_message=f"exceeded {self.timeout + 60}s"))
            await asyncio.sleep(poll_interval)

    # ── 自动提交 ──────────────────────────────────────────

    async def auto_submit_check(
        self,
        event: dict,
        file_bytes: Optional[bytes] = None,
    ) -> Optional[str]:
        """自动提交检查 — 高危告警触发沙箱分析（兼容旧接口）。"""
        outcome = await self.auto_submit_outcome(event, file_bytes=file_bytes)
        return outcome.task_id or None

    async def auto_submit_outcome(self, event: dict,
                                  file_bytes: Optional[bytes] = None) -> SandboxOutcome:
        """自动提交 → SandboxOutcome（失败也有明确终态与日志）。"""
        if not self.auto_submit or not self.enabled:
            return self._finish(SandboxOutcome(
                status=ST_UNAVAILABLE, error_code="auto_submit_disabled",
                error_message="auto_submit 未启用"))
        confidence = event.get("confidence", 0)
        severity = event.get("severity", "info")
        try:
            confidence = float(confidence)
        except (TypeError, ValueError):
            confidence = 0.0

        if not (confidence >= self.auto_threshold or severity == "critical"):
            return self._finish(SandboxOutcome(
                status=ST_FAILED, error_code="below_threshold",
                error_message=f"confidence={confidence} severity={severity}"))

        if file_bytes:
            return await self.submit_file_outcome(
                file_bytes, filename=event.get("sample_name", "auto_sample.bin"),
                priority=2)
        url = event.get("url", "")
        if url:
            return await self.submit_url_outcome(url, priority=2)
        # 修复前: 这里直接返回裸 None 且**完全无日志**（P2-17）
        logger.info("沙箱自动提交跳过: 事件无 file_bytes 且无 url event_id=%s",
                    event.get("eventId") or event.get("event_id") or "")
        return self._finish(SandboxOutcome(
            status=ST_FAILED, error_code="no_submittable_artifact",
            error_message="event carries neither file_bytes nor url"))

    # ── 工具 ──────────────────────────────────────────────

    def _finish(self, outcome: SandboxOutcome) -> SandboxOutcome:
        """记录最后一次 outcome，并按 sample_hash 留存以便追踪/去重。"""
        self.last_outcome = outcome
        if outcome.sample_hash:
            self._by_hash[outcome.sample_hash] = outcome
        # 分项计数（整改方案 §十一：监控不能只报最终结果，
        # 「提交失败」「超时」「悬空任务」是三种不同的外部依赖故障）
        self._status_counts[outcome.status] = \
            self._status_counts.get(outcome.status, 0) + 1
        if outcome.is_failure:
            self._failure_reasons[outcome.error_code or "unknown"] = \
                self._failure_reasons.get(outcome.error_code or "unknown", 0) + 1
        if outcome.status == ST_UNAVAILABLE and outcome.task_id:
            self._dangling += 1
        if outcome.is_failure:
            logger.warning("沙箱终态=%s code=%s msg=%s", outcome.status,
                           outcome.error_code, outcome.error_message)
        return outcome

    def observability(self) -> dict:
        """按终态分项计数（整改方案 §十一）。

        `dangling_tasks` = 提交失败但已经产生了 task_id 的任务数 ——
        这些任务在外部系统里可能还在跑，但本地已经没有它的跟踪记录，
        是「悬空任务」的典型来源。
        """
        by_status = dict(self._status_counts)
        return {
            "by_status": by_status,
            "by_failure_reason": dict(self._failure_reasons),
            "total_finished": sum(by_status.values()),
            "failures": sum(self._failure_reasons.values()),
            "dangling_tasks": self._dangling,
            "tracked_samples": len(self._by_hash),
            # 明确的区分：真正「判定完成」的任务数
            "verdict_capable": by_status.get(ST_COMPLETED, 0),
            "not_verdict_capable": (
                sum(by_status.values()) - by_status.get(ST_COMPLETED, 0)),
        }

    def get_status(self) -> dict:
        return {
            "enabled": self.enabled,
            "type": self.sandbox_type,
            "api_url": self.api_url,
            "auto_submit": self.auto_submit,
            "allow_internal_url": self.allow_internal_url,
            "last_outcome": (self.last_outcome.to_dict()
                             if self.last_outcome else None),
            "tracked_samples": len(self._by_hash),
            "observability": self.observability(),
        }

    def lookup_by_hash(self, sample_hash: str) -> Optional[SandboxOutcome]:
        """按样本指纹回连最近一次提交（修复前 sample_hash 从未落库）。"""
        return self._by_hash.get(sample_hash)


# ── 全局单例 ──
sandbox = SandboxConnector()
