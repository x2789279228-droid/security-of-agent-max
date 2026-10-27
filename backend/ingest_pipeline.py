"""In-process event-driven ingest pipeline (Phase 1 contract).

North-star topology (same process, Kafka as buffer — not new microservices):

    HTTP ──validate/sanitize──► Kafka(security-events-ingest) ──202
                                      │
                                      ▼
                               detect (anomaly ∥ sigma, isolated)
                                      │
                                      ▼
                               persist (batch PG commit)
                                      │
                    ┌─────────────────┼─────────────────┐
                    ▼                 ▼                 ▼
              FastPath (async)   AuditWorker      event_bus
              强信号可封禁        P0/P1 never-drop

This module is the single owner of detect / persist_batch / dispatch.
`log_ingestion.LogIngestor.ingest` is a thin facade for the single-event path.
Kafka python-ingest consumer uses `run_many` for the batch path.

See: docs/upgrade-proposals/2026-q3-ingest-event-driven.md
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Optional

from sqlalchemy.exc import IntegrityError

from anomaly_detector import AnomalyReport, anomaly_detector
from config import settings
from detection_contract import (
    STATUS_DETECTED,
    STATUS_ERROR,
    STATUS_NOT_DETECTED,
    AnalysisStatus,
    DetectionResult,
)
from event_store import event_store

logger = logging.getLogger(__name__)


def _pipeline_metrics(rr: "RunResult", seconds: float) -> None:
    try:
        from core_metrics import inc_pipeline_result, log_process, observe_pipeline_e2e
        result = rr.process_status or "success"
        observe_pipeline_e2e(seconds, result)
        inc_pipeline_result("ingest", result)
        log_process(
            logger,
            event_id=rr.eventId or "",
            stage="ingest",
            result=result,
            reason=rr.error_code or rr.error or "",
            retry_count=0,
            detect_ms=rr.detect_ms,
            persist_ms=rr.persist_ms,
            dispatch_ms=rr.dispatch_ms,
        )
    except Exception:
        pass

# 数字 severity → 枚举 (与 log_ingestion.ingest facade 保持一致)
_SEV_MAP = {10: "info", 30: "low", 50: "medium", 70: "high", 90: "critical"}

# Sigma 命中抬升异常分的下限 (与 log_ingestion.ingest EXACT 同源, 禁止改)
_SIGMA_FLOORS = {
    "critical": 0.75, "high": 0.65, "medium": 0.55, "low": 0.45,
}
_SIGMA_FLOOR_DEFAULT = 0.55


@dataclass
class DetectorError:
    detector: str          # "anomaly" | "sigma"
    message: str
    phase: str = "detect"        # 失败发生的阶段
    error_code: str = "detector_error"
    detector_version: str = ""   # 失败的检测器版本（整改方案 §二.2 验收 3）


@dataclass
class DetectResult:
    """Per-event detection output. Always returned; detector crashes do not abort ingest."""
    log_data: dict
    anomaly: AnomalyReport
    sigma: dict
    detect_ms: float = 0.0
    errors: list[DetectorError] = field(default_factory=list)
    analysis: AnalysisStatus = field(default_factory=lambda: AnalysisStatus(
        status=STATUS_NOT_DETECTED))

    @property
    def analysis_status(self) -> str:
        """整体分析状态: detected / not_detected / inconclusive / error / partial"""
        return self.analysis.status

    @property
    def analysis_complete(self) -> bool:
        """分析是否完整。False → 下游禁止按阴性收口。"""
        return self.analysis.complete

    @property
    def can_close_as_negative(self) -> bool:
        return self.analysis.can_close_as_negative


@dataclass
class PersistItem:
    session_id: str
    log_data: dict
    anomaly_score: float = 0.0
    correlation_id: str = ""


@dataclass
class PersistResult:
    stored: Any            # event_store.StoredEvent；ok=False 时可为 None
    log_data: dict
    anomaly: AnomalyReport
    session_id: str
    persist_ms: float = 0.0
    idempotent: bool = False
    ok: bool = True
    retryable: bool = False
    error_class: str = ""
    error_code: str = ""
    error: str = ""


@dataclass
class DispatchResult:
    event_id: int
    fastpath: bool = False
    audit_accepted: str = ""   # queued | shed | overflow | deferred | direct
    dispatch_ms: float = 0.0


@dataclass
class RunResult:
    """HTTP/sync facade payload (single event).

    status 仍是 HTTP 兼容字段（成功为 review_queued）。
    process_status 才是业务结果：success / retrying / failed / dlq。
    event_id 是库主键游标；eventId 是稳定业务 ID。
    """
    status: str
    event_id: int
    event_type: str
    severity: str
    anomaly: dict
    sigma: dict
    detect_ms: float = 0.0
    persist_ms: float = 0.0
    dispatch_ms: float = 0.0
    detector_errors: list[str] = field(default_factory=list)
    process_status: str = "success"
    retryable: bool = False
    error_class: str = ""
    error_code: str = ""
    error: str = ""
    idempotent: bool = False
    eventId: str = ""

    def as_http_dict(self) -> dict:
        body = {
            "status": self.status,
            "event_id": self.event_id,
            "event_type": self.event_type,
            "severity": self.severity,
            "anomaly": self.anomaly,
            "sigma": self.sigma,
        }
        if self.eventId:
            body["eventId"] = self.eventId
        if self.process_status and self.process_status != "success":
            body["process_status"] = self.process_status
            body["retryable"] = self.retryable
            if self.error:
                body["error"] = self.error
        return body


def empty_anomaly(reasons: Optional[list[str]] = None,
                  status: str = STATUS_NOT_DETECTED) -> AnomalyReport:
    """空异常报告。

    `status` 显式化：失败时调用方应传 STATUS_ERROR / STATUS_INCONCLUSIVE，
    避免「用 0.0 分数冒充一次成功的阴性判断」(整改方案 §二.2)。
    """
    rep = AnomalyReport(
        event_id=0,
        anomaly_score=0.0,
        is_anomaly=False,
        deviation_sigma=0.0,
        reasons=list(reasons or []),
    )
    # AnomalyReport 是普通 dataclass, 允许注入契约字段 (提交 D 会正式声明)
    rep.status = status
    return rep


def empty_sigma(status: str = STATUS_NOT_DETECTED,
                error_code: str = "", error_message: str = "") -> dict:
    """空 Sigma 结果。

    `status` 字段承载统一契约状态，区分「完整执行且未命中」与
    「引擎故障 / 部分规则失败」（整改方案 §二.2）。
    """
    return {"detected": False, "rule_count": 0, "attack_types": [],
            "max_severity": "", "hits": [], "status": status,
            "error_code": error_code, "error_message": error_message,
            "rules_evaluated": 0, "rules_failed": 0}


# ── 内部 helpers ──

def _ingestor(ingestor: Any):
    """解析调用方传入的 LogIngestor; None → 进程内单例 (懒 import 防循环)。"""
    if ingestor is None:
        from log_ingestion import log_ingestor
        return log_ingestor
    return ingestor


def _normalize_event(log_data: dict) -> dict:
    """字段归一化 + 数字 severity 映射 (与 LogIngestor.ingest facade 同语义)。

    单事件路径的 facade 已归一化; Kafka 批量路径直接进 run_many,
    必须在这里补齐归一化, 否则检测器/FastPath 看到 camelCase/数字 severity。
    归一化幂等, 双重调用无副作用。
    """
    from log_ingestion import log_ingestor
    normalized = log_ingestor._normalize_fields(log_data)
    severity = normalized.get("severity", "info")
    if isinstance(severity, (int, float)):
        severity = _SEV_MAP.get(int(severity), "medium")
        normalized["severity"] = severity
    return normalized


def _anomaly_payload(report: AnomalyReport) -> dict:
    """HTTP facade 返回的 anomaly 子对象 (与旧 ingest 返回一致)。"""
    return {
        "score": report.anomaly_score,
        "is_anomaly": bool(report.is_anomaly),
        "reasons": list(report.reasons or []),
    }


def _build_run_result(log_data: dict, persist: PersistResult, dispatch_res: DispatchResult,
                      detect_ms: float = 0.0, errors: Optional[list[str]] = None) -> RunResult:
    from event_identity import get_event_id
    stored_id = int(getattr(persist.stored, "id", 0) or 0) if persist.stored is not None else 0
    business_id = (
        getattr(persist.stored, "event_id", "") if persist.stored is not None else ""
    ) or get_event_id(log_data)
    return RunResult(
        status="review_queued",
        event_id=stored_id,
        eventId=business_id,
        event_type=log_data.get("event", log_data.get("type", "UNKNOWN")),
        severity=log_data.get("severity", "info"),
        anomaly=_anomaly_payload(persist.anomaly),
        sigma=log_data.get("_sigma", {"detected": False}),
        detect_ms=detect_ms,
        persist_ms=persist.persist_ms,
        dispatch_ms=dispatch_res.dispatch_ms,
        detector_errors=list(errors or []),
        process_status="success",
        retryable=False,
        idempotent=bool(persist.idempotent),
    )


def _incomplete_run_result(
    log_data: dict,
    *,
    retryable: bool,
    error: str = "",
    error_class: str = "",
    error_code: str = "",
    detect_ms: float = 0.0,
) -> RunResult:
    from retry_policy import STATUS_FAILED, STATUS_RETRYING
    process_status = STATUS_RETRYING if retryable else STATUS_FAILED
    sigma = log_data.get("_sigma") if isinstance(log_data.get("_sigma"), dict) else empty_sigma()
    anomaly = log_data.get("_anomaly") if isinstance(log_data.get("_anomaly"), dict) else None
    from event_identity import get_event_id
    return RunResult(
        status=process_status,
        event_id=0,
        eventId=get_event_id(log_data),
        event_type=log_data.get("event", log_data.get("type", "UNKNOWN")),
        severity=log_data.get("severity", "info"),
        anomaly=anomaly or _anomaly_payload(empty_anomaly()),
        sigma=sigma or empty_sigma(),
        detect_ms=detect_ms,
        detector_errors=[error] if error else [],
        process_status=process_status,
        retryable=retryable,
        error_class=error_class,
        error_code=error_code,
        error=error,
    )


# ── Public API ──

async def detect(log_data: dict) -> DetectResult:
    """Run anomaly + sigma with isolation.

    Rules:
      - Never raise to the caller. Detector exceptions become DetectorError.
      - When settings.ingest_parallel_detect: asyncio.gather both.
      - Fuse Sigma hit into anomaly score using the SAME floors as
        log_ingestion.ingest (critical=0.75, high=0.65, medium=0.55, low=0.45).
      - Write fused `_anomaly` and `_sigma` onto log_data (in-place) so FastPath
        and audit_triage keep working.
      - Record detect_ms.

    整改方案 §二（P0-1）：新增统一状态传播。
      - 每个检测器产出一个 `DetectionResult`，区分
        detected / not_detected / inconclusive / error / partial；
      - 失败时 `score=None`（不是 0.0）；
      - 整体 `AnalysisStatus` 写回 `log_data["_anomaly"]`，下游据此
        禁止把「检测器故障」当作阴性收口。
    """
    t0 = time.perf_counter()
    errors: list[DetectorError] = []
    anomaly_report: AnomalyReport = None
    sigma_result: dict = None
    event_key = str(log_data.get("eventId") or log_data.get("event_id") or "")

    def _sigma_version() -> str:
        try:
            from sigma_detector import sigma_detector as _sd
            return str(getattr(_sd, "detector_version", "") or
                       getattr(_sd, "version", "") or "")
        except Exception:
            return ""

    async def _run_anomaly():
        nonlocal anomaly_report, errors
        try:
            report = await anomaly_detector.analyze(log_data)
        except Exception as e:  # 隔离: 检测器崩溃不拖垮 ingest
            logger.warning(f"[Pipeline] anomaly detection failed: {e}")
            errors.append(DetectorError(
                detector="anomaly", message=str(e),
                error_code=f"{type(e).__name__}:anomaly_analyze",
                detector_version=str(getattr(anomaly_detector, "version", "") or ""),
            ))
            report = empty_anomaly(reasons=["anomaly_error"])
            report.status = STATUS_ERROR
        anomaly_report = report

    async def _run_sigma():
        nonlocal sigma_result, errors
        try:
            from sigma_detector import sigma_detector  # 懒 import: pySigma 构建失败也隔离
            # PERF-2026-10-26（Wave 1-2）：detect_for_event 是 40ms 级的
            # **同步 CPU 段**（150 规则逐条 SQL + 每事件私有 SQLite），
            # 裸调用会把 12 个 audit worker、9 个消费循环与 FastAPI 共享的
            # 唯一事件循环整个卡死 —— 压测的 HTTP p50 2s 与消费 14~22 eps
            # 上限的直接来源（见 PERF 报告勘误 1）。引擎本身线程安全
            # （每事件私有 :memory: 连接 + 快照租约锁），丢线程池即可。
            # 注意 to_thread 只解除事件循环饿死（GIL 下不加 CPU 并行）；
            # 吞吐提升靠预筛/批量/多进程（Wave 1-3/1-4/1-5）。
            result = await asyncio.to_thread(sigma_detector.detect_for_event, log_data)
        except Exception as e:
            logger.warning(f"[Pipeline] sigma detection failed: {e}")
            errors.append(DetectorError(
                detector="sigma", message=str(e),
                error_code=f"{type(e).__name__}:sigma_detect",
                detector_version=_sigma_version(),
            ))
            result = empty_sigma()
            result["status"] = STATUS_ERROR
        sigma_result = result

    if bool(getattr(settings, "ingest_parallel_detect", True)):
        await asyncio.gather(_run_anomaly(), _run_sigma())
    else:
        # 顺序路径 (可测): 先 anomaly 后 sigma, 与旧 log_ingestion.ingest 一致
        await _run_anomaly()
        await _run_sigma()

    # ── Sigma 命中融合 (与旧 log_ingestion.ingest 逐字段同源) ──
    if anomaly_report is None:
        anomaly_report = empty_anomaly(reasons=["anomaly_error"])
        anomaly_report.status = STATUS_ERROR
        errors.append(DetectorError(detector="anomaly", message="no_result",
                                    error_code="no_result:anomaly",
                                    detector_version=""))
    if sigma_result is None:
        sigma_result = empty_sigma()
        sigma_result["status"] = STATUS_ERROR
        errors.append(DetectorError(detector="sigma", message="no_result",
                                    error_code="no_result:sigma",
                                    detector_version=_sigma_version()))

    # P0-2：只有**待聚合**命中（阈值证据尚未产生）时不得当作 Sigma 命中。
    # 修复前只判断 detected —— 聚合规则的前置筛选命中会走到这里，
    # 把 anomaly score 抬到 Sigma severity 下限（SIG-001 high → 0.65），
    # FastPath 随后按 `_fused_conf >= 0.7` 判强信号进封禁决策，
    # 单事件就这样绕过了「窗口超阈值后才处置」的设计。
    # 引擎层已把 pending-only 的 detected 置 False；这里是防御同一契约，
    # 旧引擎/陈旧载荷下也不会复活这条路径。
    _sigma_pending_only = bool(
        (sigma_result.get("pending_aggregation") or [])
    ) and not sigma_result.get("confirmed_hits")
    if sigma_result.get("detected") and not _sigma_pending_only:
        event_type = log_data.get("event", log_data.get("type", "UNKNOWN"))
        logger.info(
            f"[Sigma] {event_type}: {sigma_result.get('rule_count')} rules hit, "
            f"types={sigma_result.get('attack_types')}, "
            f"severity={sigma_result.get('max_severity')}"
        )
        sev_floor = _SIGMA_FLOORS.get(
            str(sigma_result.get("max_severity") or "").lower(), _SIGMA_FLOOR_DEFAULT,
        )
        if anomaly_report.anomaly_score < sev_floor:
            anomaly_report.anomaly_score = sev_floor
        anomaly_report.is_anomaly = True
        if "sigma_hit" not in (anomaly_report.reasons or []):
            anomaly_report.reasons = list(anomaly_report.reasons or []) + [
                f"Sigma命中:{','.join(sigma_result.get('attack_types') or [])}"
            ]
    elif _sigma_pending_only:
        logger.info(
            "[Sigma] pending aggregation only (%s) — 不抬分、不进处置, "
            "等待 Flink 聚合窗口判定",
            sigma_result.get("pending_aggregation"),
        )

    # ── 统一契约: 状态传播 (整改方案 §二.2) ──
    # Sigma 引擎可能在**内部**吞掉单条规则的 SQL 失败并返回 detected=False,
    # 那种情况下 detect_for_event 会带上 _status=partial; 这里必须原样传播,
    # 否则「100 条规则里 1 条 critical 规则挂了」会被当成完整阴性。
    sigma_status = str(sigma_result.get("status") or (
        STATUS_DETECTED if sigma_result.get("detected") else STATUS_NOT_DETECTED))
    anomaly_status = str(getattr(anomaly_report, "status", "") or (
        STATUS_DETECTED if anomaly_report.is_anomaly else STATUS_NOT_DETECTED))

    # 失败明细：DetectorError 是「捕获异常」的权威来源（带阶段与版本），
    # DetectionResult 里的 error_code/error_message 优先用它补齐。
    err_by_detector = {e.detector: e for e in errors}
    sigma_err = err_by_detector.get("sigma")
    anom_err = err_by_detector.get("anomaly")

    detector_results = [
        DetectionResult(
            detector="sigma",
            detector_version=_sigma_version(),
            event_id=event_key,
            status=sigma_status,
            score=float(sigma_result.get("max_score") or 0.0)
            if sigma_result.get("detected") else (
                None if sigma_status in ("error", "partial", "inconclusive") else 0.0),
            score_type="sigma_max_severity_floor" if sigma_result.get("detected") else None,
            severity=str(sigma_result.get("max_severity") or "") or None,
            evidence_ids=[str(h.get("rule_id")) for h in (sigma_result.get("hits") or [])
                          if isinstance(h, dict) and h.get("rule_id")],
            rule_version=str(sigma_result.get("rule_version") or "") or None,
            error_code=str(sigma_result.get("error_code") or "")
                        or ((sigma_err.error_code if sigma_err else "") or None),
            error_message=str(sigma_result.get("error_message") or "")
                            or ((f"[{sigma_err.phase}] {sigma_err.message}"
                                 if sigma_err else "") or None),
            # 阶段进**结构化字段**（消息里的前缀保持不变）
            phase=(sigma_err.phase if sigma_err else "") or "",
        ),
        DetectionResult(
            detector="anomaly",
            detector_version=str(getattr(anomaly_detector, "version", "") or ""),
            event_id=event_key,
            status=anomaly_status,
            score=(None if anomaly_status in ("error", "inconclusive")
                   else float(anomaly_report.anomaly_score)),
            score_type="anomaly_score",
            severity=str(log_data.get("severity") or "") or None,
            analysis_window=anomaly_report.analysis_window
            if isinstance(getattr(anomaly_report, "analysis_window", None), dict) else None,
            error_code=str(getattr(anomaly_report, "error_code", "") or "")
                        or ((anom_err.error_code if anom_err else "") or None),
            error_message=str(getattr(anomaly_report, "error_message", "") or "")
                            or ((f"[{anom_err.phase}] {anom_err.message}"
                                 if anom_err else "") or None),
            # 阶段进**结构化字段**（消息里的前缀保持不变）
            phase=(anom_err.phase if anom_err else "") or "",
        ),
    ]
    analysis = AnalysisStatus.build(detector_results)

    # 融合结果写回 log_data (in-place), FastPath / audit_triage / persist 同源读取
    log_data["_anomaly"] = {
        "score": anomaly_report.anomaly_score,
        "is_anomaly": anomaly_report.is_anomaly,
        "reasons": anomaly_report.reasons,
        "sigma": anomaly_report.deviation_sigma,
        # ── 新增: 分析完整性 (整改方案 §二.2) ──
        "analysis_status": analysis.status,
        "analysis_complete": analysis.complete,
        "can_close_as_negative": analysis.can_close_as_negative,
        "detector_status": dict(analysis.detectors),
        "detector_errors": analysis.error_summary(),
    }
    log_data["_sigma"] = sigma_result

    detect_ms = (time.perf_counter() - t0) * 1000.0
    try:
        from metrics import observe_ingest_stage, inc_detector_error
        from core_metrics import inc_pipeline_result, observe_pipeline_stage
        observe_ingest_stage("detect", detect_ms / 1000.0)
        observe_pipeline_stage("detect", detect_ms / 1000.0)
        inc_pipeline_result("detect", "fail" if errors else "success")
        for err in errors:
            inc_detector_error(err.detector)
    except Exception:
        pass

    # 情报富化(2026-10-27 路线 3): 检测完成后、落库前的旁路增强。
    # 开关 settings.intel_enrich_enabled 默认关闭 —— 关闭时本步零开销零变化;
    # 开启时 IP/域名/哈希/CVE(KEV) 命中写进 log_data.raw_data.threat_intel,
    # 随 store_batch 落库可查。fail-open + 超时保护, 不引入新的丢数据点。
    try:
        from threat_intel.intel_enricher import enrich_event_if_enabled
        log_data = await enrich_event_if_enabled(log_data)
    except asyncio.CancelledError:
        raise
    except Exception:
        logger.debug("[Pipeline] intel enrich dispatch failed", exc_info=True)

    return DetectResult(
        log_data=log_data, anomaly=anomaly_report, sigma=sigma_result,
        detect_ms=detect_ms, errors=errors, analysis=analysis,
    )


async def persist_batch(session, items: list[tuple[DetectResult, str]]) -> list[PersistResult]:
    """Batch-insert DetectResults.

    items: list of (DetectResult, session_id)
    Must call event_store.store_batch (single commit). On IntegrityError, fall
    back to per-item event_store.store. Preserve eventId idempotency.
    Empty items → [].
    """
    if not items:
        return []
    from capacity import db_write_gate
    async with db_write_gate().acquire():
        return await _persist_batch_unlocked(session, items)


async def _persist_batch_unlocked(session, items: list[tuple[DetectResult, str]]) -> list[PersistResult]:
    t0 = time.perf_counter()
    from event_identity import ensure_identity, resolve
    rows = []
    for dr, session_id in items:
        stamped = ensure_identity(dr.log_data if isinstance(dr.log_data, dict) else {})
        if isinstance(dr.log_data, dict):
            dr.log_data.update(stamped)
        else:
            dr.log_data = stamped
        ident = resolve(dr.log_data)
        rows.append((
            dr.log_data,
            session_id,
            float(dr.anomaly.anomaly_score or 0.0),
            ident.correlation_id or dr.log_data.get("correlation_id", "") or "",
        ))
    from retry_policy import classify_exception

    stored_list: list = []
    item_errors: list = []
    try:
        stored_list = list(await event_store.store_batch(session, rows))
        if len(stored_list) < len(items):
            stored_list.extend([None] * (len(items) - len(stored_list)))
        item_errors = [None] * len(items)
    except IntegrityError:
        # store_batch 内部已 rollback + 逐条回退; 这里双保险不丢已成功行
        logger.warning("[Pipeline] store_batch raised IntegrityError — per-item store() fallback")
        stored_list, item_errors = await _persist_rows_one_by_one(session, rows)
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        logger.warning(
            "[Pipeline] store_batch failed (%s) — per-item fallback so successes are kept",
            type(exc).__name__,
        )
        try:
            await session.rollback()
        except Exception:
            pass
        stored_list, item_errors = await _persist_rows_one_by_one(session, rows)
    persist_ms = (time.perf_counter() - t0) * 1000.0
    try:
        from metrics import observe_ingest_stage
        from core_metrics import observe_pipeline_stage
        observe_ingest_stage("persist", persist_ms / 1000.0)
        observe_pipeline_stage("persist", persist_ms / 1000.0)
    except Exception:
        pass
    results = []
    for (dr, session_id), stored, item_exc in zip(items, stored_list, item_errors):
        if stored is None:
            verdict = classify_exception(item_exc or RuntimeError("persist failed"))
            results.append(PersistResult(
                stored=None, log_data=dr.log_data, anomaly=dr.anomaly,
                session_id=session_id, persist_ms=persist_ms,
                ok=False, retryable=verdict.retryable,
                error_class=verdict.error_class, error_code=verdict.error_code,
                error=verdict.message,
            ))
            try:
                from core_metrics import inc_pipeline_result, log_process
                from event_identity import get_event_id
                inc_pipeline_result("persist", "fail")
                log_process(
                    logger, event_id=get_event_id(dr.log_data),
                    stage="persist", result="fail",
                    reason=verdict.error_code or "persist_failed",
                )
            except Exception:
                pass
            continue
        results.append(PersistResult(
            stored=stored, log_data=dr.log_data, anomaly=dr.anomaly,
            session_id=session_id, persist_ms=persist_ms,
            idempotent=bool(getattr(stored, "idempotent", False)),
            ok=True,
        ))
        try:
            from core_metrics import inc_pipeline_result
            inc_pipeline_result("persist", "success")
        except Exception:
            pass
    return results


async def _persist_rows_one_by_one(session, rows: list) -> tuple[list, list]:
    stored_list = []
    item_errors = []
    for event_data, session_id, anomaly_score, correlation_id in rows:
        try:
            stored_list.append(await event_store.store(
                session, event_data, session_id,
                anomaly_score=anomaly_score, correlation_id=correlation_id,
            ))
            item_errors.append(None)
        except asyncio.CancelledError:
            raise
        except Exception as item_exc:
            stored_list.append(None)
            item_errors.append(item_exc)
    return stored_list, item_errors


async def dispatch(
    session_id: str,
    persist: PersistResult,
    *,
    ingestor: Any = None,
) -> DispatchResult:
    """Index background + FastPath (create_task, retries) + audit_worker.submit + event_bus.

    FastPath trigger/cooldown/dual-track (allow_blocking) MUST match current
    log_ingestion.ingest semantics. Retry on_threat_detected up to
    settings.ingest_fastpath_retries. Do not await SSH.
    """
    t0 = time.perf_counter()
    ingestor = _ingestor(ingestor)
    stored = persist.stored
    log_data = persist.log_data
    anomaly_report = persist.anomaly
    event_type = log_data.get("event", log_data.get("type", "UNKNOWN"))
    severity = log_data.get("severity", "info")
    fastpath_triggered = False
    audit_accepted = ""
    replay = bool(persist.idempotent)
    skip_side_effects = replay

    # 2b. 记忆树索引 + 滑动窗口 → 后台执行 (不阻塞 ingest 返回)。
    # 名额满了就跳过这一次索引，事件本身已经落库。重放幂等命中不再二次索引。
    if not skip_side_effects:
        event_text = json.dumps(log_data, ensure_ascii=False)
        try:
            from capacity import background_task_gate, schedule_bounded
            await schedule_bounded(
                ingestor._index_background(
                    session_id, log_data, event_text, bool(anomaly_report.is_anomaly),
                ),
                gate=background_task_gate(),
                label=f"index-{stored.id}",
            )
        except Exception as ie:
            logger.warning(f"[Pipeline] index background task spawn failed: {ie}")

    # 3. 快速响应: 异常分数极高 / severity=critical / Sigma 命中 critical → create_task
    #    (语义逐行迁移自 log_ingestion.ingest; FastPath 只此一份实现)
    # P0-2：pending-only（只有待聚合命中）不得作为强信号 ——
    # 阈值证据尚未产生，单事件只能告警/审计，封禁等 Flink SIGMA_AGGREGATE 告警。
    _sigma_info = log_data.get("_sigma") or {}
    _sigma_pending_only = bool(
        (_sigma_info.get("pending_aggregation") or [])
    ) and not _sigma_info.get("confirmed_hits")
    _sigma_confirmed = bool(_sigma_info.get("detected")) and not _sigma_pending_only
    _sigma_critical = (
        _sigma_confirmed
        and _sigma_info.get("max_severity") == "critical"
    )
    _fp_trigger = (
        anomaly_report.anomaly_score >= 0.5
        or anomaly_report.deviation_sigma >= 3
        or severity == "critical"
        or _sigma_critical
    )
    # 冷却去重: 同源(源IP+威胁类型)事件在窗口内不重复编排响应链路
    _fp_key = f"{log_data.get('src_ip', '')}|{log_data.get('threat_type') or event_type}"
    if _fp_trigger and not ingestor._fastpath_allow(_fp_key):
        logger.debug(f"[FastPath] cooldown skip: {_fp_key}")
        _fp_trigger = False
    if skip_side_effects:
        _fp_trigger = False
    if _fp_trigger:
        try:
            from response_engine import get_orchestrator
            _resp_orch = get_orchestrator()
            sigma_info = log_data.get("_sigma") or {}
            _sigma_conf_map = {"high": 0.85, "medium": 0.65, "low": 0.45}
            _sigma_conf = 0.0
            for hit in (sigma_info.get("hits") or []):
                # P0-2：待聚合命中不是结论，不参与融合置信度 ——
                # 否则 SIG-001 单条 /login 的高置信度仍会把 _fused_conf 抬过 0.7。
                if isinstance(hit, dict) and hit.get("requires_aggregation"):
                    continue
                _sigma_conf = max(
                    _sigma_conf,
                    _sigma_conf_map.get(str(hit.get("confidence") or "").lower(), 0.5),
                )
            if _sigma_confirmed and sigma_info.get("max_severity") == "critical":
                _sigma_conf = max(_sigma_conf, 0.85)
            _evt_conf = log_data.get("confidence", 0)
            try:
                _evt_conf_f = float(_evt_conf)
                if _evt_conf_f > 1:
                    _evt_conf_f = _evt_conf_f / 100.0
            except (TypeError, ValueError):
                _evt_conf_f = 0.0
            _fused_conf = min(1.0, max(
                float(anomaly_report.anomaly_score or 0) * 1.2,
                _sigma_conf,
                _evt_conf_f,
            ))
            # v5 修复(A):双轨封禁门槛
            #   强信号(Sigma critical 命中 或 融合置信度>=0.7) → FastPath 可封禁
            #   仅 severity=critical(无检测器佐证) → 仅告警, 封禁等 Audit-LLM confirmed
            # P0-2: pending-only 事件**永远**进不了强信号 —— 只能告警/审计
            # (allow_blocking=False), 执行类动作只属于 Flink SIGMA_AGGREGATE 告警。
            _strong_signal = bool(
                (not _sigma_pending_only)
                and (
                    _sigma_critical
                    or _fused_conf >= 0.7
                )
            )
            # v5 修复:不再把 low/info 抬成 high。未知级别下限取 medium
            _fp_sev = severity if severity in ("critical", "high", "medium") else "medium"
            _fp_msg = log_data.get(
                "message",
                f"异常检测快速响应: {', '.join(anomaly_report.reasons)}",
            )
            fast_threat = {
                "threat_type": log_data.get("threat_type") or event_type,
                "event": event_type,
                "confidence": _fused_conf,
                "severity": _fp_sev,
                "threat_level": _fp_sev,
                "src_ip": log_data.get("src_ip", ""),
                "dst_ip": log_data.get("dst_ip", ""),
                "message": _fp_msg,
                "reason": (
                    f"FastPath: {event_type} severity={_fp_sev} "
                    f"confidence={_fused_conf:.2f} "
                    f"sigma={bool(sigma_info.get('detected'))} "
                    f"anomaly={float(anomaly_report.anomaly_score or 0):.2f}"
                ),
                "session_id": session_id,
                "event_id": stored.id,
                "anomaly_reasons": anomaly_report.reasons,
                "response_source": (
                    "fastpath_strong" if _strong_signal else "fastpath_severity"
                ),
                "allow_blocking": _strong_signal,
            }
            # P1-H: 失败按 ingest_fastpath_retries 重试后打日志; create_task → ingest/run_many
            # 不等待 SSH/响应编排
            _fp_retries = max(0, int(getattr(settings, "ingest_fastpath_retries", 2) or 0))

            # 独立 session 后台执行, 避免与请求 session 并发冲突
            async def _fast_response(threat_info: dict, evt_id: int, sid: str):
                from models import async_session as db_session
                attempts = _fp_retries + 1
                for attempt in range(attempts):
                    try:
                        async with db_session() as s:
                            await _resp_orch.on_threat_detected(
                                session=s, threat_info=threat_info,
                                event_id=evt_id, session_id=sid,
                                allow_blocking=bool(threat_info.get("allow_blocking", True)),
                            )
                        return
                    except Exception as fp_err:
                        logger.warning(
                            f"[FastPath] Quick response attempt {attempt + 1}/{attempts} "
                            f"failed for event #{evt_id}: {fp_err}"
                        )
                        if attempt + 1 < attempts:
                            await asyncio.sleep(0.2)
                logger.error(
                    f"[FastPath] Quick response failed after {attempts} attempts "
                    f"for event #{evt_id}"
                )

            from capacity import background_task_gate, schedule_bounded
            scheduled = await schedule_bounded(
                _fast_response(fast_threat, stored.id, session_id),
                gate=background_task_gate(),
                label=f"fastpath-{stored.id}",
            )
            fastpath_triggered = scheduled
            if scheduled:
                logger.warning(
                    f"[FastPath] Quick response triggered for event #{stored.id}: "
                    f"score={anomaly_report.anomaly_score:.2f} "
                    f"mode={'strong(block-capable)' if _strong_signal else 'severity(alert-only)'}"
                )
        except Exception as fp_err:
            logger.warning(f"[FastPath] Quick response setup failed: {fp_err}")

    # 4. Audit-LLM 流水线 (有界 worker,禁止无界 create_task)
    already_audited = replay and bool(getattr(stored, "analyzed", False))
    if already_audited:
        audit_accepted = "idempotent_skip"
    else:
        ingestor._track_audit_status(stored.id, "pending", event_type=event_type)
        from audit_worker import audit_worker
        audit_accepted = await audit_worker.submit(
            session_id=session_id,
            event_id=stored.id,
            log_data=log_data,
            anomaly_report=anomaly_report,
        )
        if audit_accepted == "overflow":
            await ingestor._fallback_analysis(
                stored.id, log_data, anomaly_report, "queue_overflow",
            )
            await ingestor._mark_analyzed(
                stored.id, error="queue_overflow", status="fallback", quality="shed",
            )
        elif audit_accepted == "shed":
            ingestor._track_audit_status(
                stored.id, "pending", queued="audit_pq",
            )
        elif audit_accepted == "deferred":
            ingestor._track_audit_status(
                stored.id, "pending", queued="audit_overflow",
            )
        elif audit_accepted == "spilled":
            ingestor._track_audit_status(
                stored.id, "pending", queued="audit_spill",
            )
        elif audit_accepted == "rejected":
            ingestor._track_audit_status(
                stored.id, "pending", queued="rejected_draining",
            )

    if not skip_side_effects:
        _publish_security_event(stored.id, event_type, severity, log_data, anomaly_report)

    dispatch_ms = (time.perf_counter() - t0) * 1000.0
    try:
        from metrics import observe_ingest_stage
        from core_metrics import inc_pipeline_result, observe_pipeline_stage
        observe_ingest_stage("dispatch", dispatch_ms / 1000.0)
        observe_pipeline_stage("dispatch", dispatch_ms / 1000.0)
        inc_pipeline_result("dispatch", "success")
    except Exception:
        pass
    return DispatchResult(
        event_id=stored.id,
        fastpath=fastpath_triggered,
        audit_accepted=audit_accepted or "",
        dispatch_ms=dispatch_ms,
    )


def _publish_security_event(event_id: int, event_type: str, severity: str,
                             log_data: dict, anomaly_report: AnomalyReport) -> None:
    """security_event 总线广播 (同步, 与旧 ingest 相同载荷)。"""
    try:
        from event_bus import event_bus
        from event_identity import bus_fields
        event_bus.publish("security_event", {
            **bus_fields(stored_id=event_id, event=log_data),
            "event_type": event_type,
            "severity": severity,
            "src_ip": log_data.get("src_ip", ""),
            "dst_ip": log_data.get("dst_ip", ""),
            "message": log_data.get("message", "")[:100],
            "anomaly_score": anomaly_report.anomaly_score,
            "is_anomaly": anomaly_report.is_anomaly,
        })
    except Exception as eb_err:
        logger.warning(f"[Pipeline] event_bus publish failed: {eb_err}")


async def _detect_bounded(payloads: list[dict]) -> list[Optional[DetectResult]]:
    """按配置的扇出宽度检测。同时在飞的 detect 不超过 audit_batch_concurrency。

    等闸的时间用下游等待上限，整批墙钟用批次超时。
    单条超时或异常只让该槽位为 None（调用方记 retrying），不得拖垮整批。
    asyncio.gather 的返回值不是业务成功判定。
    """
    from capacity import batch_fanout_gate
    from retry_policy import gather_results

    if not payloads:
        return []
    width = max(1, int(getattr(settings, "audit_batch_concurrency", 8) or 8))
    budget = max(0.05, float(getattr(settings, "http_ingest_batch_timeout_s", 30) or 30))
    wait = max(0.05, float(getattr(settings, "http_ingest_downstream_wait_s", 2) or 2))
    gate = batch_fanout_gate()
    out: list[Optional[DetectResult]] = [None] * len(payloads)
    deadline = time.monotonic() + budget
    for offset in range(0, len(payloads), width):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        window = payloads[offset:offset + width]
        permit_wait = min(remaining, wait)

        async def _one(payload: dict, slot_wait: float = permit_wait, left: float = remaining) -> DetectResult:
            async with gate.acquire(timeout=slot_wait):
                return await asyncio.wait_for(detect(payload), timeout=max(0.05, left))

        try:
            part = await asyncio.wait_for(
                gather_results(*(_one(payload) for payload in window)),
                timeout=remaining,
            )
        except asyncio.TimeoutError:
            break
        except asyncio.CancelledError:
            raise
        for i, item in enumerate(part):
            if isinstance(item, DetectResult):
                out[offset + i] = item
    return out


async def run_one(session, session_id: str, log_data: dict, *, ingestor: Any = None) -> RunResult:
    """Single-event path: detect → persist_batch([one]) → dispatch.

    Used by LogIngestor.ingest (HTTP sync fallback and any one-shot caller).
    """
    t0 = time.perf_counter()
    log_data = _normalize_event(log_data)
    detected = await _detect_bounded([log_data])
    dr = detected[0] if detected else None
    if dr is None:
        rr = _incomplete_run_result(
            log_data, retryable=True,
            error="detect timeout", error_class="TimeoutError", error_code="detect_timeout",
        )
        _pipeline_metrics(rr, time.perf_counter() - t0)
        return rr
    persists = await persist_batch(session, [(dr, session_id)])
    persist = persists[0]
    if persist is None or not persist.ok or persist.stored is None:
        rr = _incomplete_run_result(
            log_data,
            retryable=bool(getattr(persist, "retryable", True)),
            error=getattr(persist, "error", "") or "persist failed",
            error_class=getattr(persist, "error_class", "") or "PersistError",
            error_code=getattr(persist, "error_code", "") or "persist_failed",
            detect_ms=dr.detect_ms,
        )
        _pipeline_metrics(rr, time.perf_counter() - t0)
        return rr
    dispatch_res = await dispatch(session_id, persist, ingestor=ingestor)
    rr = _build_run_result(
        log_data, persist, dispatch_res,
        detect_ms=dr.detect_ms,
        errors=[f"{e.detector}:{e.message}" for e in dr.errors],
    )
    _pipeline_metrics(rr, time.perf_counter() - t0)
    return rr


async def run_many(
    session,
    events: list[tuple[str, dict]],
    *,
    ingestor: Any = None,
) -> list[RunResult]:
    """Batch path: detect (isolated) → persist surviving items → dispatch each.

    events: list of (session_id, log_data)
    返回与 events 等长的 RunResult。单条失败不得把整批标成失败，也不得让
    gather 没抛错就被当成全部成功。已落库条目通过 eventId 幂等跳过副作用。
    """
    from retry_policy import classify_exception

    t0 = time.perf_counter()
    prepped = [(sid, _normalize_event(d)) for sid, d in events]
    if not prepped:
        return []
    detected = await _detect_bounded([d for _, d in prepped])
    results: list[Optional[RunResult]] = [None] * len(prepped)

    persist_items: list[tuple[DetectResult, str]] = []
    persist_idx: list[int] = []
    detect_by_idx: dict[int, DetectResult] = {}
    for i, ((sid, data), dr) in enumerate(zip(prepped, detected)):
        if dr is None:
            results[i] = _incomplete_run_result(
                data, retryable=True,
                error="detect timeout", error_class="TimeoutError",
                error_code="detect_timeout",
            )
            continue
        persist_items.append((dr, sid))
        persist_idx.append(i)
        detect_by_idx[i] = dr

    persists: list[PersistResult] = []
    if persist_items:
        try:
            persists = await persist_batch(session, persist_items)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            verdict = classify_exception(exc)
            for i in persist_idx:
                results[i] = _incomplete_run_result(
                    prepped[i][1],
                    retryable=verdict.retryable,
                    error=verdict.message,
                    error_class=verdict.error_class,
                    error_code=verdict.error_code,
                    detect_ms=detect_by_idx[i].detect_ms,
                )
            persists = []

    for i, persist in zip(persist_idx, persists):
        dr = detect_by_idx[i]
        sid = prepped[i][0]
        data = prepped[i][1]
        if persist is None or not persist.ok or persist.stored is None:
            results[i] = _incomplete_run_result(
                data,
                retryable=bool(getattr(persist, "retryable", True)) if persist else True,
                error=getattr(persist, "error", "") if persist else "persist failed",
                error_class=getattr(persist, "error_class", "") if persist else "PersistError",
                error_code=getattr(persist, "error_code", "") if persist else "persist_failed",
                detect_ms=dr.detect_ms,
            )
            continue
        try:
            dispatch_res = await dispatch(sid, persist, ingestor=ingestor)
        except Exception as e:
            logger.error(
                f"[Pipeline] dispatch failed for event #{persist.stored.id} "
                f"(session={sid}): {e}", exc_info=True,
            )
            dispatch_res = DispatchResult(event_id=persist.stored.id)
        results[i] = _build_run_result(
            persist.log_data, persist, dispatch_res,
            detect_ms=dr.detect_ms,
            errors=[f"{err.detector}:{err.message}" for err in dr.errors],
        )

    elapsed = time.perf_counter() - t0
    out: list[RunResult] = []
    for i, item in enumerate(results):
        if item is None:
            rr = _incomplete_run_result(
                prepped[i][1], retryable=True,
                error="not processed", error_code="incomplete",
            )
        else:
            rr = item
        _pipeline_metrics(rr, elapsed)
        out.append(rr)
    return out
