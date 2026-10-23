"""结构化日志（生产可观测性基线）

2026-10-23 引入（第一阶段止血）：
  此前 app.py 用 basicConfig 纯文本日志，生产排障只能 grep 文本，
  且日志行与 HTTP 请求之间没有任何关联字段。本模块提供：

  1. request-id 上下文（contextvars）：RequestContextMiddleware 写入，
     任意代码 ``get_request_id()`` 读取；无请求上下文时返回 "-"。
  2. JSONLogFormatter：每行一个 JSON 对象（ts/level/logger/message/
     request_id/trace_id + extra 字段）。trace_id 从当前 OTel span 提取
     （未装 OTel 或无活动 span 时为空）。
  3. configure_logging()：按 settings.log_format 装配 root + uvicorn logger。
     env_name=prod 默认 JSON；dev/test 默认文本（本地可读性优先，
     需要时显式设 SHARED_MEMORY_LOG_FORMAT=json）。

零新依赖：formatter 用标准库 json.dumps 实现，不引入 structlog。
extra 字段约定：logger.info("msg", extra={"event_id": 42}) →
JSON 里出现 "event_id": 42；文本格式下追加为 key=value。
"""
from __future__ import annotations

import json
import logging
import sys
from contextvars import ContextVar

request_id_var: ContextVar[str] = ContextVar("request_id", default="-")

# logging.LogRecord 自带的属性，不属于业务 extra
_STD_RECORD_ATTRS = frozenset({
    "name", "msg", "args", "levelname", "levelno", "pathname", "filename",
    "module", "exc_info", "exc_text", "stack_info", "lineno", "funcName",
    "created", "msecs", "relativeCreated", "thread", "threadName",
    "processName", "process", "taskName", "message", "asctime",
})


def get_request_id() -> str:
    return request_id_var.get()


def _trace_id() -> str:
    """当前 OTel span 的 trace_id（hex）；不可用返回空串。"""
    try:
        from opentelemetry import trace
        ctx = trace.get_current_span().get_span_context()
        if ctx.is_valid:
            return format(ctx.trace_id, "032x")
    except Exception:
        pass
    return ""


class JSONLogFormatter(logging.Formatter):
    """单行 JSON 日志。extra 里传的键值对原样进入顶层字段。"""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "request_id": request_id_var.get(),
        }
        tid = _trace_id()
        if tid:
            payload["trace_id"] = tid
        for key, val in record.__dict__.items():
            if key not in _STD_RECORD_ATTRS and not key.startswith("_"):
                payload[key] = val
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        try:
            return json.dumps(payload, ensure_ascii=False, default=str)
        except Exception:
            return json.dumps({"message": record.getMessage(), "level": record.levelname})


class TextLogFormatter(logging.Formatter):
    """带 request_id 的文本日志（本地开发用）。"""

    def __init__(self) -> None:
        super().__init__(
            fmt="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        )

    def format(self, record: logging.LogRecord) -> str:
        base = super().format(record)
        rid = request_id_var.get()
        if rid != "-":
            base = f"{base} [req={rid}]"
        return base


def configure_logging() -> None:
    """装配 root + uvicorn logger。幂等可重复调用。

    注意: 只移除**本模块此前装上的** handler（_soc_owned 标记）。
    此前版本粗暴清除 root 全部 handler —— pytest 的 caplog 捕获 handler
    也挂在 root 上，import app 后所有依赖 caplog 的测试集体失明
    （全量跑挂、单文件跑复现不了的经典顺序依赖）。
    """
    from config import settings

    fmt = (getattr(settings, "log_format", "") or "").strip().lower()
    if not fmt:
        # prod 默认 JSON；dev/test 默认文本
        fmt = "json" if getattr(settings, "env_name", "dev") == "prod" else "text"
    formatter: logging.Formatter
    if fmt == "json":
        formatter = JSONLogFormatter()
    else:
        formatter = TextLogFormatter()

    root = logging.getLogger()
    if root.level in (logging.NOTSET, logging.WARNING):
        root.setLevel(logging.INFO)
    for h in list(root.handlers):
        if getattr(h, "_soc_owned", False):
            root.removeHandler(h)
    handler = logging.StreamHandler(sys.stdout)
    handler._soc_owned = True
    handler.setFormatter(formatter)
    root.addHandler(handler)

    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        lg = logging.getLogger(name)
        lg.handlers.clear()
        lg.propagate = True  # 统一经 root 的 JSON handler 输出


def log_extra(**fields) -> dict:
    """便捷封装：logger.info("...", **log_extra(event_id=42))。"""
    return {"extra": fields}


__all__ = [
    "JSONLogFormatter",
    "TextLogFormatter",
    "configure_logging",
    "get_request_id",
    "log_extra",
    "request_id_var",
]
