"""Request-Id 中间件 + 全局异常处理（生产可观测性基线）

2026-10-23 引入（第一阶段止血）：
  - 每个请求分配 request_id（透传上游 X-Request-ID，或生成 16 hex），
    写入 contextvars（日志自动携带）与响应头 X-Request-ID；
  - 记录访问日志（method/path/status/耗时/request_id），
    /metrics、/docs 等探针路径降为 DEBUG 防噪音；
  - unhandled_exception_handler：未捕获异常返回规范 500 信封
    （此前裸 500 无 JSON 体、无 request_id，排障只能翻服务端日志）。

注册顺序（Starlette 最后注册 = 最外层）：
  CORS（最外） → RequestContextMiddleware → Metrics → ... → auth（最内）。
"""
from __future__ import annotations

import logging
import time
import uuid

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from observability.logging_setup import get_request_id, log_extra, request_id_var

logger = logging.getLogger("soc.request")

# 这些路径每次健康检查/抓取都打 INFO 会淹没日志
_QUIET_PATHS = ("/metrics", "/docs", "/redoc", "/openapi.json", "/api/health")

_MAX_INBOUND_REQUEST_ID = 64


def _resolve_request_id(request: Request) -> str:
    incoming = (request.headers.get("x-request-id") or "").strip()
    # 只接受安全字符，防日志注入
    if incoming and len(incoming) <= _MAX_INBOUND_REQUEST_ID \
            and all(c.isalnum() or c in "-_" for c in incoming):
        return incoming
    return uuid.uuid4().hex[:16]


class RequestContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        request_id = _resolve_request_id(request)
        token = request_id_var.set(request_id)
        start = time.perf_counter()
        try:
            try:
                response = await call_next(request)
            except Exception:
                # 全局 exception handler 也可能接住，但中间件层异常（更外层组件抛出）
                # 只会走到这里 —— 必须在这里兜底记日志并返回规范 500。
                duration_ms = (time.perf_counter() - start) * 1000
                logger.exception(
                    "unhandled request error %s %s (%.1fms)",
                    request.method, request.url.path, duration_ms,
                    **log_extra(status=500),
                )
                response = JSONResponse(
                    status_code=500,
                    content={
                        "error": {
                            "code": "internal_error",
                            "message": "Internal server error",
                            "request_id": request_id,
                        }
                    },
                )
            response.headers["X-Request-ID"] = request_id
            duration_ms = (time.perf_counter() - start) * 1000
            level = logging.DEBUG if request.url.path in _QUIET_PATHS else logging.INFO
            logger.log(
                level, "%s %s -> %d (%.1fms)",
                request.method, request.url.path, response.status_code, duration_ms,
                **log_extra(
                    method=request.method, path=request.url.path,
                    status=response.status_code, duration_ms=round(duration_ms, 1),
                ),
            )
            return response
        finally:
            request_id_var.reset(token)


def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """FastAPI 全局 Exception handler：路由内未捕获异常 → 规范 500 信封。"""
    logger.exception(
        "unhandled exception on %s %s: %s",
        request.method, request.url.path, exc,
    )
    return JSONResponse(
        status_code=500,
        content={
            "error": {
                "code": "internal_error",
                "message": "Internal server error",
                "request_id": get_request_id(),
            }
        },
    )


__all__ = [
    "RequestContextMiddleware",
    "unhandled_exception_handler",
]
