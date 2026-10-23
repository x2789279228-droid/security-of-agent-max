"""Request-Id 中间件 + 全局异常处理 + 结构化日志（2026-10-23 第一阶段止血）

覆盖:
  - 每个响应带 X-Request-ID; 上游传入的合法 id 被透传
  - 恶意/超长 X-Request-ID 被替换为生成的 id (防日志注入)
  - 路由内未捕获异常 → 500 规范信封(含 request_id), 不再裸 500
  - JSONLogFormatter 输出单行 JSON 且携带 request_id
  - 真实 app 上 /api/health 亦带 X-Request-ID
"""
import json
import logging

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from observability.logging_setup import JSONLogFormatter, get_request_id, request_id_var
from observability.request_middleware import RequestContextMiddleware, unhandled_exception_handler


def _make_app() -> FastAPI:
    app = FastAPI()
    app.add_middleware(RequestContextMiddleware)
    app.add_exception_handler(Exception, unhandled_exception_handler)

    @app.get("/echo-ok")
    async def ok():
        return {"request_id": get_request_id()}

    @app.get("/boom")
    async def boom():
        raise ValueError("exploded")

    return app


def test_response_carries_request_id():
    c = TestClient(_make_app(), raise_server_exceptions=False)
    r = c.get("/echo-ok")
    assert r.status_code == 200
    rid = r.headers["x-request-id"]
    assert rid and len(rid) <= 64
    # 路由内读到的 request_id 与响应头一致
    assert r.json()["request_id"] == rid


def test_inbound_request_id_is_passthrough():
    c = TestClient(_make_app(), raise_server_exceptions=False)
    r = c.get("/echo-ok", headers={"X-Request-ID": "abc-123_XYZ"})
    assert r.headers["x-request-id"] == "abc-123_XYZ"


def test_malicious_request_id_is_replaced():
    c = TestClient(_make_app(), raise_server_exceptions=False)
    evil = "id with spaces\ninjected-log-line"
    r = c.get("/echo-ok", headers={"X-Request-ID": evil})
    rid = r.headers["x-request-id"]
    assert rid != evil
    assert all(ch.isalnum() or ch in "-_" for ch in rid)


def test_unhandled_exception_returns_envelope_with_request_id():
    c = TestClient(_make_app(), raise_server_exceptions=False)
    r = c.get("/boom")
    assert r.status_code == 500
    body = r.json()
    assert body["error"]["code"] == "internal_error"
    assert body["error"]["request_id"] == r.headers["x-request-id"]


def test_json_formatter_emits_single_line_json_with_request_id():
    token = request_id_var.set("test-rid-42")
    try:
        rec = logging.LogRecord(
            name="unit", level=logging.INFO, pathname=__file__, lineno=1,
            msg="hello %s", args=("world",), exc_info=None,
        )
        line = JSONLogFormatter().format(rec)
    finally:
        request_id_var.reset(token)
    payload = json.loads(line)  # 单行合法 JSON
    assert payload["message"] == "hello world"
    assert payload["request_id"] == "test-rid-42"
    assert payload["level"] == "INFO"


def test_real_app_health_carries_request_id():
    """真实 app(全中间件栈)上 request-id 也不缺位。"""
    from app import app
    c = TestClient(app)
    r = c.get("/api/health")
    assert r.status_code == 200
    assert "x-request-id" in r.headers
