# -*- coding: utf-8 -*-
"""P0-3 回归：security-events-ingest 的传输包装（wrapper）schema 契约。

## 背景

HTTP 网关投递到 ``security-events-ingest`` 的是**传输包装**：

    {uuid, eventId, correlationId, type, session_id, source_id, _ts, body}

修复前该 topic 绑到 ``security_event.schema.json``（要求顶层
eventType/severity/message/timestamp），而 wrapper 只有 eventId、
其余在 body 里且键名不同 → ``produce_raw_batch`` 发送前校验失败 →
``continue`` → ``produced=0`` → 网关整批 503 not_durable。
运行环境没装 jsonschema 时校验被跳过，问题被掩盖 —— TestClient/mock
测试全绿，上了 Kafka 就是全 503。

修复后：新增 ``ingest_wrapper.schema.json`` 并在 catalog 里把
``security-events-ingest`` 绑到它；body 单独要求网关盖章的 eventId。
"""
import asyncio
import os
from pathlib import Path

import pytest

os.environ.setdefault("SHARED_MEMORY_SKIP_DOTENV", "1")

from config import settings                          # noqa: E402
from schema_registry import schema_registry          # noqa: E402

BACKEND = Path(__file__).resolve().parents[1]
TOPIC = settings.kafka_topic_ingest_process  # security-events-ingest


def _build_wrappers(n: int = 3) -> list[dict]:
    """用与 ``routers.logs._enqueue_ingest`` 完全相同的代码路径构造真实载荷。"""
    import routers.logs as logs_router

    captured = []
    from kafka_producer import kafka_producer

    async def fake_produce(messages, topic="", key_field="uuid", trace_id=""):
        captured.extend(messages)
        return len(messages)

    # _enqueue_ingest 内部 `from kafka_producer import kafka_producer`
    # 拿的是同一个单例; 替换实例方法即可拦截。
    # P1(测试基建): 前序异步测试的全局连接池绑定在**已关闭**的 pytest-asyncio
    # 循环上; 本函数用独立 asyncio.run 循环执行时会从池里拿到死连接,
    # authenticate() 的后台刷写任务永远等不到唤醒 → asyncio.run 收尾挂死。
    # 先 dispose 引擎, 让本循环建立全新连接。
    import models as _models
    try:
        asyncio.run(_models.dispose_engines())
    except Exception:
        pass
    orig = kafka_producer.produce_raw_batch
    kafka_producer.produce_raw_batch = fake_produce
    try:
        n = asyncio.run(logs_router._enqueue_ingest(
            "sess-test", "wrapper-test-key",
            [{"message": f"hello {i}", "severity": "low"} for i in range(n)]))
    finally:
        kafka_producer.produce_raw_batch = orig
    assert n == len(captured) == 3
    return captured


# ══════════════════════════════════════════════════════════════
# 1. 真实 wrapper 通过 topic 契约
# ══════════════════════════════════════════════════════════════

def test_real_wrapper_passes_topic_schema():
    """_enqueue_ingest 产出的**真实**载荷必须通过 security-events-ingest 校验。

    修复前: wrapper 顶层没有 eventType/severity/message/timestamp,
    security_event.schema.json 校验返回 4 个错误 → produced=0 → 网关 503。
    """
    pytest.importorskip("jsonschema")
    for msg in _build_wrappers():
        errors = schema_registry.validate(TOPIC, msg)
        assert not errors, f"网关 wrapper 未通过 topic 契约: {errors[:3]}"


def test_wrapper_schema_maps_to_ingest_topic():
    """topic → schema 绑定必须是 wrapper, 不是扁平 security_event。"""
    schema_file = schema_registry._schema_file_for_topic(TOPIC)
    assert schema_file == "ingest_wrapper.schema.json", (
        f"security-events-ingest 绑到了 {schema_file} —— "
        "网关 wrapper 会被发送前校验拒绝(全量 503 not_durable)")


def test_flat_security_event_rejected_by_wrapper_schema():
    """反向钉: 扁平业务事件**不满足** wrapper 契约（缺 body）。

    没有这条, 绑定回退到旧 schema 时本文件第一条会静默变绿。
    """
    pytest.importorskip("jsonschema")
    flat = {"eventId": "e1", "eventType": "BRUTE_FORCE", "severity": "high",
            "message": "m", "timestamp": 1700000000000}
    errors = schema_registry.validate(TOPIC, flat)
    assert errors, "扁平事件竟通过了 wrapper 契约 —— topic 绑定可能已回退"


def test_wrapper_requires_stamped_body_event_id():
    """body.eventId 是消费端幂等键, 缺失必须被网关侧校验拦下。"""
    pytest.importorskip("jsonschema")
    wrapper = {
        "uuid": "u1", "eventId": "e1", "type": "security_event",
        # body 缺 eventId（网关没盖章）
        "body": {"message": "no identity"},
    }
    errors = schema_registry.validate(TOPIC, wrapper)
    assert any("eventId" in e for e in errors), f"缺盖章 eventId 未被拦截: {errors}"


# ══════════════════════════════════════════════════════════════
# 2. produce_raw_batch 真实链路：produced == len(events)
# ══════════════════════════════════════════════════════════════

def test_produce_raw_batch_accepts_all_real_wrappers(monkeypatch):
    """真实 wrapper 走 produce_raw_batch 全链路（schema+cipher+gate+send），
    断言 produced == len(events)。

    修复前这里返回 0 —— 校验失败静默 continue，上游只见 503。
    """
    from kafka_producer import kafka_producer

    sent = []

    class _FakeProducer:
        def send(self, topic, key=None, value=None, headers=None):
            fut = asyncio.get_running_loop().create_future()
            sent.append((topic, key, value))
            fut.set_result(type("MD", (), {"topic": topic, "partition": 0,
                                           "offset": len(sent)})())
            return fut

    monkeypatch.setattr(kafka_producer, "_started", True, raising=False)
    monkeypatch.setattr(kafka_producer, "_producer", _FakeProducer(), raising=False)
    # cipher 密钥在测试环境未配置 → 置为恒等, 只验证 schema 门禁。
    # kafka_producer 引用的是 field_cipher 单例, 替换实例方法即可。
    from field_cipher import field_cipher as _cipher
    monkeypatch.setattr(_cipher, "encrypt_message", lambda m: m, raising=True)

    wrappers = _build_wrappers(3)
    produced = asyncio.run(kafka_producer.produce_raw_batch(
        wrappers, topic=TOPIC, key_field="uuid"))
    assert produced == len(wrappers), (
        f"produced={produced}, 期望 {len(wrappers)} —— wrapper 在发送前校验被拒")
    assert len(sent) == len(wrappers)
    for topic, _key, value in sent:
        assert topic == TOPIC
        assert isinstance(value, dict)


# ══════════════════════════════════════════════════════════════
# 3. 网关鉴权：单条/批量共用（P0-3/P0-5）
# ══════════════════════════════════════════════════════════════

def _request_with_headers(headers: dict[str, str]):
    from fastapi import Request

    scope = {
        "type": "http", "method": "POST", "path": "/api/logs/ingest/batch",
        "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()],
    }
    return Request(scope)


def test_batch_auth_rejects_invalid_key(monkeypatch):
    """无效 key 必须 403 —— 修复前 batch 只透传 header, 从不校验。"""
    from fastapi import HTTPException

    import routers.logs as logs_router
    from source_registry import source_registry

    monkeypatch.setattr(source_registry, "authenticate", lambda k: None)
    with pytest.raises(HTTPException) as exc:
        logs_router._authenticate_source(
            _request_with_headers({"X-API-Key": "forged-key"}))
    assert exc.value.status_code == 403


def test_batch_auth_accepts_valid_key(monkeypatch):
    from routers.logs import _authenticate_source
    from source_registry import source_registry

    class _Src:
        name = "sim"

    monkeypatch.setattr(source_registry, "authenticate",
                        lambda k: _Src() if k == "good-key" else None)
    got = _authenticate_source(_request_with_headers({"X-API-Key": "good-key"}))
    assert got == "good-key"


def test_batch_auth_allows_missing_key_without_kafka(monkeypatch):
    """HTTP(非 Kafka) 模式下不带 key 保持既有行为：放行（与单条接口一致）。"""
    import routers.logs as logs_router
    from source_registry import source_registry

    monkeypatch.setattr(source_registry, "authenticate", lambda k: None)
    monkeypatch.setattr(logs_router.settings, "kafka_enabled", False, raising=False)
    got = logs_router._authenticate_source(_request_with_headers({}))
    assert got == ""


def test_single_endpoint_uses_shared_auth(monkeypatch):
    """单条接口与批量走同一个 _authenticate_source（防两处漂移）。"""
    import inspect

    import routers.logs as logs_router

    single = inspect.getsource(logs_router.ingest_log)
    batch = inspect.getsource(logs_router.ingest_log_batch)
    assert "_authenticate_source(request)" in single
    assert "_authenticate_source(request)" in batch
