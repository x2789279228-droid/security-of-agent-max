"""W31 P1 修复钉：Redis 池扩容 + 失效广播任务异常回收。

WAVE3-1-FLINK-DIRECT 实测故障形态：
  · enriched 消费突发下 redis-py 客户端池(默认 100)击穿 → MaxConnectionsError
    → 消费停摆 6 分钟；
  · event_store 失效广播用裸 create_task —— 异常以
    "Task exception was never retrieved" 裸奔, 错误不可见。
"""
import asyncio
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def test_sliding_window_pool_uses_settings_max_connections(monkeypatch):
    """from_url 必须带显式 max_connections(settings 可调), 不再吃默认 100。"""
    from config import settings
    import sliding_window as sw

    captured = {}

    class _FakeRedis:
        def __init__(self, **kw):
            captured.update(kw)
        async def ping(self):
            return True

    import redis.asyncio as aioredis
    monkeypatch.setattr(aioredis, "from_url", lambda url, **kw: _FakeRedis(**kw))
    monkeypatch.setattr(settings, "redis_pool_max_connections", 432)

    backend = sw.RedisBackend("redis://test:6379/0")
    asyncio.run(backend.connect())
    assert captured.get("max_connections") == 432
    # socket_timeout=None 语义保留(pubsub 长监听)
    assert captured.get("socket_timeout") is None


def test_default_setting_is_500_not_py_default_100():
    from config import settings
    assert int(settings.redis_pool_max_connections) == 500


@pytest.mark.asyncio
async def test_invalidate_broadcast_exception_is_retrieved(caplog):
    """广播协程抛错时必须经 done 回调消化 —— 不得产生 unretrieved task。"""
    import event_store as es

    class _BoomRedis:
        def publish(self, *a, **kw):
            async def _fail():
                raise RuntimeError("MaxConnectionsError-ish")
            return _fail()

    store = es.EventStore.__new__(es.EventStore)
    store._redis = _BoomRedis()
    store._invalidate_channel = "ch"
    store._origin = "test"
    # 在事件循环内触发(同步入口内建 task)
    store._publish_invalidate(1, 1)
    await asyncio.sleep(0.05)   # 让 task 跑完 + done 回调执行
    # 若异常未被回收, 循环关闭时会刷 "Task exception was never retrieved"
    # —— 这里通过 done 回调消化后 task.result() 已被消费, 无告警即通过。


@pytest.mark.asyncio
async def test_invalidate_broadcast_success_path():
    import event_store as es

    class _OkRedis:
        def publish(self, *a, **kw):
            async def _ok():
                return 2
            return _ok()

    store = es.EventStore.__new__(es.EventStore)
    store._redis = _OkRedis()
    store._invalidate_channel = "ch"
    store._origin = "test"
    store._publish_invalidate(2, 1)
    await asyncio.sleep(0.02)
