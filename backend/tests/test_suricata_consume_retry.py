# -*- coding: utf-8 -*-
"""R9: Suricata Kafka 消费循环必须有监督重启 (P2)。

修复前整个 _consume_loop 包在一次性 try/except 中 — broker 重启/网络抖动
一次, 消费任务死亡且 _running 仍 True, 之后 EVE 告警静默消失。

验证: 假 AIOKafkaConsumer 第一次 start() 抛 ConnectionError, 第二次成功并
产出一条告警 → 断言循环仍在(第二次尝试发生)且告警经 process_eve 处理;
以及连续失败时退避封顶 30s。
"""
from __future__ import annotations

import asyncio
import os
import sys

import pytest

os.environ.setdefault("SHARED_MEMORY_SKIP_DOTENV", "1")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class _FlakyConsumer:
    """第一次 start 抛 ConnectionError, 之后正常消费一条消息。"""

    starts = 0
    created = []

    def __init__(self, *a, **k):
        type(self).created.append(self)
        self._stopped = False

    async def start(self):
        type(self).starts += 1
        if type(self).starts == 1:
            raise ConnectionError("broker restarting")
        # 第二次: 吐一条消息后让循环自然结束(_running 置 False)
        self._msg = {"timestamp": "2026-10-29T00:00:00", "event_type": "alert",
                     "signature_id": 1001, "signature": "ET test",
                     "src_ip": "1.2.3.4", "dest_ip": "5.6.7.8", "severity": 3}

    def __aiter__(self):
        return self

    async def __anext__(self):
        if getattr(self, "_msg", None) is not None:
            m = self._msg
            self._msg = None

            class _M:
                value = m
            return _M()
        raise StopAsyncIteration

    async def stop(self):
        self._stopped = True


@pytest.mark.asyncio
async def test_consume_loop_survives_transient_failure(monkeypatch):
    import ids_connector.suricata_connector as mod

    from ids_connector.suricata_connector import SuricataConnector

    monkeypatch.setattr(mod, "settings", mod.settings, raising=False)
    monkeypatch.setattr(mod.settings, "suricata_eve_topic", "suricata-eve", raising=False)
    import aiokafka
    monkeypatch.setattr(aiokafka, "AIOKafkaConsumer", _FlakyConsumer)

    conn = SuricataConnector()
    processed = []

    async def _spy(eve):
        processed.append(eve)
        conn._running = False  # 处理完即退出循环
        return None

    monkeypatch.setattr(conn, "process_eve", _spy)
    conn._running = True

    # 退避别真睡 1s
    sleeps = []

    async def _fast_sleep(s):
        sleeps.append(s)

    monkeypatch.setattr(mod.asyncio, "sleep", _fast_sleep)

    await asyncio.wait_for(conn._consume_loop(), timeout=5)

    assert _FlakyConsumer.starts >= 2, "首次失败后必须有第二次尝试(监督重启缺失)"
    assert len(processed) == 1, "恢复后消息应被 process_eve 处理"
    assert sleeps and sleeps[0] >= 1.0, "失败后应有退避再重试"


@pytest.mark.asyncio
async def test_consume_loop_backoff_capped(monkeypatch):
    """连续失败: 退避 1→2→4→... 封顶 30s。"""
    import ids_connector.suricata_connector as mod
    from ids_connector.suricata_connector import SuricataConnector

    class _AlwaysFail:
        starts = 0

        def __init__(self, *a, **k):
            pass

        async def start(self):
            type(self).starts += 1
            if type(self).starts >= 5:
                conn._running = False  # 5 次后外部停止
            raise ConnectionError("down")

        async def stop(self):
            return None

    import aiokafka
    monkeypatch.setattr(aiokafka, "AIOKafkaConsumer", _AlwaysFail)

    conn = SuricataConnector()
    conn._running = True
    sleeps = []

    async def _fast_sleep(s):
        sleeps.append(s)

    monkeypatch.setattr(mod.asyncio, "sleep", _fast_sleep)

    await asyncio.wait_for(conn._consume_loop(), timeout=5)

    assert sleeps, "无退避即无重试"
    assert all(s <= 30.0 for s in sleeps), f"退避应封顶 30s: {sleeps}"
    # 序列形如 1,2,4,8... (前一次成功则复位, 这里全失败所以递增)
    assert sleeps[0] == 1.0
    for a, b in zip(sleeps, sleeps[1:]):
        assert b == min(a * 2, 30.0)
