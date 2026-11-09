# -*- coding: utf-8 -*-
"""R6: 优雅停机必须清理 5 个采集引擎 (P1-9)。

修复前: app.py 启动了 capture_engine/pcap_store/flow_aggregator/edr_adapter/
suricata_connector 五个长任务引擎, 但 lifecycle.shutdown_platform() 从不调用
它们的 stop() —— capture_enabled 时停机丢 PCAP 尾包、pcap_files 缺最后一条
记录、在途 flow 丢弃。

本测试: monkeypatch 五个单例为 AsyncMock, 断言
  1) shutdown_platform() 逐个 await 了全部 5 个 stop();
  2) 全部 stop 发生在 DB dispose 之前;
  3) 单个引擎 stop 抛异常不阻断其余引擎与后续停机流程。
"""
from __future__ import annotations

import os
import sys
from unittest.mock import AsyncMock

import pytest

os.environ.setdefault("SHARED_MEMORY_SKIP_DOTENV", "1")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

ENGINE_ATTRS = [
    ("traffic_capture.capture_engine", "capture_engine"),
    ("ids_connector.suricata_connector", "suricata_connector"),
    ("edr_fusion.edr_adapter", "edr_adapter"),
    ("traffic_capture.pcap_store", "pcap_store"),
    ("traffic_capture.flow_aggregator", "flow_aggregator"),
]


@pytest.mark.asyncio
async def test_shutdown_platform_stops_all_five_engines(monkeypatch):
    import lifecycle

    calls: list[str] = []
    mocks = {}
    for mod_name, attr in ENGINE_ATTRS:
        m = AsyncMock()
        m.stop.side_effect = lambda *a, _n=attr, **k: calls.append(_n)
        mocks[attr] = m
        module = __import__(mod_name, fromlist=[attr])
        monkeypatch.setattr(module, attr, m)

    async def _fake_dispose():
        calls.append("__dispose__")

    monkeypatch.setattr("models.dispose_engines", _fake_dispose)

    # 其余停机依赖(Redis/Kafka 等)在测试进程多半未起 — 各自包了 try/except,
    # 但为避免真实连接尝试拖慢, 把已知入口一并 mock 掉。
    async def _noop(*a, **k):
        return None

    for mod_name, attr in [
        ("audit_worker", "audit_worker"),
        ("scheduler", "scheduler"),
        ("event_bus", "event_bus"),
        ("summary_compression.summary", "summary"),
        ("summary_compression", "embedder"),
        ("sliding_window", "sliding_window"),
    ]:
        try:
            module = __import__(mod_name, fromlist=[attr])
            obj = getattr(module, attr)
            monkeypatch.setattr(obj, "stop", AsyncMock(side_effect=lambda *a, _n=attr, **k: calls.append(_n)), raising=False)
        except Exception:
            pass
    monkeypatch.setattr("drain.drain.begin", lambda: None, raising=False)
    monkeypatch.setattr("drain.drain.mark_stopped", lambda: None, raising=False)
    monkeypatch.setattr("config.settings.kafka_enabled", False, raising=False)
    try:
        from response_engine.human_approval import approval_queue
        monkeypatch.setattr(approval_queue, "drain_persistence", AsyncMock(_noop), raising=False)
    except Exception:
        pass

    await lifecycle.shutdown_platform()

    for _, attr in ENGINE_ATTRS:
        assert attr in calls, f"{attr}.stop() 未被停机路径调用"
    # 存储刷写在 DB dispose 之前
    assert calls.index("__dispose__") == len(calls) - 1
    assert calls.index("pcap_store") < calls.index("__dispose__")
    assert calls.index("flow_aggregator") < calls.index("__dispose__")


@pytest.mark.asyncio
async def test_engine_stop_failure_does_not_break_shutdown(monkeypatch):
    import lifecycle

    ok = AsyncMock()
    ok.stop.side_effect = lambda *a, **k: None
    boom = AsyncMock()
    boom.stop.side_effect = RuntimeError("x")

    mod_cap = __import__("traffic_capture.capture_engine", fromlist=["capture_engine"])
    mod_pc = __import__("traffic_capture.pcap_store", fromlist=["pcap_store"])
    monkeypatch.setattr(mod_cap, "capture_engine", boom)
    monkeypatch.setattr(mod_pc, "pcap_store", ok)

    monkeypatch.setattr("drain.drain.begin", lambda: None, raising=False)
    monkeypatch.setattr("drain.drain.mark_stopped", lambda: None, raising=False)
    monkeypatch.setattr("config.settings.kafka_enabled", False, raising=False)
    monkeypatch.setattr("models.dispose_engines", AsyncMock())

    # capture_engine.stop 抛错不向上传播, pcap_store 仍被 flush, 停机走完
    await lifecycle.shutdown_platform()
    assert ok.stop.await_count == 1
