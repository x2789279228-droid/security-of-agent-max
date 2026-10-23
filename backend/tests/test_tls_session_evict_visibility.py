# -*- coding: utf-8 -*-
"""TLS 挂起会话被驱逐时，**证据不许静默消失**（整改方案 §十三「全量回归」行，§9.43）。

## 缺陷

`encrypted_traffic/session_collector.py` 里有两条「丢掉一个挂起会话」的路径，
行为完全不一致：

| 路径 | 修复前 | 结果 |
|---|---|---|
| 超时 `_sweep_expired` | `stats["expired"] += 1` + `await self._flush(key)` | **落库 + 计数** ✓ |
| 溢出 `_evict_oldest` | `self._pending.pop(oldest, None)` | **直接丢掉** ✗ |

实测（修复前）：

```
_flush 被调用 : []          ← 没落库
落库记录      : []          ← 没落库
stats         : {'sessions': 0, 'expired': 0, 'pending': 2000}
```

被驱逐的会话**不进 `tls_sessions`、不评分、不触发 LLM 语义判定** ——
C2 检测的证据**静默消失**，而 `stats()` 里**看不出**有任何东西被丢。
而且它恰好发生在**流量最高**的时候（>2000 个并发挂起握手），
也就是攻击最可能发生的时候。

这条路径是**活的**：`app.py:267-272` 把
`tls_session_collector.on_message` 接到 dissector 上。
而 `TlsSessionCollector` 此前**没有任何测试**。

## 本守卫盯什么

1. 溢出时被驱逐的会话**必须落库**（核心性质）；
2. 驱逐**必须被计数**（`stats["evicted"]` + `soc_tls_session_evicted_total`）；
3. 超时路径**不受影响**（原有行为不能被这次修复改坏）；
4. **不写放大**：驱逐只是把 flush 提前，落库总数不变；
5. 两条「丢弃会话」的路径**对称**（都有落库 + 计数）。

⚠ 判据用**行为**（flush 被调用 / 计数变化 / 指标值），不用源码文本。

⚠ 本仓库**没有**配 pytest 的 asyncio 自动模式（`pytest.ini` 里没有），
所以异步场景一律 `asyncio.run(...)` —— 与仓库既有写法一致。
"""
from __future__ import annotations

import asyncio
import os
import sys
import time

import pytest

os.environ.setdefault("SHARED_MEMORY_SKIP_DOTENV", "1")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core_metrics  # noqa: E402
from encrypted_traffic import session_collector as sc_mod  # noqa: E402
from encrypted_traffic.session_collector import TlsSessionCollector  # noqa: E402
from prometheus_client import CollectorRegistry, Counter  # noqa: E402


class FakeMsg:
    """最小 TLS 消息替身（只带被测代码真正读到的字段）。"""

    def __init__(self, method, src_ip="10.0.0.1", dst_ip="10.0.0.2",
                 dst_port=443, ts=None):
        self.protocol = "TLS"
        self.method = method
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.timestamp = ts if ts is not None else time.time()


@pytest.fixture()
def fresh_counter():
    """把指标换到独立注册表，避免污染全局计数。"""
    reg = CollectorRegistry()
    ctr = Counter("test_tls_session_evicted_total", "t", registry=reg)
    old = core_metrics.TLS_SESSION_EVICTED
    core_metrics.TLS_SESSION_EVICTED = ctr
    try:
        yield reg
    finally:
        core_metrics.TLS_SESSION_EVICTED = old


def _metric_value(reg, name="test_tls_session_evicted_total") -> float:
    for metric in reg.collect():
        for sample in metric.samples:
            if sample.name == name:
                return float(sample.value)
    return 0.0


def _instrument(c):
    """把 flush / persist 换成记录器（不落真库）。"""
    calls = {"flushed": [], "persisted": []}

    async def fake_flush(self, key):
        calls["flushed"].append(key)
        self._pending.pop(key, None)
        calls["persisted"].append(key)

    async def fake_persist(self, session):
        calls["persisted"].append(("persisted", getattr(session, "src_ip", "?")))

    c._flush = fake_flush.__get__(c, TlsSessionCollector)
    c._persist = fake_persist.__get__(c, TlsSessionCollector)
    return c, calls


async def _fill(c, n, ts=None, tag="10.1"):
    now = ts if ts is not None else time.time()
    for i in range(n):
        await c.on_message(FakeMsg("ClientHello",
                                   src_ip="%s.%d.%d" % (tag, i // 256, i % 256),
                                   ts=now))


class TestTheEvictedSessionIsNotLost:
    def test_the_evicted_session_is_flushed(self, fresh_counter):
        """【核心性质】缓冲区满时，被驱逐的那一条**必须落库**。

        修复前：`_evict_oldest` 直接 `pop` 掉 → 证据静默消失。
        """
        async def scenario():
            c, calls = _instrument(TlsSessionCollector())
            await _fill(c, sc_mod._MAX_PENDING)
            assert len(c._pending) == sc_mod._MAX_PENDING
            oldest = min(c._pending.items(),
                         key=lambda kv: kv[1]["first_seen"])[0]
            calls["flushed"].clear()
            await c.on_message(FakeMsg("ClientHello", src_ip="10.9.9.9"))
            return calls, oldest, c

        calls, oldest, c = asyncio.run(scenario())
        assert oldest in calls["flushed"], (
            "被驱逐的会话没有落库 —— TLS 会话静默消失，"
            "C2 检测的证据在高峰期被丢弃")
        assert oldest not in c._pending

    def test_the_eviction_is_counted(self, fresh_counter):
        """驱逐**必须被计数** —— 否则「高峰期在丢会话」不可见。"""
        async def scenario():
            c, calls = _instrument(TlsSessionCollector())
            await _fill(c, sc_mod._MAX_PENDING)
            before = c.stats["evicted"]
            await c.on_message(FakeMsg("ClientHello", src_ip="10.9.9.8"))
            return c, before

        c, before = asyncio.run(scenario())
        assert c.stats["evicted"] == before + 1, c.stats

    def test_the_eviction_is_visible_in_the_metric(self, fresh_counter):
        """指标自增 —— `stats` 全仓**没有消费方**，只加本地计数仍然不可见。"""
        async def scenario():
            c, calls = _instrument(TlsSessionCollector())
            await _fill(c, sc_mod._MAX_PENDING)
            before = _metric_value(fresh_counter)
            await c.on_message(FakeMsg("ClientHello", src_ip="10.9.9.7"))
            return _metric_value(fresh_counter), before

        after, before = asyncio.run(scenario())
        assert after == before + 1, (
            "驱逐没有进指标 —— 高峰期丢会话在 /metrics 里看不见")

    def test_no_eviction_means_no_count(self, fresh_counter):
        """反向判据：没触发驱逐就不能计数。

        只钉「驱逐会计数」而不钉「不驱逐不计数」，
        守卫会放过一个无条件计数的实现。
        """
        async def scenario():
            c, calls = _instrument(TlsSessionCollector())
            await _fill(c, 3)
            return c.stats["evicted"], _metric_value(fresh_counter)

        evicted, metric = asyncio.run(scenario())
        assert evicted == 0, evicted
        assert metric == 0.0, metric


class TestTheTimeoutPathIsUnchanged:
    def test_an_expired_session_is_still_flushed_and_counted(self, fresh_counter):
        """超时路径**不受影响**（这次修复不能改坏既有行为）。"""
        async def scenario():
            c, calls = _instrument(TlsSessionCollector())
            old = time.time() - sc_mod._SESSION_TIMEOUT - 1
            await c.on_message(FakeMsg("ClientHello", src_ip="10.0.0.9", ts=old))
            await c.on_message(FakeMsg("ClientHello", src_ip="10.0.0.10"))
            return c, calls

        c, calls = asyncio.run(scenario())
        assert ("10.0.0.9", "10.0.0.2", 443) in calls["flushed"], calls
        assert c.stats["expired"] == 1, c.stats
        assert c.stats["evicted"] == 0, c.stats


class TestTheTwoDropPathsAreSymmetric:
    def test_both_paths_flush_and_count(self, fresh_counter):
        """两条「丢弃会话」的路径必须**对称**：都有落库 + 计数。

        这条把「对称性」本身钉住 —— 将来有人只改一条路径，这条会转红。
        """
        async def scenario():
            c, calls = _instrument(TlsSessionCollector())
            old = time.time() - sc_mod._SESSION_TIMEOUT - 1
            await c.on_message(FakeMsg("ClientHello", src_ip="10.0.0.9", ts=old))
            await c.on_message(FakeMsg("ClientHello", src_ip="10.0.0.10"))
            timeout_ok = (c.stats["expired"] == 1 and bool(calls["flushed"]))

            # 填充到上限（注意：填充过程本身可能已经触发过驱逐，
            # 所以后面一律用**增量**断言，不用绝对值）
            await _fill(c, sc_mod._MAX_PENDING)
            calls["flushed"].clear()
            evicted_before = c.stats["evicted"]
            await c.on_message(FakeMsg("ClientHello", src_ip="10.9.9.6"))
            evict_ok = (c.stats["evicted"] == evicted_before + 1
                        and bool(calls["flushed"]))
            return timeout_ok, evict_ok, c.stats

        timeout_ok, evict_ok, stats = asyncio.run(scenario())
        assert timeout_ok, f"超时路径不完整：{stats}"
        assert evict_ok, f"溢出路径不完整：{stats}"

    def test_the_eviction_does_not_add_flushes(self, fresh_counter):
        """**不写放大**：驱逐只是把 flush 提前，落库总数不变。

        被驱逐的会话本来也会在 `_SESSION_TIMEOUT` 之后被 flush；
        驱逐若额外把整批都冲一遍，就成了写放大。
        """
        async def scenario():
            c, calls = _instrument(TlsSessionCollector())
            n = sc_mod._MAX_PENDING
            await _fill(c, n)
            flushed_before = len(calls["flushed"])
            await c.on_message(FakeMsg("ClientHello", src_ip="10.9.9.5"))
            return len(calls["flushed"]) - flushed_before, len(c._pending)

        delta, pending = asyncio.run(scenario())
        assert delta == 1, (
            f"一次驱逐引发了 {delta} 次 flush —— 写放大")
        assert pending == sc_mod._MAX_PENDING, pending


class TestThePremises:
    def test_the_buffer_limit_is_actually_reachable(self):
        """前提守卫：上限是个真实可达的数（否则下面几条测不到任何东西）。"""
        assert sc_mod._MAX_PENDING >= 2, sc_mod._MAX_PENDING

    def test_the_collector_is_wired_in_production(self):
        """前提守卫：这条路径是**活的**（`app.py` 接到 dissector 上）。"""
        app = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                           "app.py")
        with open(app, "rb") as fh:
            src = fh.read().decode("utf-8")
        assert "tls_session_collector.on_message" in src, (
            "app.py 里没有接线 —— 这条路径是休眠的，严重级别要重估")


if __name__ == "__main__":       # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
