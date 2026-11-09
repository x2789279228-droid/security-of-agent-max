# -*- coding: utf-8 -*-
"""R20: 滑动窗口键必须挂 TTL (P2 — Redis 内存随历史 session 单调增长)。"""
from __future__ import annotations

import os
import sys
from datetime import datetime, timezone

import pytest

os.environ.setdefault("SHARED_MEMORY_SKIP_DOTENV", "1")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class _FakeBackend:
    def __init__(self):
        self.lists: dict[str, list] = {}
        self.ttls: dict[str, int] = {}

    async def rpush(self, key, value):
        self.lists.setdefault(key, []).append(value)

    async def lpush(self, key, value):
        self.lists.setdefault(key, []).insert(0, value)

    async def lpop(self, key):
        lst = self.lists.get(key)
        return lst.pop(0) if lst else None

    async def llen(self, key):
        return len(self.lists.get(key, []))

    async def lrange(self, key, start, stop):
        return self.lists.get(key, [])[start:stop + 1]

    async def delete(self, key):
        self.lists.pop(key, None)

    async def expire(self, key, ttl_seconds):
        self.ttls[key] = ttl_seconds


@pytest.mark.asyncio
async def test_window_and_evicted_keys_get_ttl(monkeypatch):
    from sliding_window import SlidingWindow, WINDOW_KEY, EVICTED_KEY

    fb = _FakeBackend()
    sw = SlidingWindow()
    monkeypatch.setattr(sw, "backend", fb, raising=False)
    monkeypatch.setattr(sw, "max_size", 2, raising=False)  # 触发淘汰路径

    for i in range(3):
        await sw.add_message(
            session_id="sess-ttl", agent_id="agent-1", role="user", content=f"m{i}",
        )

    wkey = WINDOW_KEY.format(session_id="sess-ttl")
    ekey = EVICTED_KEY.format(session_id="sess-ttl")
    assert fb.ttls.get(wkey, 0) > 0, "窗口键必须挂 TTL"
    assert fb.ttls.get(wkey) == sw.window_minutes * 60 * 4
    assert fb.ttls.get(ekey, 0) == 24 * 3600, "淘汰键必须挂 24h TTL"
