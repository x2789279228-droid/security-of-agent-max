# -*- coding: utf-8 -*-
"""R8: pop_matching 遇损坏 payload 必须 zrem + dead_letter, 不许静默 continue。

修复前: `except Exception: continue` — 损坏成员永久滞留 ZSET 扫描窗口头部,
任务静默消失(无 dead_letter 可重放)且永不清除; pop_highest 对同情况有完整
清理链, 两路径行为不一致。
"""
from __future__ import annotations

import json
import os
import sys

import pytest

os.environ.setdefault("SHARED_MEMORY_SKIP_DOTENV", "1")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from audit_pq import AuditPriorityQueue, PQ_KEY, PQ_PAYLOAD_PREFIX  # noqa: E402


class FakeRedis:
    def __init__(self):
        self.kv = {}
        self.z = {}

    async def set(self, k, v, ex=None):
        self.kv[k] = v

    async def get(self, k):
        return self.kv.get(k)

    async def delete(self, *keys):
        for k in keys:
            self.kv.pop(k, None)

    async def zrange(self, key, a, b):
        return list(self.z.keys())

    async def zrem(self, key, member):
        self.z.pop(member, None)
        return 1


def _mk_pq(fake: FakeRedis) -> AuditPriorityQueue:
    pq = AuditPriorityQueue()
    pq.set_redis(fake)
    return pq


def _put(fake: FakeRedis, member: str, payload: bytes):
    fake.z[member] = 100.0
    fake.kv[f"{PQ_PAYLOAD_PREFIX}{member}"] = payload


@pytest.mark.asyncio
async def test_pop_matching_corrupt_payload_cleaned_and_dead_lettered(monkeypatch):
    fake = FakeRedis()
    _put(fake, "evt-corrupt", b"{not-json")
    _put(fake, "evt-ok-1", json.dumps({"event_id": 1, "tier": "P1"}).encode())
    _put(fake, "evt-ok-2", json.dumps({"event_id": 2, "tier": "P1"}).encode())

    dead = []
    import audit_pq as mod

    async def _rec(member, reason, detail=""):
        dead.append((member, reason))

    monkeypatch.setattr(mod, "_dead_letter", _rec)

    pq = _mk_pq(fake)
    got = []
    while True:
        p = await pq.pop_matching(lambda payload: payload.get("tier") == "P1")
        if p is None:
            break
        got.append(p["event_id"])
        if len(got) > 5:
            break

    # 两个正常任务都被弹出, 损坏的不在其中
    assert sorted(got) == [1, 2]
    # ZSET 无滞留成员(修复前 evt-corrupt 永久滞留)
    assert list(fake.z.keys()) == []
    # 损坏成员进了 dead_letter
    assert ("evt-corrupt", "payload_corrupt") in dead


@pytest.mark.asyncio
async def test_pop_matching_corrupt_increments_lost_metric(monkeypatch):
    fake = FakeRedis()
    _put(fake, "evt-bad", b"garbage{")

    import metrics as metrics_mod
    calls = []
    monkeypatch.setattr(metrics_mod, "inc_audit_pq_lost",
                        lambda reason: calls.append(reason))

    async def _no_dead(member, reason, detail=""):
        return None

    monkeypatch.setattr(audit_pq_mod(), "_dead_letter", _no_dead)

    pq = _mk_pq(fake)
    assert await pq.pop_matching(lambda p: True) is None
    assert "payload_corrupt" in calls
    assert fake.z == {}


def audit_pq_mod():
    import audit_pq as mod
    return mod
