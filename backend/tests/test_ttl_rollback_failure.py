# -*- coding: utf-8 -*-
"""TTL/回滚失败不得伪装成功。"""
from __future__ import annotations

import pytest


class _FakeRedis:
    def __init__(self, payload=None):
        self.payload = payload
        self.removed = []
        self.deleted = []
        self.zadded = {}  # member -> score

    async def zrangebyscore(self, key, lo, hi, withscores=False):
        # 与真实 redis 一致: withscores=True 才返回 (member, score) 元组
        if withscores:
            return [("FW-RULE-1", 1.0)]
        return ["FW-RULE-1"]

    async def get(self, key):
        return self.payload

    async def exists(self, key):
        return 1 if self.payload is not None else 0

    async def zrem(self, key, member):
        self.removed.append(member)
        return 1

    async def zadd(self, key, mapping):
        self.zadded.update(mapping)
        return 1

    async def incr(self, key):
        return 1

    async def expire(self, key, ttl):
        return 1

    async def delete(self, key):
        self.deleted.append(key)
        return 1


@pytest.mark.asyncio
async def test_ssh_firewall_rollback_returns_error_when_queries_fail():
    from response_engine.ssh_firewall import SshFirewallAdapter

    fw = SshFirewallAdapter()
    fw._client = object()

    def _boom(cmd, timeout=None, skip_whitelist=False):
        raise RuntimeError("ssh down")

    fw._exec = _boom
    out = fw.rollback("FW-RULE-1")
    assert out["status"] == "error", out
    assert "状态未知" in out["message"] or "无法查询" in out["message"], out


@pytest.mark.asyncio
async def test_ttl_keeps_index_when_rollback_fails():
    from response_engine.ttl_manager import TtlManager

    redis = _FakeRedis(payload='{"action_name":"block_ip","params":{}}')
    mgr = TtlManager()

    async def _fail(rule_id, action, params):
        return {"success": False, "rule_id": rule_id}

    mgr._redis = redis
    mgr._rollback_fn = _fail
    await mgr._process_expired()
    # P2 语义升级(原子认领 + 退避): 先 zrem 认领, 失败后必须**重新入索引**
    # 按退避重试 — 不变量仍是"回滚失败时规则不得从 TTL 索引里消失",
    # 且 payload/计数器不得被清理。
    assert redis.zadded.get("FW-RULE-1") is not None, (
        "回滚失败时必须重新入索引(退避重试)")
    assert redis.deleted == [], "回滚失败时不得删除 TTL payload/计数器"


@pytest.mark.asyncio
async def test_recovery_keeps_index_when_rollback_fails():
    from response_engine.ttl_manager import TtlManager

    redis = _FakeRedis(payload=None)  # key lost
    mgr = TtlManager()

    async def _fail(rule_id, action, params):
        return {"success": False}

    mgr._redis = redis
    mgr._rollback_fn = _fail
    await mgr.recover_on_startup()
    assert redis.removed == [], "恢复失败时不得删除 TTL 索引"
