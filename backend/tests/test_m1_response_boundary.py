# -*- coding: utf-8 -*-
"""M1 响应边界回归：高危动作必须经 SafeExecutor。

覆盖：
  * block_ip 走完整检查链（白名单/参数/资产/幂等/TTL/post-validate）；
  * 同一目标 + 时长的重复封禁命中幂等，不重复写规则；
  * dry_run 不调用真实 live_fn；
  * isolate_host / dns_sinkhole 也带 SafeExecutor 审计链；
  * 低 grounding 分数会被 ⓪ 闸门拦截。
"""
from __future__ import annotations

import asyncio
import importlib
from pathlib import Path

import pytest

BACKEND = Path(__file__).resolve().parents[1]
rr = importlib.import_module("response_engine.response_registry")


class _FakePipeline:
    def __init__(self, redis):
        self.redis = redis
        self.ops = []

    def set(self, key, value, ex=None):
        self.ops.append(("set", key, value, ex))
        return self

    def zadd(self, key, mapping):
        self.ops.append(("zadd", key, mapping))
        return self

    def delete(self, key):
        self.ops.append(("delete", key))
        return self

    def zrem(self, key, member):
        self.ops.append(("zrem", key, member))
        return self

    async def execute(self):
        for op in self.ops:
            if op[0] == "set":
                self.redis.data[op[1]] = op[2]
            elif op[0] == "zadd":
                self.redis.zsets.setdefault(op[1], {}).update(op[2])
            elif op[0] == "delete":
                self.redis.data.pop(op[1], None)
            elif op[0] == "zrem":
                self.redis.zsets.get(op[1], {}).pop(op[2], None)
        return [True] * len(self.ops)


class _FakeRedis:
    def __init__(self):
        self.data = {}
        self.zsets = {}

    async def exists(self, key):
        return 1 if key in self.data else 0

    async def set(self, key, value, ex=None):
        self.data[key] = value
        return True

    async def get(self, key):
        return self.data.get(key)

    async def delete(self, key):
        self.data.pop(key, None)
        return 1

    def pipeline(self):
        return _FakePipeline(self)

    async def zrangebyscore(self, key, lo, hi, withscores=False):
        return []

    async def zrem(self, key, member):
        self.zsets.get(key, {}).pop(member, None)
        return 1


class _FakeFirewall:
    def __init__(self):
        self.block_calls = []
        self.isolate_calls = []
        self.sinkhole_calls = []
        self.last_rule_id = ""

    def block_ip(self, ip, duration=0, rule_id=""):
        self.block_calls.append((ip, duration, rule_id))
        self.last_rule_id = rule_id
        return {"status": "success", "rule_id": rule_id, "family": "ipv4"}

    def isolate_host(self, host, isolation_type="network", extra_ips=None, isolation_id=""):
        self.isolate_calls.append((host, isolation_type, extra_ips, isolation_id))
        self.last_rule_id = isolation_id
        return {
            "status": "success", "success": True, "complete": True,
            "families_applied": ["ipv4"], "families_missing": [],
            "rule_ids": [isolation_id], "isolation_id": isolation_id,
        }

    def sinkhole_domain(self, domain="", ipv4=None, ipv6=None, marker_id=""):
        self.sinkhole_calls.append((domain, ipv4, ipv6, marker_id))
        return {"status": "success", "success": True, "marker_id": marker_id,
                "backend": "hosts"}

    def run_verify_command(self, cmd, timeout=None):
        return {"success": True, "stdout": f"1 DROP {self.last_rule_id}",
                "stderr": "", "returncode": 0}


@pytest.fixture()
def boundary(monkeypatch):
    from response_engine import ssh_firewall as fw_mod
    from response_engine.safe_executor import safe_executor as se
    from response_engine.ttl_manager import ttl_manager
    from response_engine.execution_modes import execution_router, MODE_DRY_RUN

    fw = _FakeFirewall()
    fake_redis = _FakeRedis()
    monkeypatch.setattr(fw_mod, "ssh_firewall", fw)
    monkeypatch.setattr(rr, "_ensure_firewall_connected", lambda: _async_none())
    fw_mod.ssh_firewall._connected = True
    fw_mod.ssh_firewall._config["host"] = "fw-test"
    old_se_redis = se._redis
    old_ttl_redis = ttl_manager._redis
    old_router_mode = execution_router.mode
    se.set_redis(fake_redis)
    ttl_manager.set_redis(fake_redis)
    execution_router.mode = MODE_DRY_RUN
    try:
        yield fw, fake_redis, se, ttl_manager
    finally:
        se._redis = old_se_redis
        ttl_manager._redis = old_ttl_redis
        execution_router.mode = old_router_mode


async def _async_none():
    return None


@pytest.mark.asyncio
async def test_block_ip_goes_through_safe_executor_and_is_idempotent(monkeypatch):
    from response_engine import ssh_firewall as fw_mod
    from response_engine.safe_executor import safe_executor as se
    from response_engine.ttl_manager import ttl_manager
    fake = _FakeFirewall()
    fake_redis = _FakeRedis()
    monkeypatch.setattr(fw_mod, "ssh_firewall", fake)
    monkeypatch.setattr(rr, "_ensure_firewall_connected", _async_none)
    old_redis = se._redis
    old_ttl_redis = ttl_manager._redis
    se.set_redis(fake_redis)
    ttl_manager.set_redis(fake_redis)
    monkeypatch.setattr(rr, "_execution_mode", lambda: "live")
    try:
        first = await rr._block_ip("10.0.0.5", reason="probe", duration_minutes=60)
        second = await rr._block_ip("10.0.0.5", reason="probe", duration_minutes=60)
    finally:
        se._redis = old_redis
        ttl_manager._redis = old_ttl_redis

    assert first["success"] is True, first
    assert first["mode"] == "ssh_firewall_paramiko", first
    assert len(fake.block_calls) == 1, fake.block_calls
    assert first["audit"]["checks"]["whitelist"]["passed"] is True
    assert first["audit"]["checks"]["params"]["passed"] is True
    assert "asset_whitelist" in first["audit"]["checks"]
    assert first["audit"]["checks"]["idempotency"]["state"] == "evaluated"
    assert first["ttl_registered"] is True, first
    assert first["auto_unblock"]["mechanism"] == "redis_ttl", first
    assert first["auto_unblock"]["restart_survives"] is True, first

    assert second["mode"] == "idempotent_skip", second
    assert len(fake.block_calls) == 1, "重复封禁不得再次写 iptables"


@pytest.mark.asyncio
async def test_block_ip_dry_run_does_not_call_live_fn(monkeypatch):
    from response_engine import ssh_firewall as fw_mod
    from response_engine.safe_executor import safe_executor as se
    fake = _FakeFirewall()
    monkeypatch.setattr(fw_mod, "ssh_firewall", fake)
    monkeypatch.setattr(rr, "_execution_mode", lambda: "dry_run")
    old_redis = se._redis
    se._redis = None
    try:
        result = await rr._block_ip("10.0.0.6", duration_minutes=30)
    finally:
        se._redis = old_redis
    assert result["success"] is True, result
    assert result["mode"] == "dry_run", result
    assert result["would_execute"] is True
    assert fake.block_calls == [], "dry_run 不得触达真实 SSH/防火墙"


@pytest.mark.asyncio
async def test_isolate_host_and_dns_sinkhole_have_safe_executor_audit(monkeypatch):
    from response_engine import ssh_firewall as fw_mod
    fake = _FakeFirewall()
    monkeypatch.setattr(fw_mod, "ssh_firewall", fake)
    monkeypatch.setattr(rr, "_ensure_firewall_connected", _async_none)
    monkeypatch.setattr(rr, "_execution_mode", lambda: "live")

    iso = await rr._isolate_host("10.0.0.7", duration_minutes=0)
    assert iso["success"] is True, iso
    assert "asset_whitelist" in iso["audit"]["checks"]
    assert iso["audit"]["checks"]["whitelist"]["passed"] is True
    assert fake.isolate_calls and fake.isolate_calls[0][0] == "10.0.0.7"

    sink = await rr._dns_sinkhole(domain="evil.example.com")
    assert sink["success"] is True, sink
    assert sink["audit"]["checks"]["whitelist"]["skipped"] is True
    assert "sinkhole" in sink["audit"]["checks"]["whitelist"]["reason"]
    assert fake.sinkhole_calls and fake.sinkhole_calls[0][0] == "evil.example.com"


@pytest.mark.asyncio
async def test_in_progress_idempotency_does_not_double_execute(monkeypatch):
    from response_engine.safe_executor import SafeExecutor

    class _LockRedis:
        async def set(self, key, value, nx=False, ex=None):
            if nx:
                return False  # 已被另一个执行者占住
            return True

        async def get(self, key):
            return "in_progress"

        async def exists(self, key):
            return 1

    se = SafeExecutor()
    se._redis = _LockRedis()
    result = await se.execute(
        action_name="block_ip",
        command="iptables -I INPUT -s 10.0.0.9 -j DROP -m comment --comment 'FW-RULE-99999'",
        params={"src_ip": "10.0.0.9"},
        platform="linux",
        live_fn=lambda cmd: (_ for _ in ()).throw(AssertionError("must not execute")),
        mode_override="live",
    )
    assert result["mode"] == "in_progress", result
    assert result["success"] is True


@pytest.mark.asyncio
async def test_clear_idempotency_for_target_scans_prefix():
    from response_engine.safe_executor import SafeExecutor

    class _ScanRedis:
        def __init__(self):
            self.deleted = []

        async def scan_iter(self, match=None):
            assert match == "soc:idem:block_ip:10.0.0.9:*"
            yield "soc:idem:block_ip:10.0.0.9:60"

        async def delete(self, key):
            self.deleted.append(key)
            return 1

    se = SafeExecutor()
    se._redis = _ScanRedis()
    assert await se.clear_idempotency_for_target("block_ip", "10.0.0.9") == 1
    assert se._redis.deleted == ["soc:idem:block_ip:10.0.0.9:60"]


def test_error_text_redacts_url_secrets():
    from response_engine.response_executor import redact_text_for_log

    text = "POST https://hooks.example.com/notify?token=SECRET123 failed"
    out = redact_text_for_log(text)
    assert "SECRET123" not in out, out
    assert "hooks.example.com" in out


@pytest.mark.asyncio
async def test_preview_never_executes_side_effects(monkeypatch):
    """预览必须对所有动作生效，不能只覆盖 block/isolate/sinkhole。"""
    from response_engine.preview import preview_actions
    from response_engine import ssh_firewall as fw_mod

    fake = _FakeFirewall()
    monkeypatch.setattr(fw_mod, "ssh_firewall", fake)
    called = []

    async def _boom(*a, **k):
        called.append(1)
        raise AssertionError("webhook called during preview")

    monkeypatch.setattr(rr, "_send_webhook", _boom)
    actions = [
        {"name": "kill_session", "params": {"session_id": "sess-1", "user": "u"}},
        {"name": "rate_limit", "params": {"src_ip": "10.0.0.5"}},
        {"name": "send_alert", "params": {
            "title": "t", "message": "m", "webhook_url": "http://example.com/hook",
        }},
    ]
    out = await preview_actions(actions)
    assert all(x["success"] for x in out), out
    assert called == [], "预览触发了真实 webhook"
    assert fake.block_calls == [] and fake.isolate_calls == []
    for item in out:
        assert item["preview"].get("mode") == "dry_run", item


@pytest.mark.asyncio
async def test_low_grounding_score_blocks_before_execution(monkeypatch):
    from response_engine import ssh_firewall as fw_mod
    from response_engine.safe_executor import safe_executor as se
    fake = _FakeFirewall()
    monkeypatch.setattr(fw_mod, "ssh_firewall", fake)
    monkeypatch.setattr(rr, "_ensure_firewall_connected", _async_none)
    monkeypatch.setattr(rr, "_execution_mode", lambda: "live")
    old_redis = se._redis
    se._redis = None
    try:
        result = await rr._block_ip(
            "10.0.0.8", duration_minutes=30, grounding_score=0.1,
        )
    finally:
        se._redis = old_redis
    assert result["success"] is False, result
    assert result.get("blocked_by") == "grounding_gate", result
    assert fake.block_calls == [], "grounding 未通过不得触达真实执行"
