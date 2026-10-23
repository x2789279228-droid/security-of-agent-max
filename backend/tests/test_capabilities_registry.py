# -*- coding: utf-8 -*-
"""能力登记表：状态必须是三档之一，verified 必须有证据。"""
from __future__ import annotations

import pytest

from capabilities_registry import load_registry, runtime_enabled


def test_registry_loads_and_statuses_are_valid():
    reg = load_registry()
    caps = reg["capabilities"]
    assert len(caps) >= 10, caps
    assert reg["version"], "capabilities.yaml 缺少 version"
    assert reg["updated_at"], "capabilities.yaml 缺少 updated_at"
    for cap in caps:
        assert cap["status"] in {"verified", "experimental", "disabled"}, cap
        assert cap.get("id"), cap


def test_verified_capabilities_have_evidence():
    for cap in load_registry()["capabilities"]:
        if cap["status"] == "verified":
            assert cap.get("evidence"), f"{cap['id']} 标为 verified 却没有证据"
            assert cap.get("last_verified"), f"{cap['id']} 标为 verified 却没有最后验证日期"


def test_old_capability_ids_are_preserved():
    ids = {c["id"] for c in load_registry()["capabilities"]}
    for legacy in ("ndr", "edr", "threat_intel", "zeroday", "phishing"):
        assert legacy in ids, f"旧前端依赖的能力 id 丢失: {legacy}"


def test_runtime_enabled_reads_settings():
    class _S:
        kafka_enabled = True
        edr_enabled = False

    assert runtime_enabled({"runtime_setting": "kafka_enabled"}, _S) is True
    assert runtime_enabled({"runtime_setting": "edr_enabled"}, _S) is False
    assert runtime_enabled({}, _S) is True


@pytest.mark.asyncio
async def test_capabilities_endpoint_exposes_status_and_evidence():
    from routers.capabilities import capabilities_status

    out = await capabilities_status(user=None)
    assert out["capabilities"], out
    first = out["capabilities"][0]
    for key in ("id", "name", "status", "enabled", "count", "evidence", "last_verified"):
        assert key in first, first
