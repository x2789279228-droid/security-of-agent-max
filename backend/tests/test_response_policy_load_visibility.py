# -*- coding: utf-8 -*-
"""响应**策略文件**的加载失败必须**可见**（整改报告 §9.56）。

## 背景

`response_engine/policy_store.py::load_all` 对每个文件：

* 解析失败 / 不是映射 → `logger.warning` + **跳过**；
* 校验不过 → `logger.warning` + **跳过**。

→ **策略集静默变小**：一条有语法错的策略文件 = 那条策略**根本不存在**，
而它本该拦住的威胁因此**不被拦**，却没有任何「降级」信号。

而不对称的是：**整库**加载失败反而有可见回退
（`response_policies.reload()` → `rows=[]` → 回退代码种子 → `source="code"`）。

本守卫盯什么：

1. **文件级失败被记录**（解析失败 / 校验不过，各有 reason）；
2. **引擎**把它记进 `_load_errors`（可查）；
3. **重载端点**把失败清单一起返回（运维点「重载」就能看到少了哪几条）；
4. **计数**可数；
5. **反向判据**：健康目录**没有**失败；`load_all` 的签名与行为不变。
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND))

import pytest  # noqa: E402

GOOD_YAML = """id: POL-PROBE-OK
name: 探针正常策略
enabled: true
description: 守卫用
match:
  threat_type: PROBE
  min_confidence: 0.5
  min_severity: medium
actions:
- name: send_alert
  params:
    severity: medium
auto_execute: true
require_approval: false
priority: 10
cooldown_minutes: 30
"""

BROKEN_YAML = """id: POL-PROBE-BROKEN
name: 语法坏掉的策略
match:
  threat_type: PROBE
   min_confidence: 0.5
actions: [
"""

#: 缺 name → 校验不过
INVALID_YAML = """id: POL-PROBE-INVALID
description: 没有 name
match:
  threat_type: PROBE
actions:
- name: send_alert
"""


def _dir_with(*contents: str) -> str:
    d = tempfile.mkdtemp(prefix="policy_probe_")
    for i, c in enumerate(contents):
        with open(os.path.join(d, f"P{i}.yml"), "w", encoding="utf-8") as f:
            f.write(c)
    return d


def _count(reason: str) -> int:
    from prometheus_client import REGISTRY
    v = REGISTRY.get_sample_value(
        "soc_response_policy_load_failed_total", {"reason": reason})
    return 0 if v is None else v


class TestTheFileLevelFailuresAreReported:
    def test_a_broken_file_is_reported(self):
        from response_engine import policy_store
        d = _dir_with(GOOD_YAML, BROKEN_YAML)
        policies, errors = policy_store.load_all_with_errors(d)
        assert len(policies) == 1, policies
        assert len(errors) == 1, errors
        assert errors[0]["reason"] in ("parse", "invalid"), errors[0]
        assert errors[0]["path"], errors[0]

    def test_an_invalid_policy_is_reported(self):
        from response_engine import policy_store
        d = _dir_with(GOOD_YAML, INVALID_YAML)
        policies, errors = policy_store.load_all_with_errors(d)
        assert len(policies) == 1, policies
        assert len(errors) == 1, errors
        assert errors[0]["reason"] == "invalid", errors[0]

    def test_a_healthy_directory_has_no_errors(self):
        """**反向判据**：全都正常时不得凭空报失败。"""
        from response_engine import policy_store
        d = _dir_with(GOOD_YAML)
        policies, errors = policy_store.load_all_with_errors(d)
        assert len(policies) == 1, policies
        assert errors == [], errors

    def test_load_all_keeps_its_old_behaviour(self):
        """**反向判据**：`load_all` 的签名与返回值**不变**（只是要策略列表）。"""
        from response_engine import policy_store
        d = _dir_with(GOOD_YAML, BROKEN_YAML)
        out = policy_store.load_all(d)
        assert isinstance(out, list), out
        assert len(out) == 1, out


class TestTheEngineAndTheEndpointSeeTheFailures:
    def test_the_engine_records_the_load_errors(self):
        from response_engine.response_policies import policy_engine
        d = _dir_with(GOOD_YAML, BROKEN_YAML)
        try:
            policy_engine.reload(d)
            assert policy_engine._load_errors, "引擎没有记录加载失败"
            assert policy_engine._load_source == "yaml", policy_engine._load_source
        finally:
            policy_engine.reload()

    @pytest.mark.asyncio
    async def test_the_reload_endpoint_returns_the_failures(self, monkeypatch):
        """运维点「重载」就能看到少了哪几条。"""
        import importlib
        routers = importlib.import_module("routers.response")
        from response_engine.response_policies import policy_engine

        async def _noop_audit(*a, **k):
            return None

        monkeypatch.setattr(routers, "_audit", _noop_audit)
        d = _dir_with(GOOD_YAML, BROKEN_YAML)
        old_dir = getattr(policy_engine, "_policies_dir", None)
        try:
            # 端点不接受目录参数 → 它重载的是**默认**策略目录，
            # 所以要把引擎的 _policies_dir 指到临时目录。
            policy_engine._policies_dir = d
            out = await routers.reload_response_policies(
                session=None, request=None, user=None)
            assert out.get("failed", 0) >= 1, out
            assert out.get("load_errors"), out
        finally:
            policy_engine._policies_dir = old_dir
            policy_engine.reload()

    def test_the_failures_are_counted(self):
        from response_engine.response_policies import policy_engine
        d = _dir_with(GOOD_YAML, BROKEN_YAML)
        before = _count("parse") + _count("invalid")
        try:
            policy_engine.reload(d)
            after = _count("parse") + _count("invalid")
            assert after > before, f"失败没有被计数：{before} → {after}"
        finally:
            policy_engine.reload()


if __name__ == "__main__":       # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
