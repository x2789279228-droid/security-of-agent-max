# -*- coding: utf-8 -*-
"""整改方案 §八：共享事件标记必须**真的送到下游**（2026-10-20，§9.32）。

文档 §八 第 3 条：

> 但下游汇总时，必须避免同一事件仅因为出现在两条链里就被重复计算成两份独立证据。

## 缺陷

引擎**已经算好了**这个标记 —— `AttackChain.shared_event_ids` /
`overlaps_other_chain`，由 `_dedup_chains()` 填，
而它的 docstring 明写着：

> 改成把共享事件**标注出来**（`shared_event_ids`），
> 让下游知道自己不能按链累加。

**但两个序列化点都把它们丢了**：

| 序列化点 | 面向谁 |
|---|---|
| `routers/ops.py::list_chains` | 运维界面（`/api/security/chains`） |
| `tool_registry.py::_correlation_chains` | LLM（`correlation.chains` 工具载荷） |

于是那句「让下游知道自己不能按链累加」是**空头支票** ——
下游根本看不到这个标记，重复计数的风险**无法规避**，只能靠下游自己想到。

## 这类缺陷为什么难发现

* 字段**存在**、**有 docstring**、**有测试覆盖其计算**
  （`test_review_correlation.py` 的 Q8 系列）；
* 但**没有任何一条断言「有人读它」**。

**生产者写对了，不等于有人看。**
（与本轮 `test_correlation_observability_exposed.py` 记的
「`observability` 零消费方」是同一个形态。）

## 三道守卫

1. **运行时**：两个出口都必须真的带上标记（带值，不只是有 key）。
2. **静态**：全仓任何「序列化一条链」的字典字面量都必须带这两个字段 ——
   这样**将来新增**的序列化点也会被抓到。
3. **前提**：静态扫描器必须真的找得到已知的序列化点（否则它恒绿）。
"""
from __future__ import annotations

import ast
import asyncio
import io
import os
import sys

import pytest

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BACKEND)

from correlation_engine import CorrelationResult  # noqa: E402
from routers import ops as ops_router  # noqa: E402
from tool_registry import _correlation_chains  # noqa: E402

SKIP_DIRS = {"node_modules", ".venv", "venv", "__pycache__", ".git",
             "frontend", "dist", "build", ".pytest_cache", "event_archive"}


class _Chain:
    """最小 AttackChain 替身：带**共享事件**标记。"""

    def __init__(self, chain_id="c1", shared=(7,)):
        self.chain_id = chain_id
        self.pattern_name = "brute_force"
        self.confidence = 0.9
        self.events = [{"id": 1, "event_type": "SSH_BRUTE"},
                       {"id": 7, "event_type": "C2_BEACON"}]
        self.src_ips = {"1.1.1.1"}
        self.dst_ips = {"2.2.2.2"}
        self.time_span_minutes = 5.0
        self.alert = "x"
        self.partial = False
        self.actor = "1.1.1.1"
        self.shared_event_ids = list(shared)
        self.overlaps_other_chain = bool(shared)


def _result() -> CorrelationResult:
    r = CorrelationResult()
    r.chains = [_Chain()]
    r.reject_reasons = {}
    r.matched_patterns = ["port_scan_to_c2"]
    r.source_ip_count = 1
    r.total_events_analyzed = 8
    return r


# ── 1. 运行时：两个出口 ──────────────────────────────────────────────


class TestTheMarkerReachesDownstream:
    def test_the_api_payload_carries_the_shared_event_marker(self, monkeypatch):
        async def _fake_analyze(session, session_id, time_window_minutes=1440):
            return _result()

        monkeypatch.setattr(
            ops_router, "correlation_engine",
            type("E", (), {"analyze": staticmethod(_fake_analyze)}),
        )
        out = asyncio.run(ops_router.list_chains(session_id="s1", session=None))
        chain = out["chains"][0]
        assert chain.get("shared_event_ids") == [7], (
            f"/api/security/chains 没有把共享事件送出来：{chain}")
        assert chain.get("overlaps_other_chain") is True, chain

    def test_the_tool_payload_carries_the_shared_event_marker(self, monkeypatch):
        """LLM 看到的那个载荷也必须带标记 ——
        否则模型会按链累加，把同一事件当成两份独立证据。"""
        import tool_registry

        async def _fake_analyze(session, session_id, time_window_minutes=1440):
            return _result()

        monkeypatch.setattr(
            tool_registry, "correlation_engine",
            type("E", (), {"analyze": staticmethod(_fake_analyze)}),
        )
        chains = asyncio.run(_correlation_chains(None, session_id="s1"))
        chain = chains[0]
        assert chain.get("shared_event_ids") == [7], (
            f"correlation.chains 工具载荷没有带共享事件标记：{chain}")
        assert chain.get("overlaps_other_chain") is True, chain


# ── 2. 静态：任何链序列化点都必须带标记 ──────────────────────────────


def _chain_serializations() -> list:
    """找出全仓所有「序列化一条链」的字典字面量。

    判据：字典字面量里有 `chain_id` 键 —— 那是链序列化的特征字段。
    返回 [(文件:行号, 键集合)]。
    """
    out = []
    for dirpath, dirnames, filenames in os.walk(BACKEND):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            if not fn.endswith(".py"):
                continue
            p = os.path.join(dirpath, fn)
            rel = os.path.relpath(p, BACKEND).replace("\\", "/")
            try:
                tree = ast.parse(io.open(p, encoding="utf-8").read())
            except (OSError, SyntaxError):
                continue
            for node in ast.walk(tree):
                if not isinstance(node, ast.Dict):
                    continue
                keys = [k.value for k in node.keys
                        if isinstance(k, ast.Constant) and isinstance(k.value, str)]
                if "chain_id" in keys:
                    out.append((f"{rel}:{node.lineno}", set(keys)))
    return out


class TestEveryChainSerializationCarriesTheMarker:
    def test_the_scanner_finds_the_known_serialization_points(self):
        """前提守卫：扫描器必须真的找得到 —— 否则它恒绿。"""
        found = _chain_serializations()
        assert len(found) >= 2, (
            f"只找到 {len(found)} 个链序列化点：{found} —— "
            f"扫描器坏了，或序列化点改成了别的写法")

    def test_every_chain_serialization_carries_the_shared_event_marker(self):
        """每个链序列化点都必须带 `shared_event_ids` + `overlaps_other_chain`。

        这条会抓住**将来新增**的序列化点 ——
        引擎那句「让下游知道自己不能按链累加」对每个出口都要成立。
        """
        missing = []
        for where, keys in _chain_serializations():
            for need in ("shared_event_ids", "overlaps_other_chain"):
                if need not in keys:
                    missing.append(f"{where} 缺 {need}")
        assert not missing, (
            "有链的序列化点没有带共享事件标记（§八「下游不得把同一事件算成两份证据」）：\n  "
            + "\n  ".join(missing))


# ── 3. 前提：引擎确实会算出这个标记 ──────────────────────────────────


class TestTheEngineReallyProducesTheMarker:
    def test_two_chains_sharing_an_event_get_the_marker(self):
        """标记不是摆设：两条链共享一个事件时，标记必须真的被填上。"""
        from correlation_engine import AttackChain

        def _chain(cid, ids):
            c = AttackChain(
                chain_id=cid, pattern_name="p", confidence=0.9,
                events=[{"id": i, "event_type": "X"} for i in ids],
                src_ips=set(), dst_ips=set(),
                time_span_minutes=1.0, alert="",
            )
            return c

        from correlation_engine import correlation_engine as ENGINE
        a = _chain("a", [1, 2, 3])
        b = _chain("b", [3, 4, 5])
        kept = ENGINE._dedup_chains([a, b])
        assert len(kept) == 2, kept
        for c in kept:
            assert c.overlaps_other_chain is True, c
            assert c.shared_event_ids == [3], c.shared_event_ids


if __name__ == "__main__":       # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
