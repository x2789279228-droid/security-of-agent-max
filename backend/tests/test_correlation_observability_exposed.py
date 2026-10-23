"""
关联链的 `observability` 必须真的被运维侧看到（本轮新增）。

## 缺陷

`CorrelationResult.observability`（`correlation_engine.py:331`）算出了
`chains_matched` / `chains_partial` / `chains_overlapping` /
`reject_reasons` / `matched_patterns` / `source_ip_count`，且它的
docstring 明确写着它存在的理由：

    `chains_matched=0` 有两种完全不同的原因：
    这段时间真的没有攻击，或者模式已经退化到永远匹配不上。
    把两者压成一个数字，仪表盘就再也帮不上排障。

**但全仓零消费方。** 运维侧的 `/api/security/chains`
（`routers/ops.py::list_chains`）返回 `chains` / `temporal_groups` /
`total_events_analyzed`，**唯独没有 observability**。

后果很具体：运维在界面上看到 `chains: []` 时，
**无法区分「这段时间确实没有攻击」与「CEP 模式退化到永远匹配不上」**
—— 而这两种情况在界面上长得一模一样，正是这个属性要解决的问题。

（`total_events_analyzed` 倒是被手工复制进了响应，说明作者意识到了
需要暴露一点东西，只是漏了主体部分。）

## 为什么这类缺陷特别难被发现

字段**存在**、**有 docstring**、**有测试覆盖其计算**，
甚至验收报告 §7.1 还把它列成了已覆盖项 ——
`tests/test_review_correlation.py` 断言的是「`observability` 算得对不对」，
没有任何一条断言「有人读它」。

**生产者写对了，不等于有人看。**
这与本轮 `inc_intel_ioc` 那类缺陷同源：产出面完整，消费面为空。
"""
from __future__ import annotations

import asyncio

import pytest

from correlation_engine import CorrelationResult
from routers import ops as ops_router


class _Chain:
    """最小 AttackChain 替身：只带 list_chains 实际读取的属性。"""

    def __init__(self, chain_id="c1"):
        self.chain_id = chain_id
        self.pattern_name = "brute_force"
        self.confidence = 0.9
        self.events = [{"id": 1, "event_type": "SSH_BRUTE"}]
        self.src_ips = {"1.1.1.1"}
        self.dst_ips = {"2.2.2.2"}
        self.time_span_minutes = 5.0
        self.alert = "x"
        self.partial = False
        self.overlaps_other_chain = False


def _call(monkeypatch, result: CorrelationResult) -> dict:
    async def _fake_analyze(session, session_id, time_window_minutes=1440):
        return result

    monkeypatch.setattr(
        ops_router, "correlation_engine",
        type("E", (), {"analyze": staticmethod(_fake_analyze)}),
    )
    return asyncio.run(ops_router.list_chains(session_id="s1", session=None))


@pytest.fixture()
def empty_result() -> CorrelationResult:
    """零链 + 明确的拒绝原因 —— 正是「退化」与「没攻击」最易混淆的场景。"""
    r = CorrelationResult()
    r.reject_reasons = {"too_few_events": 7, "chain_duration_exceeded": 3}
    r.matched_patterns = []
    r.source_ip_count = 4
    r.total_events_analyzed = 42
    return r


def test_chains_endpoint_exposes_observability(monkeypatch, empty_result):
    """核心：响应里必须有 observability 块。"""
    out = _call(monkeypatch, empty_result)
    assert "observability" in out, (
        "/api/security/chains 没有返回 observability —— "
        "运维无法区分「没有攻击」与「模式退化」，"
        "而 CorrelationResult.observability 存在的唯一理由就是区分这两者"
    )


def test_exposed_observability_carries_the_reject_reason_breakdown(monkeypatch, empty_result):
    """分项拒绝原因必须真的传出去，而不只是有个空壳 key。"""
    obs = _call(monkeypatch, empty_result)["observability"]
    assert obs["reject_reasons"] == {"too_few_events": 7, "chain_duration_exceeded": 3}, \
        "被拒链的分项原因没有透出 —— 「为什么没匹配上」在运维侧仍然是黑盒"
    assert obs["chains_matched"] == 0
    assert obs["total_events_analyzed"] == 42


def test_chains_endpoint_keeps_its_existing_fields(monkeypatch, empty_result):
    """新增字段不得破坏既有响应契约。"""
    out = _call(monkeypatch, empty_result)
    for key in ("session_id", "causal_graph", "chains", "temporal_groups",
                "total_events_analyzed"):
        assert key in out, f"既有字段 {key} 丢失了"


def test_matched_chains_are_counted_separately_from_partial(monkeypatch):
    """有链时 matched / partial / overlapping 必须分列。"""
    a, b = _Chain("c1"), _Chain("c2")
    b.partial = True
    b.overlaps_other_chain = True
    r = CorrelationResult(chains=[a, b])
    r.reject_reasons = {}
    r.source_ip_count = 1

    obs = _call(monkeypatch, r)["observability"]
    assert obs["chains_matched"] == 2
    assert obs["chains_partial"] == 1
    assert obs["chains_overlapping"] == 1


def test_observability_is_the_real_property_not_a_copy(monkeypatch, empty_result):
    """防退化：端点必须复用 `CorrelationResult.observability`。

    手工再拼一份字段的话，日后 `observability` 增删字段时端点会悄悄落后 ——
    那正是本缺陷的成因。
    """
    out = _call(monkeypatch, empty_result)
    assert out["observability"] == empty_result.observability
