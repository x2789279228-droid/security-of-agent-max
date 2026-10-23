# -*- coding: utf-8 -*-
"""案例自动派单的结果必须**可观测**（整改方案 §十一.1，§9.34）。

## 缺陷

`_maybe_auto_dispatch` 的失败路径只有一行 `logger.warning`：

    except Exception as e:
        logger.warning(f"[Case] auto-dispatch failed: {e}")
        return False

后果（生产侧）：
  · 案例**已经建好并提交**，但**没有工单**、没人被叫醒；
  · 案例停在 `open`，在指标上与「本来就不需要派单」**完全同形**；
  · 唯一痕迹是一行日志 —— 没有任何计数。

而它的返回值本身把两件事混成同一个 `False`：
「优先级不够、不需要派单」与「**派单失败了**」。

## 本守卫盯什么

1. 三个出口各记一次，且 **`failed` 与 `skipped` 必须是不同的计数**；
2. 指标**真的**出现在 /metrics 文本里（声明了却没注册 = 没人看得到）；
3. 标签白名单正好三个值（多一个少一个都会让归并悄悄发生）。
"""
from __future__ import annotations

import asyncio
import os
import sys

import pytest

os.environ.setdefault("SHARED_MEMORY_SKIP_DOTENV", "1")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core_metrics  # noqa: E402
from core_metrics import (  # noqa: E402
    _CASE_DISPATCH_RESULT_ALLOW,
    record_case_auto_dispatch,
)
from prometheus_client import CollectorRegistry, Counter, generate_latest  # noqa: E402


class _FakeResult:
    def __init__(self, value=None):
        self._value = value

    def scalar_one_or_none(self):
        return self._value


class _FakeSession:
    """只实现 `_maybe_auto_dispatch` 用到的那几个方法。"""

    def __init__(self, existing=None, boom=False):
        self._existing = existing
        self._boom = boom

    async def execute(self, *a, **k):
        if self._boom:
            raise RuntimeError("db down")
        return _FakeResult(self._existing)

    async def get(self, *a, **k):
        return None


class _FakeCase:
    def __init__(self, priority="high", status="open"):
        self.id = 1
        self.priority = priority
        self.status = status
        self.title = "t"
        self.case_number = "CASE-1"


@pytest.fixture()
def fresh_counter():
    """把派单计数器绑到独立注册表，测试之间互不污染。"""
    reg = CollectorRegistry()
    ctr = Counter("test_case_auto_dispatch_total", "t", ["result"], registry=reg)
    old = core_metrics.CASE_AUTO_DISPATCH
    core_metrics.CASE_AUTO_DISPATCH = ctr
    try:
        yield reg
    finally:
        core_metrics.CASE_AUTO_DISPATCH = old


def _value(reg, result: str) -> float:
    for metric in reg.collect():
        for sample in metric.samples:
            if sample.name == "test_case_auto_dispatch_total" \
                    and sample.labels.get("result") == result:
                return float(sample.value)
    return 0.0


def _dispatch(case, session):
    from case_manager import case_manager
    return asyncio.run(case_manager._maybe_auto_dispatch(session, case))


class TestTheThreeOutcomesAreCounted:
    def test_a_skipped_dispatch_is_counted_as_skipped(self, fresh_counter):
        """优先级不够 → skipped。"""
        case = _FakeCase(priority="low")
        assert _dispatch(case, _FakeSession()) is False
        assert _value(fresh_counter, "skipped") == 1.0, (
            "「不需要派单」没有计数")

    def test_a_successful_dispatch_is_counted_as_ok(self, fresh_counter):
        """已有工单、只补状态 → ok。"""
        case = _FakeCase(priority="high", status="responding")
        assert _dispatch(case, _FakeSession(existing=42)) is True
        assert _value(fresh_counter, "ok") == 1.0, "成功派单没有计数"

    def test_a_failed_dispatch_is_counted_as_failed(self, fresh_counter):
        """⚠ 核心性质：**派单失败必须被计数**。

        修复前它只有一行 warning 日志 ——
        案例建好了却没人派单，在指标上与「不需要派单」完全同形。
        """
        case = _FakeCase(priority="high")
        assert _dispatch(case, _FakeSession(boom=True)) is False
        assert _value(fresh_counter, "failed") == 1.0, (
            "派单失败没有计数 —— 案例已建但没有工单这件事在指标上不可见")

    def test_failed_and_skipped_are_different_counters(self, fresh_counter):
        """「派单失败」与「不需要派单」必须**分开** ——
        只有前者需要人介入。"""
        _dispatch(_FakeCase(priority="low"), _FakeSession())
        _dispatch(_FakeCase(priority="high"), _FakeSession(boom=True))
        assert _value(fresh_counter, "skipped") == 1.0
        assert _value(fresh_counter, "failed") == 1.0
        assert _value(fresh_counter, "ok") == 0.0


class TestTheMetricIsReallyVisible:
    def test_the_counter_appears_in_the_metrics_text(self):
        """声明了却没注册 = 没人看得到。

        这条从**默认注册表**导出（不是测试替身），
        所以它验证的是「真实 /metrics 里真的有这一行」。
        """
        record_case_auto_dispatch("failed")
        text = generate_latest().decode("utf-8")
        assert "soc_case_auto_dispatch_total" in text, (
            "/metrics 里没有 soc_case_auto_dispatch_total —— "
            "指标声明了却没注册 = 没有任何面板能看见它")
        assert 'result="failed"' in text, text[-2000:]

    def test_the_label_allowlist_has_exactly_three_values(self):
        assert _CASE_DISPATCH_RESULT_ALLOW == {"ok", "skipped", "failed"}, (
            "派单结果的白名单变了：多一个值会被归并、"
            "少一个值则该结果会被记成别的 —— "
            f"现在的是 {sorted(_CASE_DISPATCH_RESULT_ALLOW)}")

    def test_an_unknown_result_is_clamped_to_failed(self):
        """未知取值必须落到**保守**的一侧（failed），
        而不是悄悄变成「成功」。"""
        from core_metrics import clamp_label
        assert clamp_label("whatever", _CASE_DISPATCH_RESULT_ALLOW, "failed") == "failed"


if __name__ == "__main__":       # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
