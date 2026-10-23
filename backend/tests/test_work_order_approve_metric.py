# -*- coding: utf-8 -*-
"""工单审批的结果必须**可观测**，且「审批通过后执行响应动作」这句必须是真的
（整改方案 §十一.1，§9.36）。

## 缺陷

`_execute_approved_actions` 的名字与 docstring 都说「审批通过后执行响应动作」，
而函数体只做两件事：
  ① 取一个 `get_orchestrator()` **却从头到尾没用过**（死代码）；
  ② 把案例状态改成 `responding`。

真正的响应动作执行在**另一条路径**上
（`response_orchestrator` → 内存态 `approval_queue` → `_poll_approval`
→ `response_executor.execute_actions`）。

于是系统里有**两套并行的审批机制**：
* 内存态审批票 —— 进程重启即丢，但通过后**真的**执行动作；
* 数据库态工单审批 —— 持久、运维实际操作的是它，但通过后**不执行**任何动作。

「工单审批通过后到底要不要执行响应动作」属**产品语义决策**
（接上可能与内存票路径重复执行）→ 登记为待决项 25，本轮不擅自接。

本轮只做安全的三件事：删死代码、改正 docstring、给失败加计数。

## 本守卫盯什么

1. 三个出口各记一次（approved / skipped / failed）；
2. **死代码不得回来**（`_execute_approved_actions` 里不许再取 orchestrator）；
3. docstring 必须说清「不执行任何响应动作」——
   注释与实现不一致本身就是缺陷的一种，而它**最难被发现**。
"""
from __future__ import annotations

import asyncio
import inspect
import os
import sys

import pytest

os.environ.setdefault("SHARED_MEMORY_SKIP_DOTENV", "1")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core_metrics  # noqa: E402
from core_metrics import (  # noqa: E402
    _WORK_ORDER_APPROVE_ALLOW,
    record_work_order_approve,
)
from prometheus_client import CollectorRegistry, Counter, generate_latest  # noqa: E402
from work_order_service import WorkOrderService  # noqa: E402


class _FakeOrder:
    def __init__(self, order_id=1, approval_status="pending", case_id=7):
        self.id = order_id
        self.case_id = case_id
        self.approval_status = approval_status
        self.approved_by = ""
        self.approved_at = None
        self.status = "pending"
        self.updated_at = None
        self.order_number = "WO-TEST-1"


class _FakeCase:
    def __init__(self):
        self.id = 7
        self.event_ids = [1, 2]
        self.status = "open"
        self.updated_at = None


class _FakeSession:
    """最小 session 替身。

    `fail_case_get=True` 让**审批后的推进步骤**抛异常 ——
    用来验证「审批写进库了但推进失败」这条路径会被记成 failed。
    """

    def __init__(self, order=None, fail_case_get=False):
        self._order = order
        self._fail_case_get = fail_case_get
        self.added = []

    async def get(self, model, pk):
        name = getattr(model, "__name__", "")
        if "WorkOrder" in name:
            return self._order
        if "SecurityCase" in name:
            if self._fail_case_get:
                raise RuntimeError("case lookup failed")
            return _FakeCase()
        return None

    async def commit(self):
        return None

    def add(self, obj):
        self.added.append(obj)

    async def execute(self, *a, **k):
        raise RuntimeError("not used in this test")

    async def flush(self):
        return None


@pytest.fixture()
def fresh_counter():
    reg = CollectorRegistry()
    ctr = Counter("test_work_order_approve_total", "t", ["result"], registry=reg)
    old = core_metrics.WORK_ORDER_APPROVE
    core_metrics.WORK_ORDER_APPROVE = ctr
    try:
        yield reg
    finally:
        core_metrics.WORK_ORDER_APPROVE = old


def _value(reg, result: str) -> float:
    for metric in reg.collect():
        for sample in metric.samples:
            if sample.name == "test_work_order_approve_total" \
                    and sample.labels.get("result") == result:
                return float(sample.value)
    return 0.0


class TestTheApprovalOutcomesAreCounted:
    def test_an_approved_order_is_counted_as_approved(self, fresh_counter):
        svc = WorkOrderService()
        out = asyncio.run(svc.approve(
            _FakeSession(order=_FakeOrder()), order_id=1, approved_by="admin"))
        assert out.get("success") is True, out
        assert _value(fresh_counter, "approved") == 1.0, "审批通过没有计数"

    def test_a_missing_order_is_counted_as_skipped(self, fresh_counter):
        svc = WorkOrderService()
        out = asyncio.run(svc.approve(_FakeSession(order=None), order_id=99))
        assert out.get("success") is False, out
        assert _value(fresh_counter, "skipped") == 1.0, (
            "工单不存在没有被记成 skipped")

    def test_an_already_approved_order_is_counted_as_skipped(self, fresh_counter):
        svc = WorkOrderService()
        out = asyncio.run(svc.approve(
            _FakeSession(order=_FakeOrder(approval_status="approved")), order_id=1))
        assert out.get("success") is False, out
        assert _value(fresh_counter, "skipped") == 1.0, (
            "已审批的工单没有被记成 skipped")

    def test_a_failed_post_approval_step_is_counted_as_failed(self, fresh_counter):
        """⚠ 核心性质：审批**已经写进数据库**、但推进步骤抛异常 → failed。

        修复前这条失败只留一行 warning 日志，指标上与「审批通过」同形。
        """
        svc = WorkOrderService()
        out = asyncio.run(svc.approve(
            _FakeSession(order=_FakeOrder(), fail_case_get=True), order_id=1))
        assert out.get("success") is True, out   # 审批本身成功了
        assert _value(fresh_counter, "failed") == 1.0, (
            "推进步骤失败没有计数 —— 审批成功但推进失败在指标上看不出来")
        assert _value(fresh_counter, "approved") == 0.0, (
            "推进失败被记成了 approved")


class TestTheDeadCodeStaysDead:
    def test_the_post_approval_helper_does_not_fetch_the_orchestrator(self):
        """`get_orchestrator()` 取了却没用过 —— 死代码。

        它读起来像「审批通过后要执行响应动作」，实际不执行。
        留着它，后人会以为动作被执行了。

        ⚠ 判据必须**看代码不看文本**：docstring 里为了说明这件事
        **会提到** `get_orchestrator()` —— 用 `in src` 判定会误报
        （本轮第一版就栽在这里）。所以走 AST，只看函数体里的**调用**。
        """
        import ast
        src = inspect.getsource(WorkOrderService._execute_approved_actions)
        tree = ast.parse(src.lstrip() if src.startswith((" ", "\t")) else src)
        fn = tree.body[0]
        calls = []
        for node in ast.walk(fn):
            if isinstance(node, ast.Call):
                f = node.func
                if isinstance(f, ast.Name):
                    calls.append(f.id)
                elif isinstance(f, ast.Attribute):
                    calls.append(f.attr)
        assert "get_orchestrator" not in calls, (
            "_execute_approved_actions 里又调用了 get_orchestrator —— "
            f"它取来不用，是死代码，且会让人误以为这里会执行响应动作：{calls}")

    def test_the_docstring_says_it_does_not_execute_actions(self):
        """注释与实现不一致本身是缺陷的一种，而且**最难被发现** ——
        读代码的人会把 docstring 当成事实。"""
        doc = WorkOrderService._execute_approved_actions.__doc__ or ""
        assert "不执行任何响应动作" in doc, (
            "_execute_approved_actions 的 docstring 必须说清它**不**执行响应动作；"
            f"现在的说法是：{doc[:120]!r}")

    def test_the_helper_returns_a_bool(self):
        """返回成败供调用方记账（此前无返回值 → 失败完全不可见）。"""
        svc = WorkOrderService()
        ok = asyncio.run(svc._execute_approved_actions(
            _FakeSession(order=_FakeOrder()), _FakeOrder()))
        assert ok is True, ok
        bad = asyncio.run(svc._execute_approved_actions(
            _FakeSession(order=_FakeOrder(), fail_case_get=True), _FakeOrder()))
        assert bad is False, bad


class TestTheMetricIsReallyVisible:
    def test_the_counter_appears_in_the_metrics_text(self):
        record_work_order_approve("failed")
        text = generate_latest().decode("utf-8")
        assert "soc_work_order_approve_total" in text, (
            "/metrics 里没有 soc_work_order_approve_total")
        assert 'result="failed"' in text

    def test_the_label_allowlist_has_exactly_three_values(self):
        assert _WORK_ORDER_APPROVE_ALLOW == {"approved", "skipped", "failed"}, (
            f"白名单变了：{sorted(_WORK_ORDER_APPROVE_ALLOW)}")


if __name__ == "__main__":       # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
