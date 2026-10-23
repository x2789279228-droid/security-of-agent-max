"""
§十一.2「所有用于运维决策的状态词表保持一致」——
运维监控页的思维链状态不得把终态事件显示成「分析进行中」。

缺陷（routers/ops.py::observability_thought_chain）：

    status = "running"                      # ← 无条件默认
    if evt:
        st = (audit or {}).get("status") or ""
        if st in ("completed", "failed", "fallback"):
            status = st
        elif getattr(evt, "analyzed", False) and audit:
            status = "completed"
        elif raw.get("_audit_llm_error"):
            status = "failed"
    # 三个分支都不命中 → 保持 "running"

缺口：当 `evt.analyzed=True` 但 `raw_data` 里没有 `_audit_llm` 时，
三个分支全不命中，事件被**永远**显示成「分析进行中」。

这不是假设：`_mark_analyzed` 只在 `if db_evt and not db_evt.analyzed`
时才写 `_audit_llm`（log_ingestion.py:648），对**已分析过**的事件是空操作。
于是「重复处理 / 事件被别的路径标过 analyzed / 载荷写入失败」
都会留下 analyzed=True + 无 _audit_llm 的组合。

「永远停在 running」比报错更糟：运维会一直等一个永远不会结束的审核，
而事件其实早已终结。

注：本文件走**真实端点函数**，只替换 event_store / snapshot 的 IO，
确保测的是端点里的推导逻辑，而不是复制一份逻辑出来自测。
"""
from __future__ import annotations

import asyncio

import pytest

from routers import ops as ops_router
from observability import thought_events
from event_store import event_store as _real_event_store


class _Evt:
    """最小 SecurityEvent 替身：只带端点实际读取的属性。"""

    def __init__(self, *, analyzed: bool, raw_data: dict, session_id: str = ""):
        self.analyzed = analyzed
        self.raw_data = raw_data
        self.session_id = session_id


def _call(monkeypatch, evt, *, has_snapshot: bool = False):
    """驱动真实端点函数，返回它实际吐给监控页的 status。

    端点在函数体内 `from event_store import event_store`，
    因此必须打在真实单例上，打 ops_router 的模块属性无效。
    """

    async def _fake_get_by_id(session, event_id, prefer_db=False):
        return evt

    monkeypatch.setattr(
        thought_events, "snapshot", lambda eid: ({"k": 1} if has_snapshot else {})
    )
    monkeypatch.setattr(_real_event_store, "get_by_id", _fake_get_by_id)
    out = asyncio.run(
        ops_router.observability_thought_chain(event_id=1, session=None, user=None)
    )
    return out["status"]


# ── 正常路径：这些行为修复前后都应保持 ──

def test_unstarted_event_reports_running(monkeypatch):
    """尚未标记 analyzed —— 确实在飞，必须是 running。"""
    evt = _Evt(analyzed=False, raw_data={})
    assert _call(monkeypatch, evt) == "running"


@pytest.mark.parametrize("st", ["completed", "failed", "fallback"])
def test_terminal_audit_status_is_passed_through(monkeypatch, st):
    evt = _Evt(analyzed=True, raw_data={"_audit_llm": {"status": st}})
    assert _call(monkeypatch, evt) == st


def test_audit_error_reports_failed(monkeypatch):
    evt = _Evt(analyzed=False, raw_data={"_audit_llm_error": "llm timeout"})
    assert _call(monkeypatch, evt) == "failed"


def test_audit_payload_without_terminal_status_still_falls_back_to_completed(monkeypatch):
    """修复前 `elif analyzed and audit -> completed` 的行为必须保留。

    审计载荷存在但状态非终态（如 pending/skipped）时，端点原本就归为 completed。
    本次只补缺口、不改既有语义，这条钉住它。
    """
    evt = _Evt(analyzed=True, raw_data={"_audit_llm": {"quality": "llm", "summary": "x"}})
    assert _call(monkeypatch, evt) == "completed"


# ── 缺口本身 ──

def test_analyzed_event_without_audit_never_reports_running(monkeypatch):
    """核心回归：已标记 analyzed 却拿不到审计载荷时，绝不能显示 running。

    修复前该组合恒返回 "running"，且永不收敛。
    """
    evt = _Evt(analyzed=True, raw_data={})
    status = _call(monkeypatch, evt)
    assert status != "running", (
        "已 analyzed（分析已终结）的事件被显示为「分析进行中」且永不收敛"
    )


def test_analyzed_event_with_empty_audit_dict_never_reports_running(monkeypatch):
    """raw_data 里 `_audit_llm: {}`（显式空字典）与完全没有同样危险。

    `audit or {}` 会把它归一成空字典，于是 `elif analyzed and audit` 因
    audit 为假值而不命中 —— 与「没有该键」是同一条路径。
    """
    evt = _Evt(analyzed=True, raw_data={"_audit_llm": {}})
    assert _call(monkeypatch, evt) != "running"


def test_unknown_terminal_marker_is_distinct_from_running(monkeypatch):
    """补上的兜底必须是一个与 running 可区分的终态标记。

    若兜底仍写 "running"，本条与上一条同义，等于没修；
    若返回空串，监控页会渲染成空白，同样不可接受。
    """
    evt = _Evt(analyzed=True, raw_data={})
    status = _call(monkeypatch, evt)
    assert status == "unknown"


def test_emitted_status_always_from_the_declared_vocabulary(monkeypatch):
    """端点只允许吐出这一组词表里的值（§十一.2：状态词表保持一致）。"""
    allowed = {"running", "completed", "failed", "fallback", "unknown"}

    cases = [
        _Evt(analyzed=False, raw_data={}),                                    # 未开始
        _Evt(analyzed=True, raw_data={}),                                     # 缺口
        _Evt(analyzed=True, raw_data={"_audit_llm": {}}),                     # 显式空
        _Evt(analyzed=True, raw_data={"_audit_llm": {"status": "completed"}}),  # 终态
        _Evt(analyzed=True, raw_data={"_audit_llm": {"status": "fallback"}}),   # 降级
        _Evt(analyzed=False, raw_data={"_audit_llm_error": "boom"}),          # 出错
        _Evt(analyzed=True, raw_data={"_audit_llm": {"quality": "llm"}}),      # 无 status
    ]
    for evt in cases:
        st = _call(monkeypatch, evt)
        assert st in allowed, f"吐出了词表外的状态 {st!r}（evt={evt.raw_data!r}）"
