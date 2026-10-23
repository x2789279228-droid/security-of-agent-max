"""
P1-b 负面测试 ③: D-4 CAD 独立证据核验

修复前的两个真实缺陷：

A) **`extra = actual_set - claimed_set` 是恒空集死代码。**
   ```python
   actual_events = [await get_by_id(eid) for eid in claimed_ids]   # ← 只查 claimed
   actual_ids   = [e.id for e in actual_events]
   extra = actual_set - claimed_set     # actual_set ⊆ claimed_set → 恒为空
   ```
   于是「数据库中存在但 Agent 未引用」这条分支**永远不会触发**。
   读起来像做了双向核对，实际只单向核对了「声称的 ID 是否存在」。

B) **`evidence_quotes` 从未被读取。**
   断言携带 `evidence_quotes`（CAD 的数据模型里都有这个字段），
   但 `verify_claims` 只用 `claimed_ids` 查存在性。
   结果：Agent 声称「引用了 failed password for root」，
   而那条事件里根本没有这句话 —— 照样 `verified=True`，
   并且计入 `evidence_completeness`，让 CAD 报告显得一切正常。

真正独立的核验应该是：拿声称的引用原文去比对**事件的真实字段**。

验收: 新测试在旧代码下失败，修复后通过。
"""
import asyncio
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ.setdefault("SHARED_MEMORY_DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("SHARED_MEMORY_JWT_SECRET", "test-secret")
os.environ.setdefault("SHARED_MEMORY_LLM_API_KEY", "test")
os.environ.setdefault("SHARED_MEMORY_EMBEDDING_API_KEY", "test")
os.environ.setdefault("SHARED_MEMORY_ADMIN_PASSWORD", "test")

import sqlalchemy.ext.asyncio as _sa_async

_orig = _sa_async.create_async_engine


def _patched(url, **kw):
    for k in ("pool_size", "max_overflow", "pool_pre_ping", "pool_recycle"):
        kw.pop(k, None)
    return _orig(url, **kw)


_sa_async.create_async_engine = _patched
import models  # noqa: F401


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


class _Evt(dict):
    """最小 StoredEvent 替身（dict 形态即可，CAD 只读字段）。"""

    def __init__(self, eid, **fields):
        super().__init__(id=eid, **fields)
        self.id = eid


class _Store:
    """按 id 返回事件；缺失返回 None。"""

    def __init__(self, events: dict):
        self._events = events
        self.queried: list = []

    async def get_by_id(self, session, eid):
        self.queried.append(eid)
        return self._events.get(eid)


def _verify(store, evidence_ids, quotes, claim="某断言"):
    import cad as _mod
    from cad import PenetratingVerifier

    original = _mod.event_store
    _mod.event_store = store
    try:
        return _run(PenetratingVerifier().verify_claims(None, "", [{
            "claim": claim,
            "type": "SANGFOR_ALERT",
            "evidence_ids": evidence_ids,
            "evidence_quotes": quotes,
            "severity": "high",
        }]))
    finally:
        _mod.event_store = original


REAL_EVENT = _Evt(
    1,
    message="failed password for root from 10.0.0.9",
    src_ip="10.0.0.9",
    dst_ip="10.0.0.5",
    event_type="SSH_BRUTEFORCE",
    severity="high",
    protocol="ssh",
    raw_data={"detail": "publickey rejected for user admin"},
)


# ═══════════════════════════════════════════
# B) evidence_quotes 必须被真正读取并核验
# ═══════════════════════════════════════════


class TestQuoteGrounding:
    def test_fabricated_quote_is_not_verified(self):
        """核心回归：引用原文在事件里不存在 → 不得 verified=True。"""
        store = _Store({1: REAL_EVENT})
        reports = _verify(store, [1], ["payload 完全捏造的 xyzzy 内容"])
        assert len(reports) == 1
        r = reports[0]
        assert r.verified is False, (
            "伪造的引用原文仍被判 verified —— CAD 只查 ID 存在性"
        )
        assert r.severity == "high"

    def test_fabricated_quote_is_recorded(self):
        store = _Store({1: REAL_EVENT})
        r = _verify(store, [1], ["完全捏造的内容"])[0]
        assert r.quote_checked == 1
        assert r.quote_grounded == 0
        assert r.ungrounded_quotes == ["完全捏造的内容"]

    def test_genuine_quote_is_verified(self):
        """对照组：真实存在的引用原文仍应通过。"""
        store = _Store({1: REAL_EVENT})
        r = _verify(store, [1], ["failed password for root"])[0]
        assert r.verified is True
        assert r.quote_checked == 1
        assert r.quote_grounded == 1

    def test_quote_matching_is_case_and_space_insensitive(self):
        store = _Store({1: REAL_EVENT})
        r = _verify(store, [1], ["Failed   Password  For Root"])[0]
        assert r.verified is True, "归一化后应容忍大小写与空白差异"

    def test_partial_fabrication_fails(self):
        store = _Store({1: REAL_EVENT})
        r = _verify(store, [1], ["failed password for root", "不存在的另一段引用"])[0]
        assert r.verified is False
        assert r.quote_grounded == 1
        assert len(r.ungrounded_quotes) == 1

    def test_quote_matched_against_raw_data_fields(self):
        """raw_data 里的字段也要参与比对。"""
        store = _Store({1: REAL_EVENT})
        r = _verify(store, [1], ["publickey rejected for user admin"])[0]
        assert r.verified is True

    def test_quotes_with_no_events_are_all_ungrounded(self):
        """声称有引用但一个事件都查不到 → 全部无溯源。"""
        store = _Store({})
        r = _verify(store, [1], ["任何引用"])[0]
        assert r.quote_checked == 1
        assert r.ungrounded_quotes == ["任何引用"]

    def test_no_quotes_still_verifies_on_id_existence(self):
        """没给引用原文时，退回 ID 存在性判定（不是新缺陷）。"""
        store = _Store({1: REAL_EVENT})
        r = _verify(store, [1], [])[0]
        assert r.verified is True
        assert r.quote_checked == 0


# ═══════════════════════════════════════════
# A) extra 恒空死代码
# ═══════════════════════════════════════════


class TestExtraDeadCodeRemoved:
    def test_no_unreachable_extra_branch_in_source(self):
        """`extra = actual_set - claimed_set` 必须从**可执行代码**里消失。

        actual_ids 完全来自对 claimed_ids 的逐个查询，
        于是 actual_set ⊆ claimed_set，extra 恒为空 ——
        「数据库中存在但 Agent 未引用」这条分支永远走不到。

        只检查非注释行：解释该缺陷的注释里会出现这个字面量。
        """
        import inspect
        import cad

        src = inspect.getsource(cad.PenetratingVerifier.verify_claims)
        code_lines = [
            ln for ln in src.splitlines()
            if not ln.lstrip().startswith("#")
        ]
        code = "\n".join(code_lines)
        assert "extra = actual_set - claimed_set" not in code, (
            "恒空集死代码仍在：看起来做了双向核对，实际只核对了单向"
        )
        assert "if extra:" not in code

    def test_missing_id_still_detected(self):
        """删掉 extra 不能误伤真正的失实检测。"""
        store = _Store({1: REAL_EVENT})
        r = _verify(store, [1, 999_999], [])[0]
        assert r.verified is False
        assert r.severity == "high"
        assert "999999" in r.discrepancy

    def test_all_ids_exist_is_verified(self):
        store = _Store({1: REAL_EVENT, 2: _Evt(2, message="x", event_type="E",
                                                severity="low", src_ip="1.1.1.1",
                                                dst_ip="2.2.2.2", protocol="tcp")})
        r = _verify(store, [1, 2], [])[0]
        assert r.verified is True
        assert set(r.actual_evidence_ids) == {1, 2}


# ═══════════════════════════════════════════
# 报告口径必须暴露引用核验结果
# ═══════════════════════════════════════════


class TestReportExposesQuoteVerification:
    def _run_cad(self, monkeypatch, events, evidence_ids, quotes):
        from agents import agent_cad as ac
        from cad import CircuitBreaker

        store = _Store(events)
        monkeypatch.setattr(ac, "verifier", ac.verifier)

        import cad as _mod
        original = _mod.event_store
        _mod.event_store = store

        cb = CircuitBreaker(persist=False)
        monkeypatch.setattr(ac, "circuit_breaker", cb)

        try:
            return _run(ac.cad_agent.audit_pipeline(
                None, 1,
                {"evidence_trail": [{
                    "claim": "SSH 爆破",
                    "type": "BRUTEFORCE",
                    "evidence_ids": evidence_ids,
                    "evidence_quotes": quotes,
                    "severity": "high",
                }]},
            ))
        finally:
            _mod.event_store = original

    def test_report_includes_quote_counters(self, monkeypatch):
        rep = self._run_cad(monkeypatch, {1: REAL_EVENT}, [1], ["完全不存在的引用"])
        pv = rep["penetrating_verification"]
        assert pv["quotes_checked"] == 1, "报告未暴露引用核验口径"
        assert pv["quotes_grounded"] == 0
        assert pv["quotes_fabricated"] == 1

    def test_fabricated_quote_lowers_completeness(self, monkeypatch):
        """伪造引用必须拉低证据完整度（此前它是 1.0，看着一切正常）。"""
        rep = self._run_cad(monkeypatch, {1: REAL_EVENT}, [1], ["完全不存在的引用"])
        pv = rep["penetrating_verification"]
        assert pv["evidence_completeness"] == 0.0
        assert pv["hallucination_count"] == 1

    def test_genuine_quote_keeps_completeness(self, monkeypatch):
        rep = self._run_cad(monkeypatch, {1: REAL_EVENT}, [1],
                            ["failed password for root"])
        pv = rep["penetrating_verification"]
        assert pv["evidence_completeness"] == 1.0
        assert pv["hallucination_count"] == 0

    def test_discrepancy_entry_carries_ungrounded_quotes(self, monkeypatch):
        rep = self._run_cad(monkeypatch, {1: REAL_EVENT}, [1], ["完全不存在的引用"])
        ds = rep["penetrating_verification"]["high_severity_discrepancies"]
        assert ds, "伪造引用未进高危差异列表"
        assert ds[0]["ungrounded_quotes"] == ["完全不存在的引用"]
        assert ds[0]["quote_checked"] == 1


# ═══════════════════════════════════════════
# 与既有 NA 口径的兼容
# ═══════════════════════════════════════════


class TestNaCompatibilityWithQuotes:
    def test_no_ids_is_unverifiable_not_hallucination(self):
        """无 evidence_ids → unverifiable，不因缺引用被判幻觉。"""
        reports = _verify(_Store({1: REAL_EVENT}), [], ["任意引用"])
        r = reports[0]
        assert r.unverifiable is True
        assert r.verified is False

    def test_existing_na_tests_still_hold(self):
        """test_cad_noevidence_na 的两条口径不受影响。"""
        reports = _verify(_Store({}), [9_999_999_999], ["x"])
        r = reports[0]
        assert r.verified is False and r.unverifiable is False
        assert r.severity == "high"
