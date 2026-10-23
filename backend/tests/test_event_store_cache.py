"""EventStore 热缓存一致性：失效广播、TTL 兜底、代次防回写、先提交后失效。"""
import inspect

import pytest
from event_store import EventStore, _HotCacheEntry
from config import settings


def _snapshot(eid=1, *, analyzed=True, message="x", audit=True):
    raw = {"_audit_llm": {"status": "completed"}} if audit else {}
    return {
        "id": eid,
        "session_id": "s",
        "event_type": "X",
        "severity": "info",
        "src_ip": "",
        "dst_ip": "",
        "message": message,
        "raw_data": raw,
        "anomaly_score": 0.0,
        "correlation_id": "",
        "created_at": "",
        "analyzed": analyzed,
        "idempotent": False,
    }


class _FakeEvt:
    def __init__(self, eid=1, message="from-db", analyzed=True, audit=True):
        self.id = eid
        self.session_id = "s"
        self.event_type = "X"
        self.severity = "info"
        self.src_ip = ""
        self.dst_ip = ""
        self.message = message
        self.raw_data = {"_audit_llm": {"status": "completed", "note": "db"}} if audit else {}
        self.anomaly_score = 0.0
        self.analyzed = analyzed
        self.created_at = None


def test_invalidate_removes_hot_cache_entry():
    store = EventStore()
    store._cache_put(42, {"id": 42, "analyzed": False, "raw_data": {}})
    store.invalidate(42, broadcast=False)
    assert 42 not in store._hot_cache
    assert store.current_generation(42) == 1


def test_update_hot_cache_merges_fields():
    store = EventStore()
    store._cache_put(7, {"id": 7, "analyzed": False})
    store.update_hot_cache(7, analyzed=True, raw_data={"_audit_llm": {"status": "completed"}})
    data = store._cache_data(7)
    assert data["analyzed"] is True
    assert data["raw_data"]["_audit_llm"]["status"] == "completed"


def test_invalidate_missing_id_is_noop():
    store = EventStore()
    store.invalidate(999, broadcast=False)
    store.invalidate(None, broadcast=False)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_get_by_id_revalidates_unanalyzed_cache(monkeypatch):
    """ingest 热缓存 analyzed=False 时必须回源 DB,否则 Temporal 写回后 API 永远 pending。"""
    store = EventStore()
    store._cache_put(9302, _snapshot(9302, analyzed=False, audit=False))

    class FakeSession:
        async def get(self, model, eid):
            assert eid == 9302
            return _FakeEvt(9302, message="x", analyzed=True, audit=True)

    stored = await store.get_by_id(FakeSession(), 9302)
    assert stored is not None
    assert stored.analyzed is True
    assert stored.raw_data["_audit_llm"]["status"] == "completed"
    assert store._cache_data(9302)["analyzed"] is True


@pytest.mark.asyncio
async def test_get_by_id_prefer_db_bypasses_fresh_cache():
    store = EventStore()
    store._cache_put(1, _snapshot(1, message="cached"))

    class FakeSession:
        async def get(self, model, eid):
            return _FakeEvt(1, message="from-db")

    stored = await store.get_by_id(FakeSession(), 1, prefer_db=True)
    assert stored.message == "from-db"
    assert stored.raw_data["_audit_llm"]["note"] == "db"


def test_ttl_defaults_to_shortest_audit_lane():
    """TTL 按 P2 车道超时推导，不是拍脑袋的固定秒数。"""
    store = EventStore()
    assert store._hot_cache_ttl_s == float(settings.audit_timeout_p2_s)
    assert store._hot_cache_ttl_s > 0


@pytest.mark.asyncio
async def test_ttl_expires_analyzed_cache(monkeypatch):
    store = EventStore()
    store._hot_cache_ttl_s = 2.0
    clock = {"t": 1000.0}
    monkeypatch.setattr("event_store.time.monotonic", lambda: clock["t"])
    store._cache_put(1, _snapshot(1, message="cached"))

    hits = []

    class FakeSession:
        async def get(self, model, eid):
            hits.append(eid)
            return _FakeEvt(1, message="from-db")

    clock["t"] = 1001.5
    stored = await store.get_by_id(FakeSession(), 1)
    assert stored.message == "cached"
    assert hits == []

    clock["t"] = 1002.1
    stored = await store.get_by_id(FakeSession(), 1)
    assert stored.message == "from-db"
    assert hits == [1]


def test_stale_put_rejected_after_invalidate():
    store = EventStore()
    store._cache_put(5, _snapshot(5, message="old"))
    gen_at_read = store.current_generation(5)
    store.invalidate(5, broadcast=False)
    assert 5 not in store._hot_cache
    ok = store._cache_put(5, _snapshot(5, message="old"), expected_gen=gen_at_read)
    assert ok is False
    assert 5 not in store._hot_cache
    ok = store._cache_put(
        5, _snapshot(5, message="new"), expected_gen=store.current_generation(5)
    )
    assert ok is True
    assert store._cache_data(5)["message"] == "new"


@pytest.mark.asyncio
async def test_get_by_id_does_not_write_back_stale_snapshot():
    store = EventStore()
    store._cache_put(8, _snapshot(8, analyzed=False, audit=False, message="stale"))
    gen_at_read = store.current_generation(8)

    class FakeSession:
        async def get(self, model, eid):
            store.invalidate(8, broadcast=False)
            return _FakeEvt(8, message="should-not-cache", analyzed=False, audit=False)

    stored = await store.get_by_id(FakeSession(), 8)
    assert stored.message == "should-not-cache"
    assert 8 not in store._hot_cache
    assert store.current_generation(8) == gen_at_read + 1


@pytest.mark.asyncio
async def test_commit_then_invalidate_order():
    store = EventStore()
    order = []

    class Sess:
        async def commit(self):
            order.append("commit")

    store.invalidate = lambda eid, *, broadcast=True: order.append(("invalidate", eid))
    await store.commit_then_invalidate(Sess(), 11, 12)
    assert order == ["commit", ("invalidate", 11), ("invalidate", 12)]


@pytest.mark.asyncio
async def test_commit_then_invalidate_skips_notify_when_commit_fails():
    store = EventStore()
    order = []

    class Bad:
        async def commit(self):
            order.append("commit")
            raise RuntimeError("fail")

    store.invalidate = lambda eid, *, broadcast=True: order.append("invalidate")
    with pytest.raises(RuntimeError):
        await store.commit_then_invalidate(Bad(), 1)
    assert order == ["commit"]


def test_remote_invalidate_uses_generation_and_ignores_own_echo():
    store = EventStore()
    store._cache_put(3, _snapshot(3))
    store._apply_remote_invalidate(3, remote_gen=1, origin=store._origin)
    assert 3 in store._hot_cache
    store._apply_remote_invalidate(3, remote_gen=2, origin="other")
    assert 3 not in store._hot_cache
    assert store.current_generation(3) == 2
    store._cache_put(3, _snapshot(3), expected_gen=2)
    store._apply_remote_invalidate(3, remote_gen=1, origin="other")
    assert 3 in store._hot_cache


def test_parse_invalidate_payload_json_and_legacy_int():
    store = EventStore()
    assert store._parse_invalidate_payload("42") == (42, None, None)
    eid, gen, origin = store._parse_invalidate_payload(
        '{"id": 7, "gen": 3, "origin": "abc"}'
    )
    assert (eid, gen, origin) == (7, 3, "abc")
    eid, gen, origin = store._parse_invalidate_payload(b"9")
    assert eid == 9


def test_write_paths_notify_after_commit():
    """三个原先漏通知的写入点 + scheduler 倒置顺序，一律走 commit 后再失效。"""
    from pathlib import Path
    from routers.logs import reset_stuck
    from routers.audit import run_audit_llm_pipeline
    from scheduler import Scheduler

    backend = Path(__file__).resolve().parents[1]
    app_src = (backend / "app.py").read_text(encoding="utf-8")
    assert "commit_then_invalidate" in app_src
    assert "commit_then_invalidate" in inspect.getsource(reset_stuck)
    assert "commit_then_invalidate" in inspect.getsource(run_audit_llm_pipeline)
    reap = inspect.getsource(Scheduler._reap_stuck_audits)
    assert "commit_then_invalidate" in reap
    before, _, after = reap.partition("if n:")
    assert "invalidate" not in before
    assert "commit_then_invalidate" in after


def test_hot_cache_entry_type_after_put():
    store = EventStore()
    store._cache_put(1, _snapshot(1))
    assert isinstance(store._hot_cache[1], _HotCacheEntry)
    assert store._hot_cache[1].gen == 0
