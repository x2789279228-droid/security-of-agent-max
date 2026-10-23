"""
P3-5: CAD 熔断的故障恢复探针测试。

P1-b 已覆盖：跨进程持久化、真 HALF_OPEN、连续失败计数、监督故障类别、
持久化失败路径。**故障恢复**这一层此前是空白，实测挖出两个缺陷：

A) **`clear_supervision_failures` 是唯一不先载入权威状态就落库的路径。**
   另外三条落库路径（`record_audit_result` / `reset` /
   `record_supervision_failure`）都先 `await self._load_persisted()`，
   只有它直接 `await self._persist()`。
   于是：一个持有陈旧内存副本的进程跑成功监督，就把**自己的陈旧状态**
   （可能是 closed）覆盖回 DB，覆盖掉别的进程刚写入的熔断。
   跨进程保护靠的从来不是 version，而是这条纪律；纪律有一个洞。

B) **损坏/未知的持久化状态 fail-open。**
   `_load_persisted` 原样读入 ``row.state``，而 `tripped` 判据是
   ``state in ("open", "half_open")``。实测五种取值全部 fail-open：

       DB state='TRIPPED'   → 读回 'TRIPPED'   tripped=False
       DB state='Open'      → 读回 'Open'      tripped=False
       DB state='OPEN'      → 读回 'OPEN'      tripped=False
       DB state='half-open' → 读回 'half-open' tripped=False
       DB state='bogus'     → 读回 'bogus'     tripped=False

   tripped=False 意味着自动响应闸门放行 —— 一条**状态不可读**的记录
   等于熔断器被静默关闭。对安全闸门来说这是最坏的缺省方向。

另记一条**已记录但未修**的既有限制（不是本轮引入）：
`_persist` 的 WHERE 只有 ``id == 1``，没有 version 谓词 ——
docstring 声称的「乐观并发」并未实现，实际是 last-write-wins。
本文件用测试把当前行为钉住，使这个差距是**被记录的**而非被误以为已修。
真正补上需要区分「行不存在」与「版本冲突」两种 rowcount==0，
而 P1-b 已经在这两者的区分上栽过一次，属于独立一轮工作。
"""
import asyncio
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ.setdefault("SHARED_MEMORY_DATABASE_URL", "sqlite+aiosqlite:///:memory:")

import sqlalchemy.ext.asyncio as _sa_async  # noqa: E402

_orig = _sa_async.create_async_engine


def _patched(url, **kw):
    for k in ("pool_size", "max_overflow", "pool_pre_ping", "pool_recycle"):
        kw.pop(k, None)
    return _orig(url, **kw)


_sa_async.create_async_engine = _patched

from models import Base, CadCircuitState, async_session, engine_oltp  # noqa: E402
from sqlalchemy import delete  # noqa: E402

engine_begin = engine_oltp.begin


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


def _db_breaker():
    from cad import CircuitBreaker
    return CircuitBreaker(persist=True)


async def _wipe():
    async with async_session() as s:
        await s.execute(delete(CadCircuitState))
        await s.commit()


async def _seed(**kw):
    fields = {"id": 1, "version": 1}
    fields.update(kw)
    async with async_session() as s:
        s.add(CadCircuitState(**fields))
        await s.commit()


async def _read():
    async with async_session() as s:
        row = await s.get(CadCircuitState, 1)
        return None if row is None else {
            "state": row.state, "version": row.version,
            "supervision_failures": row.supervision_failures,
        }


@pytest.fixture()
def db():
    async def _prep():
        async with engine_begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        await _wipe()
    _run(_prep())
    yield
    _run(_wipe())


# ═══════════════════════════════════════════
# A. 落库纪律：每条路径都必须先载入权威状态
# ═══════════════════════════════════════════

class TestPersistDiscipline:
    """跨进程保护靠「先载入再写」，不是靠 version。缺口必须钉死。"""

    def test_clear_supervision_failures_loads_before_persist(self, db, monkeypatch):
        """**核心回归**：清理监督故障计数前必须先载入权威状态。

        修复前本方法直接 `_persist()`，是四条落库路径里唯一不载入的。
        """
        cb = _db_breaker()
        calls = []
        real_load = cb._load_persisted
        real_persist = cb._persist

        async def _spy_load():
            calls.append("load")
            return await real_load()

        async def _spy_persist():
            calls.append("persist")
            return await real_persist()

        monkeypatch.setattr(cb, "_load_persisted", _spy_load)
        monkeypatch.setattr(cb, "_persist", _spy_persist)

        cb.state.supervision_failures = 2
        _run(cb.clear_supervision_failures())

        assert calls.index("load") < calls.index("persist"), (
            f"clear_supervision_failures 未先载入就落库，调用序={calls}"
        )

    def test_stale_success_does_not_clobber_tripped_state(self, db):
        """端到端：陈旧进程跑成功监督，不得把别的进程的熔断覆盖掉。"""
        async def scenario():
            # 进程 A：监督故障累加到熔断
            a = _db_breaker()
            a.state.SUPERVISION_FAILURE_THRESHOLD = 3
            for _ in range(3):
                await a.record_supervision_failure("cad blew up")
            assert a.state.state == "open"

            tripped = await _read()
            assert tripped["state"] == "open", "A 的熔断未落库"

            # 进程 B：陈旧副本（内存里还是 closed，且带着旧的失败计数）
            b = _db_breaker()
            b.state.state = "closed"
            b.state.supervision_failures = 2

            # B 跑成功监督
            await b.clear_supervision_failures()

            after = await _read()
            assert after["state"] == "open", (
                f"陈旧进程把熔断状态覆盖成了 {after['state']!r} —— "
                f"自动响应闸门会放行"
            )

        _run(scenario())

    def test_other_persist_paths_already_load(self, db):
        """回归护栏：另外三条路径本来就在载入，别把它们改坏。"""
        cb = _db_breaker()
        seen = []
        real_load, real_persist = cb._load_persisted, cb._persist

        async def _spy_load():
            seen.append("load")
            return await real_load()

        async def _spy_persist():
            seen.append("persist")
            return await real_persist()

        cb._load_persisted, cb._persist = _spy_load, _spy_persist
        cb.state.WARMUP_AUDITS = 0
        _run(cb.record_audit_result(1.0, 0.0, True))
        assert seen.index("load") < seen.index("persist")

        seen.clear()
        _run(cb.record_supervision_failure("boom"))
        assert seen.index("load") < seen.index("persist")

        seen.clear()
        _run(cb.reset())
        assert seen.index("load") < seen.index("persist")


# ═══════════════════════════════════════════
# B. 损坏状态必须 fail-closed
# ═══════════════════════════════════════════

class TestCorruptStateFailsClosed:
    @pytest.mark.parametrize("bad", ["TRIPPED", "Open", "OPEN",
                                     "half-open", "bogus", "", "  "])
    def test_unknown_state_is_not_treated_as_closed(self, db, bad):
        """状态不可读 ≠ 熔断器关闭。"""
        _run(_seed(state=bad, reason="legacy row"))
        cb = _db_breaker()
        _run(cb._load_persisted())
        assert cb.state.tripped is True, (
            f"DB 里 state={bad!r} 被读成了 tripped=False —— "
            f"自动响应闸门会放行（fail-open）"
        )

    def test_unknown_state_is_surfaced_not_swallowed(self, db):
        """失败关闭的同时必须留痕，否则运维无从判断。"""
        _run(_seed(state="bogus", reason="legacy"))
        cb = _db_breaker()
        _run(cb._load_persisted())
        assert "bogus" in cb.state.reason, (
            f"未知状态未写进 reason，实际 {cb.state.reason!r}"
        )
        st = cb.get_status()
        assert st.get("store_error"), "未知状态未出现在 store_error 里"

    def test_valid_states_are_untouched(self, db):
        """防过度收紧：三个合法值必须原样保留。"""
        for good in ("closed", "open", "half_open"):
            _run(_wipe())
            _run(_seed(state=good))
            cb = _db_breaker()
            _run(cb._load_persisted())
            assert cb.state.state == good
            expected_tripped = good in ("open", "half_open")
            assert cb.state.tripped is expected_tripped

    def test_state_case_is_normalised(self, db):
        """大小写/空白差异应当被吸收，而不是当成未知值。"""
        _run(_seed(state="  OPEN  "))
        cb = _db_breaker()
        _run(cb._load_persisted())
        assert cb.state.state == "open"
        assert cb.state.tripped is True

    def test_absent_row_is_not_corruption(self, db):
        """表里没行 = 还没熔断过，属正常冷启动，不得按损坏处理。"""
        cb = _db_breaker()
        loaded = _run(cb._load_persisted())
        assert loaded is False
        assert cb.state.state == "closed"
        assert cb.state.tripped is False

    def test_manual_reset_still_works_from_corrupt_state(self, db):
        """失败关闭不能变成无法恢复的死锁 —— 人工重置必须能解锁。"""
        _run(_seed(state="bogus"))
        cb = _db_breaker()
        _run(cb._load_persisted())
        assert cb.state.tripped is True
        _run(cb.reset())
        assert cb.state.state == "closed"
        assert cb.state.tripped is False


# ═══════════════════════════════════════════
# C. 已记录但未修的既有限制（钉住真实行为）
# ═══════════════════════════════════════════

class TestKnownLimitationLastWriteWins:
    """`_persist` 没有 version 谓词 —— 这一点被钉住，使差距可见。"""

    def test_persist_where_clause_has_no_version_predicate(self):
        import inspect
        from cad import CircuitBreaker

        src = inspect.getsource(CircuitBreaker._persist)
        assert "CadCircuitState.version ==" not in src, (
            "若将来补上真正的乐观并发，请同步更新本测试与本文件头部说明"
        )

    def test_write_is_last_one_wins(self, db):
        """当前语义：后写者覆盖前者。"""
        async def scenario():
            a = _db_breaker()
            a.state.WARMUP_AUDITS = 0
            await a.record_audit_result(1.0, 0.0, True)   # 熔断
            assert (await _read())["state"] == "open"

            # 绕过载入纪律直接写，模拟「纪律被破坏」的极端情况
            c = _db_breaker()
            c.state.state = "closed"
            await c._persist()
            assert (await _read())["state"] == "closed", (
                "若这里不再被覆盖，说明乐观并发已实现 —— "
                "请更新 C 类测试与本文件头部说明"
            )

        _run(scenario())

    def test_version_still_increments(self, db):
        """version 字段仍在递增（可观测），但不构成并发保护。"""
        cb = _db_breaker()
        v0 = cb.state.version
        _run(cb._persist())
        assert cb.state.version > v0
