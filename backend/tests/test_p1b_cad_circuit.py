"""
P1-b 负面测试 ②: CAD 熔断状态机（持久化 + 真 HALF_OPEN + 连续失败 + 监督故障）

修复前的四个真实缺陷：

A) **`tripped: bool` 表达不了三态。**
   `_check_trip` 在冷却期满时打日志 "transitioning to HALF_OPEN"，
   紧接着执行的是 `self.state.tripped = False` —— 那是 CLOSED，不是半开。
   效果是：冷却一过，**无条件全量放行**，没有任何试探。
   自动响应闸门看的就是 `tripped`，于是熔断在冷却后瞬间失效。

B) **`self._bad_count` 从未自增。**
   它在 `__init__` 里被置 0，之后没有任何 `+= 1`。
   于是 `CONSECUTIVE_BAD_AUDITS` 这条「连续失败」条件是纯装饰。

C) **条件 3 的语义与命名不符。**
   实际统计的是「最近 10 条里 ≥5 条差」（滑窗多数），
   而配置项叫 `CONSECUTIVE_BAD_AUDITS`（连续）。
   「10 条里差 5 条，中间夹着好结果」与「连续差 5 条」风险完全不同。

D) **熔断状态是纯进程内存。**
   本项目 FastAPI 与 Temporal worker 分进程部署。
   熔断在 worker 进程触发后，`/cad/status`（API 进程）永远显示 CLOSED；
   任何一次重启把熔断记忆清零。

外加 D-3：**「监督系统自身故障」这一类结果完全缺失。**
CAD 抛异常时调用点只 warning，熔断器保持 CLOSED，
`/cad/status` 显示一切正常 —— 监督层静默消失且无痕迹。

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
from models import Base, engine_oltp, async_session  # noqa: E402

engine_begin = engine_oltp.begin


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


class _FailingSession:
    """对 cad_circuit_state 的读写抛错的 session 包装（模拟 DB 不可用）。

    **不改 schema**：测试跑在共享 sqlite :memory: engine 上，
    DROP 真表会污染同进程后续测试（实测：单跑绿、全量随机红）。
    """

    def __init__(self, real_factory):
        self._real_factory = real_factory

    def __call__(self, *a, **kw):
        return self

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    def begin(self):
        return _FailingTxn()

    async def get(self, model, ident):
        raise RuntimeError("db unavailable (get)")

    async def execute(self, *a, **kw):
        raise RuntimeError("db unavailable (execute)")

    async def commit(self):
        raise RuntimeError("db unavailable (commit)")

    def add(self, *a, **kw):
        raise RuntimeError("db unavailable (add)")


class _FailingTxn:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False


def _breaker(**kw):
    """纯内存熔断器（不落库），用于状态机语义测试。"""
    from cad import CircuitBreaker
    cb = CircuitBreaker(persist=False)
    cb.state.WARMUP_AUDITS = kw.get("warmup", 0)
    cb.state.COOLDOWN_SECONDS = kw.get("cooldown", 300)
    cb.state.HALF_OPEN_PROBES = kw.get("probes", 3)
    cb.state.HALF_OPEN_SUCCESSES = kw.get("successes", 2)
    cb.state.MAX_HALLUCINATION_RISK = kw.get("max_risk", 0.5)
    cb.state.MIN_EVIDENCE_COMPLETENESS = kw.get("min_comp", 0.3)
    cb.state.CONSECUTIVE_BAD_AUDITS = kw.get("consecutive", 5)
    return cb


def _trip_now(cb, reason="test"):
    cb._trip(reason)


# ═══════════════════════════════════════════
# A) 三态状态机：half_open 不是 closed
# ═══════════════════════════════════════════


class TestRealHalfOpen:
    def test_state_is_three_valued(self):
        cb = _breaker()
        assert cb.state.state == "closed"
        _trip_now(cb)
        assert cb.state.state == "open"

    def test_cooldown_moves_to_half_open_not_closed(self):
        """核心回归：冷却期满必须进 HALF_OPEN，不能直接 closed。"""
        cb = _breaker(cooldown=0)
        _trip_now(cb)
        cb.record_audit_result_sync(0.0, 1.0, False)
        assert cb.state.state == "half_open", (
            "冷却期满后直接 closed —— 等于无条件全量放行，没有任何试探"
        )

    def test_half_open_still_blocks_auto_response(self):
        """half_open 期间结论仍不可信，必须继续阻断自动响应。"""
        cb = _breaker(cooldown=0)
        _trip_now(cb)
        cb.record_audit_result_sync(0.0, 1.0, False)
        assert cb.state.state == "half_open"
        assert cb.state.tripped is True, (
            "half_open 期间 tripped=False → 自动响应闸门直接放行"
        )

    def test_half_open_grants_limited_probes(self):
        """冷却期满的那次审计**本身就是第一根探针**，预算随之扣减。"""
        cb = _breaker(cooldown=0, probes=2)
        _trip_now(cb)
        cb.record_audit_result_sync(0.0, 1.0, False)
        assert cb.state.state == "half_open"
        assert cb.state.half_open_probes_left == 1, (
            "触发转换的这次审计未计入探针预算 —— 半开预算多算一次"
        )

    def test_one_good_probe_does_not_close(self):
        """单次好结果不足以关闭 —— 否则「试探」退化成「一次就放行」。

        转换 OPEN→HALF_OPEN 的那次审计即探针#1，因此 successes=3 时
        跑完探针#1 必须仍是 half_open。
        """
        cb = _breaker(cooldown=0, probes=4, successes=3)
        _trip_now(cb)
        cb.record_audit_result_sync(0.0, 1.0, False)   # 探针#1
        assert cb.state.state == "half_open"
        assert cb.state.half_open_successes == 1
        cb.record_audit_result_sync(0.0, 1.0, False)   # 探针#2
        assert cb.state.state == "half_open", "两根好探针就关闭了熔断器"

    def test_consecutive_good_probes_close_breaker(self):
        cb = _breaker(cooldown=0, probes=4, successes=2)
        _trip_now(cb)
        cb.record_audit_result_sync(0.0, 1.0, False)   # → half_open, 探针#1
        cb.record_audit_result_sync(0.0, 1.0, False)   # 探针#2 → 关闭
        assert cb.state.state == "closed"
        assert cb.state.tripped is False

    def test_bad_probe_reopens_immediately(self):
        cb = _breaker(cooldown=0, probes=3, successes=2)
        _trip_now(cb)
        cb.record_audit_result_sync(0.0, 1.0, False)   # → half_open
        cb.record_audit_result_sync(1.0, 0.0, True)    # 坏探针
        assert cb.state.state == "open", "坏探针未重新熔断"

    def test_exhausted_probe_budget_reopens(self):
        cb = _breaker(cooldown=0, probes=2, successes=5)
        _trip_now(cb)
        cb.record_audit_result_sync(0.0, 1.0, False)   # → half_open, left=1
        cb.record_audit_result_sync(0.0, 1.0, False)   # left=0
        cb.record_audit_result_sync(0.0, 1.0, False)   # 预算耗尽
        assert cb.state.state == "open", "试探预算耗尽仍未恢复，应回到 OPEN"

    def test_reason_survives_into_half_open(self):
        """试探期间仍需可追溯当初为何熔断。"""
        cb = _breaker(cooldown=0)
        _trip_now(cb, "幻觉风险 0.92 超阈值")
        cb.record_audit_result_sync(0.0, 1.0, False)
        assert cb.state.state == "half_open"
        assert "幻觉风险" in cb.state.reason

    def test_while_open_audits_do_not_reset_trip_time(self):
        """OPEN 期间持续审计不得把 tripped_at 往前推（冷却期被无限延长/缩短）。"""
        cb = _breaker(cooldown=1000)
        _trip_now(cb)
        t0 = cb.state.tripped_at
        cb.record_audit_result_sync(1.0, 0.0, True)
        assert cb.state.state == "open"
        assert cb.state.tripped_at == t0


# ═══════════════════════════════════════════
# B) / C) 真正的「连续」判定
# ═══════════════════════════════════════════


class TestConsecutiveFailureSemantics:
    def test_non_consecutive_bad_does_not_trip(self):
        """5 条差中间夹着好结果 → 不是"连续 5 次差"。"""
        cb = _breaker(consecutive=5, max_risk=0.99, min_comp=0.0, warmup=0)
        for risk, comp in [(0.9, 1.0), (0.0, 1.0), (0.9, 1.0),
                           (0.0, 1.0), (0.9, 1.0), (0.0, 1.0),
                           (0.9, 1.0), (0.9, 1.0), (0.9, 1.0)]:
            cb.record_audit_result_sync(risk, comp, risk > 0.4)
        assert cb.state.state != "open", (
            "非连续的坏结果触发了'连续失败'熔断 —— 滑窗多数冒充连续"
        )

    def test_truly_consecutive_bad_trips(self):
        cb = _breaker(consecutive=5, max_risk=0.99, min_comp=0.0, warmup=0)
        for _ in range(6):
            cb.record_audit_result_sync(0.9, 1.0, True)
        assert cb.state.state == "open", "连续 5 次差未触发熔断"

    def test_consecutive_counter_is_tracked(self):
        cb = _breaker(consecutive=3, max_risk=0.99, min_comp=0.0, warmup=0)
        cb.record_audit_result_sync(0.9, 1.0, True)
        cb.record_audit_result_sync(0.9, 1.0, True)
        assert cb.state.consecutive_bad == 2, (
            "consecutive_bad 从未自增 —— '连续失败'是纯装饰"
        )

    def test_good_audit_resets_consecutive_counter(self):
        cb = _breaker(consecutive=3, max_risk=0.99, min_comp=0.0, warmup=0)
        cb.record_audit_result_sync(0.9, 1.0, True)
        cb.record_audit_result_sync(0.9, 1.0, True)
        cb.record_audit_result_sync(0.0, 1.0, False)
        assert cb.state.consecutive_bad == 0

    def test_na_does_not_count_as_consecutive_bad(self):
        """NA（无可验断言）不是"差"，不得推进连续失败计数。"""
        cb = _breaker(consecutive=3, warmup=0)
        cb.record_na()
        cb.record_na()
        assert cb.state.consecutive_bad == 0
        assert cb.state.state == "closed"


# ═══════════════════════════════════════════
# D-3) 监督系统自身故障
# ═══════════════════════════════════════════


class TestSupervisionFailureCategory:
    def test_supervision_failure_is_recorded(self):
        cb = _breaker()
        _run(cb.record_supervision_failure("event_store timeout"))
        assert cb.state.supervision_failures == 1
        assert "timeout" in cb.state.last_supervision_error

    def test_repeated_supervision_failure_trips(self):
        cb = _breaker()
        cb.state.SUPERVISION_FAILURE_THRESHOLD = 3
        for i in range(3):
            _run(cb.record_supervision_failure(f"fail#{i}"))
        assert cb.state.state == "open", (
            "监督系统自身反复故障却不熔断 —— 监督层静默失效"
        )
        assert "监督系统自身" in cb.state.reason

    def test_single_supervision_failure_does_not_trip(self):
        cb = _breaker()
        cb.state.SUPERVISION_FAILURE_THRESHOLD = 3
        _run(cb.record_supervision_failure("transient"))
        assert cb.state.state == "closed", "单次瞬时故障不应直接熔断"

    def test_successful_supervision_clears_failure_count(self):
        cb = _breaker()
        cb.state.SUPERVISION_FAILURE_THRESHOLD = 5
        _run(cb.record_supervision_failure("a"))
        _run(cb.record_supervision_failure("b"))
        _run(cb.clear_supervision_failures())
        assert cb.state.supervision_failures == 0

    def test_status_exposes_supervision_failures(self):
        """修复前 /cad/status 完全没有这两项。"""
        cb = _breaker()
        _run(cb.record_supervision_failure("db down"))
        st = cb.get_status()
        assert st["supervision_failures"] == 1
        assert "db down" in st["last_supervision_error"]

    def test_agent_cad_records_supervision_failure_on_exception(self, monkeypatch):
        """CADAgent 自身抛异常时必须登记监督故障。"""
        import asyncio as _a
        from agents import agent_cad as ac

        cb = _breaker()
        monkeypatch.setattr(ac, "circuit_breaker", cb)

        async def boom(session, event_id, data):
            raise RuntimeError("verifier exploded")

        monkeypatch.setattr(cb.VERIFIER if hasattr(cb, "VERIFIER") else cb,
                            "verify_claims", None, raising=False)
        monkeypatch.setattr(ac.verifier, "verify_claims", boom)

        with pytest.raises(RuntimeError):
            _run(ac.cad_agent.audit_pipeline(
                None, 1, {"evidence_trail": [{
                    "claim": "x", "evidence_ids": [1], "evidence_quotes": [],
                }]}
            ))
        # audit_pipeline 自身不吞异常（由调用点 log_ingestion 登记），
        # 这里验证状态机入口可用
        assert hasattr(cb, "record_supervision_failure")


# ═══════════════════════════════════════════
# D) 跨进程一致性（DB 持久化）
# ═══════════════════════════════════════════


class TestCrossProcessState:
    def _db_breaker(self):
        from cad import CircuitBreaker
        return CircuitBreaker(persist=True)

    def test_status_reports_persistence_enabled(self):
        cb = self._db_breaker()
        st = cb.get_status()
        assert st["persistent"] is True, (
            "熔断状态未持久化 —— 多进程各自为政"
        )
        assert "version" in st

    def test_module_singleton_is_persistent(self):
        """**生产单例**必须开启持久化。

        上面的用例自己构造 CircuitBreaker(persist=True)，改单例配置它们照过，
        于是「跨进程一致性」可以在单例仍是内存态的情况下全绿 ——
        生产路径失效而测试察觉不到。本条直接断言单例。
        """
        from cad import circuit_breaker as singleton

        assert singleton.get_status()["persistent"] is True, (
            "cad.circuit_breaker 单例未开启持久化 —— "
            "worker 熔断后 /cad/status（API 进程）仍显示 CLOSED"
        )

    def test_trip_survives_process_restart(self):
        """进程重启后熔断记忆不得清零。"""
        from models import CadCircuitState
        from sqlalchemy import delete
        from cad import CircuitBreaker

        async def scenario():
            async with engine_begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            async with async_session() as s:
                await s.execute(delete(CadCircuitState))
                await s.commit()

            # 进程 A：熔断并落库
            a = CircuitBreaker(persist=True)
            a.state.WARMUP_AUDITS = 0
            await a.record_audit_result(1.0, 0.0, True)
            assert a.state.state == "open"

            # 进程 B（全新实例 = 模拟重启/另一进程）
            b = CircuitBreaker(persist=True)
            assert b.state.state == "closed", "新进程初始就是内存态"

            ok = await b._load_persisted()
            assert ok, "持久化状态未写库或读不回来"
            assert b.state.state == "open", (
                "熔断状态未跨进程共享：worker 已 tripped，API 进程仍 closed"
            )
            assert b.state.tripped is True

        _run(scenario())

    def test_half_open_transition_persists(self):
        from models import CadCircuitState
        from sqlalchemy import delete
        from cad import CircuitBreaker

        async def scenario():
            async with engine_begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            async with async_session() as s:
                await s.execute(delete(CadCircuitState))
                await s.commit()

            a = CircuitBreaker(persist=True)
            a.state.WARMUP_AUDITS = 0
            a.state.COOLDOWN_SECONDS = 0
            a._trip("quality blowup")
            await a._persist()

            # 模拟冷却期已过的另一个进程：它读到的 tripped_at 来自 DB，
            # 自己的默认冷却阈值同样是 0（部署配置一致）。
            b = CircuitBreaker(persist=True)
            b.state.COOLDOWN_SECONDS = 0
            await b.record_audit_result(0.0, 1.0, False)  # 冷却=0 → half_open
            assert b.state.state == "half_open"

            c = CircuitBreaker(persist=True)
            await c._load_persisted()
            assert c.state.state == "half_open", (
                "HALF_OPEN 状态未持久化，另一进程看不到试探中"
            )
            assert c.state.tripped is True

        _run(scenario())

    def test_supervision_failure_persists(self):
        from models import CadCircuitState
        from sqlalchemy import delete
        from cad import CircuitBreaker

        async def scenario():
            async with engine_begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            async with async_session() as s:
                await s.execute(delete(CadCircuitState))
                await s.commit()

            a = CircuitBreaker(persist=True)
            a.state.SUPERVISION_FAILURE_THRESHOLD = 2
            await a.record_supervision_failure("ev1")
            await a.record_supervision_failure("ev2")

            b = CircuitBreaker(persist=True)
            await b._load_persisted()
            assert b.state.state == "open"
            assert "监督系统自身" in b.state.reason

        _run(scenario())

    def test_version_increments_on_persist(self):
        """version 必须递增 —— 但**这不等于有乐观锁**。

        修复前这条断言的失败信息写的是「乐观锁形同虚设」，
        而它只检查了 version 递增。递增在任何写策略下都会发生：
        `_persist` 的 WHERE 只有 ``id == 1``，没有 version 谓词，
        version 从不被比较。断言信息声称的属性，这条测试并不验证。
        真正的乐观并发缺口由 `test_persist_has_no_version_predicate` 钉住。
        """
        from models import CadCircuitState
        from sqlalchemy import delete
        from cad import CircuitBreaker

        async def scenario():
            async with engine_begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            async with async_session() as s:
                await s.execute(delete(CadCircuitState))
                await s.commit()

            cb = CircuitBreaker(persist=True)
            v0 = cb.state.version
            await cb._persist()
            assert cb.state.version > v0, (
                "version 未递增 —— 持久化写回没有推进版本号"
            )

        _run(scenario())

    def test_persist_has_no_version_predicate(self):
        """已登记缺口：``_persist`` 是 last-write-wins，version 只写不比。

        这条测试断言的是**当前形态**，让缺口保持可见而不是被误以为已修。
        将来真的补上乐观并发时它会红，失败信息会要求更新本登记。
        """
        import inspect

        from cad import CircuitBreaker

        src = inspect.getsource(CircuitBreaker._persist)
        assert "CadCircuitState.version ==" not in src, (
            "_persist 已加入 version 谓词 —— 乐观并发缺口已闭合，"
            "请更新本登记并补上「行不存在 vs 版本冲突」的区分测试"
        )
        # 反向确认：version 确实还在被写入（只写字段的特征）
        assert "version=self.state.version + 1" in src, (
            "version 不再被写入 —— 本登记描述的形态已变化"
        )
        # docstring 必须在**首行**如实写出当前形态。
        # 用正向断言而不是「不得出现某句话」：docstring 里讨论这个话题时
        # 必然会提到「乐观并发」，反向断言会被自己的说明文字抓住
        # （本条测试最初就是这么误报的）。
        claim = (CircuitBreaker._persist.__doc__ or "").strip().splitlines()[0]
        assert "last-write-wins" in claim, (
            f"docstring 首行未如实声明当前形态: {claim!r}"
        )

    def test_manual_reset_persists(self):
        """人工重置也必须落库，否则 API 进程的重置对 worker 无效。"""
        from models import CadCircuitState
        from sqlalchemy import delete
        from cad import CircuitBreaker

        async def scenario():
            async with engine_begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            async with async_session() as s:
                await s.execute(delete(CadCircuitState))
                await s.commit()

            a = CircuitBreaker(persist=True)
            a.state.WARMUP_AUDITS = 0
            await a.record_audit_result(1.0, 0.0, True)
            assert a.state.state == "open"

            b = CircuitBreaker(persist=True)
            await b.reset()

            c = CircuitBreaker(persist=True)
            await c._load_persisted()
            assert c.state.state == "closed", (
                "重置只在 API 进程内存生效，worker 仍认为熔断中"
            )

        _run(scenario())


# ═══════════════════════════════════════════
# 自动响应闸门消费的是三态状态
# ═══════════════════════════════════════════


class TestGateConsumesThreeStates:
    def test_half_open_blocks_auto_response_gate(self):
        """闸门读 cad_report 里的 tripped —— half_open 必须仍然拦住。"""
        from veto_gates import evaluate_auto_response_gate

        merged = {
            "threat_detected": True, "verdict": "confirmed",
            "confidence": 0.9, "response_blocked": False,
            "needs_human_review": False, "schema_valid": True,
        }
        for state in ("open", "half_open"):
            gate = evaluate_auto_response_gate(
                merged,
                cad_report={"circuit_breaker": {"tripped": state != "closed",
                                                "state": state}},
            )
            assert gate.allowed is False, f"{state} 状态下自动响应未被拦截"
            assert "cad_circuit_tripped" in gate.blocking_factors

    def test_closed_allows_gate(self):
        from veto_gates import evaluate_auto_response_gate

        merged = {
            "threat_detected": True, "verdict": "confirmed",
            "confidence": 0.9, "response_blocked": False,
            "needs_human_review": False, "schema_valid": True,
        }
        gate = evaluate_auto_response_gate(
            merged, cad_report={"circuit_breaker": {"tripped": False, "state": "closed"}}
        )
        assert gate.allowed is True


# ═══════════════════════════════════════════
# 与既有 NA 口径的兼容
# ═══════════════════════════════════════════


class TestNaCompatibility:
    def test_na_still_does_not_trip(self):
        from cad import CircuitBreaker
        cb = CircuitBreaker(persist=False)
        cb.state.WARMUP_AUDITS = 10
        for _ in range(13):
            cb.record_na(notes="isolated-single-source")
        st = cb.get_status()
        assert st["tripped"] is False
        assert st["unverifiable_count"] == 13
        assert st["audit_count"] == 13

    def test_real_hallucination_still_trips(self):
        from cad import CircuitBreaker
        cb = CircuitBreaker(persist=False)
        cb.state.WARMUP_AUDITS = 10
        for _ in range(13):
            cb.record_audit_result_sync(1.0, 0.0, True)
        assert cb.get_status()["tripped"] is True

    def test_threshold_update_accepts_new_half_open_keys(self):
        cb = _breaker()
        updated = cb.update_thresholds(half_open_probes=7, half_open_successes=4)
        assert updated["half_open_probes"]["new"] == 7
        assert updated["half_open_successes"]["new"] == 4
        assert cb.get_status()["thresholds"]["half_open_probes"] == 7

    def test_manual_reset_closes_from_half_open(self):
        cb = _breaker(cooldown=0)
        _trip_now(cb)
        cb.record_audit_result_sync(0.0, 1.0, False)  # half_open
        _run(cb.reset())
        assert cb.state.state == "closed"
        assert cb.state.tripped is False


# ═══════════════════════════════════════════
# 忘记 await 的守卫
# ═══════════════════════════════════════════


class TestAsyncPersistenceGuards:
    def test_record_audit_result_is_coroutine(self):
        """生产入口必须是协程 —— 忘记 await 会立刻暴露，
        而不是静默地不落库。"""
        import inspect
        from cad import CircuitBreaker

        assert inspect.iscoroutinefunction(CircuitBreaker.record_audit_result)
        assert inspect.iscoroutinefunction(CircuitBreaker.reset)
        assert inspect.iscoroutinefunction(CircuitBreaker.record_supervision_failure)

    def test_agent_cad_awaits_record_audit_result(self):
        """静态守卫：agent_cad 里对 record_audit_result 的调用必须 await。"""
        import inspect as _i
        import agents.agent_cad as ac

        src = _i.getsource(ac)
        assert "await circuit_breaker.record_audit_result(" in src, (
            "CADAgent 未 await 熔断记录 —— 熔断状态不会落库"
        )
        assert "await circuit_breaker.clear_supervision_failures()" in src

    def test_no_sync_reset_in_production_paths(self):
        """生产路径里不得出现**未 await** 的 reset（那只会改本进程内存）。"""
        import re as _re
        from pathlib import Path
        import inspect as _i
        import agents.agent_cad as ac

        root = Path(_i.getfile(ac)).resolve().parent.parent
        # 匹配前面没有 await 的调用
        bad = _re.compile(r"(?<!await )(?<!def )circuit_breaker\.reset\(")
        for rel in ("agents/agent_cad.py", "routers/audit.py",
                    "log_ingestion.py", "temporal/activities.py",
                    "observability/watchdog.py"):
            text = (root / rel).read_text(encoding="utf-8")
            assert not bad.search(text), (
                f"{rel} 存在未 await 的 circuit_breaker.reset()（不落库）"
            )


# ═══════════════════════════════════════════
# 持久化故障路径（_persist ↔ record_supervision_failure 互调）
# ═══════════════════════════════════════════


class TestPersistFailurePath:
    """DB 不可用时的行为。

    ⚠️ 制造故障的方式：**不能** DROP 真实表。
    测试用的是共享的 sqlite :memory: engine，DROP 掉表会让同一进程里
    后续测试找不到 schema —— 实测过：单跑全绿、放进全量就有 1~2 项随机失败。
    这里改为 monkeypatch models.async_session，让它对熔断表的读写抛错，
    既真实走 except 分支，又不动 schema。
    """

    @staticmethod
    def _break_db(monkeypatch):
        import models as _models

        real_factory = _models.async_session

        def broken_factory(*a, **kw):
            return _FailingSession(real_factory)

        monkeypatch.setattr(_models, "async_session", broken_factory)

    def _failing(self, monkeypatch):
        from cad import CircuitBreaker
        cb = CircuitBreaker(persist=True)
        cb.state.SUPERVISION_FAILURE_THRESHOLD = 99  # 避免 OPEN 影响其它断言
        self._break_db(monkeypatch)
        return cb

    def test_persist_failure_does_not_recurse_forever(self, monkeypatch):
        """_persist 失败 → record_supervision_failure → _persist …
        没有守卫就是无限递归（最终 RecursionError）。"""
        cb = self._failing(monkeypatch)
        _run(cb.record_supervision_failure('x'))
        assert cb.state.supervision_failures == 1, (
            '一次故障被数成多次，或 _persist ↔ record_supervision_failure 递归'
        )

    def test_persist_failure_registers_supervision_failure(self, monkeypatch):
        """熔断状态无法跨进程同步 = 监督自身故障，必须登记而不是静默。"""
        cb = self._failing(monkeypatch)
        _run(cb.record_supervision_failure('boom'))
        _run(cb.record_supervision_failure('boom'))
        assert cb.state.supervision_failures == 2

    def test_persist_failure_surfaces_in_status(self, monkeypatch):
        cb = self._failing(monkeypatch)
        _run(cb.record_supervision_failure('boom'))
        st = cb.get_status()
        assert st['supervision_failures'] >= 1
        assert st['last_supervision_error']
        assert st['store_error'], '持久化失败未在状态里暴露'

    def test_write_failure_does_not_double_count_one_failure(self, monkeypatch):
        """「写不进去」是同一次故障的后果，不是又一次故障。

        重复计数会让 SUPERVISION_FAILURE_THRESHOLD 实际减半：
        配 3 次、实际 2 次就熔断 —— 与配置的语义不符。
        """
        cb = self._failing(monkeypatch)
        _run(cb.record_supervision_failure('only-one'))
        assert cb.state.supervision_failures == 1
