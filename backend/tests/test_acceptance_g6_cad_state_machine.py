"""
验收 · 第六组：CAD 状态机与持久化（D-2 / D-3 / D-4）→ 门槛 C + D

规范原文（§二.6）：
  · 「CAD 的熔断状态必须跨进程一致，HALF_OPEN 必须是真正的有限试探」
  · 「CAD 自身运行失败必须作为独立状态被监控，不能等同于『没发现问题』」
  · 「必须区分『CAD 无法验证事件』（有效业务结果）与『CAD 自身运行失败』
    （监督能力丧失）—— 后者必须单独监控」
  · 「CAD 的独立证据核验结论必须真正影响发布与响应决策」

本组做**真实故障注入**：
  · 状态机：全部用真实审计结果驱动，不用 `_trip()` 直接改状态
  · 持久化：真连 sqlite，真读回
  · DB 故障：让 cad_circuit_state 的读写真的抛错
  · 损坏状态：把 DB 里的 state 写成不可识别的值
"""
import asyncio

import pytest

from cad import CLOSED, HALF_OPEN, OPEN, CircuitBreaker
from models import Base, CadCircuitState, async_session, engine_oltp

engine_begin = engine_oltp.begin


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


GOOD = (0.05, 0.95)   # hallucination_risk, evidence_completeness
BAD = (0.95, 0.05)


def _feed(br: CircuitBreaker, sample, times: int = 1):
    for _ in range(times):
        br.record_audit_result_sync(
            hallucination_risk=sample[0],
            evidence_completeness=sample[1],
            anomaly_detected=sample[0] > 0.4,
        )
    return br


async def _fresh_db():
    """建表并清空 cad_circuit_state —— 每条 DB 用例都必须从这里开始。

    不清表的话，「读到的是上一条用例留下的熔断」会让断言看起来通过，
    而它其实什么都没证明（实测踩过：单跑绿、全量随机红）。
    """
    from sqlalchemy import delete

    async with engine_begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    async with async_session() as s:
        await s.execute(delete(CadCircuitState))
        await s.commit()


# ══════════════════════════════════════════════════════════════
# G6-S1~S3 · 三态状态机（真实审计结果驱动）
# ══════════════════════════════════════════════════════════════

class TestStateMachine:
    def test_s1_bad_trend_trips_and_good_trend_does_not(self):
        """G6-S1：坏趋势累积到阈值 → 熔断；好趋势同样次数 → 不熔断。

        正对照必须存在，否则「熔断阈值=0」这种退化实现也能过。
        """
        br = _feed(CircuitBreaker(persist=False), BAD, br_warm := 10)
        assert br.state.state == OPEN, f"未熔断: {br.state.state}"
        assert br.state.tripped is True
        assert br.state.reason, "熔断必须留下原因"
        assert br.state.tripped_at > 0

        ok = _feed(CircuitBreaker(persist=False), GOOD, 10)
        assert ok.state.state == CLOSED, f"好趋势被误熔断: {ok.state.state}"
        assert ok.state.tripped is False

    def test_s2_warmup_period_blocks_early_trip(self):
        """预热期内不熔断：系统刚启动时基线未建立。"""
        br = _feed(CircuitBreaker(persist=False), BAD, 3)
        assert br.state.state == CLOSED, "预热期内被误熔断"
        assert br.state.audit_count == 3

    def test_s3_half_open_is_limited_not_full_release(self):
        """G6-S2：冷却到期进入 HALF_OPEN，且是**有限试探**。

        关键断言是「不是全量放行」：HALF_OPEN 期间 tripped 仍为 True，
        探针预算被逐根消耗（probes_left 单调递减）。

        另记一条实测结论：在默认阈值下（HALF_OPEN_PROBES=3 > 成功所需
        HALF_OPEN_SUCCESSES=2），``half_open_probes_left <= 0`` 那条
        「预算耗尽 → 回 OPEN」的分支**不可达** —— 任何序列要么在第 2 根
        好探针处关闭，要么在第 1 根坏探针处立即重新熔断。
        它是防御性代码，不是活跃路径，不要拿它当「有限试探」的证据。
        """
        br = _feed(CircuitBreaker(persist=False), BAD, 10)
        assert br.state.state == OPEN
        br.state.COOLDOWN_SECONDS = 0

        _feed(br, GOOD)                       # 触发转换的这次即第一根探针
        assert br.state.state == HALF_OPEN
        assert br.state.tripped is True, "半开期间不得被视为可自动响应"
        assert br.state.half_open_probes_left == br.state.HALF_OPEN_PROBES - 1

        _feed(br, GOOD)                       # 第二根好探针 → 关闭
        assert br.state.state == CLOSED
        assert br.state.tripped is False

    def test_s3b_default_thresholds_make_exhaustion_branch_unreachable(self):
        """把上一条的结论钉死：预算耗尽分支在默认配置下走不到。

        这条的价值在于「别把不可达分支当成已验证的保护」——
        真正的有限试探保护来自「坏探针立即回熔断」(s4) 与
        「半开期间 tripped 仍为 True」(s3)。
        """
        probes = CircuitBreaker(persist=False).state.HALF_OPEN_PROBES
        successes = CircuitBreaker(persist=False).state.HALF_OPEN_SUCCESSES
        assert probes > successes, (
            "阈值关系变了：预算耗尽分支可能重新可达，"
            "请补上该分支的执行用例并更新本条"
        )

    def test_s4_one_bad_probe_reopens_immediately(self):
        """G6-S2：半开期间**一次**坏探针即判定未恢复，不给「多试几次」。"""
        br = _feed(CircuitBreaker(persist=False), BAD, 10)
        br.state.COOLDOWN_SECONDS = 0
        _feed(br, GOOD)                       # → half_open
        assert br.state.state == HALF_OPEN
        _feed(br, BAD)
        assert br.state.state == OPEN, "坏探针后未立即重新熔断"
        assert "半开试探失败" in br.state.reason

    def test_s5_enough_good_probes_close_the_breaker(self):
        """G6-S2：连续 HALF_OPEN_SUCCESSES 根好探针才关闭。

        注意「触发转换的那次审计本身就是第一根探针」—— 所以从 OPEN
        出发只需再喂 HALF_OPEN_SUCCESSES 次好结果。多喂一次会走到
        CLOSED 分支，而此时 10 条滑窗里还留着熔断前的坏趋势，会立刻
        再次熔断（实测：喂 3 次 → 回到 OPEN/half_open）。
        """
        br = _feed(CircuitBreaker(persist=False), BAD, 10)
        br.state.COOLDOWN_SECONDS = 0
        need = br.state.HALF_OPEN_SUCCESSES
        _feed(br, GOOD, need)
        assert br.state.state == CLOSED, f"好探针后未恢复: {br.state.state}"
        assert br.state.tripped is False

    def test_s6_tripped_covers_both_non_closed_states(self):
        """G6-D1：tripped 对 open 与 half_open 都为 True。

        自动响应闸门读的就是这个属性；只覆盖 open 的话，
        半开试探期就成了无人看管的自动放行窗口。
        """
        br = CircuitBreaker(persist=False)
        assert br.state.tripped is False
        br.state.state = OPEN
        assert br.state.tripped is True
        br.state.state = HALF_OPEN
        assert br.state.tripped is True
        br.state.state = CLOSED
        assert br.state.tripped is False


# ══════════════════════════════════════════════════════════════
# G6-S7 · 「无法验证」与「运行失败」是两件事
# ══════════════════════════════════════════════════════════════

class TestNaVersusFailure:
    def test_s7_na_never_trips_but_is_observable(self):
        """G6-D4：「无可验断言」不是幻觉，累积再多也不得熔断。

        反向确认：同样次数的**真实坏趋势**会熔断 ——
        否则这条可能只是因为阈值太高而空过。
        """
        br = CircuitBreaker(persist=False)
        for _ in range(50):
            br.record_na(notes="single-source: 无分解证据可穿透验证")
        assert br.state.state == CLOSED, "无可验断言被当成幻觉累积"
        assert br.state.audit_count == 50
        # NA 的计数字段叫 unverifiable_count（不是 na_count）
        assert br.get_status()["unverifiable_count"] == 50, "NA 未被单独计数（不可观测）"
        assert "无分解证据" in br.state.last_na_note

        mirror = _feed(CircuitBreaker(persist=False), BAD, 10)
        assert mirror.state.state == OPEN, "对照组失效：真实坏趋势也没熔断"

    def test_s8_supervision_failures_trip_with_distinct_reason(self):
        """G6-D3：监督系统**自身**连续故障达阈值 → 熔断，且原因可区分。

        熔断原因必须与质量原因不同，否则运维看到「连续审核质量低」
        会去查模型，而真实原因是 CAD 自己挂了。
        """
        br = CircuitBreaker(persist=False)
        br.state.SUPERVISION_FAILURE_THRESHOLD = 3

        async def run():
            await br.record_supervision_failure("CAD db down #1")
            assert br.state.state != OPEN, "1 次故障就熔断，阈值不生效"
            await br.record_supervision_failure("CAD db down #2")
            assert br.state.state != OPEN, "2 次故障就熔断"
            await br.record_supervision_failure("CAD db down #3")

        _run(run())
        assert br.state.state == OPEN
        assert "监督系统自身" in br.state.reason
        assert "CAD db down" in br.state.reason, "熔断原因里看不到实际错误"
        assert br.state.last_supervision_error == "CAD db down #3"

    def test_s9_successful_supervision_clears_the_failure_counter(self):
        """G6-D3：一次成功的监督运行是**反向信号**，必须清零故障计数。

        没有这条，监督坏过一次就永远坏着 —— 熔断后再也不会自动恢复。
        """
        br = CircuitBreaker(persist=False)
        br.state.SUPERVISION_FAILURE_THRESHOLD = 99

        async def run():
            await br.record_supervision_failure("boom")
            await br.record_supervision_failure("boom")
            assert br.state.supervision_failures == 2
            await br.clear_supervision_failures()

        _run(run())
        assert br.state.supervision_failures == 0, "成功后故障计数未清零"
        assert br.state.last_supervision_error == ""

    def test_s10_supervision_failure_is_distinct_from_quality_in_status(self):
        """G6-D4：/cad/status 必须能分辨「质量差」与「监督挂了」。"""
        br = CircuitBreaker(persist=False)
        br.state.SUPERVISION_FAILURE_THRESHOLD = 99
        _run(br.record_supervision_failure("boom"))

        st = br.get_status()
        assert st["supervision_failures"] == 1
        assert st["last_supervision_error"] == "boom"
        # NA 计数与故障计数是**两个**字段，不共用一个数字
        assert st["unverifiable_count"] == 0
        assert st["supervision_failures"] == 1


# ══════════════════════════════════════════════════════════════
# G6-S4/S5 · 跨进程持久化 + 真实 DB 故障注入
# ══════════════════════════════════════════════════════════════

class _FailingSession:
    """对 cad_circuit_state 的读写抛错（模拟 DB 不可用）。

    **不改 schema**：测试跑在共享 sqlite :memory: engine 上，
    DROP/重建真表会污染同进程后续测试。
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
        return self

    async def __aenter_tx__(self):
        return self

    async def get(self, model, ident):
        raise RuntimeError("db unavailable (get)")

    async def execute(self, *a, **kw):
        raise RuntimeError("db unavailable (execute)")

    async def commit(self):
        raise RuntimeError("db unavailable (commit)")

    def add(self, *a, **kw):
        raise RuntimeError("db unavailable (add)")


class TestCrossProcessPersistence:
    def test_s11_trip_survives_a_fresh_instance(self):
        """G6-S4：进程 A 熔断 → 进程 B（全新实例）必须读到 OPEN。

        本项目 FastAPI 与 Temporal worker 分进程部署；
        熔断只在 worker 生效的话，/cad/status 会一直显示正常。
        """

        async def scenario():
            await _fresh_db()
            a = CircuitBreaker(persist=True)
            a.state.WARMUP_AUDITS = 0
            await a.record_audit_result(BAD[0], BAD[1], True)
            assert a.state.state == OPEN, "A 进程未熔断"

            b = CircuitBreaker(persist=True)
            assert b.state.state == CLOSED, "新实例初始应为内存态（对照前提）"
            ok = await b._load_persisted()
            assert ok, "持久化状态读不回来"
            assert b.state.state == OPEN, "熔断未跨进程共享"
            assert b.state.tripped is True

        _run(scenario())

    def test_s12_half_open_is_visible_to_other_processes(self):
        """G6-S4：半开试探态也必须落库，否则另一进程会当成已恢复。"""

        async def scenario():
            await _fresh_db()
            a = CircuitBreaker(persist=True)
            a.state.WARMUP_AUDITS = 0
            a.state.COOLDOWN_SECONDS = 0
            await a.record_audit_result(BAD[0], BAD[1], True)
            assert a.state.state == OPEN

            b = CircuitBreaker(persist=True)
            b.state.COOLDOWN_SECONDS = 0
            await b.record_audit_result(GOOD[0], GOOD[1], False)
            assert b.state.state == HALF_OPEN

            c = CircuitBreaker(persist=True)
            await c._load_persisted()
            assert c.state.state == HALF_OPEN, "HALF_OPEN 未跨进程可见"
            assert c.state.tripped is True

        _run(scenario())

    def test_s13_unreadable_state_fails_closed(self):
        """G6-S4：DB 里的状态值不可识别时，必须按 OPEN 处理。

        失败方向必须是「拿不准就不放行」：
        原实现原样读入 row.state，而 tripped 判据是
        ``state in ("open","half_open")`` —— 一条**状态不可读**的记录
        等于熔断器被静默关闭。

        注意只取**真正非法**的值：读取端会做 ``.strip().lower()``，
        所以 "Open"/"OPEN"/"CLOSED" 这类大小写变体是合法的，
        它们归到下面的正对照里。``None`` 也不在列表里 ——
        ``cad_circuit_state.state`` 是 NOT NULL 列，写不进去，
        「库里没有 state」不是本用例要覆盖的形态（那是另一类故障）。
        """

        async def scenario():
            await _fresh_db()
            async with async_session() as s:
                s.add(CadCircuitState(
                    id=1, state="TRIPPED", reason="?", tripped_at=0.0,
                    consecutive_bad=0, audit_count=0, supervision_failures=0,
                    last_supervision_error="", half_open_probes_left=0, version=0,
                ))
                await s.commit()

            for bad in ("TRIPPED", "half-open", "bogus", "", "closed!"):
                async with async_session() as s:
                    row = await s.get(CadCircuitState, 1)
                    row.state = bad
                    await s.commit()

                br = CircuitBreaker(persist=True)
                await br._load_persisted()
                assert br.state.state == OPEN, \
                    f"损坏状态 {bad!r} 被读成 {br.state.state!r}（应为 OPEN）"
                assert br.state.tripped is True
                assert "不可识别" in br.state.reason

        _run(scenario())

    def test_s14_control_recognised_states_are_read_back_exactly(self):
        """正对照：合法状态（含大小写变体）必须被**归一后**原样读回。

        "Open"/"OPEN" 经 ``.strip().lower()`` 等价于 "open"，
        它们不是损坏数据，不能被一刀切成 OPEN。
        """
        async def scenario():
            await _fresh_db()
            cases = [(CLOSED, CLOSED), (OPEN, OPEN), (HALF_OPEN, HALF_OPEN),
                     ("Open", OPEN), ("OPEN", OPEN), (" half_open ", HALF_OPEN)]
            for raw, expected in cases:
                async with async_session() as s:
                    row = await s.get(CadCircuitState, 1)
                    if row is None:
                        s.add(CadCircuitState(id=1, state=raw, reason="r",
                                              tripped_at=1.0, consecutive_bad=0,
                                              audit_count=0, supervision_failures=0,
                                              last_supervision_error="",
                                              half_open_probes_left=0, version=0))
                    else:
                        row.state = raw
                    await s.commit()

                br = CircuitBreaker(persist=True)
                assert await br._load_persisted() is True
                assert br.state.state == expected, \
                    f"合法状态 {raw!r} 被读成 {br.state.state!r}（应为 {expected!r}）"

        _run(scenario())

    def test_s15_db_failure_is_recorded_not_silently_swallowed(self, monkeypatch):
        """G6-S5 故障注入：DB 全挂时，落库失败必须留下可观测痕迹。

        反向确认：同样注入故障，一次成功的 ``record_audit_result``
        在 DB 正常时不会留下 store_error。
        """

        async def scenario():
            await _fresh_db()
            import models as _models
            real = _models.async_session
            monkeypatch.setattr(
                _models, "async_session",
                lambda *a, **kw: _FailingSession(real),
            )

            br = CircuitBreaker(persist=True)
            br.state.WARMUP_AUDITS = 0
            br.state.SUPERVISION_FAILURE_THRESHOLD = 99
            ok = await br._persist()
            assert ok is False, "DB 全挂时 _persist 竟然报告成功"
            assert br._store_error, "持久化失败没有留下可观测错误"

            # 记录一次监督故障：写不进去仍必须计数，不能静默
            await br.record_supervision_failure("boom during db outage")
            assert br.state.supervision_failures == 1, \
                "DB 故障时监督故障未被计数"

        _run(scenario())

        monkeypatch.undo()
        healthy = CircuitBreaker(persist=True)
        _run(healthy._persist())
        assert healthy._store_error == "", "DB 正常时不应有 store_error"

    def test_s16_persist_failure_does_not_recurse_forever(self, monkeypatch):
        """G6-S5：_persist ↔ record_supervision_failure 互调必须有递归守卫。"""
        import models as _models
        real = _models.async_session
        monkeypatch.setattr(
            _models, "async_session",
            lambda *a, **kw: _FailingSession(real),
        )

        br = CircuitBreaker(persist=True)
        br.state.WARMUP_AUDITS = 0
        br.state.SUPERVISION_FAILURE_THRESHOLD = 99
        _run(br.record_audit_result(BAD[0], BAD[1], True))  # 不得 RecursionError

    def test_s17_control_persist_actually_round_trips(self):
        """正对照：DB 正常时状态真的写得进、读得回。

        没有这条，s15/s16 可能只是因为表根本不存在才「失败」。
        """

        async def scenario():
            await _fresh_db()
            a = CircuitBreaker(persist=True)
            a.state.WARMUP_AUDITS = 0
            await a.record_audit_result(BAD[0], BAD[1], True)
            assert a._store_error == ""

            async with async_session() as s:
                row = await s.get(CadCircuitState, 1)
                assert row is not None, "熔断状态未落库（行不存在）"
                assert row.state == OPEN

        _run(scenario())


# ══════════════════════════════════════════════════════════════
# G6-S9 · 生产单例与观测面
# ══════════════════════════════════════════════════════════════

class TestSupervisionSurface:
    def test_s18_production_singleton_is_persistent(self):
        """生产单例必须开启持久化，否则跨进程一致性在测试里绿、上线就失效。"""
        from cad import circuit_breaker as singleton

        st = singleton.get_status()
        assert st["persistent"] is True
        assert "version" in st
        assert "state" in st and "tripped" in st

    def test_s19_report_carries_the_state_the_gate_reads(self):
        """G6-D1：CAD 报告里的 circuit_breaker 必须是状态机自己的输出。"""
        br = _feed(CircuitBreaker(persist=False), BAD, 10)
        st = br.get_status()
        assert st["tripped"] is True
        assert st["state"] == OPEN
        assert st["reason"] == br.state.reason
