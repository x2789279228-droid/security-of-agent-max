"""
P3-6（第二处）：规则沙箱 ``/rules/sandbox`` 的查询参数上界，以及
「审计工具 / 规则沙箱」两条路径共享同一份判定规则的收敛契约。

修复的缺陷（先核实再动手，不是读一行路由就下结论）：
    ``rule_manager.sandbox_test`` 的 ``event_ids`` 分支写成
    ``select(SecurityEvent).where(SecurityEvent.id.in_(event_ids))``
    之后直接 ``.scalars().all()`` —— **不套 limit**，与 P3-6 修复前的
    ``tool_registry._event_store_query`` 是同一个缺陷形状；
    ``limit`` 也没有上界。入口是 ``POST /ops/rules/sandbox``，
    参数直接取自请求体 ``body.get("event_ids")`` / ``body.get("limit", 100)``
    （admin 门控）。

    比审计工具更贵一档：取回的每一行还要跑一次完整的 Sigma
    ``detector.detect()``，所以同样的 ID 数量放大出更多 CPU 开销。

为什么是**拒绝**而不是截断（与审计工具侧同一判据）：
    截断后算出的 hit_rate / fp_rate 是「前 500 条里的命中率」，
    而调用方拿它做规则调优 —— 那是一个比越界查询更难被发现的错误结论。

全仓收敛扫描（37 处 ``.in_(``，35 处生产代码）确认的现状：
    · tool_registry.py        已由 P3-6 封顶
    · rule_manager.py         本文件覆盖（唯一从请求体可达的无界实例）
    · learn_loop/orchestrator 已有界 ``[:_settings_int(..., 5000)]``
    · event_replay.py         已有界 ``[:32]``
    · case_manager / post_mortem_service   取内部累积的 case.event_ids
    · vector_store / rag      由检索 top_k 约束
    · 其余约 22 处            枚举字面量，与本缺陷无关
"""
import pytest

import rule_manager as rm_mod
import tool_registry as tr_mod
from capacity import check_query_bounds


def _run(coro):
    import asyncio
    return asyncio.run(coro)


class _ScalarResult:
    def __init__(self, rows):
        self._rows = rows

    def scalars(self):
        return self

    def all(self):
        return list(self._rows)


class _EmptySession:
    """沙箱在越界检查之后才会执行查询，这里让它返回 0 行。"""

    async def execute(self, stmt):
        return _ScalarResult([])


# ══════════════════════════════════════════════════════════════════
# A. 中立规则本身的契约
# ══════════════════════════════════════════════════════════════════

class TestSharedRuleContract:
    """``capacity.check_query_bounds`` 只判定、不抛异常。

    两个调用点的错误表达不同（工具侧要抛异常进 ToolResult，
    沙箱侧沿用 dict 风格），规则只有一份，表达留给各自模块。
    """

    def test_returns_none_when_within_bound(self):
        assert check_query_bounds(limit=100, event_ids=[1, 2, 3]) is None
        assert check_query_bounds(limit=100) is None
        assert check_query_bounds(event_ids=list(range(500))) is None

    def test_reports_offending_field_and_bound(self):
        assert check_query_bounds(limit=100000) == ("limit", 100000, 1000)
        assert check_query_bounds(limit=0) == ("limit", 0, 1000)
        assert check_query_bounds(event_ids=list(range(501))) == (
            "event_ids", 501, 500
        )

    def test_non_numeric_limit_is_a_violation_not_a_crash(self):
        assert check_query_bounds(limit="abc")[0] == "limit"

    def test_limit_takes_precedence_over_event_ids(self):
        """两个都越界时先报 limit —— 判定顺序必须是确定的。"""
        v = check_query_bounds(limit=99999, event_ids=list(range(999)))
        assert v[0] == "limit"


# ══════════════════════════════════════════════════════════════════
# B. 规则沙箱：负面测试
# ══════════════════════════════════════════════════════════════════

class TestSandboxRejectsOutOfBounds:
    def test_event_ids_over_bound_is_rejected(self):
        out = _run(rm_mod.rule_manager.sandbox_test(
            _EmptySession(), {"name": "r"}, event_ids=list(range(501)), limit=501,
        ))
        assert out["success"] is False
        assert out["field"] == "event_ids"
        assert out["limit"] == 500

    def test_limit_over_bound_is_rejected(self):
        out = _run(rm_mod.rule_manager.sandbox_test(
            _EmptySession(), {"name": "r"}, event_ids=None, limit=100000,
        ))
        assert out["success"] is False
        assert out["field"] == "limit"

    def test_nonpositive_limit_is_rejected(self):
        out = _run(rm_mod.rule_manager.sandbox_test(
            _EmptySession(), {"name": "r"}, limit=0,
        ))
        assert out["success"] is False
        assert out["field"] == "limit"

    def test_rejection_never_reaches_the_database(self):
        """越界时不得打到 DB —— 这是这条修复真正要拦下的成本。"""
        class _Boom:
            async def execute(self, stmt):
                raise AssertionError("越界请求不应执行到数据库")

        out = _run(rm_mod.rule_manager.sandbox_test(
            _Boom(), {"name": "r"}, event_ids=list(range(501)), limit=501,
        ))
        assert out["success"] is False


# ══════════════════════════════════════════════════════════════════
# C. 防过度收紧
# ══════════════════════════════════════════════════════════════════

class TestSandboxStillWorksWithinBound:
    def test_within_bound_query_runs(self):
        """正好等于上界的合法请求必须照常跑完。"""
        out = _run(rm_mod.rule_manager.sandbox_test(
            _EmptySession(), {"name": "r"},
            event_ids=list(range(500)), limit=500,
        ))
        assert "success" not in out, "合法请求被误拒"
        assert out["total_tested"] == 0
        assert out["hit_rate"] == 0.0

    def test_default_limit_still_runs(self):
        out = _run(rm_mod.rule_manager.sandbox_test(
            _EmptySession(), {"name": "r"},
        ))
        assert "success" not in out


# ══════════════════════════════════════════════════════════════════
# D. 收敛契约：两条路径共享同一份上界
# ══════════════════════════════════════════════════════════════════

class TestTwoPathsShareOneBound:
    """这是「一份权威规则」的定义：改配置，两处一起变。

    只测单侧会漏掉「两处各自抄了一份上界、改了一处忘了另一处」这种漂移。
    """

    def test_shrinking_bound_applies_to_both_paths(self, monkeypatch):
        from config import settings

        mp = pytest.MonkeyPatch()
        try:
            mp.setattr(settings, "tool_query_max_event_ids", 5)

            # 路径一：规则沙箱
            out = _run(rm_mod.rule_manager.sandbox_test(
                _EmptySession(), {"name": "r"},
                event_ids=list(range(6)), limit=6,
            ))
            assert out["success"] is False and out["limit"] == 5

            # 路径二：审计工具
            import mcp_guard as mg

            class _NoneDetector:
                def observe_pre_exec(self, rec):
                    return None

            monkeypatch.setattr(mg.mcp_guard, "detector", _NoneDetector())
            reg = tr_mod.ToolRegistry()
            reg.register("t.q", tr_mod._event_store_query, description="q",
                         risk_level=tr_mod.RISK_LOW)
            with pytest.raises(tr_mod.ToolParameterRejected) as ei:
                _run(reg.execute("t.q", session=None,
                                 event_ids=list(range(6)), limit=6))
            assert ei.value.limit == 5
        finally:
            mp.undo()

    def test_zero_bound_denies_everything_on_both_paths(self, monkeypatch):
        """上界 0 = 全部拒绝，且**不能**被吞回默认值。

        capacity._int_setting 写的是 ``int(getattr(...) or default)``，
        会把 0 变成 1000；这里两个调用点都必须走 strict_int_setting 那条路。
        """
        from config import settings

        mp = pytest.MonkeyPatch()
        try:
            mp.setattr(settings, "tool_query_max_limit", 0)

            out = _run(rm_mod.rule_manager.sandbox_test(
                _EmptySession(), {"name": "r"}, limit=1,
            ))
            assert out["success"] is False, "上界 0 未生效 —— 0 被吞成默认值了"

            import mcp_guard as mg

            class _NoneDetector:
                def observe_pre_exec(self, rec):
                    return None

            monkeypatch.setattr(mg.mcp_guard, "detector", _NoneDetector())
            with pytest.raises(tr_mod.ToolParameterRejected):
                tr_mod._check_query_bounds("t.q", limit=1)
        finally:
            mp.undo()
