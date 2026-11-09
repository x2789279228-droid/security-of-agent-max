"""Wave 0-4（PERF-OPT-PLAN-2026-10-26）：PQ 三角闭合计量。

恒等式：enqueue_total = dequeue_total + lost_total + depth，
即 gap = enqueue - dequeue - lost - depth 应恒 0（容许在途抖动）。
prometheus Counter 是进程级全局 —— 测试全部用**增量**断言。
"""
import pytest

import audit_pq as pq_mod
from audit_pq import pq_depth_snapshot, pq_triangulation


@pytest.fixture(autouse=True)
def _restore_depth_cache():
    saved = pq_mod._DEPTH_CACHE.get("v")
    yield
    pq_mod._DEPTH_CACHE["v"] = saved or 0


def test_gap_zero_across_enqueue_pop_cycle():
    """入队/出队计数与深度快照同步走 → gap 增量恒 0。"""
    from metrics import inc_audit_pq_dequeue, inc_audit_pq_enqueue

    base = pq_triangulation()

    inc_audit_pq_enqueue("P1")
    pq_mod._DEPTH_CACHE["v"] += 1
    t1 = pq_triangulation()
    assert (t1["gap"] - base["gap"]) == 0
    assert (t1["depth"] - base["depth"]) == 1

    inc_audit_pq_dequeue("P1")
    pq_mod._DEPTH_CACHE["v"] -= 1
    t2 = pq_triangulation()
    assert (t2["gap"] - base["gap"]) == 0


def test_gap_counts_loss_as_zero_when_counted():
    """有计数的损耗（lost）→ 账目仍闭合。"""
    from metrics import inc_audit_pq_enqueue, inc_audit_pq_lost

    base = pq_triangulation()
    inc_audit_pq_enqueue("P0")
    inc_audit_pq_lost("expired")
    # 深度不变（入队即损耗，从未进池）→ gap 增量 0
    t = pq_triangulation()
    assert (t["gap"] - base["gap"]) == 0


def test_gap_exposes_uncounted_loss():
    """深度掉了但没有任何计数（未计数损耗路径）→ gap 增量为 +1 被暴露。"""
    # 先垫高深度（缓存可能为 0，再减会被 max(0,·) 吞掉）
    pq_mod._DEPTH_CACHE["v"] = pq_mod._DEPTH_CACHE.get("v", 0) + 3
    base = pq_triangulation()
    pq_mod._DEPTH_CACHE["v"] -= 1
    t = pq_triangulation()
    assert (t["gap"] - base["gap"]) == 1


def test_triangulation_shape_and_snapshot_consistency():
    """返回结构完整，且 depth 字段与同步快照同源（capacity 背压读同一份数）。"""
    t = pq_triangulation()
    assert set(t) == {"enqueue", "dequeue", "lost", "depth", "gap"}
    assert t["depth"] == pq_depth_snapshot()
    assert t["gap"] == t["enqueue"] - t["dequeue"] - t["lost"] - t["depth"]
