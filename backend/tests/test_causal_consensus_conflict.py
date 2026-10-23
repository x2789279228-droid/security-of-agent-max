"""因果引擎的**方向冲突**守卫（整改方案 §三.3）。

整改方案 §三.3 原文：
  「同时需要修复 GES 输出中可能同时存在 A → B 和 B → A 的矛盾方向」
  验收：「强数据证据与领域先验冲突时，保留冲突信息」

`causal_chain/ges.py::consensus()` 负责把 PC 与 GES 的结果合并。
修复前它 `for a, b in sorted(pc_dir | ges_dir)` 直接遍历并集，
PC 说 A→B、GES 说 B→A 时**两条都会进 `directed` 列表** ——
下游拿到的不是「方向不确定」，而是「两个互相矛盾的事实」。

这一组性质此前**没有回归**：`consensus()` 在生产被 `learn.py:104` 调用，
但全仓 `tests/` 搜 `consensus(` / `conflict_candidates` → 零命中
（`test_rag_hybrid.py` 里的 consensus 是 RAG 融合的另一个同名概念）。
"""
from __future__ import annotations

import os

os.environ.setdefault("SHARED_MEMORY_SKIP_DOTENV", "1")

from causal_chain.ges import consensus  # noqa: E402


def _pc(directed, skeleton=None):
    sk = skeleton if skeleton is not None else [
        list(sorted(e)) for e in directed]
    return {"directed": [list(e) for e in directed], "skeleton": sk}


def _ges(directed, undirected=None, skeleton=None):
    sk = skeleton if skeleton is not None else [
        list(sorted(e)) for e in directed] + [list(e) for e in (undirected or [])]
    return {"directed": [list(e) for e in directed],
            "undirected": [list(e) for e in (undirected or [])],
            "skeleton": sk}


class TestDirectionConflictIsPreservedNotContradicted:
    """§三.3：方向冲突要**标出来**，不能同时输出两个相反的事实。"""

    def test_opposite_directions_do_not_both_appear_as_directed(self):
        """【已修复】PC 说 A→B、GES 说 B→A → 输出**不得**同时含两条反向边。"""
        pc = _pc([("A", "B")])
        ges = _ges([("B", "A")])
        out = consensus(pc, ges)

        pairs = [(e["cause"], e["effect"]) for e in out["directed"]]
        assert ("A", "B") not in pairs or ("B", "A") not in pairs, (
            f"同时输出了两个互相矛盾的方向：{pairs}")
        assert len(out["directed"]) == 1, (
            f"冲突应当只输出一条（标为 undirected），实得 {out['directed']}")

    def test_conflict_is_marked_and_candidates_are_preserved(self):
        """【已修复】冲突必须**标出来**，并保留两个候选方向。"""
        pc = _pc([("A", "B")])
        ges = _ges([("B", "A")])
        out = consensus(pc, ges)

        edge = out["directed"][0]
        assert edge["orientation"] == "undirected", edge
        assert edge["orientation_source"] == "conflict", edge
        assert edge["confidence"] == "undirected_or_conflict", edge
        assert edge["identifiability"] == "not_identified", edge
        assert edge["conflict_candidates"] == [["A", "B"], ["B", "A"]], edge
        assert out["direction_conflicts"] == [["A", "B"]], out["direction_conflicts"]

    def test_agreeing_direction_stays_data_invariant(self):
        """【正向对照】两算法同向时仍应标成数据识别出来的方向。"""
        pc = _pc([("A", "B")])
        ges = _ges([("A", "B")])
        out = consensus(pc, ges)

        edge = out["directed"][0]
        assert edge["cause"] == "A" and edge["effect"] == "B", edge
        assert edge["orientation"] == "directed", edge
        assert edge["orientation_source"] == "data_invariant", edge
        assert edge["identifiability"] == "identified", edge
        assert edge["confidence"] == "high_confidence", edge
        assert out["direction_conflicts"] == [], out["direction_conflicts"]

    def test_score_only_edge_is_not_claimed_as_data_derived(self):
        """【已修复】GES 侧未 compelled 的边 → 方向来自搜索顺序，不是数据。

        注意前提：GES 的 `directed` 是它找到的 DAG 的**全部**边，
        而 `undirected` 是其中**可逆**的子集 —— 两者有交集。
        所以要让 `score_search` 可达，GES 必须**既**在 `directed` 里有这条边、
        **又**在 `undirected` 里标它可逆（PC 也同向时才落到 high_confidence）。
        """
        pc = _pc([("A", "B")], skeleton=[["A", "B"]])
        ges = _ges([("A", "B")], undirected=[("A", "B")], skeleton=[["A", "B"]])
        out = consensus(pc, ges)

        edge = [e for e in out["directed"] if {e["cause"], e["effect"]} == {"A", "B"}]
        assert edge, out["directed"]
        e = edge[0]
        assert e["orientation_source"] == "score_search", e
        assert e["identifiability"] == "not_identified", e

    def test_skeleton_disagreement_is_not_a_direction_conflict(self):
        """骨架不一致 ≠ 方向冲突：不能把「算法没共识」标成「方向矛盾」。"""
        pc = _pc([("A", "B")], skeleton=[["A", "B"]])
        ges = _ges([("C", "D")], skeleton=[["C", "D"]])
        out = consensus(pc, ges)

        assert out["direction_conflicts"] == [], out["direction_conflicts"]
        assert all(e.get("orientation_source") != "conflict"
                   for e in out["directed"]), out["directed"]
        assert out["only_pc"] == [["A", "B"]], out["only_pc"]
        assert out["only_ges"] == [["C", "D"]], out["only_ges"]
