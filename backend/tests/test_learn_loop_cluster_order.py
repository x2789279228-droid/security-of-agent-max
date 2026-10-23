# -*- coding: utf-8 -*-
"""学习闭环的**聚类必须与输入顺序无关**（整改报告 §9.49）。

## 背景

整改方案 §十.2 点名了一条性质：

> 「只比较簇代表，结果依赖插入顺序 | 明确采用的聚类策略，并通过**样本排列测试**
> 验证稳定性」
> 「最终需要验证：相同样本集合仅改变输入顺序，不会产生不可解释的簇变化」

`learn_loop/models_cluster.py::build_clusters` 是学习闭环（`scheduler.py` 每日
02:15 UTC + `POST /api/ops/learn-loop/run`）的 FP/漏报**家族聚类**。
它此前有**两个**顺序依赖：

1. **簇划分依赖到达顺序** —— 贪心算法把新样本只与「簇代表」比，
   而簇代表是**已并入成员的并集**（会长大）。
   实测：3 个样本，顺序 `[A,B,C]` 得 **1** 个簇，顺序 `[A,C,B]` 得 **2** 个簇。
2. **簇号是位置号** —— `learn_cluster_{idx}` 由创建顺序决定，
   而 `propose` 的 24h 去重键正是 `label_cluster:{cluster_id}`
   → 另一个家族**静默地**被去重吞掉，人工打标永远轮不到它。

取数侧也缺一环：`orchestrator._step_clusters` 的查询**没有 ORDER BY**
（`IN (...)` 不保证返回顺序）→ 同一批事件两次查询的顺序可能不同。

## 本守卫盯什么

1. **排列测试**：同一批样本的所有排列 → 同一划分、同一簇号；
2. **簇号内容寻址**：不同家族不撞号；加入无关家族不改变另一个簇的号；
3. **鲁棒**：非数字 id 不再让**整次**聚类丢失；
4. **取数显式定序**（AST 层，结构性检查）；
5. **反向判据**：相似事件**仍然**要能并成一个簇（不许把修复做成「都不聚」）。
"""
from __future__ import annotations

import ast
import itertools
import os
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND))

from learn_loop.models_cluster import build_clusters  # noqa: E402

#: 三个人工构造的事件，刻意让「顺序」能改变贪心聚类的结果：
#:   sim(A,B)=2/3 ≥ 阈值、sim(B,C)=1/2 ≥ 阈值、sim(A,C)=1/4 < 阈值
#: 修复前：`[A,B,C]` → 1 个簇；`[A,C,B]` → 2 个簇（实测）。
A = {"id": 1, "event_type": "PORT_SCAN", "src_ip": "10.0.0.1", "message": ""}
B = {"id": 2, "event_type": "PORT_SCAN", "src_ip": "10.0.0.1", "message": "zeta"}
C = {"id": 3, "event_type": "BRUTE_FORCE", "src_ip": "10.0.0.1", "message": "zeta"}

#: 第二个家族：与 A/B/C 都不相似（不同网段 + 不同词）
D = {"id": 4, "event_type": "SQL_INJECTION", "src_ip": "192.168.5.7", "message": "drop table"}

#: 第三个家族：**排序上排在 A/B/C 之前**（id 0/4/5 中 0 最小）——
#: 专门用来暴露「位置号」：别的家族一来就把 X 挤到别的号上。
Y0 = {"id": 0, "event_type": "SQL_INJECTION", "src_ip": "192.168.5.7", "message": "drop table"}
Y1 = {"id": 4, "event_type": "SQL_INJECTION", "src_ip": "192.168.5.8", "message": "drop table"}
Y2 = {"id": 5, "event_type": "SQL_INJECTION", "src_ip": "192.168.5.9", "message": "drop table users"}


def _shape(clusters):
    """簇的**身份**形状：{cluster_id: (成员 event_ids, size)}。"""
    return {c["cluster_id"]: (tuple(c["event_ids"]), c["size"]) for c in clusters}


class TestTheClusteringIsOrderIndependent:
    def test_every_permutation_gives_the_same_partition(self):
        """【核心性质】同一批样本，**所有排列** → 同一划分。"""
        base = None
        for perm in itertools.permutations([A, B, C]):
            got = _shape(build_clusters(list(perm), min_size=1, threshold=0.5))
            if base is None:
                base = got
                continue
            assert got == base, f"排列 {sorted(e['id'] for e in perm)} 的划分变了：{got} != {base}"

    def test_every_permutation_gives_the_same_cluster_ids(self):
        """簇号也必须与顺序无关（内容寻址，不是位置号）。"""
        ids = set()
        for perm in itertools.permutations([A, B, C]):
            ids.add(tuple(sorted(c["cluster_id"] for c in
                                 build_clusters(list(perm), min_size=1, threshold=0.5))))
        assert len(ids) == 1, f"不同排列给出了不同的簇号集合：{ids}"

    def test_the_known_counterexample_stays_merged(self):
        """钉住那个**具体的**反例：修复前 `[A,B,C]` 是 1 个簇、`[A,C,B]` 是 2 个簇。

        现在两种顺序都必须是**同一个**结果（1 个簇，成员 {1,2,3}）。
        """
        for order in ([A, B, C], [A, C, B]):
            cl = build_clusters(list(order), min_size=1, threshold=0.5)
            assert len(cl) == 1, f"顺序 {sorted(e['id'] for e in order)} 的簇数变了：{cl}"
            assert set(cl[0]["event_ids"]) == {1, 2, 3}, cl[0]


class TestTheClusterIdIsContentAddressed:
    def test_a_family_keeps_its_id_when_another_family_sorts_before_it(self):
        """【能真正分辨「位置号」与「内容寻址」的一条】

        同一家族，**即使另一个家族排在它前面**，簇号也必须不变。

        位置号的病根就在这里：它只说「我是第几个」——
        别的家族一来（而且排在前面）就把它挤到别的号上。
        而 `propose` 的 24h 去重键正是 `label_cluster:{cluster_id}`
        → 同一个家族换个号就被当成新家族；**另一个家族**的号又可能与它撞上
        → 提议被**静默吞掉**。
        """
        x = [A, B, C]                       # id 1,2,3
        y = [Y0, Y1, Y2]                    # id 0,4,5 → 排序上排在 x 前面

        def _id_of(events, member_ids):
            for c in build_clusters(list(events), min_size=1, threshold=0.5):
                if set(c["event_ids"]) & set(member_ids):
                    return c["cluster_id"]
            return None

        alone = _id_of(x, {1, 2, 3})
        together = _id_of(x + y, {1, 2, 3})
        assert alone is not None and together is not None, "家族没被聚出来"
        assert alone == together, (
            f"同一个家族的簇号被别的家族挤变了：{alone} → {together}"
            "（位置号，不是内容寻址）")

    def test_two_different_families_never_share_a_cluster_id(self):
        """不同家族**不得**撞号 —— 撞号会让 24h 去重把一个家族静默吞掉。"""
        cl = build_clusters([A, B, C, D], min_size=1, threshold=0.5)
        ids = [c["cluster_id"] for c in cl]
        assert len(ids) == len(set(ids)), f"两个家族共用了同一个簇号：{ids}"

    def test_adding_an_unrelated_family_does_not_change_the_other_id(self):
        """加入一个**无关**家族，不得改变另一个簇的号（人工打标的锚点要稳）。"""
        before = _shape(build_clusters([A, B, C], min_size=1, threshold=0.5))
        after = _shape(build_clusters([A, B, C, D], min_size=1, threshold=0.5))
        for cid, shape in before.items():
            assert cid in after, f"加入无关家族后，原簇号 {cid} 消失了"
            assert after[cid] == shape, f"加入无关家族后，原簇 {cid} 的成员变了：{after[cid]} != {shape}"


class TestTheClusteringIsRobust:
    def test_a_non_numeric_id_does_not_destroy_the_whole_clustering(self):
        """一个坏 id 不得带走**整次**聚类。

        修复前 `int(e.get("id"))` 遇非数字 id 抛 `ValueError` →
        `orchestrator` 只能记 partial 并丢掉**全部**簇。
        """
        bad = {"id": "abc", "event_type": "PORT_SCAN", "src_ip": "10.0.0.1", "message": ""}
        cl = build_clusters([bad, A, B], min_size=1, threshold=0.5)
        assert cl, "一个非数字 id 把整次聚类带走了"
        assert sum(c["size"] for c in cl) == 3, f"成员数不对：{cl}"

    def test_events_without_any_id_are_still_clustered(self):
        """没有 id 的事件也必须能聚类（不能被当成「无效」丢掉）。"""
        e1 = {"event_type": "PORT_SCAN", "src_ip": "10.0.0.1", "message": "q"}
        e2 = {"event_type": "PORT_SCAN", "src_ip": "10.0.0.1", "message": "q"}
        cl = build_clusters([e1, e2], min_size=1, threshold=0.5)
        assert len(cl) == 1 and cl[0]["size"] == 2, cl


class TestTheProductionPathIsDeterministic:
    def test_the_event_queries_have_an_explicit_order_by(self):
        """取数必须**显式定序**（`IN (...)` 不保证返回顺序）。

        ⚠ 这是**结构性**检查（AST），不是行为检查：
        真正的性质由上面的**排列测试**保证；这里钉的是那道**纵深防御**
        ——「取数顺序确定」，免得有人删掉它之后没人发现。
        """
        src = (BACKEND / "learn_loop" / "orchestrator.py").read_text(encoding="utf-8")
        tree = ast.parse(src)

        def _is_select_security_event(call):
            if not (isinstance(call.func, ast.Name) and call.func.id == "select"):
                return False
            for a in call.args:
                if isinstance(a, ast.Name) and a.id == "SecurityEvent":
                    return True
            return False

        selects = [c for c in ast.walk(tree) if isinstance(c, ast.Call) and _is_select_security_event(c)]
        assert selects, "没找到 select(SecurityEvent) 查询 —— 判据本身失效了"

        # 找出所有 order_by(...).value 子树里包含的 select 调用
        covered = set()
        for call in ast.walk(tree):
            if not isinstance(call, ast.Call):
                continue
            if not (isinstance(call.func, ast.Attribute) and call.func.attr == "order_by"):
                continue
            for sub in ast.walk(call.func.value):
                if sub in selects:
                    covered.add(id(sub))
        missing = [s for s in selects if id(s) not in covered]
        assert not missing, (
            "这些取数查询没有 ORDER BY —— 同一批数据两次查询顺序可能不同，"
            f"聚类随之给出不同的「家族」：行 {[s.lineno for s in missing]}")


class TestTheReverseCriterion:
    def test_similar_events_still_merge_into_one_cluster(self):
        """**反向判据**：修复不得把「不聚了」当成修复。

        三个高度相似的事件必须**仍然**并成一个簇。
        """
        events = [
            {"id": 101, "event_type": "PORT_SCAN", "src_ip": "10.0.0.7",
             "message": "portscan sweep detected high volume"},
            {"id": 102, "event_type": "PORT_SCAN", "src_ip": "10.0.0.8",
             "message": "portscan sweep detected high volume"},
            {"id": 103, "event_type": "PORT_SCAN", "src_ip": "10.0.0.9",
             "message": "portscan sweep detected massive volume"},
        ]
        cl = build_clusters(events, min_size=3, threshold=0.5)
        assert len(cl) == 1, cl
        assert set(cl[0]["event_ids"]) == {101, 102, 103}, cl[0]
        assert cl[0]["net"] == "10.0.0.0/24", cl[0]


if __name__ == "__main__":       # pragma: no cover
    import pytest
    raise SystemExit(pytest.main([__file__, "-q"]))
