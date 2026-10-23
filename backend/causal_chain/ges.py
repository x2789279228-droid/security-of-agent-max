"""GES-style BIC 贪心搜索(小 p 二进制 DAG)。

不是 Chickering 全套 CPDAG 算子;节点 ≤ 20 时 forward/backward/reverse 足够作 PC 对照。
两算法骨架一致的边才标 high_confidence。

整改方案 §三.3（不要把搜索顺序当成数据识别出来的方向）:

本实现输出的是一个**具体 DAG**（搜索过程中每步都要求无环），但
Markov 等价类里的多条 DAG 在数据上不可区分。之前 `ges_learn`
把 `"undirected"` 硬编码成 `[]`，等于宣称「每条边的方向都由数据
识别出来了」—— 那是假的：搜索先加边还是先加反向边完全取决于
遍历顺序。

现在按**v-结构**判定方向是否被数据强制：
  对边 A→B，若 B 的父集合里存在某个 A' 与 A 不相邻，
  则 (A, A', B) 是 v-结构，A→B 被数据 compelled；
  否则该边可逆 → 归入 `undirected`，并标注
  `orientation_source="score_search"`、`identifiability="not_identified"`。
真正 compelled 的边才标 `orientation_source="data_invariant"`。
"""
from __future__ import annotations

import numpy as np


def _pack_parents(data: np.ndarray, parents: tuple[int, ...]) -> np.ndarray:
    if not parents:
        return np.zeros(data.shape[0], dtype=np.int64)
    z = data[:, list(parents)].astype(np.int64)
    weights = (1 << np.arange(z.shape[1], dtype=np.int64))
    return (z * weights).sum(axis=1)


def bic_node(data: np.ndarray, child: int, parents: tuple[int, ...]) -> float:
    n = data.shape[0]
    y = data[:, child].astype(np.int8)
    keys = _pack_parents(data, parents)
    ll = 0.0
    k_params = 0
    for k in np.unique(keys):
        mask = keys == k
        ys = y[mask]
        m = int(ys.size)
        if m == 0:
            continue
        p = float(np.clip(ys.mean(), 1e-9, 1 - 1e-9))
        ones = int(ys.sum())
        ll += ones * np.log(p) + (m - ones) * np.log(1 - p)
        k_params += 1
    return float(ll - 0.5 * k_params * np.log(max(n, 2)))


def bic_graph(data: np.ndarray, parents: dict[int, tuple[int, ...]]) -> float:
    return float(sum(bic_node(data, i, parents.get(i, ())) for i in range(data.shape[1])))


def _has_cycle(parents: dict[int, tuple[int, ...]], p: int) -> bool:
    visiting = set()
    seen = set()

    def dfs(n: int) -> bool:
        if n in visiting:
            return True
        if n in seen:
            return False
        visiting.add(n)
        for pr in parents.get(n, ()):
            if dfs(pr):
                return True
        visiting.remove(n)
        seen.add(n)
        return False

    return any(dfs(i) for i in range(p))


def ges_learn(
    data: np.ndarray,
    names: list[str],
    *,
    max_parents: int = 3,
) -> dict:
    data = np.asarray(data, dtype=np.uint8)
    p = data.shape[1]
    parents: dict[int, tuple[int, ...]] = {i: () for i in range(p)}
    score = bic_graph(data, parents)

    def try_apply(new_parents) -> bool:
        nonlocal parents, score
        if _has_cycle(new_parents, p):
            return False
        s = bic_graph(data, new_parents)
        if s > score + 1e-9:
            parents = new_parents
            score = s
            return True
        return False

    improved = True
    while improved:
        improved = False
        best = None
        best_s = score
        for child in range(p):
            pa = parents[child]
            if len(pa) >= max_parents:
                continue
            for pr in range(p):
                if pr == child or pr in pa:
                    continue
                cand = dict(parents)
                cand[child] = tuple(sorted(pa + (pr,)))
                if _has_cycle(cand, p):
                    continue
                s = bic_graph(data, cand)
                if s > best_s + 1e-9:
                    best_s = s
                    best = cand
        if best is not None:
            parents = best
            score = best_s
            improved = True

    improved = True
    while improved:
        improved = False
        best = None
        best_s = score
        for child in range(p):
            pa = parents[child]
            for pr in pa:
                cand = dict(parents)
                cand[child] = tuple(x for x in pa if x != pr)
                s = bic_graph(data, cand)
                if s > best_s + 1e-9:
                    best_s = s
                    best = cand
        if best is not None:
            parents = best
            score = best_s
            improved = True

    improved = True
    while improved:
        improved = False
        best = None
        best_s = score
        for child in range(p):
            for pr in parents[child]:
                if child in parents[pr]:
                    continue
                cand = dict(parents)
                cand[child] = tuple(x for x in parents[child] if x != pr)
                if len(cand[pr]) >= max_parents:
                    continue
                cand[pr] = tuple(sorted(cand[pr] + (child,)))
                if _has_cycle(cand, p):
                    continue
                s = bic_graph(data, cand)
                if s > best_s + 1e-9:
                    best_s = s
                    best = cand
        if best is not None:
            parents = best
            score = best_s
            improved = True

    directed = []
    for child, pa in parents.items():
        for pr in pa:
            directed.append((names[pr], names[child]))
    skeleton = {tuple(sorted(e)) for e in directed}
    compelled, reversible = _split_by_vstructure(parents, p, names)
    return {
        "algorithm": "ges",
        "directed": sorted(directed),
        "undirected": sorted(reversible),
        "compelled": sorted(compelled),
        "skeleton": sorted(skeleton),
        "bic": score,
        "n": int(data.shape[0]),
        "p": p,
        "note": ("greedy BIC search over DAGs; no CPDAG projection. "
                 "Edges not compelled by a v-structure have "
                 "orientation_source=score_search, not data."),
    }


def _split_by_vstructure(
    parents: dict[int, tuple[int, ...]], p: int, names: list[str]
) -> tuple:
    """把 DAG 的边拆成「数据强制方向」与「搜索顺序决定方向」。

    判定：边 A→B 被 compelled ⟺ 存在 A' ∈ pa(B)，A' 与 A 在骨架上不相邻。
    此时 (A, A', B) 构成 collider，不改变 A→B 就会破坏 v-结构，
    所以任何与该 Markov 等价类同分布的 DAG 都必须保持 A→B。
    其余边两端都可逆（CPDAG 里就是无向边），本实现没做 CPDAG 投影，
    因此只能如实标成 `undirected`，而不是假装方向来自数据。
    """
    adj: set[frozenset] = set()
    for child, pa in parents.items():
        for pr in pa:
            adj.add(frozenset((pr, child)))
    compelled: list[list[str]] = []
    reversible: list[list[str]] = []
    for child, pa in parents.items():
        for pr in pa:
            forced = any(
                other != pr and frozenset((other, child)) in adj
                and frozenset((pr, other)) not in adj
                for other in pa
            )
            (compelled if forced else reversible).append([names[pr], names[child]])
    return compelled, reversible


def consensus(pc_result: dict, ges_result: dict) -> dict:
    """骨架一致 → high_confidence;只一边有 → algorithm_disagree。

    整改方案 §三.3：修复「同一对节点同时输出 A→B 和 B→A」的矛盾。

    修复前 `for a, b in sorted(pc_dir | ges_dir)` 直接遍历并集，
    PC 说 A→B、GES 说 B→A 时两条都会进 `directed` 列表 ——
    下游拿到的不是「方向不确定」，而是「两个互相矛盾的事实」。
    修复后：同一骨架上若两算法方向相反，只输出一条，
    `orientation="undirected"`、`orientation_source="conflict"`、
    `confidence="undirected_or_conflict"`、
    `identifiability="not_identified"`。
    """
    pc_sk = {tuple(sorted(e)) for e in pc_result.get("skeleton") or []}
    ges_sk = {tuple(sorted(e)) for e in ges_result.get("skeleton") or []}
    both = pc_sk & ges_sk
    only_pc = pc_sk - ges_sk
    only_ges = ges_sk - pc_sk
    pc_dir = {(a, b) for a, b in pc_result.get("directed") or []}
    ges_dir = {(a, b) for a, b in ges_result.get("directed") or []}
    ges_und = {tuple(sorted(e)) for e in ges_result.get("undirected") or []}

    oriented: list[dict] = []
    conflicts: set[tuple[str, str]] = set()
    for a, b in sorted(pc_dir | ges_dir):
        sk = tuple(sorted((a, b)))
        if sk not in both:
            conf = "algorithm_disagree"
        elif (a, b) in pc_dir and (a, b) in ges_dir:
            conf = "high_confidence"
        elif (a, b) in pc_dir or (a, b) in ges_dir:
            # 骨架一致但定向不一
            if (b, a) in pc_dir or (b, a) in ges_dir:
                conf = "undirected_or_conflict"
                conflicts.add(sk)
            else:
                conf = "high_confidence" if (a, b) in pc_dir and (a, b) in ges_dir else "oriented_by_one"
        else:
            conf = "algorithm_disagree"
        oriented.append({"cause": a, "effect": b, "confidence": conf})

    seen_sk: set[tuple[str, str]] = set()
    directed: list[dict] = []
    for e in oriented:
        sk = tuple(sorted((e["cause"], e["effect"])))
        if sk in conflicts:
            if sk in seen_sk:
                continue          # 丢掉互为反向的那一条，避免输出矛盾
            seen_sk.add(sk)
            a, b = sorted(sk)
            directed.append({
                "cause": a, "effect": b,
                "orientation": "undirected",
                "orientation_source": "conflict",
                "confidence": "undirected_or_conflict",
                "identifiability": "not_identified",
                "conflict_candidates": [[a, b], [b, a]],
            })
            continue
        # GES 侧未 compelled 的边：方向来自搜索顺序，不是数据
        from_score_only = e["confidence"] == "high_confidence" and sk in ges_und
        item = dict(e)
        item["orientation"] = "directed"
        item["orientation_source"] = (
            "score_search" if from_score_only else "data_invariant")
        item["identifiability"] = (
            "not_identified" if from_score_only else "identified")
        directed.append(item)
    return {
        "directed": directed,
        "skeleton_agree": [list(e) for e in sorted(both)],
        "only_pc": [list(e) for e in sorted(only_pc)],
        "only_ges": [list(e) for e in sorted(only_ges)],
        "agree_rate": (len(both) / max(len(pc_sk | ges_sk), 1)),
        "direction_conflicts": [list(e) for e in sorted(conflicts)],
    }
