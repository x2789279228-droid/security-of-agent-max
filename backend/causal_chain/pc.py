"""PC 算法(约束式) — 二进制变量 + G² 条件独立。

输出 CPDAG: directed 有向边, undirected 未定向边。未定向边不算 CEP 因果支持。
Pearl 第 1→2 层的结构输入,不在本文件做 do()。
"""
from __future__ import annotations

from itertools import combinations
from typing import Iterable, Optional

import numpy as np

try:
    from scipy.stats import chi2 as _chi2
except Exception:  # pragma: no cover
    _chi2 = None

try:
    import scipy as _scipy
except Exception:  # pragma: no cover
    _scipy = None


def stat_backend() -> dict:
    """当前 G² 检验所用的**统计后端**及其版本。

    整改方案 §九.1 / §十一.2 要求「统一并记录统计后端、依赖版本和
    检验参数」。

    为什么这条必须落进输出而不是只写在文档里：修复前的兜底对任意 df
    都套用 df=1 的公式，它**改变 p 值**。也就是说同一份数据在装了
    scipy 的机器和没装的机器上学出的图可能不同，而结果里没有任何
    痕迹能区分这两张图。没有后端记录，「结果可追溯」就无从谈起。

    返回值刻意用纯 dict + str，便于随图 JSON 落库。
    """
    if _chi2 is not None:
        return {
            "chi2": "scipy.stats.chi2.sf",
            "scipy_version": getattr(_scipy, "__version__", "") if _scipy else "",
        }
    return {"chi2": "gammaincc_fallback", "scipy_version": ""}


def test_parameters(alpha: float, max_cond: int) -> dict:
    """检验参数快照 —— 与 ``stat_backend`` 一起构成结果的可追溯性。"""
    return {"alpha": float(alpha), "max_cond": int(max_cond)}


def _gammaincc(a: float, x: float) -> float:
    """正则化上不完全 Gamma 函数 Q(a, x)（无 scipy 时的 χ² 兜底）。

    序列展开 + Lentz 连分式，标准 Numerical Recipes 做法。
    a = df/2, x = stat/2 时 Q(a, x) 就是卡方上尾概率。
    """
    import math

    if x < 0.0 or a <= 0.0:
        return float("nan")
    if x == 0.0:
        return 1.0
    if x < a + 1.0:                       # 小的 x 用级数展开 P(a,x)，Q = 1 - P
        ap = a
        total = 1.0 / a
        delta = total
        for _ in range(1000):
            ap += 1.0
            delta *= x / ap
            total += delta
            if abs(delta) < abs(total) * 1e-15:
                break
        p = total * math.exp(-x + a * math.log(x) - math.lgamma(a))
        return float(min(1.0, max(0.0, 1.0 - p)))
    # 大的 x 用连分式直接算 Q(a,x)
    tiny = 1e-300
    b = x + 1.0 - a
    c = 1.0 / tiny
    d = 1.0 / b
    h = d
    for i in range(1, 1000):
        an = -i * (i - a)
        b += 2.0
        d = an * d + b
        if abs(d) < tiny:
            d = tiny
        c = b + an / c
        if abs(c) < tiny:
            c = tiny
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < 1e-15:
            break
    q = math.exp(-x + a * math.log(x) - math.lgamma(a)) * h
    return float(min(1.0, max(0.0, q)))


def _chi2_sf(stat: float, df: int) -> float:
    """χ² 上尾概率。df <= 0 → NaN（**不可计算**），不再是 1.0。

    整改方案 §提交 E：修复前 `df <= 0 → return 1.0`，而 G² 检验里
    「p 大」的含义是「不能拒绝独立」→ 于是**算不出来的检验被当成了
    「两变量独立」的证据**，直接把边删掉。那是最坏的一种错误：
    没有证据，却给出了确定的否定结论。
    """
    if df <= 0:
        return float("nan")
    if not (stat == stat):                # NaN 透传
        return float("nan")
    if _chi2 is not None:
        return float(_chi2.sf(max(stat, 0.0), df))
    # 无 scipy：用正则化上不完全 Gamma，**任意 df 都正确**
    # （修复前恒用 erfc，那是 df=1 的公式，对 df>1 系统性偏小）
    return _gammaincc(df / 2.0, max(stat, 0.0) / 2.0)


#: 不可判定的原因分类。整改方案 §十一 要求监控「因果检验的自由度、稀疏度」，
#: 但 NaN 只有「算不出来」这一个出口 —— 样本太少、变量恒定、分层全退化
#: 是三种完全不同的运维问题，合成一个数字就又回到「压成一个计数」。
G2_UNDECIDABLE_REASONS = ("same_var", "too_few_rows", "all_strata_degenerate")


def g2_pvalue(
    data: np.ndarray,
    i: int,
    j: int,
    cond: Iterable[int],
    tally: Optional[dict] = None,
) -> float:
    """G² 条件独立 p 值。p 大 → 不能拒绝独立。

    **算不出来时返回 NaN**，调用方必须区分 NaN（不可判定）与 1.0
    （判定为独立）。修复前 `n < 8` / `i == j` / `df <= 0` 一律返回
    1.0，也就是「样本不够，所以判定独立」—— 把证据不足写成了
    确定的否定结论。

    ``tally`` 是可选的出参，累加各原因计数与检验总量。
    它是**旁路**：不传就完全不产生开销，行为与不传时逐位一致。

    ⚠️ 别把「自由度」直接当成可观测指标：df 是每个检验各自的量，
    没有单一值可报。可报的是 **df<=0 的检验数**（`df_degenerate`）——
    那才是「检验做不了」的规模，而稀疏度另有 `untestable_pairs`。
    """
    def _bump(key: str) -> None:
        if tally is not None:
            tally[key] = tally.get(key, 0) + 1

    n = data.shape[0]
    _bump("tests_total")
    if i == j:
        _bump("same_var")
        return float("nan")
    if n < 8:
        _bump("too_few_rows")
        return float("nan")
    cond = tuple(int(c) for c in cond)
    x = data[:, i].astype(np.int8)
    y = data[:, j].astype(np.int8)
    if cond:
        z = data[:, list(cond)].astype(np.int64)
        weights = (1 << np.arange(z.shape[1], dtype=np.int64))
        keys = (z * weights).sum(axis=1)
    else:
        keys = np.zeros(n, dtype=np.int64)

    g2 = 0.0
    df = 0
    for k in np.unique(keys):
        mask = keys == k
        xs = x[mask]
        ys = y[mask]
        if xs.size < 4:
            continue
        n00 = int(np.sum((xs == 0) & (ys == 0)))
        n01 = int(np.sum((xs == 0) & (ys == 1)))
        n10 = int(np.sum((xs == 1) & (ys == 0)))
        n11 = int(np.sum((xs == 1) & (ys == 1)))
        table = np.array([[n00, n01], [n10, n11]], dtype=float)
        if table.sum() < 4:
            continue
        if (table.sum(axis=0) == 0).any() or (table.sum(axis=1) == 0).any():
            continue
        expected = table.sum(axis=1, keepdims=True) * table.sum(axis=0, keepdims=True) / table.sum()
        nz = table > 0
        exp = np.clip(expected, 1e-12, None)
        g2 += float(2.0 * np.sum(table[nz] * np.log(table[nz] / exp[nz])))
        df += 1
    if df <= 0:
        # 所有分层都退化（样本太少 / 某列恒定）→ 检验算不出来
        _bump("all_strata_degenerate")
        _bump("df_degenerate")
        return float("nan")
    _bump("df_computed")
    return _chi2_sf(g2, df)


def pc_skeleton(
    data: np.ndarray,
    *,
    alpha: float = 0.05,
    max_cond: int = 3,
    stats: Optional[dict] = None,
) -> tuple[set[tuple[int, int]], dict[tuple[int, int], tuple[int, ...]]]:
    """无向骨架 + sepset。边以 i<j 存储。

    整改方案 §提交 E：p 值为 NaN（检验不可计算）时**不删边**。
    修复前 `g2_pvalue` 在算不出来时返回 1.0，而这里只判断
    `pval > alpha` —— 于是「样本不足」被当成「检验通过独立」，
    骨架被静默删空。不可判定就保留边，并把次数写进 `stats`，
    让「骨架稠密是因为检验做不了」这件事本身可观测。
    """
    p = data.shape[1]
    adj = {i: set(j for j in range(p) if j != i) for i in range(p)}
    sepset: dict[tuple[int, int], tuple[int, ...]] = {}
    untestable = 0
    # 只有调用方要 stats 时才累计原因；不传 stats 就零额外开销。
    tally: Optional[dict] = {} if stats is not None else None
    for depth in range(0, max_cond + 1):
        changed = True
        while changed:
            changed = False
            pairs = [(i, j) for i in range(p) for j in sorted(adj[i]) if i < j]
            for i, j in pairs:
                if j not in adj[i]:
                    continue
                candidates = [k for k in adj[i] if k != j]
                if len(candidates) < depth:
                    continue
                for s in combinations(candidates, depth):
                    pval = g2_pvalue(data, i, j, s, tally=tally)
                    if pval != pval:          # NaN：不可判定，不删边
                        untestable += 1
                        continue
                    if pval > alpha:
                        adj[i].discard(j)
                        adj[j].discard(i)
                        sepset[(i, j)] = tuple(s)
                        sepset[(j, i)] = tuple(s)
                        changed = True
                        break
    skeleton = {(min(i, j), max(i, j)) for i in adj for j in adj[i] if i < j}
    if stats is not None:
        stats.update({
            "untestable_pairs": untestable,
            "alpha": float(alpha),
            "max_cond": int(max_cond),
            "skeleton_edges": len(skeleton),
            "p": p, "n": int(data.shape[0]),
            # 统计后端与检验参数：同一份数据在不同后端下可能学出不同的图，
            # 不记录就没法解释两张图的差异（整改方案 §九.1 / §十一.2）。
            **stat_backend(),
            "test_parameters": test_parameters(alpha, max_cond),
            # 不可判定的**原因拆分** —— 样本太少 / 变量恒定 / 分层全退化
            # 是三种不同的运维问题，合成一个 untestable 数字就又回到
            # 「压成一个计数」。
            "undecidable": {k: int(v) for k, v in sorted(tally.items())},
        })
    return skeleton, sepset


def _orient_v_structures(
    skeleton: set[tuple[int, int]],
    sepset: dict[tuple[int, int], tuple[int, ...]],
    p: int,
):
    undirected = {frozenset(e) for e in skeleton}
    directed: set[tuple[int, int]] = set()
    neighbors = {i: set() for i in range(p)}
    for a, b in skeleton:
        neighbors[a].add(b)
        neighbors[b].add(a)
    for z in range(p):
        nbrs = list(neighbors[z])
        for x, y in combinations(nbrs, 2):
            if frozenset((x, y)) in undirected:
                continue
            s = sepset.get((x, y), sepset.get((y, x), ()))
            if z not in s:
                directed.add((x, z))
                directed.add((y, z))
                undirected.discard(frozenset((x, z)))
                undirected.discard(frozenset((y, z)))
    return directed, undirected, neighbors


def _meek_rules(directed: set[tuple[int, int]], undirected: set[frozenset], neighbors: dict) -> None:
    def is_adj(a, b):
        return frozenset((a, b)) in undirected or (a, b) in directed or (b, a) in directed

    changed = True
    while changed:
        changed = False
        # R1: a→b − c, a not adj c ⇒ b→c
        for a, b in list(directed):
            for c in list(neighbors[b]):
                if c == a:
                    continue
                if frozenset((b, c)) not in undirected:
                    continue
                if is_adj(a, c):
                    continue
                directed.add((b, c))
                undirected.discard(frozenset((b, c)))
                changed = True
        # R2: a→b→c 且 a−c ⇒ a→c
        for a, b in list(directed):
            for c in [t for (s, t) in directed if s == b]:
                if frozenset((a, c)) in undirected:
                    directed.add((a, c))
                    undirected.discard(frozenset((a, c)))
                    changed = True
        # R3: a−b, c→b, d→b, a−c, a−d, c not adj d ⇒ a→b
        for edge in list(undirected):
            a, b = tuple(edge)
            for src, dst in ((a, b), (b, a)):
                parents = [s for (s, t) in directed if t == dst and s != src]
                if len(parents) < 2:
                    continue
                for c, d in combinations(parents, 2):
                    if is_adj(c, d):
                        continue
                    if frozenset((src, c)) in undirected and frozenset((src, d)) in undirected:
                        directed.add((src, dst))
                        undirected.discard(frozenset((src, dst)))
                        changed = True
                        break


def pc_learn(
    data: np.ndarray,
    names: list[str],
    *,
    alpha: float = 0.05,
    max_cond: int = 3,
) -> dict:
    """返回 {directed:[(u,v)], undirected:[(u,v)], skeleton:[...]} 用变量名。"""
    data = np.asarray(data, dtype=np.uint8)
    p = data.shape[1]
    if p != len(names):
        raise ValueError("names length mismatch")
    stats: dict = {}
    skeleton, sepset = pc_skeleton(data, alpha=alpha, max_cond=max_cond,
                                   stats=stats)
    directed, undirected, neighbors = _orient_v_structures(skeleton, sepset, p)
    _meek_rules(directed, undirected, neighbors)
    # 丢掉双向冲突:保留都不定向
    both = {(a, b) for (a, b) in directed if (b, a) in directed}
    for a, b in list(both):
        directed.discard((a, b))
        directed.discard((b, a))
        undirected.add(frozenset((a, b)))
    undirected_pairs = [tuple(sorted(e)) for e in undirected]
    return {
        "algorithm": "pc",
        "directed": [(names[a], names[b]) for a, b in sorted(directed)],
        "undirected": [(names[a], names[b]) for a, b in undirected_pairs],
        "skeleton": [(names[a], names[b]) for a, b in sorted(skeleton)],
        "alpha": alpha,
        "n": int(data.shape[0]),
        "p": p,
        # 不可判定的条件独立检验次数 —— 「骨架稠密」有两种完全不同的
        # 原因（数据真有依赖 / 检验做不了），下游必须能分开
        "stats": stats,
        # 未定向边数：整改方案 §十一 要监控「未定向边数」。
        # 它高不代表算法坏了（v-结构不足时本来就该留未定向），
        # 但持续升高意味着图长期停在第 1 层的结构信息量上。
        "undirected_edges": len(undirected_pairs),
        "directed_edges": len(directed),
    }
