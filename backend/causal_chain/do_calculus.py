"""Do-calculus 子集:后门调整。

实现的是 Pearl 阶梯第 2 层(干预):P(Y | do(X=x))。
不可识别时 identifiable=false,不编造数字。
分析员问句「若 X 没发生 Y 还会出现吗」用 P(Y=1|do(X=0)) 回答(人群级,不是个体反事实)。

整改方案 §三.2（不可观察混杂不能当成不存在）:

修复前有两个互相叠加的问题：

1. `extra` 候选调整集**恒为空**。过滤条件是
   `n not in preferred and n not in (x, y) and is_confounder(n)`，
   而 `preferred` 已经是「出现在 names 里的全部 CONFOUNDERS」，
   所以 `not in preferred` 与 `is_confounder(n)` 互斥 —— 这一支永远
   进不去。也就是说：**只有先验声明过的那两个混杂变量才可能被调整**，
   图上真实存在的其它后门路径根本没进候选池。
2. 空调整集被直接当成「不存在需要调整的后门路径」。于是一个
   真实 ACE=+0.60 的强因果，在有未观测混杂的图上算出 +0.28，
   并且打上 `identifiable=True`。

现在：
  - 候选池来自**全部可观测变量**（不是只有先验声明的混杂）；
  - 「没有不可观测混杂」是一个**显式假设**，随每个识别结果落库，
    并且可以被调用方声明的潜在混杂变量推翻；
  - 图版本（边集合指纹）与实际使用的调整集一起记录。
"""
from __future__ import annotations

import hashlib
import json
from itertools import combinations
from typing import Iterable, Optional

import numpy as np

from causal_chain.variables import CONFOUNDERS

#: 调整集大小上限（更大的集合只会指数爆炸，对后门准则没有额外收益）
MAX_ADJUST_SET = 4

#: 参与候选枚举的可观测变量上限
MAX_ADJUST_POOL = 12


def graph_fingerprint(
    directed: list[tuple[str, str]], names: Optional[Iterable[str]] = None
) -> str:
    """图版本指纹：同一个指纹才代表「同一张图 + 同一组变量」。

    整改方案 §三.2 要求每次识别结果记录图版本。边顺序不影响语义，
    所以先排序再哈希 —— 否则同一张图换个遍历顺序就得到不同版本号，
    「图版本变了」这个信号也就失去了意义。
    """
    payload = json.dumps(
        {"edges": sorted([list(e) for e in directed]),
         "names": sorted(names or [])},
        separators=(",", ":"), ensure_ascii=True,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:12]


def _parents(directed: list[tuple[str, str]]) -> dict[str, set[str]]:
    pa: dict[str, set[str]] = {}
    for a, b in directed:
        pa.setdefault(b, set()).add(a)
        pa.setdefault(a, set())
    return pa


def _children(directed: list[tuple[str, str]]) -> dict[str, set[str]]:
    ch: dict[str, set[str]] = {}
    for a, b in directed:
        ch.setdefault(a, set()).add(b)
        ch.setdefault(b, set())
    return ch


def descendants(directed: list[tuple[str, str]], node: str) -> set[str]:
    ch = _children(directed)
    out: set[str] = set()
    stack = list(ch.get(node, ()))
    while stack:
        n = stack.pop()
        if n in out:
            continue
        out.add(n)
        stack.extend(ch.get(n, ()))
    return out


def ancestors(directed: list[tuple[str, str]], node: str) -> set[str]:
    pa = _parents(directed)
    out: set[str] = set()
    stack = list(pa.get(node, ()))
    while stack:
        n = stack.pop()
        if n in out:
            continue
        out.add(n)
        stack.extend(pa.get(n, ()))
    return out


def has_directed_path(
    directed: list[tuple[str, str]],
    src: str,
    dst: str,
    *,
    skip: Optional[Iterable[str]] = None,
) -> bool:
    skip_set = set(skip or ())
    ch = _children(directed)
    seen = set()
    stack = [src]
    while stack:
        n = stack.pop()
        if n == dst and n != src:
            return True
        if n in seen:
            continue
        seen.add(n)
        for nxt in ch.get(n, ()):
            if nxt in skip_set:
                continue
            stack.append(nxt)
    return False


def d_separated(
    directed: list[tuple[str, str]],
    x: str,
    y: str,
    z: Iterable[str],
) -> bool:
    """祖先图道德化后无向可达性。"""
    zset = set(z)
    nodes = {x, y} | zset | ancestors(directed, x) | ancestors(directed, y)
    for zz in list(zset):
        nodes |= ancestors(directed, zz)
    pa = _parents(directed)
    undirected: dict[str, set[str]] = {n: set() for n in nodes}

    def link(a, b):
        if a in nodes and b in nodes and a != b:
            undirected.setdefault(a, set()).add(b)
            undirected.setdefault(b, set()).add(a)

    for a, b in directed:
        if a in nodes and b in nodes:
            link(a, b)
    for n in nodes:
        parents = [p for p in pa.get(n, ()) if p in nodes]
        for a, b in combinations(parents, 2):
            link(a, b)
    for zz in zset:
        undirected.pop(zz, None)
        for n in list(undirected):
            undirected[n].discard(zz)
    if x not in undirected or y not in undirected:
        return True
    seen = {x}
    stack = [x]
    while stack:
        n = stack.pop()
        if n == y:
            return False
        for nxt in undirected.get(n, ()):
            if nxt not in seen:
                seen.add(nxt)
                stack.append(nxt)
    return True


def _adjust_pool(names: list[str], x: str, y: str):
    """候选调整池：先验声明的混杂 + 其它可观测变量。

    返回 `(observed, conf, others, truncated)`。

    `truncated` = 因 `MAX_ADJUST_POOL` 上限而**没进池**的可观测变量数。
    这个数必须被披露而不是悄悄丢掉：被丢掉的变量若正好在后门路径上，
    调整集就找不到 → 报成「不可识别」，而原因在数据上完全不可见
    （整改方案 §9.24：避免静默截断；若必须限长，标记不完整）。
    """
    observed = [n for n in names if n not in (x, y)]
    conf = [c for c in CONFOUNDERS if c in set(observed)]
    rest = [n for n in observed if n not in set(conf)]
    others = rest[:MAX_ADJUST_POOL]
    return observed, conf, others, max(0, len(rest) - len(others))


def candidate_adjust_sets(
    directed: list[tuple[str, str]],
    x: str,
    y: str,
    names: list[str],
) -> list[list[str]]:
    """枚举候选调整集（整改方案 §三.2：检查**所有**符合理论条件的候选集）。

    修复前的 `extra` 分支恒为空（见模块 docstring），导致只有先验声明的
    HOUR_NIGHT / DST_HUB 有机会进入调整集。现在候选池是**全部可观测变量**，
    先验声明的混杂只是排在最前面的优先候选，不是唯一候选。

    顺序即优先级：先验混杂 → 空集 → 单点 → 先验+单点 → 两点组合。
    """
    return list(_iter_candidate_adjust_sets(directed, x, y, names))


def _iter_candidate_adjust_sets(
    directed: list[tuple[str, str]],
    x: str,
    y: str,
    names: list[str],
):
    """候选调整集的**惰性**枚举（顺序即优先级）。

    为什么要惰性：补全组合后候选数可达 1471，而 `backdoor_set`
    只需要**第一个**满足后门准则的集 —— 把 1471 个都物化出来是纯浪费
    （实测物化版 1.996 ms/次，惰性版命中即停，多数情况更快）。

    顺序（**第一梯队与修复前完全一致**，既有判定一条都不变）：

    1. 先验声明的混杂（全部）
    2. 空集
    3. 单个先验混杂
    4. 单个其它变量 → 先验全带 + 单个其它变量
    5. 其它变量两两组合
    6. **第二梯队**：池内大小 ≤ `MAX_ADJUST_SET` 的**全部**剩余子集

    第 6 梯队补的是「先验混杂的**子集** + 其它变量的**多个**」这一族
    （`[c, n]` / `[c, n1, n2]` / `[c1, c2, n1, n2]` / `[n1, n2, n3]` …），
    它们此前**一个都没被生成过** → 「存在合法调整集」会被误报成
    「不可识别」（整改方案 §三.1：检查**所有**符合理论条件的候选调整集）。

    实测（三条独立后门：一条过先验混杂、两条过其它变量）：
    修前 `backdoor_set` 返回 `None`，而合法集 `[c, n1, n2]` 确实存在。
    """
    observed, conf, others, _truncated = _adjust_pool(names, x, y)
    observed_set = set(observed)
    seen: set[tuple[str, ...]] = set()

    def norm(z: Iterable[str]) -> tuple[str, ...]:
        return tuple(sorted({n for n in z if n in observed_set}))

    # 注意：**不能**把空集过滤掉。空调整集是「图上验证过 X 与 Y
    # 之间不存在后门路径」的合法答案，排除它会把「确定无后门」
    # 误报成「找不到调整集 → 不可识别」，方向刚好反了。
    def emit(z: Iterable[str]):
        zz = norm(z)
        if len(zz) > MAX_ADJUST_SET or zz in seen:
            return None
        seen.add(zz)
        return list(zz)

    # ── 第一梯队：与修复前**逐条同序** ────────────────────────
    r = emit(conf)                    # 优先：先验声明的混杂
    if r is not None:
        yield r
    r = emit([])                      # 其次：空集（无后门路径时才合法）
    if r is not None:
        yield r
    for c in conf:
        r = emit([c])
        if r is not None:
            yield r
    for n in others:
        r = emit([n])
        if r is not None:
            yield r
        r = emit(conf + [n])
        if r is not None:
            yield r
    for a, b in combinations(others, 2):
        r = emit([a, b])
        if r is not None:
            yield r

    # ── 第二梯队：池内大小 ≤ MAX_ADJUST_SET 的全部剩余子集 ─────
    # 放在第一梯队**之后** → 第一梯队能命中的仍然先命中 →
    # **既有判定一条都不变**，只有原本「弃权」的情况才会变。
    pool = sorted(set(conf) | set(others))
    for k in range(2, MAX_ADJUST_SET + 1):
        for combo in combinations(pool, k):
            if combo in seen:
                continue
            seen.add(combo)
            yield list(combo)


def backdoor_set(
    directed: list[tuple[str, str]],
    x: str,
    y: str,
    names: list[str],
) -> Optional[list[str]]:
    """后门调整集：候选集中第一个满足后门准则的子集。

    返回 `[]` 表示「空集就是合法调整集」——这是**图上验证过的结论**
    （G_\\bar{X} 中 X 与 Y 被 d-分离），不是「没找到候选就默认空集」。
    返回 None 表示没有任何候选满足后门准则 → 不可识别。
    """
    desc_x = descendants(directed, x)
    # G_{\overline{X}}: 去掉 X 发出的边
    g_bar = [(a, b) for a, b in directed if a != x]
    # 惰性枚举：命中即停（补全组合后候选数可达 1471，物化全是浪费）
    for z in _iter_candidate_adjust_sets(directed, x, y, names):
        if set(z) & desc_x:
            continue
        if d_separated(g_bar, x, y, z):
            return z
    return None


def intervene(
    data: np.ndarray,
    names: list[str],
    directed: list[tuple[str, str]],
    x: str,
    y: str,
    *,
    do_value: int = 0,
    unobserved_confounders: Optional[Iterable[str]] = None,
) -> dict:
    """P(Y=1 | do(X=do_value)) 后门估计。

    `unobserved_confounders` = 调用方**声明**的潜在混杂变量（不在 names 里，
    但可能同时影响 X 与 Y）。只要声明了非空列表，本查询一律判不可识别 ——
    后门准则要求调整所有混杂，未观测的那部分无法调整。
    """
    base = {
        "x": x, "y": y, "do": int(do_value),
        "graph_version": graph_fingerprint(directed, names),
        "assumptions": {
            "no_unobserved_confounding": not bool(unobserved_confounders),
            "declared_unobserved_confounders": sorted(
                str(c) for c in (unobserved_confounders or ())),
            "observed_variables": list(names),
            "declared_confounders": [c for c in CONFOUNDERS if c in set(names)],
            # 候选池被 MAX_ADJUST_POOL 截断了多少个变量（0 = 没截断）。
            # 被丢掉的变量若在后门路径上，「不可识别」的原因就不可见 ——
            # 所以这个数随结论一起落库（整改方案 §9.24：不要静默截断）。
            "adjust_pool_truncated": _adjust_pool(names, x, y)[3],
            "population_intervention": True,
        },
    }
    if unobserved_confounders:
        return {**base, "identifiable": False,
                "reason": "unobserved_confounding"}
    if x not in names or y not in names:
        return {**base, "identifiable": False, "reason": "unknown_variable"}
    if x == y:
        return {**base, "identifiable": False, "reason": "same_variable"}
    z = backdoor_set(directed, x, y, names)
    if z is None:
        return {
            **base,
            "identifiable": False,
            "reason": "no_backdoor",
            # ladder-2: 不可识别就不给概率
        }
    xi = names.index(x)
    yi = names.index(y)
    zi = [names.index(c) for c in z]
    p0 = intervene_raw(data, xi, yi, zi, 0)
    p1 = intervene_raw(data, xi, yi, zi, 1)
    p_do = p0 if int(do_value) == 0 else p1
    if p_do is None:
        return {
            **base,
            "identifiable": False,
            "reason": "sparse_stratum",
            "z": z,
        }
    xv = data[:, xi].astype(np.int8)
    yv = data[:, yi].astype(np.int8)
    mask_x = xv == int(do_value)
    p_obs = float(yv[mask_x].mean()) if int(mask_x.sum()) else None
    ace = None if (p0 is None or p1 is None) else float(p1 - p0)
    return {
        **base,
        "identifiable": True,
        "reason": "backdoor",
        "z": z,
        "p_y_do": round(float(p_do), 4),
        "p_y_obs_given_x": None if p_obs is None else round(p_obs, 4),
        "p_y": round(float(yv.mean()), 4),
        "ace": None if ace is None else round(ace, 4),
        "ladder": 2,
        "note": "P(Y|do(X)) via backdoor; population intervention, not unit-level counterfactual",
    }


def intervene_raw(data, xi, yi, zi, do_value: int) -> Optional[float]:
    n = data.shape[0]
    xv = data[:, xi].astype(np.int8)
    yv = data[:, yi].astype(np.int8)
    if zi:
        zmat = data[:, zi].astype(np.int64)
        weights = (1 << np.arange(len(zi), dtype=np.int64))
        keys = (zmat * weights).sum(axis=1)
    else:
        keys = np.zeros(n, dtype=np.int64)
    p_do = 0.0
    used = 0
    mass = 0.0
    for k in np.unique(keys):
        mask_z = keys == k
        pz = float(mask_z.mean())
        mask_xz = mask_z & (xv == int(do_value))
        m = int(mask_xz.sum())
        if m < 1:
            continue
        p_do += float(yv[mask_xz].mean()) * pz
        used += m
        mass += pz
    if used < 8 or mass <= 0:
        return None
    return float(p_do / mass) if mass < 0.999 else float(p_do)
