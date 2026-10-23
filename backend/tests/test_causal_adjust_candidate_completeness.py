# -*- coding: utf-8 -*-
"""因果调整集的候选枚举必须**穷举**池内所有合规候选
（整改方案 §三.1「检查**所有**符合理论条件的候选调整集」，§9.42）。

## 缺陷（实测复现）

「extra 候选调整集恒为空」那一条早已修好（候选池变成全部可观测变量），
但**组合**这一层仍不完整：生成的候选只有五族
（先验混杂全带 / 空集 / 单点 / 先验全带+单点 / 其它变量两两组合），
于是**「先验混杂的子集 + 其它变量的多个」这一族一个都没生成过**。

实测（三条独立后门：一条过先验混杂 c、两条过其它变量 n1/n2）：

```
backdoor_set 返回 : None          ← 报成「不可识别」
穷举得到的合法集  : [['HOUR_NIGHT', 'N1', 'N2'], ...]
```

即：**效果其实可识别，却被判成不可识别**（漏报方向）。

## 本守卫盯什么

1. 存在合法调整集时，`backdoor_set` **必须**找到它（核心性质）；
2. 池内大小 ≤ `MAX_ADJUST_SET` 的**全部**子集都必须出现在候选里；
3. **既有判定一条都不变** —— 修前能识别的案例，选的还是**同一个**集；
4. 顺序即优先级：原先那五族必须仍排在补全的组合**之前**；
5. 空集必须保留（它是「图上验证过没有后门路径」的合法答案）；
6. 候选池被 `MAX_ADJUST_POOL` 截断了多少个变量，必须**披露**。

⚠ 判据用**行为**（返回值 / 候选集合），不用源码文本。
"""
from __future__ import annotations

import itertools
import os
import sys

import numpy as np
import pytest

os.environ.setdefault("SHARED_MEMORY_SKIP_DOTENV", "1")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from causal_chain.do_calculus import (  # noqa: E402
    MAX_ADJUST_POOL, MAX_ADJUST_SET, _adjust_pool, backdoor_set,
    candidate_adjust_sets, d_separated, descendants, intervene,
)
from causal_chain.variables import CONFOUNDERS  # noqa: E402

X, Y = "PORT_SCAN", "C2_BEACON"
NAMES = [X, Y, "HOUR_NIGHT", "DST_HUB", "N1", "N2"]


def _legacy_candidates(directed, x=X, y=Y, names=NAMES):
    """**修复前**的候选枚举（原样复刻，用于对照）。"""
    observed = [n for n in names if n not in (x, y)]
    conf = [c for c in CONFOUNDERS if c in set(observed)]
    others = [n for n in observed if n not in set(conf)][:MAX_ADJUST_POOL]
    out, seen = [], set()

    def add(z):
        zz = tuple(sorted({n for n in z if n in set(observed)}))
        if len(zz) > MAX_ADJUST_SET or zz in seen:
            return
        seen.add(zz)
        out.append(list(zz))

    add(conf)
    add([])
    for c in conf:
        add([c])
    for n in others:
        add([n])
        add(conf + [n])
    for a, b in itertools.combinations(others, 2):
        add([a, b])
    return out


def _legacy_backdoor_set(directed, x=X, y=Y, names=NAMES):
    desc_x = descendants(directed, x)
    g_bar = [(a, b) for a, b in directed if a != x]
    for z in _legacy_candidates(directed, x, y, names):
        if set(z) & desc_x:
            continue
        if d_separated(g_bar, x, y, z):
            return z
    return None


def _all_pool_subsets(names=NAMES, x=X, y=Y):
    """候选池内大小 ≤ MAX_ADJUST_SET 的**全部**子集。"""
    _observed, conf, others, _trunc = _adjust_pool(names, x, y)
    pool = sorted(set(conf) | set(others))
    out = []
    for k in range(0, MAX_ADJUST_SET + 1):
        for combo in itertools.combinations(pool, k):
            out.append(list(combo))
    return out


#: 三条独立后门：一条过先验混杂、两条过其它变量
THREE_BACKDOORS = [
    ("HOUR_NIGHT", X), ("HOUR_NIGHT", Y),
    ("N1", X), ("N1", Y),
    ("N2", X), ("N2", Y),
]

#: 对照组：修前就能识别的五种形态 —— 修后必须选**同一个**集
UNCHANGED_CASES = [
    ("单条后门（先验混杂）",
     [("HOUR_NIGHT", X), ("HOUR_NIGHT", Y)], ["DST_HUB", "HOUR_NIGHT"]),
    ("单条后门（其它变量）",
     [("N1", X), ("N1", Y)], ["N1"]),
    ("两条后门（混杂 + 其它）",
     [("HOUR_NIGHT", X), ("HOUR_NIGHT", Y), ("N1", X), ("N1", Y)],
     ["DST_HUB", "HOUR_NIGHT", "N1"]),
    ("无后门（X → Y 直连）",
     [(X, Y)], ["DST_HUB", "HOUR_NIGHT"]),
    ("对撞点 M",
     [("HOUR_NIGHT", X), ("HOUR_NIGHT", "M"), ("N1", "M"), ("N1", Y), (X, Y)],
     ["DST_HUB", "HOUR_NIGHT"]),
]


class TestTheSearchFindsAValidSetWhenOneExists:
    def test_three_independent_backdoors_are_identified(self):
        """【核心性质】三条独立后门 → **可识别**（修前返回 None）。"""
        got = backdoor_set(THREE_BACKDOORS, X, Y, NAMES)
        assert got is not None, (
            "存在合法调整集却报成「不可识别」—— "
            "效果其实可识别，这是漏报方向的缺陷")
        assert set(got) == {"HOUR_NIGHT", "N1", "N2"}, got

    def test_the_premise_really_has_three_independent_backdoors(self):
        """前提守卫：这三条后门必须**真的**互相独立。

        否则「找到了合法集」可能只是因为图退化成了一条后门。
        """
        for a, b in (("HOUR_NIGHT", X), ("N1", X), ("N2", X)):
            assert (a, b) in THREE_BACKDOORS, (a, b)
        for a in ("HOUR_NIGHT", "N1", "N2"):
            assert (a, Y) in THREE_BACKDOORS, a
        # 单调任何一个都堵不住另外两条
        for only in ({"HOUR_NIGHT"}, {"N1"}, {"N2"}):
            z = sorted(only)
            assert not d_separated(
                [(a, b) for a, b in THREE_BACKDOORS if a != X], X, Y, z), (
                f"只调 {z} 就能堵住 —— 那就不是三条独立后门，前提失效")

    def test_the_legacy_implementation_really_did_fail_on_this_case(self):
        """前提守卫：修复前**确实**在这个案例上返回 None。

        没有这一条，上面那条可能是因为「本来就能识别」而绿。
        """
        assert _legacy_backdoor_set(THREE_BACKDOORS, X, Y, NAMES) is None, (
            "修复前的实现在这个案例上并没有失败 —— 对照组失效")


class TestTheEnumerationIsExhaustive:
    def test_every_pool_subset_of_allowed_size_is_generated(self):
        """池内大小 ≤ MAX_ADJUST_SET 的**全部**子集都必须在候选里。"""
        cands = candidate_adjust_sets(THREE_BACKDOORS, X, Y, NAMES)
        got = {tuple(sorted(c)) for c in cands}
        want = {tuple(sorted(s)) for s in _all_pool_subsets()}
        missing = sorted(want - got)
        assert not missing, (
            f"候选枚举漏了 {len(missing)} 个合规候选：{missing[:8]} —— "
            "「存在合法调整集」会被误报成「不可识别」")

    def test_the_empty_set_is_still_generated(self):
        """空集必须保留 —— 它是「图上验证过没有后门路径」的合法答案。"""
        cands = candidate_adjust_sets(THREE_BACKDOORS, X, Y, NAMES)
        assert [] in cands, "空集被过滤掉了"

    def test_the_legacy_families_still_come_first(self):
        """顺序即优先级：原先那五族必须仍排在补全的组合**之前**。"""
        cands = candidate_adjust_sets(THREE_BACKDOORS, X, Y, NAMES)
        legacy = [tuple(sorted(c)) for c in _legacy_candidates(THREE_BACKDOORS)]
        legacy_set = set(legacy)
        first_new = min(i for i, c in enumerate(cands)
                        if tuple(sorted(c)) not in legacy_set)
        last_legacy = max(i for i, c in enumerate(cands)
                           if tuple(sorted(c)) in legacy_set)
        assert last_legacy < first_new, (
            "补全的组合排到了原有五族之前 —— 既有判定可能被改变")


class TestTheExistingVerdictsAreUnchanged:
    @pytest.mark.parametrize("title,graph,expected", UNCHANGED_CASES)
    def test_the_same_adjustment_set_is_still_chosen(self, title, graph, expected):
        """既有判定**一条都不变**：修前能识别的，选的还是同一个集。"""
        before = _legacy_backdoor_set(graph, X, Y, NAMES)
        after = backdoor_set(graph, X, Y, NAMES)
        assert before == expected, (
            f"{title}：对照组的期望值本身不对（修前是 {before}，用例写的是 {expected}）")
        assert after == before, (
            f"{title}：调整集从 {before} 变成了 {after} —— "
            "这次修复只该影响原本「弃权」的情况")


class TestThePoolTruncationIsDisclosed:
    def test_the_truncation_count_is_reported(self):
        """候选池被 `MAX_ADJUST_POOL` 截断了多少个变量，必须随结论落库。

        被丢掉的变量若在后门路径上 → 「不可识别」的原因在数据上完全不可见
        （整改方案 §9.24：避免静默截断；若必须限长，标记不完整）。
        """
        n_obs = MAX_ADJUST_POOL + 6
        names = [X, Y, "HOUR_NIGHT", "DST_HUB"] + ["N%d" % i for i in range(n_obs - 4)]
        rng = np.random.default_rng(11)
        data = rng.integers(0, 2, size=(120, len(names)))
        r = intervene(data, names, [("HOUR_NIGHT", X), ("HOUR_NIGHT", Y)], X, Y)
        got = (r.get("assumptions") or {}).get("adjust_pool_truncated")
        expect = max(0, (n_obs - 2) - len(CONFOUNDERS) - MAX_ADJUST_POOL)
        assert got == expect, (
            f"截断数披露不对：got={got}，预期 {expect} —— "
            "「不可识别」的原因会因此在数据上不可见")

    def test_no_truncation_reports_zero(self):
        names = [X, Y, "HOUR_NIGHT", "DST_HUB", "N1"]
        rng = np.random.default_rng(3)
        data = rng.integers(0, 2, size=(60, len(names)))
        r = intervene(data, names, [("HOUR_NIGHT", X), ("HOUR_NIGHT", Y)], X, Y)
        assert (r.get("assumptions") or {}).get("adjust_pool_truncated") == 0


if __name__ == "__main__":       # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
