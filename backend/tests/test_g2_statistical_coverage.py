"""G² 条件独立检验的统计覆盖 —— 整改方案 §九.2 点名要求的四个维度。

## 这批测试为什么存在

整改方案 §九.2 原文：

> 此外，G² 相关测试应覆盖**低频稀疏数据、不同条件集大小、不同自由度和
> 边缘概率**，并检查**输出图的骨架与方向状态**是否符合预期。

§九.2 还要求：

> 不要保留一个形式上可运行、实际上改变 p 值的备用实现。

原有 `test_causal_chain.py` 6 条里，与本项相关的只有骨架一条。
低频稀疏、cond 集大小、df 维度、边缘概率**一条都没有** ——
所以那四项要求在本轮之前是**未兑现**的，不是「已验证但没写清楚」。

另外，无 scipy 的 χ² 兜底此前只做过**一次性手工比对**
（df 1~40 × 14 个统计量共 560 点，最大绝对误差 3.775e-15）。
手工验证留不下回归：下次有人改 `_gammaincc`，没有任何测试会红。
本文件把它固化成 `test_scipy_free_chi2_matches_reference`。
"""
import os
import sys

import numpy as np
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from causal_chain import pc                                   # noqa: E402
from causal_chain.pc import _chi2_sf, g2_pvalue, pc_learn, pc_skeleton  # noqa: E402

scipy_stats = pytest.importorskip("scipy.stats", reason="本用例以 scipy 为参照")


# ══════════════════════════════════════════════════════════════
# A. 不同自由度
# ══════════════════════════════════════════════════════════════

@pytest.mark.parametrize("df", [1, 2, 3, 5, 8, 13, 21, 34])
def test_chi2_sf_matches_reference_across_df(df):
    """每个 df 都要对上参照实现 —— 修复前的 erfc 公式只在 df=1 正确。"""
    for stat in (0.0, 0.5, 1.0, 3.84, 10.0, 25.0, 60.0):
        got = _chi2_sf(stat, df)
        assert got == pytest.approx(float(scipy_stats.chi2.sf(stat, df)),
                                    abs=1e-9), f"df={df} stat={stat}"


def test_chi2_sf_is_monotone_increasing_in_df():
    """固定统计量下，df 越大 p 越大（该统计量相对越不极端）。

    方向反了说明自由度没真正参与计算。注意方向：**先增后减**才对，
    写成「递减」会把正确的实现判成错的 —— 这条断言本身就是文档说的
    「统计口径要钉住」的一部分，写错比不写更糟。
    """
    stat = 6.0
    values = [_chi2_sf(stat, df) for df in range(1, 12)]
    assert all(a < b for a, b in zip(values, values[1:])), values


@pytest.mark.parametrize("df", [0, -1, -100])
def test_nonpositive_df_is_undecidable_not_one(df):
    """⚠️ §九.1 的红线：df<=0 必须「检验无法执行」，不得用 p=1.0 代替。

    p 大在 PC 里的含义是「不能拒绝独立」→ 于是算不出来的检验
    会被当成「两变量独立」的证据，直接把边删掉。
    没有证据，却给出了确定的否定结论。
    """
    got = _chi2_sf(10.0, df)
    assert got != got, f"df={df} 返回了 {got}，应返回 NaN（不可计算）"
    assert got != 1.0


def test_g2_matches_hand_computed_statistic_and_df():
    """G² 与 df 的算法本身：对照手工构造的 2×2 列联表。

    这里不用参照实现算 p，而是**独立**按教科书公式算一遍 G² 与 df，
    再看 `g2_pvalue` 的返回是否与 `_chi2_sf(G², df)` 一致 ——
    钉的是「检验统计量怎么聚合、df 怎么数」，不是 p 本身。
    """
    rng = np.random.default_rng(7)
    n = 2000
    x = rng.random(n) < 0.45
    y = rng.random(n) < 0.55
    x[np.random.default_rng(11).random(n) < 0.5] = 1      # 强化关联
    data = np.stack([x, y], axis=1).astype(np.uint8)

    n00 = int(np.sum((data[:, 0] == 0) & (data[:, 1] == 0)))
    n01 = int(np.sum((data[:, 0] == 0) & (data[:, 1] == 1)))
    n10 = int(np.sum((data[:, 0] == 1) & (data[:, 1] == 0)))
    n11 = int(np.sum((data[:, 0] == 1) & (data[:, 1] == 1)))
    table = np.array([[n00, n01], [n10, n11]], dtype=float)

    expected = (table.sum(axis=1, keepdims=True)
                * table.sum(axis=0, keepdims=True) / table.sum())
    nz = table > 0
    g2 = 2.0 * float(np.sum(table[nz] * np.log(table[nz] / expected[nz])))
    df = (table.shape[0] - 1) * (table.shape[1] - 1)       # 无条件集时 df=1

    got = g2_pvalue(data, 0, 1, ())
    assert got == pytest.approx(float(scipy_stats.chi2.sf(g2, df)), abs=1e-9)


def test_conditioning_increases_df():
    """有条件集时 df 必须大于 1 —— 条件集不参与 df 计算是典型实现错误。"""
    rng = np.random.default_rng(3)
    n = 4000
    z = (rng.random(n) < 0.5).astype(np.uint8)
    x = np.where(z == 1, rng.random(n) < 0.7, rng.random(n) < 0.2).astype(np.uint8)
    y = np.where(z == 1, rng.random(n) < 0.7, rng.random(n) < 0.2).astype(np.uint8)
    data = np.stack([x, y, z], axis=1)

    stats_marg: dict = {}
    stats_cond: dict = {}
    pc_skeleton(data[:, :2], stats=stats_marg)
    pc_skeleton(data, max_cond=1, stats=stats_cond)
    assert stats_marg["undecidable"]["df_computed"] == 1, stats_marg
    assert stats_cond["undecidable"]["df_computed"] > 1, \
        f"条件集没有增加 df: {stats_cond}"


# ══════════════════════════════════════════════════════════════
# B. 低频稀疏数据
# ══════════════════════════════════════════════════════════════

def test_never_occurring_event_is_undecidable_not_independent():
    """⚠️ §九.1：稀疏分层不得被静默跳过，且不得用 p=1.0 顶替。

    修好的表现是返回 NaN 并在 ``tally`` 里留下原因；
    修之前返回 1.0，PC 会据此把边删掉 ——
    「样本不够所以判定独立」，把证据不足写成了确定的否定结论。
    """
    rng = np.random.default_rng(5)
    n = 3000
    rare = np.zeros(n, dtype=np.uint8)                     # 该事件一次都没发生
    other = (rng.random(n) < 0.5).astype(np.uint8)
    assert rare.sum() == 0
    data = np.stack([rare, other], axis=1)

    tally: dict = {}
    got = g2_pvalue(data, 0, 1, (), tally=tally)
    assert got != got, f"稀疏数据返回了 p={got}，应判定为不可计算"
    assert tally.get("all_strata_degenerate", 0) >= 1, tally
    assert tally.get("df_computed", 0) == 0, \
        f"分层全退化却仍算出了 df: {tally}"


def test_rare_but_observed_event_is_still_computable():
    """反向约束：稀疏**不等于**不可判定。

    事件出现过（哪怕只有几次），2×2 表仍可算 → 就必须给出 p 值，
    不能因为「看着稀疏」就退化成 NaN，否则等于把所有低频信号
    一起丢掉 —— 那会系统性地漏掉真正的低频攻击。
    """
    rng = np.random.default_rng(23)
    n = 4000
    rare = np.zeros(n, dtype=np.uint8)
    rare[rng.choice(n, size=40, replace=False)] = 1        # 1% 的稀有事件
    other = (rng.random(n) < 0.5).astype(np.uint8)
    data = np.stack([rare, other], axis=1)

    tally: dict = {}
    got = g2_pvalue(data, 0, 1, (), tally=tally)
    assert got == got, f"1%% 的稀有事件被判成不可计算: {got}"
    assert 0.0 <= got <= 1.0
    assert tally.get("df_computed", 0) == 1, tally


def test_constant_column_is_undecidable():
    """恒定列没有方差，任何「检验结果」都是伪确定性。"""
    n = 500
    data = np.stack([np.zeros(n), np.ones(n)], axis=1).astype(np.uint8)
    tally: dict = {}
    got = g2_pvalue(data, 0, 1, (), tally=tally)
    assert got != got, f"恒定列返回了 p={got}"
    assert tally.get("all_strata_degenerate", 0) == 1, tally


def test_too_few_rows_is_counted_separately():
    """样本不足与分层退化是两种运维问题，不能合成一个计数。"""
    data = np.array([[0, 1]] * 5, dtype=np.uint8)
    tally: dict = {}
    got = g2_pvalue(data, 0, 1, (), tally=tally)
    assert got != got
    assert tally.get("too_few_rows", 0) == 1, tally
    assert tally.get("all_strata_degenerate", 0) == 0, \
        "样本不足被记成了分层退化 —— 排障时会找错方向"


def test_same_var_is_counted_separately():
    data = np.random.default_rng(1).random((200, 2)).astype(np.uint8)
    tally: dict = {}
    assert g2_pvalue(data, 0, 0, (), tally=tally) != g2_pvalue(data, 0, 0, (), tally=tally)
    assert tally.get("same_var", 0) == 2, tally


def test_tally_is_optional_and_does_not_change_result():
    """``tally`` 是旁路：不传不得改变返回值，也不得产生额外开销。"""
    data = np.random.default_rng(2).random((400, 3)).astype(np.uint8)
    plain = g2_pvalue(data, 0, 1, ())
    tally: dict = {}
    with_tally = g2_pvalue(data, 0, 1, (), tally=tally)
    assert tally.get("tests_total") == 1, tally
    # NaN != NaN，用「同为 NaN 或逐位相等」比较，否则这条断言会在
    # 恰好不可判定的数据上假红
    if plain != plain:
        assert with_tally != with_tally
    else:
        assert with_tally == plain


# ══════════════════════════════════════════════════════════════
# C. 边缘概率
# ══════════════════════════════════════════════════════════════

@pytest.mark.parametrize("rate", [0.5, 0.25, 0.05])
def test_detection_survives_skewed_marginals(rate):
    """边缘概率越偏，同等关联越难检出，但**不该突然变成 NaN**。

    退化到「不可判定」与「检验算完了、只是不显著」是两回事：
    前者说明分层崩了，后者是一个正常的统计结论。
    """
    rng = np.random.default_rng(13)
    n = 6000
    x = (rng.random(n) < rate).astype(np.uint8)
    y = x.copy()                                            # 完全等价 → 应强显著
    data = np.stack([x, y], axis=1)
    got = g2_pvalue(data, 0, 1, ())
    assert got == got, f"rate={rate} 退化成不可判定: {got}"
    assert got < 0.01, f"rate={rate} 完全等价的两个变量却 p={got}"


def test_rare_and_balanced_are_not_collapsed_into_one_number():
    """稀疏列产生的不可判定次数必须单独可见。

    「有一条平衡列」与「有一条恒为 0 的列」被合成一个 `untestable`
    数字，排障时就分不出该升级采样还是该查依赖。
    """
    rng = np.random.default_rng(17)
    n = 3000
    never = np.zeros(n, dtype=np.uint8)                   # 该事件从未发生
    bal = (rng.random(n) < 0.5).astype(np.uint8)
    mixed = np.stack([bal, bal, never], axis=1)
    stats: dict = {}
    pc_skeleton(mixed, stats=stats)
    undecidable = stats["undecidable"]
    assert undecidable.get("all_strata_degenerate", 0) >= 1, \
        f"恒为 0 的列导致的不可判定没有被单独计数: {undecidable}"
    assert undecidable.get("df_computed", 0) >= 1, \
        "平衡列之间的检验也应照常完成，不能一起被算成不可判定"
    assert stats["untestable_pairs"] >= 1


# ══════════════════════════════════════════════════════════════
# D. 不同条件集大小
# ══════════════════════════════════════════════════════════════

def _chain(n=900, seed=19):
    rng = np.random.default_rng(seed)
    a = (rng.random(n) < 0.3).astype(np.uint8)
    b = np.where(a == 1, rng.random(n) < 0.8, rng.random(n) < 0.1).astype(np.uint8)
    c = np.where(b == 1, rng.random(n) < 0.8, rng.random(n) < 0.1).astype(np.uint8)
    d = (rng.random(n) < 0.3).astype(np.uint8)             # 独立噪声
    names = ["A", "B", "C", "NOISE"]
    return np.stack([a, b, c, d], axis=1), names


@pytest.mark.parametrize("max_cond", [0, 1, 2, 3])
def test_skeleton_only_shrinks_as_max_cond_grows(max_cond):
    """条件集变大只能让骨架**更稀疏**，不能凭空长出新边。

    反向漂移说明某次检验的 p 值算错了方向 ——
    这正是 §九.1 抱怨的「真实依赖从图中被删除」的对偶错误。
    """
    X, _ = _chain()
    sk0, _ = pc_skeleton(X, alpha=0.05, max_cond=0)
    sk, _ = pc_skeleton(X, alpha=0.05, max_cond=max_cond)
    assert sk <= sk0, f"max_cond={max_cond} 让骨架多出了边: {sk - sk0}"


@pytest.mark.parametrize("max_cond", [0, 1, 2, 3])
def test_true_chain_edges_survive_every_cond_size(max_cond):
    """真边 A→B、B→C 在每种条件集大小下都必须留在骨架里。"""
    X, names = _chain()
    sk, _ = pc_skeleton(X, alpha=0.05, max_cond=max_cond)
    pairs = {tuple(sorted(e)) for e in sk}
    assert (0, 1) in pairs, f"max_cond={max_cond} 丢了 A-B: {pairs}"
    assert (1, 2) in pairs, f"max_cond={max_cond} 丢了 B-C: {pairs}"
    assert (0, 3) not in pairs, f"max_cond={max_cond} 凭空长出噪声边"


def test_tests_total_grows_with_cond_size():
    """条件集越大，检验次数越多 —— 用来监控计算量与不可判定比例。"""
    X, _ = _chain()
    counts = []
    for max_cond in (0, 1, 2):
        stats: dict = {}
        pc_skeleton(X, alpha=0.05, max_cond=max_cond, stats=stats)
        counts.append(stats["undecidable"]["tests_total"])
    assert counts[0] < counts[1] <= counts[2], counts


# ══════════════════════════════════════════════════════════════
# E. 骨架与方向状态
# ══════════════════════════════════════════════════════════════

def test_directed_and_undirected_are_mutually_exclusive_states():
    """一条边要么已定向、要么未定向，不能同时出现在两边。"""
    X, names = _chain()
    out = pc_learn(X, names, alpha=0.05)
    undirected = {frozenset(e) for e in out["undirected"]}
    for src, dst in out["directed"]:
        assert frozenset((src, dst)) not in undirected, \
            f"{src}->{dst} 既定向又未定向 —— 方向状态自相矛盾"


def test_every_edge_is_in_skeleton_or_oriented():
    """定向边与未定向边合起来必须覆盖全部骨架边，否则有边凭空消失。"""
    X, names = _chain()
    out = pc_learn(X, names, alpha=0.05)
    skeleton = {frozenset(e) for e in out["skeleton"]}
    oriented = {frozenset(e) for e in out["directed"]}
    undirected = {frozenset(e) for e in out["undirected"]}
    assert skeleton == oriented | undirected, \
        f"骨架边既没定向也没留未定向: {skeleton - (oriented | undirected)}"


def test_plain_chain_is_left_undirected_not_guessed():
    """⚠️ §九.3 的核心要求：**无 collider 时不得凭先验硬给方向**。

    A→B→C 是一条链，没有任何 v-结构（collider）。此时
    {A→B→C, A←B←C, A←B→C} 在 Markov 等价类里是同一个分布 ——
    数据**根本无法**区分谁是原因。所以正确行为是把边留作「未定向」。

    写这条之前我一度断言「真实链必须被定向」，跑出来是 `directed=[]`。
    那不是缺陷，是 PC 的教科书行为：强行定向才是缺陷，
    因为那会让下游把「猜出来的方向」当成有数据支持的因果结论。
    """
    X, names = _chain()
    out = pc_learn(X, names, alpha=0.05)
    undirected = {frozenset(e) for e in out["undirected"]}
    assert frozenset(("A", "B")) in undirected, out
    assert frozenset(("B", "C")) in undirected, out
    assert out["directed"] == [], f"无 collider 却给出了方向: {out['directed']}"


def _collider(n=3000, seed=29):
    """A→C←B：存在 v-结构，PC 有依据把方向定出来。"""
    rng = np.random.default_rng(seed)
    a = (rng.random(n) < 0.35).astype(np.uint8)
    b = (rng.random(n) < 0.35).astype(np.uint8)
    c = ((a | b) * (rng.random(n) < 0.85)).astype(np.uint8)
    return np.stack([a, b, c], axis=1), ["A", "B", "C"]


def test_collider_is_oriented_from_data():
    """有 collider 时必须能定出方向 —— 否则上一条就成了「永远不定向」。"""
    X, names = _collider()
    out = pc_learn(X, names, alpha=0.05)
    directed = set(map(tuple, out["directed"]))
    assert ("A", "C") in directed and ("B", "C") in directed, out
    assert out["directed_edges"] == len(out["directed"])
    assert out["undirected_edges"] == len(out["undirected"])


def test_direction_counts_match_the_returned_lists():
    X, names = _chain()
    out = pc_learn(X, names, alpha=0.05)
    assert out["directed_edges"] == len(out["directed"])
    assert out["undirected_edges"] == len(out["undirected"])
    # 骨架边数应等于「已定向 + 未定向」，否则有边既没算进任何一边
    assert len(out["skeleton"]) == out["directed_edges"] + out["undirected_edges"]


def test_noise_variable_is_not_oriented_towards_anything():
    """独立噪声不得被连上边，否则图会随样本量单调变稠。"""
    X, names = _chain()
    out = pc_learn(X, names, alpha=0.05)
    edges = {frozenset(e) for e in out["skeleton"]}
    assert all(3 not in e for e in edges), f"噪声变量被连上了边: {edges}"


# ══════════════════════════════════════════════════════════════
# F. 无 scipy 兜底必须与参照实现数值一致
# ══════════════════════════════════════════════════════════════
#
# §九.2：「不要保留一个形式上可运行、实际上改变 p 值的备用实现」。
# 修复前的兜底对任意 df 都套用 df=1 的 erfc 公式 —— 形式上能跑，
# 但 df>1 时系统性偏小，会把「算得出但该保留的边」删掉。

def _fallback(stat, df):
    return pc._chi2_sf(stat, df) if pc._chi2 is None else None


def test_scipy_free_chi2_matches_reference(monkeypatch):
    """无 scipy 模式下逐点对照 scipy，最大误差须在 1e-9 内。"""
    monkeypatch.setattr(pc, "_chi2", None)
    worst = 0.0
    for df in range(1, 41):
        for stat in (0.0, 0.1, 0.5, 1.0, 3.841, 10.0, 30.0, 100.0):
            got = pc._chi2_sf(stat, df)
            want = float(scipy_stats.chi2.sf(stat, df))
            worst = max(worst, abs(got - want))
    assert worst < 1e-9, f"无 scipy 兜底与 scipy 最大偏差 {worst:.3e}"


def test_scipy_free_fallback_is_not_the_df1_erfc_formula(monkeypatch):
    """反向证明：兜底**不能**等于 df=1 的 erfc 公式。

    没有这条，只钉「与 scipy 一致」仍可能被一个恰好只在少数点上
    取巧的实现蒙混过去。这里直接断言 df>1 时两者显著不同。
    """
    import math

    monkeypatch.setattr(pc, "_chi2", None)
    df, stat = 8, 12.0
    ours = pc._chi2_sf(stat, df)
    naive_df1 = math.erfc(math.sqrt(stat / 2.0))       # 修复前对任意 df 的做法
    want = float(scipy_stats.chi2.sf(stat, df))
    assert abs(ours - naive_df1) > 1e-6, "兜底退回了 df=1 的 erfc 公式"
    assert abs(ours - want) < 1e-9
    assert abs(naive_df1 - want) > 1e-3, \
        "参照点失效：naive 公式已与 scipy 一致，这条用例失去意义"


def test_scipy_path_and_fallback_agree_end_to_end(monkeypatch):
    """同一批数据，有 scipy 与无 scipy 必须给出**同一个骨架**。

    这是 §九.2 的原始抱怨：「安装与不安装 SciPy 时学出的图不一致」。
    """
    X, names = _chain()
    with_scipy = pc_learn(X, names, alpha=0.05)

    monkeypatch.setattr(pc, "_chi2", None)
    without = pc_learn(X, names, alpha=0.05)

    assert without["skeleton"] == with_scipy["skeleton"], \
        (without["skeleton"], with_scipy["skeleton"])
    assert without["directed"] == with_scipy["directed"]
