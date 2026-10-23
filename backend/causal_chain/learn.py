"""结构学习编排:样本 → PC + GES → 共识边 → 后门 ACE。"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from causal_chain.compare import annotate_chain, candidate_edges
from causal_chain.do_calculus import intervene
from causal_chain.ges import consensus, ges_learn
from causal_chain.pc import pc_learn
from causal_chain.variables import (
    DEFAULT_BIN_MINUTES,
    DEFAULT_MIN_WINDOWS,
    TACTIC_RANK,
    events_to_matrix,
    is_attack_node,
    is_confounder,
    prior_forbids,
)


def _orient_with_prior(pc: dict) -> list[tuple[str, str]]:
    """PC 未定向边用战术序 / 混杂→攻击 定向。运营 DAG 以 PC 为主,GES 只打标签。"""
    directed = [(a, b) for a, b in pc.get("directed") or []]
    have = set(directed)

    def add(a, b):
        if (a, b) in have or (b, a) in have:
            return
        have.add((a, b))
        directed.append((a, b))

    for e in pc.get("undirected") or []:
        if not e or len(e) != 2:
            continue
        a, b = e[0], e[1]
        if is_confounder(a) and not is_confounder(b):
            add(a, b)
            continue
        if is_confounder(b) and not is_confounder(a):
            add(b, a)
            continue
        ra, rb = TACTIC_RANK.get(a), TACTIC_RANK.get(b)
        if ra is not None and rb is not None:
            if ra < rb:
                add(a, b)
            elif rb < ra:
                add(b, a)
    return directed


def _split_prior_oriented(
    pc: dict,
    directed: list[tuple[str, str]],
) -> tuple[list[tuple[str, str]], list[tuple[str, str]]]:
    """把 `directed` 拆成「数据推导」与「纯先验」两段。

    整改方案 §九.3：

    > 「TACTIC_RANK 可以继续作为搜索偏好和冲突信息，但未定向的边不能
    > 只因为先验排序不同，就在输出中变成具有数据支持的因果方向。」
    > 「建议继续保留：**原始的数据推导方向。先验偏好的方向。** 冲突标记。
    > 未定向状态。数据置信度与先验影响的独立字段。」

    实测（2026-10-19）：在一条 `PORT_SCAN → BRUTE_FORCE → C2_BEACON`
    的链状数据上，PC **一条有向边都没定出来**（无 v-结构），
    `_orient_with_prior` 于是按 TACTIC_RANK 定向出两条；
    而 GES 从数据推出了**方向相反**的两条。同一份输出里于是同时存在：

        edges:     BRUTE_FORCE → PORT_SCAN   orientation_source=data_invariant
        directed:  PORT_SCAN → BRUTE_FORCE   （纯先验，与上一条矛盾）

    `directed` 会被 `store.save_graph` 落库、被 `query_do` 与
    `annotate_chains` 当成「学出来的因果图」使用，而两者之间**没有任何
    字段能区分** —— 这正是文档说的「先验伪装成证据」。

    本函数**只做披露**：不改变 `directed` 的任何内容与顺序。
    「运营 DAG 以 PC 为主」是既定设计（见 `_orient_with_prior` 的 docstring），
    改口径属于设计决策，不在披露范围内。
    """
    data_directed = {(a, b) for a, b in (pc.get("directed") or [])}
    data_part, prior_part = [], []
    for a, b in directed:
        (data_part if (a, b) in data_directed else prior_part).append((a, b))
    return data_part, prior_part


def learn_from_matrix(
    X,
    names: list[str],
    *,
    alpha: float = 0.05,
    apply_prior: bool = True,
    max_cond: int = 3,
) -> dict:
    """从二进制矩阵学出因果图。

    ``max_cond`` / ``alpha`` 是 G² 条件独立检验的参数，整改方案
    §九.1 要求「统一并记录统计后端、依赖版本和检验参数」——
    它们与统计后端一起进 ``provenance``，让这张图日后可被解释。
    """
    pc = pc_learn(X, names, alpha=alpha, max_cond=max_cond)
    ges = ges_learn(X, names)
    cons = consensus(pc, ges)
    directed_pairs = _orient_with_prior(pc)
    # §九.3：`directed` 里的边出处不同 —— PC 从数据定向的，与按 TACTIC_RANK
    # / 混杂先验定向的。后者**不是**数据支持的因果方向，必须单独可查。
    directed_data, directed_prior = _split_prior_oriented(pc, directed_pairs)
    # 先验标记,不删边(消融用)
    edges = []
    for e in cons["directed"]:
        item = dict(e)
        if e.get("orientation") == "undirected":
            # 方向冲突时 cause/effect 只是字典序占位，**不是**因果方向，
            # 所以既不能判先验违规，也不该拿它去算 ACE
            item["prior_violation"] = False
            item["ace"] = None
            item["identifiable"] = False
            item["p_y_do"] = None
            item["identifiability_reason"] = "direction_conflict"
            edges.append(item)
            continue
        item["prior_violation"] = prior_forbids(e["cause"], e["effect"])
        if apply_prior and item["prior_violation"]:
            item["confidence"] = "prior_violation"
        # ACE
        if is_attack_node(e["cause"]) and is_attack_node(e["effect"]):
            q = intervene(X, names, directed_pairs, e["cause"], e["effect"], do_value=0)
            item["ace"] = q.get("ace")
            item["identifiable"] = q.get("identifiable", False)
            item["p_y_do"] = q.get("p_y_do")
            item["backdoor_set"] = list(q.get("z") or [])
            item["graph_version"] = q.get("graph_version", "")
            # 识别假设必须随结论落库：没有这条，下游看到 ACE=0.66 时
            # 无从知道它建立在「不存在未观测混杂」这个假设之上
            item["identification_assumptions"] = q.get("assumptions") or {}
        else:
            item["ace"] = None
            item["identifiable"] = False
            item["p_y_do"] = None
            item["backdoor_set"] = []
            item["graph_version"] = ""
        edges.append(item)
    pc_stats = pc.get("stats") or {}
    return {
        "ok": True,
        "reason": "",
        "learned_at": datetime.now(timezone.utc).isoformat(),
        "n": int(getattr(X, "shape", [0])[0]),
        "names": names,
        # 结果可追溯性：算法 + 统计后端 + 依赖版本 + 检验参数。
        # 没有它，两次学出的图看起来一模一样，却可能来自不同的
        # χ² 实现（装/没装 scipy），差异无处解释。
        "provenance": {
            "algorithms": ["pc", "ges"],
            "chi2_backend": pc_stats.get("chi2", ""),
            "scipy_version": pc_stats.get("scipy_version", ""),
            "alpha": float(alpha),
            "max_cond": int(max_cond),
        },
        "pc": pc,
        "ges": ges,
        "agree_rate": cons["agree_rate"],
        "edges": edges,
        "directed": directed_pairs,
        # 运营 DAG 的**出处拆分**（整改方案 §九.3）。两者合起来等于
        # `directed`，但分开才看得出哪些方向是数据给的、哪些是先验给的。
        # 与 `edges[].orientation_source`（data_invariant / score_search /
        # conflict）配合，就能看出「先验方向与数据方向相反」这种矛盾。
        "directed_data": [list(e) for e in directed_data],
        "directed_prior": [list(e) for e in directed_prior],
        "skeleton_agree": cons["skeleton_agree"],
        "candidates": candidate_edges(edges),
        "ladder": 2,
    }


def learn_from_events(
    events,
    *,
    bin_minutes: int = DEFAULT_BIN_MINUTES,
    min_windows: int = DEFAULT_MIN_WINDOWS,
    alpha: float = 0.05,
    apply_prior: bool = True,
) -> dict:
    mat = events_to_matrix(events, bin_minutes=bin_minutes, min_windows=min_windows)
    if not mat.get("ok"):
        return {
            "ok": False,
            "reason": mat.get("reason") or "insufficient_data",
            "n": mat.get("n", 0),
            "names": mat.get("names") or [],
            "edges": [],
            "directed": [],
            "candidates": [],
            "pc": {},
            "ges": {},
            "agree_rate": 0.0,
        }
    result = learn_from_matrix(mat["X"], mat["names"], alpha=alpha, apply_prior=apply_prior)
    result["dropped"] = mat.get("dropped") or []
    result["bin_minutes"] = bin_minutes
    return result


def query_do(
    graph: dict,
    x: str,
    y: str,
    *,
    do_value: int = 0,
    data=None,
    names: Optional[list[str]] = None,
) -> dict:
    names = names or graph.get("names") or []
    directed = graph.get("directed") or []
    if data is None:
        return {"identifiable": False, "reason": "no_data", "x": x, "y": y, "do": do_value}
    return intervene(data, names, directed, x, y, do_value=do_value)


def annotate_chains(chains: list[dict], graph: dict, *, data=None) -> list[dict]:
    """给关联链打因果标注。

    图本身不可用时给 `insufficient_data` 而不是 `unknown` ——
    「没有图可用」和「图上有链但方向不明」是两件事，前者连
    可达性都没得查，后者是查了但不确定。整改方案 §三.1。
    """
    if not graph or not graph.get("ok"):
        return [{**c, "causal_verdict": "insufficient_data",
                 "identifiable": False, "data_available": False,
                 "ace": None, "backdoor_set": [],
                 "identifiability_reason": "no_graph"} for c in chains]
    directed = graph.get("directed") or []
    names = graph.get("names") or []
    return [
        annotate_chain(c, directed=directed, names=names, data=data)
        for c in chains
    ]
