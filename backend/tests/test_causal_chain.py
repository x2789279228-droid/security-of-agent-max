"""因果链 PC/GES + 后门 do:合成 SCM 可证伪。"""
import os
import sys

import numpy as np
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from causal_chain.compare import annotate_chain
from causal_chain.do_calculus import intervene
from causal_chain.learn import learn_from_events, learn_from_matrix
from causal_chain.pc import pc_learn
from causal_chain.variables import events_to_matrix


def _true_chain_matrix(n=700, seed=0):
    rng = np.random.default_rng(seed)
    night = rng.random(n) < 0.35
    ps = np.where(night, rng.random(n) < 0.78, rng.random(n) < 0.12).astype(np.uint8)
    bf = np.where(ps == 1, rng.random(n) < 0.84, rng.random(n) < 0.05).astype(np.uint8)
    c2 = np.where(
        bf == 1,
        rng.random(n) < 0.82,
        np.where(night, rng.random(n) < 0.22, rng.random(n) < 0.04),
    ).astype(np.uint8)
    fa = (rng.random(n) < 0.07).astype(np.uint8)
    names = ["PORT_SCAN", "BRUTE_FORCE", "C2_BEACON", "FILE_ACCESS", "HOUR_NIGHT"]
    X = np.stack([ps, bf, c2, fa, night.astype(np.uint8)], axis=1)
    return X, names


def _spurious_night_matrix(n=700, seed=1):
    """夜间同时抬升扫描/爆破/C2,无真链。CEP 仍会因共现命中。"""
    rng = np.random.default_rng(seed)
    night = rng.random(n) < 0.40
    ps = np.where(night, rng.random(n) < 0.80, rng.random(n) < 0.08).astype(np.uint8)
    bf = np.where(night, rng.random(n) < 0.80, rng.random(n) < 0.08).astype(np.uint8)
    c2 = np.where(night, rng.random(n) < 0.80, rng.random(n) < 0.08).astype(np.uint8)
    fa = (rng.random(n) < 0.06).astype(np.uint8)
    names = ["PORT_SCAN", "BRUTE_FORCE", "C2_BEACON", "FILE_ACCESS", "HOUR_NIGHT"]
    X = np.stack([ps, bf, c2, fa, night.astype(np.uint8)], axis=1)
    return X, names


def _edge_set(result) -> set:
    return {(e["cause"], e["effect"]) for e in result.get("edges") or []
            if e.get("confidence") in ("high_confidence", "oriented_by_one")}


def test_pc_recovers_true_chain_skeleton():
    X, names = _true_chain_matrix()
    pc = pc_learn(X, names, alpha=0.05)
    sk = {tuple(sorted(e)) for e in pc["skeleton"]}
    true_sk = {tuple(sorted(e)) for e in [
        ("PORT_SCAN", "BRUTE_FORCE"),
        ("BRUTE_FORCE", "C2_BEACON"),
    ]}
    assert true_sk <= sk, f"missing true skeleton {true_sk - sk}; got {sk}"


def test_learn_recalls_true_chain_and_do_port_scan_drops_c2():
    X, names = _true_chain_matrix()
    result = learn_from_matrix(X, names, alpha=0.05)
    assert result["ok"]
    directed = result["directed"]
    true_edges = {("PORT_SCAN", "BRUTE_FORCE"), ("BRUTE_FORCE", "C2_BEACON")}
    got = set(map(tuple, directed))
    recall = len(true_edges & got) / len(true_edges)
    assert recall >= 2 / 3, f"recall={recall} directed={got}"
    q_ps = intervene(X, names, directed, "PORT_SCAN", "C2_BEACON", do_value=0)
    q_fa = intervene(X, names, directed, "FILE_ACCESS", "C2_BEACON", do_value=0)
    assert q_ps.get("identifiable"), q_ps
    assert q_ps.get("ace") is not None and q_ps["ace"] > 0.15, q_ps
    if q_fa.get("identifiable") and q_fa.get("ace") is not None:
        assert abs(q_fa["ace"]) < q_ps["ace"], (q_fa, q_ps)


def test_night_confounder_marks_cep_chain_spurious():
    """夜间混杂造出来的伪因果链，绝不能拿到 causal_support。

    判定方式用「否定式」而不是枚举具体取值：整改方案 §三.1 把
    verdict 拆成 5 种（insufficient_data / not_identifiable /
    insufficient_causal_evidence / causal_support / unknown），
    枚举会把「因为 ACE 不显著」和「因为根本没有后门路径」这两种
    完全不同的情况混为一谈，而本测试真正要锁的是**唯一的那条红线**。
    """
    X, names = _spurious_night_matrix()
    result = learn_from_matrix(X, names, alpha=0.05)
    directed = result["directed"]
    chain = {
        "pattern_id": "port_scan_to_c2",
        "pattern_name": "端口扫描→暴力破解→C2",
        "events": [
            {"event_type": "PORT_SCAN"},
            {"event_type": "BRUTE_FORCE"},
            {"event_type": "C2_BEACON"},
        ],
    }
    annotated = annotate_chain(chain, directed=directed, names=names, data=X)
    q = intervene(X, names, directed, "PORT_SCAN", "C2_BEACON", do_value=0)
    if q.get("identifiable") and q.get("ace") is not None:
        assert abs(q["ace"]) < 0.15, q
    assert annotated["causal_verdict"] != "causal_support", annotated
    assert annotated["causal_verdict"] in (
        "insufficient_causal_evidence", "not_identifiable",
        "insufficient_data", "unknown"), annotated


def test_no_data_never_yields_causal_support():
    """整改方案 §三.1：data=None 时禁止输出 causal_support。

    修复前 `q` 退化成 `{"identifiable": False}` 后直接落到
    `elif path_ok` 分支 —— **零数据**也能拿到 causal_support，
    依据只是一张图上的可达性。
    """
    X, names = _spurious_night_matrix()
    result = learn_from_matrix(X, names, alpha=0.05)
    chain = {
        "pattern_id": "port_scan_to_c2",
        "pattern_name": "端口扫描→暴力破解→C2",
        "events": [{"event_type": "PORT_SCAN"}, {"event_type": "C2_BEACON"}],
    }
    annotated = annotate_chain(
        chain, directed=result["directed"], names=names, data=None)
    assert annotated["causal_verdict"] == "insufficient_data", annotated
    assert annotated["data_available"] is False
    assert annotated["identifiable"] is False
    assert annotated["ace"] is None
    # 图上可达也必须照实记录，但不能被当成因果支持。
    # 修复前这里写的是 `in (True, False)` —— 任何布尔值都能过，
    # 等于没有断言。改成一条真能失败的不变式：path_ok 与 missing_edges 必须一致。
    assert isinstance(annotated["causal_path_ok"], bool)
    if annotated["causal_path_ok"]:
        assert annotated["causal_missing_edges"] == [], (
            f"path_ok=True 却报了缺边: {annotated['causal_missing_edges']}")
    else:
        assert annotated["causal_missing_edges"], (
            "path_ok=False 却没有记录任何缺边 —— 不可达的步骤去哪了")
    assert "backdoor_set" in annotated
    assert annotated["identifiability_reason"]


def test_insufficient_windows_returns_empty():
    from datetime import datetime, timezone, timedelta
    now = datetime.now(timezone.utc)
    events = [
        {
            "event_type": "PORT_SCAN",
            "src_ip": "1.1.1.1",
            "dst_ip": "10.0.0.1",
            "created_at": now + timedelta(minutes=i),
            "anomaly_score": 0.1,
        }
        for i in range(5)
    ]
    result = learn_from_events(events, min_windows=40)
    assert result["ok"] is False
    assert result["reason"] == "insufficient_data"
    assert result["edges"] == []


def test_events_to_matrix_bins_and_night_flag():
    from datetime import datetime, timezone
    events = []
    base = datetime(2026, 9, 5, 2, 0, tzinfo=timezone.utc)
    for i in range(80):
        src = f"10.0.0.{i % 8}"
        ts = base.replace(minute=(i * 7) % 60, hour=1 + (i // 15) % 6)
        if i % 2 == 0:
            events.append({
                "event_type": "PORT_SCAN",
                "src_ip": src, "dst_ip": "192.168.1.1",
                "created_at": ts, "anomaly_score": 0.7 if i % 7 == 0 else 0.1,
            })
        if i % 3 == 0:
            events.append({
                "event_type": "C2_BEACON",
                "src_ip": src, "dst_ip": "8.8.8.8",
                "created_at": ts, "anomaly_score": 0.2,
            })
    mat = events_to_matrix(events, bin_minutes=30, min_windows=10)
    assert mat["ok"] is True
    assert "HOUR_NIGHT" in mat["names"]
    assert "PORT_SCAN" in mat["names"]
    assert mat["X"].shape[0] >= 10


# ══════════════════════════════════════════════════════════════
# §九.3：先验方向不得伪装成数据支持的方向
# ══════════════════════════════════════════════════════════════

def _chain_3var(n=600, seed=11):
    """A → B → C 的链，且 A 与 C 之间没有直达边。

    于是骨架是 A—B—C 而**不存在 v-结构**（A—B 的另一端 C 与 B 相邻，
    构成 shield），PC 应当把所有边留成未定向 —— 这正是先验唯一定向的场景。
    """
    rng = np.random.default_rng(seed)
    a = rng.integers(0, 2, n)
    b = a ^ (rng.random(n) < 0.10)
    c = b ^ (rng.random(n) < 0.10)
    names = ["PORT_SCAN", "BRUTE_FORCE", "C2_BEACON"]
    return np.column_stack([a, b, c]).astype(np.uint8), names


class TestPriorOrientationIsSeparable:
    """整改方案 §九.3：

    > 「未定向的边不能只因为先验排序不同，就在输出中变成具有数据支持的
    > 因果方向。」…「建议继续保留：原始的数据推导方向。先验偏好的方向。」

    实测（修复前）：`_orient_with_prior` 返回裸 `list[tuple]`，
    「这条边是 PC 从数据定向的」与「这条边是 TACTIC_RANK 定的」这个信息
    在函数出口就丢了。同一份输出里会同时出现

        edges:    BRUTE_FORCE → PORT_SCAN  orientation_source=data_invariant
        directed: PORT_SCAN → BRUTE_FORCE  （纯先验，与上一条**方向相反**）

    而 `directed` 会被落库、被 `query_do` / `annotate_chains` 当成
    「学出来的因果图」。修复只做披露，不动 `directed` 的内容与顺序。
    """

    def test_the_scenario_really_leaves_pc_edges_undirected(self):
        """前提守卫：不先把「PC 定向为空」核实清楚，下面几条都在测别的路径。"""
        X, names = _chain_3var()
        res = learn_from_matrix(X, names, alpha=0.05, max_cond=3)
        assert res["pc"]["directed"] == [], res["pc"]["directed"]
        assert res["pc"]["undirected"], res["pc"]["undirected"]

    def test_prior_and_data_directed_edges_are_separable(self):
        X, names = _chain_3var()
        res = learn_from_matrix(X, names, alpha=0.05, max_cond=3)
        directed = [tuple(e) for e in res["directed"]]
        data_part = [tuple(e) for e in res["directed_data"]]
        prior_part = [tuple(e) for e in res["directed_prior"]]

        assert data_part == [], f"PC 没定向任何边，数据段却有：{data_part}"
        assert prior_part, "PC 全部未定向时，TACTIC_RANK 必然接手 —— 却没被标出来"
        assert sorted(data_part + prior_part) == sorted(directed), (
            "两段合起来必须逐位等于 directed")

    def test_a_prior_edge_is_never_counted_as_data_derived(self):
        """纯先验段必须**恰好**是「directed 减去 PC 数据定向」的那部分。

        只断言「段内的边不在 pc.directed 里」是**空断言** ——
        整段为空时它恒绿（实测：把两段合并冒充成数据边时，这条仍绿）。
        所以这里断言的是等式本身。
        """
        X, names = _chain_3var()
        res = learn_from_matrix(X, names, alpha=0.05, max_cond=3)
        pc_dir = {(a, b) for a, b in (res["pc"]["directed"] or [])}
        directed = [tuple(e) for e in res["directed"]]
        expected_prior = [e for e in directed if e not in pc_dir]
        assert expected_prior, "前提守卫：本数据集上先验段不该是空的"
        assert [tuple(e) for e in res["directed_prior"]] == expected_prior, (
            "纯先验段被算错了 —— 边被冒充成了数据推导出来的")
        assert [tuple(e) for e in res["directed_data"]] == [
            e for e in directed if e in pc_dir]

    def test_the_prior_contradiction_with_data_becomes_visible(self):
        """本条是修复的核心价值：矛盾**查得出来**。

        修复前 `directed` 与 `edges` 方向相反这件事没有任何字段能表达；
        现在只要比对 `directed_prior` 与 `edges[].orientation_source` 即可。
        """
        X, names = _chain_3var()
        res = learn_from_matrix(X, names, alpha=0.05, max_cond=3)
        prior = {tuple(e) for e in res["directed_prior"]}
        data_edges = {
            (e["cause"], e["effect"]) for e in res["edges"]
            if e.get("orientation_source") == "data_invariant"
        }
        contradictions = {(b, a) for a, b in prior if (b, a) in data_edges}
        assert contradictions, (
            "本数据集上应当存在「先验方向与数据方向相反」的边 —— "
            "若哪天不再出现，先确认是不是前提守卫（PC 定向为空）失效了")

    def test_the_disclosure_does_not_change_the_operational_dag(self):
        """披露是纯增量：`directed` 的内容与顺序必须逐位不变。"""
        from causal_chain.learn import _orient_with_prior

        X, names = _chain_3var()
        res = learn_from_matrix(X, names, alpha=0.05, max_cond=3)
        assert res["directed"] == _orient_with_prior(res["pc"]), (
            "加披露字段顺手改了运营 DAG —— 那是设计决策，不在披露范围内")
