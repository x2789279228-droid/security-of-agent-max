"""
§十一 P2 剩余三项指标：因果链可观测性 / 基线版本号 / 聚类截断计数。

整改方案 §十一 P2 第 1 条那 7 行指标表里，此前「部分覆盖」的三项，
本轮补齐到可观测。注意这三项有个共同的失败形态：

    **加了字段，但没有消费方** —— 生产方塞了，`stats()` 里没读，
    效果与只打一行日志完全相同。

所以每条断言都要求「值真的从对外出口读出来」，而不是「字段存在」。
"""
import asyncio
import os

import pytest

os.environ.setdefault("SHARED_MEMORY_SKIP_DOTENV", "1")

import numpy as np  # noqa: E402


# ══════════════════════════════════════════════════════════════
# #3 因果链：不可判定的原因拆分 + 未定向边数
# ══════════════════════════════════════════════════════════════

def test_pc_stats_report_undecidable_reasons():
    """不可判定必须能拆成原因，不能只有「算不出来」一个数字。

    样本太少、变量恒定、分层全退化是三种不同的运维问题：
    前者要加数据，后者要改特征抽取，第三者要降维度。
    合成一个 `untestable` 计数就又回到「压成一个数字」。
    """
    from causal_chain.pc import G2_UNDECIDABLE_REASONS, pc_skeleton

    # 4 行 < 8 → 每个检验都因 too_few_rows 不可判定
    data = np.array([[0, 0], [0, 1], [1, 0], [1, 1]], dtype=np.uint8)
    stats: dict = {}
    pc_skeleton(data, alpha=0.05, max_cond=1, stats=stats)

    ud = stats.get("undecidable")
    assert ud, f"stats 里没有不可判定的原因拆分: {stats}"
    assert ud.get("too_few_rows", 0) > 0, \
        f"样本不足没有被单独计数: {ud}"
    assert ud.get("tests_total", 0) > 0, "没有记录检验总量"
    assert ud.get("df_computed", 0) == 0, \
        "4 行的数据不可能算出 df>0 的检验"
    # 原因分类常量必须与实际用到的键对得上
    for key in ud:
        assert key in G2_UNDECIDABLE_REASONS or key in (
            "tests_total", "df_computed", "df_degenerate"), \
            f"stats 里的 {key!r} 不在声明的原因分类里，改代码时漏改了常量"


def test_pc_stats_untestable_pairs_agrees_with_reasons():
    """``untestable_pairs`` 与原因拆分必须一致 —— 同一个事实两个出口。

    两个数字不等意味着至少有一个是错的，而看代码很难发现。
    """
    from causal_chain.pc import pc_skeleton

    rng = np.random.default_rng(7)
    data = rng.integers(0, 2, size=(12, 4)).astype(np.uint8)
    stats: dict = {}
    pc_skeleton(data, alpha=0.05, max_cond=2, stats=stats)

    ud = stats["undecidable"]
    reasons_total = sum(
        v for k, v in ud.items()
        if k in ("same_var", "too_few_rows", "all_strata_degenerate"))
    assert stats["untestable_pairs"] == reasons_total, (
        f"untestable_pairs={stats['untestable_pairs']} 与原因拆分合计 "
        f"{reasons_total} 不一致")


def test_pc_learn_exposes_undirected_edge_count():
    """``pc_learn`` 必须报出未定向边数（§十一 明列的指标）。"""
    from causal_chain.pc import pc_learn

    rng = np.random.default_rng(11)
    x = rng.integers(0, 2, size=300)
    y = (x ^ (rng.integers(0, 2, size=300) < 0.2)).astype(int)
    data = np.column_stack([x, y, rng.integers(0, 2, size=300)]).astype(np.uint8)
    names = ["a", "b", "c"]

    out = pc_learn(data, names, alpha=0.05)
    assert "undirected_edges" in out, "pc_learn 未暴露未定向边数"
    assert out["undirected_edges"] == len(out["undirected"]), \
        "undirected_edges 与 undirected 列表长度对不上"
    assert out["directed_edges"] == len(out["directed"])


def test_pc_learn_stats_propagates_to_matrix_learner():
    """``learn_from_matrix`` 必须把 pc 的 stats 带出来。

    ⚠️ 这条是**接线**断言，不是函数断言。上一版报告写「stats 出了 pc.py
    就丢了」，实际是跟着 ``result["pc"]`` 传出去的 —— 报告写错了。
    这条把「确实传了」钉住，免得下次真丢掉时没人发现。
    """
    from causal_chain.learn import learn_from_matrix

    rng = np.random.default_rng(3)
    data = rng.integers(0, 2, size=(120, 3)).astype(np.uint8)
    out = learn_from_matrix(data, ["a", "b", "c"], alpha=0.05)

    assert out.get("ok") is True, out.get("reason")
    pc = out.get("pc") or {}
    assert pc.get("stats"), "pc.stats 没有透传到 learn_from_matrix 的返回里"
    assert "untestable_pairs" in pc["stats"]


# ══════════════════════════════════════════════════════════════
# #4 异常检测基线版本号
# ══════════════════════════════════════════════════════════════

def _analyze(det, ev):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(det.analyze(ev))
    finally:
        loop.close()


def test_baseline_version_advances_on_real_update():
    """基线真的变了 → 代数必须 +1。"""
    from anomaly_detector import AnomalyDetector

    det = AnomalyDetector()
    assert det.baseline_version == 0
    for i in range(3):
        _analyze(det, {"event": "E", "src_ip": "10.5.0.1", "event_id": 100 + i})
    assert det.baseline_version == 3, \
        f"3 次真实更新后代数应为 3，实际 {det.baseline_version}"


def test_baseline_version_does_not_advance_on_replay():
    """幂等重放**不得**推进代数。

    这是代数能不能用来判别「基线变没变」的前提：若重放也 +1，
    版本号会随重放次数漂移，于是「今天比昨天新」这个判断失去意义。
    """
    from anomaly_detector import AnomalyDetector

    det = AnomalyDetector()
    _analyze(det, {"event": "E", "src_ip": "10.5.0.2", "event_id": 4242})
    after_first = det.baseline_version
    assert after_first == 1

    for _ in range(5):
        _analyze(det, {"event": "E", "src_ip": "10.5.0.2", "event_id": 4242})
    assert det.baseline_version == after_first, \
        f"重放推进了代数: {after_first} -> {det.baseline_version}"


def test_report_carries_baseline_version():
    """代数必须出现在报告里 —— 字段加了没人读等于没加。"""
    from anomaly_detector import AnomalyDetector

    det = AnomalyDetector()
    rep = _analyze(det, {"event": "E", "src_ip": "10.5.0.3", "event_id": 777})
    assert hasattr(rep, "baseline_version")
    assert rep.baseline_version == det.baseline_version >= 1

    # 重放时报告里的代数应当保持不变（读的是当前基线状态）
    rep2 = _analyze(det, {"event": "E", "src_ip": "10.5.0.3", "event_id": 777})
    assert rep2.baseline_version == rep.baseline_version


def test_baseline_version_survives_reload():
    """代数必须持久化 —— 否则重启一次版本归零，判别力当场失效。"""
    import json

    from anomaly_detector import AnomalyDetector

    store: dict = {}

    class _FakePipe:
        """aioredis 的 pipeline 命令是**同步缓冲**的，execute 才 await。"""

        def __init__(self, store):
            self.store = store
            self.pending: list = []

        def setex(self, key, ttl, value):
            self.pending.append((key, value))

        async def execute(self):
            for k, v in self.pending:
                self.store[k] = v
            self.pending.clear()

    class _FakeRedis:
        def pipeline(self):
            return _FakePipe(store)

        async def get(self, key):
            raw = store.get(key)
            return raw.encode() if isinstance(raw, str) else raw

        async def scan_iter(self, match=None, count=None):
            for key in list(store):
                if key.startswith("anomaly:baseline:") and ":" in key[len(
                        "anomaly:baseline:"):]:
                    yield key

    det = AnomalyDetector()
    det.redis = _FakeRedis()
    det.baseline_version = 41
    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(det._save_baselines_to_redis(force=True))
    finally:
        loop.close()

    raw = store.get("anomaly:baseline:global:version")
    assert raw is not None, "基线代数没有被持久化"
    assert json.loads(raw)["v"] == 41

    # 新实例从 Redis 恢复后应接着 41 走，而不是回到 0
    det2 = AnomalyDetector()
    det2.redis = _FakeRedis()
    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(det2.load_baselines_from_redis())
    finally:
        loop.close()
    assert det2.baseline_version == 41, \
        f"重启后基线代数应恢复到 41，实际 {det2.baseline_version}"


# ══════════════════════════════════════════════════════════════
# #5 聚类特征截断计数
# ══════════════════════════════════════════════════════════════

def test_cluster_stats_count_truncated_features():
    """截断计数必须真的从 `features_truncated` 汇总出来。

    ⚠️ 该字段在 ``SampleFeatures`` 上早就有，但一直没人读 ——
    「加了字段就以为可观测」的典型。这条要求值真的出现在 ``stats()``。

    用公开的 ``add_sample`` 造样本而不是直接改 ``_samples``：
    私有字典绕过入口等于绕过了特征提取，而「截断」正是提取阶段打的标。
    """
    from zeroday_detect.variant_cluster import VariantCluster

    vc = VariantCluster()
    assert vc.stats["truncated_features"] == 0
    assert vc.stats["truncated_features_ratio"] is None

    vc.add_sample({"api_calls": ["a.exe"], "files_written": ["c:/t1"]}, "h1")
    vc.add_sample({"api_calls": ["b.exe"], "files_written": ["c:/t2"]}, "h2")
    assert vc.stats["total_samples"] == 2

    # 标记其中一条「因上游截断而不完整」
    feats = next(f for f in vc._samples.values()
                 if f.sample_hash.startswith("h1"))
    feats.features_truncated = True

    st = vc.stats
    assert st["truncated_features"] == 1, \
        f"truncated_features 未汇总 features_truncated: {st}"
    assert st["truncated_features_ratio"] == pytest.approx(0.5)


def test_cluster_stats_truncated_ratio_is_none_when_empty():
    """空集合时比率必须是 None 而不是 0.0。

    0.0 会被读成「截断率为零，一切正常」；实际上「没有样本」
    与「样本都没被截断」是完全不同的两件事。
    """
    from zeroday_detect.variant_cluster import VariantCluster

    st = VariantCluster().stats
    assert st["total_samples"] == 0
    assert st["truncated_features_ratio"] is None, \
        "空集合的截断比率应是 None（未知），不是 0.0（已知为零）"
