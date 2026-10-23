"""
§十一.2「文档只承诺当前真正实现的算法与约束」——
变种聚类的特征向量，必须与上游行为分析**实际产出的字段**一致。

发现（2026-10-18 本轮查证，非推测）：

`zeroday_detect/variant_cluster.py` 的模块 docstring 声称行为向量是
「API 调用 / 文件操作 / 注册表 / 网络 IOC / MITRE / 签名」**6 类**，
`_extract_features` 也确实逐个读了 6 个键：

    analysis.get("signatures")      ✅ BehaviorAnalysis 产出
    analysis.get("api_calls")       ❌ 上游从不产出
    analysis.get("registry_keys")   ❌ 上游从不产出
    analysis.get("mitre_techniques")✅ BehaviorAnalysis 产出
    analysis.get("network_iocs")    ✅ BehaviorAnalysis 产出
    analysis.get("file_iocs")       ✅ BehaviorAnalysis 产出

`zeroday_detect/behavior_analyzer.py::BehaviorAnalysis.to_dict()` 的键集里
**没有** `api_calls`、也没有 `registry_keys`，于是这两类特征在真实管线上恒为空集
—— 审查报告 P3-9 记的「实测恒为空集」得到代码级确认。

需要说清楚的两点，避免误判：

  * **注册表信息并没有丢**。behavior_analyzer:201-202 把
    `behavior.summary.keys` 归进了 `file_iocs`（action="registry"），
    所以注册表键仍然参与聚类 —— 只是走的 `file:` 前缀而非 `reg:` 前缀。
    真正完全不存在的是 `api_calls`。
  * 因此**功能上没有缺陷**，聚类靠其余 4 类正常工作。
    缺陷在于文档：读者会以为 API 调用参与了家族划分，而它从未参与过。
    这正是该条要求所说的「可能导致使用者误解结果的可信度」。

    修法是让文档说真话，并由本文件钉住 —— 改代码不改文档（或反之）会变红。

注意本文件守的不变式不是「不一致消失」，而是「不一致必须被显式声明」：
`api_calls` / `registry_keys` 的读取分支仍在代码里，只是已不再被默默
宣称为行为向量成分。
"""
from __future__ import annotations

import inspect
import re

import pytest

from zeroday_detect import variant_cluster as vc_mod
from zeroday_detect.behavior_analyzer import BehaviorAnalysis
from zeroday_detect.variant_cluster import VariantCluster


def _read_keys() -> set[str]:
    """聚类实际从 analysis 里读的所有键。"""
    src = inspect.getsource(VariantCluster._extract_features)
    return set(re.findall(r'analysis\.get\(\s*"([a-z_]+)"', src))


def _produced_keys() -> set[str]:
    """上游行为分析实际产出的所有键。"""
    return set(BehaviorAnalysis.__dataclass_fields__)


def test_unproduced_feature_keys_are_explicitly_declared_in_the_docstring():
    """核心回归：聚类不得**静默**依赖上游不产出的字段。

    注意这里刻意**不**断言「不一致消失」。`api_calls` / `registry_keys`
    在本轮被查明并写进文档说明，但它们本身仍然存在于代码里 —— 断言它们消失
    等于要求把可能复用的读取分支删掉，那是超出本次范围的功能改动。

    真正该守的不变式是：**每一个上游不产出、却被读取的字段，
    都必须在模块 docstring 里被显式点名并标注「无上游生产者」。**
    新增一个静默不一致（例如上游改名或新增字段）会立刻转红。
    """
    doc = vc_mod.__doc__ or ""
    unproduced = sorted(_read_keys() - _produced_keys())
    assert unproduced == ["api_calls", "registry_keys"], (
        "无上游生产者的读取键集合变了 —— 若上游新增了产出，"
        "请同步更新模块 docstring 的行为向量成分表与本断言"
    )
    for field in unproduced:
        assert field in doc, (
            f"{field} 被读取但上游不产出，却没在 docstring 里显式点名 —— "
            "读者会误以为它参与了家族划分"
        )
    assert "无上游生产者" in doc


def test_registry_keys_actually_arrive_via_file_iocs():
    """钉住「注册表信息没丢」这一事实，防止后人误删或误判。

    behavior_analyzer:201-202 把 behavior.summary.keys 归入 file_iocs，
    action="registry"。若哪天改成独立的 registry_keys 字段，
    本条会红 —— 那时本文件的两条断言需要一并更新。
    """
    produced = _produced_keys()
    assert "file_iocs" in produced
    assert "registry_keys" not in produced

    # 真实载荷里，注册表键确实以 file_iocs 出现并能进入特征集
    # （token 经 put() 统一小写，避免大小写变体绕过相似度比较）
    feats = VariantCluster()._extract_features(
        {"file_iocs": [{"path": r"HKLM\Software\Evil", "action": "registry"}]},
        "h1",
    )
    assert "file:hklm\\software\\evil" in feats.to_feature_set()
    assert feats.registry_keys == set(), "前提：registry_keys 字段本身未被填充"


def test_api_calls_never_arrives_in_the_real_pipeline():
    """把「API 调用从未参与聚类」钉成显式事实。

    这条不是断言 bug（功能上没有 bug），而是断言**文档不能宣称它参与了**。
    """
    feats = VariantCluster()._extract_features(
        {"signatures": ["Sig_A"], "mitre_techniques": ["T1071"]},
        "h1",
    )
    assert feats.api_calls == set()
    assert feats.to_feature_set() == {"sig:sig_a", "mitre:t1071"}


def test_module_docstring_declares_the_unproduced_families():
    """docstring 必须点名无上游生产者的字段，而不是含糊地列在行为向量里。

    只检查「提到了」不够 —— 必须同时要求它被标记为未接入，
    否则等于把原来那句误导性描述换个说法再说一遍。
    """
    doc = vc_mod.__doc__ or ""
    for field in ("api_calls", "registry_keys"):
        assert field in doc, (
            f"模块 docstring 未点名 {field} —— "
            "它被读取但上游从不产出，必须显式说明而不是默默留在行为向量清单里"
        )
    assert "无上游生产者" in doc, (
        "docstring 需要一句「无上游生产者」的显式标注，"
        "否则读者仍会以为这些特征参与了家族划分"
    )


def test_docstring_does_not_claim_dbscan():
    """P3-9 已修部分：家族划分是相似图连通分量，不是 DBSCAN。"""
    doc = (vc_mod.__doc__ or "").upper()
    assert "DBSCAN" not in doc, "docstring 仍宣称 DBSCAN —— 实际实现是连通分量（单链）"


def test_family_definition_is_still_documented():
    """反过来也钉住：修文档不能把「家族定义」这段删掉。

    整改方案 §十.2 明确要求先定清业务定义（两两相似 vs 相似链连接），
    删掉它等于把已经澄清过的东西又变回隐含约定。
    """
    doc = vc_mod.__doc__ or ""
    assert "连通分量" in doc, "家族定义（相似图的连通分量）不得从 docstring 消失"
    assert "单链" in doc


# ══════════════════════════════════════════════════════════════════════════
# §十.2 行为不变式：顺序无关性 / 空特征不可判定 / 无特征不成族
#
# 上面那些用例守的是「文档与特征契约」。文档 §十.2 的验收原话另有两句：
#   「相同样本集合仅改变输入顺序，不会产生不可解释的簇变化」
#   「无效或空特征不会人为形成同一家族」
# 这两句曾经真的坏过（cluster_id 是自增序号；两个空集相似度直接 return 1.0），
# 而修复只写在 docstring 里，没有行为守卫 —— 属于「整改声明 ≠ 整改成立」。
# ══════════════════════════════════════════════════════════════════════════

def _analysis(sigs, mits=None):
    return {
        "signatures": list(sigs),
        "mitre_techniques": list(mits or []),
        "network_iocs": [],
        "file_iocs": [],
    }


_SAMPLES = {
    "a1": _analysis(["s1", "s2", "s3"]),
    "a2": _analysis(["s2", "s3", "s4"]),
    "a3": _analysis(["s3", "s4", "s5"]),
    "b1": _analysis(["t1", "t2", "t3"]),
    "b2": _analysis(["t2", "t3", "t4"]),
    "c1": _analysis(["z9"]),
    "bad1": _analysis([]),        # 无任何有效特征
    "bad2": _analysis([""]),      # 只有占位串，同样没有有效特征
}


def _partition(order):
    """按给定顺序喂样本，返回 {cluster_id: [成员...]}。"""
    vc = VariantCluster()
    for name in order:
        vc.add_sample(_SAMPLES[name], sample_hash=name)
    out: dict[int, list[str]] = {}
    for name in order:
        out.setdefault(vc._samples[name].cluster_id, []).append(name)
    return {cid: sorted(m) for cid, m in out.items()}


def test_partition_and_cluster_ids_do_not_depend_on_input_order():
    """§十.2：簇划分与 cluster_id 都必须与到达顺序无关。

    **这条守卫的实际灵敏度（2026-10-19 实测，别误以为它更灵敏）：**
    顺序无关性在本实现里是**双层保障** ——
      1. `_components()` 把遍历起点、分量成员、分量顺序**全部排序**；
      2. `_cluster_id_for()` 取 `min(hashes)`，与传入顺序无关。
    实测注入结果：
      - 只把 `min(hashes)` 改成「取第一个」→ 本用例**仍然绿**（第 1 层挡住）；
      - 只把 `_components()` 的排序去掉 → 仍然**绿**（第 2 层挡住）；
      - **两层同时**去掉 → 才红，且红的原因是「换序后簇划分变了」。
    所以它守的是「这个性质」，不是「任何单点改动的回归」。别拿它当
    「改了排序逻辑测试一定会响」的依据；那属于对守卫灵敏度的错误预期。
    """
    base = _partition(list(_SAMPLES))
    multi = [c for c, m in base.items() if len(m) > 1]
    assert multi, f"前提守卫：本数据集应当存在多成员簇，实得 {base}"

    names = list(_SAMPLES)
    for i in range(1, len(names)):
        perm = names[i:] + names[:i]
        assert _partition(perm) == base, (
            f"换序后簇划分变了（旋转 {i} 位）:\n{base}\n{_partition(perm)}")


def test_two_featureless_samples_are_undecidable_not_identical():
    """空特征集之间**不可判定**，绝不能是 1.0。"""
    import math

    empty = vc_mod.jaccard_similarity(set(), set())
    assert isinstance(empty, float) and math.isnan(empty), (
        f"两个空集合的相似度是 {empty!r} —— 应为 NaN(不可判定)。"
        "返回 1.0 会让毫无可比特征的样本被判成同一个家族")
    assert not (empty >= 0.5), "NaN 参与 `sim >= threshold` 比较会抛错而非静默通过"
    assert vc_mod.jaccard_similarity({"a"}, {"a"}) == 1.0, (
        "前提守卫：完全相同的非空特征集相似度应当是 1.0，"
        "否则上面那条 NaN 断言可能是被『恒返回常数』骗过去的")


def test_samples_without_valid_features_never_form_one_family():
    """§十.2：无效/空特征不得人为聚成同一家族。"""
    parts = _partition(["bad1", "bad2", "a1", "a2"])
    bad_ids = {cid for cid, members in parts.items()
               if set(members) & {"bad1", "bad2"}}
    for cid in bad_ids:
        members = set(parts[cid])
        assert not ({"bad1", "bad2"} <= members), (
            f"两个无有效特征的样本被合并成同一家族（cluster {cid}={parts[cid]}）—— "
            "这正是 §十.2 点名的『无效特征人为形成同一家族』")
    # 也不能混进有特征的家族
    for cid, members in parts.items():
        if {"bad1", "bad2"} & set(members):
            assert members in (["bad1"], ["bad2"]), (
                f"无特征样本混进了正常家族：{parts[cid]}")


def test_a_featureless_query_reports_inconclusive():
    """查询侧同样：没有可比特征时返回 inconclusive 而不是 0 相似度。"""
    vc = VariantCluster()
    vc.add_sample(_analysis(["s1", "s2", "s3"]), sample_hash="h1")
    res = vc.find_similar(_analysis([]))
    assert res and res[0]["status"] == "inconclusive", res
    assert res[0]["reason"] == "no_comparable_features", res
    assert res[0]["similarity"] is None, res
# ══════════════════════════════════════════════════════════════════════════
# §十.2：显示精度与原始判定值必须一致
# ══════════════════════════════════════════════════════════════════════════

class TestSimilarityReportingContract:
    """整改方案 §十.2 的一行：

      「round(sim, 3) 隐藏实际阈值差异 → **显示精度与原始判定值一致**，
        避免把 0.4996 显示成 0.500 却判为『相似』」

    现在的契约是：`find_similar` 返回的 `similarity` 是**未取整的判定值**，
    `similarity_display` 只用于展示，`meets_threshold` 用**原值**判定。

    这一条此前**没有任何回归**（全仓 `tests/` 搜 `similarity_display` /
    `meets_threshold` → 零命中）—— 而它正是「0.4996 显示成 0.500 却判为
    相似」这类误读的来源。
    """

    def test_similarity_value_is_not_rounded(self):
        """判定用的相似度必须是**原值** —— 文档举的例子就是 0.4996。"""
        a = {f"x{i}" for i in range(1249)}
        b = {f"x{i}" for i in range(2500)}
        sim = vc_mod.jaccard_similarity(a, b)
        assert sim == 0.4996, sim                      # 1249 / 2500
        assert round(sim, 3) == 0.5, "前提失效：取整后不再等于 0.5"
        assert sim != round(sim, 3), \
            "相似度被取整了 —— 判定值会与显示值不一致（0.4996 → 0.500）"

    def test_find_similar_reports_raw_similarity_and_a_separate_display(self):
        """`similarity` 是原值，`similarity_display` 是展示值，两者分开。

        注意：`find_similar` 会把**查询样本自身**也列进去（相似度 1.0），
        所以要按 `sample_hash` 定位目标条目，不能假设 `res[0]` 是它。
        """
        vc = VariantCluster()
        vc.add_sample(_analysis(["s1", "s2"]), sample_hash="a")
        vc.add_sample(_analysis(["s1", "s2", "s3"]), sample_hash="b")

        res = vc.find_similar(_analysis(["s1", "s2", "s3"]))
        assert res, res
        top = next(r for r in res if r["sample_hash"] == "a")
        assert top["similarity"] == 2 / 3, top          # 原值，不是 0.667
        assert top["similarity_display"] == "0.667", top  # 展示值单独一份
        assert top["meets_threshold"] is True, top

    def test_meets_threshold_agrees_with_the_raw_value(self):
        """`meets_threshold` 必须由**原值**决定，不能由展示值决定。"""
        vc = VariantCluster()
        vc.add_sample(_analysis(["s1", "s2"]), sample_hash="a")
        vc.add_sample(_analysis(["s1", "s2", "s3"]), sample_hash="b")
        for threshold in (0.5, 0.6, 0.7):
            res = vc.find_similar(_analysis(["s1", "s2", "s3"]),
                                   threshold=threshold)
            for r in res:
                assert r["meets_threshold"] == (r["similarity"] >= threshold), \
                    (threshold, r)
# ══════════════════════════════════════════════════════════════════════════
# §十.2：特征集的「限长」缺口
# ══════════════════════════════════════════════════════════════════════════

class TestFeatureSetIsNotSilentlyTruncated:
    """特征集**不得**再被静默截断（文档 §十.2 点名的老缺陷）。

    修复前 `sigs[:20]` 静默截断 → 后续签名全丢。
    现在 `_extract_features()` 不截断，所以这条性质成立。

    ⚠ 但「不截断」同时意味着**没有上限** —— 见下一个 strict xfail。
    """

    def test_signatures_are_not_silently_truncated_at_twenty(self):
        """30 个签名必须**全部**进特征集（老实现只留前 20 个）。"""
        vc = VariantCluster()
        vc.add_sample(_analysis([f"s{i}" for i in range(30)]), sample_hash="a")
        feats = vc._samples["a"]
        assert len(feats.to_feature_set()) == 30, \
            f"特征集只剩 {len(feats.to_feature_set())} 个 —— 又被截断了"

    @pytest.mark.xfail(strict=True, reason=(
        "已知缺口：特征集**没有上限**，且 features_truncated 在生产代码里"
        "零赋值（唯一赋值在测试里手工设置）→ stats['truncated_features'] "
        "结构性恒为 0，是死计数器。见验收报告 §9.24 / 待决项 22。"
        "补上限会改变聚类结果，方向可能是漏报，不该由一次审计单方面决定。"))
    def test_feature_set_is_bounded_and_marked_when_truncated(self):
        """【缺口】特征集必须有上限，且被截断时必须打标记。"""
        vc = VariantCluster()
        vc.add_sample(_analysis([f"s{i}" for i in range(5000)]), sample_hash="big")
        feats = vc._samples["big"]
        assert feats.features_truncated is True, (
            "5000 个签名却没有标记截断 —— 特征集无上限")
        assert len(feats.to_feature_set()) < 5000, "特征集没有被限长"


# ══════════════════════════════════════════════════════════════════════════
# §十.2「相同样本集合」：增量构建必须与全量重建一致（2026-10-20，§9.30）
# ══════════════════════════════════════════════════════════════════════════


class TestOverwrittenSamplesDoNotLeaveStaleEdges:
    """`add_sample(analysis, sample_hash=...)` 允许调用方**显式**指定 hash，
    此时 hash **不再由特征派生** —— 同一个 hash 可以带**不同特征**被提交多次。

    修复前只覆盖特征、**不清掉按旧特征算出来的边**：
      · 旧边残留 → 当前特征毫不相干（Jaccard=0）的两个样本仍被判成**同族**；
      · **增量构建与全量重建结果不一致** —— 同样本集合（按最终状态），
        两种构建给出不同的簇划分。

    文档 §十.2：「相同样本集合仅改变输入顺序，不会产生不可解释的簇变化」。

    ⚠ 正常情形（**同样本重复提交、特征相同**）下修复是**空操作** ——
    清掉的边会被同一段逻辑重新算回来。那条路径也必须被钉住。
    """

    V1 = _analysis(["s1", "s2"])      # 与 X 同族
    V2 = _analysis(["z9", "z8"])      # 与 X 毫无相似
    X = _analysis(["s1", "s2"])

    @staticmethod
    def _partition(vc):
        out = {}
        for h, f in vc._samples.items():
            out.setdefault(f.cluster_id, []).append(h)
        return {cid: sorted(m) for cid, m in out.items()}

    def test_the_old_edge_is_removed_when_features_are_overwritten(self):
        """核心性质：覆盖特征后，按旧特征算出来的边必须消失。"""
        vc = VariantCluster()
        vc.add_sample(self.V1, sample_hash="dup")
        vc.add_sample(self.X, sample_hash="X")
        # 此刻 dup 与 X 相似 → 同族
        assert len(vc._components()) == 1, vc._components()

        vc.add_sample(self.V2, sample_hash="dup")     # 同 hash，特征换掉
        comps = [sorted(c) for c in vc._components()]
        assert comps == [["X"], ["dup"]], (
            f"覆盖特征后旧边仍在：{comps} —— 当前特征 Jaccard=0，不该同族")

    def test_incremental_build_matches_a_fresh_build(self):
        """**同样本集合（最终状态）**，增量构建与全量重建必须一致。"""
        fresh = VariantCluster()
        fresh.add_sample(self.V2, sample_hash="dup")
        fresh.add_sample(self.X, sample_hash="X")

        incr = VariantCluster()
        incr.add_sample(self.V1, sample_hash="dup")
        incr.add_sample(self.X, sample_hash="X")
        incr.add_sample(self.V2, sample_hash="dup")

        assert self._partition(incr) == self._partition(fresh), (
            "增量构建与全量重建给出不同的簇划分 —— "
            f"{self._partition(incr)} vs {self._partition(fresh)}")

    def test_a_duplicate_with_identical_features_keeps_its_cluster(self):
        """正常情形不能被改坏：同样本重复提交（特征相同）必须照旧成族。"""
        vc = VariantCluster()
        vc.add_sample(self.X, sample_hash="X")
        vc.add_sample(self.V1, sample_hash="dup")
        vc.add_sample(self.V1, sample_hash="dup")     # 重复提交，特征相同
        comps = [sorted(c) for c in vc._components()]
        assert comps == [["X", "dup"]], comps

    def test_the_duplicate_counter_still_counts(self):
        """记账不能被修复顺手删掉。"""
        vc = VariantCluster()
        vc.add_sample(self.V1, sample_hash="dup")
        vc.add_sample(self.V1, sample_hash="dup")
        assert vc.stats.get("duplicate_submissions") == 1, vc.stats

    def test_samples_with_zero_overlap_never_share_a_cluster(self):
        """用户可见的性质：家族归属必须由**当前**特征支撑。"""
        from zeroday_detect.variant_cluster import jaccard_similarity

        vc = VariantCluster()
        vc.add_sample(self.V1, sample_hash="dup")
        vc.add_sample(self.X, sample_hash="X")
        vc.add_sample(self.V2, sample_hash="dup")
        for comp in vc._components():
            if len(comp) < 2:
                continue
            a, b = comp[0], comp[1]
            sim = jaccard_similarity(vc._samples[a].to_feature_set(),
                                      vc._samples[b].to_feature_set())
            assert sim > 0, (
                f"{a} 与 {b} 被判成同族，但当前特征的 Jaccard = {sim}")
