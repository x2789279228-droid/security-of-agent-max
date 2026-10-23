"""
variant_cluster.py — 样本相似度聚类（变种识别）

基于沙箱报告的行为特征对样本进行聚类：
  - 相似度: Jaccard（与 `self_play.novelty` 不同源，全仓只此一份）
  - 家族划分: **相似图的连通分量**（单链连接）
  - 新家族发现: 无法归入已知簇的样本标记为潜在零日

**行为向量的真实成分（§十一.2：只承诺当前真正实现的）**

`_extract_features` 读 6 个键，但只有 4 个在真实管线上有上游生产者：

| 特征前缀 | 读取的键 | 上游 `BehaviorAnalysis.to_dict()` 是否产出 |
|---|---|---|
| `sig:` | `signatures` | ✅ 产出 |
| `mitre:` | `mitre_techniques` | ✅ 产出 |
| `net:` | `network_iocs` | ✅ 产出 |
| `file:` | `file_iocs` | ✅ 产出（**含注册表键**，见下） |
| `api:` | `api_calls` | ❌ **无上游生产者**，真实管线上恒为空集 |
| `reg:` | `registry_keys` | ❌ **无上游生产者**，真实管线上恒为空集 |

两点必须说清楚，避免误读：

  1. **注册表信息并没有丢**。`behavior_analyzer.py:201-202` 把
     `behavior.summary.keys` 归入 `file_iocs`（action="registry"），
     所以注册表键**确实参与**家族划分，只是走 `file:` 前缀而非 `reg:`。
     `registry_keys` 这个独立字段是历史遗留的未接入分支。
  2. **真正完全不存在的是 `api_calls`**。本模块既不读沙箱原始报告的
     API 调用序列，也没有别的模块生产它 —— 它从未参与过家族划分。

因此**功能上没有缺陷**，聚类靠 4 类特征正常工作。缺陷在文档：
修订前本文档写「行为向量: API 调用 / 文件操作 / 注册表 / 网络 IOC / MITRE /
签名」，会让读者以为 API 调用参与了家族划分，而它从未参与过 ——
这会让人高估家族划分的证据强度。
`tests/test_clustering_feature_contracts.py` 已把上表钉成回归，
上游一旦开始产出 `api_calls` / `registry_keys` 该测试即转红并需要更新本表。

整改记录（整改方案 §十.2，2026-10-18 审查）：

1. **两个空集合的相似度曾经是 1.0**。修复前 `jaccard_similarity(set(), set())`
   直接 `return 1.0`。于是两条**完全没有可比特征**的样本相似度 100%，
   被判成同一个家族 —— 这是凭空造出来的高相似度，比漏报更危险。
   现在返回 NaN（不可判定），任何 `sim >= threshold` 比较都为 False。

2. **畸形 IOC 生成 `net:` / `file:` 占位 token**。修复前
   `ioc.get("value", "")` 在字段缺失时得到空串，再 f-string 成 `"net:"`。
   所有畸形样本都共享同一个占位 token，于是它们两两「高度相似」。
   现在逐个校验，非法值记入 `invalid_tokens` 并排除出特征集。

3. **簇划分依赖插入顺序**。修复前只与「簇里第一个样本」（簇代表）比较，
   而簇代表就是最早 add 的那个；输入顺序一换，簇就重组。
   现在采用**连通分量**：家族 = 相似图的连通分量，成员关系与输入顺序无关。

4. **家族定义先定清楚再选算法**（整改方案明确要求）。
   本实现选择「**相似链连接**」而不是「所有成员两两相似」：
     - 两两相似（全链接）对噪声更稳健，但要求更高、召回更低；
     - 相似链连接（单链接）只要存在一条相似链就同族，符合「变种可能
       只在局部特征上与母本相似」的实际；
     - 代价是单链接会出现「链式漂移」，所以 `get_cluster_info` 里会给出
       簇的**内聚度**（簇内最小相似度），让低内聚的簇可被识别出来。

5. **`cluster_id` 内容寻址**：由连通分量内最小 sample_hash 的哈希导出，
   与到达顺序无关 —— 同一批样本无论什么顺序进来，簇 id 完全一致。
   （整改前 cluster_id 是自增序号，插入顺序直接决定簇号。）

6. **`sigs[:20]` 静默截断 / `round(sim, 3)` 隐藏阈值差异**：
   `get_cluster_info` 标注 `samples_truncated`；
   `find_similar` 同时给出未取整的 `similarity` 与展示用的
   `similarity_display`，避免把 0.4996 显示成 0.500 却判为「相似」。
"""
import hashlib
import logging
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

#: 归入已有簇的相似度阈值（>= 该值才连接）
CLUSTER_THRESHOLD = 0.5

#: 解析器常见的「有字段但没值」占位串，一律不算有效特征。
#: 注意这里**不**设最小长度门槛：短标识（"s1"、"T1"）是完全合法的特征，
#: 按长度过滤会把它们误杀 —— 那是另一种凭空制造漏报的方式。
PLACEHOLDER_VALUES = frozenset({
    "", "-", "--", "?", "n/a", "na", "none", "null", "nil", "unknown",
    "unspecified", "undefined", "empty", "无", "空", "未知",
})

#: `find_similar` 一次最多返回多少条（截断时会被标注）
DEFAULT_TOP_K = 5


def _clean_token(value) -> tuple:
    """把一个原始字段值清洗成特征 token。

    Returns: (token 或 None, 原始值)
    空串 / None / 占位串（"n/a"、"unknown"…）返回 (None, 原始值)，
    调用方负责把它记进 `invalid_tokens`。
    """
    if value is None or isinstance(value, bool):
        return None, value
    text = str(value).strip()
    if text.lower() in PLACEHOLDER_VALUES:
        return None, text
    return text.lower(), text


@dataclass
class SampleFeatures:
    """样本行为特征向量（各集合里存的已是校验后的规范 token）"""
    sample_hash: str = ""
    api_calls: set = field(default_factory=set)
    files_written: set = field(default_factory=set)
    registry_keys: set = field(default_factory=set)
    network_hosts: set = field(default_factory=set)
    mitre_ids: set = field(default_factory=set)
    signatures: set = field(default_factory=set)
    cluster_id: int = -1
    family: str = ""
    #: 被判为无效而排除的特征（可观测：畸形 IOC 不该悄悄消失）
    invalid_tokens: list = field(default_factory=list)
    #: 特征是否因上游截断而不完整
    features_truncated: bool = False

    def to_feature_set(self) -> set:
        """合并所有特征为统一集合（用于 Jaccard 相似度）"""
        features = set()
        features.update(f"api:{c}" for c in self.api_calls)
        features.update(f"file:{f}" for f in self.files_written)
        features.update(f"reg:{r}" for r in self.registry_keys)
        features.update(f"net:{n}" for n in self.network_hosts)
        features.update(f"mitre:{m}" for m in self.mitre_ids)
        features.update(f"sig:{s}" for s in self.signatures)
        return features


def jaccard_similarity(a: set, b: set) -> float:
    """Jaccard 相似度。

    **两个空集合返回 NaN（不可判定），不是 1.0。**

    整改方案 §十.2：修复前空集合对空集合返回 1.0，于是毫无特征可比的两条
    样本被判成「完全相似的同一个家族」。没有可比特征就是**无法判断**，
    NaN 让所有 `>= 阈值` 的比较为 False，既不会聚到一起，也不会被当成
    「相似度 0」参与排序。
    """
    if not a and not b:
        return float("nan")
    if not a or not b:
        return 0.0
    intersection = len(a & b)
    union = len(a | b)
    return intersection / union if union > 0 else 0.0


def _cluster_id_for(hashes) -> int:
    """由连通分量内最小 sample_hash 派生簇号（内容寻址，与顺序无关）。"""
    anchor = min(hashes) if hashes else ""
    return int(hashlib.sha1(anchor.encode("utf-8"), usedforsecurity=False).hexdigest()[:8], 16)


class VariantCluster:
    """样本变种聚类引擎（家族 = 相似图连通分量）"""

    def __init__(self, threshold: float = CLUSTER_THRESHOLD):
        self._samples: dict[str, SampleFeatures] = {}
        #: 相似图邻接表：hash → {与之相似度 >= 阈值的 hash}
        self._adj: dict[str, set] = defaultdict(set)
        self._threshold = float(threshold)
        self._family_map: dict[int, str] = {}
        #: 被判定为「无有效特征」的样本数（可观测性）
        self._no_feature_samples = 0
        self._duplicate_submissions = 0

    # ── 聚类核心 ────────────────────────────────────────────

    def _components(self) -> list:
        """相似图的连通分量，按最小 hash 排序 → 结果与插入顺序无关。"""
        seen = set()
        out = []
        for start in sorted(self._samples):
            if start in seen:
                continue
            comp = []
            queue = deque([start])
            seen.add(start)
            while queue:
                node = queue.popleft()
                comp.append(node)
                for nxt in sorted(self._adj.get(node, ())):
                    if nxt not in seen:
                        seen.add(nxt)
                        queue.append(nxt)
            out.append(sorted(comp))
        out.sort(key=lambda c: c[0])
        return out

    def _reindex(self) -> None:
        """按连通分量重建 cluster_id，并把家族名重新贴回样本。"""
        for comp in self._components():
            cid = _cluster_id_for(comp)
            for h in comp:
                f = self._samples.get(h)
                if f is not None:
                    f.cluster_id = cid
                    f.family = self._family_map.get(cid, "")

    # ── 对外接口 ────────────────────────────────────────────

    def add_sample(self, analysis: dict, sample_hash: str = "") -> int:
        """
        添加样本到聚类引擎

        analysis: BehaviorAnalysis.to_dict() 或沙箱报告
        返回: cluster_id

        特征为空时**不会**创建家族，也不会返回 -1 之外的语义：
        返回的簇号是「该样本当前所在的分量」，若它没有有效特征，
        它自成一个单点分量（相似度不可判定 ≠ 与谁相似）。
        """
        features = self._extract_features(analysis, sample_hash)
        feature_set = features.to_feature_set()
        sh = features.sample_hash

        if not feature_set:
            # 无有效特征：不能凭空聚类，但样本本身要留下可追踪的痕迹
            self._no_feature_samples += 1
            features.cluster_id = _cluster_id_for([sh])
            self._samples[sh] = features
            self._reindex()
            return features.cluster_id

        if sh in self._samples:
            # 同一样本重复提交：覆盖特征而不是产生两条，重复次数单独记账
            self._duplicate_submissions += 1
            #
            # ⚠ **覆盖特征前必须先清掉按旧特征算出来的边**（2026-10-20，§9.30）。
            #
            # `sample_hash` 可以由调用方**显式**指定，此时它**不再由特征派生** ——
            # 于是同一个 hash 可能带**不同特征**被提交多次。
            # 修复前只覆盖特征、**不清边**，于是：
            #   · 「按旧特征算出来的边」残留 → 当前特征毫不相干（Jaccard=0）
            #     的两个样本仍被判成**同族**；
            #   · **增量构建与全量重建结果不一致** ——
            #     同样本集合（最终状态），两种构建给出不同的簇划分。
            # 文档 §十.2 要求「相同样本集合仅改变输入顺序，
            # 不会产生不可解释的簇变化」。
            #
            # 正常情形（**同样本重复提交、特征相同**）下这是**空操作**：
            # 清掉的边会被下面同一段逻辑重新算回来。
            for other_hash in list(self._adj.get(sh, ())):
                self._adj[other_hash].discard(sh)
            self._adj.pop(sh, None)

        # 与所有已有样本比较，建相似边（这一步与到达顺序无关）
        for other_hash, other in self._samples.items():
            if other_hash == sh:
                continue
            sim = jaccard_similarity(feature_set, other.to_feature_set())
            if sim == sim and sim >= self._threshold:      # NaN 会被挡掉
                self._adj[sh].add(other_hash)
                self._adj[other_hash].add(sh)

        self._samples[sh] = features
        self._reindex()
        return features.cluster_id

    def find_similar(
        self,
        analysis: dict,
        threshold: Optional[float] = None,
        top_k: int = DEFAULT_TOP_K,
    ) -> list[dict]:
        """查找与给定分析最相似的已知样本。

        返回值里的 `similarity` 是**未取整**的判定值，`similarity_display`
        只用于展示。整改前只给 `round(sim, 3)`，于是 0.4996 显示成 0.500
        却因为没过阈值被排除 —— 看着像命中，实际没命中。
        """
        threshold = self._threshold if threshold is None else float(threshold)
        features = self._extract_features(analysis)
        feature_set = features.to_feature_set()

        if not feature_set:
            return [{
                "status": "inconclusive",
                "reason": "no_comparable_features",
                "sample_hash": None,
                "similarity": None,
                "similarity_display": "N/A",
                "cluster_id": None,
                "family": "",
                "truncated": False,
                "total_matches": 0,
            }]

        scored = []
        for h, sample in self._samples.items():
            sim = jaccard_similarity(feature_set, sample.to_feature_set())
            if sim == sim and sim >= threshold:
                scored.append((sim, h, sample))
        scored.sort(key=lambda t: (-t[0], t[1]))          # 并列按 hash 兜底

        results = [{
            "status": "ok",
            "sample_hash": h,
            "similarity": sim,
            "similarity_display": f"{sim:.3f}",
            "meets_threshold": sim >= threshold,
            "cluster_id": sample.cluster_id,
            "family": sample.family,
        } for sim, h, sample in scored]

        total = len(results)
        top = results[:max(0, int(top_k))]
        for r in top:
            r["total_matches"] = total
            r["truncated"] = total > len(top)
        return top

    def label_cluster(self, cluster_id: int, family: str):
        """为簇标记家族名"""
        self._family_map[cluster_id] = family
        for h, f in self._samples.items():
            if f.cluster_id == cluster_id:
                f.family = family

    def cluster_members(self, cluster_id: int) -> list:
        """簇内成员（按 hash 排序，保证确定性）"""
        return sorted(h for h, f in self._samples.items()
                      if f.cluster_id == cluster_id)

    def get_cluster_info(self, cluster_id: int, limit: int = 20) -> dict:
        """获取簇信息。

        整改前 `samples[:20]` 是**静默**截断：调用方看到 20 条就以为
        簇只有 20 个样本。现在显式返回 `total_samples` 与
        `samples_truncated`，并且给出簇内最小相似度（内聚度）——
        单链接聚类容易出现「链式漂移」，内聚度就是用来发现那种簇的。
        """
        members = self.cluster_members(cluster_id)
        sims = []
        for i, a in enumerate(members):
            fa = self._samples[a].to_feature_set()
            for b in members[i + 1:]:
                s = jaccard_similarity(fa, self._samples[b].to_feature_set())
                if s == s:
                    sims.append(s)
        return {
            "cluster_id": cluster_id,
            "family": self._family_map.get(cluster_id, "unknown"),
            "sample_count": len(members),
            "samples": members[:limit],
            "samples_truncated": len(members) > limit,
            "total_samples": len(members),
            "min_similarity": (round(min(sims), 4) if sims else None),
            "mean_similarity": (round(sum(sims) / len(sims), 4) if sims else None),
            "linkage": "single",
        }

    def get_unclustered(self) -> list:
        """获取未归入任何已知家族的样本（潜在零日）"""
        return sorted(h for h, f in self._samples.items() if not f.family)

    # ── 特征提取 ────────────────────────────────────────────

    def _extract_features(self, analysis: dict, sample_hash: str = "") -> SampleFeatures:
        """从分析结果提取特征（逐个校验，非法值记账后排除）"""
        if not isinstance(analysis, dict):
            logger.warning(
                "[variant_cluster] 非 dict 的分析结果，特征为空: %r",
                type(analysis).__name__)
            return SampleFeatures(sample_hash=sample_hash,
                                 invalid_tokens=["<non-dict analysis>"])

        if not sample_hash:
            # 没有 hash 就用特征内容兜底，避免所有样本挤在 "" 这一个键上
            sample_hash = self._content_hash(analysis)

        features = SampleFeatures(sample_hash=sample_hash)

        def put(target: set, prefix: str, value) -> None:
            token, raw = _clean_token(value)
            if token is None:
                features.invalid_tokens.append(f"{prefix}:{raw!r}")
                return
            target.add(token)

        for s in (analysis.get("signatures") or []):
            put(features.signatures, "sig", s)
        for s in (analysis.get("api_calls") or []):
            put(features.api_calls, "api", s)
        for s in (analysis.get("registry_keys") or []):
            put(features.registry_keys, "reg", s)

        for tech in (analysis.get("mitre_techniques") or []):
            value = tech.get("id") if isinstance(tech, dict) else tech
            put(features.mitre_ids, "mitre", value)

        for ioc in (analysis.get("network_iocs") or []):
            value = ioc.get("value") if isinstance(ioc, dict) else ioc
            put(features.network_hosts, "net", value)

        for ioc in (analysis.get("file_iocs") or []):
            value = ioc.get("path") if isinstance(ioc, dict) else ioc
            put(features.files_written, "file", value)

        if features.invalid_tokens:
            logger.info(
                "[variant_cluster] sample=%s 排除 %d 个无效特征: %s",
                sample_hash, len(features.invalid_tokens),
                features.invalid_tokens[:5])
        return features

    @staticmethod
    def _content_hash(analysis: dict) -> str:
        """无 sample_hash 时的稳定兜底标识（同一份内容 → 同一个键）"""
        import json
        payload = json.dumps(analysis, sort_keys=True, ensure_ascii=False,
                             default=str)
        return "content:" + hashlib.sha256(
            payload.encode("utf-8")).hexdigest()[:24]

    # ── 可观测性 ────────────────────────────────────────────

    @property
    def stats(self) -> dict:
        clusters = self._components()
        feats = list(self._samples.values())
        no_feature = sum(1 for f in feats if not f.to_feature_set())
        # §十一 要求的「特征截断数」。`SampleFeatures.features_truncated`
        # 早就有了，但一直没被汇总 —— 字段在、没人读，正是「加了字段
        # 就以为可观测」的典型：生产方塞了，消费方没接。
        truncated = sum(1 for f in feats if getattr(f, "features_truncated", False))
        return {
            "total_samples": len(self._samples),
            "total_clusters": len(clusters),
            "labeled_families": len(self._family_map),
            "unclustered": len(self.get_unclustered()),
            # §十一 要求监控「聚类无有效特征数、样本重复率、特征截断数」
            "samples_without_features": no_feature,
            "samples_without_features_ever": self._no_feature_samples,
            "duplicate_submissions": self._duplicate_submissions,
            "truncated_features": truncated,
            "truncated_features_ratio": (
                round(truncated / len(feats), 4) if feats else None),
            "similarity_threshold": self._threshold,
            "linkage": "single",
            "cluster_sizes": sorted((len(c) for c in clusters), reverse=True),
        }


# ── 全局单例 ──
variant_cluster = VariantCluster()
