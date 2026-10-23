"""
learn_loop.models_cluster — FP/漏报事件的相似聚类(纯函数)

复用:
  - zeroday_detect.variant_cluster.jaccard_similarity(不重复实现第三份 Jaccard)
  - self_play.novelty.tokenize(只读导入工具函数, 不触碰 self_play 其它模块)

事件特征集合:
  - event:{event_type}
  - rule:{rule_id}(若有)
  - net:{src_ip/24}(IPv6 用 /64; 解析失败退化为整 IP)
  - 消息词法 token

贪心聚类: 与已有簇代表取 Jaccard, 相似度 >= learn_loop_jaccard 并入,
否则新建簇。只返回 size >= learn_loop_cluster_min_size 的簇。

2026-10-20 修复（整改报告 §9.49）—— 本模块此前有**两个**顺序依赖：

1. **簇划分依赖到达顺序**：贪心算法把新样本只与「簇代表」比，
   而簇代表是**已并入成员的并集**（会长大）→ 同一批样本换个顺序进来，
   划分会变（实测：3 个样本，顺序 [A,B,C] 得 1 个簇，[A,C,B] 得 2 个簇）。
   修法：**聚类前按确定性全序排序** → 划分成为「事件集合」的函数。
   ⚠ 聚类算法本身**没动**（仍是贪心/leader）——「家族」的定义
   （全链接 vs 相似链）是**业务定义**，不单方面代拍（待决项 31）。
2. **簇号是位置号**：`learn_cluster_{idx}` 由创建顺序决定 →
   24h 去重键 `label_cluster:{cluster_id}` 会把**另一个家族**的提议静默吞掉。
   修法：簇号改为**内容寻址**（由成员身份派生）→ 不同家族不会撞号。
"""
from __future__ import annotations

import hashlib
import ipaddress
import logging

from zeroday_detect.variant_cluster import jaccard_similarity

from config import settings

logger = logging.getLogger(__name__)


def _subnet(ip: str) -> str:
    """IPv4 → ip/24, IPv6 → ip/64; 解析失败返回原 IP。"""
    if not ip:
        return ""
    ip = str(ip).strip()
    try:
        ver = ipaddress.ip_address(ip).version
        prefix = 24 if ver == 4 else 64
        return str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))
    except ValueError:
        return ip


def event_feature_set(evt: dict) -> set:
    """把单个事件转成聚类特征集合。"""
    features = set()
    event_type = str(evt.get("event_type") or evt.get("event") or evt.get("type") or "").strip()
    if event_type:
        features.add(f"event:{event_type.upper()}")
    rule_id = str(evt.get("rule_id") or "").strip()
    if rule_id:
        features.add(f"rule:{rule_id.upper()}")
    src_ip = str(evt.get("src_ip") or "").strip()
    net = _subnet(src_ip)
    if net:
        features.add(f"net:{net}")
    message = str(evt.get("message") or evt.get("msg") or "")
    if message:
        try:
            from self_play.novelty import tokenize  # 只读工具导入
            features.update(f"tok:{t}" for t in tokenize(message))
        except Exception as e:
            logger.debug("[learn_loop.cluster] tokenize unavailable: %s", e)
    return features


def _int_or_none(raw):
    """能转 int 就转，转不了返回 None（**不抛异常**）。"""
    if raw is None:
        return None
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def _member_key(evt: dict, feats: set) -> str:
    """成员的稳定身份串：id + 特征集指纹（没有 id 也有兜底）。

    修复前 `int(e.get("id"))` 遇到非数字 id 会抛 ValueError →
    **整次聚类**被一个坏 id 带走（`orchestrator` 只能记 partial 并丢掉全部簇）。
    """
    raw_id = evt.get("id")
    id_part = "" if raw_id is None else str(raw_id)
    feat_part = hashlib.sha1("|".join(sorted(feats)).encode("utf-8"), usedforsecurity=False).hexdigest()[:12]
    return f"{id_part}:{feat_part}"


def _sort_key(evt: dict, feats: set) -> tuple:
    """事件的确定性全序键：先 id（数字优先），再特征集，再成员身份串。

    三个层级合起来对**不同**事件是全序；完全相同的事件互相可替换，
    顺序无所谓。
    """
    id_num = _int_or_none(evt.get("id"))
    if id_num is not None:
        id_key = (0, id_num, "")
    else:
        raw_id = evt.get("id")
        id_key = (1, 0, "" if raw_id is None else str(raw_id))
    return (id_key, tuple(sorted(feats)), _member_key(evt, feats))


def _cluster_id_for(member_keys) -> str:
    """**内容寻址**的簇号：与到达顺序、与簇在结果列表里的位置都无关。

    修复前 `learn_cluster_{idx}` 是**位置号** → 24h 去重键
    `label_cluster:{cluster_id}` 会把**另一个家族**的提议静默吞掉。
    """
    anchor = "|".join(sorted(member_keys))
    return "learn_cluster_" + hashlib.sha1(anchor.encode("utf-8"), usedforsecurity=False).hexdigest()[:12]


def build_clusters(
    events: list[dict],
    *,
    min_size: int = 0,
    threshold: float = 0.5,
) -> list[dict]:
    """贪心聚类事件 dict 列表 → size>=min_size 的簇(按 size 降序)。

    每簇记录: cluster_id / size / event_ids / event_type(众数) / net(众数) /
    feature_count(代表特征数, 供人工打标参考)。
    """
    if min_size <= 0:
        try:
            min_size = int(getattr(settings, "learn_loop_cluster_min_size", 3) or 3)
        except Exception:
            min_size = 3
    if threshold <= 0:
        try:
            threshold = float(getattr(settings, "learn_loop_jaccard", 0.5) or 0.5)
        except Exception:
            threshold = 0.5

    # ── 确定性全序：簇划分必须是「事件集合」的函数，不是「到达顺序」的函数 ──
    prepared = []
    for evt in events:
        if not isinstance(evt, dict):
            continue
        feats = event_feature_set(evt)
        if not feats:
            continue
        prepared.append((evt, feats))
    prepared.sort(key=lambda pair: _sort_key(pair[0], pair[1]))

    clusters: list[dict] = []
    for evt, feats in prepared:
        best_idx = -1
        best_sim = threshold
        for idx, cl in enumerate(clusters):
            rep = cl["_features"]
            sim = jaccard_similarity(feats, rep)
            if sim >= best_sim:
                best_sim = sim
                best_idx = idx
        if best_idx >= 0:
            cl = clusters[best_idx]
            cl["_features"] |= feats
            cl["_events"].append(evt)
            cl["_keys"].append(_member_key(evt, feats))
        else:
            clusters.append({
                "_features": set(feats),
                "_events": [evt],
                "_keys": [_member_key(evt, feats)],
            })

    result = []
    for cl in clusters:
        size = len(cl["_events"])
        if size < min_size:
            continue
        from collections import Counter
        types = Counter(str(e.get("event_type") or "") for e in cl["_events"])
        nets = Counter(_subnet(str(e.get("src_ip") or "")) for e in cl["_events"] if e.get("src_ip"))
        result.append({
            "cluster_id": _cluster_id_for(cl["_keys"]),
            "size": size,
            "event_ids": sorted({
                i for i in (_int_or_none(e.get("id")) for e in cl["_events"])
                if i is not None
            }),
            "event_type": types.most_common(1)[0][0] if types else "",
            "net": nets.most_common(1)[0][0] if nets else "",
            "feature_count": len(cl["_features"]),
            "similarity_threshold": round(threshold, 3),
        })

    result.sort(key=lambda c: c["size"], reverse=True)
    return result
