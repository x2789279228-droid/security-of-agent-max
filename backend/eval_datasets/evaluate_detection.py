"""
检测引擎量化评估器（整改方案 §十三「量化评估」维度）。

与 :mod:`eval_datasets.evaluate_behavior` / :mod:`eval_datasets.evaluate_grounding`
同构，输出 Precision / Recall / 误报率 / 漏报率。

## 三条纪律（与前两个评估器一致）

1. **判定跑真检测器**，不在评估器里复刻档位逻辑。
2. 阈值扫描必然要复刻判定（否则只能扫一个写死的点），所以复刻结果
   会被 :func:`_assert_reimplementation_matches` **强制**与真检测器
   逐条比对，不一致直接抛错 —— 否则扫出来的区间是自说自话。
3. 指标必须说明**分母是谁**。误报率的分母 TN 完全由注入的良性样本数
   决定，所以 :func:`fp_rate_by_base_rate` 在三档基准率下分别报告。

## 一个必须说清的结构性事实

当前 11 条规则里有 8 条的判据包含 ``event|contains``，也就是说
**上游 `normalize_event_type` 一旦把事件标成 C2_BEACON，Sigma 必然命中**。
这类命中测的是上游分类器，不是 Sigma。

所以 Sigma 的结果按 ``evidence_kind`` 拆开报：
``raw_indicator`` 才是 Sigma 自身的增量价值。如果它接近 0，
结论是「当前规则库对上游分类器没有增量」，而不是「Sigma 坏了」。
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import statistics
import sys
from pathlib import Path

# Windows 控制台可能是 GBK；报告含 ⚠ / ✅ 等字符，直接 print 会崩。
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

from eval_datasets.detection_cases import (
    anomaly_cases, correlation_cases, sigma_cases,
)

# ── 被评估的真引擎 ────────────────────────────────────────────
from sigma_engine.engine import PySigmaDetector

from anomaly_detector import ANOMALY_SCORE_THRESHOLD, AnomalyDetector
from correlation_engine import ATTACK_CHAIN_PATTERNS, CorrelationEngine

RULES_DIR = "sigma_engine/rules"
LOOP = asyncio.new_event_loop()


def _norm(etypes: set) -> set:
    from correlation_engine import normalize_event_type
    return {normalize_event_type(t) for t in etypes}


#: 「负类」标签。suspicious 不在其中 —— 它既不是阳性也不是阴性。
_NEGATIVE_LABEL = "benign"


def _binary(case_list, pred_label: str, negative_label: str = _NEGATIVE_LABEL) -> dict:
    """给定「预测为正」的标签，产出混淆矩阵与 P/R/F1/FP率/FN率。

    ⚠️ 只统计真值为二分类的样本。第三类（如 `suspicious` 候选、异常检测的
    `inconclusive`）被**排除**在分子分母之外，既不算 TP 也不算 TN。

    把候选算成 TN 会虚高特异度，算成 FN 会虚高漏报率 ——
    两种都会让指标失去意义。整改方案 §二要求的正是这个区分：
    「partial 不可以直接视为完整阴性」。

    **`negative_label` 必须按家族传入**（2026-10-19 修复）：
    三个检测器家族的负类标签**并不相同** ——
        Sigma        正类 `malicious`   负类 `benign`
        异常检测      正类 `detected`    负类 `not_detected`
        关联引擎      正类 `chain`       负类 `no_chain`
    修复前这里写死 `_NEGATIVE_LABEL = "benign"`，于是异常检测的
    `not_detected` 与关联引擎的 `no_chain` 全被判成「第三类候选」而排除。
    实测后果：
        correlation  tp=2 fp=0 **tn=0** fn=0 excluded_suspicious=**6**
                     → 误报率 **null**；accuracy=(2+0)/2=1.0 报成 100% 准确，
                       而那个总体里**一条负样本都没有**，结构上无法表达误报
        anomaly      tp=1 fp=0 **tn=0** fn=2 excluded_suspicious=**2**
                     → 误报率 **null**
    而 §十三 验收要求「分别报告各类检测器的 Precision、Recall、
    **误报率与漏报率**」—— 这两个家族的误报率因此是算不出来的。
    """
    tp = fp = tn = fn = 0
    skipped = 0
    for c in case_list:
        if c["expect"] not in (pred_label, negative_label):
            skipped += 1
            continue
        pos = (c["expect"] == pred_label)
        hit = bool(c["got_positive"])
        if pos and hit:
            tp += 1
        elif pos and not hit:
            fn += 1
        elif not pos and hit:
            fp += 1
        else:
            tn += 1
    n = tp + fp + tn + fn
    prec = tp / (tp + fp) if (tp + fp) else None
    rec = tp / (tp + fn) if (tp + fn) else None
    f1 = (2 * prec * rec / (prec + rec)) if (prec and rec and (prec + rec)) else None
    fpr = fp / (fp + tn) if (fp + tn) else None
    fnr = fn / (fn + tp) if (fn + tp) else None
    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "excluded_suspicious": skipped,
        "precision": prec, "recall": rec, "f1": f1,
        "false_positive_rate": fpr, "false_negative_rate": fnr,
        "accuracy": (tp + tn) / n if n else None,
        # 整改方案 §四 的验收指标「每千条事件误报量」。
        # 这里给的是**每千条良性事件**的口径（与 FPR 同源、与基准率无关）；
        # 「每千条摄入事件」的运营负担口径在 precision_by_prevalence 里
        # （那一档才知道基准率）。分母写进名字里，免得读的人自己猜。
        "false_positives_per_1k_benign": (fpr * 1000) if fpr is not None else None,
    }


# ══════════════════════════════════════════════════════════════
# Sigma
# ══════════════════════════════════════════════════════════════

def run_sigma(rules_dir: str = RULES_DIR) -> list:
    """跑真引擎。

    ⚠️ `got_positive` 的口径：**确定检出**才算阳性。
    带 x-soc-aggregation 的规则（SIG-001/007）在单事件阶段只满足
    前置筛选，阈值证据尚未产生 —— 那不是检出，是候选。
    把它算成阳性会让「一次正常登录」变成一个统计上的误报，
    从而**逼着人去调规则**，而真正该修的是「用不充分的证据下执行动作」。

    这些命中单独记在 `partial_only`，不混进 P/R 分子分母。
    """
    det = PySigmaDetector(rules_dir)
    out = []
    for c in sigma_cases():
        r = det.detect_for_event(dict(c["event"]))
        hits = r.get("hits", []) or []
        pending = set(r.get("pending_aggregation") or [])
        confirmed = [h for h in hits if h["rule_id"] not in pending]
        out.append({
            "id": c["id"], "expect": c["expect"],
            # 确定检出：有命中，且至少一条不是「待聚合」
            "got_positive": bool(confirmed),
            "raw_detected": bool(r.get("detected")),
            "partial_only": bool(hits) and not confirmed,
            "status": r.get("status", ""),
            "pending_aggregation": sorted(pending),
            "severity": max((h["severity"] for h in confirmed),
                            key=lambda s: SEVERITY_RANK.get(s, 0), default=""),
            "actions": sorted({h["action_recommend"] for h in confirmed}),
            "attack_types": sorted({t for h in confirmed
                                    for t in (h["attack_type"],) if t}),
            "evidence_kind": c["evidence_kind"], "note": c["note"],
            "rules_evaluated": r.get("rules_evaluated"),
            "rules_failed": r.get("rules_failed"),
        })
    return out


SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def sigma_breakdown(rows: list) -> dict:
    """按 evidence_kind 拆分命中来源。

    这是本评估最关键的一张表：它回答「Sigma 到底贡献了多少
    独立于上游分类器的检出」。

    ⚠️ 只有 ``raw_indicator`` / ``event_type_only`` 两类的真值是恶意；
    ``lookalike`` / ``benign`` 两类的真值是**良性**。把它们当成
    「正类=benign」去算，会输出一份「良性样本被漏报」的反向结论 ——
    那看起来像指标，其实是口径错误。
    """
    by_kind: dict = {}
    for kind in sorted({r["evidence_kind"] for r in rows}):
        sub = [r for r in rows if r["evidence_kind"] == kind]
        malicious = kind in ("raw_indicator", "event_type_only")
        m = _binary(sub, "malicious")
        m["n"] = len(sub)
        m["expect_malicious"] = malicious
        m["hit_ids"] = [r["id"] for r in sub if r["got_positive"]]
        # 「漏报」只在**真值为恶意、且该样本进入了二分类统计总体**时成立。
        # `suspicious`（待聚合候选）被 _binary 排除 —— 它没有确定结论，
        # 把它记成漏报，等于凭空造一条不存在的缺陷，还会让报告去
        # 「修」一个根本没坏的东西。
        m["miss_ids"] = [r["id"] for r in sub
                         if malicious and r["expect"] == "malicious"
                         and not r["got_positive"]]
        # 「误报」同理：只统计真值为良性且确实报阳的样本
        m["false_alarm_ids"] = [r["id"] for r in sub
                                if not malicious
                                and r["expect"] == _NEGATIVE_LABEL
                                and r["got_positive"]]
        # 候选单列，既不进漏报也不进误报
        m["candidate_ids"] = [
            r["id"] for r in sub
            if r["expect"] not in ("malicious", _NEGATIVE_LABEL)]
        by_kind[kind] = m
    raw_m = by_kind.get("raw_indicator", {})
    raw_hits = raw_m.get("tp", 0)
    # 分母必须是**进入二分类统计的** raw_indicator 样本数（TP+FN），
    # 而不是该分组的全部行。待聚合候选没有确定结论，把它算进分母
    # 会把命中率从 1.000 压到 0.667 —— 那不是 Sigma 漏检，
    # 是评估口径把「候选」当成了「阴性」。
    raw_total = raw_hits + raw_m.get("fn", 0)
    echo_hits = by_kind.get("event_type_only", {}).get("tp", 0)
    # 分母必须是**真阳性**。第一版用「所有命中的行」当分母，把 3 条误报
    # 算了进去，于是 raw_indicator 占比被稀释成 0.462 —— 那不是
    # 「Sigma 增量能力低」，只是分母里混进了错误命中。
    true_hits = sum(1 for r in rows
                    if r["got_positive"] and r["expect"] == "malicious")
    benign_fp = sum(
        len(v["false_alarm_ids"])
        for k, v in by_kind.items() if not v["expect_malicious"])
    return {
        "by_evidence_kind": by_kind,
        "raw_indicator_hit_rate": (raw_hits / raw_total) if raw_total else None,
        # 命中来源拆分以真阳性为分母；误报单列，不混进来
        "raw_indicator_share_of_tp": (raw_hits / true_hits) if true_hits else None,
        "upstream_echo_share": (echo_hits / true_hits) if true_hits else None,
        "true_hits": true_hits,
        "benign_false_alarms": benign_fp,
    }


# ══════════════════════════════════════════════════════════════
# 异常检测
# ══════════════════════════════════════════════════════════════

def _probe_report(det: AnomalyDetector, event: dict):
    async def go():
        return await det.analyze(dict(event))
    return LOOP.run_until_complete(go())


def _feed(det: AnomalyDetector, events):
    for e in events:
        _probe_report(det, e)


def run_anomaly() -> list:
    out = []
    for c in anomaly_cases():
        det = AnomalyDetector()
        _feed(det, c["baseline"])
        rep = _probe_report(det, c["probe"])
        out.append({
            "id": c["id"], "expect": c["expect"], "note": c["note"],
            "status": rep.status, "anomaly_score": rep.anomaly_score,
            "is_anomaly": rep.is_anomaly,
            "deviation_sigma": rep.deviation_sigma,
            "got_positive": (rep.status == "detected"),
            "inconclusive_dimensions": list(rep.inconclusive_dimensions),
            "baseline_samples": rep.baseline_samples,
            "effective_weights": dict(rep.effective_weights),
            # §四 验收指标表的「检测延迟 | 从异常出现到被识别的时间」。
            # 取自生产路径写进 analysis_window 的那个值（见 §9.27）。
            "detection_latency_seconds": _win(rep).get("detection_latency_seconds"),
            "ingest_latency_seconds": _win(rep).get("ingest_latency_seconds"),
            "known_gap": c.get("known_gap"),
        })
    return out


def _win(rep) -> dict:
    """取报告的 analysis_window（没有就当空 dict）。"""
    w = getattr(rep, "analysis_window", None)
    return w if isinstance(w, dict) else {}


def cold_start_breakdown(rows: list) -> dict:
    """按「新实体 / 成熟实体」分档报告（整改方案 §七）。

    文档 §七 要求「**至少按新实体、成熟实体、不同部署规模、不同时间窗口
    分别报告**」，而修复前评估器只给**单一汇总** ——
    于是「冷启动检测表现」这一项根本没被单独报出来。

    分档依据是**基线样本量**与 `COLD_START_MIN_SAMPLES` 的关系：
    低于门槛的实体**结构上**就没有统计维度（判 inconclusive），
    这正是「新 IP / 新资产不会系统性失明」要考察的那一档。

    ⚠ 「不同部署规模」「不同时间窗口」两档**本报告仍未覆盖** ——
    标定集里没有按部署规模/窗口长度分层的样本（§9.27 登记为待补）。
    """
    from anomaly_detector import COLD_START_MIN_SAMPLES

    def _grp(rs):
        if not rs:
            return {"n": 0, "detected": 0, "inconclusive": 0, "not_detected": 0,
                    "recall": None, "_note": "该档没有样本"}
        det = sum(1 for r in rs if r["status"] == "detected")
        inc = sum(1 for r in rs if r["status"] == "inconclusive")
        nd = sum(1 for r in rs if r["status"] == "not_detected")
        should = [r for r in rs if r["expect"] == "detected"]
        rec = (sum(1 for r in should if r["status"] == "detected") / len(should)
               if should else None)
        return {"n": len(rs), "detected": det, "inconclusive": inc,
                "not_detected": nd, "recall": rec}

    mature = [r for r in rows if r["baseline_samples"] >= COLD_START_MIN_SAMPLES]
    fresh = [r for r in rows if r["baseline_samples"] < COLD_START_MIN_SAMPLES]
    out = {
        "cold_start_min_samples": COLD_START_MIN_SAMPLES,
        "mature": _grp(mature),
        "fresh": _grp(fresh),
        "_note": "「不同部署规模」「不同时间窗口」两档未覆盖 —— "
                 "标定集没有按这两维分层的样本（§9.27 登记为待补）。",
    }
    # 新实体档：若出现「判成 not_detected」就是**结构性失明**（漏报），
    # 必须显式点出来，不能混在计数里。
    out["fresh_structurally_blind"] = [
        r["id"] for r in fresh if r["status"] == "not_detected"]
    return out


def latency_summary(rows: list) -> dict:
    """检测延迟的汇总（整改方案 §四）。

    **分母是「进入二分类统计的异常样本数」**，不可算的条数单列 ——
    「没测到」与「测到是 0」必须能被区分开（同 §9.25 的
    `false_positives_per_1k_benign` 口径：分母为空时给 None，不给 0）。

    ⚠ **这些数字在标定集上不是链路延迟。**
    标定集的事件时间锚在**固定基准** `BASE_DT`（2026-10-19 02:00 +08:00），
    于是「分析时刻 − 事件时间」量到的是
    **标定集锚点到本次运行时刻的年龄**，与真实管道延迟无关。
    这里报它只有一个目的：**证明这条指标真的被算出来了**。
    真实延迟必须从生产流量测（§9.27 登记为待验证项）。
    """
    vals = [r.get("detection_latency_seconds") for r in rows]
    ok = [float(v) for v in vals if v is not None]
    out = {
        "measured": len(ok),
        "unavailable": len(vals) - len(ok),
        "min_seconds": min(ok) if ok else None,
        "max_seconds": max(ok) if ok else None,
        "median_seconds": round(statistics.median(ok), 3) if ok else None,
        "ingest_measured": sum(
            1 for r in rows if r.get("ingest_latency_seconds") is not None),
        "_note": "标定集用固定时间锚点，这些数字是「锚点年龄」而非真实链路延迟；"
                 "真实延迟必须从生产流量测。",
    }
    return out


def _assert_reimplementation_matches(rows: list) -> None:
    """阈值扫描用的判定复刻必须与真检测器逐条一致。

    真判定是 ``anomaly_score > ANOMALY_SCORE_THRESHOLD or sigma > 3``，
    这里用同一组字段复刻；任何一条不一致就说明复刻走样了，
    扫出来的阈值区间不可信。
    """
    for r in rows:
        reimpl = (r["anomaly_score"] is not None
                  and r["anomaly_score"] > ANOMALY_SCORE_THRESHOLD) \
            or (r["deviation_sigma"] > 3.0)
        if reimpl != bool(r["is_anomaly"]):
            raise AssertionError(
                f"异常检测判定复刻不一致：{r['id']} "
                f"score={r['anomaly_score']} sigma={r['deviation_sigma']} "
                f"真实现={r['is_anomaly']} 复刻={reimpl}")


def sweep_anomaly_threshold(rows: list, step: float = 0.05) -> dict:
    """扫描 anomaly 判定阈值，给出可接受的区间与当前值的落点。

    ## 为什么必须同时给「网格区间」和「精确上界」

    网格扫描给出的是**在网格上完美**的阈值集合。真正约束人的是
    「最低的那条应检出得分」——设它为 ``m``，可行区间其实是 ``[0, m)``。
    网格只会报出**小于 m 的最后一个网格点**，于是报告里写着
    「区间 = [0.0, 0.4]」而实际 ``m = 0.4357``。

    这不是小数点的问题，是**决策依据被量化了**：
    照着「≤0.4」去调阈值，会比必要值多降 0.0357，
    而多降的部分直接变成额外的误报面。
    这与整改方案 §十 批评变种聚类的
    「`round(sim,3)` 把 0.4996 显示成 0.500，隐藏实际阈值差异」是同一类缺陷，
    只是这次发生在**报告自己的结论依据**上。

    另一个容易漏掉的分支：正样本还可能被 ``sigma > 3`` 命中，
    那条对阈值不敏感（任何 t 都算命中），**不构成上界**。
    """
    _assert_reimplementation_matches(rows)
    grid = [round(x * step, 4) for x in range(int(1 / step) + 1)]
    scored = [r for r in rows if r["known_gap"] is None]
    perfect = []
    for t in grid:
        ok = True
        for r in scored:
            hit = (r["anomaly_score"] is not None and r["anomaly_score"] > t) \
                or (r["deviation_sigma"] > 3.0)
            want = (r["expect"] == "detected")
            if want and not hit:
                ok = False
                break
        if ok:
            perfect.append(t)

    # 精确上界：只由「必须靠分数命中」的应检出样本决定（sigma 命中的不构成约束）
    binding = [
        r["anomaly_score"] for r in scored
        if r["expect"] == "detected"
        and r["anomaly_score"] is not None
        and not (r["deviation_sigma"] > 3.0)
    ]
    exact_sup = min(binding) if binding else None

    # ── 完整约束：负类与「不可判」类也参与判定（整改报告 §9.60）────
    #
    # 修复前本函数**只**检查「不漏掉应检出样本」，于是 `exact_upper_bound`
    # 只是一个**召回下界**；而工具的渲染把它印成「精确**可行**区间」，
    # 报告 §4.4 / §6.2 / 待决项 18 / §9.28.2 又照着这个区间给行动项。
    #
    # 实测（2026-10-20，标定集 8 条）：「结构性不可判」那两条得分
    # 0.4957 / 0.4357 **高于**那个上界 → 任何 t < 0.4357 的阈值都会把
    # 「全新源 IP」判成 detected。于是：
    #   · 负类下界   = 0.1714（阈值必须 ≥ 它，否则已知正常样本变误报）
    #   · 不可判下界 = 0.4957（阈值低于它 ⇒ 不可判样本被报成 detected）
    #   · 完整可行区间 = [0.4957, 0.4357) —— **空集**
    # 也就是说：**没有任何阈值**能同时满足三条 ⇒ 缺口不是阈值问题。
    #
    # ⚠ 下界是**约束**不是**判决**：「不可判样本是否可以被报成 detected」
    # 取决于冷启动规则的设计（待决项 41）。这里只把两侧的数算出来，
    # 让「可行区间为空」这件事**在工具输出里可见**，而不是只写在报告里。
    neg_scores = [
        r["anomaly_score"] for r in scored
        if r["expect"] == "not_detected" and r["anomaly_score"] is not None
    ]
    inc_scores = [
        r["anomaly_score"] for r in scored
        if r["expect"] == "inconclusive" and r["anomaly_score"] is not None
    ]
    fp_lower = max(neg_scores) if neg_scores else None
    inc_lower = max(inc_scores) if inc_scores else None
    lower_candidates = [x for x in (fp_lower, inc_lower) if x is not None]
    complete_lower = max(lower_candidates) if lower_candidates else None
    complete_feasible = (
        exact_sup is None or complete_lower is None
        or complete_lower < exact_sup)

    # 逐档体检：每个候选阈值下，标定集有哪几条与标注不一致。
    # 「有没有一个阈值能让标定集完全自洽」这个问题，只有这张表能回答。
    mismatch_table = []
    for t in grid:
        missed, false_pos, flipped = [], [], []
        for r in scored:
            hit = (r["anomaly_score"] is not None and r["anomaly_score"] > t) \
                or (r["deviation_sigma"] > 3.0)
            if r["expect"] == "detected" and not hit:
                missed.append(r["id"])
            elif r["expect"] == "not_detected" and hit:
                false_pos.append(r["id"])
            elif r["expect"] == "inconclusive" and hit:
                flipped.append(r["id"])
        mismatch_table.append({
            "threshold": t,
            "missed_positives": missed,
            "false_positives": false_pos,
            "inconclusive_reported_detected": flipped,
            "n_mismatch": len(missed) + len(false_pos) + len(flipped),
        })
    feasible_thresholds = [
        e["threshold"] for e in mismatch_table if e["n_mismatch"] == 0]

    return {
        "step": step,
        "current": ANOMALY_SCORE_THRESHOLD,
        "perfect_thresholds": perfect,
        "grid_upper": perfect[-1] if perfect else None,
        "exact_upper_bound": exact_sup,       # 区间右端是**开**的：t < exact_sup
        "current_is_perfect": any(
            abs(t - ANOMALY_SCORE_THRESHOLD) < 1e-9 for t in perfect),
        "false_positive_lower_bound": fp_lower,
        "inconclusive_lower_bound": inc_lower,
        "complete_lower_bound": complete_lower,
        "complete_feasible": complete_feasible,
        "complete_feasible_interval": (
            [complete_lower, exact_sup]
            if complete_feasible and complete_lower is not None
            and exact_sup is not None else None),
        "feasible_thresholds": feasible_thresholds,
        "threshold_mismatch_table": mismatch_table,
        "note": ("exact_upper_bound 只是**召回下界**（只约束「不漏掉应检出样本」）；"
                 "完整可行区间还要满足负类不被误报、不可判类不被翻成 "
                 "detected —— 见 complete_lower_bound / complete_feasible。"
                 "同一份标定集上 complete_feasible=False ⇒ 缺口不是阈值问题。"),
    }


# ══════════════════════════════════════════════════════════════
# 关联引擎
# ══════════════════════════════════════════════════════════════

def run_correlation() -> list:
    eng = CorrelationEngine()
    out = []
    for c in correlation_cases():
        # `only_pattern` 用例只在指定模式上判定：同一段序列在不同模式上
        # 结论可以不同（约束不同），混在一起评会让标注歧义变成假 MISS。
        keys = ([c["only_pattern"]] if c.get("only_pattern")
                else list(ATTACK_CHAIN_PATTERNS))
        best = None
        rejects: dict = {}
        for pk in keys:
            pat = ATTACK_CHAIN_PATTERNS[pk]
            ch = eng._match_pattern(pk, pat, "10.60.0.1",
                                    c["events"], rejects=rejects)
            if ch is None:
                continue
            if best is None or len(ch.events) > len(best.events) \
                    or (len(ch.events) == len(best.events)
                        and ch.partial and not best.partial):
                best = ch
        out.append({
            "id": c["id"], "expect": c["expect"], "note": c["note"],
            "only_pattern": c.get("only_pattern"),
            "got_positive": best is not None,
            "pattern": best.pattern_name if best else "",
            "matched_steps": list(best.matched_steps) if best else [],
            "skipped_steps": list(best.skipped_steps) if best else [],
            "partial": bool(best.partial) if best else None,
            "time_span": best.time_span_minutes if best else None,
        })
    return out


# ══════════════════════════════════════════════════════════════
# 误报率 vs 基准率
# ══════════════════════════════════════════════════════════════

def precision_by_prevalence(rows: list, pred_label: str,
                            prevalences=(0.5, 0.1, 0.01, 0.001)) -> dict:
    """精确率随攻击占比（基准率）的变化。

    ## 这里有一个容易搞错、而且第一版就写错了的地方

    **误报率 FPR = FP/(FP+TN) 与基准率无关**，这是它的定义决定的
    （分子分母都只在良性类内部）。把良性样本按 1:1 / 1:9 / 1:99 注入，
    FPR 一个字都不会变 —— 第一版实现就是这样，三档输出完全相同，
    却顶着「误报率随基准率变化」的标题，属于用真结论的壳包装假问题。

    真正随基准率变化的是**精确率 PPV = TP/(TP+FP)**：基准率越低，
    良性基数越大，那几条误报在分母里的占比越高，精确率越低。
    生产环境里攻击占比通常远低于 1%，所以**只报标定集上的精确率
    会系统性高估**。

    本函数用真实的 TP/FP 计数，在给定基准率下解析地重算精确率，
    不靠复制样本凑数（复制不会改变 FPR，只会稀释精确率的口径）。

    ⚠️ 混淆矩阵**委托给 :func:`_binary`**，不自己数。第一版这里写的是
    ``r["expect"] != pred_label``，那会把 ``suspicious``（待聚合候选）
    一并当成阴性，于是候选既混进 TN 抬高特异度、又在有命中时混进 FP。
    与 :func:`_binary` 的排除规则脱节，同一份报告里两个总分的分母
    就不一样了 —— 这是最难被发现的一类口径漂移。
    """
    m = _binary(rows, pred_label)
    tp, fp, tn, fn = m["tp"], m["fp"], m["tn"], m["fn"]

    recall = m["recall"]
    fpr = m["false_positive_rate"]
    fnr = m["false_negative_rate"]
    spec = tn / (fp + tn) if (fp + tn) else None

    out = {
        "confusion": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "recall": recall,
        # 关键结论：这两个量与基准率无关，是检测器的**类条件**属性
        "false_positive_rate": fpr,
        "specificity": spec,
        # 每千条**良性**事件里的误报数（与基准率无关）
        "false_positives_per_1k_benign": (fpr * 1000) if fpr is not None else None,
        "by_prevalence": {},
        "_note": ("FPR/specificity 与基准率无关（定义使然）；"
                  "随基准率变化的是 precision / NPV"),
    }
    for prev in prevalences:
        if not (0 < prev < 1):
            continue
        p_pos, p_neg = prev, 1.0 - prev
        d_ppv = recall * p_pos + fpr * p_neg
        # NPV 的分母用**漏报率**而不是误报率 —— 第一版误用了 FPR，
        # 算出 NPV > 1 这种不可能的值。
        d_npv = spec * p_neg + fnr * p_pos
        out["by_prevalence"][f"{prev:.3f}"] = {
            "prevalence": prev,
            "precision": (recall * p_pos / d_ppv) if d_ppv else None,
            "negative_predictive_value": (spec * p_neg / d_npv) if d_npv else None,
            # 整改方案 §四：「每千条事件误报量 —— 直观衡量实际运营负担」。
            # 分母是**摄入的全部事件**：良性事件里有 (1-p) 比例，
            # 其中 FPR 那一部分会被误报 → 每千条摄入事件的误报数。
            # 注意这与 FPR 不同：FPR 的分母只在良性类内部，与基准率无关。
            "false_positives_per_1k": (1000 * p_neg * fpr) if fpr is not None else None,
        }
    out["by_prevalence"]["current_ppv"] = _binary(rows, pred_label)["precision"]
    return out


# ══════════════════════════════════════════════════════════════
# 报告
# ══════════════════════════════════════════════════════════════

def _f(v, nd=3):
    return "  n/a" if v is None else f"{v:.{nd}f}"


def _block(title, m, labels=("malicious", "benign"), pos="malicious"):
    L = [f"-- {title} " + "-" * max(0, 66 - len(title))]
    L.append(f"  TP={m['tp']}  FP={m['fp']}  TN={m['tn']}  FN={m['fn']}")
    L.append(f"  Precision={_f(m['precision'])}  Recall={_f(m['recall'])}  "
             f"F1={_f(m['f1'])}")
    L.append(f"  误报率(FP/(FP+TN))={_f(m['false_positive_rate'])}  "
             f"漏报率(FN/(FN+TP))={_f(m['false_negative_rate'])}  "
             f"准确率={_f(m['accuracy'])}")
    return L


def render(sigma_rows, anomaly_rows, corr_rows, sigma_bd, sweep) -> str:
    L = ["=" * 78, "检测引擎量化评估报告（标定集，非生产数据）", "=" * 78, ""]

    L.append("【Sigma】" + "-" * 66)
    L.append(f"{'case':12} {'expect':10} {'kind':16} {'hit':5} {'partial':8} "
             f"{'severity':9} {'actions':16} types")
    for r in sigma_rows:
        mark = "OK " if (r["got_positive"] == (r["expect"] == "malicious")) else "MISS"
        L.append(f"{r['id']:12} {r['expect']:10} {r['evidence_kind']:16} "
                 f"{mark:5} {str(r['partial_only']):8} "
                 f"{(r['severity'] or '-'):9} {(','.join(r['actions']) or '-'):16} "
                 f"{','.join(r['attack_types'])}")
    part = [r for r in sigma_rows if r["partial_only"]]
    if part:
        L.append("")
        L.append(f"  待聚合（partial_only，不计入 P/R）{len(part)} 条：")
        for r in part:
            L.append(f"    {r['id']:12} status={r['status']:10} "
                     f"pending={','.join(r['pending_aggregation'])}")
    L.append("")
    L.extend(_block("Sigma 总体", _binary(sigma_rows, "malicious")))
    L.append("")
    L.append("  按证据来源拆分（真值为恶意的两类才算 TP）：")
    for kind, m in sigma_bd["by_evidence_kind"].items():
        tag = "恶意" if m["expect_malicious"] else "良性"
        L.append(f"    {kind:16} n={m['n']:<3} 真值={tag}  "
                 f"TP={m['tp']:<3} FP={m['fp']:<3} "
                 f"Precision={_f(m['precision'])} Recall={_f(m['recall'])}")
        if m["miss_ids"]:
            L.append(f"      漏报: {', '.join(m['miss_ids'])}")
        if m["false_alarm_ids"]:
            L.append(f"      误报: {', '.join(m['false_alarm_ids'])}")
        if m.get("candidate_ids"):
            L.append(f"      候选(待聚合，既非漏报也非误报): "
                     f"{', '.join(m['candidate_ids'])}")
    L.append(f"  raw_indicator 命中率（Sigma 自身增量检出）= "
             f"{_f(sigma_bd['raw_indicator_hit_rate'])}")
    L.append(f"  {sigma_bd['true_hits']} 个真阳性中，来自原始指标的 = "
             f"{_f(sigma_bd['raw_indicator_share_of_tp'])}")
    L.append(f"  {sigma_bd['true_hits']} 个真阳性中，仅复述上游分类器的 = "
             f"{_f(sigma_bd['upstream_echo_share'])}")
    L.append(f"  另有良性误报 {sigma_bd['benign_false_alarms']} 条"
             "（不计入上面的真阳性占比）")
    L.append("  → raw_indicator 才是 Sigma 自身的增量检出能力；"
             "event_type_only 测的是上游分类器。")
    L.append("")
    prev = precision_by_prevalence(sigma_rows, "malicious")
    L.append("  误报率 / 特异度（**与基准率无关**，是类条件属性）：")
    L.append(f"    FPR={_f(prev['false_positive_rate'])}  "
             f"Recall={_f(prev['recall'])}  Specificity={_f(prev['specificity'])}")
    L.append("  精确率随攻击占比变化（这才是随基准率变的量）：")
    L.append(f"    {'基准率':>8} {'Precision':>10} {'NPV':>10} {'每千条误报':>12}")
    for k, v in prev["by_prevalence"].items():
        if k == "current_ppv":
            continue
        L.append(f"    {v['prevalence']:>8.1%} {_f(v['precision']):>10} "
                 f"{_f(v['negative_predictive_value']):>10} "
                 f"{_f(v.get('false_positives_per_1k'), 1):>12}")
    L.append(f"    标定集实测 PPV={_f(prev['by_prevalence']['current_ppv'])}")
    L.append("    ⚠ 标定集恶意占比远高于生产，只报实测 PPV 会系统性高估。")
    if prev["confusion"]["fp"] == 0:
        L.append("    ⚠ 本标定集 FP=0，所以各基准率下 Precision 同为 1.000 ——")
        L.append("      这是**样本集没有误报**的性质，不是「生产环境精确率不随")
        L.append("      基准率下降」。生产上只要出现哪怕 1 条误报，低基准率下")
        L.append("      精确率就会立刻塌下来；该结论必须用真实流量重测。")

    L.append("")
    L.append("【异常检测】" + "-" * 62)
    L.append(f"{'case':12} {'expect':14} {'status':14} {'score':>7} {'anom':6} dims")
    for r in anomaly_rows:
        mark = "OK " if (r["status"] == r["expect"]) else "MISS"
        L.append(f"{r['id']:12} {r['expect']:14} {r['status']:14} "
                 f"{r['anomaly_score']:>7.4f} {str(r['is_anomaly']):6} {mark} "
                 f"{','.join(r['inconclusive_dimensions'])}")
    L.append("")
    lat = latency_summary(anomaly_rows)
    L.append(f"  检测延迟（事件时间→分析时刻）：{lat['measured']} 条可算，"
             f"{lat['unavailable']} 条不可算")
    if lat["measured"]:
        L.append(f"    实测 min={_f(lat['min_seconds'])}s "
                 f"中位={_f(lat['median_seconds'])}s "
                 f"max={_f(lat['max_seconds'])}s")
    L.append("    ⚠ 这些数字**不是链路延迟**：标定集的事件时间锚在固定基准")
    L.append("      2026-10-19 02:00 (+08:00)，量到的是**锚点到本次运行的年龄**。")
    L.append("      这里报它只为证明这条指标**真的被算出来了**；")
    L.append("      真实延迟必须从生产流量测（§9.27 登记为待验证）。")
    L.append("")
    cs = cold_start_breakdown(anomaly_rows)
    L.append("  按基线是否成立分档（§七 要求「按新实体、成熟实体…分别报告」）：")
    L.append(f"    成熟实体（基线 ≥ {cs['cold_start_min_samples']} 样本）"
             f"：{cs['mature']['n']} 条，检出 {cs['mature']['detected']}，"
             f"不可判 {cs['mature']['inconclusive']}，"
             f"阴性 {cs['mature']['not_detected']}")
    L.append(f"    新实体 / 冷启动（基线 < {cs['cold_start_min_samples']} 样本）"
             f"：{cs['fresh']['n']} 条，检出 {cs['fresh']['detected']}，"
             f"不可判 {cs['fresh']['inconclusive']}，"
             f"阴性 {cs['fresh']['not_detected']}")
    if cs["fresh_structurally_blind"]:
        L.append(f"    ⚠ 新实体档出现「判成 not_detected」："
                 f"{cs['fresh_structurally_blind']} —— "
                 f"那是**结构性失明**（把没证据当成阴性），不是一般漏报")
    else:
        L.append("    ✅ 新实体档没有出现「判成 not_detected」——"
                 "新 IP 不会被系统性当成阴性（它们判 inconclusive）")
    L.append("    ⚠ 「不同部署规模」「不同时间窗口」两档**未覆盖**（§9.27 登记为待补）")
    L.append("")
    pos_rows = [r for r in anomaly_rows if r["expect"] == "detected"]
    L.append(f"  召回（应检出 {len(pos_rows)} 条，实际 "
             f"{sum(1 for r in pos_rows if r['is_anomaly'])} 条）")
    inc = [r for r in anomaly_rows if r["status"] == "inconclusive"]
    L.append(f"  判为 inconclusive 的有 {len(inc)} 条 —— "
             "这些**不计入**阴性，是结构性不可判，不是漏报也不是误报")
    L.append("")
    L.append(f"  阈值扫描：当前 ANOMALY_SCORE_THRESHOLD = {sweep['current']}")
    L.append(f"    召回下界 = [0, {sweep['exact_upper_bound']})"
             f"   ← 只约束「不漏掉应检出样本」，**不是**可行区间")
    L.append(f"    负类下界   = {_f(sweep.get('false_positive_lower_bound'), 4)}"
             f"   ← 阈值必须 ≥ 它，否则已知正常样本变误报")
    L.append(f"    不可判下界 = {_f(sweep.get('inconclusive_lower_bound'), 4)}"
             f"   ← 阈值低于它，「结构性不可判」的样本会被报成 detected")
    if sweep.get("complete_feasible"):
        L.append(f"    完整可行区间 = [{_f(sweep.get('complete_lower_bound'), 4)}, "
                 f"{_f(sweep.get('exact_upper_bound'), 4)})"
                 f"   ← 正样本全检出 ∧ 负类不误报 ∧ 不可判类不翻转")
    else:
        L.append(f"    ⚠ 完整可行区间 = **空集**"
                 f"（下界 {_f(sweep.get('complete_lower_bound'), 4)} ≥ "
                 f"上界 {_f(sweep.get('exact_upper_bound'), 4)}）—— "
                 f"**没有任何阈值**能同时满足三条约束 ⇒ 缺口不是阈值问题")
    L.append(f"    网格(步长 {sweep['step']})上「只按召回」完美落点 = "
             f"{sweep['perfect_thresholds'][:1]} ~ "
             f"{sweep['perfect_thresholds'][-1:]}")
    if sweep["exact_upper_bound"] is not None and sweep["grid_upper"] is not None:
        gap = sweep["exact_upper_bound"] - sweep["grid_upper"]
        if gap > 1e-9:
            L.append(f"    ⚠ 网格上界 {sweep['grid_upper']} 比精确上界低 "
                     f"{gap:.4f} —— 照网格值调阈值会多降这么多，"
                     f"多出来的部分直接变成额外误报面")
    L.append(f"    当前值落在网格区间内 = {sweep['current_is_perfect']}")
    L.append(f"    注：{sweep['note']}")

    L.append("")
    L.append("【关联引擎】" + "-" * 62)
    L.append(f"{'case':12} {'expect':10} {'hit':5} {'partial':8} {'span':>7} pattern")
    for r in corr_rows:
        mark = "OK " if (r["got_positive"] == (r["expect"] == "chain")) else "MISS"
        L.append(f"{r['id']:12} {r['expect']:10} {mark:5} "
                 f"{str(r['partial']):8} {_f(r['time_span'],1):>7} {r['pattern']}")
    L.append("")
    L.extend(_block("关联引擎总体",
                    _binary(corr_rows, "chain", negative_label="no_chain"),
                    pos="chain"))

    L.append("")
    L.append("【结论边界】" + "-" * 62)
    L.append("  · 本数据集是**合成标定集**，用于比较实现与标注的一致性，")
    L.append("    不代表生产流量分布。绝对误报率/召回率不可外推。")
    L.append("  · 真实检测能力仍需生产黄金样本 + 真实流量基线复测。")
    L.append("")
    return "\n".join(L)


def dataset_info() -> dict:
    """数据集版本 + 内容哈希，保证报告可追溯到具体用例文件。"""
    files = ["detection_cases.py"]
    h = hashlib.sha256()
    for name in files:
        p = Path(__file__).parent / name
        h.update(p.read_bytes())
    return {
        "version": "synthetic-calibration-2026-10-21",
        "kind": "synthetic",
        "files": files,
        "sha256": h.hexdigest(),
    }


def main(argv: list | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    info = dataset_info()
    sigma_rows = run_sigma()
    anomaly_rows = run_anomaly()
    corr_rows = run_correlation()
    sigma_bd = sigma_breakdown(sigma_rows)
    sweep = sweep_anomaly_threshold(anomaly_rows)
    if "--json" in argv:
        print(json.dumps({
            "dataset": info,
            "sigma": {"rows": sigma_rows, "breakdown": sigma_bd,
                      "overall": _binary(sigma_rows, "malicious"),
                      "prevalence": precision_by_prevalence(
                          sigma_rows, "malicious")},
            "anomaly": {"rows": anomaly_rows,
                        "detected_recall": _binary(
                            anomaly_rows, "detected",
                            negative_label="not_detected"),
                        "sweep": sweep,
                        "latency": latency_summary(anomaly_rows),
                        "cold_start": cold_start_breakdown(anomaly_rows)},
            "correlation": {"rows": corr_rows,
                            "overall": _binary(corr_rows, "chain",
                                               negative_label="no_chain")},
        }, ensure_ascii=False, indent=2, default=str))
    else:
        print(
            f"数据集: {info['version']} ({info['kind']}) "
            f"sha256={info['sha256'][:16]}"
        )
        print(render(sigma_rows, anomaly_rows, corr_rows, sigma_bd, sweep))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
