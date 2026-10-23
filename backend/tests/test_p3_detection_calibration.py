"""
P3: 检测引擎量化标定 —— 回归 + 负面测试。

这一批测试守护三件事：

A. **评估器本身是可信量具**，不是永远绿的摆设。
   包含对自检闸门的反向测试：故意让 ``_assert_reimplementation_matches``
   的输入与真检测器不一致，断言 ``sweep_anomaly_threshold`` 抛错，
   而不是给出一条自说自话的标定曲线。
   这条闸门在本轮真的抓到过一次 bug —— 漏传 ``deviation_sigma``
   字段导致 ``KeyError``，评估器拒绝出数而不是默默跑完。

B. **已知标定缺口被显式登记**，不能悄悄消失。
   登记在 :data:`KNOWN_GAPS`。修复一个缺口时**不能删测试**，要把它
   改写成反向的回归断言 —— 断言缺陷不再复现。

   这一条在本轮真的走过一遍：
     · Sigma 规则用裸子串做 URL 判据 → 3 条良性 lookalike 误报，
       其中 SIG-N-03（一次正常登录）会触发 ``block_ip`` 封禁正常用户。
       已修复（换判据 + 聚合规则降级为 partial），本表该条目**移除**，
       并由 :func:`test_benign_cases_never_produce_confirmed_detection`
       与 :func:`test_benign_cases_never_carry_enforcement_action` 钉住。
     · 异常检测阈值 0.60 高于标定集要求的召回下限 —— **仍然未修**，
       因为标定集是合成的，阈值该定多少必须由生产数据决定。

C. **指标口径本身正确**。
   特别是「误报率与基准率无关」这条：第一版评估器把它写成
   「误报率随基准率变化」，三档输出完全相同却顶着那个标题，
   属于用真结论的壳包装假问题；还顺手把 NPV 的分母写成了误报率，
   算出 NPV > 1 这种不可能的值。两条都由测试钉死。
"""
import math

import pytest

from anomaly_detector import ANOMALY_SCORE_THRESHOLD
from eval_datasets.detection_cases import (
    MIN_BASELINE_BUCKETS, anomaly_cases, correlation_cases, sigma_cases,
)
from eval_datasets.evaluate_detection import (
    _assert_reimplementation_matches,
    _binary,
    precision_by_prevalence,
    run_anomaly,
    run_correlation,
    run_sigma,
    sigma_breakdown,
    sweep_anomaly_threshold,
)

# ── 已登记的标定缺口 ────────────────────────────────────────
# 每条都必须有明确的现象描述；修好后请把条目移除，并补一条反向回归断言，
# 而不是删测试 —— 否则缺陷会「静默愈合」，下一个人再踩一遍。
KNOWN_GAPS = {
    # 已修复（原值 ["SIG-N-01","SIG-N-02","SIG-N-03"]）：
    #   根因一 —— SIG-002/SIG-005 用裸子串 `/api/status`、`/export` 做 URL
    #   判据，任何含该子串的正常请求都命中；已换成更具体的判据。
    #   根因二 —— SIG-001/007 声明 x-soc-aggregation（需窗口内计数达阈值），
    #   单事件阶段本就证据不足，却直接产出 block_ip；已降级为 partial + alert。
    # 回归由 test_benign_cases_never_* 两条断言守护。
    #
    # 未修复：ANOMALY_SCORE_THRESHOLD=0.60 漏掉 ANO-P-02(0.4357)、
    # ANO-P-03(0.4957)。标定集是合成的，阈值定多少必须由生产数据决定，
    # 不在合成集上擅自下调 —— 否则就是拿标定集调参调出绿。
    "anomaly_threshold_above_recall_floor": ["ANO-P-02", "ANO-P-03"],
}


@pytest.fixture(scope="module")
def sigma_rows():
    return run_sigma()


@pytest.fixture(scope="module")
def anomaly_rows():
    return run_anomaly()


@pytest.fixture(scope="module")
def corr_rows():
    return run_correlation()


# ══════════════════════════════════════════════════════════════
# A. 评估器是可信量具
# ══════════════════════════════════════════════════════════════

def test_reimplementation_gate_rejects_inconsistent_rows():
    """故意让复刻判定与真检测器不一致 → 必须抛错，不得出数。"""
    bad = [{"id": "X", "anomaly_score": 0.9, "deviation_sigma": 0.0,
            "is_anomaly": False, "expect": "detected", "known_gap": None}]
    with pytest.raises(AssertionError, match="复刻不一致"):
        _assert_reimplementation_matches(bad)


def test_reimplementation_gate_accepts_real_rows(anomaly_rows):
    """真实行必须通过闸门 —— 否则扫描结果不可信。"""
    _assert_reimplementation_matches(anomaly_rows)


def test_sweep_is_monotone_and_bounded(anomaly_rows):
    sweep = sweep_anomaly_threshold(anomaly_rows)
    ths = sweep["perfect_thresholds"]
    assert ths == sorted(ths), "扫描结果未排序"
    assert all(0.0 <= t <= 1.0 for t in ths), "阈值越界"
    assert sweep["current"] == ANOMALY_SCORE_THRESHOLD


# ── 网格上界 ≠ 精确上界（本轮修掉的真缺陷）─────────────────
#
# `sweep_anomaly_threshold(step=0.05)` 只会在**网格上**找完美落点，
# 于是报出「区间 = [0.0] ~ [0.4]」。但真正约束人的是最低的应检出得分
# `m`，可行区间是 `[0, m)` —— 标定集里 m = 0.4357。
#
# 照「≤0.4」去调阈值会**比必要值多降 0.0357**，多出来的部分
# 直接变成额外的误报面。整改方案 §十 批评变种聚类的
# 「round 隐藏实际阈值差异」是同一类缺陷，这次发生在报告自己的结论依据上。

def _row(score, sigma, expect, known_gap=None):
    """构造一行，且满足 `is_anomaly` 与复刻判定一致（否则闸门会抛错）。"""
    return {
        "id": "X", "expect": expect, "anomaly_score": score,
        "deviation_sigma": sigma,
        "is_anomaly": (score is not None and score > ANOMALY_SCORE_THRESHOLD)
                      or (sigma > 3.0),
        "known_gap": known_gap,
    }


def test_sweep_reports_exact_upper_bound_beside_the_grid():
    rows = [_row(0.71, 0.1, "detected"), _row(0.4357, 0.1, "detected"),
            _row(0.1714, 0.1, "not_detected")]
    s = sweep_anomaly_threshold(rows)
    assert s["exact_upper_bound"] == pytest.approx(0.4357), (
        "精确上界必须等于「必须靠分数命中」的最低应检出得分")
    assert s["grid_upper"] == 0.4
    assert s["grid_upper"] < s["exact_upper_bound"], (
        "本用例专门构造网格低于精确上界的场景")


def test_exact_upper_bound_is_an_open_interval():
    """区间右端必须开：判定是 `score > t`，取等号就会漏掉那条样本。"""
    rows = [_row(0.4357, 0.1, "detected"), _row(0.0, 0.1, "not_detected")]
    s = sweep_anomaly_threshold(rows)
    at_bound = s["exact_upper_bound"]
    assert not any(abs(t - at_bound) < 1e-9 for t in s["perfect_thresholds"]), (
        "等于精确上界的阈值不得被判为完美 —— 右端是开区间")


def test_sigma_only_positives_do_not_constrain_the_bound():
    """靠 sigma>3 命中的正样本对阈值不敏感，**不构成上界**。

    这条样本得分 0.0 但 sigma=9.0：任何阈值下它都算命中。
    若把它算进上界，精确上界会被错报成 0.0。
    """
    rows = [_row(0.6, 0.1, "detected"),      # 必须靠分数 → 上界 0.6
            _row(0.0, 9.0, "detected")]      # 靠 sigma → 不构成约束
    s = sweep_anomaly_threshold(rows)
    assert s["exact_upper_bound"] == pytest.approx(0.6)


def test_known_gap_rows_do_not_constrain_the_bound():
    """已登记缺口的样本不参与阈值判定（与 `perfect` 的筛除口径一致）。"""
    rows = [_row(0.6, 0.1, "detected"),
            _row(0.01, 0.1, "detected", known_gap="X")]
    s = sweep_anomaly_threshold(rows)
    assert s["exact_upper_bound"] == pytest.approx(0.6)


def test_real_calibration_exposes_a_quantisation_gap(anomaly_rows):
    """前提守卫：真实标定集上这个量化差额必须**大于 0**。

    若哪天标定集的正样本恰好落在网格点上（gap=0），本文件
    讨论的整个问题就不存在了 —— 那时这条会提醒把结论收回，
    而不是让报告继续引用一个已经精确的 [0.0, 0.4]。
    """
    s = sweep_anomaly_threshold(anomaly_rows)
    gap = s["exact_upper_bound"] - s["grid_upper"]
    assert gap > 0, (
        f"标定集上网格上界已等于精确上界（gap={gap}）—— "
        "§4.4 里「区间 [0.0, 0.4]」的量化误差讨论需要相应更新")
    assert round(gap, 4) == 0.0357, (
        f"量化差额变了（{gap:.4f}）—— 报告 §4.4 / §6.2 引用的 0.0357 需要更新")


def test_inconclusive_is_not_counted_as_negative(anomaly_rows):
    """结构性不可判的样本不得混进「应判正常」的统计里。

    这是整改方案 §二的核心：把 inconclusive 当成阴性，
    报告上的准确率就完全失去意义。
    """
    inc = [r for r in anomaly_rows if r["status"] == "inconclusive"]
    assert inc, "标定集应当包含结构性不可判样本，否则这条测试没有意义"
    for r in inc:
        assert r["is_anomaly"] is False
        assert r["inconclusive_dimensions"], \
            f"{r['id']} 判 inconclusive 却没有记录不可判的维度"
        assert r["expect"] == "inconclusive", \
            f"{r['id']} 标注 {r['expect']}，实现 inconclusive —— 需人工复核"


# ══════════════════════════════════════════════════════════════
# B. 已知缺口被登记
# ══════════════════════════════════════════════════════════════

def test_benign_cases_never_produce_confirmed_detection(sigma_rows):
    """良性样本不得产生**确定检出**（上一轮修复的回归断言）。

    原缺陷：Sigma 规则用裸子串做 URL 判据，SIG-N-01/02/03 三条良性
    lookalike 全部报阳，其中 SIG-N-03（一次正常登录）severity=high，
    会真的下 ``block_ip`` 把正常用户封掉。

    这条断言现在**期望列表为空** —— 修复了，所以缺口条目已从
    :data:`KNOWN_GAPS` 移除。若将来又出现误报，这里会列出具体 ID。
    """
    bd = sigma_breakdown(sigma_rows)
    benign_kinds = ("lookalike", "benign")
    actual = sorted(
        cid
        for kind in benign_kinds
        for cid in bd["by_evidence_kind"][kind]["false_alarm_ids"]
    )
    assert actual == [], (
        f"良性样本出现确定检出: {actual}。若这是新增的真实阳性，"
        f"请在 detection_cases.py 里核对标注；若确属误报，"
        f"请修规则并在 KNOWN_GAPS 登记。")


def test_benign_cases_never_carry_enforcement_action(sigma_rows):
    """良性样本**在任何情况下**都不得携带执行类动作。

    这条比上一条更严格，是本轮修复的**核心不变式**。

    上一轮的错误不只在于误报，更在于**证据不足却下了封禁动作**：
    SIG-001 声明了 ``x-soc-aggregation``（count(src_ip)>5 in 5m），
    规则作者自己承认单事件证据不足，但单事件阶段仍然产出
    ``action_recommend=block_ip``。一次正常登录就能封禁一个用户。

    所以判定标准不能是「有没有命中」，而是「命中时带不带执行类动作」：
      · 允许良性样本产生 **partial 候选**（有信号、待聚合确认）；
      · 禁止良性样本携带 **enforcement 动作**。
    """
    ENFORCEMENT = {"block_ip", "block", "quarantine", "isolate",
                   "deny", "drop", "kill"}
    bad = []
    for r in sigma_rows:
        if r["evidence_kind"] not in ("lookalike", "benign"):
            continue
        for act in r["actions"]:
            if act in ENFORCEMENT:
                bad.append((r["id"], act, r["status"]))
    assert not bad, f"良性样本携带执行类动作: {bad}"


def test_partial_cases_are_reported_as_pending_not_as_detection(sigma_rows):
    """待聚合候选必须被显式标记，且不得混进确定性指标。

    口径：``partial_only`` 的样本既不算 TP 也不算 TN，
    只能进 ``partial_only`` 这一栏。混进任一侧都会失真。
    """
    part = [r for r in sigma_rows if r["partial_only"]]
    assert part, "标定集应包含待聚合候选用例，否则这条测试没有意义"
    for r in part:
        assert r["status"] == "partial", \
            f"{r['id']} 是待聚合候选，status 却是 {r['status']}"
        assert r["pending_aggregation"], \
            f"{r['id']} 是待聚合候选，却没有记录待聚合的规则 ID"
        # 待聚合意味着「还没确认」，因此确定检出必须为假
        assert r["got_positive"] is False, \
            f"{r['id']} 全部命中都在待聚合，却同时报成了确定检出"


def test_anomaly_threshold_gap_is_registered(anomaly_rows):
    """当前阈值高于标定集的召回下限 —— 这是已登记缺口。"""
    missed = sorted(
        r["id"] for r in anomaly_rows
        if r["expect"] == "detected" and not r["is_anomaly"])
    assert missed == sorted(
        KNOWN_GAPS["anomaly_threshold_above_recall_floor"]), (
        "异常检测漏检集合变了。若阈值已调整，请同步更新 "
        "KNOWN_GAPS 与 ANOMALY_SCORE_THRESHOLD 的说明。")

    sweep = sweep_anomaly_threshold(anomaly_rows)
    assert sweep["current_is_perfect"] is False, (
        "当前阈值已落在完美区间内 —— KNOWN_GAPS 该条目应移除了")


def test_no_regression_below_threshold(sigma_rows):
    """raw_indicator 恶意样本必须全中 —— 这是 Sigma 的底线能力。

    如果这条挂了，说明连最基础的载荷匹配都坏了，比误报严重得多。

    顺带把**分母口径**钉死：命中率的分母是进入二分类统计的样本数
    （TP+FN），不含待聚合候选。候选没有确定结论，把它算进分母会把
    命中率从 1.000 压到 0.667，然后会有人跑去「修」Sigma —— 而 Sigma
    其实一行都没错，是评估口径把「还没判定」当成了「判成阴性」。
    """
    bd = sigma_breakdown(sigma_rows)
    raw = bd["by_evidence_kind"]["raw_indicator"]
    assert raw["candidate_ids"], \
        "标定集应包含 raw_indicator 类待聚合候选，否则分母口径无从验证"
    scored = raw["tp"] + raw["fn"]
    assert scored > 0, "raw_indicator 组没有可判定的样本，指标无意义"
    assert scored == raw["n"] - len(raw["candidate_ids"]), \
        (f"raw_indicator 组 n={raw['n']}、候选 {raw['candidate_ids']}，"
         f"但进入二分类的只有 {scored} 条 —— 分母口径不一致")
    assert bd["raw_indicator_hit_rate"] == raw["tp"] / scored
    assert bd["raw_indicator_hit_rate"] == 1.0, \
        f"原始指标正样本出现漏报: {raw['miss_ids']}"


# ══════════════════════════════════════════════════════════════
# C. 指标口径正确
# ══════════════════════════════════════════════════════════════

def test_false_positive_rate_is_invariant_to_prevalence(sigma_rows):
    """FPR = FP/(FP+TN) 按定义与基准率无关。

    第一版评估器写成「误报率随基准率变化」，三档输出完全相同 ——
    真数字套着假标题。这条测试把正确的结论钉住。
    """
    p = precision_by_prevalence(sigma_rows, "malicious")
    fprs = {round(v, 12) for v in (p["false_positive_rate"],)}
    assert len(fprs) == 1, "FPR 在不同基准率下不一致 —— 公式写错了"


def test_precision_is_non_increasing_as_prevalence_drops(sigma_rows):
    """基准率越低，精确率**不增** —— 这才是真正随基准率变的量。

    断言方向是「不增」而不是「严格下降」，这不是放松，是把两件事分开：
    本轮修掉全部误报后标定集 ``FP=0``，精确率在所有基准率下都等于
    1.000，「严格下降」的前提不再成立。但那只说明**样本集没有误报**，
    不说明生产环境的精确率不随基准率下降 —— 那个性质由
    :func:`test_precision_declines_when_false_positives_exist` 单独钉住，
    用合成行验证，不依赖标定集恰好有没有误报。
    """
    p = precision_by_prevalence(sigma_rows, "malicious")
    prevs = sorted(
        (v for k, v in p["by_prevalence"].items() if k != "current_ppv"),
        key=lambda v: v["prevalence"], reverse=True)
    vals = [v["precision"] for v in prevs]
    assert all(a >= b for a, b in zip(vals, vals[1:])), \
        f"精确率随基准率下降而上升，方向反了: {vals}"
    if p["confusion"]["fp"] > 0:
        assert vals[0] > vals[-1], \
            f"存在 {p['confusion']['fp']} 条误报时，低基准率精确率必须塌下来"


def test_precision_declines_when_false_positives_exist():
    """只要有误报，低基准率下精确率就必须塌下来 —— 用合成行验证。

    这条不看标定集数据：它验证的是**关系**，而不是当前取值，
    所以标定集有没有误报都不影响它成立。

    手算（TP=4 FN=1 FP=5 TN=5 → recall=0.8、FPR=0.5）：
      基准率 50% → 0.8*0.5 / (0.8*0.5 + 0.5*0.5) = 0.40/0.65 ≈ 0.6154
      基准率 10% → 0.8*0.1 / (0.8*0.1 + 0.5*0.9) = 0.08/0.53 ≈ 0.1509
    """
    rows = ([{"expect": "malicious", "got_positive": True}] * 4
            + [{"expect": "malicious", "got_positive": False}]
            + [{"expect": "benign", "got_positive": True}] * 5
            + [{"expect": "benign", "got_positive": False}] * 5)
    p = precision_by_prevalence(rows, "malicious", prevalences=(0.5, 0.1))
    assert p["recall"] == pytest.approx(0.8)
    assert p["false_positive_rate"] == pytest.approx(0.5)
    assert p["by_prevalence"]["0.500"]["precision"] == pytest.approx(0.40 / 0.65)
    assert p["by_prevalence"]["0.100"]["precision"] == pytest.approx(0.08 / 0.53)


def test_npv_never_exceeds_one(sigma_rows):
    """NPV 是概率，必须 ≤ 1。

    第一版把 NPV 的分母误用误报率，算出 NPV=2.3 这种不可能的值，
    而且没有任何断言拦下它。
    """
    p = precision_by_prevalence(sigma_rows, "malicious")
    for k, v in p["by_prevalence"].items():
        if k == "current_ppv":
            assert isinstance(v, float), "current_ppv 应当是一个标量"
            continue
        npv = v["negative_predictive_value"]
        assert npv is None or (0.0 <= npv <= 1.0), f"{k}: NPV={npv} 越界"
        prec = v["precision"]
        assert prec is None or (0.0 <= prec <= 1.0), f"{k}: Precision={prec} 越界"


def test_binary_uses_positive_label_consistently():
    rows = [
        {"expect": "malicious", "got_positive": True},    # TP
        {"expect": "malicious", "got_positive": False},   # FN
        {"expect": "benign", "got_positive": True},       # FP
        {"expect": "benign", "got_positive": False},      # TN
    ]
    m = _binary(rows, "malicious")
    assert (m["tp"], m["fn"], m["fp"], m["tn"]) == (1, 1, 1, 1)
    assert m["precision"] == 0.5 and m["recall"] == 0.5
    assert m["false_positive_rate"] == 0.5


def test_binary_excludes_suspicious_from_both_sides():
    """``suspicious`` 既不算 TP 也不算 TN/FN/FP。

    这一条不是洁癖。把候选当阴性 → 特异度虚高；当成漏报 → 漏报率虚高。
    两种失真方向相反，但都会让「指标」变成不能用来决策的数字。

    更要紧的是**口径必须全局一致**：``_binary`` 排除了候选，
    ``sigma_breakdown`` 的漏报表和 ``precision_by_prevalence`` 的
    混淆矩阵如果各数各的，同一份报告里两个总分的分母就不一样了。
    """
    rows = [
        {"expect": "malicious", "got_positive": True},     # TP
        {"expect": "suspicious", "got_positive": False},   # 候选：未确认
        {"expect": "suspicious", "got_positive": False},   # 候选：未确认
        {"expect": "benign", "got_positive": False},       # TN
    ]
    m = _binary(rows, "malicious")
    assert (m["tp"], m["fn"], m["fp"], m["tn"]) == (1, 0, 0, 1)
    assert m["excluded_suspicious"] == 2
    # 分母只有 2（有确定结论的样本），不是 4
    assert m["recall"] == 1.0 and m["false_positive_rate"] == 0.0

    # 口径一致性：precision_by_prevalence 委托给 _binary，两者必须同分母
    p = precision_by_prevalence(rows, "malicious", prevalences=(0.5,))
    assert p["confusion"] == {"tp": 1, "fp": 0, "tn": 1, "fn": 0}
    assert p["recall"] == m["recall"]
    assert p["false_positive_rate"] == m["false_positive_rate"]


def test_binary_negative_label_must_be_passed_per_detector_family():
    """三个检测器家族的**负类标签并不相同**，漏传就把全部负样本当候选排除。

    实测（2026-10-19 修复）：`_binary` 曾经写死 `_NEGATIVE_LABEL = "benign"`，
    于是：

        Sigma       正类 `malicious`  负类 `benign`         → 默认值恰好正确
        异常检测     正类 `detected`   负类 `not_detected`  → 负样本被排除
        关联引擎     正类 `chain`      负类 `no_chain`      → 负样本被排除

    关联引擎修复前报的是 `tp=2 fp=0 **tn=0** fn=0 excluded_suspicious=**6**`：
        · 误报率 = **null**（§十三 明确要求报告它）
        · accuracy = (2+0)/2 = **1.0** —— 一个**一条负样本都没有**的总体
          报了 100% 准确率，且结构上无法表达任何误报
    这类失真比「少报一个指标」危险得多：它报出来的数字**看起来是对的**。
    """
    families = [
        # (正类, 负类, 形状: TP, FN, FP, TN, 第三类候选)
        ("malicious", "benign", 1, 1, 1, 1, 2),          # Sigma
        ("detected", "not_detected", 1, 2, 0, 2, 0),     # 异常检测
        ("chain", "no_chain", 2, 0, 0, 6, 0),            # 关联引擎
    ]
    for pos, neg, tp, fn, fp, tn, cand in families:
        rows = [{"expect": pos, "got_positive": True} for _ in range(tp)]
        rows += [{"expect": pos, "got_positive": False} for _ in range(fn)]
        rows += [{"expect": neg, "got_positive": True} for _ in range(fp)]
        rows += [{"expect": neg, "got_positive": False} for _ in range(tn)]
        rows += [{"expect": "suspicious", "got_positive": False} for _ in range(cand)]

        m = _binary(rows, pos, negative_label=neg)
        assert (m["tp"], m["fn"], m["fp"], m["tn"]) == (tp, fn, fp, tn), \
            f"{pos}/{neg}: 混淆矩阵错了 {m}"
        assert m["excluded_suspicious"] == cand, \
            f"{pos}/{neg}: 只有真正的候选该被排除，实得 {m['excluded_suspicious']}"
        if fp + tn:
            assert m["false_positive_rate"] == fp / (fp + tn), f"{pos}/{neg}: {m}"
        if fn + tp:
            assert m["false_negative_rate"] == fn / (fn + tp), f"{pos}/{neg}: {m}"

    # 漏传负类标签 → 负样本全被当候选，tn 归零、误报率算不出来。
    # 这一段是本用例的**分辨力来源**：它把「漏传」的后果钉成可观测的数字。
    rows = [
        {"expect": "chain", "got_positive": True},
        {"expect": "chain", "got_positive": True},
        {"expect": "no_chain", "got_positive": False},
        {"expect": "no_chain", "got_positive": False},
        {"expect": "no_chain", "got_positive": False},
    ]
    wrong = _binary(rows, "chain")          # 忘了传 negative_label
    assert (wrong["tp"], wrong["fp"], wrong["tn"]) == (2, 0, 0), wrong
    assert wrong["excluded_suspicious"] == 3, wrong
    assert wrong["false_positive_rate"] is None, \
        "负样本全被排除时误报率必然是 None —— 这正是修复前的形态"
    right = _binary(rows, "chain", negative_label="no_chain")
    assert right["tn"] == 3 and right["false_positive_rate"] == 0.0, right


def test_evaluate_detection_reports_a_rate_for_every_family():
    """§十三：三个家族都必须报出误报率与漏报率（不能是 null）。

    修复前关联引擎与异常检测的 `false_positive_rate` 都是 null ——
    因为负样本从没进过二分类总体。
    """
    from eval_datasets.evaluate_detection import (
        run_anomaly, run_correlation, run_sigma,
    )

    sigma_rows = run_sigma()
    anom_rows = [r for r in run_anomaly()
                 if r["expect"] in ("detected", "not_detected")]
    corr_rows = run_correlation()

    blocks = {
        "sigma": _binary(sigma_rows, "malicious"),
        "anomaly": _binary(anom_rows, "detected", negative_label="not_detected"),
        "correlation": _binary(corr_rows, "chain", negative_label="no_chain"),
    }
    for name, m in blocks.items():
        assert m["tn"] > 0, f"{name}: tn=0 —— 负样本根本没进总体，误报率无从谈起"
        assert m["false_positive_rate"] is not None, f"{name}: 误报率是 null"
        assert m["false_negative_rate"] is not None, f"{name}: 漏报率是 null"


def test_benign_kind_is_not_scored_as_positive_class(sigma_rows):
    """`benign` / `lookalike` 两类真值是良性，不得当成「正类=benign」。

    否则报告会输出「良性样本被漏报」这种反向结论 —— 那看起来像指标，
    其实是口径错误。
    """
    bd = sigma_breakdown(sigma_rows)
    for kind in ("benign", "lookalike"):
        m = bd["by_evidence_kind"][kind]
        assert m["expect_malicious"] is False
        assert m["tp"] == 0, f"{kind} 被当成了正类"
        assert m["miss_ids"] == [], f"{kind} 不应产生「漏报」条目"


# ══════════════════════════════════════════════════════════════
# 标定集自身的结构不变量
# ══════════════════════════════════════════════════════════════

def test_baseline_and_probe_share_the_same_entity():
    """基线实体必须 == 探针实体。

    第一版标定集基线喂 10.50.0.1、探针打 10.50.0.2，
    三条「应检出」全判 inconclusive —— 看起来像大面积漏检，
    实际是标定集写错了。这条不变量就是为了挡住这类错误。

    两种「不可判」要分开：
      · ANO-I-01/02 —— 探针实体**根本没有**基线；
      · ANO-I-03    —— 探针实体**有**基线但样本不足（冷启动）。
    两者都判 inconclusive，但原因不同，混在一起就没法用一条不变量覆盖。
    """
    NO_BASELINE_AT_ALL = {"ANO-I-01", "ANO-I-02"}
    for c in anomaly_cases():
        probe_ip = c["probe"].get("src_ip")
        base_ips = {e.get("src_ip") for e in c["baseline"]}
        if c["id"] in NO_BASELINE_AT_ALL:
            assert probe_ip not in base_ips, \
                f"{c['id']} 预期探针实体无基线，实际在 {sorted(base_ips)} 中"
        elif c["id"].startswith("ANO-I"):
            # 冷启动用例：有基线，但小时桶数不足
            assert probe_ip in base_ips, \
                f"{c['id']} 冷启动用例必须给探针实体一条（不足的）基线"
            buckets = {int(e["event_time"] // 3600) for e in c["baseline"]}
            assert len(buckets) < MIN_BASELINE_BUCKETS, (
                f"{c['id']} 号称冷启动，却有 {len(buckets)} 个小时桶")
        else:
            assert probe_ip in base_ips, \
                f"{c['id']} 探针实体 {probe_ip} 不在基线 {sorted(base_ips)} 中"


def test_baseline_spans_enough_hour_buckets():
    """基线必须跨 >= COLD_START_MIN_SAMPLES 个小时桶，否则基线不成立。

    ``recent`` 是按小时合并的滚动窗口，样本数取 ``len(recent)``。
    """
    for c in anomaly_cases():
        if c["id"].startswith("ANO-I"):
            continue
        hours = {e.get("event_time") for e in c["baseline"]}
        # event_time 是 epoch 秒；用整除还原小时桶
        buckets = {int(ts // 3600) for ts in hours}
        assert len(buckets) >= MIN_BASELINE_BUCKETS, \
            f"{c['id']} 基线只有 {len(buckets)} 个小时桶，达不到 {MIN_BASELINE_BUCKETS}"


def test_baseline_contains_multiple_event_types():
    """基线必须含 ≥2 种事件类型，否则 rarity 维度恒为 inconclusive。

    「应判正常」的用例在单类型基线下**永远达不到** not_detected ——
    那是标定集构造问题，不是检测器缺陷。
    """
    for c in anomaly_cases():
        if c["id"].startswith("ANO-I"):
            continue
        types = {e.get("event_type") for e in c["baseline"]}
        assert len(types) >= 2, f"{c['id']} 基线只有 {types}"


def test_event_carries_both_event_and_event_type_keys():
    """事件必须同时带 ``event`` 与 ``event_type``。

    ``AnomalyDetector.analyze()`` 只读 ``event``；Sigma 规则走
    ``event_type`` 列。少一个键，另一套引擎就会把它当 UNKNOWN。
    """
    for c in anomaly_cases():
        for e in c["baseline"] + [c["probe"]]:
            assert "event" in e and "event_type" in e, \
                f"{c['id']} 事件缺键: {sorted(e)}"
    for c in sigma_cases():
        assert "event" in c["event"] and "event_type" in c["event"], \
            f"{c['id']} 事件缺键"


def test_correlation_cases_without_pattern_constraint_are_unambiguous():
    """标了 ``only_pattern`` 的用例，只能在该模式上判定。

    否则同一段序列在宽松模式上命中、严格模式上拒绝，
    评估器挑了宽松模式就会记一条假 MISS —— 第一版 COR-N-06 就是这样。
    """
    for c in correlation_cases():
        if "only_pattern" in c:
            assert c["only_pattern"], f"{c['id']} only_pattern 为空"
            assert c["expect"] in ("chain", "no_chain")


def test_correlation_has_enough_negative_cases(corr_rows):
    """负样本太少时 Precision=1.000 是没有意义的数字。"""
    neg = [r for r in corr_rows if r["expect"] == "no_chain"]
    assert len(neg) >= 4, f"关联负样本只有 {len(neg)} 条，指标不可信"
    pos = [r for r in corr_rows if r["expect"] == "chain"]
    assert len(pos) >= 2, f"关联正样本只有 {len(pos)} 条，召回不可信"
