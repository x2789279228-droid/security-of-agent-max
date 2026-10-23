"""
P3: Grounding 评估流程。

`grounding_verifier.py` 里的六个权重与两个阈值（0.8 / 0.4）在 P3 之前
**从未被任何数据检验过** —— 没有标注集、没有标定脚本、没有测试引用它们。
本模块把那份缺失的证据补上：

  1. 跑 `eval_datasets.grounding_cases.CASES`，产出逐条结果
  2. 混淆矩阵 + 每类 P/R/F1（known_gap 样本单独记账，不混入准确率）
  3. **分离裕度**：干净样本最低分 与 未硬否决样本最高分 之差
  4. **阈值扫描**：扫描全 (grounded_t, partial_t) 组合，找出数据集完全满足的区间
     —— 这就是把「0.8/0.4 看起来合理」变成「数据支持 [x, y]」的地方
  5. **硬否决覆盖率**：多少 ungrounded 样本其实是靠硬否决拦下的，
     而不是靠分数阈值 —— 用于判断阈值现在还剩多少实际作用

⚠️ 关于第 4 项的一个陷阱（必须守住）：
   阈值扫描需要按候选阈值重算档位，如果直接重算，测的就是**这里的重实现**
   而不是 `GroundingVerifier` 本身。所以 `_verdict_for` 这个重实现会被
   强制与真 verifier 在**真阈值**上逐条比对，不一致直接抛错。
   量具自己错了却给出漂亮的标定曲线，是这类工作最容易出的事故。

用法：
    python -m eval_datasets.evaluate_grounding          # 文本报告
    python -m eval_datasets.evaluate_grounding --json   # 机器可读
"""
from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field

from eval_datasets.grounding_cases import CASES, events_for, knowledge_for
from grounding_verifier import (
    _VERDICT_GROUNDED_THRESHOLD,
    _VERDICT_PARTIAL_THRESHOLD,
    grounding_verifier,
)

LABELS = ("grounded", "partially_grounded", "ungrounded")

# 数据集用便于书写的短标签，verifier 发的是真 verdict 串。
# 统一到真值 —— 词表不一致会让混淆矩阵的行列对不上，
# 而且会让「实现返回了什么」这件事在报告里失真。
_EXPECT_ALIAS = {
    "grounded": "grounded",
    "partial": "partially_grounded",
    "ungrounded": "ungrounded",
}


@dataclass
class CaseResult:
    """单条标注样本的评估结果。"""

    case_id: str
    expect: str
    got: str
    score: float
    hard_fail: list[str] = field(default_factory=list)
    known_gap: str | None = None

    @property
    def hit(self) -> bool:
        return self.expect == self.got

    @property
    def counted(self) -> bool:
        """known_gap 样本不计入准确率（它们是「检不出」，不是「判错」）。"""
        return self.known_gap is None


@dataclass
class EvalReport:
    results: list[CaseResult]

    # ── 混淆矩阵 ──
    @property
    def confusion(self) -> dict:
        return {
            want: {
                got: sum(1 for r in self.results if r.expect == want and r.got == got)
                for got in LABELS
            }
            for want in LABELS
        }

    # ── 每类 P/R/F1（只统计计入准确率的样本）──
    @property
    def per_class(self) -> dict:
        scored = [r for r in self.results if r.counted]
        out = {}
        for label in LABELS:
            tp = sum(1 for r in scored if r.expect == label and r.got == label)
            fp = sum(1 for r in scored if r.expect != label and r.got == label)
            fn = sum(1 for r in scored if r.expect == label and r.got != label)
            prec = tp / (tp + fp) if (tp + fp) else None
            rec = tp / (tp + fn) if (tp + fn) else None
            f1 = (
                2 * prec * rec / (prec + rec)
                if prec is not None and rec is not None and (prec + rec)
                else None
            )
            # 整改方案 §十三 验收要求「分别报告各类检测器的 Precision、Recall、
            # **误报率与漏报率**」。这里补上后两个率值 —— 此前只有 P/R/F1。
            #
            # 口径：逐类(one-vs-rest)把当前 label 当正类。
            #   TN = 计入准确率的样本总数 − tp − fp − fn
            #        分母用 `counted`（排除 known_gap），与 accuracy 同一总体 ——
            #        已知检不出的样本既不是误报也不是漏报，混进去会同时虚高
            #        特异度与拉低召回。
            #   FPR = FP / (FP + TN)   —— 「真不是这个类却被判成这个类」
            #   FNR = FN / (FN + TP)   —— 「是这个类却没判出来」= 1 − recall
            tn = len(scored) - tp - fp - fn
            fpr = fp / (fp + tn) if (fp + tn) else None
            fnr = fn / (fn + tp) if (fn + tp) else None
            out[label] = {
                "tp": tp, "fp": fp, "fn": fn, "tn": tn,
                "precision": prec, "recall": rec, "f1": f1,
                "false_positive_rate": fpr, "false_negative_rate": fnr,
            }
        return out

    @property
    def accuracy(self) -> float | None:
        scored = [r for r in self.results if r.counted]
        if not scored:
            return None
        return sum(1 for r in scored if r.hit) / len(scored)

    @property
    def misses(self) -> list:
        return [r for r in self.results if r.counted and not r.hit]

    # ── 分离裕度 ──
    @property
    def separation(self) -> dict:
        """干净样本的最低分，越界样本的最高分。

        两个必须分开的口径：
          · 「有硬否决」的样本分数再高也会被判 ungrounded，混进来会虚高裕度；
          · known_gap 样本是**已知检不出**，不是「判错了」——
            把它算进来会让裕度永久钉在 0，这个指标就再也测不出回归了。
            所以它不进裕度，但在下面单独报出来，信息不丢。
        """
        scored = [r for r in self.results if r.counted]
        clean = [r.score for r in scored if r.expect == "grounded"]
        bad_nohf = [
            r.score
            for r in scored
            if r.expect in ("partially_grounded", "ungrounded") and not r.hard_fail
        ]
        bad_hf = [r.score for r in scored if r.hard_fail]
        gaps = [
            r.score for r in self.results
            if r.known_gap and r.expect in ("partially_grounded", "ungrounded")
        ]
        return {
            "min_grounded": min(clean) if clean else None,
            "max_bad_without_hard_fail": max(bad_nohf) if bad_nohf else None,
            "max_bad_with_hard_fail": max(bad_hf) if bad_hf else None,
            "margin_without_hard_fail": (
                min(clean) - max(bad_nohf) if clean and bad_nohf else None
            ),
            "known_gap_max_score": max(gaps) if gaps else None,
        }

    # ── 硬否决覆盖率 ──
    @property
    def hard_fail_coverage(self) -> dict:
        bad = [r for r in self.results
               if r.expect in ("partially_grounded", "ungrounded") and r.counted]
        caught = [r for r in bad if r.hard_fail]
        return {
            "bad_total": len(bad),
            "caught_by_hard_fail": len(caught),
            "decided_by_threshold_only": len(bad) - len(caught),
        }


# ═══════════════════════════════════════════
# 档位重实现（仅供阈值扫描使用）
# ═══════════════════════════════════════════

def _verdict_for(score: float, hard_fail: list, g_t: float, p_t: float) -> str:
    """按候选阈值重算档位。

    这段逻辑是 grounding_verifier.py:366-374 的等价重写。
    它的可信度由 `_assert_reimplementation_matches` 保证 —— 不一致就抛错。
    """
    if hard_fail:
        return "ungrounded"
    if score >= g_t:
        return "grounded"
    if score >= p_t:
        return "partially_grounded"
    return "ungrounded"


def _assert_reimplementation_matches(report: EvalReport) -> None:
    """强制重实现在真阈值上与真 verifier 逐条一致。

    没有这一步，阈值扫描扫的是这个函数而不是 GroundingVerifier，
    扫出来的「标定曲线」可能是纯粹的自说自话。
    """
    for r in report.results:
        recomputed = _verdict_for(
            r.score, r.hard_fail, _VERDICT_GROUNDED_THRESHOLD, _VERDICT_PARTIAL_THRESHOLD
        )
        if recomputed != r.got:
            raise AssertionError(
                f"档位重实现与真 verifier 不一致：{r.case_id} "
                f"score={r.score} hard_fail={r.hard_fail} "
                f"真实现={r.got} 重实现={recomputed}。"
                f"阈值扫描结果不可信 —— 请先修正 _verdict_for。"
            )


def run_dataset(cases: list | None = None) -> EvalReport:
    """跑标注集，返回完整报告。"""
    results: list[CaseResult] = []
    for case in cases if cases is not None else CASES:
        rep = grounding_verifier.verify_chunk(
            claims=[case["claim"]],
            events=events_for(case),
            knowledge_chunks=knowledge_for(case),
            chunk_id=case["id"],
        ).claims[0]
        results.append(
            CaseResult(
                case_id=case["id"],
                expect=_EXPECT_ALIAS.get(case["expect"], case["expect"]),
                got=rep.verdict,
                score=rep.grounding_score,
                hard_fail=list(rep.hard_fail_reasons or []),
                known_gap=case.get("known_gap"),
            )
        )
    return EvalReport(results)


# ═══════════════════════════════════════════
# 阈值扫描
# ═══════════════════════════════════════════

def sweep_thresholds(
    report: EvalReport, step: float = 0.01, lo: float = 0.0, hi: float = 1.0
) -> dict:
    """扫描全部 (grounded_t, partial_t) 组合，找出数据集完全满足的区间。"""
    _assert_reimplementation_matches(report)

    scored = [r for r in report.results if r.counted]
    n_steps = int(round((hi - lo) / step)) + 1
    grid = [round(lo + i * step, 4) for i in range(n_steps)]

    perfect: list = []
    per_grounded: dict = {}
    for g_t in grid:
        ok = []
        for p_t in grid:
            if p_t > g_t:
                continue  # partial 阈值不可能高于 grounded 阈值
            hits = sum(
                1
                for r in scored
                if _verdict_for(r.score, r.hard_fail, g_t, p_t) == r.expect
            )
            if hits == len(scored):
                ok.append(p_t)
        if ok:
            perfect.append((g_t, min(ok), max(ok)))
            per_grounded[g_t] = (min(ok), max(ok))

    return {
        "step": step,
        "perfect_regions": perfect,
        "current": (_VERDICT_GROUNDED_THRESHOLD, _VERDICT_PARTIAL_THRESHOLD),
        "current_is_perfect": any(
            abs(g - _VERDICT_GROUNDED_THRESHOLD) < 1e-9
            and lo_p - 1e-9 <= _VERDICT_PARTIAL_THRESHOLD <= hi_p + 1e-9
            for g, lo_p, hi_p in perfect
        ),
        # ── 精确边界（由数据决定，与网格无关）──────────────────
        # 判定是 `score >= g_t`：
        #   · 干净样本要留在 grounded → g_t <= min_grounded        （**闭**上界）
        #   · 越界样本不能被当成 grounded → g_t > max_bad_without_hard_fail（**开**下界）
        # 网格只能报出「小于它的最后一个网格点」，于是：
        #   · 上界可能低估（真实 0.8034 → 网格 0.80，余量被说成 0.00）
        #   · 下界可能高估（真实 >0.6 即可 → 网格 0.61，白严 0.01）
        # 而用网格上界做「是否越界」的判断，会在真实上界 0.8034、
        # 当前阈值 0.802 时**误报「已越出数据支持区间」**，进而推动人
        # 不必要地调低阈值。判据必须用精确值。
        "exact_lower_exclusive": report.separation["max_bad_without_hard_fail"],
        "exact_upper_inclusive": report.separation["min_grounded"],
    }


# ═══════════════════════════════════════════
# 报告渲染
# ═══════════════════════════════════════════

def render_report(report: EvalReport, sweep: dict | None = None) -> str:
    L: list[str] = []
    L.append("=" * 78)
    L.append("Grounding 标定评估报告")
    L.append("=" * 78)

    L.append("")
    L.append("── 逐条结果 " + "─" * 60)
    L.append(f"{'case':34} {'expect':10} {'got':10} {'score':>7}  hard_fail")
    for r in report.results:
        flag = "OK " if r.hit else ("GAP" if r.known_gap else "MISS")
        hf = ",".join(x.split(":")[0] for x in r.hard_fail) or "-"
        L.append(f"{r.case_id:34} {r.expect:10} {r.got:10} {r.score:7.4f}  {hf}  [{flag}]")

    L.append("")
    L.append("── 混淆矩阵（行=标注，列=实现）" + "─" * 46)
    cm = report.confusion
    L.append(f"{'':12}" + "".join(f"{c:>12}" for c in LABELS))
    for want in LABELS:
        L.append(f"{want:12}" + "".join(f"{cm[want][got]:>12}" for got in LABELS))

    L.append("")
    L.append("── 每类指标 " + "─" * 62)
    L.append(f"{'class':12} {'TP':>4} {'FP':>4} {'FN':>4} {'precision':>10} {'recall':>8} {'F1':>8}")
    for label, m in report.per_class.items():
        def f(v):
            return "  n/a" if v is None else f"{v:.3f}"
        L.append(f"{label:12} {m['tp']:>4} {m['fp']:>4} {m['fn']:>4} "
                 f"{f(m['precision']):>10} {f(m['recall']):>8} {f(m['f1']):>8}")

    acc = report.accuracy
    L.append("")
    L.append(f"准确率（不含 known_gap）= {'n/a' if acc is None else f'{acc:.4f}'}"
             f"   命中 {sum(1 for r in report.results if r.counted and r.hit)}"
             f"/{sum(1 for r in report.results if r.counted)}")

    gaps = [r for r in report.results if r.known_gap]
    if gaps:
        L.append("")
        L.append("── 已登记的已知缺口（不计入准确率）" + "─" * 40)
        for r in gaps:
            L.append(f"  {r.case_id:34} {r.known_gap}")
            L.append(f"    {'':<34} 实测 {r.got} / score {r.score:.4f}")

    L.append("")
    L.append("── 分离裕度 " + "─" * 62)
    s = report.separation
    def g(v):
        return "n/a" if v is None else f"{v:.4f}"
    L.append(f"  干净样本最低分              = {g(s['min_grounded'])}")
    L.append(f"  未硬否决的越界样本最高分     = {g(s['max_bad_without_hard_fail'])}")
    L.append(f"  → 裕度                      = {g(s['margin_without_hard_fail'])}")
    L.append(f"  （参考）被硬否决样本最高分   = {g(s['max_bad_with_hard_fail'])}"
             "  ← 分数再高也会被硬否决压成 ungrounded")
    if s["known_gap_max_score"] is not None:
        L.append(f"  （参考）known_gap 样本最高分 = {g(s['known_gap_max_score'])}"
                 "  ← 不计入裕度，否则裕度恒为 0、失去回归检测能力")

    L.append("")
    L.append("── 硬否决 vs 阈值：谁在真正做决定 " + "─" * 38)
    c = report.hard_fail_coverage
    L.append(f"  应判非 grounded 的样本     = {c['bad_total']}")
    L.append(f"  其中被硬否决拦下           = {c['caught_by_hard_fail']}")
    L.append(f"  仅靠分数阈值判定           = {c['decided_by_threshold_only']}")

    if sweep is not None:
        L.append("")
        L.append("── 阈值扫描（数据集完全满足的区间）" + "─" * 40)
        cur_g, cur_p = sweep["current"]
        L.append(f"  当前阈值 grounded≥{cur_g} / partial≥{cur_p}")
        L.append(f"  当前阈值落在完全满足区间内  = {sweep['current_is_perfect']}")
        regions = sweep["perfect_regions"]
        if not regions:
            L.append("  ★ 没有任何阈值组合能让本数据集全对 —— 需先修实现")
            L.append("    （这说明问题不在标定：重调阈值救不了结构性缺陷）")
        else:
            gs = [r[0] for r in regions]
            p_hi = max(r[2] for r in regions)
            exact_lo = sweep.get("exact_lower_exclusive")
            exact_hi = sweep.get("exact_upper_inclusive")
            if exact_hi is not None and exact_lo is not None:
                L.append(f"  精确可行区间 = ({exact_lo:.4f}, {exact_hi:.4f}]"
                         f"   ← 下端**开**（越界样本不得被当成 grounded）、"
                         f"上端**闭**（干净样本要留在 grounded）")
                L.append(f"  ★ 当前 grounded={cur_g} 距精确上界 {exact_hi:.4f} "
                         f"还有 {exact_hi - cur_g:.4f} 余量")
            L.append(f"  网格(步长 {sweep['step']})上完美落点 = "
                     f"[{min(gs):.2f}, {max(gs):.2f}]"
                     f"   ← 网格量化值，边界以精确值为准")
            L.append(f"  在该区间内 partial 阈值上界      = {p_hi:.2f}"
                     f"（网格值）")
            if exact_hi is not None and cur_g > exact_hi + 1e-9:
                L.append("  ★★ 当前阈值已越出数据支持区间 —— 提高阈值会开始误杀干净断言")
            elif exact_lo is not None and cur_g <= exact_lo + 1e-9:
                L.append("  ★★ 当前阈值已低于数据支持下界 —— 越界样本会被当成 grounded")
            if exact_hi is not None and max(gs) is not None \
                    and abs(max(gs) - exact_hi) > 1e-9:
                L.append(f"  ⚠ 网格上界 {max(gs):.2f} 与精确上界 {exact_hi:.4f} 不一致 "
                         f"（差 {exact_hi - max(gs):+.4f}）—— 以精确值为准")
            if exact_lo is not None and min(gs) is not None \
                    and abs(min(gs) - exact_lo) > 1e-9:
                L.append(f"  ⚠ 网格下界 {min(gs):.2f} 与精确下界 {exact_lo:.4f} 不一致"
                         f"（差 {min(gs) - exact_lo:+.4f}）—— 网格比真实约束更严")
            if cur_p > p_hi:
                L.append("  ★★ 当前 partial 阈值高于数据支持上界 —— 会把可溯源部分误判为无溯源")

    if report.misses:
        L.append("")
        L.append("── 未命中 " + "─" * 64)
        for r in report.misses:
            L.append(f"  {r.case_id}: 标注 {r.expect}，实现 {r.got} (score={r.score:.4f})")

    L.append("")
    return "\n".join(L)


def main(argv: list | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    report = run_dataset()
    sweep = sweep_thresholds(report)

    if "--json" in argv:
        print(json.dumps(
            {
                "results": [r.__dict__ for r in report.results],
                "confusion": report.confusion,
                "per_class": report.per_class,
                "accuracy": report.accuracy,
                "separation": report.separation,
                "hard_fail_coverage": report.hard_fail_coverage,
                "sweep": {
                    "perfect_regions": sweep["perfect_regions"],
                    "current": sweep["current"],
                    "current_is_perfect": sweep["current_is_perfect"],
                },
            },
            ensure_ascii=False, indent=2, default=str,
        ))
    else:
        print(render_report(report, sweep))

    return 0 if not report.misses else 1


if __name__ == "__main__":
    raise SystemExit(main())
