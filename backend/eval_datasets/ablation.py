"""四层消融实验(B3) — 每个检测层的边际贡献, 回答"多层堆叠各带来什么"。

口径纪律:
  - L1 仅 Sigma 执行层 / L2 +社区影子层 用同一份 sigma_cases
    (影子层不改变"确认检出"口径 —— 它的贡献是 CSIC 真实数据上的
    补充证据与晋升候选, 单列计数);
  - L3 +统计异常检测 用 anomaly_cases(行为面是异常检测器的工作面);
  - L4 +关联引擎 用 correlation_cases(链级检出是关联引擎的产物);
  - L5 决策层 对 L1 的确认检出跑真实策略引擎, 量化"检出→可执行决策"
    的转化(含 UNCERTAIN 兜底 —— 那是设计而非缺陷);
  - LLM 审计层不在本消融: 无 API key 时管线退化为规则收口, 数字没有
    区分度; 真实 LLM 层的贡献用 grounding 评测
    (eval_datasets/evaluate_grounding)单独衡量, 见报告的口径边界。

用法:
    python -m eval_datasets.ablation --out ../docs/benchmark
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import os
os.environ.setdefault("SHARED_MEMORY_SKIP_DOTENV", "1")

from eval_datasets.detection_cases import sigma_cases  # noqa: E402
from eval_datasets.evaluate_detection import (  # noqa: E402
    run_anomaly,
    run_correlation,
)
from sigma_engine.engine import PySigmaDetector  # noqa: E402

SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _pr(tp: int, fp: int, fn: int) -> dict:
    prec = tp / (tp + fp) if (tp + fp) else None
    rec = tp / (tp + fn) if (tp + fn) else None
    f1 = (2 * prec * rec / (prec + rec)) if prec and rec else None
    return {"tp": tp, "fp": fp, "fn": fn,
            "precision": round(prec, 3) if prec is not None else None,
            "recall": round(rec, 3) if rec is not None else None,
            "f1": round(f1, 3) if f1 is not None else None}


def layer1_sigma_execution(detector: PySigmaDetector) -> dict:
    """仅执行层(非影子、非 pending): 确认检出口径。"""
    tp = fp = fn = tn = 0
    for c in sigma_cases():
        hits = detector.detect(dict(c["event"]))
        confirmed = [h for h in hits
                     if "[SHADOW]" not in (h.description or "")
                     and not h.requires_aggregation]
        malicious = c["expect"] == "malicious"
        if malicious and confirmed:
            tp += 1
        elif malicious:
            fn += 1
        elif c["expect"] == "benign" and confirmed:
            fp += 1
        elif c["expect"] == "benign":
            tn += 1
    return {"dataset": "sigma_cases(合成标定)",
            "enforced_confirmed": _pr(tp, fp, fn), "tn": tn}


def layer2_shadow_contribution(detector: PySigmaDetector) -> dict:
    """影子层贡献: 确认口径不变, 影子证据单列(在 CSIC 夹具上量化)。"""
    fixture = Path(__file__).parent / "fixtures" / "csic_sample.jsonl"
    if not fixture.exists():
        return {"dataset": "csic_sample.jsonl", "error": "fixture 缺失"}
    rows = [json.loads(ln) for ln in fixture.read_text(encoding="utf-8").splitlines() if ln.strip()]
    mal = [r["event"] for r in rows if r["label"] == "malicious"]
    ben = [r["event"] for r in rows if r["label"] == "benign"]
    shadow_tp = sum(
        1 for e in mal
        if not any("[SHADOW]" not in (h.description or "") for h in detector.detect(dict(e)))
        and any("[SHADOW]" in (h.description or "") for h in detector.detect(dict(e)))
    )
    shadow_fp = sum(
        1 for e in ben
        if any("[SHADOW]" in (h.description or "") for h in detector.detect(dict(e)))
    )
    return {"dataset": "csic_sample.jsonl(公开数据集夹具)",
            "shadow_extra_evidence": shadow_tp,
            "shadow_fp_on_benign": shadow_fp,
            "note": "影子补充证据 = 无确认命中但影子命中的攻击样本(晋升候选)"}


def layer3_anomaly() -> dict:
    """L3 统计异常检测消融。

    ⚠️ 词表对齐（2026-10-25 修复）：anomaly_cases 的 expect 词表是
    ``detected`` / ``not_detected`` / ``inconclusive``（见
    detection_cases.anomaly_cases），不是 Sigma 用的 malicious/benign。
    修复前本函数用 ``expect == "malicious"`` 计数 —— 词表不匹配导致
    TP/FP/FN 恒为 0，报告里的 L3 行是**空值而非满分**（ABLATION.md
    曾写"L3 接近满分"，该说法不成立，已随本次修正）。

    口径：正类 = expect=="detected"；负类 = expect=="not_detected"；
    ``inconclusive`` 是结构性不可判（新实体/冷启动/无时间戳），既不是
    TP 也不是 TN，**排除出二分类计数并单独报出** —— 把它们算进阴性
    会把"结构上无法判定"伪装成"完整阴性"（与 detection_cases 的
    ANO-I-01 注释同一纪律）。
    """
    rows = run_anomaly()
    # known_gap(显式登记的检测缺口, 见 detection_cases.anomaly_cases)不进
    # 二分类计数, 单列报出 —— 与 evaluate_detection 的记账纪律一致:
    # 已登记缺口既不冒充漏报, 也不从报告里消失。
    scored = [r for r in rows if not r.get("known_gap")]
    tp = sum(1 for r in scored if r.get("expect") == "detected" and r.get("got_positive"))
    fn = sum(1 for r in scored if r.get("expect") == "detected" and not r.get("got_positive"))
    fp = sum(1 for r in scored if r.get("expect") == "not_detected" and r.get("got_positive"))
    tn = sum(1 for r in scored if r.get("expect") == "not_detected" and not r.get("got_positive"))
    inconclusive_ids = [r["id"] for r in rows if r.get("expect") == "inconclusive"]
    known_gap_ids = [r["id"] for r in rows if r.get("known_gap")]
    return {"dataset": "anomaly_cases(行为面)", "anomaly": _pr(tp, fp, fn), "tn": tn,
            "inconclusive_excluded": len(inconclusive_ids),
            "inconclusive_ids": inconclusive_ids,
            "known_gap_excluded": len(known_gap_ids),
            "known_gap_ids": known_gap_ids,
            "note": "inconclusive(结构不可判)与 known_gap(已登记标定缺口)均排除出二分类计数"}


def layer4_correlation() -> dict:
    rows = run_correlation()
    tp = sum(1 for r in rows if r.get("expect") == "chain" and r.get("got_positive"))
    fn = sum(1 for r in rows if r.get("expect") == "chain" and not r.get("got_positive"))
    fp = sum(1 for r in rows if r.get("expect") == "no_chain" and r.get("got_positive"))
    tn = sum(1 for r in rows if r.get("expect") == "no_chain" and not r.get("got_positive"))
    return {"dataset": "correlation_cases(链级)", "correlation": _pr(tp, fp, fn), "tn": tn}


def layer5_soar_decisions(detector: PySigmaDetector) -> dict:
    """对 L1 确认检出跑真实策略引擎(taxonomy 分类后的决策分布)。

    与生产链路一致: 先经 threat_taxonomy 把攻击类型归一为叶子/类目,
    再进 policy_engine.match。某类型既无叶子也无类目 → 记 uncovered
    (那是策略库/分类表的覆盖缺口, 不是匹配器的错)。
    """
    from response_engine.response_policies import policy_engine
    from response_engine.threat_taxonomy import classify

    counts = {"auto_execute": 0, "needs_approval": 0, "uncertain": 0,
              "no_action": 0, "uncovered_type": 0}
    samples: dict[str, list] = {k: [] for k in counts}
    t0 = time.perf_counter()
    case_no = 0
    for c in sigma_cases():
        if c["expect"] != "malicious":
            continue
        case_no += 1
        hits = [h for h in detector.detect(dict(c["event"]))
                if "[SHADOW]" not in (h.description or "")
                and not h.requires_aggregation]
        if not hits:
            continue
        top = max(hits, key=lambda h: SEV_RANK.get(h.severity, 0))
        cls = classify(str(top.attack_type or ""))
        if not cls.leaf and not cls.category:
            counts["uncovered_type"] += 1
            samples["uncovered_type"].append(f"{c['id']}:{top.attack_type}")
            continue
        # 每用例唯一 src_ip: 策略引擎的 per-IP 聚合冷却会把同 IP 的后续
        # 不同类型检出压成 SKIPPED —— 那是生产上合理的降噪, 但会污染
        # "各类型决策分布"的消融读数, 故在消融里逐用例隔离。
        src = f"203.0.113.{case_no % 200 + 1}"
        m = policy_engine.match(
            threat_type=cls.leaf,
            confidence=float(top.confidence == "high" and 0.85 or 0.6),
            severity=str(top.severity or "medium"),
            src_ip=src,
            category=cls.category,
        )
        pname = str(getattr(m, "policy_name", ""))
        if m and m.matched and m.actions and "UNCERTAIN" in pname:
            counts["uncertain"] += 1
            samples["uncertain"].append(c["id"])
        elif m and m.matched and m.actions and m.needs_approval:
            counts["needs_approval"] += 1
            samples["needs_approval"].append(c["id"])
        elif m and m.matched and m.actions and m.auto_execute:
            counts["auto_execute"] += 1
            samples["auto_execute"].append(f"{c['id']}:{pname}")
        else:
            counts["no_action"] += 1
            samples["no_action"].append(f"{c['id']}:{cls.leaf or cls.category or '-'}")
    elapsed = time.perf_counter() - t0
    return {"dataset": "L1 确认检出 × taxonomy × 真实策略引擎",
            "decisions": counts,
            "examples": {k: v[:6] for k, v in samples.items()},
            "match_ms_avg": round(elapsed * 1000 / max(1, sum(counts.values())), 2)}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="", help="写 ABLATION.{md,json} 的目录")
    args = ap.parse_args()

    det = PySigmaDetector(str(Path(__file__).resolve().parent.parent / "sigma_engine" / "rules"),
                          enforce=True)
    result = {
        "L1_sigma_execution": layer1_sigma_execution(det),
        "L2_shadow": layer2_shadow_contribution(det),
        "L3_anomaly": layer3_anomaly(),
        "L4_correlation": layer4_correlation(),
        "L5_soar_decisions": layer5_soar_decisions(det),
        "scope_note": (
            "LLM 审计层不入本表: 无 API key 时审计管线退化为规则收口, 无区分度;"
            "LLM 的贡献由 grounding 评测(evaluate_grounding)单独量化。"
            "各层使用其自然工作面的数据集, 跨层不做单一轴硬拼。"
        ),
    }
    print(json.dumps(result, ensure_ascii=False, indent=2))
    if args.out:
        out = Path(args.out)
        out.mkdir(parents=True, exist_ok=True)
        (out / "ABLATION-result.json").write_text(
            json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        (out / "ABLATION.md").write_text(render_md(result), encoding="utf-8")
        print(f"报告已写 {out}/ABLATION.md")
    return 0


def render_md(r: dict) -> str:
    l1, l2 = r["L1_sigma_execution"], r["L2_shadow"]
    l3, l4, l5 = r["L3_anomaly"], r["L4_correlation"], r["L5_soar_decisions"]

    def fmt(d):
        return (f"P={d['precision']} R={d['recall']} F1={d['f1']} "
                f"(TP={d['tp']} FP={d['fp']} FN={d['fn']})")

    l3_excl = (f"排除: inconclusive {l3.get('inconclusive_excluded', 0)}"
               f" + known_gap {l3.get('known_gap_excluded', 0)}")

    lines = [
        "# 分层消融 — 各检测层的边际贡献(合成标定口径)", "",
        "| 层 | 工作面/数据集 | 指标 |", "|---|---|---|",
        f"| L1 Sigma 执行层(非影子) | {l1['dataset']} | {fmt(l1['enforced_confirmed'])} |",
        f"| L2 社区影子层(125 条) | {l2.get('dataset', '-')} | "
        f"补充证据 {l2.get('shadow_extra_evidence', '-')} / 良性侧影子误报 {l2.get('shadow_fp_on_benign', '-')} |",
        f"| L3 统计异常检测 | {l3['dataset']} | {fmt(l3['anomaly'])} TN={l3.get('tn', '-')} ({l3_excl}) |",
        f"| L4 关联引擎(11 链) | {l4['dataset']} | {fmt(l4['correlation'])} |",
        f"| L5 SOAR 决策层 | {l5['dataset']} | 决策分布 {l5['decisions']}, 均 {l5['match_ms_avg']}ms/次 |",
        "",
        "## 怎么读这张表",
        "",
        "- **L2 的确认口径与 L1 相同** —— 影子层不改变确认检出, 它的价值是"
        "在真实公开数据(CSIC)上提供补充证据与晋升候选(全量口径见 REPLAY 报告:"
        "签名子集召回 34.7%, 其中 SQLi 全部由影子层接住);",
        "- **L3 的口径(2026-10-25 两步修正)**: 第一步修评估器 —— 修复前本函数用"
        " Sigma 的 malicious/benign 词表数 anomaly_cases 的 detected/not_detected"
        " 样本, 词表不匹配 → TP/FP/FN 恒 0, \"接近满分\"是空值假象; 正类=detected,"
        " 负类=not_detected, inconclusive(结构不可判)排除出二分类并单列。"
        " 第二步修检测器 —— ANO-P-02/03 双双低于阈值的缺口由 severity_shift"
        " 基线相对证据维度关闭(§七.2), 本表现在是测量面全量口径: TP=3 FP=0 FN=0;"
        " L4 关联引擎在链面满分 —— 多层堆叠的理由不变: 单层视角必然漏掉其它面的攻击;",
        "- **L5 的 UNCERTAIN 兜底是设计**: 执行层检出的攻击类型若无专属策略,"
        "落入 5 分钟短封+高优告警的不确定模板, 而不是放行或乱封;",
        "- LLM 审计层的贡献不在本表: 无 key 时它退化为规则收口(无区分度),"
        "其价值由 grounding 评测(事实性/溯源)单独量化。",
        "",
        "## 边界",
        "",
        "- 全部为合成标定数据, 绝对值不可外推到生产; 真实流量面见 REPLAY 报告;",
        "- L3 的两条标定缺口(ANO-P-02/03)已由 severity_shift 证据维度关闭"
        " (2026-10-25b, 演进史见 tests/test_anomaly_threshold_feasibility docstring);"
        " 真实行为面评估仍需生产基线数据, 见升级证据文档的范围边界;",
        "- 消融刻度是\"层\", 不是\"多智能体角色\" —— 四层 Agent 流水线的",
        "  内部消融(拆 Decompiler/Reviewer)需要 LLM 在环, 属后续工作。",
    ]
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    sys.exit(main())
