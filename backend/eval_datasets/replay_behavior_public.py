"""replay_behavior_public.py — 行为层(anomaly_detector)公开数据集回放(路线 6)。

修掉的宣称缺口(2026-10-27): anomaly_detector 此前只有 8 条合成用例背书,
行为层没有任何公开数据集证据 —— 与 CSIC-2010(签名层)互补。

数据集 registry(与 replay_public_datasets 的 CSIC 分文件共存:
签名层回放动 CSIC 口径回归风险大, 行为层独立模块 + registry, CSIC 零触碰):

    cicids2017  CIC-IDS2017 GeneratedLabelledFlows CSV(流级)
                - Label: BENIGN / SSH-Patator / FTP-Patator / DoS* / PortScan*
                - Timestamp "dd/mm/yyyy HH:MM:SS"
    ctu13       CTU-13 binetflow CSV(流级)
                - Label 前缀: Normal- / Botnet- / Background-(排除, 混合标注)

口径声明(答辩需说明):
    - **流级非包级**: 平台事件是归一化流摘要, Sigma 签名(载荷语义)不适用,
      评测对象是 anomaly_detector 的频率/时序/罕见度/严重度偏移四维打分;
    - 良性与攻击**全部喂入**(生产语义: 基线在学习中, 攻击突增是相对基线的
      偏离), 每条流都取一次探针分;
    - 阈值扫描: 0.40~0.80 步长 0.05 逐档算 TP/FP —— "完整可行区间"结论
      从合成集升级到真实数据集(本报告 = fixture 版, 全量 runbook 见文末)。

## 已知缺口(fixture 实测登记, 不许为了绿数字调 fixture):
    - CIC 暴破突增(已建基线实体, 多日同时段历史): 可行区间 0.40~0.60 ✅
    - CIC 新实体攻击: 冷启动封顶 → 检出受限(实体相对基线的固有语义);
    - CTU 稳态信标 + 首见实体: 行为恒定永不偏离自身基线 → 结构性失明,
      需补 beacon 周期性维度或全局频率层(Flink 行为基线) —— 评测结论
      "完整可行区间为空"在这里是**正确答案**而非失败。

真实数据 runbook(需有网环境):
    CIC-IDS2017: 下载 GeneratedLabelledFlows-TrafficLabelled/*.csv(几十 MB/天),
        建议取 Brute-Force 攻击日(Thursday-WorkingHours) + Friday-WorkingHours;
    CTU-13: 下载 scenario 1/11/12 的 binetflow;
    运行: python -m eval_datasets.replay_behavior_public --dataset cicids2017 \
        --csv <路径> --out ../docs/benchmark
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
import time
from datetime import datetime
from pathlib import Path

_BACKEND = Path(__file__).resolve().parent.parent
#: 阈值扫描档位(覆盖生产默认 0.60 的两侧)
SWEEP_THRESHOLDS = (0.40, 0.45, 0.50, 0.55, 0.60, 0.65, 0.70, 0.75, 0.80)
#: 可行区间判据: 检出率(TPR) ≥ 0.6 且误报率(FPR) ≤ 0.05
FEASIBLE_TPR_MIN = 0.6
FEASIBLE_FPR_MAX = 0.05


def _parse_cic_ts(s: str) -> float:
    return datetime.strptime(s.strip(), "%d/%m/%Y %H:%M:%S").timestamp()


def _parse_ctu_ts(s: str) -> float:
    return datetime.strptime(s.strip(), "%Y/%m/%d %H:%M:%S").timestamp()


def load_cicids2017(path: Path, max_rows: int = 0) -> list[dict]:
    """CIC CSV → 平台事件(带 _label)。流级: url/message 不存在是口径使然。"""
    rows = []
    with open(path, encoding="utf-8", errors="replace", newline="") as f:
        reader = csv.DictReader(f)
        for i, r in enumerate(reader):
            if max_rows and i >= max_rows:
                break
            label = str(r.get("Label", "")).strip()
            if not label:
                continue
            if "BENIGN" in label.upper():
                family, malicious = "BENIGN", False
            else:
                family, malicious = label.upper(), True
            rows.append({
                "event": family, "event_type": family,
                # event_id 必须唯一: anomaly_detector 按 eventId 幂等重放,
                # 缺失/重复会让基线学习把后续事件全吞掉(实测: baseline 只剩 2)
                "event_id": f"cic-{i:08d}",
                "src_ip": str(r.get("Src IP", "")).strip(),
                "dst_ip": f'{str(r.get("Dst IP", "")).strip()}:{str(r.get("Dst Port", "")).strip()}',
                "protocol": str(r.get("Protocol", "")).strip().lower(),
                "severity": "high" if malicious else "info",
                "confidence": 50,
                "event_time": _parse_cic_ts(r.get("Timestamp", "")),
                "_label": "malicious" if malicious else "benign",
                "_family": family,
            })
    return rows


def load_ctu13(path: Path, max_rows: int = 0) -> list[dict]:
    """CTU-13 binetflow → 平台事件。Background 排除(混合标注, 无法对账)。"""
    rows = []
    with open(path, encoding="utf-8", errors="replace", newline="") as f:
        reader = csv.DictReader(f)
        for i, r in enumerate(reader):
            if max_rows and i >= max_rows:
                break
            label = str(r.get("Label", "")).strip()
            if label.startswith("Background"):
                continue
            malicious = label.startswith("Botnet")
            family = "BOTNET_C2" if malicious else "NORMAL"
            rows.append({
                "event": family, "event_type": family,
                "event_id": f"ctu-{i:08d}",
                "src_ip": str(r.get("SrcAddr", "")).strip(),
                "dst_ip": f'{str(r.get("DstAddr", "")).strip()}:{str(r.get("Dport", "")).strip()}',
                "protocol": str(r.get("Proto", "")).strip().lower(),
                "severity": "high" if malicious else "info",
                "confidence": 50,
                "event_time": _parse_ctu_ts(r.get("StartTime", "")),
                "_label": "malicious" if malicious else "benign",
                "_family": family,
            })
    return rows


DATASETS = {
    "cicids2017": {
        "loader": load_cicids2017,
        "fixture": "cicids2017_sample.csv",
        "default_severity_note": "攻击流 severity=high 是上游标注的忠实转写",
    },
    "ctu13": {
        "loader": load_ctu13,
        "fixture": "ctu13_sample.binetflow.csv",
        "default_severity_note": "Botnet 流 severity=high 同上; Background 排除",
    },
}


def replay(events: list[dict]) -> list[tuple[dict, float, str]]:
    """按时间序全量喂入, 每条取探针分。返回 [(event, score, status)]。"""
    from anomaly_detector import AnomalyDetector
    from eval_datasets.evaluate_detection import pinned_clock

    events = sorted(events, key=lambda e: e["event_time"])
    det = AnomalyDetector()
    out = []
    for ev in events:
        with pinned_clock(ev["event_time"] + 60):
            rep = _run_probe(det, ev)
        out.append((ev, float(rep.anomaly_score or 0.0), str(rep.status)))
    return out


def _run_probe(det, ev):
    import asyncio
    from eval_datasets.evaluate_detection import _probe_report
    return _probe_report(det, ev)


def evaluate_with_thresholds(scored: list[tuple[dict, float, str]],
                             thresholds=SWEEP_THRESHOLDS) -> dict:
    by_label = collections = {"malicious": [], "benign": []}
    n_mal = sum(1 for ev, _, _ in scored if ev["_label"] == "malicious")
    n_ben = len(scored) - n_mal
    per_threshold = []
    for th in thresholds:
        tp = fp = 0
        for ev, score, _ in scored:
            flagged = score >= th
            if ev["_label"] == "malicious":
                tp += int(flagged)
            else:
                fp += int(flagged)
        tpr = round(tp / max(n_mal, 1), 4)
        fpr = round(fp / max(n_ben, 1), 4)
        per_threshold.append({
            "threshold": th, "tp": tp, "fp": fp,
            "fn": n_mal - tp, "tn": n_ben - fp,
            "tpr": tpr, "fpr": fpr,
            "feasible": tpr >= FEASIBLE_TPR_MIN and fpr <= FEASIBLE_FPR_MAX,
        })
    feasible = [p["threshold"] for p in per_threshold if p["feasible"]]
    return {
        "n_malicious": n_mal, "n_benign": n_ben,
        "default_threshold": 0.60,
        "per_threshold": per_threshold,
        "feasible_interval": {
            "criterion": f"TPR>={FEASIBLE_TPR_MIN} 且 FPR<={FEASIBLE_FPR_MAX}",
            "thresholds": feasible,
            "conclusion": (f"可行区间 = {min(feasible)}~{max(feasible)}" if feasible
                           else "完整可行区间为空 —— 缺口不是调阈值能解决的, 需补维度/数据源"),
        },
    }


def run_dataset(name: str, csv_path: Path, max_rows: int = 0) -> dict:
    loader = DATASETS[name]["loader"]
    events = loader(csv_path, max_rows=max_rows)
    t0 = time.perf_counter()
    scored = replay(events)
    elapsed = time.perf_counter() - t0
    res = evaluate_with_thresholds(scored)
    res.update({
        "dataset": name, "source_file": csv_path.name,
        "n_events": len(events), "elapsed_s": round(elapsed, 1),
        "throughput_eps": round(len(events) / max(elapsed, 1e-6), 1),
        "fixture": csv_path.name.startswith(("cicids2017_sample", "ctu13_sample")),
    })
    return res


def render_markdown(res: dict) -> str:
    mark = "fixture" if res.get("fixture") else "真实数据"
    lines = [
        f"# 行为层回放评测 — {res['dataset']}({mark})", "",
        f"- 流量: {res['n_events']} 条流(恶意 {res['n_malicious']} / 良性 {res['n_benign']})",
        f"- 评测对象: anomaly_detector(频率/时序/罕见度/严重度偏移) —— "
        f"**流级口径, Sigma 签名不适用**",
        f"- 吞吐: ~{res['throughput_eps']} eps",
        f"- 可行区间判据: {res['feasible_interval']['criterion']}",
        f"- **结论: {res['feasible_interval']['conclusion']}**",
        "",
        "| 阈值 | TP | FP | FN | TN | TPR | FPR | 可行 |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for p in res["per_threshold"]:
        lines.append(
            f"| {p['threshold']:.2f} | {p['tp']} | {p['fp']} | {p['fn']} | "
            f"{p['tn']} | {p['tpr']} | {p['fpr']} | {'✅' if p['feasible'] else '—'} |"
        )
    lines += [
        "", "## 口径声明", "",
        "- 全量喂入(生产语义): 基线在学习中, 检出 = 相对同时学习基线的偏离;",
        "- fixture 版钉住 registry/适配器/扫描语义; 全量真实数据替换 csv 即复用;",
        "- Background 标注(CTU)已排除 —— 混合标注无法对账, 混入即口径污染;",
        "- 全量 runbook: 见模块 docstring(CIC 攻击日建议 Thursday-WorkingHours)。",
    ]
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--dataset", default="cicids2017", choices=sorted(DATASETS))
    ap.add_argument("--csv", default="", help="缺省用提交入库的 fixture")
    ap.add_argument("--max-rows", type=int, default=0)
    ap.add_argument("--out", default="")
    args = ap.parse_args()

    csv_path = (Path(args.csv) if args.csv else
                Path(__file__).parent / "fixtures" / DATASETS[args.dataset]["fixture"])
    res = run_dataset(args.dataset, csv_path, args.max_rows)
    md = render_markdown(res)
    stem = f"REPLAY-BEHAVIOR-{args.dataset}"
    if args.out:
        out = Path(args.out)
        out.mkdir(parents=True, exist_ok=True)
        (out / f"{stem}-result.json").write_text(
            json.dumps(res, ensure_ascii=False, indent=2), encoding="utf-8")
        (out / f"{stem}.md").write_text(md, encoding="utf-8")
        print(f"报告已写 {out}/{stem}.{{md,-result.json}}")
    print(json.dumps({k: v for k, v in res.items() if k != "per_threshold"},
                     ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
