"""replay_network_public.py — E2 公开网络数据集回放（REMEDIATION-PLAN 路线 E2）。

两个数据集（均下载缓存到 tools/datasets-cache/）：

  unsw_nb15     UNSW-NB15 特征编码 CSV（镜像 InitRoot/UNSW_NB15 —— 官方在
                SharePoint 需人工下载, 已如实登记）。数值特征向量: 二分类
                label(0/1), proto/service/state 为编码值。**无 URL/UA 文本** ——
                web/proxy 类 Sigma 规则预期零命中(与 CSIC 对进程规则同理),
                命中面 = 自研 network 规则 + 异常检测。
  cicids2018_flows  CSE-CIC-IDS2018 CICFlowMeter 流特征 CSV
                (AWS Open Data cse-cic-ids2018, Thursday-01-03 渗透日,
                331,125 行, Benign 238,037 / Infilteration 93,063)。
                同为数值特征向量, 同上边界。
  cicids2018_evtx   CSE-CIC-IDS2018 原始 Windows EVTX(15 台受害机, 渗透攻击期
                全量事件流) —— **复用 E1 的 evtx→sysmon_parser→detect 管线**
                (eval_datasets/replay_edr_public), 是进程面规则的第二攻击语料。

诚实口径: 特征向量语料上 Sigma URL 规则不命中是**数据形态事实**而非引擎缺陷;
EVTX 面是攻击期事件流, 不可作良性 FP 语料(B3 良性门禁仍等 24h 真机基线)。

用法:
    cd backend
    python -m eval_datasets.replay_network_public --dataset unsw_nb15 --root ../tools/datasets-cache [--limit N]
    python -m eval_datasets.replay_network_public --dataset cicids2018_flows --root ../tools/datasets-cache
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
import time
from collections import Counter
from datetime import date
from pathlib import Path

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND))


def _rule_id_of(hit) -> str:
    if isinstance(hit, dict):
        return str(hit.get("rule_id", ""))
    return str(getattr(hit, "rule_id", "") or "")


def _detect_corpus(det, events: list[dict], label: str):
    """跑检测并返回 per-rule 计数 + 命中事件数。"""
    per_rule: Counter = Counter()
    events_with_hits = 0
    t0 = time.time()
    for ev in events:
        try:
            hits = det.detect(ev) or []
        except Exception:
            continue
        rids = {_rule_id_of(h) for h in hits}
        rids.discard("")
        if rids:
            events_with_hits += 1
            for rid in rids:
                per_rule[rid] += 1
    dt = time.time() - t0
    return {
        "n": len(events), "hit_events": events_with_hits,
        "distinct_rules": len(per_rule),
        "elapsed_s": round(dt, 1),
        "eps": round(len(events) / max(dt, 1e-6), 1),
        "per_rule_top": dict(per_rule.most_common(15)),
        "label": label,
    }


def parse_unsw_nb15(root: Path, limit: int = 0) -> tuple[list, list]:
    """UNSW-NB15(镜像) → 平台事件。特征向量 → message 承载关键特征摘要。"""
    files = ["UNSW_NB15_training-set.csv", "UNSW_NB15_testing-set.csv"]
    benign, attack = [], []
    for fn in files:
        p = root / "unsw_nb15" / fn
        if not p.is_file():
            continue
        with open(p, encoding="utf-8", errors="replace") as f:
            for row in csv.DictReader(f):
                ev = {
                    "event": "NETWORK_FLOW", "type": "NETWORK_FLOW",
                    "severity": "medium" if row.get("label") == "1" else "info",
                    "protocol": "tcp",
                    "message": (
                        f"UNSW-NB15 flow proto={row.get('xProt','-')} "
                        f"serv={row.get('xServ','-')} state={row.get('xState','-')} "
                        f"dur={row.get('dur','0')}s spkts={row.get('spkts','0')} "
                        f"sbytes={row.get('sbytes','0')} rate={row.get('rate','0')}"),
                    "src_ip": "203.0.113.200",   # 数据集匿名(镜像无 IP) → 合成常量
                    "dst_ip": "10.30.0.10",
                    "_sim": True,
                    "_ground_truth": "attack" if row.get("label") == "1" else "benign",
                }
                (attack if row.get("label") == "1" else benign).append(ev)
    if limit:
        benign, attack = benign[:limit], attack[:limit]
    return benign, attack


def parse_cicids2018_flows(root: Path, limit: int = 0) -> tuple[list, list]:
    """CIC-IDS2018 CICFlowMeter CSV → 平台事件(数值特征 → message 摘要)。"""
    p = root / "cicids2018" / "Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv"
    benign, attack = [], []
    if not p.is_file():
        return benign, attack
    with open(p, encoding="utf-8", errors="replace") as f:
        for row in csv.DictReader(f):
            lbl = str(row.get("Label", "")).strip()
            is_attack = lbl.lower() not in ("benign", "")
            try:
                dport = int(float(row.get("Dst Port", "0") or 0))
            except ValueError:
                dport = 0
            proto = str(row.get("Protocol", "0"))
            proto_name = {"0": "hopopt", "6": "tcp", "17": "udp"}.get(proto, f"proto{proto}")
            ev = {
                "event": "NETWORK_FLOW", "type": "NETWORK_FLOW",
                "severity": "high" if is_attack else "info",
                "protocol": proto_name,
                "dst_port": dport,
                "message": (
                    f"CIC-IDS2018 flow {lbl} dst_port={dport} proto={proto_name} "
                    f"ts={row.get('Timestamp','')} dur={row.get('Flow Duration','0')} "
                    f"pkts={row.get('Tot Fwd Pkts','0')}+{row.get('Tot Bwd Pkts','0')}"),
                "src_ip": "203.0.113.201",
                "dst_ip": "10.30.0.11",
                "_sim": True,
                "_ground_truth": "attack" if is_attack else "benign",
            }
            (attack if is_attack else benign).append(ev)
    if limit:
        benign, attack = benign[:limit], attack[:limit]
    return benign, attack


def run(dataset: str, root: Path, limit: int) -> dict:
    from sigma_engine.engine import PySigmaDetector

    print("loading detector…", flush=True)
    det = PySigmaDetector(str(BACKEND / "sigma_engine" / "rules"), enforce=False)
    st = det.stats()
    print(f"rules={st.get('rules_count')} shadow={st.get('shadow_count')}", flush=True)

    if dataset == "unsw_nb15":
        benign, attack = parse_unsw_nb15(root, limit)
    elif dataset == "cicids2018_flows":
        benign, attack = parse_cicids2018_flows(root, limit)
    else:
        raise SystemExit(f"unknown dataset {dataset}")

    print(f"corpus: benign={len(benign)} attack={len(attack)}", flush=True)
    res = {
        "generated_at": date.today().isoformat(),
        "dataset": dataset,
        "source_note": {
            "unsw_nb15": "镜像 InitRoot/UNSW_NB15(官方 SharePoint 需人工下载); 特征编码 CSV, 无 URL/UA 文本",
            "cicids2018_flows": "AWS Open Data cse-cic-ids2018 Thursday-01-03-2018(渗透日); CICFlowMeter 数值特征",
        }.get(dataset, ""),
        "classes": {
            "benign": _detect_corpus(det, benign, "benign"),
            "malicious": _detect_corpus(det, attack, "malicious"),
        },
        "honesty": [
            "特征向量语料: Sigma URL/UA 类规则不命中是数据形态事实, 非引擎缺陷",
            "攻击期事件流不可作良性 FP 语料; B3 良性门禁仍等 24h 真机 Sysmon 基线",
            "EVTX 面(cicids2018_evtx)复用 E1 管线, 见 replay_edr_public",
        ],
    }
    return res


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", required=True,
                    choices=["unsw_nb15", "cicids2018_flows"])
    ap.add_argument("--root", default="../tools/datasets-cache")
    ap.add_argument("--limit", type=int, default=0, help="0 = 全量")
    ap.add_argument("--out", default="")
    args = ap.parse_args()
    res = run(args.dataset, Path(args.root), args.limit)
    out = Path(args.out) if args.out else (
        BACKEND / "eval_datasets" / f"REPLAY-{args.dataset.upper()}-latest.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(res, ensure_ascii=False, indent=1), encoding="utf-8")
    for cls, c in res["classes"].items():
        print(f"[{cls}] n={c['n']} hit_events={c['hit_events']} "
              f"rules={c['distinct_rules']} ({c['elapsed_s']}s, {c['eps']}eps)")
        for rid, n in list(c["per_rule_top"].items())[:5]:
            print(f"    {rid}: {n}")
    print(f"-> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
