"""replay_edr_public.py — E1 公开 EDR 数据集回放（REMEDIATION-PLAN 路线 E1）。

数据：EVTX-ATTACK-SAMPLES（sbousseaden, MIT; 278 个 .evtx, 按 ATT&CK 战术目录组织,
文件名常内嵌 technique 编号如 `_t1098`）→ python-evtx 逐条 XML →
`edr_fusion.sysmon_parser.SysmonParser.parse()`（E1 修复后含 timestamp/ProcessGuid
关联键）→ `sigma_engine.mapping.apply_mapping` → PySigmaDetector.detect
→ **per-technique 命中表**（B3 转正的攻击命中证据燃料）。

technique 标注口径（诚实）：文件名内嵌 `tXXXX[.YYY]` 时取之；否则按**战术目录**
粒度标注（tactic:<name>），不猜具体技术。

良性边界：本数据集是**攻击期全量事件流**（含攻击机上的正常进程活动），
不能当良性 FP 语料 —— B3 的良性 Sysmon 门禁仍等 24h 真机基线（见报告）。

用法：
    cd backend
    python -m eval_datasets.replay_edr_public --root ../tools/datasets-cache/evtx-attack-samples/EVTX-ATTACK-SAMPLES-master \
        [--per-file-cap 3000] [--out ../docs/benchmark/EDR-REPLAY-2026-10-30.json]
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from collections import Counter, defaultdict
from datetime import date
from pathlib import Path

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND))

_TECH_RE = re.compile(r"[tT](\d{4}(?:\.\d{3})?)(?![0-9])")
_SKIP_DIRS = {"EVTX_ATT&CK_Metadata", "AutomatedTestingTools", ".vscode", ".git"}


def technique_of(path: Path) -> tuple[str, str]:
    """(tactic, technique) — technique 仅当文件名内嵌编号, 否则空(按战术粒度)。"""
    tactic = path.parent.name
    m = _TECH_RE.search(path.stem)
    tech = f"T{m.group(1)}" if m else ""
    return tactic, tech


def _rule_id_of(hit) -> str:
    if isinstance(hit, dict):
        return str(hit.get("rule_id", ""))
    return str(getattr(hit, "rule_id", "") or "")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True)
    ap.add_argument("--per-file-cap", type=int, default=3000)
    ap.add_argument("--out", default="")
    args = ap.parse_args()
    root = Path(args.root)

    from Evtx import Evtx  # python-evtx

    from edr_fusion.sysmon_parser import SysmonParser
    from sigma_engine.engine import PySigmaDetector
    from sigma_engine.mapping import apply_mapping

    print("loading detector…", flush=True)
    det = PySigmaDetector(str(BACKEND / "sigma_engine" / "rules"), enforce=False)
    st = det.stats()
    print(f"rules={st.get('rules_count')} shadow={st.get('shadow_count')}", flush=True)
    parser = SysmonParser()

    files = [p for p in sorted(root.rglob("*.evtx"))
             if not any(part in _SKIP_DIRS for part in p.parts)]
    print(f"evtx files: {len(files)}", flush=True)

    per_rule: Counter = Counter()
    per_group: dict = defaultdict(lambda: {
        "files": 0, "records": 0, "parsed": 0, "events_with_hits": 0,
        "distinct_rules": set(), "top_rules": Counter(),
    })
    detect_errors = 0
    t0 = time.time()
    for fi, path in enumerate(files, 1):
        tactic, tech = technique_of(path)
        gkey = f"{tactic}/{tech}" if tech else f"{tactic}/(未标技术)"
        g = per_group[gkey]
        g["files"] += 1
        try:
            with Evtx.Evtx(str(path)) as evtx:
                for rec in evtx.records():
                    g["records"] += 1
                    if g["records"] - (g["records"] - 1) > args.per_file_cap:
                        break
                    try:
                        xml = rec.xml()
                    except Exception:
                        continue
                    e = parser.parse(xml)
                    if e is None:
                        continue
                    g["parsed"] += 1
                    ev = apply_mapping(e.to_dict())
                    try:
                        hits = det.detect(ev)
                    except Exception:
                        detect_errors += 1
                        continue
                    rids = {_rule_id_of(h) for h in hits or []}
                    rids.discard("")
                    if rids:
                        g["events_with_hits"] += 1
                        g["distinct_rules"] |= rids
                        for rid in rids:
                            per_rule[rid] += 1
                            g["top_rules"][rid] += 1
        except Exception as exc:
            print(f"  [warn] {path.name}: {exc}", flush=True)
        if fi % 20 == 0:
            print(f"  [{fi}/{len(files)} files] {time.time()-t0:.0f}s "
                  f"total_rule_hits(events)={sum(per_rule.values())}", flush=True)

    out_groups = {}
    for k, g in sorted(per_group.items()):
        out_groups[k] = {
            "files": g["files"], "records": g["records"], "parsed": g["parsed"],
            "events_with_hits": g["events_with_hits"],
            "distinct_rules": len(g["distinct_rules"]),
            "top_rules": dict(g["top_rules"].most_common(5)),
        }
    result = {
        "generated_at": date.today().isoformat(),
        "dataset": "EVTX-ATTACK-SAMPLES (sbousseaden, MIT license)",
        "files": len(files), "per_file_cap": args.per_file_cap,
        "elapsed_s": round(time.time() - t0, 1),
        "detect_errors": detect_errors,
        "total_hit_events": sum(v["events_with_hits"] for v in out_groups.values()),
        "distinct_rules_fired": len(per_rule),
        "per_rule_total": dict(per_rule.most_common(30)),
        "per_group": out_groups,
        "honesty": [
            "technique 仅取文件名内嵌编号, 其余按战术目录粒度",
            "攻击期事件流不得用作良性 FP 语料; 良性 24h Sysmon 基线未采集",
            "命中含影子规则(shadow) —— 是证据不是执法",
        ],
    }
    out = Path(args.out) if args.out else BACKEND / "eval_datasets" / "EDR-REPLAY-latest.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, ensure_ascii=False, indent=1), encoding="utf-8")
    print(json.dumps({k: result[k] for k in
                      ("files", "elapsed_s", "total_hit_events", "distinct_rules_fired",
                       "detect_errors")}, ensure_ascii=False))
    print(f"-> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
