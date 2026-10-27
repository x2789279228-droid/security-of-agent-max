"""evaluate_attack_coverage.py — Atomic Red Team 检出对账(路线 1)。

ground-truth(tools/atomic-runner.py 产出) × 平台告警导出 →
per-technique 检出/漏检 + ATT&CK 覆盖矩阵。

对账口径(2026-10-27):
    某次 run "被检出" = 存在平台告警满足任一:
      a) 技术匹配: run.technique ∈ alert.techniques(平台提取的 ATT&CK 标签);
      b) 主机+时间窗匹配: alert.host == run.host 且 alert 时间落在
         [run.start-60s, run.end+600s](日志链路延迟容差)。
    判 a 优先 —— 技术标签是强证据, b 是行为面兜底。

告警导出格式(JSON 数组, 从 /api/logs/events 或 OPS 导出裁剪):
    [{"id": 1, "timestamp": "2026-10-27T02:00:05+00:00",
      "host": "TEST-VM", "src_ip": "10.0.20.5",
      "techniques": ["T1059"], "event_type": "...", "severity": "high"}]

真实数据 runbook: docs/upgrade/ATOMIC-REDTEAM-RUNBOOK.md
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

_ALERT_TOLERANCE_BEFORE = timedelta(seconds=60)
_ALERT_TOLERANCE_AFTER = timedelta(seconds=600)


def _parse_ts(s: str) -> datetime:
    dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def load_ground_truth(path: Path) -> list[dict]:
    runs = []
    for ln in path.read_text(encoding="utf-8").splitlines():
        if ln.strip():
            runs.append(json.loads(ln))
    return runs


def match_run(run: dict, alerts: list[dict]) -> list[dict]:
    """返回命中该 run 的告警列表(强证据技术匹配优先, 行为面兜底)。"""
    start = _parse_ts(run["start"]) - _ALERT_TOLERANCE_BEFORE
    end = _parse_ts(run["end"]) + _ALERT_TOLERANCE_AFTER
    host = str(run.get("host", "")).lower()
    hits = []
    for a in alerts:
        techniques = {str(t).upper() for t in (a.get("techniques") or [])}
        if run["technique"].upper().split(".")[0] in techniques:
            hits.append({**a, "_match": "technique"})
            continue
        ts = a.get("timestamp")
        if not ts:
            continue
        if not (start <= _parse_ts(ts) <= end):
            continue
        if host and str(a.get("host", "")).lower() == host:
            hits.append({**a, "_match": "host+window"})
    return hits


def evaluate(ground_truth: list[dict], alerts: list[dict]) -> dict:
    per_run = []
    per_technique: dict[str, dict] = {}
    for run in ground_truth:
        hits = match_run(run, alerts)
        tech = run["technique"].split(".")[0].upper()
        per_run.append({
            "run_id": run.get("run_id", ""),
            "technique": run["technique"],
            "host": run.get("host", ""),
            "detected": bool(hits),
            "matches": [
                {"alert_id": h.get("id"), "match": h["_match"],
                 "techniques": h.get("techniques", [])}
                for h in hits
            ],
        })
        bucket = per_technique.setdefault(tech, {"runs": 0, "detected": 0, "match_kinds": set()})
        bucket["runs"] += 1
        bucket["detected"] += int(bool(hits))
        bucket["match_kinds"].update(h["_match"] for h in hits)
    detected_techs = sum(1 for v in per_technique.values() if v["detected"])
    return {
        "runs_n": len(ground_truth),
        "alerts_n": len(alerts),
        "techniques_n": len(per_technique),
        "techniques_detected": detected_techs,
        "coverage": round(detected_techs / max(len(per_technique), 1), 4),
        "per_technique": {
            t: {"runs": v["runs"], "detected": v["detected"],
                "match_kinds": sorted(v["match_kinds"])}
            for t, v in sorted(per_technique.items())
        },
        "per_run": per_run,
        "missed": [
            r["run_id"] or r["technique"] for r in per_run if not r["detected"]
        ],
    }


def render_markdown(res: dict, source_note: str) -> str:
    lines = [
        "# ATT&CK 覆盖评测 — Atomic Red Team 真实行为检出", "",
        f"- 执行 run: {res['runs_n']} / 技术: {res['techniques_n']}",
        f"- 平台告警: {res['alerts_n']}",
        f"- **技术覆盖: {res['techniques_detected']}/{res['techniques_n']}"
        f" ({res['coverage']:.0%})**",
        f"- 漏检 run: {len(res['missed'])} 条(每条都要登记 known_gap + 候选规则)",
        f"- {source_note}",
        "",
        "| 技术 | run 数 | 检出 | 匹配方式 |",
        "|---|---|---|---|",
    ]
    for t, v in res["per_technique"].items():
        mark = "✅" if v["detected"] else "❌"
        lines.append(f"| {mark} {t} | {v['runs']} | {v['detected']} | {','.join(v['match_kinds']) or '-'} |")
    lines += [
        "", "## 口径声明", "",
        "- 技术=强证据(平台提取的 ATT&CK 标签)；主机+时间窗=行为面兜底",
        "  (±60s/±600s 容差)，防'没检出来但时间对得上就算中'的自欺；",
        "- 覆盖率只统计**首批已执行**技术 —— 是当前检测面的事实清单，",
        "  不是能力上限声明；扩面靠路线 4 的字段解锁与影子规则晋升；",
        "- 真实数据 runbook: docs/upgrade/ATOMIC-REDTEAM-RUNBOOK.md。",
    ]
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--ground-truth", required=True, help="atomic-runner 产出的 JSONL")
    ap.add_argument("--alerts", required=True, help="平台告警导出 JSON 数组")
    ap.add_argument("--out", default="", help="写 ATTACK-COVERAGE.{md,-result.json} 目录")
    ap.add_argument("--source-note", default="", help="报告来源说明(如测试 VM 名/日期)")
    args = ap.parse_args()

    gt = load_ground_truth(Path(args.ground_truth))
    alerts = json.loads(Path(args.alerts).read_text(encoding="utf-8"))
    res = evaluate(gt, alerts)
    md = render_markdown(res, args.source_note)
    if args.out:
        out = Path(args.out)
        out.mkdir(parents=True, exist_ok=True)
        (out / "ATTACK-COVERAGE-result.json").write_text(
            json.dumps(res, ensure_ascii=False, indent=2), encoding="utf-8")
        (out / "ATTACK-COVERAGE.md").write_text(md, encoding="utf-8")
        print(f"报告已写 {out}/ATTACK-COVERAGE.{{md,-result.json}}")
    print(json.dumps({k: v for k, v in res.items() if k != "per_run"},
                     ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
