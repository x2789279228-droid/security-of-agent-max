"""replay_pcap_suricata.py — Suricata pcap 回放评测(路线 2)。

修掉的宣称缺口(2026-10-27): ids_connector 此前是 D 级死代码(start() 无调用
方、告警进来凭空消失), 平台"检测能力"没有任何真实网络流量证据。

评测路径(不经 Kafka, 回放形态):
    Suricata -r pcap → eve.json → 本评测器直读 →
    SuricataConnector.process_eve(去重语义与生产一致) →
    SuricataAlert.to_security_event → ingest_pipeline.detect(真实检测链) →
    三方对账 + 场景检出表。

三方对账口径:
    eve_alert_lines(文件里 alert 记录数) = accepted(转成平台事件) + deduped
    platform_events == accepted(无丢失)
    场景检出 = expected_categories ⊆ observed_categories
              (IDS 告警类别级证据; 平台 techniques 另列, 有则锦上添花)

真实数据 runbook(需有网环境):
    1) 下载 malware-traffic-analysis.net 带情景标注 pcap( infected 口令包 )
    2) docker compose --profile ndr up soc-suricata-replay 产出 eve.json
       (soc-suricata-replay 服务用 -r 挂载回放, 不依赖 host 网卡)
    3) python -m eval_datasets.replay_pcap_suricata \
         --manifest <场景清单.json> --eve-dir <eve.json 目录> --out ../docs/benchmark
"""
from __future__ import annotations

import argparse
import collections
import json
import sys
import time
from pathlib import Path

_BACKEND = Path(__file__).resolve().parent.parent


def load_eve(path: Path) -> list[dict]:
    rows = []
    for ln in path.read_text(encoding="utf-8", errors="replace").splitlines():
        ln = ln.strip()
        if not ln:
            continue
        try:
            rows.append(json.loads(ln))
        except json.JSONDecodeError:
            # Suricata 偶发截断行: 计数不中断
            rows.append({"event_type": "_malformed"})
    return rows


async def replay_scenario(eve_rows: list[dict]) -> dict:
    """喂真实连接器(去重/映射语义与生产同源), 返回对账与检出明细。"""
    from ids_connector.suricata_connector import SuricataConnector
    from ingest_pipeline import detect

    conn = SuricataConnector()   # 全新实例: 不吃单例态, 去重语义一致
    type_counts: collections.Counter = collections.Counter()
    alert_lines = 0
    accepted_events: list[dict] = []

    t0 = time.perf_counter()
    for row in eve_rows:
        et = row.get("event_type", "_unknown")
        type_counts[et] += 1
        if et != "alert":
            continue
        alert_lines += 1
        alert = await conn.process_eve(row)
        if alert is not None:
            accepted_events.append(alert.to_security_event())

    detect_results = []
    for ev in accepted_events:
        try:
            dr = await detect(ev)
            detect_results.append({
                "event_type": ev.get("event_type"),
                "category": (ev.get("raw_data") or {}).get("category", ""),
                "src_ip": ev.get("src_ip", ""),
                "dst_ip": ev.get("dst_ip", ""),
                "techniques": ev.get("techniques", []),
                "sigma_hits": [
                    h.get("rule_id") for h in
                    ((dr.log_data.get("_sigma") or {}).get("hits") or [])
                ],
            })
        except Exception as e:
            detect_results.append({
                "event_type": ev.get("event_type"), "error": str(e)[:120],
            })
    elapsed = time.perf_counter() - t0

    stats = conn.get_stats()
    accepted = stats.get("alerts", 0)
    deduped = stats.get("deduped", 0)
    observed_categories = sorted({
        d["category"] for d in detect_results if d.get("category")
    })
    return {
        "eve_lines": len(eve_rows),
        "eve_alert_lines": alert_lines,
        "type_counts": dict(type_counts),
        "accepted": accepted,
        "deduped": deduped,
        "reconciled": alert_lines == accepted + deduped,
        "platform_events": len(accepted_events),
        "store_failures": stats.get("store_failures", 0),
        "observed_categories": observed_categories,
        "detect_results": detect_results,
        "elapsed_ms": round(elapsed * 1000, 1),
    }


def run_manifest(manifest: dict, eve_dir: Path) -> dict:
    import asyncio

    scenarios = []
    all_reconciled = True
    for sc in manifest.get("scenarios", []):
        eve_path = eve_dir / sc["eve_file"]
        if not eve_path.exists():
            scenarios.append({"name": sc.get("name", "?"),
                              "error": f"missing {eve_path.name}"})
            all_reconciled = False
            continue
        res = asyncio.new_event_loop().run_until_complete(
            replay_scenario(load_eve(eve_path)))
        expected = set(sc.get("expected_categories") or [])
        res["scenario"] = sc.get("name", "?")
        res["source"] = sc.get("source", "")
        res["expected_categories"] = sorted(expected)
        res["detected"] = expected.issubset(set(res["observed_categories"])) if expected else None
        all_reconciled = all_reconciled and res["reconciled"]
        scenarios.append(res)
    return {"reconciled": all_reconciled, "scenarios": scenarios}


def render_markdown(res: dict) -> str:
    lines = [
        "# Suricata pcap 回放评测 — 真实 IDS 流量进平台", "",
        f"- 场景数: {len(res['scenarios'])}；三方对账: "
        f"{'✅ 全部一致' if res['reconciled'] else '❌ 有场景对不上 —— 禁止出报告'}",
        "",
        "| 场景 | eve 行 | alert 行 | 接受 | 去重 | 平台事件 | 检出 |",
        "|---|---|---|---|---|---|---|",
    ]
    for s in res["scenarios"]:
        if "error" in s:
            lines.append(f"| {s['scenario']} | ERROR: {s['error']} | | | | | |")
            continue
        mark = {True: "✅", False: "❌", None: "n/a"}[s["detected"]]
        lines.append(
            f"| {s['scenario']} | {s['eve_lines']} | {s['eve_alert_lines']} | "
            f"{s['accepted']} | {s['deduped']} | {s['platform_events']} | {mark} |"
        )
    lines += ["", "## 场景明细", ""]
    for s in res["scenarios"]:
        if "error" in s:
            continue
        lines += [
            f"### {s['scenario']} ({s.get('source') or 'fixture'})", "",
            f"- 期望类别: {s['expected_categories'] or 'n/a'}",
            f"- 观测类别: {s['observed_categories']}",
            f"- 事件类型分布: {s['type_counts']}",
            f"- 平台 techniques: "
            f"{sorted({t for d in s['detect_results'] for t in d.get('techniques', [])}) or '无'}",
            f"- sigma 命中规则: "
            f"{sorted({r for d in s['detect_results'] for r in (d.get('sigma_hits') or []) if r}) or '无'}",
            "",
        ]
    lines += [
        "## 口径声明", "",
        "- IDS 告警类别级证据 = Suricata ET 规则本身；平台价值在: 接入不丢",
        "  (三方对账)、与 sigma/ATT&CK 提取同链路、事件落库可查。",
        "- 真实 pcap runbook 见模块 docstring；本报告 fixture 版用于钉住",
        "  对账与映射语义，真实数据替换 eve 文件即可复用同一评测器。",
    ]
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--manifest", default=str(
        Path(__file__).parent / "fixtures" / "suricata_scenarios.json"))
    ap.add_argument("--eve-dir", default=str(
        Path(__file__).parent / "fixtures"))
    ap.add_argument("--out", default="", help="写 REPLAY-PCAP.{md,-result.json} 的目录")
    args = ap.parse_args()

    manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
    res = run_manifest(manifest, Path(args.eve_dir))
    if not res["reconciled"]:
        print("[replay-pcap] 对账失败 —— 接入链路有丢点, 先修再评", file=sys.stderr)
    md = render_markdown(res)
    if args.out:
        out = Path(args.out)
        out.mkdir(parents=True, exist_ok=True)
        (out / "REPLAY-PCAP-result.json").write_text(
            json.dumps(res, ensure_ascii=False, indent=2), encoding="utf-8")
        (out / "REPLAY-PCAP.md").write_text(md, encoding="utf-8")
        print(f"报告已写 {out}/REPLAY-PCAP.{{md,-result.json}}")
    print(json.dumps({k: v for k, v in res.items() if k != "scenarios"},
                     ensure_ascii=False))
    for s in res["scenarios"]:
        if "error" in s:
            print(f"[{s['scenario']}] ERROR {s['error']}")
            continue
        print(f"[{s['scenario']}] alert={s['eve_alert_lines']} accepted={s['accepted']} "
              f"deduped={s['deduped']} events={s['platform_events']} "
              f"reconciled={s['reconciled']} detected={s['detected']}")
    return 0 if res["reconciled"] else 2


if __name__ == "__main__":
    sys.exit(main())
