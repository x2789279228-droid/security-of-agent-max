"""backtest_promotion.py — B3 回测转正引擎（REMEDIATION-PLAN-2026-10-30 路线 B3）。

影子 → 执法的**唯一**通道（红线：没有回测证据不许直接翻 x-soc-shadow 标志）：

  1. 良性硬门禁：CSIC-2010 良性全集(normalTrafficTest+Training, 36000 条)
     逐规则误报计数 —— **FP=0 才有转正资格**；
  2. 命中证据：CSIC-2010 攻击全集(anomalousTrafficTest, 25065 条)
     逐规则命中计数 —— **攻击命中 ≥1 才转正**（无证据不转正）；
  3. 决策三分（纯函数 decide）：
       promote               fp==0 且 atk_hits>=1
       keep_shadow_no_evidence fp==0 且 atk_hits==0
       keep_shadow_fp          fp>0（记录 precision = atk/(atk+fp)）
  4. --apply     把 promote 集合的 hq_*.yml 改写为执法（x-soc-shadow: false
     + 转正溯源字段）；--demote-all 一键回影子（全部 hq_* 影子化，含清除
     溯源字段）—— 转正可逆，出问题一条命令回滚。

语料适用边界（诚实口径）：CSIC 是 web 语料 —— 进程面规则(process_creation/
registry/…)在本语料上既无误报也无命中，落入 keep_shadow_no_evidence；
它们的转正等待 E1 的良性 Sysmon 语料，本引擎不替代。

用法：
    cd backend
    python -m eval_datasets.backtest_promotion --root ../tools/datasets-cache \
        [--limit-benign N --limit-attack N] [--out ../docs/benchmark/RULE-PROMOTION-2026-10-30.json] \
        [--apply] [--demote-all]
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from datetime import date
from pathlib import Path

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND))

PROMOTE = "promote"
KEEP_NO_EVIDENCE = "keep_shadow_no_evidence"
KEEP_FP = "keep_shadow_fp"


def decide(fp: int, atk_hits: int) -> str:
    """转正决策（纯函数，测试钉死语义）。

    fp>0 → 无论如何不转正（良性误报是硬门禁）；
    fp==0 且 atk_hits>=1 → 转正（FP=0 + 有攻击命中证据）；
    fp==0 且 atk_hits==0 → 无证据不转正（影子保观察）。
    """
    if fp > 0:
        return KEEP_FP
    if atk_hits >= 1:
        return PROMOTE
    return KEEP_NO_EVIDENCE


def _rule_id_of(hit) -> str:
    if isinstance(hit, dict):
        return str(hit.get("rule_id", ""))
    return str(getattr(hit, "rule_id", "") or "")


def _replay_evtx_dir(det, root: str, label: str):
    """EVTX 目录回放(evtx→sysmon_parser→mapping→detect), 返回 (per-rule命中, 事件数)。

    B3 第二门禁(2026-10-31): 与 replay_edr_public 同一管线 —— 良性目录计 FP,
    攻击目录计命中证据; cap 400000(良性 FP 门禁须全覆盖, B3 终版 2026-11-01)。
    """
    import time as _time
    from collections import Counter as _C
    from pathlib import Path as _P
    from Evtx import Evtx as _EvtxMod   # 子模块; 类是 _EvtxMod.Evtx(E1 同口径)
    from edr_fusion.sysmon_parser import SysmonParser as _SP
    from sigma_engine.mapping import apply_mapping as _am

    files = sorted(_P(root).rglob("*.evtx"))
    if not files:
        print(f"[{label}] no evtx under {root}", flush=True)
        return _C(), 0
    parser = _SP()
    per_rule = _C()
    n = 0
    t0 = _time.time()
    for fi, path in enumerate(files, 1):
        try:
            with _EvtxMod.Evtx(str(path)) as evtx:
                cnt = 0
                for rec in evtx.records():
                    cnt += 1
                    if cnt > 400000:
                        break
                    try:
                        xml = rec.xml()
                    except Exception:
                        continue
                    e = parser.parse(xml)
                    if e is None:
                        continue
                    n += 1
                    try:
                        hits = det.detect(_am(e.to_dict())) or []
                    except Exception:
                        continue
                    for h in hits:
                        rid = _rule_id_of(h)
                        if rid:
                            per_rule[rid] += 1
        except Exception as exc:
            print(f"  [warn] {path.name}: {exc}", flush=True)
        if fi % 25 == 0:
            print(f"[{label}] {fi}/{len(files)} files, {n} events, "
                  f"{_time.time()-t0:.0f}s", flush=True)
    print(f"[{label}] done: {len(files)} files / {n} events", flush=True)
    return per_rule, n


def run_corpus(det, events: list[dict], label: str, progress_every: int = 5000) -> Counter:
    """一个语料跑完，返回 per-rule 命中计数。"""
    hits: Counter = Counter()
    t0 = time.time()
    for i, evt in enumerate(events, 1):
        try:
            results = det.detect(evt)
        except Exception:
            continue
        for r in results or []:
            rid = _rule_id_of(r)
            if rid:
                hits[rid] += 1
        if progress_every and i % progress_every == 0:
            dt = time.time() - t0
            print(f"[{label}] {i}/{len(events)} ({dt:.0f}s, {i/max(dt,0.001):.1f} eps)",
                  flush=True)
    return hits


def _hq_rule_file_map(active_dir: Path) -> dict[str, Path]:
    """x-soc-id → hq_*.yml 文件路径（一遍解析）。"""
    import yaml

    mapping: dict[str, Path] = {}
    for f in sorted(active_dir.glob("hq_*.yml")):
        try:
            d = yaml.safe_load(f.read_text(encoding="utf-8"))
        except Exception:
            continue
        if isinstance(d, dict) and d.get("x-soc-id"):
            mapping[str(d["x-soc-id"])] = f
    return mapping


def _rewrite_rule(path: Path, *, shadow: bool, promotion: dict | None = None) -> bool:
    """幂等改写一条 hq_ 规则的影子/执法状态（保留其余字段与顺序无关性）。"""
    import yaml

    try:
        d = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(d, dict):
            return False
        changed = bool(d.get("x-soc-shadow")) != shadow
        d["x-soc-shadow"] = shadow
        for k in ("x-soc-promoted-at", "x-soc-promotion-fp", "x-soc-promotion-hits"):
            d.pop(k, None)
        if promotion:
            d["x-soc-promoted-at"] = promotion.get("date", "")
            d["x-soc-promotion-fp"] = promotion.get("fp", 0)
            d["x-soc-promotion-hits"] = promotion.get("atk_hits", 0)
        path.write_text(
            yaml.safe_dump(d, allow_unicode=True, sort_keys=False), encoding="utf-8")
        return changed
    except Exception:
        return False


def _normalized(events: list[dict]) -> list[dict]:
    """深解码 url 的规范化视图（与 replay_public_datasets 评测口径同源：
    CSIC 载荷普遍双重编码, 0.347 基线即在此口径上测得）。"""
    from eval_datasets.replay_public_datasets import deep_decode

    out = []
    for e in events:
        e2 = dict(e)
        e2["url"] = deep_decode(e.get("url", ""))
        out.append(e2)
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default="../tools/datasets-cache")
    ap.add_argument("--out", default="")
    ap.add_argument("--limit-benign", type=int, default=0)
    ap.add_argument("--limit-attack", type=int, default=0)
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--demote-all", action="store_true")
    # B3 第二门禁(2026-10-31): Sysmon 良性 FP 硬门禁 + EVTX 攻击命中证据
    ap.add_argument("--benign-evtx-root", default="",
                    help="良性 Sysmon evtx 目录(真机基线); FP=0 硬门禁第二道")
    ap.add_argument("--edr-root", default="",
                    help="攻击 EVTX 目录(EVTX-ATTACK-SAMPLES); 命中即攻击证据")
    args = ap.parse_args()

    from eval_datasets.replay_public_datasets import parse_csic_file
    from sigma_engine.engine import PySigmaDetector

    root = Path(args.root)
    if args.demote_all:
        active_dir = BACKEND / "sigma_engine" / "rules_community_active"
        files = sorted(active_dir.glob("hq_*.yml"))
        n = sum(1 for f in files if _rewrite_rule(f, shadow=True))
        print(f"demote-all: {n}/{len(files)} 条 hq_* 已回影子（幂等，已是影子不计 changed）")
        return 0

    benign: list[dict] = []
    for name in ("normalTrafficTraining.txt", "normalTrafficTest.txt"):
        p = root / name
        if p.is_file():
            benign.extend(parse_csic_file(p))
    atk_path = root / "anomalousTrafficTest.txt"
    attack = parse_csic_file(atk_path) if atk_path.is_file() else []
    if args.limit_benign:
        benign = benign[: args.limit_benign]
    if args.limit_attack:
        attack = attack[: args.limit_attack]
    print(f"corpus: benign={len(benign)} attack={len(attack)}", flush=True)
    if not benign or not attack:
        print("[FAIL] 语料缺失（--root 指向 datasets-cache）", file=sys.stderr)
        return 2

    print("loading detector (1675 rules)…", flush=True)
    det = PySigmaDetector(str(BACKEND / "sigma_engine" / "rules"), enforce=False)
    stats = det.stats()
    print(f"rules={stats.get('rules_count')} shadow={stats.get('shadow_count')}", flush=True)

    fp_hits = run_corpus(det, benign, "benign")
    atk_hits = run_corpus(det, attack, "attack")

    # B3 第二门禁(2026-10-31): Sysmon 良性 FP + EVTX 攻击证据
    sysmon_fp = Counter()
    evtx_atk = Counter()
    sysmon_n = evtx_n = 0
    if args.benign_evtx_root:
        sysmon_fp, sysmon_n = _replay_evtx_dir(det, args.benign_evtx_root, "benign-sysmon")
    if args.edr_root:
        evtx_atk, evtx_n = _replay_evtx_dir(det, args.edr_root, "attack-evtx")
    # 规范化视图（深解码）第二轮：FP 硬门禁要求两种视图都为 0；
    # 攻击命中证据任一视图达标即可（生产 canonical 视图介于两者之间）。
    fp_norm = run_corpus(det, _normalized(benign), "benign-norm")
    atk_norm = run_corpus(det, _normalized(attack), "attack-norm")

    # 只对 hq_ 批量规则做决策（自研/旧执法规则不在本引擎管辖）
    rid2file = _hq_rule_file_map(BACKEND / "sigma_engine" / "rules_community_active")
    decisions: dict[str, dict] = {}
    for rid in sorted(set(fp_hits) | set(atk_hits) | set(rid2file)):
        if rid not in rid2file:
            continue  # 非 hq_ 规则（自研/手适配），不动
        fp = (int(fp_hits.get(rid, 0)) + int(fp_norm.get(rid, 0))
              + int(sysmon_fp.get(rid, 0)))
        atk = (int(atk_hits.get(rid, 0)) + int(atk_norm.get(rid, 0))
               + int(evtx_atk.get(rid, 0)))
        decisions[rid] = {
            "fp": fp,
            "fp_raw": int(fp_hits.get(rid, 0)),
            "fp_norm": int(fp_norm.get(rid, 0)),
            "fp_sysmon": int(sysmon_fp.get(rid, 0)),
            "atk_hits": atk,
            "atk_raw": int(atk_hits.get(rid, 0)),
            "atk_norm": int(atk_norm.get(rid, 0)),
            "atk_evtx": int(evtx_atk.get(rid, 0)),
            "decision": decide(fp, atk),
            "file": rid2file[rid].name,
        }

    summary = Counter(v["decision"] for v in decisions.values())
    out = {
        "generated_at": date.today().isoformat(),
        "corpus": {"benign": len(benign), "attack": len(attack),
                   "source": "CSIC-2010 (tools/datasets-cache)",
                   "benign_sysmon_events": sysmon_n,
                   "attack_evtx_events": evtx_n,},
        "rules_evaluated": len(decisions),
        "summary": dict(summary),
        "decisions": decisions,
        "red_line": "promote 仅当 fp==0 且 atk_hits>=1; FP>0 一律留影子",
    }
    out_path = Path(args.out) if args.out else BACKEND / "eval_datasets" / "RULE-PROMOTION-latest.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"summary: {dict(summary)}  -> {out_path}", flush=True)

    top = sorted((v for v in decisions.values() if v["decision"] == PROMOTE),
                 key=lambda v: -v["atk_hits"])[:10]
    for v in top:
        print(f"  promote {v['file']}: fp=0 atk_hits={v['atk_hits']}")

    if args.apply:
        today = date.today().isoformat()
        n = 0
        for rid, v in decisions.items():
            if v["decision"] == PROMOTE:
                if _rewrite_rule(rid2file[rid], shadow=False,
                                 promotion={"date": today, "fp": v["fp"],
                                            "atk_hits": v["atk_hits"]}):
                    n += 1
        print(f"applied: {n} 条转正（执法）; 回滚: python -m eval_datasets.backtest_promotion --demote-all")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
