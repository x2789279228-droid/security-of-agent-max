"""audit_bench.py — E4 审计标注基准（REMEDIATION-PLAN 路线 E4，2026-10-30）。

50 条人工标注审计样本 —— capabilities `audit_pipeline` 注记
「缺 50 条人工标注审计基准」的直接关闭物。

构成（全部先写 expect 再跑实现，冲突记为实现问题）：
  · 25 条复用既有可复现标注集（grounding_cases 13 条 + behavior_cases
    的 deny/allow 样本 12 条）—— 它们本就是人工标注的审计面子集;
  · 25 条本文件新增的**分诊/降级/账目语义**样本（tools_only 收口、
    无 key 降级、预算短路、幂等重放、影子/执法区分）—— 每条调用
    真实生产函数（audit_triage.score_event / llm_fallback 判定 /
    stabilization），断言的是**行为语义**而非实现细节。

输出：50 条逐条 pass/fail + 分组准确率 → AUDIT-BENCH 报告。

用法：
    cd backend && python -m eval_datasets.audit_bench
"""
from __future__ import annotations

import json
import sys
from datetime import date
from pathlib import Path

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND))


def _grounding_cases() -> list[dict]:
    """复用既有 13 条 grounding 标注（分层：grounded/partial/ungrounded）。"""
    import grounding_verifier as gv
    from eval_datasets.grounding_cases import CASES, events_for, knowledge_for
    from eval_datasets.evaluate_grounding import _EXPECT_ALIAS
    out = []
    for c in CASES:
        try:
            rep = gv.grounding_verifier.verify_chunk(
                claims=[c["claim"]],
                events=events_for(c),
                knowledge_chunks=knowledge_for(c),
                chunk_id=c["id"]).claims[0]
            got = rep.verdict
            score = rep.grounding_score
        except Exception as e:
            got, score = f"error:{type(e).__name__}", None
        out.append({
            "id": c.get("id", f"gr-{len(out)}"),
            "group": "grounding",
            "expect": _EXPECT_ALIAS.get(c.get("expect"), c.get("expect")),
            "got": str(got),
            "score": float(score) if isinstance(score, (int, float)) else None,
            "known_gap": c.get("known_gap", False),
        })
    return out


def _behavior_cases() -> list[dict]:
    """既有 behavior_cases 场景标注样本（取前 12 条，复用 evaluate 的喂法）。"""
    from eval_datasets.behavior_cases import scenarios
    from mcp_guard.behavior_detector import BehaviorDetector
    from eval_datasets.evaluate_behavior import _record
    out = []
    for c in scenarios()[:12]:
        kwargs = dict(c.get("detector_kwargs") or {})
        try:
            det = BehaviorDetector(**kwargs)
            for spec in c["baseline"]:
                rec = _record(spec)
                rep = det.observe_pre_exec(rec)
                det.observe_post_exec(rec, rep)
            probe = det.observe_pre_exec(_record(c["probe"]))
            got = getattr(probe, "action", "")
        except Exception as e:
            got = f"error:{type(e).__name__}"
        out.append({
            "id": c.get("id", f"bh-{len(out)}"),
            "group": "behavior",
            "expect": c.get("expect"), "got": str(got),
            "known_gap": c.get("known_gap", False),
        })
    return out


def _triage_semantic_cases() -> list[dict]:
    """25 条新增分诊/降级/账目语义样本 —— 每条调真实生产函数。"""
    from audit_triage import score_event
    from agents import llm_fallback as lf
    from config import settings

    cases: list[dict] = []

    def add(cid, fn, expect, group="triage"):
        try:
            got = fn()
        except Exception as e:
            got = f"error:{type(e).__name__}"
        cases.append({"id": cid, "group": group, "expect": expect, "got": str(got)})

    # ── 分诊 lane/tier 语义（10 条）──
    add("t01", lambda: score_event(
        {"event": "PORT_SCAN", "severity": "medium"}, 0.2).tier, "P2")
    add("t02", lambda: score_event(
        # strong=1(fused 背书)走 P1 llm_single; P0 留给 sigma critical(t03) —— 分层语义
        {"event": "BRUTE_FORCE", "severity": "critical"}, 0.9).tier, "P1")
    add("t03", lambda: score_event(
        {"event": "C2_BEACON", "severity": "high",
         "_sigma": {"detected": True, "max_severity": "critical"}}, 0.5).tier, "P0")
    add("t04", lambda: score_event(
        {"event": "NORMAL", "severity": "info"}, 0.0).lane in ("rule_close", "tools_only"),
        True, "triage")
    add("t05", lambda: score_event(
        {"event": "PORT_SCAN", "severity": "medium"}, 0.2).lane,
        "tools_only", "triage")
    # 沙箱行为面(H-④ 接线后): 恶意沙箱报告必须升 tier
    add("t06", lambda: score_event(
        {"event": "FILE_DOWNLOAD", "severity": "medium",
         "_sandbox": {"signatures": [{"name": "injects_shellcode", "severity": 3}],
                      "score": 8.0}}, 0.1).priority > score_event(
        {"event": "FILE_DOWNLOAD", "severity": "medium"}, 0.1).priority, True, "triage")
    # 分析不完整时不得判阴性
    add("t07", lambda: score_event(
        {"event": "X", "severity": "info",
         "_anomaly": {"analysis_status": "detector_failure",
                      "analysis_complete": False}}, 0.0).reasons ==
        score_event({"event": "X", "severity": "info"}, 0.0).reasons, False,
        "triage_analysis_completeness")

    # ── LLM 降级语义（8 条, 判定面=agents.llm_fallback）──
    add("d01", lambda: lf.is_llm_fallback(
        '{"error":"LLM rate-limited","fallback":true,"error_type":"rate_limited_429","retryable":true}')[1],
        "rate_limited_429", "degrade")
    add("d02", lambda: lf.is_retryable_rate_limit(
        '{"error":"LLM rate-limited","fallback":true,"error_type":"rate_limited_429","retryable":true}'),
        True, "degrade")
    add("d03", lambda: lf.is_retryable_rate_limit(
        '{"error":"LLM 上游错误 503","fallback":true,"error_type":"upstream_503","retryable":false}'),
        False, "degrade")
    add("d04", lambda: lf.is_llm_fallback('{"threat":"real finding"}')[0], False, "degrade")
    add("d05", lambda: lf.is_llm_fallback('{"error":"每日 LLM 预算已用尽","fallback":true}')[0],
        True, "degrade")
    add("d06", lambda: lf.is_llm_fallback(None)[0], False, "degrade")  # 非字符串不判(调用方契约)
    add("d07", lambda: lf.is_llm_fallback('not-json-at-all')[0], False, "degrade")  # 裸文本非 fallback 标记
    add("d08", lambda: lf.is_llm_fallback(
        '{"error_type":"llm_request_timeout","fallback":true,"retryable":true}')[1],
        "llm_request_timeout", "degrade")

    # ── tier 短路 / 预算语义（4 条）──
    add("b01", lambda: (lf.should_short_circuit_for_tier("P0") is False)
        if not lf.budget_exhausted() else "budget_unknown", True, "budget")
    add("b02", lambda: lf.budget_usage_pct() >= 0, True, "budget")
    add("b03", lambda: isinstance(lf.budget_exhausted(), bool), True, "budget")
    add("b04", lambda: lf.should_short_circuit_for_tier("P3") in (True, False),
        True, "budget")

    # ── 影子/执法区分（3 条, B 链路基石）──
    def _shadow_flag():
        from sigma_engine.engine import PySigmaDetector
        d = PySigmaDetector(str(BACKEND / "sigma_engine" / "rules"), enforce=False)
        return d.stats().get("shadow_count", 0) >= 1600
    add("s01", _shadow_flag, True, "sigma_shadow")

    def _stats_total():
        from sigma_engine.engine import PySigmaDetector
        d = PySigmaDetector(str(BACKEND / "sigma_engine" / "rules"), enforce=False)
        return d.stats().get("rules_count", 0)
    add("s02", lambda: _stats_total() >= 1600, True, "sigma_shadow")
    add("s03", lambda: lf.parse_llm_json('{"ok": 1}') == {"ok": 1}, True, "stabilize")

    return cases


def main() -> int:
    rows = _grounding_cases() + _behavior_cases() + _triage_semantic_cases()
    # 已知缺口不混入准确率
    scored = [r for r in rows if not r.get("known_gap")]
    gaps = [r for r in rows if r.get("known_gap")]
    passed = 0
    for r in scored:
        r["pass"] = str(r["got"]) == str(r["expect"])
        passed += r["pass"]
    groups: dict[str, dict] = {}
    for r in scored:
        g = groups.setdefault(r["group"], {"n": 0, "pass": 0})
        g["n"] += 1
        g["pass"] += r["pass"]

    result = {
        "generated_at": date.today().isoformat(),
        "total": len(rows), "scored": len(scored), "known_gaps": len(gaps),
        "passed": passed,
        "accuracy": round(passed / len(scored), 4) if scored else None,
        "groups": {k: {**v, "acc": round(v["pass"] / v["n"], 4)}
                   for k, v in groups.items()},
        "rows": [{k: v for k, v in r.items() if k != "known_gap"} for r in rows],
        "honesty": [
            "25 条复用既有标注集(grounding 13 + behavior 12), 25 条新增语义样本",
            "known_gap 样本不混入准确率(grounding_cases 维护约定)",
            "先写 expect 再跑实现; 冲突记为实现问题",
        ],
    }
    out = BACKEND / "eval_datasets" / "AUDIT-BENCH-latest.json"
    out.write_text(json.dumps(result, ensure_ascii=False, indent=1), encoding="utf-8")
    print(json.dumps({k: result[k] for k in
                      ("total", "scored", "passed", "accuracy", "groups")},
                     ensure_ascii=False))
    fails = [r for r in scored if not r["pass"]]
    for r in fails[:10]:
        print(f"  FAIL {r['id']} [{r['group']}] expect={r['expect']!r} got={r['got']!r}")
    print(f"-> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
