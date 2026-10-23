"""CEP / Python 关联链 vs 因果 DAG。"""
from __future__ import annotations

from typing import Any, Optional

from causal_chain.do_calculus import has_directed_path, intervene
from causal_chain.variables import CONFOUNDERS, is_attack_node, prior_forbids

# 与 Flink AnomalyDetectionJob 三模式对齐(不 import Java/kafka 缓存)
CEP_PATTERNS = {
    "port_scan_to_c2": ["PORT_SCAN", "BRUTE_FORCE", "C2_BEACON"],
    "lateral_movement": ["SUSPICIOUS_LOGIN", "FILE_ACCESS", "LATERAL_MOVE"],
    "data_exfil": ["FILE_ACCESS", "DATA_EXFIL"],
}

ACE_SPURIOUS = 0.05

#: `causal_verdict` 的取值域。整改方案 §三.1 要求下游能区分这 5 种结论，
#: 不能把它们压成一个真假值。
#:   insufficient_data          —— 没有数据，任何因果结论都不成立
#:   not_identifiable           —— 有数据，但后门调整集不存在（识别假设不满足）
#:   insufficient_causal_evidence —— 可识别，但 ACE 不显著 / 无法估计
#:   causal_support             —— 可识别且统计上支持该因果效应
#:   unknown                    —— 结构上就没有可判定的攻击链步骤，
#:                                或攻击序列在学到的因果图上不成立（path_ok=False）
VERDICTS = (
    "causal_support",
    "insufficient_causal_evidence",
    "not_identifiable",
    "insufficient_data",
    "unknown",
)


def _steps_of(chain: dict) -> list[str]:
    pid = str(chain.get("pattern_id") or chain.get("patternId") or "")
    if pid in CEP_PATTERNS:
        return list(CEP_PATTERNS[pid])
    name = str(chain.get("pattern_name") or "")
    for k, steps in CEP_PATTERNS.items():
        if k in name or name.endswith(k):
            return list(steps)
    events = chain.get("events") or []
    out = []
    for e in events:
        if isinstance(e, dict):
            t = str(e.get("event_type") or "")
        else:
            t = str(e)
        if t and t not in out:
            out.append(t)
    return out


def _data_available(data, first: str, last: str, names: list[str]) -> bool:
    """是否有足够的观测数据去做一次后门估计。

    整改方案 §三.1：`data is None` 时绝不能输出 causal_support ——
    修复前 `q` 退化成 `{"identifiable": False}`，然后直接落到
    `elif path_ok` 分支，于是**零数据**也能拿到 causal_support，
    依据只是一张图上的可达性。
    """
    if data is None:
        return False
    if not first or not last:
        return False
    if first not in names or last not in names:
        return False
    try:
        rows = int(getattr(data, "shape", [0])[0])
    except (TypeError, ValueError, IndexError):
        return False
    return rows > 0


def _decide_verdict(
    *, has_steps: bool, data_available: bool, identifiable: bool,
    ace: Optional[float], ace_spurious: float, path_ok: bool,
) -> str:
    """整改方案 §三.1 的判定顺序（顺序本身就是修复的一部分）。

        data_available → identifiable → statistical_support → path_ok

    修复前只有 `identifiable → path_ok` 两级，且 path_ok 是**最后
    一级且无门槛**：任何不可识别的链只要图上可达就得到 causal_support。

    ## `path_ok` 是 causal_support 的最后一道闸（整改方案 §三.1）

    实测（2026-10-19）：修复前本函数的签名里**根本没有 path_ok** ——
    它被算出来、被写进 `causal_path_ok`，却完全不参与判定。
    于是一条 `PORT_SCAN → BRUTE_FORCE → C2_BEACON` 的链，
    只要学到的图里恰好存在 `PORT_SCAN → C2_BEACON` 的直达边、
    而**两段相邻步骤在图上都不可达**，照样拿到 `causal_support`（ACE=0.5955）。
    也就是说：图明确不支持这个攻击序列，下游却被告知「有因果支持」。

    这与 §九.3「不要把先验/推测当成由数据识别出来的方向」是同一类错误：
    结论的强度超过了数据真正支持的范围。

    `path_ok` 设为**必填**而不是带默认值 —— 默认 True 等于
    「忘了传就静默放行」，正是这里要修的那个失效形态本身。
    """
    if not has_steps:
        return "unknown"
    if not data_available:
        return "insufficient_data"
    if not identifiable:
        return "not_identifiable"
    statistical_support = ace is not None and abs(float(ace)) >= ace_spurious
    if not statistical_support:
        # 可识别但 ACE 不显著或估计不出来 —— 这是「证据不足」，
        # 不是「伪相关」，也不是「因果支持」
        return "insufficient_causal_evidence"
    if not path_ok:
        # 统计上 A 对末步的效应成立，但**攻击序列本身**在图上不成立。
        # 报 causal_support 会让下游把一条图不支持的叙事当成因果证据。
        return "unknown"
    return "causal_support"


def annotate_chain(
    chain: dict,
    *,
    directed: list[tuple[str, str]],
    names: list[str],
    data,
    ace_spurious: float = ACE_SPURIOUS,
) -> dict:
    steps = [s for s in _steps_of(chain) if is_attack_node(s)]
    skip = set(CONFOUNDERS)
    path_ok = True
    missing = []
    if len(steps) >= 2:
        for a, b in zip(steps, steps[1:]):
            if a not in names or b not in names:
                path_ok = False
                missing.append((a, b))
                continue
            if not has_directed_path(directed, a, b, skip=skip):
                path_ok = False
                missing.append((a, b))
    first, last = (steps[0], steps[-1]) if steps else ("", "")
    data_available = _data_available(data, first, last, names)
    q: dict[str, Any] = {"identifiable": False, "reason": "no_data"}
    if data_available:
        q = intervene(data, names, directed, first, last, do_value=0)
    ace = q.get("ace")
    identifiable = bool(q.get("identifiable"))
    verdict = _decide_verdict(
        has_steps=bool(steps),
        data_available=data_available,
        identifiable=identifiable,
        ace=ace,
        ace_spurious=ace_spurious,
        path_ok=path_ok,
    )

    out = dict(chain)
    out["causal_verdict"] = verdict
    out["causal_steps"] = steps
    out["causal_path_ok"] = path_ok
    out["causal_missing_edges"] = [list(p) for p in missing]
    out["ace"] = ace
    out["identifiable"] = identifiable
    out["data_available"] = data_available
    # 识别假设与实际使用的调整集必须随结论一起落库（整改方案 §三.2）
    out["graph_version"] = q.get("graph_version", "")
    out["backdoor_set"] = list(q.get("z") or [])
    out["identifiability_reason"] = q.get("reason", "")
    out["p_y_do"] = q.get("p_y_do")
    out["do_query"] = {"x": first, "y": last, "do": 0} if first else {}
    return out


def candidate_edges(
    consensus_directed: list[dict],
    *,
    cep_pairs: Optional[set[tuple[str, str]]] = None,
) -> list[dict]:
    """两算法一致、先验不违、CEP 没有的新边 → 人审候选,不自动广播。"""
    cep_pairs = cep_pairs or set()
    for pid, steps in CEP_PATTERNS.items():
        for a, b in zip(steps, steps[1:]):
            cep_pairs.add((a, b))
    out = []
    for e in consensus_directed:
        if e.get("confidence") != "high_confidence":
            continue
        a, b = e["cause"], e["effect"]
        if not is_attack_node(a) or not is_attack_node(b):
            continue
        if prior_forbids(a, b):
            continue
        if (a, b) in cep_pairs:
            continue
        out.append({**e, "status": "candidate"})
    return out
