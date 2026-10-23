"""工具行为签名检测器 — UEBA-for-AI（v1 可解释统计）。

observe_pre_exec 只打分；observe_post_exec 在 allow/confirm 时更新指纹。
默认 confirm（enforce）：偏离升级为人工确认。检测器故障 fail-open。
"""

from __future__ import annotations

import logging
import math
import threading
import time
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional, Tuple

from .behavior_signature import (
    GLOBAL_CALLER,
    ToolBehaviorSignature,
    extract_features,
)
from .call_record import ToolCallRecord

logger = logging.getLogger("mcp_guard.behavior_detector")

_ANOMALY_MAX = 200
_HISTORY_MAX = 80
_LEARN_DEDUP_SEC = 600
_SEQ_MIN_FROM = 5
DEFAULT_WEIGHTS = {"param": 0.35, "seq": 0.25, "time": 0.15, "caller": 0.25}

# ── 判定里有两个「0.8」，语义**不同**，必须分别命名 ──────────────────────
#
# 1) STRONG_DIM_THRESHOLD —— 单维度强信号门限。
#    ``is_anomaly = 加权分 >= warn_threshold  或  任一维度 >= STRONG_DIM_THRESHOLD``
#    这是一条与加权分**并行**的触发路径：某个维度单独到 0.8 就足以判为异常，
#    即使加权分被其他维度稀释得很低。
#
# 2) SEVERITY_HIGH_SCORE —— 事件 severity 的分档门限（看的是**加权分**）。
#
# 历史上这两处都写成字面量 0.8，数值又与 DEFAULT_CONFIRM=0.8 相同，
# 于是「改 confirm 阈值」看起来像「也改了 strong 门限」——
# 实际上 strong 门限**不跟随任何配置项**（§9.66 实测：把 confirm 调到 0.9
# 后，单维 0.85 的样本仍被判为 is_anomaly，却因档位门限未命中而**不做任何处置**）。
# 分名命名是为了让这件事**看得见**，不是为了改行为。
STRONG_DIM_THRESHOLD = 0.8
SEVERITY_HIGH_SCORE = 0.8
_MODE_ALIASES = {
    "enforce": "confirm",
    "confirm": "confirm",
    "deny": "deny",
    "block": "deny",
    "shadow": "shadow",
    "alert": "shadow",
    "log": "shadow",
}


def canonical_mode(raw: str | None) -> str:
    """enforce=confirm（偏离需确认）；deny=拒绝；shadow=只告警。未知值按 confirm。"""
    key = str(raw or "confirm").strip().lower()
    return _MODE_ALIASES.get(key, "confirm")


def parse_weights(raw: str) -> dict[str, float]:
    weights = dict(DEFAULT_WEIGHTS)
    text = str(raw or "").strip()
    if not text:
        return weights
    for part in text.split(","):
        if ":" not in part:
            continue
        key, value = part.split(":", 1)
        try:
            weights[key.strip()] = float(value)
        except ValueError:
            continue
    return weights


@dataclass
class SignatureReport:
    anomaly_score: Optional[float]
    is_anomaly: bool
    reasons: list[str] = field(default_factory=list)
    dimensions: dict = field(default_factory=dict)
    cold_start: bool = False
    sample_count: int = 0
    action: str = "logged"  # logged | confirm | deny
    learned: bool = False

    def to_dict(self) -> dict:
        return {
            "score": self.anomaly_score,
            "is_anomaly": self.is_anomaly,
            "reasons": list(self.reasons),
            "dimensions": dict(self.dimensions),
            "cold_start": self.cold_start,
            "sample_count": self.sample_count,
            "action": self.action,
            "learned": self.learned,
        }

    def to_event(self, rec: ToolCallRecord) -> dict:
        return {
            "tool_name": rec.tool_name,
            "caller": rec.caller,
            "source": rec.source,
            "decision": rec.decision,
            "score": self.anomaly_score,
            "reasons": list(self.reasons)[:6],
            "dimensions": dict(self.dimensions),
            "trace_id": rec.trace_id,
            "event_id": rec.event_id,
            "session_id": rec.session_id,
            "severity": "high" if (self.anomaly_score or 0) >= SEVERITY_HIGH_SCORE else "medium",
            "ts": rec.ts.isoformat() if rec.ts else "",
        }


# ═══════════════════════════════════════════
# 签名 → 决策升级规则（全平台唯一来源，P3-1）
# ═══════════════════════════════════════════
# 修复前这条规则只写在 McpGuardServer._apply_enforcement 里，
# 于是「策略在一处配置、在两处执行」变成了「只在一处执行」：
#   · MCP Guard 的响应侧工具走 _apply_enforcement → deny 生效
#   · tool_registry._pre_execute_check 只把分数拼进 reason 字符串，
#     然后无条件 passed=True → deny 完全失效
# 实测：同一份 action="deny" 的 SignatureReport，
#   MCP Guard 侧最终决策=deny，审计工具侧 passed=True（reason 仅「score=0.97」）。
# 也就是说运维把 tool_signature_mode 配成 deny 之后，11 个审计工具一个都不会拦。
#
# 抽到这里是因为它是对 SignatureReport.action 的直接解释，
# 两个执行点都已经依赖本模块，不必为十几行规则另开一个模块。

DECISION_RANK = {"allow": 0, "require_confirmation": 1, "deny": 2}


def _config_number(settings, name: str, default, caster):
    """从 settings 读一个数值配置项，**保留合法的 0**。

    ## 为什么不能用 `getattr(s, name, default) or default`

    那个写法把 **falsy 值**（尤其是 `0`）当成「没配」⇒ 退回默认值。
    实测（§9.67）：运维把 ``tool_signature_warn_threshold`` 配成 **0**
    （语义 = 一切都触发），生产实际拿到的是 **0.6**；
    四个阈值/样本数全部如此。

    ⇒ 运维**改了配置却看不到效果**，且没有任何日志提示。
    `0` 对这些字段是**合法且有意义**的取值（阈值 0 = 全部命中），
    不能被静默吞掉。

    正确的兜底条件是「**没配**」（None / 属性不存在），不是「值为 0」。
    """
    if settings is None:
        return caster(default)
    raw = getattr(settings, name, None)
    if raw is None:
        return caster(default)
    try:
        return caster(raw)
    except (TypeError, ValueError):
        # 配了但类型不对 —— 退回默认并**不留痕**是原来的行为；
        # 这里显式吞掉异常以保持与原实现一致的容错度。
        return caster(default)


def escalate_decision(
    current: str, report: Optional[SignatureReport]
) -> Tuple[str, str]:
    """把行为签名报告的 action 升级到决策档位。只升不降。

    Args:
        current: 当前决策档位
        report: 签名报告；None 或 action="logged" 表示只记录不处置

    Returns:
        (decision, reason) —— 未升级时 decision 原样返回、reason 为空串
    """
    if report is None or report.action in (None, "logged"):
        return current, ""

    desired = "deny" if report.action == "deny" else "require_confirmation"
    if DECISION_RANK.get(desired, 0) <= DECISION_RANK.get(current, 0):
        return current, ""

    detail = "; ".join(report.reasons[:3]) or f"score={report.anomaly_score}"
    return desired, f"behavior_signature: {detail}"


class BehaviorDetector:
    """每 (tool, caller) 一份指纹 + 调用者级 Markov / 工具直方图。"""

    def __init__(
        self,
        min_samples: Optional[int] = None,
        weights: Optional[dict] = None,
        enabled: Optional[bool] = None,
        persist: bool = False,
        warn_threshold: Optional[float] = None,
        mode: Optional[str] = None,
    ):
        self._lock = threading.Lock()
        self._signatures: dict[tuple[str, str], ToolBehaviorSignature] = {}
        self._caller_hist: dict[str, deque] = defaultdict(lambda: deque(maxlen=_HISTORY_MAX))
        self._caller_markov: dict[str, Counter] = defaultdict(Counter)
        self._caller_markov_from: dict[str, Counter] = defaultdict(Counter)
        self._caller_tools: dict[str, Counter] = defaultdict(Counter)
        self._caller_n: dict[str, int] = defaultdict(int)
        self._learn_seen: dict[tuple, float] = {}
        self._anomalies: deque = deque(maxlen=_ANOMALY_MAX)
        self._min_samples_override = min_samples
        self._weights_override = weights
        self._enabled_override = enabled
        self._warn_override = warn_threshold
        self._mode_override = mode
        self.persist = persist
        self._dirty: set[tuple[str, str]] = set()

    def reset(self) -> None:
        with self._lock:
            self._signatures.clear()
            self._caller_hist.clear()
            self._caller_markov.clear()
            self._caller_markov_from.clear()
            self._caller_tools.clear()
            self._caller_n.clear()
            self._learn_seen.clear()
            self._anomalies.clear()
            self._dirty.clear()

    def _settings(self):
        try:
            from config import settings
            return settings
        except Exception:
            return None

    def enabled(self) -> bool:
        if self._enabled_override is not None:
            return bool(self._enabled_override)
        s = self._settings()
        return bool(getattr(s, "tool_signature_enabled", True)) if s else True

    def min_samples(self) -> int:
        if self._min_samples_override is not None:
            return int(self._min_samples_override)
        s = self._settings()
        return _config_number(s, "tool_signature_min_samples", 30, int)

    def warn_threshold(self) -> float:
        if self._warn_override is not None:
            return float(self._warn_override)
        s = self._settings()
        return _config_number(s, "tool_signature_warn_threshold", 0.6, float)

    def confirm_threshold(self) -> float:
        s = self._settings()
        return _config_number(s, "tool_signature_confirm_threshold", 0.8, float)

    def deny_threshold(self) -> float:
        s = self._settings()
        return _config_number(s, "tool_signature_deny_threshold", 0.95, float)

    def mode(self) -> str:
        if self._mode_override is not None:
            return canonical_mode(self._mode_override)
        s = self._settings()
        raw = getattr(s, "tool_signature_mode", "confirm") if s else "confirm"
        return canonical_mode(raw)

    def weights(self) -> dict[str, float]:
        if self._weights_override is not None:
            return dict(self._weights_override)
        s = self._settings()
        raw = getattr(s, "tool_signature_weights", "") if s else ""
        return parse_weights(raw)

    def _sig(self, tool: str, caller: str) -> ToolBehaviorSignature:
        key = (tool, caller)
        sig = self._signatures.get(key)
        if sig is None:
            sig = ToolBehaviorSignature(tool_name=tool, caller=caller)
            self._signatures[key] = sig
        return sig

    def observe(self, rec: ToolCallRecord) -> Optional[SignatureReport]:
        """打分并按规则学习。测试便捷入口。"""
        report = self.observe_pre_exec(rec)
        self.observe_post_exec(rec, report)
        return report

    def observe_pre_exec(self, rec: ToolCallRecord) -> Optional[SignatureReport]:
        """只打分，不更新指纹。失败返回 None（fail-open）。"""
        if not self.enabled():
            return None
        try:
            with self._lock:
                return self._score_locked(rec)
        except Exception as e:
            logger.warning("behavior_detector score failed (non-fatal): %s", e)
            return None

    def observe_post_exec(self, rec: ToolCallRecord, report: Optional[SignatureReport] = None) -> None:
        """allow / require_confirmation 写入指纹；deny / self_play 不学。"""
        if not self.enabled():
            return
        try:
            with self._lock:
                learned = self._learn_locked(rec)
                if report is not None:
                    report.learned = learned
                if report is not None and report.is_anomaly:
                    self._record_anomaly_locked(rec, report)
            if report is not None and report.is_anomaly:
                self._emit(rec, report)
        except Exception as e:
            logger.warning("behavior_detector learn failed (non-fatal): %s", e)

    def _score_locked(self, rec: ToolCallRecord) -> SignatureReport:
        min_n = self.min_samples()
        features = extract_features(rec.arguments)
        rec.ts.timestamp() if rec.ts else time.time()
        hour = rec.ts.astimezone(timezone.utc).hour if rec.ts else datetime.now(timezone.utc).hour
        local = self._signatures.get((rec.tool_name, rec.caller))
        glob = self._signatures.get((rec.tool_name, GLOBAL_CALLER))
        sample_count = local.sample_count if local else 0

        dims: dict[str, Optional[float]] = {}
        reasons: list[str] = []

        param_src = local if local and local.ready(min_n) else glob if glob and glob.ready(min_n) else None
        if param_src is not None:
            p_score, p_why = param_src.score_params(features)
            dims["param"] = p_score
            reasons.extend(p_why)
            t_score, t_why = param_src.score_time(hour)
            dims["time"] = t_score
            reasons.extend(t_why)

        s_score, s_why = self._score_seq(rec.caller, rec.tool_name)
        if s_score is not None:
            dims["seq"] = s_score
            reasons.extend(s_why)

        c_score, c_why = self._score_caller(rec, glob if glob and glob.ready(min_n) else None, min_n)
        if c_score is not None:
            dims["caller"] = c_score
            reasons.extend(c_why)

        if not dims:
            return SignatureReport(
                anomaly_score=None,
                is_anomaly=False,
                reasons=[f"学习中 ({sample_count}/{min_n})"],
                dimensions={},
                cold_start=True,
                sample_count=sample_count,
                action="logged",
            )

        weights = self.weights()
        numer = 0.0
        denom = 0.0
        for name, value in dims.items():
            if value is None:
                continue
            w = float(weights.get(name, 0.0))
            numer += w * float(value)
            denom += w
        score = (numer / denom) if denom > 0 else 0.0
        score = max(0.0, min(1.0, score))
        strong = any(float(v) >= STRONG_DIM_THRESHOLD for v in dims.values() if v is not None)
        is_anomaly = score >= self.warn_threshold() or strong
        action = "logged"
        mode = self.mode()
        max_dim = max((float(v) for v in dims.values() if v is not None), default=0.0)
        if is_anomaly and mode != "shadow":
            if mode == "deny" and (score >= self.deny_threshold() or max_dim >= self.deny_threshold()):
                action = "deny"
            elif mode in ("confirm", "deny") and (
                score >= self.confirm_threshold() or max_dim >= self.confirm_threshold()
            ):
                action = "confirm"
        return SignatureReport(
            anomaly_score=round(score, 4),
            is_anomaly=is_anomaly,
            reasons=reasons[:8],
            dimensions={k: round(float(v), 4) for k, v in dims.items() if v is not None},
            cold_start=False,
            sample_count=sample_count,
            action=action if is_anomaly else "logged",
        )

    def _score_seq(self, caller: str, tool: str) -> tuple[Optional[float], list[str]]:
        hist = self._caller_hist.get(caller)
        if not hist:
            return None, []
        prev = hist[-1][0]
        from_n = int(self._caller_markov_from[caller].get(prev, 0))
        if from_n < _SEQ_MIN_FROM:
            return None, []
        cnt = int(self._caller_markov[caller].get(f"{prev}>{tool}", 0))
        p = cnt / from_n
        if p <= 0:
            return 0.95, [f"caller={caller} 在 {prev} 后直接 {tool},转移概率 0/{from_n}"]
        if p < 0.02:
            return 0.8, [f"caller={caller} 在 {prev} 后接 {tool},转移概率 {cnt}/{from_n}"]
        # p=1 → 0；罕见转移抬分
        score = max(0.0, min(1.0, -math.log(max(p, 1e-9)) / 6.0))
        if score < 0.35:
            return 0.0, []
        return score, [f"caller={caller} 序列 {prev}→{tool} 概率 {p:.2f}"]

    def _score_caller(
        self, rec: ToolCallRecord, glob: Optional[ToolBehaviorSignature], min_n: int,
    ) -> tuple[Optional[float], list[str]]:
        reasons: list[str] = []
        score = 0.0
        informed = False
        n = int(self._caller_n.get(rec.caller, 0))
        if n >= min_n:
            informed = True
            frac = self._caller_tools[rec.caller][rec.tool_name] / n
            if frac <= 0:
                score = max(score, 0.9)
                reasons.append(
                    f"{rec.caller} 调用 {rec.tool_name},该 caller 历史未见此工具 (n={n})"
                )
            elif frac < 0.02:
                score = max(score, 0.75)
                reasons.append(
                    f"{rec.caller} 很少调用 {rec.tool_name} ({frac:.1%} of {n})"
                )
        if glob is not None:
            informed = True
            total = sum(glob.role_counts.values()) or sum(glob.source_counts.values())
            # 该 tool 的 caller 分布：用 source/role；同时也看 glob 是否几乎全是别的 caller
            # glob 是 (tool, *)，sample_count 是所有 caller 合计。当前 (tool, caller) 计数：
            local = self._signatures.get((rec.tool_name, rec.caller))
            local_n = local.sample_count if local else 0
            if glob.sample_count >= min_n and local_n <= 0:
                score = max(score, 0.85)
                reasons.append(
                    f"{rec.tool_name} 历史 {glob.sample_count} 次均非 caller={rec.caller}"
                )
            if rec.caller_role and total >= min_n:
                rf = glob.role_counts[rec.caller_role] / max(1, sum(glob.role_counts.values()))
                if glob.role_counts[rec.caller_role] <= 0:
                    score = max(score, 0.7)
                    reasons.append(f"角色 {rec.caller_role} 从未调用 {rec.tool_name}")
                elif rf < 0.02:
                    score = max(score, 0.55)
        if rec.tool_match_method and rec.tool_match_method != "exact":
            informed = True
            score = max(score, 0.8)
            reasons.append(f"tool_match_method={rec.tool_match_method}")
        if not informed:
            return None, []
        return score, reasons

    def _should_learn(self, rec: ToolCallRecord) -> bool:
        if rec.decision == "deny":
            return False
        if rec.source == "self_play":
            return False
        return rec.decision in ("allow", "require_confirmation")

    def _learn_locked(self, rec: ToolCallRecord) -> bool:
        now = rec.ts.timestamp() if rec.ts else time.time()
        # 调用者历史 / Markov 对 deny 也更新——否则 "alert×50 再 isolate" 的序列维会被 deny 打断。
        # 指纹本体（参数分布）仍按 _should_learn 过滤。
        hist = self._caller_hist[rec.caller]
        prev = hist[-1][0] if hist else None
        if prev:
            self._caller_markov[rec.caller][f"{prev}>{rec.tool_name}"] += 1
            self._caller_markov_from[rec.caller][prev] += 1
        hist.append((rec.tool_name, now))
        cutoff = now - 3600
        while hist and hist[0][1] < cutoff:
            hist.popleft()

        if not self._should_learn(rec):
            return False

        key = (rec.caller, rec.tool_name, rec.arg_digest or "")
        last = self._learn_seen.get(key)
        if last and (now - last) < _LEARN_DEDUP_SEC:
            # 十分钟内同参数只学 1 次，但仍计入 caller 直方图（上面已记序列）
            return False
        self._learn_seen[key] = now
        if len(self._learn_seen) > 4000:
            stale = [k for k, ts in self._learn_seen.items() if now - ts > _LEARN_DEDUP_SEC]
            for k in stale[:2000]:
                self._learn_seen.pop(k, None)

        features = extract_features(rec.arguments)
        hour = rec.ts.astimezone(timezone.utc).hour if rec.ts else datetime.now(timezone.utc).hour
        weekday = rec.ts.astimezone(timezone.utc).weekday() if rec.ts else 0
        for caller_key in (rec.caller or "unknown", GLOBAL_CALLER):
            sig = self._sig(rec.tool_name, caller_key)
            sig.update(
                ts=now, hour=hour, weekday=weekday, features=features,
                role=rec.caller_role, source=rec.source, decision=rec.decision,
                duration_ms=rec.duration_ms,
            )
            self._dirty.add((rec.tool_name, caller_key))
        self._caller_tools[rec.caller][rec.tool_name] += 1
        self._caller_n[rec.caller] += 1
        return True

    def _record_anomaly_locked(self, rec: ToolCallRecord, report: SignatureReport) -> None:
        item = {
            "ts": rec.ts.isoformat() if rec.ts else datetime.now(timezone.utc).isoformat(),
            "tool_name": rec.tool_name,
            "caller": rec.caller,
            "source": rec.source,
            "score": report.anomaly_score,
            "dimensions": dict(report.dimensions),
            "reasons": list(report.reasons),
            "mode": self.mode(),
            "action_taken": report.action,
            "trace_id": rec.trace_id,
            "event_id": rec.event_id,
            "decision": rec.decision,
        }
        self._anomalies.append(item)

    def _emit(self, rec: ToolCallRecord, report: SignatureReport) -> None:
        """只发 SSE；思维链节点由 ingest_tool_call / Guard._finish 走 emit_tool_result。"""
        try:
            from event_bus import event_bus
            event_bus.publish("tool_anomaly", report.to_event(rec))
        except Exception:
            pass

    def recent_anomalies(self, limit: int = 20) -> list:
        with self._lock:
            items = list(self._anomalies)
        return items[-limit:][::-1]

    def list_signatures(self) -> list:
        min_n = self.min_samples()
        with self._lock:
            return [sig.summary(min_n) for sig in self._signatures.values()]

    def stats(self) -> dict:
        min_n = self.min_samples()
        with self._lock:
            sigs = list(self._signatures.values())
            anomalies = len(self._anomalies)
        ready = sum(1 for s in sigs if s.ready(min_n))
        return {
            "enabled": self.enabled(),
            "mode": self.mode(),
            "min_samples": min_n,
            "fingerprints": len(sigs),
            "ready": ready,
            "learning": max(0, len(sigs) - ready),
            "anomalies": anomalies,
        }

    def get_signature(self, tool_name: str, caller: str = GLOBAL_CALLER) -> Optional[dict]:
        with self._lock:
            sig = self._signatures.get((tool_name, caller))
            return sig.summary(self.min_samples()) if sig else None
