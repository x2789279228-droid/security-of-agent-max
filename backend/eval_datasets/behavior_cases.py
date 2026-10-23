"""
P3: 行为检测（UEBA-for-AI）权重与阈值的标定数据集。

与 ``eval_datasets/grounding_cases.py`` 同构，但对象是
``mcp_guard.behavior_detector.BehaviorDetector`` 的**四个维度权重**
与**三个阈值**：

    权重  param 0.35 / seq 0.25 / caller 0.25 / time 0.15
    阈值  warn 0.6 / confirm 0.8 / deny 0.95

修复前这些常数与 grounding 的 0.8/0.4 一样，**没有任何标注集、标定脚本
或测试支撑** —— 是「看起来合理」的数。P3-1 又刚让它们第一次真正对
审计工具生效（此前 ``_pre_execute_check`` 只打分不处置），所以现在
正是给它们建标定集的时机。

## 为什么每条样本是「基线 + 探针」两段

检测器必须先见过足够的正常调用才能形成指纹，所以单条调用无法独立判定。
每条样本描述一个场景：
    · ``baseline`` —— 用 decision="allow" 喂进检测器的正常调用
    · ``probe``    —— 待判定的那一次调用
    · ``expect``   —— 期望的 ``SignatureReport.action``

## 可复现性的两个必要条件

1. **时间戳全部显式指定。** `time` 维度直接看 ``rec.ts`` 的小时，
   不给固定时间戳则结果随运行时刻漂移。
2. **基线调用间隔 > 600 秒。** ``_LEARN_DEDUP_SEC = 600`` 会把
   同 ``(caller, tool, arg_digest)`` 的重复学习去重 —— 40 条参数完全相同
   且挤在一小时内的话，指纹只会被学一次，基线根本不成立。

## 维护约定

与 Grounding 同一套：新增样本**先写 expect，再看实现算出的分数**。
实现与标注冲突时是实现的问题，不要为了让测试变绿去改 expect。
确实检不出的类别用 ``known_gap`` 显式登记，由评估器单独记账。

⚠️ ``expect="deny"`` 的样本必须在 ``detector_kwargs`` 里把 mode 设为
``"deny"`` —— 默认 mode 是 ``confirm``，那种配置下永远产生不了 deny。
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

# 基线起点：2026-10-19 10:00 UTC（周一）。固定值 = 可复现。
BASE_TS = datetime(2026, 10, 19, 10, 0, 0, tzinfo=timezone.utc)

# 基线调用间隔必须超过 _LEARN_DEDUP_SEC(600)，否则同参数只学一次。
LEARN_SPACING = 700

# 基线长度：默认 min_samples=30，取 40 留余量。
BASELINE_N = 40


def _ts(hour_offset: int, index: int) -> datetime:
    return BASE_TS + timedelta(hours=hour_offset, seconds=index * LEARN_SPACING)


def baseline_calls(
    tool: str,
    caller: str,
    args: dict,
    *,
    n: int = BASELINE_N,
    start_hour: int = 0,
    role: str = "admin",
    source: str = "mcp_guard",
) -> list:
    """构造 n 条「正常调用」基线。

    start_hour 是相对 BASE_TS 的小时偏移。跨度约 n*700 秒 ≈ 7.8 小时。
    """
    out = []
    for i in range(n):
        out.append({
            "tool_name": tool,
            "caller": caller,
            "caller_role": role,
            "source": source,
            "arguments": dict(args),
            "decision": "allow",
            "reason": "baseline",
            "ts": _ts(start_hour, i),
        })
    return out


def probe_call(
    tool: str,
    caller: str,
    args: dict,
    *,
    hour_offset: int,
    role: str = "admin",
    source: str = "mcp_guard",
    tool_match_method: str = "exact",
    decision: str = "allow",
) -> dict:
    """构造待判定的那一次调用。"""
    return {
        "tool_name": tool,
        "caller": caller,
        "caller_role": role,
        "source": source,
        "arguments": dict(args),
        "decision": decision,
        "reason": "probe",
        "tool_match_method": tool_match_method,
        "ts": _ts(hour_offset, 0),
    }


# ── 常用的正常参数 ────────────────────────────────────────
_BLOCK_RFC = {"ip": "10.0.0.5", "duration": 3600}
_BLOCK_RFC2 = {"ip": "10.0.0.6", "duration": 3600}
_QUERY = {"session_id": "sess-1", "limit": 100}
_ALERT = {"message": "block 10.0.0.5 by analyst after manual review"}


def same_length(base: str, replacement: str) -> str:
    """构造与 base **等长**的字符串，用于隔离「只建模了长度」这一事实。

    由代码保证长度相等，而不是靠手数 —— 否则以后改一句文案，
    标定集就会悄悄变成另一个场景，而测试仍然绿着。
    """
    target = len(base)
    text = replacement[:target].ljust(target, "x")
    assert len(text) == target, "同长构造失败"
    return text


# ═══════════════════════════════════════════
# 场景
# ═══════════════════════════════════════════

SCENARIOS = [
    # ── logged：完全落在基线内 ───────────────────────────
    {
        "id": "identical_repeat",
        "note": "参数/调用者/时间窗全部落在基线内 —— 四个维度都应为 0",
        "baseline": baseline_calls("block_ip", "alice", _BLOCK_RFC),
        "probe": probe_call("block_ip", "alice", _BLOCK_RFC, hour_offset=1),
        "detector_kwargs": {"mode": "deny"},
        "expect": "logged",
    },
    {
        "id": "neighbouring_ip_same_class",
        "note": "换一个同网段的 IP（同属 rfc1918）—— param 不应触发",
        "baseline": baseline_calls("block_ip", "alice", _BLOCK_RFC),
        "probe": probe_call("block_ip", "alice", _BLOCK_RFC2, hour_offset=1),
        "detector_kwargs": {"mode": "deny"},
        "expect": "logged",
    },
    {
        "id": "baseline_spans_hours",
        "note": "基线本身跨多小时 → 该小时有历史占比 → time 维度不应触发",
        "baseline": baseline_calls("event_store.query", "bot", _QUERY),
        "probe": probe_call("event_store.query", "bot", _QUERY, hour_offset=2),
        "detector_kwargs": {"mode": "deny"},
        "expect": "logged",
    },

    # ── confirm：单维度偏离 ──────────────────────────────
    {
        "id": "off_hours_only",
        "note": "只偏离时段：基线全在 10–17 点，探针落在 03 点 → time 维 0.85",
        "baseline": baseline_calls("event_store.query", "bot", _QUERY),
        "probe": probe_call("event_store.query", "bot", _QUERY, hour_offset=17),
        "detector_kwargs": {"mode": "confirm"},
        "expect": "confirm",
    },
    {
        "id": "caller_uses_new_tool",
        "note": "该 caller 从未用过这个工具 → caller 维 0.9",
        "baseline": baseline_calls("block_ip", "alice", _BLOCK_RFC),
        "probe": probe_call("alert_only", "alice", _ALERT, hour_offset=1),
        "detector_kwargs": {"mode": "confirm"},
        "expect": "confirm",
    },
    {
        "id": "non_exact_tool_match",
        "note": "工具名靠模糊匹配才命中 → tool_match_method != exact → caller 维 0.8",
        "baseline": baseline_calls("block_ip", "alice", _BLOCK_RFC),
        "probe": probe_call(
            "block_ip", "alice", _BLOCK_RFC, hour_offset=1,
            tool_match_method="fuzzy",
        ),
        "detector_kwargs": {"mode": "confirm"},
        "expect": "confirm",
    },

    # ── deny：强单维度信号（需 mode=deny）────────────────
    {
        "id": "new_ip_class_public",
        "note": "基线全是 rfc1918，探针打**真公网** IP → param 0.95",
        "baseline": baseline_calls("block_ip", "alice", _BLOCK_RFC),
        "probe": probe_call(
            "block_ip", "alice", {"ip": "8.8.8.8", "duration": 3600},
            hour_offset=1,
        ),
        "detector_kwargs": {"mode": "deny"},
        "expect": "deny",
    },
    {
        "id": "numeric_zscore_outlier",
        "note": "duration 基线恒为 3600（σ=0），探针 999999 → z=8 → param 1.0",
        "baseline": baseline_calls("block_ip", "alice", _BLOCK_RFC),
        "probe": probe_call(
            "block_ip", "alice", {"ip": "10.0.0.5", "duration": 999999},
            hour_offset=1,
        ),
        "detector_kwargs": {"mode": "deny"},
        "expect": "deny",
    },
    {
        "id": "impossible_transition",
        "note": "基线是 query→alert 交替，从未 query→block_ip → seq 0.95",
        "baseline": (
            baseline_calls("event_store.query", "bot", _QUERY, n=20)
            + baseline_calls("alert_only", "bot", _ALERT, n=20, start_hour=4)
        ),
        "probe": probe_call("block_ip", "bot", _BLOCK_RFC, hour_offset=8),
        "detector_kwargs": {"mode": "deny"},
        "expect": "deny",
    },

    # ── known_gap：应该被拦住但当前检不出 ────────────────
    # 这两条的「等长」由 same_length() 保证 —— 只建模长度的文本特征
    # 在长度不变时完全看不出内容变化。
    {
        "id": "new_payload_same_length",
        "note": "message 内容完全不同但**长度与基线相同** → param 无子项触发",
        "baseline": baseline_calls("alert_only", "alice", _ALERT),
        "probe": probe_call("alert_only", "alice", {
            "message": same_length(
                _ALERT["message"], "root 0day RCE reverse bind shell on srv01"
            ),
        }, hour_offset=1),
        "detector_kwargs": {"mode": "deny"},
        "expect": "confirm",
        "known_gap": "only_length_of_free_text_is_modeled",
    },
    {
        "id": "new_target_same_class",
        "note": "target 字段换成从未见过的值，但同类且等长 → IP 类维度不触发",
        "baseline": baseline_calls("vulnerability_scan", "alice", {
            "target": "10.0.0.5", "scan_type": "fast",
        }),
        "probe": probe_call("vulnerability_scan", "alice", {
            # 同为 rfc1918（IP 维度看不见），长度与基线 target 相同
            "target": same_length("10.0.0.5", "10.0.0.77"),
            "scan_type": "fast",
        }, hour_offset=1),
        "detector_kwargs": {"mode": "deny"},
        "expect": "confirm",
        "known_gap": "target_hash_top_never_scored",
    },
]


def scenarios():
    """返回场景列表。"""
    return list(SCENARIOS)
