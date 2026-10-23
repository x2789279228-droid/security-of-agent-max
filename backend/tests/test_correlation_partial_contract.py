"""§八：关联引擎的模式匹配错误**必须**标成部分失败，不能当成没有攻击链。

整改方案 §八 验收段原文：

    「另外，你报告指出 correlation_engine.analyze() 的部分模式异常会被日志后
    继续吞掉。该行为应纳入统一检测契约：存在模式匹配错误时，必须标记本次分析
    为部分失败，不能直接当成没有攻击链。」

## 修复前实测（不是推断）

注入「全部 11 个模式匹配器抛异常」后跑 `analyze()`：

| | 修复前 | 修复后 |
|---|---|---|
| `chains` | 0 | 0 |
| `reject_reasons` | `{'pattern_error': 11}` | `{'pattern_error': 11}` |
| **上报 `record_detection` 的状态** | **`not_detected`** | **`error`** |

修复前的 `not_detected` 与「基线：一切正常、确实没有攻击」**逐位相同**，
于是在 `soc_detection_outcomes_total` 这张时间序列上，
「匹配器全部崩溃」与「这段时间没有攻击」完全无法区分 ——
这正是整改方案 §二 禁止的「检测失败被编码成真实阴性」。

注入「枢纽主机关联抛异常」更严重：修复前它**只写日志**，
连 `reject_reasons` 都不写，结果对象与干净路径逐位相同。
"""
import asyncio
from datetime import datetime, timedelta, timezone

import pytest

from correlation_engine import (
    ATTACK_CHAIN_PATTERNS,
    CorrelationEngine,
    CorrelationResult,
)

# ── 夹具 ──────────────────────────────────────────────────────────


class _Row:
    """`_analyze_inner` / `_match_hub_hosts` 吃的是 ORM 对象，不是 dict。"""

    def __init__(self, d):
        self.id = d["id"]
        self.event_type = d["event_type"]
        self.severity = d["severity"]
        self.src_ip = d["src_ip"]
        self.dst_ip = d["dst_ip"]
        self.message = d["message"]
        self.created_at = d["created_at"]


class _Scalars:
    def __init__(self, rows):
        self._rows = rows

    def all(self):
        return self._rows


class _Res:
    def __init__(self, rows):
        self._rows = rows

    def scalars(self):
        return _Scalars(self._rows)


class _Session:
    """只实现 `execute()` —— `_analyze_inner` 只用它做一次 select。"""

    def __init__(self, rows):
        self._rows = rows

    async def execute(self, stmt):
        return _Res(self._rows)


# 事件时间落在 `_analyze_inner` 的回溯窗口内
T0 = datetime.now(timezone.utc) - timedelta(minutes=5)


def ev(eid, etype, minutes=0, src="1.1.1.1", dst="2.2.2.2", severity="high"):
    return _Row({
        "id": eid, "event_type": etype, "severity": severity,
        "src_ip": src, "dst_ip": dst, "message": "",
        "created_at": T0 + timedelta(minutes=minutes),
    })


#: 命中 port_scan_to_c2（PORT_SCAN/BRUTE_FORCE/C2_BEACON, min_match=3）
CHAIN_EVENTS = [
    ev(1, "PORT_SCAN", 0),
    ev(2, "BRUTE_FORCE", 1),
    ev(3, "C2_BEACON", 2),
]
#: 什么也命中不了
QUIET_EVENTS = [ev(1, "DNS_QUERY", 0)]


def _boom(_exc=RuntimeError("matcher exploded")):
    def _f(*a, **k):
        raise _exc
    return _f


def _break(engine, keys):
    """只让指定 pattern_key 抛异常，其余照常跑。"""
    original = engine._match_pattern
    keys = set(keys)

    def wrapped(pattern_key, *a, **k):
        if pattern_key in keys:
            raise RuntimeError(f"matcher exploded: {pattern_key}")
        return original(pattern_key, *a, **k)

    engine._match_pattern = wrapped
    return engine


def _run(engine, events=None, monkeypatch=None, session_id="s-1"):
    """跑一次 `analyze()`，同时捕获它上报给指标层的状态。"""
    import core_metrics

    recorded = []
    monkeypatch.setattr(
        core_metrics, "record_detection",
        lambda detector, outcome, seconds=0.0: recorded.append(outcome),
    )
    result = asyncio.run(
        engine.analyze(_Session(events if events is not None else QUIET_EVENTS),
                       session_id))
    return result, recorded


# ── 核心：失败不得被编码成真实阴性 ────────────────────────────────


class TestPatternFailureIsNotANegative:
    def test_all_patterns_failing_is_reported_as_error(self, monkeypatch):
        """全部模式都崩 → `error`，绝不是 `not_detected`。"""
        engine = CorrelationEngine()
        engine._match_pattern = _boom()
        result, recorded = _run(engine, monkeypatch=monkeypatch)

        assert recorded == ["error"], (
            "全部模式匹配失败却报成 %r —— 与「确实没有攻击」完全同形"
            % recorded)
        assert result.status == "error"
        assert result.chains == []

    def test_all_patterns_failing_marks_analysis_incomplete(self, monkeypatch):
        engine = CorrelationEngine()
        engine._match_pattern = _boom()
        result, _ = _run(engine, monkeypatch=monkeypatch)

        assert result.analysis_complete is False
        assert result.pattern_errors == len(ATTACK_CHAIN_PATTERNS)
        obs = result.observability
        assert obs["analysis_complete"] is False
        assert obs["status"] == "error"
        assert obs["pattern_errors"] == len(ATTACK_CHAIN_PATTERNS)

    def test_some_patterns_failing_is_partial(self, monkeypatch):
        """只有一部分模式坏 → `partial`：还有有效证据，但分析不完整。"""
        engine = _break(CorrelationEngine(), ["ransomware", "web_attack"])
        result, recorded = _run(engine, monkeypatch=monkeypatch)

        assert result.status == "partial"
        assert recorded == ["partial"]
        assert result.pattern_errors == 2
        assert result.analysis_complete is False

    def test_matched_chains_survive_a_broken_pattern(self, monkeypatch):
        """有命中 + 部分模式坏 → 链保留，但状态是 `partial` 不是 `detected`。

        对齐 `detection_contract.combine_status` 的规则：
        「某引擎失败时保留其他引擎的有效结果，整体标注为 partial」。
        """
        engine = _break(CorrelationEngine(), ["ransomware"])
        result, recorded = _run(engine, CHAIN_EVENTS, monkeypatch)

        assert result.chains, "本用例的前提是事件能命中一条链"
        assert len(result.chains) == 1
        assert result.status == "partial", (
            "有效命中必须保留，但分析不完整不能报成 detected")
        assert recorded == ["partial"]

    def test_clean_run_stays_not_detected(self, monkeypatch):
        """回归：一切正常且没命中，仍然是 `not_detected`。"""
        result, recorded = _run(CorrelationEngine(), QUIET_EVENTS, monkeypatch)

        assert result.status == "not_detected"
        assert result.analysis_complete is True
        assert result.pattern_errors == 0 and result.hub_error is False
        assert recorded == ["not_detected"]

    def test_clean_run_with_a_hit_stays_detected(self, monkeypatch):
        """回归：一切正常且有命中，仍然是 `detected`。"""
        result, recorded = _run(CorrelationEngine(), CHAIN_EVENTS, monkeypatch)

        assert result.status == "detected"
        assert recorded == ["detected"]


class TestHubFailureLeavesATrace:
    def test_hub_failure_is_recorded_at_all(self, monkeypatch):
        """修复前枢纽异常只写日志，结果对象与干净路径逐位相同。"""
        engine = CorrelationEngine()
        engine._match_hub_hosts = _boom()
        result, recorded = _run(engine, QUIET_EVENTS, monkeypatch)

        assert result.hub_error is True
        assert "hub_error" in result.reject_reasons, (
            "枢纽主机关联崩溃在结果对象上不留任何痕迹 —— "
            "跨源 Kill Chain 这条路径整个消失却看不出来")
        assert result.analysis_complete is False
        assert result.observability["hub_error"] is True

    def test_hub_failure_alone_is_partial_not_error(self, monkeypatch):
        """主路径全部模式都正常跑完 → 只是丢了跨源串联，属 partial。

        不能报 error：11 个模式都给出了完整的阴性证据，
        说自己「一点证据都没有」是虚假的。
        """
        engine = CorrelationEngine()
        engine._match_hub_hosts = _boom()
        result, recorded = _run(engine, QUIET_EVENTS, monkeypatch)

        assert result.status == "partial"
        assert result.pattern_errors == 0
        assert recorded == ["partial"]

    def test_hub_failure_with_a_hit_is_partial(self, monkeypatch):
        engine = CorrelationEngine()
        engine._match_hub_hosts = _boom()
        result, recorded = _run(engine, CHAIN_EVENTS, monkeypatch)

        assert result.chains
        assert result.status == "partial"
        assert recorded == ["partial"]


class TestIncompleteCannotBeTreatedAsNegative:
    """§二 的状态表：partial / error 一律**不能**视为干净。"""

    @pytest.mark.parametrize("status", ["partial", "error"])
    def test_contract_refuses_to_treat_incomplete_as_clean(self, status):
        from detection_contract import can_treat_as_negative, is_incomplete

        assert is_incomplete(status) is True
        assert can_treat_as_negative(status) is False

    def test_reported_statuses_are_inside_the_contract_vocabulary(self, monkeypatch):
        """上报的状态必须是 `detection_contract.ALL_STATUSES` 里的词。

        `core_metrics` 会把不在白名单里的值夹成 "error"，
        那样「拼错了一个词」就会被伪装成「检测器失败」——
        错误会被指标本身吞掉。所以这里先在源头拦住。
        """
        from detection_contract import ALL_STATUSES

        for engine, events in (
            (CorrelationEngine(), QUIET_EVENTS),
            (_break(CorrelationEngine(), ["ransomware"]), QUIET_EVENTS),
            (_boom_engine(), QUIET_EVENTS),
            (CorrelationEngine(), CHAIN_EVENTS),
        ):
            result, recorded = _run(engine, events, monkeypatch)
            assert recorded == [result.status]
            assert result.status in ALL_STATUSES


def _boom_engine():
    e = CorrelationEngine()
    e._match_pattern = _boom()
    return e


class TestPatternErrorsCountDistinctPatterns:
    def test_many_source_ips_do_not_inflate_pattern_errors(self, monkeypatch):
        """`pattern_errors` 记的是**坏了几个模式**，不是失败了几次。

        修复前 `reject_reasons["pattern_error"]` 按 (源IP × 模式) 累加，
        一个源跑 11 次就是 11；10 个源跑同一个坏模式就是 110 ——
        读起来像「110 个模式坏了」。
        """
        events = [ev(1, "PORT_SCAN", 0, src="1.1.1.1"),
                  ev(2, "PORT_SCAN", 0, src="2.2.2.2"),
                  ev(3, "PORT_SCAN", 0, src="3.3.3.3")]
        engine = _break(CorrelationEngine(), ["ransomware"])
        result, _ = _run(engine, events, monkeypatch)

        assert result.source_ip_count == 3
        assert result.pattern_errors == 1, (
            "3 个源 IP 不该把「1 个模式坏了」放大成 %d" % result.pattern_errors)
        # 尝试次数仍然如实记账，两个数字的语义不同
        assert result.reject_reasons["pattern_error"] == 3


class TestNoFieldNamedPartial:
    """命名陷阱守卫：`AttackChain.partial` 与「分析不完整」不是一回事。

    `AttackChain.partial` = 这条链命中时跳了步（模式退化，链的属性）。
    分析不完整 = 引擎这次没跑完（分析的属性）。
    两个 partial 混用会让下游分不清到底该重跑分析还是该复查模式。
    """

    def test_correlation_result_has_no_field_named_partial(self):
        import dataclasses

        names = {f.name for f in dataclasses.fields(CorrelationResult)}
        assert "partial" not in names, (
            "CorrelationResult 又出现了名为 partial 的字段 —— "
            "它会与 AttackChain.partial 混淆")

    def test_the_two_partials_mean_different_things(self, monkeypatch):
        engine = _break(CorrelationEngine(), ["ransomware"])
        result, _ = _run(engine, CHAIN_EVENTS, monkeypatch)

        # 链本身是完整的（没跳步），但分析不完整
        assert all(c.partial is False for c in result.chains)
        assert result.status == "partial"
        assert result.analysis_complete is False
