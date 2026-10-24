# -*- coding: utf-8 -*-
"""P0-2 回归：待聚合（pending-agg）命中不得触发单事件处置链路。

## 背景

规则声明 ``x-soc-aggregation``（count/op/timeframe）时，单事件命中只是
**前置筛选**，真正的判定要等 Flink 聚合窗口给出阈值证据。修复前的链路是：

1. ``engine.detect_for_event`` 对聚合规则命中仍返回 ``detected=True``
   （只带 ``requires_aggregation=True``）；
2. ``ingest_pipeline.detect`` 只判断 ``sigma_result["detected"]``，
   把 anomaly score 抬到 Sigma severity 下限（SIG-001 high → 0.65）；
3. FastPath 用 ``_fused_conf >= 0.7`` 判 ``_strong_signal`` →
   ``allow_blocking=True``。

于是一条 ``/login`` 事件（SIG-001 前置命中 + confidence high → 0.85）就能
进入**封禁**决策 —— 绕过「窗口超阈值后才处置」的设计，并与 Flink 聚合
告警形成双触发。

修复后 ``detected`` 只反映**已确证**（非聚合）命中；本文件从
engine → ingest → audit_triage → FastPath 逐层钉住。
"""
import os

import pytest

os.environ.setdefault("SHARED_MEMORY_SKIP_DOTENV", "1")

from sigma_engine.engine import PySigmaDetector  # noqa: E402

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# SIG-001 的前置判据：url 含 /api/auth/login；声明 x-soc-aggregation
SIG001_EVENT = {
    "event": "HTTP_REQUEST",
    "url": "/api/auth/login",
    "src_ip": "203.0.113.50",
    "dst_ip": "10.0.0.9",
    "message": "POST /api/auth/login",
}


@pytest.fixture(scope="module")
def detector():
    return PySigmaDetector("sigma_engine/rules")


# ══════════════════════════════════════════════════════════════
# 1. 引擎层：pending-only 命中 → detected=False
# ══════════════════════════════════════════════════════════════

def test_pending_only_hit_is_not_detected(detector):
    """SIG-001 单事件命中只产生 pending 候选，不得报 detected=True。"""
    result = detector.detect_for_event(dict(SIG001_EVENT))
    assert result["detected"] is False, (
        "待聚合命中被报成了确定检出 —— 单事件会由此抬分并进入封禁决策")
    assert result["status"] == "partial"
    assert result["confirmed_hits"] == 0
    assert "SIG-001" in (result.get("pending_aggregation") or []), (
        f"pending_aggregation 未记录 SIG-001: {result.get('pending_aggregation')}")


def test_confirmed_hit_still_detected(detector):
    """对照组：非聚合规则（SIG-003 路径遍历）的单事件命中仍是确定检出。

    没有这条，「修过头」把所有命中都降成 partial 也会让上一条变绿。
    """
    result = detector.detect_for_event({
        "event": "PATH_TRAVERSAL",
        "url": "/../../../etc/passwd",
        "src_ip": "203.0.113.51",
    })
    assert result["detected"] is True, "非聚合规则命中必须保持确定检出"
    assert result["confirmed_hits"] >= 1
    assert not (result.get("pending_aggregation") or [])


def test_pending_hits_keep_declared_action_downgraded(detector):
    """pending 命中携带的动作仍是降级后的 alert（不携带 block_ip）。"""
    result = detector.detect_for_event(dict(SIG001_EVENT))
    for hit in result["hits"]:
        if hit.get("rule_id") == "SIG-001":
            assert hit["action_recommend"] == "alert"
            assert hit["requires_aggregation"] is True


# ══════════════════════════════════════════════════════════════
# 2. ingest 层：pending-only 不得抬 anomaly score
# ══════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_detect_does_not_lift_score_for_pending_only():
    """SIG-001 单事件不得把 anomaly score 抬到 Sigma severity 下限(0.65)。

    修复前这里只看 detected=True 就抬分 —— 高分是 FastPath 强信号判定的
    直接输入，等于把「还没凑够阈值」的候选直接送进封禁门槛。
    """
    from ingest_pipeline import _SIGMA_FLOORS, detect

    dr = await detect(dict(SIG001_EVENT))
    sigma = dr.log_data.get("_sigma") or {}
    assert sigma.get("detected") is False
    assert "SIG-001" in (sigma.get("pending_aggregation") or [])
    high_floor = _SIGMA_FLOORS["high"]
    assert dr.anomaly.anomaly_score < high_floor, (
        f"pending-only 事件分数被抬到 {dr.anomaly.anomaly_score} "
        f"(>= Sigma high 下限 {high_floor})")


@pytest.mark.asyncio
async def test_detect_still_lifts_score_for_confirmed_hits():
    """对照组：确认命中仍抬分到 severity 下限（原语义不变）。"""
    from ingest_pipeline import _SIGMA_FLOORS, detect

    dr = await detect({
        "event": "PATH_TRAVERSAL",
        "url": "/../../../etc/passwd",
        "src_ip": "203.0.113.52",
    })
    sigma = dr.log_data.get("_sigma") or {}
    assert sigma.get("detected") is True
    floor = _SIGMA_FLOORS.get(str(sigma.get("max_severity") or "").lower())
    if floor:
        assert dr.anomaly.anomaly_score >= min(floor, 1.0)


# ══════════════════════════════════════════════════════════════
# 3. audit_triage：融合置信度忽略待聚合命中
# ══════════════════════════════════════════════════════════════

def test_fused_confidence_ignores_pending_hits():
    """pending 命中的 high 置信度不得把融合置信度抬过处置门槛。"""
    from audit_triage import _fused_confidence

    pending_only = {
        "_sigma": {
            "detected": False, "max_severity": "high",
            "hits": [{"rule_id": "SIG-001", "confidence": "high",
                      "requires_aggregation": True}],
            "pending_aggregation": ["SIG-001"], "confirmed_hits": 0,
        },
    }
    assert _fused_confidence(pending_only, 0.0) == pytest.approx(0.0), (
        "待聚合命中的置信度参与了融合 —— 单事件又被抬上去了")


def test_fused_confidence_still_counts_confirmed_hits():
    """对照组：确认命中的置信度照常参与融合（原语义不变）。"""
    from audit_triage import _fused_confidence

    confirmed = {
        "_sigma": {
            "detected": True, "max_severity": "high",
            "hits": [{"rule_id": "SIG-003", "confidence": "high",
                      "requires_aggregation": False}],
        },
    }
    assert _fused_confidence(confirmed, 0.0) == pytest.approx(0.85)


# ══════════════════════════════════════════════════════════════
# 4. FastPath：pending-only 永远不设 allow_blocking=True（源码钉）
# ══════════════════════════════════════════════════════════════
#
# dispatch() 是重编排路径（要 DB/编排器才能真跑），链路语义用源码断言钉住，
# 与 test_sigma_aggregation_action_chain 里 4a 的取舍一致：源码断言挡
# 「门条件被删/被改写」这类回归，真执行由验收环境覆盖。

def _pipeline_src():
    with open(os.path.join(BACKEND, "ingest_pipeline.py"), encoding="utf-8") as f:
        return f.read()


def test_fastpath_strong_signal_gated_by_pending_only():
    src = _pipeline_src()
    assert "_sigma_pending_only" in src, \
        "FastPath 未读取 pending-only 状态"
    assert "not _sigma_pending_only" in src and "_strong_signal" in src, \
        "_strong_signal 未被 pending-only 门控 —— 单事件仍可进封禁决策"


def test_fastpath_confidence_skips_aggregation_hits():
    src = _pipeline_src()
    assert 'hit.get("requires_aggregation")' in src, \
        "FastPath 融合置信度未跳过待聚合命中"


def test_ingest_detect_checks_pending_before_lifting():
    src = _pipeline_src()
    assert "_sigma_pending_only" in src and "_SIGMA_FLOORS" in src, \
        "ingest_pipeline.detect 未在抬分前检查 pending-only"
