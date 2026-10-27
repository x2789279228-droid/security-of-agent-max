# -*- coding: utf-8 -*-
"""聚合降级回归（PERF-OPT Wave 0-2，2026-10-26）。

修复前：`_analyze_inner` 的聚合规则是"任一维度 inconclusive ⇒ 整体
inconclusive"。一个 src 基线充分的成熟报告，会因 dst 侧无基线
（target_concentration None）或事件缺时间戳被整个作废成「无法判定」——
压测观测的 100% inconclusive 有相当一部分来自这条规则与
"小时桶数成熟度门槛"的叠加。

修复后两条语义（本文件钉住）：
  S1 至少一个**实体相对证据**可用 → 按证据判定，不可判维度逐维披露
     （status=not_detected + inconclusive_dimensions 保留 + reasons 留痕
      + error_code=partial_evidence_disclosure）；
  S2 一个实体相对证据都没有（全新实体/首触流量）→ 仍然整体
     inconclusive —— q6_3 防误报语义保持：新实体不判、也不假装能判。
     短窗突发流量（如 PERF 压测 15 分钟全首触）因此**设计上**就是
     inconclusive；改变它需要待决项 41 的冷启动规则（需独立 FP 评估）。
"""
import asyncio
import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ.setdefault("SHARED_MEMORY_DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("SHARED_MEMORY_JWT_SECRET", "test-secret")
os.environ.setdefault("SHARED_MEMORY_LLM_API_KEY", "test")
os.environ.setdefault("SHARED_MEMORY_EMBEDDING_API_KEY", "test")
os.environ.setdefault("SHARED_MEMORY_ADMIN_PASSWORD", "test")

from anomaly_detector import AnomalyDetector

try:
    from zoneinfo import ZoneInfo
    _TZ = ZoneInfo("Asia/Shanghai")
except Exception:                                   # pragma: no cover
    from datetime import timezone as _tz
    _TZ = _tz(timedelta(hours=8))

#: 锚点固定 = 可复现（周一 02:00 +08:00 起的 12 个小时桶）
BASE_DT = datetime(2026, 10, 26, 2, 0, 0, tzinfo=_TZ)


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


def _ev(seq, src, dst, sev="info", etype="BENIGN", hours=1.0):
    return {
        "event_id": f"pe-{seq}",
        "event": etype,
        "event_type": etype,
        "severity": sev,
        "src_ip": src,
        "dst_ip": dst,
        "message": "",
        "event_time": (BASE_DT + timedelta(hours=hours)).isoformat(),
    }


def _feed(det, events):
    for e in events:
        _run(det.analyze(dict(e)))


class TestPartialEvidenceDemotion:
    def test_mature_src_with_new_dst_verdicts_instead_of_inconclusive(self):
        """S1：src 基线 12 桶成熟、dst 全新 → 按证据出 not_detected + 披露。

        修复前该场景整体 inconclusive（target_concentration None 一票否决）。
        """
        det = AnomalyDetector()
        baseline = [
            _ev(i, "10.50.1.1", "10.20.30.40", hours=float(h))
            for h in range(12)
            for i in range(h * 50, h * 50 + 5)      # 每小时 5 条，速率平稳
        ]
        _feed(det, baseline)
        # 探针：同 src（成熟）、**全新 dst**、平稳速率、工作时间、info
        probe = _ev(99999, "10.50.1.1", "10.99.99.99", hours=12.1)
        rep = _run(det.analyze(probe))

        assert rep.status == "not_detected", (
            f"实体证据可用却被否决成 {rep.status} —— 聚合降级回归"
        )
        assert rep.is_anomaly is False
        # 不可判维度必须逐维披露，不得静默
        assert "target_concentration" in rep.inconclusive_dimensions
        assert any(r.startswith("partial_evidence:") for r in rep.reasons)
        assert rep.error_code == "partial_evidence_disclosure"

    def test_missing_event_time_demoted_to_disclosure_when_entity_mature(self):
        """S1（续）：成熟实体 + 事件缺时间戳 → not_detected + temporal 披露。"""
        det = AnomalyDetector()
        baseline = [
            _ev(i, "10.50.2.1", "10.20.30.40", hours=float(h))
            for h in range(12)
            for i in range(h * 50, h * 50 + 5)
        ]
        _feed(det, baseline)
        probe = _ev(99998, "10.50.2.1", "10.20.30.40", hours=12.1)
        probe.pop("event_time")                      # 剥掉时间戳
        rep = _run(det.analyze(probe))
        assert rep.status == "not_detected"
        assert "temporal" in rep.inconclusive_dimensions
        assert rep.error_code == "partial_evidence_disclosure"


class TestFirstContactStaysInconclusive:
    def test_brand_new_entity_critical_rare_stays_inconclusive(self):
        """S2：全新实体 + critical + 罕见类型（= 压测 P1 的典型形态）

        必须保持整体 inconclusive —— q6_3 防误报语义 + 待决项 41。
        改变它需要带独立 FP 评估的冷启动规则，不得从聚合层悄悄放行。
        """
        det = AnomalyDetector()
        # 用另一个实体的良性流量把全局统计喂成熟（rarity 可判定）
        baseline = [
            _ev(i, "10.50.3.1", "10.20.30.40", hours=float(h))
            for h in range(12)
            for i in range(h * 50, h * 50 + 5)
        ]
        _feed(det, baseline)
        probe = _ev(99997, "10.66.66.66", "10.20.30.40",
                    sev="critical", etype="ATTACK_BRUTEFORCE", hours=12.1)
        rep = _run(det.analyze(probe))

        assert rep.status == "inconclusive", (
            f"首触实体被判成 {rep.status} —— q6_3 防误报语义被突破；"
            "若要改变此行为，走待决项 41（冷启动规则 + 独立 FP 评估），"
            "不得从聚合层放行"
        )
        assert rep.is_anomaly is False
        assert rep.error_code == "inconclusive_dimensions"
        assert "statistical_deviation" in rep.inconclusive_dimensions
