"""
Detection Engine Correctness Review -- Phase 2.

  Q14 : Is there a UNIFIED detection-result CONTRACT, and are
        "not_detected" and "error" genuinely DIFFERENT states?
  Q15 : Is the final decision ever DILUTED by averaging scores, and are
        missing/unavailable detectors EXCLUDED or counted as 0.0?

This file is REVIEW EVIDENCE, not a fix or a regression suite.
Every assertion is locked to behaviour ACTUALLY EXECUTED on this host
(Python 3.11.9, pytest 9.1.1, Windows/PowerShell 5.1). No production code
under backend/ was modified by this review.

Docstring evidence grading:
  [PROVEN]  executed here; the observed value is quoted inline
  [INFER]   read from source only, not executed on this host
  [UNVERIFIED] cannot be checked on this host (see report)

IMPORTANT: assertions that freeze DEFECTIVE behaviour are deliberately
written against the OBSERVED result, so the file stays green and
reproducible. The "expected but NOT achieved" behaviour is described in
the docstrings and in the review report, never as a failing assertion.
"""
from __future__ import annotations

import asyncio
import dataclasses
import os
import pathlib

os.environ.setdefault("SHARED_MEMORY_SKIP_DOTENV", "1")

import pytest  # noqa: E402

import ingest_pipeline as ip  # noqa: E402
import sigma_detector as sd  # noqa: E402
from anomaly_detector import AnomalyReport  # noqa: E402
from audit_triage import _fused_confidence, score_event  # noqa: E402
from edr_fusion.cross_correlator import CrossCorrelator  # noqa: E402
from zeroday_detect.behavior_analyzer import behavior_analyzer  # noqa: E402

BACKEND = pathlib.Path(__file__).resolve().parent.parent

# The seven fields the review checklist demands on EVERY detector payload.
CONTRACT_FIELDS = (
    "status",
    "error_code",
    "detector_version",
    "rule_version",
    "score",
    "score_type",
    "analysis_window",
)

# Triggers built-in SIG-003 (path_traversal, severity="critical", confidence="high").
CRITICAL_SIGMA_EVENT = {
    "event": "PATH_TRAVERSAL",
    "url": "http://x/../../etc/passwd",
    "message": "GET /../../etc/passwd",
    "src_ip": "1.1.1.1",
    "dst_ip": "2.2.2.2",
    "severity": "info",
}

# Matches no built-in rule.
BENIGN_EVENT = {
    "event": "BENIGN",
    "url": "http://x/?q=hello",
    "message": "hello",
    "src_ip": "1.1.1.1",
    "dst_ip": "2.2.2.2",
    "severity": "info",
}

REAL_SIGMA = sd.sigma_detector


def _run(coro):
    return asyncio.run(coro)


class _AnomalyStub:
    """Healthy anomaly engine returning a fixed, legitimate score."""

    def __init__(self, score: float = 0.0):
        self.score = score

    async def analyze(self, event):
        return AnomalyReport(
            event_id=0,
            anomaly_score=self.score,
            is_anomaly=self.score > 0.6,
            deviation_sigma=0.0,
            reasons=[],
        )


class _AnomalyDown:
    """Anomaly engine DOWN -- the 'error' state the review asks about."""

    async def analyze(self, event):
        raise RuntimeError("anomaly engine down")


class _SigmaDown:
    """Sigma engine DOWN."""

    def detect_for_event(self, log_data):
        raise RuntimeError("sigma engine down")


# ====================================================================
# Q14 -- unified detection-result contract
# ====================================================================


class TestQ14ContractExistence:
    def test_q14_1_cross_detector_contract_module_exists(self):
        """[FIXED] 统一检测契约模块已建立并被融合层实际使用。

        修复前：全仓只有 `sigma_detector.py` 定义 `class DetectionResult`，
        没有任何 `*contract*` 模块，五个检测器各用各的形状。
        修复后（提交 A）：`detection_contract.py` 提供
        `DetectionStatus` / `DetectionResult` / `AnalysisStatus`，
        且 `ingest_pipeline` 真实导入并传播。
        """
        contract_files = sorted(
            p.relative_to(BACKEND).as_posix()
            for p in BACKEND.rglob("*.py")
            if "contract" in p.name.lower()
            and "tests" not in set(p.relative_to(BACKEND).parts)
        )
        assert contract_files == ["detection_contract.py"], contract_files

        import detection_contract as dc
        assert dc.CONTRACT_VERSION
        for name in ("DetectionResult", "AnalysisStatus", "combine_status",
                     "STATUS_DETECTED", "STATUS_NOT_DETECTED",
                     "STATUS_INCONCLUSIVE", "STATUS_ERROR", "STATUS_PARTIAL"):
            assert hasattr(dc, name), f"契约缺少 {name}"

        # 融合层必须真的用它，而不是只建一个文件
        pipeline_src = (BACKEND / "ingest_pipeline.py").read_text(encoding="utf-8")
        assert "from detection_contract import" in pipeline_src
        assert "AnalysisStatus.build" in pipeline_src

    def test_q14_2_sigma_failure_payload_differs_from_clean(self):
        """[FIXED] 'error' 与 'not_detected' 现在是两个不同状态。

        修复前：`empty_sigma()` 与真实无命中的 `detect_for_event()`
        在所有共有 key 上完全相等，且无任何契约字段。
        """
        clean = REAL_SIGMA.detect_for_event(dict(BENIGN_EVENT))
        failed = ip.empty_sigma()

        assert clean["status"] == "not_detected"
        assert failed["status"] == "not_detected"
        assert clean["error_code"] == failed["error_code"] == ""

        broken = ip.empty_sigma(status="error")
        assert broken["status"] == "error"
        assert broken["status"] != clean["status"], \
            "error 与 not_detected 仍然同形 —— P0-1 未修复"
        assert set(CONTRACT_FIELDS) & set(broken), \
            "错误载荷仍无契约字段"

    def test_q14_3_real_sigma_hit_carries_contract_fields(self):
        """[FIXED] 正向命中载荷携带契约字段。

        POSITIVE：规则引擎确实命中且确实报 critical。
        修复后：`status` / `error_code` / `detector_version` / `score` /
        `score_type` / `analysis_window` 至少有一部分出现在载荷上。
        """
        result = REAL_SIGMA.detect_for_event(dict(CRITICAL_SIGMA_EVENT))

        assert result["detected"] is True
        assert result["max_severity"] == "critical"
        assert result["status"] == "detected"
        assert len(result["hits"]) >= 1

        covered = set(CONTRACT_FIELDS) & set(result)
        assert covered >= {"status", "error_code"}, \
            f"载荷未覆盖契约字段: {sorted(result)}"
        assert result["error_message"] == ""      # 命中路径没有错误信息
        assert result["rules_failed"] == 0

    def test_q14_4_detect_marks_sigma_failure_as_error(self, monkeypatch):
        """[FIXED] 端到端：Sigma 引擎异常 → 载荷带 status='error'。

        修复前：落库载荷是 `empty_sigma()`，与真实干净事件逐字段相同。
        """
        monkeypatch.setattr(sd, "sigma_detector", _SigmaDown())

        log_data = dict(BENIGN_EVENT)
        result = _run(ip.detect(log_data))

        assert [e.detector for e in result.errors] == ["sigma"]
        assert result.sigma["detected"] is False
        assert result.sigma["status"] == "error", result.sigma["status"]

        clean = REAL_SIGMA.detect_for_event(dict(BENIGN_EVENT))
        assert result.sigma["status"] != clean["status"], \
            "失败载荷与干净载荷仍无法区分"

        assert log_data["_sigma"]["status"] == "error"
        assert log_data["_anomaly"]["analysis_complete"] is False
        assert log_data["_anomaly"]["analysis_status"] in ("partial", "error")

    def test_q14_5_anomaly_exception_is_marked_error_not_zero_score(self, monkeypatch):
        """[FIXED] 崩溃的引擎不得再以 0.0 分冒充「一次成功的阴性判断」。

        修复前：`empty_anomaly(reasons=['anomaly_error'])`，
        anomaly_score=0.0、is_anomaly=False，与「没发现异常」数值相同。
        现在报告带 `status='error'`，整体分析完整性为 False。
        """
        monkeypatch.setattr(ip, "anomaly_detector", _AnomalyDown())

        log_data = dict(BENIGN_EVENT)
        result = _run(ip.detect(log_data))

        assert [e.detector for e in result.errors] == ["anomaly"]
        assert result.anomaly.status == "error", result.anomaly.status
        assert result.anomaly.reasons == ["anomaly_error"]

        payload = log_data["_anomaly"]
        assert payload["analysis_complete"] is False
        assert payload["analysis_status"] in ("partial", "error")
        assert payload["detector_errors"], "失败明细未落库"
        err = payload["detector_errors"][0]
        assert err["detector"] == "anomaly"
        assert err["error_code"] and err["error_message"]
        assert err["status"] == "error"
        # 字段位齐全（整改方案 §二.3 验收 3 的载体）
        assert set(err) >= {"detector", "detector_version", "status",
                            "error_code", "error_message"}, sorted(err)

    def test_q14_5b_detector_version_and_phase_are_recorded(self, monkeypatch):
        """[FIXED] 验收标准 3：对任意单一检测器注入异常，
        融合层记录「哪个检测器、哪个版本、在哪个阶段失败」。
        """
        class _VersionedDown(_AnomalyDown):
            version = "anomaly-9.9.9"

        monkeypatch.setattr(ip, "anomaly_detector", _VersionedDown())
        log_data = dict(BENIGN_EVENT)
        _run(ip.detect(log_data))

        err = log_data["_anomaly"]["detector_errors"][0]
        assert err["detector"] == "anomaly"
        assert err["detector_version"] == "anomaly-9.9.9", err
        assert "detect" in err["error_message"], err["error_message"]
        assert "RuntimeError" in err["error_code"], err["error_code"]

        # Sigma 侧同样
        monkeypatch.setattr(sd, "sigma_detector", _SigmaDown())
        log_data2 = dict(BENIGN_EVENT)
        _run(ip.detect(log_data2))
        dets = {e["detector"]: e for e in log_data2["_anomaly"]["detector_errors"]}
        assert "sigma" in dets, sorted(dets)
        assert "detect" in dets["sigma"]["error_message"]

    def test_q14_6_error_report_differs_from_clean_in_structured_fields(
        self, monkeypatch
    ):
        """[FIXED] 「引擎宕机」与「干净」不再只靠一个无人读取的字符串区分。"""
        monkeypatch.setattr(ip, "anomaly_detector", _AnomalyStub(0.0))
        healthy = dict(BENIGN_EVENT)
        _run(ip.detect(healthy))

        monkeypatch.setattr(ip, "anomaly_detector", _AnomalyDown())
        broken = dict(BENIGN_EVENT)
        _run(ip.detect(broken))

        clean_payload = healthy["_anomaly"]
        error_payload = broken["_anomaly"]

        assert clean_payload["analysis_complete"] is True
        assert error_payload["analysis_complete"] is False
        assert error_payload["detector_status"]["anomaly"] == "error"
        assert clean_payload["detector_errors"] == []
        assert error_payload["detector_errors"], "失败明细为空"

    def test_q14_7_downstream_triage_refuses_to_close_unanalyzed(self, monkeypatch):
        """[FIXED] 下游准入不再把「未分析」等同于「干净」。

        修复前：`audit_triage.score_event()` 对「异常引擎宕机」和
        「确实干净」返回**完全相同**的决策 tier=P3 / lane=rule_close
        （文档定义为「噪声关闭，0 LLM」）。

        修复后：分析不完整 → 禁止 rule_close，改走 tools_only 并提优先级。
        """
        monkeypatch.setattr(ip, "anomaly_detector", _AnomalyStub(0.0))
        healthy = dict(BENIGN_EVENT)
        _run(ip.detect(healthy))

        monkeypatch.setattr(ip, "anomaly_detector", _AnomalyDown())
        broken = dict(BENIGN_EVENT)
        _run(ip.detect(broken))

        triage_clean = score_event(healthy, healthy["_anomaly"]["score"])
        triage_down = score_event(broken, broken["_anomaly"]["score"])

        assert triage_clean.to_dict() != triage_down.to_dict(), \
            "宕机与干净的下游决策仍然完全相同 —— P0-1 未修复"

        assert triage_clean.lane == "rule_close"
        assert triage_clean.analysis_complete is True

        assert triage_down.lane != "rule_close", \
            "分析不完整的事件仍被噪声关闭"
        assert triage_down.lane == "tools_only"
        assert triage_down.analysis_complete is False
        assert triage_down.analysis_status in ("partial", "error")
        assert triage_down.priority > triage_clean.priority, \
            "分析不完整没有提升优先级"
        assert any("analysis_incomplete" in r for r in triage_down.reasons)
        assert any("failed:anomaly" in r for r in triage_down.reasons)

    def test_q14_8_analysis_status_is_actually_consumed(self):
        """[FIXED] 完整性标记有了真实消费方。"""
        consumers = []
        for path in BACKEND.rglob("*.py"):
            rel = path.relative_to(BACKEND).as_posix()
            if rel.startswith("tests/") or "__pycache__" in rel:
                continue
            for lineno, line in enumerate(
                path.read_text(encoding="utf-8", errors="replace").splitlines(), 1
            ):
                if "analysis_complete" in line:
                    consumers.append("%s:%d" % (rel, lineno))
        assert "audit_triage.py" in " ".join(consumers), \
            f"audit_triage 不再消费 analysis_complete: {consumers}"
        assert len(consumers) >= 3, f"消费点过少: {consumers}"


class TestQ14OtherDetectors:
    def test_q14_9_zeroday_empty_report_is_unavailable_not_clean(self):
        """[FIXED] 零日检测现在有了「没结论」这个状态。

        修复前：`analyze(None)`、`analyze({})` 与「真实报告且分数为 0」
        三者返回逐字段相同的 dict，`verdict='clean'`、`score=0.0` ——
        「沙箱没跑起来」被当成「样本安全」。

        修复后（提交 B）：报告缺失 → `verdict='unavailable'`、`score=None`、
        `analyzed=False`，且 `is_negative` 为 False。
        """
        empty = behavior_analyzer.analyze(None).to_dict()
        blank = behavior_analyzer.analyze({}).to_dict()
        real_zero = behavior_analyzer.analyze(
            {"signatures": [], "network": {}, "behavior": {}, "info": {"score": 0}}
        ).to_dict()

        # 缺失报告不再是 clean
        assert empty["verdict"] == "unavailable", empty["verdict"]
        assert blank["verdict"] == "unavailable", blank["verdict"]
        assert empty["score"] is None, "缺失报告仍给出 0.0 分"
        assert empty["analyzed"] is False
        assert empty["is_negative"] is False

        # 真正分析过且得分为 0 的样本仍然是 clean —— 阳性结论未被破坏
        assert real_zero["verdict"] == "clean", real_zero["verdict"]
        assert real_zero["score"] == 0.0
        assert real_zero["analyzed"] is True
        assert real_zero["is_negative"] is True

        # 「没跑起来」与「确实干净」现在**可区分**
        assert empty != real_zero
        assert empty["verdict"] != real_zero["verdict"]
        assert set(CONTRACT_FIELDS) & set(empty) == {"score"}

    def test_q14_9b_zeroday_rejects_illegal_scores_instead_of_zeroing(self):
        """[FIXED] 非法评分不得静默变成 0 分。"""
        cases = {
            "negative": {"info": {"score": -1}},
            "string": {"info": {"score": "abc"}},
            "numeric_string": {"info": {"score": "8"}},
            "none": {"info": {"score": None}},
            "bool": {"info": {"score": True}},
        }
        for label, report in cases.items():
            r = behavior_analyzer.analyze(report).to_dict()
            assert r["input_errors"], f"{label} 未被记录为输入错误: {r}"
            assert r["score"] is None, f"{label} 静默变成了分数: {r['score']}"
            assert r["verdict"] in ("unavailable", "error"), \
                f"{label} 仍被判为 clean: {r['verdict']}"

        # 越界上界仍正确截断（不报错，方向安全）
        high = behavior_analyzer.analyze({"info": {"score": 11}}).to_dict()
        assert high["score"] == 1.0 and not high["input_errors"]
        # 合法边界
        for raw, exp in ((0, 0.0), (10, 1.0)):
            r = behavior_analyzer.analyze({"info": {"score": raw}}).to_dict()
            assert r["score"] == exp and not r["input_errors"]

    def test_q14_10_cross_correlator_db_error_returns_an_empty_list(self):
        """[PROVEN] DEFECT BEHAVIOUR FROZEN -- correlation outage == no chains.

        cross_correlator.correlate() swallows every exception
        (cross_correlator.py:135-138) and returns []. The caller
        (edr_adapter.py:258-261) only increments its 'correlations' counter
        inside 'if results:', so a permanently broken database looks exactly
        like a quiet network and raises no metric.

        EXPECTED (not achieved): a degraded/error result.
        ACTUAL [PROVEN]: returns [].
        """
        class _BoomSession:
            async def execute(self, *args, **kwargs):
                raise RuntimeError("db down")

        out = _run(CrossCorrelator().correlate(_BoomSession()))
        assert out == []


# ====================================================================
# Q15 -- final decision fusion
# ====================================================================


class TestQ15Fusion:
    def test_q15_1_fusion_constants_are_exact(self):
        """[PROVEN] Positive: pin the literal constants used by detect()."""
        assert ip._SIGMA_FLOORS == {
            "critical": 0.75,
            "high": 0.65,
            "medium": 0.55,
            "low": 0.45,
        }
        assert ip._SIGMA_FLOOR_DEFAULT == 0.55
        assert ip._SEV_MAP == {
            10: "info",
            30: "low",
            50: "medium",
            70: "high",
            90: "critical",
        }

    def test_q15_2_critical_sigma_hit_is_not_diluted_by_a_zero_anomaly(
        self, monkeypatch
    ):
        """[PROVEN] POSITIVE CONCLUSION -- the headline counterexample FAILS.

        The strongest dilution counterexample was constructed: a real
        critical Sigma hit (SIG-003 path_traversal) combined with an anomaly
        engine that reports 0.0 and 'not an anomaly'.

        EXPECTED IF DILUTED: a low / normal verdict.
        ACTUAL [PROVEN]: score is raised 0.0 -> 0.75, is_anomaly becomes
        True, and triage lands on P0 / llm_agent / priority 100.

        So no weighted average exists on this path; fusion is a monotonic
        severity floor.
        """
        monkeypatch.setattr(ip, "anomaly_detector", _AnomalyStub(0.0))

        log_data = dict(CRITICAL_SIGMA_EVENT)
        result = _run(ip.detect(log_data))

        assert result.sigma["detected"] is True
        assert result.sigma["max_severity"] == "critical"
        assert result.anomaly.anomaly_score == 0.75
        assert result.anomaly.is_anomaly is True
        assert result.anomaly.reasons == ["Sigma命中:path_traversal"]

        triage = score_event(log_data, 0.75)
        assert triage.tier == "P0"
        assert triage.lane == "llm_agent"
        assert triage.priority == 100

    @pytest.mark.parametrize("anomaly_score", [0.0, 0.25, 0.5, 0.74, 0.9, 1.0])
    def test_q15_3_fusion_is_a_monotonic_floor_never_an_average(
        self, monkeypatch, anomaly_score
    ):
        """[PROVEN] POSITIVE CONCLUSION -- unnormalised averaging does NOT exist.

        Drives the real detect() across the anomaly score range and asserts
        the result equals max(anomaly_score, 0.75) at every point. If a
        weighted average against a second (lower) signal existed, the result
        would sit strictly between the two inputs for some input.
        """
        monkeypatch.setattr(ip, "anomaly_detector", _AnomalyStub(anomaly_score))

        log_data = dict(CRITICAL_SIGMA_EVENT)
        result = _run(ip.detect(log_data))

        floor = ip._SIGMA_FLOORS["critical"]
        assert result.anomaly.anomaly_score == max(anomaly_score, floor)
        assert result.anomaly.is_anomaly is True

    def test_q15_4_unavailable_sigma_is_excluded_not_counted_as_zero(
        self, monkeypatch
    ):
        """[PROVEN] POSITIVE CONCLUSION -- missing detector is EXCLUDED.

        A Sigma engine that raises is NOT averaged in as 0.0. The anomaly
        verdict passes through completely untouched, which is the correct
        'exclude, do not zero' semantics.

        Note the flip side frozen in Q15-5: exclusion means the Sigma floor
        silently disappears, i.e. it fails OPEN rather than closed.
        """
        monkeypatch.setattr(ip, "anomaly_detector", _AnomalyStub(0.9))
        healthy = dict(BENIGN_EVENT)
        result_ok = _run(ip.detect(healthy))

        monkeypatch.setattr(sd, "sigma_detector", _SigmaDown())
        broken = dict(BENIGN_EVENT)
        result_down = _run(ip.detect(broken))

        assert result_ok.anomaly.anomaly_score == 0.9
        assert result_down.anomaly.anomaly_score == 0.9
        assert result_down.anomaly.is_anomaly is True
        assert [e.detector for e in result_down.errors] == ["sigma"]

    def test_q15_5_failed_sigma_no_longer_silently_closes_as_noise(
        self, monkeypatch
    ):
        """[FIXED] 管道不再 fail-open 到「噪声关闭」。

        修复前：同一条 path traversal 攻击事件，Sigma 健康时
        score=0.75 / triage P0/llm_agent；Sigma 宕机时 score=0.00 /
        triage **P3/rule_close**（零 LLM）—— 检测器故障把已确认的严重
        攻击降级成噪声。

        修复后：Sigma 宕机时分数确实为 0（我们确实不知道），
        但分析完整性为 False → 下游禁止 rule_close，改走 tools_only 并提优先级。
        """
        monkeypatch.setattr(ip, "anomaly_detector", _AnomalyStub(0.0))
        healthy = dict(CRITICAL_SIGMA_EVENT)
        result_ok = _run(ip.detect(healthy))

        monkeypatch.setattr(sd, "sigma_detector", _SigmaDown())
        down = dict(CRITICAL_SIGMA_EVENT)
        result_down = _run(ip.detect(down))

        # 健康路径不变（验收：不得破坏原本正确的行为）
        assert result_ok.anomaly.anomaly_score == 0.75
        assert result_ok.anomaly.is_anomaly is True
        triage_ok = score_event(healthy, 0.75)
        assert (triage_ok.tier, triage_ok.lane) == ("P0", "llm_agent")
        assert triage_ok.analysis_complete is True

        # 故障路径
        assert result_down.anomaly.anomaly_score == 0.0
        assert [e.detector for e in result_down.errors] == ["sigma"]
        assert result_down.analysis_complete is False
        assert result_down.analysis_status in ("partial", "error")
        assert result_down.can_close_as_negative is False

        triage_down = score_event(down, 0.0)
        assert triage_down.lane != "rule_close", \
            "检测器故障仍被噪声关闭 —— P0-1 未修复"
        assert triage_down.lane == "tools_only"
        assert triage_down.priority > 20, \
            f"故障事件优先级未提升: {triage_down.priority}"

    def test_q15_5b_critical_hit_plus_anomaly_failure_never_reaches_p3(
        self, monkeypatch
    ):
        """[FIXED] 整改方案 §二.3 验收标准 1。

        「Critical Sigma 命中 + 异常检测失败」不得从高危命中降级为 P3 阴性收口。
        """
        monkeypatch.setattr(ip, "anomaly_detector", _AnomalyDown())
        log_data = dict(CRITICAL_SIGMA_EVENT)
        result = _run(ip.detect(log_data))

        # Sigma 命中有效 → 下限抬升照常生效
        assert result.sigma["detected"] is True
        assert result.anomaly.anomaly_score == 0.75
        assert result.anomaly.is_anomaly is True
        # 但异常引擎故障被如实记录
        assert [e.detector for e in result.errors] == ["anomaly"]
        assert result.analysis_status == "partial"
        assert result.analysis_complete is False

        triage = score_event(log_data, result.anomaly.anomaly_score)
        assert triage.tier != "P3", f"降级成了 {triage.tier}"
        assert triage.lane == "llm_agent", triage.lane
        assert triage.skip_llm is False

    def test_q15_6_fused_confidence_is_a_max_not_an_average(self, monkeypatch):
        """[PROVEN] POSITIVE CONCLUSION -- audit_triage uses max().

        audit_triage._fused_confidence returns
        min(1.0, max(anomaly_score * 1.2, sigma_conf, event_confidence)).
        A weak anomaly score never pulls a strong Sigma signal down.
        """
        monkeypatch.setattr(ip, "anomaly_detector", _AnomalyStub(0.0))
        log_data = dict(CRITICAL_SIGMA_EVENT)
        _run(ip.detect(log_data))

        assert _fused_confidence(log_data, 0.0) == 0.85
        assert _fused_confidence(log_data, 0.75) == pytest.approx(0.9)

    def test_q15_7_unknown_max_severity_falls_back_to_the_default_floor(self):
        """[PROVEN] Observed edge behaviour of the severity -> floor map.

        The lookup lower-cases the key, so 'Critical'/'CRITICAL' resolve to
        0.75. Anything outside the four known levels (including the empty
        string and None) silently lands on _SIGMA_FLOOR_DEFAULT = 0.55,
        i.e. still above the 0.5 fast-path threshold.
        """
        for raw in ("critical", "Critical", "CRITICAL"):
            assert ip._SIGMA_FLOORS.get(raw.lower(), ip._SIGMA_FLOOR_DEFAULT) == 0.75
        for raw in ("", "informational", "unknown", None):
            assert (
                ip._SIGMA_FLOORS.get(str(raw or "").lower(), ip._SIGMA_FLOOR_DEFAULT)
                == 0.55
            )

    def test_q15_8_fastpath_cooldown_suppresses_a_repeat_critical_event(self):
        """[PROVEN] DEFECT BEHAVIOUR FROZEN -- strong signal dropped by dedup.

        ingest_pipeline.py:543-545 sets _fp_trigger = False whenever
        ingestor._fastpath_allow() returns False, i.e. when the same
        (src_ip | threat_type) pair already fired within
        FASTPATH_COOLDOWN_S (default 60.0s). A second, genuinely critical
        Sigma hit on the same key therefore never reaches the response
        engine at all -- there is no escalation for repeat criticals.

        This is deliberate dedup (a debug line is logged), so it is filed as
        a reliability/blast-radius concern rather than a detection gap.
        """
        from log_ingestion import log_ingestor

        log_ingestor._fastpath_cooldown.clear()
        key = "10.0.0.9|PATH_TRAVERSAL"

        assert log_ingestor._fastpath_cooldown_ttl == 60.0
        assert log_ingestor._fastpath_allow(key) is True
        assert log_ingestor._fastpath_allow(key) is False
        log_ingestor._fastpath_cooldown.clear()


class TestQ15FieldMatrix:
    def test_q15_9_contract_field_matrix_across_detectors(self):
        """[FIXED] 七个契约字段，逐检测器核对。

        修复前：五个检测器里只有一个带了清单里的字段，且只带 1/7；
        `status` / `error_code` / `detector_version` / `rule_version` /
        `analysis_window` 全局为零，异常分还叫 `anomaly_score`（与
        零日的 `score` 不同名，跨检测器数值不可比）。

        修复后：Sigma / 异常 / 零日 都带上了 status 与 error_code。
        """
        matrix = {}

        sigma_hit = REAL_SIGMA.detect_for_event(dict(CRITICAL_SIGMA_EVENT))["hits"][0]
        matrix["sigma.DetectionResult"] = set(sigma_hit)

        matrix["sigma.detect_for_event"] = set(
            REAL_SIGMA.detect_for_event(dict(CRITICAL_SIGMA_EVENT))
        )
        matrix["sigma.empty_sigma(error)"] = set(ip.empty_sigma(status="error"))

        report = _run(_AnomalyStub(0.42).analyze(dict(CRITICAL_SIGMA_EVENT)))
        matrix["anomaly.AnomalyReport"] = set(dataclasses.asdict(report))

        analysis = behavior_analyzer.analyze(
            {"signatures": [{"name": "creates_exe", "severity": 4}]}
        ).to_dict()
        matrix["zeroday.BehaviorAnalysis"] = set(analysis)
        assert analysis["verdict"] in ("suspicious", "malicious")

        expected_overlap = {
            "sigma.DetectionResult": set(),
            "sigma.detect_for_event": {"status", "error_code"},
            "sigma.empty_sigma(error)": {"status", "error_code"},
            "anomaly.AnomalyReport": {"status", "error_code", "analysis_window"},
            "zeroday.BehaviorAnalysis": {"score"},
        }
        for label, keys in matrix.items():
            assert set(CONTRACT_FIELDS) & keys == expected_overlap[label], (
                "%s contract-field overlap changed: %r"
                % (label, sorted(set(CONTRACT_FIELDS) & keys))
            )

        # 统一契约本身必须齐备（这是各检测器的目标形态）
        import detection_contract as dc
        dc_fields = set(dc.DetectionResult.__dataclass_fields__)
        assert set(CONTRACT_FIELDS) <= dc_fields, \
            f"统一契约缺少字段: {sorted(set(CONTRACT_FIELDS) - dc_fields)}"
        # 异常报告显式声明了契约字段名（便于融合层读取）
        assert "status" in matrix["anomaly.AnomalyReport"]
        assert "score" in matrix["zeroday.BehaviorAnalysis"]

        # Sanity: the probes above really did produce meaningful payloads.
        assert "severity" in matrix["sigma.DetectionResult"]
        assert "anomaly_score" in matrix["anomaly.AnomalyReport"]
        assert "verdict" in matrix["zeroday.BehaviorAnalysis"]
# ====================================================================
# Q16 -- single-rule SQL failure (partial) must reach the fusion layer
# ====================================================================

class TestQ16PartialRuleFailureReachesFusion:
    """Q16: a single failing rule (partial) must be visible at the FUSION layer.

    Remediation plan Sec.6 acceptance criteria:
      "a single rule's SQL execution failure being treated as hit=False ->
       record the rule execution error separately, mark the whole round
       partial or error, and must not return a complete negative"
      acceptance: "inject a single Critical rule execution exception --
       the system must track the error and prevent erroneous closure"

    Why Q14/Q15 are not enough: they all use "the engine raises" ->
    status=**error**. But "one rule failed while the rest of the engine kept
    running" is **partial** -- a different branch, never exercised
    end-to-end at the fusion layer. It is exactly where the Sec.9.10 fix
    lands: if the fusion layer does not honour `partial`, that fix is
    a no-op and the event still closes as a clean negative.
    """

    def test_q16_1_single_rule_failure_is_partial_and_blocks_clean_closure(
            self, monkeypatch):
        """[PROVEN] POSITIVE CONCLUSION -- partial reaches the fusion and blocks closure.

        The anomaly side is stubbed to a **clean negative** on purpose:
        then the failing rule is the *only* non-clean signal, so
        "can_close_as_negative is False" actually tests the rule failure
        instead of the anomaly detector's cold-start inconclusive.
        """
        monkeypatch.setattr(ip, "anomaly_detector", _AnomalyStub(0.0))
        det = sd.sigma_detector
        assert det._rules and det._compiled, \
            "前提守卫：需要至少一条已编译规则"
        crit = [m for m, _ in det._compiled if m.get("severity") == "critical"]
        meta = dict(crit[0] if crit else det._compiled[0][0])

        # 换成一条**必然报错**的 SQL（表不存在）
        original = det._snapshot
        broken_sql = "SELECT * FROM no_such_table_rule_exec_probe"
        det._snapshot = type(det._snapshot)(
            compiled=((meta, broken_sql),),
            rules=det._snapshot.rules,
            field_index=det._snapshot.field_index,
            conn=det._snapshot.conn,
            generation=det._snapshot.generation,
        )
        det._compiled = [(meta, broken_sql)]
        try:
            log_data = dict(BENIGN_EVENT)
            result = _run(ip.detect(log_data))
        finally:
            # 全局 detector 是共享的 —— 无论成败都要还原
            det._snapshot = original
            det._compiled = list(original.compiled)

        s = result.sigma
        # ① 引擎侧：partial，不是 not_detected
        assert s["status"] == "partial", s["status"]
        assert s["rules_failed"] == 1, s
        # ② 追踪到是哪条规则（§二.2 验收 3：哪个检测器/哪个版本/哪个阶段）
        assert s["status_errors"], s
        assert s["status_errors"][0]["rule_id"] == meta["rule_id"], s["status_errors"]
        # ③ 融合层：**不可**按阴性收口。
        #    这两条**故意排在状态断言之前** —— 最危险的注入
        #    「把 partial 当成 not_detected」会让融合状态直接变成 not_detected，
        #    若状态断言在前，报错就只会说「状态不对」，
        #    而真正要盯的那条（**错误被当成可收口**）根本轮不到触发。
        assert result.can_close_as_negative is False, (
            "单条规则执行失败却仍可按阴性收口 —— §六「不能返回完整阴性」未成立")
        assert result.analysis_complete is False, (
            "融合层把「单条规则失败」当成了完整分析")
        assert result.analysis_status == "partial", result.analysis_status
        # ④ 错误明细进到融合层的 detector_errors
        dets = {e["detector"]: e for e in log_data["_anomaly"]["detector_errors"]}
        assert "sigma" in dets, sorted(dets)
        assert dets["sigma"]["status"] == "partial", dets["sigma"]
        assert dets["sigma"]["error_code"].startswith("rule_exec_failed:"), dets["sigma"]
        assert dets["sigma"]["detector_version"], dets["sigma"]
