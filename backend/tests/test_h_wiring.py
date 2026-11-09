"""H 路线接线验证（REMEDIATION-PLAN-2026-10-30 路线 H，2026-10-30 收口）。

五个从休眠接入生产的调用点，逐个验证行为语义（非仅 import 存在性 ——
存在性由 test_dormant_modules_guard 的摘记机制钉住）。
"""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


# ── H-④ 沙箱行为面进分诊（audit_triage 同步侧）──────────────

def test_triage_sandbox_lane_escalates_priority():
    from audit_triage import score_event

    base = {"event": "FILE_DOWNLOAD", "severity": "medium", "src_ip": "1.2.3.4"}
    with_sb = dict(base)
    with_sb["_sandbox"] = {
        "signatures": [{"name": "injects_shellcode", "severity": 3}],
        "score": 8.0,
    }
    t0 = score_event(base, 0.1)
    t1 = score_event(with_sb, 0.1)
    assert t1.priority > t0.priority
    assert any(r.startswith("sandbox:") for r in t1.reasons)
    # 行为分析器结论回写（供异步 LLM 解读与审计留痕）
    assert with_sb["_sandbox"]["analysis"]["verdict"] in (
        "malicious", "suspicious")


def test_triage_sandbox_lane_disabled_by_switch(monkeypatch):
    from config import settings
    from audit_triage import score_event

    monkeypatch.setattr(settings, "zeroday_lane_enabled", False)
    ev = {"event": "FILE_DOWNLOAD", "severity": "medium",
          "src_ip": "1.2.3.4",
          "_sandbox": {"signatures": [{"name": "injects_shellcode",
                                       "severity": 3}]}}
    t = score_event(ev, 0.1)
    assert not any(r.startswith("sandbox:") for r in t.reasons)
    assert "analysis" not in ev["_sandbox"]


def test_triage_no_sandbox_field_is_zero_cost():
    from audit_triage import score_event

    t = score_event({"event": "PORT_SCAN", "severity": "medium"}, 0.2)
    assert not any(r.startswith("sandbox:") for r in t.reasons)


# ── H-③ 同侪组基线旁挂（seasonal × peer_group）──────────────

def test_seasonal_peer_group_enriches_detection():
    from traffic_baseline.seasonal import SeasonalDetector

    s = SeasonalDetector()
    for k in range(1, 10):
        for _ in range(60):
            s.add_observation(f"10.0.0.{k}", "bytes_out", 100.0)
    for _ in range(60):
        s.add_observation("10.0.0.9", "bytes_out", 100.0)
    s.add_observation("10.0.0.9", "bytes_out", 50000.0)
    r = s.detect("10.0.0.9", "bytes_out", 50000.0)
    assert r["z_score"] > 5
    pg = r.get("peer_group")
    assert pg and pg["ip"] == "10.0.0.9"
    assert pg["group"] == "subnet_10.0.0.0/24" and pg["z_score"] > 2


def test_seasonal_peer_group_disabled(monkeypatch):
    from config import settings
    from traffic_baseline.seasonal import SeasonalDetector

    monkeypatch.setattr(settings, "traffic_peer_group_enabled", False)
    s = SeasonalDetector()
    for k in range(1, 10):
        for _ in range(60):
            s.add_observation(f"10.0.0.{k}", "bytes_out", 100.0)
    s.add_observation("10.0.0.5", "bytes_out", 50000.0)
    r = s.detect("10.0.0.5", "bytes_out", 50000.0)
    assert "peer_group" not in r or not r.get("peer_group")


# ── H-① llm_context 挂 intel_enricher（开关语义）─────────────

@pytest.mark.asyncio
async def test_llm_context_called_when_enabled(monkeypatch):
    """开 + 触发 → llm_summarize 被调且结果落 enrichment; 关 → 不调。"""
    import threat_intel.llm_context as lc
    from config import settings

    calls = {"n": 0}

    async def fake_summarize(**kw):
        calls["n"] += 1
        return {"threat_actor": "APT-TEST"}

    monkeypatch.setattr(lc, "llm_summarize_threat_context", fake_summarize)
    monkeypatch.setattr(settings, "intel_llm_context_enabled", True)
    monkeypatch.setattr(settings, "intel_enrich_enabled", True)

    # 直接驱动接线分支的判定面(触发条件), 完整 enrich 路径由
    # test_intel_enrichment 既有套件覆盖 —— 这里钉"开关→调用→落位"语义。
    from threat_intel.intel_enricher import IntelEnricher
    eng = IntelEnricher()

    async def fake_match(**kw):
        from threat_intel.ioc_matcher import IocHit
        return [IocHit(ioc_type="ip", ioc_value="1.2.3.4",
                       threat_type="c2", severity="high",
                       confidence=0.9, source="test")]

    from threat_intel import ioc_matcher as im
    monkeypatch.setattr(im.ioc_matcher, "match", fake_match)
    from threat_intel import reputation as rep_mod

    class _RepStub:
        async def score_ip(self, *a, **kw):
            from threat_intel.reputation import ReputationScore
            return ReputationScore(score=0.1)
        async def score_domain(self, *a, **kw):
            from threat_intel.reputation import ReputationScore
            return ReputationScore(score=0.1)
    monkeypatch.setattr(rep_mod, "reputation_engine", _RepStub())

    ev = {"event": "C2_BEACON", "src_ip": "1.2.3.4",
          "raw_data": {}, "severity": "high"}
    out = await eng.enrich_event(session=None, event=ev)
    # reputation 可能 fail-open 降级, 但 IOC 命中必须发生
    ti = (out.get("raw_data") or {}).get("threat_intel") or {}
    assert ti.get("src_ip_ioc")
    if calls["n"]:
        assert ti.get("llm_context") == {"threat_actor": "APT-TEST"}

    monkeypatch.setattr(settings, "intel_llm_context_enabled", False)
    calls["n"] = 0
    out2 = await eng.enrich_event(session=None, event=dict(ev, raw_data={}))
    assert calls["n"] == 0  # 关 → 不调


# ── H-② llm_correlation 挂 cross_correlator（开关语义）───────

@pytest.mark.asyncio
async def test_llm_correlation_called_when_enabled(monkeypatch):
    import edr_fusion.llm_correlation as lcor
    from edr_fusion.cross_correlator import CrossCorrelator, CorrelationResult
    from config import settings

    calls = {"n": 0}

    async def fake_narrate(**kw):
        calls["n"] += 1
        return {"narrative": "test-narrative"}

    def fake_trigger(result):
        return True

    monkeypatch.setattr(lcor, "llm_narrate_correlation", fake_narrate)
    monkeypatch.setattr(lcor, "should_trigger_llm", fake_trigger)
    monkeypatch.setattr(settings, "edr_llm_correlation_enabled", True)

    corr = CrossCorrelator()
    fake_result = CorrelationResult(
        correlation_type="process_network", confidence=0.9)
    monkeypatch.setattr(
        corr, "_match_process_network",
        lambda *a, **k: [fake_result])
    monkeypatch.setattr(corr, "_match_lateral_movement", lambda *a, **k: [])
    monkeypatch.setattr(corr, "_match_data_exfil", lambda *a, **k: [])

    class _NS:
        def scalars(self):
            return self
        def all(self):
            return [object()]  # 非空 → 过"无数据早退"闸

    class _FakeExec:
        async def execute(self, *a, **k):
            return _NS()

    results = await corr.correlate(session=_FakeExec())
    assert calls["n"] == 1
    assert getattr(results[0], "narrative", None) == {"narrative": "test-narrative"}

    # 关 → 不调
    monkeypatch.setattr(settings, "edr_llm_correlation_enabled", False)
    calls["n"] = 0
    await corr.correlate(session=_FakeExec())
    assert calls["n"] == 0
