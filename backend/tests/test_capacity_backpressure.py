"""Wave 2-1 复合背压信号（PERF-OPT-PLAN-2026-10-26）。

验收口径：
  1. 准入闸门(admit_http)绑真实瓶颈 —— Kafka lag / PQ 深度过载必须拒绝；
  2. Kafka 拉取暂停(kafka_fetch_paused)**仍只看**处理队列 —— 停拉会加深
     lag，lag 信号只用于准入，这是 2-1 的红线；
  3. lag 比信号的容量未标定(kafka_consumption_eps=0)时恒 0 ——
     不许用拍脑袋阈值触发过载拒绝；
  4. 复合信号沿用高/低水位滞回（高闩低开，中间保持）。
"""
import pytest


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    import capacity
    from config import settings

    capacity.reset_gates()
    monkeypatch.setattr(settings, "audit_queue_high_watermark", 0.8)
    monkeypatch.setattr(settings, "audit_queue_low_watermark", 0.5)
    yield
    capacity.reset_gates()


def _set_ratios(monkeypatch, queue: float, lag: float, pq: float):
    import capacity

    monkeypatch.setattr(capacity, "audit_queue_ratio", lambda: queue)
    monkeypatch.setattr(capacity, "kafka_lag_ratio", lambda: lag)
    monkeypatch.setattr(capacity, "pq_depth_ratio", lambda: pq)
    return capacity


def test_lag_trips_admission_but_not_fetch_pause(monkeypatch):
    """lag 过载 → 准入拒绝(原因含 kafka_lag)，但拉取不停。"""
    capacity = _set_ratios(monkeypatch, queue=0.1, lag=0.95, pq=0.0)

    assert capacity.note_pressure() is True
    assert "kafka_lag" in capacity._pressure_reasons
    # 红线：停拉会加深 lag —— 拉取暂停不看 lag
    assert capacity.kafka_fetch_paused() is False


@pytest.mark.asyncio
async def test_queue_only_overload_keeps_legacy_reason(monkeypatch):
    """只有队列信号过载 → reason 保持旧字符串 audit_queue_high_watermark（API 兼容）。"""
    from capacity import AdmissionDenied

    capacity = _set_ratios(monkeypatch, queue=0.99, lag=0.0, pq=0.0)
    capacity.note_pressure()

    with pytest.raises(AdmissionDenied) as ei:
        await capacity.admit_http(direct=False)
    assert ei.value.reason == "audit_queue_high_watermark"


@pytest.mark.asyncio
async def test_admission_denied_reason_names_the_signal(monkeypatch):
    from capacity import AdmissionDenied

    capacity = _set_ratios(monkeypatch, queue=0.1, lag=0.95, pq=0.0)
    capacity.note_pressure()

    with pytest.raises(AdmissionDenied) as ei:
        await capacity.admit_http(direct=False)
    assert "kafka_lag" in ei.value.reason
    assert ei.value.reason.startswith("backpressure:")


@pytest.mark.asyncio
async def test_pq_depth_alone_denies_admission(monkeypatch):
    from capacity import AdmissionDenied

    capacity = _set_ratios(monkeypatch, queue=0.1, lag=0.0, pq=0.95)
    capacity.note_pressure()

    with pytest.raises(AdmissionDenied) as ei:
        await capacity.admit_http(direct=True)
    assert "audit_pq" in ei.value.reason


def test_composite_hysteresis_latches(monkeypatch):
    """高闩（0.95）→ 中间带保持（0.7）→ 低开（0.4）→ 中间带保持。"""
    capacity = _set_ratios(monkeypatch, queue=0.0, lag=0.0, pq=0.0)

    # lag 0.95 → 闩上
    _set_ratios(monkeypatch, queue=0.0, lag=0.95, pq=0.0)
    assert capacity.note_pressure() is True
    # 0.7 在 (0.5, 0.8) 中间带 → 保持闩上
    _set_ratios(monkeypatch, queue=0.0, lag=0.7, pq=0.0)
    assert capacity.note_pressure() is True
    # 0.4 ≤ 低水位 → 打开
    _set_ratios(monkeypatch, queue=0.0, lag=0.4, pq=0.0)
    assert capacity.note_pressure() is False
    # 0.7 中间带 → 保持打开
    _set_ratios(monkeypatch, queue=0.0, lag=0.7, pq=0.0)
    assert capacity.note_pressure() is False


def test_lag_ratio_disabled_until_calibrated(monkeypatch):
    """kafka_consumption_eps=0（未标定）→ lag 比恒 0，不论 lag 多大。"""
    import core_metrics
    from config import settings

    from capacity import kafka_lag_ratio

    core_metrics._KAFKA_LAG_STATE.clear()
    core_metrics.set_kafka_lag("security-events-ingest", 12_216)

    monkeypatch.setattr(settings, "kafka_consumption_eps", 0)
    assert kafka_lag_ratio() == 0.0

    # 标定后：eps=10、允许积压 60s → 阈值 600 条；lag 12216 → 比 20.36
    monkeypatch.setattr(settings, "kafka_consumption_eps", 10)
    monkeypatch.setattr(settings, "kafka_lag_allowed_backlog_s", 60)
    assert kafka_lag_ratio() == pytest.approx(12_216 / 600)

    core_metrics._KAFKA_LAG_STATE.clear()


def test_pq_ratio_reads_snapshot(monkeypatch):
    """深度比 = pq_depth_snapshot / audit_pq_capacity，封顶 1.0。"""
    from config import settings

    import audit_pq
    from capacity import pq_depth_ratio

    monkeypatch.setattr(settings, "audit_pq_capacity", 2000)
    monkeypatch.setattr(audit_pq, "_DEPTH_CACHE", {"v": 1500})
    assert pq_depth_ratio() == pytest.approx(0.75)

    monkeypatch.setattr(audit_pq, "_DEPTH_CACHE", {"v": 99_999})
    assert pq_depth_ratio() == 1.0


def test_snapshot_exposes_all_three_ratios(monkeypatch):
    """capacity.snapshot() 暴露三路比值与触发原因 —— 观测口径与闸门一致。"""
    capacity = _set_ratios(monkeypatch, queue=0.2, lag=0.3, pq=0.4)
    snap = capacity.snapshot()
    assert snap["audit_queue_ratio"] == pytest.approx(0.2)
    assert snap["kafka_lag_ratio"] == pytest.approx(0.3)
    assert snap["pq_depth_ratio"] == pytest.approx(0.4)
    assert snap["pressure"] is False
    assert snap["pressure_reasons"] == []
