"""retry_policy: 临时/永久分类、指数退避、事件级结果。"""
import asyncio
import json

import pytest

from retry_policy import (
    KIND_PERMANENT,
    KIND_TRANSIENT,
    ORDER_STRICT,
    ORDER_UNORDERED,
    STATUS_DLQ,
    STATUS_FAILED,
    STATUS_RETRYING,
    STATUS_SUCCESS,
    EventOutcome,
    allows_key_overtake,
    backoff_delay,
    budget_exhausted,
    clamp_delay_to_budget,
    classify_error_text,
    classify_exception,
    count_statuses,
    gather_results,
    normalize_ordering,
    outcome_from_verdict,
)


def test_schema_and_decode_are_permanent():
    v = classify_exception(json.JSONDecodeError("x", "doc", 0))
    assert v.kind == KIND_PERMANENT
    assert v.retryable is False
    assert v.error_code == "decode_error"

    v = classify_exception(ValueError("schema 校验失败: missing field"))
    assert v.kind == KIND_PERMANENT
    assert v.error_code == "schema_invalid"

    v = classify_error_text("Schema 校验失败: foo", error_class="SchemaError")
    assert v.kind == KIND_PERMANENT
    assert v.retryable is False


def test_timeout_and_db_operational_are_transient():
    v = classify_exception(TimeoutError("downstream timeout"))
    assert v.kind == KIND_TRANSIENT
    assert v.retryable is True

    v = classify_exception(ConnectionError("broker down"))
    assert v.kind == KIND_TRANSIENT

    v = classify_exception(OSError("network unreachable"))
    assert v.kind == KIND_TRANSIENT


def test_unknown_defaults_to_bounded_transient():
    v = classify_exception(RuntimeError("weird"))
    assert v.kind == KIND_TRANSIENT
    assert v.retryable is True


def test_backoff_grows_and_caps(monkeypatch):
    rng = __import__("random").Random(0)
    d1 = backoff_delay(1, initial=1.0, multiplier=2.0, max_delay=30.0, jitter=0.0, rng=rng)
    d2 = backoff_delay(2, initial=1.0, multiplier=2.0, max_delay=30.0, jitter=0.0, rng=rng)
    d3 = backoff_delay(3, initial=1.0, multiplier=2.0, max_delay=30.0, jitter=0.0, rng=rng)
    d8 = backoff_delay(8, initial=1.0, multiplier=2.0, max_delay=30.0, jitter=0.0, rng=rng)
    assert d1 == 1.0
    assert d2 == 2.0
    assert d3 == 4.0
    assert d8 == 30.0
    jittered = backoff_delay(1, initial=1.0, jitter=0.2, rng=__import__("random").Random(1))
    assert 0.8 <= jittered <= 1.2


def test_budget_clamp():
    assert clamp_delay_to_budget(8.0, slept=55.0, budget=60.0) == 5.0
    assert clamp_delay_to_budget(8.0, slept=60.0, budget=60.0) == 0.0
    assert budget_exhausted(60.0, 60.0) is True
    assert budget_exhausted(12.0, 60.0) is False


def test_ordering_contract():
    assert normalize_ordering("strict") == ORDER_STRICT
    assert normalize_ordering("unordered") == ORDER_UNORDERED
    assert allows_key_overtake("strict") is False
    assert allows_key_overtake("unordered") is True


def test_event_outcome_committable():
    assert EventOutcome.success(event_id="a").committable() is True
    assert EventOutcome.dlq(error="schema").committable() is True
    assert EventOutcome.retrying(error="timeout").committable() is False
    assert EventOutcome.failed(error="bad").committable() is False


def test_outcome_from_verdict_and_counts():
    perm = classify_exception(ValueError("schema 校验失败"))
    o = outcome_from_verdict(perm, dlq_confirmed=True)
    assert o.status == STATUS_DLQ
    t = outcome_from_verdict(classify_exception(TimeoutError("t")))
    assert t.status == STATUS_RETRYING
    tallies = count_statuses([
        EventOutcome.success(),
        EventOutcome.success(),
        EventOutcome.retrying(),
        EventOutcome.failed(),
        EventOutcome.dlq(),
    ])
    assert tallies[STATUS_SUCCESS] == 2
    assert tallies[STATUS_RETRYING] == 1
    assert tallies[STATUS_FAILED] == 1
    assert tallies[STATUS_DLQ] == 1


@pytest.mark.asyncio
async def test_gather_results_keeps_per_item_exceptions():
    async def ok():
        return "ok"

    async def boom():
        raise TimeoutError("x")

    out = await gather_results(ok(), boom(), ok())
    assert out[0] == "ok"
    assert isinstance(out[1], TimeoutError)
    assert out[2] == "ok"
