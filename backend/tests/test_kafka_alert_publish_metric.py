# -*- coding: utf-8 -*-
"""告警发布的结果必须**可观测**（整改方案 §十一.1，§9.35）。

## 缺陷

`kafka_producer.publish_alert` 的四种失败模式**全部不可见**：

| 失败模式 | 修复前 |
|---|---|
| producer 未启动 | `return`，无痕迹 |
| schema 校验拒收 | `logger.warning` + `return`，无计数 |
| 盖章 / 加密抛异常 | `logger.warning` + `return`，无计数 |
| **broker 发送失败** | `_send_bounded` 返回 False，**返回值被丢掉** |

最后一条最隐蔽：`_send_bounded` 明确返回 bool，而 `publish_alert`
直接 `await` 它、**不接返回值**。

后果：**一条告警彻底消失**（没入队、没重试、没计数），
运维侧根本不知道有威胁。

## 不对称（本条最有说服力的证据）

原始事件路径 `produce_raw` 的同类拒收**是有计数的**
（`record_ingest("kafka", "validation_failed", reason="schema")`），
而**告警路径一个指标都没有** ——
也就是说：**丢告警比丢原始事件更难被发现**。
"""
from __future__ import annotations

import asyncio
import os
import sys

import pytest

os.environ.setdefault("SHARED_MEMORY_SKIP_DOTENV", "1")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core_metrics  # noqa: E402
import kafka_producer as kp  # noqa: E402
from core_metrics import (  # noqa: E402
    _KAFKA_ALERT_RESULT_ALLOW,
    record_kafka_alert_publish,
)
from prometheus_client import CollectorRegistry, Counter, generate_latest  # noqa: E402


@pytest.fixture()
def fresh_counter():
    reg = CollectorRegistry()
    ctr = Counter("test_kafka_alert_publish_total", "t", ["result"], registry=reg)
    old = core_metrics.KAFKA_ALERT_PUBLISH
    core_metrics.KAFKA_ALERT_PUBLISH = ctr
    try:
        yield reg
    finally:
        core_metrics.KAFKA_ALERT_PUBLISH = old


def _value(reg, result: str) -> float:
    for metric in reg.collect():
        for sample in metric.samples:
            if sample.name == "test_kafka_alert_publish_total" \
                    and sample.labels.get("result") == result:
                return float(sample.value)
    return 0.0


def _producer(monkeypatch, *, started=True, send_ok=True,
              schema_errors=None, boom=None):
    """构造一个可控的 producer（不发真 Kafka）。

    ⚠ `schema_registry.validate` **必须**总是被替换掉：
    真实校验器会要求 `alertId` 等字段，把最小 payload 拒掉 ——
    于是每次都走 schema 分支，根本到不了「发送成功/失败」那两条路
    （本轮第一版就栽在这里：ok 与 send_failed 两条用例都是绿的假象）。
    """
    p = kp.KafkaProducerWrapper()
    p._started = started
    p._producer = object()          # 非 None 即视为「已连接」

    async def _fake_send(topic, key, value, headers):
        return send_ok

    monkeypatch.setattr(p, "_send_bounded", _fake_send)

    errs = list(schema_errors) if schema_errors is not None else []
    monkeypatch.setattr(
        kp.schema_registry, "validate", lambda topic, body: list(errs))

    if boom is not None:
        def _raise(*a, **k):
            raise boom
        monkeypatch.setattr(kp, "stamp_identity", _raise)
    return p


class TestAlertPublishOutcomesAreCounted:
    def test_a_published_alert_is_counted_as_ok(self, monkeypatch, fresh_counter):
        p = _producer(monkeypatch, send_ok=True)
        asyncio.run(p.publish_alert({"src_ip": "1.2.3.4"}))
        assert _value(fresh_counter, "ok") == 1.0, "成功发布没有计数"

    def test_a_failed_send_is_counted_as_send_failed(self, monkeypatch, fresh_counter):
        """⚠ 核心性质：**broker 发送失败必须被看见**。

        修复前 `_send_bounded` 的返回值被直接丢掉 ——
        名额超时 / broker 报错时，调用方与指标都一无所知。
        """
        p = _producer(monkeypatch, send_ok=False)
        asyncio.run(p.publish_alert({"src_ip": "1.2.3.4"}))
        assert _value(fresh_counter, "send_failed") == 1.0, (
            "broker 发送失败没有计数 —— 告警就此消失")
        assert _value(fresh_counter, "ok") == 0.0, (
            "发送失败被记成了成功")

    def test_a_schema_rejection_is_counted(self, monkeypatch, fresh_counter):
        p = _producer(monkeypatch, schema_errors=["bad field"])
        asyncio.run(p.publish_alert({"src_ip": "1.2.3.4"}))
        assert _value(fresh_counter, "schema_rejected") == 1.0, (
            "schema 拒收没有计数")

    def test_an_exception_is_counted_as_error(self, monkeypatch, fresh_counter):
        p = _producer(monkeypatch, boom=RuntimeError("stamp failed"))
        asyncio.run(p.publish_alert({"src_ip": "1.2.3.4"}))
        assert _value(fresh_counter, "error") == 1.0, "异常没有计数"

    def test_a_not_started_producer_is_counted(self, monkeypatch, fresh_counter):
        p = _producer(monkeypatch, started=False)
        asyncio.run(p.publish_alert({"src_ip": "1.2.3.4"}))
        assert _value(fresh_counter, "not_started") == 1.0, (
            "producer 未启动时告警被丢弃，却没有计数")

    def test_the_four_failure_modes_are_distinguishable(self, monkeypatch, fresh_counter):
        """四种失败**必须互不相同** ——
        「未启动」「schema 拒收」「异常」「发送失败」的处置完全不同。

        ⚠ `boom` 那条会把 `stamp_identity` 替换成抛异常的版本，
        之后**必须复原** —— 否则下面「发送失败」那条也会走异常分支
        （被记成 error），本轮第一版就栽在这里。
        """
        asyncio.run(_producer(monkeypatch, started=False).publish_alert({}))
        asyncio.run(_producer(monkeypatch, schema_errors=["e"]).publish_alert({}))
        asyncio.run(_producer(monkeypatch, boom=RuntimeError("x")).publish_alert({}))
        monkeypatch.undo()
        asyncio.run(_producer(monkeypatch, send_ok=False).publish_alert({}))
        for result in ("not_started", "schema_rejected", "error", "send_failed"):
            assert _value(fresh_counter, result) == 1.0, (
                f"{result} 的计数不对：{_value(fresh_counter, result)}")


class TestTheMetricIsReallyVisible:
    def test_the_counter_appears_in_the_metrics_text(self):
        record_kafka_alert_publish("send_failed")
        text = generate_latest().decode("utf-8")
        assert "soc_kafka_alert_publish_total" in text, (
            "/metrics 里没有 soc_kafka_alert_publish_total")
        assert 'result="send_failed"' in text

    def test_the_label_allowlist_has_exactly_five_values(self):
        assert _KAFKA_ALERT_RESULT_ALLOW == {
            "ok", "not_started", "schema_rejected", "error", "send_failed",
        }, f"白名单变了：{sorted(_KAFKA_ALERT_RESULT_ALLOW)}"

    def test_an_unknown_result_is_clamped_to_a_failure(self):
        from core_metrics import clamp_label
        assert clamp_label("weird", _KAFKA_ALERT_RESULT_ALLOW, "error") == "error"


if __name__ == "__main__":       # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
