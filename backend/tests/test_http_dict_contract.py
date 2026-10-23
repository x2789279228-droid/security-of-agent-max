# -*- coding: utf-8 -*-
"""整改方案 §十三「全量回归」行的回归守卫：HTTP 兼容载荷的键集合契约。

## 为什么有这条守卫

整改方案 §十三「全量回归」行要求：

> 全量测试通过，并且原有测试没有通过删除断言或放宽安全要求来人为变绿。

本文件对应的是「**放宽断言**」这一类。

`tests/test_ingest_pipeline.py::test_run_one_return_keys_match_facade`
原先断言的是**精确键集合**：

    assert set(http_dict.keys()) == {
        "status", "event_id", "event_type", "severity", "anomaly", "sigma",
    }

后来被改成了子集断言：

    assert {…}.issubset(http_dict.keys())

子集断言**丢掉了「不得出现意外键」这一条** ——
载荷里悄悄多出 `detect_ms`（内部耗时）、`error_class`（内部异常类）
之类字段时，子集断言照样绿。

而 `RunResult` 内部有 10 个字段
（`detect_ms` / `persist_ms` / `dispatch_ms` / `detector_errors` /
`error_class` / `error_code` / `idempotent` / `process_status` /
`retryable` / `error`），其中 **7 个本就不该**出现在 HTTP 兼容载荷里。
键集合契约就是拦住这件事的那道闸。

## 判据为什么这样写

* **精确等式，不是子集** —— 要守的就是「不多不少」。
* **逐形态钉** —— `as_http_dict()` 的键集合是**条件性**的
  （`eventId` 非空才有；`process_status != "success"` 才有
  `process_status` / `retryable` / `error`），
  所以不能只钉一种形态，否则另一种形态的回归无人看管。
* **前提守卫** —— 断言三种形态的键集合**互不相同**。
  少了这条，某天有人把条件判断删成「总是全给」时，
  「精确等式」会因为期望值没跟着改而绿 ——
  这正是「守卫绿不等于守卫有效」的形态之一。
* **不走数据库** —— 本文件只钉 `as_http_dict()` 这个纯函数，
  真实 `run_one` 路径上的同一契约由
  `tests/test_ingest_pipeline.py::test_run_one_return_keys_match_facade` 负责。
  两者合起来才是完整的：一个是契约本身，一个是契约的真实消费路径。
"""
import pytest

from ingest_pipeline import RunResult

# ── 恒定出现的键（任何形态都有） ────────────────────────────────────
BASE_KEYS = {"status", "event_id", "event_type", "severity", "anomaly", "sigma"}

# ── 只在特定条件下出现的键 ──────────────────────────────────────────
#   eventId          : 业务稳定 ID 非空时
#   process_status   : 业务结果不是 success 时
#   retryable        : 同上（与 process_status 同时出现）
#   error            : 同上，且 error 非空
CONDITIONAL_KEYS = {"eventId", "process_status", "retryable", "error"}

# ── 绝不该出现在 HTTP 兼容载荷里的内部字段 ──────────────────────────
INTERNAL_ONLY_KEYS = {
    "detect_ms", "persist_ms", "dispatch_ms", "detector_errors",
    "error_class", "error_code", "idempotent",
}


def _result(**over) -> RunResult:
    """一个最小可用的 RunResult（成功路径）。"""
    base = dict(
        status="review_queued",
        event_id=42,
        event_type="BRUTE_FORCE",
        severity="high",
        anomaly={"score": 0.0, "is_anomaly": False, "reasons": []},
        sigma={"detected": False},
    )
    base.update(over)
    return RunResult(**base)


class TestHttpDictKeySetContract:
    """`as_http_dict()` 的精确键集合契约。"""

    def test_success_without_event_id_has_exactly_the_base_keys(self):
        body = _result().as_http_dict()
        assert set(body.keys()) == BASE_KEYS, (
            f"成功路径的键集合变了：多出 {set(body) - BASE_KEYS}，"
            f"少了 {BASE_KEYS - set(body)}")

    def test_success_with_event_id_adds_exactly_one_key(self):
        body = _result(eventId="p1g-1").as_http_dict()
        assert set(body.keys()) == BASE_KEYS | {"eventId"}, (
            f"带 eventId 的成功路径键集合不对：{sorted(body)}")
        assert body["eventId"] == "p1g-1"

    def test_empty_event_id_is_omitted_not_emitted_as_blank(self):
        """空串 eventId 不该进载荷 —— 进了的话下游会收到一个「有 ID」的假象。"""
        body = _result(eventId="").as_http_dict()
        assert set(body.keys()) == BASE_KEYS, (
            f"空 eventId 不该出现在载荷里：{sorted(body)}")

    def test_failure_path_adds_exactly_process_status_retryable_and_error(self):
        body = _result(process_status="retrying", retryable=True,
                       error="db timeout").as_http_dict()
        assert set(body.keys()) == BASE_KEYS | {
            "process_status", "retryable", "error"}, (
            f"失败路径的键集合不对：{sorted(body)}")
        assert body["process_status"] == "retrying"
        assert body["retryable"] is True
        assert body["error"] == "db timeout"

    def test_failure_path_without_error_text_omits_the_error_key(self):
        """`error` 只在非空时出现 —— 空串进载荷等于宣告「有错误但没内容」。"""
        body = _result(process_status="failed", retryable=False, error="").as_http_dict()
        assert set(body.keys()) == BASE_KEYS | {"process_status", "retryable"}, (
            f"空 error 不该进载荷：{sorted(body)}")

    def test_success_process_status_is_never_emitted(self):
        """`process_status == "success"` 是默认值，不该出现在载荷里。"""
        body = _result(process_status="success").as_http_dict()
        assert "process_status" not in body, (
            "success 是默认值，出现在载荷里会让下游以为出了状态变化")

    def test_internal_only_fields_never_leak(self):
        """内部字段一个都不该进 HTTP 载荷。

        `detect_ms` / `error_class` 这些是给内部日志和指标用的，
        进了 HTTP 载荷就等于把内部实现细节变成了对外契约 ——
        一旦有人开始依赖它们，再想收回来就是破坏性变更。
        """
        body = _result(
            detect_ms=12.5, persist_ms=3.0, dispatch_ms=1.5,
            detector_errors=["sigma boom"], error_class="OperationalError",
            error_code="db_operational", idempotent=True,
        ).as_http_dict()
        leaked = INTERNAL_ONLY_KEYS & set(body.keys())
        assert not leaked, f"内部字段泄漏到 HTTP 载荷：{sorted(leaked)}"


class TestGuardIsNotVacuous:
    """前提守卫：这个守卫必须真的能区分东西。"""

    def test_the_three_shapes_have_different_key_sets(self):
        """三种形态的键集合必须互不相同。

        少了这条，某天有人把 `as_http_dict()` 里的条件判断删成
        「总是把所有字段都塞进去」，而期望值又没跟着改 ——
        「精确等式」会照样绿，因为期望值和实际值会一起变。
        这条断言让「守卫和被守卫的对象一起漂」这件事露出来。
        """
        a = set(_result().as_http_dict().keys())
        b = set(_result(eventId="p1g-1").as_http_dict().keys())
        c = set(_result(eventId="p1g-1", process_status="retrying",
                        retryable=True, error="db timeout").as_http_dict().keys())
        assert a != b, "有无 eventId 的键集合竟相同 —— 条件判断形同虚设"
        assert b != c, "成功与失败的键集合竟相同 —— process_status 分支没生效"
        assert a != c
        assert len(a) == 6 and len(b) == 7 and len(c) == 10, (
            f"形态规模变了：{len(a)}/{len(b)}/{len(c)}")

    def test_the_guard_detects_an_extra_key(self):
        """守卫自己得能红：往载荷里塞一个意外键，精确等式必须抓住它。"""
        good = _result().as_http_dict()
        assert set(good.keys()) == BASE_KEYS
        tampered = dict(good)
        tampered["surprise"] = 1
        assert set(tampered.keys()) != BASE_KEYS, (
            "守卫对多出来的键无感 —— 它守的不是「不多不少」")

    def test_the_guard_detects_a_missing_key(self):
        """守卫自己也得能红：少一个键同样要被抓到。"""
        good = _result().as_http_dict()
        tampered = {k: v for k, v in good.items() if k != "sigma"}
        assert set(tampered.keys()) != BASE_KEYS, (
            "守卫对少掉的键无感 —— 它守的不是「不多不少」")


@pytest.mark.parametrize("process_status,expect_extra", [
    ("success", set()),
    ("retrying", {"process_status", "retryable"}),
    ("failed", {"process_status", "retryable"}),
    ("dlq", {"process_status", "retryable"}),
])
def test_every_process_status_expands_to_the_documented_keys(process_status, expect_extra):
    """每种业务结果都对应**一组已登记的**额外键。

    新增一种 `process_status` 时，这条会要求把它的键集合登记下来 ——
    而不是让它悄悄带出别的字段。
    """
    body = _result(process_status=process_status, error="x").as_http_dict()
    expected = BASE_KEYS | expect_extra
    if process_status != "success":
        expected |= {"error"}      # error 非空时一定出现
    assert set(body.keys()) == expected, (
        f"process_status={process_status} 的键集合未登记：{sorted(body)}")
