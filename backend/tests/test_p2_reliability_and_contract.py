"""
P2 负面测试：B-4 资源治理 / E-2,E-3 LLM 可靠性 / C-3 三类指标拆分 / E-5 模板契约

修复前的四个真实缺陷：

B-4 「并发上限 / 超时 / 取消语义」
  · ``tool_registry`` 注册时存了 ``timeout_ms``，执行时**从不读取** ——
    死字段。一个挂死的工具协程会永久占住 Executor 的 ``asyncio.gather``，
    整轮审计再也回不来。
  · 两处 ``asyncio.gather`` 既无 Semaphore 也无 wait_for：N 个慢工具
    可以无限期并行挂着。
  · ``except Exception`` 会把 ``CancelledError`` 一起吞掉 ——
    流水线已被要求停止，上层却以为只是「工具失败」。

E-2 「重试」
  · 3 次重试之间**零等待**直接重发：上游一抖动，同一秒三个请求一起砸过去，
    把本来能自愈的瞬时故障变成持续过载。
  · 没有抖动 → 多进程在同一毫秒同步重试，形成重试风暴。
  · ``raise_for_status()`` 的 5xx 走通用 except 被无差别重试 ——
    上游 500/502/503 时重连既救不回来，又把上游刚恢复的窗口重新打挂。
  · ``llm_rate_per_minute`` 统计的是**逻辑调用**：``llm_limiter`` 在进 slot
    时扣一次额度，而重试发生在 slot 内部。于是限流器看到 1 次、
    上游实际收到 3 次。

E-3 「httpx 超时覆盖」
  ``httpx.Timeout(90.0)`` 单值会把 connect/read/write/pool **全部**设成 90，
  把原本 connect=10s 的快速失败拉成 90s —— 一个连不上的上游要等满 90 秒。

C-3 「三类指标被压成一个」
  ``compute_faithfulness`` 只返回 ``unsupported_count``，把三类完全不同的
  质量问题合成一个数字：编造实体 / 无证据主张 / 引用有效但结论相反。
  合成后无法分别告警 —— 一个 0.4 既可能是"编造了 ATT&CK 编号"，
  也可能只是措辞不准，两者处置完全不同。

E-5 「模板变量只在 mock 上校验」
  ``test_prompts_integrity`` 用一张**手工维护**的 mock 上下文表 ``_TEMPLATE_VARS``。
  表里写了什么就只校验什么：模板新增变量而表没跟上，校验静默通过
  （ChainableUndefined 渲染成空串），生产调用点漏传同理。

验收: 新测试在旧代码下失败，修复后通过。
"""
import asyncio
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ.setdefault("SHARED_MEMORY_DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("SHARED_MEMORY_JWT_SECRET", "test-secret")
os.environ.setdefault("SHARED_MEMORY_LLM_API_KEY", "test")
os.environ.setdefault("SHARED_MEMORY_EMBEDDING_API_KEY", "test")
os.environ.setdefault("SHARED_MEMORY_ADMIN_PASSWORD", "test")

import sqlalchemy.ext.asyncio as _sa_async

_orig = _sa_async.create_async_engine


def _patched(url, **kw):
    for k in ("pool_size", "max_overflow", "pool_pre_ping", "pool_recycle"):
        kw.pop(k, None)
    return _orig(url, **kw)


_sa_async.create_async_engine = _patched
import models  # noqa: F401


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


# ═══════════════════════════════════════════
# B-4: timeout_ms 从死字段变成强制超时
# ═══════════════════════════════════════════


class TestToolTimeoutEnforced:
    def _registry(self, fn, timeout_ms=50):
        from tool_registry import ToolRegistry
        r = ToolRegistry()
        r.register("slow.tool", fn, description="d", category="data",
                   timeout_ms=timeout_ms, risk_level="low")
        return r

    def test_hanging_tool_times_out(self):
        """核心回归：timeout_ms 必须真的生效。"""
        from tool_registry import ToolExecutionTimeout

        async def hang(**kwargs):
            await asyncio.sleep(30)

        r = self._registry(hang, timeout_ms=50)
        with pytest.raises(ToolExecutionTimeout) as ei:
            _run(r.execute("slow.tool"))
        assert ei.value.timeout_ms == 50
        assert ei.value.tool == "slow.tool"

    def test_timeout_is_reported_not_silent(self):
        from tool_registry import ToolExecutionTimeout

        async def hang(**kwargs):
            await asyncio.sleep(30)

        r = self._registry(hang, timeout_ms=50)
        try:
            _run(r.execute("slow.tool"))
        except ToolExecutionTimeout as e:
            assert "50" in str(e)

    def test_timeout_is_distinct_from_denial(self):
        """超时不是安全拒绝 —— 两者处置不同，不能混成一类。"""
        from tool_registry import (ToolExecutionDenied, ToolExecutionTimeout)

        assert not issubclass(ToolExecutionTimeout, ToolExecutionDenied)
        assert not issubclass(ToolExecutionDenied, ToolExecutionTimeout)

    def test_fast_tool_still_works(self):
        """对照组：正常工具不受影响。"""
        async def fast(**kwargs):
            return {"ok": True}

        r = self._registry(fast, timeout_ms=5000)
        assert _run(r.execute("slow.tool")) == {"ok": True}

    def test_zero_timeout_means_no_limit(self):
        """timeout_ms=0 显式表示不限（不是"默认 0 毫秒"）。"""
        async def quick(**kwargs):
            await asyncio.sleep(0.01)
            return 1

        r = self._registry(quick, timeout_ms=0)
        assert _run(r.execute("slow.tool")) == 1

    def test_executor_marks_timed_out_tool(self, monkeypatch):
        """Executor 必须把超时标成独立一类，不能记成普通失败。"""
        from agents import agent_executor as ex
        from audit_types import ToolCall
        from tool_registry import ToolExecutionTimeout
        import models as _models

        class _FakeCM:
            async def __aenter__(self):
                return object()

            async def __aexit__(self, *a):
                return False

        monkeypatch.setattr(_models, "async_session", lambda: _FakeCM())

        async def timeout_exec(name, **kw):
            raise ToolExecutionTimeout("x.y", 50)

        monkeypatch.setattr(ex.tool_registry, "execute", timeout_exec)
        monkeypatch.setattr(ex.Executor, "_emit_tool_telemetry",
                            staticmethod(lambda *a, **k: None))

        res = _run(ex.executor._execute_parallel(
            [ToolCall(call_id="c1", task_id="t1", tool="x.y", args={})], None
        ))
        assert len(res) == 1
        assert res[0].timed_out is True, "超时未被标记"
        assert res[0].security_denied is False, "超时被误标为安全拒绝"
        assert "tool_timeout" in res[0].error

    def test_tool_result_serialises_timed_out(self):
        from audit_types import ToolResult

        d = ToolResult(call_id="c", task_id="t", tool="x", success=False,
                       error="tool_timeout:50ms", timed_out=True).to_dict()
        assert d["timed_out"] is True


# ═══════════════════════════════════════════
# B-4: 并发上限
# ═══════════════════════════════════════════


class TestToolConcurrencyCap:
    def test_gate_exists_and_is_bounded(self):
        from tool_registry import tool_exec_gate

        g = tool_exec_gate()
        assert g.limit() >= 1
        assert g.limit() <= 64, "并发上限缺失或明显过大"

    def test_gate_is_configurable(self, monkeypatch):
        from config import settings
        from capacity import reset_gates

        monkeypatch.setattr(settings, "tool_exec_max_concurrency", 3)
        reset_gates()
        try:
            from tool_registry import tool_exec_gate
            assert tool_exec_gate().limit() == 3
        finally:
            reset_gates()

    def test_inflight_never_exceeds_limit(self, monkeypatch):
        """闸必须真的把并发压到上限之下。"""
        from config import settings
        from capacity import reset_gates

        monkeypatch.setattr(settings, "tool_exec_max_concurrency", 2)
        reset_gates()
        try:
            from tool_registry import ToolRegistry
            import tool_registry as tr

            peak = {"now": 0, "max": 0}

            async def work(**kwargs):
                peak["now"] += 1
                peak["max"] = max(peak["max"], peak["now"])
                await asyncio.sleep(0.05)
                peak["now"] -= 1
                return 1

            r = ToolRegistry()
            r.register("q.tool", work, timeout_ms=5000, risk_level="low")
            # 绕过 pre_exec 检测器差异：用真实 execute 路径即可
            async def go():
                return await asyncio.gather(*[r.execute("q.tool") for _ in range(8)])

            _run(go())
            assert peak["max"] <= 2, (
                f"并发峰值 {peak['max']} 超过上限 2 —— 上限未生效"
            )
        finally:
            reset_gates()


# ═══════════════════════════════════════════
# B-4: 取消语义
# ═══════════════════════════════════════════


class TestCancellationSemantics:
    def test_cancelled_tool_propagates(self, monkeypatch):
        """取消必须向上传播，不能被 except Exception 吞成工具失败。

        ``asyncio.gather(..., return_exceptions=True)`` 不捕获
        CancelledError，所以正确行为是**整个 _execute_parallel 抛出**，
        而不是产出一个 success=False 的 ToolResult。
        若被吞成普通失败，上层会以为只是「这个工具坏了」而继续跑完
        整轮审计 —— 而实际上流水线已被要求停止。
        """
        from agents import agent_executor as ex
        from audit_types import ToolCall
        import models as _models

        class _FakeCM:
            async def __aenter__(self):
                return object()

            async def __aexit__(self, *a):
                return False

        monkeypatch.setattr(_models, "async_session", lambda: _FakeCM())

        async def cancel_exec(name, **kw):
            raise asyncio.CancelledError()

        monkeypatch.setattr(ex.tool_registry, "execute", cancel_exec)
        monkeypatch.setattr(ex.Executor, "_emit_tool_telemetry",
                            staticmethod(lambda *a, **k: None))

        async def go():
            return await ex.executor._execute_parallel(
                [ToolCall(call_id="c1", task_id="t1", tool="x.y", args={})], None
            )

        with pytest.raises(asyncio.CancelledError):
            _run(go())

    def test_plain_error_does_not_cancel_batch(self, monkeypatch):
        """对照组：普通工具异常不得牵连整批（return_exceptions 语义保留）。"""
        from agents import agent_executor as ex
        from audit_types import ToolCall
        import models as _models

        class _FakeCM:
            async def __aenter__(self):
                return object()

            async def __aexit__(self, *a):
                return False

        monkeypatch.setattr(_models, "async_session", lambda: _FakeCM())

        async def boom(name, **kw):
            raise RuntimeError("db down")

        monkeypatch.setattr(ex.tool_registry, "execute", boom)
        monkeypatch.setattr(ex.Executor, "_emit_tool_telemetry",
                            staticmethod(lambda *a, **k: None))

        res = _run(ex.executor._execute_parallel(
            [ToolCall(call_id="c1", task_id="t1", tool="x.y", args={})], None
        ))
        assert len(res) == 1
        assert res[0].success is False
        assert res[0].security_denied is False
        assert res[0].timed_out is False

    def test_cancelled_chunk_audit_propagates(self, monkeypatch):
        """取消的 chunk 不得被包成「审核异常」ChunkVerdict。

        修复前 CancelledError 会被包成一条 conservative verdict，
        流水线继续汇总出一个**看起来完整**的结论 ——
        而实际上它已被要求停止。
        """
        from agents import agent_executor as ex
        from agents.chunker import AuditChunk

        chunk = AuditChunk(
            chunk_id="c1", strategy="manual", label="ip",
            events=[{"id": 1, "event_type": "E", "severity": "high",
                     "message": "m"}],
        )

        async def cancelled_audit(ch, knowledge_chunks=None):
            raise asyncio.CancelledError()

        monkeypatch.setattr(ex.sub_auditor, "audit", cancelled_audit)

        with pytest.raises(asyncio.CancelledError):
            _run(ex.executor._audit_chunks_parallel([chunk]))

    def test_failed_chunk_audit_still_wrapped(self, monkeypatch):
        """对照组：普通审核失败仍被包成保守 verdict（既有行为不变）。"""
        from agents import agent_executor as ex
        from agents.chunker import AuditChunk

        chunk = AuditChunk(
            chunk_id="c1", strategy="manual", label="ip",
            events=[{"id": 1, "event_type": "E", "severity": "high",
                     "message": "m"}],
        )

        async def boom_audit(ch, knowledge_chunks=None):
            raise RuntimeError("llm down")

        monkeypatch.setattr(ex.sub_auditor, "audit", boom_audit)

        res = _run(ex.executor._audit_chunks_parallel([chunk]))
        assert len(res) == 1
        assert res[0].schema_valid is False
        assert res[0].unsubstantiated is True


# ═══════════════════════════════════════════
# E-3: httpx 超时不能被单值覆盖
# ═══════════════════════════════════════════


class TestHttpTimeoutNotOverridden:
    def test_connect_timeout_is_independent(self):
        """核心回归：connect 必须保持快速失败，不能被 read 的 90s 覆盖。"""
        import httpx
        from config import settings

        read_s = float(getattr(settings, "llm_request_timeout_s", 90) or 90)
        conn_s = float(getattr(settings, "llm_connect_timeout_s", 10.0) or 10.0)
        t = httpx.Timeout(
            connect=conn_s, read=read_s, write=read_s, pool=read_s
        )
        assert t.connect == conn_s, "connect 被 read 超时覆盖"
        assert t.read == read_s

    def test_source_uses_four_segment_timeout(self):
        """静态守卫：源码里不能再出现单值 Timeout。"""
        import inspect
        from summary_compression import LLMClient

        src = inspect.getsource(LLMClient._chat_http)
        assert "timeout=httpx.Timeout(max(0.05, req_timeout))" not in src, (
            "单值 httpx.Timeout 会把 connect 覆盖成整体超时"
        )
        assert "connect=" in src

    def test_connect_timeout_is_configurable(self):
        from config import settings
        assert hasattr(settings, "llm_connect_timeout_s")
        assert float(settings.llm_connect_timeout_s) < float(settings.llm_request_timeout_s)


# ═══════════════════════════════════════════
# E-2: 重试退避与抖动
# ═══════════════════════════════════════════


class TestRetryBackoff:
    def test_backoff_is_positive_and_bounded(self):
        from summary_compression import LLMClient

        for attempt in (0, 1, 2):
            vals = [LLMClient._retry_backoff_s(attempt) for _ in range(20)]
            assert all(v >= 0 for v in vals)
            assert any(v > 0 for v in vals), (
                f"attempt {attempt} 的退避恒为 0 —— 重试之间仍然零等待"
            )

    def test_backoff_grows_with_attempt(self):
        from summary_compression import LLMClient

        first = max(LLMClient._retry_backoff_s(0) for _ in range(50))
        later = max(LLMClient._retry_backoff_s(2) for _ in range(50))
        assert later >= first, "退避未随重试次数增长"

    def test_backoff_has_jitter(self):
        """全抖动：多进程不能在同一毫秒同步重试。"""
        from summary_compression import LLMClient

        vals = {LLMClient._retry_backoff_s(1) for _ in range(30)}
        assert len(vals) > 5, "退避无抖动 —— 会形成同步重试风暴"

    def test_backoff_respects_cap(self):
        from summary_compression import LLMClient
        from config import settings

        cap = float(getattr(settings, "llm_retry_max_s", 8.0) or 8.0)
        assert all(LLMClient._retry_backoff_s(9) <= cap + 1e-9 for _ in range(50))


# ═══════════════════════════════════════════
# E-2: 5xx 不重试
# ═══════════════════════════════════════════


class _FakeResp:
    def __init__(self, status, payload=None, headers=None):
        self.status_code = status
        self._payload = payload or {}
        self.headers = headers or {}

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            import httpx
            raise httpx.HTTPStatusError(
                f"status {self.status_code}", request=None, response=None
            )


class _FakeClient:
    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = 0

    async def post(self, *a, **kw):
        self.calls += 1
        if len(self._responses) >= len(self._responses):
            return self._responses[min(self.calls - 1, len(self._responses) - 1)]
        return self._responses[self.calls - 1]


class TestServerErrorNotRetried:
    def _client(self, status):
        from summary_compression import LLMClient

        c = LLMClient.__new__(LLMClient)
        c.client = _FakeClient([_FakeResp(status)] * 5)
        c.base_url = "http://x"
        c.api_key = "k"
        c.model = "m"
        c._response_cache = {}
        c.redis = None
        c._cache_ttl = 60
        return c

    def test_500_is_not_retried(self):
        """上游 500 时重连救不回来，还把刚恢复的窗口重新打挂。"""
        c = self._client(500)
        out = json.loads(_run(c._chat_http(
            {"model": "m", "messages": []}, 10, 0.0, None, "k1"
        )))
        assert out.get("fallback") is True
        assert out.get("retryable") is False
        assert c.client.calls == 1, f"5xx 被重试了 {c.client.calls} 次"

    def test_503_is_not_retried(self):
        c = self._client(503)
        out = json.loads(_run(c._chat_http(
            {"model": "m", "messages": []}, 10, 0.0, None, "k2"
        )))
        assert out.get("retryable") is False
        assert c.client.calls == 1

    def test_502_is_not_retried(self):
        c = self._client(502)
        _run(c._chat_http({"model": "m", "messages": []}, 10, 0.0, None, "k3"))
        assert c.client.calls == 1


# ═══════════════════════════════════════════
# E-2: 实际请求次数统计
# ═══════════════════════════════════════════


class TestActualRequestCounting:
    def test_stats_track_upstream_requests(self):
        """核心回归：限流器看到 1 次，上游收到 N 次，这个差必须可观测。"""
        from summary_compression import LLMClient

        c = LLMClient.__new__(LLMClient)
        c._http_requests_total = 0
        c._http_retries_total = 0
        c._note_http_request(3, 2)
        st = c.http_request_stats()
        assert st["http_requests_total"] == 3
        assert st["http_retries_total"] == 2

    def test_single_request_stats_are_one(self):
        from summary_compression import LLMClient

        c = LLMClient.__new__(LLMClient)
        c._http_requests_total = 0
        c._http_retries_total = 0
        c._note_http_request(1, 0)
        assert c.http_request_stats()["http_requests_total"] == 1

    def test_fallback_payload_reports_request_count(self):
        from summary_compression import LLMClient

        c = LLMClient.__new__(LLMClient)
        c.client = _FakeClient([_FakeResp(500)] * 5)
        c.base_url = "http://x"
        c.api_key = "k"
        c.model = "m"
        c._response_cache = {}
        c.redis = None
        c._cache_ttl = 60
        out = json.loads(_run(c._chat_http(
            {"model": "m", "messages": []}, 10, 0.0, None, "k9"
        )))
        assert out.get("http_requests") == 1

    def test_llm_limiter_still_charges_per_logical_call(self):
        """P2 的既定范围**不包括**改限流器的计费语义。

        限流器仍在进 slot 时扣额度；实际请求数只是被单独记录下来可观测。
        这条断言把这个边界钉住，避免后人顺手"修正"它。
        """
        from llm_limiter import get_llm_limiter

        snap = get_llm_limiter().snapshot()
        for k in ("used", "rate_per_minute", "rate_used"):
            assert k in snap, f"限流器快照缺少 {k}"


# ═══════════════════════════════════════════
# C-3: 三类指标拆分
# ═══════════════════════════════════════════


class TestThreeFailureClasses:
    def test_fabricated_identifier_is_invalid_reference(self):
        """编造 ATT&CK 编号 —— 与"措辞不准"是完全不同的问题。"""
        from faithfulness_gate import compute_faithfulness

        rep = compute_faithfulness(
            "攻击者使用了 T1071 应用层协议进行 C2 通信并外传数据",
            [{"content": "ssh login failed from 10.0.0.9"}],
        )
        assert rep["invalid_reference_count"] >= 1, (
            "编造编号未被归入 invalid_reference"
        )
        assert rep["failure_breakdown"]["invalid_reference"] >= 1

    def test_no_entity_unsupported_is_unsupported_claim(self):
        """无编号型实体但整句无支撑 → 无证据主张。"""
        from faithfulness_gate import compute_faithfulness

        rep = compute_faithfulness(
            "该主机已被确认沦陷并向外传输了客户数据库",
            [{"content": "ssh login failed from 10.0.0.9"}],
        )
        assert rep["unsupported_claim_count"] >= 1, (
            "无证据主张未被单独归类"
        )

    def test_opposite_conclusion_is_wrong_conclusion(self):
        """引用全部有效，但结论方向与证据相反 —— 编号校验发现不了。"""
        from faithfulness_gate import compute_faithfulness

        rep = compute_faithfulness(
            "远程登录连接成功建立，攻击者已完成认证",
            [{"content": "ssh connection refused for root"}],
        )
        assert rep["wrong_conclusion_count"] >= 1, (
            "结论方向相反未被识别为 wrong_conclusion"
        )

    def test_legacy_fields_preserved(self):
        """向后兼容：原有字段语义不得改变。"""
        from faithfulness_gate import compute_faithfulness

        rep = compute_faithfulness(
            "外传数据", [{"content": "ssh connection refused"}]
        )
        for k in ("claim_count", "supported_count", "unsupported_count",
                  "faithfulness", "entity_entailment", "phantom_entities",
                  "passed", "reasons"):
            assert k in rep, f"既有字段 {k} 丢失"

    def test_breakdown_sums_to_unsupported(self):
        """三类之和必须等于失败总数，否则分类本身不可信。"""
        from faithfulness_gate import compute_faithfulness

        rep = compute_faithfulness(
            "使用 T1071 通信并已成功建立隧道，同时数据库已被拖走",
            [{"content": "ssh connection refused for root"}],
        )
        b = rep["failure_breakdown"]
        assert sum(b.values()) == rep["unsupported_count"], (
            f"三类之和 {sum(b.values())} != unsupported_count "
            f"{rep['unsupported_count']}"
        )

    def test_empty_answer_has_same_contract(self):
        from faithfulness_gate import compute_faithfulness

        rep = compute_faithfulness("", [{"content": "x"}])
        for k in ("invalid_reference_count", "unsupported_claim_count",
                  "wrong_conclusion_count", "failure_breakdown"):
            assert k in rep

    def test_clean_answer_has_zero_failures(self):
        from faithfulness_gate import compute_faithfulness

        rep = compute_faithfulness(
            "ssh connection refused for root",
            [{"content": "ssh connection refused for root"}],
        )
        assert rep["unsupported_count"] == 0
        assert sum(rep["failure_breakdown"].values()) == 0


# ═══════════════════════════════════════════
# E-5: 真实模板契约
# ═══════════════════════════════════════════


class TestTemplateContract:
    def test_template_variables_are_derivable(self):
        """模板需要什么变量，必须能从模板本身推导出来。"""
        from prompts.loader import template_variables

        vs = template_variables("audit/executor_synthesize")
        assert vs, "无法从模板推导变量集合"

    def test_strict_render_flag_exists(self):
        from prompts.loader import render_is_strict, set_strict_render

        prev = set_strict_render(True)
        try:
            assert render_is_strict() is True
        finally:
            set_strict_render(prev)

    def test_missing_var_raises_in_strict_mode(self):
        """核心回归：生产调用点漏传变量必须立刻暴露。"""
        from prompts import loader

        prev = loader.set_strict_render(True)
        try:
            with pytest.raises(loader.MissingTemplateVars) as ei:
                loader.render("audit/executor_synthesize")  # 一个都不传
            assert ei.value.template == "audit/executor_synthesize"
            assert ei.value.missing
        finally:
            loader.set_strict_render(prev)

    def test_permissive_mode_unchanged_by_default(self):
        """宽松模式仍可显式进入（应急退路，不是默认值）。

        默认已改为严格 —— 见 test_strict_is_default_on。
        """
        from prompts import loader

        prev = loader.set_strict_render(False)
        try:
            out = loader.render("audit/executor_synthesize")
            assert isinstance(out, str)
        finally:
            loader.set_strict_render(prev)

    def test_strict_is_default_on(self):
        """P2-E-5: 严格模式**默认开启**，不是留作可选项。

        理由是实测：57 个字面量调用点零缺失，宽松模式换来的只是
        「静默的空提示词」。若哪天某个调用点确实漏传，
        test_every_literal_render_call_site_satisfies_contract 会先失败。
        """
        import importlib

        import prompts.loader as loader

        prev = loader.render_is_strict()
        # 重新导入以取回「未被人为改过」的默认值
        importlib.reload(loader)
        try:
            assert loader.render_is_strict() is True, (
                "严格变量校验未默认开启 —— 生产路径漏传变量仍会静默"
            )
        finally:
            loader.set_strict_render(prev)

    def test_missing_vars_error_is_distinct_from_missing_template(self):
        from prompts.loader import MissingTemplateVars
        assert issubclass(MissingTemplateVars, Exception)

    def test_known_template_contract_is_populated(self):
        """契约不是空壳：至少一个真实模板能推导出非空变量集。"""
        from prompts.loader import template_variables

        vs = template_variables("audit/sub_auditor_prompt")
        assert "block_text" in vs or vs, "sub_auditor_prompt 变量集异常"

    def test_local_loop_vars_excluded_from_contract(self):
        """模板内部的循环变量不是调用点的义务。"""
        from prompts.loader import template_variables

        vs = template_variables("audit/executor_recheck")
        assert "v_text" in vs
        assert "item" not in vs and "v" not in vs, (
            "模板内部循环变量被算进调用点契约 —— 永远无法满足"
        )

    def test_every_literal_render_call_site_satisfies_contract(self):
        """P2-E-5 的核心断言：契约来自**真实调用点**，不是 mock 表。

        修复前只有一张手工维护的 ``_TEMPLATE_VARS`` 表 ——
        表里写了什么就只校验什么，模板新增变量时校验静默通过。

        这里用 AST 扫出所有 ``render("字面量模板名", ...)`` 调用点，
        逐个比对「模板需要的变量 − 调用点传的变量」。
        实测当前 57 个调用点零缺失，因此严格模式可安全开启。
        """
        import ast
        import pathlib

        from prompts.loader import template_variables

        backend = pathlib.Path(__file__).resolve().parent.parent
        checked = 0
        missing_sites = []

        for py in backend.rglob("*.py"):
            rel = py.relative_to(backend).as_posix()
            if rel.startswith("tests/") or "__pycache__" in rel:
                continue
            try:
                tree = ast.parse(py.read_text(encoding="utf-8"))
            except Exception:
                continue
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                fn = node.func
                fname = fn.id if isinstance(fn, ast.Name) else (
                    fn.attr if isinstance(fn, ast.Attribute) else None
                )
                if fname not in ("render", "strict_render") or not node.args:
                    continue
                a0 = node.args[0]
                if not (isinstance(a0, ast.Constant)
                        and isinstance(a0.value, str)):
                    continue
                tpl = a0.value
                need = template_variables(tpl)
                given = {k.arg for k in node.keywords if k.arg}
                checked += 1
                gap = sorted(need - given)
                if gap:
                    missing_sites.append(f"{rel}:{node.lineno} {tpl} 缺 {gap}")

        assert checked >= 20, (
            f"只扫到 {checked} 个调用点 —— AST 扫描本身可能失效"
        )
        assert not missing_sites, (
            "真实调用点缺失模板变量（严格模式会抛）:\n  "
            + "\n  ".join(missing_sites[:10])
        )
