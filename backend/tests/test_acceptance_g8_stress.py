"""
验收 · 第三轮：并发压测（门槛 D/E 的运行证据）

规范原文（§三.3）：
  「在全量回归之外做一次并发压测，记录并发峰值、实际 LLM 请求数、
    失败率与任务残留。」

本文件**不做覆盖率统计，也不预设阈值即合格**，只把四个数字测出来并
把可判定的性质钉死：

  1. 并发峰值      —— 受 capacity.BoundedGate 上限约束，不越界
  2. 实际 LLM 请求数 —— 用 LLMClient.http_request_stats()，
                     而不是「逻辑调用数」
  3. 失败率        —— 注入的失败必须原样出现在结果里，不得被吞成成功
  4. 任务残留      —— 跑完之后不得有孤儿 asyncio.Task，
                     且所有闸的 inflight 必须归零
"""
import asyncio
import json

import pytest


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


# ══════════════════════════════════════════════════════════════
# 压测一：工具执行闸的并发峰值
# ══════════════════════════════════════════════════════════════

class TestToolConcurrencyStress:
    @pytest.mark.parametrize("limit,workers", [(4, 40), (8, 96)])
    def test_s1_peak_never_exceeds_the_gate_limit(self, monkeypatch, limit, workers):
        """D-1：并发峰值受闸约束，且压测完闸必须完全归还名额。"""
        from capacity import reset_gates, snapshot
        from config import settings
        import tool_registry as tr

        reset_gates()
        monkeypatch.setattr(settings, "tool_exec_max_concurrency", limit)

        class _Probe:
            def __init__(self):
                self.cur = 0
                self.peak = 0
                self.done = 0

            async def __call__(self, **kwargs):
                self.cur += 1
                self.peak = max(self.peak, self.cur)
                try:
                    await asyncio.sleep(0.01)
                    self.done += 1
                    return {"ok": True}
                finally:
                    self.cur -= 1

        probe = _Probe()
        name = "acc_g8_probe"
        tr.tool_registry.register(
            name=name, category="diagnostic", risk_level=tr.RISK_LOW,
            description="压测探针", fn=probe, timeout_ms=5000,
        )
        try:
            async def t():
                return await asyncio.gather(*[
                    tr.tool_registry.execute(name) for _ in range(workers)
                ])

            results = _run(t())
            gate = tr.tool_exec_gate()

            assert probe.peak <= limit, \
                f"并发峰值 {probe.peak} 超过上限 {limit}"
            assert probe.peak > 1, f"根本没有并发（peak={probe.peak}）"
            assert probe.done == workers, f"有任务丢失: {probe.done}/{workers}"
            assert len(results) == workers
            assert all(r == {"ok": True} for r in results)
            assert gate.inflight() == 0, f"闸名额未归还: {gate.snapshot()}"
            assert gate.waiters() == 0, f"闸内仍有等待者: {gate.snapshot()}"
            assert snapshot()  # 观测面可导出
        finally:
            tr.tool_registry._tools.pop(name, None)
            reset_gates()


# ══════════════════════════════════════════════════════════════
# 压测二：并发 LLM 出口的「实际请求数」
# ══════════════════════════════════════════════════════════════

class TestLlmRequestCounting:
    def test_s2_upstream_requests_are_counted_under_concurrency(self, monkeypatch):
        """E-2：N 个并发逻辑调用各重试 k 次 → 上游真实请求数 = N*(k+1)。

        量的是 ``LLMClient.http_request_stats()``，不是逻辑调用计数；
        这正是 P2-E-2 建立的独立口径。
        """
        import httpx
        import summary_compression as sc
        from summary_compression import LLMClient

        fake = sc.LLMClient.__new__(LLMClient)
        fake.api_key = "k"
        fake.base_url = "http://llm.invalid/v1"
        fake.model = "m"
        fake._response_cache = {}
        fake.redis = None
        fake._cache_ttl = 60

        attempts = {"n": 0}
        retries_per_call = 2

        class _Http:
            async def post(self, url, **kw):
                attempts["n"] += 1
                # 每个逻辑调用：前 retries_per_call 次连接失败，第 3 次成功
                if (attempts["n"] - 1) % (retries_per_call + 1) < retries_per_call:
                    raise httpx.ConnectError("refused")
                return _OK()

        class _OK:
            status_code = 200
            headers = {}

            def json(self):
                return {"choices": [{"message": {"content": "ok"}}],
                        "usage": {"total_tokens": 8, "prompt_tokens": 4,
                                  "completion_tokens": 4}}

            def raise_for_status(self):
                return None

        fake.client = _Http()

        class _Cost:
            def record(self, *a, **k):
                pass

            def is_over_budget(self):
                return False

            def stats(self):
                return {}

        monkeypatch.setattr(sc, "cost_tracker", _Cost())

        real_sleeps = []

        async def _fake_sleep(s):
            real_sleeps.append(s)

        monkeypatch.setattr(sc.asyncio, "sleep", _fake_sleep)

        n_calls = 6

        async def drive():
            payload = {"model": "m", "messages": [{"content": "x"}],
                       "temperature": 0.3}
            return await asyncio.gather(*[
                fake._chat_http(payload, 4, 0.0, 0, f"k{i}")
                for i in range(n_calls)
            ])

        outs = _run(drive())
        stats = fake.http_request_stats()

        expected = n_calls * (retries_per_call + 1)
        assert stats["http_requests_total"] == expected, \
            f"实际请求数 {stats['http_requests_total']} ≠ 预期 {expected}"
        assert stats["http_retries_total"] == n_calls * retries_per_call
        assert attempts["n"] == expected, \
            f"上游实际收到 {attempts['n']} 次，与统计口径不一致"
        assert all(o == "ok" for o in outs)
        assert len(real_sleeps) == n_calls * retries_per_call, \
            f"退避次数不符: {len(real_sleeps)}"
        assert all(s >= 0.0 for s in real_sleeps)

    def test_s3_failures_are_counted_not_hidden(self, monkeypatch):
        """对照组：全部失败时，请求数同样要记账，且失败体可判别。"""
        import httpx
        import summary_compression as sc
        from summary_compression import LLMClient
        from agents.llm_fallback import is_llm_fallback

        fake = LLMClient.__new__(LLMClient)
        fake.api_key = "k"
        fake.base_url = "http://llm.invalid/v1"
        fake.model = "m"
        fake._response_cache = {}
        fake.redis = None
        fake._cache_ttl = 60

        attempts = {"n": 0}

        class _Http:
            async def post(self, url, **kw):
                attempts["n"] += 1
                raise httpx.ConnectError("refused")

        fake.client = _Http()

        class _Cost:
            def record(self, *a, **k):
                pass

            def is_over_budget(self):
                return False

            def stats(self):
                return {}

        monkeypatch.setattr(sc, "cost_tracker", _Cost())

        async def _no_sleep(s):
            return None

        monkeypatch.setattr(sc.asyncio, "sleep", _no_sleep)

        out = _run(fake._chat_http(
            {"model": "m", "messages": [{"content": "x"}]}, 4, 0.0, 0, "k"))
        data = json.loads(out)
        assert data["fallback"] is True
        assert is_llm_fallback(out)[0] is True
        assert fake.http_request_stats()["http_requests_total"] == 3
        assert attempts["n"] == 3


# ══════════════════════════════════════════════════════════════
# 压测三：并发审计流水线的失败率与任务残留
# ══════════════════════════════════════════════════════════════

class TestPipelineStress:
    def test_s4_failure_rate_is_faithful_and_no_task_leaks(self, monkeypatch):
        """D-2：注入的失败必须原样计入失败率，且不留下孤儿 Task。

        注入规则：每第 3 个 pipeline 的 LLM 返回降级体。
        因此期望失败率 = floor(n/3)/n —— 断言实测值等于注入值，
        任何「失败被吞成成功」都会让这条失败。
        """
        from agents import agent_executor as ex
        from audit_types import ToolCall
        from eval_datasets.grounding_cases import C2_BEACON

        N = 12
        fail_every = 3

        _LLM_OK = json.dumps({
            "threat_detected": True, "threat_type": "C2_BEACON",
            "confidence": 0.9, "severity": "high", "summary": "周期性外连",
            "threat_claims": [{
                "type": "C2", "confidence": 0.85, "evidence_ids": [2],
                "evidence_quotes": ["outbound beacon to 203.0.113.45 every 60s"],
                "severity": "high", "summary": "周期性外连",
            }],
            "conclusion": "confirmed", "reasoning": "周期性外连",
        }, ensure_ascii=False)
        _LLM_DEAD = json.dumps(
            {"error": "LLM调用失败", "fallback": True}, ensure_ascii=False)

        ctx = {"call": 0}

        async def fake_chat(messages, **kw):
            ctx["call"] += 1
            return _LLM_DEAD if ctx["call"] % fail_every == 0 else _LLM_OK

        monkeypatch.setattr(ex.summary.llm, "chat", fake_chat)
        chunk = ex.AuditChunk(chunk_id="c0", strategy="manual", label="ip",
                              events=[dict(C2_BEACON)])
        monkeypatch.setattr(ex.chunker, "chunk",
                            lambda events, chain_event_ids=None: [chunk])
        monkeypatch.setattr(ex.Executor, "_emit_tool_telemetry",
                            staticmethod(lambda *a, **k: None))

        async def one():
            return await ex.executor.execute(
                tool_calls=[ToolCall(call_id="x1", task_id="t1",
                                     tool="llm.deep_analyze", args={})],
                depth="deep", raw_event=dict(C2_BEACON),
            )

        async def stress():
            # all_tasks() 必须在**运行中的** loop 内调用，
            # 放在协程外会 RuntimeError: no running event loop
            before = set(asyncio.all_tasks())
            out = await asyncio.gather(*[one() for _ in range(N)],
                                       return_exceptions=True)
            after = set(asyncio.all_tasks())
            return out, after - before

        results, leaked = _run(stress())

        crashed = [r for r in results if isinstance(r, Exception)]
        assert crashed == [], f"压测中出现未捕获异常: {crashed[:2]}"
        assert len(results) == N

        degraded = [r for r in results
                    if str(r.terminal_reason or "").startswith("llm_fallback")]
        expect_degraded = N // fail_every
        assert len(degraded) == expect_degraded, (
            f"注入 {expect_degraded} 次失败，实测 {len(degraded)} 次 —— "
            "失败被吞掉或凭空多出"
        )

        # 失败率：这里按「结论不可信」口径统计，而不是按「抛异常」口径
        untrusted = [r for r in results if r.needs_human_review
                     or str(r.terminal_reason or "").startswith("llm_fallback")]
        rate = len(untrusted) / N
        assert rate >= expect_degraded / N - 1e-9, f"失败率被低报: {rate}"

        assert leaked == set(), f"压测后残留 {len(leaked)} 个 asyncio.Task"

        from capacity import db_write_gate, kafka_produce_gate
        assert db_write_gate().inflight() == 0
        assert kafka_produce_gate().inflight() == 0
