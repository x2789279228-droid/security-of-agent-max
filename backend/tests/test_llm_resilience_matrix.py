"""G 路线：LLM 韧性故障注入矩阵（REMEDIATION-PLAN-2026-10-30 路线 G1）。

五类故障 × 验证面：
  终态标记（fallback JSON, 下游 llm_fallback.is_llm_fallback 判定）
  重试语义（retryable=True 可重新入队 / False 终态）
  时延上界（429 ≤ 短重试窗；超时受分段超时约束；不无限等）
  缓存路径（命中零上游调用；故障期间缓存仍可达 —— 缓存门在预算闸之前）
  分级降级（llm_fallback.should_short_circuit_for_tier 的 tier 短路）

架构事实（如实）：平台是**降级语义**（fallback 标记 + 可重试入队 + 分级短路），
不是备模型热切换 —— llm_backup 模型切换不存在于当前实现。
"""
import asyncio
import json
import time
from pathlib import Path
import sys

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import summary_compression as sc
from summary_compression import LLMClient


def _resp(status: int, headers: dict | None = None, body: dict | None = None):
    return httpx.Response(status_code=status, headers=headers or {},
                          json=body or {}, request=httpx.Request("POST", "http://x/v1"))


class _FakeUpstream:
    """按脚本回放的假上游：每次 post() 弹出下一个动作（Response 或异常）。"""

    def __init__(self, script):
        self.script = list(script)
        self.calls = 0

    async def post(self, *a, **kw):
        self.calls += 1
        act = self.script.pop(0) if self.script else self.script_fallback()
        if isinstance(act, Exception):
            raise act
        return act

    def script_fallback(self):
        return _resp(200, body={"choices": [{"message": {"content": "ok"}}]})


def _mk_client(script, monkeypatch):
    monkeypatch.setattr(sc.settings, "llm_api_key", "test-key", raising=False)
    monkeypatch.setattr(sc.settings, "llm_429_retry_s", 0.05, raising=False)
    monkeypatch.setattr(sc.settings, "llm_connect_timeout_s", 0.2, raising=False)
    c = LLMClient()
    fake = _FakeUpstream(script)
    c.client = httpx.AsyncClient()          # 占位(真实请求由 fake 接管)
    c.client.post = fake.post               # type: ignore[method-assign]
    return c, fake


def _msgs(unique: str):
    return [{"role": "user", "content": f"matrix-{unique}"}]


# ── 矩阵：五类故障 ──────────────────────────────────────────

@pytest.mark.asyncio
async def test_fault_429_short_retry_then_retryable_marker(monkeypatch):
    """429：一次短重试后放弃 → fallback 标记 rate_limited_429, retryable=True。"""
    c, fake = _mk_client([_resp(429), _resp(429)], monkeypatch)
    t0 = time.monotonic()
    out = await c.chat(_msgs("429"))
    dt = time.monotonic() - t0
    d = json.loads(out)
    assert d["fallback"] is True and d["error_type"] == "rate_limited_429"
    assert d["retryable"] is True
    assert fake.calls == 2                      # 首发 + 1 次短重试, 不无限打
    assert dt < 1.0, f"429 路径时延 {dt:.2f}s 应受短重试窗约束"
    from agents.llm_fallback import is_llm_fallback, is_retryable_rate_limit
    ok, reason = is_llm_fallback(out)
    assert ok and reason == "rate_limited_429"
    assert is_retryable_rate_limit(out) is True  # 可重新入队


@pytest.mark.asyncio
async def test_fault_timeout_bounded_and_retryable(monkeypatch):
    """超时：TimeoutException 直捕不重试 → llm_request_timeout, retryable=True。"""
    c, fake = _mk_client([httpx.ReadTimeout("read timed out")], monkeypatch)
    t0 = time.monotonic()
    out = await c.chat(_msgs("timeout"))
    dt = time.monotonic() - t0
    d = json.loads(out)
    assert d["error_type"] == "llm_request_timeout" and d["retryable"] is True
    assert fake.calls == 1                      # 超时不重试(P2-E-2 语义)
    assert dt < 5.0


@pytest.mark.asyncio
async def test_fault_invalid_key_401_exhausts_then_fallback(monkeypatch):
    """无效 key(401)：走通用异常重试 3 次(退避) → 兜底 fallback, 不崩调用方。"""
    monkeypatch.setattr(LLMClient, "_retry_backoff_s",
                        staticmethod(lambda attempt: 0.01))
    c, fake = _mk_client([_resp(401)] * 5, monkeypatch)
    out = await c.chat(_msgs("401"))
    d = json.loads(out)
    assert d["fallback"] is True
    assert 3 <= fake.calls <= 4                 # 3 次尝试边界
    from agents.llm_fallback import is_llm_fallback
    assert is_llm_fallback(out)[0] is True


@pytest.mark.asyncio
async def test_fault_network_down_connect_error(monkeypatch):
    """断网(ConnectError)：3 次退避重试后兜底 fallback。"""
    monkeypatch.setattr(LLMClient, "_retry_backoff_s",
                        staticmethod(lambda attempt: 0.01))
    c, fake = _mk_client([httpx.ConnectError("no route to host")] * 5, monkeypatch)
    out = await c.chat(_msgs("netdown"))
    assert json.loads(out)["fallback"] is True
    assert fake.calls >= 3


@pytest.mark.asyncio
async def test_fault_model_offline_404(monkeypatch):
    """模型下线(404)：通用重试后兜底 fallback(不把它当 5xx 快速路径)。"""
    monkeypatch.setattr(LLMClient, "_retry_backoff_s",
                        staticmethod(lambda attempt: 0.01))
    c, fake = _mk_client([_resp(404)] * 5, monkeypatch)
    out = await c.chat(_msgs("404"))
    assert json.loads(out)["fallback"] is True
    assert fake.calls >= 3


@pytest.mark.asyncio
async def test_fault_upstream_5xx_no_retry(monkeypatch):
    """5xx：P2-E-2 立即放弃不重试 → upstream_5xx, retryable=False。"""
    c, fake = _mk_client([_resp(503)] * 3, monkeypatch)
    out = await c.chat(_msgs("5xx"))
    d = json.loads(out)
    assert d["error_type"] == "upstream_503" and d["retryable"] is False
    assert fake.calls == 1


# ── 缓存路径 ────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_cache_hit_zero_upstream_calls(monkeypatch):
    """成功响应缓存后, 同 prompt 第二次命中零上游调用。"""
    c, fake = _mk_client([_resp(200, body={"choices": [{"message": {"content": "answer-A"}}]})],
                         monkeypatch)
    m = _msgs("cache")
    first = await c.chat(m)
    assert first == "answer-A" and fake.calls == 1
    second = await c.chat(m)
    assert second == "answer-A" and fake.calls == 1  # 未再打上游


@pytest.mark.asyncio
async def test_cache_reachable_during_upstream_fault(monkeypatch):
    """故障期间缓存仍可达：上游已 429, 但先前缓存的同 prompt 照常返回
    （缓存查询在预算/上游之前 —— 门禁不饿死缓存）。"""
    c, fake = _mk_client([
        _resp(200, body={"choices": [{"message": {"content": "cached-ok"}}]}),
        _resp(429), _resp(429),
    ], monkeypatch)
    m = _msgs("during-fault")
    assert await c.chat(m) == "cached-ok"
    out = await c.chat(m)                       # 上游已坏, 应命中缓存
    assert out == "cached-ok" and fake.calls == 1


@pytest.mark.asyncio
async def test_no_key_gate_no_upstream_call(monkeypatch):
    """无 key 前置闸：不发任何上游请求 → LLM未配置 fallback。"""
    monkeypatch.setattr(sc.settings, "llm_api_key", "", raising=False)
    c, fake = _mk_client([_resp(200)], monkeypatch)
    c.api_key = ""
    out = await c.chat(_msgs("nokey"))
    d = json.loads(out)
    assert d["fallback"] is True and "未配置" in d["error"]
    assert fake.calls == 0


def test_tier_short_circuit_degrades_low_tier_first():
    """分级降级：预算耗尽时低优 tier 短路, 高优(P0)保留 —— 降级有序。"""
    from agents import llm_fallback as lf
    assert lf.should_short_circuit_for_tier("P3") in (True, False)  # 依预算态
    # 直接验证语义函数本体: 预算尽 → 非 P0 短路, P0 不短路
    lf.budget_exhausted = lambda: True  # type: ignore[assignment]
    assert lf.should_short_circuit_for_tier("P2") is True
    assert lf.should_short_circuit_for_tier("P0") is False
    lf.budget_exhausted = lambda: False  # type: ignore[assignment]
    assert lf.should_short_circuit_for_tier("P3") is False
