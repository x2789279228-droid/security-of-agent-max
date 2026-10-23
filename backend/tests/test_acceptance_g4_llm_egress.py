"""
验收 · 第四组：LLM 出口与 Schema（E-1 ~ E-5）→ 门槛 B + C

规范原文（§二.4）：
  E-1  深度分析 fallback 不得伪装成功
  E-2  重试必须带退避与抖动，实际请求数必须单独统计
  E-3  HTTPX 超时不得被单值覆盖
  E-4  Schema 校验错误不得把非法结果放行
  E-5  模板变量契约必须在**真实调用点**生效，而非只对手工 mock 上下文测试

本文件全部为**实际执行**：
  · E-1 真实驱动 executor.execute()，观察 ToolResult / prompt 内容 / terminal_reason
  · E-2 真实驱动 _chat_http（注入假 httpx client，统计真实发出的请求次数）
  · E-3 从真实 _chat_http 捕获的 httpx.Timeout 对象里读四段值
  · E-4 真实执行 validate_*_output
  · E-5 AST 扫出真实调用点并**真的调用 render()** 渲染一遍
"""
import asyncio
import json

import httpx
import pytest

from agents.llm_fallback import is_llm_fallback
from audit_schemas import (
    validate_reviewer_output,
    validate_sub_auditor_output,
    validate_synthesis_output,
)


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


# ══════════════════════════════════════════════════════════════
# E-1 · 深度分析 fallback 不得伪装成功
# ══════════════════════════════════════════════════════════════

FALLBACK_JSON = json.dumps(
    {"error": "每日 LLM 预算已用尽", "fallback": True}, ensure_ascii=False
)


def _run_deep(monkeypatch, chat_return):
    """真实驱动 executor.execute 的 deep 档（沿用已验证可用的 harness）。"""
    from agents import agent_executor as ex
    from audit_types import ToolCall

    captured = []

    async def fake_chat(messages, **kw):
        captured.append(messages)
        return chat_return

    monkeypatch.setattr(ex.summary.llm, "chat", fake_chat)

    chunk = ex.AuditChunk(
        chunk_id="c1", strategy="manual", label="ip",
        events=[{"id": 1, "event_type": "C2_BEACON", "severity": "high",
                 "message": "beacon"}],
    )
    monkeypatch.setattr(ex.chunker, "chunk", lambda events, chain_event_ids=None: [chunk])
    verdict = ex.ChunkVerdict(
        chunk_id="c1", threat_detected=True,
        threat_claims=[{
            "type": "C2", "confidence": 0.9,
            "evidence_ids": [1], "evidence_quotes": ["beacon"],
            "severity": "high", "summary": "c2 beacon 周期上报",
        }],
        all_event_ids_in_chunk=[1],
    )

    async def fake_audit(ch, knowledge_chunks=None):
        return verdict

    monkeypatch.setattr(ex.sub_auditor, "audit", fake_audit)

    res = _run(ex.executor.execute(
        tool_calls=[ToolCall(call_id="c1", task_id="t1",
                             tool="llm.deep_analyze", args={})],
        depth="deep",
        raw_event={"event": "C2_BEACON", "severity": "high", "src_ip": "10.0.0.5"},
    ))
    return res, captured


class TestDeepAnalyzeFallback:
    """E-1：降级响应不得伪装成一次成功的深度研判。"""

    def test_s1_fallback_is_not_reported_as_success(self, monkeypatch):
        res, captured = _run_deep(monkeypatch, FALLBACK_JSON)

        deep = [r for r in res.tool_results if r.tool == "llm.deep_analyze"]
        assert deep, "deep_analyze 的 ToolResult 必须保留（供审计追溯）"
        assert deep[0].success is False, "降级被标记为 success=True —— E-1 未修复"
        assert "llm_fallback" in (deep[0].error or "")
        assert res.deep_analysis == "", "降级正文不得留在 deep_analysis 字段"
        assert str(res.terminal_reason or "").startswith("llm_fallback:"), \
            f"终态原因未记录降级: {res.terminal_reason!r}"

        blob = json.dumps(captured, ensure_ascii=False)
        assert "fallback" not in blob, "降级 JSON 进入了 LLM prompt —— 模型会被要求采信一段报错"
        assert "预算已用尽" not in blob

    def test_s2_control_normal_deep_analysis_still_works(self, monkeypatch):
        """正对照：正常 deep 输出必须仍然成功并保留正文。"""
        res, _ = _run_deep(monkeypatch, "深度研判：观察到固定周期外连，疑似 C2 心跳。")
        deep = [r for r in res.tool_results if r.tool == "llm.deep_analyze"]
        assert deep and deep[0].success is True, "正对照失败：正常 deep 输出被误判"
        assert "疑似 C2 心跳" in res.deep_analysis

    def test_s3_every_degradation_form_is_recognized(self):
        """E-1 识别面：四种降级形态都必须被识别，且正常输出不被误伤。

        只断言「被识别 + 原因非空」。注意 reason 的粒度：
        agents/llm_fallback._reason_from_error 只认固定 marker，
        `upstream_503` / `llm_request_timeout` 这类 error_type **不会**出现在
        reason 里（降级体里已带 error_type，调用方仍可取到）。
        这属于标签粒度的可观测性缺口，不构成「伪装成功」。
        """
        cases = [
            json.dumps({"error": "每日 LLM 预算已用尽", "fallback": True}),
            json.dumps({"error": "LLM未配置", "fallback": True}),
            json.dumps({"error": "LLM request timeout", "fallback": True,
                        "error_type": "llm_request_timeout", "retryable": True}),
            json.dumps({"error": "LLM 上游错误 503", "fallback": True,
                        "error_type": "upstream_503", "retryable": False}),
        ]
        for text in cases:
            ok, reason = is_llm_fallback(text)
            assert ok is True, f"降级响应未被识别: {text}"
            assert reason, f"降级被识别但没有原因标签: {text}"

        # 正对照：真实模型输出绝不能被当成降级，否则会把成功当失败处理
        for good in ('{"verdict": "confirmed", "summary": "确认存在暴力破解"}',
                     "深度研判：周期性外连。"):
            ok, reason = is_llm_fallback(good)
            assert ok is False, f"正常输出被误判为降级: {good} → {reason}"


# ══════════════════════════════════════════════════════════════
# E-4 · Schema 校验不得把非法结果放行
# ══════════════════════════════════════════════════════════════

class TestSchemaFailClosed:
    """E-4：结构非法时要么明确报错，要么返回收敛后的结构，绝不原样放行。"""

    # ── 验收发现 G4-F1 ──────────────────────────────────────────
    # SubAuditorOutputSchema.check_severity 只做 lower().strip()，
    # **没有**枚举校验 —— 与同文件的 ThreatClaimSchema.check_severity
    # （raise ValueError）和 SynthesisOutputSchema.check_severity（raise）
    # 不一致。后果：非法顶层 severity 得到 errors == []，
    # 于是 sub_auditor 把它写进 ChunkVerdict.schema_valid = True
    # （"结构验证通过"），而该字段实际从未被校验。
    #
    # 实测过的安全影响：merged 的 severity 在生产路径上会经过
    # faithfulness_gate → sanitize_merged_audit → cap_reported_severity，
    # 非法值被归一为 "info"，因此**未形成误封或漏封**。
    # 这是可观测性/一致性缺陷，不是安全缺陷。
    # strict=True：谁修好了这条用例会变成 XPASS 失败，提醒摘掉标记。
    @pytest.mark.xfail(
        strict=True, raises=AssertionError,
        reason="验收发现 G4-F1：SubAuditorOutputSchema 顶层 severity 无枚举校验，"
               "非法值得到 schema_valid=True",
    )
    def test_s4_illegal_severity_is_converged_not_passed_through(self):
        parsed, errors = validate_sub_auditor_output(json.dumps({
            "threat_detected": True, "confidence": 0.9,
            "severity": "SUPER_CRITICAL_NOT_A_LEVEL",
            "summary": "x", "threat_claims": [],
        }))
        assert errors, "非法 severity 未产生任何错误 —— E-4 未修复"
        assert parsed is not None, "可收敛的输出不应被整体丢弃"
        assert parsed["severity"] in (
            "critical", "high", "medium", "low", "info"
        ), f"非法 severity 被原样放行: {parsed['severity']!r}"

    def test_s4b_nested_claim_severity_is_validated(self):
        """对照组：同一份文件里，**断言级** severity 确实有枚举校验。

        没有这条，上面那条 xfail 就可能被误读成「整个 schema 层都不校验」。
        """
        parsed, errors = validate_sub_auditor_output(json.dumps({
            "threat_detected": True, "confidence": 0.9, "severity": "high",
            "summary": "x",
            "threat_claims": [{
                "type": "C2", "confidence": 0.9,
                "evidence_ids": [1], "evidence_quotes": ["beacon"],
                "severity": "SUPER_CRITICAL", "summary": "s",
            }],
        }))
        assert errors, "断言级非法 severity 未报错"
        claims = parsed.get("threat_claims") or []
        assert claims and claims[0]["severity"] == "info", \
            f"断言级非法 severity 未被收敛: {claims}"

    def test_s5_illegal_reviewer_conclusion_collapses_to_suspicious(self):
        parsed, errors = validate_reviewer_output(json.dumps({
            "conclusion": "totally_made_up_conclusion",
            "reasoning": "x", "confidence": 0.8,
        }))
        assert errors, "非法 conclusion 未报错"
        assert parsed["conclusion"] == "suspicious", \
            f"非法 conclusion 被原样放行: {parsed['conclusion']!r}"

    def test_s6_unparsable_output_yields_none_not_partial_dict(self):
        for fn in (validate_sub_auditor_output, validate_synthesis_output,
                   validate_reviewer_output):
            parsed, errors = fn("模型今天不太想输出 JSON，抱歉。")
            assert parsed is None, f"{fn.__name__} 对不可解析文本返回了内容: {parsed!r}"
            assert errors, f"{fn.__name__} 对不可解析文本没有报错"

    def test_s7_evidence_less_claim_is_dropped_by_schema(self):
        """evidence_ids 为空 = 不可修复 → 整条断言必须被丢弃。

        注意区分：``evidence_quotes`` 为空**不是** schema 级错误
        （引文缺失由 GroundingVerifier 按 hallucination_risk 软惩罚处理）；
        真正 fail-closed 的是 evidence_ids 为空 —— 凭空补一个 ID 就是伪造证据。
        """
        parsed, errors = validate_sub_auditor_output(json.dumps({
            "threat_detected": True, "confidence": 0.9, "severity": "high",
            "summary": "x",
            "threat_claims": [{
                "type": "C2", "confidence": 0.9,
                "evidence_ids": [], "evidence_quotes": ["看起来像证据"],
                "severity": "high", "summary": "凭空断言",
            }],
        }))
        assert errors, "无证据断言未报错"
        assert parsed.get("threat_claims") == [], \
            f"无证据断言未被丢弃: {parsed.get('threat_claims')!r}"

    def test_s8_control_valid_output_passes_clean(self):
        """正对照：合法输出 errors 必须为空，且字段被规范化保留。"""
        parsed, errors = validate_sub_auditor_output(json.dumps({
            "threat_detected": True, "confidence": 0.88, "severity": "high",
            "summary": "检测到暴力破解",
            "threat_claims": [{
                "type": "BRUTE_FORCE", "confidence": 0.9,
                "evidence_ids": [1], "evidence_quotes": ["Failed password for root"],
                "severity": "high", "summary": "root 暴力破解",
            }],
        }))
        assert errors == [], f"合法输出被误判: {errors}"
        assert parsed["threat_claims"][0]["evidence_ids"] == [1]
        assert parsed["threat_detected"] is True


# ══════════════════════════════════════════════════════════════
# E-2 / E-3 · 重试、请求数统计、超时四段
# ══════════════════════════════════════════════════════════════

class _FakeResp:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self.headers = {}
        self._payload = payload or {
            "choices": [{"message": {"content": "ok"}}],
            "usage": {"total_tokens": 10, "prompt_tokens": 5, "completion_tokens": 5},
        }

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise httpx.HTTPStatusError("boom", request=None, response=None)


class _FakeHttp:
    """记录真实发出的请求次数与 timeout 参数。"""

    def __init__(self, behaviours):
        self._behaviours = list(behaviours)
        self.calls = []

    async def post(self, url, **kw):
        self.calls.append(kw)
        b = self._behaviours.pop(0) if self._behaviours else _FakeResp()
        if isinstance(b, Exception):
            raise b
        return b


def _make_client(monkeypatch, behaviours):
    from summary_compression import LLMClient

    fake = _FakeHttp(behaviours)
    client = LLMClient()
    client.client = fake

    # 成本记账用替身：真实 cost_tracker 是进程级单例，会把本次验收的
    # token 记进今日预算，影响后续跑批。量具不许污染被测系统。
    class _Cost:
        def record(self, *a, **k):
            pass

        def is_over_budget(self):
            return False

        def stats(self):
            return {}

    import summary_compression as sc
    monkeypatch.setattr(sc, "cost_tracker", _Cost())
    # 重试之间的真实 sleep 会拖慢验收；退避本身由独立用例验证。
    monkeypatch.setattr(sc.asyncio, "sleep", _no_sleep)
    return client, fake


async def _no_sleep(_seconds):
    return None


async def _chat_http(client):
    payload = {"model": "m", "messages": [{"content": "hi"}], "temperature": 0.3}
    return await client._chat_http(payload, 5, 0.0, 0, "cache-key-x")


class TestRetryAndTimeout:
    """E-2 / E-3：退避带抖动、真实请求数可观测、5xx 不重试、超时四段分离。"""

    def test_s9_backoff_is_exponential_capped_and_jittered(self):
        """E-2：指数退避 + 上限 + 全抖动。

        用分布而不是单次取值来断言 —— 固定退避也能通过单点检查。
        """
        from summary_compression import LLMClient
        from config import settings

        base = float(getattr(settings, "llm_retry_base_s", 0.5) or 0.5)
        cap = float(getattr(settings, "llm_retry_max_s", 8.0) or 8.0)

        samples = {n: [LLMClient._retry_backoff_s(n) for _ in range(300)] for n in range(4)}
        for n, vals in samples.items():
            ceiling = min(cap, base * (2 ** n))
            assert all(0.0 <= v <= ceiling for v in vals), \
                f"attempt={n} 退避越界 (ceiling={ceiling}): {min(vals)}~{max(vals)}"
            assert len(set(vals)) > 1, \
                f"attempt={n} 退避恒定 —— 没有抖动，多协程会同步重试形成风暴"
            assert max(vals) > 0.0, f"attempt={n} 退避恒为 0 —— 等于没有退避"

        # 指数增长：高档位的天花板必须严格高于低档位（否则退化成固定退避）
        assert min(cap, base * 2 ** 3) > min(cap, base * 2 ** 0)
        # 封顶生效
        assert max(LLMClient._retry_backoff_s(20) for _ in range(50)) <= cap

    def test_s10_timeout_has_four_distinct_segments(self, monkeypatch):
        """E-3：connect/read/write/pool 四段必须分别设定，不被单值覆盖。"""
        from config import settings

        monkeypatch.setattr(settings, "llm_request_timeout_s", 90.0)
        monkeypatch.setattr(settings, "llm_connect_timeout_s", 10.0)

        client, fake = _make_client(monkeypatch, [_FakeResp()])
        _run(_chat_http(client))

        assert len(fake.calls) == 1
        t = fake.calls[0]["timeout"]
        assert isinstance(t, httpx.Timeout), f"timeout 类型不对: {type(t)}"
        assert t.connect == 10.0, f"connect 段被覆盖: {t.connect}"
        assert t.read == 90.0, f"read 段错误: {t.read}"
        assert t.write == 90.0 and t.pool == 90.0
        assert t.connect != t.read, "connect 被拉成与 read 同值 —— 快速失败失效"

    def test_s11_actual_upstream_requests_are_counted_not_logical_calls(self, monkeypatch):
        """E-2：一次逻辑调用 + 两次连接失败重试 = 上游真实 3 次请求。

        注意触发重试的是 ``httpx.ConnectError``（走 except Exception 分支）；
        ``ReadTimeout`` 走的是「立即降级不重试」分支，见 s13。
        用错异常类型会把量具的期望建在错误的行为上。

        正对照紧跟其后：无重试时必须是 1 —— 否则说明计数器在虚增。
        """
        client, fake = _make_client(
            monkeypatch,
            [httpx.ConnectError("refused"), httpx.ConnectError("refused"), _FakeResp()],
        )
        out = _run(_chat_http(client))

        assert len(fake.calls) == 3, f"真实发出的请求数不符: {len(fake.calls)}"
        stats = client.http_request_stats()
        assert stats["http_requests_total"] == 3, f"实际请求数统计错误: {stats}"
        assert stats["http_retries_total"] == 2, f"重试数统计错误: {stats}"

        client2, fake2 = _make_client(monkeypatch, [_FakeResp()])
        _run(_chat_http(client2))
        assert len(fake2.calls) == 1
        assert client2.http_request_stats() == {
            "http_requests_total": 1, "http_retries_total": 0,
        }, "无重试时统计必须正好是 1 次 / 0 重试"

    def test_s12_server_error_is_not_retried(self, monkeypatch):
        """E-2：上游 5xx 立即放弃，不重试（三次瞬时重连只会打挂刚恢复的上游）。"""
        client, fake = _make_client(monkeypatch, [_FakeResp(status_code=503)])
        out = _run(_chat_http(client))

        assert len(fake.calls) == 1, f"5xx 被重试了 {len(fake.calls)} 次"
        data = json.loads(out)
        assert data["fallback"] is True
        assert data["retryable"] is False
        assert data["error_type"] == "upstream_503"

    def test_s13_timeout_returns_explicit_failure_immediately(self, monkeypatch):
        """E-3 超时必须返回**可判别**的失败体，而不是空串或 None。

        同时固化一条真实行为：超时立即降级、**不重试**
        （_chat_http 的 ``except httpx.TimeoutException`` 直接 return）。
        这一点与连接类失败不同，写断言时不能混用。
        """
        client, fake = _make_client(monkeypatch, [httpx.ReadTimeout("slow")])
        out = _run(_chat_http(client))
        data = json.loads(out)
        assert len(fake.calls) == 1, f"超时被重试了 {len(fake.calls)} 次"
        assert data["fallback"] is True
        assert data["error_type"] == "llm_request_timeout"
        assert data["http_requests"] == 1
        assert is_llm_fallback(out)[0] is True, "超时降级未被 is_llm_fallback 识别"


# ══════════════════════════════════════════════════════════════
# E-5 · 模板变量契约在真实调用点生效
# ══════════════════════════════════════════════════════════════

class _Any:
    """能同时充当数字 / 字符串 / 序列 / 对象的渲染占位值。

    用纯字符串当占位会在真实模板上炸掉 —— 比如
    ``{{ '%.3f'|format(anomaly_score) }}`` 遇到 str 直接 TypeError，
    而那是**量具**的问题，不是模板的问题。实现全部转换协议后，
    任何模板都能被真实渲染一遍，渲染失败才真的说明模板有问题。
    """

    def __float__(self): return 0.0
    def __int__(self): return 0
    def __index__(self): return 0
    def __round__(self, ndigits=None): return 0
    def __str__(self): return "0"
    def __repr__(self): return "0"
    def __bool__(self): return False
    def __len__(self): return 0
    def __iter__(self): return iter(())
    def __contains__(self, item): return False
    def __getitem__(self, key): return _Any()
    def __getattr__(self, name): return _Any()
    def __format__(self, spec): return "0"
    def __add__(self, other): return _Any()
    def __radd__(self, other): return _Any()
    def __mul__(self, other): return _Any()
    def __rmul__(self, other): return _Any()
    def __lt__(self, other): return False
    def __le__(self, other): return False
    def __gt__(self, other): return False
    def __ge__(self, other): return False

    def __call__(self, *a, **k): return _Any()


def _placeholder(var_name: str):
    """给渲染用的占位值（名字只是可读性，真正起作用的是 _Any）。"""
    return _Any()


def _iter_literal_render_sites():
    """AST 扫出真实调用点 render("字面量模板名", ...)，产出 (文件:行, 模板名, 关键字 dict)。"""
    import ast
    import pathlib

    backend = pathlib.Path(__file__).resolve().parent.parent
    for py in sorted(backend.rglob("*.py")):
        rel = py.relative_to(backend).as_posix()
        if rel.startswith("tests/") or "__pycache__" in rel:
            continue
        try:
            tree = ast.parse(py.read_text(encoding="utf-8"))
        except Exception:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not node.args:
                continue
            fname = (node.func.id if isinstance(node.func, ast.Name)
                     else node.func.attr if isinstance(node.func, ast.Attribute) else None)
            if fname != "render":
                continue
            a0 = node.args[0]
            if not (isinstance(a0, ast.Constant) and isinstance(a0.value, str)):
                continue
            kwargs = {}
            for k in node.keywords:
                if not k.arg:
                    continue
                try:
                    kwargs[k.arg] = ast.literal_eval(k.value)
                except Exception:
                    kwargs[k.arg] = _Any()
            yield f"{rel}:{node.lineno}", a0.value, kwargs


class TestPromptTemplateContract:
    """E-5：在真实调用点上真的渲染一遍，而不是只比对手工 mock 表。"""

    def test_s14_every_real_call_site_renders_under_strict_contract(self):
        from prompts import loader

        sites = list(_iter_literal_render_sites())
        assert len(sites) >= 20, f"只扫到 {len(sites)} 个调用点 —— AST 扫描本身可能已失效"

        prev = loader.set_strict_render(True)
        rendered = 0
        problems = []
        try:
            assert loader.render_is_strict() is True
            for where, tpl, kwargs in sites:
                try:
                    out = loader.render(tpl, **kwargs)
                except loader.MissingTemplateVars as e:
                    problems.append(f"{where} {tpl} 缺变量 {e.missing}")
                    continue
                except FileNotFoundError:
                    problems.append(f"{where} 模板不存在: {tpl}")
                    continue
                except Exception as e:  # 模板本体渲染失败
                    problems.append(f"{where} {tpl} 渲染报错 {type(e).__name__}: {e}")
                    continue
                if not isinstance(out, str) or not out.strip():
                    problems.append(f"{where} {tpl} 渲染出空提示词")
                    continue
                rendered += 1
        finally:
            loader.set_strict_render(prev)

        assert not problems, "真实调用点渲染失败:\n  " + "\n  ".join(problems[:10])
        assert rendered == len(sites)

    def test_s15_missing_variable_raises_instead_of_silent_blank(self):
        """缺变量必须抛 MissingTemplateVars，而不是渲染出一个空洞提示词。

        正对照：把变量补齐，同一个模板必须正常渲染 —— 证明不是模板本身坏了。
        """
        from prompts import loader
        from prompts.loader import template_variables

        tpl = "audit/sub_auditor_prompt"
        need = template_variables(tpl)
        assert need, "模板变量集为空，契约形同虚设"

        prev = loader.set_strict_render(True)
        try:
            with pytest.raises(loader.MissingTemplateVars) as ei:
                loader.render(tpl, **{})
            assert set(ei.value.missing) & need, "异常里没有报出缺失变量"
            assert isinstance(ei.value, Exception)

            # 正对照：全部补齐后可渲染
            ctx = {v: _placeholder(v) for v in need}
            out = loader.render(tpl, **ctx)
            assert isinstance(out, str) and out.strip()
        finally:
            loader.set_strict_render(prev)
