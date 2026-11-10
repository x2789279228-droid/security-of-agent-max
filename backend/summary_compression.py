import asyncio
import json
import logging
import hashlib
import time
import re
from collections import defaultdict
from datetime import date

import httpx

from config import settings

logger = logging.getLogger(__name__)

_CJK_RE = re.compile(r"[\u4e00-\u9fff]")


def estimate_tokens(text: str) -> int:
    """估算 token 数（中文按字计，其余按 2 字符/1 token）"""
    if not text:
        return 0
    chinese = len(_CJK_RE.findall(text))
    other = len(text) - chinese
    return chinese + int(other / 2) + 1


class CostTracker:
    """LLM 成本追踪器 — 每日预算 + 每事件费用

    预算与单价来自 settings (SHARED_MEMORY_LLM_DAILY_BUDGET_TOKENS /
    SHARED_MEMORY_LLM_PRICE_INPUT_PER_1K_TOKENS /
    SHARED_MEMORY_LLM_PRICE_OUTPUT_PER_1K_TOKENS)。
    输入/输出分别计价, 与主流 API 计费模型一致。
    用量同时落库于 llm_traces (由 trace_hook 持久化), 内存仅作运行期门禁;
    重启后用 restore_today_usage() 从 DB 重建当日用量, 保证预算门禁不因重启失效。
    """

    def __init__(
        self,
        daily_budget_tokens: int = 5_000_000,
        price_input_per_1k: float = 0.0,
        price_output_per_1k: float = 0.0,
        unlimited: bool = None,
    ):
        self.daily_budget = daily_budget_tokens
        self.price_input_per_1k = price_input_per_1k
        self.price_output_per_1k = price_output_per_1k
        if unlimited is None:
            unlimited = daily_budget_tokens <= 0
        self._unlimited = bool(unlimited)
        self._daily_usage: dict[str, int] = defaultdict(int)  # date → total_tokens
        self._daily_prompt: dict[str, int] = defaultdict(int)  # date → prompt_tokens
        self._daily_completion: dict[str, int] = defaultdict(int)  # date → completion_tokens
        self._event_costs: dict[int, int] = {}  # event_id → total_tokens
        self._call_count: dict[str, int] = defaultdict(int)  # date → call_count

    def record(self, tokens: int, event_id: int = 0,
               prompt_tokens: int = 0, completion_tokens: int = 0):
        today = date.today().isoformat()
        self._daily_usage[today] += tokens
        self._daily_prompt[today] += prompt_tokens or 0
        self._daily_completion[today] += completion_tokens or 0
        self._call_count[today] += 1
        if event_id:
            self._event_costs[event_id] = self._event_costs.get(event_id, 0) + tokens
        # Prometheus 暴露 token 消耗(供对齐 token reduction 目标)
        try:
            from metrics import inc_llm_tokens
            inc_llm_tokens("llm", int(tokens or 0))
        except Exception:
            pass

    def restore_today_usage(self, tokens: int, calls: int = 0,
                            prompt_tokens: int = 0, completion_tokens: int = 0) -> None:
        """从持久化数据恢复今日用量 (启动时调用, 覆盖而非累加)"""
        today = date.today().isoformat()
        self._daily_usage[today] = max(0, int(tokens or 0))
        self._daily_prompt[today] = max(0, int(prompt_tokens or 0))
        self._daily_completion[today] = max(0, int(completion_tokens or 0))
        if calls:
            self._call_count[today] = max(0, int(calls or 0))

    def is_over_budget(self) -> bool:
        if self._unlimited:
            return False
        today = date.today().isoformat()
        return self._daily_usage[today] >= self.daily_budget

    def remaining_budget(self):
        if self._unlimited:
            return None
        today = date.today().isoformat()
        return max(0, self.daily_budget - self._daily_usage[today])

    def estimate_cost_yuan(self, prompt_tokens: int, completion_tokens: int) -> float:
        """按输入/输出每千 token 单价估算费用。

        返回人民币元(¥): price_*_per_1k 的单位为 ¥/1K tokens
        (本项目按 mimo-v2.5 官方单价配置, 0.001 输入 / 0.002 输出)。
        """
        cost = 0.0
        if self.price_input_per_1k > 0:
            cost += (max(0, int(prompt_tokens or 0)) / 1000) * self.price_input_per_1k
        if self.price_output_per_1k > 0:
            cost += (max(0, int(completion_tokens or 0)) / 1000) * self.price_output_per_1k
        return round(cost, 4)

    # 弃用别名: 历史命名误标 JPY(实为人民币元), 保留一个版本供旧调用方过渡
    estimate_cost_jpy = estimate_cost_yuan

    def stats(self) -> dict:
        today = date.today().isoformat()
        used = self._daily_usage.get(today, 0)
        prompt = self._daily_prompt.get(today, 0)
        completion = self._daily_completion.get(today, 0)
        return {
            "daily_budget": self.daily_budget,
            "today_usage": used,
            "today_prompt": prompt,
            "today_completion": completion,
            "today_calls": self._call_count.get(today, 0),
            "remaining": self.remaining_budget(),
            "over_budget": self.is_over_budget(),
            "unlimited": bool(self._unlimited),
            "usage_pct": (0.0 if self._unlimited else
                          round(used / self.daily_budget * 100, 1) if self.daily_budget else 0.0),
            "price_input_per_1k": self.price_input_per_1k,
            "price_output_per_1k": self.price_output_per_1k,
            "estimated_cost_yuan": self.estimate_cost_yuan(prompt, completion),
            # 弃用键: 与 estimated_cost_yuan 同值, 保留一个版本供前端/脚本迁移
            "estimated_cost_jpy": self.estimate_cost_yuan(prompt, completion),
            "tracked_events": len(self._event_costs),
        }


cost_tracker = CostTracker(
    daily_budget_tokens=settings.llm_daily_budget_tokens,
    unlimited=getattr(settings, "llm_budget_unlimited", None),
    price_input_per_1k=settings.llm_price_input_per_1k_tokens,
    price_output_per_1k=settings.llm_price_output_per_1k_tokens,
)


def _extract_text_content(data: dict) -> str:
    """从 LLM 响应中稳健提取文本内容（兼容 OpenAI 标准与讯飞 MaaS/ASTRON 等非标准 schema）。

    OpenAI 兼容: {choices:[{message:{content}}]} 或 delta.content (流式)
    ASTRON/讯飞 MaaS: 可能为 {content:...} / {output_text:...} / {text:...} / {response:...}
    """
    if not isinstance(data, dict):
        raise ValueError("LLM 响应不是 JSON 对象")
    # 标准 OpenAI chat/completions
    try:
        choices = data.get("choices") or []
        if choices:
            msg = choices[0].get("message") or choices[0].get("delta") or {}
            c = msg.get("content")
            if isinstance(c, list):  # 多模态 content 数组 → 取首个 text
                for part in c:
                    if isinstance(part, dict) and part.get("type") == "text":
                        c = part.get("text")
                        break
            if c is not None:
                return str(c)
    except Exception:
        pass
    # 常见非标准/扁平字段
    for key in ("output_text", "text", "content", "response", "answer", "result"):
        v = data.get(key)
        if isinstance(v, str) and v:
            return v
    # 嵌套 choices[0].text (AISTUDIO/部分 vLLM)
    try:
        c = data["choices"][0].get("text")
        if isinstance(c, str) and c:
            return c
    except Exception:
        pass
    raise ValueError(f"无法从 LLM 响应提取文本: {list(data.keys())[:6]}")


class LLMClient:
    """LLM 客户端 — 支持重试、降级、成本控制、响应缓存"""

    def __init__(self):
        self.api_key = settings.llm_api_key
        self.base_url = settings.llm_base_url.rstrip("/")
        self.model = settings.llm_model
        self.client: httpx.AsyncClient | None = None
        # LLM 响应缓存: 进程内 dict 作为快速路径, Redis 作为跨重启/跨容器共享源
        self._response_cache: dict[str, str] = {}  # key → response(JSON {v,t}), 快速路径
        self.redis = None
        self._cache_ttl = settings.llm_cache_ttl

    def set_redis(self, redis_client):
        self.redis = redis_client

    async def ensure_client(self):
        if self.client is None:
            self.client = httpx.AsyncClient(
                timeout=httpx.Timeout(connect=10.0, read=90.0, write=10.0, pool=10.0),
            )

    @staticmethod
    def _prompt_text(messages: list[dict]) -> str:
        """拼接消息文本(缓存键/用量估算用)。

        2026-11-10 多模态兼容: content 可能是 OpenAI 多模态数组
        [{type:image_url},{type:text},...] —— 只取 text 片段, 图像不计字符。
        MiniMax 时代视觉链路从未真实启用, 此前 "\n".join 直接炸 TypeError。
        """
        parts = []
        for m in messages:
            c = m.get("content", "")
            if isinstance(c, str):
                parts.append(c)
            elif isinstance(c, list):
                parts.append(" ".join(
                    p.get("text", "") for p in c
                    if isinstance(p, dict) and p.get("type") == "text"
                ))
        return "\n".join(p for p in parts if p)

    async def chat(self, messages: list[dict], temperature: float = 0.3, model: str = "") -> str:
        from trace_hook import emit_trace, get_trace_context

        t_start = time.time()
        prompt_text = self._prompt_text(messages)
        prompt_tokens = estimate_tokens(prompt_text)
        ctx = get_trace_context()
        event_id = int(ctx.get("event_id", 0) or 0)
        # 2026-11-09: model 纳入缓存键 —— 同一 prompt 走不同模型(如视觉/非视觉)
        # 的响应不可互串, 否则视觉调用会命中纯文本模型的缓存。
        use_model = model or self.model

        # 响应缓存（相同 prompt + temperature → 缓存响应）: Redis 主源 + 本地 dict 快速路径
        # 缓存命中是零 token 成本路径（不扣预算），必须置于预算门禁之前——
        # 否则预算耗尽期间连免费命中也不可达，缓存"只出不进"随 TTL 枯竭（被门禁饿死）。
        digest = hashlib.md5(
            f"{prompt_text}:{temperature}:{use_model}".encode("utf-8"), usedforsecurity=False
        ).hexdigest()
        cache_key = f"llmcache:{digest}"
        cached = await self._cache_get(cache_key)
        if cached is not None:
            emit_trace(
                status="success", cache_hit=True,
                prompt_tokens=prompt_tokens, completion_tokens=0, total_tokens=0,
                latency_ms=(time.time() - t_start) * 1000,
            )
            return cached

        # 成本检查：超预算时降级（仅拦真实 API 调用，上面的缓存命中不受门禁影响）
        if cost_tracker.is_over_budget():
            logger.warning("[CostControl] Daily budget exhausted, returning fallback")
            emit_trace(
                status="degraded", error_type="budget_exhausted",
                prompt_tokens=prompt_tokens,
                latency_ms=(time.time() - t_start) * 1000,
            )
            return json.dumps({
                "error": "每日 LLM 预算已用尽", "fallback": True,
                "budget_stats": cost_tracker.stats(),
            }, ensure_ascii=False)

        if not self.api_key:
            logger.warning("LLM API key not configured, returning fallback")
            emit_trace(
                status="degraded", error_type="no_api_key",
                prompt_tokens=prompt_tokens,
                latency_ms=(time.time() - t_start) * 1000,
            )
            return json.dumps({"error": "LLM未配置", "fallback": True}, ensure_ascii=False)
        await self.ensure_client()
        payload = {
            "model": use_model,
            "messages": messages,
            "temperature": temperature,
            "reasoning_split": True,  # MiniMax-M3: thinking 拆到独立字段，不污染 JSON 输出
        }
        effort = (getattr(settings, "llm_reasoning_effort", "") or "").strip()
        if effort:
            payload["reasoning_effort"] = effort
        from llm_limiter import LlmRateExceeded, LlmSlotTimeout, get_llm_limiter
        _triage = (ctx.get("log_data") or {}).get("_audit_triage") or {}
        _tier = str(_triage.get("tier") or ctx.get("tier") or "P2")
        try:
            async with get_llm_limiter().acquire(tier=_tier):
                return await self._chat_http(
                    payload, prompt_tokens, t_start, event_id, cache_key,
                )
        except LlmSlotTimeout as e:
            logger.warning("LLM slot timeout: %s", e)
            emit_trace(
                status="degraded", error_type="llm_slot_timeout",
                prompt_tokens=prompt_tokens,
                latency_ms=(time.time() - t_start) * 1000,
            )
            return json.dumps({
                "error": "LLM slot timeout", "fallback": True,
                "error_type": "llm_slot_timeout", "retryable": True,
            }, ensure_ascii=False)
        except LlmRateExceeded as e:
            logger.warning("LLM rate limit: %s", e)
            emit_trace(
                status="degraded", error_type="llm_rate_limited",
                prompt_tokens=prompt_tokens,
                latency_ms=(time.time() - t_start) * 1000,
            )
            return json.dumps({
                "error": "LLM rate limit", "fallback": True,
                "error_type": "llm_rate_limited", "retryable": True,
            }, ensure_ascii=False)

    async def chat_stream(self, messages: list[dict], temperature: float = 0.3,
                          model: str = ""):
        """流式对话 — 逐 delta 产出帧 dict（Copilot 专用，2026-11 AI Web改造）。

        model: 覆盖默认模型（Copilot 图像理解走独立视觉模型时传入），
        空 = 用 self.model。

        与 chat() 共享三道门禁（api_key → 日预算 → 限流槽），但有两处刻意不同：
        - 不走响应缓存：流式答案按会话语境即时生成，相同 prompt 的缓存命中
          无意义（会话历史不同 → prompt 不同）；
        - 不做 429/5xx 重试：流式一旦开始已向调用方吐出增量，重试会造成
          内容重复；交互场景由前端提示后用户手动重发更诚实（明示，不伪装）。

        产出帧协议（dict，由 routers/copilot.py 转 SSE 帧）：
          {"type": "reasoning", "text": str}   思考增量（网关未拆分思考时无此帧）
          {"type": "content",   "text": str}   正文增量
          {"type": "error",     "text": str, "error_type": str, "fallback": True}
          {"type": "done",      "content": str, "reasoning": str, "usage": {...}}

        reasoning 兼容三种网关口径：delta.reasoning_content（DeepSeek-R1/GLM/
        MiniMax 流式通用）、delta.reasoning（部分 vLLM）、content 数组内的
        thinking 分片。HTTP 400 且带 reasoning_effort 时先剥参重发一次
        （与 chat() 的降级口径一致，此时流尚未开始，重发无害）。
        """
        from trace_hook import emit_trace, get_trace_context

        t_start = time.time()
        prompt_text = self._prompt_text(messages)
        prompt_tokens = estimate_tokens(prompt_text)
        ctx = get_trace_context()
        event_id = int(ctx.get("event_id", 0) or 0)

        def _err(error_type: str, text: str) -> dict:
            emit_trace(
                status="degraded", error_type=error_type,
                model=self.model, prompt_tokens=prompt_tokens,
                latency_ms=(time.time() - t_start) * 1000,
            )
            return {"type": "error", "text": text, "fallback": True,
                    "error_type": error_type}

        # 门禁 1：未配置 key —— 与 chat() 同口径（诚实降级，不抛异常打断 SSE）
        if not self.api_key:
            yield _err("no_api_key", "LLM 未配置，无法流式生成")
            return
        # 门禁 2：日预算（只拦真实调用）
        if cost_tracker.is_over_budget():
            logger.warning("[CostControl] Daily budget exhausted, stream rejected")
            yield _err("budget_exhausted", "每日 LLM 预算已用尽，流式生成被降级")
            return

        await self.ensure_client()
        payload = {
            "model": model or self.model,
            "messages": messages,
            "temperature": temperature,
            "stream": True,
            "reasoning_split": True,  # MiniMax-M3: 思考拆到独立字段，不污染正文
        }
        effort = (getattr(settings, "llm_reasoning_effort", "") or "").strip()
        if effort:
            payload["reasoning_effort"] = effort

        from llm_limiter import LlmSlotTimeout, LlmRateExceeded, get_llm_limiter
        try:
            async with get_llm_limiter().acquire(tier="P2"):
                async for frame in self._chat_stream_http(
                    payload, prompt_tokens, t_start, event_id, effort,
                ):
                    yield frame
        except LlmSlotTimeout as e:
            logger.warning("LLM slot timeout (stream): %s", e)
            yield _err("llm_slot_timeout", "LLM 并发槽超时，请稍后重试")
        except LlmRateExceeded as e:
            logger.warning("LLM rate limit (stream): %s", e)
            yield _err("llm_rate_limited", "LLM 限流中，请稍后重试")

    async def _chat_stream_http(self, payload, prompt_tokens, t_start, event_id, effort):
        """chat_stream 的 HTTP 执行段（限流槽内调用）。"""
        from trace_hook import emit_trace

        model_name = str(payload.get("model") or self.model)

        req_payload = dict(payload)
        req_timeout = float(getattr(settings, "llm_request_timeout_s", 90) or 90)
        content_parts: list[str] = []
        reasoning_parts: list[str] = []
        completion_tokens = 0
        try:
            resp = await self.client.post(
                f"{self.base_url}/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                    "Accept": "text/event-stream",
                },
                json=req_payload,
                timeout=httpx.Timeout(
                    connect=float(getattr(settings, "llm_connect_timeout_s", 10.0) or 10.0),
                    read=max(0.05, req_timeout),
                    write=max(0.05, req_timeout),
                    pool=max(0.05, req_timeout),
                ),
            )
            # 400 + reasoning_effort：网关不认识该参数 —— 剥掉重发一次
            #（此刻流尚未开始，无重复输出风险，与 chat() 降级口径一致）
            if resp.status_code == 400 and effort:
                req_payload.pop("reasoning_effort", None)
                resp = await self.client.post(
                    f"{self.base_url}/chat/completions",
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json",
                        "Accept": "text/event-stream",
                    },
                    json=req_payload,
                    timeout=httpx.Timeout(
                        connect=float(getattr(settings, "llm_connect_timeout_s", 10.0) or 10.0),
                        read=max(0.05, req_timeout),
                        write=max(0.05, req_timeout),
                        pool=max(0.05, req_timeout),
                    ),
                )
            if resp.status_code == 429:
                yield {"type": "error", "text": "LLM 限流（429），请稍后重试",
                       "fallback": True, "error_type": "rate_limited_429",
                       "retryable": True}
                return
            if resp.status_code >= 500:
                yield {"type": "error", "text": f"LLM 上游错误 {resp.status_code}",
                       "fallback": True, "error_type": f"upstream_{resp.status_code}",
                       "retryable": False}
                return
            if resp.status_code != 200:
                body_snippet = (await resp.aread())[:200].decode("utf-8", errors="replace")
                logger.warning("LLM stream unexpected status %s: %s",
                               resp.status_code, body_snippet)
                yield {"type": "error", "text": f"LLM 流式接口异常 {resp.status_code}",
                       "fallback": True, "error_type": f"http_{resp.status_code}",
                       "retryable": False}
                return

            # 逐行解析 OpenAI 兼容 SSE：`data: {...}` 行，`data: [DONE]` 结束。
            # 部分网关在事件间夹注释行（`:` 开头）与心跳空行，均跳过。
            async for line in resp.aiter_lines():
                if not line or line.startswith(":"):
                    continue
                if not line.startswith("data:"):
                    continue
                data_str = line[5:].strip()
                if data_str == "[DONE]":
                    break
                try:
                    chunk = json.loads(data_str)
                except ValueError:
                    continue
                choices = chunk.get("choices") or []
                if not choices:
                    continue
                delta = choices[0].get("delta") or {}
                # reasoning 增量：reasoning_content（主流）/ reasoning（部分 vLLM）
                r = delta.get("reasoning_content") or delta.get("reasoning") or ""
                if r:
                    reasoning_parts.append(str(r))
                    yield {"type": "reasoning", "text": str(r)}
                c = delta.get("content")
                if isinstance(c, list):
                    # content 数组（多模态网关）：取 text 分片
                    c = "".join(
                        p.get("text", "") for p in c
                        if isinstance(p, dict) and p.get("type") == "text"
                    )
                if c:
                    content_parts.append(str(c))
                    completion_tokens += estimate_tokens(str(c))
                    yield {"type": "content", "text": str(c)}

        except httpx.TimeoutException as e:
            logger.warning("LLM stream timeout: %s", type(e).__name__)
            emit_trace(
                status="degraded", error_type="llm_request_timeout",
                model=model_name, prompt_tokens=prompt_tokens,
                latency_ms=(time.time() - t_start) * 1000,
            )
            # 已吐出的增量不撤回 —— 补一个 error 帧，前端如实标注"中断"
            yield {"type": "error", "text": "LLM 流式响应超时中断", "fallback": True,
                   "error_type": "llm_request_timeout", "retryable": True}
            return
        except Exception as e:
            logger.warning("LLM stream failed: %s", e)
            emit_trace(
                status="degraded", error_type=type(e).__name__,
                model=model_name, prompt_tokens=prompt_tokens,
                latency_ms=(time.time() - t_start) * 1000,
            )
            yield {"type": "error", "text": "LLM 流式响应中断", "fallback": True,
                   "error_type": type(e).__name__, "retryable": True}
            return

        content = "".join(content_parts)
        reasoning = "".join(reasoning_parts)
        total_tokens = prompt_tokens + completion_tokens
        cost_tracker.record(
            total_tokens, event_id=event_id,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
        )
        emit_trace(
            status="success",
            model=model_name,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=total_tokens,
            latency_ms=(time.time() - t_start) * 1000,
        )
        yield {"type": "done", "content": content, "reasoning": reasoning,
               "usage": {"prompt_tokens": prompt_tokens,
                         "completion_tokens": completion_tokens,
                         "total_tokens": total_tokens}}

    @staticmethod
    def _retry_backoff_s(attempt: int) -> float:
        """P2-E-2: 指数退避 + 全抖动（full jitter）。

        base * 2^attempt 上限，再乘 [0,1) 随机因子。
        全抖动而非固定退避：多进程/多协程同时失败时，固定退避会让它们
        在同一毫秒一起重试，形成同步重试风暴。
        """
        import random as _random

        base = float(getattr(settings, "llm_retry_base_s", 0.5) or 0.5)
        cap = float(getattr(settings, "llm_retry_max_s", 8.0) or 8.0)
        try:
            n = max(0, int(attempt))
        except (TypeError, ValueError):
            n = 0
        ceiling = min(cap, base * (2 ** n))
        return max(0.0, _random.uniform(0.0, ceiling))

    def _note_http_request(self, actual_requests: int, retries: int) -> None:
        """P2-E-2: 记录**实际**打到上游的请求数。

        修复前 llm_rate_per_minute 统计的是「逻辑调用」——
        llm_limiter 在进 slot 时扣一次，而重试发生在 slot 内部。
        于是重试放大时，限流器看到的是 1 次，实际是 3 次。
        真实请求数在这里单独可观测，不改限流器的计费语义。
        """
        n = max(0, int(actual_requests or 0))
        if n <= 0:
            return
        self._http_requests_total = getattr(self, "_http_requests_total", 0) + n
        self._http_retries_total = getattr(self, "_http_retries_total", 0) + max(
            0, int(retries or 0)
        )
        if n > 1:
            logger.warning(
                f"LLM logical call became {n} upstream requests "
                f"(retries={retries}) — rate limiting sees 1, upstream sees {n}"
            )

    def http_request_stats(self) -> dict:
        """实际 HTTP 请求统计（与逻辑调用分开）。"""
        return {
            "http_requests_total": getattr(self, "_http_requests_total", 0),
            "http_retries_total": getattr(self, "_http_retries_total", 0),
        }

    async def _chat_http(self, payload, prompt_tokens, t_start, event_id, cache_key) -> str:

        from trace_hook import emit_trace
        last_error = None
        retries = 0
        _no_reasoning_split = False
        # P2-E-2: 实际发出的 HTTP 请求数。修复前只有「逻辑调用」计数：
        # llm_limiter 在**进 slot 时**扣一次额度，而重试发生在 slot 内部，
        # 于是 llm_rate_per_minute 统计的是逻辑调用而非真实打到
        # 上游的请求数 —— 限流器在重试放大时看不到真实压力。
        actual_requests = 0
        for attempt in range(3):
            try:
                req_payload = dict(payload)
                if _no_reasoning_split:
                    req_payload.pop("reasoning_split", None)
                req_timeout = float(getattr(settings, "llm_request_timeout_s", 90) or 90)
                actual_requests += 1
                resp = await self.client.post(
                    f"{self.base_url}/chat/completions",
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json",
                    },
                    json=req_payload,
                    # P2-E-3: 单值 Timeout 会把 connect/read/write/pool
                    # 全部覆盖成同一个数 —— 原本 connect=10s 的快速失败
                    # 被拉成 90s，一个连不上的上游要等满 90 秒。
                    # 显式给四段：连接仍快速失败，整体仍受 req_timeout 约束。
                    timeout=httpx.Timeout(
                        connect=float(getattr(settings, "llm_connect_timeout_s", 10.0) or 10.0),
                        read=max(0.05, req_timeout),
                        write=max(0.05, req_timeout),
                        pool=max(0.05, req_timeout),
                    ),
                )
                if resp.status_code == 400 and "reasoning_effort" in req_payload:
                    payload.pop("reasoning_effort", None)
                    continue
                if resp.status_code == 429:
                    try:
                        from metrics import inc_llm_429
                        inc_llm_429()
                    except Exception:
                        pass
                    retry_after = (resp.headers.get("retry-after") or "").strip()
                    wait_cap = float(getattr(settings, "llm_429_retry_s", 1.0) or 1.0)
                    wait_s = wait_cap
                    if retry_after:
                        try:
                            wait_s = min(wait_cap, max(0.05, float(retry_after)))
                        except ValueError:
                            pass
                    retries += 1
                    last_error = f"HTTP 429 Too Many Requests (attempt {attempt+1})"
                    emit_trace(
                        status="degraded", error_type="rate_limited_429",
                        prompt_tokens=prompt_tokens,
                        latency_ms=(time.time() - t_start) * 1000,
                        retry_count=retries,
                    )
                    if retries <= 1:
                        logger.warning(
                            "LLM rate-limited (429), short retry %.2fs (attempt %s)",
                            wait_s, attempt + 1,
                        )
                        await asyncio.sleep(wait_s)
                        continue
                    logger.warning("LLM 429 after short retry — releasing slot")
                    return json.dumps({
                        "error": "LLM rate-limited",
                        "fallback": True,
                        "error_type": "rate_limited_429",
                        "retryable": True,
                        "http_requests": actual_requests,
                    }, ensure_ascii=False)

                # P2-E-2: 5xx 立即放弃，不重试。
                # 修复前走 `except Exception` 无差别重发：上游 500/502/503 时
                # 三次瞬时重连既救不回来，又把上游刚恢复的窗口重新打挂。
                if resp.status_code >= 500:
                    logger.error(
                        f"LLM upstream {resp.status_code} — not retrying "
                        f"(attempt {attempt+1})"
                    )
                    emit_trace(
                        status="degraded", error_type=f"upstream_{resp.status_code}",
                        model=self.model,
                        prompt_tokens=prompt_tokens,
                        latency_ms=(time.time() - t_start) * 1000,
                        retry_count=retries,
                    )
                    return json.dumps({
                        "error": f"LLM 上游错误 {resp.status_code}",
                        "fallback": True,
                        "error_type": f"upstream_{resp.status_code}",
                        "retryable": False,
                        "http_requests": actual_requests,
                    }, ensure_ascii=False)

                resp.raise_for_status()
                data = resp.json()
                try:
                    content = _extract_text_content(data)
                except (ValueError, KeyError, IndexError, TypeError):
                    if req_payload.get("reasoning_split") and not _no_reasoning_split:

                        # reasoning_split=True 时 content 可能为空(reasoning 在
                        # 独立字段), 关闭该参数让模型把正文写回 content
                        logger.warning(
                            "LLM content extraction failed with reasoning_split, "
                            "retrying with reasoning_split disabled"
                        )
                        _no_reasoning_split = True
                        retries += 1
                        continue
                    raise
                usage = data.get("usage") or {}
                total_tokens = int(usage.get("total_tokens", 0)) or (
                    prompt_tokens + estimate_tokens(content)
                )

                # 成本记录
                cost_tracker.record(
                    total_tokens, event_id=event_id,
                    prompt_tokens=int(usage.get("prompt_tokens", prompt_tokens)),
                    completion_tokens=int(usage.get("completion_tokens", estimate_tokens(content))),
                )

                # 缓存响应(Redis 主源 + 本地快速路径); TTL 交由 Redis EXPIRE 管理, 不做全量清空
                await self._cache_set(cache_key, content)

                emit_trace(
                    status="success",
                    model=self.model,
                    prompt_tokens=int(usage.get("prompt_tokens", prompt_tokens)),
                    completion_tokens=int(usage.get("completion_tokens", estimate_tokens(content))),
                    total_tokens=total_tokens,
                    latency_ms=(time.time() - t_start) * 1000,
                    retry_count=retries,
                )
                self._note_http_request(actual_requests, retries)
                return content
            except httpx.TimeoutException as e:
                logger.warning("LLM request timeout after %.1fs: %s", req_timeout, type(e).__name__)
                emit_trace(
                    status="degraded", error_type="llm_request_timeout",
                    model=self.model,
                    prompt_tokens=prompt_tokens,
                    latency_ms=(time.time() - t_start) * 1000,
                    retry_count=retries,
                )
                self._note_http_request(actual_requests, retries)
                return json.dumps({
                    "error": "LLM request timeout", "fallback": True,
                    "error_type": "llm_request_timeout", "retryable": True,
                    "http_requests": actual_requests,
                }, ensure_ascii=False)
            except Exception as e:
                retries += 1
                last_error = e
                logger.warning(f"LLM call attempt {attempt+1} failed: {e}")
                # P2-E-2: 指数退避 + 抖动。
                # 修复前三次重试之间**零等待**直接重发 —— 上游一抖动，
                # 同一秒内三个请求一起砸过去，把本来能自愈的瞬时故障
                # 变成持续过载。抖动避免多进程在同一时刻同步重试。
                if attempt < 2:
                    await asyncio.sleep(self._retry_backoff_s(attempt))
        logger.error(f"LLM call failed after retries: {last_error}")
        self._note_http_request(actual_requests, retries)
        emit_trace(
            status="degraded", error_type=type(last_error).__name__ if last_error else "unknown",
            model=self.model,
            prompt_tokens=prompt_tokens,
            latency_ms=(time.time() - t_start) * 1000,
            retry_count=retries,
        )
        return json.dumps({"error": "LLM调用失败", "fallback": True}, ensure_ascii=False)

    async def close(self):
        if self.client:
            await self.client.aclose()

    # ── LLM 响应缓存基底 (Redis 主源 + 本地 dict 快速路径) ──

    async def _cache_get(self, key: str):
        """取缓存; 命中返回内容, 未命中/异常返回 None(降级实时调用)。"""
        # 1) 本地快速路径
        local = self._response_cache.get(key)
        if local is not None:
            return local
        # 2) Redis 共享源(raw 即响应内容; 命中后回填本地)
        if self.redis is not None and key.startswith("llmcache:"):
            try:
                raw = await self.redis.get(key)
                if raw is not None:
                    text_val = raw.decode() if isinstance(raw, (bytes, bytearray)) else raw
                    self._response_cache[key] = text_val
                    if len(self._response_cache) > 5000:  # 极简上限防本地畸形膨胀
                        self._response_cache.pop(next(iter(self._response_cache)), None)
                    return text_val
            except Exception:
                pass
        return None

    async def _cache_set(self, key: str, content: str):
        """写入 Redis(带 TTL)与本地快速路径; Redis 不可用时静默降级为仅本地。"""
        self._response_cache[key] = content
        if self.redis is not None and key.startswith("llmcache:"):
            try:
                await self.redis.setex(key, self._cache_ttl, content)
            except Exception:
                pass


def is_degraded_vector(vec, eps: float = 1e-5) -> bool:
    """降级产物判定：None / 空 / **全零**（每个分量的绝对值都 <= eps）。

    `EmbeddingClient.embed()` 在失败时（无 API key / 重试耗尽）返回
    **维度正确但内容全零**的向量 —— 它与真实向量**不可区分**：
    长度对得上、能过维度护栏、`bool(vec)` 为真（所以 `if v` 那种
    「过滤失败结果」的惯例**拦不住**它）。

    后果（2026-10-20 实测，整改报告 §9.50）：
    - 存进向量库 → 一条「看起来正常、实际无信息」的脏数据；
    - 拿它去检索 → 相似度恒为 0 → 阈值全灭 → 兜底逻辑返回
      **任意一条**记录，被当成「相关记忆」交给 LLM。

    零向量是**失败信号**，不是合法结果。
    ⚠ 同一类的 `embed_batch()` 对同一失败返回 **None** ——
    两个 API 对「失败」的表达原本就不一致；本函数是**唯一**的判定口
    （`rag/seeder.py` 此前有一份**局部**实现，阈值同为 1e-5）。
    """
    if vec is None:
        return True
    try:
        vals = [float(x) for x in vec]
    except (TypeError, ValueError):
        return True
    if not vals:
        return True
    return not any(abs(x) > eps for x in vals)


class EmbeddingClient:
    """Embedding 客户端 — 支持Redis缓存与降级"""

    def __init__(self):
        self.api_key = settings.embedding_api_key
        self.base_url = settings.embedding_base_url.rstrip("/")
        self.model = settings.embedding_model
        self.client: httpx.AsyncClient | None = None
        self.redis = None
        # 缓存命中计数: hits/misses/errors — 嵌入命中率指标的数据源
        # (Redis 未注入/故障计入 misses, 该"全 miss"状态因此可见)
        self._stats = {"hits": 0, "misses": 0, "errors": 0}

    def stats(self) -> dict:
        total = self._stats["hits"] + self._stats["misses"]
        return {
            **self._stats,
            "total": total,
            "hit_rate": round(self._stats["hits"] / total, 4) if total else 0.0,
        }

    def set_redis(self, redis_client):
        self.redis = redis_client

    async def ensure_client(self):
        if self.client is None:
            self.client = httpx.AsyncClient(timeout=60.0)

    async def embed(self, text: str, type_: str = "db") -> list[float]:
        """向量化。

        type_ 默认为 "db"（用于构建向量库）；查询检索时调用方应传 "query" 以启用 MiniMax
        的不对称检索方案。本方法兼容两种响应格式：
          - MiniMax embo-01:  {vectors: [[...]], base_resp: {...}}
          - OpenAI 兼容:     {data: [{embedding: [...]}], ...}

        可观测性: 每条调用经 emit_trace(caller="embedding") 落 AgentTrace,
        cache_hit 区分缓存命中/未命中,供 agent-traces/stats 聚合命中率。
        """
        from trace_hook import emit_trace

        t_start = time.time()

        def _trace(**kw):
            emit_trace(caller="embedding", operation="embed", model=self.model,
                       total_tokens=0, latency_ms=(time.time() - t_start) * 1000, **kw)

        if not self.api_key:
            self._stats["errors"] += 1
            logger.warning("Embedding API key not configured, returning zero vector")
            _trace(status="degraded", error_type="no_api_key")
            return [0.0] * settings.embedding_dim

        # 缓存键包含 type，避免 db/query 互相串扰
        cache_key = f"embed_cache:{type_}:{hashlib.md5(text.encode('utf-8'), usedforsecurity=False).hexdigest()}"
        if self.redis:
            try:
                cached = await self.redis.get(cache_key)
            except Exception as e:
                # Redis 故障降级为 miss 继续真实调用（此前会直接冒泡中断检索）
                logger.warning(f"Embedding cache read failed, falling back to API: {e}")
                cached = None
            if cached:
                self._stats["hits"] += 1
                _trace(status="success", cache_hit=True)
                return json.loads(cached)
        self._stats["misses"] += 1

        await self.ensure_client()
        # 双协议负载(2026-11-10): MiniMax embo 系用 texts+type; OpenAI 兼容
        # 端点(火山方舟/DeepSeek/标准网关)用 input 数组。判定口径与
        # _post_embedding() 批量路径一致 —— 此前单条路径硬编码 MiniMax 协议,
        # 切方舟后 400(embed: unexpected field 'texts')。
        _low = (str(self.model or "") + "|" + str(self.base_url or "")).lower()
        if "embo" in _low or "minimax" in _low:
            payload = {"model": self.model, "texts": [text], "type": type_}
        else:
            payload = {"model": self.model, "input": [text]}
        last_error = None
        for attempt in range(2):
            try:
                resp = await self.client.post(
                    f"{self.base_url}/embeddings",
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json",
                    },
                    json=payload,
                )
                resp.raise_for_status()
                data = resp.json()
                # 双协议响应兼容：MiniMax (vectors) / OpenAI (data[].embedding)
                if isinstance(data, dict) and "vectors" in data and data["vectors"]:
                    result = data["vectors"][0]
                elif isinstance(data, dict) and "data" in data and data["data"]:
                    result = data["data"][0]["embedding"]
                else:
                    raise ValueError(f"Unknown embedding response keys: {list(data.keys()) if isinstance(data, dict) else type(data)}")
                if self.redis:
                    await self.redis.setex(cache_key, settings.embedding_cache_ttl, json.dumps(result))
                _trace(status="success", cache_hit=False)
                return result
            except Exception as e:
                last_error = e
                logger.warning(f"Embedding attempt {attempt+1} failed: {e}")
        self._stats["errors"] += 1
        logger.error(f"Embedding call failed after retries: {last_error}")
        _trace(status="error", error_type="embedding_failed")
        return [0.0] * settings.embedding_dim


    async def _post_embedding(self, texts, type_):
        import os as _o
        # 2026-11-10 修复: 默认值原为 "texts"(MiniMax 硬编码) —— 切 OpenAI 兼容
        # 端点(火山方舟等)后批量路径必 400 且静默降级零向量。改为默认 auto:
        # 按模型/网关自适应; 显式设 texts/input 时尊重人工指定。
        batch_key = _o.environ.get("SHARED_MEMORY_EMBEDDING_BATCH_KEY", "").strip().lower() or "auto"
        low = (str(self.model or "") + "|" + str(self.base_url or "")).lower()
        if batch_key not in ("texts", "input"):
            batch_key = "texts" if ("embo" in low or "minimax" in low) else "input"
        payload = {"model": self.model, batch_key: texts}
        if batch_key == "texts":
            payload["type"] = type_
        resp = await self.client.post(
            f"{self.base_url}/embeddings",
            headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
            json=payload)
        resp.raise_for_status()
        data = resp.json()
        if isinstance(data, dict) and data.get("vectors"):
            return list(data["vectors"])
        if isinstance(data, dict) and isinstance(data.get("data"), list):
            return [d["embedding"] for d in data["data"] if isinstance(d, dict) and "embedding" in d]
        raise ValueError("Unknown embedding response keys")

    async def embed_batch(self, texts, type_: str = "db"):
        import json as _json
        import hashlib as _hash
        import logging as _log
        from trace_hook import emit_trace
        t0 = __import__("time").time()
        items = list(texts)
        out = [None] * len(items)
        miss_idx = []
        for i, tx in enumerate(items):
            if not isinstance(tx, str) or not tx.strip():
                out[i] = [0.0] * settings.embedding_dim
                continue
            key = f"embed_cache:{type_}:{_hash.md5(tx.encode('utf-8'), usedforsecurity=False).hexdigest()}"
            val = None
            if self.redis:
                try:
                    val = await self.redis.get(key)
                except Exception:
                    val = None
            if val:
                self._stats["hits"] += 1
                try:
                    out[i] = _json.loads(val)
                except Exception:
                    out[i] = None
            else:
                self._stats["misses"] += 1
                miss_idx.append(i)
        failures = 0
        if miss_idx:
            await self.ensure_client()
            need = [items[i] for i in miss_idx]
            got = []
            for attempt in range(2):
                try:
                    got = await self._post_embedding(need, type_)
                    break
                except Exception as e:
                    failures += 1
                    if attempt == 0:
                        _log.getLogger(__name__).warning(f"Embedding batch attempt1 failed: {e}")
            if not got:
                for i in miss_idx:
                    out[i] = [0.0] * settings.embedding_dim
                emit_trace(caller="embedding", operation="embed_batch", model=self.model,
                           total_tokens=0, latency_ms=(__import__("time").time()-t0)*1000,
                           status="error", error_type="embedding_failed")
            else:
                for k, i in enumerate(miss_idx):
                    emb = got[k] if k < len(got) else [0.0]*settings.embedding_dim
                    out[i] = emb
                    key = f"embed_cache:{type_}:{_hash.md5(str(items[i]).encode('utf-8'), usedforsecurity=False).hexdigest()}"
                    if self.redis:
                        try:
                            await self.redis.setex(key, settings.embedding_cache_ttl, _json.dumps(emb))
                        except Exception:
                            pass
        emit_trace(caller="embedding", operation="embed_batch", model=self.model,
                   total_tokens=0, latency_ms=(__import__("time").time()-t0)*1000,
                   status=("degraded" if failures else ("success" if miss_idx else "cache")),
                   cache_hit=not bool(miss_idx))
        return out

    async def embed_many(self, texts, type_: str = "db"):
        import os as _o
        size = max(1, int(_o.environ.get("EMBED_BATCH_SIZE", "100") or "100"))
        texts = list(texts)
        acc = []
        for i in range(0, len(texts), size):
            acc.extend(await self.embed_batch(texts[i:i+size], type_=type_))
        return acc

    async def close(self):
        if self.client:
            await self.client.aclose()


class SummaryCompression:
    def __init__(self):
        self.llm = LLMClient()

    async def ensure_client(self):
        await self.llm.ensure_client()

    async def compress(self, text: str, max_tokens: int = 500) -> str:
        from prompts import render
        prompt = render("analysis/summary_compress", max_tokens=max_tokens, text=text)
        return await self.llm.chat([
            {"role": "system", "content": render("analysis/summary_compress_system")},
            {"role": "user", "content": prompt},
        ])

    async def summarize_conversation(self, messages: list[dict]) -> str:
        text = "\n".join(
            f"[{m.get('agent_id','unknown')}][{m.get('role','user')}]: {m.get('content','')}"
            for m in messages
        )
        return await self.compress(text)

    async def close(self):
        await self.llm.close()


summary = SummaryCompression()
embedder = EmbeddingClient()
