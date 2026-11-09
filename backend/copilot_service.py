"""
Copilot 服务 — 对话式安全分析助手（2026-11 AI Web 改造）

定位：把平台已有的三块 AI 能力（审计证据链 / RAG 知识检索 / LLM 流式生成）
编排成一条**固定顺序、只读、可解释**的问答流水线，供前端 /copilot 页消费。

流水线（每步都向前端发 stage 帧，ThinkingRail 可视化）：
    1. context  — 有 event_id 时拉取事件 + 审计结论 + 证据摘录（复用
                  audit-llm 证据链的取数口径，routers/audit.py::get_evidence_trail）
    2. rag      — 检索安全知识库，产出引用块（复用 rag/retriever，citation
                  字段原生带 doc_id/source/score —— 同时补上"检索无生成回答"缺口）
    3. answer   — LLM 流式生成（summary_compression.LLMClient.chat_stream），
                  reasoning 增量与正文增量分帧转发

治理口径（与 mcp_guard / 全站「明示，不伪装」一致）：
- 工具白名单固定为上述三步，全部只读，不让模型自由调工具；
- 视觉模型未配置时如实发 vision skipped 帧，不静默丢弃图片；
- RAG 无命中时如实标注"无知识库引用"，不假装引用。
"""
import json
import logging
import time
import uuid
from typing import AsyncIterator

from sqlalchemy.ext.asyncio import AsyncSession

from config import settings

logger = logging.getLogger(__name__)

# ── 提示词 ─────────────────────────────────────────────────────────────────

# 2026-11-09: 提示词正文迁移 prompts/copilot_system.j2(prompts_integrity 守卫
# 要求 system prompt 一律入库模板目录, .py 内不留内联正文); 模块级渲染一次缓存。
from prompts import render

SYSTEM_PROMPT = render("copilot_system").strip()

RAG_NO_HITS_NOTE = "（知识库本次无命中，以下回答未引用知识库）"

# ── 上下文装配 ─────────────────────────────────────────────────────────────

_EVIDENCE_MAX = 6          # 证据链最多带进 prompt 的条数
_EVIDENCE_SNIPPET = 160    # 每条证据摘录截断长度


async def build_event_context(session: AsyncSession, event_id: int) -> dict | None:
    """拉取事件 + 审计结论，拼装成 prompt 用的上下文块（纯只读）。

    取数口径与 routers/audit.py::get_evidence_trail 一致：
    evt.raw_data._audit_llm 里存四层流水线的完整产物。
    """
    from event_store import event_store

    evt = await event_store.get_by_id(session, event_id, prefer_db=True)
    if not evt:
        return None
    raw = evt.raw_data or {}
    audit = raw.get("_audit_llm", {}) or {}
    error = raw.get("_audit_llm_error", "") or audit.get("error", "")

    evidence = audit.get("evidence_trail") or []
    if not isinstance(evidence, list):
        evidence = []
    evidence_brief = []
    for item in evidence[:_EVIDENCE_MAX]:
        if isinstance(item, dict):
            text = str(item.get("assertion") or item.get("evidence") or item)[:_EVIDENCE_SNIPPET]
            evidence_brief.append(text)
        else:
            evidence_brief.append(str(item)[:_EVIDENCE_SNIPPET])

    reviewer = audit.get("reviewer") or audit.get("final_verdict") or {}
    if not isinstance(reviewer, dict):
        reviewer = {"raw": str(reviewer)}
    hallucination = audit.get("hallucination") or {}
    if not isinstance(hallucination, dict):
        hallucination = {}

    return {
        "event_id": event_id,
        "event_type": evt.event_type,
        "severity": evt.severity,
        "message": (evt.message or "")[:300],
        "src_ip": getattr(evt, "src_ip", "") or "",
        "dst_ip": getattr(evt, "dst_ip", "") or "",
        "audit_status": audit.get("status")
        or ("failed" if error else ("completed" if audit else "pending")),
        "audit_error": error or None,
        "reviewer_verdict": {
            k: reviewer.get(k)
            for k in ("verdict", "confidence", "reasoning", "summary")
            if reviewer.get(k) is not None
        },
        "hallucination_risk": {
            k: hallucination.get(k) for k in ("risk", "score", "details") if hallucination.get(k) is not None
        },
        "evidence_brief": evidence_brief,
        "pipeline_duration_s": audit.get("pipeline_duration_s"),
    }


def context_to_prompt(ctx: dict) -> str:
    """事件上下文 → prompt 文本块。"""
    lines = [
        f"- 事件 #{ctx['event_id']}：{ctx['event_type']}（severity={ctx['severity']}）",
        f"- 摘要：{ctx['message']}",
    ]
    if ctx.get("src_ip") or ctx.get("dst_ip"):
        lines.append(f"- 源/目的：{ctx.get('src_ip') or '?'} → {ctx.get('dst_ip') or '?'}")
    if ctx.get("audit_status") == "completed":
        lines.append(f"- 平台审计结论：{json.dumps(ctx.get('reviewer_verdict') or {}, ensure_ascii=False)}")
        if ctx.get("hallucination_risk"):
            lines.append(f"- 幻觉风险自评：{json.dumps(ctx['hallucination_risk'], ensure_ascii=False)}")
        if ctx.get("evidence_brief"):
            lines.append("- 审计证据摘录：")
            lines.extend(f"  · {e}" for e in ctx["evidence_brief"])
    elif ctx.get("audit_error"):
        lines.append(f"- 平台审计异常：{ctx['audit_error']}")
    else:
        lines.append(f"- 平台审计状态：{ctx.get('audit_status') or 'pending'}（尚无结论）")
    return "\n".join(lines)


# ── RAG 检索 ───────────────────────────────────────────────────────────────

def chunks_to_citations(chunks: list[dict], limit: int = 6) -> list[dict]:
    """retriever chunks → 前端引用条目（裁剪正文为摘要）。"""
    out = []
    for i, c in enumerate(chunks[:limit], start=1):
        content = str(c.get("content") or "")
        out.append({
            "index": i,
            "chunk_id": c.get("chunk_id"),
            "doc_id": c.get("doc_id"),
            "title": c.get("title") or "(未命名文档)",
            "source": c.get("source") or "",
            "score": c.get("score"),
            "snippet": content[:200],
        })
    return out


def citations_to_prompt(citations: list[dict]) -> str:
    if not citations:
        return RAG_NO_HITS_NOTE
    lines = []
    for c in citations:
        lines.append(f"[{c['index']}] {c['title']}（source={c['source'] or '未知'}）：{c['snippet']}")
    return "\n".join(lines)


# ── 消息组装 ───────────────────────────────────────────────────────────────

def build_messages(
    question: str,
    event_ctx: dict | None,
    citations: list[dict],
    history: list[dict],
    image_data_url: str = "",
) -> tuple[list[dict], str]:
    """组装 LLM 消息序列。返回 (messages, vision_note)。

    vision_note 非空表示图片被降级处理的原因（前端如实展示）。
    """
    blocks: list[str] = []
    if event_ctx:
        blocks.append("【告警上下文】\n" + context_to_prompt(event_ctx))
    if citations:
        blocks.append("【知识库引用】\n" + citations_to_prompt(citations))
    else:
        blocks.append("【知识库引用】\n" + RAG_NO_HITS_NOTE)
    context_text = "\n\n".join(blocks)

    # 历史：只保留 user/assistant，且截最近 N 轮（防止 prompt 无界膨胀）
    max_messages = max(2, int(getattr(settings, "copilot_history_max_turns", 6)) * 2)
    clean_history = [
        {"role": str(m.get("role") or "user"), "content": str(m.get("content") or "")}
        for m in (history or [])
        if m.get("role") in ("user", "assistant") and m.get("content")
    ][-max_messages:]

    vision_note = ""
    user_content: str | list[dict] = question
    if image_data_url:
        if not (settings.llm_vision_model or "").strip():
            vision_note = "视觉模型未配置（SHARED_MEMORY_LLM_VISION_MODEL 为空），本次图片未参与分析"
        else:
            user_content = [
                {"type": "text", "text": question},
                {"type": "image_url", "image_url": {"url": image_data_url}},
            ]

    messages: list[dict] = [{"role": "system", "content": SYSTEM_PROMPT}]
    if context_text:
        messages.append({"role": "system", "content": context_text})
    messages.extend(clean_history)
    messages.append({"role": "user", "content": user_content})
    return messages, vision_note


def vision_enabled() -> bool:
    return bool((getattr(settings, "llm_vision_model", "") or "").strip())


# ── 流水线主体 ─────────────────────────────────────────────────────────────

# LLMClient 无全局单例（各模块自行实例化），这里持有进程级一份以复用
# httpx 连接池；实例轻量（构造只读配置），首请求才真正建连。
from summary_compression import LLMClient  # noqa: E402  (延迟到模块底部会打断类型标注)

_llm_client: LLMClient | None = None


def _get_llm() -> LLMClient:
    global _llm_client
    if _llm_client is None:
        _llm_client = LLMClient()
    return _llm_client


async def run_copilot_stream(
    session: AsyncSession,
    question: str,
    event_id: int | None = None,
    history: list[dict] | None = None,
    image_data_url: str = "",
    mode: str = "auto",
) -> AsyncIterator[dict]:
    """完整问答流水线。产出帧 dict（与 LLMClient.chat_stream 帧协议对齐）：
        {"type": "stage", "stage": str, "detail": str}
        {"type": "context", "event": {...} | None}
        {"type": "citations", "citations": [...]}
        {"type": "reasoning" | "content", "text": str}
        {"type": "vision_note", "text": str}
        {"type": "error", "text": str, "error_type": str, "fallback": True}
        {"type": "done", "content": str, "citations": [...], "usage": {...}}
    """
    from rag.retriever import retriever

    llm = _get_llm()

    t_start = time.time()
    session_id = str(uuid.uuid4())

    yield {
        "type": "stage", "stage": "meta",
        "detail": json.dumps({
            "session_id": session_id,
            "model": (settings.llm_vision_model if image_data_url and vision_enabled()
                      else settings.llm_model),
            "vision_enabled": vision_enabled(),
        }, ensure_ascii=False),
    }

    # ── 1. 告警上下文 ──
    event_ctx: dict | None = None
    if event_id:
        yield {"type": "stage", "stage": "context", "detail": f"拉取事件 #{event_id} 与审计结论"}
        try:
            event_ctx = await build_event_context(session, int(event_id))
        except Exception as exc:  # 上下文失败不致命 —— 降级为纯问答
            logger.warning("copilot event context failed for #%s: %s", event_id, exc)
            yield {"type": "stage", "stage": "context",
                   "detail": f"事件上下文拉取失败，降级为通用问答（{type(exc).__name__}）"}
            event_ctx = None
        yield {"type": "context", "event": event_ctx}

    # ── 2. RAG 检索（mode=rag 强制走，auto 也默认走 —— 检索是廉价只读操作）──
    citations: list[dict] = []
    yield {"type": "stage", "stage": "rag", "detail": "检索安全知识库"}
    try:
        top_k = max(1, int(getattr(settings, "copilot_rag_top_k", 4)))
        result = await retriever.retrieve(
            session, query=question, query_embedding=None, top_k=top_k,
        )
        citations = chunks_to_citations(result.chunks or [])
    except Exception as exc:
        logger.warning("copilot rag retrieve failed: %s", exc)
        yield {"type": "stage", "stage": "rag", "detail": f"知识库检索失败，跳过引用（{type(exc).__name__}）"}
    yield {"type": "citations", "citations": citations}

    # ── 3. 视觉降级提示 ──
    messages, vision_note = build_messages(
        question, event_ctx, citations, history or [], image_data_url,
    )
    if vision_note:
        yield {"type": "vision_note", "text": vision_note}

    # ── 4. 流式生成 ──
    yield {"type": "stage", "stage": "answer", "detail": "生成回答"}
    use_model = (settings.llm_vision_model or "").strip() \
        if (image_data_url and vision_enabled()) else ""
    full_content_parts: list[str] = []
    usage: dict = {}
    async for frame in llm.chat_stream(messages, temperature=0.3, model=use_model):
        if frame.get("type") == "done":
            # 流式段内部的 done 不透传 —— 最终 done 由流水线末尾统一发
            # （带 citations/usage/session_id/latency 的完整版），客户端只收到一次
            usage = frame.get("usage") or {}
            continue
        if frame.get("type") == "content":
            full_content_parts.append(frame.get("text") or "")
        yield frame

    # ── 5. 落库（user + assistant 双写，与 chat.py 三 Agent 会话同表）──
    try:
        from models import Conversation
        session.add(Conversation(
            session_id=session_id, agent_id="user", role="user",
            content=question,
        ))
        answer_text = "".join(full_content_parts)
        if answer_text:
            session.add(Conversation(
                session_id=session_id, agent_id="copilot", role="assistant",
                content=answer_text,
            ))
        await session.commit()
    except Exception as exc:
        logger.warning("copilot conversation persist failed: %s", exc)
        try:
            await session.rollback()
        except Exception:
            pass

    yield {
        "type": "done", "content": "".join(full_content_parts),
        "citations": citations, "usage": usage,
        "session_id": session_id,
        "latency_ms": round((time.time() - t_start) * 1000),
    }
