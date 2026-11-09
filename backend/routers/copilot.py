"""
Copilot 路由 — 对话式安全分析助手（2026-11 AI Web 改造）

端点：
    POST /api/copilot/stream        流式问答（SSE；reasoning/token/citations 分帧）
    GET  /api/copilot/capabilities  能力自省（模型名/视觉开关/预算状态）

帧协议（copilot_service.run_copilot_stream 的 dict → SSE event/data）：
    meta | stage | context | citations | vision_note | reasoning | token | done | error

鉴权：operator 及以上（与审计触发同档）；限流沿用全局 HTTP 限流。
对话落库：conversations 表（agent_id="copilot"），复用三 Agent 会话的存储。
"""
import json
import logging

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sse_starlette.sse import EventSourceResponse
from sqlalchemy.ext.asyncio import AsyncSession

from auth import RequireRole, UserInfo
from config import settings
from models import get_session
from summary_compression import cost_tracker

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["copilot"])

# data URL 白名单前缀 + 大小上限（base64 体积 ≈ 原图 × 1.37，给足余量）
_ALLOWED_IMAGE_PREFIXES = ("data:image/png;base64,", "data:image/jpeg;base64,",
                           "data:image/webp;base64,", "data:image/gif;base64,")


class CopilotMessage(BaseModel):
    role: str
    content: str


class CopilotRequest(BaseModel):
    question: str = Field(min_length=1, max_length=4000)
    event_id: int | None = None
    image_data_url: str = Field(default="", max_length=10_000_000)
    history: list[CopilotMessage] = Field(default_factory=list, max_length=40)
    mode: str = Field(default="auto", pattern="^(auto|rag)$")


def _sse(frame: dict) -> dict:
    return {"event": frame.get("type") or "message", "data": json.dumps(frame, ensure_ascii=False)}


@router.post("/copilot/stream")
async def copilot_stream(
    req: CopilotRequest,
    session: AsyncSession = Depends(get_session),
    user: UserInfo = Depends(RequireRole("operator")),
):
    """流式安全问答。图片仅在配置了视觉模型时参与分析（否则发 vision_note 降级帧）。"""
    from copilot_service import run_copilot_stream

    image_url = (req.image_data_url or "").strip()
    if image_url and not image_url.startswith(_ALLOWED_IMAGE_PREFIXES):
        # 与 memory_guard 的 base64 警惕口径一致：非白名单格式直接拒，不静默丢弃
        return _sse({"type": "error", "text": "不支持的图片格式（仅 PNG/JPEG/WebP/GIF data URL）",
                     "fallback": True, "error_type": "image_format_rejected"})

    async def generator():
        try:
            async for frame in run_copilot_stream(
                session,
                question=req.question.strip(),
                event_id=req.event_id,
                history=[m.model_dump() for m in req.history],
                image_data_url=image_url,
                mode=req.mode,
            ):
                yield _sse(frame)
        except Exception as exc:  # 流水线级兜底：任何未捕获异常都转成结构化 error 帧
            logger.exception("copilot stream failed")
            yield _sse({"type": "error", "text": f"Copilot 流水线异常（{type(exc).__name__}）",
                        "fallback": True, "error_type": type(exc).__name__})

    return EventSourceResponse(generator())


@router.get("/copilot/capabilities")
async def copilot_capabilities(user: UserInfo = Depends(RequireRole("operator"))):
    """前端空态/输入区按此渲染能力开关（未配置视觉模型时置灰并说明原因）。"""
    budget = {}
    try:
        budget = cost_tracker.stats()
    except Exception:
        pass
    return {
        "model": settings.llm_model or "",
        "vision_enabled": bool((settings.llm_vision_model or "").strip()),
        "vision_model": settings.llm_vision_model or "",
        "rag_available": bool(settings.qdrant_enabled or settings.rag_hybrid_enabled),
        "over_budget": bool(cost_tracker.is_over_budget()),
        "budget": budget,
    }
