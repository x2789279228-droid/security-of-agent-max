"""Copilot 流式问答测试（2026-11 AI Web 改造）。

覆盖：
- SSE 帧契约：run_copilot_stream 的帧经 /api/copilot/stream 原样转发为 event/data
- 鉴权门禁：无 token 401；图片格式白名单拒绝
- chat_stream 门禁帧：未配置 key / 预算耗尽 → 诚实降级 error 帧（不抛异常打断 SSE）
- 纯函数：citations 组装 / build_messages 视觉降级与多模态 content 数组

外部依赖全部打桩：LLM 流、RAG 检索、事件存储、DB session。
"""
import asyncio
import json
import sys
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from auth import UserInfo, get_current_user  # noqa: E402
import copilot_service  # noqa: E402
from copilot_service import (  # noqa: E402
    build_messages,
    chunks_to_citations,
    citations_to_prompt,
)
from routers.copilot import router as copilot_router  # noqa: E402
from summary_compression import LLMClient  # noqa: E402


def _app() -> FastAPI:
    app = FastAPI()
    app.include_router(copilot_router)

    async def _fake_session():
        yield None

    async def _fake_user():
        return UserInfo(username="tester", role="operator", jti="test-jti")

    # 覆盖内层 get_current_user（RequireRole 依赖它，admin 恒通过）
    app.dependency_overrides[get_current_user] = _fake_user
    return app


@pytest.fixture()
def client():
    with TestClient(_app()) as c:
        yield c


# ── 帧契约 ─────────────────────────────────────────────────────────────────

def _fake_stream_frames():
    """模拟 run_copilot_stream 的最小帧序列。"""

    async def _gen(*args, **kwargs):
        yield {"type": "meta", "detail": json.dumps({"session_id": "s-1"})}
        yield {"type": "stage", "stage": "context", "detail": "拉取事件 #1"}
        yield {"type": "context", "event": None}
        yield {"type": "stage", "stage": "rag", "detail": "检索知识库"}
        yield {"type": "citations", "citations": [{"index": 1, "title": "T", "source": "x", "snippet": "s"}]}
        yield {"type": "stage", "stage": "answer", "detail": "生成回答"}
        yield {"type": "reasoning", "text": "先看证据…"}
        yield {"type": "token", "text": "结论：是攻击。"}
        yield {"type": "done", "content": "结论：是攻击。", "citations": [], "usage": {"total_tokens": 9}, "latency_ms": 5}

    return _gen


def test_stream_frame_contract(client, monkeypatch):
    monkeypatch.setattr(copilot_service, "run_copilot_stream", _fake_stream_frames())
    resp = client.post("/api/copilot/stream", json={"question": "这是攻击吗"})
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/event-stream")
    body = resp.text
    # event: 行与 data: 行成对出现，关键帧全部到位
    for name in ("meta", "stage", "context", "citations", "reasoning", "token", "done"):
        assert f"event: {name}" in body, f"missing frame {name}"
    assert "结论：是攻击。" in body


def test_stream_requires_auth():
    # 无 dependency 覆盖的裸 app：无 token → 401（与平台 RBAC 口径一致）
    app = FastAPI()
    app.include_router(copilot_router)
    with TestClient(app, raise_server_exceptions=False) as c:
        resp = c.post("/api/copilot/stream", json={"question": "x"})
    assert resp.status_code == 401


def test_stream_rejects_bad_image_format(client):
    resp = client.post(
        "/api/copilot/stream",
        json={"question": "看图", "image_data_url": "data:text/html;base64,PHNjcmlwdD4="},
    )
    # 非白名单图片格式 → 结构化 error（非 SSE），不静默丢图
    assert resp.status_code == 200
    assert "image_format_rejected" in resp.text


def test_stream_run_failure_degrades_to_error_frame(client, monkeypatch):
    async def _boom(*args, **kwargs):
        raise RuntimeError("pipeline exploded")
        yield  # pragma: no cover

    monkeypatch.setattr(copilot_service, "run_copilot_stream", _boom)
    resp = client.post("/api/copilot/stream", json={"question": "x"})
    assert resp.status_code == 200
    assert "RuntimeError" in resp.text and "error" in resp.text


# ── chat_stream 门禁帧 ─────────────────────────────────────────────────────

def _consume(gen):
    return asyncio.get_event_loop().run_until_complete(_consume_async(gen))


async def _consume_async(gen):
    return [frame async for frame in gen]


def test_chat_stream_no_api_key_yields_error_frame(monkeypatch):
    from config import settings

    monkeypatch.setattr(settings, "llm_api_key", "")
    frames = _consume(LLMClient().chat_stream([{"role": "user", "content": "hi"}]))
    assert frames and frames[0]["type"] == "error"
    assert frames[0]["error_type"] == "no_api_key"
    assert frames[0]["fallback"] is True


def test_chat_stream_budget_exhausted_yields_error_frame(monkeypatch):
    from config import settings
    from summary_compression import cost_tracker

    monkeypatch.setattr(settings, "llm_api_key", "k-test")
    monkeypatch.setattr(
        type(cost_tracker), "is_over_budget",
        lambda self: True, raising=True,
    )
    frames = _consume(LLMClient().chat_stream([{"role": "user", "content": "hi"}]))
    assert frames and frames[0]["type"] == "error"
    assert frames[0]["error_type"] == "budget_exhausted"


# ── 纯函数 ─────────────────────────────────────────────────────────────────

def test_chunks_to_citations_trims_and_indexes():
    chunks = [
        {"chunk_id": "c1", "doc_id": "d1", "title": "C2 检测", "source": "MITRE", "score": 0.9, "content": "x" * 500},
        {"title": "无 id 块", "content": "y"},
    ]
    cits = chunks_to_citations(chunks)
    assert [c["index"] for c in cits] == [1, 2]
    assert len(cits[0]["snippet"]) == 200
    assert cits[1]["doc_id"] is None


def test_citations_prompt_roundtrip():
    cits = chunks_to_citations([{"title": "T1", "source": "S", "content": "abc"}])
    prompt = citations_to_prompt(cits)
    assert "[1] T1" in prompt and "abc" in prompt
    # 无命中 → 如实标注，不假装引用
    assert "无命中" in citations_to_prompt([])


def test_build_messages_vision_gating(monkeypatch):
    from config import settings

    monkeypatch.setattr(settings, "llm_vision_model", "")
    msgs, note = build_messages("看这张图", None, [], [], "data:image/png;base64,AAA")
    assert note and "视觉模型未配置" in note
    # 未配置时图片被剥除 —— user 内容仍是纯文本
    assert isinstance(msgs[-1]["content"], str)

    monkeypatch.setattr(settings, "llm_vision_model", "glm-4v")
    msgs, note = build_messages("看这张图", None, [], [], "data:image/png;base64,AAA")
    assert note == ""
    parts = msgs[-1]["content"]
    assert isinstance(parts, list)
    assert {"type": "image_url", "image_url": {"url": "data:image/png;base64,AAA"}} in parts
    assert parts[0]["type"] == "text"

    # 无图无事件 → 不含上下文块，但 RAG 占位仍如实存在
    msgs, note = build_messages("纯文本问题", None, [], [], "")
    assert note == ""
    assert any("知识库引用" in str(m.get("content")) for m in msgs)
    # 历史裁剪：只保留 user/assistant
    hist = [{"role": "system", "content": "junk"}, {"role": "user", "content": "q"},
            {"role": "assistant", "content": "a"}] * 10
    msgs, _ = build_messages("再来一问", None, [], hist, "")
    non_system = [m for m in msgs if m["role"] != "system"]
    assert len(non_system) <= 1 + 12 + 1  # 截断在 max_turns*2 内
