# -*- coding: utf-8 -*-
"""embedding 的**降级产物**不得与真实向量混同（整改报告 §9.50）。

## 背景（一次真实踩坑）

`EmbeddingClient.embed()` 在失败时（无 API key / 重试耗尽）返回
**维度正确但内容全零**的向量。它与真实向量**不可区分**：

* 长度对得上 → 能过 `vector_store` 的**维度护栏**；
* `bool(vec)` 为真 → 拦不住 `if v` 那种「过滤失败结果」的惯例；
* 相似度恒为 0 → 阈值过滤后必然为空。

实测后果（2026-10-20）：

1. **脏数据入库**：`store_memory(零向量)` 真的把这条「没算出来」的
   降级产物写进了库（`mem.id=1`，768 维全零）。
2. **假阳性检索**：`vector_store._search_pgvector` 的兜底
   `filtered if filtered else rows[:1]` → 阈值全灭时返回**任意一条**记录
   → 被上层当成「相关记忆」交给 LLM —— 那条记忆与查询**毫无关系**。

而 `rag/seeder.py` 早就有零向量识别（「API 失败或返回零向量(降级产物)
→ 视为失败, 不存脏数据」）—— **同一个判断只在一个地方实现了**。

## 本守卫盯什么

1. **判定口只有一个**：`summary_compression.is_degraded_vector()`；
2. **入库口**：记忆与知识库都不收降级产物；
3. **检索口**：降级产物**不得**走到后端（后端兜底会返回任意一条）；
4. **反向判据**：真实向量（含「部分分量为 0」的）**不得**被误判为降级 ——
   这是收紧型改动最该防的方向。
"""
from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND))

from summary_compression import is_degraded_vector  # noqa: E402


def _run(coro):
    return asyncio.run(coro)


def _reset_db():
    from models import Base, engine

    async def reset():
        async with engine.connect() as conn:
            await conn.run_sync(Base.metadata.drop_all)
            await conn.run_sync(Base.metadata.create_all)

    _run(reset())


class TestTheJudgmentPoint:
    def test_none_and_empty_are_degraded(self):
        assert is_degraded_vector(None) is True
        assert is_degraded_vector([]) is True

    def test_the_all_zero_vector_is_degraded(self):
        from config import settings
        assert is_degraded_vector([0.0] * settings.embedding_dim) is True

    def test_a_tiny_vector_is_degraded(self):
        """eps 语义：全部分量都 <= 1e-5 视为「占位零向量」（与 seeder 旧口径一致）。"""
        assert is_degraded_vector([1e-9, 0.0, 5e-6]) is True

    def test_a_real_vector_is_not_degraded(self):
        """**反向判据**：真实向量不得被误判 —— 这是收紧型改动的风险方向。"""
        from config import settings
        vec = [0.01 * (i % 7) for i in range(settings.embedding_dim)]
        assert is_degraded_vector(vec) is False

    def test_a_vector_with_some_zero_components_is_not_degraded(self):
        """**反向判据**：只有**部分**分量为 0 的向量是真实向量，不得被拒。"""
        assert is_degraded_vector([0.0, 0.0, 0.02, 0.0, 0.04]) is False

    def test_the_zero_vector_defeats_the_if_v_idiom(self):
        """前提守卫：为什么需要这个判定。

        `if v` 是调用方过滤「失败结果」的常用写法，
        而**全零向量是非空 list** → `bool()` 为真 → 拦不住。
        """
        zero = [0.0] * 8
        assert bool(zero) is True
        assert is_degraded_vector(zero) is True


class TestTheStoreSide:
    def test_store_memory_refuses_the_degradation_product(self):
        """降级产物**不得**写进库（它不是「算出来了」）。"""
        from config import settings
        _reset_db()
        from models import async_session
        from vector_store import vector_store

        zero = [0.0] * settings.embedding_dim

        async def scenario():
            async with async_session() as session:
                mem = await vector_store.store_memory(
                    session, "降级产物", zero, agent_id="probe", source_type="agent_output")
                return mem.embedding

        assert _run(scenario()) is None, "降级产物被写进库了"

    def test_store_memory_still_stores_a_real_vector(self):
        """**反向判据**：正常向量照写（别把闸门做成「全都不写」）。"""
        from config import settings
        _reset_db()
        from models import async_session
        from vector_store import vector_store

        vec = [0.01 * (i % 7) for i in range(settings.embedding_dim)]

        async def scenario():
            async with async_session() as session:
                mem = await vector_store.store_memory(
                    session, "正常", vec, agent_id="probe", source_type="agent_output")
                return mem.embedding

        emb = _run(scenario())
        assert emb is not None and len(emb) == settings.embedding_dim


class TestTheSearchSide:
    def test_search_similar_returns_empty_for_the_degradation_product(self, monkeypatch):
        """降级产物的查询 → **空**（不是「任意一条」）。"""
        from config import settings
        _reset_db()
        from models import async_session
        from vector_store import vector_store

        zero = [0.0] * settings.embedding_dim

        async def scenario():
            async with async_session() as session:
                return await vector_store.search_similar(session, zero, top_k=5)

        assert _run(scenario()) == []

    def test_search_similar_never_reaches_the_backends(self, monkeypatch):
        """**不得**走到后端 —— 后端的兜底会返回任意一条记录。

        前提：`_search_pgvector` 的 `filtered if filtered else rows[:1]`
        在零向量查询下必然返回**与查询无关**的一条。
        这里把两个后端都换成「被调用就记账」的桩，
        断言它们**一次都没被调用**。
        """
        from config import settings
        _reset_db()
        from models import async_session
        from vector_store import vector_store

        called = []

        async def _fake_qdrant(*a, **k):
            called.append("qdrant")
            return []

        async def _fake_pg(*a, **k):
            called.append("pg")
            return []

        monkeypatch.setattr(vector_store, "_search_qdrant", _fake_qdrant)
        monkeypatch.setattr(vector_store, "_search_pgvector", _fake_pg)

        zero = [0.0] * settings.embedding_dim

        async def scenario():
            async with async_session() as session:
                return await vector_store.search_similar(session, zero, top_k=5)

        assert _run(scenario()) == []
        assert called == [], f"降级产物的查询走到了后端：{called}"


class TestTheQdrantWriteSide:
    def test_upsert_chunk_skips_the_degradation_product(self, monkeypatch):
        """Qdrant 写入口也拒收降级产物（保护**所有**调用方）。"""
        from config import settings
        from qdrant_store import qdrant_store

        called = []

        async def _fake_call(fn):
            called.append(fn)
            return True

        monkeypatch.setattr(qdrant_store, "_call", _fake_call)

        zero = [0.0] * settings.embedding_dim
        res = _run(qdrant_store.upsert_chunk(chunk_id="c1", doc_id=1, vector=zero, payload={}))
        assert res is None, f"降级产物被写进了向量库：{res}"
        assert called == [], f"仍然调用了 Qdrant：{called}"


class TestTheSingleSourceOfTruth:
    def test_the_seeder_uses_the_shared_judgment(self):
        """seeder 此前有一份**局部**零向量判定 → 现在必须收敛到同一个函数。"""
        src = (BACKEND / "rag" / "seeder.py").read_text(encoding="utf-8")
        assert "is_degraded_vector(vec, eps=_ZERO_EPS)" in src, (
            "seeder 仍在用局部判定 —— 同一份判断出现两个实现时，迟早给出两个答案")
        assert "max((abs(x) for x in vec)" not in src, (
            "seeder 里仍有局部的零向量判定")


if __name__ == "__main__":       # pragma: no cover
    import pytest
    raise SystemExit(pytest.main([__file__, "-q"]))
