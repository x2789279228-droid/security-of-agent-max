"""因果图落库 + chains 缺图时 verdict=unknown。"""
import asyncio
import os
import sys

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


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


async def _reset():
    from models import Base, engine
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)


def test_save_and_latest_graph():
    async def t():
        await _reset()
        from causal_chain.learn import learn_from_matrix
        from causal_chain.store import latest_graph, save_graph
        from models import async_session
        from tests.test_causal_chain import _true_chain_matrix
        X, names = _true_chain_matrix(n=400, seed=2)
        result = learn_from_matrix(X, names)
        async with async_session() as s:
            saved = await save_graph(s, result)
            assert saved["id"]
            g = await latest_graph(s)
        assert g and g["ok"]
        assert g["directed"]
    _run(t())


def test_annotate_insufficient_data_without_graph():
    """图不可用 → `insufficient_data`（不是 `unknown`）。

    整改方案 §三.1 把 verdict 拆成 5 种之后，「没有图可用」和
    「图上有链但方向不明」必须分开：前者连可达性都没得查，
    后者是查了但不确定。原来两者都叫 `unknown`，
    下游无法区分「系统还没学到东西」和「学了但学不出来」。
    """
    from causal_chain.learn import annotate_chains
    chains = [{"pattern_name": "端口扫描→C2", "pattern_id": "port_scan_to_c2"}]
    out = annotate_chains(chains, {"ok": False})
    assert out[0]["causal_verdict"] == "insufficient_data"
    assert out[0]["data_available"] is False
    assert out[0]["identifiability_reason"] == "no_graph"
