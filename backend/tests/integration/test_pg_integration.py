"""真实 PostgreSQL 集成测试（testcontainers, opt-in）。

背景（2026-10-23 第二阶段）：修复前 229 个测试文件全部跑在 sqlite 内存库上 ——
PostgreSQL 方言、pgvector、tsvector 生成列、JSONB、alembic 迁移链
**从未被验证过**；而压测报告已实测出 sqlite 永远测不到的 ingest 故障。

本文件在真实 PG 16 容器里跑三件事：
  1. alembic upgrade head → 全部表 + 版本戳（含 PG 专有的 tsvector 生成列）
  2. 迁移幂等性（upgrade head 两次）
  3. 审批工单持久化往返（写 → 新实例 restore）

跳过条件（任意一个即整文件 skip，不阻塞常规测试流）：
  - 未安装 testcontainers
  - Docker daemon 不可用

CI: ubuntu runner 自带 Docker → 正常执行；本地开发：启动 Docker Desktop 后
`pytest tests/integration` 手动跑。
"""
from __future__ import annotations

import asyncio
import os
import sqlite3
import subprocess

import pytest

pytest.importorskip("testcontainers", reason="testcontainers 未安装")


def _docker_available() -> bool:
    try:
        r = subprocess.run(
            ["docker", "ps"], capture_output=True, timeout=15,
            shell=os.name == "nt",
        )
        return r.returncode == 0
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not _docker_available(), reason="Docker daemon 不可用"
)

_BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture(scope="module")
def pg_url():
    from testcontainers.postgres import PostgresContainer
    with PostgresContainer("pgvector/pgvector:0.8.2-pg16") as pg:
        # testcontainers 返回 psycopg2 URL; 换 asyncpg 驱动给 SQLAlchemy async
        url = pg.get_connection_url().replace("psycopg2", "asyncpg")
        yield url


def _alembic_cfg(db_url: str):
    import argparse
    from alembic.config import Config
    cfg = Config(os.path.join(_BACKEND_DIR, "alembic.ini"))
    cfg.set_main_option("script_location", os.path.join(_BACKEND_DIR, "migrations"))
    cfg.cmd_opts = argparse.Namespace(x=[f"db_url={db_url}"])
    return cfg



def _pg_scalar_all(pg_url: str, sqls: list[str]) -> list:
    """异步引擎逐条执行并返回首列值列表(替代 psycopg2 同步断言连接)。"""
    import asyncio as _aio
    from sqlalchemy.ext.asyncio import create_async_engine as _cae

    async def _q():
        eng = _cae(pg_url)
        try:
            out = []
            async with eng.connect() as c:
                from sqlalchemy import text as _text
                for s in sqls:
                    r = await c.execute(_text(s))
                    row = r.first()
                    out.append(row[0] if row else None)
            return out
        finally:
            await eng.dispose()

    return _aio.run(_q())

def test_alembic_upgrade_head_on_real_postgres(pg_url):
    """真 PG 上迁移到 head: 表全量建立 + tsvector 生成列 + 版本戳。"""
    from alembic import command
    command.upgrade(_alembic_cfg(pg_url), "head")

    got = _pg_scalar_all(pg_url, [
        "SELECT string_agg(tablename, ',' ORDER BY tablename) FROM pg_tables WHERE schemaname='public'",
        "SELECT 1 FROM information_schema.columns "
        "WHERE table_name='knowledge_chunks' AND column_name='search_tsv'",
        "SELECT 1 FROM pg_indexes WHERE indexname='knowledge_chunks_tsv_gin'",
    ])
    tables = set((got[0] or "").split(","))
    assert {"security_events", "approval_tickets", "audit_dead_letters", "alembic_version"} <= tables
    assert got[1] is not None, "search_tsv 生成列缺失 (baseline 迁移未生效)"
    assert got[2] is not None, "tsv GIN 索引缺失"


def test_alembic_upgrade_is_idempotent_on_real_postgres(pg_url):
    from alembic import command
    command.upgrade(_alembic_cfg(pg_url), "head")
    command.upgrade(_alembic_cfg(pg_url), "head")  # 第二次必须 no-op
    # 版本仍是 head（0001_baseline 及其后继）
    version = _pg_scalar_all(pg_url, ["SELECT version_num FROM alembic_version"])[0]
    assert version, "版本戳丢失"


@pytest.mark.asyncio
async def test_approval_persistence_roundtrip_on_real_postgres(pg_url, monkeypatch):
    """审批工单在真 PG 上: 提交 → 落库 → 新队列实例 restore 恢复。

    全程单事件循环: asyncpg 连接绑定 loop, 不能分段用不同 loop 驱动同一引擎。
    """
    from alembic import command
    # migrations/env.py 内部会 asyncio.run()；在 pytest-asyncio 的
    # 运行中事件循环里直接调用会抛 "asyncio.run() cannot be called from
    # a running event loop"。放到线程里执行。
    await asyncio.to_thread(command.upgrade, _alembic_cfg(pg_url), "head")

    from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
    eng = create_async_engine(pg_url)
    Session = async_sessionmaker(eng, expire_on_commit=False)

    import models as models_mod
    monkeypatch.setattr(models_mod, "async_session", Session)

    from response_engine.human_approval import ApprovalQueue
    q1 = ApprovalQueue()
    q1.set_session_factory(Session)
    ticket = q1.submit(
        threat_info={"threat_type": "BRUTE_FORCE", "src_ip": "203.0.113.7"},
        policy_name="pg-integration-test",
        actions=[{"name": "isolate_host", "params": {"host": "203.0.113.7"}}],
        timeout_minutes=15, priority="p1",
    )
    await q1.drain_persistence()

    q2 = ApprovalQueue()
    q2.set_session_factory(Session)
    restored = await q2.restore()
    assert restored >= 1
    pending = [t for t in q2.list_pending() if t.id == ticket.id]
    assert pending, "restore 未恢复提交的工单"
    t = pending[0]
    assert t.policy_name == "pg-integration-test"
    assert t.sig == ticket.sig
    ok = q2.approve(t.id, "pg-tester")
    assert ok is not None
    await eng.dispose()
