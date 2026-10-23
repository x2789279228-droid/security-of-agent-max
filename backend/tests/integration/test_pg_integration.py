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
    with PostgresContainer("postgres:16-alpine") as pg:
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


def test_alembic_upgrade_head_on_real_postgres(pg_url):
    """真 PG 上迁移到 head: 表全量建立 + tsvector 生成列 + 版本戳。"""
    from alembic import command
    command.upgrade(_alembic_cfg(pg_url), "head")

    from sqlalchemy import create_engine, text
    eng = create_engine(pg_url.replace("asyncpg", "psycopg2"))
    with eng.connect() as c:
        tables = {r[0] for r in c.execute(text(
            "SELECT tablename FROM pg_tables WHERE schemaname='public'"))}
        assert "security_events" in tables
        assert "approval_tickets" in tables
        assert "audit_dead_letters" in tables
        assert "alembic_version" in tables
        # baseline 里的 PG 专有对象: knowledge_chunks.search_tsv 生成列 + GIN 索引
        col = c.execute(text(
            "SELECT 1 FROM information_schema.columns "
            "WHERE table_name='knowledge_chunks' AND column_name='search_tsv'"
        )).fetchone()
        assert col is not None, "search_tsv 生成列缺失 (baseline 迁移未生效)"
        idx = c.execute(text(
            "SELECT 1 FROM pg_indexes WHERE indexname='knowledge_chunks_tsv_gin'"
        )).fetchone()
        assert idx is not None, "tsv GIN 索引缺失"
    eng.dispose()


def test_alembic_upgrade_is_idempotent_on_real_postgres(pg_url):
    from alembic import command
    command.upgrade(_alembic_cfg(pg_url), "head")
    command.upgrade(_alembic_cfg(pg_url), "head")  # 第二次必须 no-op
    # 版本仍是 head（0001_baseline 及其后继）
    from sqlalchemy import create_engine, text
    eng = create_engine(pg_url.replace("asyncpg", "psycopg2"))
    with eng.connect() as c:
        version = c.execute(text("SELECT version_num FROM alembic_version")).scalar()
        assert version, "版本戳丢失"
    eng.dispose()


@pytest.mark.asyncio
async def test_approval_persistence_roundtrip_on_real_postgres(pg_url, monkeypatch):
    """审批工单在真 PG 上: 提交 → 落库 → 新队列实例 restore 恢复。

    全程单事件循环: asyncpg 连接绑定 loop, 不能分段用不同 loop 驱动同一引擎。
    """
    from alembic import command
    command.upgrade(_alembic_cfg(pg_url), "head")

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
