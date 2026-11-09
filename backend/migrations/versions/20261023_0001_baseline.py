"""baseline: 全量建表 + 既有 PG 卷补列（取代 models.py 的 except:pass 伪迁移）

Revision ID: 0001_baseline
Revises:
Create Date: 2026-10-23

背景（2026-10-23 第一阶段止血）：
  此前 schema 演进靠三套并存：init.sql 手写建表 + Base.metadata.create_all +
  models._migrate_existing_tables 里 `except: pass` 吞错的手搓 ALTER。
  同一 schema 双份维护，变更失败静默，无法审计「这个库到底迁到哪了」。

  本迁移是管理基线：
  1) 空库 → create_all 全量建表；
  2) alembic 之前的既有 PG 卷（旧 pgdata volume）→ create_all(checkfirst)
     补建缺失的表 + 下方幂等 ALTER 补列（原列表原样收编，但不再吞错：
     语句全部 IF NOT EXISTS 幂等，失败即报、启动即停）；
  3) 完成后写 alembic_version，之后的演进走正常 revision 链。

  既有生产库首次升级：直接 `alembic upgrade head`（或 AUTO_MIGRATE=true）
  即可，无需 stamp —— 本迁移天然幂等。
"""
from typing import Sequence, Union

from alembic import op
from sqlalchemy import text

revision: str = "0001_baseline"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# 原 models._migrate_existing_tables 的语句列表，原样收编（幂等，PG only）。
# search_tsv 是 PG 专有生成列，不在 ORM 模型里 —— 全新 PG 库也需要这些语句。
_LEGACY_PG_STATEMENTS = [
    "ALTER TABLE security_events ADD COLUMN IF NOT EXISTS anomaly_score REAL DEFAULT 0.0",
    "ALTER TABLE security_events ADD COLUMN IF NOT EXISTS status VARCHAR(30) DEFAULT 'new'",
    "ALTER TABLE security_events ADD COLUMN IF NOT EXISTS case_id INTEGER",
    "ALTER TABLE security_events ADD COLUMN IF NOT EXISTS event_id VARCHAR(64)",
    "ALTER TABLE security_events ADD COLUMN IF NOT EXISTS correlation_id VARCHAR(128)",
    "ALTER TABLE security_events ADD COLUMN IF NOT EXISTS parent_event_id VARCHAR(64)",
    "ALTER TABLE security_events ADD COLUMN IF NOT EXISTS trace_id VARCHAR(128)",
    # 幂等兜底: 同一 eventId 只落库一次 (替换 Redis 24h 去重)
    "CREATE UNIQUE INDEX IF NOT EXISTS uq_security_events_event_id ON security_events(event_id)",
    # 可观测: pipeline_spans 增加 trace_id 列 (关联 OTel/Tempo)
    "ALTER TABLE pipeline_spans ADD COLUMN IF NOT EXISTS trace_id VARCHAR(32) DEFAULT ''",
    "ALTER TABLE llm_traces ADD COLUMN IF NOT EXISTS trace_id VARCHAR(32) DEFAULT ''",
    "CREATE INDEX IF NOT EXISTS idx_llm_traces_trace_id ON llm_traces(trace_id)",
    "ALTER TABLE memories ADD COLUMN IF NOT EXISTS source_type VARCHAR(30) DEFAULT 'agent_output'",
    "ALTER TABLE memories ADD COLUMN IF NOT EXISTS provenance_id VARCHAR(100) DEFAULT ''",
    "ALTER TABLE memories ADD COLUMN IF NOT EXISTS content_hash VARCHAR(64) DEFAULT ''",
    "ALTER TABLE memories ADD COLUMN IF NOT EXISTS trust REAL DEFAULT 0.2",
    "ALTER TABLE memories ADD COLUMN IF NOT EXISTS signed BOOLEAN DEFAULT FALSE",
    "ALTER TABLE knowledge_docs ADD COLUMN IF NOT EXISTS content_hash VARCHAR(64) DEFAULT ''",
    "ALTER TABLE knowledge_docs ADD COLUMN IF NOT EXISTS approval_status VARCHAR(20) DEFAULT 'pending'",
    "ALTER TABLE knowledge_docs ADD COLUMN IF NOT EXISTS submitted_by VARCHAR(80) DEFAULT ''",
    "ALTER TABLE knowledge_docs ADD COLUMN IF NOT EXISTS approved_by VARCHAR(80) DEFAULT ''",
    "UPDATE knowledge_docs SET approval_status = 'signed_import' "
    "WHERE source IN ('mitre-attack','capec','cve','seed','playbook') "
    "AND (approval_status IS NULL OR approval_status = 'pending')",
    "ALTER TABLE knowledge_docs ADD COLUMN IF NOT EXISTS published_at TIMESTAMPTZ",
    "ALTER TABLE knowledge_docs ADD COLUMN IF NOT EXISTS valid_until TIMESTAMPTZ",
    "ALTER TABLE knowledge_docs ADD COLUMN IF NOT EXISTS cutoff_policy VARCHAR(20) DEFAULT 'strict'",
    "ALTER TABLE knowledge_chunks ADD COLUMN IF NOT EXISTS search_lex TEXT DEFAULT ''",
    "ALTER TABLE self_play_learned_rules ADD COLUMN IF NOT EXISTS review_report JSONB DEFAULT '{}'",
    "ALTER TABLE knowledge_chunks ADD COLUMN IF NOT EXISTS search_tsv tsvector "
    "GENERATED ALWAYS AS (to_tsvector('simple', coalesce(search_lex,'') || ' ' || "
    "coalesce(title,'') || ' ' || coalesce(content,''))) STORED",
    "CREATE INDEX IF NOT EXISTS knowledge_chunks_tsv_gin ON knowledge_chunks USING gin(search_tsv)",
]


def upgrade() -> None:
    bind = op.get_bind()
    from models import Base

    # 0) 2026-11-10: vector 扩展必须先于建表 —— models 的 embedding 列是
    # pgvector Vector 类型, 无扩展的全新库(如 testcontainers 裸 postgres)
    # 会在 create_all 时报 type "vector" does not exist。生产 init.sql 已建
    # 扩展, IF NOT EXISTS 对其无操作。集成测试容器镜像已同步 pgvector。
    if bind.dialect.name == "postgresql":
        bind.execute(text("CREATE EXTENSION IF NOT EXISTS vector"))

    # 1) 全量建表（幂等）：空库建齐；既有库 checkfirst 跳过已存在的表。
    #    含本次新增的 approval_tickets（审批工单持久化）。
    Base.metadata.create_all(bind, checkfirst=True)

    # 2) 既有 PG 卷补列 + PG 专有对象（tsvector 生成列等）。
    if bind.dialect.name == "postgresql":
        for stmt in _LEGACY_PG_STATEMENTS:
            bind.execute(text(stmt))


def downgrade() -> None:
    # baseline 的 downgrade = 放弃整个 schema（仅开发环境使用）
    bind = op.get_bind()
    from models import Base
    Base.metadata.drop_all(bind)
