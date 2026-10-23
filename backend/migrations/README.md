# Alembic 迁移指南（2026-10-23 第一阶段止血引入）

## 背景：为什么引入 Alembic

此前 schema 演进靠三套并存，且互不感知：

1. `init.sql` 手写建表（全新部署用）；
2. `models.Base.metadata.create_all`（幂等补表，但**不会改既有表**）；
3. `models._migrate_existing_tables` 里一段手搓 `ALTER TABLE ... ADD COLUMN`
   列表，且**循环体是 `except: pass`** —— 任何一条失败都静默吞掉，
   无法审计「这个库到底迁移到了什么状态」。

同一 schema 在 init.sql 与 ORM 双份维护，漂移只是时间问题。
现在：**结构演进的唯一权威路径是 `migrations/versions/*.py`**；
`init.sql` 仅作全新部署的参考文档（不再是权威）。

## 现有迁移

| Revision | 内容 |
|----------|------|
| `0001_baseline` | 全量建表（`create_all(checkfirst)`）+ 既有 PG 卷补列（原 ALTER 列表收编，幂等、失败可见）+ PG 专有 tsvector 生成列 |

`0001_baseline` 天然幂等：空库全量建表；alembic 之前的既有 pgdata 卷
先补建缺失的表，再逐条 `IF NOT EXISTS` 补列。**既有生产库直接
`alembic upgrade head` 即可纳入管理，无需 stamp。**

## 日常操作（在 `backend/` 目录下）

```bash
alembic upgrade head                        # 升到最新（部署/启动时自动执行亦可）
alembic revision --autogenerate -m "add xx" # 对照 models.Base 差异生成迁移
alembic current                             # 看当前库在哪个版本
alembic history                             # 迁移链
alembic downgrade -1                        # 回滚一步（慎用，先备份）
```

## 应用启动自动迁移

`SHARED_MEMORY_AUTO_MIGRATE=true`（docker-compose 已默认开启）时，
app lifespan 在 `init_db()` 之前执行 `alembic upgrade head`
（经 `asyncio.to_thread`，因 env.py 内部用 `asyncio.run`）。

**fail-closed：迁移失败 → 启动中止**，不允许未迁移的 schema 接流量。

## 注意事项

- `alembic.ini` 保持 **ASCII-only**：Windows 中文系统的 configparser 用 GBK
  读取该文件，中文注释会直接崩（中文文档一律放本文件或迁移脚本 docstring）。
- 连接串不写在 ini 里：`env.py` 从 `config.settings.database_url` 注入；
  测试可用 `alembic -x db_url=sqlite+aiosqlite:///./t.db upgrade head` 覆盖。
- autogenerate 生成后**必须人工审查**：ORM 无法表达 tsvector 生成列、
  PG 分区等，生成的 diff 可能包含误删/误改。
- 写新迁移的规则：**只前进不改历史**；已合入 main 的迁移脚本视为不可变。
