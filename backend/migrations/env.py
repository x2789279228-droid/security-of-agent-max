"""Alembic 迁移环境（async 引擎版）

- 目标 metadata: models.Base（唯一权威 schema 源）
- 连接 URL: config.settings.database_url（经 -x db_url= 覆盖，测试用）
- 运行时: 异步引擎（asyncpg/aiosqlite），alembic.command.upgrade 从同步
  上下文调用时由本文件的 asyncio.run 驱动；app lifespan 中经
  asyncio.to_thread 调用（事件循环内不能嵌套 asyncio.run）。
"""
import asyncio
from logging.config import fileConfig

from alembic import context
from sqlalchemy.ext.asyncio import async_engine_from_config

config = context.config

if config.config_file_name is not None:
    # disable_existing_loggers 必须 False: 默认 True 会把进程里**所有已存在**
    # logger 置为 disabled —— pytest 全量跑时 test_migrations 一执行,
    # threat_intel.reputation 等业务 logger 从此静默, caplog 全部失明。
    fileConfig(config.config_file_name, disable_existing_loggers=False)

from models import Base  # noqa: E402  (sys.path 已由 alembic.ini prepend)

target_metadata = Base.metadata


def _resolve_db_url() -> str:
    x_args = context.get_x_argument(as_dictionary=True)
    override = x_args.get("db_url") or ""
    if override:
        return override
    from config import settings
    return settings.database_url


def run_migrations_offline() -> None:
    """离线模式：只生成 SQL 不连库（--sql）。"""
    config.set_main_option("sqlalchemy.url", _resolve_db_url())
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def _do_run_migrations(connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


async def _run_async_migrations() -> None:
    config.set_main_option("sqlalchemy.url", _resolve_db_url())
    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
    )
    async with connectable.connect() as connection:
        await connection.run_sync(_do_run_migrations)
    await connectable.dispose()


def run_migrations_online() -> None:
    asyncio.run(_run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
