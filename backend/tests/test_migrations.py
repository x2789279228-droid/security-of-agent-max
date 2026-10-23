"""Alembic 迁移体系（2026-10-23 第一阶段止血）

修复前的缺陷: schema 演进靠 init.sql + create_all + except:pass 手搓 ALTER
三套并存, 变更失败静默, 无法审计库的迁移状态。

覆盖:
  - alembic upgrade head 在空库上全量建表 (含新增的 approval_tickets)
  - alembic_version 版本戳写入
  - 重复执行 upgrade head 幂等 (no-op)
  - baseline 迁移的 downgrade 可清空 (开发环境语义)
"""
import os
import sqlite3

import pytest
from alembic import command
from alembic.config import Config

_BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _make_config(db_path: str) -> Config:
    import argparse
    cfg = Config(os.path.join(_BACKEND_DIR, "alembic.ini"))
    cfg.set_main_option("script_location", os.path.join(_BACKEND_DIR, "migrations"))
    # env.py 经 context.get_x_argument 读取; 命令式调用要经 cmd_opts 注入
    # (Windows 路径必须转 posix, 否则 URL 解析把 \ 当转义)
    url = f"sqlite+aiosqlite:///{db_path}".replace("\\", "/")
    cfg.cmd_opts = argparse.Namespace(x=[f"db_url={url}"])
    return cfg


def _tables(db_path: str) -> set:
    con = sqlite3.connect(db_path)
    try:
        return {r[0] for r in con.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
    finally:
        con.close()


def _version(db_path: str):
    con = sqlite3.connect(db_path)
    try:
        return con.execute("SELECT version_num FROM alembic_version").fetchall()
    finally:
        con.close()


def test_upgrade_head_creates_full_schema_and_stamps_version(tmp_path):
    db = str(tmp_path / "mig.db")
    command.upgrade(_make_config(db), "head")

    tables = _tables(db)
    assert "security_events" in tables
    assert "approval_tickets" in tables  # 本次止血新增表
    assert "alembic_version" in tables
    assert _version(db) == [("0001_baseline",)]


def test_upgrade_head_is_idempotent(tmp_path):
    db = str(tmp_path / "mig.db")
    cfg = _make_config(db)
    command.upgrade(cfg, "head")
    # 再跑一次: no-op 不抛错, 版本不变
    command.upgrade(cfg, "head")
    assert _version(db) == [("0001_baseline",)]


def test_downgrade_baseline_clears_schema(tmp_path):
    db = str(tmp_path / "mig.db")
    cfg = _make_config(db)
    command.upgrade(cfg, "head")
    command.downgrade(cfg, "base")
    tables = _tables(db)
    assert "security_events" not in tables
    assert "approval_tickets" not in tables
    assert _version(db) == []
