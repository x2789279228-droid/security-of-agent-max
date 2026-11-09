"""
应用用户存储 — 注册用户（bcrypt 哈希）+ 查询校验

环境变量中的 admin_user / admin_password 仍作为内置超管，不写入 app_users。
"""
from __future__ import annotations

import asyncio
import logging
import re
from typing import Optional

import bcrypt
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from models import AppUser

logger = logging.getLogger(__name__)

USERNAME_RE = re.compile(r"^[a-zA-Z0-9_\u4e00-\u9fff]{3,32}$")
MIN_PASSWORD_LEN = 8


def validate_username(username: str) -> Optional[str]:
    u = (username or "").strip()
    if not u:
        return "请输入用户名"
    if not USERNAME_RE.match(u):
        return "用户名需 3–32 位，仅字母、数字、下划线或中文"
    return None


def validate_password(password: str) -> Optional[str]:
    if not password:
        return "请输入密码"
    if len(password) < MIN_PASSWORD_LEN:
        return f"密码至少 {MIN_PASSWORD_LEN} 位"
    return None


def hash_password(password: str) -> str:
    """同步版 — 仅供线程池/CLI 使用; 事件循环内请用 hash_password_async。"""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    """同步版 — 仅供线程池/CLI 使用; 事件循环内请用 verify_password_async。"""
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except Exception:
        return False


async def hash_password_async(password: str) -> str:
    # R7(P2): bcrypt cost≈12 单次 ~150-300ms 纯 CPU, 事件循环内直跑会把
    # 全部在途请求(含 Kafka 消费循环/SSE)一起卡住 — 与全项目 to_thread 纪律对齐。
    return await asyncio.to_thread(hash_password, password)


async def verify_password_async(password: str, password_hash: str) -> bool:
    return await asyncio.to_thread(verify_password, password, password_hash)


async def get_by_username(session: AsyncSession, username: str) -> Optional[AppUser]:
    stmt = select(AppUser).where(AppUser.username == username.strip())
    result = await session.execute(stmt)
    return result.scalar_one_or_none()


async def create_user(
    session: AsyncSession,
    username: str,
    password: str,
    role: str = "viewer",
) -> AppUser:
    user = AppUser(
        username=username.strip(),
        password_hash=await hash_password_async(password),
        role=role or "viewer",
        is_active=True,
    )
    session.add(user)
    await session.commit()
    await session.refresh(user)
    logger.info(f"[Auth] Registered user: {user.username} role={user.role}")
    return user
