"""分布式锁 / 任务认领（Redis SET NX EX）

2026-10-23 第二阶段（可靠性）引入。

修复前的问题：关键互斥点全是**进程内**判断 ——
  - 审计入口的 `analyzed` 预检是 check-then-act（log_ingestion._audit_pipeline）；
  - 审计在飞集合 `audit_worker.holds()` 是模块级内存 set。
后端一旦多进程部署（uvicorn workers / 多容器），同一事件会被两个进程
同时审计：双倍 LLM 成本、结论互相覆盖。响应执行的幂等虽有 Redis，
但 Redis 不可用时保护静默消失（§9.52，本阶段改为 fail-closed）。

设计：
  - try_acquire(key, ttl_s): `SET key token NX EX ttl`，拿到=True。
    TTL 到期自动释放（持有者崩溃不产生死锁）；不需要显式 release 的
    场景（审计认领）靠 TTL 收尾，需要提前释放的场景用 release()。
  - Redis 不可用 → try_acquire 返回 None（"未知"），调用方决定
    fail-open（审计，互斥退化为尽力而为 + 指标可见）还是 fail-closed
    （高危动作，直接拒绝）。**本模块不做策略决定**。
"""
from __future__ import annotations

import logging
import uuid
from typing import Optional

logger = logging.getLogger(__name__)

_TOKEN = uuid.uuid4().hex  # 进程唯一, release 时校验防止误删他人的锁


async def _default_client():
    """取进程共享的 Redis 客户端（sliding_window 装配的那个）。"""
    try:
        from sliding_window import sliding_window
        return await sliding_window.get_redis()
    except Exception:
        return None


async def try_acquire(key: str, ttl_s: int, client=None) -> Optional[bool]:
    """尝试获取锁。

    Returns:
      True   — 获得锁
      False  — 已被他人持有
      None   — Redis 不可用（互斥无法执行），由调用方决定 fail-open/closed
    """
    c = client if client is not None else await _default_client()
    if c is None:
        return None
    try:
        res = c.set(key, _TOKEN, ex=max(1, int(ttl_s)), nx=True)
        if hasattr(res, "__await__"):
            res = await res
        return bool(res)
    except Exception as e:
        logger.debug("try_acquire(%s) failed: %s", key, e)
        return None


async def release(key: str, client=None) -> None:
    """尽力释放锁。TTL 兜底：拿不到客户端时静默等过期。"""
    c = client if client is not None else await _default_client()
    if c is None:
        return
    try:
        res = c.delete(key)
        if hasattr(res, "__await__"):
            await res
    except Exception as e:
        logger.debug("release(%s) failed: %s", key, e)


async def redis_available() -> bool:
    """当前进程是否有可用 Redis 客户端（不 ping，只看装配状态）。"""
    return await _default_client() is not None
