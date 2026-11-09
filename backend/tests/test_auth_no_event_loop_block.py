# -*- coding: utf-8 -*-
"""R7: bcrypt 哈希/校验不得阻塞事件循环 (P2)。

bcrypt cost≈12 单次 ~150-300ms 纯 CPU。修复前 login/register 在 async def 内
直跑 bcrypt.checkpw/hashpw —— 期间全部在途请求停摆。

验证方式: 事件循环上并挂一个 5ms 周期的心跳任务, 在 await bcrypt 协程期间
统计心跳 tick 数。若实现退化为同步直跑(阻塞 loop), 心跳会停摆, tick 数远低于
预期下限; to_thread 实现下心跳持续跳动。
"""
from __future__ import annotations

import asyncio
import os
import sys
import time

import pytest

os.environ.setdefault("SHARED_MEMORY_SKIP_DOTENV", "1")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


async def _heartbeat_ticks(coro, min_ticks: int) -> int:
    """运行 coro 的同时数心跳; 返回 coro 运行期间的心跳次数。"""
    ticks = 0

    async def beat():
        nonlocal ticks
        while True:
            await asyncio.sleep(0.005)
            ticks += 1

    hb = asyncio.create_task(beat())
    try:
        await coro
    finally:
        hb.cancel()
        try:
            await hb
        except asyncio.CancelledError:
            pass
    assert ticks >= min_ticks, (
        f"事件循环被阻塞: 200ms+ 的 CPU 工作期间心跳仅 {ticks} 次 (期望 ≥ {min_ticks})"
    )
    return ticks


@pytest.mark.asyncio
async def test_verify_password_async_does_not_block_loop():
    from user_store import hash_password_async, verify_password_async

    h = await hash_password_async("correct-horse-battery")
    t0 = time.monotonic()
    await _heartbeat_ticks(
        verify_password_async("correct-horse-battery", h), min_ticks=15
    )
    elapsed = time.monotonic() - t0
    # 若 bcrypt 真在工作(而非被 mock 掉), 单次校验应有可观测耗时
    assert elapsed > 0.01


@pytest.mark.asyncio
async def test_hash_password_async_does_not_block_loop():
    from user_store import hash_password_async

    await _heartbeat_ticks(hash_password_async("another-password-123"), min_ticks=15)


@pytest.mark.asyncio
async def test_verify_wrong_password_returns_false():
    from user_store import hash_password_async, verify_password_async

    h = await hash_password_async("right")
    assert await verify_password_async("wrong", h) is False
    assert await verify_password_async("right", "not-a-hash") is False
