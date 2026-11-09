"""scheduler_leader.py — A3 多进程调度选主（REMEDIATION-PLAN-2026-10-30 路线 A3-①）。

背景（PERF-OPT-PLAN 1-5 障碍②）：backend 有 17 个 scheduler 周期循环
（SLA/KPI/PQ drain/自博弈评审/因果学习/demo 流量…）。单进程时代天然单份；
多 worker 部署后每个 worker 各跑一套 → 告警翻倍、KPI 重复聚合、PQ 双消费者
互抢。选主：**全局唯一 leader** 跑全部调度循环，follower 只服务
HTTP/Kafka 消费/审计执行（这些按进程扩展正是多进程的目的）。

语义：
  - Redis 可用：`SET soc:scheduler:leader <token> NX EX ttl`；拿到即 leader，
    每 ttl/3 续约（token 校验防误续）。续约失败/锁被夺 → 停掉调度循环
    （cancel + gather），回到竞选；期间 CRITICAL 日志可见。
  - Redis 不可用（try_acquire 返回 None）：**退回单进程行为直接启动**——
    与认领锁同一约定：Redis 缺席时互斥退化为尽力而为，不因此停摆
    （单容器部署语义不变；多容器无 Redis 属配置错误，日志告警可见）。
"""
from __future__ import annotations

import asyncio
import logging
from typing import Awaitable, Callable, Optional

from distributed_lock import try_acquire

logger = logging.getLogger(__name__)

LEADER_KEY = "soc:scheduler:leader"


class LeaderElection:
    """全局调度 leader 选举（Redis SET NX + 心跳续约 + 失联降级）。"""

    def __init__(self, key: str = LEADER_KEY, ttl_s: int = 30,
                 client=None, identity: str = ""):
        self.key = key
        self.ttl = max(5, int(ttl_s))
        self.interval = max(1, self.ttl // 3)
        self._client = client
        self.identity = identity or f"pid:{__import__('os').getpid()}"
        self.is_leader = False
        self._task: Optional[asyncio.Task] = None
        self._token: Optional[str] = None

    async def try_become_leader_once(self) -> Optional[bool]:
        """单次竞选。True=成为 leader（并记住 token 供续约/释放）。"""
        from distributed_lock import _TOKEN
        res = await try_acquire(self.key, self.ttl, client=self._client)
        if res is True:
            self._token = _TOKEN
            self.is_leader = True
        return res

    async def renew(self) -> bool:
        """续约（token 校验）。True=仍是 leader。"""
        if self._client is None or self._token is None:
            return False
        import redis as _redis  # noqa: F401
        try:
            from distributed_lock import _RELEASE_LUA  # 同款 token 校验风格
        except Exception:
            pass
        lua = """
        if redis.call('GET', KEYS[1]) == ARGV[1] then
            return redis.call('EXPIRE', KEYS[1], ARGV[2])
        end
        return 0
        """
        try:
            res = self._client.eval(lua, 1, self.key, self._token, self.ttl)
            if hasattr(res, "__await__"):
                res = await res
            ok = bool(int(res or 0))
            if not ok:
                self.is_leader = False
            return ok
        except Exception as e:
            logger.warning("[LeaderElection] renew failed: %s", e)
            return False

    async def release(self) -> None:
        """显式释放（token 校验，防误删他人锁）。"""
        if self._client is None or self._token is None:
            return
        lua = """
        if redis.call('GET', KEYS[1]) == ARGV[1] then
            return redis.call('DEL', KEYS[1])
        end
        return 0
        """
        try:
            res = self._client.eval(lua, 1, self.key, self._token)
            if hasattr(res, "__await__"):
                res = await res
        except Exception as e:
            logger.debug("[LeaderElection] release failed: %s", e)
        finally:
            self.is_leader = False
            self._token = None

    async def supervise(
        self,
        start_loops: Callable[[], Awaitable[None]],
        stop_loops: Callable[[], Awaitable[None]],
    ) -> None:
        """常驻任务：竞选 → 启动调度循环 → 心跳；失联 → 停循环 → 回竞选。

        Redis 不可用（首竞选返回 None）时直接 start_loops（单进程语义），
        不再反复尝试（避免 Redis 抖动时循环反复启停）。
        """
        first = True
        while True:
            res = await self.try_become_leader_once()
            if res is None:
                if first:
                    logger.warning(
                        "[LeaderElection] Redis 不可用 —— 退回单进程语义直接启动调度循环"
                        "（多容器部署请配置 Redis）")
                    await start_loops()
                return
            if res is True:
                logger.info("[LeaderElection] %s 成为调度 leader（ttl=%ss）",
                            self.identity, self.ttl)
                await start_loops()
                # 心跳：续约失败即让位
                while True:
                    await asyncio.sleep(self.interval)
                    if not await self.renew():
                        logger.critical(
                            "[LeaderElection] leader 租约丢失（%s）—— 停止调度循环并回到竞选",
                            self.identity)
                        await stop_loops()
                        break
                continue
            if first:
                logger.info("[LeaderElection] %s 是 follower（leader 已存在），仅服务流量",
                            self.identity)
            first = False
            await asyncio.sleep(self.interval)
