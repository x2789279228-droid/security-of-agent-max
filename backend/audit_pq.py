"""
审计优先级队列 (Audit Priority Queue)

inflight 满时: P0/P1 入 Redis ZSET 等待拉取, P2/P3 立即降级收口。
score = priority * 1e12 + (max_ts - enqueued_at_ms)  → 高优优先,同优早到优先。

成员 JSON: {event_id, session_id, anomaly_score, anomaly_reasons, max_rounds,
            triage, log_data_ref?} — log_data 内联(事件体通常不大)。
"""
from __future__ import annotations

import json
import logging
import time
from typing import Optional

logger = logging.getLogger(__name__)

PQ_KEY = "soc:audit:pq"
PQ_PAYLOAD_PREFIX = "soc:audit:pq:payload:"  # event_id → JSON payload

# 原子弹出：ZPOPMIN + GET + DEL 必须在同一次 EVAL 里完成。
# 否则 zpopmin 成功后进程崩溃，payload 变孤儿，任务不可恢复。
_POP_LUA = """
local items = redis.call('ZPOPMIN', KEYS[1], 1)
if #items == 0 then return nil end
local member = items[1]
local key = ARGV[1] .. member
local payload = redis.call('GET', key)
redis.call('DEL', key)
if not payload then return {member, ''} end
return {member, payload}
"""


async def _dead_letter(member: str, reason: str, detail: str = "") -> None:
    """丢失任务落死信（best-effort, 不影响队列主路径）。"""
    try:
        from audit_dead_letters import record
        await record(int(member), reason=reason, detail=detail)
    except Exception as e:
        logger.debug(f"[AuditPQ] dead letter record failed: {e}")


def _payload_is_temporal_agent(payload: dict) -> bool:
    """payload 是否 Temporal Agent 车道 (llm_agent/llm_deep) — 用真实 triage 推断。"""
    try:
        from audit_triage import score_event, uses_temporal
        tri = score_event(
            dict(payload.get("log_data") or {}),
            float(payload.get("anomaly_score") or 0),
        )
        return bool(uses_temporal(tri.lane))
    except Exception:
        return False


class AuditPriorityQueue:
    def __init__(self):
        self._redis = None

    def set_redis(self, redis_client) -> None:
        self._redis = redis_client
        logger.info("AuditPQ: Redis enabled (key=%s)", PQ_KEY)

    @property
    def available(self) -> bool:
        return self._redis is not None

    def _score(self, priority: int, enqueued_at_ms: Optional[int] = None) -> float:
        # 高 priority 在前; 同档用 (大时间戳 - now) 让早到的更大? 
        # ZSET 默认小分在前 — 我们用负分或用大数: score = -priority*1e12 - ts
        # 取 ZPOPMIN 时最小分 = 最高优 + 最早
        pri = max(0, min(100, int(priority or 0)))
        ts = int(enqueued_at_ms if enqueued_at_ms is not None else time.time() * 1000)
        return float(-pri * 1_000_000_000_000 - ts)

    async def enqueue(
        self,
        *,
        event_id: int,
        session_id: str,
        log_data: dict,
        anomaly_score: float,
        anomaly_reasons: list,
        max_rounds: int = 3,
        priority: int = 50,
        tier: str = "P1",
        ttl_s: int = 900,
    ) -> bool:
        if self._redis is None:
            return False
        try:
            now_ms = int(time.time() * 1000)
            member = str(int(event_id))
            payload = {
                "event_id": int(event_id),
                "session_id": session_id,
                "log_data": log_data,
                "anomaly_score": float(anomaly_score or 0),
                "anomaly_reasons": list(anomaly_reasons or [])[:20],
                "max_rounds": int(max_rounds or 3),
                "priority": int(priority),
                "tier": tier,
                "enqueued_at_ms": now_ms,
                "ttl_s": max(60, int(ttl_s)),
                "retry_count": int((log_data or {}).get("_pq_retry") or 0),
            }
            pipe = self._redis.pipeline()
            # payload TTL = 4×业务 TTL: 只是**安全网**(防消费者整体死亡后无限堆积);
            # 真正的过期语义在 pop 侧 —— 过期任务显式 dead_letter, 不许静默消失。
            pipe.set(
                f"{PQ_PAYLOAD_PREFIX}{member}",
                json.dumps(payload, ensure_ascii=False, default=str),
                ex=max(60, int(ttl_s)) * 4,
            )
            pipe.zadd(PQ_KEY, {member: self._score(priority, now_ms)})
            # 残留修复(2026-10-24): 删除 ZSET 整体 expire —— 修复前队列静默
            # 2×TTL 后整队消失(含刚入队、payload 仍存活的任务), 与 never-drop
            # 承诺冲突。ZSET 现在持久, 陈旧任务由 pop 侧显式过期出队。
            await pipe.execute()
            try:
                from metrics import inc_audit_pq_enqueue
                inc_audit_pq_enqueue(tier)
            except Exception:
                pass
            logger.info(
                f"[AuditPQ] enqueue event#{event_id} tier={tier} pri={priority}"
            )
            return True
        except Exception as e:
            logger.warning(f"[AuditPQ] enqueue failed: {e}")
            return False

    @staticmethod
    def _payload_expired(payload: dict) -> bool:
        """payload 是否已超过业务 TTL (enqueued_at_ms + 2×ttl_s)。"""
        try:
            enq = int(payload.get("enqueued_at_ms") or 0)
            ttl = int(payload.get("ttl_s") or 900)
            return enq > 0 and (time.time() * 1000 - enq) > ttl * 2 * 1000
        except (TypeError, ValueError):
            return False

    async def _pop_stale_skipping(self, max_skips: int = 16) -> Optional[dict]:
        """连续弹出并跳过陈旧任务 (每次跳过都显式 dead_letter)。"""
        for _ in range(max_skips):
            res = await self._redis.eval(_POP_LUA, 1, PQ_KEY, PQ_PAYLOAD_PREFIX)
            if not res:
                return None
            member, raw = res[0], res[1]
            if isinstance(member, bytes):
                member = member.decode()
            if isinstance(raw, bytes):
                raw = raw.decode()
            if not raw:
                await _dead_letter(member, "payload_missing", "stale skip")
                continue
            payload = json.loads(raw)
            if self._payload_expired(payload):
                try:
                    from metrics import inc_audit_pq_lost
                    inc_audit_pq_lost("expired")
                except Exception:
                    pass
                await _dead_letter(member, "expired", "stale skip")
                continue
            try:
                from metrics import inc_audit_pq_dequeue
                inc_audit_pq_dequeue(str(payload.get("tier") or "?"))
            except Exception:
                pass
            return payload
        return None

    async def pop_highest(self) -> Optional[dict]:
        """弹出最高优先级任务; 空队列返回 None。"""
        if self._redis is None:
            return None
        # 优先走 Lua：ZPOPMIN + GET + DEL 原子完成，避免“成员已出队、
        # payload 变孤儿”的不可恢复窗口。fake/旧客户端不支持 eval 时回退。
        if hasattr(self._redis, "eval"):
            try:
                res = await self._redis.eval(
                    _POP_LUA, 1, PQ_KEY, PQ_PAYLOAD_PREFIX,
                )
                if not res:
                    return None
                member, raw = res[0], res[1]
                if isinstance(member, bytes):
                    member = member.decode()
                if isinstance(raw, bytes):
                    raw = raw.decode()
                if not raw:
                    logger.error(
                        f"[AuditPQ] LOST member={member} reason=payload_missing (atomic pop)"
                    )
                    try:
                        from metrics import inc_audit_pq_lost
                        inc_audit_pq_lost("payload_missing")
                    except Exception:
                        pass
                    await _dead_letter(member, "payload_missing", "atomic pop")
                    return None
                try:
                    payload = json.loads(raw)
                except json.JSONDecodeError as e:
                    # 成员已被原子弹出并删除；损坏 payload 不能再走 fallback
                    # （那会弹出另一个任务，造成乱序/丢失）。
                    logger.error(
                        f"[AuditPQ] LOST member={member} reason=payload_corrupt: {e}"
                    )
                    try:
                        from metrics import inc_audit_pq_lost
                        inc_audit_pq_lost("payload_corrupt")
                    except Exception:
                        pass
                    await _dead_letter(member, "payload_corrupt", str(e))
                    return None
                # 残留修复(2026-10-24): 陈旧任务显式过期出队(不再靠整队 TTL) ——
                # 过期任务 dead_letter 后继续取下一个, 不静默消失。
                if self._payload_expired(payload):
                    try:
                        from metrics import inc_audit_pq_lost
                        inc_audit_pq_lost("expired")
                    except Exception:
                        pass
                    await _dead_letter(member, "expired",
                                       f"ttl_s={payload.get('ttl_s')}")
                    return await self._pop_stale_skipping()
                try:
                    from metrics import inc_audit_pq_dequeue
                    inc_audit_pq_dequeue(str(payload.get("tier") or "?"))
                except Exception:
                    pass
                return payload
            except Exception as e:
                logger.warning(f"[AuditPQ] atomic pop failed, fallback: {e}")
        try:
            # ZPOPMIN: 最小 score = 最高优
            items = await self._redis.zpopmin(PQ_KEY, count=1)
            if not items:
                return None
            member, _score = items[0]
            if isinstance(member, bytes):
                member = member.decode()
            raw = await self._redis.get(f"{PQ_PAYLOAD_PREFIX}{member}")
            await self._redis.delete(f"{PQ_PAYLOAD_PREFIX}{member}")
            if not raw:
                # payload 先于 ZSET 成员过期：任务已不可恢复，必须显式可见。
                logger.error(
                    f"[AuditPQ] LOST member={member} reason=payload_missing "
                    "(payload TTL 先于 ZSET 过期，任务无法重放)"
                )
                try:
                    from metrics import inc_audit_pq_lost
                    inc_audit_pq_lost("payload_missing")
                except Exception:
                    pass
                await _dead_letter(member, "payload_missing", "fallback pop")
                return None
            if isinstance(raw, bytes):
                raw = raw.decode()
            try:
                payload = json.loads(raw)
            except json.JSONDecodeError as e:
                logger.error(
                    f"[AuditPQ] LOST member={member} reason=payload_corrupt: {e}"
                )
                try:
                    from metrics import inc_audit_pq_lost
                    inc_audit_pq_lost("payload_corrupt")
                except Exception:
                    pass
                await _dead_letter(member, "payload_corrupt", str(e))
                return None
            try:
                from metrics import inc_audit_pq_dequeue
                inc_audit_pq_dequeue(str(payload.get("tier") or "?"))
            except Exception:
                pass
            return payload
        except Exception as e:
            logger.warning(f"[AuditPQ] pop failed: {e}")
            return None

    async def depth(self) -> int:
        if self._redis is None:
            return 0
        try:
            return int(await self._redis.zcard(PQ_KEY) or 0)
        except Exception:
            return 0

    async def peek_highest(self) -> Optional[dict]:
        """窥视最高优任务 (ZRANGE 0 0 + 读 payload), 不弹出; 空队列返回 None。"""
        if self._redis is None:
            return None
        try:
            try:
                items = await self._redis.zrange(PQ_KEY, 0, 0, withscores=True)
                member = items[0][0] if items else None
            except TypeError:
                # fake/旧客户端不支持 withscores kwarg
                members = await self._redis.zrange(PQ_KEY, 0, 0)
                member = members[0] if members else None
            if member is None:
                return None
            if isinstance(member, bytes):
                member = member.decode()
            raw = await self._redis.get(f"{PQ_PAYLOAD_PREFIX}{member}")
            if not raw:
                return None
            if isinstance(raw, bytes):
                raw = raw.decode()
            return json.loads(raw)
        except Exception as e:
            logger.warning(f"[AuditPQ] peek failed: {e}")
            return None

    async def pop_matching(self, predicate=None, *, window: int = 50) -> Optional[dict]:
        """按 ZSET 顺序扫描窗口内第一个满足 predicate 的成员并弹出。

        predicate=None → 等价 pop_highest (ZPOPMIN)。
        弹出成功时计 inc_audit_pq_dequeue(tier); 无匹配返回 None(不弹队头)。
        """
        if self._redis is None:
            return None
        if predicate is None:
            return await self.pop_highest()
        try:
            members = await self._redis.zrange(PQ_KEY, 0, max(0, int(window) - 1))
            for m in members or []:
                if isinstance(m, bytes):
                    m = m.decode()
                raw = await self._redis.get(f"{PQ_PAYLOAD_PREFIX}{m}")
                if not raw:
                    # 幽灵成员：立即清理 + 计数，避免“永远扫不到、也无告警”。
                    await self._redis.zrem(PQ_KEY, m)
                    logger.error(
                        f"[AuditPQ] LOST member={m} reason=payload_missing "
                        "(pop_matching)"
                    )
                    try:
                        from metrics import inc_audit_pq_lost
                        inc_audit_pq_lost("payload_missing")
                    except Exception:
                        pass
                    await _dead_letter(m, "payload_missing", "pop_matching ghost")
                    continue
                if isinstance(raw, bytes):
                    raw = raw.decode()
                try:
                    payload = json.loads(raw)
                except Exception:
                    continue
                try:
                    ok = bool(predicate(payload))
                except Exception:
                    ok = False
                if not ok:
                    continue
                removed = await self._redis.zrem(PQ_KEY, m)
                if not removed:
                    continue  # 并发被抢, 继续扫
                await self._redis.delete(f"{PQ_PAYLOAD_PREFIX}{m}")
                try:
                    from metrics import inc_audit_pq_dequeue
                    inc_audit_pq_dequeue(str(payload.get("tier") or "?"))
                except Exception:
                    pass
                return payload
            return None
        except Exception as e:
            logger.warning(f"[AuditPQ] pop_matching failed: {e}")
            return None

    async def pop_first_runnable(self, agent_full: bool = False, *, window: int = 50) -> Optional[dict]:
        """D-D: Agent 槽满时跳过队头 Temporal-agent 任务, 弹出第一个可运行任务。

        agent_full=False → 等价 pop_highest。
        agent_full=True  → 弹出窗口内第一个非 agent 车道 (llm_single/tools) 任务;
                            全是 agent 任务时返回 None, 队头 P0 留在队列不弹出。
        """
        if not agent_full:
            return await self.pop_highest()
        return await self.pop_matching(
            lambda payload: not _payload_is_temporal_agent(payload),
            window=window,
        )

    async def purge_stale(self, max_age_s: int = 900) -> int:
        """清理过期 payload 已消失但仍在 ZSET 的幽灵成员。"""
        if self._redis is None:
            return 0
        n = 0
        try:
            members = await self._redis.zrange(PQ_KEY, 0, 200)
            for m in members or []:
                if isinstance(m, bytes):
                    m = m.decode()
                exists = await self._redis.exists(f"{PQ_PAYLOAD_PREFIX}{m}")
                if not exists:
                    await self._redis.zrem(PQ_KEY, m)
                    await _dead_letter(m, "purged_ghost", "purge_stale")
                    n += 1
        except Exception as e:
            logger.debug(f"[AuditPQ] purge skipped: {e}")
        return n


def pq_ttl_for_tier(tier: str) -> int:
    """分档 PQ TTL; 实现放 audit_triage,这里 re-export 避免循环 import 调用点分散。"""
    from audit_triage import pq_ttl_for_tier as _impl
    return _impl(tier)


audit_pq = AuditPriorityQueue()
