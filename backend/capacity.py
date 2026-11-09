"""统一资源容量。

每种昂贵资源只有一个闸，上限全部来自 settings。
入口在接受新工作前询问；闸满或审计队列到达高水位时拒绝，不再创建任务把过载藏起来。
水位降到低水位之后，Kafka 恢复拉取，已经接住的队列由原有 worker 继续消化。
"""
from __future__ import annotations

import asyncio
import logging
import time
from contextlib import asynccontextmanager
from typing import AsyncIterator, Callable, Optional

from config import settings

logger = logging.getLogger(__name__)


class GateTimeout(Exception):
    """等不到资源槽，或单批墙钟耗尽。"""

    def __init__(self, gate: str):
        self.gate = gate
        super().__init__(gate)


class AdmissionDenied(Exception):
    """上游不应再接收新工作。"""

    def __init__(self, reason: str):
        self.reason = reason
        self.status = overload_status()
        self.retry_after = overload_retry_after()
        super().__init__(reason)


class BatchRejected(Exception):
    """单次请求超过配置的批次硬顶。"""

    def __init__(self, reason: str, limit: int, count: int):
        self.reason = reason
        self.limit = int(limit)
        self.count = int(count)
        super().__init__(f"{reason}:{count}>{limit}")


class IngestCapacityError(Exception):
    """批次处理到一半下游不再接受。已成功的条数单独返回。"""

    def __init__(self, reason: str, accepted: int, total: int):
        self.reason = reason
        self.accepted = int(accepted)
        self.total = int(total)
        super().__init__(reason)


class BoundedGate:
    """活上限闸。每次 acquire 读配置，超时抛 GateTimeout，不在闸内睡眠躲过载。"""

    def __init__(self, name: str, limit_getter: Callable[[], int], timeout_getter: Callable[[], float]):
        self.name = name
        self._limit_getter = limit_getter
        self._timeout_getter = timeout_getter
        self._cv: Optional[asyncio.Condition] = None
        self._inflight = 0
        self._waiters = 0

    def limit(self) -> int:
        try:
            return max(1, int(self._limit_getter()))
        except (TypeError, ValueError):
            return 1

    def default_timeout(self) -> float:
        try:
            return max(0.05, float(self._timeout_getter()))
        except (TypeError, ValueError):
            return 1.0

    def inflight(self) -> int:
        return self._inflight

    def waiters(self) -> int:
        return self._waiters

    def saturated(self) -> bool:
        return self._inflight >= self.limit()

    def snapshot(self) -> dict:
        return {
            "name": self.name,
            "inflight": self._inflight,
            "waiters": self._waiters,
            "limit": self.limit(),
        }

    def _ensure(self) -> asyncio.Condition:
        if self._cv is None:
            self._cv = asyncio.Condition()
        return self._cv

    async def try_acquire(self) -> bool:
        cv = self._ensure()
        async with cv:
            if self._inflight >= self.limit():
                return False
            self._inflight += 1
            return True

    async def release(self) -> None:
        cv = self._ensure()
        async with cv:
            self._inflight = max(0, self._inflight - 1)
            cv.notify_all()

    @asynccontextmanager
    async def acquire(self, timeout: Optional[float] = None) -> AsyncIterator[None]:
        to = self.default_timeout() if timeout is None else max(0.01, float(timeout))
        cv = self._ensure()
        entered = False
        async with cv:
            self._waiters += 1
            try:
                deadline = time.monotonic() + to
                while self._inflight >= self.limit():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise GateTimeout(self.name)
                    try:
                        await asyncio.wait_for(cv.wait(), timeout=remaining)
                    except asyncio.TimeoutError:
                        raise GateTimeout(self.name) from None
                self._inflight += 1
                entered = True
            finally:
                self._waiters = max(0, self._waiters - 1)
        try:
            yield
        finally:
            if entered:
                await self.release()


def _int_setting(name: str, default: int) -> int:
    try:
        return int(getattr(settings, name, default) or default)
    except (TypeError, ValueError):
        return default


def _float_setting(name: str, default: float) -> float:
    try:
        return float(getattr(settings, name, default) or default)
    except (TypeError, ValueError):
        return default


def strict_int_setting(name: str, default: int) -> int:
    """P3-6: 读取**保留显式 0** 的整数配置。

    与 ``_int_setting`` 的唯一区别是不写 ``or default`` ——
    那个写法会把配置里的 0 吞成 default。对容量/并发这类非负参数无害，
    但对「上界」是有害的：``tool_query_max_limit=0`` 的含义是**全部拒绝**，
    经 ``_int_setting`` 读出来会变成 1000，一个安全边界被静默放宽。

    纯新增函数，不改 ``_int_setting``/``_float_setting`` 的既有语义。
    """
    raw = getattr(settings, name, default)
    try:
        return int(raw)
    except (TypeError, ValueError):
        return default


def check_query_bounds(*, limit=None, event_ids=None):
    """P3-6: 事件查询类接口的共同参数规则，返回第一个越界项。

    返回 ``(field, value, bound)``；全部合法则返回 ``None``。

    **只判定不抛异常**：调用点的错误表达不同 ——
    审计工具侧要抛 ``ToolParameterRejected`` 进 ToolResult，
    规则沙箱侧沿用本模块既有的 ``{"success": False, "error": ...}`` 风格。
    规则只有这一份，表达留给各自模块。

    为什么这类查询必须设界（实测依据）：
    ``event_ids`` 分支普遍写成 ``select(...).where(col.in_(ids))`` 后直接
    ``.scalars().all()``，**不套 limit** —— 上界形同虚设；
    而这些 ids 的来源可能是 LLM 自由文本（P3-6 的审计工具）
    或 HTTP 请求体（``/rules/sandbox``），能被放大到任意规模。

    ``limit < 1`` 一并判越界：limit=0 返回空列表，
    而空列表在下游与「没查到任何东西」完全同形。
    """
    max_limit = strict_int_setting("tool_query_max_limit", 1000)
    max_ids = strict_int_setting("tool_query_max_event_ids", 500)

    if limit is not None:
        try:
            n = int(limit)
        except (TypeError, ValueError):
            return ("limit", limit, max_limit)
        if n < 1 or n > max_limit:
            return ("limit", limit, max_limit)

    if event_ids and len(event_ids) > max_ids:
        return ("event_ids", len(event_ids), max_ids)

    return None


def overload_status() -> int:
    code = _int_setting("http_overload_status", 503)
    return code if code in (429, 503) else 503


def overload_retry_after() -> int:
    return max(1, _int_setting("http_overload_retry_after_s", 2))


def body_limit_bytes() -> int:
    return max(0, _int_setting("http_ingest_max_body_bytes", 1_048_576))


def body_too_large(nbytes: Optional[int]) -> bool:
    if nbytes is None:
        return False
    limit = body_limit_bytes()
    return limit > 0 and int(nbytes) > limit


def batch_policy() -> str:
    policy = str(getattr(settings, "http_ingest_batch_policy", "chunk") or "chunk").strip().lower()
    return policy if policy in ("chunk", "reject") else "chunk"


def batch_limits() -> tuple[int, int, str]:
    max_batch = max(1, _int_setting("http_ingest_max_batch", 200))
    absolute = max(max_batch, _int_setting("http_ingest_absolute_max", 1000))
    return max_batch, absolute, batch_policy()


def plan_batch_count(count: int) -> tuple[str, int]:
    """返回 ('ok'|'chunk'|'reject', 使用的上限)。"""
    max_batch, absolute, policy = batch_limits()
    n = int(count)
    if n > absolute:
        return "reject", absolute
    if n > max_batch and policy == "reject":
        return "reject", max_batch
    if n > max_batch:
        return "chunk", max_batch
    return "ok", max_batch


def ensure_batch_allowed(count: int) -> int:
    """返回切块大小。超过硬顶时抛 BatchRejected。"""
    decision, limit = plan_batch_count(count)
    if decision == "reject":
        raise BatchRejected("batch_limit", limit, count)
    return limit


def chunk_list(items: list, size: int) -> list[list]:
    step = max(1, int(size))
    return [items[i:i + step] for i in range(0, len(items), step)]


_GATES: dict[str, BoundedGate] = {}
# 处理队列（审计内存队列）单信号闩 —— kafka_fetch_paused 专用
_queue_pressure = False
# 复合背压信号闩（HTTP 准入用）+ 最近一次触发原因
_pressure = False
_pressure_reasons: tuple[str, ...] = ()


def reset_gates() -> None:
    """测试或配置切换时丢掉旧闸。Condition 绑在创建它的事件循环上。"""
    global _pressure, _queue_pressure, _pressure_reasons
    _GATES.clear()
    _pressure = False
    _queue_pressure = False
    _pressure_reasons = ()


def _gate(name: str, limit_getter: Callable[[], int], timeout_getter: Callable[[], float]) -> BoundedGate:
    gate = _GATES.get(name)
    if gate is None:
        gate = BoundedGate(name, limit_getter, timeout_getter)
        _GATES[name] = gate
    return gate


def db_write_gate() -> BoundedGate:
    return _gate(
        "db_write",
        lambda: _int_setting("db_write_max_concurrency", 8),
        lambda: _float_setting("db_write_timeout_s", 5.0),
    )


def kafka_produce_gate() -> BoundedGate:
    return _gate(
        "kafka_produce",
        lambda: _int_setting("kafka_produce_max_inflight", 32),
        lambda: _float_setting("kafka_produce_timeout_s", 10.0),
    )


def batch_fanout_gate() -> BoundedGate:
    return _gate(
        "batch_fanout",
        lambda: _int_setting("audit_batch_concurrency", 8),
        lambda: _float_setting("http_ingest_downstream_wait_s", 2.0),
    )


def background_task_gate() -> BoundedGate:
    """接入后的后台任务（快速响应、案例聚合）。满了就跳过，不再往事件循环里堆任务。"""
    return _gate(
        "background",
        lambda: _int_setting("http_background_max", 8),
        lambda: 0.05,
    )


async def schedule_bounded(coro, *, gate: BoundedGate, label: str) -> bool:
    """占到名额才创建任务。占不到就关掉协程并返回 False。"""
    if not await gate.try_acquire():
        coro.close()
        logger.warning("%s skipped: background task cap is full", label)
        return False

    async def _run():
        try:
            await coro
        except asyncio.CancelledError:
            raise
        finally:
            await gate.release()

    try:
        asyncio.create_task(_run(), name=label)
    except Exception:
        await gate.release()
        coro.close()
        raise
    return True


_ratio_warned = False


def audit_queue_ratio() -> float:
    global _ratio_warned
    try:
        from audit_worker import audit_worker
        cap = max(1, int(audit_worker._queue_max()))
        return float(audit_worker.queue_depth()) / float(cap)
    except Exception as exc:
        if not _ratio_warned:
            _ratio_warned = True
            logger.warning(
                "audit queue ratio unavailable, admission stays open: %s",
                type(exc).__name__,
            )
        return 0.0


def _latch(current: bool, ratio: float, high: float, low: float) -> bool:
    """高水位闩上，低水位才打开。中间地带保持原状态，避免抖动。"""
    if ratio >= high:
        return True
    if ratio <= low:
        return False
    return current


def _watermarks() -> tuple[float, float]:
    high = _float_setting("audit_queue_high_watermark", 0.8)
    low = _float_setting("audit_queue_low_watermark", 0.5)
    return high, min(low, high)


def kafka_lag_ratio() -> float:
    """Kafka lag 比信号：total_lag / (实测消费容量 × 允许积压秒数)。

    容量未标定（kafka_consumption_eps=0）时恒 0 —— 不许用拍脑袋阈值
    触发过载拒绝。PERF-2026-10-26 实测：lag 峰值 12216 全程无任何闸门
    读它（当时唯一背压信号审计队列比峰值仅 27%）—— 本函数就是缺的那条线；
    标定数字以 PERF-2 复测回填 config。
    """
    capacity_eps = _float_setting("kafka_consumption_eps", 0)
    if capacity_eps <= 0:
        return 0.0
    backlog_s = max(1.0, _float_setting("kafka_lag_allowed_backlog_s", 60))
    try:
        from core_metrics import total_kafka_lag
        lag = max(0, int(_cluster_max("kafka_lag", float(total_kafka_lag()))))
    except Exception:
        return 0.0
    return lag / (capacity_eps * backlog_s)


def pq_depth_ratio() -> float:
    """PQ（P0/P1 LLM 溢出池）深度比：同步快照 / audit_pq_capacity。

    快照允许陈旧（enqueue/depth 成功路径刷新）—— 背压带滞回，不要求会计
    级精确；Redis 未接线时恒 0，信号自然失效而非误报。
    """
    cap = strict_int_setting("audit_pq_capacity", 2000)
    if cap <= 0:
        return 0.0
    try:
        from audit_pq import pq_depth_snapshot
        local = float(pq_depth_snapshot())
    except Exception:
        local = 0.0
    # A3-③: 集群内最深 worker 的 PQ 计入本进程准入信号
    worst = _cluster_max("pq_depth", local)
    return min(1.0, worst / float(cap))


# ── A3-③ 共享压力 Gauge（REMEDIATION-PLAN-2026-10-30 路线 A3）──
# 多 worker 时各进程只看得见自己的 lag/队列深度；准入闸门若只读本进程读数，
# 另一 worker 的积压会被无视。每 worker 把本地读数发布到 Redis Hash
# （soc:gauge:<kind>，field=worker_id，EX 90s），合并取**全集群 max** ——
# 闸门语义从"本进程没压"升级为"集群里最紧的 worker 没压才放行"。

_WORKER_ID = (__import__("os").environ.get("SHARED_MEMORY_WORKER_ID")
              or f"{__import__('socket').gethostname()}-{__import__('os').getpid()}")

_GAUGE_KINDS = ("kafka_lag", "audit_queue_ratio", "pq_depth")

#: 其它 worker 的最新读数（kind → max），由 publish_worker_gauges 刷新
_CLUSTER_GAUGES: dict[str, float] = {}


async def publish_worker_gauges(redis_client, interval_s: int = 10) -> None:
    """常驻任务：发布本 worker 压力读数 + 合并远端（取 max）。

    失败只记 debug —— 共享 Gauge 是增强不是依赖，Redis 抖动时退回单进程
    读数（语义不劣于修复前）。接线点在 app lifespan（每个 worker 都要发，
    不能放 leader-only 的 scheduler 循环里）。
    """
    import asyncio as _aio

    while True:
        try:
            from core_metrics import total_kafka_lag
            from audit_pq import pq_depth_snapshot

            local = {
                "kafka_lag": float(total_kafka_lag()),
                "audit_queue_ratio": round(audit_queue_ratio(), 4),
                "pq_depth": float(pq_depth_snapshot()),
            }
            pipe = redis_client.pipeline()
            for kind, val in local.items():
                pipe.hset(f"soc:gauge:{kind}", _WORKER_ID, val)
                pipe.expire(f"soc:gauge:{kind}", 90)
            await pipe.execute()

            merged: dict[str, float] = {}
            for kind in _GAUGE_KINDS:
                raw = await redis_client.hgetall(f"soc:gauge:{kind}") or {}
                best = 0.0
                for wid, val in raw.items():
                    wid_s = wid.decode() if isinstance(wid, bytes) else str(wid)
                    if wid_s == _WORKER_ID:
                        continue
                    try:
                        best = max(best, float(val))
                    except (TypeError, ValueError):
                        continue
                merged[kind] = best
            _CLUSTER_GAUGES.clear()
            _CLUSTER_GAUGES.update(merged)
        except Exception as e:
            logger.debug("publish_worker_gauges skipped: %s", e)
        await _aio.sleep(max(2, interval_s))


def _cluster_max(kind: str, local: float) -> float:
    """本地读数与集群远端读数取 max（远端缺省 0 = 单进程语义不变）。"""
    try:
        return max(float(local), float(_CLUSTER_GAUGES.get(kind, 0.0)))
    except (TypeError, ValueError):
        return float(local)


def queue_pressure() -> bool:
    """处理队列（审计内存队列）单信号闩 —— kafka_fetch_paused 专用。

    拉取暂停**不**看 lag：停拉会加深 lag（PERF-OPT-PLAN 2-1 红线），
    lag 信号只用于 HTTP 准入。
    """
    global _queue_pressure
    high, low = _watermarks()
    _queue_pressure = _latch(_queue_pressure, audit_queue_ratio(), high, low)
    return _queue_pressure


def note_pressure() -> bool:
    """复合背压信号闩：max(队列比, Kafka lag 比, PQ 深度比)。

    只用于 HTTP 准入（admit_http）。2026-10-26 前准入只看审计队列深度，
    压测中它峰值仅 27% 从未触发，而真实背压在 Kafka lag（峰值 12216）上
    系统不自知 —— 本函数把准入闸门绑到真实瓶颈。
    """
    global _pressure, _pressure_reasons
    high, low = _watermarks()
    ratios = {
        # A3-③: 准入信号取集群 max（其它 worker 的积压也是本集群的背压）
        "audit_queue": _cluster_max("audit_queue_ratio", audit_queue_ratio()),
        "kafka_lag": kafka_lag_ratio(),
        "audit_pq": pq_depth_ratio(),
    }
    peak = max(ratios.values())
    _pressure = _latch(_pressure, peak, high, low)
    _pressure_reasons = tuple(k for k, v in ratios.items() if v >= high) if _pressure else ()
    return _pressure


def kafka_fetch_paused() -> bool:
    return queue_pressure()


def fetch_pause_interval() -> float:
    return max(0.05, _float_setting("kafka_fetch_pause_s", 0.5))


async def admit_http(*, direct: bool) -> None:
    """HTTP 入口。复合背压信号过载，或对应下游的闸已经占满，就拒绝这次请求。"""
    if note_pressure():
        if not _pressure_reasons or _pressure_reasons == ("audit_queue",):
            # 只有队列信号过载：保留旧 reason 字符串（API 消费方兼容）
            raise AdmissionDenied("audit_queue_high_watermark")
        raise AdmissionDenied("backpressure:" + "+".join(_pressure_reasons))
    if direct:
        if db_write_gate().saturated() or batch_fanout_gate().saturated():
            raise AdmissionDenied("downstream_saturated")
        return
    if kafka_produce_gate().saturated():
        raise AdmissionDenied("kafka_produce_saturated")


def snapshot() -> dict:
    llm = {}
    try:
        from llm_limiter import get_llm_limiter
        llm = get_llm_limiter().snapshot()
    except Exception:
        llm = {}
    return {
        "pressure": note_pressure(),
        "pressure_reasons": list(_pressure_reasons),
        "audit_queue_ratio": round(audit_queue_ratio(), 4),
        "kafka_lag_ratio": round(kafka_lag_ratio(), 4),
        "pq_depth_ratio": round(pq_depth_ratio(), 4),
        "batch": {
            "max_batch": batch_limits()[0],
            "absolute_max": batch_limits()[1],
            "policy": batch_limits()[2],
            "body_bytes": body_limit_bytes(),
        },
        "gates": {
            name: gate.snapshot()
            for name, gate in _GATES.items()
        },
        "llm": llm,
    }
