"""
零丢失账本广播 — 把「入队 = 落库 + 幂等吸收」的实时账目推上 event_bus。

为什么走总线而不是 REST: 大屏 kiosk (/screen) 无 JWT, SSE 是它唯一的
活数据通道（/api/events/stream 无鉴权依赖, 与 agent_stage 同一安全面）。
账本等式与 PERF-2026-10-26 报告同口径:

    入队 enqueued = 接收 received − 拒绝 rejected − 校验失败 validation_failed
    落库 inserted = stats_counter Redis 绝对计数（低频对账吸收漂移）
    幂等吸收 absorbed = enqueued − inserted

每 INTERVAL 秒一条, bulk 车道按 key 合并（同键只留最新），洪峰不刷屏。
"""
import asyncio
import logging
import time

logger = logging.getLogger(__name__)


def _interval() -> float:
    import config
    return max(1.0, float(config.settings.ledger_interval_s))


def _registry():
    """测试可替换的注册表入口 (默认全局 REGISTRY)。"""
    override = globals().get("_REGISTRY_OVERRIDE")
    if override is not None:
        return override
    from prometheus_client import REGISTRY
    return REGISTRY


def _sample(metric_name: str) -> float:
    """Prometheus 指标全 label 组合求和; 无样本/异常返回 0。

    2026-10-27: 不能用 REGISTRY.get_sample_value —— 0.26.0 要求标签精确
    等于空字典, 带 label 的指标(received{source}/lag{topic})一律返回
    None (live 实测)。手动遍历求和, 跨 label 组合聚合。
    """
    total = 0.0
    try:
        for metric in _registry().collect():
            for s in metric.samples:
                if s.name == metric_name:
                    total += float(s.value or 0.0)
    except Exception:
        pass
    return total


async def _tick(prev: dict | None) -> dict:
    """构造并发布一帧账本; 返回 prev 状态供下轮窗口增量计算。

    2026-10-27 口径修正: 等式行改用**窗口增量** —— received 是进程内
    Counter (重启归零) 而 inserted 是 Redis 累计值, 绝对值混排会让
    等式看起来不闭合 (28 = 20,698 + 0)。增量口径下每帧都闭合:
    Δ入队 = Δ落库 + Δ幂等 (+本窗内仍在管道中的少量在途)。
    """
    from event_bus import event_bus

    received = _sample("soc_ingest_received_total")
    rejected = _sample("soc_ingest_rejected_total")
    validation_failed = _sample("soc_ingest_validation_failed_total")
    kafka_lag = _sample("soc_kafka_consumer_lag")
    dlq_depth = _sample("soc_dlq_depth")

    enqueued = max(0.0, received - rejected - validation_failed)

    inserted: int | None = None
    try:
        from stats_counter import snapshot as stats_snapshot
        snap = await stats_snapshot()
        if snap is not None:
            inserted = int(snap.get("total") or 0)
    except Exception as e:
        logger.debug(f"ledger: stats snapshot failed: {e}")

    now = time.time()
    eps = 0.0
    if prev is not None and now > prev["ts"]:
        eps = max(0.0, (received - prev["received"]) / (now - prev["ts"]))

    frame = {
        "received": int(received),
        "rejected": int(rejected),
        "validation_failed": int(validation_failed),
        "enqueued": int(enqueued),
        "inserted": inserted,
        "absorbed": None if inserted is None else max(0, int(enqueued) - inserted),
        "kafka_lag": int(kafka_lag),
        "dlq_depth": int(dlq_depth),
        "eps": round(eps, 1),
        "interval_s": round(_interval(), 1),
        "ts": now,
    }

    # 窗口增量 (第二帧起才有): 等式行展示这组, 数字口径一致恒闭合
    if prev is not None and inserted is not None and prev.get("inserted") is not None:
        d_recv = max(0, int(received) - int(prev["received"]))
        d_rej = max(0, int(rejected) - int(prev["rejected"]))
        d_val = max(0, int(validation_failed) - int(prev["validation_failed"]))
        d_ins = max(0, inserted - int(prev["inserted"]))
        d_enq = max(0, d_recv - d_rej - d_val)
        frame["win_enqueued"] = d_enq
        frame["win_inserted"] = d_ins
        frame["win_absorbed"] = max(0, d_enq - d_ins)

    event_bus.publish("ledger", frame)
    return {
        "received": received,
        "rejected": rejected,
        "validation_failed": validation_failed,
        "inserted": inserted,
        "ts": now,
    }


async def run_forever() -> None:
    logger.info(f"Ledger broadcast started (interval={_interval():.1f}s)")
    prev: dict | None = None
    while True:
        try:
            prev = await _tick(prev)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.debug(f"ledger broadcast failed: {e}")
        await asyncio.sleep(_interval())


def start() -> None:
    """在 lifespan 中调用: 挂一个后台广播任务。失败只降级(无账本推送)。"""
    asyncio.get_running_loop().create_task(run_forever())
