"""
temporal.worker — Temporal Worker(独立常驻进程)

注册 AuditPipelineWorkflow + 各 Activity, 消费 temporal.task_queue。
独立进程运行:
  docker compose up -d temporal-worker  或  python -m temporal.worker
"""
import asyncio
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("temporal-worker")


async def run_worker():
    import os
    from config import settings
    from temporalio.client import Client
    from temporalio.worker import Worker

    # 初始化 OTel(让 activity 内 pipeline_tracer.span 导出到 collector → Tempo/Jaeger)
    try:
        from otel_setup import setup_otel
        setup_otel()
    except Exception as e:
        logging.getLogger(__name__).warning(f"worker otel init failed: {e}")

    try:
        from observability.pipeline_tracer import pipeline_tracer
        pipeline_tracer.enable_persist()
    except Exception as e:
        logging.getLogger(__name__).warning(f"worker pipeline_spans persist failed: {e}")

    # v6: 接入 Redis,使 save_result/cad_verify 的:
    #   - event_store.invalidate(broadcast) 能通知 backend 丢弃热缓存
    #   - event_bus.publish(audit_complete) 提醒 backend SSE。
    #     Pub/Sub 是 at-most-once。审计正文在 SecurityEvent 行里，
    #     SSE 收到提醒后按 event_id 回源，不把这条消息当成唯一副本。
    try:
        import redis.asyncio as aioredis
        from event_store import event_store
        from event_bus import event_bus
        from temporal import client as temporal_client
        from audit_pq import audit_pq
        # socket_timeout=None: event_bus/event_store 用此客户端 pubsub.listen()
        # 长期阻塞监听; redis-py 8 默认 5s 超时会把空闲连接打断(redis-py#2807)
        r = aioredis.from_url(
            settings.redis_url, decode_responses=True, socket_timeout=None,
            # W31 P1(2026-10-30): 与 sliding_window 同口径显式扩容(默认 100 击穿)
            max_connections=int(getattr(settings, "redis_pool_max_connections", 500)),
        )
        await r.ping()
        event_store.set_redis(r)
        event_bus.set_redis(r)
        temporal_client.set_redis(r)
        audit_pq.set_redis(r)
        logger.info(f"Temporal worker Redis bridge ready ({settings.redis_url})")
    except Exception as e:
        logging.getLogger(__name__).warning(
            f"worker redis bridge unavailable (cache/SSE cross-process broken): {e}"
        )

    from temporal.workflows import AuditPipelineWorkflow, SelfPlayWorkflow
    from temporal.activities import (
        audit_round, save_result, trigger_response, cad_verify,
        selfplay_init, selfplay_round, selfplay_finalize,
    )

    # v5 修复:并发上限。此前无上限,216 个 workflow 同时启动时
    # 上百个 audit_round 并发打 LLM API → MiniMax 429 风暴 → 大量审计降级。
    # 每个活动内含多路 LLM 调用,12 路并发 ≈ 30-50 req/min,处于厂商限流安全区。
    try:
        concurrency = int(os.environ.get("TEMPORAL_CONCURRENCY", "12"))
    except ValueError:
        concurrency = 12

    client = await Client.connect(settings.temporal_host, namespace=settings.temporal_namespace)
    worker = Worker(
        client,
        task_queue=settings.temporal_task_queue,
        workflows=[AuditPipelineWorkflow, SelfPlayWorkflow],
        activities=[
            audit_round, save_result, trigger_response, cad_verify,
            selfplay_init, selfplay_round, selfplay_finalize,
        ],
        max_concurrent_activities=concurrency,
        max_concurrent_workflow_tasks=concurrency,
    )
    logger.info(
        f"Temporal worker starting: {settings.temporal_host} "
        f"queue={settings.temporal_task_queue} concurrency={concurrency}"
    )
    await worker.run()


if __name__ == "__main__":
    asyncio.run(run_worker())
