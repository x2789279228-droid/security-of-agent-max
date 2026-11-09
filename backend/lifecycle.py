"""优雅停机顺序。

0. 停采集入口(NDR/EDR/IDS 五引擎)，并 flush 存储(PCAP 轮转落库 / 在途 flow 落库)
   —— 必须先于数据库 dispose，否则尾部包丢、pcap_files 缺最后一条记录、
   在途流丢弃(2026-10-29 复审 P1-9 修复)。
1. draining：不再接受新任务。
2. Kafka 停止拉取。已经进处理函数的这批允许收尾，不确认未完成的位点。
3. 审计 worker 等待在途任务，超时后把内存里剩下的任务写入 Kafka 或 spill 日志。
4. 刷生产者缓冲区，再关闭消费者（只提交已完成水位）。
5. 停调度器、Redis 桥、Redis、数据库连接。

取消不是成功。各循环在 finally 里做清理，然后继续抛出 CancelledError。
"""
from __future__ import annotations

import logging

from config import settings
from drain import drain

logger = logging.getLogger(__name__)


async def _stop_capture_engines() -> None:
    """停 5 个采集/接入引擎并刷存储。各自独立 try/except: 一个失败不停别的。"""
    # 1) 先停"入口"(不再产生新事件): capture → suricata → edr
    for name, mod, attr in (
        ("capture_engine", "traffic_capture.capture_engine", "capture_engine"),
        ("suricata_connector", "ids_connector.suricata_connector", "suricata_connector"),
        ("edr_adapter", "edr_fusion.edr_adapter", "edr_adapter"),
    ):
        try:
            module = __import__(mod, fromlist=[attr])
            engine = getattr(module, attr)
            await engine.stop()
        except Exception as exc:
            logger.error("Shutdown: %s stop failed: %s", name, exc)
    # 2) 再刷存储(pcap 轮转关闭当前文件+落元数据; flow 落在途流) — 需 DB 仍可用
    for name, mod, attr in (
        ("pcap_store", "traffic_capture.pcap_store", "pcap_store"),
        ("flow_aggregator", "traffic_capture.flow_aggregator", "flow_aggregator"),
    ):
        try:
            module = __import__(mod, fromlist=[attr])
            engine = getattr(module, attr)
            await engine.stop()
        except Exception as exc:
            logger.error("Shutdown: %s flush failed: %s", name, exc)


async def shutdown_platform() -> None:
    drain.begin()
    logger.info("Shutdown: draining, new work is rejected")

    await _stop_capture_engines()

    from kafka_consumer import kafka_consumer_manager
    from kafka_producer import kafka_producer

    if settings.kafka_enabled:
        try:
            await kafka_consumer_manager.begin_drain()
        except Exception as exc:
            logger.error("Shutdown: consumer drain failed, audit spill still runs: %s", exc)

    try:
        from audit_worker import audit_worker
        report = await audit_worker.stop()
        logger.info("Shutdown: audit drain %s", report)
        try:
            from core_metrics import log_process, record_shutdown_leftover
            spilled = int(report.get("spilled") or 0)
            lost = int(report.get("volatile_lost") or 0)
            record_shutdown_leftover(
                "audit_worker", leftover=spilled + lost, spilled=spilled, lost=lost,
            )
            if spilled or lost:
                log_process(
                    logger, event_id="", stage="shutdown",
                    result="lost" if lost else "partial",
                    reason="audit_drain",
                    retry_count=0,
                    spilled=spilled, lost=lost,
                )
        except Exception:
            pass
    except Exception as exc:
        logger.error("Shutdown: audit drain failed: %s", exc)

    if settings.kafka_enabled:
        try:
            await kafka_producer.flush()
        except Exception as exc:
            logger.error("Shutdown: producer flush failed: %s", exc)
        try:
            await kafka_producer.stop()
        except Exception as exc:
            logger.error("Shutdown: producer stop failed: %s", exc)
        try:
            await kafka_consumer_manager.stop()
        except Exception as exc:
            logger.error("Shutdown: consumer stop failed: %s", exc)

    try:
        from scheduler import scheduler
        await scheduler.stop()
    except Exception as exc:
        logger.error("Shutdown: scheduler stop failed: %s", exc)

    try:
        from event_bus import event_bus
        await event_bus.stop_redis_bridge()
    except Exception as exc:
        logger.error("Shutdown: redis bridge stop failed: %s", exc)

    try:
        from summary_compression import summary, embedder
        await summary.close()
        await embedder.close()
    except Exception as exc:
        logger.error("Shutdown: model clients close failed: %s", exc)

    try:
        from sliding_window import sliding_window
        await sliding_window.close()
    except Exception as exc:
        logger.error("Shutdown: redis close failed: %s", exc)

    try:
        # 审批 write-behind 必须在 DB dispose 之前排空，否则已批准工单
        # 的 DB 状态可能仍是 pending（重启后可被重复审批/执行）。
        from response_engine.human_approval import approval_queue
        await approval_queue.drain_persistence()
    except Exception as exc:
        logger.error("Shutdown: approval persistence drain failed: %s", exc)

    try:
        from models import dispose_engines
        await dispose_engines()
    except Exception as exc:
        logger.error("Shutdown: database dispose failed: %s", exc)

    drain.mark_stopped()
    logger.info("Shutdown complete")
