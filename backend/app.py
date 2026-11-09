# -*- coding: utf-8 -*-
"""
共享记忆安全审计 Agent 平台 — FastAPI 主入口

职责:
  - 应用生命周期管理 (lifespan: 初始化 / 关闭)
  - 中间件注册 (CORS / 速率限制)
  - 路由挂载 (15 个业务域 Router)

所有 API 端点已拆分到 routers/ 子模块，本文件不再定义端点。
"""

import asyncio
import logging
import json
import time
from collections import defaultdict
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from config import settings
from models import init_db, async_session, NetworkFlow, PcapFile
from observability.logging_setup import configure_logging
from sliding_window import sliding_window
from summary_compression import summary, embedder
from context_stream import context_stream
from anomaly_detector import anomaly_detector
from scheduler import scheduler
from source_registry import source_registry
from kafka_consumer import kafka_consumer_manager
from kafka_producer import kafka_producer
from response_engine import ssh_transport
from rag import seed_knowledge_base

# 结构化日志（JSON in prod / 带 request_id 的文本 in dev）——取代裸 basicConfig
configure_logging()
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting up...")
    # 数据库迁移: schema 演进的权威路径 (alembic), 必须先于 create_all。
    # to_thread: env.py 内部用 asyncio.run, 不能在运行中的事件循环里直接调。
    # fail-closed: 迁移失败阻止启动, 不允许未迁移的 schema 接流量。
    if getattr(settings, "auto_migrate", False):
        import os as _os
        from alembic import command as _alembic_command
        from alembic.config import Config as _AlembicConfig
        _backend_dir = _os.path.dirname(_os.path.abspath(__file__))
        _cfg = _AlembicConfig(_os.path.join(_backend_dir, "alembic.ini"))
        _cfg.set_main_option("script_location", _os.path.join(_backend_dir, "migrations"))
        try:
            await asyncio.to_thread(_alembic_command.upgrade, _cfg, "head")
            logger.info("Database migrations applied (alembic upgrade head)")
        except Exception as e:
            logger.error(f"Database migration failed — refusing to start: {e}")
            raise
    # auto_migrate=False 时也要 fail-closed：旧数据卷缺新列不能带病启动。
    from models import assert_schema_current
    await assert_schema_current()
    await init_db()
    # 审批工单持久化: 注入 session 工厂并恢复上次进程未决的 PENDING 工单
    # (修复前审批队列是纯内存 dict, 重启即丢全部高危待办)
    try:
        from response_engine.human_approval import approval_queue as _aq
        _aq.set_session_factory(async_session)
        _restored = await _aq.restore()
        if _restored:
            logger.warning("ApprovalQueue: %d pending ticket(s) restored from DB", _restored)
        _cleaned = await _aq.cleanup_db(max_age_hours=72)
        if _cleaned:
            logger.info("ApprovalQueue: cleaned %d terminal ticket row(s) from DB", _cleaned)
    except Exception as e:
        logger.warning(f"ApprovalQueue persistence init failed: {e}")
    # 成本控制: 从 llm_traces 重建今日用量, 保证预算门禁不因重启失效
    try:
        from datetime import datetime, timezone, timedelta
        from sqlalchemy import select, func
        from models import AgentTrace, async_session as db_session
        from summary_compression import cost_tracker
        today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
        async with db_session() as _s:
            used, prompt, completion = (await _s.execute(
                select(
                    func.coalesce(func.sum(AgentTrace.total_tokens), 0),
                    func.coalesce(func.sum(AgentTrace.prompt_tokens), 0),
                    func.coalesce(func.sum(AgentTrace.completion_tokens), 0),
                ).where(AgentTrace.created_at >= today_start)
            )).one()
            calls = (await _s.execute(
                select(func.count(AgentTrace.id)).where(AgentTrace.created_at >= today_start)
            )).scalar() or 0
        cost_tracker.restore_today_usage(
            tokens=int(used), calls=int(calls),
            prompt_tokens=int(prompt), completion_tokens=int(completion),
        )
        logger.info(
            f"CostControl: restored today usage={used} tokens / {calls} calls, "
            f"budget={cost_tracker.daily_budget}, over_budget={cost_tracker.is_over_budget()}"
        )
    except Exception as e:
        logger.warning(f"CostControl: failed to restore today usage (will start from zero): {e}")
    await sliding_window.connect()
    await summary.ensure_client()
    await embedder.ensure_client()
    # Connect Redis for context_stream
    redis_client = await sliding_window.get_redis()
    _gauge_task = None
    if redis_client:
        embedder.set_redis(redis_client)
        # A3-③(2026-10-30): 多 worker 压力读数共享 —— 每 worker 发布本地
        # lag/队列比/PQ 深度到 Redis, 准入闸门按集群 max 判断。
        from capacity import publish_worker_gauges
        _gauge_task = asyncio.create_task(publish_worker_gauges(redis_client))
        # v6: LLM 响应缓存接入同一 Redis(跨重启/跨容器共享), 替代原纯进程内缓存
        summary.llm.set_redis(redis_client)
        context_stream.set_redis(redis_client)
        anomaly_detector.set_redis(redis_client)
        # 回滚记录双写 Redis：进程重启后已执行动作仍可回滚
        from response_engine.response_executor import rollback_store
        rollback_store.set_redis(redis_client)
        # v6: Temporal worker 跨进程写回后,需 Redis 广播才能:
        #   1) 丢弃本进程 event_store 热缓存(否则 pipeline API 永远 pending)
        #   2) 把 audit_complete 注入本进程 SSE(否则 Monitor 看不到报告)
        from event_store import event_store as _event_store
        from event_bus import event_bus as _event_bus
        from temporal import client as _temporal_client
        from audit_pq import audit_pq as _audit_pq
        _event_store.set_redis(redis_client)
        _event_bus.set_redis(redis_client)
        _temporal_client.set_redis(redis_client)
        _audit_pq.set_redis(redis_client)
        await _event_store.start_invalidate_listener()
        await _event_bus.start_redis_bridge()
        await anomaly_detector.load_baselines_from_redis()
    # ── 响应执行层：失败关闭的默认模式 + Redis 幂等 + 持久化 TTL ──
    try:
        from response_engine.safe_executor import safe_executor
        from response_engine.ttl_manager import ttl_manager
        from response_engine.response_registry import ttl_rollback

        safe_executor.initialize()
        if redis_client:
            safe_executor.set_redis(redis_client)
            ttl_manager.set_redis(redis_client)
            ttl_manager.set_rollback_callback(ttl_rollback)
            await ttl_manager.recover_on_startup()
            await ttl_manager.start_scanner()
        mode = getattr(settings, "execution_mode", "dry_run")
        if mode == "live":
            logger.warning(
                "[Response] execution_mode=live —— 真实封禁/隔离已启用；"
                "请确认这是隔离靶场且已完成审批与资产白名单配置"
            )
        else:
            logger.info(f"[Response] execution_mode={mode}（真实执行关闭）")
        logger.info(
            "[Response] SafeExecutor initialized: redis=%s ttl=%s",
            bool(redis_client), bool(redis_client),
        )
    except Exception as e:
        # 初始化失败必须显式暴露；不能静默回落到 live。
        logger.error(f"[Response] SafeExecutor/TTL init failed: {e}")
    logger.info("安全审计模式: 所有事件全量存储，无有损压缩 + 异常基线持久化")
    if not settings.llm_api_key:
        logger.warning("LLM API key not set — LLM calls will return fallback responses")
    if not settings.embedding_api_key:
        logger.warning("Embedding API key not set — embeddings will return zero vectors")
    logger.info(f"LLM: {settings.llm_model} @ {settings.llm_base_url}")
    logger.info(
        "容量: llm并发=%s llm每分钟=%s 审计队列=%s 批大小=%s 策略=%s "
        "db写并发=%s kafka在途=%s",
        settings.llm_global_concurrency,
        settings.llm_rate_per_minute,
        settings.audit_queue_max,
        settings.http_ingest_max_batch,
        settings.http_ingest_batch_policy,
        settings.db_write_max_concurrency,
        settings.kafka_produce_max_inflight,
    )
    logger.info(f"Embedding: {settings.embedding_model} @ {settings.embedding_base_url}")
    logger.info(f"Embedding dim: {settings.embedding_dim}")

    # Qdrant 知识库 / 记忆集合就绪（缺失则创建，避免检索 404）
    try:
        from qdrant_store import qdrant_store
        from vector_store import vector_store as _mem_vs
        ok = await qdrant_store.ensure_collection()
        logger.info(
            f"Qdrant knowledge collection ready={ok} "
            f"name={settings.qdrant_collection} "
            f"size={settings.qdrant_vector_size or settings.embedding_dim}"
        )
        await _mem_vs._ensure_memories_collection()
    except Exception as e:
        logger.warning(f"Qdrant ensure_collection skipped: {e}")

    # 配置响应引擎传输层
    if settings.response_ssh_host:
        # v4 修复(2026-09-01):key_file 解析顺序:
        #   1. settings.response_ssh_key_file (env 显式配置)
        #   2. /tmp/ssh-keys/id_rsa (entrypoint 期望路径)
        #   3. /root/.ssh/id_rsa (兼容旧配置,entrypoint 也会 cp 到这里)
        import os as _os
        key_candidates = [
            settings.response_ssh_key_file,
            "/tmp/ssh-keys/id_rsa",
            "/root/.ssh/id_rsa",
        ]
        _key_file = next((p for p in key_candidates if p and _os.path.isfile(p)), settings.response_ssh_key_file)
        if not _os.path.isfile(_key_file):
            logger.warning(f"Response SSH key not found at any candidate: {key_candidates}; transport will be stub")
        ssh_transport.configure(
            host=settings.response_ssh_host,
            port=settings.response_ssh_port,
            user=settings.response_ssh_user,
            key_file=_key_file,
        )
        logger.info(f"Response SSH transport configured: {settings.response_ssh_user}@{settings.response_ssh_host}:{settings.response_ssh_port} key={_key_file}")
    else:
        logger.info("Response transport mode: stub (set RESPONSE_SSH_HOST to enable real execution)")

    # 播种安全知识库
    try:
        async with async_session() as rag_session:
            await seed_knowledge_base(rag_session)
    except Exception as e:
        logger.warning(f"Knowledge base seeding failed (will retry): {e}")

    # 启动时后台回填缺失 embedding(幂等, 独立 session; seed 因 count>10 skip 时也照常触发)
    try:
        from rag.seeder import launch_embedding_backfill
        launch_embedding_backfill(scope="chunks")
        launch_embedding_backfill(scope="memories")
    except Exception as e:
        logger.warning(f"Startup embedding backfill launch failed: {e}")

    # 数据源注册表初始化
    source_registry.load_from_config()
    try:
        await source_registry.load_from_db(async_session)
        await source_registry._backfill_pending(async_session)
    except Exception as e:
        logger.warning(f"SourceRegistry DB load failed: {e}; 继续使用 config 缓存")

    # 资产管理 — 从 DB 重建内存缓存
    try:
        from routers.assets import refresh_asset_cache
        await refresh_asset_cache()
    except Exception as e:
        logger.warning(f"[Assets] cache init failed: {e}")

    # SSH 防火墙适配器初始化（可选）
    if settings.fw_ssh_host:
        from response_engine.ssh_firewall import ssh_firewall
        ssh_firewall.configure(
            host=settings.fw_ssh_host,
            port=settings.fw_ssh_port,
            username=settings.fw_ssh_user,
            password=settings.fw_ssh_password,
            use_sudo=settings.fw_use_sudo,
        )
        logger.info(f"SSH firewall adapter configured: {settings.fw_ssh_user}@{settings.fw_ssh_host}")

    # Sigma 检测引擎
    from sigma_detector import sigma_detector
    logger.info(f"Sigma detector: {sigma_detector.stats()['rules_count']} rules loaded")
    try:
        from self_play.reviewer import seed_global_overlay
        n = await seed_global_overlay()
        logger.info(f"Self-Play overlay seeded {n} shadow/promoted rules")
    except Exception as e:
        logger.warning(f"Self-Play overlay seed skipped: {e}")

    # ── NDR 模块初始化（按配置按需启用） ──
    if settings.capture_enabled:
        from traffic_capture.capture_engine import capture_engine
        from traffic_capture.flow_aggregator import flow_aggregator
        from traffic_capture.pcap_store import pcap_store

        # 流持久化回调: FlowRecord → network_flows 表
        # (缺此接线时聚合结果会被直接丢弃, /api/ndr/flows 恒为空)
        async def _persist_flow(record):
            from datetime import datetime as _dt, timezone as _tz
            async with async_session() as session:
                session.add(NetworkFlow(
                    src_ip=record.src_ip, dst_ip=record.dst_ip,
                    src_port=record.src_port, dst_port=record.dst_port,
                    protocol=record.protocol, direction=record.direction,
                    bytes_in=record.bytes_in, bytes_out=record.bytes_out,
                    packets_in=record.packets_in, packets_out=record.packets_out,
                    duration_ms=record.duration_ms, tcp_flags=record.tcp_flags,
                    app_protocol=record.app_protocol, sensor_id=record.sensor_id,
                    flow_start=_dt.fromtimestamp(record.flow_start, tz=_tz.utc) if record.flow_start else None,
                    flow_end=_dt.fromtimestamp(record.flow_end, tz=_tz.utc) if record.flow_end else None,
                    raw_data={"packet_count": record.packet_count},
                ))
                await session.commit()

        flow_aggregator.on_flow_complete(_persist_flow)

        # PCAP 元数据持久化回调: 轮转关闭文件时写入 pcap_files 表
        async def _persist_pcap_meta(meta):
            from datetime import datetime as _dt
            async with async_session() as session:
                session.add(PcapFile(
                    file_path=meta["file_path"],
                    file_size=meta.get("file_size", 0),
                    sensor_id=meta.get("sensor_id", ""),
                    interface=meta.get("interface", ""),
                    packet_count=meta.get("packet_count", 0),
                    capture_start=_dt.fromisoformat(meta["capture_start"]) if meta.get("capture_start") else None,
                    capture_end=_dt.fromisoformat(meta["capture_end"]) if meta.get("capture_end") else None,
                    bpf_filter=settings.capture_bpf_filter,
                    status=meta.get("status", "closed"),
                    storage_tier=meta.get("storage_tier", "hot"),
                ))
                await session.commit()

        pcap_store.set_db_callback(_persist_pcap_meta)

        # 协议解析层: dissector 识别协议 → 各解析器 → TLS 会话关联落库
        # (缺此接线时 /api/ndr/tls 恒为空)
        from protocol_parser.dissector import dissector
        from protocol_parser.tls_parser import tls_parser
        from protocol_parser.http_parser import http_parser
        from protocol_parser.dns_parser import dns_parser
        from protocol_parser.smb_parser import smb_parser
        from encrypted_traffic.session_collector import tls_session_collector
        dissector.register_parser("TLS", tls_parser)
        dissector.register_parser("HTTP", http_parser)
        dissector.register_parser("DNS", dns_parser)
        dissector.register_parser("SMB", smb_parser)
        dissector.on_message(tls_session_collector.on_message)

        capture_engine.register_handler(dissector.on_packet)
        capture_engine.register_handler(flow_aggregator.on_packet)
        capture_engine.register_handler(pcap_store.on_packet)
        await flow_aggregator.start()
        await pcap_store.start()
        await capture_engine.start()
        logger.info("NDR 流量采集引擎已启动")

    if settings.edr_enabled:
        from edr_fusion.edr_adapter import edr_adapter
        await edr_adapter.start()
        logger.info("EDR 融合适配器已启动")

    if settings.suricata_enabled:
        # IDS 接入(2026-10-27 路线 2): 连接器消费 suricata-eve topic,
        # 默认处理器转 SecurityEvent → detect → 落库。需 kafka_enabled 同开。
        if not settings.kafka_enabled:
            logger.warning("suricata_enabled=true 但 kafka_enabled=false, IDS 接入跳过")
        else:
            from ids_connector.suricata_connector import suricata_connector
            await suricata_connector.start()
            logger.info("Suricata IDS 连接器已启动 (topic=%s)",
                        settings.suricata_eve_topic or "suricata-eve")

    if settings.intel_enabled:
        from threat_intel.ioc_matcher import ioc_matcher
        await ioc_matcher.refresh_cache()
        logger.info("威胁情报 IOC 缓存已加载")

    if settings.sandbox_enabled:
        from zeroday_detect.sandbox_connector import sandbox
        logger.info(f"沙箱连接器就绪: {sandbox.sandbox_type} @ {sandbox.api_url}")

    # Kafka 消息总线（可选）
    if settings.kafka_enabled:
        # 注册 Flink↔Python 跨运行时 Schema 契约 (best-effort, 失败不影响消费)
        from schema_registry import schema_registry
        register_results = await schema_registry.register_all()
        failed_subjects = [r.subject for r in register_results if not r.ok]
        if failed_subjects:
            logger.error(
                "[Schema] %s 个 subject 注册失败（冲突未核对待为失败）: %s",
                len(failed_subjects),
                ", ".join(failed_subjects),
            )
        await kafka_producer.start()
        await kafka_consumer_manager.start()
        logger.info("Kafka 模式已启用: 数据通过 Kafka + Flink 流水线处理 (Python 为薄消费者)")
    else:
        logger.info("HTTP 直连模式: 设置 SHARED_MEMORY_KAFKA_ENABLED=true 启用 Kafka")

    # 有界审计 worker(取代无界 create_task)
    try:
        from audit_worker import audit_worker
        await audit_worker.start()
    except Exception as e:
        logger.warning(f"AuditWorkerPool start failed: {e}")

    # 启动定时调度器
    await scheduler.start(async_session)
    logger.info("Scheduler started")

    # 零丢失账本广播 (SSE ledger 频道, 大屏账本面板数据源)
    try:
        from ledger_broadcast import start as start_ledger_broadcast
        start_ledger_broadcast()
        logger.info("Ledger broadcast started")
    except Exception as e:
        logger.warning(f"Ledger broadcast start failed: {e}")

    # 攻击态势广播 (SSE attack_geo 频道, 大屏攻击地图数据源)
    try:
        from attack_geo_broadcast import start as start_attack_geo_broadcast
        start_attack_geo_broadcast()
        logger.info("Attack geo broadcast started")
    except Exception as e:
        logger.warning(f"Attack geo broadcast start failed: {e}")

    # 可观测性
    # OpenTelemetry 标准 trace (→ otel-collector → Tempo)
    # 放在 lifespan 而非模块 import 期: 见文件下方"OpenTelemetry 说明"。
    if getattr(settings, "otel_enabled", True):
        try:
            from otel_setup import setup_otel
            setup_otel(app=app)
        except Exception as e:
            logger.warning(f"OTel setup failed: {e}")
    else:
        logger.info("OpenTelemetry disabled (otel_enabled=false)")

    from observability.health_monitor import health_monitor
    from observability.watchdog import watchdog
    from observability.pipeline_tracer import pipeline_tracer
    health_monitor.set_diagnose_callback(watchdog.diagnose)
    pipeline_tracer.enable_persist()
    logger.info("Observability: health monitor + watchdog + pipeline tracer initialized")

    try:
        from audit_worker import recover_unanalyzed
        restored = await recover_unanalyzed()
        if restored:
            logger.info("Startup recovered %d unanalyzed audit tasks from the database", restored)
    except Exception as e:
        logger.warning(f"Unanalyzed audit recovery skipped: {e}")

    # 审计死信重放(2026-10-23 第二阶段): PQ 丢失的任务上次运行时已落库,
    # 这里把它们再送进 worker —— "丢失→可见→可重放"闭环的最后一环。
    try:
        from audit_dead_letters import replay_dead_letters
        _replayed = await replay_dead_letters(limit=500)
        if _replayed:
            logger.warning("Audit dead letters replayed into worker: %d", _replayed)
    except Exception as e:
        logger.warning(f"Audit dead letter replay skipped: {e}")

    # 启动时清理长期 stuck 未分析事件，避免积压拖垮队列。
    # 已经回到审计队列或 spill 重放里的不标失败，否则刚恢复的任务会被清掉。
    if settings.stuck_auto_reset_minutes and settings.stuck_auto_reset_minutes > 0:
        try:
            from datetime import datetime, timezone, timedelta
            from sqlalchemy import select
            from models import SecurityEvent
            cutoff = datetime.now(timezone.utc) - timedelta(minutes=settings.stuck_auto_reset_minutes)
            async with async_session() as _s:
                rows = (await _s.execute(
                    select(SecurityEvent).where(
                        SecurityEvent.analyzed == False,
                        SecurityEvent.created_at < cutoff,
                    ).limit(500)
                )).scalars().all()
                from audit_worker import audit_worker as _audit_worker
                from event_store import event_store as _es
                n = 0
                reset_ids = []
                for e in rows:
                    if _audit_worker.holds(int(e.id)):
                        continue
                    e.analyzed = True
                    raw = dict(e.raw_data or {})
                    raw["_audit_llm_error"] = "auto_reset_stuck_on_startup"
                    audit = dict(raw.get("_audit_llm") or {})
                    audit.update({
                        "status": "failed",
                        "error": "auto_reset_stuck_on_startup",
                        "note": "cleared on backend startup",
                    })
                    raw["_audit_llm"] = audit
                    e.raw_data = raw
                    reset_ids.append(e.id)
                    n += 1
                if n:
                    await _es.commit_then_invalidate(_s, *reset_ids)
                    logger.warning(f"Cleared {n} stuck unanalyzed events older than {settings.stuck_auto_reset_minutes}m")
        except Exception as e:
            logger.warning(f"Stuck auto-reset skipped: {e}")

    yield

    # ── Shutdown ──
    # draining → 停拉 Kafka → 等审计任务或写成可恢复记录 → 刷生产者 →
    # 只提交已完成位点 → 关 Redis / Kafka / 数据库。
    try:
        from response_engine.ttl_manager import ttl_manager
        await ttl_manager.stop_scanner()
    except Exception as e:
        logger.warning(f"[Response] TTL scanner stop failed: {e}")
    # A3-③: 共享 Gauge 发布任务随进程退出取消
    try:
        if _gauge_task is not None:
            _gauge_task.cancel()
            await asyncio.gather(_gauge_task, return_exceptions=True)
    except Exception:
        pass
    from lifecycle import shutdown_platform
    await shutdown_platform()


# ════════════════════════════════════════════
# 应用实例 + 中间件
# ════════════════════════════════════════════

import os
_is_prod = os.environ.get("SHARED_MEMORY_ENV_NAME", settings.env_name) == "prod"

app = FastAPI(
    title="共享记忆服务层",
    version="2.0.0",
    lifespan=lifespan,
    docs_url=None if _is_prod else "/docs",
    redoc_url=None if _is_prod else "/redoc",
    openapi_url=None if _is_prod else "/openapi.json",
)

# 注: CORSMiddleware 的注册位置在文件末尾(所有中间件之后)。
#     Starlette 的 add_middleware / @app.middleware 执行 user_middleware.insert(0, ...),
#     即"最后注册 = 最外层"。若 CORS 先于 auth/rate_limit 注册, 它会落在最内层,
#     而 auth/rate_limit 用 return JSONResponse 直接返回 401/403/429 (不经过 call_next),
#     这些错误响应就不会带 Access-Control-Allow-Origin →
#     浏览器报 CORS "Failed to fetch" 而非可读的 401, 且违反 CORS 规范
#     (跨源请求的错误响应同样必须携带 ACAO)。
#     前端 lib/eventStream.ts 依赖这个 401 来清凭证并跳登录页;
#     CORS 位置错误时令牌过期会表现为"永远重连中"而不是登出。

# ── 全局认证中间件 ──
# 所有 /api/* 端点默认需要 JWT 认证 (Bearer header 或 ?token= query param)
# 白名单路径无需认证

_PUBLIC_PATHS = frozenset({
    "/api/auth/login",
    "/api/auth/register",
    "/api/health",
    "/docs", "/redoc", "/openapi.json",
    "/metrics",
})


@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    path = request.url.path
    from http_guards import allowlist_blocks, mtls_blocks
    blocked = allowlist_blocks(request)
    if blocked:
        return JSONResponse(status_code=403, content={"detail": blocked})
    mtls_err = mtls_blocks(request)
    if mtls_err:
        return JSONResponse(status_code=403, content={"detail": mtls_err})
    if path.startswith("/api/") and path not in _PUBLIC_PATHS:
        # 支持 Authorization header 和 query param (SSE EventSource 不支持自定义 header)
        token = None
        auth_header = request.headers.get("authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
        elif "token" in request.query_params:
            token = request.query_params["token"]

        if not token:
            return JSONResponse(status_code=401, content={"detail": "Missing authorization"})

        try:
            from auth import decode_access_token
            payload = await decode_access_token(token)
            request.state.user = payload
        except HTTPException as e:
            return JSONResponse(status_code=e.status_code, content={"detail": e.detail})

    response = await call_next(request)
    # 移除 Server 版本头 (starlette MutableHeaders 无 dict.pop, 用 del + 存在性检查)
    if "server" in response.headers:
        del response.headers["server"]
    return response


# ── 速率限制中间件 ──

_rate_limit_store: dict[str, list[float]] = defaultdict(list)
_RATE_LIMIT_CLEANUP_INTERVAL = 300
_last_rate_limit_cleanup = 0.0

from http_guards import rate_limit_decision as _rate_limit_decision
from http_guards import rate_limit_quota as _rate_limit_quota


def _resolve_rate_limit_key(request: Request) -> str:
    """v4 修复(2026-09-01):按 (api_key | X-Forwarded-For | client_ip) 分桶,避免 127.0.0.1 共桶

    优先级:
      1. X-API-Key 头(真实数据源)→ key:<truncated>
      2. Authorization Bearer token  → key:<truncated>
      3. X-Forwarded-For 第一项      → ip:<xff>
      4. request.client.host         → ip:<host>

    桶 key 截断到 32 字符,防止恶意长 header 撑爆 _rate_limit_store 内存
    """
    # 1. X-API-Key
    api_key = request.headers.get("X-API-Key", "").strip()
    if api_key:
        return f"key:{api_key[:32]}"
    # 2. Authorization Bearer
    auth = request.headers.get("Authorization", "").strip()
    if auth.lower().startswith("bearer "):
        token = auth[7:].strip()
        if token:
            return f"key:{token[:32]}"
    # 3. X-Forwarded-For(取第一项 = 真实客户端 IP)
    # P1: XFF 是**客户端可伪造**的头 — 无条件信任时攻击者每次请求轮换 XFF
    # 即可绕过全部限流(含 crit/strict 桶)。与 http_guards.client_ip 同一门槛:
    # 仅在 trust_proxy=true(部署在可信反代后)时采用, 否则用直连地址。
    if getattr(settings, "trust_proxy", False):
        xff = request.headers.get("X-Forwarded-For", "").strip()
        if xff:
            first_ip = xff.split(",")[0].strip()
            if first_ip:
                return f"ip:{first_ip[:64]}"
    # 4. client.host
    return f"ip:{request.client.host if request.client else 'unknown'}"


def _rate_limit_bucket(request: Request) -> Optional[tuple]:
    """返回 (桶 key, 命名空间);豁免路径返回 None。

    命名空间让"高危点名端点"(crit)与普通流量(std)互不占额度。
    """
    path = request.url.path
    counted, namespace = _rate_limit_decision(path, request.method)
    if not counted:
        return None
    return f"{namespace}:{_resolve_rate_limit_key(request)}", namespace


@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    global _last_rate_limit_cleanup
    bucket = _rate_limit_bucket(request)
    # 白名单路径直接 pass, 不计入限流
    if bucket is None:
        return await call_next(request)
    if settings.rate_limit_per_minute <= 0:
        return await call_next(request)
    # v4 修复:按 (api_key | xff | client_ip) 分桶,而非纯 client_ip
    rate_key, namespace = bucket
    now = time.time()
    window = 60.0
    if now - _last_rate_limit_cleanup > _RATE_LIMIT_CLEANUP_INTERVAL:
        _last_rate_limit_cleanup = now
        stale_keys = [k for k, ts in _rate_limit_store.items() if not ts or ts[-1] < now - window]
        for k in stale_keys:
            del _rate_limit_store[k]
    timestamps = _rate_limit_store[rate_key]
    cutoff = now - window
    _rate_limit_store[rate_key] = [t for t in timestamps if t > cutoff]
    limit = _rate_limit_quota(namespace)
    if len(_rate_limit_store[rate_key]) >= limit:
        return JSONResponse(
            status_code=429,
            content={
                "detail": "Rate limit exceeded",
                "limit_per_minute": limit,
                "scope": namespace,
            },
        )
    _rate_limit_store[rate_key].append(now)
    return await call_next(request)


@app.middleware("http")
async def ingest_body_limit_middleware(request: Request, call_next):
    """接入入口在读正文前按 Content-Length 拒绝。真正的批大小仍由路由再查一次。"""
    path = request.url.path
    if request.method == "POST" and (
        path == "/api/logs/ingest" or path.startswith("/api/logs/ingest/")
    ):
        from capacity import body_too_large
        raw = request.headers.get("content-length")
        if raw and str(raw).isdigit() and body_too_large(int(raw)):
            return JSONResponse(
                status_code=413,
                content={"status": "rejected", "reason": "body_too_large"},
            )
    return await call_next(request)


# ════════════════════════════════════════════
# 路由挂载 — 14 个业务域 Router
# ════════════════════════════════════════════

from routers.auth import router as auth_router
from routers.sources import router as sources_router
from routers.kafka import router as kafka_router
from routers.dlq import router as dlq_router
from routers.assets import router as assets_router
from routers.logs import router as logs_router
from routers.chat import router as chat_router
from routers.audit import router as audit_router
from routers.response import router as response_router
from routers.rag import router as rag_router
from routers.phishing import router as phishing_router
from routers.ndr import router as ndr_router
from routers.edr_intel import router as edr_intel_router
from routers.ops import router as ops_router
from routers.copilot import router as copilot_router
from routers.capabilities import router as capabilities_router
from routers.benchmark import router as benchmark_router
from routers.demo_seed import router as demo_seed_router
from routers.self_play import router as self_play_router
from routers.causal import router as causal_router

app.include_router(auth_router)
app.include_router(sources_router)
app.include_router(kafka_router)
app.include_router(dlq_router)
app.include_router(assets_router)
app.include_router(logs_router)
app.include_router(chat_router)
app.include_router(audit_router)
app.include_router(response_router)
app.include_router(rag_router)
app.include_router(phishing_router)
app.include_router(ndr_router)
app.include_router(capabilities_router)
app.include_router(benchmark_router)
# R12(复审 P1-8): 演示路由仅在显式 SHARED_MEMORY_DEMO_MODE=true 时挂载 —
# 修复前 /api/demo/seed|clear 无条件进生产路由, 且无任何"退出演示态"的服务端开关。
if settings.demo_mode:
    app.include_router(demo_seed_router)
else:
    logger.info("Demo mode disabled — /api/demo/* not mounted (set SHARED_MEMORY_DEMO_MODE=true to enable)")
app.include_router(edr_intel_router)
app.include_router(ops_router)
app.include_router(self_play_router)
app.include_router(causal_router)
app.include_router(copilot_router)

logger.info(f"Mounted 18 routers — {len(app.routes)} routes total")

# ── OpenTelemetry 说明（初始化已移入 lifespan，见下）──
# 2026-10-03: 原先在本模块 import 期无条件 setup_otel()。OTel 的全局 TracerProvider
# 是一次性的（第二次 set_tracer_provider 被静默忽略），于是：
#   1) 任何 import app 的代码都会永久抢占该进程级全局；
#   2) 测试无法注入自己的 provider —— test_trace_otel 只能"看谁先 import"，
#      且它标注为"还原"的那句 set_tracer_provider 本身就是被忽略的空操作；
#   3) 测试期间还会真的向 otel-collector:4317 发包。
# 现在改为在 lifespan 启动阶段初始化：import app 不再有副作用，测试可自行控制
# provider；且 FastAPI 在 lifespan 之后才开始构建中间件栈，此时 add_middleware
# 仍然有效。

# ── Prometheus 指标出口 (Python 侧; 与 Flink 9250 对齐, 统一可观测) ──
# 注: 用轻量 metrics.py (兼容 FastAPI 0.14x _IncludedRouter), 替代
# prometheus-fastapi-instrumentator (其内省 route.path 与新版 FastAPI 不兼容 → 全请求 500)
from metrics import metrics_endpoint, MetricsMiddleware

app.add_middleware(MetricsMiddleware)
app.add_api_route("/metrics", metrics_endpoint, include_in_schema=False, methods=["GET"])
logger.info("Prometheus /metrics enabled (metrics.py)")

# ── Request-Id + 全局异常处理 ──
# 注册在 Metrics 之后 → 位于 CORS(最外) 之下、Metrics 之上：
# 所有路径(含 /metrics、401/403/429 短路响应)都带 X-Request-ID，日志可关联。
from observability.request_middleware import RequestContextMiddleware, unhandled_exception_handler

app.add_middleware(RequestContextMiddleware)
app.add_exception_handler(Exception, unhandled_exception_handler)

# ════════════════════════════════════════════
# CORS — 必须最后注册(Starlette insert(0) → 最后注册=最外层)
# ════════════════════════════════════════════
# 放在这里而不是文件开头, 是为了让 auth/rate_limit/allowlist/mTLS 直接返回的
# 401/403/429 也经过 CORS 包装并带上 Access-Control-Allow-Origin。
# 详见本文件 FastAPI 实例创建处的说明。
app.add_middleware(
    CORSMiddleware,
    allow_origins=json.loads(settings.allowed_origins),
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-API-Key"],
)
