import os
from pathlib import Path

from pydantic_settings import BaseSettings

#: 2026-10-20 修复（整改报告 §9.48）：`SHARED_MEMORY_SKIP_DOTENV` 之前**只**挡住了
#: `_load_project_root_env()`（把项目根 .env 灌进 os.environ 那条通道），
#: **挡不住** pydantic-settings 自己的 dotenv 源 —— `class Config` 里的
#: `env_file = ".env"` 是**无条件**的，只受 CWD 约束。
#:
#: 实测后果：README 文档的 `pytest backend/tests -q`（**仓库根**执行）
#: 在**收集期**直接崩（16 条 extra_forbidden）—— 因为仓库根有 `.env`，
#: 而里面的键既不是 `SHARED_MEMORY_` 前缀、也不是 Settings 的声明字段；
#: pydantic-settings 会把 dotenv 里**任何未声明的键**当成 extra 塞进数据，
#: `extra="forbid"` 于是直接抛 ValidationError。
#: conftest 已经设了开关，**仍然崩** —— 开关根本没管到这条通道。
#:
#: 现在这个开关同时管住**两条**通道：打开 ⇒ **一个 .env 都不读**
#: （既不灌 os.environ，也不作为 dotenv 源）。
_SKIP_DOTENV = os.environ.get("SHARED_MEMORY_SKIP_DOTENV", "").strip() in (
    "1", "true", "TRUE", "yes"
)


class Settings(BaseSettings):
    # Database
    database_url: str = "postgresql+asyncpg://localhost:5432/shared_memory"
    redis_url: str = "redis://localhost:6379/0"
    # W31 P1(2026-10-30): redis-py from_url 默认池上限 100 —— enriched 消费
    # 突发下(pubsub 长连接 + 每事件幂等/缓存/广播)击穿 → MaxConnectionsError
    # 消费停摆(WAVE3-1-FLINK-DIRECT 实测)。服务端 maxclients=10000, 500 无压力。
    redis_pool_max_connections: int = 500

    # LLM
    llm_api_key: str = ""
    llm_base_url: str = ""
    llm_model: str = ""
    # Audit 路径默认关掉 thinking/reasoning（网关不认则自动剥离重试）
    llm_reasoning_effort: str = "none"
    # Copilot 图像理解（2026-11 AI Web 改造）：空 = 视觉能力关闭，
    # Copilot 前端如实置灰并说明原因（明示，不伪装）。需 OpenAI 兼容
    # 视觉模型（如 glm-4v / gpt-4o-mini / minimax-vl），与 llm_base_url 同网关。
    llm_vision_model: str = ""
    # Copilot 会话历史最多带入的对话轮数（防止 prompt 无界膨胀）
    copilot_history_max_turns: int = 6
    # Copilot 每次问答检索知识库的引用条数上限
    copilot_rag_top_k: int = 4

    # Embedding
    embedding_api_key: str = ""
    embedding_base_url: str = ""
    embedding_model: str = ""
    embedding_dim: int = 768

    # Service
    storage_backend: str = "redis"           # "redis" | "deque"
    sliding_window_size: int = 500
    sliding_window_minutes: int = 15         # 时间窗口（分钟）
    embedding_cache_ttl: int = 3600
    # LLM 响应缓存 TTL(秒): Redis 化后跨重启/跨容器共享; 默认 24h 收割"24h 内重复 prompt"
    llm_cache_ttl: int = 86400
    vector_search_threshold: float = 0.75

    # Qdrant 向量数据库 (RAG 知识库检索; 空则禁用 Qdrant, 回退 pgvector)
    qdrant_url: str = ""                     # 例: http://qdrant:6333
    qdrant_collection: str = "soc_knowledge_chunks"
    qdrant_memories_collection: str = "agent_memories"   # agent 记忆向量 collection
    qdrant_vector_size: int = 0              # 0 则取 embedding_dim
    qdrant_enabled: bool = True              # True=优先用 Qdrant 检索, 不可用时回退 pgvector
    qdrant_timeout: float = 5.0

    # RAG 混合检索 (dense + BM25 sparse + RRF + cross-encoder)
    rag_hybrid_enabled: bool = True
    rag_hybrid_collection: str = ""          # 空则用 {qdrant_collection}_v2
    rag_rrf_k: int = 60
    rag_prefetch: int = 20                   # 每路召回条数，融合后再截 top_k
    rag_bm25_backend: str = "builtin"        # builtin | fastembed
    rag_query_rewrite: str = "rules"         # off | rules | llm
    rag_hyde: str = "empty_only"             # off | empty_only | always
    rag_rerank_enabled: bool = True
    rag_rerank_url: str = ""                 # 空=不用 Infinity/CE，走特征重排；例 http://soc-bge-rerank:7997/rerank
    rag_rerank_api_key: str = ""             # 空且目标为本地 Infinity 时不带 Bearer
    rag_rerank_model: str = "BAAI/bge-reranker-v2-m3"
    rag_rerank_top_n: int = 20

    # Log Ingestion
    log_batch_size: int = 20                 # 累积多少条触发自动分析
    log_batch_interval: int = 300            # 或间隔多少秒触发（5分钟）

    # Security
    jwt_secret: str = ""
    allowed_origins: str = '["http://localhost:3001", "http://127.0.0.1:3001"]'
    rate_limit_per_minute: int = 120
    # 不可逆写动作(DLQ replay 等)独立配额,与 crit/std 分桶,默认远低于 120/min
    rate_limit_strict_per_minute: int = 10
    # HTTP 全局限流白名单的"追加项"(逗号分隔路径前缀, 见 http_guards.RATE_LIMIT_WHITELIST)
    # 默认白名单已覆盖全部业务域/运营只读端点; 此处只用于现场临时放开某个前缀, 无需改代码
    rate_limit_whitelist: str = ""
    admin_user: str = "admin"
    admin_password: str = ""
    # 公开自助注册默认关闭；演示/测试环境显式开启。
    allow_self_registration: bool = False

    # Response Engine Transport
    response_transport_mode: str = "auto"    # "stub" | "ssh" | "auto"
    response_ssh_host: str = ""              # Windows 宿主机 IP
    response_ssh_port: int = 22              # SSH 端口
    response_ssh_user: str = ""              # SSH 用户名
    response_ssh_key_file: str = ""          # SSH 私钥路径（容器内）
    response_ssh_key: str = ""               # SSH 私钥内容（直接填入，自动写入文件）
    # 主机密钥校验：默认失败关闭。known_hosts 必须存在；仅隔离靶场可显式放开。
    response_ssh_known_hosts: str = "/tmp/ssh/known_hosts"
    response_ssh_allow_unknown_host: bool = False

    # Kafka 消息总线
    kafka_bootstrap: str = "localhost:9092"
    kafka_topic_raw: str = "security-logs-raw"
    kafka_topic_validated: str = "security-logs-validated"
    kafka_topic_rejected: str = "security-logs-rejected"
    kafka_topic_enriched: str = "security-events-enriched"
    kafka_topic_alerts: str = "security-alerts"
    kafka_topic_audit_queue: str = "security-audit-queue"
    kafka_topic_audit_results: str = "security-audit-results"
    kafka_topic_cep_partial: str = "security-cep-partial"
    kafka_topic_cep_patterns: str = "security-cep-patterns"
    # Suricata EVE JSON topic (ids_connector 消费; 空串 = 用连接器缺省 "suricata-eve")
    suricata_eve_topic: str = ""
    kafka_topic_sigma_hit: str = "security-sigma-hit"   # pySigma 聚合候选 → Flink 阈值窗口
    kafka_topic_behavior_alerts: str = "security-behavior-alerts"  # L4 Flink 行为基线
    # Kafka 三解耦: HTTP 网关处理队列 (Python 权威检测的排队消费通道)
    kafka_topic_ingest_process: str = "security-events-ingest"
    # Python 从 ingest-process 队列消费做全量检测(启=权威); 置 false 可退回到旧 Flink enriched/alerts 驱动
    python_process_ingest_queue: bool = True
    # 旧 Flink enriched handler 不再补排 LLM 审计(Python 主导权威时关闭双 LLM 成本与双审计)
    kafka_flink_secondary_llm: bool = False
    # 审计溢出 topic：内存队列满且 Redis PQ 失败时，P0/P1 持久化到此，禁止静默丢弃
    kafka_topic_audit_overflow: str = "security-audit-overflow"
    kafka_consumer_group: str = "soc-backend"
    # DLQ 查询索引保留天数。到期删除索引行；原始负载在库里只有密文。
    # Kafka topic security-logs-dlq 的 broker 保留时间仍按部署配置，默认与这里一致。
    dlq_retention_days: int = 30
    kafka_enabled: bool = False              # True=Kafka 模式, False=兼容旧 HTTP 直连模式
    # ── Kafka 客户端安全（生产化: 内部链路 SASL_SSL; 默认 PLAINTEXT 保持演示兼容）──
    # 见 kafka_security.aiokafka_security_kwargs(); 所有 producer/consumer 构造点
    # 都必须展开 **aiokafka_security_kwargs(), 防止"一半加密一半明文"。
    kafka_security_protocol: str = "PLAINTEXT"   # PLAINTEXT | SASL_SSL
    kafka_sasl_mechanism: str = "SCRAM-SHA-512"
    kafka_sasl_username: str = ""                # 容器内默认 soc-app (compose 注入)
    kafka_sasl_password: str = ""
    kafka_ssl_ca_file: str = ""                  # 容器内 CA PEM 路径 (/etc/kafka/secrets/ca-cert.pem)
    kafka_ssl_check_hostname: bool = False       # bootstrap 用容器名, 证书带全 SAN 后可开
    # Confluent Schema Registry (跨运行时 Schema 契约, 见 schema_registry.py)
    schema_registry_url: str = "http://schema-registry:8081"
    # Flink JobManager REST (管道状态聚合, 见 routers/kafka.py)
    flink_jobmanager_url: str = "http://flink-jobmanager:8081"

    # ── OpenTelemetry (标准 trace 体系 → otel-collector → Tempo) ──
    otel_enabled: bool = True
    otel_endpoint: str = "http://otel-collector:4317"
    # Tempo 查询 API 地址(R20): 此前 3 处硬编码 http://tempo:3200, 换部署拓扑必改代码
    tempo_url: str = "http://tempo:3200"
    env_name: str = "dev"
    # 演示模式开关(R12, 复审 P1-8): 只有显式开启才挂载 /api/demo/seed|clear|status。
    # 修复前 demo 路由无条件挂载在生产路由上, operator 即可灌/清演示数据,
    # 且退出演示态只能靠人工记得跑 clear。
    demo_mode: bool = False
    # 日志格式: ""=按 env 自动(prod=json, 其余=text); 显式 "json"|"text" 覆盖
    log_format: str = ""
    # 启动时自动执行 alembic upgrade head（生产/容器部署建议开启;
    # 迁移失败将阻止启动 —— fail-closed, 不允许带未迁移的 schema 进流量）
    auto_migrate: bool = False

    # ── Temporal (4 层 Agent 编排: 可靠性/长任务/可视化) ──
    temporal_enabled: bool = False        # True=用 Temporal 编排, False=回退 async 兜底
    temporal_host: str = "temporal:7233"
    temporal_namespace: str = "default"
    temporal_task_queue: str = "audit-pipeline"
    # r6: 单 workflow 执行硬上限(秒); 超时由 Temporal 终止,避免永久 RUNNING
    temporal_workflow_execution_timeout_s: int = 900
    # Temporal llm_agent 在飞上限(只计 Agent 工作流, 不含 llm_single)
    audit_inflight_max: int = 4
    # 兼容旧名: Agent 工作流槽; 默认等于 audit_inflight_max
    audit_llm_agent_inflight_max: int = 4
    # start_workflow 墙钟超时, 防止 worker 卡在 Temporal 任务分发
    audit_temporal_start_timeout_s: float = 5.0
    # 运行中 stuck 收口阈值(分钟); analyzed=false 超过该时长 → fallback reap
    stuck_audit_reap_minutes: int = 5
    # LLM 通道分层: 软/硬预算水位(%); 硬水位下仍保留 P0 最小 LLM hop
    audit_soft_budget_pct: float = 70.0
    audit_hard_budget_pct: float = 95.0
    # P0 预留日预算比例(0-0.5); 软门禁不消耗该预留
    audit_p0_reserve_pct: float = 0.25
    # FastPath 强信号后是否降为复盘轻车道
    audit_fastpath_demote: bool = True
    # 优先级队列: inflight 满时 P0/P1 等待时长(秒); 分档 TTL 见下方
    audit_pq_ttl_s: int = 900
    audit_pq_ttl_p0_s: int = 3600
    audit_pq_ttl_p1_s: int = 1800
    audit_pq_ttl_p2_s: int = 300
    # PQ 拉取间隔(秒) / 每轮条数 — 入站 ~12 ev/s 时 5/s 会净堆积
    audit_pq_drain_interval_s: float = 0.2
    audit_pq_drain_batch: int = 20
    # Agent 槽满时跳过队头 P0, 继续抽 P1 llm_single, 避免 P1 dequeue=0
    audit_pq_skip_blocked_agent: bool = True
    # P1 默认不走 Temporal
    audit_p1_use_temporal: bool = False
    # 结论缓存 (同签名短期内复用)
    audit_cache_ttl_s: int = 600
    # 跨进程审计认领 TTL(秒): SET NX EX 抢占, 防多进程重复审计同一事件。
    # 应 ≥ 最长审计车道超时(audit_timeout_p0_s=90); 认领失败=他进程在审, 跳过。
    audit_claim_ttl_s: int = 120
    # 流量型事件(DDOS/PORT_SCAN)默认规则收口, 不进 LLM
    audit_volumetric_skip_llm: bool = True
    audit_llm_single_timeout_s: float = 15.0
    audit_max_rounds_agent: int = 1
    # 有界审计 worker(取代无界 create_task + 双 Semaphore)
    audit_workers: int = 12
    audit_queue_max: int = 2000
    # P0/P1 内存队列满时不返回 overflow：Redis PQ → Kafka overflow → 进程内 deque。
    # deque 和内存堆都是易失的。停机时把剩下的任务写入 Kafka 或 spill 日志；
    # 写不出去就计 volatile_lost，不能再叫绝不丢失。
    audit_p0_never_drop: bool = True
    audit_p1_never_drop: bool = True
    shutdown_drain_timeout_s: float = 20.0
    audit_spill_path: str = ""
    audit_recovery_limit: int = 2000
    # ── Ingest 事件驱动 Phase 1（同进程分层，不拆微服务）──
    ingest_http_queued_status: int = 202          # Kafka 入队成功返回码；同步回退仍 200
    ingest_parallel_detect: bool = True           # anomaly + sigma 并行；失败隔离
    ingest_store_batch_size: int = 50             # Kafka 消费批落库条数
    ingest_store_batch_flush_ms: int = 100        # 未满批也按墙钟 flush
    ingest_fastpath_retries: int = 2              # FastPath on_threat_detected 失败重试次数
    audit_timeout_p0_s: float = 90.0
    audit_timeout_p1_s: float = 45.0
    audit_timeout_p2_s: float = 20.0
    audit_timeout_p3_s: float = 10.0
    audit_max_rounds_deep: int = 2
    audit_max_rounds_standard: int = 1
    # DB 双池: OLTP 短租(ingest/API/audit SQL); BG 给索引/调度
    db_pool_oltp_size: int = 24
    db_pool_oltp_overflow: int = 8
    db_pool_oltp_timeout_s: float = 5.0
    db_pool_bg_size: int = 8
    db_pool_bg_overflow: int = 4
    db_pool_bg_timeout_s: float = 10.0
    # 全平台 LLM HTTP 并发(Audit + enhancer + RAG); 每进程
    llm_global_concurrency: int = 8
    llm_p0_reserve: int = 2
    llm_slot_timeout_s: float = 30.0
    llm_429_retry_s: float = 1.0
    # 单次 LLM HTTP 超时。每分钟请求上限，0 表示不再叠加速率闸（并发闸仍然生效）。
    llm_request_timeout_s: float = 90.0
    # P2-E-3: 连接超时单独可配。修复前用 httpx.Timeout(单值) 把
    # connect/read/write/pool 全部设成 llm_request_timeout_s ——
    # 一个连不上的上游要等满 90 秒才失败，而不是 connect 设的 10 秒。
    llm_connect_timeout_s: float = 10.0
    # P2-E-2: 通用重试的指数退避基数与上限（全抖动）。
    # 修复前三次重试之间零等待直接重发。
    llm_retry_base_s: float = 0.5
    llm_retry_max_s: float = 8.0
    llm_rate_per_minute: int = 600
    # ── 资源容量。入口只读这一组，业务路径不要再写死另一套数字。──
    # HTTP：绝对上限是单次请求硬顶。max_batch 是单批处理上限。
    # batch_policy=chunk 时按 max_batch 切块；=reject 时超过 max_batch 直接 413。
    http_ingest_max_body_bytes: int = 1_048_576
    http_ingest_max_batch: int = 200
    http_ingest_absolute_max: int = 1000
    http_ingest_batch_policy: str = "chunk"
    http_ingest_batch_timeout_s: float = 30.0
    http_ingest_downstream_wait_s: float = 2.0
    http_overload_status: int = 503
    http_overload_retry_after_s: int = 2
    # 接入之后的后台任务（快速响应、案例聚合）同时最多这么多个。满了就跳过，不堆积。
    http_background_max: int = 8
    # 审计队列水位。高水位拒绝新的 HTTP 接入并暂停 Kafka 拉取；降到低水位后继续消化。
    audit_queue_high_watermark: float = 0.8
    audit_queue_low_watermark: float = 0.5
    # 单批检测扇出（HTTP 直连、Kafka python-ingest、手动分析共用这一闸）
    audit_batch_concurrency: int = 8
    # 数据库：连接池见 db_pool_*。这里是并发写上限，以及 PostgreSQL 语句超时。
    db_write_max_concurrency: int = 8
    db_write_timeout_s: float = 5.0
    db_query_timeout_s: float = 30.0
    # Kafka 生产：单批条数、进程内在途发送、单次发送超时。
    kafka_produce_batch_size: int = 100
    kafka_produce_max_inflight: int = 32
    kafka_produce_timeout_s: float = 10.0
    # P2-B-4: 工具执行并发上限 + 闸门准入等待。
    # 修复前 Executor 的 asyncio.gather 无 Semaphore：一批挂死的工具
    # 会让整轮审计永不返回（且 timeout_ms 是死字段，从未被读取）。
    tool_exec_max_concurrency: int = 8
    tool_exec_admit_timeout_s: float = 5.0
    # 单个工具执行超时（毫秒）。0 = 退回注册表里各工具自报的 timeout_ms。
    tool_exec_default_timeout_ms: int = 0
    # P3-6: 审计查询工具的参数上界。
    # 修复前 event_store.query 的 limit 原样透传给 event_store.query，
    # 而 event_ids 分支连 limit 都不看（直接 .scalars().all()）——
    # 这两个值都能经 missed_threats[].evidence 自由文本被放大到任意规模。
    # 取值依据：生产路径合法的 limit 最大是 200（Decomposer 硬编码 20/50/100/200），
    # 这里给 5 倍余量，既不打断现有审计，又把放大面截断。
    tool_query_max_limit: int = 1000
    # event_ids 的上界单独更小：它每一项都要进 SQL 的 IN 列表，代价随项数增长。
    tool_query_max_event_ids: int = 500
    # Kafka 消费。若进程里已经设置了不带前缀的旧环境变量，启动时仍优先用旧变量。
    kafka_consume_concurrency: int = 1
    kafka_max_poll_records: int = 50
    # 单次 poll 后允许的处理上限。过短会在慢审计时被踢出组，循环直接结束且以前不会拉起。
    kafka_max_poll_interval_ms: int = 600000
    kafka_consumer_restart_initial_s: float = 1.0
    kafka_consumer_restart_max_s: float = 30.0
    # 生产者与消费者重试能力对齐: 首启失败(broker 未就绪等)后由监督循环
    # 指数退避重试, 不再一次性永久失效(否则 ingest 静默降级 HTTP→PG)。
    kafka_producer_restart_initial_s: float = 1.0
    kafka_producer_restart_max_s: float = 30.0
    kafka_audit_store_concurrency: int = 12
    kafka_fetch_pause_s: float = 0.5
    # ── 背压复合信号（PERF-OPT-PLAN-2026-10-26 Wave 2-1/2-2）──
    # 准入闸门(admit_http)的信号从"只看审计内存队列"扩为
    # max(队列比, Kafka lag 比, PQ 深度比)；Kafka 拉取暂停仍只看审计内存队列
    # （停拉会加深 lag —— lag 信号只用于拒绝新进入，不用于停拉）。
    # kafka_consumption_eps: 实测稳态消费容量(events/s)。0=未标定 → lag 信号
    # 不启用（不许用拍脑袋阈值触发过载拒绝）。标定口径：PERF 压测排空段实测；
    # PERF-2(2026-10-30) 标定值 = **8 eps**（1675 规则、2CPU 容器、单 worker 稳态
    # 8.4-8.6 实测取整；2 worker 配对实测 2.08× 近线性）——该规模栈部署时设 8，
    # 换规则库规模/机器须重标。lag 阈值条数 = eps × 允许积压秒数。
    kafka_consumption_eps: int = 0
    kafka_lag_allowed_backlog_s: int = 60
    # P0/P1 LLM 溢出池(PQ)的深度容量：深度比 = zcard / 该值。
    audit_pq_capacity: int = 2000
    # ── H 路线接线开关（REMEDIATION-PLAN 2026-10-30 路线 H，2026-10-30 收口）──
    # 全部 fail-open：异常只降级为"无该增强"，不阻断主链路。
    # LLM 类默认关（成本护栏：内部走 llm_enhancer/llm_limiter）；本地计算类默认开。
    intel_llm_context_enabled: bool = False     # ①IOC 命中后 LLM 威胁上下文摘要
    edr_llm_correlation_enabled: bool = False   # ②跨源关联结果 LLM 叙事
    traffic_peer_group_enabled: bool = True     # ③同侪组基线(纯本地计算)
    zeroday_lane_enabled: bool = True           # ④沙箱行为解读进分诊 lane(同步分析器;
                                                #   LLM 解读另受 llm 成本护栏)
    learn_variant_cluster_enabled: bool = True  # ⑤恶意样本变体聚类进学习闭环(本地)
    # 消费侧重试：区分临时故障与永久错误。旧实现是 0.5s+1.0s=1.5s 总等待。
    kafka_retry_initial_s: float = 1.0
    kafka_retry_multiplier: float = 2.0
    kafka_retry_max_delay_s: float = 30.0
    kafka_retry_jitter: float = 0.2
    kafka_retry_budget_s: float = 60.0
    kafka_retry_max_attempts: int = 5
    # 延迟重试 Topic。ordering=strict（默认）不发 retry topic，避免同一业务键后续消息越过未完成记录。
    # ordering=unordered 才允许发往 retry topic 并提交原 offset。
    kafka_retry_topic_enabled: bool = False
    kafka_topic_retry: str = "security-logs-retry"
    kafka_retry_ordering: str = "strict"  # strict | unordered
    kafka_retry_topic_max_hops: int = 5
    kafka_retry_topic_delay_s: float = 15.0
    # EventStore 热缓存。TTL 是失效广播丢失后的陈旧上界，不能替代正确的失效。
    # 0 = 取 audit_timeout_p2_s（最短审计车道超时，流水线状态新鲜度要求）。
    event_store_hot_cache_ttl_s: float = 0
    event_store_hot_cache_max: int = 2000
    # EventBus SSE。queue_max 是可合并的状态队列；critical 满了不踢已入队事件。
    event_bus_max_subscribers: int = 256
    event_bus_queue_max: int = 500
    event_bus_critical_queue_max: int = 200

    # Sigma 检测引擎: pySigma=真 Sigma(pySigma+SQLite backend 读 rules/*.yml), legacy=原纯 dict 匹配
    sigma_engine: str = "pySigma"

    # 数据源认证（JSON: api_key → 源名）。
    # 2026-10-23 安全修复：删除源码内置的演示密钥默认值 —— 公开仓库里谁能读到
    # 谁就能伪装成合法日志源。现在默认空 = 不预置任何来源（fail-closed）；
    # 演示环境请显式设置（见 .env.example 的示例值），生产必须换成私有密钥。
    source_api_keys: str = ""
    # 本地情报 csv 导入的白名单目录(R14): 空 = 禁用本地导入(默认, 防任意文件读);
    # 配置后仅允许该目录内文件(如 /data/feeds)。HTTP 导入请用 csv_http。
    intel_local_feed_dir: str = ""

    # SSH 防火墙适配器 (Linux iptables)
    fw_ssh_host: str = ""
    fw_ssh_port: int = 22
    fw_ssh_user: str = ""
    fw_ssh_password: str = ""
    fw_use_sudo: bool = True
    # 主机密钥校验：默认失败关闭。known_hosts 必须存在；仅隔离靶场可显式放开。
    fw_ssh_known_hosts: str = "/tmp/ssh/known_hosts"
    fw_ssh_allow_unknown_host: bool = False

    # MCP Guard 网关
    mcp_guard_enabled: bool = True       # 启用 4 层 Guard 检查
    security_guard_enabled: bool = True  # 启用 SecurityGuard (意图/频率/序列)

    # ── Tool 行为签名 (UEBA-for-AI) ──
    # persist=写 PG；enabled=检测器；mode=confirm(enforce) 偏离需确认，deny=拒绝，shadow=只告警
    tool_call_log_persist: bool = True
    tool_signature_enabled: bool = True
    tool_signature_mode: str = "confirm"         # confirm|enforce | deny | shadow
    tool_signature_min_samples: int = 30
    tool_signature_warn_threshold: float = 0.6
    tool_signature_confirm_threshold: float = 0.8
    tool_signature_deny_threshold: float = 0.95
    tool_signature_log_retention_days: int = 180
    tool_signature_weights: str = "param:0.35,seq:0.25,time:0.15,caller:0.25"

    # ── 案例自动派单 ──
    # 命中这些 priority 的自动聚合案例 → 自动派生工单并推进到 responding (逗号分隔)
    case_auto_order_priorities: str = "high,critical"
    # 自动工单默认指派人（空则保持 pending 无负责人）
    case_default_assignee: str = "admin"

    # resolved 案例停留超过该小时数仍未人工 closed → scheduler 自动 closed (0=不自动关闭)
    case_auto_close_hours: int = 24
    # 自动响应成功后，案例空闲超过该分钟 → 完成工单并 resolved（0=立即收口，负值=关闭此功能）
    case_auto_resolve_idle_minutes: int = 10

    # stuck 事件自动清理阈值（分钟）；0=启动时不自动清理
    stuck_auto_reset_minutes: int = 30

    # ── 安全执行层 (SafeExecutor) ──
    # 默认 dry_run：真实执行必须由部署环境显式开启（最小惊讶 + 失败关闭）。
    execution_mode: str = "dry_run"          # dry_run | mock | live
    # fail-closed(2026-10-23): live 模式下幂等检查不可用(Redis 挂) → 拒绝执行。
    # 执行侧幂等是纯 Redis(§9.52), Redis 失效时放行=重复封禁无防护。
    # 仅隔离靶场且接受该风险时才可显式关闭。
    require_idempotency_for_live: bool = True
    protected_assets: str = ""               # 受保护 IP/CIDR（逗号分隔）
    protected_assets_labels: str = ""        # 对应标签（逗号分隔）
    fw_ssh_user_readonly: str = ""           # 只读 SSH 账号（nmap/查询用）
    ttl_scan_interval: int = 30             # TTL 过期扫描间隔（秒）

    # ── 控制面安全（审批 HMAC / JWT 吊销 / 来源限制）──
    # 2026-10-23：prod 环境不再允许回退 jwt_secret（见 security_crypto.control_hmac_key）
    # —— 审批签名与 JWT 必须使用不同密钥，泄露时不至于一起失守。
    control_hmac_key: str = ""               # prod 必填；dev/test 空则回退 jwt_secret
    approval_ttl_minutes: int = 15
    approval_ttl_critical_minutes: int = 10
    api_allowlist: str = ""                  # 逗号分隔 IP/CIDR，空=不启用
    api_allowlist_allow_loopback: bool = True
    trust_proxy: bool = False
    service_token: str = ""                  # X-SOC-Service-Token；空=不启用
    mtls_enforce: bool = False               # 要求 X-SSL-Client-Verify=SUCCESS

    # ── 终端遏制 (containment) ──
    dns_sinkhole_ipv4: str = "127.0.0.2"
    dns_sinkhole_ipv6: str = "::ffff:127.0.0.2"
    ldap_url: str = ""
    ldap_bind_dn: str = ""
    ldap_bind_password: str = ""
    ldap_base_dn: str = ""
    graph_tenant: str = ""
    graph_client_id: str = ""
    graph_client_secret: str = ""
    forensic_snapshot_timeout_s: int = 15
    forensic_include_dump: bool = False
    forensic_dump_max_mb: int = 64
    kill_process_max_matches: int = 20

    # ── NDR 流量采集 ──
    capture_enabled: bool = False            # 启用网络流量采集
    capture_interface: str = "eth0"          # 抓包网卡
    capture_bpf_filter: str = ""             # BPF 过滤表达式（空=全量）
    capture_method: str = "libpcap"          # libpcap | dpdk | af_packet
    capture_snap_len: int = 262144           # 每包最大捕获字节
    pcap_storage_path: str = "/data/pcap"    # PCAP 文件存储目录
    pcap_rotation_mb: int = 100              # 单文件上限 (MB)
    pcap_rotation_sec: int = 3600            # 单文件最长时长 (秒)
    pcap_retention_days: int = 7             # 热存储保留天数
    flow_idle_timeout: int = 300             # 流空闲超时 (秒)
    flow_active_timeout: int = 3600          # 流最大存活 (秒)
    sensor_id: str = "sensor-01"             # 探针标识

    # ── 加密流量识别 ──
    ja3_db_path: str = ""                    # JA3 已知指纹库路径（CSV）
    mitm_enabled: bool = False               # 启用 TLS 解密代理
    mitm_listen_port: int = 8443             # 解密代理监听端口
    mitm_ca_cert: str = ""                   # CA 证书路径
    mitm_ca_key: str = ""                    # CA 私钥路径
    tls_risk_self_signed: float = 0.8        # 自签名证书风险权重
    tls_risk_expired: float = 0.6            # 过期证书风险权重
    tls_risk_unknown_ja3: float = 0.4        # 未知 JA3 指纹风险权重

    # ── EDR 融合 ──
    edr_enabled: bool = False                # 启用 EDR 数据接入
    sysmon_kafka_topic: str = "edr-sysmon"   # Sysmon 日志 Kafka Topic
    winevent_kafka_topic: str = "edr-winevent"  # Windows Event Log Topic
    edr_correlation_window: int = 300        # 跨源关联时间窗口 (秒)

    # ── IDS 接入 (Suricata EVE) ──
    # 2026-10-27 路线 2: 连接器接线(需 kafka_enabled 同开); 回放评测
    # 不经 Kafka, 直接读 eve.json(见 eval_datasets/replay_pcap_suricata.py)。
    suricata_enabled: bool = False

    # ── 威胁情报 ──
    intel_enabled: bool = False              # 启用威胁情报拉取
    intel_poll_interval: int = 60            # 默认拉取间隔 (分钟)
    misp_url: str = ""                       # MISP 实例地址
    misp_api_key: str = ""                   # MISP API Key
    misp_verify_ssl: bool = True
    taxii_url: str = ""                      # TAXII 服务器地址
    taxii_user: str = ""
    taxii_password: str = ""
    ioc_match_threshold: float = 0.8         # IOC 匹配置信度阈值
    # 情报富化(2026-10-27): 与 intel_enabled(拉取)解耦 —— 富化只读 IOC 缓存,
    # 默认关闭保证接入主链路行为与富化上线前完全一致(fail-open, 只计数不阻塞)。
    intel_enrich_enabled: bool = False
    intel_enrich_timeout_ms: int = 800       # 单事件富化超时, 超时放行原事件

    # ── 沙箱检测 ──
    sandbox_enabled: bool = False            # 启用沙箱联动
    sandbox_type: str = "cape"               # cape | cuckoo
    sandbox_api_url: str = "http://localhost:8090"  # CAPE/Cuckoo API
    sandbox_api_key: str = ""
    sandbox_timeout: int = 300               # 分析超时 (秒)
    sandbox_auto_submit: bool = False        # 高危告警自动提交样本
    sandbox_auto_threshold: float = 0.8      # 自动提交置信度阈值

    # ── NDR Kafka Topics ──
    kafka_topic_flows: str = "ndr-flows"
    kafka_topic_tls: str = "ndr-tls-sessions"
    kafka_topic_pcap_meta: str = "ndr-pcap-meta"

    # ── LLM 增强器 (P0.S 引入) ──
    # 三大模块各自开关;默认 false 保留纯规则路径,任何时候关闭即降级
    llm_traffic_enabled: bool = False              # 流量大模型
    llm_phishing_enabled: bool = False             # 钓鱼大模型
    llm_data_security_enabled: bool = False        # 数据安全大模型
    # NDR 扩展模块 LLM 开关
    llm_encrypted_traffic_enabled: bool = False    # 加密流量 LLM 语义判定
    llm_edr_enabled: bool = False                  # EDR 跨源关联 LLM 叙事
    llm_intel_enabled: bool = False                # 威胁情报 LLM 上下文摘要
    llm_sandbox_enabled: bool = False              # 沙箱行为 LLM 解读
    # 模块日预算 (¥/天).任一模块超限 → 该模块降级,不挤占其它模块
    llm_traffic_budget_jpy_per_day: int = 5
    llm_phishing_budget_jpy_per_day: int = 75
    llm_data_security_budget_jpy_per_day: int = 5
    llm_encrypted_traffic_budget_jpy_per_day: int = 5
    llm_edr_budget_jpy_per_day: int = 5
    llm_intel_budget_jpy_per_day: int = 3
    llm_sandbox_budget_jpy_per_day: int = 5
    # 全局 LLM 增强器并发上限 — 已并入 llm_global_concurrency; 保留作 alias
    llm_enhancer_concurrency: int = 8
    # LLM 增强器单次超时 (秒)
    llm_enhancer_timeout_sec: int = 15

    # ── Red vs Blue Self-Play ──
    self_play_enabled: bool = True
    self_play_default_rounds: int = 8
    self_play_inject: bool = False          # True=把仿真事件送进生产 ingest(打上 _self_play)
    self_play_use_llm: bool = False         # False=课程目录规划,不烧 LLM
    self_play_wait_audit: bool = False      # True=等待 Audit-LLM 结论(演示/论文 full 模式)
    self_play_wait_audit_s: float = 8.0
    self_play_decoy_ratio: float = 0.2
    self_play_max_inflight: int = 1
    self_play_rag_top_k: int = 8
    self_play_llm_timeout_s: float = 20.0
    self_play_review_enabled: bool = True
    self_play_review_fp_max: float = 0.05
    self_play_review_llm: bool = True
    self_play_review_replay: bool = True
    self_play_shadow_hours: float = 24.0
    self_play_review_interval_s: int = 900
    self_play_review_batch: int = 20
    self_play_diverse_env: bool = False     # True=随机拓扑,默认仍 10 主机固定
    self_play_background_traffic: bool = False

    # ── 因果攻击链 (PC / GES, 批式, 不进 Flink 热路径) ──
    causal_enabled: bool = True
    causal_bin_minutes: int = 30
    causal_alpha: float = 0.05
    causal_min_windows: int = 40
    causal_learn_interval_s: int = 900
    causal_lookback_hours: int = 48

    # ── 每日学习闭环 (learn_loop: 收割→统计/聚类/序列→提议→自动应用) ──
    learn_loop_enabled: bool = True
    learn_loop_hourly_enabled: bool = False      # True=每小时走 run_cycle(hourly); False=保持原 generate_tuning_suggestions
    learn_loop_hour_utc: int = 2                 # 每日 UTC 触发钟点
    learn_loop_minute: int = 15                  # 每日 UTC 触发分钟
    learn_loop_lookback_hours: int = 24          # 收割窗口回溯小时
    learn_loop_auto_apply: bool = True           # 白名单动作自动应用
    learn_loop_cluster_min_size: int = 3         # 聚类最小簇大小
    learn_loop_jaccard: float = 0.5              # 事件聚类 Jaccard 阈值
    learn_loop_markov_min_count: int = 5         # 序列转移最小计数
    learn_loop_markov_min_p: float = 0.4         # 序列转移最小条件概率
    learn_loop_prior_clip: float = 0.2           # 信誉先验单侧 clip（±0.2）
    learn_loop_harvest_cases_limit: int = 500    # 收割案例上限
    learn_loop_harvest_events_limit: int = 5000  # 收割事件扫描上限

    # ── 演示流量（默认关；仅仿真事件打 _demo，不写生产 Sigma）──
    demo_traffic_enabled: bool = False
    demo_traffic_interval_s: int = 300

    # ── 大屏实况面板 (A1/A2/A3: agent 实况 / 攻击地图 / 零丢失账本) ──
    # 广播走 SSE (ledger / attack_geo 频道), bulk 车道按 key 合并只留最新帧。
    ledger_interval_s: float = 3.0               # 零丢失账本广播间隔(秒)
    attack_geo_interval_s: float = 5.0           # 攻击态势广播间隔(秒)
    attack_geo_window: int = 400                 # 态势回看的事件窗口(条, id 倒序)
    attack_geo_max_points: int = 24              # 态势图攻击点上限
    home_lat: float = 27.95                      # 受击方纬度 (默认湖南科技大学)
    home_lon: float = 112.93                     # 受击方经度
    home_label: str = "湖南科技大学"              # 受击方名称(态势图中心标签)

    # ── LLM 成本控制 (P0.T 引入; 2026-10-23 第二阶段默认对齐) ──
    # 默认给真实上限: 5M tokens/天(演示/中小流量远用不完; 超限走分级降级,
    # P0 有 audit_p0_reserve_pct 预留不会被饿死)。生产可按量调整或显式关闭。
    # 此前默认 0+unlimited=True = 成本完全无界, 预算体系(soft/hard pct)是死配置。
    llm_daily_budget_tokens: int = 5_000_000
    # False=预算硬门禁(超限低优车道降级, P0 保留); True=只记账不关(回退到无上限)
    llm_budget_unlimited: bool = False
    llm_price_input_per_1k_tokens: float = 0.0            # 输入每千 token 单价(¥), 0=不估算费用
    llm_price_output_per_1k_tokens: float = 0.0           # 输出每千 token 单价(¥), 0=不估算费用

    class Config:
        # 2026-10-20（§9.48）：见文件头 _SKIP_DOTENV 的说明。
        # 开关打开 ⇒ 不读任何 .env（此前只挡了 os.environ 注入那条通道，
        # pydantic 自己的 dotenv 源是**另一条**通道，会绕过开关）。
        env_file = None if _SKIP_DOTENV else ".env"
        env_prefix = "SHARED_MEMORY_"


def _load_project_root_env() -> None:
    """从项目根目录加载 .env 并注入 os.environ，兼容乱码注释/非 UTF-8 行。

    背景：pydantic-settings 的 env_file='.env' 只从运行 CWD 查找，且 python-dotenv
    在 .env 含非 UTF-8(GBK)中文注释时整文件解析失败。此函数逐行按 ASCII 安全解析
    只提取 KEY=VALUE，跳过注释/乱码行，兼容「本机以 backend/ 为 CWD」。
    已存在环境变量(如 docker 注入)不覆盖。

    2026-10-03 安全修复：新增 SHARED_MEMORY_SKIP_DOTENV 开关。
      本函数在 **import 期**改写进程 os.environ —— 这意味着测试进程会加载开发者
      机器上的真实 .env。实测后果：.env 里的 RESPONSE_POLICIES_DIR 指向 Linux
      容器路径(/data/response_policies)，在 Windows 上不存在 → 全局 policy_engine
      指向空目录 → 全量测试 15 个失败中的 10 个。
      同一路径还会泄漏 FW_SSH_PASSWORD / QDRANT_URL / FIELD_ENCRYPTION_KEY 等，
      使"无凭据时应当降级"的测试在配了真实凭据的机器上反而去连真实服务。

      因此测试必须显式设 SHARED_MEMORY_SKIP_DOTENV=1（见 tests/conftest.py，
      须早于任何 config/models 的 import）。
    """
    import re
    if _SKIP_DOTENV:
        return
    for cand in (Path(__file__).resolve().parent.parent / ".env", Path.cwd() / ".env"):
        if not cand.exists():
            continue
        try:
            raw = cand.read_bytes().splitlines()
        except Exception:
            continue
        for ln in raw:
            if not all(b < 128 for b in ln):    # 跳过含非 ASCII(中文注释/乱码)行
                continue
            line = ln.decode("latin-1").strip()
            if not line or line.startswith("#"):
                continue
            m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$", line)
            if m:
                k, v = m.group(1), m.group(2).strip().strip('"').strip("'")
                if k not in os.environ:
                    os.environ[k] = v


_load_project_root_env()
settings = Settings()
