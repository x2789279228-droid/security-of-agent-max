from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Text, DateTime, Date, JSON, Boolean, Float, ForeignKey, UniqueConstraint
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncAttrs
from sqlalchemy.ext.mutable import MutableDict, MutableList
from sqlalchemy.orm import DeclarativeBase
from pgvector.sqlalchemy import Vector

from config import settings

# JSON 列用 MutableDict 包装，确保嵌套修改（raw_data["key"]=v）能被 SQLAlchemy 追踪
MutableJSON = MutableDict.as_mutable(JSON)
# list 类型的 JSON 列用 MutableList 包装（services/tags/iocs 等数组字段）
MutableListJSON = MutableList.as_mutable(JSON)

def _make_engine(pool_size: int, max_overflow: int, pool_timeout: float):
    """SQLite(测试)不传 PG 池参数; 生产 PG 才启用 QueuePool。"""
    url = settings.database_url
    kw = {"echo": False}
    if not str(url or "").startswith("sqlite"):
        kw.update(
            pool_size=int(pool_size),
            max_overflow=int(max_overflow),
            pool_timeout=float(pool_timeout),
            pool_pre_ping=True,
            pool_recycle=1800,
        )
    if str(url or "").startswith("postgresql"):
        query_timeout = float(getattr(settings, "db_query_timeout_s", 30) or 30)
        kw["connect_args"] = {"command_timeout": query_timeout}
    return create_async_engine(url, **kw)


# OLTP: ingest / API / audit 短租 SQL。LLM 等待期间不得占用这些连接。
engine_oltp = _make_engine(
    getattr(settings, "db_pool_oltp_size", 24),
    getattr(settings, "db_pool_oltp_overflow", 8),
    getattr(settings, "db_pool_oltp_timeout_s", 5.0),
)
# 后台索引/调度独立池,避免 memory_tree 把 ingest 饿死。
# sqlite :memory: 必须共用同一 engine,否则是两套空库。
if str(settings.database_url or "").startswith("sqlite"):
    engine_bg = engine_oltp
else:
    engine_bg = _make_engine(
        getattr(settings, "db_pool_bg_size", 8),
        getattr(settings, "db_pool_bg_overflow", 4),
        getattr(settings, "db_pool_bg_timeout_s", 10.0),
    )
engine = engine_oltp  # 兼容旧 import
async_session = async_sessionmaker(engine_oltp, expire_on_commit=False)
async_session_bg = async_sessionmaker(engine_bg, expire_on_commit=False)

class Base(AsyncAttrs, DeclarativeBase):
    pass

class Memory(Base):
    __tablename__ = "memories"

    id = Column(Integer, primary_key=True, autoincrement=True)
    agent_id = Column(String(50), nullable=False, default="shared")
    content = Column(Text, nullable=False)
    embedding = Column(Vector(None))
    metadata_ = Column("metadata", JSON, default=dict)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    # PR2 写时门
    source_type = Column(String(30), default="agent_output")  # event|kb|operator|agent_output
    provenance_id = Column(String(100), default="")
    content_hash = Column(String(64), default="")
    trust = Column(Float, default=0.2)
    signed = Column(Boolean, default=False)

class Conversation(Base):
    __tablename__ = "conversations"

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(String(100), nullable=False)
    agent_id = Column(String(50), nullable=False)
    role = Column(String(20), nullable=False)
    content = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    # 上游唯一事件 ID (Flink/UUID) — 唯一索引实现幂等, 替换原 Redis 24h 去重
    # (跨运行时重放/Exactly-Once 兜底: 同一 eventId 只落库一次)
    event_id = Column(String(64), nullable=True, unique=True, index=True)
    correlation_id = Column(String(128), nullable=True, index=True)
    parent_event_id = Column(String(64), nullable=True, index=True)
    trace_id = Column(String(128), nullable=True)
    session_id = Column(String(100), nullable=False, index=True)
    event_type = Column(String(50), nullable=False)
    severity = Column(String(20), nullable=False, index=True)
    src_ip = Column(String(45))
    dst_ip = Column(String(45))
    protocol = Column(String(20))
    action = Column(String(20))
    message = Column(Text)
    raw_data = Column(MutableJSON, default=dict)
    # P0 修复：将异常分数从 raw_data JSON 中提升为独立列 + 索引，
    # 让 event_store.get_unreviewed_anomalies 能在 SQL 层直接过滤，
    # 避免"近 50 条未审核事件均低分 → AgentD 漏报"的隐患（见 issue B4/C2）。
    anomaly_score = Column(Float, default=0.0, index=True)
    analyzed = Column(Boolean, default=False, index=True)
    status = Column(String(30), default="new", index=True)  # new|acknowledged|investigating|resolved|closed|false_positive
    case_id = Column(Integer, ForeignKey("security_cases.id"), nullable=True, index=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

class MemoryTreeNode(Base):
    """记忆树节点 — 安全审计版：纯关联索引，不做内容压缩"""
    __tablename__ = "memory_tree_nodes"

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(String(100), nullable=False, index=True)
    parent_id = Column(Integer, ForeignKey("memory_tree_nodes.id"), nullable=True, index=True)
    depth = Column(Integer, default=0)
    node_type = Column(String(20), default="leaf")  # "leaf" | "summary"(分组)
    content = Column(Text, nullable=True)            # 原始内容（永远保留）
    summary = Column(Text, nullable=True)            # 分组标签（非压缩摘要）
    importance = Column(Float, default=1.0)          # 所有节点同等重要=1.0
    compression_route = Column(String(20), default="independent")  # 关联分组ID
    token_count = Column(Integer, default=0)
    metadata_ = Column("metadata", JSON, default=dict)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

class KnowledgeDoc(Base):
    """知识库文档"""
    __tablename__ = "knowledge_docs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    title = Column(String(200), nullable=False)
    content = Column(Text, nullable=False)
    source = Column(String(50), default="internal")
    threat_types = Column(JSON, default=list)
    severity = Column(String(20), default="medium")
    tags = Column(JSON, default=list)
    metadata_ = Column("metadata", JSON, default=dict)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    # PR2 RAG 投毒门
    content_hash = Column(String(64), default="")
    approval_status = Column(String(20), default="pending")  # pending|approved|rejected|signed_import
    submitted_by = Column(String(80), default="")
    approved_by = Column(String(80), default="")
    published_at = Column(DateTime(timezone=True), nullable=True)
    valid_until = Column(DateTime(timezone=True), nullable=True)
    cutoff_policy = Column(String(20), default="strict")


class KnowledgeChunk(Base):
    """知识库分块（含向量）"""
    __tablename__ = "knowledge_chunks"

    id = Column(Integer, primary_key=True, autoincrement=True)
    doc_id = Column(Integer, ForeignKey("knowledge_docs.id"), nullable=False, index=True)
    chunk_id = Column(String(100), unique=True, index=True)
    content = Column(Text, nullable=False)
    title = Column(String(200), default="")
    source = Column(String(50), default="")
    threat_types = Column(JSON, default=list)
    severity = Column(String(20), default="medium")
    tags = Column(JSON, default=list)
    embedding = Column(Vector(None))
    token_count = Column(Integer, default=0)
    search_lex = Column(Text, default="")    # IOC/CJK 预切词，供 tsvector / 词法召回
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class ResponseLog(Base):
    """响应日志 — 全量审计记录"""
    __tablename__ = "response_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(String(100), default="", index=True)
    event_id = Column(Integer, default=0, index=True)
    threat_type = Column(String(50), default="", index=True)
    threat_confidence = Column(Float, default=0.0)
    threat_severity = Column(String(20), default="info")
    src_ip = Column(String(45), default="", index=True)
    policy_name = Column(String(100), default="")
    action_name = Column(String(50), default="", index=True)
    action_params = Column(MutableJSON, default=dict)
    action_success = Column(Boolean, default=False)
    action_result = Column(MutableJSON, default=dict)
    rollback_token = Column(String(100), default="")
    auto_execute = Column(Boolean, default=False)
    approval_id = Column(String(100), default="")
    approval_status = Column(String(20), default="")
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class ContainmentRecord(Base):
    """遏制动作持久化 — 隔离/封禁/隔离区/sinkhole/账户禁用，供回滚与双栈对账。"""
    __tablename__ = "containment_records"

    id = Column(Integer, primary_key=True, autoincrement=True)
    action_name = Column(String(50), default="", index=True)
    target_type = Column(String(30), default="")          # ip | host | file | account | domain | message
    target_id = Column(String(500), default="", index=True)
    host_ip = Column(String(45), default="", index=True)
    families = Column(MutableListJSON, default=list)      # ["ipv4","ipv6"]
    rule_ids = Column(MutableListJSON, default=list)
    backend = Column(String(30), default="")              # firewall | host_ssh | ldap | graph | dns
    status = Column(String(20), default="applied", index=True)  # applied|partial|failed|rolled_back|unconfigured
    snapshot_id = Column(String(100), default="")
    payload = Column(MutableJSON, default=dict)
    rollback_token = Column(String(100), default="", index=True)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)


class AgentTrace(Base):
    """Agent 轨迹 — LLM 调用留痕（审计流水线各环节）"""
    __tablename__ = "llm_traces"

    id = Column(Integer, primary_key=True, autoincrement=True)
    caller = Column(String(50), default="unknown", index=True)      # audit_pipeline | evidence_verifier | ...
    operation = Column(String(50), default="chat", index=True)      # decompose | execute | review | verify | ...
    model = Column(String(100), default="")
    event_id = Column(Integer, default=0, index=True)
    session_id = Column(String(100), default="", index=True)
    trace_id = Column(String(32), default="", index=True)  # W3C 32 hex, 对齐 Tempo / thought steps
    prompt_tokens = Column(Integer, default=0)
    completion_tokens = Column(Integer, default=0)
    total_tokens = Column(Integer, default=0)
    latency_ms = Column(Float, default=0.0)
    cache_hit = Column(Boolean, default=False)
    status = Column(String(20), default="success", index=True)      # success | degraded | error
    error_type = Column(String(50), default="")
    retry_count = Column(Integer, default=0)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)


class PipelineSpan(Base):
    """流水线阶段 Span — 全链路追踪"""
    __tablename__ = "pipeline_spans"

    id = Column(Integer, primary_key=True, autoincrement=True)
    span_id = Column(String(20), default="", index=True)
    event_id = Column(Integer, default=0, index=True)
    session_id = Column(String(100), default="", index=True)
    # W3C trace-id (32 hex) — 关联标准 OTel/Tempo trace 树
    trace_id = Column(String(32), default="", index=True)
    stage = Column(String(30), default="", index=True)       # ingest | decomposer | executor | ...
    status = Column(String(20), default="running", index=True)  # running | success | error | timeout
    start_time = Column(Float, default=0.0)
    end_time = Column(Float, default=0.0)
    latency_ms = Column(Float, default=0.0)
    error = Column(Text, default="")
    metadata_ = Column("metadata", MutableJSON, default=dict)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)


class DiagnosticReport(Base):
    """看门狗诊断报告 — 全链路自动诊断结果"""
    __tablename__ = "diagnostic_reports"

    id = Column(Integer, primary_key=True, autoincrement=True)
    trigger_reason = Column(String(200), default="")
    trigger_stage = Column(String(50), default="", index=True)
    severity = Column(String(20), default="medium", index=True)  # critical | high | medium | low
    stage_metrics = Column(MutableJSON, default=dict)
    root_cause = Column(Text, default="")
    recommendations = Column(MutableJSON, default=list)
    llm_analysis = Column(Text, default="")
    affected_event_count = Column(Integer, default=0)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)


class EvalRun(Base):
    """质量评估运行 — 一次检索/忠实度评估"""
    __tablename__ = "eval_runs"

    id = Column(String(64), primary_key=True)
    run_type = Column(String(50), nullable=False, index=True)       # rag | faithfulness
    subject_id = Column(String(100), default="", index=True)
    evaluator = Column(String(50), default="heuristic")
    status = Column(String(20), default="completed")
    prompt_version = Column(String(50), default="")
    retrieval_strategy = Column(String(50), default="")
    query = Column(Text, default="")
    answer = Column(Text, default="")
    ground_truth = Column(Text, default="")
    contexts = Column(JSON, default=list)
    input_payload = Column(JSON, default=dict)
    output_payload = Column(JSON, default=dict)
    error = Column(Text, default="")
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)


class PhishingRecord(Base):
    """钓鱼检测记录"""
    __tablename__ = "phishing_records"

    id = Column(Integer, primary_key=True, autoincrement=True)
    detection_type = Column(String(20), nullable=False, index=True)  # email / web / domain
    target = Column(String(500), default="")
    risk_level = Column(String(20), default="safe", index=True)      # safe / suspicious / phishing
    confidence = Column(Float, default=0.0)
    score = Column(Float, default=0.0)
    indicators = Column(JSON, default=list)
    summary = Column(Text, default="")
    suggested_actions = Column(JSON, default=list)
    raw_input = Column(MutableJSON, default=dict)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)


class PhishingDrill(Base):
    """钓鱼演练活动"""
    __tablename__ = "phishing_drills"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(200), nullable=False)
    drill_type = Column(String(20), default="email")                 # email / sms
    template_subject = Column(String(500), default="")
    template_body = Column(Text, default="")
    target_count = Column(Integer, default=0)
    status = Column(String(20), default="draft", index=True)         # draft / running / completed
    sent_count = Column(Integer, default=0)
    opened_count = Column(Integer, default=0)
    clicked_count = Column(Integer, default=0)
    reported_count = Column(Integer, default=0)
    start_time = Column(DateTime(timezone=True), nullable=True)
    end_time = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)


class PhishingDrillRecord(Base):
    """钓鱼演练目标记录"""
    __tablename__ = "phishing_drill_records"

    id = Column(Integer, primary_key=True, autoincrement=True)
    drill_id = Column(Integer, ForeignKey("phishing_drills.id"), nullable=False, index=True)
    target_identifier = Column(String(200), default="")              # 邮箱 / 手机号
    sent_at = Column(DateTime(timezone=True), nullable=True)
    opened_at = Column(DateTime(timezone=True), nullable=True)
    clicked_at = Column(DateTime(timezone=True), nullable=True)
    reported_at = Column(DateTime(timezone=True), nullable=True)
    verdict = Column(String(20), default="pending", index=True)      # pending / sent / opened / clicked / reported
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class EvalScore(Base):
    """质量评估指标得分"""
    __tablename__ = "eval_scores"

    id = Column(Integer, primary_key=True, autoincrement=True)
    run_id = Column(String(64), ForeignKey("eval_runs.id"), index=True)
    metric = Column(String(50), nullable=False)
    score = Column(Float, default=0.0)
    threshold = Column(Float, default=0.5)
    passed = Column(Boolean, default=False)
    reason = Column(Text, default="")
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


# ════════════════════════════════════════════
# 事件运营闭环模型
# ════════════════════════════════════════════

class SecurityCase(Base):
    """安全案例 — 多条告警事件的聚合容器"""
    __tablename__ = "security_cases"

    id = Column(Integer, primary_key=True, autoincrement=True)
    case_number = Column(String(30), unique=True, index=True)   # CASE-20260801-001
    title = Column(String(300), default="")
    status = Column(String(30), default="open", index=True)
    # open → investigating → pending_approval → responding → resolved → closed
    priority = Column(String(20), default="medium", index=True)  # critical|high|medium|low
    threat_type = Column(String(50), default="")
    severity = Column(String(20), default="medium")
    confidence = Column(Float, default=0.0)
    src_ips = Column(MutableListJSON, default=list)
    dst_ips = Column(MutableListJSON, default=list)
    event_ids = Column(MutableListJSON, default=list)
    event_count = Column(Integer, default=0)
    assignee = Column(String(100), default="")
    sla_deadline = Column(DateTime(timezone=True), nullable=True)
    disposition = Column(Text, default="")              # 最终处置结论
    disposition_by = Column(String(100), default="")
    disposition_at = Column(DateTime(timezone=True), nullable=True)
    tags = Column(MutableListJSON, default=list)
    metadata_ = Column("metadata", MutableJSON, default=dict)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    closed_at = Column(DateTime(timezone=True), nullable=True)
    sla_breached = Column(Boolean, default=False, server_default="false", index=True)


class WorkOrder(Base):
    """工单 — 持久化任务跟踪（处置/审批/复盘/回滚）"""
    __tablename__ = "work_orders"

    id = Column(Integer, primary_key=True, autoincrement=True)
    order_number = Column(String(30), unique=True, index=True)  # WO-20260801-001
    case_id = Column(Integer, ForeignKey("security_cases.id"), nullable=True, index=True)
    order_type = Column(String(30), default="disposition", index=True)
    # disposition | approval | review | rollback
    title = Column(String(300), default="")
    description = Column(Text, default="")
    status = Column(String(30), default="pending", index=True)
    # pending → assigned → in_progress → completed → cancelled
    priority = Column(String(20), default="medium")
    assignee = Column(String(100), default="")
    created_by = Column(String(100), default="system")
    approval_status = Column(String(20), default="")    # pending|approved|rejected（审批类工单）
    approved_by = Column(String(100), default="")
    approved_at = Column(DateTime(timezone=True), nullable=True)
    reject_reason = Column(Text, default="")
    sla_deadline = Column(DateTime(timezone=True), nullable=True)
    sla_breached = Column(Boolean, default=False)
    result = Column(MutableJSON, default=dict)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    completed_at = Column(DateTime(timezone=True), nullable=True)


class PostMortem(Base):
    """复盘报告 — 案例关闭后的结构化复盘"""
    __tablename__ = "post_mortems"

    id = Column(Integer, primary_key=True, autoincrement=True)
    case_id = Column(Integer, ForeignKey("security_cases.id"), unique=True, index=True)
    title = Column(String(300), default="")
    summary = Column(Text, default="")
    timeline = Column(MutableListJSON, default=list)     # [{time, event, detail}]
    root_cause = Column(Text, default="")
    impact_assessment = Column(Text, default="")
    lessons_learned = Column(MutableListJSON, default=list)
    action_items = Column(MutableListJSON, default=list)  # [{item, owner, deadline, done}]
    false_positive_count = Column(Integer, default=0)
    detection_gaps = Column(Text, default="")
    rule_improvements = Column(MutableListJSON, default=list)
    author = Column(String(100), default="")
    reviewer = Column(String(100), default="")
    status = Column(String(20), default="draft", index=True)  # draft|reviewed|published
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class FeedbackRecord(Base):
    """误报/反馈记录 — 运营人员对检测结论的纠正"""
    __tablename__ = "feedback_records"

    id = Column(Integer, primary_key=True, autoincrement=True)
    event_id = Column(Integer, ForeignKey("security_events.id"), nullable=True, index=True)
    case_id = Column(Integer, ForeignKey("security_cases.id"), nullable=True, index=True)
    feedback_type = Column(String(30), default="false_positive", index=True)
    # false_positive | true_positive | missed_threat | rule_suggestion
    original_conclusion = Column(String(50), default="")
    operator_conclusion = Column(String(50), default="")
    reason = Column(Text, default="")
    rule_id = Column(String(30), default="", index=True)
    rule_suggestion = Column(Text, default="")
    submitted_by = Column(String(100), default="")
    status = Column(String(20), default="submitted", index=True)
    # submitted → reviewed → applied | dismissed
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)
    reviewed_at = Column(DateTime(timezone=True), nullable=True)


class RuleVersion(Base):
    """规则版本 — Sigma 规则 / 响应策略的版本管理"""
    __tablename__ = "rule_versions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    rule_type = Column(String(30), default="sigma", index=True)  # sigma | response_policy
    rule_id = Column(String(50), default="", index=True)         # SIG-001 / C2通信自动封禁
    version = Column(Integer, default=1)
    content = Column(MutableJSON, default=dict)
    change_summary = Column(Text, default="")
    changed_by = Column(String(100), default="")
    is_active = Column(Boolean, default=True, index=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)


# ════════════════════════════════════════════
# 每日学习闭环 (learn_loop)
# ════════════════════════════════════════════

class LearningRun(Base):
    """学习闭环单次运行 — 收割→统计/聚类/序列→提议→自动应用 全周期留痕。"""
    __tablename__ = "learning_runs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    window_start = Column(DateTime(timezone=True), nullable=True)
    window_end = Column(DateTime(timezone=True), nullable=True)
    trigger = Column(String(20), default="daily")   # daily|hourly|manual
    status = Column(String(20), default="running", index=True)  # running|completed|failed
    harvest = Column(MutableJSON, default=dict)
    model_summary = Column(MutableJSON, default=dict)
    actions_proposed = Column(Integer, default=0)
    actions_auto_applied = Column(Integer, default=0)
    actions_failed = Column(Integer, default=0)
    error = Column(Text, default="")
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)


class LearningAction(Base):
    """学习闭环提议的动作 — 自动白名单动作自动应用，其余留待人工复核。"""
    __tablename__ = "learning_actions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    run_id = Column(Integer, ForeignKey("learning_runs.id"), nullable=False, index=True)
    action_type = Column(String(40), index=True)
    target_type = Column(String(30), default="")
    target_id = Column(String(120), default="", index=True)
    mechanism = Column(String(20), default="")  # baseline|reputation|feedback|degrade|tune|postmortem|case
    payload = Column(MutableJSON, default=dict)
    confidence = Column(Float, default=0.0)
    status = Column(String(20), default="proposed", index=True)
    # proposed|auto_applied|applied|dismissed|rolled_back
    apply_result = Column(MutableJSON, default=dict)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)
    applied_at = Column(DateTime(timezone=True), nullable=True)
    applied_by = Column(String(100), default="")


class ReputationPrior(Base):
    """信誉先验 — learn_loop 根据运营 TP/FP 反馈对 IP/域名信誉分做有界微调。"""
    __tablename__ = "reputation_priors"

    id = Column(Integer, primary_key=True, autoincrement=True)
    target = Column(String(255), index=True)
    target_type = Column(String(16), default="ip")  # ip|domain
    delta = Column(Float, default=0.0)
    tp_count = Column(Integer, default=0)
    fp_count = Column(Integer, default=0)
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    __table_args__ = (UniqueConstraint("target", "target_type", name="uq_reputation_priors_target_type"),)


class BaselineSnapshot(Base):
    """基线快照 — 与 scheduler._snapshot_baselines 的 raw SQL 建表保持同构。"""
    __tablename__ = "baseline_snapshots"

    id = Column(Integer, primary_key=True, autoincrement=True)
    entity_type = Column(String(50), nullable=False)
    entity_key = Column(String(255), nullable=False)
    snapshot = Column(MutableJSON, default=dict)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


# ════════════════════════════════════════════
# NDR 流量采集与协议解析
# ════════════════════════════════════════════

class NetworkFlow(Base):
    """网络流记录 — 五元组聚合流（NetFlow / 采集引擎生成）"""
    __tablename__ = "network_flows"

    id = Column(Integer, primary_key=True, autoincrement=True)
    src_ip = Column(String(45), nullable=False, index=True)
    dst_ip = Column(String(45), nullable=False, index=True)
    src_port = Column(Integer, default=0)
    dst_port = Column(Integer, default=0, index=True)
    protocol = Column(String(20), default="TCP", index=True)     # TCP | UDP | ICMP
    direction = Column(String(10), default="outbound")           # inbound | outbound | lateral
    bytes_in = Column(Integer, default=0)
    bytes_out = Column(Integer, default=0)
    packets_in = Column(Integer, default=0)
    packets_out = Column(Integer, default=0)
    duration_ms = Column(Float, default=0.0)
    tcp_flags = Column(String(20), default="")                   # SYN,ACK,FIN 聚合
    app_protocol = Column(String(30), default="", index=True)    # HTTP | DNS | TLS | SMB | RDP | FTP | SSH
    country_src = Column(String(5), default="")
    country_dst = Column(String(5), default="")
    asn_src = Column(String(20), default="")
    asn_dst = Column(String(20), default="")
    sensor_id = Column(String(50), default="", index=True)       # 采集探针标识
    flow_start = Column(DateTime(timezone=True), index=True)
    flow_end = Column(DateTime(timezone=True))
    raw_data = Column(MutableJSON, default=dict)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)


class TlsSession(Base):
    """TLS 会话元数据 — 加密流量识别的核心数据"""
    __tablename__ = "tls_sessions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    flow_id = Column(Integer, ForeignKey("network_flows.id"), nullable=True, index=True)
    src_ip = Column(String(45), nullable=False, index=True)
    dst_ip = Column(String(45), nullable=False, index=True)
    dst_port = Column(Integer, default=443)
    sni = Column(String(300), default="", index=True)            # Server Name Indication
    ja3_hash = Column(String(64), default="", index=True)        # JA3 客户端指纹
    ja3s_hash = Column(String(64), default="", index=True)       # JA3S 服务端指纹
    ja4_hash = Column(String(64), default="", index=True)        # JA4 指纹
    tls_version = Column(String(10), default="")                 # TLSv1.2 | TLSv1.3
    cipher_suite = Column(String(100), default="")
    cert_subject = Column(String(500), default="")
    cert_issuer = Column(String(500), default="")
    cert_serial = Column(String(100), default="")
    cert_not_before = Column(DateTime(timezone=True), nullable=True)
    cert_not_after = Column(DateTime(timezone=True), nullable=True)
    cert_san = Column(MutableJSON, default=list)                 # Subject Alternative Names
    cert_is_self_signed = Column(Boolean, default=False)
    cert_chain_valid = Column(Boolean, default=True)
    alpn = Column(String(50), default="")                        # h2 | http/1.1
    is_expired = Column(Boolean, default=False, index=True)
    risk_score = Column(Float, default=0.0)                      # 加密流量风险评分
    risk_reasons = Column(MutableJSON, default=list)
    sensor_id = Column(String(50), default="", index=True)
    session_start = Column(DateTime(timezone=True), index=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)


class PcapFile(Base):
    """PCAP 文件存储记录 — 全量抓包回溯"""
    __tablename__ = "pcap_files"

    id = Column(Integer, primary_key=True, autoincrement=True)
    file_path = Column(String(500), nullable=False)
    file_size = Column(Integer, default=0)
    sensor_id = Column(String(50), default="", index=True)
    interface = Column(String(50), default="")
    packet_count = Column(Integer, default=0)
    flow_count = Column(Integer, default=0)
    capture_start = Column(DateTime(timezone=True), index=True)
    capture_end = Column(DateTime(timezone=True))
    bpf_filter = Column(String(500), default="")
    status = Column(String(20), default="capturing", index=True)  # capturing | closed | archived | deleted
    storage_tier = Column(String(10), default="hot")             # hot | warm | cold
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)


# ════════════════════════════════════════════
# EDR 融合
# ════════════════════════════════════════════

class EdrEvent(Base):
    """EDR 遥测事件 — Sysmon / Windows Event Log / 商业 EDR"""
    __tablename__ = "edr_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    source_type = Column(String(30), nullable=False, index=True)  # sysmon | winevent | crowdstrike | carbonblack
    event_id = Column(Integer, default=0, index=True)             # Sysmon EventID (1=ProcessCreate, 3=NetworkConnect...)
    computer_name = Column(String(200), default="", index=True)
    user_name = Column(String(200), default="")
    process_name = Column(String(500), default="", index=True)
    process_id = Column(Integer, default=0)
    parent_process = Column(String(500), default="")
    command_line = Column(Text, default="")
    image_hash = Column(String(128), default="", index=True)      # SHA256
    src_ip = Column(String(45), default="", index=True)
    dst_ip = Column(String(45), default="", index=True)
    dst_port = Column(Integer, default=0)
    file_path = Column(String(1000), default="")
    registry_key = Column(String(1000), default="")
    event_data = Column(MutableJSON, default=dict)                # 原始事件数据
    severity = Column(String(20), default="info", index=True)
    mitre_technique = Column(String(50), default="", index=True)  # T1059.001
    correlation_key = Column(String(100), default="", index=True) # 跨源关联键 (computer+process+time)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)


# ════════════════════════════════════════════
# 威胁情报
# ════════════════════════════════════════════

class ThreatIoc(Base):
    """威胁情报 IOC — STIX/TAXII / MISP / 手动导入"""
    __tablename__ = "threat_iocs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    ioc_type = Column(String(30), nullable=False, index=True)    # ip | domain | url | file_hash | email | cidr
    ioc_value = Column(String(1000), nullable=False, index=True)
    threat_type = Column(String(50), default="", index=True)     # malware | phishing | c2 | apt | ransomware
    severity = Column(String(20), default="medium", index=True)
    confidence = Column(Float, default=0.0)
    source = Column(String(100), default="", index=True)         # misp | otx | alienvault | manual
    stix_id = Column(String(200), default="", index=True)
    mitre_attack_id = Column(String(50), default="")
    first_seen = Column(DateTime(timezone=True), nullable=True)
    last_seen = Column(DateTime(timezone=True), nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    # tags 是数组：MutableDict 会拒绝 list（实测 "Attribute 'tags' does not
    # accept objects of type <class 'list'>"），必须用 MutableList。
    tags = Column(MutableListJSON, default=list)
    context = Column(MutableJSON, default=dict)                  # 附加上下文（家族名、样本哈希等）
    is_active = Column(Boolean, default=True, index=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class ThreatIntelFeed(Base):
    """威胁情报源配置 — TAXII 服务器 / MISP 实例"""
    __tablename__ = "threat_intel_feeds"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(200), nullable=False)
    feed_type = Column(String(30), nullable=False)               # taxii | misp | csv | csv_http | stix_bundle
    url = Column(String(1000), default="")
    api_key = Column(String(500), default="")
    collection = Column(String(200), default="")
    poll_interval_min = Column(Integer, default=60)              # 拉取间隔（分钟）
    last_poll_at = Column(DateTime(timezone=True), nullable=True)
    last_poll_status = Column(String(20), default="idle")        # idle | success | error
    last_poll_count = Column(Integer, default=0)
    enabled = Column(Boolean, default=True, index=True)
    config = Column(MutableJSON, default=dict)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


# ════════════════════════════════════════════
# 零日 / 沙箱检测
# ════════════════════════════════════════════

class SandboxTask(Base):
    """沙箱分析任务 — CAPE / Cuckoo 联动"""
    __tablename__ = "sandbox_tasks"

    id = Column(Integer, primary_key=True, autoincrement=True)
    task_id = Column(String(100), default="", index=True)        # 沙箱侧任务 ID
    sample_hash = Column(String(128), default="", index=True)    # SHA256
    sample_name = Column(String(500), default="")
    sample_type = Column(String(50), default="")                 # pe | elf | pdf | docx | url | pcap
    source = Column(String(50), default="manual", index=True)    # manual | auto_alert | edr | email
    source_event_id = Column(Integer, default=0, index=True)     # 触发来源事件
    sandbox_type = Column(String(30), default="cape")            # cape | cuckoo
    status = Column(String(30), default="pending", index=True)   # pending | running | completed | failed
    priority = Column(Integer, default=1)
    behavior_summary = Column(Text, default="")
    verdict = Column(String(30), default="", index=True)         # clean | suspicious | malicious
    score = Column(Float, default=0.0)
    mitre_techniques = Column(MutableJSON, default=list)        # [{id, name, tactic}]
    network_iocs = Column(MutableJSON, default=list)             # [{type, value}]
    file_iocs = Column(MutableJSON, default=list)                # [{path, hash, action}]
    process_tree = Column(MutableJSON, default=list)
    screenshots = Column(MutableJSON, default=list)
    report_url = Column(String(1000), default="")
    submitted_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)


# ════════════════════════════════════════════
# 安全运营 — 资产管理 (P0.A)
# ════════════════════════════════════════════

class Asset(Base):
    """资产 — 主机/服务器/网络设备/终端/容器/云资产"""
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, autoincrement=True)
    asset_key = Column(String(100), unique=True, nullable=False, index=True)
    asset_type = Column(String(30), nullable=False)                  # host|server|network_device|endpoint|container|cloud_asset
    ip = Column(String(45), default="", index=True)
    hostname = Column(String(200), default="")
    os = Column(String(80), default="")
    services = Column(MutableListJSON, default=list)                # [{port, proto, name, version}]
    business_owner = Column(String(100), default="", index=True)
    tech_owner = Column(String(100), default="")
    business_unit = Column(String(100), default="", index=True)
    criticality = Column(String(20), default="medium", index=True)   # critical|high|medium|low
    environment = Column(String(20), default="prod")                # prod|staging|dev|test
    tags = Column(MutableListJSON, default=list)
    exposure = Column(String(20), default="internal")                # internet_facing|dmz|internal|restricted
    source = Column(String(30), default="manual")                   # manual|nmap|edr|cmdb_api
    first_seen = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    last_seen = Column(DateTime(timezone=True), nullable=True)
    last_scan_id = Column(Integer, nullable=True)
    is_active = Column(Boolean, default=True, index=True)
    metadata_ = Column("metadata", MutableJSON, default=dict)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class AssetChange(Base):
    """资产变更历史 — 字段级 diff"""
    __tablename__ = "asset_changes"

    id = Column(Integer, primary_key=True, autoincrement=True)
    asset_id = Column(Integer, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    change_type = Column(String(30))                                 # created|updated|discovered|decommissioned
    diff = Column(MutableJSON, default=dict)                          # {field: {old, new}}
    source = Column(String(30), default="manual")
    changed_by = Column(String(100), default="")
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)


class AssetDiscoveryTask(Base):
    """资产发现任务 — 按计划扫描"""
    __tablename__ = "asset_discovery_tasks"

    id = Column(Integer, primary_key=True, autoincrement=True)
    task_id = Column(String(50), unique=True, index=True)
    scope = Column(String(200))
    scanner = Column(String(30))                                      # nmap|edr|cmdb_api
    status = Column(String(20), default="pending", index=True)        # pending|running|completed|failed
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    new_count = Column(Integer, default=0)
    changed_count = Column(Integer, default=0)
    result = Column(MutableJSON, default=dict)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


# ════════════════════════════════════════════
# 安全运营 — 数据源持久化 (P0.G)
# ════════════════════════════════════════════

class DataSource(Base):
    """已注册数据源 — API Key 白名单持久化"""
    __tablename__ = "data_sources"

    id = Column(Integer, primary_key=True, autoincrement=True)
    api_key_hash = Column(String(128), unique=True, nullable=False, index=True)
    name = Column(String(100), nullable=False)
    source_type = Column(String(30), default="generic")
    enabled = Column(Boolean, default=True, index=True)
    registered_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    last_seen = Column(DateTime(timezone=True), nullable=True)
    total_events = Column(Integer, default=0)
    rejected_events = Column(Integer, default=0)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    revoked_by = Column(String(100), default="")
    metadata_ = Column("metadata", MutableJSON, default=dict)


class DataSourceRejection(Base):
    """数据源接入拒绝记录 — 安全审计"""
    __tablename__ = "data_source_rejections"

    id = Column(Integer, primary_key=True, autoincrement=True)
    api_key_prefix = Column(String(40), default="")
    reason = Column(String(40), default="")
    source_ip = Column(String(45), default="")
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)


# ════════════════════════════════════════════
# 安全运营 — 操作审计 trail (P0.H)
# ════════════════════════════════════════════

class AuditTrail(Base):
    """操作审计 trail — who did what when，防篡改取证"""
    __tablename__ = "audit_trail"

    id = Column(Integer, primary_key=True, autoincrement=True)
    actor = Column(String(100), nullable=False, index=True)
    actor_role = Column(String(50), default="")
    action = Column(String(60), nullable=False, index=True)           # case.transition|order.approve|rule.publish|asset.update|...
    target_type = Column(String(30), index=True)                      # case|work_order|rule|asset|playbook|source
    target_id = Column(String(60), default="")
    before = Column(MutableJSON, default=dict)
    after = Column(MutableJSON, default=dict)
    ip = Column(String(45), default="")
    user_agent = Column(String(200), default="")
    reason = Column(Text, default="")
    prev_hash = Column(String(64), default="")
    row_hash = Column(String(64), default="", index=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)


# ════════════════════════════════════════════
# 应用用户（自助注册；内置 admin 仍走环境变量）
# ════════════════════════════════════════════

class AppUser(Base):
    """平台登录用户 — bcrypt 哈希，默认 role=viewer"""
    __tablename__ = "app_users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(64), nullable=False, unique=True, index=True)
    password_hash = Column(String(128), nullable=False)
    role = Column(String(30), nullable=False, default="viewer")  # viewer|operator|admin
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    last_login_at = Column(DateTime(timezone=True), nullable=True)


# ════════════════════════════════════════════
# 安全运营 — 运营 KPI 快照 (P0.B)
# ════════════════════════════════════════════

class SelfPlayMatch(Base):
    """红蓝自博弈对局"""
    __tablename__ = "self_play_matches"

    id = Column(Integer, primary_key=True, autoincrement=True)
    match_id = Column(String(64), unique=True, nullable=False, index=True)
    status = Column(String(20), default="pending", index=True)  # pending|running|completed|stopped|failed
    mode = Column(String(20), default="sigma")  # sigma|inject|full
    curriculum_level = Column(Integer, default=0)
    total_rounds = Column(Integer, default=0)
    completed_rounds = Column(Integer, default=0)
    config = Column(MutableJSON, default=dict)
    metrics = Column(MutableJSON, default=dict)
    winner = Column(String(20), default="")  # red|blue|draw
    started_at = Column(DateTime(timezone=True), nullable=True)
    finished_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class SelfPlayRound(Base):
    """自博弈单回合"""
    __tablename__ = "self_play_rounds"

    id = Column(Integer, primary_key=True, autoincrement=True)
    match_id = Column(String(64), nullable=False, index=True)
    round_num = Column(Integer, default=0, index=True)
    curriculum_level = Column(Integer, default=0)
    red_plan = Column(MutableJSON, default=dict)
    events = Column(MutableListJSON, default=list)
    blue_obs = Column(MutableListJSON, default=list)
    outcome = Column(String(20), default="")  # red_win|blue_win|mixed|decoy_only
    metrics = Column(MutableJSON, default=dict)
    learned = Column(MutableListJSON, default=list)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)


class SelfPlayLearnedRule(Base):
    """自博弈学到的检测规则候选(默认不写生产 Sigma)"""
    __tablename__ = "self_play_learned_rules"

    id = Column(Integer, primary_key=True, autoincrement=True)
    rule_id = Column(String(50), default="", index=True)
    match_id = Column(String(64), default="", index=True)
    source_round = Column(Integer, default=0)
    title = Column(String(300), default="")
    attack_type = Column(String(50), default="")
    mitre_id = Column(String(20), default="")
    severity = Column(String(20), default="medium")
    conditions = Column(MutableJSON, default=dict)
    sigma_yaml = Column(Text, default="")
    status = Column(String(20), default="candidate", index=True)  # candidate|shadow|promoted|dismissed
    review_report = Column(MutableJSON, default=dict)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)


class CausalGraph(Base):
    """PC+GES 学到的事件类型因果图(批式,不进 Flink 热路径)。"""
    __tablename__ = "causal_graphs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    algorithm = Column(String(20), default="pc+ges")
    n_windows = Column(Integer, default=0)
    bin_minutes = Column(Integer, default=30)
    names = Column(MutableListJSON, default=list)
    directed = Column(MutableListJSON, default=list)
    edges = Column(MutableListJSON, default=list)
    pc = Column(MutableJSON, default=dict)
    ges = Column(MutableJSON, default=dict)
    agree_rate = Column(Float, default=0.0)
    reason = Column(String(80), default="")
    ok = Column(Boolean, default=False)
    candidates = Column(MutableListJSON, default=list)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)


class CausalEdge(Base):
    """因果图的单条边(含 ACE / 先验冲突)。"""
    __tablename__ = "causal_edges"

    id = Column(Integer, primary_key=True, autoincrement=True)
    graph_id = Column(Integer, ForeignKey("causal_graphs.id"), nullable=True, index=True)
    cause = Column(String(50), default="", index=True)
    effect = Column(String(50), default="", index=True)
    confidence = Column(String(40), default="")
    ace = Column(Float, nullable=True)
    identifiable = Column(Boolean, default=False)
    prior_violation = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class KpiSnapshot(Base):
    """KPI 快照 — MTTD/MTTR/案例周期/FP率/SLA breach率等聚合"""
    __tablename__ = "kpi_snapshots"
    # 不加唯一约束: 同一 metric_key 需按 dimensions(如 priority) 存多行,
    # 且 jsonb 无法参与 UNIQUE; 去重由 kpi_calculator 应用层 upsert 保证

    id = Column(Integer, primary_key=True, autoincrement=True)
    snapshot_date = Column(Date, nullable=False, index=True)
    period = Column(String(10), nullable=False)                      # daily|weekly|monthly
    metric_key = Column(String(60), nullable=False, index=True)      # mttd|mttr|case_cycle|fp_rate|sla_breach_rate|case_count
    metric_value = Column(Float, default=0.0)
    dimensions = Column(MutableJSON, default=dict)                    # {priority}|{threat_type}|{assignee}|{}
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


# ════════════════════════════════════════════
# MCP Guard — 工具调用审计 / 行为签名
# ════════════════════════════════════════════

class ToolCallLog(Base):
    """工具调用审计（append-only）。内存 ring 的持久化副本，留存 ≥ 6 个月。"""
    __tablename__ = "tool_call_log"

    id = Column(Integer, primary_key=True, autoincrement=True)
    ts = Column(DateTime(timezone=True), nullable=False, index=True)
    tool_name = Column(String(64), nullable=False, index=True)
    caller = Column(String(64), nullable=False, default="unknown", index=True)
    caller_role = Column(String(32), default="")
    source = Column(String(32), nullable=False, default="mcp_guard", index=True)
    session_id = Column(String(64), default="")
    trace_id = Column(String(64), default="", index=True)
    event_id = Column(Integer, default=0, index=True)
    arguments = Column(MutableJSON, default=dict)
    arg_digest = Column(String(32), default="")
    decision = Column(String(32), default="", index=True)
    reason = Column(Text, default="")
    checks = Column(MutableListJSON, default=list)
    exec_status = Column(String(32), nullable=True)
    duration_ms = Column(Float, default=0.0)
    tool_match_method = Column(String(16), default="exact")
    signature_score = Column(Float, nullable=True, index=True)
    signature_reasons = Column(MutableListJSON, default=list)


class ToolSignature(Base):
    """(tool_name, caller) 行为指纹。PR2 检测器写入，PR1 先建表。"""
    __tablename__ = "tool_signatures"

    tool_name = Column(String(64), primary_key=True)
    caller = Column(String(64), primary_key=True)
    payload = Column(MutableJSON, default=dict)
    sample_count = Column(Integer, nullable=False, default=0)
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class ToolAnomaly(Base):
    """工具调用行为偏离告警。PR2 检测器写入，PR1 先建表。"""
    __tablename__ = "tool_anomalies"

    id = Column(Integer, primary_key=True, autoincrement=True)
    ts = Column(DateTime(timezone=True), nullable=False, index=True)
    call_id = Column(Integer, nullable=True)
    tool_name = Column(String(64), nullable=False, index=True)
    caller = Column(String(64), nullable=False, index=True)
    score = Column(Float, nullable=False)
    dimensions = Column(MutableJSON, default=dict)
    reasons = Column(MutableListJSON, default=list)
    mode = Column(String(16), nullable=False, default="shadow")
    action_taken = Column(String(16), nullable=False, default="logged")
    trace_id = Column(String(64), default="")


class DlqRecord(Base):
    """死信恢复索引。

    原始负载只放 payload_ciphertext。查询接口不读这列。
    同一条 Kafka 消息（topic, partition, offset）重复失败时更新这一行，不另开一条。
    """
    __tablename__ = "dlq_records"
    __table_args__ = (
        UniqueConstraint(
            "original_topic", "original_partition", "original_offset",
            name="uq_dlq_source_offset",
        ),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    event_id = Column(String(128), default="", index=True)
    original_topic = Column(String(200), nullable=False, default="", index=True)
    original_partition = Column(Integer, nullable=False, default=-1)
    original_offset = Column(Integer, nullable=False, default=-1)
    consumer_group = Column(String(200), default="")
    attempt_count = Column(Integer, nullable=False, default=1)
    first_failed_at = Column(DateTime(timezone=True), nullable=False, index=True)
    last_failed_at = Column(DateTime(timezone=True), nullable=False, index=True)
    error_class = Column(String(80), default="")
    error_code = Column(String(80), default="", index=True)
    sanitized_error = Column(Text, default="")
    message_schema_version = Column(String(40), default="")
    envelope_version = Column(String(20), default="dlq.v1")
    message_timestamp = Column(DateTime(timezone=True), nullable=True)
    payload_ciphertext = Column(Text, default="")
    payload_sha256 = Column(String(64), default="")
    payload_complete = Column(Boolean, default=False)
    trace_id = Column(String(128), default="")
    kafka_dlq_acked = Column(Boolean, default=False)
    replay_status = Column(String(20), default="pending", index=True)
    replayed_at = Column(DateTime(timezone=True), nullable=True)
    replayed_by = Column(String(100), default="")
    replay_idempotency_key = Column(String(120), default="", index=True)
    replay_claimed_at = Column(DateTime(timezone=True), nullable=True)
    replay_result = Column(JSON, default=dict)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class AuditDeadLetter(Base):
    """审计死信（2026-10-23 第二阶段）。

    修复前：Redis PQ 的 payload TTL 先于 ZSET 成员过期时，任务"丢得只剩
    一个计数器"（inc_audit_pq_lost）—— 漏审不可恢复、不可审计。
    现在：发现丢失的瞬间把 event_id 落库（同 event+reason 幂等），
    启动时 audit_dead_letters.replay_dead_letters() 把未重放的再送进
    audit worker，形成"丢失 → 可见 → 可重放"的闭环。
    """
    __tablename__ = "audit_dead_letters"

    id = Column(Integer, primary_key=True, autoincrement=True)
    event_id = Column(Integer, nullable=False, index=True)
    reason = Column(String(60), nullable=False, default="payload_missing")
    detail = Column(Text, default="")
    replay_attempts = Column(Integer, nullable=False, default=0)
    replayed_at = Column(DateTime(timezone=True), nullable=True)
    replay_note = Column(String(200), default="")
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    __table_args__ = (
        UniqueConstraint("event_id", "reason", name="uq_audit_dead_letter_event_reason"),
    )


class ApprovalTicketRecord(Base):
    """审批工单持久化（2026-10-23 第一阶段止血）。

    修复前 ApprovalQueue 是纯进程内存 dict（human_approval.py）——
    后端重启即丢全部 PENDING 高危操作工单，审批链在故障下不可用：
    提交方等不到批准（最终超时），审批人看不到待办，已批动作无据可查。

    现为 write-behind：工单提交/批准/拒绝时异步落库，启动时 restore()
    把非终态工单拉回内存。行仅由后端单进程写（多进程幂等属第二阶段）。
    """
    __tablename__ = "approval_tickets"

    id = Column(String(64), primary_key=True)          # uuid4 hex
    policy_name = Column(String(200), default="")
    threat_info = Column(JSON, default=dict)
    actions = Column(JSON, default=list)
    actions_digest = Column(String(64), default="")    # approve 时防篡改比对
    sig = Column(String(128), default="")              # 审批 HMAC 签名（外部审批回传）
    status = Column(String(20), default="pending", index=True)
    created_at = Column(Float, default=0.0, index=True)
    expires_at = Column(Float, default=0.0)
    approved_by = Column(String(100), default="")
    approved_at = Column(Float, default=0.0)
    reject_reason = Column(Text, default="")
    result = Column(JSON, nullable=True)
    priority = Column(String(8), default="p2")
    match_status = Column(String(40), default="")
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class CadCircuitState(Base):
    """P1-D-2: CAD 熔断器的**跨进程权威状态**（单行，key=1）。

    修复前熔断器是模块级单例的纯进程内存：
      · FastAPI 进程里 `/cad/status` 显示 CLOSED，
        而 Temporal worker 进程里可能早已 tripped（两套内存互不可见）；
      · 进程重启即清零，且没有任何记录表明「曾经熔断过」。

    现改为 DB 单行 + 乐观并发（version CAS）：
    每个进程写自己的本地缓存，但所有状态转移都必须先落库；
    读缓存时校验 version，发现被别的进程改过则重新加载。
    """
    __tablename__ = "cad_circuit_state"

    id = Column(Integer, primary_key=True, default=1)
    # 状态机位置: closed / open / half_open
    state = Column(String(20), nullable=False, default="closed")
    reason = Column(Text, default="")
    # 熔断发生时刻（epoch 秒）。跨进程比较冷却期必须用它，不能用本地 clock。
    tripped_at = Column(Float, default=0.0)
    # 连续坏审核计数（真正的"连续"，修复前 _bad_count 从未自增）
    consecutive_bad = Column(Integer, nullable=False, default=0)
    audit_count = Column(Integer, nullable=False, default=0)
    # 监督系统自身故障计数（CAD 抛异常 / 熔断不可持久化）
    supervision_failures = Column(Integer, nullable=False, default=0)
    last_supervision_error = Column(Text, default="")
    # half_open 探针预算：冷却后只允许 N 次试探，不是一次性全放行
    half_open_probes_left = Column(Integer, nullable=False, default=0)
    # 乐观锁：所有状态转移都必须带上读到的 version
    version = Column(Integer, nullable=False, default=0)
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


async def assert_schema_current() -> None:
    """PG 启动自检：Alembic 未开启时，缺少新表/列必须拒绝启动。"""
    url = str(settings.database_url or "")
    if not url.startswith("postgresql"):
        return
    from sqlalchemy import inspect as _inspect

    required_tables = {"approval_tickets", "audit_dead_letters"}
    required_columns = {"correlation_id", "parent_event_id", "trace_id"}

    def _check(sync_conn):
        insp = _inspect(sync_conn)
        tables = set(insp.get_table_names())
        missing_tables = sorted(required_tables - tables)
        missing_cols = []
        if "security_events" in tables:
            cols = {c.get("name") for c in insp.get_columns("security_events")}
            missing_cols = sorted(required_columns - cols)
        if missing_tables or missing_cols:
            raise RuntimeError(
                "数据库 schema 落后：缺少表 "
                f"{missing_tables or '无'}，security_events 缺少列 "
                f"{missing_cols or '无'}。请运行 `alembic upgrade head`，"
                "或设置 SHARED_MEMORY_AUTO_MIGRATE=true 后重启。"
            )

    async with engine_oltp.connect() as conn:
        await conn.run_sync(_check)


async def init_db():
    """建表（幂等）。

    2026-10-23：schema 演进的权威路径改为 Alembic（backend/migrations/），
    原先这里 `except: pass` 吞错的手搓 ALTER 列表已移入
    migrations/versions/ 的 baseline 迁移（幂等、有日志、失败可见）。
    本函数保留 create_all 供测试/全新 sqlite 部署使用；生产 PG 卷由
    SHARED_MEMORY_AUTO_MIGRATE=true 触发 `alembic upgrade head` 管理。
    """
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def dispose_engines() -> None:
    """关闭连接池。停机路径在业务写入完成之后调用。"""
    await engine_oltp.dispose()
    if engine_bg is not engine_oltp:
        await engine_bg.dispose()

async def get_session():
    async with async_session() as session:
        yield session
