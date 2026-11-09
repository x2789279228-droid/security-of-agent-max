"""
cross_correlator.py — 网络流量 × 终端遥测跨源关联

将 NDR 网络流量事件与 EDR 终端遥测进行时间窗口关联，
发现单源无法检测的攻击链。

关联规则:
  1. 网络连接 × 进程创建:
     同一主机在 T 秒内，EDR 记录到进程创建 + NDR 记录到该进程的网络连接
     → 可疑外联 (如 powershell.exe → 外部 IP:4444)

  2. DNS 查询 × 进程创建:
     EDR DNS 查询 (Sysmon 22) + NDR DNS 流量 → 域名信誉交叉验证

  3. SMB 横向移动:
     NDR SMB 流量 (445) + EDR 登录事件 (4624 Type 3) → 横向移动确认

  4. 数据外泄:
     NDR 大流量外发 + EDR 文件访问/压缩操作 → 数据外泄链

用法:
    from edr_fusion.cross_correlator import cross_correlator
    result = await cross_correlator.correlate(session, time_window=300)
"""
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Optional

from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings

logger = logging.getLogger(__name__)


@dataclass
class CorrelationResult:
    """跨源关联结果"""
    correlation_type: str       # process_network | dns_cross | lateral_move | data_exfil
    confidence: float = 0.0
    severity: str = "medium"
    description: str = ""
    network_event: dict = field(default_factory=dict)
    edr_event: dict = field(default_factory=dict)
    mitre_technique: str = ""
    indicators: list = field(default_factory=list)
    timestamp: float = 0.0

    def to_dict(self) -> dict:
        return {
            "correlation_type": self.correlation_type,
            "confidence": round(self.confidence, 2),
            "severity": self.severity,
            "description": self.description,
            "network_event": self.network_event,
            "edr_event": self.edr_event,
            "mitre_technique": self.mitre_technique,
            "indicators": self.indicators,
        }


# 可疑外联进程（不应主动发起网络连接的进程）
_SUSPICIOUS_NETWORK_PROCESSES = {
    "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "certutil.exe", "regsvr32.exe", "rundll32.exe",
    "wmic.exe", "bitsadmin.exe", "msiexec.exe",
}

# 可疑目标端口
_SUSPICIOUS_PORTS = {4444, 5555, 6666, 7777, 8888, 9999, 1337, 31337,
                     1234, 4321, 12345, 54321}


class CrossCorrelator:
    """跨源关联引擎"""

    def __init__(self):
        self.window_sec = settings.edr_correlation_window

    async def correlate(
        self,
        session: AsyncSession,
        time_window: Optional[int] = None,
    ) -> list[CorrelationResult]:
        """
        执行跨源关联分析

        查询最近 time_window 秒内的 EDR 事件和网络流，
        按规则进行关联匹配。
        """
        window = time_window or self.window_sec
        results = []

        try:
            from models import EdrEvent, NetworkFlow

            cutoff = datetime.now(timezone.utc) - timedelta(seconds=window)

            # 查询最近的 EDR 事件
            edr_q = await session.execute(
                select(EdrEvent)
                .where(EdrEvent.created_at >= cutoff)
                .order_by(desc(EdrEvent.created_at))
                .limit(500)
            )
            edr_events = edr_q.scalars().all()

            # 查询最近的网络流
            flow_q = await session.execute(
                select(NetworkFlow)
                .where(NetworkFlow.created_at >= cutoff)
                .order_by(desc(NetworkFlow.created_at))
                .limit(500)
            )
            flows = flow_q.scalars().all()

            if not edr_events or not flows:
                return results

            # 规则 1: 可疑进程外联
            results.extend(self._match_process_network(edr_events, flows))

            # 规则 2: SMB 横向移动
            results.extend(self._match_lateral_movement(edr_events, flows))

            # 规则 3: 数据外泄
            results.extend(self._match_data_exfil(edr_events, flows))

            logger.info(
                "跨源关联完成: %d EDR × %d 流 → %d 关联结果",
                len(edr_events), len(flows), len(results),
            )
        except Exception as e:
            logger.error("跨源关联异常: %s", e, exc_info=True)

        # H-②(2026-10-30 REMEDIATION-PLAN 路线 H): 关联结果 LLM 叙事
        # —— edr_fusion/llm_correlation.py 从休眠接入生产。fail-open + 开关 +
        # 成本护栏；只叙述置信度最高的一条(should_trigger 内含阈值)。
        try:
            from config import settings as _cfg
            if results and getattr(_cfg, "edr_llm_correlation_enabled", False):
                from edr_fusion.llm_correlation import (
                    llm_narrate_correlation,
                    should_trigger_llm,
                )
                _top = max(results, key=lambda r: getattr(r, "confidence", 0))
                if should_trigger_llm(_top):
                    _d = _top.to_dict()
                    _nar = await llm_narrate_correlation(
                        correlation_type=str(_d.get("correlation_type", "")),
                        confidence=float(_d.get("confidence", 0)),
                        network_event=_d.get("network_event", {}) or {},
                        edr_event=_d.get("edr_event", {}) or {},
                        mitre_technique=str(_d.get("mitre_technique", "")),
                        indicators=list(_d.get("indicators", []) or []),
                    )
                    if _nar:
                        _top.narrative = _nar
        except Exception as _e:
            logger.debug("llm_correlation wiring skipped: %s", _e)

        return results

    def _match_process_network(self, edr_events, flows) -> list[CorrelationResult]:
        """规则 1: 可疑进程 × 网络连接"""
        results = []

        # 收集进程创建事件
        process_events = [
            e for e in edr_events
            if e.event_id == 1 and e.process_name  # Sysmon ProcessCreate
        ]

        for proc in process_events:
            proc_name = proc.process_name.lower().split("\\")[-1] if proc.process_name else ""
            if proc_name not in _SUSPICIOUS_NETWORK_PROCESSES:
                continue

            # 查找同一源 IP 的网络流
            proc_ip = proc.src_ip or ""
            for flow in flows:
                if flow.src_ip != proc_ip:
                    continue
                # 时间窗口检查
                if flow.flow_start and proc.created_at:
                    delta = abs(
                        flow.flow_start.timestamp() - proc.created_at.timestamp()
                    )
                    if delta > self.window_sec:
                        continue

                indicators = [f"suspicious_process:{proc_name}"]
                severity = "high"

                if flow.dst_port in _SUSPICIOUS_PORTS:
                    indicators.append(f"suspicious_port:{flow.dst_port}")
                    severity = "critical"

                results.append(CorrelationResult(
                    correlation_type="process_network",
                    confidence=0.85,
                    severity=severity,
                    description=(
                        f"可疑进程 {proc_name} 在 {proc.computer_name} 上发起网络连接 "
                        f"→ {flow.dst_ip}:{flow.dst_port}"
                    ),
                    network_event={
                        "src_ip": flow.src_ip, "dst_ip": flow.dst_ip,
                        "dst_port": flow.dst_port, "app_protocol": flow.app_protocol,
                    },
                    edr_event={
                        "process": proc.process_name,
                        "command_line": proc.command_line[:200],
                        "computer": proc.computer_name,
                    },
                    mitre_technique="T1059",
                    indicators=indicators,
                ))

        return results

    def _match_lateral_movement(self, edr_events, flows) -> list[CorrelationResult]:
        """规则 2: SMB 流量 × 网络登录

        P1: 修复前有三处硬伤 —
          ① `logon.raw_data` 不存在(模型字段是 event_data) → 首个登录事件即
             AttributeError, 整条规则从未真正跑通过(被 correlate() 的 except 吞成日志);
          ② `logon.user` 不存在(模型字段是 user_name) — 同上;
          ③ "目标 IP 匹配"只做空值检查不做相等比较 → O(登录×SMB流) 笛卡尔积,
             4624 Type3 + 445 端口是 Windows 网络常态, 每分钟批量产出
             confidence=0.75/high 的假横向移动告警。
        现在按**同一发起源**关联: flow.src_ip == logon.src_ip(登录源 IP 与 SMB
        流发起方一致才算同一行为者), 并按 src_ip 预索引消除笛卡尔积。
        """
        results = []

        # 网络登录事件 (4624 Type 3) — 字段名与模型对齐(event_data/user_name)
        logon_events = [
            e for e in edr_events
            if e.event_id == 4624
            and isinstance(getattr(e, "event_data", None), dict)
            and str(e.event_data.get("logon_type", "")).lower() in ("network", "3")
        ]
        # 没有"登录来源 IP"就无法与流建立行为者关联 — 如实放弃, 不做假关联
        logon_events = [e for e in logon_events if (e.src_ip or "").strip()]

        # SMB 流 (端口 445), 按发起源预索引
        flows_by_src: dict[str, list] = {}
        for f in flows:
            if f.dst_port == 445 or (f.app_protocol or "").upper() == "SMB":
                flows_by_src.setdefault((f.src_ip or "").strip(), []).append(f)

        for logon in logon_events:
            candidates = flows_by_src.get((logon.src_ip or "").strip(), [])
            for flow in candidates:
                # 同一行为者: SMB 流的发起源 == 网络登录的来源 IP
                if flow.flow_start and logon.created_at:
                    delta = abs(
                        flow.flow_start.timestamp() - logon.created_at.timestamp()
                    )
                    if delta > self.window_sec:
                        continue

                results.append(CorrelationResult(
                    correlation_type="lateral_move",
                    confidence=0.75,
                    severity="high",
                    description=(
                        f"SMB 横向移动: {flow.src_ip} → {flow.dst_ip} "
                        f"(用户: {logon.user_name})"
                    ),
                    network_event={
                        "src_ip": flow.src_ip, "dst_ip": flow.dst_ip,
                        "protocol": "SMB",
                    },
                    edr_event={
                        "user": logon.user_name,
                        "computer": logon.computer_name,
                        "logon_type": "Network",
                        "logon_src_ip": logon.src_ip,
                    },
                    mitre_technique="T1021.002",
                    indicators=["smb_lateral_move"],
                ))

        return results

    def _match_data_exfil(self, edr_events, flows) -> list[CorrelationResult]:
        """规则 3: 大流量外发 × 文件操作"""
        results = []

        # 文件相关 EDR 事件
        file_events = [
            e for e in edr_events
            if e.event_id in (11, 23, 15)  # FileCreate / FileDelete / FileCreateStreamHash
        ]

        # 大流量外发 (> 10MB)
        large_flows = [
            f for f in flows
            if f.bytes_out > 10 * 1048576 and f.direction == "outbound"
        ]

        for flow in large_flows:
            for fe in file_events:
                if fe.src_ip != flow.src_ip:
                    continue
                if flow.flow_start and fe.created_at:
                    delta = abs(
                        flow.flow_start.timestamp() - fe.created_at.timestamp()
                    )
                    if delta > self.window_sec * 2:
                        continue
                # P1: EdrEvent 没有 event_name 字段 — 修复前这里 AttributeError,
                # 整条外泄规则从未跑通(被 correlate() 的 except 吞掉)。
                fe_event_name = {
                    11: "FileCreate", 23: "FileDelete", 15: "FileCreateStreamHash",
                }.get(getattr(fe, "event_id", 0), f"Event-{getattr(fe, 'event_id', 0)}")

                results.append(CorrelationResult(
                    correlation_type="data_exfil",
                    confidence=0.65,
                    severity="high",
                    description=(
                        f"疑似数据外泄: {flow.src_ip} 外发 "
                        f"{flow.bytes_out / 1048576:.1f}MB → {flow.dst_ip}, "
                        f"伴随文件操作 ({fe_event_name})"
                    ),
                    network_event={
                        "src_ip": flow.src_ip, "dst_ip": flow.dst_ip,
                        "bytes_out": flow.bytes_out,
                    },
                    edr_event={
                        "file_path": fe.file_path,
                        "event": fe_event_name,
                        "computer": fe.computer_name,
                    },
                    mitre_technique="T1048",
                    indicators=["large_outbound", "file_activity"],
                ))

        return results


# ── 全局单例 ──
cross_correlator = CrossCorrelator()
