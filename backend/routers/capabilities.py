"""B 类高级能力总览 — 能力启用状态 + Prometheus 指标聚合 (供前端统一 dashboard)

2026-10-21：数据源改为 `backend/capabilities.yaml`（单一事实源），
把“配置开关”与“是否已验证”分开：
  - status: verified / experimental / disabled
  - enabled: 当前运行配置是否打开
  - evidence / last_verified: 该项能力的证据与最后验证日期
"""

import logging
import re

from fastapi import APIRouter, Depends
from prometheus_client import generate_latest

from auth import get_current_user, UserInfo
from capabilities_registry import load_registry, runtime_enabled
from config import settings

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["capabilities"])

# 兼容旧客户端：YAML 不可用时的兜底清单。
_FALLBACK = [
    ("ndr", "NDR 流量分析", "soc_ndr_flows_", lambda: settings.capture_enabled),
    ("edr", "EDR 融合", "soc_edr_events_", lambda: settings.edr_enabled),
    ("threat_intel", "威胁情报", "soc_intel_ioc_", lambda: settings.intel_enabled),
    ("zeroday", "0day 沙箱", "soc_sandbox_submissions_", lambda: settings.sandbox_enabled),
    ("phishing", "反钓鱼", "soc_phishing_detections_", lambda: True),
]

# 兼容旧测试/旧调用方使用的 (name, prefix, enabled) 三元组。
_CAPABILITIES = [(name, prefix, enabled) for name, _label, prefix, enabled in _FALLBACK]


def _parse_metric_values(text: str, prefix: str) -> int:
    """从 Prometheus 文本提取以 prefix 开头(去 _total)的指标总值。"""
    prefix = (prefix or "").strip()
    if not prefix:
        return 0
    total = 0
    key = prefix.rstrip("_")
    for m in re.finditer(rf"\n({re.escape(key)}(?:_total)?){{(.*?)}} ([0-9.]+)", "\n" + text):
        total += float(m.group(3))
    # 也匹配无 label 形式(如 soc_tls_sessions_total 1.0)
    for m in re.finditer(rf"\n{re.escape(key)}(?:_total)? ([0-9.]+)", "\n" + text):
        total += float(m.group(1))
    return int(total)


@router.get("/capabilities/status")
async def capabilities_status(user: UserInfo = Depends(get_current_user)):
    """返回能力登记表 + 运行开关 + 累计指标。"""
    text = generate_latest().decode()
    registry = load_registry()
    out = []
    if registry["capabilities"]:
        for cap in registry["capabilities"]:
            prefix = str(cap.get("metric_prefix") or "")
            out.append({
                "id": str(cap.get("id") or ""),
                "name": str(cap.get("name") or cap.get("id") or ""),
                "status": str(cap.get("status") or "disabled"),
                "enabled": runtime_enabled(cap, settings),
                "count": _parse_metric_values(text, prefix),
                "evidence": str(cap.get("evidence") or ""),
                "last_verified": str(cap.get("last_verified") or ""),
                "demo": str(cap.get("demo") or ""),
                "notes": str(cap.get("notes") or ""),
            })
    else:
        for name, label, prefix, enabled in _FALLBACK:
            out.append({
                "id": name,
                "name": label,
                "status": "experimental" if enabled() else "disabled",
                "enabled": bool(enabled()),
                "count": _parse_metric_values(text, prefix),
                "evidence": "",
                "last_verified": "",
                "demo": "",
                "notes": "",
            })
    return {
        "version": registry.get("version") or "",
        "updated_at": registry.get("updated_at") or "",
        "capabilities": out,
    }
