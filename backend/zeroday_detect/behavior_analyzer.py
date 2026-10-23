"""
behavior_analyzer.py — 沙箱报告行为分析

解析 CAPE/Cuckoo 报告，提取:
  - 行为摘要（进程树、文件操作、注册表修改、网络活动）
  - MITRE ATT&CK 技术映射
  - 网络 IOC（C2 地址、下载 URL、DNS 查询）
  - 文件 IOC（释放文件、修改文件）
  - 综合恶意度评分

整改方案 §五.1（P0-5，2026-10-18 审查）：

修复前 `analyze(None)` 与 `analyze({})` 返回**逐字段相同**的结果
`verdict="clean", score=0.0, behavior_summary=""` —— 「沙箱没跑起来」
与「分析完成且样本确实干净」无法区分。

现在：
  - 报告缺失 / 非 dict → `verdict="unavailable"`，`score=None`，**不是 clean**
  - CAPE 评分非法（字符串 / bool / 越界）→ 明确标记 `input_errors`，
    不再静默变成 0 分
  - `score` 无有效值时是 `None` 而不是 `0.0`

用法:
    from zeroday_detect.behavior_analyzer import behavior_analyzer
    analysis = behavior_analyzer.analyze(report_dict)
"""
import logging
import math
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

#: 判定「没发现威胁」的合法 verdict —— 其余都是"没结论"
NEGATIVE_VERDICT = "clean"
VERDICT_UNAVAILABLE = "unavailable"
VERDICT_ERROR = "error"

#: CAPE info.score 的合法区间（CAPE 0-10）
CAPE_SCORE_MIN = 0.0
CAPE_SCORE_MAX = 10.0


def _normalize_cape_score(raw) -> tuple:
    """校验 CAPE info.score → (归一化值|None, 错误列表)。

    整改方案 §五.1：非法输入进入明确的输入错误状态，不静默变成 0 分。
    上界越界（>10）安全截断且不算错误 —— 方向对安全无影响。
    """
    if isinstance(raw, bool):
        return None, [f"cape_score_bool:{raw!r}"]
    if raw is None:
        return None, ["cape_score_missing"]
    if not isinstance(raw, (int, float)):
        return None, [f"cape_score_type:{type(raw).__name__}"]
    val = float(raw)
    if math.isnan(val):
        return None, ["cape_score_nan"]
    if math.isinf(val):
        return CAPE_SCORE_MAX, ["cape_score_inf_clamped"]
    if val < CAPE_SCORE_MIN:
        return None, [f"cape_score_out_of_range:{val}"]
    if val > CAPE_SCORE_MAX:
        return CAPE_SCORE_MAX, []      # 上界截断，方向安全
    return val, []

# CAPE 签名 → MITRE ATT&CK 映射
_SIGNATURE_MITRE = {
    "creates_exe": ("T1105", "Ingress Tool Transfer"),
    "injection_runpe": ("T1055", "Process Injection"),
    "injection_resumethread": ("T1055.003", "Thread Execution Hijacking"),
    "persistence_autorun": ("T1547.001", "Registry Run Keys"),
    "persistence_service": ("T1543.003", "Windows Service"),
    "disables_security": ("T1562.001", "Disable or Modify Tools"),
    "antivm": ("T1497", "Virtualization/Sandbox Evasion"),
    "antisandbox": ("T1497.003", "Time Based Evasion"),
    "network_cnc": ("T1071", "Application Layer Protocol"),
    "ransomware_files": ("T1486", "Data Encrypted for Impact"),
    "credential_dumping": ("T1003", "OS Credential Dumping"),
    "keylogger": ("T1056.001", "Keylogging"),
    "banker": ("T1555", "Credentials from Password Stores"),
    "rat": ("T1219", "Remote Access Software"),
}


@dataclass
class BehaviorAnalysis:
    """行为分析结果

    整改方案 §五.1：`score=None` 表示「没有可用分数」，与 `0.0`
    （"算过了，就是 0"）语义不同。`verdict` 只有在报告有效且分析完成
    之后才可能是 clean/suspicious/malicious。
    """
    verdict: str = VERDICT_UNAVAILABLE   # clean | suspicious | malicious | unavailable | error
    score: Optional[float] = None
    behavior_summary: str = ""
    mitre_techniques: list = field(default_factory=list)
    network_iocs: list = field(default_factory=list)
    file_iocs: list = field(default_factory=list)
    process_tree: list = field(default_factory=list)
    signatures: list = field(default_factory=list)
    # ── 可观测性（整改方案 §十一）──
    analyzed: bool = False          # False → 没有有效报告，verdict 不可用
    input_errors: list = field(default_factory=list)

    @property
    def is_negative(self) -> bool:
        """能否被当作「未发现威胁」。只有真正分析过且得分为 0 才可以。"""
        return self.analyzed and self.verdict == NEGATIVE_VERDICT

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict,
            "score": round(self.score, 3) if self.score is not None else None,
            "behavior_summary": self.behavior_summary,
            "mitre_techniques": self.mitre_techniques,
            "network_iocs": self.network_iocs,
            "file_iocs": self.file_iocs,
            "process_tree": self.process_tree,
            "signatures": self.signatures,
            "analyzed": self.analyzed,
            "is_negative": self.is_negative,
            "input_errors": list(self.input_errors),
        }


class BehaviorAnalyzer:
    """沙箱报告行为分析器"""

    def analyze(self, report: dict) -> BehaviorAnalysis:
        """分析 CAPE/Cuckoo 报告

        整改方案 §五.1：报告缺失 → `unavailable`（不是 clean）；
        非法评分 → 记入 `input_errors` 并把 score 置 None（不是 0）。
        """
        result = BehaviorAnalysis()
        score = 0.0
        techniques = []
        sigs = []

        if not isinstance(report, dict) or not report:
            result.verdict = VERDICT_UNAVAILABLE
            if report is not None:
                result.input_errors.append(
                    f"report_type_invalid:{type(report).__name__}")
            logger.warning("沙箱报告缺失或格式非法，未产生恶意性判定")
            return result

        # 1. 签名分析
        signatures = report.get("signatures", [])
        for sig in signatures:
            sig_name = sig.get("name", "")
            sig_severity = sig.get("severity", 1)
            sigs.append(sig_name)

            # 严重度加权
            score += min(sig_severity * 0.1, 0.4)

            # MITRE 映射
            if sig_name in _SIGNATURE_MITRE:
                tid, tname = _SIGNATURE_MITRE[sig_name]
                techniques.append({"id": tid, "name": tname, "signature": sig_name})

        # 2. 网络 IOC 提取
        network = report.get("network", {})

        for host in network.get("hosts", []):
            ip = host.get("ip", "")
            if ip and not ip.startswith(("10.", "192.168.", "172.")):
                result.network_iocs.append({"type": "ip", "value": ip})
                score += 0.1

        for domain in network.get("domains", []):
            d = domain.get("domain", "")
            if d:
                result.network_iocs.append({"type": "domain", "value": d})

        for http_req in network.get("http", []):
            uri = http_req.get("uri", "")
            if uri:
                result.network_iocs.append({"type": "url", "value": uri})
                score += 0.05

        for dns in network.get("dns", []):
            request = dns.get("request", "")
            if request:
                result.network_iocs.append({"type": "dns", "value": request})

        # 3. 文件 IOC
        behavior = report.get("behavior", {})
        for f in behavior.get("summary", {}).get("files", [])[:20]:
            result.file_iocs.append({"path": f, "action": "accessed"})
        for f in behavior.get("summary", {}).get("files_written", [])[:20]:
            result.file_iocs.append({"path": f, "action": "written"})
            score += 0.02
        for f in behavior.get("summary", {}).get("files_deleted", [])[:10]:
            result.file_iocs.append({"path": f, "action": "deleted"})
            score += 0.03

        # 4. 注册表
        for reg in behavior.get("summary", {}).get("keys", [])[:10]:
            result.file_iocs.append({"path": reg, "action": "registry"})

        # 5. 进程树
        proctree = report.get("behavior", {}).get("processtree", [])
        for proc in proctree[:10]:
            result.process_tree.append({
                "name": proc.get("name", ""),
                "pid": proc.get("pid", 0),
                "command_line": proc.get("command_line", "")[:200],
                "children": len(proc.get("children", [])),
            })

        # 6. malfamily（如果 CAPE 识别了家族）
        malfamily = report.get("malfamily", "")
        if malfamily:
            sigs.append(f"family:{malfamily}")
            score += 0.3

        # 7. 综合评分
        # 整改方案 §五.1：非法评分不得静默变成 0 分。
        # 修复前 `isinstance(cape_score,(int,float))` 对 bool / NaN / 负数
        # 一律放行（True 被当 1 → 0.1 分），对 str/None 静默跳过。
        cape_score, score_err = _normalize_cape_score(
            (report.get("info") or {}).get("score", 0))
        result.input_errors.extend(score_err)
        if cape_score is not None:
            score = max(score, cape_score / 10)  # CAPE 0-10 → 0-1

        result.signatures = sigs[:20]
        result.mitre_techniques = techniques[:15]

        # 判定
        if result.input_errors:
            # 评分来源不可信 → 不产出恶意性判定（整改方案 §五.1）
            result.score = None
            result.verdict = VERDICT_ERROR
            result.behavior_summary = "报告评分非法，无法判定"
            return result

        result.analyzed = True
        result.score = min(score, 1.0)
        if result.score >= 0.7:
            result.verdict = "malicious"
        elif result.score >= 0.3:
            result.verdict = "suspicious"
        else:
            result.verdict = NEGATIVE_VERDICT

        # 行为摘要
        summary_parts = []
        if sigs:
            summary_parts.append(f"触发 {len(sigs)} 条签名")
        if result.network_iocs:
            summary_parts.append(f"{len(result.network_iocs)} 个网络 IOC")
        if result.file_iocs:
            summary_parts.append(f"{len(result.file_iocs)} 个文件操作")
        if techniques:
            summary_parts.append(f"映射 {len(techniques)} 个 ATT&CK 技术")
        if malfamily:
            summary_parts.append(f"家族: {malfamily}")
        result.behavior_summary = "; ".join(summary_parts) or "无显著恶意行为"

        return result


# ── 全局单例 ──
behavior_analyzer = BehaviorAnalyzer()
