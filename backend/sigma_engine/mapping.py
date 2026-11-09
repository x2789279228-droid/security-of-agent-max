"""
sigma_engine.mapping — 薄版字段映射 pipeline（平台归一化事件 → Sigma 标准字段）

用途: 供引入 SigmaHQ 社区规则时, 把平台 ingest 的归一化事件(见 COMMUNITY_RULES_GUIDE.md
第 1 节字段表)转换为社区规则索引使用的 Sigma 标准字段名。
强调"薄": 只覆盖平台现有字段即可直接命中的映射; 新增日志源时按尾部规范扩展。
"""
import re
from typing import Dict, Any

# ── 平台字段 → 常见 Sigma 标准字段 别名表 ──
# 值为可选的 sigma 等价字段; 键为平台字段名。同一平台字段可对应多个 sigma 字段。
PLATFORM_TO_SIGMA: Dict[str, list[str]] = {
    "event": ["event", "event.category", "category"],     # 平台归一化事件类型
    "event_type": ["event", "event.category"],
    "src_ip": ["src_ip", "source.ip", "client-ip", "c-ip"],
    "source_ip": ["src_ip", "source.ip", "client-ip", "c-ip"],
    "dst_ip": ["dst_ip", "destination.ip", "dest_ip", "dst"],
    "dest_ip": ["dst_ip", "destination.ip", "dest_ip", "dst"],
    "url": ["url", "http.url", "http.url_original", "cs-uri-query", "cs-uri-stem",
            # 2026-10-25 B1 扩容: SigmaHQ webserver/proxy 规则的高频 URI 字段
            # (普查: c-uri×12 / cs-uri×2 / c-uri-query×1), 同源于平台 url
            "c-uri", "cs-uri", "c-uri-query", "UriPath", "UriQuery"],
    "message": ["message", "details"],
    "dst_port": ["dst_port", "destination.port", "dest_port"],
    "protocol": ["protocol", "network.protocol"],
    "server": ["server", "destination.hostname"],
    "host": ["host", "destination.hostname",
             # SigmaHQ proxy 规则的 cs-host(普查 ×11)同源于平台 host/server
             "cs-host", "c-host", "Hostname"],
    # SigmaHQ web(webserver) 补充字段
    "method": ["method", "http.method", "cs-method", "c-method"],
    "status": ["status", "http.response.status_code", "sc-status", "c-status"],   # HTTP 状态码 (SigmaHQ 用 sc-status 做 filter)
    "user_agent": ["user_agent", "http.user_agent", "cs-user-agent",
                   # SigmaHQ proxy 规则的 c-useragent(普查 ×24)同源于平台 user_agent
                   "c-useragent", "UserAgent", "cs-UserAgent"],
    "referer": ["referer", "http.referrer", "cs-referer", "c-referer"],
    # 2026-10-27 路线 4: DNS 查询域。SigmaHQ network/dns 类规则的 detection
    # 字段是裸 `query`(实测 14/14), 平台字段 dns_query(Suricata EVE dns.rrname/
    # Zeek dns.query/Sysmon EID22 QueryName 归一)。释放 dns 类别规则解锁面。
    "dns_query": ["dns_query", "dns.query", "dns.query.name", "dns.question.name",
                  "query", "rrname"],
    # 2026-10-27 路线 4 预铺: 文件哈希。当前平台类别(webserver/proxy/network/dns)
    # 无 hash 字段规则(实测普查 0 条, hash 规则全在 windows 类=需 Sysmon 数据源
    # 的第二批), 链路先通, 第二批字段(process.command_line 等)到位后即测解锁。
    # W1-6: 算法目标字段由 _HASH_TARGETS 路由(不再一对全写), 此处仅登记源键。
    "file_hash": ["file_hash"],
    "sha256": ["file_hash"],
    "sha1": ["file_hash"],
    "md5": ["file_hash"],
    # ── 2026-10-30 B1 第二批字段（REMEDIATION-PLAN 路线 B1）──
    # 来源 = edr_fusion/sysmon_parser.py::SysmonEvent.to_dict() 的归一键
    # (+ winevent_parser 同名键 + syslog auth 的 user_name)。目标是解锁
    # SigmaHQ windows 进程面与 linux 认证类规则 —— 键名与解析器产出严格
    # 对齐，解析器改名时 mapping 必须跟着改（由 COMPAT_FIELDS 一致性测试
    # test_sigma_mapping_compat_sync.py 钉住）。
    "event_id": ["EventID"],                       # Sysmon/WinEvent 路由字段
    "process_name": ["Image", "ImageLoaded", "process.name"],
    "command_line": ["CommandLine", "ProcessCommandLine", "process.command_line"],
    "parent_process": ["ParentImage", "ParentProcessName"],
    "user_name": ["User", "SubjectUserName", "user.name"],
    "file_path": ["TargetFilename", "file.path"],
    "registry_key": ["TargetObject"],
    "image_hash": ["file_hash"],                   # sysmon_parser 已提取纯 SHA256
}

#: W1-6(复审 P3): 哈希按算法路由 — 修复前 file_hash 一对全写
#: sha256/sha1/md5 全部目标字段, MD5 值也会出现在 sha256 字段(黑名单规则
#: 跨算法错配)。键名即算法的直连; 泛化名按 hex 长度识别算法后路由。
_HASH_TARGETS = {
    "sha256": ["file.hash.sha256", "sha256"],
    "sha1": ["file.hash.sha1", "sha1"],
    "md5": ["file.hash.md5", "md5"],
}
_HASH_LEN = {64: "sha256", 40: "sha1", 32: "md5"}

__all__ = ["PLATFORM_TO_SIGMA", "apply_mapping"]

#: "IPv4:port" 形态。端口拆分只认这个 —— IPv6 字面量含多个冒号,
#: "见冒号就拆"的宽松写法（rpartition）会把它拆坏：
#: "2001:db8::1".rpartition(":") → host "2001:db8:" + port 1，
#: 目标 IP 从此匹配不上任何规则。平台校验面（Flink/HTTP）当前收 IPv4，
#: 但 mapping 是纯函数，防御在拆分处而不是假设上游永远干净。
_IPV4_PORT_RE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})$")


def _is_hex(s: str) -> bool:
    try:
        int(s, 16)
        return True
    except ValueError:
        return False


def apply_mapping(event: Dict[str, Any]) -> Dict[str, Any]:
    """把平台事件(含 src_ip/dst_ip(可含端口)/url/... )转为 Sigma 标准字段 dict。

    端口: 若 dst_ip 形如 "1.2.3.4:9200"（严格 IPv4:port），拆出 dst_port；
    其它含冒号的值（IPv6、畸形输入）原样保留 —— 宁可不拆端口，
    不可损坏目标地址。
    输出 = {sigma_field: value}, 同字段名同时保留平台原名, 便于规则双名引用。
    """
    out: Dict[str, Any] = {}
    for src, targets in PLATFORM_TO_SIGMA.items():
        if src in event and event[src] is not None:
            v = event[src]
            if isinstance(v, str) and src in ("dst_ip", "dest_ip"):
                m = _IPV4_PORT_RE.match(v.strip())
                if m:
                    v = m.group(1)
                    out["dst_port"] = int(m.group(2))
            out[src] = v
            if src in ("file_hash", "sha256", "sha1", "md5", "image_hash"):
                # W1-6: 哈希算法路由(见 _HASH_TARGETS 注释)。
                # image_hash: sysmon_parser 从 Hashes 提取的纯 SHA256 ——
                # 按长度路由, 脏值(非 hex/非标长)只落 file_hash 泛化名。
                algo = src if src in _HASH_TARGETS else (
                    _HASH_LEN.get(len(str(v))) if _is_hex(str(v)) else None)
                out.setdefault("file_hash", v)
                if algo:
                    for t in _HASH_TARGETS[algo]:
                        out.setdefault(t, v)
                continue
            for t in targets:
                if t not in out:
                    out[t] = v
    # 保留平台其余字段(便于依赖字段的映射/调试)
    for k, v in event.items():
        out.setdefault(k, v)
    return out


MAPPING_NOTE = '''
## 新增日志源时如何补映射

在 PLATFORM_TO_SIGMA 中为平台新字段增加一行:
    "your_field": ["sigma.same_or_mapped"]

- 优先映射到 Sigma 标准字段(如 network.protocol / destination.port), 便于 SigmaHQ 直接引用;
- 若社区规则只依赖平台则知字段名相同, 可省略;
- 映射只在"社区规则(未含平台字段名)"上生效; 平台自有规则仍用原名直接匹配;
- 每加一个日志源建议: 1) 扩展 mapping; 2) 用 dry_run_import 对样本验证命中率后再灰度。
'''
