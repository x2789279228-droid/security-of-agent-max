"""
SSH 防火墙适配器 — 通过 SSH 连接 Linux 虚拟机执行 iptables 真实封禁/隔离/回滚

与现有 transport.py 的关系：
  - transport.py: 通用 SSH 传输（Windows PowerShell 命令）
  - ssh_firewall.py: 专用 Linux iptables 防火墙操作（本模块）

安全加固:
  - 命令白名单: _exec() 中所有命令必须通过 CommandWhitelist 检查
  - 参数强校验: block_ip/isolate_host 对 IP 做 ipaddress 严格校验
  - 核心资产保护: 封禁/隔离前检查 AssetWhitelist
  - 最小权限: nmap/list_rules 等只读操作不加 sudo

能力：
  - block_ip: iptables DROP 封禁 + rule_id 追踪
  - isolate_host: 入站+出站全隔离
  - vulnerability_scan: nmap 真实扫描
  - rollback: 按 rule_id 精确回滚
  - rollback_all: 一键清理所有演示规则
  - list_rules: 查询当前 iptables 规则
  - health_check: 连接健康检查

配置：通过 platform config.py 的环境变量
  SHARED_MEMORY_FW_SSH_HOST      虚拟机 IP
  SHARED_MEMORY_FW_SSH_PORT      SSH 端口 (默认 22)
  SHARED_MEMORY_FW_SSH_USER      SSH 用户名
  SHARED_MEMORY_FW_SSH_PASSWORD  SSH 密码
  SHARED_MEMORY_FW_USE_SUDO      是否使用 sudo (默认 true)
"""
import asyncio
import hashlib
import ipaddress
import logging
import os
import re
import secrets
import time
from datetime import datetime
from typing import Optional

from config import settings

logger = logging.getLogger(__name__)

try:
    import paramiko
    HAS_PARAMIKO = True
except ImportError:
    HAS_PARAMIKO = False
    logger.warning("paramiko not installed — SSH firewall adapter disabled")

# 地址族常量
FAMILY_IPV4 = "ipv4"
FAMILY_IPV6 = "ipv6"

# 未撤销状态集合(block=active, isolate=isolated); get_active_rules 按此过滤
_ACTIVE_STATUSES = ("active", "isolated", "applied")


def _new_rule_seq() -> str:
    """10 位随机规则序号(secrets)。

    修复前 random.randint(10000,99999): 约 300 条规则即有 50% 概率碰撞,
    rule_id 撞车会让 TTL/回滚定位到错误规则。
    """
    return f"{secrets.randbelow(10 ** 10):010d}"


def _parse_rule_line(line: str) -> tuple[str, str, str]:
    """解析 `iptables -L <chain> -n --line-numbers` 的一行规则。

    返回 (comment, src, dst); 不匹配规则行(表头/空行)返回 ("", "", "")。
    列序: num target prot opt(--) source destination [/* comment */]
    """
    parts = line.strip().split()
    if len(parts) < 6 or not parts[0].isdigit():
        return "", "", ""
    try:
        sep = parts.index("--", 1)
    except ValueError:
        return "", "", ""
    src = parts[sep + 1] if len(parts) > sep + 1 else ""
    dst = parts[sep + 2] if len(parts) > sep + 2 else ""
    m = re.search(r"/\*\s*([A-Za-z0-9_\-]+)\s*\*/", line)
    comment = m.group(1) if m else ""
    return comment, src, dst

# 域名强校验: 字母/数字/连字符/点, ≤253, 无路径无空格 — sinkhole 拼命令前必须通过
_DOMAIN_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.\-]{0,251}[A-Za-z0-9])?$")
_MARKER_RE = re.compile(r"^SOC-SH-[A-Za-z0-9\-]{1,32}$")


def _normalize_ip(value: str) -> tuple[str, str]:
    """校验并规范化 IP; 返回 (规范化字符串, family)。IPv4-mapped 地址按 IPv6 处理。"""
    try:
        addr = ipaddress.ip_address(str(value).strip())
    except ValueError:
        raise ValueError(f"非法 IP 地址: {value}")
    family = FAMILY_IPV6 if addr.version == 6 else FAMILY_IPV4
    return str(addr), family


def _table_for(family: str) -> str:
    """family → iptables / ip6tables"""
    return "ip6tables" if family == FAMILY_IPV6 else "iptables"


class SshFirewallAdapter:
    """
    SSH 防火墙适配器

    通过 paramiko SSH 连接 Linux 虚拟机，执行 iptables 命令。
    所有方法都是同步的（paramiko 是同步库），在 async 上下文中用 asyncio.to_thread 调用。
    """

    def __init__(self):
        self._client: Optional[object] = None
        self._config = {
            "host": "",
            "port": 22,
            "username": "",
            "password": "",
            "use_sudo": True,
            "connect_timeout": 8,
            "exec_timeout": 10,
            "known_hosts": "",
            "allow_unknown_host": False,
        }
        self._connected = False
        # 规则追踪（内存）
        self._active_rules: dict[str, dict] = {}

    def configure(self, host: str, port: int = 22, username: str = "",
                  password: str = "", use_sudo: bool = True,
                  known_hosts: str = "", allow_unknown_host: bool | None = None):
        """配置 SSH 连接参数

        v5 修复:configure 时即解析主机名并缓存 IP。burst 高并发期间
        Docker 内嵌 DNS (127.0.0.11) 偶发丢包导致 paramiko 连接报
        "Name or service not known"(2026-09-01 复现:block_ip 连续 error)。
        缓存后连接直接用 IP, 不再依赖每次 DNS; 连接异常时清缓存重新解析。

        2026-10-21: 主机密钥默认失败关闭。known_hosts 缺失时不再静默接受
        任意主机密钥；仅当 allow_unknown_host=True（隔离靶场显式开启）才
        回退到 AutoAddPolicy。
        """
        self._config.update({
            "host": host,
            "port": port,
            "username": username,
            "password": password,
            "use_sudo": use_sudo,
            "resolved_ip": "",
            "known_hosts": known_hosts or getattr(settings, "fw_ssh_known_hosts", ""),
            "allow_unknown_host": (
                getattr(settings, "fw_ssh_allow_unknown_host", False)
                if allow_unknown_host is None else allow_unknown_host
            ),
        })
        self._resolve_host()

    def _resolve_host(self) -> None:
        host = self._config.get("host") or ""
        if not host:
            return
        try:
            import socket as _socket
            infos = _socket.getaddrinfo(host, int(self._config.get("port") or 22))
            ip = infos[0][4][0] if infos else ""
            if ip and ip != host:
                self._config["resolved_ip"] = ip
                logger.info(f"SSH firewall: resolved {host} -> {ip} (cached)")
        except Exception as e:
            logger.warning(f"SSH firewall: pre-resolve {host} failed: {e}")

    @property
    def enabled(self) -> bool:
        return HAS_PARAMIKO and bool(self._config["host"] and self._config["username"])

    def connect(self) -> str:
        """建立 SSH 连接

        v5 修复:瞬时 DNS/网络抖动重试 (burst 高并发下 Docker 内嵌 DNS
        偶发 "Name or service not known", 导致 block_ip 误报 error)。
        重试节奏 1s/3s, 共 3 次尝试; 第 2 次起清空 DNS 缓存重新解析
        (容器重建后 IP 可能变化)。
        """
        last_err: Exception | None = None
        for attempt, wait in enumerate((0.0, 1.0, 3.0), start=1):
            try:
                return self._connect_once()
            except Exception as e:
                last_err = e
                self._config["resolved_ip"] = ""
                if wait:
                    time.sleep(wait)
                self._resolve_host()
        raise last_err  # type: ignore[misc]

    def _connect_once(self) -> str:
        if not HAS_PARAMIKO:
            raise RuntimeError("paramiko 未安装")
        # P2: 重连前先关旧连接, 否则旧 socket 泄漏(每次重连丢一个 fd)
        if self._client is not None:
            try:
                self._client.close()
            except Exception:
                pass
            self._client = None
            self._connected = False
        cfg = self._config
        client = paramiko.SSHClient()
        # 主机密钥校验：默认失败关闭。
        # - known_hosts 存在：只接受其中已登记的主机密钥（RejectPolicy）
        # - known_hosts 缺失：除非显式 allow_unknown_host=True，否则拒绝连接
        #   （静默 AutoAddPolicy 会让 MITM 完整劫持 iptables 封禁通道）
        known_hosts = str(cfg.get("known_hosts") or "").strip()
        allow_unknown = bool(cfg.get("allow_unknown_host"))
        if known_hosts and os.path.isfile(known_hosts):
            try:
                client.load_host_keys(known_hosts)
            except Exception as e:
                raise RuntimeError(
                    f"SSH known_hosts 加载失败: {known_hosts}: {e}"
                ) from e
        elif not allow_unknown:
            raise RuntimeError(
                "SSH 主机密钥校验失败：known_hosts 不存在 "
                f"({known_hosts or '未配置'})。请先登记目标主机密钥，"
                "或在隔离靶场显式设置 SHARED_MEMORY_FW_SSH_ALLOW_UNKNOWN_HOST=true"
            )
        if allow_unknown:
            logger.warning(
                "SSH 防火墙：allow_unknown_host=True —— 正在接受未登记的主机密钥，"
                "仅限隔离靶场使用"
            )
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # nosec B507
        else:
            client.set_missing_host_key_policy(paramiko.RejectPolicy())

        # v4 修复(2026-09-01):私钥类型自动探测,支持 ED25519/RSA/ECDSA/DSS
        # 之前硬编码 password=cfg["password"],但 SOC 私钥是 ED25519,paramiko 用 password 走不通
        # 优先用 pkey(cfg 里 private_key_path),回退到 password
        pkey = None
        key_path = cfg.get("private_key_path", "")
        if key_path and os.path.isfile(key_path):
            try:
                # paramiko 没有统一 from_private_key_file,按顺序试各种 key 类型
                for key_cls in (paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey, paramiko.DSSKey):
                    try:
                        pkey = key_cls.from_private_key_file(key_path)
                        logger.info(f"SSH firewall: loaded {key_cls.__name__} from {key_path}")
                        break
                    except paramiko.ssh_exception.PasswordRequiredException:
                        logger.warning(f"SSH firewall: {key_path} is encrypted, needs passphrase (not supported)")
                        break
                    except paramiko.ssh_exception.SSHException:
                        continue  # 试下一个 key 类型
            except Exception as e:
                logger.warning(f"SSH firewall: failed to load key {key_path}: {e}")

        # v5 修复:优先用 configure 时缓存的 IP, 绕开每次连接的 DNS 依赖
        connect_host = cfg.get("resolved_ip") or cfg["host"]

        if pkey is not None:
            client.connect(
                hostname=connect_host,
                port=cfg["port"],
                username=cfg["username"],
                pkey=pkey,
                timeout=cfg["connect_timeout"],
                allow_agent=False,
                look_for_keys=False,
            )
        else:
            # 回退到密码登录
            client.connect(
                hostname=connect_host,
                port=cfg["port"],
                username=cfg["username"],
                password=cfg["password"],
                timeout=cfg["connect_timeout"],
                allow_agent=False,
                look_for_keys=False,
            )
        self._client = client
        self._connected = True
        info = self._exec("uname -a; echo '---'; iptables --version 2>/dev/null || echo 'iptables NOT FOUND'", skip_whitelist=True)
        logger.info(f"SSH firewall connected: {cfg['username']}@{cfg['host']}:{cfg['port']}")
        return info

    def close(self):
        """关闭 SSH 连接"""
        if self._client:
            self._client.close()
            self._client = None
            self._connected = False

    def _exec(self, cmd: str, timeout: Optional[int] = None, skip_whitelist: bool = False) -> str:
        """执行命令并返回 stdout（含命令白名单检查）"""
        if self._client is None:
            raise RuntimeError("SSH 未连接，请先调用 connect()")

        # 命令白名单检查
        if not skip_whitelist:
            from .command_whitelist import command_whitelist
            allowed, rule_id, reason = command_whitelist.check(cmd, platform="linux")
            if not allowed:
                raise RuntimeError(f"命令白名单拒绝: {reason} (命令: {cmd[:100]})")

        t = timeout or self._config["exec_timeout"]
        # 最小权限: 仅 iptables/ip6tables 命令加 sudo，nmap/诊断命令不加。
        # `-n`(非交互): sudo 需要密码时立即失败, 而不是挂到 exec 超时。
        if self._config["use_sudo"] and not cmd.startswith("sudo"):
            if (cmd.startswith("iptables") or cmd.startswith("iptables ")
                    or cmd.startswith("ip6tables") or cmd.startswith("ip6tables ")):
                cmd = f"sudo -n {cmd}"
        stdin, stdout, stderr = self._client.exec_command(cmd, timeout=t)  # nosec B601
        out = stdout.read().decode("utf-8", errors="ignore")
        err = stderr.read().decode("utf-8", errors="ignore")
        rc = stdout.channel.recv_exit_status()
        # P0-3: 以退出码为准。修复前仅 `rc!=0 且 stderr 非空` 才抛错 —
        # stderr 为空的失败(如 iptables 规则未写入)被当成功上报, 主结果失真;
        # sudo 密码提示也被 `"password for" not in err` 误判为成功。
        if rc != 0:
            if "password" in err.lower():
                raise RuntimeError(
                    f"sudo 需要交互密码(已按非交互 -n 执行) rc={rc}: {err.strip()[:200]}\n命令: {cmd}"
                )
            raise RuntimeError(
                f"命令执行失败 rc={rc}: {err.strip()[:500] or '(stderr 为空)'}\n命令: {cmd}"
            )
        return out

    # ── 防火墙 API ──

    def run_verify_command(self, cmd: str, timeout: Optional[int] = None) -> dict:
        """执行只读验证命令，返回与 transport 一致的结构。

        post_validator 期望 `exec_fn` 返回 dict（含 stdout），而 `_exec`
        直接返回字符串并在失败时抛异常。这里做一层适配，供 SafeExecutor
        的 verify_fn 使用。
        """
        try:
            out = self._exec(cmd, timeout=timeout)
            return {"success": True, "stdout": out, "stderr": "", "returncode": 0}
        except Exception as e:
            return {
                "success": False,
                "stdout": "",
                "stderr": str(e),
                "returncode": -1,
                "error": str(e),
            }

    def block_ip(self, ip: str, duration: int = 3600, rule_id: str = "") -> dict:
        """按地址族封禁 IP: IPv4→iptables, IPv6→ip6tables(IP 先规范化再拼命令)。

        `rule_id` 可由上层预生成（SafeExecutor 需要它做 TTL 注册）；
        未提供时保持原有的随机生成行为。
        """
        # 参数强校验 + 规范化
        try:
            norm_ip, family = _normalize_ip(ip)
        except ValueError:
            return {"status": "error", "message": f"非法 IP 地址: {ip}"}

        # 核心资产保护
        from .asset_whitelist import asset_whitelist
        is_protected, reason = asset_whitelist.check(ip, "block_ip")
        if is_protected:
            return {"status": "blocked", "message": reason}

        rule_id = str(rule_id or "").strip()
        if rule_id and not re.fullmatch(r"FW-RULE-[0-9]{5,12}", rule_id):
            return {"status": "error", "message": f"非法 rule_id: {rule_id}"}
        rule_id = rule_id or f"FW-RULE-{_new_rule_seq()}"
        table = _table_for(family)
        cmd = f"{table} -I INPUT -s {norm_ip} -j DROP -m comment --comment '{rule_id}'"
        try:
            self._exec(cmd)
        except Exception as e:
            logger.error(f"[Firewall] block {norm_ip} failed on {table}: {e}")
            return {"status": "error", "message": f"{table} 封禁命令执行失败: {e}",
                    "rule_id": rule_id, "ip": norm_ip, "family": family,
                    "command": cmd}
        # 记录规则
        self._active_rules[rule_id] = {
            "ip": norm_ip, "family": family, "duration": duration, "chain": "INPUT",
            "created_at": datetime.now().isoformat(), "status": "active",
        }
        logger.info(f"[Firewall] IP {norm_ip} blocked ({family}): {rule_id}")
        return {
            "status": "success",
            "device": "Linux-iptables-SSH",
            "rule_id": rule_id,
            "ip": norm_ip,
            "family": family,
            "duration": duration,
            "command": cmd,
            "message": f"IP {norm_ip} 已通过 {table} 封禁",
        }

    def isolate_host(self, host: str, isolation_type: str = "network",
                     extra_ips: Optional[list] = None,
                     isolation_id: str = "") -> dict:
        """双栈隔离主机: 每个地址(host + extra_ips)在对应族表写 INPUT -s + OUTPUT -d DROP。

        返回 complete / families_applied / families_missing — 有请求的协议族未全部写入时
        complete=False, 不允许宣称完全隔离。ip6tables 缺失等单族失败会被捕获并标记该族 missing。
        """
        # 参数强校验 + 规范化
        try:
            norm_host, _host_family = _normalize_ip(host)
        except ValueError:
            return {"status": "error", "message": f"非法 IP 地址: {host}"}

        # 核心资产保护
        from .asset_whitelist import asset_whitelist
        is_protected, reason = asset_whitelist.check(host, "isolate_host")
        if is_protected:
            return {"status": "blocked", "message": reason}

        # 收集全部目标地址(host + extra_ips, 去重)并逐个规范化
        seen_norm: set[str] = set()
        targets: list[tuple[str, str]] = []  # (normalized_ip, family)
        for raw in [host] + list(extra_ips or []):
            raw = str(raw or "").strip()
            if not raw:
                continue
            try:
                norm, family = _normalize_ip(raw)
            except ValueError as e:
                return {"status": "error", "message": str(e), "host": host}
            if norm not in seen_norm:
                seen_norm.add(norm)
                targets.append((norm, family))
        if not targets:
            return {"status": "error", "message": "没有可隔离的 IP 地址", "host": host}

        requested_families = sorted({fam for _, fam in targets})
        isolation_id = str(isolation_id or "").strip()
        if isolation_id and not re.fullmatch(r"EDR-ISO-[0-9]{5,12}", isolation_id):
            return {"status": "error", "message": f"非法 isolation_id: {isolation_id}"}
        isolation_id = isolation_id or f"EDR-ISO-{_new_rule_seq()}"
        ok_families: set[str] = set()  # INPUT+OUTPUT 全部写成功的族
        written = 0                    # 成功写入的规则条数
        commands: list[str] = []
        for norm_ip, family in targets:
            table = _table_for(family)
            chain_ok = True
            for chain, flag in (("INPUT", "-s"), ("OUTPUT", "-d")):
                cmd = (f"{table} -I {chain} {flag} {norm_ip} -j DROP "
                       f"-m comment --comment '{isolation_id}'")
                commands.append(cmd)
                try:
                    self._exec(cmd)
                    written += 1
                except Exception as e:
                    chain_ok = False
                    logger.error(f"[Firewall] isolate {norm_ip} {chain} failed on {table}: {e}")
            if chain_ok:
                ok_families.add(family)

        applied = sorted(ok_families)
        missing = sorted(f for f in requested_families if f not in ok_families)
        complete = bool(written) and not missing
        if written:
            self._active_rules[isolation_id] = {
                "host": host, "ip": norm_host, "families": requested_families,
                "families_applied": applied, "families_missing": missing,
                "isolation_type": isolation_type,
                "created_at": datetime.now().isoformat(), "status": "isolated",
            }
            logger.info(f"[Firewall] Host {host} isolated: {isolation_id} "
                        f"(applied={applied} missing={missing})")
        return {
            "status": "success" if written else "error",
            "device": "Linux-iptables-SSH",
            "success": bool(written),
            "complete": complete,
            "families_applied": applied,
            "families_missing": missing,
            "rule_ids": [isolation_id] if written else [],
            "isolation_id": isolation_id,
            "commands": commands,
            "host": host,
            "ip": norm_host,
            "isolation_type": isolation_type,
            "message": (f"主机 {host} 已执行网络隔离 ({'/'.join(applied) or '无'})"
                         if written else f"主机 {host} 隔离失败(未写入任何规则)"),
        }

    def vulnerability_scan(self, target: str, scan_type: str = "fast") -> dict:
        """通过 SSH 在虚拟机执行 nmap 扫描"""
        try:
            check = self._exec("nmap --version")
            if "Nmap" not in check:
                raise RuntimeError("nmap 未安装")
        except Exception:
            return {
                "status": "degraded",
                "device": "Linux-iptables-SSH",
                "target": target,
                "vulnerabilities": [],
                "message": "虚拟机未安装 nmap，扫描降级",
            }
        flags = {"fast": "-T4 -F", "full": "-A -T4", "custom": "-sV"}.get(scan_type, "-T4 -F")
        out = self._exec(f"nmap {flags} {target}", timeout=60)
        open_ports = [ln.strip() for ln in out.splitlines() if "/tcp" in ln and "open" in ln]
        return {
            "status": "success",
            "device": "Linux-iptables-SSH",
            "target": target,
            "scan_type": scan_type,
            "open_ports": open_ports,
            "raw_output": out[:2000],
            "message": f"nmap 扫描完成，发现 {len(open_ports)} 个开放端口",
        }

    _ALREADY_GONE_MARKERS = ("does a matching rule exist", "bad rule")

    def _delete_rule(self, table: str, chain: str, comment: str,
                     src: str = "", dst: str = "") -> tuple[bool, bool]:
        """按匹配(而非行号)删除一条规则, 返回 (deleted, already_gone)。

        P1: 旧实现先列表取行号再 `-D chain <行号>`, 两次 SSH 往返之间若有并发
        插入/删除, 行号偏移会删掉**别人的**规则。按完整匹配(-s/-d + comment)删除
        由 iptables 原子完成, 与并发变更无关。
        首选带 IP 的完整匹配(白名单 LX-006/LX-012); 解析失败时退化为纯 comment 匹配
        (LX-006/LX-012 扩展分支)。规则已被并发删除时按幂等处理(already_gone)。
        """
        comment = comment.replace("'", "")
        if (table, chain) == ("iptables", "INPUT") and re.fullmatch(
                r"\d{1,3}(\.\d{1,3}){3}", src or ""):
            spec = f"-s {src} -j DROP -m comment --comment '{comment}'"
        elif (table, chain) == ("iptables", "OUTPUT") and re.fullmatch(
                r"\d{1,3}(\.\d{1,3}){3}", dst or ""):
            spec = f"-d {dst} -j DROP -m comment --comment '{comment}'"
        elif (table, chain) == ("ip6tables", "INPUT") and re.fullmatch(
                r"[0-9a-fA-F:]+", src or ""):
            spec = f"-s {src} -j DROP -m comment --comment '{comment}'"
        elif (table, chain) == ("ip6tables", "OUTPUT") and re.fullmatch(
                r"[0-9a-fA-F:]+", dst or ""):
            spec = f"-d {dst} -j DROP -m comment --comment '{comment}'"
        else:
            spec = f"-m comment --comment '{comment}'"
        try:
            self._exec(f"{table} -D {chain} {spec}")
            return True, False
        except Exception as e:
            msg = str(e).lower()
            if any(k in msg for k in self._ALREADY_GONE_MARKERS):
                # 列表到删除之间被并发移除 → 幂等, 不算失败
                return False, True
            raise

    def rollback(self, rule_id: str) -> dict:
        """按 rule_id 回滚 — 扫描 iptables+ip6tables × INPUT+OUTPUT, 删除全部匹配注释行。

        修复: 旧实现删除第一个匹配行即 return, 隔离规则(同一 isolation_id 写 INPUT+OUTPUT/
        双族)会残留 OUTPUT 或另一族规则。
        """
        deleted = 0
        deleted_chains: list[str] = []
        queries_ok = 0
        query_errors: list[str] = []
        delete_errors: list[str] = []
        for table in ("iptables", "ip6tables"):
            for chain in ("INPUT", "OUTPUT"):
                try:
                    out = self._exec(f"{table} -L {chain} -n --line-numbers")
                    queries_ok += 1
                except Exception as e:
                    query_errors.append(f"{table}:{chain}: {e}")
                    continue  # 表/链不可用(如未装 ip6tables) → 跳过该族
                matched = 0
                for line in out.splitlines():
                    comment, src, dst = _parse_rule_line(line)
                    if comment != rule_id:
                        continue
                    matched += 1
                    try:
                        ok, already_gone = self._delete_rule(table, chain, comment, src, dst)
                        if ok:
                            deleted += 1
                        elif already_gone:
                            matched -= 1  # 并发已删, 不计入也不报错
                    except Exception as e:
                        delete_errors.append(f"{table}:{chain} [{comment}]: {e}")
                if matched > 0:
                    deleted_chains.append(f"{table}:{chain}")
        if deleted:
            if rule_id in self._active_rules:
                self._active_rules[rule_id]["status"] = "revoked"
            logger.info(f"[Firewall] Rule {rule_id} rolled back: {deleted} lines {deleted_chains}")
            return {"status": "success", "rule_id": rule_id, "deleted": deleted,
                    "deleted_chains": deleted_chains,
                    "idempotent": False,
                    "message": f"规则 {rule_id} 已回滚(删除 {deleted} 条)"}
        # 没删到任何行 ≠ 回滚成功。必须区分三种情况：
        #   ① 查询成功、规则确实不存在 → 幂等成功；
        #   ② 查询成功、但删除失败 → 失败（规则仍在）；
        #   ③ 所有查询都失败（SSH 断/权限）→ 失败（无法确认）。
        if delete_errors:
            return {"status": "error", "rule_id": rule_id, "deleted": 0,
                    "deleted_chains": deleted_chains,
                    "errors": delete_errors[:5],
                    "message": f"规则 {rule_id} 删除失败，仍可能存在"}
        if queries_ok == 0:
            return {"status": "error", "rule_id": rule_id, "deleted": 0,
                    "deleted_chains": [],
                    "errors": query_errors[:5],
                    "message": f"无法查询 iptables/ip6tables，规则 {rule_id} 状态未知"}
        if rule_id in self._active_rules:
            self._active_rules[rule_id]["status"] = "revoked"
        return {"status": "success", "rule_id": rule_id, "deleted": 0,
                "deleted_chains": [], "idempotent": True,
                "message": f"规则 {rule_id} 已回滚(无可删除项, 幂等)"}

    def rollback_all(self) -> dict:
        """回滚所有本演示期间写入的规则 — 双族扫描(iptables + ip6tables) × INPUT/OUTPUT

        P1: 与 rollback 相同, 按匹配删除而非行号, 避免并发下删错规则。
        """
        count = 0
        errors: list[str] = []
        for table in ("iptables", "ip6tables"):
            for chain in ("INPUT", "OUTPUT"):
                try:
                    out = self._exec(f"{table} -L {chain} -n --line-numbers")
                except Exception:
                    continue
                for line in out.splitlines():
                    comment, src, dst = _parse_rule_line(line)
                    if not (comment.startswith("FW-RULE-") or comment.startswith("EDR-ISO-")):
                        continue
                    try:
                        ok, already_gone = self._delete_rule(table, chain, comment, src, dst)
                        if ok:
                            count += 1
                        elif already_gone:
                            count += 1  # 幂等: 视同已清理
                    except Exception as e:
                        errors.append(f"{table}:{chain} [{comment}]: {e}")
        for rid in list(self._active_rules):
            self._active_rules[rid]["status"] = "revoked"
        logger.info(f"[Firewall] Rolled back {count} rules")
        result = {"status": "ok", "rolled_back": count,
                  "message": f"已回滚 {count} 条规则"}
        if errors:
            result["errors"] = errors[:5]
        if count == 0:
            result["idempotent"] = True  # 无规则可清理 = 重复调用, 幂等成功
        return result

    # ── DNS sinkhole ──

    def _sudo(self, cmd: str) -> str:
        """给非 iptables 管理命令按配置加 sudo(_exec 只自动处理 iptables/ip6tables)。"""
        if self._config.get("use_sudo") and not cmd.startswith("sudo"):
            return f"sudo -n {cmd}"
        return cmd

    def sinkhole_domain(self, domain: str, ipv4: Optional[str] = None,
                        ipv6: Optional[str] = None, marker_id: str = "") -> dict:
        """把恶意域名指向黑洞 IP(装了 dnsmasq → drop-in 配置; 否则追加 /etc/hosts)。

        ⚠ skip_whitelist 豁免仅限本方法与 unsinkhole_domain: 所有命令由常量模板 +
        经严格校验的 domain(_DOMAIN_RE) / IP(ipaddress) / marker(_MARKER_RE) 拼装,
        不接受任何含用户自由文本的命令串, 也不会把 skip_whitelist 暴露给外部调用方。
        """
        d = str(domain or "").strip()
        marker_id = str(marker_id or "").strip()
        if not self._connected:
            return {"status": "error", "success": False, "mode": "unconfigured",
                    "domain": d, "marker_id": marker_id, "backend": "unconfigured",
                    "message": "SSH 防火墙未连接"}
        if not _DOMAIN_RE.match(d) or len(d) > 253 or ".." in d:
            return {"status": "error", "success": False, "mode": "invalid",
                    "domain": d, "marker_id": marker_id, "backend": "unconfigured",
                    "message": f"非法域名: {domain!r}"}
        if not _MARKER_RE.match(marker_id):
            marker_id = f"SOC-SH-{hashlib.sha1(d.encode('ascii'), usedforsecurity=False).hexdigest()[:10].upper()}"
        # IP 规范化; v4-mapped IPv6 不能作真实 AAAA/主机条目, 只参与 IPv4 语义
        try:
            v4_norm = _normalize_ip(ipv4)[0] if ipv4 else ""
            v6_raw = _normalize_ip(ipv6)[0] if ipv6 else ""
        except ValueError as e:
            return {"status": "error", "success": False, "mode": "invalid",
                    "domain": d, "marker_id": marker_id, "backend": "unconfigured",
                    "message": str(e)}
        v6_native = ""
        if v6_raw:
            try:
                a6 = ipaddress.ip_address(v6_raw)
                v6_native = v6_raw if a6.ipv4_mapped is None else ""
            except ValueError:
                v6_native = ""
        if not v4_norm and not v6_native:
            return {"status": "error", "success": False, "mode": "invalid",
                    "domain": d, "marker_id": marker_id, "backend": "unconfigured",
                    "message": "没有可用的黑洞 IP(ipv4/ipv6)"}

        try:
            probe = self._exec("test -x /usr/sbin/dnsmasq && echo DNSMASQ_OK || echo NO_DNSMASQ",
                               skip_whitelist=True)
        except Exception:
            probe = ""

        try:
            if "DNSMASQ_OK" in probe:
                backend = "dnsmasq"
                conf = f"/etc/dnsmasq.d/soc-sinkhole-{marker_id}.conf"
                lines = []
                if v4_norm:
                    lines.append(f"address=/{d}/{v4_norm}")
                if v6_native:
                    lines.append(f"address=/{d}/{v6_native}")
                args = " ".join(f"'{ln}'" for ln in lines)
                write_cmd = f"printf '%s\\n' {args} | {self._sudo(f'tee {conf}')}"
                self._exec(write_cmd, skip_whitelist=True)
                # 生效需重启/重载 dnsmasq; 失败仅告警, drop-in 下次启动即生效
                try:
                    self._exec(self._sudo("pkill -HUP dnsmasq"), skip_whitelist=True)
                except Exception:
                    logger.warning(f"[Firewall] dnsmasq reload failed for {d} (drop-in saved)")
            else:
                backend = "hosts"
                lines = []
                if v4_norm:
                    lines.append(f"{v4_norm} {d} # {marker_id}")
                if v6_native:
                    lines.append(f"{v6_native} {d} # {marker_id}")
                # 幂等: 同 marker 已存在则跳过
                try:
                    hosts = self._exec("cat /etc/hosts", skip_whitelist=True)
                except Exception:
                    hosts = ""
                if marker_id not in hosts:
                    args = " ".join(f"'{ln}'" for ln in lines)
                    append_cmd = f"printf '%s\\n' {args} | {self._sudo('tee -a /etc/hosts')}"
                    self._exec(append_cmd, skip_whitelist=True)
        except Exception as e:
            logger.error(f"[Firewall] sinkhole {d} write failed: {e}")
            return {"status": "error", "success": False, "mode": "error",
                    "domain": d, "marker_id": marker_id, "backend": "unconfigured",
                    "message": f"sinkhole 写入失败: {e}"}

        logger.info(f"[Firewall] DNS sinkhole {d} -> {backend} ({marker_id})")
        return {"status": "success", "success": True, "mode": "live",
                "domain": d, "marker_id": marker_id, "backend": backend,
                "message": f"DNS sinkhole {d} 已写入 {backend} (marker={marker_id})"}

    def unsinkhole_domain(self, domain: str = "", marker_id: str = "") -> dict:
        """撤销 DNS sinkhole: 按 marker 删 /etc/hosts 行 + dnsmasq drop-in 文件。

        ⚠ 同 sinkhole_domain 的 skip_whitelist 豁免说明; 命令恒为常量模板 + 已校验参数。
        """
        d = str(domain or "").strip()
        marker_id = str(marker_id or "").strip()
        if not self._connected:
            return {"status": "error", "success": False, "mode": "unconfigured",
                    "domain": d, "marker_id": marker_id, "backend": "unconfigured",
                    "message": "SSH 防火墙未连接"}
        if d and (not _DOMAIN_RE.match(d) or len(d) > 253 or ".." in d):
            return {"status": "error", "success": False, "mode": "invalid",
                    "domain": d, "marker_id": marker_id, "backend": "unconfigured",
                    "message": f"非法域名: {domain!r}"}
        if not _MARKER_RE.match(marker_id):
            if not d:
                return {"status": "error", "success": False, "mode": "invalid",
                        "domain": d, "marker_id": marker_id, "backend": "unconfigured",
                        "message": "缺少 marker_id 或 domain"}
            marker_id = f"SOC-SH-{hashlib.sha1(d.encode('ascii'), usedforsecurity=False).hexdigest()[:10].upper()}"
        done: list[str] = []
        try:
            self._exec(self._sudo(f"sed -i '/{marker_id}/d' /etc/hosts"), skip_whitelist=True)
            done.append("hosts")
        except Exception as e:
            logger.warning(f"[Firewall] unsinkhole hosts cleanup failed: {e}")
        try:
            conf = f"/etc/dnsmasq.d/soc-sinkhole-{marker_id}.conf"
            self._exec(self._sudo(f"rm -f {conf}"), skip_whitelist=True)
            done.append("dnsmasq")
        except Exception as e:
            logger.warning(f"[Firewall] unsinkhole dnsmasq cleanup failed: {e}")
        if not done:
            return {"status": "error", "success": False, "mode": "error",
                    "domain": d, "marker_id": marker_id, "backend": "unconfigured",
                    "message": "unsinkhole 清理命令全部失败"}
        logger.info(f"[Firewall] DNS unsinkhole {d or marker_id} cleaned={done}")
        return {"status": "success", "success": True, "mode": "live",
                "domain": d, "marker_id": marker_id,
                "backend": "dnsmasq" if "dnsmasq" in done else "hosts",
                "cleaned": done,
                "message": f"DNS sinkhole 已撤销 ({d or marker_id})"}

    def list_rules(self) -> dict:
        """查询虚拟机 iptables 规则"""
        try:
            out = self._exec("iptables -L INPUT -n --line-numbers")
            return {"status": "ok", "rules_output": out}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def health_check(self) -> dict:
        """健康检查"""
        try:
            hostname = self._exec("uname -n").strip()
            uptime = self._exec("uptime").strip()
            return {
                "status": "ok",
                "device": "Linux-iptables-SSH",
                "host": self._config["host"],
                "info": f"{hostname}\n{uptime}",
                "active_rules": len([r for r in self._active_rules.values() if r["status"] in _ACTIVE_STATUSES]),
                "time": datetime.now().isoformat(),
            }
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def get_active_rules(self) -> list[dict]:
        """获取所有未撤销规则(status ∈ active/isolated/applied)。

        修复: 隔离记录 status='isolated', 旧实现只滤 active 导致 _restore_host 永远找不到。
        """
        return [
            {"rule_id": rid, **info}
            for rid, info in self._active_rules.items()
            if info.get("status") in _ACTIVE_STATUSES
        ]

    async def get_active_rules_async(self) -> list[dict]:
        """内存台账 + Redis TTL 索引合并视图。

        P1: 台账纯内存, 进程重启后远端 iptables 规则仍在但平台找不到也解不了
        (成孤儿规则)。TTL 索引(soc:ttl:*)是持久的 — 合并后 unblock/restore/
        运维视图在重启后仍能看到并回滚这些规则。内存记录优先。
        """
        rules = self.get_active_rules()
        seen = {r.get("rule_id") for r in rules}
        try:
            from .ttl_manager import ttl_manager
            ttl_entries = await ttl_manager.list_active()
        except Exception as e:
            logger.debug("TTL index merge skipped: %s", e)
            ttl_entries = []
        for item in ttl_entries:
            rid = str(item.get("rule_id") or "")
            if not rid or rid in seen:
                continue
            params = item.get("params") or {}
            rules.append({
                "rule_id": rid,
                "ip": params.get("src_ip", ""),
                "host": params.get("host_ip", ""),
                "status": "active" if item.get("action_name") == "block_ip" else "isolated",
                "action_name": item.get("action_name", ""),
                "expires_at": item.get("expires_at", 0),
                "source": "ttl_index",
            })
            seen.add(rid)
        return rules

    # ── 异步包装器（避免阻塞事件循环） ──

    async def async_connect(self) -> str:
        return await asyncio.to_thread(self.connect)

    async def async_block_ip(self, ip: str, duration: int = 3600) -> dict:
        return await asyncio.to_thread(self.block_ip, ip, duration)

    async def async_isolate_host(self, host: str, isolation_type: str = "network",
                                 extra_ips: Optional[list] = None) -> dict:
        return await asyncio.to_thread(self.isolate_host, host, isolation_type, extra_ips)

    async def async_vulnerability_scan(self, target: str, scan_type: str = "fast") -> dict:
        return await asyncio.to_thread(self.vulnerability_scan, target, scan_type)


# 全局单例
ssh_firewall = SshFirewallAdapter()
