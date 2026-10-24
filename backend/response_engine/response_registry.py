"""
响应动作注册表 (Response Registry)

管理所有可用的响应动作及其定义。
每个动作是一个异步函数，支持回滚。

注册的动作:
  - block_ip        封禁源IP (通过 Windows 防火墙)
  - unblock_ip      解封IP (回滚)
  - isolate_host    隔离主机 (防火墙全阻断)
  - restore_host    恢复主机 (回滚)
  - rate_limit      对IP限速 (通过 QoS 策略)
  - remove_rate_limit 取消限速 (回滚)
  - kill_session    终止用户会话 (RDP/本地)
  - send_alert      发送告警通知

执行模式:
  - stub:  模拟执行，只打日志
  - ssh:   通过 SSH 在 Windows 宿主机执行真实命令
  - auto:  优先 SSH，失败回退 stub

配置 (config.py):
  RESPONSE_TRANSPORT_MODE=auto|stub|ssh
  RESPONSE_SSH_HOST=192.168.1.1
  RESPONSE_SSH_USER=administrator
  RESPONSE_SSH_KEY_FILE=/root/.ssh/id_rsa
"""
import asyncio
import base64
import hashlib
import ipaddress
import logging
import re
import secrets
from dataclasses import dataclass, field
from typing import Callable, Coroutine, Optional
from urllib.parse import urlsplit

from config import settings
from .transport import ssh_transport

logger = logging.getLogger(__name__)


# ── 危险等级 ──

ACTION_SEVERITY_LOW = "low"
ACTION_SEVERITY_MEDIUM = "medium"
ACTION_SEVERITY_HIGH = "high"
ACTION_SEVERITY_CRITICAL = "critical"

# 自动执行阈值：低于此等级的可自动执行，高于此等级需审批
AUTO_EXECUTE_THRESHOLD = {
    ACTION_SEVERITY_LOW: True,
    ACTION_SEVERITY_MEDIUM: True,
    ACTION_SEVERITY_HIGH: False,      # high 需审批
    ACTION_SEVERITY_CRITICAL: False,  # critical 需审批
}

# 是否需要审批的危险等级集合
APPROVAL_REQUIRED = {ACTION_SEVERITY_HIGH, ACTION_SEVERITY_CRITICAL}


@dataclass
class ResponseActionDef:
    """响应动作定义"""
    name: str
    description: str
    severity: str                     # 危险等级
    category: str                     # "network" | "host" | "session" | "notification"
    reversible: bool                  # 是否可回滚
    timeout_ms: int = 30000           # 执行超时
    rollback_fn: Optional[Callable] = None  # 回滚函数
    params_schema: dict = field(default_factory=dict)  # 参数JSON Schema


class ResponseRegistry:
    """响应动作注册表"""

    def __init__(self):
        self._actions: dict[str, ResponseActionDef] = {}
        self._exec_fns: dict[str, Callable[..., Coroutine]] = {}
        self._rollback_fns: dict[str, Callable[..., Coroutine]] = {}

    def register(
        self,
        name: str,
        exec_fn: Callable[..., Coroutine],
        description: str,
        severity: str = ACTION_SEVERITY_MEDIUM,
        category: str = "network",
        reversible: bool = True,
        timeout_ms: int = 30000,
        rollback_fn: Optional[Callable[..., Coroutine]] = None,
        params_schema: Optional[dict] = None,
    ):
        """注册一个响应动作"""
        self._actions[name] = ResponseActionDef(
            name=name,
            description=description,
            severity=severity,
            category=category,
            reversible=reversible,
            timeout_ms=timeout_ms,
            rollback_fn=rollback_fn,
            params_schema=params_schema or {},
        )
        self._exec_fns[name] = exec_fn
        if rollback_fn:
            self._rollback_fns[name] = rollback_fn
        logger.info(
            f"Registered response action: {name} "
            f"(severity={severity}, category={category}, "
            f"reversible={reversible})"
        )

    def get_action(self, name: str) -> Optional[ResponseActionDef]:
        return self._actions.get(name)

    def list_actions(self, category: str = "") -> list[ResponseActionDef]:
        if category:
            return [a for a in self._actions.values() if a.category == category]
        return list(self._actions.values())

    async def execute(self, name: str, **kwargs) -> dict:
        """执行动作，返回 {success, result, rollback_token}

        幂等检查已移至 SafeExecutor（Redis 持久化），此处不再做内存幂等。
        """
        action = self._actions.get(name)
        if not action:
            raise ValueError(f"Unknown action: {name}")

        fn = self._exec_fns.get(name)
        if not fn:
            raise ValueError(f"No executor for action: {name}")

        try:
            import asyncio
            result = await asyncio.wait_for(fn(**kwargs), timeout=action.timeout_ms / 1000)
            rollback_token = f"rb_{name}_{kwargs.get('src_ip', kwargs.get('target', 'unknown'))}_{int(__import__('time').time())}"
            inner_ok = True
            if isinstance(result, dict):
                # P0-2: 桩回退(未真实执行)一律按失败上报, 不虚报成功
                if result.get("success") is False or result.get("_stub"):
                    inner_ok = False
            logger.info(f"Action {name} executed: {str(result)[:100]}")
            return {
                "success": inner_ok,
                "result": result,
                "rollback_token": rollback_token,
            }
        except asyncio.TimeoutError:
            # P1: wait_for 超时不会终止 to_thread 里的 SSH — 远端规则可能**已经写入**。
            # 上报 outcome=unknown 而不是普通失败, SafeExecutor 据此保留幂等占位锁,
            # 防止告警重放触发重复封禁。
            logger.error(
                f"Action {name} timed out after {action.timeout_ms}ms — "
                f"outcome unknown (remote side-effect possible)"
            )
            return {
                "success": False,
                "outcome": "unknown",
                "timed_out": True,
                "error": f"timeout after {action.timeout_ms}ms (结果未知, 远端副作用可能已发生)",
            }
        except Exception as e:
            logger.error(f"Action {name} failed: {e}")
            return {"success": False, "error": str(e)}

    async def rollback(self, name: str, **kwargs) -> dict:
        """回滚动作"""
        fn = self._rollback_fns.get(name)
        if not fn:
            return {"success": False, "error": f"No rollback for action: {name}"}
        try:
            result = await fn(**kwargs)
            logger.info(f"Rollback {name}: {str(result)[:100]}")
            return {"success": True, "result": result}
        except Exception as e:
            logger.error(f"Rollback {name} failed: {e}")
            return {"success": False, "error": str(e)}

    def needs_approval(self, name: str) -> bool:
        """该动作是否需要审批"""
        action = self._actions.get(name)
        if not action:
            return True  # 未知动作，保守处理
        return action.severity in APPROVAL_REQUIRED


response_registry = ResponseRegistry()


# ── 动作分级辅助（审批分级强制用）──

_SEVERITY_ORDER = [
    ACTION_SEVERITY_LOW,
    ACTION_SEVERITY_MEDIUM,
    ACTION_SEVERITY_HIGH,
    ACTION_SEVERITY_CRITICAL,
]


def max_action_severity(actions: list) -> str:
    """返回动作列表中的最高危险等级（未知动作按 CRITICAL 保守处理）"""
    best = ACTION_SEVERITY_LOW
    for act in actions or []:
        name = act.get("name", "") if isinstance(act, dict) else ""
        action_def = response_registry.get_action(name)
        sev = action_def.severity if action_def else ACTION_SEVERITY_CRITICAL
        if _SEVERITY_ORDER.index(sev) > _SEVERITY_ORDER.index(best):
            best = sev
    return best


def has_critical_action(actions: list) -> bool:
    """动作列表中是否包含 CRITICAL 级动作。

    CRITICAL 动作（如 isolate_host）无论策略 auto_execute 与否，
    一律必须人工审批；HIGH 动作（如 block_ip）允许策略显式豁免。
    """
    return max_action_severity(actions) == ACTION_SEVERITY_CRITICAL


# ════════════════════════════════════════════
# 输入验证工具函数
# ════════════════════════════════════════════

def _validate_ip(value: str) -> str:
    """验证并规范化 IP 地址，防止命令注入"""
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        raise ValueError(f"Invalid IP address: {value}")

def _validate_alphanumeric(value: str, max_len: int = 128) -> str:
    """仅允许字母数字和有限安全字符"""
    if not value:
        return value
    sanitized = re.sub(r'[^a-zA-Z0-9_\.\-\:\/\ ]', '', value)
    if len(sanitized) > max_len:
        sanitized = sanitized[:max_len]
    return sanitized

def _sanitize_powershell_string(value: str) -> str:
    """转义 PowerShell 字符串中的危险字符"""
    if not value:
        return value
    return value.replace('`', '``').replace('"', '`"').replace('$', '`$').replace('\n', ' ').replace('\r', ' ')

def _validate_positive_int(value: int, name: str = "value") -> int:
    if not isinstance(value, int) or value < 0:
        raise ValueError(f"{name} must be a positive integer, got {value}")
    return value

def _validate_domain(domain: str, max_len: int = 253) -> str:
    """域名强校验: 仅字母/数字/连字符/点, ≤253, 无路径/空格(dns_sinkhole 参数)。"""
    d = str(domain or "").strip()
    if not d:
        raise ValueError("domain 不能为空")
    if len(d) > max_len:
        raise ValueError(f"domain 长度超限 ({len(d)} > {max_len})")
    if not re.fullmatch(r"[A-Za-z0-9.\-]+", d):
        raise ValueError(f"domain 含非法字符: {domain!r}")
    if ".." in d or d.startswith(("-", ".")) or d.endswith(("-", ".")):
        raise ValueError(f"domain 格式非法: {domain!r}")
    return d

def _families_for(host_ip: str, extra: Optional[list] = None) -> list:
    """host_ip + extra_ips → 去重排序的协议族列表(供 mock/dry_run 结果用)。"""
    fams = []
    for raw in [host_ip] + list(extra or []):
        raw = str(raw or "").strip()
        if not raw:
            continue
        addr = ipaddress.ip_address(raw)
        f = "ipv6" if addr.version == 6 else "ipv4"
        if f not in fams:
            fams.append(f)
    return sorted(fams)

def _marker_for_domain(domain: str) -> str:
    """域名 → 确定性 sinkhole marker(SOC-SH-<sha1 前 10 位>) — 回滚无需额外状态。"""
    import hashlib as _h
    return f"SOC-SH-{_h.sha1(domain.encode('ascii'), usedforsecurity=False).hexdigest()[:10].upper()}"

def _same_host(record_ip: str, target: str) -> bool:
    """记录里的 host/ip 与目标是否同一地址(先字符串相等, 再按 ipaddress 规范化比较)。"""
    record_ip = str(record_ip or "").strip()
    target = str(target or "").strip()
    if not record_ip or not target:
        return False
    if record_ip == target:
        return True
    try:
        return ipaddress.ip_address(record_ip) == ipaddress.ip_address(target)
    except ValueError:
        return False

def _execution_mode() -> str:
    """读取 config.execution_mode(live|dry_run|mock)。

    直连 ssh_firewall 的动作(block_ip/isolate_host/dns_sinkhole)不走 SafeExecutor,
    需自行按模式路由: mock/dry_run 不建立 SSH、不执行, 返回带 mode 标签的结果。

    PR2: 预览(preview_mode ContextVar)优先 — 预览请求内强制 dry_run,
    不改变全局 execution_router.mode。
    """
    try:
        from .preview import preview_mode
        if preview_mode.get():
            return "dry_run"
    except Exception:
        pass
    return getattr(settings, "execution_mode", "live") or "live"

async def _ensure_firewall_connected() -> Optional[str]:
    """确保 ssh_firewall 已配置并连接; 返回 None=就绪, 否则错误信息。"""
    from .ssh_firewall import ssh_firewall
    if ssh_firewall._connected and ssh_firewall._config.get("host"):
        return None
    try:
        from config import settings as _s
        if not ssh_firewall._config.get("host"):
            ssh_firewall.configure(
                host=_s.fw_ssh_host, port=_s.fw_ssh_port,
                username=_s.fw_ssh_user, password=_s.fw_ssh_password,
                use_sudo=_s.fw_use_sudo,
                known_hosts=getattr(_s, "fw_ssh_known_hosts", ""),
                allow_unknown_host=getattr(_s, "fw_ssh_allow_unknown_host", False),
            )
        if not ssh_firewall._connected:
            await asyncio.to_thread(ssh_firewall.connect)
        return None
    except Exception as ce:
        logger.error(f"ssh_firewall auto-connect failed: {ce}")
        return str(ce)

def _auto_unblock_info(
    action: str,
    rule_ids: str,
    duration_minutes: int,
    *,
    mechanism: str = "in_process_task",
    restart_survives: bool = False,
) -> dict:
    """自动解封的**机制与局限**（整改报告 §9.53）。

    这段信息要跟着动作结果落进 `response_logs` —— 运维看得到
    「这次封禁靠的是 Redis TTL（扛重启）还是进程内定时任务（不扛重启）」。
    """
    scheduled = bool(rule_ids) and duration_minutes > 0
    if scheduled and mechanism == "redis_ttl":
        note = (
            "自动解封由 Redis TTL + 后台扫描器驱动，进程重启后仍会执行；"
            "若 Redis 不可用，TTL 注册会失败并回退为进程内任务（此时不扛重启）。"
        )
    elif scheduled:
        note = (
            "自动解封是**进程内**的定时任务；进程重启 / 发布 / 崩溃会导致这次"
            "自动解封**静默丢失**（规则将一直留存）—— 整改报告 §9.53。"
        )
    else:
        note = "本次未调度自动解封"
    return {
        "scheduled": scheduled,
        "mechanism": mechanism if scheduled else "",
        "restart_survives": bool(restart_survives and scheduled),
        "duration_minutes": duration_minutes,
        "rule_ids": rule_ids,
        "note": note,
    }


def _record_auto_unblock_scheduled(action: str) -> None:
    """记录一次「自动解封已调度」（用的是扛不住重启的机制）→ §9.53。"""
    try:
        from core_metrics import record_auto_unblock_scheduled
        record_auto_unblock_scheduled(action)
    except Exception:
        pass


async def _auto_rollback(rule_id: str, delay_seconds: int, label: str) -> None:
    """延时后按 rule_id 回滚(隔离 TTL / 封禁 TTL 共用)。"""
    try:
        await asyncio.sleep(delay_seconds)
        from .ssh_firewall import ssh_firewall
        rb = await asyncio.to_thread(ssh_firewall.rollback, rule_id)
        logger.info(f"[auto-rollback] {label} rule_id={rule_id}: {rb.get('status')}")
    except Exception as e:
        logger.error(f"[auto-rollback] {label} rule_id={rule_id} failed: {e}")


async def ttl_rollback(rule_id: str, action_name: str, params: dict) -> dict:
    """TTL 管理器的回滚回调：只负责按 rule_id 删除真实规则。

    与进程内 `_auto_rollback` 的区别：该回调由 Redis 持久化索引驱动，
    进程重启后仍会被 `ttl_manager` 扫描到并执行。
    """
    from .ssh_firewall import ssh_firewall
    try:
        rb = await asyncio.to_thread(ssh_firewall.rollback, rule_id)
        return {
            "success": rb.get("status") == "success",
            "rule_id": rule_id,
            "action": action_name,
            "detail": rb,
        }
    except Exception as e:
        logger.error(f"[ttl-rollback] {rule_id} ({action_name}) failed: {e}")
        return {"success": False, "rule_id": rule_id, "action": action_name, "error": str(e)}

# ════════════════════════════════════════════
# 响应动作实现 (真实执行 + 桩回退)
# ════════════════════════════════════════════

def _mode() -> str:
    """获取当前执行模式"""
    return getattr(settings, "response_transport_mode", "auto")


async def _stub_fallback(action: str, reason: str = "", **fields) -> dict:
    """SSH 不可用（或命令被拒）时的桩回退。

    ⚠ `reason` 必须带上**真实原因**（整改方案 §9.45）：
    修复前这里写死一句「SSH transport requires RESPONSE_SSH_HOST config」——
    而实际卡点可能是**命令白名单拒绝**（平台没把 platform 转发给 transport），
    运维照着这句话去查 SSH 配置会**完全走错方向**。

    桩回退**不执行任何动作**，但它**必须说清为什么没执行**。
    """
    if not reason:
        reason = "SSH transport not configured"
    logger.warning(
        f"[STUB] {action} would execute: {fields} (reason: {reason})"
    )
    # P0-2: 桩回退**没有执行任何动作**, 必须如实上报失败。
    # 修复前不带 success 键, execute() 只判 `success is False` → 桩被当成执行成功,
    # 策略冷却/审计/动作日志全部失真(运维以为已处置, 实际什么都没发生)。
    return {"action": action, "mode": "stub", "_stub": True, **fields,
            "success": False, "reason": reason}


def _ps_cmd(script: str) -> str:
    """将 PowerShell 脚本编码为 Base64 单行命令，避免引号转义问题"""
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    return f"powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand {encoded}"


async def _exec(cmd: str, action: str, platform: str = "windows", **fields) -> dict:
    """
    统一执行入口 — 通过 SafeExecutor 安全层路由

    安全检查链: 命令白名单 → 参数校验 → 资产保护 → 幂等 → 模式路由 → 执行 → 验证

    platform 参数(2026-09-01 v4 修复):
      - "windows" (默认): 保留原 netsh / PowerShell 行为,向后兼容
      - "linux": 触发 LINUX_RULES 白名单(iptables),用于 soc-firewall 等 Linux 目标
    """
    from .safe_executor import safe_executor

    # 提取 TTL 和 rule_id 参数（如果动作函数传入了）
    ttl_seconds = fields.pop("_ttl_seconds", 0)
    rule_id = fields.pop("_rule_id", "")

    async def _live_fn(command: str) -> dict:
        """真实 SSH 执行（保留原有 stub 回退逻辑）

        ⚠ **platform 必须转发**（整改方案 §9.45）：
        修复前这里是 `ssh_transport.run(command, powershell=use_powershell)`
        —— **没传 platform**，于是 `transport.run()` 用它自己的默认值
        `platform="linux"` 去查白名单。而本路径的命令是 **windows** 形态
        （`_ps_cmd()` 已 Base64 编码），linux 规则里**没有任何一条能匹配**
        → **每一个 Windows 响应动作都被白名单拒绝**。

        实测（修复前）：
            第一道（safe_executor, platform="windows"）→ allowed, WIN-004 ✓
            第二道（transport.run,  platform="linux"）  → REJECTED ✗
        → auto 模式下退化成桩，且拒绝原因被换成
          「SSH transport requires RESPONSE_SSH_HOST config」（**误导**）。

        ⚠ `powershell` 必须是 **False**：命令**已经是** `_ps_cmd()` 产出的
        最终形态（`powershell -NoProfile ... -EncodedCommand <b64>`），
        再让 transport 编码一次会变成**双层** powershell ——
        内层脚本的 `exit N` 会被外层吞掉，**失败的动作会被报成 success**。
        单层时，远端执行的就是被白名单校验过的那条命令。
        """
        mode = _mode()
        reason = ""
        if mode == "ssh" or (mode == "auto" and ssh_transport.enabled):
            result = await ssh_transport.run(
                command, powershell=False, platform=platform,
            )
            if result["success"]:
                logger.info(f"[SSH/{platform}] {action} OK: {result['stdout'][:100]}")
                return {"action": action, "mode": "ssh", **fields, **result}
            # ⚠ 白名单拒绝时 `stderr` 是**空串**，只用它会把原因打成空
            reason = result.get("error") or result.get("stderr") or ""
            if mode == "ssh":
                logger.error(f"[SSH/{platform}] {action} FAILED: {reason[:200]}")
                return {"action": action, "mode": "ssh", "success": False, **fields, **result}
            logger.warning(
                f"[SSH/{platform}] {action} failed, fallback to stub: {reason[:150]}"
            )
        return await _stub_fallback(action, reason=reason, **fields)

    return await safe_executor.execute(
        action_name=action,
        command=cmd,
        params=fields,
        platform=platform,
        live_fn=_live_fn,
        ttl_seconds=ttl_seconds,
        rule_id=rule_id,
        # 预览模式必须对**所有**动作生效，不只 block/isolate/sinkhole。
        # 之前 _exec 未传 mode_override，kill_session/rate_limit 等仍按 live 执行。
        mode_override=_execution_mode(),
    )


# ── 1. block_ip / unblock_ip (Linux iptables) ──
# v4 修复(2026-09-01):目标 soc-firewall 是 alpine Linux,改用 iptables
# 旧实现用 netsh advfirewall(Windows 命令),在 Linux 上 exit 127 + stub fallback 假装成功
#
# v4.1 修复(2026-09-01):走 ssh_firewall.SshFirewallAdapter (paramiko) 而不是 transport.ssh_transport
# 原因:Docker 9p bind mount 在 uvicorn 进程 namespace 不可见,transport.ssh_transport 永远走 stub
# ssh_firewall 用 paramiko + /api/firewall/connect 已在容器内真验证可连 soc-firewall

async def _block_ip(src_ip: str, reason: str = "", duration_minutes: int = 60, **kwargs) -> dict:
    """
    封禁源IP — 按地址族走 ssh_firewall(IPv4→iptables INPUT, IPv6→ip6tables INPUT)。

    2026-10-21：**所有**真实封禁都必须经过 SafeExecutor 的检查链
    （命令白名单 / 参数校验 / 资产保护 / Redis 幂等 / 模式路由 /
    post-validator / TTL 注册）。此前本函数直连 ssh_firewall，
    导致 high 级动作可被 operator 绕过审批、无幂等保护、无后置验证。

    TTL 优先用 Redis（`ttl_manager`，可跨进程重启）；仅当 Redis 不可用
    时才回退到进程内 `create_task`，并在返回值中如实标注“不扛重启”。
    """
    src_ip = _validate_ip(src_ip)
    duration_minutes = _validate_positive_int(duration_minutes, "duration_minutes")
    try:
        addr = ipaddress.ip_address(src_ip)
    except ValueError as e:
        return {"action": "block_ip", "success": False, "mode": "invalid",
                "error": str(e), "src_ip": src_ip}
    norm_ip = str(addr)
    family = "ipv6" if addr.version == 6 else "ipv4"
    table = "ip6tables" if family == "ipv6" else "iptables"
    rule_id = f"FW-RULE-{secrets.randbelow(10 ** 10):010d}"
    rule_name = f"RE_Block_{norm_ip.replace('.', '_').replace(':', '_')}"
    command = (
        f"{table} -I INPUT -s {norm_ip} -j DROP "
        f"-m comment --comment '{rule_id}'"
    )

    from .safe_executor import safe_executor
    from .ssh_firewall import ssh_firewall

    params: dict = {
        "src_ip": norm_ip,
        "duration_minutes": duration_minutes,
        "rule_id": rule_id,
        "rule_name": rule_name,
    }
    for key in ("event_id", "eventId", "grounding_score"):
        if kwargs.get(key) is not None:
            params[key] = kwargs[key]

    async def _live_fn(_cmd: str) -> dict:
        err = await _ensure_firewall_connected()
        if err:
            return {
                "success": False, "mode": "error", "action": "block_ip",
                "src_ip": norm_ip, "rule_name": rule_name,
                "error": f"ssh_firewall connect failed: {err}",
            }
        # paramiko 是同步库；放在线程里，避免 SSH 延迟阻塞事件循环。
        fw_result = await asyncio.to_thread(
            ssh_firewall.block_ip,
            norm_ip, duration=duration_minutes * 60, rule_id=rule_id,
        )
        success = fw_result.get("status") == "success"
        return {
            "action": "block_ip",
            "success": success,
            "mode": "ssh_firewall_paramiko",
            "src_ip": norm_ip,
            "duration_minutes": duration_minutes,
            "rule_name": rule_name,
            "firewall_rule_id": fw_result.get("rule_id", rule_id),
            "family": fw_result.get("family", family),
            "detail": fw_result,
        }

    async def _verify_fn(cmd: str) -> dict:
        # post_validator 会传只读查询命令；不能复用 _live_fn（否则会再次封禁）。
        return await asyncio.to_thread(ssh_firewall.run_verify_command, cmd)

    ttl_seconds = duration_minutes * 60
    result = await safe_executor.execute(
        action_name="block_ip",
        command=command,
        params=params,
        platform="linux",
        live_fn=_live_fn,
        ttl_seconds=ttl_seconds,
        rule_id=rule_id,
        verify_fn=_verify_fn,
        idempotency_key=f"soc:idem:block_ip:{norm_ip}:{duration_minutes}",
        # duration=0（永久封禁）只做 5 分钟短去重；否则手动解封后 24h 内
        # 真实再攻击会被 idempotent_skip 静默放过。
        idempotency_ttl=(ttl_seconds if ttl_seconds > 0 else 300),
        mode_override=_execution_mode(),
    )

    mode = result.get("mode", "")
    if mode in ("dry_run", "mock", "idempotent_skip"):
        result.setdefault("action", "block_ip")
        result.setdefault("src_ip", norm_ip)
        result.setdefault("duration_minutes", duration_minutes)
        result.setdefault("rule_name", rule_name)
        result.setdefault("family", family)
        if mode == "dry_run":
            result.setdefault("would_execute", True)
            result.setdefault("firewall_rule_id", f"FW-RULE-MOCK-{sum(map(ord, norm_ip)) % 100000}")
        elif mode == "mock":
            result.setdefault("firewall_rule_id", rule_id)
        if mode == "idempotent_skip":
            result["auto_unblock"] = {
                "scheduled": True,
                "mechanism": "idempotent_skip",
                "restart_survives": True,
                "duration_minutes": duration_minutes,
                "rule_ids": rule_id,
                "note": "同一目标/时长的封禁已存在，本次未重复执行；TTL 沿用首次注册。",
            }
        else:
            result["auto_unblock"] = _auto_unblock_info("block_ip", "", 0)
        return result

    # live 结果：SafeExecutor 已在执行成功且 ttl_seconds>0 时注册 Redis TTL。
    if result.get("success") and duration_minutes > 0:
        if result.get("ttl_registered"):
            result["auto_unblock"] = _auto_unblock_info(
                "block_ip", rule_id, duration_minutes,
                mechanism="redis_ttl", restart_survives=True,
            )
            _record_auto_unblock_scheduled("block_ip")
            logger.info(
                f"[block_ip] auto-unblock registered in Redis for {norm_ip} "
                f"in {duration_minutes}min (rule_id={rule_id})"
            )
        else:
            # Redis 不可用 → 明确降级，不再假装“已调度且扛重启”。
            asyncio.create_task(
                _auto_rollback(rule_id, duration_minutes * 60, f"[block_ip] {norm_ip}")
            )
            result["auto_unblock"] = _auto_unblock_info(
                "block_ip", rule_id, duration_minutes,
                mechanism="in_process_task", restart_survives=False,
            )
            _record_auto_unblock_scheduled("block_ip")
            logger.warning(
                f"[block_ip] Redis TTL unavailable → in-process auto-unblock for "
                f"{norm_ip} in {duration_minutes}min (restart will lose it)"
            )
    else:
        result["auto_unblock"] = _auto_unblock_info("block_ip", "", 0)

    return result


async def _unblock_ip(src_ip: str, reason: str = "", **kwargs) -> dict:
    """解封IP — 找该 IP 的 active 封禁记录(FW-RULE), 逐条 ssh_firewall.rollback。"""
    exec_mode = _execution_mode()
    if exec_mode != "live":
        return {"action": "unblock_ip", "success": True, "mode": exec_mode,
                "src_ip": src_ip, "deleted_count": 0,
                "message": f"[{exec_mode.upper()}] unblock_ip 模拟"}
    from .ssh_firewall import ssh_firewall
    try:
        active = await ssh_firewall.get_active_rules_async()
        deleted = 0
        for r in active:
            # 只解封 block 记录, 不动隔离记录(status=isolated)
            if r.get("status") not in ("active", "applied") or not r.get("ip"):
                continue
            if _same_host(r.get("ip", ""), src_ip):
                rb = await asyncio.to_thread(ssh_firewall.rollback, r.get("rule_id", ""))
                if rb.get("status") == "success":
                    deleted += int(rb.get("deleted", 1))
        if deleted:
            # 手动解封后清除幂等完成标记，允许下一次真实再封禁。
            from .safe_executor import safe_executor
            await safe_executor.clear_idempotency_for_target("block_ip", src_ip)
        return {
            "action": "unblock_ip",
            "success": deleted > 0,
            "mode": "ssh_firewall_paramiko",
            "src_ip": src_ip,
            "deleted_count": deleted,
        }
    except Exception as e:
        logger.error(f"[unblock_ip] ssh_firewall failed: {e}")
        return {"action": "unblock_ip", "success": False, "error": str(e), "mode": "error", "src_ip": src_ip}


# ── 2. isolate_host / restore_host (防火墙全阻断) ──
# v4.1(2026-09-01):改走 ssh_firewall.isolate_host / rollback,绕开 9p namespace 问题

async def _isolate_host(host_ip: str, reason: str = "", isolation_type: str = "network",
                        extra_ips: Optional[list] = None, peer_ip: Optional[str] = None,
                        duration_minutes: int = 0, **kwargs) -> dict:
    """
    隔离主机 — 双栈: 对 host_ip(+extra_ips) 在匹配族表写 INPUT/OUTPUT DROP。

    2026-10-21：与 block_ip 一样，先经 SafeExecutor（白名单/参数/资产/幂等/
    模式/post-validator/TTL），再调用 ssh_firewall 的真实写入路径。
    complete/families_applied/families_missing 原样透传，部分遏制不虚报为完全隔离。
    """
    host_ip = _validate_ip(host_ip)
    duration_minutes = _validate_positive_int(duration_minutes, "duration_minutes")
    # extra_ips 兼容 str 或 list; peer_ip 保留向后兼容(网络隔离不使用)
    if isinstance(extra_ips, str):
        extra_list = [extra_ips]
    else:
        extra_list = [str(e) for e in (extra_ips or [])]

    try:
        norm_host = str(ipaddress.ip_address(host_ip))
        family = "ipv6" if ipaddress.ip_address(norm_host).version == 6 else "ipv4"
        families = _families_for(norm_host, extra_list)
    except ValueError as e:
        return {"action": "isolate_host", "success": False, "mode": "invalid",
                "host_ip": host_ip, "error": str(e)}

    isolation_id = f"EDR-ISO-{secrets.randbelow(10 ** 10):010d}"
    table = "ip6tables" if family == "ipv6" else "iptables"
    # 代表命令：用于白名单/审计展示；真实写入还会覆盖 OUTPUT 与 extra_ips，
    # 每一条都由 ssh_firewall._exec 的同一套白名单再次校验。
    command = (
        f"{table} -I INPUT -s {norm_host} -j DROP "
        f"-m comment --comment '{isolation_id}'"
    )

    from .safe_executor import safe_executor
    from .ssh_firewall import ssh_firewall

    params: dict = {
        "host_ip": norm_host,
        "isolation_type": isolation_type,
        "duration_minutes": duration_minutes,
        "families": families,
        "isolation_id": isolation_id,
    }
    for key in ("event_id", "eventId", "grounding_score"):
        if kwargs.get(key) is not None:
            params[key] = kwargs[key]

    async def _live_fn(_cmd: str) -> dict:
        err = await _ensure_firewall_connected()
        if err:
            return {
                "success": False, "mode": "error", "action": "isolate_host",
                "host_ip": norm_host, "error": f"connect failed: {err}",
            }
        fw_result = await asyncio.to_thread(
            ssh_firewall.isolate_host,
            norm_host, isolation_type=isolation_type,
            extra_ips=extra_list or None, isolation_id=isolation_id,
        )
        success = fw_result.get("status") == "success"
        return {
            "action": "isolate_host",
            "success": success,
            "mode": "ssh_firewall_paramiko",
            "host_ip": norm_host,
            "isolation_type": isolation_type,
            "complete": fw_result.get("complete", success),
            "families_applied": fw_result.get("families_applied", []),
            "families_missing": fw_result.get("families_missing", []),
            "rule_ids": fw_result.get("rule_ids", []),
            "isolation_id": fw_result.get("isolation_id", isolation_id),
            "detail": fw_result,
        }

    async def _verify_fn(cmd: str) -> dict:
        return await asyncio.to_thread(ssh_firewall.run_verify_command, cmd)

    ttl_seconds = duration_minutes * 60
    result = await safe_executor.execute(
        action_name="isolate_host",
        command=command,
        params=params,
        platform="linux",
        live_fn=_live_fn,
        ttl_seconds=ttl_seconds,
        rule_id=isolation_id,
        verify_fn=_verify_fn,
        idempotency_key=f"soc:idem:isolate_host:{norm_host}:{isolation_type}:{duration_minutes}",
        # duration=0（永久封禁）只做 5 分钟短去重；否则手动解封后 24h 内
        # 真实再攻击会被 idempotent_skip 静默放过。
        idempotency_ttl=(ttl_seconds if ttl_seconds > 0 else 300),
        mode_override=_execution_mode(),
    )

    mode = result.get("mode", "")
    if mode in ("dry_run", "mock", "idempotent_skip"):
        result.setdefault("action", "isolate_host")
        result.setdefault("host_ip", norm_host)
        result.setdefault("isolation_type", isolation_type)
        result.setdefault("complete", True)
        result.setdefault("families_applied", families)
        result.setdefault("families_missing", [])
        result.setdefault("rule_ids", [isolation_id])
        result.setdefault("isolation_id", isolation_id)
        if mode == "dry_run":
            result.setdefault("would_execute", True)
        if mode == "idempotent_skip":
            result["auto_unblock"] = {
                "scheduled": True,
                "mechanism": "idempotent_skip",
                "restart_survives": True,
                "duration_minutes": duration_minutes,
                "rule_ids": isolation_id,
                "note": "同一目标/类型的隔离已存在，本次未重复执行；TTL 沿用首次注册。",
            }
        else:
            result["auto_unblock"] = _auto_unblock_info("isolate_host", "", 0)
        return result

    if result.get("success") and duration_minutes > 0:
        if result.get("ttl_registered"):
            result["auto_unblock"] = _auto_unblock_info(
                "isolate_host", isolation_id, duration_minutes,
                mechanism="redis_ttl", restart_survives=True,
            )
            _record_auto_unblock_scheduled("isolate_host")
            logger.info(
                f"[isolate_host] auto-restore registered in Redis for {norm_host} "
                f"in {duration_minutes}min (rule_id={isolation_id})"
            )
        else:
            asyncio.create_task(
                _auto_rollback(isolation_id, duration_minutes * 60,
                               f"[isolate_host] {norm_host}")
            )
            result["auto_unblock"] = _auto_unblock_info(
                "isolate_host", isolation_id, duration_minutes,
                mechanism="in_process_task", restart_survives=False,
            )
            _record_auto_unblock_scheduled("isolate_host")
            logger.warning(
                f"[isolate_host] Redis TTL unavailable → in-process auto-restore for "
                f"{norm_host} in {duration_minutes}min (restart will lose it)"
            )
    else:
        result["auto_unblock"] = _auto_unblock_info("isolate_host", "", 0)
    return result


async def _restore_host(host_ip: str, reason: str = "", **kwargs) -> dict:
    """恢复主机 — get_active_rules 找 host/ip 匹配的隔离记录, 逐条 rollback(全链全族)。"""
    exec_mode = _execution_mode()
    if exec_mode != "live":
        return {"action": "restore_host", "success": True, "mode": exec_mode,
                "host_ip": host_ip, "deleted_count": 0,
                "message": f"[{exec_mode.upper()}] restore_host 模拟"}
    from .ssh_firewall import ssh_firewall
    try:
        active = await ssh_firewall.get_active_rules_async()
        deleted = 0
        matched = 0
        failed = 0
        for r in active:
            if _same_host(r.get("host", "") or r.get("ip", ""), host_ip):
                matched += 1
                rb = await asyncio.to_thread(ssh_firewall.rollback, r.get("rule_id", ""))
                if rb.get("status") == "success":
                    deleted += int(rb.get("deleted", 1))
                else:
                    failed += 1
        if failed:
            # 有匹配规则但删不掉 → 不能报 success/idempotent。
            return {
                "action": "restore_host", "success": False,
                "mode": "ssh_firewall_paramiko", "host_ip": host_ip,
                "deleted_count": deleted, "rules_matched": matched,
                "error": f"{failed} 条隔离规则回滚失败，主机可能仍被隔离",
            }
        if deleted or matched == 0:
            from .safe_executor import safe_executor
            await safe_executor.clear_idempotency_for_target("isolate_host", host_ip)
        # 幂等: 没有可恢复的隔离规则(已恢复过/从未隔离)也算成功,
        # 重复回滚不应被当作失败(rollback_batch 依赖该语义)。
        return {
            "action": "restore_host",
            "success": True,
            "mode": "ssh_firewall_paramiko",
            "host_ip": host_ip,
            "deleted_count": deleted,
            "rules_matched": matched,
            "idempotent": deleted == 0,
            **({"message": "没有待恢复的隔离规则(可能已恢复)"} if deleted == 0 else {}),
        }
    except Exception as e:
        logger.error(f"[restore_host] ssh_firewall failed: {e}")
        return {"action": "restore_host", "success": False, "error": str(e), "mode": "error", "host_ip": host_ip}


# ── 2b. dns_sinkhole / unsinkhole (DNS 沉洞) ──
# 走 ssh_firewall.sinkhole_domain(真实执行)。live 且 SSH 不可达 → success=false + unconfigured,
# 不做 stub 假装成功; mock/dry_run 按 config.execution_mode 返回模拟结果。

async def _dns_sinkhole(domain: str = "", ipv4: str = "", ipv6: str = "",
                        resolved_ip: Optional[list] = None, marker_id: str = "",
                        reason: str = "", duration_minutes: int = 0, **kwargs) -> dict:
    """DNS sinkhole: 恶意域名 → 黑洞地址(dnsmasq drop-in / hosts), 可选对解析 IP 一并封禁。"""
    # 域名强校验(字母/数字/连字符/点, ≤253, 无路径/空格)
    try:
        domain = _validate_domain(domain)
    except ValueError as e:
        return {"action": "dns_sinkhole", "success": False, "mode": "invalid",
                "domain": str(domain or ""), "error": str(e)}

    # 黑洞 IP: 缺省/空串 → settings 默认
    sink_v4 = (str(ipv4).strip() if ipv4 else "") or getattr(settings, "dns_sinkhole_ipv4", "") or ""
    sink_v6 = (str(ipv6).strip() if ipv6 else "") or getattr(settings, "dns_sinkhole_ipv6", "") or ""
    try:
        if sink_v4:
            _validate_ip(sink_v4)
        if sink_v6:
            _validate_ip(sink_v6)
    except ValueError as e:
        return {"action": "dns_sinkhole", "success": False, "mode": "invalid",
                "domain": domain, "error": str(e)}

    # 域名解析到的恶意 IP(可选, 一并封禁; str 或 list)
    resolved_ips: list[str] = []
    if isinstance(resolved_ip, str):
        resolved_ips = [resolved_ip]
    elif isinstance(resolved_ip, (list, tuple)):
        resolved_ips = [str(x) for x in resolved_ip]
    for ip in resolved_ips:
        try:
            _validate_ip(ip)
        except ValueError as e:
            return {"action": "dns_sinkhole", "success": False, "mode": "invalid",
                    "domain": domain, "error": str(e)}

    marker_id = str(marker_id or "").strip() or _marker_for_domain(domain)

    from .safe_executor import safe_executor
    from .ssh_firewall import ssh_firewall

    params: dict = {
        "domain": domain,
        "marker_id": marker_id,
        "ipv4": sink_v4,
        "ipv6": sink_v6,
    }
    for key in ("event_id", "eventId", "grounding_score"):
        if kwargs.get(key) is not None:
            params[key] = kwargs[key]

    async def _live_fn(_cmd: str) -> dict:
        err = await _ensure_firewall_connected()
        if err:
            return {
                "action": "dns_sinkhole", "success": False, "mode": "unconfigured",
                "domain": domain, "marker_id": marker_id, "backend": "unconfigured",
                "error": f"ssh_firewall connect failed: {err}",
            }
        fw_res = await asyncio.to_thread(
            ssh_firewall.sinkhole_domain,
            domain=domain, ipv4=sink_v4 or None,
            ipv6=sink_v6 or None, marker_id=marker_id,
        )
        sink_ok = bool(fw_res.get("success")) or fw_res.get("status") == "success"
        return {
            "action": "dns_sinkhole",
            "success": sink_ok,
            "mode": "ssh_firewall_paramiko",
            "domain": domain,
            "marker_id": fw_res.get("marker_id") or marker_id,
            "backend": fw_res.get("backend", "unconfigured"),
            "detail": fw_res,
        }

    # sinkhole 的命令由 ssh_firewall 内部按常量模板 + 已校验 domain/IP/marker 拼装，
    # 无法用 iptables 白名单表达；跳过白名单必须在审计里留痕。
    result = await safe_executor.execute(
        action_name="dns_sinkhole",
        command=f"dns_sinkhole domain={domain} marker={marker_id}",
        params=params,
        platform="linux",
        live_fn=_live_fn,
        ttl_seconds=0,
        rule_id=marker_id,
        idempotency_key=f"soc:idem:dns_sinkhole:{marker_id}",
        idempotency_ttl=86400,
        skip_whitelist=True,
        skip_whitelist_reason=(
            "dns_sinkhole 使用 ssh_firewall.sinkhole_domain 的常量模板，"
            "domain/IP/marker 已在入口强校验"
        ),
        mode_override=_execution_mode(),
    )

    mode = result.get("mode", "")
    if mode in ("dry_run", "mock", "idempotent_skip"):
        result.setdefault("action", "dns_sinkhole")
        result.setdefault("domain", domain)
        result.setdefault("marker_id", marker_id)
        result.setdefault("backend", "hosts")
        if mode == "dry_run":
            result.setdefault("would_execute", True)
            result.setdefault("message", f"[DRY_RUN] dns_sinkhole {domain} 未真实写入")
        elif mode == "mock":
            result.setdefault("message", "[MOCK] dns_sinkhole 已写入")
        else:
            result.setdefault("message", "同一 marker 的 sinkhole 已存在，本次未重复执行")

    sink_ok = bool(result.get("success"))
    result["complete"] = sink_ok
    if sink_ok and resolved_ips:
        blocks = []
        for ip in resolved_ips:
            br = await _block_ip(src_ip=ip, reason=f"dns_sinkhole:{domain}",
                                 duration_minutes=duration_minutes)
            blocks.append({"ip": ip, "success": br.get("success", False),
                           "detail": br.get("detail") or br.get("error") or br.get("message", "")})
        result["resolved_ip_blocks"] = blocks
        result["complete"] = sink_ok and all(b["success"] for b in blocks)
    else:
        result["complete"] = bool(sink_ok)
    return result


async def _unsinkhole_domain(domain: str = "", marker_id: str = "", reason: str = "",
                             **kwargs) -> dict:
    """撤销 DNS sinkhole(rollback_fn) — 按 marker 清 /etc/hosts + dnsmasq drop-in。"""
    d = str(domain or "").strip()
    if d:
        try:
            d = _validate_domain(d)
        except ValueError as e:
            return {"action": "dns_sinkhole", "success": False, "mode": "invalid",
                    "domain": d, "error": str(e)}
    marker = str(marker_id or "").strip() or (_marker_for_domain(d) if d else "")
    exec_mode = _execution_mode()
    if exec_mode != "live":
        return {"action": "dns_sinkhole", "success": True, "mode": exec_mode,
                "domain": d, "marker_id": marker,
                "message": f"[{exec_mode.upper()}] unsinkhole 模拟"}
    from .ssh_firewall import ssh_firewall
    err = await _ensure_firewall_connected()
    if err:
        return {"success": False, "mode": "unconfigured", "domain": d, "marker_id": marker,
                "error": f"ssh_firewall connect failed: {err}"}
    try:
        # P1: ssh_firewall 是同步 paramiko 多次往返, 直接调用会卡死整个事件循环
        # (期间全部 API/告警停摆) → 移入线程池。
        fw_res = await asyncio.to_thread(
            ssh_firewall.unsinkhole_domain, domain=d, marker_id=marker
        )
    except Exception as e:
        logger.error(f"[unsinkhole] ssh_firewall.unsinkhole_domain failed: {e}")
        return {"success": False, "mode": "error", "domain": d, "marker_id": marker, "error": str(e)}
    return {"action": "dns_sinkhole",
            "success": bool(fw_res.get("success")) or fw_res.get("status") == "success",
            "mode": "ssh_firewall_paramiko", "domain": d,
            "marker_id": fw_res.get("marker_id") or marker,
            "backend": fw_res.get("backend", "unconfigured"),
            "detail": fw_res}


# ── 3. rate_limit / remove_rate_limit (通过 QoS 策略) ──

async def _rate_limit(src_ip: str, bandwidth_kbps: int = 1000, reason: str = "", **kwargs) -> dict:
    """
    对IP限速 — Windows QoS 策略 (通过 PowerShell)
    创建基于源 IP 的流量限制策略
    """
    src_ip = _validate_ip(src_ip)
    bandwidth_kbps = _validate_positive_int(bandwidth_kbps, "bandwidth_kbps")
    safe_reason = _sanitize_powershell_string(reason[:200])
    policy_name = f"RE_RateLimit_{src_ip.replace('.','_')}"
    safe_src = _sanitize_powershell_string(src_ip)
    safe_policy = _sanitize_powershell_string(policy_name)
    band_bits = bandwidth_kbps * 1024
    ps_script = (
        f'$name = "{safe_policy}"\n'
        f'$ip = "{safe_src}"\n'
        f'$rate = {band_bits}\n'
        f'New-NetQosPolicy -Name $name -IPSourceAddress $ip '
        f'-IPProtocol TCP -ThrottleRateInBits $rate '
        f'-Description "ResponseEngine rate-limit: {safe_reason}" '
        f'-ErrorAction Stop\n'
        f'Write-Output "QoS policy $name created"'
    )
    cmd = _ps_cmd(ps_script)
    return await _exec(cmd, "rate_limit", src_ip=src_ip, bandwidth_kbps=bandwidth_kbps, policy_name=policy_name)


async def _remove_rate_limit(src_ip: str, reason: str = "", **kwargs) -> dict:
    """取消限速 — 删除 QoS 策略"""
    policy_name = f"RE_RateLimit_{src_ip.replace('.','_')}"
    ps_script = (
        f'$name = "{policy_name}"\n'
        f'Remove-NetQosPolicy -Name $name -Confirm:$false -ErrorAction SilentlyContinue\n'
        f'Write-Output "QoS policy $name removed"'
    )
    cmd = _ps_cmd(ps_script)
    return await _exec(cmd, "remove_rate_limit", src_ip=src_ip)


# ── 4. kill_session (终止用户会话) ──

async def _kill_session(session_id: str, user: str = "", reason: str = "", **kwargs) -> dict:
    """
    终止用户会话:
      - 如果 session_id 是 RDP 会话ID → logoff
      - 如果 user 提供 → 终止该用户所有进程
      - 否则当作进程名 → taskkill
    """
    if session_id and session_id.isdigit():
        safe_sid = _validate_alphanumeric(session_id, max_len=10)
        ps_script = f'logoff {safe_sid} /server:localhost 2>$null\nWrite-Output "Session {safe_sid} logged off"'
    elif user:
        safe_user = _sanitize_powershell_string(user[:64])
        # P1: `-match` 是正则匹配, user=".*"/"[a-z]" 等元字符会匹配所有用户,
        # Stop-Process -Force 将杀死目标主机全部进程 → 改 `-eq` 精确等值比较。
        ps_script = (
            f'Get-Process -IncludeUserName | '
            f'Where-Object {{$_.UserName -eq "{safe_user}"}} | '
            f'Stop-Process -Force\n'
            f'Write-Output "Processes for {safe_user} terminated"'
        )
    else:
        safe_name = _validate_alphanumeric(session_id[:64], max_len=64)
        ps_script = (
            f'Stop-Process -Name "{safe_name}" -Force -ErrorAction SilentlyContinue\n'
            f'taskkill /F /IM "{safe_name}" /T 2>$null\n'
            f'Write-Output "Process {safe_name} terminated"'
        )
    cmd = _ps_cmd(ps_script)
    return await _exec(cmd, "kill_session", session_id=session_id, user=user)


# ── 5. send_alert (发送告警通知) ──

async def _send_alert(
    title: str = "", message: str = "", severity: str = "high",
    channel: str = "webhook", webhook_url: str = "", **kwargs
) -> dict:
    """
    发送告警通知:
      - webhook:     POST JSON 到指定 URL（默认；URL 须过安全校验）
      - eventlog:    Windows 事件日志
      - display:     宿主机桌面弹窗

    ⚠ 整改报告 §9.61：**dingtalk / wework 从未实现**。
    原 docstring 与 `params_schema` 都在宣传这两个渠道，于是
    「策略配了钉钉、但平台没有实现」这件事**只留一行 warning**，
    告警**静默丢失**。现在未实现的渠道**明确失败**并给出原因
    （`unsupported_channel: <channel>`）→ 写进结构化结果，审计看得见。

    channel 参数决定发送方式。
    webhook_url 可以自定义，否则使用默认值（默认只写日志，不外发）。
    """
    # 预览模式：绝不发真实 webhook / 写事件日志 / 弹窗。
    try:
        from .preview import preview_mode
        if preview_mode.get():
            return {
                "action": "send_alert", "success": True, "mode": "dry_run",
                "would_execute": True, "channel": channel or "webhook",
                "title": title or "安全告警",
                "message": message or f"威胁告警 (严重度={severity})",
            }
    except Exception:
        pass
    if not channel or channel == "webhook":
        if webhook_url:
            title = title or "安全告警"
            message = message or f"威胁告警 (严重度={severity})"
            return await _send_webhook(title, message, severity, webhook_url)
        title = title or "安全告警"
        message = message or f"威胁告警 (严重度={severity})"
        return await _send_webhook_default(title, message, severity)

    elif channel == "eventlog":
        title = title or "安全告警"
        message = message or f"威胁告警 (严重度={severity})"
        return await _send_eventlog(title, message, severity)

    elif channel == "display":
        title = title or "安全告警"
        message = message or f"威胁告警 (严重度={severity})"
        return await _send_display_notification(title, message)

    else:
        # 未实现的渠道：此前**静默降级**成 stub（只留一行 warning），
        # 告警就这么没了。现在明确失败 + 明确原因（进结构化结果）。
        logger.error(
            f"[ALERT] 未实现的通知渠道 channel={channel}"
            f"（本平台只实现了 webhook / eventlog / display）—— 告警未送达"
        )
        return {
            "action": "send_alert", "mode": "stub", "success": False,
            "error": f"unsupported_channel: {channel}",
            "title": title, "message": message, "_stub": True,
        }




def redact_url_for_log(url: str) -> str:
    """URL → **可关联但不含密钥**的形态（整改报告 §9.63）。

    为什么：告警 webhook 的 URL **通常内嵌密钥** ——
        Slack    https://hooks.slack.com/services/T00/B00/<SECRET>
        钉钉     https://oapi.dingtalk.com/robot/send?access_token=<SECRET>
        企业微信  https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=<SECRET>
    而 `GET /response/logs` 只要**任何登录用户**（无角色门槛）→
    URL 原样落盘 = 把告警通道的钥匙发给全体登录用户。

    保留 `scheme://host[:port]/<路径首段>`（回答「发到哪台机器、哪条通道」）
    + 完整 URL 的 `sha256[:12]`（同一个目标在不同日志里仍**可关联**，
    不需要看到密钥）。**查询串与 userinfo 一律丢弃**。
    """
    raw = str(url or "")
    if not raw:
        return ""
    try:
        parts = urlsplit(raw)
    except Exception:
        return "<unparsable-url>"
    if not parts.scheme or not parts.hostname:
        # 不是 URL（或没有主机）→ 别乱改形状
        return raw
    host = parts.hostname
    try:
        if parts.port:
            host = f"{host}:{parts.port}"
    except ValueError:
        pass
    first = (parts.path or "").strip("/").split("/")[0] if parts.path else ""
    path = f"/{first}/…" if first else "/"
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]
    return f"{parts.scheme}://{host}{path}#sha256:{digest}"


def _check_webhook_url(webhook_url: str) -> tuple[bool, str]:
    """校验告警 webhook 的目标 URL。返回 `(是否放行, 原因)`。

    口径与沙箱入口**完全一致**（整改方案 §五.2）：
      · 只允许 http / https；
      · loopback / link-local / 保留段 / 组播 / 云元数据**一律拒绝**
        （`allow_private=True` 只放开 RFC1918 私有段 —— 那是内网告警
        接收方的正常形态）；
      · 域名解析后的 IP 重新校验（防 DNS 变更绕过）；
      · **解析失败不阻断**（返回放行 + `dns_resolve_failed`）：
        此时 HTTP 请求本身也会失败（httpx 同样要解析），结果相同，
        阻断只会白白吃掉一条告警。

    ⚠ 这是**同步**函数（会做阻塞 DNS 查询）→ 调用方必须放到线程里
    （`asyncio.to_thread`），别卡住事件循环。
    """
    try:
        from zeroday_detect.sandbox_status import (
            UrlRejected, validate_submittable_url,
        )
    except ImportError:
        # 校验器不可用 → **不发送**（fail-closed）：
        # 一条发不出去的安全告警，好过一条发到任意地址的告警。
        return False, "validator_unavailable"
    try:
        validate_submittable_url(webhook_url, allow_private=True, resolve_dns=True)
    except UrlRejected as e:
        if e.reason == "dns_resolve_failed":
            return True, "dns_resolve_failed"
        return False, e.reason
    return True, ""

async def _send_webhook(title: str, message: str, severity: str, webhook_url: str) -> dict:
    """通过通用 Webhook 发送告警。

    ⚠ **URL 安全校验（整改报告 §9.61）**

    修复前这里对 `webhook_url` **完全不校验** → `httpx` 直接把请求
    发到调用方给的任意地址。实测（2026-10-20）：平台会真的向
    `http://127.0.0.1:<port>/...` 发 POST，并把 `status_code` 带回来
    （= 内网探测 oracle）；而**同一个平台**的沙箱入口
    （`zeroday_detect.sandbox_status.validate_submittable_url`）
    对同一个 URL 是**拒绝**的（`loopback_not_allowed`）。
    **同一平台、两个面：一个拦一个不拦。**

    现在复用平台既有那套校验（整改方案 §五.2 的口径）：
      · 只允许 http / https；
      · **loopback / link-local / 保留段 / 组播 / 云元数据一律拒绝**
        （`allow_private=True` 只放开 RFC1918 私有段 —— 那是内网告警
        接收方的正常形态；沙箱那侧的注释写明「loopback 与云元数据
        在任何模式下都禁」）；
      · 域名解析后的 IP 重新校验（防 DNS 变更绕过）；
      · **解析失败不阻断**（此时 HTTP 请求本身也会失败，结果相同），
        但要留 warning。

    依赖方向说明：校验器住在 `zeroday_detect.sandbox_status`（平台
    **唯一**的 URL 安全策略所在，纯标准库、无项目内依赖 → 无循环）。
    局部 import 是为了不让响应引擎在导入期就依赖零日模块。
    """
    ok, reason = await asyncio.to_thread(_check_webhook_url, webhook_url)
    if not ok:
        logger.error(
            f"[ALERT] webhook URL 被安全校验拒绝: {reason}（未发出请求）: "
            f"{redact_url_for_log(webhook_url)}")
        return {
            "action": "send_alert", "mode": "webhook", "success": False,
            "error": f"webhook_url_rejected: {reason}",
            "rejected": True, "url": redact_url_for_log(webhook_url),
        }
    if reason == "dns_resolve_failed":
        # 解析失败 → 这次请求本来也会失败（httpx 同样要解析），
        # 所以不阻断发送，但必须留痕（URL 须脱敏: 可能内嵌 access_token/key）。
        logger.warning(
            f"[ALERT] webhook 域名解析失败（仍尝试发送）: {redact_url_for_log(webhook_url)}")
    try:
        import httpx
        payload = {
            "title": title,
            "message": message,
            "severity": severity,
            "source": "shared-memory-response-engine",
            "timestamp": __import__("time").time(),
        }
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(webhook_url, json=payload)
            resp.raise_for_status()
            logger.info(f"[ALERT] Webhook sent to {redact_url_for_log(webhook_url)}: {resp.status_code}")
            return {"action": "send_alert", "mode": "webhook", "success": True, "status_code": resp.status_code}
    except Exception as e:
        from .response_executor import redact_text_for_log
        # 异常文本可能内嵌完整 URL(含 token), 与返回值同口径脱敏
        logger.warning(f"[ALERT] Webhook failed: {redact_text_for_log(str(e))}")
        return {"action": "send_alert", "mode": "webhook", "success": False,
                "error": redact_text_for_log(str(e))}


async def _send_webhook_default(title: str, message: str, severity: str) -> dict:
    """使用默认渠道记录告警（写日志）"""
    logger.warning(f"[ALERT] [{severity.upper()}] {title}: {message[:200]}")
    return {
        "action": "send_alert", "mode": "log",
        "title": title, "message": message, "severity": severity,
        "success": True,
    }


async def _send_eventlog(title: str, message: str, severity: str) -> dict:
    """写入 Windows 事件日志（通过 SSH）"""
    level = "ERROR" if severity in ("critical", "high") else "WARNING"
    safe_title = _sanitize_powershell_string(title[:200])
    safe_msg = _sanitize_powershell_string(message[:500])
    ps_script = (
        f'Write-EventLog -LogName Application -Source "ResponseEngine" '
        f'-EntryType {level} -EventId 1000 -Message "{safe_title}: {safe_msg}" '
        f'-ErrorAction SilentlyContinue'
    )
    cmd = _ps_cmd(ps_script)
    return await _exec(cmd, "send_alert", title=title, message=message, severity=severity)


async def _send_display_notification(title: str, message: str) -> dict:
    """在宿主机桌面弹出通知（通过 PowerShell）"""
    safe_title = _sanitize_powershell_string(title[:200])
    safe_msg = _sanitize_powershell_string(message[:500])
    ps_script = (
        '[System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null\n'
        '$n = New-Object System.Windows.Forms.NotifyIcon\n'
        '$n.Icon = [System.Drawing.SystemIcons]::Warning\n'
        f'$n.BalloonTipTitle = "{safe_title}"\n'
        f'$n.BalloonTipText = "{safe_msg}"\n'
        '$n.Visible = $true\n'
        '$n.ShowBalloonTip(10000)'
    )
    cmd = _ps_cmd(ps_script)
    return await _exec(cmd, "send_alert", title=title, message=message, mode="notification")


# ── 注册所有动作 ──

def _init_registry(registry=None):
    """把内置动作注册到 registry（默认 = 模块级全局单例）。

    2026-10-20: 允许传入**独立**的 registry 实例。理由：全局单例一旦被
    任何代码注册过（哪怕只是测试），「生产动作集」就不再可测 ——
    守卫会变成顺序依赖（实测踩过：§9.47）。传入独立实例可以在
    **不触碰全局单例**的前提下构造一份干净的生产动作集。
    """
    registry = registry if registry is not None else response_registry
    registry.register(
        "block_ip", _block_ip,
        description="封禁源IP (通过防火墙/WAF ACL)",
        severity=ACTION_SEVERITY_HIGH,
        category="network",
        reversible=True,
        rollback_fn=_unblock_ip,
        params_schema={
            "src_ip": "str (required) 源IP",
            "reason": "str 封禁原因",
            "duration_minutes": "int 封禁时长(默认60)",
        },
    )
    registry.register(
        "isolate_host", _isolate_host,
        description="将主机隔离到隔离VLAN",
        severity=ACTION_SEVERITY_CRITICAL,
        category="host",
        reversible=True,
        rollback_fn=_restore_host,
        params_schema={
            "host_ip": "str (required) 主机IP",
            "reason": "str 隔离原因",
            "extra_ips": "list[str] 主机其他地址(如另一协议族)",
            "duration_minutes": "int 隔离时长(默认0=人工恢复)",
        },
    )
    registry.register(
        "dns_sinkhole", _dns_sinkhole,
        description="DNS sinkhole: 恶意域名指向黑洞 IP(可同时封禁解析 IP)",
        severity=ACTION_SEVERITY_HIGH,
        category="network",
        reversible=True,
        rollback_fn=_unsinkhole_domain,
        params_schema={
            "domain": "str (required) 恶意域名(字母/数字/连字符/点, ≤253)",
            "ipv4": "str 黑洞 IPv4(默认 settings.dns_sinkhole_ipv4)",
            "ipv6": "str 黑洞 IPv6(默认 settings.dns_sinkhole_ipv6)",
            "resolved_ip": "str|list 域名解析到的 IP, 一并封禁(可双栈给两个)",
            "duration_minutes": "int resolved_ip 封禁时长(默认0=人工解除)",
        },
    )
    registry.register(
        "rate_limit", _rate_limit,
        description="对源IP进行带宽限速",
        severity=ACTION_SEVERITY_MEDIUM,
        category="network",
        reversible=True,
        rollback_fn=_remove_rate_limit,
        params_schema={
            "src_ip": "str (required) 源IP",
            "bandwidth_kbps": "int 限制带宽(Kbps,默认1000)",
            "reason": "str 限速原因",
        },
    )
    registry.register(
        "kill_session", _kill_session,
        description="强制终止用户登录会话",
        severity=ACTION_SEVERITY_HIGH,
        category="session",
        reversible=False,
        params_schema={
            "session_id": "str (required) 会话ID",
            "user": "str 用户名",
            "reason": "str 终止原因",
        },
    )
    registry.register(
        "send_alert", _send_alert,
        description="发送告警通知到指定渠道",
        severity=ACTION_SEVERITY_LOW,
        category="notification",
        reversible=False,
        params_schema={
            "title": "str (required) 告警标题",
            "message": "str (required) 告警内容",
            "severity": "str 告警级别",
            "channel": "str 通知渠道(webhook/eventlog/display)",
            "webhook_url": "str 可选，webhook 渠道的目标 URL"
                            "（须过 URL 安全校验：拒绝 loopback/link-local/"
                            "云元数据/非 http(s)）",
        },
    )
    logger.info(f"Response registry initialized with {len(registry._actions)} actions")
    try:
        from response_engine.containment import register_containment_actions
        register_containment_actions(registry)
    except Exception as e:
        logger.warning("containment actions not registered: %s", e)


_init_registry()
