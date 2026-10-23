"""
统一安全执行器 (Safe Executor)

所有 SSH 命令的唯一安全通道。串联 6 层安全检查:

    ① CommandWhitelist   命令白名单（默认拒绝）
    ② ParamValidator     参数强校验（ipaddress + 正则）
    ③ AssetWhitelist     核心资产保护
    ④ IdempotencyGuard   幂等检查（Redis）
    ⑤ ExecutionMode      dry_run / mock / live 路由
    ⑥ PrivilegeSelector  最小权限账号选择

执行后:
    ⑦ PostValidator      执行后验证
    ⑧ TtlManager         TTL 自动解封注册
    ⑨ AuditTrail         审计日志

调用方式:
    from response_engine.safe_executor import safe_executor
    result = await safe_executor.execute(
        action_name="block_ip",
        command="iptables -I INPUT -s 1.2.3.4 -j DROP ...",
        params={"src_ip": "1.2.3.4", "duration": 3600},
        platform="linux",
        live_fn=ssh_exec_coroutine,
    )
"""
import hashlib
import json
import logging
import time
from typing import Callable, Coroutine, Optional

from config import settings

from .command_whitelist import command_whitelist
from .asset_whitelist import asset_whitelist
from .execution_modes import execution_router, MODE_LIVE
from .post_validator import post_validator
from .ttl_manager import ttl_manager

logger = logging.getLogger(__name__)

# 幂等 Redis key 前缀
_IDEM_PREFIX = "soc:idem:"


def _asset_whitelist_scope(assets: list) -> str:
    """受保护清单的**范围**（§9.54）。

    * `empty` —— 清单是空的（这道检查**保护不了任何东西**）；
    * `builtin_only` —— 只有内置项（实测默认就是这一档：只有 loopback），
      业务资产**一个都没保护**；
    * `configured` —— 配过业务资产（env / 运行时添加）。
    """
    if not assets:
        return "empty"
    if any(str(a.get("source") or "") != "builtin" for a in assets):
        return "configured"
    return "builtin_only"


def _record_idempotency_check(state: str) -> None:
    """记录幂等检查状态（§9.52）。指标不可用时静默忽略。"""
    try:
        from core_metrics import record_response_idempotency_check
        record_response_idempotency_check(state)
    except Exception:
        pass


def _record_grounding_gate(state: str) -> None:
    """记录 grounding 闸门状态（§9.51）。

    指标模块不可用时**静默忽略** —— 计数失败不该阻断响应动作。
    """
    try:
        from core_metrics import record_response_grounding_gate
        record_response_grounding_gate(state)
    except Exception:
        pass


class SafeExecutor:
    """统一安全执行器"""

    def __init__(self):
        self._redis = None
        # 只读动作列表 — 使用低权限账号
        self._readonly_actions = {
            "vulnerability_scan", "list_rules", "health_check",
        }

    def set_redis(self, redis_client):
        """注入 Redis 客户端"""
        self._redis = redis_client
        logger.info("[SafeExecutor] Redis client set")

    def initialize(self):
        """从配置初始化各子模块"""
        # 资产白名单
        asset_whitelist.initialize(
            protected_assets_str=getattr(settings, "protected_assets", ""),
            labels_str=getattr(settings, "protected_assets_labels", ""),
        )
        # 执行模式
        mode = getattr(settings, "execution_mode", "live")
        execution_router.mode = mode
        # TTL 扫描间隔
        ttl_manager._scan_interval = getattr(settings, "ttl_scan_interval", 30)

        logger.info(f"[SafeExecutor] Initialized (mode={mode})")

    async def execute(
        self,
        action_name: str,
        command: str,
        params: dict,
        platform: str = "linux",
        live_fn: Optional[Callable[..., Coroutine]] = None,
        ttl_seconds: int = 0,
        rule_id: str = "",
        skip_whitelist: bool = False,
        verify_fn: Optional[Callable[..., Coroutine]] = None,
        idempotency_key: str = "",
        idempotency_ttl: int = 86400,
        skip_whitelist_reason: str = "",
        mode_override: str = "",
    ) -> dict:
        """
        安全执行入口

        Args:
            action_name: 动作名称 (block_ip / isolate_host / ...)
            command: 完整 SSH 命令
            params: 动作参数
            platform: "linux" | "windows"
            live_fn: 真实 SSH 执行的异步函数 (接受 command str)
            ttl_seconds: 自动解封 TTL（0=不注册）
            rule_id: 规则 ID（TTL 和幂等用）
            skip_whitelist: 跳过命令白名单（仅限内部验证命令）
            verify_fn: 执行后验证函数；默认复用 live_fn。
                动作若自己生成多条命令（如 isolate/sinkhole），应传专门的只读查询函数，
                否则 post_validator 会把“验证查询”当成“再次执行”。
            idempotency_key: 显式幂等键；用于把“同一目标的重复请求”收敛，
                同时不把随机 rule_id 混进幂等键。
            idempotency_ttl: 幂等标记的 TTL（秒）；默认 24h。
            skip_whitelist_reason: 跳过白名单时必须写明原因，审计会记录。
            mode_override: 覆盖全局 execution_router.mode（用于以 settings 为准的
                高危动作；默认空 = 使用 execution_router.mode）。

        Returns:
            执行结果 dict，包含 mode, verified, blocked 等字段
        """
        start_time = time.time()
        audit = {
            "action": action_name,
            "platform": platform,
            "command_preview": command[:200],
            "params": {k: v for k, v in params.items() if k != "password"},
            "checks": {},
        }

        # ── ⓪ Grounding 硬门控 ──
        # 无证据支撑的审计结论不允许触发响应动作
        #
        # 2026-10-20 修复（整改报告 §9.51）：这道闸门此前**永远不会触发**，
        # 而审计里却记成「通过、满分」——
        #   ① 整个 response_engine 包里 `grounding_score` 只出现在本行：
        #      **没有任何生产代码传它**（实测）；
        #   ② 动作函数（_block_ip 等）**不转发 `**kwargs`** → 就算调用方传了
        #      也会在到达闸门之前被丢掉；
        #   ③ 没有任何测试覆盖它。
        # 「没评估过」与「评估通过」必须**分开记** —— 否则这道闸门提供的是
        # **虚假保障**（读审计的人以为「无证据不许响应」由 SafeExecutor 保证）。
        #
        # ⚠ 本次**不改变拦截行为**（仍然不拦）：把它接上属**收紧型**改动
        #   （非审计来源的响应——Kafka 告警 / EDR 融合——根本没有 grounding 分数，
        #   一旦按缺省拒绝，整个响应能力会瘫）→ 登记为**待决项 33**。
        _raw_grounding = params.get("grounding_score")
        _has_grounding = _raw_grounding is not None
        grounding_score = None
        if _has_grounding:
            try:
                grounding_score = float(_raw_grounding)
            except (TypeError, ValueError):
                _has_grounding = False
        if _has_grounding and grounding_score < 0.4:
            audit["checks"]["grounding"] = {
                "passed": False,
                "state": "evaluated_block",
                "score": grounding_score,
                "reason": f"Grounding 分数 {grounding_score:.2f} < 0.4，证据不足",
            }
            _record_grounding_gate("evaluated_block")
            logger.warning(
                f"[SafeExecutor] BLOCKED by grounding gate: {action_name} "
                f"score={grounding_score:.2f}"
            )
            return self._blocked_result(
                action_name, "grounding_gate",
                f"Grounding 验证未通过 (score={grounding_score:.2f}<0.4)，"
                f"审计结论缺乏充分证据支撑，拒绝执行响应动作",
                audit,
            )
        if _has_grounding:
            audit["checks"]["grounding"] = {
                "passed": True, "state": "evaluated_pass", "score": grounding_score,
            }
            _record_grounding_gate("evaluated_pass")
        else:
            # 没评估过 —— 如实记，**不冒充通过**（§9.51）
            audit["checks"]["grounding"] = {
                "passed": None,
                "state": "not_evaluated",
                "score": None,
                "reason": "未提供 grounding 分数 → 本闸门未评估，"
                          "此刻不提供任何保护（整改报告 §9.51）",
            }
            _record_grounding_gate("not_evaluated")
            logger.info(
                "[SafeExecutor] grounding 闸门未评估（无 grounding_score 参数）—— "
                "本闸门此刻不提供任何保护（§9.51）"
            )

        # ── ① 命令白名单 ──
        if not skip_whitelist:
            allowed, rule_ref, reason = command_whitelist.check(command, platform)
            audit["checks"]["whitelist"] = {
                "passed": allowed, "rule": rule_ref, "reason": reason
            }
            if not allowed:
                logger.warning(
                    f"[SafeExecutor] BLOCKED by whitelist: {action_name} → {reason}"
                )
                return self._blocked_result(action_name, "command_whitelist", reason, audit)
        else:
            # 跳过白名单必须留痕：这是“更弱”的路径，不能与“通过白名单”混为一谈。
            audit["checks"]["whitelist"] = {
                "passed": None,
                "skipped": True,
                "reason": skip_whitelist_reason or "internal_skip",
            }

        # ── ② 参数强校验 ──
        param_ok, param_reason = self._validate_params(action_name, params)
        audit["checks"]["params"] = {"passed": param_ok, "reason": param_reason}
        if not param_ok:
            logger.warning(
                f"[SafeExecutor] BLOCKED by param validation: {action_name} → {param_reason}"
            )
            return self._blocked_result(action_name, "param_validation", param_reason, audit)

        # ── ③ 核心资产保护 ──
        target_ip = params.get("src_ip", params.get("host_ip", params.get("host", "")))
        if target_ip:
            is_protected, asset_reason = asset_whitelist.check(target_ip, action_name)
            # 2026-10-20 修复（整改报告 §9.54）：原先这里写的是
            #   {"passed": not is_protected, "reason": asset_reason}
            # 而 `check()` 在「没命中」时返回的 reason 是**空串** ——
            # 于是审计里是「通过、理由为空」，**分不出**「没命中受保护清单」
            # 与「清单里根本没有可保护的东西」（默认只有 loopback 一条）。
            # 现在：理由**非空** + 带**保护范围**（清单条数 / 是否只含内置项）。
            _scope = asset_whitelist.list_assets()
            audit["checks"]["asset_whitelist"] = {
                "passed": not is_protected,
                "state": "evaluated",
                "reason": asset_reason or (
                    f"未命中受保护清单（当前清单 {len(_scope)} 条"
                    f"，范围 {_asset_whitelist_scope(_scope)}）"),
                "protected_count": len(_scope),
                "scope": _asset_whitelist_scope(_scope),
            }
            if is_protected:
                logger.warning(
                    f"[SafeExecutor] BLOCKED by asset whitelist: {action_name} → {asset_reason}"
                )
                return self._blocked_result(action_name, "asset_whitelist", asset_reason, audit)

        # ── ④ 幂等检查 (Redis) ──
        #
        # 2026-10-20 修复（整改报告 §9.52）：此前只记 `{"hit": False}` ——
        # 而「**没查成**」（Redis 未配置或出错）与「查了、确实没重复」
        # 返回的是**同一个值** → 审计里**看不出这道检查当时根本没跑**。
        #
        # 同一事务的**另一侧**（回滚幂等 `RollbackStore`）是「内存为主、
        # Redis 兜底」→ 同一故障下保护仍在；而**执行侧**是纯 Redis →
        # 保护整体消失（要不要补内存兜底属**收紧型**改动 → 待决项 34）。
        idempotent_hit, idem_state = await self._idempotency_check(
            action_name, params, rule_id, key_override=idempotency_key)
        audit["checks"]["idempotency"] = {"hit": idempotent_hit, "state": idem_state}
        if idem_state == "unavailable":
            audit["checks"]["idempotency"]["reason"] = (
                "Redis 不可用 → 幂等检查**未执行**；此刻这道保护不生效"
                "（执行侧是纯 Redis，回滚侧另有内存兜底，§9.52）"
            )
            _record_idempotency_check("unavailable")
            logger.warning(
                "[SafeExecutor] 幂等检查不可用(Redis 未配置或异常) → "
                "本次不提供幂等保护（§9.52）"
            )
        else:
            _record_idempotency_check(
                "evaluated_hit" if idempotent_hit else "evaluated_miss")
        if idempotent_hit:
            logger.info(
                f"[SafeExecutor] Idempotent skip: {action_name} already executed"
            )
            return {
                "success": True,
                "mode": "idempotent_skip",
                "action": action_name,
                "message": f"幂等检查: {action_name} 已执行过，跳过",
                "idempotent": True,
                "audit": audit,
            }

        # ── ⑤ 执行模式路由 ──
        effective_mode = mode_override or execution_router.mode
        audit["checks"]["execution_mode"] = {"mode": effective_mode}
        # ── ⑤-b fail-closed(2026-10-23 第二阶段): live + 幂等不可用 → 拒绝 ──
        # 修复前(§9.52): Redis 挂时幂等检查"如实记录但不保护", live 照样放行 ——
        # 同一故障下重放告警会触发**重复封禁**且无人拦截。现在 live 模式
        # 必须幂等可用; dry_run/mock 无真实副作用, 不受影响。
        if (
            effective_mode == MODE_LIVE
            and idem_state == "unavailable"
            and bool(getattr(settings, "require_idempotency_for_live", True))
        ):
            audit["checks"]["idempotency"]["fail_closed"] = True
            logger.error(
                "[SafeExecutor] FAIL-CLOSED: live 模式但幂等检查不可用(Redis 未配置/异常) "
                "→ 拒绝执行 %s (require_idempotency_for_live=true, §9.52)",
                action_name,
            )
            return self._blocked_result(
                action_name, "idempotency_unavailable",
                "live 模式要求幂等保护可用, 但 Redis 不可用 —— 拒绝执行以防止"
                "重复封禁(require_idempotency_for_live=true, §9.52)",
                audit,
            )
        if effective_mode != MODE_LIVE:
            if effective_mode == "mock":
                result = execution_router._mock(action_name, params)
            else:
                result = execution_router._dry_run(action_name, command, params, platform)
            result["audit"] = audit
            result["duration_ms"] = round((time.time() - start_time) * 1000, 1)
            return result

        # ── ⑥ 最小权限 + 真实执行 ──
        if not live_fn:
            return self._blocked_result(
                action_name, "no_executor", "live 模式需要 live_fn", audit
            )

        try:
            result = await live_fn(command)
        except Exception as e:
            logger.error(f"[SafeExecutor] Execution error: {action_name} → {e}")
            audit["checks"]["execution"] = {"error": str(e)}
            return {
                "success": False,
                "mode": "live",
                "action": action_name,
                "error": str(e),
                "audit": audit,
                "duration_ms": round((time.time() - start_time) * 1000, 1),
            }

        # 规范化结果
        if isinstance(result, dict):
            result["mode"] = result.get("mode", "live")
            result["action"] = action_name
        else:
            result = {"success": True, "mode": "live", "action": action_name, "raw": str(result)}

        # ── ⑦ 执行后验证 ──
        exec_success = result.get("success", False)
        if exec_success:
            verify_report = await post_validator.verify(
                action_name=action_name,
                params=params,
                exec_fn=verify_fn or live_fn,
                platform=platform,
            )
            result["verified"] = verify_report.get("verified", False)
            result["verify_evidence"] = verify_report.get("evidence", "")
            audit["checks"]["post_validation"] = verify_report
        else:
            result["verified"] = False

        # ── ⑧ TTL 自动解封 ──
        if exec_success and ttl_seconds > 0 and rule_id:
            ttl_result = await ttl_manager.register(
                rule_id=rule_id,
                action_name=action_name,
                params=params,
                ttl_seconds=ttl_seconds,
            )
            result["ttl_registered"] = ttl_result.get("registered", False)
            result["ttl_expires_at"] = ttl_result.get("expires_at", 0)
            audit["checks"]["ttl"] = ttl_result

        # ── ⑨ 幂等标记 (Redis) ──
        if exec_success:
            marked = await self._idempotency_mark(
                action_name, params, rule_id,
                ttl=idempotency_ttl, key_override=idempotency_key,
            )
            # 标记没写成功 ⇒ 下一次重放不会被幂等拦下（§9.52）
            audit["checks"].setdefault("idempotency", {})["marked"] = marked
            if not marked:
                audit["checks"]["idempotency"]["mark_reason"] = (
                    "幂等标记未写成功 → 下一次重放不会被幂等拦下"
                )

        # ── 审计日志 ──
        duration_ms = round((time.time() - start_time) * 1000, 1)
        result["audit"] = audit
        result["duration_ms"] = duration_ms

        logger.info(
            f"[SafeExecutor] {action_name} completed: "
            f"success={result.get('success')} verified={result.get('verified')} "
            f"mode={result.get('mode')} duration={duration_ms}ms"
        )
        return result

    # ── 内部方法 ──

    def _validate_params(self, action_name: str, params: dict) -> tuple[bool, str]:
        """参数强校验"""
        import ipaddress as _ipaddr

        # IP 类参数校验
        ip_fields = ["src_ip", "host_ip", "host", "ip", "target"]
        for field_name in ip_fields:
            value = params.get(field_name)
            if value and isinstance(value, str):
                # 排除非 IP 值（如主机名、session_id）
                if action_name in ("kill_session",) and field_name == "host":
                    continue
                try:
                    _ipaddr.ip_address(value)
                except ValueError:
                    # 允许 CIDR 格式（nmap 扫描目标）
                    try:
                        _ipaddr.ip_network(value, strict=False)
                    except ValueError:
                        return False, f"参数 {field_name}='{value}' 不是合法 IP 地址"

        # 数值参数校验
        int_fields = {
            "duration": (0, 86400 * 30),
            "duration_minutes": (0, 43200),
            "bandwidth_kbps": (1, 10000000),
            "ttl_seconds": (0, 86400 * 30),
        }
        for field_name, (lo, hi) in int_fields.items():
            value = params.get(field_name)
            if value is not None:
                if not isinstance(value, (int, float)):
                    return False, f"参数 {field_name} 必须是数值"
                if value < lo or value > hi:
                    return False, f"参数 {field_name}={value} 超出范围 [{lo}, {hi}]"

        # 字符串长度限制
        str_fields = ["reason", "rule_name", "rule_id", "session_id", "user"]
        for field_name in str_fields:
            value = params.get(field_name)
            if value and isinstance(value, str) and len(value) > 512:
                return False, f"参数 {field_name} 长度超限 ({len(value)} > 512)"

        return True, "参数校验通过"

    async def _idempotency_check(
        self, action_name: str, params: dict, rule_id: str,
        key_override: str = "",
    ) -> tuple[bool, str]:
        """Redis 幂等检查 → (hit, state)

        state: ``"evaluated"``（查了）/ ``"unavailable"``（**没查成**：
        Redis 未配置或调用出错）。

        2026-10-20 修复（整改报告 §9.52）：此前返回 bool，
        「没查成」与「查了、确实没重复」都是 False → 审计里看不出区别。
        """
        if not self._redis:
            return False, "unavailable"
        key = key_override or self._idem_key(action_name, params, rule_id)
        try:
            exists = await self._redis.exists(key)
        except Exception as e:
            logger.warning(f"[SafeExecutor] Idempotency check error: {e}")
            return False, "unavailable"
        return bool(exists), "evaluated"

    async def _idempotency_mark(
        self, action_name: str, params: dict, rule_id: str, ttl: int = 86400,
        key_override: str = "",
    ) -> bool:
        """标记已执行（Redis，默认 24 小时过期，覆盖 Kafka 重放窗口）

        返回**是否真的标记上了** —— 标记失败意味着「下一次重放不会被拦」，
        审计里必须如实写（整改报告 §9.52）。
        """
        if not self._redis:
            return False
        key = key_override or self._idem_key(action_name, params, rule_id)
        try:
            await self._redis.set(key, "1", ex=ttl)
            return True
        except Exception as e:
            logger.warning(f"[SafeExecutor] Idempotency mark error: {e}")
            return False

    @staticmethod
    def _idem_key(action_name: str, params: dict, rule_id: str) -> str:
        """生成幂等 key（含 event_id 避免不同事件误判为重复）"""
        event_id = params.get("event_id", params.get("eventId", ""))
        if rule_id and event_id:
            return f"{_IDEM_PREFIX}{action_name}:{rule_id}:{event_id}"
        if rule_id:
            return f"{_IDEM_PREFIX}{action_name}:{rule_id}"
        # 按参数排序后哈希（含 event_id）
        stable = json.dumps(params, sort_keys=True, ensure_ascii=False, default=str)
        h = hashlib.sha256(stable.encode()).hexdigest()[:16]
        return f"{_IDEM_PREFIX}{action_name}:{h}"

    @staticmethod
    def _blocked_result(
        action_name: str, check_name: str, reason: str, audit: dict
    ) -> dict:
        """构造拦截结果"""
        return {
            "success": False,
            "blocked": True,
            "blocked_by": check_name,
            "action": action_name,
            "reason": reason,
            "message": f"安全检查拦截 [{check_name}]: {reason}",
            "audit": audit,
        }

    @staticmethod
    async def _noop_fn(command: str) -> dict:
        return {"success": False, "error": "no live_fn provided"}

    def get_status(self) -> dict:
        """获取安全执行器状态"""
        return {
            "execution_mode": execution_router.mode,
            "whitelist_rules": len(command_whitelist.list_rules()),
            "protected_assets": len(asset_whitelist.list_assets()),
            "redis_connected": self._redis is not None,
        }


safe_executor = SafeExecutor()
