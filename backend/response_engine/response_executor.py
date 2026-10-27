"""
响应执行器 (Response Executor)

职责:
  1. 接收策略匹配后的动作列表
  2. 按优先级顺序执行动作
  3. 记录每个动作的结果和回滚令牌
  4. 支持批量执行和部分失败处理
  5. 支持通过回滚令牌撤销已执行的动作

执行流程:
  execute_actions(actions, threat_info)
      → 按优先级排序
      → 逐个执行（并行执行可并行动作）
      → 记录结果 + 回滚令牌
      → 返回 ActionResult

  rollback(rollback_token)
      → 根据令牌查找已执行的动作
      → 逆向逐个回滚
      → 返回回滚结果
"""
import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Optional

from .response_registry import response_registry

logger = logging.getLogger(__name__)

_SNAPSHOT_BEFORE = frozenset({"isolate_host", "kill_process", "quarantine_file"})


def _observe_duration(action_name: str, duration_ms: float) -> None:
    """动作耗时 → Prometheus 直方图（秒）。失败仅记日志，不影响执行。"""
    try:
        from metrics import observe_response_duration
        observe_response_duration(action_name, duration_ms / 1000.0)
    except Exception as e:
        logger.debug(f"metrics observe_response_duration failed: {e}")


def _maybe_prepend_snapshot(actions: list[dict], threat_info: Optional[dict]) -> list[dict]:
    names = [a.get("name") for a in actions]
    if "forensic_snapshot" in names:
        return actions
    if not any(n in _SNAPSHOT_BEFORE for n in names):
        return actions
    if any((a.get("params") or {}).get("skip_snapshot") for a in actions):
        return actions
    host_ip = ""
    pid = None
    if threat_info:
        host_ip = threat_info.get("host_ip") or threat_info.get("src_ip") or ""
        pid = threat_info.get("process_id") or threat_info.get("pid")
    for a in actions:
        p = a.get("params") or {}
        host_ip = p.get("host_ip") or p.get("src_ip") or host_ip
        if p.get("pid") is not None:
            pid = p.get("pid")
    snap = {"name": "forensic_snapshot", "params": {"host_ip": host_ip, "reason": "pre-containment snapshot"}}
    if pid not in (None, ""):
        snap["params"]["pid"] = pid
    return [snap] + actions


#: 动作参数里**不得**原样进日志的键（子串匹配，忽略大小写）。
#:
#: 为什么需要脱敏：整改报告 §9.61 要求「动作参数必须进审计」，
#: 但响应动作的参数里可能有凭据（ssh 密码、token…）。
#: 审计要回答的是「这个动作对什么做了什么」，不是「它带了什么秘密」——
#: 所以**键名保留**（「它带了 password 参数」本身就是信息），值替换成 ***。
_SENSITIVE_PARAM_PATTERNS = (
    "password", "passwd", "pwd", "secret", "token", "credential",
    "apikey", "api_key", "access_key", "private_key", "cookie",
)

#: 参数值写进日志时的最大长度（超出截断）。
_MAX_PARAM_VALUE_LEN = 500


def redact_action_params(params: dict) -> dict:
    """把动作参数整理成**可进审计**的形状。

    · 敏感键的值 → `***`（键名保留）；
    · 超长值截断（正文/命令行可能很长）；
    · 不可 JSON 序列化的值 → 字符串。

    整改报告 §9.61：此前 `ActionResult` **不带参数**，于是
    `action_rows_from_batch` 写进响应日志的 `action_params` 只有
    `{execution_mode, verified, error}` —— 「这个动作到底对什么
    做了什么」在审计里查不到（比如告警发到了哪个 webhook URL）。
    """
    if not isinstance(params, dict):
        return {}
    out: dict = {}
    for raw_key, value in params.items():
        key = str(raw_key)
        if any(p in key.lower() for p in _SENSITIVE_PARAM_PATTERNS):
            out[key] = "***"
            continue
        if isinstance(value, str):
            if value.lower().startswith(("http://", "https://")):
                # URL 可能**内嵌密钥**（告警 webhook 尤其常见）→
                # 审计里只留可关联、不含密钥的形态（整改报告 §9.63）
                from .response_registry import redact_url_for_log
                out[key] = redact_url_for_log(value)
            elif len(value) > _MAX_PARAM_VALUE_LEN:
                out[key] = value[:_MAX_PARAM_VALUE_LEN] + "…（已截断）"
            else:
                out[key] = value
        elif isinstance(value, (int, float, bool)) or value is None:
            out[key] = value
        elif isinstance(value, (list, tuple, set)):
            out[key] = [str(x)[:200] for x in list(value)[:50]]
        elif isinstance(value, dict):
            out[key] = {str(k): str(v)[:200] for k, v in list(value.items())[:50]}
        else:
            out[key] = str(value)[:_MAX_PARAM_VALUE_LEN]
    return out


def _extract_rule_id(result: "ActionResult") -> str:
    """从动作结果里提取防火墙规则 id（block_ip 的 `FW-RULE-*`）。

    存进回滚记录是**冗余保险**：常规回滚走 `_unblock_ip(src_ip)` 反查
    活跃规则即可；rule_id 直接对应 `ssh_firewall.rollback(rule_id)`，
    供排障与未来的定向删除使用。拿不到就空串（dry_run/mock 等模式
    字段名不一，不做猜测式解析）。
    """
    inner = result.result if isinstance(result.result, dict) else {}
    for key in ("firewall_rule_id", "rule_id"):
        v = inner.get(key)
        if isinstance(v, str) and v:
            return v
    return ""


def redact_text_for_log(text: str) -> str:
    """错误文本里可能带完整 URL（含 token/key），落日志前统一脱敏。"""
    if not text:
        return ""
    import re
    from .response_registry import redact_url_for_log
    return re.sub(
        r"https?://[^\s\"'<>]+",
        lambda m: redact_url_for_log(m.group(0)),
        str(text),
    )


@dataclass
class ActionResult:
    """单次动作执行结果"""
    action_name: str
    success: bool
    result: dict = field(default_factory=dict)
    error: str = ""
    rollback_token: str = ""
    duration_ms: float = 0.0
    idempotent: bool = False
    #: 动作**实际收到的参数**（已脱敏）。
    #:
    #: 整改报告 §9.61：此前 `ActionResult` 不带参数 →
    #: 响应日志里的 `action_params` 只有执行模式/校验结果/错误三项，
    #: 「动作的目标是什么」（封禁哪台机、告警发到哪个 URL）不可见。
    params: dict = field(default_factory=dict)


@dataclass
class BatchActionResult:
    """批量执行结果"""
    total: int = 0
    succeeded: int = 0
    failed: int = 0
    #: 不可逆动作（reversible=False）在回滚时的计数 —— 它们没有回滚函数，
    #: 历史上被计成 failed（PERF-2026-10-26：rollback_batch 对含 send_alert
    #: 的批次恒 failed=2），语义上它们是「无需回滚」而不是「回滚失败」。
    skipped: int = 0
    results: list[ActionResult] = field(default_factory=list)
    batch_rollback_token: str = ""
    start_time: float = 0.0
    end_time: float = 0.0
    error: str = ""

    @property
    def duration_ms(self) -> float:
        return (self.end_time - self.start_time) * 1000


class RollbackStore:
    """回滚令牌存储（内存+Redis双写）

    内存为主、Redis 为持久化兜底：进程重启后内存丢失，
    仍可通过 Redis 中的记录回滚已执行的动作（TTL 内有效）。
    Redis 写入失败只降级为纯内存模式，不影响动作执行。
    """

    # Redis key 前缀与 TTL（7 天）：超过 TTL 的回滚记录自动过期
    REDIS_KEY_PREFIX = "rollback:"
    ROLLED_PREFIX = "rollback:done:"
    REDIS_TTL_SEC = 7 * 24 * 3600

    def __init__(self):
        self._store: dict[str, list[dict]] = {}  # token → [action_records]
        self._rolled: set[str] = set()           # 已回滚 token（幂等标记）
        self._redis = None

    def set_redis(self, redis_client):
        self._redis = redis_client

    async def record(self, token: str, action_records: list[dict]):
        # P1: 回滚记录会进 Redis 存 7 天, params 必须与 ActionResult 同口径脱敏 —
        # 修复前原始 params(可含 webhook token/password 类参数)明文入库。
        # 回滚所需的 src_ip/host_ip/domain/rule_id 等非敏感键原样保留。
        action_records = [
            {**rec, "params": redact_action_params(rec.get("params", {}))}
            if isinstance(rec, dict) else rec
            for rec in action_records
        ]
        self._store[token] = action_records
        if self._redis is not None:
            try:
                await self._redis.set(
                    f"{self.REDIS_KEY_PREFIX}{token}",
                    json.dumps(action_records, ensure_ascii=False, default=str),
                    ex=self.REDIS_TTL_SEC,
                )
            except Exception as e:
                logger.warning(f"RollbackStore: failed to persist token to Redis: {e}")
        logger.info(f"RollbackStore: recorded {len(action_records)} actions under token {token[:16]}...")

    async def get(self, token: str) -> Optional[list[dict]]:
        records = self._store.get(token)
        if records:
            return records
        # 内存未命中（如进程重启后）→ 从 Redis 读取并回填
        if self._redis is not None:
            try:
                raw = await self._redis.get(f"{self.REDIS_KEY_PREFIX}{token}")
                if raw:
                    records = json.loads(raw)
                    self._store[token] = records
                    return records
            except Exception as e:
                logger.warning(f"RollbackStore: failed to read token from Redis: {e}")
        return None

    async def remove(self, token: str):
        self._store.pop(token, None)
        if self._redis is not None:
            try:
                await self._redis.delete(f"{self.REDIS_KEY_PREFIX}{token}")
            except Exception as e:
                logger.warning(f"RollbackStore: failed to delete token from Redis: {e}")

    async def mark_rolled(self, token: str):
        """标记该批次已回滚（幂等）。内存为主，Redis 持久化（TTL 与回滚记录一致 7 天）。

        进程重启后内存丢失，仍可从 Redis 判断"已回滚过"，避免重复删除规则。
        """
        self._rolled.add(token)
        if self._redis is not None:
            try:
                await self._redis.set(f"{self.ROLLED_PREFIX}{token}", "1", ex=self.REDIS_TTL_SEC)
            except Exception as e:
                logger.warning(f"RollbackStore: failed to persist rolled flag to Redis: {e}")

    async def is_rolled(self, token: str) -> bool:
        """该批次是否已回滚过（内存优先，Redis 兜底）"""
        if token in self._rolled:
            return True
        if self._redis is not None:
            try:
                if await self._redis.get(f"{self.ROLLED_PREFIX}{token}"):
                    self._rolled.add(token)
                    return True
            except Exception as e:
                logger.warning(f"RollbackStore: failed to read rolled flag from Redis: {e}")
        return False


rollback_store = RollbackStore()


class ResponseExecutor:
    """响应执行器"""

    def __init__(self):
        pass

    async def execute_actions(
        self,
        actions: list[dict],
        threat_info: Optional[dict] = None,
        parallel: bool = False,
    ) -> BatchActionResult:
        """
        执行一组响应动作

        Args:
            actions: [{"name": "block_ip", "params": {...}}, ...]
            threat_info: 威胁上下文（用于日志）
            parallel: 是否并行执行（可并行动作之间）

        Returns:
            BatchActionResult
        """
        batch_result = BatchActionResult(
            total=len(actions),
            start_time=time.time(),
        )

        if not actions:
            batch_result.end_time = time.time()
            return batch_result

        actions = _maybe_prepend_snapshot(list(actions), threat_info)
        batch_result.total = len(actions)

        # 生成批次回滚令牌（使用 crypto 随机数）
        import secrets
        batch_token = f"batch_{secrets.token_hex(16)}"
        batch_result.batch_rollback_token = batch_token
        action_records = []

        if parallel:
            # 并行执行
            tasks = [self._execute_one(action, threat_info) for action in actions]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for i, r in enumerate(results):
                if isinstance(r, Exception):
                    batch_result.results.append(ActionResult(
                        action_name=actions[i].get("name", "?"),
                        success=False,
                        error=str(r),
                    ))
                    batch_result.failed += 1
                else:
                    batch_result.results.append(r)
                    if r.success:
                        batch_result.succeeded += 1
                    else:
                        batch_result.failed += 1
                    action_records.append({
                        "action": r.action_name,
                        "success": r.success,
                        "rollback_token": r.rollback_token,
                        # 回滚记录必须存**执行时有效 params**（含注入后的
                        # src_ip/host_ip 等），而不是调用方原始 params ——
                        # 2026-10-26 前存原始值，策略批次没写 src_ip 时
                        # rollback_batch 逆向调 `_unblock_ip()` 缺必填参
                        # TypeError，iptables 规则永远删不掉（回滚断链）。
                        "params": self._effective_params(
                            r.action_name, actions[i].get("params", {}), threat_info),
                        "rule_id": _extract_rule_id(r),
                    })
        else:
            # 串行执行（按优先级）
            for action in actions:
                result = await self._execute_one(action, threat_info)
                batch_result.results.append(result)
                if result.success:
                    batch_result.succeeded += 1
                else:
                    batch_result.failed += 1
                action_records.append({
                    "action": result.action_name,
                    "success": result.success,
                    "rollback_token": result.rollback_token,
                    # 同上：存执行时有效 params（PERF-2026-10-26 回滚断链修复）
                    "params": self._effective_params(
                        result.action_name, action.get("params", {}), threat_info),
                    "rule_id": _extract_rule_id(result),
                })

        batch_result.end_time = time.time()

        # 存储回滚记录
        await rollback_store.record(batch_token, action_records)

        logger.info(
            f"Batch execute: {batch_result.succeeded}/{batch_result.total} actions OK "
            f"in {batch_result.duration_ms:.0f}ms, "
            f"rollback_token={batch_token[:16]}..."
        )

        return batch_result

    @staticmethod
    def _effective_params(action_name: str, raw_params: dict,
                          threat_info: Optional[dict] = None) -> dict:
        """计算动作的**执行时有效参数**（威胁上下文注入后的完整副本）。

        注入逻辑只有这一份（`_execute_one` 与回滚记录共用）——
        2026-10-26 前注入只发生在 `_execute_one` 的本地副本上，
        回滚记录存的是原始 params，策略批次未显式写 src_ip 时
        批量回滚因缺必填参而整体失败（PERF-2026-10-26 回滚断链）。
        """
        params = dict(raw_params or {})
        if not threat_info:
            return params

        # 根据动作类型注入合适的IP参数（仅注入该动作接受的参数）
        if action_name in ("block_ip", "rate_limit", "unblock_ip", "remove_rate_limit"):
            if "src_ip" not in params and threat_info.get("src_ip"):
                params["src_ip"] = threat_info["src_ip"]
        elif action_name in ("isolate_host", "restore_host"):
            if "host_ip" not in params and threat_info.get("src_ip"):
                params["host_ip"] = threat_info["src_ip"]
        elif action_name == "kill_session":
            if "session_id" not in params and threat_info.get("session_id"):
                params["session_id"] = threat_info["session_id"]
        elif action_name in ("kill_process", "quarantine_file", "clean_persistence", "forensic_snapshot"):
            if "host_ip" not in params:
                params["host_ip"] = threat_info.get("host_ip") or threat_info.get("src_ip") or ""
            if action_name == "kill_process":
                if "pid" not in params and threat_info.get("process_id"):
                    params["pid"] = threat_info["process_id"]
                if "sha256" not in params and threat_info.get("image_hash"):
                    params["sha256"] = threat_info["image_hash"]
            if action_name == "quarantine_file" and "path" not in params and threat_info.get("file_path"):
                params["path"] = threat_info["file_path"]
        elif action_name == "disable_account":
            if "account" not in params and threat_info.get("user_name"):
                params["account"] = threat_info["user_name"]
        elif action_name == "dns_sinkhole":
            if "domain" not in params and threat_info.get("domain"):
                params["domain"] = threat_info["domain"]
        elif action_name == "recall_email":
            if "internet_message_id" not in params and (
                threat_info.get("internet_message_id") or threat_info.get("message_id")
            ):
                params["internet_message_id"] = (
                    threat_info.get("internet_message_id") or threat_info.get("message_id")
                )

        if "reason" not in params:
            params["reason"] = (
                f"威胁类型={threat_info.get('threat_type','?')} "
                f"置信度={threat_info.get('confidence',0):.2f}"
            )
        return params

    async def _execute_one(self, action: dict, threat_info: Optional[dict] = None) -> ActionResult:
        """执行单个动作"""
        name = action.get("name", "")
        params = self._effective_params(name, action.get("params", {}), threat_info)

        t_start = time.time()
        try:
            result = await response_registry.execute(name, **params)
            duration = (time.time() - t_start) * 1000
            _observe_duration(name, duration)
            return ActionResult(
                action_name=name,
                success=result.get("success", False),
                result=result.get("result", result),
                rollback_token=result.get("rollback_token", ""),
                duration_ms=round(duration, 1),
                idempotent=result.get("idempotent", False),
                params=redact_action_params(params),
            )
        except Exception as e:
            duration = (time.time() - t_start) * 1000
            _observe_duration(name, duration)
            logger.error(f"Execute action {name} failed: {e}")
            return ActionResult(
                action_name=name,
                success=False,
                error=str(e),
                duration_ms=round(duration, 1),
                # 失败的动作同样要留下**它要对什么做什么**
                params=redact_action_params(params),
            )

    async def rollback_batch(self, batch_token: str) -> BatchActionResult:
        """
        回滚一批动作（逆向执行）

        Args:
            batch_token: 批次回滚令牌

        Returns:
            BatchActionResult
        """
        records = await rollback_store.get(batch_token)
        if not records:
            return BatchActionResult(
                total=0,
                succeeded=0,
                failed=0,
                error=f"Rollback token not found: {batch_token}",
            )

        # 幂等短路: 该批次已回滚过（本进程或重启后经 Redis 恢复）
        # → 不再逐条删除，直接返回全成功 + idempotent 标记
        if await rollback_store.is_rolled(batch_token):
            logger.info(f"Rollback token {batch_token[:16]}... already rolled back (idempotent replay)")
            return BatchActionResult(
                total=len(records),
                succeeded=len(records),
                failed=0,
                results=[
                    ActionResult(
                        action_name=f"rollback_{r.get('action', '?')}",
                        success=True,
                        idempotent=True,
                        result={"idempotent": True, "message": "already rolled back"},
                    )
                    for r in reversed(records)
                ],
                batch_rollback_token=batch_token,
            )

        logger.info(f"Rolling back {len(records)} actions from token {batch_token[:16]}...")

        # 逆向回滚（最后执行的先回滚）
        results = []
        succeeded = 0
        failed = 0
        skipped = 0

        for record in reversed(records):
            action_name = record["action"]
            params = dict(record.get("params") or {})
            # B1 live 实测补强 (2026-10-27): 回滚记录冗余保存的 rule_id 传给
            # 回滚函数 —— 策略批次未注入威胁上下文时 params 缺 src_ip,
            # block_ip 族回滚可凭 rule_id 直连 ssh_firewall (与 TTL 回滚同路)。
            if record.get("rule_id") and "rule_id" not in params:
                params["rule_id"] = record["rule_id"]

            # 不可逆动作（reversible=False，如 send_alert）没有回滚函数——
            # 它们是「无需回滚」而不是「回滚失败」。2026-10-26 前它们被
            # 计成 failed，导致含 send_alert 的批次 rollback 恒报 failed>0，
            # 且 mark_rolled 永不执行（幂等标记依赖 failed==0）。
            action_def = response_registry.get_action(action_name)
            if action_def is not None and not action_def.reversible:
                skipped += 1
                results.append(ActionResult(
                    action_name=f"rollback_{action_name}",
                    success=True,
                    idempotent=True,
                    result={"skipped": True,
                            "message": "action is not reversible; nothing to roll back"},
                ))
                continue

            try:
                result = await response_registry.rollback(action_name, **params)
                inner = result.get("result", result) if isinstance(result, dict) else {}
                ok = bool(result.get("success", False)) if isinstance(result, dict) else False
                idem = bool(inner.get("idempotent", False)) if isinstance(inner, dict) else False
                # not_found / 幂等成功都不算失败：重复回滚是合法操作
                if isinstance(inner, dict) and inner.get("status") == "not_found":
                    ok = True
                    idem = True
                if idem and not ok:
                    ok = True
                ar = ActionResult(
                    action_name=f"rollback_{action_name}",
                    success=ok,
                    result=inner if isinstance(inner, dict) else {},
                    idempotent=idem,
                )
                results.append(ar)
                if ar.success:
                    succeeded += 1
                else:
                    failed += 1
            except Exception as e:
                failed += 1
                results.append(ActionResult(
                    action_name=f"rollback_{action_name}",
                    success=False,
                    error=str(e),
                ))

        logger.info(
            f"Rollback complete: {succeeded}/{len(records)} rollbacks OK, "
            f"{skipped} skipped (non-reversible)"
        )

        # 已执行的回滚批次打上幂等标记（not_found/幂等成功也标记 —
        # 它们已按成功计数；skipped 同理不算失败；真实错误不标记，
        # 允许调用方重试）
        if failed == 0:
            await rollback_store.mark_rolled(batch_token)

        return BatchActionResult(
            total=len(records),
            succeeded=succeeded,
            failed=failed,
            skipped=skipped,
            results=results,
            batch_rollback_token=batch_token,
        )

    async def get_rollback_status(self, batch_token: str) -> dict:
        """查询回滚状态"""
        records = await rollback_store.get(batch_token)
        if not records:
            return {"found": False}
        return {
            "found": True,
            "action_count": len(records),
            "actions": [
                {"action": r["action"], "success": r["success"]}
                for r in records
            ],
        }


response_executor = ResponseExecutor()
