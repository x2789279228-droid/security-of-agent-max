"""临时故障 vs 永久错误，以及每条事件的处理结果。

asyncio.gather 的返回值不是业务成功判定。每条事件必须落到
success / retrying / failed / dlq 之一。

Kafka 延迟重试 Topic 与顺序：
  ordering=strict（默认）——同一分区/业务键的后续消息不得越过未完成记录。
    临时失败保留 offset，主消费队列在水位处等待。不把失败消息发到 retry topic。
  ordering=unordered ——允许发往延迟重试 Topic 并提交原 offset。
    同一业务键的后续消息可以越过它。只在明确不要求顺序时开启。
"""
from __future__ import annotations

import asyncio
import json
import random
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

KIND_TRANSIENT = "transient"
KIND_PERMANENT = "permanent"

STATUS_SUCCESS = "success"
STATUS_RETRYING = "retrying"
STATUS_FAILED = "failed"
STATUS_DLQ = "dlq"

ORDER_STRICT = "strict"
ORDER_UNORDERED = "unordered"

# 进程内重试默认：旧实现是 0.5s + 1.0s = 1.5s 总等待，这里改为有上限的指数退避。
DEFAULT_INITIAL_S = 1.0
DEFAULT_MULTIPLIER = 2.0
DEFAULT_MAX_DELAY_S = 30.0
DEFAULT_JITTER = 0.2
DEFAULT_BUDGET_S = 60.0
DEFAULT_MAX_ATTEMPTS = 5

_PERMANENT_NAMES = frozenset({
    "SchemaError",
    "ValidationError",
    "DecodeError",
    "JSONDecodeError",
    "UnicodeDecodeError",
    "UnicodeError",
    "FieldCipherRejected",
    "ValueError",
    "TypeError",
    "KeyError",
    "AttributeError",
    "LookupError",
    "IngestWrapper",
})

_PERMANENT_CODES = frozenset({
    "schema_invalid",
    "decode_error",
    "ingest_wrapper",
    "ciphertext_malformed",
    "plaintext_bypass",
    "key_unavailable",
    "cipher_error",
})

_TRANSIENT_NAMES = frozenset({
    "TimeoutError",
    "CancelledError",  # 分类时仍会单独挑出 asyncio.CancelledError 并上抛
    "ConnectionError",
    "ConnectionResetError",
    "ConnectionRefusedError",
    "BrokenPipeError",
    "OSError",
    "OperationalError",
    "InterfaceError",
    "DBAPIError",
    "GateTimeout",
    "IncompleteReadError",
    "KafkaConnectionError",
    "KafkaTimeoutError",
    "RequestTimedOutError",
    "UnresponsiveBrokerError",
    "CommitFailedError",
})


@dataclass(frozen=True)
class ErrorVerdict:
    kind: str
    retryable: bool
    error_class: str
    error_code: str
    message: str = ""


@dataclass
class EventOutcome:
    """单条事件的业务结果。提交位点只看 committable()。"""
    status: str
    retryable: bool = False
    error_class: str = ""
    error_code: str = ""
    error: str = ""
    attempts: int = 1
    event_id: str = ""
    stored_id: int = 0
    idempotent: bool = False
    extra: dict = field(default_factory=dict)

    def committable(self) -> bool:
        """业务成功，或永久失败已经确认进入 DLQ，才允许推进 offset。"""
        return self.status in (STATUS_SUCCESS, STATUS_DLQ)

    @classmethod
    def success(
        cls,
        *,
        event_id: str = "",
        stored_id: int = 0,
        idempotent: bool = False,
        attempts: int = 1,
        extra: Optional[dict] = None,
    ) -> "EventOutcome":
        return cls(
            status=STATUS_SUCCESS,
            retryable=False,
            event_id=event_id,
            stored_id=stored_id,
            idempotent=idempotent,
            attempts=attempts,
            extra=dict(extra or {}),
        )

    @classmethod
    def retrying(
        cls,
        *,
        error: str = "",
        error_class: str = "",
        error_code: str = "transient",
        attempts: int = 1,
        event_id: str = "",
        extra: Optional[dict] = None,
    ) -> "EventOutcome":
        return cls(
            status=STATUS_RETRYING,
            retryable=True,
            error=error,
            error_class=error_class,
            error_code=error_code or "transient",
            attempts=attempts,
            event_id=event_id,
            extra=dict(extra or {}),
        )

    @classmethod
    def failed(
        cls,
        *,
        error: str = "",
        error_class: str = "",
        error_code: str = "permanent_failure",
        attempts: int = 1,
        event_id: str = "",
        extra: Optional[dict] = None,
    ) -> "EventOutcome":
        return cls(
            status=STATUS_FAILED,
            retryable=False,
            error=error,
            error_class=error_class,
            error_code=error_code or "permanent_failure",
            attempts=attempts,
            event_id=event_id,
            extra=dict(extra or {}),
        )

    @classmethod
    def dlq(
        cls,
        *,
        error: str = "",
        error_class: str = "",
        error_code: str = "permanent_failure",
        attempts: int = 1,
        event_id: str = "",
        extra: Optional[dict] = None,
    ) -> "EventOutcome":
        return cls(
            status=STATUS_DLQ,
            retryable=False,
            error=error,
            error_class=error_class,
            error_code=error_code or "permanent_failure",
            attempts=attempts,
            event_id=event_id,
            extra=dict(extra or {}),
        )


def normalize_ordering(value: Any) -> str:
    text = str(value or ORDER_STRICT).strip().lower()
    if text in ("unordered", "any", "out_of_order", "retry_topic"):
        return ORDER_UNORDERED
    return ORDER_STRICT


def allows_key_overtake(ordering: Any) -> bool:
    """True 表示延迟重试期间，同一业务键的后续消息可以越过未完成记录。"""
    return normalize_ordering(ordering) == ORDER_UNORDERED


def backoff_delay(
    attempt: int,
    *,
    initial: float = DEFAULT_INITIAL_S,
    multiplier: float = DEFAULT_MULTIPLIER,
    max_delay: float = DEFAULT_MAX_DELAY_S,
    jitter: float = DEFAULT_JITTER,
    rng: Optional[random.Random] = None,
) -> float:
    """第 attempt 次失败之后、下一次尝试之前的等待（attempt 从 1 起）。

    delay = min(max_delay, initial * multiplier^(attempt-1))，再乘 (1 ± jitter)。
    """
    n = max(1, int(attempt or 1))
    init = max(0.0, float(initial))
    cap = max(0.0, float(max_delay))
    mult = max(1.0, float(multiplier))
    base = min(cap, init * (mult ** (n - 1)))
    j = max(0.0, float(jitter))
    if j <= 0 or base <= 0:
        return base
    picker = rng if rng is not None else random
    span = base * min(j, 1.0)
    return max(0.0, base + picker.uniform(-span, span))


def clamp_delay_to_budget(delay: float, slept: float, budget: float) -> float:
    """总睡眠不超过 budget。预算已耗尽则返回 0。"""
    d = max(0.0, float(delay))
    used = max(0.0, float(slept))
    cap = max(0.0, float(budget))
    if used >= cap:
        return 0.0
    return min(d, cap - used)


def budget_exhausted(slept: float, budget: float) -> bool:
    return max(0.0, float(slept)) >= max(0.0, float(budget))


def _exc_name(exc: BaseException) -> str:
    return type(exc).__name__


def _code_from_exc(exc: BaseException) -> str:
    code = getattr(exc, "code", None)
    if code:
        return str(code)[:80]
    return ""


def classify_exception(exc: BaseException) -> ErrorVerdict:
    """把异常分成临时可重试 / 永久不可重试。CancelledError 仍标为 transient，调用方必须原样上抛。"""
    if isinstance(exc, asyncio.CancelledError):
        return ErrorVerdict(
            kind=KIND_TRANSIENT,
            retryable=False,
            error_class="CancelledError",
            error_code="cancelled",
            message="cancelled",
        )
    name = _exc_name(exc)
    message = str(exc) or name
    code = _code_from_exc(exc)
    if code in _PERMANENT_CODES:
        return ErrorVerdict(
            kind=KIND_PERMANENT,
            retryable=False,
            error_class=name,
            error_code=code,
            message=message,
        )
    if isinstance(exc, json.JSONDecodeError) or isinstance(exc, UnicodeError):
        return ErrorVerdict(
            kind=KIND_PERMANENT,
            retryable=False,
            error_class=name,
            error_code="decode_error",
            message=message,
        )
    low = message.lower()
    if "schema" in low and ("valid" in low or "校验" in low or "missing" in low):
        return ErrorVerdict(
            kind=KIND_PERMANENT,
            retryable=False,
            error_class=name,
            error_code="schema_invalid",
            message=message,
        )
    if isinstance(exc, (ValueError, TypeError, LookupError)):
        return ErrorVerdict(
            kind=KIND_PERMANENT,
            retryable=False,
            error_class=name,
            error_code=code or "permanent_failure",
            message=message,
        )
    try:
        from field_cipher import FieldCipherRejected
    except Exception:
        FieldCipherRejected = ()  # type: ignore
    if FieldCipherRejected and isinstance(exc, FieldCipherRejected):
        return ErrorVerdict(
            kind=KIND_PERMANENT,
            retryable=False,
            error_class="FieldCipherRejected",
            error_code=code or "cipher_error",
            message=message,
        )
    try:
        from capacity import GateTimeout
    except Exception:
        GateTimeout = ()  # type: ignore
    if GateTimeout and isinstance(exc, GateTimeout):
        return ErrorVerdict(
            kind=KIND_TRANSIENT,
            retryable=True,
            error_class="GateTimeout",
            error_code="gate_timeout",
            message=message,
        )
    try:
        from sqlalchemy.exc import DBAPIError, IntegrityError, InterfaceError, OperationalError
    except Exception:
        OperationalError = InterfaceError = IntegrityError = DBAPIError = ()  # type: ignore
    if OperationalError and isinstance(exc, OperationalError):
        return ErrorVerdict(
            kind=KIND_TRANSIENT,
            retryable=True,
            error_class="OperationalError",
            error_code="db_operational",
            message=message,
        )
    if InterfaceError and isinstance(exc, InterfaceError):
        return ErrorVerdict(
            kind=KIND_TRANSIENT,
            retryable=True,
            error_class="InterfaceError",
            error_code="db_interface",
            message=message,
        )
    if IntegrityError and isinstance(exc, IntegrityError):
        # 唯一约束由 store 幂等处理，这里不当永久毒消息。
        return ErrorVerdict(
            kind=KIND_TRANSIENT,
            retryable=True,
            error_class="IntegrityError",
            error_code="db_integrity",
            message=message,
        )
    if DBAPIError and isinstance(exc, DBAPIError):
        return ErrorVerdict(
            kind=KIND_TRANSIENT,
            retryable=True,
            error_class=name,
            error_code="db_error",
            message=message,
        )
    if isinstance(exc, (TimeoutError, asyncio.TimeoutError, ConnectionError, OSError)):
        return ErrorVerdict(
            kind=KIND_TRANSIENT,
            retryable=True,
            error_class=name,
            error_code="transient",
            message=message,
        )
    if name in _PERMANENT_NAMES:
        return ErrorVerdict(
            kind=KIND_PERMANENT,
            retryable=False,
            error_class=name,
            error_code=code or "permanent_failure",
            message=message,
        )
    if name in _TRANSIENT_NAMES:
        return ErrorVerdict(
            kind=KIND_TRANSIENT,
            retryable=True,
            error_class=name,
            error_code=code or "transient",
            message=message,
        )
    # 未知异常：有界重试，避免一次分类失误就把消息送进 DLQ。
    return ErrorVerdict(
        kind=KIND_TRANSIENT,
        retryable=True,
        error_class=name,
        error_code=code or "transient",
        message=message,
    )


def classify_error_text(error: str, error_class: str = "", error_code: str = "") -> ErrorVerdict:
    if error_code in _PERMANENT_CODES:
        return ErrorVerdict(
            kind=KIND_PERMANENT,
            retryable=False,
            error_class=error_class or "PermanentError",
            error_code=error_code,
            message=error,
        )
    if error_class in _PERMANENT_NAMES:
        return ErrorVerdict(
            kind=KIND_PERMANENT,
            retryable=False,
            error_class=error_class,
            error_code=error_code or "permanent_failure",
            message=error,
        )
    if error_class in _TRANSIENT_NAMES:
        return ErrorVerdict(
            kind=KIND_TRANSIENT,
            retryable=True,
            error_class=error_class,
            error_code=error_code or "transient",
            message=error,
        )
    low = (error or "").lower()
    if "schema" in low:
        return ErrorVerdict(
            kind=KIND_PERMANENT,
            retryable=False,
            error_class=error_class or "SchemaError",
            error_code=error_code or "schema_invalid",
            message=error,
        )
    return ErrorVerdict(
        kind=KIND_TRANSIENT,
        retryable=True,
        error_class=error_class or "Error",
        error_code=error_code or "transient",
        message=error,
    )


def outcome_from_verdict(
    verdict: ErrorVerdict,
    *,
    attempts: int = 1,
    event_id: str = "",
    dlq_confirmed: bool = False,
) -> EventOutcome:
    if verdict.kind == KIND_PERMANENT:
        factory = EventOutcome.dlq if dlq_confirmed else EventOutcome.failed
        return factory(
            error=verdict.message,
            error_class=verdict.error_class,
            error_code=verdict.error_code,
            attempts=attempts,
            event_id=event_id,
        )
    return EventOutcome.retrying(
        error=verdict.message,
        error_class=verdict.error_class,
        error_code=verdict.error_code,
        attempts=attempts,
        event_id=event_id,
    )


async def gather_results(*aws):
    """并发等待。返回与输入等长的列表，元素是结果或 Exception。

    禁止用“gather 没抛错”代替每条事件的成功判定。
    CancelledError 仍向上抛，其余异常留在对应槽位。
    """
    if not aws:
        return []
    return await asyncio.gather(*aws, return_exceptions=True)


def count_statuses(outcomes: Iterable[EventOutcome]) -> dict[str, int]:
    tallies = {
        STATUS_SUCCESS: 0,
        STATUS_RETRYING: 0,
        STATUS_FAILED: 0,
        STATUS_DLQ: 0,
    }
    for item in outcomes:
        status = getattr(item, "status", "") or ""
        if status in tallies:
            tallies[status] += 1
        else:
            tallies[status] = tallies.get(status, 0) + 1
    return tallies
