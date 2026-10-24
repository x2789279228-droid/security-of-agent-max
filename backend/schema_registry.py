"""
schema_registry.py — 跨运行时 Schema 契约 (Flink ↔ Python)

权威来源是 backend/schemas/*.schema.json（catalog.json 索引）。
Avro / Java 由 CI 对齐；本模块负责：

  1. 消费侧：解密后的业务结构按 topic 校验，信封先拆再校验 payload。
  2. 生产侧：有契约的 topic 在发送前校验。
  3. 注册到 Confluent Schema Registry。409 只有在已有记录与本次内容
     完全相同（同 subject、同 schema）时才算幂等成功。
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from config import settings
from event_envelope import (
    DEFAULT_SCHEMA_VERSION,
    is_envelope,
    unwrap,
    version_errors,
)
from schema_compat import load_catalog, schemas_equal

logger = logging.getLogger(__name__)

_SCHEMAS_DIR = Path(__file__).parent / "schemas"

# 目录不可用时的兜底 topic → 文件映射
_FALLBACK_TOPIC_MAP = {
    "security-events-enriched": "security_event.schema.json",
    # Python 权威检测主通道。P0-3：网关投递的是**传输包装**
    # (uuid/eventId/body/...)，不是扁平业务事件 —— 修复前绑到
    # security_event.schema.json 会在发送前校验失败 → produced=0 →
    # 网关整批 503 not_durable。
    "security-events-ingest": "ingest_wrapper.schema.json",
    "security-audit-queue": "security_event.schema.json",
    "security-logs-raw": "security_event.schema.json",
    "security-logs-validated": "security_event.schema.json",
    "security-alerts": "alert_event.schema.json",
    # 残留修复(2026-10-24): sigma 候选此前无 schema 绑定, 契约只靠测试 ——
    # 运行时无门禁, 键名漂移(如 op 丢失)会让 Flink 悄悄回退硬编码语义。
    "security-sigma-hit": "sigma_hit.schema.json",
}

try:
    from jsonschema import Draft7Validator
    HAS_JSONSCHEMA = True
except ImportError:
    HAS_JSONSCHEMA = False
    logger.warning("jsonschema not installed — Kafka schema validation disabled")


def _topic_map_from_catalog() -> dict[str, str]:
    try:
        catalog, _ = load_catalog()
    except Exception:
        return dict(_FALLBACK_TOPIC_MAP)
    mapping: dict[str, str] = {}
    for item in catalog.get("schemas") or []:
        json_name = Path(item.get("json_schema") or "").name
        if not json_name:
            continue
        for topic in item.get("topics") or []:
            mapping[str(topic)] = json_name
    return mapping or dict(_FALLBACK_TOPIC_MAP)


def _schema_version_for_file(schema_file: str) -> str:
    try:
        catalog, _ = load_catalog()
        for item in catalog.get("schemas") or []:
            if Path(item.get("json_schema") or "").name == schema_file:
                return str(item.get("version") or DEFAULT_SCHEMA_VERSION)
        env = (catalog.get("envelope") or {}).get("version")
        if env:
            return str(env)
    except Exception:
        pass
    return DEFAULT_SCHEMA_VERSION


TOPIC_SCHEMA_MAP = _topic_map_from_catalog()


@dataclass
class RegisterOutcome:
    subject: str
    ok: bool
    idempotent: bool = False
    status_code: int = 0
    reason: str = ""
    schema_id: Optional[int] = None
    version: Optional[int] = None


class SchemaRegistryClient:
    """轻量 Schema Registry 客户端 (REST API) + 本地 JSON Schema 校验"""

    def __init__(self):
        self._validators: dict[str, Draft7Validator] = {}
        self._schemas: dict[str, dict] = {}
        self._registry_base = None
        self.last_register: list[RegisterOutcome] = []
        if settings.schema_registry_url:
            self._registry_base = settings.schema_registry_url.rstrip("/")
            if not self._registry_base.startswith("http"):
                self._registry_base = "http://" + self._registry_base

    def _load_schema(self, schema_file: str) -> dict:
        if schema_file not in self._schemas:
            path = _SCHEMAS_DIR / schema_file
            if not path.exists():
                logger.error(f"[Schema] 找不到 schema 文件: {path}")
                return {}
            with open(path, encoding="utf-8") as f:
                self._schemas[schema_file] = json.load(f)
        return self._schemas[schema_file]

    def _schema_file_for_topic(self, topic: str) -> Optional[str]:
        best = None
        for prefix, file in TOPIC_SCHEMA_MAP.items():
            if topic == prefix or topic.startswith(prefix + "-"):
                if best is None or len(prefix) > len(best[0]):
                    best = (prefix, file)
        return best[1] if best else None

    def get_validator(self, topic: str) -> Optional[Draft7Validator]:
        schema_file = self._schema_file_for_topic(topic)
        if not schema_file or not HAS_JSONSCHEMA:
            return None
        if schema_file not in self._validators:
            schema = self._load_schema(schema_file)
            if not schema:
                return None
            try:
                self._validators[schema_file] = Draft7Validator(schema)
            except Exception as e:
                logger.warning(f"[Schema] 校验器构建失败: {e}")
                return None
        return self._validators[schema_file]

    def _envelope_validator(self) -> Optional[Draft7Validator]:
        if not HAS_JSONSCHEMA:
            return None
        if "envelope.schema.json" not in self._validators:
            schema = self._load_schema("envelope.schema.json")
            if not schema:
                return None
            self._validators["envelope.schema.json"] = Draft7Validator(schema)
        return self._validators["envelope.schema.json"]

    def _collect_errors(self, validator: Optional[Draft7Validator], data: dict) -> list[str]:
        if validator is None:
            return []
        return [f"{list(e.path)}: {e.message}" for e in validator.iter_errors(data)]

    def validate(self, topic: str, event: dict) -> list[str]:
        """校验解密后的业务结构。信封先校验外层，再校验 payload。"""
        if not isinstance(event, dict):
            return ["message is not an object"]
        schema_file = self._schema_file_for_topic(topic)
        current_ver = _schema_version_for_file(schema_file) if schema_file else DEFAULT_SCHEMA_VERSION
        errors: list[str] = []
        business = event
        if is_envelope(event):
            errors.extend(self._collect_errors(self._envelope_validator(), event))
            opened = unwrap(event)
            errors.extend(version_errors(opened.schema_version, current_ver))
            business = opened.payload
        else:
            declared = event.get("schemaVersion") or event.get("schema_version") or ""
            errors.extend(version_errors(str(declared), current_ver))

        validator = self.get_validator(topic)
        if validator is not None:
            errors.extend(self._collect_errors(validator, business))
        if errors:
            ident = event.get("eventId") or event.get("event_id") or event.get("alertId") or "?"
            logger.warning(
                f"[Schema] topic={topic} 事件校验失败 ({len(errors)} 项): "
                f"{errors[0]} eventId={ident}"
            )
        return errors

    def subjects(self) -> list[tuple[str, str]]:
        """(subject, schema_file) 列表。"""
        seen: dict[str, str] = {}
        try:
            catalog, _ = load_catalog()
            for item in catalog.get("schemas") or []:
                json_name = Path(item.get("json_schema") or "").name
                for subject in item.get("subjects") or []:
                    seen[str(subject)] = json_name
        except Exception:
            pass
        if not seen:
            for prefix, schema_file in TOPIC_SCHEMA_MAP.items():
                seen[f"{prefix}-value"] = schema_file
        return list(seen.items())

    async def register_schema(
        self,
        subject: str,
        schema: dict,
        client: Any,
        *,
        strict: bool = False,
    ) -> RegisterOutcome:
        """注册一个 subject。409 必须核对已有内容，不能一律当成功。"""
        payload = {"schemaType": "JSON", "schema": json.dumps(schema, ensure_ascii=False)}
        url = f"{self._registry_base}/subjects/{subject}/versions"
        try:
            resp = await client.post(url, json=payload)
        except Exception as exc:
            return RegisterOutcome(
                subject=subject, ok=False, status_code=0, reason=f"request_failed:{type(exc).__name__}"
            )
        if resp.status_code in (200, 201):
            body = _safe_json(resp)
            return RegisterOutcome(
                subject=subject,
                ok=True,
                status_code=resp.status_code,
                reason="registered",
                schema_id=_as_int(body.get("id")),
                version=_as_int(body.get("version")),
            )
        if resp.status_code == 409:
            return await self._resolve_conflict(subject, schema, client, resp, strict=strict)
        snippet = (getattr(resp, "text", "") or "")[:240]
        return RegisterOutcome(
            subject=subject,
            ok=False,
            status_code=resp.status_code,
            reason=f"register_rejected:{snippet}",
        )

    async def _resolve_conflict(
        self,
        subject: str,
        schema: dict,
        client: Any,
        conflict_resp: Any,
        *,
        strict: bool,
    ) -> RegisterOutcome:
        conflict_body = _safe_json(conflict_resp)
        conflict_msg = str(conflict_body.get("message") or conflict_resp.text or "")[:240]

        lookup = await _post_lookup(client, self._registry_base, subject, schema)
        if lookup is not None and schemas_equal(lookup.get("schema"), schema):
            return RegisterOutcome(
                subject=subject,
                ok=True,
                idempotent=True,
                status_code=409,
                reason="duplicate_identical",
                schema_id=_as_int(lookup.get("id")),
                version=_as_int(lookup.get("version")),
            )

        latest = await _get_latest(client, self._registry_base, subject)
        if latest is not None and schemas_equal(latest.get("schema"), schema):
            return RegisterOutcome(
                subject=subject,
                ok=True,
                idempotent=True,
                status_code=409,
                reason="duplicate_identical",
                schema_id=_as_int(latest.get("id")),
                version=_as_int(latest.get("version")),
            )

        reason = "schema_conflict"
        if latest is not None:
            reason = (
                f"schema_conflict existing_id={latest.get('id')} "
                f"existing_version={latest.get('version')} {conflict_msg}"
            )
        elif conflict_msg:
            reason = f"schema_conflict {conflict_msg}"
        logger.error("[Schema] %s 注册冲突，拒绝当作成功: %s", subject, reason)
        if strict:
            logger.error("[Schema] strict 模式: %s 阻止发布", subject)
        return RegisterOutcome(
            subject=subject,
            ok=False,
            status_code=409,
            reason=reason,
            schema_id=_as_int((latest or {}).get("id")),
            version=_as_int((latest or {}).get("version")),
        )

    async def register_all(self, client: Any = None, *, strict: bool = False) -> list[RegisterOutcome]:
        """把 JSON Schema 注册到 Confluent Schema Registry。"""
        self.last_register = []
        if not self._registry_base:
            logger.info("[Schema] schema_registry_url 未配置, 跳过注册")
            return []
        own_client = client is None
        try:
            if own_client:
                import httpx
                client = httpx.AsyncClient(timeout=5)
            results: list[RegisterOutcome] = []
            for subject, schema_file in self.subjects():
                schema = self._load_schema(schema_file)
                if not schema:
                    results.append(RegisterOutcome(
                        subject=subject, ok=False, reason=f"missing_schema:{schema_file}"
                    ))
                    continue
                outcome = await self.register_schema(
                    subject, schema, client, strict=strict
                )
                results.append(outcome)
                if outcome.ok:
                    kind = "幂等跳过" if outcome.idempotent else "已注册"
                    logger.info(
                        "[Schema] %s %s (HTTP %s)", kind, subject, outcome.status_code
                    )
                else:
                    logger.error(
                        "[Schema] 注册 %s 失败: HTTP %s %s",
                        subject, outcome.status_code, outcome.reason[:200],
                    )
            self.last_register = results
            return results
        except Exception as e:
            logger.warning(f"[Schema] Schema Registry 注册失败 (不影响消费): {e}")
            failed = [RegisterOutcome(subject="*", ok=False, reason=str(e)[:200])]
            self.last_register = failed
            if strict:
                raise
            return failed
        finally:
            if own_client and client is not None:
                aclose = getattr(client, "aclose", None)
                if aclose is not None:
                    await aclose()


def _safe_json(resp: Any) -> dict:
    try:
        data = resp.json()
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _as_int(value: Any) -> Optional[int]:
    try:
        if value is None or value == "":
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


async def _post_lookup(client: Any, base: str, subject: str, schema: dict) -> Optional[dict]:
    url = f"{base}/subjects/{subject}"
    payload = {"schemaType": "JSON", "schema": json.dumps(schema, ensure_ascii=False)}
    try:
        resp = await client.post(url, json=payload)
    except Exception:
        return None
    if resp.status_code != 200:
        return None
    body = _safe_json(resp)
    return body or None


async def _get_latest(client: Any, base: str, subject: str) -> Optional[dict]:
    url = f"{base}/subjects/{subject}/versions/latest"
    try:
        resp = await client.get(url)
    except Exception:
        return None
    if resp.status_code != 200:
        return None
    return _safe_json(resp) or None


schema_registry = SchemaRegistryClient()
