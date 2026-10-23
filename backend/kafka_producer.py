"""
Kafka 生产者 — 将审计结果回写到 Kafka 消息总线

后端 Audit-LLM 完成审计后，将结果发布到 security-audit-results topic，
供下游消费者（前端 SSE、响应引擎、归档系统）使用。

增强:
  - 所有消息携带 trace_id header，支持全链路追踪
  - 敏感字段加密（apiKey 等）在发送前自动处理
"""
import asyncio
import json
import logging
import uuid
from typing import Optional

from config import settings
from event_envelope import stamp_identity
from event_identity import identity_headers, resolve
from field_cipher import FieldCipherRejected, field_cipher
from schema_registry import schema_registry

logger = logging.getLogger(__name__)


def _as_float(value, default: float) -> float:
    """容错转 float —— 聚合候选的 confidence 必须以数值形态上网。

    上游可能给字符串（规则里写的是 ``confidence: high``）或 None，
    消费端会直接 ``float()``，非数值会让整条告警处理抛异常。
    这里兜底到**保守值**：宁可置信度低（不处置），也不要凭空高。
    """
    try:
        f = float(value)
    except (TypeError, ValueError):
        return float(default)
    if f != f or f in (float("inf"), float("-inf")):   # NaN / inf
        return float(default)
    return f


try:
    from aiokafka import AIOKafkaProducer
    HAS_KAFKA = True
except ImportError:
    HAS_KAFKA = False
    logger.warning("aiokafka not installed — Kafka producer disabled")


class KafkaProducerWrapper:
    """异步 Kafka 生产者封装（带 trace_id 传播）"""

    def __init__(self):
        self._producer: Optional[object] = None
        self._started = False

    async def start(self):
        if not HAS_KAFKA or not settings.kafka_enabled:
            logger.info("Kafka producer: disabled (kafka_enabled=False or aiokafka missing)")
            return
        try:
            self._producer = AIOKafkaProducer(
                bootstrap_servers=settings.kafka_bootstrap,
                value_serializer=lambda v: json.dumps(v, ensure_ascii=False).encode("utf-8"),
                key_serializer=lambda k: k.encode("utf-8") if k else None,
                acks="all",
                # broker 已落盘但响应超时的重试不得产生重复消息。
                enable_idempotence=True,
            )
            await self._producer.start()
            self._started = True
            logger.info(f"Kafka producer started: {settings.kafka_bootstrap}")
        except Exception as e:
            logger.error(f"Kafka producer failed to start: {e}")
            self._started = False

    async def flush(self):
        """把已完成的发送缓冲刷到 broker。未启动时什么都不做。"""
        if self._producer and self._started:
            await self._producer.flush()

    async def stop(self):
        if self._producer and self._started:
            try:
                await self._producer.flush()
            except Exception as exc:
                logger.warning(f"Kafka producer flush failed: {exc}")
            await self._producer.stop()
            self._started = False
            logger.info("Kafka producer stopped")

    @staticmethod
    def _identity_headers(msg=None, trace_id: str = "") -> list:
        """消息体 + Kafka Headers 都带稳定 event_id / correlation_id / trace_id。"""
        return identity_headers(msg, trace_id=trace_id)

    @staticmethod
    def _trace_headers(trace_id: str = "") -> list:
        """兼容旧调用：仅有 trace 时仍写出 trace_id。"""
        tid = trace_id or uuid.uuid4().hex
        return identity_headers({"traceId": tid}, trace_id=tid)

    async def _send_bounded(self, topic: str, key, value, headers) -> bool:
        """占一个在途名额再发送。名额或 broker 确认超时都记失败，不继续堆 future。"""
        if not self._started or self._producer is None:
            return False
        from capacity import kafka_produce_gate
        timeout = max(0.05, float(getattr(settings, "kafka_produce_timeout_s", 10) or 10))
        try:
            async with kafka_produce_gate().acquire(timeout=timeout):
                fut = self._producer.send(topic, key=key, value=value, headers=headers)
                await asyncio.wait_for(fut, timeout=timeout)
                return True
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.warning("Kafka send failed topic=%s err=%s", topic, type(exc).__name__)
            return False

    async def publish_audit_result(self, event_id: int, result: dict, trace_id: str = ""):
        """发布审计结果到 Kafka"""
        if not self._started:
            return
        try:
            payload = {"stored_id": int(event_id), **(result or {})}
            payload["event_id"] = int(event_id)
            body = stamp_identity(payload, producer="backend.audit")
            encrypted = field_cipher.encrypt_message(body)
        except Exception as e:
            logger.warning(f"Kafka publish audit result failed: {e}")
            return
        ident = resolve(body)
        await self._send_bounded(
            settings.kafka_topic_audit_results,
            ident.event_id or str(event_id),
            encrypted,
            self._identity_headers(body, trace_id=trace_id),
        )

    async def publish_alert(self, alert: dict, trace_id: str = ""):
        """发布告警到 Kafka

        失败**必须可观测**：四种失败模式（producer 未启动 / schema 拒收 /
        盖章加密异常 / broker 发送失败）修复前**全部**只留一行日志 ——
        告警就此消失，运维侧根本不知道有威胁。
        而原始事件路径的同类拒收是**有计数的**
        （`record_ingest("kafka","validation_failed",...)`）——
        这个不对称意味着「丢告警」比「丢原始事件」更难被发现。
        """
        from core_metrics import record_kafka_alert_publish
        if not self._started:
            record_kafka_alert_publish("not_started")
            return
        try:
            body = stamp_identity(alert, producer="backend.alert")
            errors = schema_registry.validate(settings.kafka_topic_alerts, body)
            if errors:
                logger.warning(
                    "Kafka publish alert refused schema err=%s", errors[0]
                )
                record_kafka_alert_publish("schema_rejected")
                return
            encrypted = field_cipher.encrypt_message(body)
        except Exception as e:
            logger.warning(f"Kafka publish alert failed: {e}")
            record_kafka_alert_publish("error")
            return
        ident = resolve(body)
        sent = await self._send_bounded(
            settings.kafka_topic_alerts,
            ident.event_id or body.get("srcIp") or body.get("src_ip") or "",
            encrypted,
            self._identity_headers(body, trace_id=trace_id),
        )
        # ⚠ `_send_bounded` 的返回值修复前**被丢掉** ——
        # broker 发送失败（名额超时 / broker 报错）连调用方都看不见。
        record_kafka_alert_publish("ok" if sent else "send_failed")

    async def publish_sigma_hit(self, hit: dict, trace_id: str = ""):
        """发布 Sigma 聚合候选到 sigma-hit topic(供 Flink 阈值窗口聚合)。
        明文 JSON(聚合信号, 无敏感字段: src_ip/rule_id/threshold/timestamp)。

        ⚠️ 这里是一层**字段白名单**：调用方往 payload 里塞的键不会被
        自动带过去，漏一个就在这条边界上被静默丢弃。
        单事件阶段把执行类动作降级成 alert 之后，「窗口超阈值该怎么处置」
        的决定权就转移到了聚合层，所以 action_recommend/severity/attack_type
        必须在这里显式放行 —— 否则上游辛苦带过来的规则意图到 Flink 就没了，
        而 Flink 那边只能硬编码 severity=high。
        """
        if not self._started:
            return
        try:
            import json
            payload = {
                "src_ip": hit.get("src_ip", ""),
                "rule_id": hit.get("rule_id", ""),
                "threshold": int(hit.get("threshold", 0) or 0),
                "timestamp": int(hit.get("timestamp", 0) or 0),
                # ↓ 聚合窗口据此决定是否阻断，不能省
                "action_recommend": str(hit.get("action_recommend") or "alert"),
                "severity": str(hit.get("severity") or "medium"),
                "attack_type": str(hit.get("attack_type") or "custom"),
                # 数值置信度。消费端用它算策略门槛；缺了会让聚合告警
                # confidence=0.0 → 匹配不到任何策略 → 永不处置。
                # 已用 try 兜底成数值，避免上游传字符串把消费端 int()/float() 打挂。
                "confidence": _as_float(hit.get("confidence"), 0.45),
            }
        except Exception as e:
            logger.warning(f"Kafka publish_sigma_hit failed: {e}")
            return
        await self._send_bounded(
            settings.kafka_topic_sigma_hit,
            payload["src_ip"],
            json.dumps(payload),
            self._identity_headers(hit if isinstance(hit, dict) else payload, trace_id=trace_id),
        )

    # ── Kafka 解耦: Http 网关 → raw 入口直发 ──
    # 网关按 Flink raw 契约(camelCase avsc)归一化事件后投递到 security-logs-raw,
    # 由 Flink LogValidation → AnomalyDetection 转 validated/audit-queue/enriched/alerts。
    # 采用"批量 send + 一次性 await delivery"保证吞吐与 acks=all 持久化, 同时不阻塞上游。

    async def _deliver_batch(self, futures: list, label: str) -> int:
        """统一等待一批 send future 落盘(DeliveryGuarantee), 返回成功条数; 失败条记日志。

        P1: asyncio.gather(*futures, return_exceptions=True) 并发等待 ——
        禁止 for+await 串行。异常条目计入失败并打日志, 成功条目计数返回。
        """
        if not futures:
            return 0
        results = await asyncio.gather(*futures, return_exceptions=True)
        ok = 0
        for r in results:
            if isinstance(r, Exception):
                logger.warning(f"Kafka {label} message delivery failed: {r}")
            else:
                ok += 1
        return ok

    async def produce_raw_batch(
        self,
        events: list[dict],
        topic: str = "",
        key_field: str = "sourceId",
        trace_id: str = "",
    ) -> int:
        """批量写入 raw topic(网关用)。
        events: 已按 Flink raw 契约归一化的 camelCase dict。
        topic 缺省 = settings.kafka_topic_raw。
        返回成功投递条数; producer 未启动则返回 0(不应发生: 网关仅在 started 时调用)。
        """
        if not self._started or not events:
            return 0
        from capacity import chunk_list, kafka_produce_gate
        dst = topic or settings.kafka_topic_raw
        gate = kafka_produce_gate()
        size = max(1, int(getattr(settings, "kafka_produce_batch_size", 100) or 100))
        size = min(size, gate.limit())
        timeout = max(0.05, float(getattr(settings, "kafka_produce_timeout_s", 10) or 10))
        ok = 0
        for chunk in chunk_list(events, size):
            prepared = []
            for ev in chunk:
                try:
                    stamped = stamp_identity(ev, producer="backend.kafka_producer")
                    errors = schema_registry.validate(dst, stamped)
                    if errors:
                        logger.warning(
                            "Kafka produce_raw refused schema topic=%s err=%s",
                            dst, errors[0],
                        )
                        try:
                            from core_metrics import log_process, record_ingest
                            from event_identity import get_event_id
                            record_ingest("kafka", "validation_failed", reason="schema")
                            log_process(
                                logger, event_id=get_event_id(stamped),
                                stage="ingest", result="rejected", reason="schema",
                            )
                        except Exception:
                            pass
                        continue
                    value = field_cipher.encrypt_message(stamped)
                except FieldCipherRejected as exc:
                    logger.warning("Kafka produce_raw refused code=%s", exc.code)
                    try:
                        from core_metrics import log_process, record_ingest
                        from event_identity import get_event_id
                        record_ingest("kafka", "validation_failed", reason="cipher")
                        log_process(
                            logger, event_id=get_event_id(ev if isinstance(ev, dict) else {}),
                            stage="ingest", result="rejected", reason=exc.code or "cipher",
                        )
                    except Exception:
                        pass
                    continue
                prepared.append((stamped, value))
            if not prepared:
                continue

            async def _one(item_ev: dict, item_value: dict) -> bool:
                try:
                    async with gate.acquire(timeout=timeout):
                        fut = self._producer.send(
                            dst,
                            key=str(item_ev.get(key_field) or item_ev.get("eventId") or ""),
                            value=item_value,
                            headers=self._identity_headers(item_ev, trace_id=trace_id),
                        )
                        await asyncio.wait_for(fut, timeout=timeout)
                        return True
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    logger.warning("Kafka produce_raw send failed: %s", type(exc).__name__)
                    return False

            results = await asyncio.gather(
                *(_one(item_ev, item_value) for item_ev, item_value in prepared),
                return_exceptions=True,
            )
            ok += sum(1 for item in results if item is True)
        return ok

    async def produce_raw(
        self,
        event: dict,
        topic: str = "",
        key_field: str = "sourceId",
        trace_id: str = "",
    ) -> bool:
        """包装单条 produce_raw_batch。"""
        n = await self.produce_raw_batch([event], topic=topic,
                                         key_field=key_field, trace_id=trace_id)
        return n == 1

    @property
    def is_active(self) -> bool:
        return self._started


kafka_producer = KafkaProducerWrapper()
