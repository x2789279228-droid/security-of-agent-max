"""
kafka_security.py — Kafka 客户端安全连接参数（aiokafka 统一出口）

生产化缺口："内部链路 PLAINTEXT"。本模块给 backend 的全部 aiokafka
producer/consumer 提供同一份安全参数：

  - 默认 ``PLAINTEXT`` → 返回 ``{}``，客户端行为与历史版本完全一致
    （本地/单机演示零迁移成本）；
  - ``settings.kafka_security_protocol=SASL_SSL`` → SCRAM-SHA-512 认证 +
    TLS 加密（证书为部署自签名 CA，见 tools/gen-kafka-certs.sh）。

⚠️ 所有 producer/consumer 构造点都必须 ``**aiokafka_security_kwargs()`` ——
漏一处就会出现"一半连接加密、一半明文"的混合态，比全明文更难排查。
构造点全量清单（tests/test_kafka_security_wiring.py 会守卫这份清单）：
kafka_producer.KafkaProducerWrapper.start、kafka_consumer._init_dlq_producer、
kafka_consumer._consume_topic/_consume_python_ingest/_consume_cep_partial、
edr_fusion.edr_adapter、ids_connector.suricata_connector。
"""
from __future__ import annotations

import logging
import ssl

logger = logging.getLogger(__name__)


def _load_ssl_context() -> ssl.SSLContext:
    """按部署配置构建 TLS 上下文。无 CA 文件时显式降级并留痕（dev-only）。"""
    from config import settings

    ca_file = str(getattr(settings, "kafka_ssl_ca_file", "") or "").strip()
    if ca_file:
        ctx = ssl.create_default_context(cafile=ca_file)
    else:
        # 未提供 CA 却要求 SASL_SSL：跳过校验（自签演示环境可接受，生产禁止）
        logger.warning(
            "[Kafka] SASL_SSL 未配置 kafka_ssl_ca_file — 证书校验被跳过"
            "(self-signed dev fallback)。生产必须提供 CA。")
        ctx = ssl.create_default_context()
        # check_hostname 必须先关 —— CERT_NONE 与开启的 check_hostname 互斥
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    if not bool(getattr(settings, "kafka_ssl_check_hostname", False)):
        # bootstrap 走容器名(kafka-N)或 127.0.0.1，与证书 SAN 的匹配由
        # kafka_ssl_check_hostname 控制；默认关，证书带全 SAN 后可开。
        ctx.check_hostname = False
    return ctx


def aiokafka_security_kwargs() -> dict:
    """aiokafka 构造参数的安全子集；PLAINTEXT（默认）时为空 dict。"""
    from config import settings

    proto = str(getattr(settings, "kafka_security_protocol", "") or "PLAINTEXT").upper()
    if proto == "PLAINTEXT":
        return {}
    kwargs: dict = {"security_protocol": proto}
    if "SASL" in proto:
        kwargs["sasl_mechanism"] = str(
            getattr(settings, "kafka_sasl_mechanism", "") or "SCRAM-SHA-512")
        kwargs["sasl_plain_username"] = str(
            getattr(settings, "kafka_sasl_username", "") or "")
        kwargs["sasl_plain_password"] = str(
            getattr(settings, "kafka_sasl_password", "") or "")
        if not kwargs["sasl_plain_username"] or not kwargs["sasl_plain_password"]:
            logger.error(
                "[Kafka] security_protocol=%s 但未配置 kafka_sasl_username/password"
                " — 连接将认证失败", proto)
    if "SSL" in proto:
        kwargs["ssl_context"] = _load_ssl_context()
    logger.info("[Kafka] client security: protocol=%s mechanism=%s",
                proto, kwargs.get("sasl_mechanism", "-"))
    return kwargs
