"""
敏感字段加密 (Field Cipher)

Kafka 消息里的敏感字段用 Fernet (AES-128-CBC + HMAC-SHA256) 加密。
密钥: 环境变量 SHARED_MEMORY_FIELD_ENCRYPTION_KEY。
生成: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

失败关闭:
  解密失败、密钥缺失或不可用、密文格式不对、敏感字段不是字符串，
  都不再把原值当成普通明文继续处理。
  没配密钥时，明文消息仍按明文模式通过；一旦出现 ENC: 前缀，就不能确认内容，直接拒绝。
  密钥配了但无法加载时，带敏感字段的消息全部拒绝，不再静默退回明文。
"""
import base64
import json
import logging
import os
from typing import Optional

logger = logging.getLogger(__name__)

try:
    from cryptography.fernet import Fernet
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False
    logger.warning("cryptography not installed — field encryption disabled")

# 顶层和嵌套容器里都要看的敏感字段。rawData 里的驼峰别名以前没进解密，
# 密文或异常类型会直接绕过校验。
_SENSITIVE = (
    "apiKey", "api_key", "source_key",
    "srcIp", "dstIp", "src_ip", "dst_ip", "message",
)
_CONTAINERS = ("rawData", "log_data", "body")
ENC_PREFIX = "ENC:"


class FieldCipherRejected(Exception):
    """无法确认字段安全性。str(exc) 只有错误码，不带字段内容。"""

    def __init__(self, code: str, detail: str = ""):
        self.code = code
        self.detail = detail
        super().__init__(code)


class CipherDecision:
    def __init__(self, ok: bool, message: Optional[dict], code: str, detail: str = ""):
        self.ok = ok
        self.message = message
        self.code = code
        self.detail = detail


def _fernet_shape(token: str) -> bool:
    """Fernet 令牌至少包含版本、时间戳、IV 和 HMAC。格式不对和认证失败要分开。"""
    if not token or token != token.strip():
        return False
    try:
        data = base64.urlsafe_b64decode(token.encode("ascii"))
    except Exception:
        return False
    return len(data) >= 1 + 8 + 16 + 32 and data[0] == 0x80


class FieldCipher:
    """Kafka 消息敏感字段加密器。"""

    def __init__(self):
        self._fernet: Optional[object] = None
        self._enabled = False
        self._state = "disabled"
        self._init_cipher()

    def _init_cipher(self):
        """从环境变量加载密钥。坏密钥不再伪装成“加密已关闭”。"""
        self._fernet = None
        self._enabled = False
        self._state = "disabled"
        key = os.environ.get("SHARED_MEMORY_FIELD_ENCRYPTION_KEY", "")
        if not HAS_CRYPTO:
            if key:
                self._state = "broken"
                logger.error("[FieldCipher] cryptography is missing while a key is set; fail closed")
            return
        if not key:
            logger.info("[FieldCipher] No encryption key set — plaintext mode")
            return
        try:
            self._fernet = Fernet(key.encode("utf-8") if isinstance(key, str) else key)
            self._enabled = True
            self._state = "enabled"
            logger.info("[FieldCipher] Field encryption enabled")
        except Exception:
            self._state = "broken"
            logger.error("[FieldCipher] Invalid encryption key; plaintext fallback disabled")

    def reload(self) -> None:
        """测试或轮换密钥后重新读取环境变量。"""
        self._init_cipher()

    @property
    def enabled(self) -> bool:
        return self._state == "enabled"

    @property
    def state(self) -> str:
        return self._state

    def _has_sensitive_material(self, msg: dict) -> bool:
        def hot(value) -> bool:
            return value not in (None, "")

        for field in _SENSITIVE:
            if field in msg and hot(msg.get(field)):
                return True
        for name in _CONTAINERS:
            raw = msg.get(name)
            if isinstance(raw, dict):
                for field in _SENSITIVE:
                    if field in raw and hot(raw.get(field)):
                        return True
            elif name in msg and raw not in (None, "", {}):
                return True
        return False

    def _encrypt_field(self, value):
        if value is None or value == "":
            return value
        if not isinstance(value, str):
            raise FieldCipherRejected("anomalous_field", "sensitive field is not a string")
        if value.startswith(ENC_PREFIX):
            return value
        token = self._fernet.encrypt(value.encode("utf-8")).decode("utf-8")
        return ENC_PREFIX + token

    def _decrypt_field(self, value):
        if value is None or value == "":
            return value
        if not isinstance(value, str):
            raise FieldCipherRejected("anomalous_field", "sensitive field is not a string")
        if value.startswith(ENC_PREFIX):
            if self._state != "enabled" or self._fernet is None:
                raise FieldCipherRejected(
                    "cipher_unavailable",
                    "ciphertext present but cipher cannot open it",
                )
            token = value[len(ENC_PREFIX):]
            if not _fernet_shape(token):
                raise FieldCipherRejected("ciphertext_malformed", "ciphertext is not a Fernet token")
            try:
                return self._fernet.decrypt(token.encode("utf-8")).decode("utf-8")
            except Exception:
                raise FieldCipherRejected("decrypt_failed", "ciphertext did not authenticate")
        if self._state == "enabled":
            raise FieldCipherRejected(
                "plaintext_bypass",
                "sensitive field is plaintext while encryption is enabled",
            )
        return value

    def _walk(self, msg: dict, transform) -> dict:
        result = dict(msg)
        for field in _SENSITIVE:
            if field in result:
                result[field] = transform(result[field])
        for name in _CONTAINERS:
            if name not in result or result[name] is None:
                continue
            raw = result[name]
            if not isinstance(raw, dict):
                if self._state == "enabled":
                    raise FieldCipherRejected("anomalous_field", "nested payload is not an object")
                if isinstance(raw, str) and raw.startswith(ENC_PREFIX):
                    raise FieldCipherRejected(
                        "cipher_unavailable",
                        "ciphertext present but cipher cannot open it",
                    )
                continue
            copied = dict(raw)
            for field in _SENSITIVE:
                if field in copied:
                    copied[field] = transform(copied[field])
            result[name] = copied
        return result

    def encrypt_value(self, plaintext: str) -> str:
        if self._state == "broken":
            raise FieldCipherRejected("cipher_unavailable", "encryption key is unusable")
        if not self._enabled or not plaintext:
            return plaintext
        return self._encrypt_field(plaintext)

    def decrypt_value(self, ciphertext: str) -> str:
        """解密一个字段。失败时抛 FieldCipherRejected，不把密文退回成明文。"""
        return self._decrypt_field(ciphertext)

    def encrypt_message(self, msg: dict) -> dict:
        """发送前加密。密钥不可用时拒绝发送，避免悄悄改发明文。"""
        if not isinstance(msg, dict):
            raise FieldCipherRejected("anomalous_field", "payload is not an object")
        if self._state == "broken":
            raise FieldCipherRejected("cipher_unavailable", "encryption key is unusable")
        if self._state != "enabled":
            return msg
        return self._walk(msg, self._encrypt_field)

    def open_message(self, msg: dict) -> CipherDecision:
        """消费前打开消息。ok 为 False 时调用方不得把原消息当明文处理。"""
        if not isinstance(msg, dict):
            return CipherDecision(False, None, "anomalous_field", "payload is not an object")
        if self._state == "broken":
            if self._has_sensitive_material(msg):
                return CipherDecision(False, None, "cipher_unavailable", "encryption key is unusable")
            return CipherDecision(True, dict(msg), "ok", "")
        try:
            opened = self._walk(msg, self._decrypt_field)
        except FieldCipherRejected as exc:
            return CipherDecision(False, None, exc.code, exc.detail)
        return CipherDecision(True, opened, "ok", "")

    def decrypt_message(self, msg: dict) -> dict:
        """解密消息。无法确认安全性时抛错，不能再返回原密文。"""
        decision = self.open_message(msg)
        if not decision.ok or decision.message is None:
            raise FieldCipherRejected(decision.code, decision.detail)
        return decision.message

    def seal_payload(self, payload: dict) -> Optional[str]:
        """把整份原始负载封成一个密文。没有可用密钥时返回 None，调用方不得改存明文。"""
        if self._state != "enabled" or self._fernet is None or not isinstance(payload, dict):
            return None
        raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str).encode("utf-8")
        return ENC_PREFIX + self._fernet.encrypt(raw).decode("utf-8")

    def open_sealed(self, ciphertext: str) -> dict:
        """打开 DLQ 里的整包密文。失败时抛错，不返回原字符串。"""
        plain = self._decrypt_field(ciphertext)
        try:
            obj = json.loads(plain)
        except Exception:
            raise FieldCipherRejected("ciphertext_malformed", "sealed payload is not json")
        if not isinstance(obj, dict):
            raise FieldCipherRejected("anomalous_field", "sealed payload is not an object")
        return obj


field_cipher = FieldCipher()
