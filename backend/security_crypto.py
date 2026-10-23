"""Control-plane HMAC helpers (approval tickets + audit hash chain)."""
from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any, Optional


def control_hmac_key() -> bytes:
    """取控制面 HMAC 密钥。

    2026-10-03 安全修复：此前在两者皆空时返回 b""，而 hmac_hex() 会回退到源码内
    的公开常量 b"dev-hmac-unconfigured"。结果是：既没配 control_hmac_key 也没配
    jwt_secret 的部署，会用一个**提交在仓库里的常量**给审批工单签名、并给
    audit_trail 哈希链签名 —— 任何读过源码的人都能伪造审批签名（绕过人工审批直接
    执行遏制动作），或重算出合法的审计行哈希，"防篡改"承诺不成立。

    而现在（2026-10-23 第二层收紧）：
      - 两者皆空 → fail-closed 抛异常（不变）；
      - **prod 环境回退 jwt_secret 也被禁止** —— 审批签名与 JWT 必须分钥，
        否则一处泄露即两处失守。prod 未显式配置 control_hmac_key 直接拒绝启动签名。
      - dev/test 保留回退（打 warning），避免要求本地/演示配两把密钥。
    """
    from config import settings
    dedicated = getattr(settings, "control_hmac_key", "") or ""
    if dedicated:
        return dedicated.encode("utf-8")
    jwt = getattr(settings, "jwt_secret", "") or ""
    env_name = (getattr(settings, "env_name", "dev") or "dev").lower()
    if env_name == "prod":
        raise RuntimeError(
            "env_name=prod 下拒绝回退 jwt_secret 作为审批 HMAC 密钥："
            "请在 .env 显式设置 SHARED_MEMORY_CONTROL_HMAC_KEY（与 JWT_SECRET 取不同值）。"
        )
    if not jwt:
        raise RuntimeError(
            "control_hmac_key / jwt_secret 未配置：拒绝以公开默认密钥签署审批票据与审计哈希链。"
            "请在 .env 中设置 SHARED_MEMORY_CONTROL_HMAC_KEY（建议与 JWT_SECRET 取不同值）。"
        )
    import logging
    logging.getLogger(__name__).warning(
        "control_hmac_key 未配置，回退 jwt_secret —— 仅限 dev/test；"
        "生产部署必须设置独立的 SHARED_MEMORY_CONTROL_HMAC_KEY"
    )
    return jwt.encode("utf-8")


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def hmac_hex(message: str, key: Optional[bytes] = None) -> str:
    # 2026-10-03: 原先在此回退到 b"dev-hmac-unconfigured"（源码内公开常量）。
    # 现改为依赖 control_hmac_key() 自身 fail-closed —— 缺密钥时抛异常而非降级签名。
    k = key if key is not None else control_hmac_key()
    return hmac.new(k, message.encode("utf-8"), hashlib.sha256).hexdigest()


def hmac_ok(message: str, signature: str, key: Optional[bytes] = None) -> bool:
    expected = hmac_hex(message, key=key)
    got = (signature or "").strip().lower()
    if len(got) != len(expected):
        return False
    return hmac.compare_digest(expected, got)


def actions_digest(actions: list) -> str:
    return sha256_hex(canonical_json(actions or []))


def sign_approval(ticket_id: str, exp: float, digest: str, policy_name: str) -> str:
    msg = f"{ticket_id}|{int(exp)}|{digest}|{policy_name or ''}"
    return hmac_hex(msg)


def verify_approval(ticket_id: str, exp: float, digest: str, policy_name: str, sig: str) -> bool:
    msg = f"{ticket_id}|{int(exp)}|{digest}|{policy_name or ''}"
    return hmac_ok(msg, sig)
