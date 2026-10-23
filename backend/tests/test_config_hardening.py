"""配置与密钥治理（2026-10-23 第一阶段止血）

覆盖:
  - source_api_keys 默认空 —— 源码不再内置演示密钥(公开仓库=泄露)
  - control_hmac_key 在 prod 下拒绝回退 jwt_secret (fail-closed)
  - dev/test 下保留回退并可用
  - 两者皆空时任何环境都拒绝 (原有 fail-closed 行为保持)
  - log_format / auto_migrate 新设置存在且有合理默认
"""
import pytest

from config import settings
from security_crypto import control_hmac_key


def test_source_api_keys_default_is_empty():
    """源码内置演示密钥已删除; 空配置 = 无预置来源 (fail-closed)。"""
    assert settings.source_api_keys == ""


def test_control_hmac_prod_refuses_jwt_fallback(monkeypatch):
    monkeypatch.setattr(settings, "control_hmac_key", "")
    monkeypatch.setattr(settings, "jwt_secret", "some-jwt")
    monkeypatch.setattr(settings, "env_name", "prod")
    with pytest.raises(RuntimeError, match="CONTROL_HMAC_KEY"):
        control_hmac_key()


def test_control_hmac_dev_falls_back_to_jwt(monkeypatch):
    monkeypatch.setattr(settings, "control_hmac_key", "")
    monkeypatch.setattr(settings, "jwt_secret", "dev-jwt-secret")
    monkeypatch.setattr(settings, "env_name", "dev")
    assert control_hmac_key() == b"dev-jwt-secret"


def test_control_hmac_dedicated_key_takes_priority(monkeypatch):
    monkeypatch.setattr(settings, "control_hmac_key", "dedicated-key")
    monkeypatch.setattr(settings, "jwt_secret", "dev-jwt-secret")
    assert control_hmac_key() == b"dedicated-key"


def test_control_hmac_both_empty_raises_in_any_env(monkeypatch):
    monkeypatch.setattr(settings, "control_hmac_key", "")
    monkeypatch.setattr(settings, "jwt_secret", "")
    for env in ("dev", "prod"):
        monkeypatch.setattr(settings, "env_name", env)
        with pytest.raises(RuntimeError):
            control_hmac_key()


def test_new_observability_settings_exist():
    assert hasattr(settings, "log_format")
    assert hasattr(settings, "auto_migrate")
    # 默认 log_format="" = 按 env 自动 (prod→json, 其余→text)
    assert settings.log_format == ""
    assert isinstance(settings.auto_migrate, bool)
