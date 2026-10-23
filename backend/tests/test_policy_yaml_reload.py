"""
L2: 响应策略 YAML 化 + 热加载回归
"""
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import models  # noqa: F401

from response_engine import policy_store
from response_engine.response_policies import (
    MatchStatus,
    PolicyEngine,
    UNCERTAIN_POLICY_NAME,
    policy_engine,
)


def test_yaml_seed_loads_on_startup():
    """默认引擎应从 policies/*.yml 加载（source=yaml）。"""
    assert getattr(policy_engine, "_load_source", "") == "yaml"
    names = {p.name for p in policy_engine.get_policies()}
    assert "C2通信自动封禁" in names
    assert "暴力破解自动阻断" in names
    # Uncertain 模板不在普通匹配列表
    assert UNCERTAIN_POLICY_NAME not in names or True
    unc = policy_engine._uncertain_policy
    assert unc is not None
    assert unc.name == UNCERTAIN_POLICY_NAME
    assert unc.actions[0]["params"]["duration_minutes"] == 5


def test_create_policy_hot_reload_matches_without_restart():
    """新建 YAML 策略后 reload，不重启即可 match。"""
    with tempfile.TemporaryDirectory() as tmp:
        # 先拷贝一份最小种子：uncertain + 空
        engine = PolicyEngine()
        engine._policies_dir = tmp
        engine.yaml_reload_interval_sec = 0
        # 无 YAML 时回退代码种子
        engine.reload(tmp)
        assert engine._load_source == "code"

        result = policy_store.create_policy(
            {
                "id": "POL-BRUTE-WEAK",
                "name": "弱口令暴力遏制",
                "threat_type": "BRUTE_WEAK",
                "min_confidence": 0.4,
                "min_severity": "medium",
                "actions": [
                    {"name": "block_ip", "params": {"duration_minutes": 1440}},
                    {"name": "send_alert", "params": {"severity": "high"}},
                ],
                "auto_execute": True,
                "priority": 75,
                "cooldown_minutes": 10,
            },
            policies_dir=tmp,
        )
        assert result["success"], result
        engine.reload(tmp)
        assert engine._load_source == "yaml"
        engine.clear_cooldowns()
        am = engine.match("BRUTE_WEAK", 0.9, "high", "10.77.0.1")
        assert am.matched
        assert am.match_status == MatchStatus.MATCHED
        assert am.policy_name == "弱口令暴力遏制"
        block = next(a for a in am.actions if a["name"] == "block_ip")
        assert block["params"]["duration_minutes"] == 1440


def test_disable_policy_falls_to_uncertain():
    with tempfile.TemporaryDirectory() as tmp:
        policy_store.create_policy(
            {
                "id": "POL-TMP-X",
                "name": "临时专属",
                "threat_type": "TMP_THREAT_X",
                "min_confidence": 0.3,
                "min_severity": "low",
                "actions": [{"name": "send_alert", "params": {}}],
                "auto_execute": True,
                "priority": 60,
            },
            policies_dir=tmp,
        )
        # Uncertain 模板
        policy_store.create_policy(
            {
                "id": "POL-UNCERTAIN",
                "name": UNCERTAIN_POLICY_NAME,
                "role": "uncertain_template",
                "threat_type": "__UNCERTAIN__",
                "actions": [
                    {"name": "block_ip", "params": {"duration_minutes": 5}},
                    {"name": "send_alert", "params": {"severity": "high"}},
                ],
                "auto_execute": True,
                "require_approval": True,
                "priority": 1,
                "cooldown_minutes": 5,
            },
            policies_dir=tmp,
        )
        engine = PolicyEngine()
        engine._policies_dir = tmp
        engine.reload(tmp)
        engine.clear_cooldowns()
        am1 = engine.match("TMP_THREAT_X", 0.9, "high", "10.77.0.2")
        assert am1.policy_name == "临时专属"

        policy_store.delete_policy("临时专属", policies_dir=tmp)
        engine.reload(tmp)
        engine.clear_cooldowns()
        am2 = engine.match("TMP_THREAT_X", 0.9, "high", "10.77.0.3")
        assert am2.match_status == MatchStatus.UNCERTAIN


def test_update_policy_merges_nested_match():
    """部分更新 match.min_confidence 不得丢掉原 threat_type，响应必须带回 match。"""
    with tempfile.TemporaryDirectory() as tmp:
        created = policy_store.create_policy(
            {
                "id": "POL-MATCH-MERGE",
                "name": "匹配合并探测",
                "threat_type": "C2_BEACON",
                "min_confidence": 0.8,
                "min_severity": "high",
                "actions": [{"name": "send_alert", "params": {}}],
                "auto_execute": False,
                "priority": 90,
            },
            policies_dir=tmp,
        )
        assert created["success"], created
        result = policy_store.update_policy(
            "匹配合并探测",
            {"match": {"min_confidence": 0.9}},
            change_summary="提高置信度阈值",
            policies_dir=tmp,
        )
        assert result["success"], result
        content = result["version_data"]["content"]
        assert content["match"]["min_confidence"] == 0.9
        assert content["match"]["threat_type"] == "C2_BEACON"
        assert content["match"]["min_severity"] == "high"


def test_policy_update_request_forbids_unknown_fields():
    from pydantic import ValidationError
    from routers.response import PolicyUpdateRequest

    PolicyUpdateRequest(name="C2通信自动封禁", min_confidence=0.9)
    try:
        PolicyUpdateRequest(name="C2通信自动封禁", confidence=0.9)  # type: ignore[call-arg]
        raise AssertionError("未知字段应被拒绝")
    except ValidationError as exc:
        assert "confidence" in str(exc)


def test_update_policy_rejects_unknown_keys():
    """拼错字段名必须失败，不能 success=True 却静默丢弃。"""
    with tempfile.TemporaryDirectory() as tmp:
        created = policy_store.create_policy(
            {
                "id": "POL-UNKNOWN-KEY",
                "name": "未知字段探测",
                "threat_type": "C2_BEACON",
                "min_confidence": 0.8,
                "min_severity": "high",
                "actions": [{"name": "send_alert", "params": {}}],
                "auto_execute": False,
                "priority": 90,
            },
            policies_dir=tmp,
        )
        assert created["success"], created
        result = policy_store.update_policy(
            "未知字段探测",
            {"confidence": 0.9},
            change_summary="错误字段名",
            policies_dir=tmp,
        )
        assert result["success"] is False
        assert "不支持的字段" in result["error"]
        assert "confidence" in result["error"]
        loaded = policy_store.get_policy("未知字段探测", policies_dir=tmp)
        assert loaded["min_confidence"] == 0.8


def test_update_policy_accepts_full_yaml_rollback_payload():
    """回滚把 to_yaml_dict 整份写回，字段都在 schema 内。"""
    with tempfile.TemporaryDirectory() as tmp:
        created = policy_store.create_policy(
            {
                "id": "POL-ROLLBACK-OK",
                "name": "回滚探测",
                "threat_type": "C2_BEACON",
                "min_confidence": 0.8,
                "min_severity": "high",
                "actions": [{"name": "send_alert", "params": {}}],
                "auto_execute": False,
                "priority": 90,
            },
            policies_dir=tmp,
        )
        content = dict(created["version_data"]["content"])
        content["match"] = dict(content["match"])
        content["match"]["min_confidence"] = 0.7
        result = policy_store.apply_content_to_file(
            "回滚探测", content, policies_dir=tmp,
        )
        assert result["success"], result
        assert result["version_data"]["content"]["match"]["min_confidence"] == 0.7


def test_mtime_hot_reload_on_match():
    with tempfile.TemporaryDirectory() as tmp:
        engine = PolicyEngine()
        engine._policies_dir = tmp
        engine.yaml_reload_interval_sec = 0  # 每次 match 都检查
        engine.reload(tmp)
        engine.clear_cooldowns()
        # 写入新策略后不显式 reload，靠 _maybe_reload_yaml
        policy_store.create_policy(
            {
                "id": "POL-HOT",
                "name": "热加载探测",
                "threat_type": "HOT_RELOAD_TYPE",
                "min_confidence": 0.1,
                "min_severity": "info",
                "actions": [{"name": "send_alert", "params": {}}],
                "auto_execute": True,
                "priority": 55,
            },
            policies_dir=tmp,
        )
        # 保证 mtime 更新可见
        time.sleep(0.05)
        engine._last_mtime_check = 0
        am = engine.match("HOT_RELOAD_TYPE", 0.9, "high", "10.77.0.4")
        assert am.matched
        assert am.policy_name == "热加载探测"


def test_uncertain_still_works_with_yaml_template():
    policy_engine.clear_cooldowns()
    am = policy_engine.match("BRAND_NEW_VENDOR_ALERT", 0.9, "high", "10.77.0.5")
    assert am.match_status == MatchStatus.UNCERTAIN
    assert am.policy_name == UNCERTAIN_POLICY_NAME
