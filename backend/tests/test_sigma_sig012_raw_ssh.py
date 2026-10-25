# -*- coding: utf-8 -*-
"""SIG-012 — 原始 auth.log SSH 爆破规则的编译与匹配守卫。

为什么这条规则值得单独守卫:
    它是规则库第一条「对原始 syslog 文本求值、不依赖上游事件预分类」的
    聚合规则(其余内置规则匹配 url 或 event_type 关键词)。live 真机演练
    (demo/live-drill/)的检出独立性叙事就锚在它身上 ——
    若哪天规则文本、字段映射或编译链被改坏, 演练的「检出独立性」证据
    也就塌了, 必须在 CI 里第一时间红。

断言(全部用 shipped 规则文件, 不用测试副本):
  1. 真实 sshd "Failed password" 原文 → 命中 SIG-012;
  2. 命中是聚合前置语义(requires_aggregation=True, 动作被降级为告警,
     不得直接建议 block_ip —— 单条失败文本不构成爆破结论);
  3. "Invalid user" 变体 → 同样命中(第二个 selection 关键词);
  4. 正常登录 "Accepted password" → 不命中;
  5. 元数据完整: ATT&CK T1110 / attack_type=brute_force / 阈值 spec
     count(src_ip)>5 within 5m。
"""
from __future__ import annotations

import os
import sys

import pytest

os.environ.setdefault("SHARED_MEMORY_SKIP_DOTENV", "1")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sigma_engine.engine import PySigmaDetector  # noqa: E402

RULES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                         "sigma_engine", "rules")


@pytest.fixture(scope="module")
def detector() -> PySigmaDetector:
    det = PySigmaDetector(RULES_DIR, enforce=True)
    compiled: set = set()

    def _collect(obj) -> None:
        if isinstance(obj, dict):
            if "rule_id" in obj:
                compiled.add(obj["rule_id"])
        elif isinstance(obj, (list, tuple)):
            for x in obj:
                _collect(x)

    _collect(det.rules())
    assert "SIG-012" in compiled, f"SIG-012 未编译进规则库: {sorted(compiled)}"
    return det


def _sig012_hits(detector: PySigmaDetector, event: dict):
    return [h for h in detector.detect(event) if h.rule_id == "SIG-012"]


def _raw_fail_event(src: str = "203.0.113.66", user: str = "admin") -> dict:
    # 与真实 /var/log/auth.log 原文一致(syslog-adapter 会加 [hostname] 前缀,
    # message 字段保持原文可匹配)
    return {
        "event": "SYSLOG_EVENT",
        "severity": "info",
        "src_ip": src,
        "protocol": "syslog",
        "message": f"[lab-target] Failed password for invalid user {user} "
                   f"from {src} port 55000 ssh2",
        "confidence": 50,
    }


def test_raw_sshd_failure_text_hits_sig012(detector: PySigmaDetector):
    hits = _sig012_hits(detector, _raw_fail_event())
    assert len(hits) == 1, f"原始认证失败文本应命中一次 SIG-012, 实际 {len(hits)}"
    hit = hits[0]
    # 聚合前置语义: 单条事件只满足筛选, 不构成结论
    assert hit.requires_aggregation is True, "SIG-012 带 x-soc-aggregation, 必须标记前置语义"
    assert hit.action_recommend != "block_ip", (
        "单条失败文本不得直接建议封禁 (PENDING-AGG 语义被破坏)"
    )
    assert hit.aggregation_spec.get("threshold") == 5
    assert hit.aggregation_spec.get("timeframe") == "5m"


def test_invalid_user_variant_hits_sig012(detector: PySigmaDetector):
    ev = _raw_fail_event()
    ev["message"] = "[lab-target] Invalid user backup from 203.0.113.66 port 55001 ssh2"
    hits = _sig012_hits(detector, ev)
    assert len(hits) == 1, "『Invalid user』变体也应命中(selection 第二关键词)"


def test_benign_login_does_not_hit_sig012(detector: PySigmaDetector):
    ev = {
        "event": "USER_LOGIN",
        "severity": "info",
        "src_ip": "203.0.113.66",
        "protocol": "syslog",
        "message": "[lab-target] Accepted password for soc-fw from "
                   "203.0.113.66 port 55002 ssh2",
        "confidence": 90,
    }
    assert _sig012_hits(detector, ev) == [], "正常登录不应命中 SIG-012"


def test_sig012_metadata_complete(detector: PySigmaDetector):
    ev = _raw_fail_event()
    hit = _sig012_hits(detector, ev)[0]
    assert hit.attack_type == "brute_force"
    # 引擎把 SigmaRuleTag 对象原样透传(repr 形式), 断言技术 ID 在其中
    assert "t1110" in str(hit.matched_fields.get("mitre_attack_id"))
    assert hit.matched_fields.get("src_ip") == "203.0.113.66"
