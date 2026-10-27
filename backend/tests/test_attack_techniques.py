# -*- coding: utf-8 -*-
"""路线 5(2026-10-27)回归: ATT&CK 技术标签提取与告警面透传。

钉住三件事:
  1. extract_attack_techniques 的归一化口径(tag 形态/子技术/战术提取);
  2. detect() 把 techniques 写回 log_data(告警/案例/覆盖矩阵的统一读点);
  3. 真实 SIG 规则命中 → techniques 非空(端到端)。
"""
from __future__ import annotations

import asyncio
import os
import sys

import pytest

os.environ.setdefault("SHARED_MEMORY_SKIP_DOTENV", "1")
os.environ.setdefault("SHARED_MEMORY_DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("SHARED_MEMORY_JWT_SECRET", "test-secret")
os.environ.setdefault("SHARED_MEMORY_LLM_API_KEY", "test")
os.environ.setdefault("SHARED_MEMORY_EMBEDDING_API_KEY", "test")
os.environ.setdefault("SHARED_MEMORY_ADMIN_PASSWORD", "test")

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sigma_detector import extract_attack_techniques  # noqa: E402


def test_tag_form_normalization():
    """规则 tag 形态 'attack.credential-access.t1110' → T1110 + 战术。"""
    ev = {"_sigma": {"hits": [
        {"rule_id": "X", "mitre_attack_id": "attack.credential-access.t1110"},
    ]}}
    out = extract_attack_techniques(ev)
    assert out == ["T1110"]
    assert ev["raw_data"]["attack_tactics"] == ["credential-access"]


def test_subtechnique_folds_to_parent():
    ev = {"_sigma": {"hits": [
        {"rule_id": "X", "mitre_attack_id": "T1059.001"},
        {"rule_id": "Y", "mitre_attack_id": "t1059.001"},
    ]}}
    assert extract_attack_techniques(ev) == ["T1059"]


def test_dedupe_and_stable_order():
    ev = {"_sigma": {"hits": [
        {"mitre_attack_id": "T1046"},
        {"mitre_attack_id": "T1021"},
        {"mitre_attack_id": "attack.execution.t1059"},
    ]}}
    out = extract_attack_techniques(ev)
    assert out == sorted(set(out)) == ["T1021", "T1046", "T1059"]


def test_empty_and_garbage_safe():
    assert extract_attack_techniques({}) == []
    assert extract_attack_techniques({"_sigma": {"hits": None}}) == []
    assert extract_attack_techniques({"_sigma": {"hits": ["junk", 42]}}) == []


def test_detect_integration_sig003_traversal():
    """真实引擎端到端: 路径遍历 URL 命中 SIG-003 → techniques=['T1083']。"""
    from ingest_pipeline import detect

    ev = {
        "eventId": "evt-tech-001",
        "event": "WEB_ATTACK",
        "severity": "high",
        "src_ip": "203.0.113.66",
        "dst_ip": "10.30.0.10:8080",
        "url": "/download/../../etc/passwd",
        "message": "traversal probe",
    }
    result = asyncio.new_event_loop().run_until_complete(detect(ev))
    assert ev["techniques"] == ["T1083"], (
        f"detect 后 techniques={ev.get('techniques')} —— ATT&CK 告警面透传断了"
    )
    assert result is not None
