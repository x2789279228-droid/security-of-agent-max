# -*- coding: utf-8 -*-
"""Sigma 聚合告警必须满足 alert_event 契约。"""
from __future__ import annotations

import json
from pathlib import Path

import pytest


def _schema():
    path = Path(__file__).resolve().parents[1] / "schemas" / "alert_event.schema.json"
    return json.loads(path.read_text(encoding="utf-8"))


def test_sigma_aggregate_alert_matches_alert_schema():
    jsonschema = pytest.importorskip("jsonschema")
    payload = {
        "source": "sigma_aggregation",
        "alertId": "SIGMA-AGG-SIG-007-203.0.113.9-1700000000000",
        "alertType": "SIGMA_AGGREGATE",
        "eventType": "BRUTE_FORCE",
        "severity": "high",
        "srcIp": "203.0.113.9",
        "src_ip": "203.0.113.9",
        "rule_id": "SIG-007",
        "count": 6,
        "threshold": 5,
        "message": "Sigma aggregate: rule=SIG-007 count=6 threshold=5",
        "anomalyScore": 0.8,
        "confidence": 0.8,
        "timestamp": 1700000000000,
        "reasons": ["sigma_aggregate:SIG-007", "count=6 threshold=5"],
        "action_recommend": "alert",
    }
    errors = sorted(
        jsonschema.Draft7Validator(_schema()).iter_errors(payload),
        key=lambda e: list(e.path),
    )
    assert not errors, [f"{list(e.path)}: {e.message}" for e in errors]
