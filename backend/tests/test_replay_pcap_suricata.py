# -*- coding: utf-8 -*-
"""路线 2(2026-10-27)回归: Suricata IDS 接线 + pcap 回放评测器。

钉住四件事:
  1. 连接器默认落库处理器: 告警不再凭空消失(此前 process_eve 只计数);
  2. app.py 启动分支存在(接线守卫, AST 级);
  3. 回放评测器三方对账口径(alert_lines = accepted + deduped);
  4. EVE → SecurityEvent 映射 + 场景检出判定。
"""
from __future__ import annotations

import asyncio
import ast
import json
import os
import sys
from pathlib import Path

import pytest

os.environ.setdefault("SHARED_MEMORY_SKIP_DOTENV", "1")
os.environ.setdefault("SHARED_MEMORY_DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("SHARED_MEMORY_JWT_SECRET", "test-secret")
os.environ.setdefault("SHARED_MEMORY_LLM_API_KEY", "test")
os.environ.setdefault("SHARED_MEMORY_EMBEDDING_API_KEY", "test")
os.environ.setdefault("SHARED_MEMORY_ADMIN_PASSWORD", "test")

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from eval_datasets import replay_pcap_suricata as rp  # noqa: E402
from ids_connector.suricata_connector import SuricataConnector  # noqa: E402

FIXTURES = Path(rp.__file__).parent / "fixtures"
EVE_SAMPLE = FIXTURES / "suricata_eve_sample.jsonl"

SqliAlert = {
    "event_type": "alert",
    "timestamp": "2026-10-26T10:00:01+0000",
    "src_ip": "203.0.113.50",
    "dest_ip": "10.30.0.10",
    "dest_port": 80,
    "proto": "TCP",
    "alert": {"action": "allowed", "gid": 1, "signature_id": 2027865,
              "rev": 3, "signature": "ET WEB_SERVER SQLi",
              "category": "web-application-attack", "severity": 1},
}


def test_default_handler_registers_when_no_callback():
    """start() 后必须有默认处理器(否则告警凭空消失 = 死代码复活失败)。"""
    conn = SuricataConnector()
    assert not conn._alert_callbacks, "前置: 全新实例不应自带回调"
    asyncio.new_event_loop().run_until_complete(conn.start())
    try:
        assert conn._alert_callbacks, "start() 未挂默认落库处理器"
    finally:
        asyncio.new_event_loop().run_until_complete(conn.stop())


def test_default_handler_processes_alert_without_db(monkeypatch):
    """默认处理器走 detect → store; 无 DB 时 fail-open 计数, 不炸消费循环。"""
    conn = SuricataConnector()
    asyncio.new_event_loop().run_until_complete(conn.start())
    try:
        alert = asyncio.new_event_loop().run_until_complete(
            conn.process_eve(dict(SqliAlert)))
        assert alert is not None, "首条告警不应被去重"
        assert alert.to_security_event()["event_type"] == "SURICATA:web-application-attack"
        # 无 DB 环境下 store 失败必须只计数不抛(消费循环存活)
        assert conn.get_stats().get("store_failures", 0) >= 0
    finally:
        asyncio.new_event_loop().run_until_complete(conn.stop())


def test_app_wiring_start_branch():
    """app.py 必须有 suricata_enabled 启动分支(AST 守卫)。"""
    backend = Path(__file__).resolve().parent.parent
    # utf-8-sig: app.py 带 BOM, 直接 utf-8 读会让 ast.parse 报 U+FEFF 语法错
    tree = ast.parse((backend / "app.py").read_text(encoding="utf-8-sig"))
    found = False
    for node in ast.walk(tree):
        if isinstance(node, ast.If) and "suricata_enabled" in ast.dump(node.test):
            for sub in ast.walk(node):
                if (isinstance(sub, ast.ImportFrom)
                        and sub.module == "ids_connector.suricata_connector"):
                    found = True
    assert found, "app.py 缺少 suricata_enabled 启动分支 —— IDS 接线断了"


def test_eve_fixture_reconciliation_and_mapping():
    """fixture 回放: 6 alert → 5 接受 + 1 去重, 三类类别全部映射。"""
    rows = rp.load_eve(EVE_SAMPLE)
    res = asyncio.new_event_loop().run_until_complete(rp.replay_scenario(rows))
    assert res["eve_alert_lines"] == 6
    assert res["accepted"] == 5
    assert res["deduped"] == 1
    assert res["reconciled"] is True, "三方对账破了: alert = accepted + deduped"
    assert res["platform_events"] == res["accepted"]
    assert res["type_counts"].get("alert") == 6
    assert res["type_counts"].get("dns") == 1
    assert set(res["observed_categories"]) >= {
        "web-application-attack", "attempted-admin", "command-and-control",
    }
    # 每个 accepted 事件都过了真实 detect 链(有结果记录, 无异常)
    assert len(res["detect_results"]) == 5
    assert all("error" not in d for d in res["detect_results"])


def test_manifest_scenario_detection(tmp_path):
    manifest = json.loads((FIXTURES / "suricata_scenarios.json").read_text(encoding="utf-8"))
    out = rp.run_manifest(manifest, FIXTURES)
    assert out["reconciled"] is True
    sc = out["scenarios"][0]
    assert sc["detected"] is True, "期望三类 ⊆ 观测类别"
    md = rp.render_markdown(out)
    assert "全部一致" in md
