"""攻击剧本 / 手动录入端点测试（2026-11 传智杯 AI Web 改造）。

覆盖：
- log_scenarios 纯函数：目录/构建/来源标记/无预置 eventId
- POST /api/logs/scenario/{name}：Kafka 路径 202 + event_ids + 标记透传
- POST /api/logs/manual：单条注入 + inject_source=manual:<user> 审计标记
- 未知剧本 404；鉴权缺失 401

与 test_http_ingest_gateway.py 同一打桩口径：_ingest_mode→kafka、
_enqueue_ingest 捕获，绝不触真实 Kafka/PG。
"""
import sys
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from auth import UserInfo, get_current_user  # noqa: E402
import log_scenarios  # noqa: E402
from routers import logs as logs_router  # noqa: E402


def _app() -> FastAPI:
    app = FastAPI()
    app.include_router(logs_router.router)

    async def _fake_session():
        yield None

    async def _fake_user():
        return UserInfo(username="duty1", role="operator", jti="t-jti")

    app.dependency_overrides[get_current_user] = _fake_user
    return app


@pytest.fixture()
def client():
    with TestClient(_app()) as c:
        yield c


@pytest.fixture()
def kafka_mode(monkeypatch):
    """Kafka 打桩：_ingest_mode→kafka，_enqueue_ingest 捕获并全部确认。"""
    captured = []

    async def fake_enqueue(session_id, api_key, events):
        captured.append({"session_id": session_id, "api_key": api_key, "events": list(events)})
        return len(events)

    monkeypatch.setattr(logs_router, "_ingest_mode", lambda: "kafka")
    monkeypatch.setattr(logs_router, "_enqueue_ingest", fake_enqueue)
    return captured


# ── 纯函数 ─────────────────────────────────────────────────────────────────

def test_catalog_has_demo_scenarios():
    cat = {s["name"]: s for s in log_scenarios.scenario_catalog()}
    for name in ("kill_chain", "c2_beacon", "brute_force", "web_attack", "dns_exfil", "ddos", "benign", "full_story"):
        assert name in cat, f"missing scenario {name}"
        assert cat[name]["count"] > 0
        assert cat[name]["description"]


def test_build_scenario_tags_source_and_no_eventid():
    for name in log_scenarios.SCENARIOS:
        logs = log_scenarios.build_scenario(name)
        assert logs, name
        assert all(d.get("inject_source") == f"scenario:{name}" for d in logs), name
        # eventId 必须留空给入库盖章（ensure_identity）—— 预置会撞幂等去重
        assert all("eventId" not in d for d in logs), name
        assert all(isinstance(d.get("message"), str) and d["message"] for d in logs), name


def test_kill_chain_has_eight_steps():
    logs = log_scenarios.build_scenario("kill_chain")
    assert len(logs) == 8
    # 杀伤链叙事顺序: 侦察在前, C2/外泄在中后段
    assert "step 1/8" in logs[0]["message"]
    assert "step 8/8" in logs[-1]["message"]


def test_benign_is_low_severity_control_group():
    logs = log_scenarios.build_scenario("benign")
    assert all(d["severity"] in ("low", "medium") for d in logs)


# ── 端点 ───────────────────────────────────────────────────────────────────

def test_scenario_inject_kafka_202_with_tags(client, kafka_mode):
    resp = client.post("/api/logs/scenario/kill_chain")
    assert resp.status_code == 202
    data = resp.json()
    assert data["scenario"] == "kill_chain"
    assert data["count"] == 8
    assert len(data["event_ids"]) == 8
    # 打桩捕获:标记应原样进入 Kafka 消息体
    batch = kafka_mode[0]
    assert batch["events"][0]["inject_source"] == "scenario:kill_chain"


def test_scenario_unknown_name_404(client):
    resp = client.post("/api/logs/scenario/not_a_scenario")
    assert resp.status_code == 404


def test_scenario_list(client):
    resp = client.get("/api/logs/scenarios")
    assert resp.status_code == 200
    names = {s["name"] for s in resp.json()["scenarios"]}
    assert "kill_chain" in names


def test_manual_inject_stamps_operator(client, kafka_mode):
    resp = client.post("/api/logs/manual", json={
        "message": {"event": "C2_BEACON", "severity": "critical",
                    "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
                    "message": "<b>手工</b>录入的告警"},
    })
    assert resp.status_code == 202
    batch = kafka_mode[0]
    ev = batch["events"][0]
    assert ev["inject_source"] == "manual:duty1"
    # HTML 注入面:接入台手动录入同样过 _sanitize_value
    assert "<b>" not in ev["message"]


def test_manual_requires_auth():
    app = FastAPI()
    app.include_router(logs_router.router)
    with TestClient(app, raise_server_exceptions=False) as c:
        resp = c.post("/api/logs/manual", json={"message": {"event": "X"}})
    assert resp.status_code == 401


def test_manual_batch_roundtrip(client, kafka_mode):
    logs = [{"event": "PORT_SCAN", "severity": "medium", "src_ip": "1.2.3.4",
             "dst_ip": "5.6.7.8", "message": "scan"}] * 3
    resp = client.post("/api/logs/manual/batch", json={"logs": logs})
    assert resp.status_code == 202
    data = resp.json()
    assert len(data["event_ids"]) == 3
    assert kafka_mode[0]["events"][0]["inject_source"] == "manual:duty1"
