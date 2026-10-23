"""SSE 事件分类、临界队列和 SecurityEvent.id 补查。"""
import asyncio
import json

from event_bus import BusEvent, EventBus, classify_event, render_sse, should_skip_live
from event_replay import parse_refresh_ids, resolve_resume_cursor


def test_resume_cursor_ignores_epoch_seq_and_keeps_the_newer_id():
    assert resolve_resume_cursor("171000.42", "80") == (80, "event_id")
    assert resolve_resume_cursor("40", "80") == (80, "event_id")
    assert resolve_resume_cursor("171000.42", None) == (0, "ignored")
    assert resolve_resume_cursor(None, None) == (0, "none")
    assert parse_refresh_ids("3, x, 3, 0, 9") == [3, 9]


def test_sla_breach_is_critical_and_heartbeat_is_bulk():
    lane, severity, kind, eid = classify_event("pipeline_health", {"type": "sla_breach"})
    assert (lane, severity, kind, eid) == ("critical", "high", "epoch_seq", None)
    lane, severity, kind, _eid = classify_event("pipeline_health", {"type": "alert", "stage": "ingest"})
    assert lane == "critical" and severity == "high"
    lane, severity, kind, eid = classify_event("pipeline_health", {"type": "heartbeat"})
    assert (lane, severity, kind) == ("bulk", "medium", "epoch_seq")
    # agent_stage 即使带 event_id 也不推进业务游标
    lane, severity, kind, eid = classify_event(
        "agent_stage", {"event_id": 12, "status": "error", "stage": "audit"},
    )
    assert lane == "bulk" and severity == "high" and kind == "epoch_seq" and eid is None
    lane, severity, kind, eid = classify_event(
        "security_event", {"event_id": 12, "severity": "critical"},
    )
    assert (lane, severity, kind, eid) == ("critical", "critical", "event_id", 12)


def test_sse_id_does_not_rewind_or_stamp_ephemeral_events():
    high = 0
    security = BusEvent(seq=1, type="security_event", cursor_kind="event_id", event_id=100, lane="critical")
    frame, high = render_sse(security, high)
    assert frame["id"] == "100" and high == 100
    audit = BusEvent(seq=2, type="audit_complete", cursor_kind="event_id", event_id=100, lane="critical")
    frame, high = render_sse(audit, high)
    assert "id" in frame and frame["id"] == "100" and high == 100
    older = BusEvent(seq=3, type="audit_complete", cursor_kind="event_id", event_id=90, lane="critical")
    frame, high = render_sse(older, high)
    assert "id" not in frame and high == 100
    stage = BusEvent(seq=4, type="agent_stage", cursor_kind="epoch_seq", lane="bulk", data={"event_id": 100})
    frame, high = render_sse(stage, high)
    assert "id" not in frame and high == 100
    body = json.loads(frame["data"])
    assert body["_cursor_kind"] == "epoch_seq"
    assert "_event_id" not in body
    nxt = BusEvent(seq=5, type="security_event", cursor_kind="event_id", event_id=103, lane="critical")
    frame, high = render_sse(nxt, high)
    assert frame["id"] == "103" and high == 103


def test_live_overlap_skips_replayed_security_event_but_keeps_audit_notice():
    sent = {"e:security_event:101"}
    live = BusEvent(seq=1, type="security_event", cursor_kind="event_id", event_id=101, lane="critical")
    audit = BusEvent(seq=2, type="audit_complete", cursor_kind="event_id", event_id=101, lane="critical")
    older = BusEvent(seq=3, type="security_event", cursor_kind="event_id", event_id=90, lane="critical")
    fresh = BusEvent(seq=4, type="security_event", cursor_kind="event_id", event_id=102, lane="critical")
    assert should_skip_live(live, 100, sent) is True
    assert should_skip_live(audit, 100, sent) is False
    assert should_skip_live(older, 100, sent) is True
    assert should_skip_live(fresh, 100, sent) is False


def test_bulk_drops_oldest_and_coalesces_stage():
    bus = EventBus(max_subscribers=4)
    bus._queue_max = 2
    sub = bus.subscribe()
    assert sub is not None
    bus.publish("agent_thought", {"event_id": 1, "step": "a"})
    bus.publish("agent_thought", {"event_id": 2, "step": "b"})
    bus.publish("agent_thought", {"event_id": 3, "step": "c"})
    assert sub.qsize() == 2
    kept = [sub.get_nowait().data["event_id"] for _ in range(sub.qsize())]
    assert kept == [2, 3]

    sub = bus.subscribe()
    bus.publish("agent_stage", {"event_id": 7, "stage": "audit", "phase": "start", "status": "running"})
    bus.publish("agent_stage", {"event_id": 7, "stage": "audit", "phase": "start", "status": "running", "note": "newer"})
    assert sub.qsize() == 1
    evt = sub.get_nowait()
    assert evt.data["note"] == "newer"
    bus.unsubscribe(sub)


def test_critical_queue_keeps_prefix_when_a_later_event_does_not_fit():
    bus = EventBus(max_subscribers=2)
    bus._critical_queue_max = 2
    sub = bus.subscribe()
    bus.publish("security_event", {"event_id": 100, "severity": "high"})
    bus.publish("security_event", {"event_id": 101, "severity": "high"})
    bus.publish("security_event", {"event_id": 102, "severity": "critical"})
    assert sub.qsize() == 2
    assert sub.missed_critical == 1
    assert list(sub.gap_ids) == [102]
    assert [sub.get_nowait().event_id for _ in range(2)] == [100, 101]
    # 不可补查的告警可以挤掉一条已经能按 id 回放的通知，自己留下
    bus.publish("security_event", {"event_id": 200})
    bus.publish("security_event", {"event_id": 201})
    bus.publish("pipeline_health", {"type": "sla_breach", "order_number": "WO-1"})
    kinds = [sub.get_nowait().type for _ in range(sub.qsize())]
    assert "pipeline_health" in kinds
    assert sub.missed_critical >= 2
    bus.unsubscribe(sub)


def test_get_waits_until_publish():
    async def scenario():
        bus = EventBus()
        sub = bus.subscribe()
        assert sub is not None

        async def later():
            await asyncio.sleep(0.02)
            bus.publish("alert", {"event_id": 4, "severity": "high"})

        asyncio.create_task(later())
        evt = await asyncio.wait_for(sub.get(), timeout=1)
        assert evt.type == "alert"
        assert evt.event_id == 4
        bus.unsubscribe(sub)

    asyncio.run(scenario())


def test_slots_still_reject_when_full():
    bus = EventBus(max_subscribers=1)
    assert bus.subscribe() is not None
    assert bus.subscribe() is None


def test_replay_from_security_events_uses_id_not_memory_seq():
    async def scenario():
        from models import Base, SecurityEvent, async_session, engine

        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        async with async_session() as session:
            first = SecurityEvent(
                session_id="sse-cursor", event_type="BRUTE_FORCE", severity="high",
                src_ip="10.0.0.1", message="old", raw_data={"_audit_llm": {"verdict": "confirmed", "threat_detected": True}},
                analyzed=True,
            )
            second = SecurityEvent(
                session_id="sse-cursor", event_type="PORT_SCAN", severity="medium",
                src_ip="10.0.0.2", message="new", raw_data={}, analyzed=False,
            )
            session.add(first)
            session.add(second)
            await session.commit()
            await session.refresh(first)
            await session.refresh(second)
            first_id, second_id = first.id, second.id

        from event_replay import load_sse_replay
        from routers.logs import list_events

        fresh, fresh_meta = await load_sse_replay(0)
        assert fresh_meta["complete"] is True
        assert fresh_meta["cursor_reset"] is False
        assert second_id in [json.loads(frame["data"])["event_id"] for frame in fresh]

        frames, meta = await load_sse_replay(first_id)
        assert meta["complete"] is True
        assert meta["cursor_reset"] is False
        new_frames = [f for f in frames if f.get("id") == str(second_id)]
        assert len(new_frames) == 1
        body = json.loads(new_frames[0]["data"])
        assert body["event_id"] == second_id and body["_replay"] is True
        refresh = [f for f in frames if json.loads(f["data"]).get("_refresh")]
        assert any(json.loads(f["data"])["event_id"] == first_id for f in refresh)
        assert all("id" not in f for f in refresh)

        reset_frames, reset_meta = await load_sse_replay(second_id + 10_000)
        assert reset_frames == []
        assert reset_meta["cursor_reset"] is True
        assert reset_meta["complete"] is False
        assert reset_meta["max_event_id"] >= second_id

        async with async_session() as session:
            listed = await list_events(
                session_id="sse-cursor", severity="", limit=10, offset=0,
                after_id=first_id, session=session,
            )
        assert [row["id"] for row in listed] == [second_id]

    asyncio.run(scenario())


def test_redis_bridge_retries_after_subscribe_failure():
    async def scenario():
        bus = EventBus()
        bus._bridge_retry_initial = 0
        state = {"subs": 0, "stop": False}

        class PubSub:
            async def subscribe(self, _channel):
                state["subs"] += 1
                if state["subs"] == 1:
                    raise RuntimeError("redis down")

            async def listen(self):
                while not state["stop"]:
                    await asyncio.sleep(0.01)
                    if False:
                        yield None

            async def aclose(self):
                return None

        class Redis:
            def pubsub(self):
                return PubSub()

        bus.set_redis(Redis())
        await bus.start_redis_bridge()
        for _ in range(50):
            if state["subs"] >= 2:
                break
            await asyncio.sleep(0.02)
        state["stop"] = True
        bus._bridge_stop = True
        await bus.stop_redis_bridge()
        assert state["subs"] >= 2

    asyncio.run(scenario())
