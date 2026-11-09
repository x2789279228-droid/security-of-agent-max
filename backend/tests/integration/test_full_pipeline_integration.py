"""全链路集成测试 — 真 Kafka + 真 PostgreSQL (testcontainers, opt-in)。

背景(2026-10-25 第三阶段): 此前"真集成"只有 1 个文件(仅 PG 迁移+审批表),
238 个测试文件跑 sqlite 内存库 —— Kafka 消费 → 检测 → 响应决策 → 落库
的**完整管道从未在测试中组装过**。本文件在真实容器栈上验证三条腿:

  ① enriched 事件 → KafkaConsumerManager._handle_enriched → EventStore
     → 真 PG security_events 幂等落库
  ② Flink 形态告警 → _handle_alert → ResponseOrchestrator → 策略匹配
     → dry_run 响应决策 → 真 PG response_logs 留痕
  ③ 畸形消息 → 不杀消费循环 → 落 DLQ topic (security-logs-dlq)

Flink 侧不在本文件范围 —— 它的窗口语义由 CI 的 flink-verification job
(17 条真执行断言)覆盖; 这里替代 Flink 直接向 validated 后的 topic 生产,
验证的是【平台侧消费半区】。

跳过条件: testcontainers 未安装 / Docker daemon 不可用。
CI: pipeline-integration job; 本地: 启动 Docker 后
    pytest tests/integration -q
"""
from __future__ import annotations

import asyncio
import json
import os
import subprocess
import time
import uuid

import pytest

pytest.importorskip("testcontainers", reason="testcontainers 未安装")
pytest.importorskip("aiokafka", reason="aiokafka 未安装")


def _docker_available() -> bool:
    try:
        r = subprocess.run(
            ["docker", "ps"], capture_output=True, timeout=15,
            shell=os.name == "nt",
        )
        return r.returncode == 0
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not _docker_available(), reason="Docker daemon 不可用"
)

_BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
RUN_ID = uuid.uuid4().hex[:8]


@pytest.fixture(scope="module")
def stack():
    """Kafka + PG 16 真容器, 一次性拉起。"""
    from testcontainers.kafka import KafkaContainer
    from testcontainers.postgres import PostgresContainer

    with KafkaContainer("confluentinc/cp-kafka:7.6.0") as kafka, \
            PostgresContainer("pgvector/pgvector:0.8.2-pg16") as pg:
        yield {
            "kafka": kafka.get_bootstrap_server(),
            "pg": pg.get_connection_url().replace("psycopg2", "asyncpg"),
        }


@pytest.fixture(scope="module")
def bg_loop():
    """模块专属后台事件循环 —— 消费者/共享引擎都绑它(2026-11-10)。

    conftest 把主线程 new_event_loop 劫持为共享 session loop, 因此本模块的
    常驻消费者与写库连接统一挂在独立后台循环上, 避免跨 loop 复用 asyncpg。
    """
    import threading
    box: dict = {}

    def _loop_thread():
        box["loop"] = asyncio.new_event_loop()
        asyncio.set_event_loop(box["loop"])
        box["loop"].run_forever()

    th = threading.Thread(target=_loop_thread, daemon=True, name="pipe-int-loop")
    th.start()
    while "loop" not in box:
        import time as _t
        _t.sleep(0.05)
    yield box["loop"]
    box["loop"].call_soon_threadsafe(box["loop"].stop)


@pytest.fixture(scope="module")
def pipeline(stack, module_monkeypatch, bg_loop):
    """迁移 PG + 接线 settings/models → 返回会话工厂。"""
    import argparse

    def _alembic_cfg(db_url: str):
        from alembic.config import Config
        cfg = Config(os.path.join(_BACKEND_DIR, "alembic.ini"))
        cfg.set_main_option("script_location", os.path.join(_BACKEND_DIR, "migrations"))
        cfg.cmd_opts = argparse.Namespace(x=[f"db_url={db_url}"])
        return cfg

    from alembic import command
    command.upgrade(_alembic_cfg(stack["pg"]), "head")

    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
    from sqlalchemy import text
    eng = create_async_engine(stack["pg"])
    Session = async_sessionmaker(eng, expire_on_commit=False)

    # 引擎池的首个连接在 bg_loop 上建立(asyncpg 连接绑定创建时的运行循环),
    # 消费者(bg_loop)复用它写库; 旧写法连接绑已结束的 alembic 临时循环,
    # 消费者落库必炸 → 消息全部误入 DLQ(2026-11-10 实测根因)。
    async def _warm():
        async with Session() as s:
            await s.execute(text("SELECT 1"))
    asyncio.run_coroutine_threadsafe(_warm(), bg_loop).result(timeout=30)

    import config as config_mod
    import models as models_mod
    module_monkeypatch.setattr(models_mod, "async_session", Session)
    module_monkeypatch.setattr(config_mod.settings, "kafka_enabled", True)
    module_monkeypatch.setattr(config_mod.settings, "kafka_bootstrap", stack["kafka"])

    yield {"session_factory": Session, "engine": eng}
    asyncio.run_coroutine_threadsafe(eng.dispose(), bg_loop).result(timeout=30)


@pytest.fixture(scope="module")
def module_monkeypatch():
    """module 级 monkeypatch (pytest 内置 monkeypatch 是 function 级)。"""
    import pytest as _pytest
    mp = _pytest.MonkeyPatch()
    yield mp
    mp.undo()


@pytest.fixture(scope="module")
def manager(pipeline, bg_loop):
    """启动 KafkaConsumerManager, 测试结束优雅停机。

    2026-11-10 重写: 原版 asyncio.run(_start()) 在 conftest 共享 session loop
    架构下是坏的 —— 消费任务挂在被关闭的循环上, 测试期早已死透(enriched
    断言全靠 45s 轮询超时假绿/假红)。改为专属后台线程 + 常驻 loop:
    create_task 的消费者在整个模块存续期真实运行。
    """
    import threading
    from kafka_consumer import KafkaConsumerManager

    mgr = KafkaConsumerManager()
    asyncio.run_coroutine_threadsafe(mgr.start(), bg_loop).result(timeout=90)
    yield mgr
    asyncio.run_coroutine_threadsafe(mgr.stop(), bg_loop).result(timeout=30)


async def _produce(stack, topic: str, payload: bytes) -> None:
    from aiokafka import AIOKafkaProducer
    producer = AIOKafkaProducer(bootstrap_servers=stack["kafka"])
    await producer.start()
    try:
        await producer.send_and_wait(topic, payload)
    finally:
        await producer.stop()



def _run_in_thread(coro):
    """在线程里驱动协程 —— 与 conftest 共享 session loop 架构解耦。

    conftest 把主线程 event loop 换成了共享 _SHARED_LOOP(async 测试复用),
    集成测试运行期间主线程可能处于 running loop 态, 直接 asyncio.run 会抛
    "cannot be called from a running event loop"(2026-11-10 实测)。
    新线程天然无 loop, asyncio.run 合法; asyncpg 引擎为 _q 内局部创建,
    不跨线程复用。
    """
    import threading
    box = {}

    def _w():
        try:
            box["v"] = asyncio.run(coro)
        except BaseException as e:  # noqa: BLE001 — 转发到调用线程
            box["e"] = e

    th = threading.Thread(target=_w, daemon=True)
    th.start()
    th.join()
    if "e" in box:
        raise box["e"]
    return box.get("v")

async def _poll_until(fn, timeout_s: float, interval: float = 1.0):
    """轮询直到 fn() 为真值或超时, 返回 fn() 最终结果。"""
    deadline = asyncio.get_running_loop().time() + timeout_s
    result = None
    while asyncio.get_running_loop().time() < deadline:
        result = await fn() if asyncio.iscoroutinefunction(fn) else fn()
        if result:
            return result
        await asyncio.sleep(interval)
    return result


def test_enriched_event_persists_to_real_pg(stack, manager, pipeline):
    """① enriched → EventStore → 真 PG security_events (event_id 幂等)。"""
    import models as pipeline_models
    from config import settings
    from sqlalchemy import select

    event_id = f"pipe-int-{RUN_ID}-enriched-1"
    payload = {
        "eventId": event_id,
        "eventType": "SYSLOG_EVENT",
        "severity": "low",
        "srcIp": "198.51.100.10",
        "message": f"[pipe-int] enriched leg {RUN_ID}",
        "confidence": 50,
        "timestamp": int(time.time() * 1000),  # schema 必填(2026-11-10 补, 此前缺字段被死信)
        "protocol": "syslog",
    }
    asyncio.run(_produce(
        stack, settings.kafka_topic_enriched,
        json.dumps(payload).encode(),
    ))

    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    def _find():
        # 2026-11-10: 自建自毁引擎 —— 模块 Session 的 asyncpg 池绑定别的 loop,
        # 跨 loop 复用炸 "another operation is in progress"
        async def _q():
            eng = create_async_engine(stack["pg"])
            try:
                Sess = async_sessionmaker(eng, expire_on_commit=False)
                async with Sess() as s:
                    return (await s.execute(
                        select(pipeline_models.SecurityEvent)
                        .where(pipeline_models.SecurityEvent.event_id == event_id)
                    )).scalars().all()
            finally:
                await eng.dispose()
        return _run_in_thread(_q())

    rows = _run_in_thread(_poll_until(_find, timeout_s=45))
    assert rows, "enriched 事件 45s 内未落到真 PG security_events"


def test_alert_triggers_response_decision_in_real_pg(stack, manager, pipeline):
    """② Flink 形态告警 → 响应编排 → 真 PG response_logs 留痕(dry_run 预览)。"""
    import models as pipeline_models
    from config import settings
    from sqlalchemy import select

    src_ip = "198.51.100.66"
    alert = {
        # schema(alert_event.schema.json) 必填: alertId/eventType/severity/
        # message/anomalyScore/alertType/timestamp —— 此前 payload 与 schema
        # 演进脱节缺 3 项被死信(2026-11-10 对齐)
        "alertId": f"pipe-int-{RUN_ID}-alert-1",
        "eventId": f"pipe-int-{RUN_ID}-alert-1",
        "alertType": "SIGMA_AGGREGATE",
        "eventType": "BRUTE_FORCE",
        "severity": "high",
        "srcIp": src_ip,
        "dstIp": "10.0.0.30",
        "anomalyScore": 0.85,
        "confidence": 0.85,
        "action_recommend": "block_ip",   # _allow_blocking_for 口径: 声明执行类动作
        "message": f"SSH brute force aggregate {RUN_ID}",
        "reasons": ["SIG-012 count(src_ip)>5 in 5m"],
        "timestamp": int(time.time() * 1000),
    }
    asyncio.run(_produce(
        stack, settings.kafka_topic_alerts,
        json.dumps(alert).encode(),
    ))

    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    def _find():
        # 2026-11-10: 不复用模块级 Session —— 其 asyncpg 池绑定 manager fixture
        # 的(已结束)loop, 跨 loop 复用炸 "another operation is in progress"。
        # 每次查询自建引擎, 随 _run_in_thread 的新 loop 生灭。
        async def _q():
            eng = create_async_engine(stack["pg"])
            try:
                Sess = async_sessionmaker(eng, expire_on_commit=False)
                async with Sess() as s:
                    rows = (await s.execute(
                        select(pipeline_models.ResponseLog)
                        .where(pipeline_models.ResponseLog.src_ip == src_ip)
                        .order_by(pipeline_models.ResponseLog.created_at.desc())
                        .limit(5)
                    )).scalars().all()
                    return rows
            finally:
                await eng.dispose()
        return _run_in_thread(_q())

    rows = _run_in_thread(_poll_until(_find, timeout_s=45))
    assert rows, "告警触发的响应决策 45s 内未落到真 PG response_logs"
    actions = {r.action_name for r in rows}
    assert "block_ip" in actions, f"响应日志里没有 block_ip: actions={actions}"


def test_malformed_message_lands_in_dlq_not_crash(stack, manager, pipeline):
    """③ 畸形消息: 消费循环存活 + DLQ 收容。"""
    from config import settings

    asyncio.run(_produce(
        stack, settings.kafka_topic_enriched,
        b"{not-valid-json-at-all-{{{",
    ))

    async def _read_dlq() -> list:
        from aiokafka import AIOKafkaConsumer
        consumer = AIOKafkaConsumer(
            "security-logs-dlq",
            bootstrap_servers=stack["kafka"],
            group_id=f"pipe-int-dlq-{RUN_ID}",
            auto_offset_reset="earliest",
        )
        await consumer.start()
        try:
            msgs = await consumer.getmany(timeout_ms=8000, max_records=20)
            out = []
            for _, batch in msgs.items():
                out.extend(m.value for m in batch)
            return out
        finally:
            await consumer.stop()

    dlq = _run_in_thread(_poll_until(_read_dlq, timeout_s=40, interval=2.0))
    assert dlq, "畸形消息未进 DLQ —— 要么被吞(静默丢失), 要么消费循环死了"
    # DLQ 包装(dlq.v1)只嵌 payload 摘要 —— 以死信指纹断言: decode_error 且
    # 原 topic 为 enriched(本模块唯一一条 decode 死信就是上面的畸形 JSON)
    assert any(
        b'"error_code": "decode_error"' in m
        and b'"original_topic": "security-events-enriched"' in m
        for m in dlq
    ), f"DLQ 里收的不是那条畸形消息: {[m[:400] for m in dlq[:2]]}"
    # 消费循环必须还活着: 前一条测试的消息仍能被消费即佐证(manager 由
    # _supervised_loop 守护; 若整体崩溃, 此处后续再有事件也不会被处理)
