"""DLQ 超限载荷：**丢证据好过卡住整条链路**。

## 这批测试为什么存在

`persist_dlq_failure` 对超过 `MAX_DLQ_BYTES`（512 KB）的载荷原本
一律返回 `persisted=False`，理由 `payload_too_large`。

看起来是稳妥的保护，实际后果是：

    写入失败 → 调用方保留 offset → 这条 offset 永远提交不了
             → 分区水位卡死在这条消息上
             → 它后面所有消息被处理但无法提交，重启后从头再来

也就是说，**任何人往 topic 里投一条 >512 KB 的畸形消息，
就能让这个分区的 offset 永远不再推进** —— 一个输入即可触发的 DoS，
而且日志上只表现为「DLQ 写入失败」，与磁盘故障无法区分。

现在改成：载荷超限时裁掉体积、保留「失败这件事」，让 offset 能推进。
证据确实会少一块 —— 畸形 JSON 的断点通常在头部，所以保留前缀；
原始长度会写进记录，排查时可回 broker 取原文。

## 为什么这条风险此前没人发现

现有 `test_dlq_security.py` 测的是解密失败、字段注入、重放幂等，
全部用**几百字节**的小载荷。512 KB 这个上限从未被触发过 ——
包括那条会返回 `payload_too_large` 的分支。
"""
import asyncio
import json
import os

import pytest

os.environ.setdefault("SHARED_MEMORY_SKIP_DOTENV", "1")

from dlq_store import (                                   # noqa: E402
    MAX_DLQ_BYTES, MAX_DLQ_RAW_PREFIX, TRUNC_MARK,
    clamp_raw_blob, shrink_to_fit,
)


# ══════════════════════════════════════════════════════════════
# 1. 纯函数层
# ══════════════════════════════════════════════════════════════

def test_clamp_keeps_short_blob_untouched():
    blob = b"x" * 100
    kept, original = clamp_raw_blob(blob)
    assert kept == blob and original == 100


def test_clamp_keeps_head_of_oversized_blob():
    """保留**头部**：畸形 JSON 的断点通常就在前面。"""
    blob = b"HEAD-MARKER" + b"y" * (MAX_DLQ_RAW_PREFIX + 1000)
    kept, original = clamp_raw_blob(blob)
    assert kept.startswith(b"HEAD-MARKER")
    assert len(kept) == MAX_DLQ_RAW_PREFIX
    assert original == len(blob), "原始长度必须如实记录，不能报成截断后的"


def test_clamp_never_exceeds_the_limit():
    blob = b"z" * (MAX_DLQ_BYTES * 3)
    kept, original = clamp_raw_blob(blob)
    assert len(kept) <= MAX_DLQ_RAW_PREFIX < len(blob)
    assert original == MAX_DLQ_BYTES * 3


def test_shrink_leaves_a_fitting_body_untouched():
    body = {"a": 1, "b": "short"}
    assert shrink_to_fit(body) == body


def test_shrink_keeps_every_key_name():
    """只丢体积，不丢键 —— 字段名往往是排障时最需要的。"""
    body = {"src_ip": "1.1.1.1", "rule_id": "SIG-001",
            "huge": "q" * (MAX_DLQ_BYTES * 2), "tail": "w" * 1000}
    out = shrink_to_fit(body)
    assert set(out) == set(body), f"键被丢了: {set(body) - set(out)}"
    assert len(json.dumps(out, ensure_ascii=False).encode()) <= MAX_DLQ_BYTES
    assert body["huge"].startswith("qqq"), "原值不应被就地改掉"


def test_shrink_marks_what_it_cut():
    body = {"huge": "q" * (MAX_DLQ_BYTES * 2)}
    out = shrink_to_fit(body)
    assert TRUNC_MARK in out["huge"], \
        "截断没有留痕 —— 读的人会以为字段本来就这么短"


def test_shrink_handles_many_oversized_fields():
    body = {f"f{i}": "x" * (MAX_DLQ_BYTES // 2) for i in range(6)}
    out = shrink_to_fit(body)
    assert set(out) == set(body)
    assert len(json.dumps(out, ensure_ascii=False).encode()) <= MAX_DLQ_BYTES


# ══════════════════════════════════════════════════════════════
# 2. 端到端：offset 必须能推进
# ══════════════════════════════════════════════════════════════

@pytest.fixture(scope="module", autouse=True)
def _dlq_env():
    """整个模块共用一把临时密钥与建好的表。

    密钥必须是模块级的：``_persist`` 落库时用密文，``_decoded_body`` 之后
    还要拿同一把钥匙解开 —— 每次调用换一个密钥的话，后半段必然解不开，
    而那会表现成「body 是空的」，很容易被误读成修复失败。
    """
    from field_cipher import field_cipher
    from cryptography.fernet import Fernet
    from models import Base, engine

    os.environ["SHARED_MEMORY_FIELD_ENCRYPTION_KEY"] = \
        Fernet.generate_key().decode()
    field_cipher.reload()

    async def _create():
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    asyncio.run(_create())
    yield
    os.environ.pop("SHARED_MEMORY_FIELD_ENCRYPTION_KEY", None)
    field_cipher.reload()


def _persist(raw_bytes, payload=None):
    """真的落一条 DLQ 记录（走测试用 sqlite）。"""
    from dlq_store import persist_dlq_failure

    async def _run():
        return await persist_dlq_failure(
            topic="security-logs", payload=payload or {"eventId": "e-oversize"},
            error="payload is not json", retry_count=1,
            partition=3, offset=99, error_class="DecodeError",
            error_code="decode_error", raw_bytes=raw_bytes,
        )

    return asyncio.run(_run())


def test_oversized_raw_payload_is_still_recorded():
    """⚠️ 本轮修复的核心用例。

    修复前：>512 KB → persisted=False → offset 永久保留 → 分区卡死。
    修复后：记录落库（裁掉体积），offset 可以推进。
    """
    result = _persist(b"HEAD" + b"x" * (MAX_DLQ_BYTES * 2))
    assert result.persisted, (
        f"超大载荷未能落库: {result.reason} —— "
        "调用方会因此保留 offset，这条消息将永久卡住分区")


def test_oversized_payload_records_the_true_original_length():
    """截断是为了让记录能落库，不是消息本来就小 —— 长度必须如实写。"""
    blob = b"HEAD" + b"x" * (MAX_DLQ_BYTES * 2)
    result = _persist(blob)
    assert result.persisted and result.record_id
    row = _get(result.record_id)
    assert row is not None
    body = _decoded_body(row)
    assert body.get("_dlq_raw_bytes_original") == len(blob), \
        "原始长度被记成了截断后的长度，排障时会按错误的字节数去捞原文"
    assert body.get("_dlq_undecodable") is True


def test_oversized_event_body_is_recorded_with_keys_intact():
    """事件体本身超限（不是 raw_bytes）也必须能落库，且键名不丢。"""
    payload = {"eventId": "e-big", "src_ip": "10.0.0.9",
               "rawData": {"blob": "z" * (MAX_DLQ_BYTES * 2)}}
    result = _persist(None, payload=payload)
    assert result.persisted, f"超大事件体未能落库: {result.reason}"
    body = _decoded_body(_get(result.record_id))
    assert body.get("eventId") == "e-big"
    assert "rawData" in body, "键名被丢了"


def test_normal_sized_payload_is_unaffected():
    """防过度收紧：正常载荷不得被裁。"""
    payload = {"eventId": "e-ok", "rawData": "x" * 1000}
    result = _persist(b'{"eventId":"e-ok"}', payload=payload)
    assert result.persisted
    body = _decoded_body(_get(result.record_id))
    assert TRUNC_MARK not in json.dumps(body, ensure_ascii=False)
    assert "_dlq_raw_bytes_original" not in body, \
        "正常载荷不该被记成「原本超限」"
    assert _get(result.record_id).payload_complete is True


def test_truncated_record_is_flagged_incomplete_and_cannot_be_replayed():
    """⚠️ 本轮修复补上的「缺失的一环」。

    `payload_complete` 这一列早就接好了 —— 重放路径会读它，
    `not payload_complete` 就拒绝重放。但**写入侧恒写 True**，
    于是「记录里其实少了东西」这件事永远不会被任何下游发现。

    现在裁剪发生时置 False，于是：记录落库（offset 能推进），
    但重放被挡住 —— 因为重放一份被截断的消息，等于把残缺证据
    当成完整事件重新投回链路。
    """
    from dlq_store import dry_run

    result = _persist(b"HEAD" + b"x" * (MAX_DLQ_BYTES * 2))
    assert result.persisted

    row = _get(result.record_id)
    assert row.payload_complete is False, (
        "裁剪过的载荷被标成了完整 —— 重放路径会拿残缺证据重新投递")

    preview = asyncio.run(dry_run(result.record_id))
    assert preview is not None
    assert preview["ok"] is False
    assert preview["cipher_code"] == "payload_incomplete"
    assert preview["replay_allowed"] is False


def test_truncated_record_is_blocked_at_the_replay_call_itself():
    """预演拦住还不够 —— 真正会**把消息发回链路**的是 `replay_record`。

    这里钉的是实际的出口：被截断的记录调用重放必须返回 blocked，
    而不是「试着发一次看看」。否则一个宽松的重试动作就会把
    半条消息当成完整事件重新注入。
    """
    from dlq_store import replay_record

    result = _persist(b"HEAD" + b"x" * (MAX_DLQ_BYTES * 2))
    assert result.persisted

    out = asyncio.run(replay_record(result.record_id, actor="tester"))
    assert out.get("status") == "blocked", f"截断的载荷竟被重放出去: {out}"
    assert out.get("error_code") == "payload_incomplete"


def _get(record_id):
    """按 id 取回 DLQ 行（测试用 sqlite）。"""
    from models import DlqRecord, async_session

    async def _run():
        async with async_session() as session:
            return await session.get(DlqRecord, record_id)

    return asyncio.run(_run())


def _decoded_body(row):
    """解开 DLQ 行的密文载荷。"""
    if row is None:
        return {}
    from field_cipher import field_cipher

    decision = field_cipher.open_sealed(row.payload_ciphertext)
    return decision if isinstance(decision, dict) else {}
