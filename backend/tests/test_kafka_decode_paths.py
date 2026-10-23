"""Kafka **解码入口**的畸形输入处理。

## 这批测试为什么存在

`_decode_kafka_value` 是「一条消息到底算不算有效事件」的唯一判据，
它的契约写得很清楚：**解码失败是永久错误，交给调用方进 DLQ**。

但它此前**零测试覆盖** —— 现有的 `_ack_record` 用例
（`test_kafka_offset_commit.py`）传的都是已经解析好的 dict，
把 `msg.value` 直接构造成 `json.dumps(...)`，
于是「解码这一步本身」从来没被执行过。

漏掉它造成的后果不是覆盖率数字，而是两个能停掉整条链路的洞：

- **深度嵌套的 JSON**：CPython 的 C 扫描器直接爆栈，抛 `RecursionError`，
  而 `except json.JSONDecodeError` 接不住（它不是 ValueError 子类）。
- **超长整数字面量**：Python 3.11+ 的 int 转换上限（4300 位）抛的是
  **裸** `ValueError`，同样不是 `JSONDecodeError`。

两者都会穿出 `_decode_kafka_value` → 穿出 `_ack_record`，
而 `_settle_fetch` 调用点**只有 `except asyncio.CancelledError`**，
最终落到消费循环顶层的 `except Exception: logger.error("consumer crashed")`。
也就是说：**一条畸形消息就能让整个 topic 的消费循环退出**，
日志只有一行 `consumer crashed`，看起来跟网络抖动一模一样。

本文件把这三类输入（普通畸形 / 爆栈 / 超长整数）都钉成「进 DLQ」，
并钉住 DLQ 写失败时 offset 仍然保留。
"""
import asyncio
import json
import os

import pytest

os.environ.setdefault("SHARED_MEMORY_SKIP_DOTENV", "1")

import kafka_consumer                                    # noqa: E402
from kafka_consumer import (                            # noqa: E402
    KafkaConsumerManager, _decode_kafka_value,
)

TOPIC = "security-logs-rejected"


class _Msg:
    """最小消息桩。value 直接给 bytes —— 刻意绕开 json.dumps，
    否则测的永远是「合法 JSON」这一条路径。"""

    def __init__(self, value: bytes, offset: int = 7, topic: str = TOPIC):
        self.topic = topic
        self.partition = 0
        self.offset = offset
        self.headers = []
        self.timestamp = 1_700_000_000_000
        self.key = None
        self.value = value


async def _ok_handler(event, trace_id):
    return None


def _manager(monkeypatch):
    monkeypatch.setattr(KafkaConsumerManager, "_retain_backoff",
                        lambda self, tracker: 0.0)
    monkeypatch.setattr(kafka_consumer, "MAX_RETRY", 1)
    mgr = KafkaConsumerManager()
    mgr._running = True
    return mgr


def _patch_dlq(monkeypatch, mgr, calls, *, stored: bool):
    """替换 DLQ 写入，记录调用并按需模拟写入失败。"""

    async def dlq(topic, msg, error, retry_count, **kw):
        calls.append((topic, kw.get("offset"), error, kw.get("error_code")))
        return stored

    monkeypatch.setattr(mgr, "_send_to_dlq", dlq)
    return calls


# ══════════════════════════════════════════════════════════════
# 1. 纯函数层：解码失败的形态矩阵
# ══════════════════════════════════════════════════════════════

def test_valid_dict_passes_through_untouched():
    """已经是 dict 就直接返回，不重新解析（会丢原对象身份）。"""
    src = {"eventId": "x", "a": 1}
    out, err = _decode_kafka_value(src)
    assert err is None and out is src


@pytest.mark.parametrize("raw,expect", [
    (None, "empty"),
    (b"", "empty"),
    (b"   \n ", "empty"),
    (b"\xff\xfe\x00", "not utf-8"),
    (b'{"a":', "not json"),
    (b"[1,2,3]", "not an object"),
    (b'"just a string"', "not an object"),
    (b"123", "not an object"),
    (123, "unsupported payload type"),
    (["a"], "unsupported payload type"),
])
def test_malformed_inputs_return_an_error_not_an_exception(raw, expect):
    """畸形输入一律返回 (None, 原因)，**不许抛**。

    抛出去的后果不是这条消息失败，而是消费循环退出（见模块注释）。

    ⚠️ 这里刻意**不放超长载荷**：pytest 会把 param 的 repr 拼进节点 id，
    再写进 `PYTEST_CURRENT_TEST` 环境变量；10 万字符会让它超过 Windows 的
    32767 上限，整个会话在 teardown 阶段炸掉（报的是一个和本用例毫不相干的
    `ValueError: the environment variable is longer than 32767 characters`）。
    超长载荷一律走下面的独立用例。
    """
    out, err = _decode_kafka_value(raw)
    assert out is None, f"{raw!r} 竟被解成了事件"
    assert err is not None and expect in err, f"错误原因不具描述性: {err!r}"


def test_deeply_nested_json_does_not_crash():
    """⚠️ 本轮修复的核心用例。

    修复前 `json.loads` 抛 `RecursionError`，它**不是** `JSONDecodeError`，
    于是原样穿出函数 → 穿出 `_ack_record` → 整个消费循环退出。
    """
    payload = ("[" * 100_000) + ("]" * 100_000)
    out, err = _decode_kafka_value(payload.encode())
    assert out is None
    assert err and "too deep" in err, f"未按「永久错误」处理: {err!r}"


def test_deeply_nested_object_does_not_crash():
    """对象方向同样会爆栈（报错文案不同，值得单独钉）。"""
    payload = ('{"a":' * 100_000) + ("}" * 100_000)
    out, err = _decode_kafka_value(payload.encode())
    assert out is None
    assert err and "too deep" in err, f"未按「永久错误」处理: {err!r}"


def test_oversized_integer_literal_does_not_crash():
    """⚠️ 本轮修复的第二个用例：Python 3.11+ 的 int 转换上限抛裸 ValueError。"""
    payload = ("1" * 5000).encode()
    out, err = _decode_kafka_value(payload)
    assert out is None
    assert err and "out of range" in err, f"未按「永久错误」处理: {err!r}"


def test_valid_large_number_still_parses():
    """反向约束：别把 catch 写太宽，把**合法**的大数也毙了。

    4300 位是本机 CPython 的 int 上限；远小于它的数字必须照常解析。
    修复若写成「解析失败一律拒绝」就会在这里露馅。
    """
    payload = json.dumps({"n": 10 ** 500}).encode()
    out, err = _decode_kafka_value(payload)
    assert err is None, f"合法大数被误拒: {err!r}"
    assert out["n"] == 10 ** 500


# ══════════════════════════════════════════════════════════════
# 2. 接线层：解码失败必须进 DLQ
# ══════════════════════════════════════════════════════════════

@pytest.mark.parametrize("raw", [
    b'{"a":',
    b"[1,2,3]",
    b"",
])
def test_undecodable_message_goes_to_dlq(monkeypatch, raw):
    """解不出来 → 进 DLQ，且返回 True（offset 可以提交）。

    返回 True 的前提是 **DLQ 真的写成功了**：写失败必须返回 False，
    否则这条消息会被静默丢掉、offset 还照常推进 —— 丢消息且无痕迹。
    """
    mgr, calls = _manager(monkeypatch), []
    _patch_dlq(monkeypatch, mgr, calls, stored=True)

    ok = asyncio.run(mgr._ack_record(
        _Msg(raw), TOPIC, _ok_handler, "rejected_consumed", "rejected"))

    assert ok is True, "DLQ 已确认写入却不让提交 offset —— 会重复消费"
    assert len(calls) == 1, "未进 DLQ"
    assert calls[0][1] == 7, "DLQ 里没记下 offset"
    assert calls[0][3] == "decode_error"


@pytest.mark.parametrize("payload", ["deep", "bigint"])
def test_pathological_payload_goes_to_dlq(monkeypatch, payload):
    """爆栈与超长整数这两类「原本会掀翻消费循环」的输入，也必须进 DLQ。"""
    raw = (("[" * 100_000 + "]" * 100_000) if payload == "deep"
           else ("1" * 5000)).encode()
    mgr, calls = _manager(monkeypatch), []
    _patch_dlq(monkeypatch, mgr, calls, stored=True)

    ok = asyncio.run(mgr._ack_record(
        _Msg(raw), TOPIC, _ok_handler, "rejected_consumed", "rejected"))

    assert ok is True and len(calls) == 1


def test_offset_is_retained_when_dlq_write_fails(monkeypatch):
    """DLQ 写失败 → 必须返回 False，消息留在 broker。

    这是「畸形输入不许静默消失」的最后一道保险。返回 True 的话，
    这条消息既没进 DLQ、offset 又被提交，重启后**永远消失**。
    """
    mgr, calls = _manager(monkeypatch), []
    _patch_dlq(monkeypatch, mgr, calls, stored=False)

    ok = asyncio.run(mgr._ack_record(
        _Msg(("[" * 100_000 + "]" * 100_000).encode()),
        TOPIC, _ok_handler, "rejected_consumed", "rejected"))

    assert ok is False, "DLQ 写失败却提交了 offset —— 消息静默丢失"
    assert len(calls) == 1


def test_handler_is_never_invoked_for_undecodable_message(monkeypatch):
    """业务 handler 不该看到解不开的消息。"""
    mgr = _manager(monkeypatch)
    seen = []

    async def handler(event, trace_id):
        seen.append(event)
        return None

    async def dlq(*a, **kw):
        return True

    monkeypatch.setattr(mgr, "_send_to_dlq", dlq)

    asyncio.run(mgr._ack_record(
        _Msg(b'{"a":'), TOPIC, handler, "rejected_consumed", "rejected"))

    assert seen == [], "解不开的消息被交给了业务 handler"
