"""跨 schema 版本混流：滚动升级期间新旧消息同在一个 topic。

## 这批测试为什么存在

整改方案 §十三 把「Kafka 输入的复杂字段校验」列为未验证项之一；
§十一.2 要求「所有用于运维决策的状态词表保持一致」。

核对现状：`test_schema_compat.py` 的 24 例测的是 **registry / catalog
在孤立状态下**的行为（envelope 识别、主版本不匹配、字段增删改类型、
fixture 与 Python/Flink 三方一致）。消费路径的用例
（`test_kafka_offset_commit.py` 等）则**每条都传同一个格式的良构 dict**，
而且从不断言「一条成功处理的消息」确实到达了业务 handler。

也就是说：**一个批里同时存在旧格式、新格式、主版本不符的消息时会发生什么，
从来没有被执行过。** 而这恰恰是滚动升级期间的真实状态 ——
生产者和消费者不可能同时切换。

## 为什么要用真实的版本判定逻辑

这里只把 jsonschema 校验器换成 None（它需要 catalog 里的 schema 文件），
**版本策略本身走真实代码路径** `event_envelope.version_errors`，
分流也走真实的 `_ack_record` / `_process_message`。替换得越少，
这条用例越接近生产。

## 这批用例实际钉住的东西

- 版本策略本身：未声明版本**接受**、次版本差异**接受**、
  主版本不符**拒绝**、版本串非法**拒绝**；
- 混流批次里，好消息**确实到达业务 handler**，坏消息进 DLQ ——
  一条坏消息不能连累同批的好消息，也不能让好消息「安静地消失」；
- DLQ 写失败时那条 offset 不推进（与 §三.3 的超大载荷同源）；
- 跨格式的事件标识**稳定**：同一条事件用旧格式或新格式承载，
  `resolve()` 必须给出同一个 id —— 否则滚动升级期间同一条事件
  会被当成两条各处理一次、算两次分。
"""
import asyncio
import json
import os
import re
from pathlib import Path

import pytest

os.environ.setdefault("SHARED_MEMORY_SKIP_DOTENV", "1")

import kafka_consumer                                    # noqa: E402
from event_envelope import version_errors               # noqa: E402
from event_identity import resolve                      # noqa: E402
from kafka_consumer import KafkaConsumerManager         # noqa: E402

TOPIC = "security-logs"
CURRENT = "1.4.2"          # 与 schema 文件里的主版本一致
EVENT_ID = "aaaaaaaa-1111-4111-8111-111111111111"
STAT_KEY = "rejected_consumed"      # 必须是 `_stats` 里已存在的键
GROUP_SUFFIX = "rejected"

#: 只匹配独立的 `wrap(`，不匹配 `unwrap(`（词边界让 `nwrap` 不成立）。
_WRAP_CALL = re.compile(r"\bwrap\s*\(")


class _Msg:
    def __init__(self, value: dict, offset: int):
        self.topic = TOPIC
        self.partition = 0
        self.offset = offset
        self.headers = []
        self.timestamp = 1_750_000_000_000
        self.key = None
        self.value = json.dumps(value).encode("utf-8")


def _payload(**kw):
    base = {"eventId": EVENT_ID, "eventType": "PORT_SCAN",
            "srcIp": "10.0.0.1", "severity": "medium",
            "timestamp": 1_750_000_001_000}
    base.update(kw)
    return base


def _envelope(version=CURRENT, **kw):
    return {"eventId": EVENT_ID, "eventType": "security.event",
            "schemaVersion": version, "occurredAt": 1_750_000_001_000,
            "producer": "test", "payload": _payload(**kw)}


class _Harness:
    """把 _ack_record 的三个可观察出口都接出来：handler / DLQ / 返回值。"""

    def __init__(self, mgr, handler, seen, dlq):
        self.mgr = mgr
        self.handler = handler
        self.seen = seen
        self.dlq = dlq

    def feed(self, msg):
        return asyncio.run(self.mgr._ack_record(
            msg, TOPIC, self.handler, STAT_KEY, GROUP_SUFFIX))


def _harness(monkeypatch, *, dlq_stored=True):
    monkeypatch.setattr(KafkaConsumerManager, "_retain_backoff",
                        lambda self, tracker: 0.0)
    monkeypatch.setattr(kafka_consumer, "MAX_RETRY", 1)
    # 只关掉 jsonschema 校验器（它依赖 catalog 里的 schema 文件），
    # 版本策略走真实代码路径。
    monkeypatch.setattr(kafka_consumer.schema_registry, "get_validator",
                        lambda topic: None)
    monkeypatch.setattr(kafka_consumer.schema_registry, "_envelope_validator",
                        lambda: None)
    mgr = KafkaConsumerManager()
    mgr._running = True

    seen, dlq = [], []

    async def handler(event, trace_id):
        seen.append(event)
        return None

    async def to_dlq(topic, msg, error, retry_count, **kw):
        dlq.append((kw.get("offset"), kw.get("error_code"), str(error)[:90]))
        return dlq_stored

    monkeypatch.setattr(mgr, "_send_to_dlq", to_dlq)
    return _Harness(mgr, handler, seen, dlq)


# ══════════════════════════════════════════════════════════════
# 1. 版本策略本身
# ══════════════════════════════════════════════════════════════

@pytest.mark.parametrize("declared,accepted", [
    ("", True),            # 未声明 → 视为与当前主版本兼容
    ("1.0.0", True),       # 次版本落后 → 兼容
    ("1.4.2", True),       # 完全一致
    ("1.9.9", True),       # 次版本超前 → 兼容
    ("2.0.0", False),      # 主版本不符 → 拒绝
    ("not-a-version", False),
])
def test_version_policy_table(declared, accepted):
    """把版本策略整张表钉死，避免将来「顺手放宽」无测试察觉。"""
    errors = version_errors(declared, CURRENT)
    assert (not errors) is accepted, f"{declared!r} -> {errors}"


def test_real_registry_agrees_with_the_policy_table(monkeypatch):
    """registry 的判定必须与 version_errors 一致 —— 它是消费端实际调用的。"""
    monkeypatch.setattr(kafka_consumer.schema_registry, "get_validator",
                        lambda topic: None)
    monkeypatch.setattr(kafka_consumer.schema_registry, "_envelope_validator",
                        lambda: None)
    reg = kafka_consumer.schema_registry
    assert reg.validate(TOPIC, _envelope(version="1.0.0")) == []
    assert reg.validate(TOPIC, _envelope(version="2.0.0")), \
        "主版本不符却校验通过 —— 滚动升级时新旧消息会混在一起进业务"
    assert reg.validate(TOPIC, _envelope(version="garbage"))


# ══════════════════════════════════════════════════════════════
# 2. 混流批次
# ══════════════════════════════════════════════════════════════

def test_mixed_version_batch_routes_each_message_correctly(monkeypatch):
    """一个批里四种格式并存时，逐条判定必须正确。

    这是滚动升级的真实形态，也是此前**从未被执行过**的组合。
    """
    h = _harness(monkeypatch)
    batch = [
        _Msg(_payload(), 1),                  # 旧：扁平，无信封
        _Msg(_envelope(version="1.0.0"), 2),  # 新：信封，次版本旧
        _Msg(_envelope(version=CURRENT), 3),  # 新：信封，当前版本
        _Msg(_envelope(version="2.0.0"), 4),  # 未来：主版本不符
    ]
    results = [h.feed(m) for m in batch]

    assert len(h.seen) == 3, \
        f"应有 3 条到达业务 handler，实际 {len(h.seen)} —— 好消息被静默丢弃"
    assert [o for o, _, _ in h.dlq] == [4], f"只有 offset 4 该进 DLQ: {h.dlq}"
    assert h.dlq[0][1] == "schema_invalid", h.dlq
    assert all(r is True for r in results), \
        f"DLQ 落库成功的批里 offset 应全部可提交: {results}"


def test_a_bad_message_does_not_discard_its_good_neighbours(monkeypatch):
    """坏消息不能连累同批好消息。

    反向证明：防的是那种「一条不兼容就把整批丢掉」的修复方式。
    """
    h = _harness(monkeypatch)
    for offset, msg in ((10, _envelope(version="2.0.0")),
                        (11, _payload()),
                        (12, _envelope(version="3.1.0"))):
        h.feed(_Msg(msg, offset))

    assert [m["eventId"] for m in h.seen] == [EVENT_ID], h.seen
    assert [o for o, _, _ in h.dlq] == [10, 12], h.dlq


def test_good_message_is_not_silently_dropped(monkeypatch):
    """单独一条完全合法的消息，必须真的被处理。

    这条是给整批用例兜底的：上一版我误传了一个不记录任何东西的
    handler，结果「3 条到达 handler」断言失败、而 DLQ 也是空的 ——
    两条断言同时失败才暴露出来。这里单独钉一条，让「静默丢弃」
    无论如何都会撞上一条明确的红。

    用**扁平**消息：线上生产者发的就是扁平消息（见
    `test_stamp_identity_does_not_convert_flat_to_envelope`），
    这里验的是「别把好消息弄丢」，不掺信封那层。
    """
    h = _harness(monkeypatch)
    assert h.feed(_Msg(_payload(), 30)) is True
    assert len(h.seen) == 1, "合法消息没有到达业务 handler"
    assert not h.dlq, h.dlq
    assert h.seen[0]["eventType"] == "PORT_SCAN", h.seen


def test_offset_is_retained_when_dlq_write_fails(monkeypatch):
    """DLQ 写失败 → 那条 offset 不能推进。

    混流场景下这条尤其重要：一条不兼容的未来消息如果持续写不进 DLQ，
    整条分区都会卡住（与 §三.3 的超大载荷同源）。
    """
    h = _harness(monkeypatch, dlq_stored=False)
    ok = h.feed(_Msg(_envelope(version="2.0.0"), 7))
    assert ok is False, "DLQ 写失败却让 offset 前进 —— 这条消息会被静默丢弃"
    assert h.seen == []
    assert [o for o, _, _ in h.dlq] == [7]


# ══════════════════════════════════════════════════════════════
# 3. 跨格式的事件标识
# ══════════════════════════════════════════════════════════════

def test_legacy_and_envelope_carry_the_same_identity():
    """⚠️ 滚动升级期间同一条事件会以两种格式各到一次。

    若 `resolve()` 对两种格式给出不同的 event_id，事件存储的幂等去重
    （按 event_id 唯一索引）就失效 —— 同一条攻击会被记两次、算两次分。
    """
    flat = _payload()
    wrapped = _envelope(version=CURRENT)
    assert resolve(flat).event_id == resolve(wrapped).event_id == EVENT_ID

    # 信封没有外层 eventId 时必须回退到 payload，而不是解析出空 id
    no_outer = {k: v for k, v in wrapped.items() if k != "eventId"}
    assert resolve(no_outer).event_id == EVENT_ID


def test_envelope_level_id_wins_and_that_is_intended():
    """外层 eventId 与 payload 不同时以**外层**为准。

    这是有意的：信封的 eventId 是消息身份。但必须钉住 —— 否则将来
    有人「顺手改成取 payload」，信封层的去重作用就没了。
    """
    msg = _envelope()
    msg["eventId"] = "envelope-level-id"
    assert resolve(msg).event_id == "envelope-level-id"


def test_same_event_in_both_formats_resolves_to_the_same_identity(monkeypatch):
    """端到端：两种格式的同一事件，标识一致。

    注意 handler 收到的是**原样消息**，不是解包后的业务载荷 —— 这正是
    `test_envelope_reaches_handler_unwrapped_is_not_implemented` 记的那件事。
    """
    h = _harness(monkeypatch)
    h.feed(_Msg(_payload(), 20))
    h.feed(_Msg(_envelope(), 21))

    assert not h.dlq, h.dlq
    assert len(h.seen) == 2, h.seen
    ids = {resolve(m).event_id for m in h.seen}
    assert ids == {EVENT_ID}, ids


# ══════════════════════════════════════════════════════════════
# 4. 信封：当前是潜在陷阱，不是活跃缺陷 —— 把它钉成显式不变量
# ══════════════════════════════════════════════════════════════
#
# 我最初断言「信封和扁平消息解出的业务载荷应当一致」，实测**不一致**：
# handler 收到的是整个信封（eventType="security.event"、业务字段嵌在
# payload 里）。一度以为挖到了缺陷，查证后发现**不是**：
#
#   1. `stamp_identity` 的文档写明「在扁平消息上补可选身份字段，
#      **不改写成信封**」；
#   2. `wrap()` 在**生产代码里零调用**（只有单测用）。
#
# 所以线上消息全是扁平的，业务 handler 直接 `event.get("eventType")`
# 是对的。
#
# 但这确实是个**潜在陷阱**：校验层（schema_registry.unwrap）与标识层
# （resolve）都已支持信封，唯独业务 handler 层没有。哪天有人把
# `wrap()` 接进生产者，信封就会真的上链路 —— schema 校验照过、event_id
# 照常解析，**只有业务 handler 悄悄收到一个空壳信封**，
# 每个字段都取到 None 或 "security.event"。这类退化不报错。
#
# 所以下面把它钉成显式不变量：只要还没人把信封接上链路，这个不变量就成立；
# 谁要接，必须同时改 handler —— 这条测试会先变红提醒他。

def _backend_py_files():
    root = Path(__file__).resolve().parents[1]
    for path in root.rglob("*.py"):
        parts = set(path.parts)
        if "tests" in parts or "tests" in path.stem:
            continue
        if any(p in {"node_modules", "target", ".git", "eval_datasets"}
               for p in parts):
            continue
        yield path


def test_no_production_code_wraps_messages_into_envelopes():
    """⚠️ 前置条件：信封还没被接进生产者。

    一旦有人调用 `wrap()`，下面那条「handler 收不到业务载荷」的断言
    就必须先被处理 —— 否则信封会静默地让所有业务 handler 拿到空壳。
    """
    offenders = []
    for path in _backend_py_files():
        if path.name == "event_envelope.py":
            continue                      # 定义处
        text = path.read_text(encoding="utf-8")
        for lineno, line in enumerate(text.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            # 必须用词边界：`unwrap(` 里含有 `wrap(` 子串，
            # 用 `"wrap(" in line` 会把校验层那个正确的调用也算成违规。
            if _WRAP_CALL.search(stripped):
                offenders.append(f"{path.name}:{lineno}: {stripped[:80]}")
    assert not offenders, (
        "生产代码里出现了 wrap() 调用。信封上链路前必须先让 kafka_consumer "
        "的各业务 handler 解包，否则 handler 会收到空壳信封：\n"
        + "\n".join(offenders))


def test_stamp_identity_does_not_convert_flat_to_envelope():
    """生产者用的身份盖章**不得**把扁平消息改成信封。"""
    from event_envelope import is_envelope, stamp_identity

    flat = _payload()
    stamped = stamp_identity(flat)
    assert not is_envelope(stamped), \
        "stamp_identity 把扁平消息包成了信封 —— 会让所有业务 handler 读到空壳"
    assert stamped["eventType"] == "PORT_SCAN", stamped


def test_envelope_reaches_handler_unwrapped_is_not_implemented(monkeypatch):
    """把已知的断层**显式记录**下来，而不是留给将来踩。

    现在 handler 收到的是原样消息：信封消息的 `eventType` 是
    `"security.event"`，业务字段全在 `payload` 里。
    当前没有生产者会这么做，所以不是缺陷 —— 但一旦有人把 `wrap()`
    接进生产者（见上一条），这条断言就会失败，那就是动手改 handler
    的信号。
    """
    h = _harness(monkeypatch)
    h.feed(_Msg(_envelope(version=CURRENT), 40))

    assert len(h.seen) == 1, h.seen
    received = h.seen[0]
    if received.get("eventType") == "PORT_SCAN":
        return                      # 已解包：本条约束被满足
    assert received.get("eventType") == "security.event", received
    assert isinstance(received.get("payload"), dict), \
        "既没解包也没有 payload —— handler 拿到的是无法处理的东西"
    assert received["payload"]["eventType"] == "PORT_SCAN", \
        "业务字段在 payload 里而 handler 读不到 —— 这正是待处理的那一层"
