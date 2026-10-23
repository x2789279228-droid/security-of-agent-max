"""§十三「尚未验证」之一：Kafka 输入的**复杂字段校验**——范围约束未强制。

整改方案 §十三 末段把「Kafka 输入的复杂字段校验」列为尚未验证。
本轮实测后需要把结论拆成两半，**不要合起来说成「已验证」**。

## 已验证：结构性校验扎实

`schema_registry.validate()` 对 `security_event` 的必填字段、类型、
枚举约束执行得很完整，实测逐条拒绝：

| 输入 | 结果 |
|---|---|
| 缺 `timestamp` / `eventId` / `severity` | 拒绝（required property） |
| `timestamp` 是字符串 | 拒绝（not of type 'integer'） |
| `message` 是 `null` | 拒绝（not of type 'string'） |
| `rawData` 是数组 | 拒绝（not of type 'object', 'null'） |
| `anomalyReasons` 是字符串 | 拒绝（not of type 'array', 'null'） |
| `srcIp` 是数字 | 拒绝（not of type 'string', 'null'） |
| `severity='catastrophic'` | 拒绝（not one of enum） |

## 未验证 / 已确认是缺口：**范围约束一条都没强制**

`schemas/security_event.schema.json` 的 `description` 里写明了范围，
但对应的 JSON Schema 关键字（`minimum` / `maximum` / `maxLength`）**不存在**，
于是 `description` 只是注释，校验器完全不看。实测全部放行：

| 输入 | schema 里写的 | 实测 |
|---|---|---|
| `confidence = 500` | `置信度 [0, 100]` | **通过** |
| `confidence = -9999` | 同上 | **通过** |
| `timestamp = 99` | `epoch millis, 2020~2030` | **通过** |
| `timestamp = -1` | 同上 | **通过** |
| `message` 10 万字符 | `最长 500 字符` | **通过** |

## 为什么本轮**不**直接收紧契约

给权威 schema 加上 `minimum`/`maximum` 是**契约变更**：一旦生效，
真实生产方只要发过越界值就会开始被拒。而本机无法知道真实生产方的
取值范围（`confidence` 到底是 0~100 还是 0~1？`timestamp` 会不会用 -1 当哨兵？
仓库里没有任何证据支持或否定）。

**误拒与漏报是同一等级的缺陷**，且这类改动不会让任何东西变红 ——
它只会让真实流量悄悄进不了 DLQ。因此本轮只做三件事：

1. 用实测把缺口钉住（下面的 strict xfail）；
2. 在报告 §六 待办里登记；
3. 上交用户决策（契约是否收紧、范围取什么值）。

## 守卫的写法说明

这些 strict xfail 断言的是**缺口本身**（越界值当前被放行），
不是修复后的行为。谁一旦给 schema 加了范围约束，它们会 XPASS，
strict 会立刻转红，迫使作者回来更新 —— 缺口不会被悄悄遗忘，
也不会有人误以为「已经有人管了」。
"""
import copy
import json
from pathlib import Path

import pytest

from schema_registry import schema_registry

TOPIC = "security-audit-queue"
SCHEMA = (
    Path(__file__).resolve().parents[1] / "schemas" / "security_event.schema.json"
)

GOOD = {
    "eventId": "e-1",
    "eventType": "PORT_SCAN",
    "severity": "high",
    "message": "scan",
    "timestamp": 1767225600000,
    "confidence": 80,
}


def _valid(event: dict) -> bool:
    return not schema_registry.validate(TOPIC, event)


def _mutate(**kw) -> dict:
    ev = copy.deepcopy(GOOD)
    ev.update(kw)
    return ev


# ══════════════════════════════════════════════════════════════════════════
# 已验证的部分 —— 结构性校验不得退化
# ══════════════════════════════════════════════════════════════════════════

class TestStructuralValidationIsSolid:
    """这一组是**正向断言**，现在就该全绿。

    把「哪里是好的」和「哪里是缺口」分开写，避免把整个维度笼统标成已验证。
    """

    @pytest.mark.parametrize("field", ["eventId", "eventType", "severity",
                                      "message", "timestamp"])
    def test_missing_required_field_is_rejected(self, field):
        ev = copy.deepcopy(GOOD)
        ev.pop(field)
        assert not _valid(ev), f"缺必填字段 {field} 竟然通过了"

    @pytest.mark.parametrize("mutate,why", [
        (lambda e: e.update(timestamp="1767225600000"), "timestamp 是字符串"),
        (lambda e: e.update(message=None), "message 是 null"),
        (lambda e: e.update(rawData=[1, 2]), "rawData 是数组"),
        (lambda e: e.update(anomalyReasons="x"), "anomalyReasons 是字符串"),
        (lambda e: e.update(srcIp=12345), "srcIp 是数字"),
    ])
    def test_type_errors_are_rejected(self, mutate, why):
        ev = copy.deepcopy(GOOD)
        mutate(ev)
        assert not _valid(ev), f"类型错误竟然通过了：{why}"

    def test_severity_enum_is_enforced(self):
        assert not _valid(_mutate(severity="catastrophic")), (
            "severity 不在 enum 里竟然通过了")

    def test_the_baseline_event_is_valid(self):
        """前提守卫：本文件其余用例都建立在「基线合法」之上。

        若某天基线本身失效，全部缺口用例会因为「因为别的原因被拒」而假绿。
        """
        assert _valid(copy.deepcopy(GOOD)), (
            "基线事件本身通不过 —— 本文件的缺口结论全部失效")


# ══════════════════════════════════════════════════════════════════════════
# 已确认的缺口 —— 范围约束未强制
# ══════════════════════════════════════════════════════════════════════════

class TestDocumentedRangesAreNotEnforced:
    """钉住「缺口当前存在」这个事实。

    这些**不是** xfail，而是普通断言：正文断言的是「越界值当前被放行」，
    而这在今天恰好是**真的**，所以它们应当全绿。

    写成 strict xfail 会把极性弄反：缺口存在时断言通过 = XPASS，
    strict 立刻转红，等于说「缺口存在」是错误状态。
    正确的形态是「现状即断言」—— 谁加了范围约束，谁就会把它弄红，
    届时必须回来更新登记并核对真实生产方会不会被误拒。
    """

    def test_confidence_above_documented_max_is_not_rejected(self):
        assert _valid(_mutate(confidence=500)), (
            "confidence=500 现在被拒了 —— 契约可能已收紧。"
            "请更新本缺口登记，并确认真实生产方的 confidence 取值范围"
            "（0~100 还是 0~1），否则会开始误拒")

    def test_confidence_below_documented_min_is_not_rejected(self):
        assert _valid(_mutate(confidence=-9999)), (
            "confidence=-9999 现在被拒了 —— 请更新本缺口登记")

    def test_out_of_range_timestamp_is_not_rejected(self):
        assert _valid(_mutate(timestamp=-1)), (
            "timestamp=-1 现在被拒了 —— 请先确认没有生产方用它当"
            "「无时间戳」哨兵，再更新本缺口登记")

    def test_oversized_message_is_not_rejected(self):
        assert _valid(_mutate(message="x" * 100_000)), (
            "超长 message 现在被拒了 —— 请更新本缺口登记")


class TestTheGapIsProvable:
    """把「契约写了但校验器不看」这件事本身钉住。

    上一组只证明「校验器没拦」；这一组证明「schema 文本里确实声明了
    这个字段的取值语义」。两者合起来才是「契约与执行不一致」，
    缺一不可 —— 否则结论会退化成「校验器比较宽松」这种无法追责的说法。
    """

    @pytest.fixture(scope="class")
    def props(self) -> dict:
        return json.loads(SCHEMA.read_text(encoding="utf-8"))["properties"]

    @pytest.mark.parametrize("field,range_kw", [
        ("confidence", ("minimum", "maximum")),
        ("timestamp", ("minimum", "maximum")),
        ("message", ("maxLength",)),
    ])
    def test_range_is_described_but_not_declared(self, props, field, range_kw):
        spec = props[field]
        assert spec.get("description"), (
            f"{field} 连描述都没有 —— 「契约写了范围」这个前提不成立，"
            "本缺口的定性需重新评估")
        missing = [k for k in range_kw if k not in spec]
        assert missing, (
            f"{field} 已经声明了 {list(range_kw)} —— "
            "范围约束已进契约，本缺口登记应当撤销")

    def test_required_list_matches_the_five_fields(self):
        raw = json.loads(SCHEMA.read_text(encoding="utf-8"))
        assert sorted(raw["required"]) == sorted(
            ["eventId", "eventType", "severity", "message", "timestamp"])
