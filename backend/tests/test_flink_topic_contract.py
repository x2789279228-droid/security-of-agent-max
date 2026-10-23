"""
跨语言 Kafka topic 契约守卫（§6.2 第 6 条：Flink 作业部署顺序）。

## 为什么要有这个文件

backend 与 flink-jobs 各自持有一份**互不相关的 topic 字面量**：

  * Java 侧：`flink-jobs/.../util/KafkaConfig.java` 的 `TOPIC_*` 常量
  * Python 侧：`backend/config.py` 的 `kafka_topic_*` 配置项，
    外加 `kafka_consumer.py` 的模块级 `DLQ_TOPIC`

两侧当前**一致**，所以本文件不是缺陷修复，是**回归守卫**。
但不一致的后果是静默的：producer 把消息发到一个没人消费的 topic，
消费端那个 topic 永远空，**没有任何报错**。

以本次关注的 `security-sigma-hit` 为例：

  * backend 只在候选命中时往这个 topic 发（kafka_producer.py:195）
  * 唯一消费者是 `SigmaThresholdAggregationJob`（submit-jobs.sh 里**第三个**提交的作业）
  * 聚合告警不回写 → 没有策略匹配 → 不告警
  * 而单事件阶段本就禁止处置

三件事叠加就是：**既不封，也不告警，且看不出原因**。

## 这个守卫刻意不依赖 Maven / JDK

`test_sigma_aggregation_action_chain.py` 里的 18 条真编译/真执行断言在
PATH 没有 Maven 时会**静默跳过**（退出码仍是 0）—— 这类「跑没跑都绿」
的守卫等于没有。

topic 名字是纯文本字面量，用正则就能读出来，所以本文件
**只做源码文本比对**：不 import Java、不编译、不需要 Maven。
因此它永远不会因为环境缺依赖而跳过。

## 维护方式

新增/改名 Java 的 `TOPIC_*` 常量时，本文件会因
`test_every_java_topic_has_an_explicit_decision` 转红，
逼你在两个映射表里明确表态，而不是默默加一个没人对账的新 topic。
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
JAVA_CFG = ROOT / "flink-jobs" / "src" / "main" / "java" / "com" / "soc" / "util" / "KafkaConfig.java"

#: Java 常量 → Python 配置属性。**只登记确实存在对应关系的 topic。**
#: 新增映射前先确认两侧真的配对 —— 不要给没配对的东西补断言。
TOPIC_PAIRS = {
    "TOPIC_RAW_LOGS": ("config", "kafka_topic_raw"),
    "TOPIC_VALIDATED_LOGS": ("config", "kafka_topic_validated"),
    "TOPIC_REJECTED_LOGS": ("config", "kafka_topic_rejected"),
    "TOPIC_ENRICHED_EVENTS": ("config", "kafka_topic_enriched"),
    "TOPIC_ALERTS": ("config", "kafka_topic_alerts"),
    "TOPIC_AUDIT_QUEUE": ("config", "kafka_topic_audit_queue"),
    "TOPIC_CEP_PARTIAL": ("config", "kafka_topic_cep_partial"),
    "TOPIC_CEP_PATTERNS": ("config", "kafka_topic_cep_patterns"),
    "TOPIC_SIGMA_HIT": ("config", "kafka_topic_sigma_hit"),
    "TOPIC_BEHAVIOR_ALERTS": ("config", "kafka_topic_behavior_alerts"),
}

#: Java 有、Python 侧**有意没有**对应项的 topic。
#: 每一条都必须写明原因 —— 否则就是一份没人对账的孤儿常量。
JAVA_ONLY = {
    "TOPIC_DLQ": "DLQ topic 走 kafka_consumer.DLQ_TOPIC（模块常量，不在 settings 里）",
    "TOPIC_FLOWS_AGGREGATED": (
        "NDR 作业默认不提交（SUBMIT_NDR_JOBS=1 才启用），"
        "其输出 topic 后端暂未消费，见 submit-jobs.sh 注释"
    ),
}


def _java_topics() -> dict[str, str]:
    """从 KafkaConfig.java 读出所有 `public static final String TOPIC_* = "..."`。"""
    text = JAVA_CFG.read_text(encoding="utf-8")
    return dict(re.findall(
        r'public\s+static\s+final\s+String\s+(TOPIC_\w+)\s*=\s*"([^"]+)"', text
    ))


def _py_settings() -> dict[str, str]:
    """config.Settings 上的 kafka_topic_* 默认值。

    只读源码字面量而不是 import config —— 避免把整个应用配置层拖进这条轻量守卫。
    """
    text = (ROOT / "backend" / "config.py").read_text(encoding="utf-8")
    return dict(re.findall(r'^\s*(kafka_topic_\w+)\s*:\s*str\s*=\s*"([^"]+)"', text, re.M))


@pytest.fixture(scope="module")
def java_topics() -> dict[str, str]:
    assert JAVA_CFG.is_file(), f"KafkaConfig.java 不在预期位置: {JAVA_CFG}"
    return _java_topics()


@pytest.fixture(scope="module")
def py_settings() -> dict[str, str]:
    return _py_settings()


# ── 契约本体 ──

def test_sigma_hit_topic_matches_across_languages(java_topics, py_settings):
    """本次重点：聚合候选 topic 两侧必须同名。

    不一致 = 候选发到无人消费的 topic = 既不封也不告警，且无报错。
    """
    assert java_topics["TOPIC_SIGMA_HIT"] == py_settings["kafka_topic_sigma_hit"], (
        f"security-sigma-hit 两侧不一致：Java={java_topics['TOPIC_SIGMA_HIT']!r} "
        f"Python={py_settings['kafka_topic_sigma_hit']!r} —— "
        "backend 会把候选发到一个没有消费者的 topic 上，无任何报错"
    )


@pytest.mark.parametrize("java_key", sorted(TOPIC_PAIRS))
def test_all_shared_topics_match(java_topics, py_settings, java_key):
    _module, attr = TOPIC_PAIRS[java_key]
    assert attr in py_settings, (
        f"config.py 里找不到 {attr} —— 若已重命名，请同步更新 "
        "tests/test_flink_topic_contract.py 的 TOPIC_PAIRS"
    )
    assert java_topics[java_key] == py_settings[attr], (
        f"{java_key}={java_topics[java_key]!r} 与 {attr}={py_settings[attr]!r} 不一致"
    )


def test_dlq_topic_matches(java_topics):
    """DLQ topic 在 Python 侧是模块常量，不是 settings 项。"""
    from kafka_consumer import DLQ_TOPIC

    assert java_topics["TOPIC_DLQ"] == DLQ_TOPIC, (
        f"DLQ topic 两侧不一致：Java={java_topics['TOPIC_DLQ']!r} "
        f"Python={DLQ_TOPIC!r} —— DLQ 消息会写到一个 Python 侧读不回来的 topic，"
        "而原 offset 已被提交，故障将永久不可见"
    )


# ── 防漂移：新增 Java 常量必须逼出一次明确表态 ──

def test_every_java_topic_has_an_explicit_decision(java_topics):
    """KafkaConfig.java 里的每个 TOPIC_* 都必须在两个表里登记过。

    这是本文件的核心价值：防止「加了新 topic 却没人对账」。
    """
    undecided = sorted(set(java_topics) - set(TOPIC_PAIRS) - set(JAVA_ONLY))
    assert not undecided, (
        f"KafkaConfig.java 新增了 {undecided}，但没有在 TOPIC_PAIRS / JAVA_ONLY "
        "里登记对应关系。请明确：它有 Python 对应项吗？没有的话请在 JAVA_ONLY "
        "里写明原因。"
    )


def test_declared_java_only_topics_still_exist(java_topics):
    """反向检查：JAVA_ONLY 里登记的常量不能已经被删掉。"""
    vanished = sorted(set(JAVA_ONLY) - set(java_topics))
    assert not vanished, (
        f"JAVA_ONLY 登记了 {vanished}，但 KafkaConfig.java 里已经没有这些常量了 —— "
        "请删除对应登记，别让过期说明留在文件里误导后人"
    )


def test_every_java_only_entry_has_a_reason(java_topics):
    """孤儿常量登记必须带原因，空字符串等于没登记。"""
    for key, reason in JAVA_ONLY.items():
        assert reason.strip(), f"{key} 在 JAVA_ONLY 里没有写明为什么没有 Python 对应项"


# ── 反模式：消费端不许硬编码字面量 ──

def test_sigma_job_consumes_the_shared_constant():
    """SigmaThresholdAggregationJob 必须引用常量，不得内联字符串。

    内联字面量等于把契约又复制一份到第三个文件 ——
    改了常量而 job 仍读旧值，KafkaConfig 的对账就失去意义。
    """
    job = (ROOT / "flink-jobs" / "src" / "main" / "java"
           / "com" / "soc" / "job" / "SigmaThresholdAggregationJob.java")
    text = job.read_text(encoding="utf-8")
    assert "KafkaConfig.TOPIC_SIGMA_HIT" in text, (
        "SigmaThresholdAggregationJob 未引用 KafkaConfig.TOPIC_SIGMA_HIT"
    )
    assert not re.search(r'setTopics\(\s*"', text), (
        "SigmaThresholdAggregationJob 内联了 topic 字面量 —— 请改用 KafkaConfig 常量"
    )
