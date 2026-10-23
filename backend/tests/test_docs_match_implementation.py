"""
文档承诺 vs 实现：一致性守卫。

## 为什么要有这个文件

整改方案 §十一 P2 第 2 条点名了一类问题：
「文档只承诺当前真正实现的算法与约束」，并明确指出
「对于因果分析和检测规则而言，运行机制与文档承诺不一致，
可能直接导致使用者误解结果的可信度」。

实际踩到的例子（2026-10-18 核对）：

`docs/architecture/data-flow-analysis.md` 写的是

    - 时序异常 … 权重 0.15
    - 严重度 … 权重 0.25
    - is_anomaly = score > 0.6 or max_sigma > 3

而实现早已改成「证据维度 / 上下文维度」分离：严重度降到 0.15 且**只能加成
不能独立发起告警**、新增了文档里根本没提的 `target_concentration`(0.15)、
证据分母恒为 `EVIDENCE_TOTAL` 而非「可用维度之和」。
照文档心算分数的人会得出与代码不同的结论。

## 这个守卫的边界（重要）

它**只**校验文档里以表格形式写明的**数值口径**，不做全文语义比对：

- 好处：格式微调（换列宽、挪位置）不至于误报，改数值一定会被抓到；
- 代价：文档若改成散文描述而不再列数值，本测试会失败并提示
  「要么恢复数值表格，要么更新本测试的断言来源」。

这是刻意的：把口径留在文档里可被机器核对，比藏在散文里强。

## 扩展方式

后续修别的文档承诺时，在 :func:`test_documented_*` 旁加一条即可。
新增前先确认该文档确实承诺了这个量 —— **不要**给没承诺过的东西补断言。

## 守卫自身会误报，这件事要当真

本文件 2026-10-18 第一次误报：``analyze()`` 后来为加埋点拆成了外层 wrapper
+ ``_analyze_inner()``，而 ``test_documented_is_anomaly_rule_matches_code``
硬编码了 ``inspect.getsource(AnomalyDetector.analyze)``，于是找不到判定赋值。

**误报的守卫比没有守卫更糟** —— 人会开始忽略它，然后真正漂移时也不看。
所以这里的断言一律：

- 扫**整个类**而不是某个方法（方法会因重构而搬家）
- 只断言**语义存在**（"用到了这个常量"），不断言**具体写法**
  （不断言 `if a and b:` 的格式，格式化工具就能把它改红）
"""
import re
from pathlib import Path

import pytest

DOC = (Path(__file__).resolve().parents[2]
       / "docs" / "architecture" / "data-flow-analysis.md")

README = Path(__file__).resolve().parents[2] / "README.md"

#: 文档必须用这个表头声明维度权重，否则下面的解析无从下手。
TABLE_MARKER = "| 类别 | 维度 | 权重 | 说明 |"


@pytest.fixture(scope="module")
def doc_text() -> str:
    assert DOC.is_file(), f"架构文档不在预期位置: {DOC}"
    return DOC.read_text(encoding="utf-8")


def _weights_from_doc(doc: str) -> dict:
    """从文档表格里取出 ``维度 -> 权重``。

    容忍列宽/对齐差异，但要求维度名与数值都在同一行的 ``|`` 单元格里。
    """
    assert TABLE_MARKER in doc, (
        "文档里找不到异常检测维度表头。\n"
        f"若把权重表改成了散文，请把 {__name__} 里的解析改成新的口径；\n"
        "若只是挪动了位置，恢复表头即可。\n"
        "**不要**为了让测试通过而删掉权重表 —— 那正是本测试要防的事。")
    out = {}
    for line in doc.splitlines():
        m = re.match(
            r"\s*\|\s*(证据|上下文)\s*\|\s*`([a-z_]+)`\s*\|\s*([0-9.]+)\s*\|", line)
        if m:
            out[m.group(2)] = float(m.group(3))
    return out


def _doc_value(doc: str, label: str):
    """取出文档为某个常量声明的数值，两种写法都认：

    1. ``LABEL = 0.60``（行内赋值）
    2. ``| `LABEL` | 0.60 | ... |``（表格行）

    两种都支持，是为了**不强迫文档用更难读的写法** —— 表格里列常量
    本来就比散在正文里好读。
    """
    m = re.search(rf"{label}\s*=\s*([0-9.]+)", doc)
    if m:
        return float(m.group(1))
    m = re.search(rf"\|\s*`{label}`\s*\|\s*([0-9.]+)\s*\|", doc)
    if m:
        return float(m.group(1))
    return None


# ══════════════════════════════════════════════════════════════
# 异常检测维度
# ══════════════════════════════════════════════════════════════

def test_documented_dimension_weights_match_code(doc_text):
    """文档写的权重必须等于代码里的权重。

    2026-10-18 核对时发现：文档写「严重度 0.25」，实现早已是 0.15；
    文档还漏了 ``target_concentration``。照文档心算分数会算错。
    """
    from anomaly_detector import CONTEXT_DIMENSIONS, EVIDENCE_DIMENSIONS

    documented = _weights_from_doc(doc_text)
    actual = {**EVIDENCE_DIMENSIONS, **CONTEXT_DIMENSIONS}

    assert documented == actual, (
        "文档与实现的维度权重不一致：\n"
        f"  文档: {documented}\n"
        f"  实现: {actual}\n"
        "改代码时必须同步改文档，改文档时必须同步改代码。")

    # 证据 / 上下文分类也要对上 —— 分类决定「能不能独立发起告警」
    assert set(EVIDENCE_DIMENSIONS) == {
        "statistical_deviation", "rarity", "target_concentration"}, \
        "证据维度集合变了，文档表格需同步"


def test_documented_evidence_total_matches_code(doc_text):
    """文档写死的 ``EVIDENCE_TOTAL`` 必须等于代码实际求和。

    这个常量是「冷启动不误报」的关键：分母按可用维度重新归一会让
    新实体只剩一个弱维度时算出 1.0 分直接越过阈值。
    """
    from anomaly_detector import EVIDENCE_TOTAL

    m = re.search(r"EVIDENCE_TOTAL\s*=\s*([0-9.]+)", doc_text)
    assert m, "文档里没有写明 EVIDENCE_TOTAL"
    assert float(m.group(1)) == pytest.approx(EVIDENCE_TOTAL), (
        f"文档写 EVIDENCE_TOTAL={m.group(1)}，实现是 {EVIDENCE_TOTAL}")


# ── README 的算法名承诺（§十一 P2 第 1、2 条）──

def test_readme_never_claims_plain_ges_algorithm():
    """README 不得把实现称作「GES 算法」。

    `causal_chain/ges.py` 实现的是 **BIC 贪心搜索 + v-结构判定**，
    没有 Chickering 的 forward / backward / reverse 三算子，也不做 CPDAG 投影
    —— `ges.py` 自己的首段已写明「不是 Chickering 全套 CPDAG 算子」。
    README 却写「GES 算法」，读者会以为拿到的是标准 GES，
    从而高估因果图的可靠性（§十一 P2：「可能导致使用者误解结果的可信度」）。

    本断言扫**整个 README** 而不是逐处改字符串 ——
    逐处修改在下次新增章节时会漏，而漏掉的地方正是要防的。
    """
    assert README.is_file(), f"README 不在预期位置: {README}"
    text = README.read_text(encoding="utf-8")

    # 「GES 算法」/「GES算法」为裸声明；「GES-style …」是已标注的诚实写法。
    offenders = [
        (i + 1, line.strip()) for i, line in enumerate(text.splitlines())
        if re.search(r"GES\s*算法", line)
    ]
    assert not offenders, (
        "README 出现裸的「GES 算法」表述，实现其实是 GES-style 贪心搜索：\n"
        + "\n".join(f"  L{n}: {ln}" for n, ln in offenders)
        + "\n请改成「GES-style」并在 README 里保留适用边界说明。"
    )


def test_readme_documents_ges_applicability_boundary():
    """实验性算法必须标注适用边界与未验证事项（§十一 P2 第 2 条）。

    反向守卫：光把名字改成 GES-style 不够，还得说明它在什么条件下不成立。
    """
    text = README.read_text(encoding="utf-8")
    assert "GES-style" in text, "README 应使用与 ges.py 一致的 GES-style 表述"
    assert "适用边界" in text, "README 需保留 GES-style 的适用边界说明"
    assert "Chickering" in text, "适用边界里必须点明与标准 GES 的差距"
    assert "未验证" in text or "从未测过" in text, \
        "适用边界里必须列出未验证事项（真实数据骨架一致率等）"


def test_documented_thresholds_match_code(doc_text):
    """阈值、冷启动封顶、样本门槛必须与实现一致。

    这几个数字直接决定「报不报警」，是使用者最需要准确的那几个。
    """
    from anomaly_detector import (
        ANOMALY_SCORE_THRESHOLD, COLD_START_MIN_SAMPLES,
        COLD_START_SCORE_CAP, RARITY_MIN_SAMPLES, SIGMA_EQUIVALENT_THRESHOLD,
    )

    for label, value in (
        ("ANOMALY_SCORE_THRESHOLD", ANOMALY_SCORE_THRESHOLD),
        ("SIGMA_EQUIVALENT_THRESHOLD", SIGMA_EQUIVALENT_THRESHOLD),
        ("COLD_START_SCORE_CAP", COLD_START_SCORE_CAP),
        ("COLD_START_MIN_SAMPLES", float(COLD_START_MIN_SAMPLES)),
        ("RARITY_MIN_SAMPLES", float(RARITY_MIN_SAMPLES)),
    ):
        documented = _doc_value(doc_text, label)
        assert documented is not None, f"文档里没有写明 {label} 的数值"
        assert documented == pytest.approx(float(value)), (
            f"文档写 {label}={documented}，实现是 {value}")

    # 封顶必须严格低于阈值，否则按 >= 消费 score 的下游会被冷启动误触
    assert COLD_START_SCORE_CAP < ANOMALY_SCORE_THRESHOLD, \
        "冷启动封顶不低于阈值 —— 冷启动会直接告警"


def test_documented_is_anomaly_rule_matches_code(doc_text):
    """``is_anomaly`` 的判定式必须与实现一致。"""
    import inspect

    from anomaly_detector import AnomalyDetector

    assert "ANOMALY_SCORE_THRESHOLD" in doc_text, \
        "文档未声明 is_anomaly 使用的阈值常量名"

    # 扫**整个类**而不是某一个方法：`analyze()` 后来拆成了带埋点的外层 +
    # `_analyze_inner()`，判定逻辑在后者。硬编码方法名会在下次重构时
    # 误报 —— 而误报的守卫比没有守卫更糟，人会开始忽略它。
    src = inspect.getsource(AnomalyDetector)
    assert "is_anomaly =" in src, "anomaly_detector 里找不到 is_anomaly 赋值"
    assert "SIGMA_EQUIVALENT_THRESHOLD" in src, \
        ("实现里没有用到 σ 等效阈值 —— 若判定被简化成只看分数，"
         "文档声称的「两个独立条件」就是假的")

    # 文档必须同时写出两个条件，缺一个就会让人以为只看分数
    tail = doc_text[doc_text.find("is_anomaly"):][:200]
    assert "deviation_sigma" in tail and "ANOMALY_SCORE_THRESHOLD" in tail, (
        "文档的 is_anomaly 判定式不完整 —— 分数与 σ 是两个独立条件，"
        "只写一个会让人以为另一个不存在")
