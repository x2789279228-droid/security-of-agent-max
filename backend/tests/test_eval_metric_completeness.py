"""
§十三 验收「分别报告各类检测器的 Precision、Recall、**误报率与漏报率**」。

发现（2026-10-19 本轮查证，非推测）：
  `eval_datasets/evaluate_grounding.py` 与 `evaluate_behavior.py` 都是
  **三分类**评估器（grounded / partially_grounded / ungrounded、
  logged / confirm / deny），它们的 `per_class` 原本只有 tp/fp/fn/P/R/F1，
  **没有误报率与漏报率**；只有二分类的 `evaluate_detection.py` 有。
  于是 §十三 明文要求的四个指标里，后两个在两个评估器上缺失。

口径（与 `evaluate_detection.py` 文档里写明的坑保持一致）：
  逐类 one-vs-rest，把当前 label 当正类
      TN = 计入准确率的样本总数 − tp − fp − fn
      FPR = FP / (FP + TN)
      FNR = FN / (FN + TP) = 1 − recall
  分母用 `counted`（排除 known_gap）：已知检不出的样本既不是误报也不是漏报，
  算成 TN 会虚高特异度、算成 FN 会虚高漏报率。

**为什么这些用例必须用人工构造的混淆矩阵**：
当前两套黄金样本分别是 12 / 9 条计入样本，且**全部判对** ——
实测出来的 FPR、FNR 全是 0。若只在真实数据上断言「这些率存在且落在 0~1
之间」，这条守卫永远不会红：那是空断言（虽然形状与「指标缺失」不同，
但同样不设防）。所以这里用已知答案的混淆矩阵把公式钉死。
"""
from __future__ import annotations

import json
import os
import sys
from collections import Counter
from pathlib import Path

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND))
os.environ.setdefault("SHARED_MEMORY_SKIP_DOTENV", "1")

from eval_datasets.behavior_cases import SCENARIOS as BEHAVIOR_SCENARIOS  # noqa: E402
from eval_datasets.grounding_cases import CASES as GROUNDING_CASES  # noqa: E402
from eval_datasets.evaluate_behavior import ACTIONS  # noqa: E402
from eval_datasets.evaluate_behavior import EvalReport as BehaviorReport  # noqa: E402
from eval_datasets.evaluate_behavior import run_scenarios  # noqa: E402
from eval_datasets.evaluate_grounding import LABELS  # noqa: E402
from eval_datasets.evaluate_grounding import EvalReport as GroundingReport  # noqa: E402
from eval_datasets.evaluate_grounding import run_dataset  # noqa: E402


class _Stub:
    """`per_class` 只读 expect / got / counted 三个属性，鸭子类型足够。"""

    def __init__(self, expect: str, got: str, counted: bool = True):
        self.expect = expect
        self.got = got
        self.counted = counted

    def __repr__(self):  # pragma: no cover - 让断言消息可读
        return f"_Stub({self.expect}->{self.got},counted={self.counted})"


#: (name, report_cls, 正类A, 另一类B)
_TARGETS = (
    ("grounding", GroundingReport, LABELS[0], LABELS[2]),
    ("behavior", BehaviorReport, ACTIONS[0], ACTIONS[1]),
)


def _mixed(a: str, b: str) -> list:
    """A→A, A→A, A→B(漏), B→B, B→B，外加一条 known_gap（不进任何计数）。

    A 当正类：tp=2, fn=1, fp=0, tn=2 → 计入样本 5
    B 当正类：tp=2, fn=0, fp=1, tn=2
    """
    return [
        _Stub(a, a), _Stub(a, a), _Stub(a, b),
        _Stub(b, b), _Stub(b, b),
        _Stub(b, a, counted=False),   # known_gap
    ]


class TestFalsePositiveAndNegativeRatesAreReported:
    """§十三：误报率与漏报率必须在两个三分类评估器上都能报出来。"""

    def test_real_datasets_expose_all_four_rate_metrics(self):
        real = {"grounding": run_dataset().per_class,
                "behavior": run_scenarios().per_class}
        for name, _cls, _a, _b in _TARGETS:
            for label, m in real[name].items():
                for key in ("tp", "fp", "fn", "tn", "precision", "recall",
                            "false_positive_rate", "false_negative_rate"):
                    assert key in m, f"{name}.{label} 缺少 {key} —— §十三 要求报出它"
                for rate in ("false_positive_rate", "false_negative_rate"):
                    assert m[rate] is None or 0.0 <= m[rate] <= 1.0, \
                        f"{name}.{label}.{rate} 越界: {m[rate]}"

    def test_rates_follow_the_documented_formulas(self):
        """用已知答案的混淆矩阵钉死公式，而不是断言「在 0~1 之间」。"""
        for name, report_cls, a, b in _TARGETS:
            pc = report_cls(results=_mixed(a, b)).per_class

            ma = pc[a]
            assert (ma["tp"], ma["fn"], ma["fp"], ma["tn"]) == (2, 1, 0, 2), (name, ma)
            assert ma["precision"] == 1.0, (name, ma)
            assert abs(ma["recall"] - 2 / 3) < 1e-9, (name, ma)
            assert ma["false_positive_rate"] == 0.0, (name, ma)
            assert abs(ma["false_negative_rate"] - 1 / 3) < 1e-9, (name, ma)

            mb = pc[b]
            assert (mb["tp"], mb["fn"], mb["fp"], mb["tn"]) == (2, 0, 1, 2), (name, mb)
            assert abs(mb["precision"] - 2 / 3) < 1e-9, (name, mb)
            assert mb["recall"] == 1.0, (name, mb)
            assert abs(mb["false_positive_rate"] - 1 / 3) < 1e-9, (name, mb)
            assert mb["false_negative_rate"] == 0.0, (name, mb)

    def test_known_gap_excluded_from_every_denominator(self):
        """known_gap 不得进入 tp/fp/fn/tn 的任何一项。

        若把它算成 TN，A 当正类时 TN 会变成 3、误报率口径直接被稀释；
        算成 FN 则会凭空造出一条不存在的漏报。
        """
        for name, report_cls, a, b in _TARGETS:
            pc = report_cls(results=_mixed(a, b)).per_class
            assert pc[a]["tn"] == 2, (
                f"{name}: TN 应为 5−2−1−0=2，实得 {pc[a]['tn']}（known_gap 被算进去了）")
            for label, m in pc.items():
                assert m["tp"] + m["fp"] + m["fn"] + m["tn"] == 5, (
                    f"{name}.{label}: 混淆矩阵四项之和应为计入样本数 5，实得 "
                    f"{m['tp'] + m['fp'] + m['fn'] + m['tn']}")

    def test_false_negative_rate_is_one_minus_recall(self):
        for name, report_cls, a, b in _TARGETS:
            for label, m in report_cls(results=_mixed(a, b)).per_class.items():
                if m["recall"] is None:
                    # 该标签在样本里没有正例（tp=fn=0）：两个率都无定义，
                    # 且必须**同时**是 None，不能一个 None 一个 0.0。
                    assert m["false_negative_rate"] is None, (name, label, m)
                    continue
                assert abs(m["false_negative_rate"]
                           - (1 - m["recall"])) < 1e-9, (name, label, m)

    def test_rate_is_none_when_its_own_denominator_is_empty(self):
        """分母为 0 的那个率必须是 None 而不是 0.0 —— 0.0 会被读成「没有误报/漏报」。

        两个率**不可能同时**无定义：FPR 的分母是「真值不是 b 的样本数」，
        FNR 的分母是「真值是 b 的样本数」，两者相加等于计入样本总数。
        所以分别构造：
          - 全部真值都是 b → fp+tn=0 → FPR 无定义
          - 全部真值都不是 b → fn+tp=0 → FNR 无定义
        """
        for name, report_cls, a, b in _TARGETS:
            # 全部真值都是 b 且都判对：FPR 无定义，FNR = 0/(0+n) = 0.0 有定义
            only_b = report_cls(results=[_Stub(b, b), _Stub(b, b)]).per_class
            assert only_b[b]["false_positive_rate"] is None, (name, only_b[b])
            assert only_b[b]["false_negative_rate"] == 0.0, (name, only_b[b])

            # 全部真值都不是 b：FNR 无定义，FPR = 0/(0+n) = 0.0 有定义
            not_b = report_cls(results=[_Stub(a, a), _Stub(a, a)]).per_class
            assert not_b[b]["false_negative_rate"] is None, (name, not_b[b])
            assert not_b[b]["false_positive_rate"] == 0.0, (name, not_b[b])


# ══════════════════════════════════════════════════════════════════════════
# §十三 指标一致性：JSON 路径与文本渲染路径不得对同一个量给出不同的数
# ══════════════════════════════════════════════════════════════════════════

class TestExcludedRowsAreCountedNotPreFiltered:
    """「候选(排除)」必须**如实计数**，不能在进 `_binary` 之前就被丢掉。

    口径分叉实例（2026-10-19 修复）：异常检测的 `--json` 路径此前写的是

        _binary([r for r in rows if r["expect"] in ("detected","not_detected")],
                "detected", ...)

    那层预过滤把 3 条 `inconclusive` 行在 `_binary` 之前就删掉了，于是
    `excluded_suspicious` 报 **0**；而**文本渲染**是单独统计的，报 **3**。
    同一份报告的两种输出格式，对「候选(排除)」给出不同的数 ——
    验收报告 §4.1 的表格与 `--json` 因此对不上，**而没有任何一方报错**。

    预过滤还有第二个后果：它让 `excluded_suspicious` 变成一个
    「恒为 0 的死字段」，于是「第三类有没有被如实记账」这件事
    在指标上再也看不出来。删掉预过滤后 `_binary` 自己排除，
    两条路径口径统一。

    ⚠️ **本守卫必须走 `main(["--json"])`，不能自己调 `_binary`**（第一次写成
    后者，注入预过滤后 7 条全绿 —— 因为缺陷在**调用点**，守卫绕开了它）。
    与「只比较簇代表」是同一类错误：**判据测的不是被消费的那条路径**。
    """

    _FAMILIES = (
        ("sigma", "malicious", "benign"),
        ("anomaly", "detected", "not_detected"),
        ("correlation", "chain", "no_chain"),
    )

    @staticmethod
    def _emitted_json(capsys):
        """跑**真实的** `--json` 出口，读回它真正发出去的那份数据。"""
        from eval_datasets import evaluate_detection as ed

        rc = ed.main(["--json"])
        assert rc in (0, 1), rc
        return json.loads(capsys.readouterr().out)

    def test_third_class_rows_are_reported_as_excluded(self, capsys):
        from eval_datasets import evaluate_detection as ed
        from eval_datasets.evaluate_detection import _binary

        rows_by_family = {
            "sigma": ed.run_sigma(),
            "anomaly": ed.run_anomaly(),
            "correlation": ed.run_correlation(),
        }
        d = self._emitted_json(capsys)
        blocks = {
            "sigma": d["sigma"]["overall"],
            "anomaly": d["anomaly"]["detected_recall"],
            "correlation": d["correlation"]["overall"],
        }

        for name, pos, neg in self._FAMILIES:
            rows = rows_by_family[name]
            expected = sum(1 for r in rows if r["expect"] not in (pos, neg))
            got = blocks[name]["excluded_suspicious"]
            assert got == expected, (
                f"{name}: 数据集里第三类 {expected} 条，但 --json 发出的 "
                f"excluded_suspicious={got} —— 有行在进 _binary 之前就被丢掉了")
            # 顺带确认「直接调 _binary」与「实际出口」口径一致 ——
            # 两者若不等，说明有人只在其中一条路径上加了排除逻辑。
            direct = _binary(rows, pos, negative_label=neg)
            assert direct["excluded_suspicious"] == got, (
                f"{name}: 直接调用得 {direct['excluded_suspicious']}，"
                f"实际出口得 {got} —— 两条路径的排除口径分叉了")

    def test_anomaly_inconclusive_rows_are_counted_not_dropped(self, capsys):
        """异常检测这一族专有的回归：3 条 inconclusive 必须出现在计数里。"""
        from eval_datasets import evaluate_detection as ed

        rows = ed.run_anomaly()
        n_inc = sum(1 for r in rows if r["expect"] == "inconclusive")
        assert n_inc == 3, f"标定集里 inconclusive 的条数变了: {n_inc}"

        d = self._emitted_json(capsys)
        m = d["anomaly"]["detected_recall"]
        assert m["excluded_suspicious"] == n_inc, (
            f"--json 的 excluded_suspicious={m['excluded_suspicious']}，"
            f"但数据集里有 {n_inc} 条 inconclusive —— 预过滤把它们吞了")
        # 演进：(1,2,2)（ANO-P-02/03 为 known_gap 时期）→ (3,0,2)
        # （2026-10-25 severity_shift 维度关闭缺口，正类 3 条全检出）。
        assert (m["tp"], m["fn"], m["tn"]) == (3, 0, 2), m
class TestGoldenSetsStillHaveDiscriminatingPower:
    """黄金样本集必须**有区分度** —— 否则 §十三 的指标就是空转的。

    2026-10-19 的报告更正：本报告曾写「两套黄金样本全部判对 → 判别力为零」，
    那是**过强**表述。实测：grounding 集 12 条计入样本分属 3 类（grounded 5 /
    ungrounded 6 / partial 1），恒判 grounded 的**平凡检测器会错 7/12**；
    behavior 集 9 条计入样本分属 logged/confirm/deny 各 3 条，
    恒判 logged 会错 6/9。

    真正要守住的是：**数据集不能退化成「单一类别」** ——
    一旦所有期望标签相同，任何检测器都能拿 100%，
    误报率/漏报率就再也测不出东西（**那才是**「判别力为零」）。

    同时守住「评估器读到的类别分布」与「黄金样本表」同源 ——
    两者一旦漂移，报告里的 per_class 数字就不可信。
    """

    @staticmethod
    def _counts(cases) -> dict:
        counted = [c for c in cases if not c.get("known_gap")]
        return dict(Counter(c["expect"] for c in counted))

    def test_grounding_golden_set_is_not_degenerate(self):
        counts = self._counts(GROUNDING_CASES)
        total = sum(counts.values())
        assert total >= 2, f"grounding 计入样本只有 {total} 条"
        assert len(counts) >= 2, (
            f"grounding 集退化成单一类别：{counts} —— "
            "任何检测器都能拿 100%，§十三 的指标就测不出东西了")
        assert max(counts.values()) < total, (
            f"grounding 集的最大类别占 {max(counts.values())}/{total} —— "
            "恒判该类的平凡检测器就能拿满分，指标失去区分度")

    def test_behavior_golden_set_is_not_degenerate(self):
        counts = self._counts(BEHAVIOR_SCENARIOS)
        total = sum(counts.values())
        assert total >= 2, f"behavior 计入样本只有 {total} 条"
        assert len(counts) >= 2, (
            f"behavior 集退化成单一类别：{counts} —— "
            "任何检测器都能拿 100%，§十三 的指标就测不出东西了")
        assert max(counts.values()) < total, (
            f"behavior 集的最大类别占 {max(counts.values())}/{total} —— "
            "恒判该类的平凡检测器就能拿满分，指标失去区分度")

    def test_evaluator_class_counts_agree_with_the_golden_sets(self):
        """评估器读到的每类样本数必须与黄金样本表**同源**。

        这里刻意不比较**标签名**（黄金表写 `partial`，评估器写
        `partially_grounded`），只比较**总数与类别数** ——
        后者才是「区分度」真正依赖的东西。
        """
        for name, cases, report in (
            ("grounding", GROUNDING_CASES, run_dataset()),
            ("behavior", BEHAVIOR_SCENARIOS, run_scenarios()),
        ):
            expected = self._counts(cases)
            got = {label: m["tp"] + m["fn"] for label, m in report.per_class.items()}
            got = {label: n for label, n in got.items() if n}
            assert sum(got.values()) == sum(expected.values()), (
                f"{name}: 评估器计入样本 {sum(got.values())} 条，"
                f"黄金样本表 {sum(expected.values())} 条 —— 口径漂移")
            assert len(got) == len(expected), (
                f"{name}: 评估器看到 {len(got)} 个类别，黄金样本表 {len(expected)} 个 —— "
                f"{sorted(got)} vs {sorted(expected)}")
# ══════════════════════════════════════════════════════════════
# §四 验收指标：每千条事件误报量
# ══════════════════════════════════════════════════════════════

class TestFalsePositivesPerThousandIsReported:
    """整改方案 §四 的异常检测验收指标表里有这一行：

      | **每千条事件误报量** | 直观衡量实际运营负担 |

    此前**没有报**（`_binary` 只有 P/R/F1/FPR/FNR/accuracy）。

    「每千条事件」有两种分母，必须分清，否则读的人会自己猜：

      · `false_positives_per_1k_benign` —— 每千条**良性**事件里的误报数。
        与 FPR 同源，**与基准率无关**。
      · `false_positives_per_1k`（按基准率分档）—— 每千条**摄入事件**里的
        误报数，这才是「运营负担」：良性事件占 (1-p)，其中 FPR 那部分被误报。
    """

    def test_binary_reports_per_1k_benign(self):
        from eval_datasets.evaluate_detection import _binary

        # 3 正 + 2 负：tp=3, fn=0, fp=1, tn=1 → FPR = 1/2 = 0.5
        rows = [
            {"expect": "malicious", "got_positive": True},
            {"expect": "malicious", "got_positive": True},
            {"expect": "malicious", "got_positive": True},
            {"expect": "benign", "got_positive": True},     # 误报
            {"expect": "benign", "got_positive": False},
        ]
        m = _binary(rows, "malicious")
        assert "false_positives_per_1k_benign" in m, sorted(m)
        assert m["false_positive_rate"] == 0.5, m
        assert m["false_positives_per_1k_benign"] == 500.0, m

    def test_per_1k_is_none_when_its_own_denominator_is_empty(self):
        """分母为空时必须是 None 而不是 0.0 —— 0.0 会被读成「没有误报」。

        FPR 的分母是 `fp + tn`，所以要让它为空，**一条负样本都不能有**
        （只有 1 条负样本时 fp=0/tn=1 → FPR=0.0，那是「有定义且为 0」，
        与「算不出来」是两回事）。
        """
        from eval_datasets.evaluate_detection import _binary

        rows = [
            {"expect": "malicious", "got_positive": True},
        ]
        m = _binary(rows, "malicious")
        assert m["fp"] == 0 and m["tn"] == 0, m
        assert m["false_positive_rate"] is None, m
        assert m["false_positives_per_1k_benign"] is None, m

    def test_prevalence_table_reports_the_operational_burden(self):
        """每档基准率下的「每千条摄入事件误报量」= 1000 × (1-p) × FPR。"""
        from eval_datasets.evaluate_detection import precision_by_prevalence

        rows = [
            {"expect": "malicious", "got_positive": True},
            {"expect": "malicious", "got_positive": True},
            {"expect": "malicious", "got_positive": True},
            {"expect": "benign", "got_positive": True},     # fp=1
            {"expect": "benign", "got_positive": False},    # tn=1
        ]
        prev = precision_by_prevalence(rows, "malicious")
        fpr = prev["false_positive_rate"]
        assert fpr == 0.5, prev
        assert "false_positives_per_1k_benign" in prev, sorted(prev)
        assert prev["false_positives_per_1k_benign"] == 500.0, prev
        for key, v in prev["by_prevalence"].items():
            if key == "current_ppv":
                continue
            p = v["prevalence"]
            assert "false_positives_per_1k" in v, (key, sorted(v))
            assert v["false_positives_per_1k"] == 1000 * (1 - p) * fpr, (key, v)
