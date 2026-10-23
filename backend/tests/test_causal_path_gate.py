"""§三.1：`path_ok` 必须是 `causal_support` 的最后一道闸（本轮修复）。

整改方案 §三.1 给出的判定伪代码是**五级**，最后两级写得很明确：

    elif not statistical_support: verdict = "insufficient_causal_evidence"
    elif path_ok:                 verdict = "causal_support"
    else:                         verdict = "unknown"

## 修复前实测（不是推断）

`_decide_verdict` 的签名里**根本没有 path_ok** ——
它被 `annotate_chain` 算出来、写进 `causal_path_ok` 字段，却完全不参与判定。

构造：学到的图里只保留 `PORT_SCAN → C2_BEACON` 的**直达边**，
于是 `PORT_SCAN → BRUTE_FORCE` 与 `BRUTE_FORCE → C2_BEACON`
两段相邻步骤**在图上都不可达**（`path_ok = False`），
但 `intervene(PORT_SCAN, C2_BEACON)` 完全可识别、ACE = 0.5955。

| | 修复前 | 修复后 |
|---|---|---|
| `causal_path_ok` | False | False |
| `causal_verdict` | **`causal_support`** | **`unknown`** |
| `ace` | 0.5955 | 0.5955 |

也就是说：因果图明确**不支持**这条攻击序列，下游却被告知「有因果支持」，
且带着一个漂亮的 ACE 数值。这与 §九.3「不要把先验/推测当成由数据识别出来的
方向」是同一类错误 —— **结论的强度超过了数据真正支持的范围**。

对照组（图上是完整的 `PORT_SCAN → BRUTE_FORCE → C2_BEACON`）
前后都仍是 `causal_support`，本修复不改变它。
"""
import inspect

import numpy as np
import pytest

from causal_chain.compare import (
    VERDICTS,
    _decide_verdict,
    _steps_of,
    annotate_chain,
)


# ── 夹具 ──────────────────────────────────────────────────────────


def _true_chain_matrix(n=700, seed=0):
    """有真实 PORT_SCAN → BRUTE_FORCE → C2_BEACON 结构的 SCM。"""
    rng = np.random.default_rng(seed)
    night = rng.random(n) < 0.35
    ps = np.where(night, rng.random(n) < 0.78, rng.random(n) < 0.12).astype(np.uint8)
    bf = np.where(ps == 1, rng.random(n) < 0.84, rng.random(n) < 0.05).astype(np.uint8)
    c2 = np.where(
        bf == 1,
        rng.random(n) < 0.82,
        np.where(night, rng.random(n) < 0.22, rng.random(n) < 0.04),
    ).astype(np.uint8)
    fa = (rng.random(n) < 0.07).astype(np.uint8)
    names = ["PORT_SCAN", "BRUTE_FORCE", "C2_BEACON", "FILE_ACCESS", "HOUR_NIGHT"]
    X = np.stack([ps, bf, c2, fa, night.astype(np.uint8)], axis=1)
    return X, names


CHAIN = {
    "pattern_id": "port_scan_to_c2",
    "pattern_name": "端口扫描→暴力破解→C2",
    "events": [
        {"event_type": "PORT_SCAN"},
        {"event_type": "BRUTE_FORCE"},
        {"event_type": "C2_BEACON"},
    ],
}

#: 图上只有首尾直达边 → 两段相邻步骤都不可达
BROKEN_GRAPH = [("PORT_SCAN", "C2_BEACON")]
#: 图上是完整链条
TRUE_GRAPH = [("PORT_SCAN", "BRUTE_FORCE"), ("BRUTE_FORCE", "C2_BEACON")]


def _annotate(directed):
    X, names = _true_chain_matrix()
    return annotate_chain(CHAIN, directed=directed, names=names, data=X)


# ── 核心：图不支持的攻击序列不得拿到 causal_support ────────────────


class TestPathOkGatesCausalSupport:
    def test_path_not_in_graph_never_yields_causal_support(self):
        out = _annotate(BROKEN_GRAPH)

        assert out["causal_path_ok"] is False
        assert out["causal_verdict"] != "causal_support", (
            "攻击序列在因果图上不成立，却拿到了 causal_support —— "
            "整改方案 §三.1 要求这种情况判 unknown")
        assert out["causal_verdict"] == "unknown"

    def test_the_test_premise_holds(self):
        """前提守卫：上面的用例必须真的处在「可识别 + ACE 显著」的状态。

        否则它可能只是因为 `identifiable=False` 才没拿到 causal_support，
        那样就测不到 path_ok 这道闸 —— 用例会变成永远绿的摆设。
        """
        out = _annotate(BROKEN_GRAPH)
        assert out["data_available"] is True
        assert out["identifiable"] is True
        assert out["ace"] is not None and abs(out["ace"]) >= 0.2, (
            "本用例的前提是 ACE 显著；不显著的话 verdict 会是 "
            "insufficient_causal_evidence，测的就不是 path_ok 了")

    def test_missing_edges_are_reported_not_silently_dropped(self):
        out = _annotate(BROKEN_GRAPH)
        missing = [tuple(p) for p in out["causal_missing_edges"]]
        assert ("PORT_SCAN", "BRUTE_FORCE") in missing
        assert ("BRUTE_FORCE", "C2_BEACON") in missing

    def test_true_chain_still_gets_causal_support(self):
        """回归：图上是完整链条时，结论不得被这道闸误伤。"""
        out = _annotate(TRUE_GRAPH)

        assert out["causal_path_ok"] is True
        assert out["causal_missing_edges"] == []
        assert out["causal_verdict"] == "causal_support"


class TestPathOkIsRequiredArgument:
    def test_decide_verdict_refuses_to_run_without_path_ok(self):
        """`path_ok` 必须**必填**。

        如果给它默认值 True，那么任何忘记传它的调用点都会静默放行 ——
        正是本轮要修的那个失效形态本身。默认值是最容易把闸拆掉的写法。
        """
        sig = inspect.signature(_decide_verdict)
        assert "path_ok" in sig.parameters
        assert sig.parameters["path_ok"].default is inspect.Parameter.empty, (
            "path_ok 不能有默认值：默认 True 等于「忘了传就放行」")

        with pytest.raises(TypeError):
            _decide_verdict(
                has_steps=True, data_available=True, identifiable=True,
                ace=0.5, ace_spurious=0.2,
                # 故意不传 path_ok
            )

    def test_every_verdict_is_inside_the_declared_vocabulary(self):
        """五种判定都必须落在 `VERDICTS` 里 —— 词表是下游的解析依据。"""
        for verdict in (
            "unknown", "insufficient_data", "not_identifiable",
            "insufficient_causal_evidence", "causal_support",
        ):
            assert verdict in VERDICTS

    def test_unknown_has_two_distinct_reachable_causes(self):
        """`unknown` 现在有两个来源，两个都必须走通。

        1. 没有可判定的攻击链步骤（修复前就有）
        2. 攻击序列在图上不成立（本轮新增）

        只测第 1 个会让第 2 个悄悄回退 —— 而它正是本轮的缺陷。
        """
        no_steps = _decide_verdict(
            has_steps=False, data_available=True, identifiable=True,
            ace=0.9, ace_spurious=0.2, path_ok=True)
        bad_path = _decide_verdict(
            has_steps=True, data_available=True, identifiable=True,
            ace=0.9, ace_spurious=0.2, path_ok=False)

        assert no_steps == "unknown"
        assert bad_path == "unknown"

    def test_earlier_gates_still_take_precedence(self):
        """path_ok 是**最后**一道闸：前面几级优先，不能被它盖掉。"""
        base = dict(has_steps=True, ace=0.9, ace_spurious=0.2)

        assert _decide_verdict(
            data_available=False, identifiable=True, path_ok=False,
            **base) == "insufficient_data"
        assert _decide_verdict(
            data_available=True, identifiable=False, path_ok=False,
            **base) == "not_identifiable"
        assert _decide_verdict(
            data_available=True, identifiable=True, path_ok=False,
            has_steps=True, ace=0.01, ace_spurious=0.2) == \
            "insufficient_causal_evidence"


class TestStepExtractionIsUnchanged:
    def test_steps_are_the_three_attack_stages(self):
        """闸只加在判定上，步骤抽取本身不能被顺手改掉。"""
        assert _steps_of(CHAIN) == ["PORT_SCAN", "BRUTE_FORCE", "C2_BEACON"]


# ══════════════════════════════════════════════════════════════════════════
# 跨语言契约：前端必须逐个区分后端的五种判定
# ══════════════════════════════════════════════════════════════════════════
#
# 整改方案 §三.1 末段：
#   「还应当确保前端和下游融合逻辑区分 causal_support、not_identifiable、
#     insufficient_data 和 unknown，不能把这些结果统一映射成一个真假值。」
#
# 修复前 `SecurityAudit.tsx` 只有三支三元表达式：
#     causal_support ? '因果支持' : (spurious ? '伪相关' : '未知')
#
# 两个问题：
#   1. `spurious` **不在后端 VERDICTS 里** → 永远不成立，是死分支；
#   2. 其余四种判定全部落进 `'未知'` —— 界面上完全同形。
#
# 第 2 条与本轮的 path_ok 修复叠加后更糟：`unknown` 现在可能表示
# 「这条攻击序列在因果图上不成立」，而它与「没有数据」显示成同一个词。

def _frontend_source() -> str:
    from pathlib import Path
    p = Path(__file__).resolve().parents[2] / "frontend" / "src" / "pages" / "SecurityAudit.tsx"
    assert p.exists(), f"找不到前端文件: {p}"
    return p.read_text(encoding="utf-8")


def _label_map_keys() -> set:
    import re
    src = _frontend_source()
    m = re.search(
        r"const\s+CAUSAL_VERDICT_LABEL[^=]*=\s*\{(.*?)\}",
        src, re.S)
    assert m, (
        "前端找不到 CAUSAL_VERDICT_LABEL 映射表 —— "
        "五种判定很可能又被压回了单一标签")
    return set(re.findall(r"([a-z_]+)\s*:", m.group(1)))


class TestFrontendDistinguishesEveryVerdict:
    def test_every_backend_verdict_has_a_frontend_label(self):
        keys = _label_map_keys()
        missing = set(VERDICTS) - keys
        assert not missing, (
            f"前端缺少这些判定的标签: {sorted(missing)} —— "
            "它们会全部显示成同一个词")

    def test_frontend_labels_exactly_the_backend_vocabulary(self):
        """多出来的键同样是错的：后端不产出它，它就是永远不成立的死分支。"""
        keys = _label_map_keys()
        extra = keys - set(VERDICTS)
        assert not extra, (
            f"前端标签表里有后端从不产出的取值: {sorted(extra)} —— "
            "死分支会让人以为存在一种其实没有的结论")

    def test_labels_are_all_distinct(self):
        """五个标签必须互不相同 —— 相同就等于又压回去了。"""
        import re
        src = _frontend_source()
        m = re.search(
            r"const\s+CAUSAL_VERDICT_LABEL[^=]*=\s*\{(.*?)\}",
            src, re.S)
        labels = re.findall(r":[ ]*'([^']+)'", m.group(1))
        assert len(labels) == len(VERDICTS)
        assert len(set(labels)) == len(labels), (
            f"标签有重复: {labels} —— 不同的判定显示成同一个词")

    def test_unknown_values_fall_back_to_the_raw_string(self):
        """表里没有的取值直接显示原值，不能谎报成「未知」。"""
        import re
        src = _frontend_source()
        assert "CAUSAL_VERDICT_LABEL[c.causal_verdict] ?? c.causal_verdict" in src, (
            "缺少 `?? c.causal_verdict` 兜底 —— "
            "后端将来新增一种判定时，界面会把它显示成别的结论")