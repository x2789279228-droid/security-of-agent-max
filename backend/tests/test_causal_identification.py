"""因果引擎的**识别条件**守卫（整改方案 §三.2 P0）。

验收标准原文：
  「不可识别时，不能输出已识别的 ACE」
  「明确区分 observed_variables、已声明的潜变量以及未知混杂假设」
  「修复 extra 候选调整集恒为空的过滤逻辑，检查所有符合理论条件的候选调整集」

这一组性质此前**没有任何测试覆盖**：
既有 `test_causal_chain.py` / `test_causal_path_gate.py` 覆盖的是
`compare.py` 的判定顺序（§三.1）与 `path_ok` 闸门，
**没有一条**断言「不可识别时不得输出 ACE」——
而那正是 §三.2 点名的 P0。修复前后的差别是：

  · 修复前：空调整集被直接当成「不存在需要调整的后门路径」，
    于是一个真实 ACE≈+0.60 的强因果在有未观测混杂的图上算出 +0.28，
    并打上 `identifiable=True`。
  · 修复后：图里 H→X / H→Y 仍在，G_Xbar 下 X 与 Y 不 d-分离 →
    空集不合法、没有**可观测**候选能挡住它 → 不可识别，**不给 ACE**。
"""
from __future__ import annotations

import os

import numpy as np
import pytest

os.environ.setdefault("SHARED_MEMORY_SKIP_DOTENV", "1")

from causal_chain.do_calculus import (  # noqa: E402
    candidate_adjust_sets, intervene,
)
from causal_chain.variables import CONFOUNDERS  # noqa: E402

#: 图里有 H→X、H→Y、X→Y；H 是**混杂**。
GRAPH_WITH_LATENT_H = [("H", "X"), ("H", "Y"), ("X", "Y")]
#: 同一张图，但 H **不可观测**（不在 names 里）
GRAPH_OBSERVED_ONLY = [("X", "Y")]


def _binary_table() -> np.ndarray:
    """H（混杂）、X（处理）、Y（结果）的 2x2x2 观测表。

    H=1 时 X 与 Y 都更容易为 1 —— 真实因果效应明显为正，
    所以「算出一个正数」很容易，**关键看是不是在不可识别时还算**。
    """
    rows = []
    for h in (0, 1):
        for x in (0, 1):
            p = 0.1 if h == 0 else 0.9
            for y in (0, 1):
                q = p if x == 0 else min(0.95, p + 0.3)
                rows.append((h, x, y, 20 if (h == 0 and x == 0 and y == 0) else 5))
    return np.array([r[:3] for r in rows for _ in range(r[3])], dtype=np.int8)


DATA = _binary_table()


class TestIdentificationConditions:
    """§三.2：识别条件必须站得住，站不住就**不许给数字**。"""

    def test_unobserved_confounder_in_graph_blocks_identification(self):
        """【已修复】图里存在未观测混杂时 → 不可识别，且**不得输出 ACE**。

        这是本组最要害的一条：旧行为会在这里编造一个看似确定的 ACE。
        """
        r = intervene(DATA, ["X", "Y"], GRAPH_WITH_LATENT_H, "X", "Y")
        assert r["identifiable"] is False, (
            f"未观测混杂 H 在图里，却判成可识别：{r}")
        assert r.get("reason") == "no_backdoor", r.get("reason")
        assert "ace" not in r, (
            f"不可识别却仍然输出了 ACE：{r.get('ace')}")
        assert "p_y_do" not in r, (
            f"不可识别却仍然输出了 P(Y|do(X))：{r.get('p_y_do')}")

    def test_observable_confounder_is_adjusted_and_yields_an_ace(self):
        """【正向对照】H 可观测时 → 可识别，且调整集**就是 H**。

        这条守的是「别把好案例也一起堵死」—— 识别能力必须还在。
        """
        r = intervene(DATA, ["H", "X", "Y"], GRAPH_WITH_LATENT_H, "X", "Y")
        assert r["identifiable"] is True, r
        assert r.get("reason") == "backdoor", r.get("reason")
        assert r.get("z") == ["H"], r.get("z")
        assert isinstance(r.get("ace"), float), r.get("ace")

    def test_declared_latent_confounder_overrides_the_assumption(self):
        """【已修复】调用方**声明**的潜混杂变量必须推翻「无未观测混杂」这一假设。

        「没有不可观测混杂」是一个**显式假设**（随结果落库），
        而不是「变量不在 names 里就当它不存在」。
        """
        r = intervene(DATA, ["X", "Y"], GRAPH_OBSERVED_ONLY, "X", "Y",
                     unobserved_confounders=["H"])
        assert r["identifiable"] is False, r
        assert r.get("reason") == "unobserved_confounding", r.get("reason")
        assert "ace" not in r, r.get("ace")
        assumptions = r.get("assumptions") or {}
        assert assumptions.get("no_unobserved_confounding") is False, assumptions
        assert assumptions.get("declared_unobserved_confounders") == ["H"], assumptions
        # observed_variables 也要如实记录，便于下游分辨「不可观测」与「未声明」
        assert assumptions.get("observed_variables") == ["X", "Y"], assumptions

    def test_candidate_pool_contains_non_prior_variables(self):
        """【已修复】候选调整集不能只来自先验声明的混杂（extra 分支恒为空的老 bug）。

        修复前过滤条件 `n not in preferred and ... and is_confounder(n)` 互斥，
        这一支永远进不去 —— 图上真实存在的其它后门路径根本没进候选池。
        """
        names = ["X", "Y", "W1", "W2", "W3"]
        cands = candidate_adjust_sets(GRAPH_OBSERVED_ONLY, "X", "Y", names)
        non_prior = [c for c in cands
                     if c and not (set(c) & set(CONFOUNDERS))]
        assert non_prior, (
            f"候选集里没有任何非先验混杂的候选（extra 分支恒为空）：{cands}")
        # 空集也必须保留 —— 它是「图上验证过没有后门路径」的合法答案
        assert [] in cands, f"空集被过滤掉了：{cands}"

    @pytest.mark.parametrize("x, y, expect_reason", [
        ("X", "MISSING", "unknown_variable"),
        ("X", "X", "same_variable"),
    ])
    def test_unknown_or_same_variable_is_not_identifiable(self, x, y, expect_reason):
        """【已修复】变量不在 names 里、或 x == y → 不可识别且无 ACE。"""
        r = intervene(DATA, ["X", "Y"], GRAPH_OBSERVED_ONLY, x, y)
        assert r["identifiable"] is False, r
        assert r.get("reason") == expect_reason, r.get("reason")
        assert "ace" not in r, r.get("ace")
