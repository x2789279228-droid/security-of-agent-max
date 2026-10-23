# -*- coding: utf-8 -*-
"""整改方案 §十一.2：所有用于运维决策的**状态词表保持一致**。

文档 §十一.2 原文：

> - 所有用于运维决策的状态词表保持一致。

## 这条守卫守什么

检测语义的规范词表只有一个（`detection_contract.ALL_STATUSES`）：

    detected / not_detected / inconclusive / error / partial

本守卫扫**检测状态词表的消费方**（导入/引用 `detection_contract` 的模块），
把「状态槽位」上的字符串字面量全部收集起来，要求每个字面量要么

* 属于规范词表；要么
* 在**登记表** `REGISTERED_OTHER` 里，且**登记了它属于哪套词表**。

登记表是**显式**的：新增一个非规范词必须先登记理由，
否则本守卫变红 —— 这正是「词表保持一致」从愿望变成不变式的地方。

## 为什么登记表要「反向检查」

登记表若只进不出，会积攒早已不用的词，最后**失去意义**。
所以本守卫还要求：登记的每个词**必须真的在代码里出现**。

## 前提守卫（否则本守卫可能恒绿）

* 检测链路不能为空，且必须包含 `detection_contract.py` 本身；
* 扫描必须真的抓到规范词表里的字面量（抓到 0 个 = 扫描器坏了）；
* **已知答案自检**：往一段合成代码里塞一个非规范词，
  扫描器必须报出来 —— 扫描器自己也可能恒绿。
"""
import ast
import io
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

#: 检测语义的规范词表
CANON = {"detected", "not_detected", "inconclusive", "error", "partial"}

#: 登记表：检测链路里**确实存在**、但属于**别的词表**的状态值。
#: 键 = 字面量，值 = 它属于哪套词表 / 为什么不是检测结论。
REGISTERED_OTHER = {
    "review_queued":
        "HTTP 兼容字段（`RunResult.status`），不是检测结论；"
        "见 `ingest_pipeline._build_run_result` 的 docstring",
    "fallback":
        "审计跟踪状态（`_mark_analyzed` 的 status 槽位，与 `quality='shed'` 配对），"
        "不是检测结论",
    # ── §9.51 本轮新增：grounding 闸门的状态（**同一套词表**，审计与指标共用）──
    "evaluated_pass":
        "grounding 闸门状态（`audit['checks']['grounding']['state']` 与指标 "
        "`soc_response_grounding_gate_total{state=}`）：这道闸门**确实评估过**"
        "且通过；不属于检测结论词表（整改报告 §9.51）",
    "evaluated_block":
        "grounding 闸门状态（同上）：评估过但**不通过** → 动作被拦；"
        "不属于检测结论词表（整改报告 §9.51）",
    "not_evaluated":
        "grounding 闸门状态（同上）：**根本没有 grounding 分数** → 闸门未评估、"
        "不提供任何保护；不属于检测结论词表（整改报告 §9.51）",
    # ── §9.52 本轮新增：幂等检查状态（**另一套词表**）──
    "evaluated_hit":
        "幂等检查状态（指标 `soc_response_idempotency_check_total{state=}`）："
        "查了且命中重复 → 动作被跳过；不属于检测结论词表（整改报告 §9.52）",
    "evaluated_miss":
        "幂等检查状态（同上）：查了且**不是**重复 → 动作照常执行；"
        "不属于检测结论词表（整改报告 §9.52）",
    "unavailable":
        "幂等检查状态（同上）：**Redis 不可用 → 检查根本没跑** → 此刻幂等保护"
        "不生效；不属于检测结论词表（整改报告 §9.52）",
}

#: 「状态槽位」的名字
STATUS_SLOTS = {
    "status", "state", "verdict", "outcome", "analysis_status",
    "detection_status", "detector_status", "final_status", "result_status",
}

SKIP_DIRS = {"node_modules", ".venv", "venv", "__pycache__", ".git",
             "frontend", "dist", "build", ".pytest_cache", "event_archive"}


# ── 扫描器 ──────────────────────────────────────────────────────────


def detect_chain_modules() -> set:
    """导入/引用 detection_contract 的模块 = 检测状态词表的消费方。"""
    mods = set()
    for dirpath, dirnames, filenames in os.walk(BACKEND):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            if not fn.endswith(".py"):
                continue
            p = os.path.join(dirpath, fn)
            rel = os.path.relpath(p, BACKEND).replace("\\", "/")
            try:
                src = io.open(p, encoding="utf-8").read()
            except OSError:
                continue
            if ("detection_contract" in src or "ALL_STATUSES" in src
                    or "STATUS_DETECTED" in src or "STATUS_NOT_DETECTED" in src
                    or "STATUS_INCONCLUSIVE" in src):
                mods.add(rel)
    return mods


def _slot_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def status_literals(source: str) -> list:
    """抓出「状态槽位」上的字符串字面量。返回 [(行号, 槽位, 值)]。

    覆盖三种写法：
      1. 关键字实参：f(status="x")
      2. 赋值：x.status = "x" / status = "x"
      3. 字典字面量：{"status": "x"}
      4. 比较：status == "x" / status in {"x"}
    """
    out = []
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            for kw in node.keywords:
                if (kw.arg in STATUS_SLOTS and isinstance(kw.value, ast.Constant)
                        and isinstance(kw.value.value, str)):
                    out.append((kw.value.lineno, kw.arg, kw.value.value))
        elif isinstance(node, ast.Assign):
            for tgt in node.targets:
                name = _slot_name(tgt)
                if (name in STATUS_SLOTS and isinstance(node.value, ast.Constant)
                        and isinstance(node.value.value, str)):
                    out.append((node.value.lineno, name, node.value.value))
        elif isinstance(node, ast.Dict):
            for k, v in zip(node.keys, node.values):
                if (isinstance(k, ast.Constant) and k.value in STATUS_SLOTS
                        and isinstance(v, ast.Constant)
                        and isinstance(v.value, str)):
                    out.append((v.lineno, k.value, v.value))
        elif isinstance(node, ast.Compare):
            name = _slot_name(node.left)
            if name in STATUS_SLOTS:
                for cmp_ in node.comparators:
                    if isinstance(cmp_, ast.Constant) and isinstance(cmp_.value, str):
                        out.append((cmp_.lineno, name, cmp_.value))
                    elif isinstance(cmp_, (ast.Set, ast.List, ast.Tuple)):
                        for el in cmp_.elts:
                            if isinstance(el, ast.Constant) and isinstance(el.value, str):
                                out.append((el.lineno, name, el.value))
    return out


# ── 前提守卫 ────────────────────────────────────────────────────────


class TestTheScannerItself:
    def test_the_detection_chain_is_not_empty(self):
        chain = detect_chain_modules()
        assert chain, "检测链路的消费方一个都没找到 —— 扫描器坏了"
        assert "detection_contract.py" in chain, (
            f"规范词表自己不在链路里：{sorted(chain)}")

    def test_the_scanner_finds_canonical_status_literals(self):
        """扫描器必须真的抓到规范词表 —— 抓到 0 个就是空转。"""
        found = []
        for rel in detect_chain_modules():
            p = os.path.join(BACKEND, rel.replace("/", os.sep))
            try:
                found += [v for _l, _s, v in status_literals(
                    io.open(p, encoding="utf-8").read())]
            except (OSError, SyntaxError):
                continue
        assert found, "一个状态字面量都没抓到 —— 扫描器坏了"
        assert set(found) & CANON, (
            f"只抓到非规范词 {sorted(set(found))} —— 扫描器没在工作")

    def test_the_scanner_has_a_known_answer(self):
        """**已知答案自检**：塞一个非规范词，扫描器必须报出来。

        扫描器自己也可能恒绿（槽位名写错、AST 形态漏了），
        所以要有这个自检 —— 它是「本守卫能变红」的唯一依据。
        """
        src = (
            "def f():\n"
            "    status = 'totally_not_a_status'\n"
            "    return {'status': 'another_bogus_word'}\n"
        )
        vals = {v for _l, _s, v in status_literals(src)}
        assert "totally_not_a_status" in vals, vals
        assert "another_bogus_word" in vals, vals

    def test_the_canonical_set_matches_the_contract(self):
        """规范词表本身必须与 `detection_contract` 一致 ——
        有人加了第 6 个状态而没改这里，本守卫要抓到。"""
        from detection_contract import ALL_STATUSES

        assert set(ALL_STATUSES) == CANON, (
            f"契约里的状态集合变了：{sorted(ALL_STATUSES)} "
            f"（本守卫登记的是 {sorted(CANON)}）")


# ── 本体 ────────────────────────────────────────────────────────────


class TestStatusVocabularyIsConsistent:
    def test_every_status_literal_in_the_detection_chain_is_registered(self):
        """检测链路上的每个状态字面量，规范或已登记 —— 否则就是词表漂移。"""
        offenders = []
        for rel in sorted(detect_chain_modules()):
            p = os.path.join(BACKEND, rel.replace("/", os.sep))
            try:
                lits = status_literals(io.open(p, encoding="utf-8").read())
            except (OSError, SyntaxError):
                continue
            for lineno, slot, val in lits:
                if val in CANON or val in REGISTERED_OTHER:
                    continue
                offenders.append("%s:%d  %s = %r" % (rel, lineno, slot, val))
        assert not offenders, (
            "检测链路里出现了未登记的状态词（§十一.2「状态词表保持一致」）：\n  "
            + "\n  ".join(offenders)
            + "\n  → 要么改用规范词表，要么在 REGISTERED_OTHER 里登记它属于哪套词表。")

    def test_the_registry_is_not_stale(self):
        """登记表里的每个词都**必须真的在代码里出现**。

        登记表只进不出的话，会积攒一堆早已不用的词，
        最后就没人知道它到底管不管用 —— 登记表会失去意义。
        """
        used = set()
        for rel in detect_chain_modules():
            p = os.path.join(BACKEND, rel.replace("/", os.sep))
            try:
                used |= {v for _l, _s, v in status_literals(
                    io.open(p, encoding="utf-8").read())}
            except (OSError, SyntaxError):
                continue
        stale = sorted(set(REGISTERED_OTHER) - used)
        assert not stale, (
            f"登记表里的词在代码里已经不存在了：{stale} —— 登记过期，删掉它")

    def test_every_registered_word_has_a_reason(self):
        """登记理由为空串 = 静默白名单。"""
        for word, reason in REGISTERED_OTHER.items():
            assert reason and len(reason.strip()) >= 8, (
                f"登记项 {word!r} 没有写清它属于哪套词表")


if __name__ == "__main__":       # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
