"""
零日链后半段的**已知缺口**：`behavior_analyzer` → `variant_cluster` 在生产里没人调用。

## 事实（2026-10-18 本轮全仓扫描，非推测）

| 组件 | 生产调用方 |
|---|---|
| `sandbox_connector`（提交 / 轮询 / 状态机） | ✅ `routers/edr_intel.py:237` 等 |
| `behavior_analyzer.analyze()` | ❌ **零生产调用方**（只有测试） |
| `variant_cluster.add_sample()` / `find_similar()` / `get_cluster_info()` / `get_unclustered()` / `label_cluster()` | ❌ **零生产调用方**（只有测试） |

扫描口径与 `test_metric_wiring_guard.py` 一致：AST 扫全 backend，
排除 `tests/`；**不排除被扫描文件自身**（§11 A 里踩过的坑）。

## 后果

沙箱确实跑起来了：事件提交、`task_id` 拿到、状态机记录、
报告 `payload` 也确实挂在了 `SandboxOutcome.report` 上
（`sandbox_connector.py:414`）。

**但拿到报告之后，没有任何东西去解读它**：
没有 `clean` / `suspicious` / `malicious` 判定被产出，
没有任何样本进入家族聚类，`variant_cluster.stats` 永远是全零。

所以整改方案 §十.2 修的那 6 条聚类缺陷（空集合相似度 1.0、
畸形 IOC 占位 token、簇划分顺序依赖、`sigs[:20]` 静默截断、
`round(sim,3)` 隐藏阈值差异、cluster_id 内容寻址）
**规则全都正确，但规则从未被执行**。

同理，§十三「零日与聚类」这条验收维度：
「故障不等于 clean，无有效特征不等于高相似度」这些**性质**都成立，
但成立的前提是分析真的跑过 —— 而它在生产里没跑。

## 为什么用 strict xfail 而不是直接断言

这个缺口不是「修完了」，是「还没修」：
接线涉及若干尚未决定的设计问题（见下），不该由一次扫描顺手替用户拍板。
但它也绝不能只躺在报告里 —— 必须持续出现在 CI 视野中。

`@pytest.mark.xfail(strict=True, raises=AssertionError)` 正好满足：

* 现在：标记为**预期失败**，测试计数里可见；
* 将来有人接线让它真的通过 → **XPASS 且 strict → 整条转红**，
  强制把标记摘掉、把报告结论改掉。

于是这个缺口**无法被静默遗忘**：修好了必须回来改文档，
忘了修就一直挂在回归输出里。

## 接线的设计问题（本文件不替用户决定）

1. **内存无上界**：`variant_cluster._samples` 只增不减，
   每个样本的 `SampleFeatures` 常驻。单例是进程级的。
2. **全量重建**：`add_sample` 每次都调 `_reindex()` →
   `_components()` 遍历全部样本，N 个样本累计 O(N²)。
3. **何时喂**：`_finish()` 是唯一收敛点，但该路径上的
   `SandboxOutcome` **没有** `sample_hash`（`sandbox_connector.py:413-415`），
   而 `add_sample` 靠它做键。
4. **家族标注策略**：谁调用 `label_cluster`、什么时候标。

这些都需要先定，再接线。**不要为了让它变绿就随手 `_finish` 里加一行。**
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

BACKEND = Path(__file__).resolve().parents[1]
ZERODAY = BACKEND / "zeroday_detect"

#: (目标模块文件, 必须被生产代码调用的方法名)
ANALYSIS_CHAIN = [
    ("behavior_analyzer.py", "analyze"),
    ("variant_cluster.py", "add_sample"),
    ("variant_cluster.py", "find_similar"),
]


def _prod_callers(target_file: str, method: str) -> set[str]:
    """在**生产代码**里找出对该方法的调用（排除 tests/ 与零日包自身）。

    ## 为什么必须导入感知，不能只匹配方法名

    第一版按 `Call(func.attr == "analyze")` 匹配，结果把
    `anomaly_detector.analyze()`、`IntelEnricher.analyze()`、
    `_AnomalyStub(0.42).analyze()` 全算成了 `behavior_analyzer.analyze()` 的调用方 ——
    strict xfail 立刻 XPASS 转红。

    **按方法名匹配会把同名的其它对象一并算进来。**
    所以这里先做导入绑定分析：只有真正从 `zeroday_detect.*` 导入了
    零日单例/类、并在其上调用该方法的，才算数。
    """
    callers: set[str] = set()
    for py in BACKEND.rglob("*.py"):
        rel = py.relative_to(BACKEND).as_posix()
        if rel.startswith("tests") or rel.startswith("zeroday_detect"):
            continue
        try:
            tree = ast.parse(py.read_text(encoding="utf-8-sig"))
        except SyntaxError:
            continue

        # 本模块里由零日导入绑定出来的名字
        bound: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                if not (node.module or "").startswith("zeroday_detect"):
                    continue
                # from zeroday_detect.behavior_analyzer import behavior_analyzer
                # from zeroday_detect.variant_cluster import variant_cluster, VariantCluster
                for alias in node.names:
                    bound.add(alias.asname or alias.name)
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.startswith("zeroday_detect."):
                        bound.add(alias.asname or alias.name.split(".")[-1])
        if not bound:
            continue

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            f = node.func
            # 形如 behavior_analyzer.analyze(...)
            if isinstance(f, ast.Attribute) and f.attr == method \
                    and isinstance(f.value, ast.Name) and f.value.id in bound:
                callers.add(rel)
            # 形如 VariantCluster().add_sample(...) 的实例方法
            elif isinstance(f, ast.Attribute) and f.attr == method \
                    and isinstance(f.value, ast.Call) and isinstance(f.value.func, ast.Name) \
                    and f.value.func.id in bound:
                callers.add(rel)
    return callers


@pytest.mark.parametrize("target_file,method", ANALYSIS_CHAIN,
                         ids=[f"{f}:{m}" for f, m in ANALYSIS_CHAIN])
@pytest.mark.xfail(strict=True, raises=AssertionError, reason="已知缺口：零日分析链后半段未接入生产，见模块 docstring")
def test_zero_day_analysis_chain_has_a_production_caller(target_file, method):
    """零日链的每个环节都必须有生产调用方。

    接线时务必一并处理本文件 docstring 末尾列出的 4 个设计问题，
    并把本标记摘掉 —— strict 会在真的通过时转红提醒你。
    """
    callers = _prod_callers(target_file, method)
    assert callers, (
        f"zeroday_detect/{target_file}::{method}() 在生产代码里零调用方 —— "
        "沙箱报告拿到后没有任何东西解读它"
    )


@pytest.mark.xfail(strict=True, raises=AssertionError, reason="已知缺口：变种聚类 stats 零消费方")
def test_variant_cluster_stats_is_read_somewhere():
    """聚类的可观测出口必须有人读，否则 `stats` 永远是全零。"""
    callers = _prod_callers("variant_cluster.py", "stats")
    assert callers, "variant_cluster.stats 没有生产读取方"


def test_the_gap_is_still_real_so_this_file_is_not_vacuous():
    """前提守卫：本文件在缺口被修好之前必须真的扫到「零调用方」。

    如果哪天接线完成了而标记没摘，这条会提醒 —— 防止本文件
    在「什么都没查」的状态下长期全绿。
    """
    analyze_callers = _prod_callers("behavior_analyzer.py", "analyze")
    add_callers = _prod_callers("variant_cluster.py", "add_sample")
    if analyze_callers or add_callers:
        pytest.skip(
            "零日链已出现生产调用方 "
            f"(analyze={sorted(analyze_callers)}, add_sample={sorted(add_callers)}) —— "
            "请把 strict xfail 标记摘掉并更新验收报告 §十三 对应结论"
        )
    assert not analyze_callers and not add_callers, \
        "前提：缺口仍在，strict xfail 才成立"
