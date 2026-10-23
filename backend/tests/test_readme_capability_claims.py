"""README 能力表列出的模块，必须真的有生产调用方 —— 否则就得标出来（本轮新增）

## 要守住的是什么

README 有一张「NDR / EDR / Threat Intel / 反钓鱼」能力表，
逐个列出各包下的模块（`encrypted_traffic/` 那一行能点出 6 个模块名）。
这张表是仓库的**门面**，读者据此判断系统具备哪些能力。

本轮把该表引用的模块逐个对照 `test_dormant_modules_guard.py` 的休眠清单，
结果是 **7 个被列为已交付能力的模块，生产代码里零导入方**：

| README 行 | 休眠模块 |
|---|---|
| 146 行为异常分析 | `behavior_analyzer` / `llm_behavior` /（`variant_cluster` 聚类能力） |
| 152 加密流量 | `mitm_proxy` |
| 155 流量基线 | `peer_group` |
| 156 EDR 融合 | `llm_correlation` |
| 157 IDS 对接 | `suricata_connector` |
| 158 威胁情报 | `stix_taxii` / `intel_enricher` / `llm_context` |

同一张表还引用了 **32 个确实活着的模块**（`phishing_guard/*`、`capture_engine`、
`flow_aggregator`、`ioc_matcher`、`reputation`、`cross_correlator` …）——
这个对照就是本文件的前提守卫：证明解析器认得出活模块，
否则「全部合规」和「什么都没匹配上」长得一模一样。

## 修法是标注，不是删除

这些模块的**代码是对的**（有测试、规则正确）。
删掉会让将来接线时无从对照，而 §11.2 的处置原则本来就是
「不一致必须被显式声明」而非「不一致必须消失」。

所以 README 里给每个休眠模块加了 `⚠未接线` 标记 + 图例，
本文件守住两件事：

* 休眠模块**必须**带标记（新睡的模块不许悄悄混进能力表）；
* 活着的模块**不许**带标记（接线之后标记要摘掉，否则变成新的谎言）。

## 扫描口径（本轮在这上面翻车一次）

第一版只扫表格**右列**的显式 `pkg/module`，漏掉了**左列**（模块名那一栏）
里的 `zeroday_detect/behavior_analyzer` 和 `ids_connector/suricata_connector`
—— 漏掉的两个恰好是最显眼的两个整模块缺口。
把 7 个数成了 5 个。**左列也要扫。**
"""
from __future__ import annotations

import importlib.util
import re
from pathlib import Path

import pytest

BACKEND = Path(__file__).resolve().parents[1]
REPO = BACKEND.parent
README = REPO / "README.md"
GUARD = Path(__file__).with_name("test_dormant_modules_guard.py")

#: 标记写成什么样。README 用的是 `⚠未接线` / `⚠能力未接线`。
MARKER = "未接线"
#: 标记必须出现在模块名之后的这段距离内（字符数）
MARKER_WINDOW = 30


def _load_dormant_names() -> set[str]:
    """从休眠守卫里取「未接线」清单，避免这里维护第二份。

    `tests/` 没有 `__init__.py`，不能直接 `import test_dormant_modules_guard`，
    所以按文件路径加载 —— 单一事实来源优先于 import 语法上的方便。
    """
    spec = importlib.util.spec_from_file_location("_dormant_guard", GUARD)
    assert spec and spec.loader, f"加载 {GUARD} 失败"
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    names: set[str] = set()
    for rel, _ in getattr(mod, "DORMANT_CAPABILITIES", []):
        names.add(rel[:-3])                      # 去掉 .py
    for rel in getattr(mod, "PARTIALLY_DORMANT", {}):
        names.add(rel[:-3])
    return names


DORMANT_STEMS = _load_dormant_names()

#: 表格行里出现的 `pkg/module` 形式
EXPLICIT = re.compile(r"([a-z_][a-z0-9_]*/[a-z_][a-z0-9_]*)(?:\.py)?")
#: 表格行里出现的包前缀 `pkg/`
PKG = re.compile(r"([a-z_][a-z0-9_]*)/")
#: 表格行里出现的裸模块名。**后面允许带标注**（`(tls_metadata ⚠未接线)`）——
#: 第一版写成 `\(([a-z_][a-z0-9_]*)\)` 要求紧跟 `)`，于是
#: 一旦给模块加上标记，它就对解析器彻底隐形 ——
#: 「过期标记」那条检查因此在结构上永远不可能触发，
#: 它是因为**看不见**才绿的，不是因为检查过。
BARE = re.compile(r"\(([a-z_][a-z0-9_]*)[^)]*\)")


def _capability_rows() -> list[tuple[int, str]]:
    lines = README.read_text(encoding="utf-8").splitlines()
    rows = []
    for i, line in enumerate(lines, 1):
        s = line.strip()
        if not s.startswith("|") or set(s) <= set("|- "):
            continue
        rows.append((i, line))
    return rows


def _module_exists(stem: str) -> bool:
    return (BACKEND / f"{stem}.py").exists()


def _dormant_refs_in(row: str) -> list[str]:
    """这一行引用到的、休眠的模块。"""
    return sorted(s for s in _refs_in(row) if s in DORMANT_STEMS)


def _refs_in(row: str) -> set[str]:
    """这一行引用到的所有模块（活的 + 休眠的）。

    归属规则：行内出现 `pkg/` 时，该行的裸模块名归属那个包 ——
    否则 `peer_group` 这种裸名根本对不上 `traffic_baseline/peer_group`。
    """
    pkgs = set(PKG.findall(row))
    stems = {s for s in EXPLICIT.findall(row) if _module_exists(s)}
    for bare in BARE.findall(row):
        for pk in pkgs:
            cand = f"{pk}/{bare}"
            if _module_exists(cand):
                stems.add(cand)
                break
        else:
            if _module_exists(bare):
                stems.add(bare)
    return stems


def _all_referenced() -> set[str]:
    out: set[str] = set()
    for _ln, row in _capability_rows():
        out |= _refs_in(row)
    return out


def _marked(row: str, stem: str) -> bool:
    """该模块名后面必须紧跟着标记。

    窗口到**下一个 `(` 为止** —— 表里模块名都写成 `名字 (模块)` 或 `(模块)`，
    下一个左括号就是「下一个模块」的起点。不截断的话，
    紧挨在被标记模块之前的那个活模块会被算成也带标记
    （`session_collector` 后面 24 个字符就是 `mitm_proxy` 的标记）。
    """
    tail = stem.rsplit("/", 1)[-1]
    for m in re.finditer(re.escape(tail), row):
        seg = row[m.end(): m.end() + MARKER_WINDOW]
        seg = seg.split("(", 1)[0]
        if MARKER in seg:
            return True
    return False


# ═══════════════════════════════════════════
# 前提守卫：解析器必须认得出活模块
# ═══════════════════════════════════════════

@pytest.mark.parametrize("live_module", [
    "phishing_guard/email_detector",
    "traffic_capture/capture_engine",
    "threat_intel/ioc_matcher",
    "edr_fusion/cross_correlator",
])
def test_parser_finds_live_modules_referenced_by_readme(live_module):
    """已知答案自检：这 4 个模块在能力表里、且确实活着，必须被解析到。

    没有这条，「所有休眠模块都已标注」和「整个解析器什么都没匹配上」
    完全无法区分。

    注意这里查的是**解析后的模块集合**，不是文本里有没有那条路径 ——
    README 把模块写成裸名（`email_detector`），包名在行首左列。
    """
    assert live_module in _all_referenced(), (
        f"{live_module} 不在 README 能力表的解析结果里 —— "
        "表格改了或解析器退化了，请核实"
    )
    assert live_module not in DORMANT_STEMS, (
        f"{live_module} 已被登记为休眠 —— 若它真的接线了，"
        "请同步更新 test_dormant_modules_guard.py 的清单"
    )


# ═══════════════════════════════════════════
# 主断言：双向 —— 休眠的必须标，活的不许标
# ═══════════════════════════════════════════

def test_every_dormant_module_in_readme_is_marked_as_unwired():
    """README 能力表里出现的每个休眠模块，都必须带 `未接线` 标记。"""
    violations = []
    for ln, row in _capability_rows():
        for stem in _dormant_refs_in(row):
            if not _marked(row, stem):
                violations.append(f"README.md:{ln}  {stem} 未标注「{MARKER}」")
    assert not violations, (
        "以下模块在生产里零导入方，却被 README 当作已交付能力列出：\n  "
        + "\n  ".join(violations)
        + "\n请在该模块名后加 `⚠未接线`（删除不合适：代码是对的，"
          "接线后还要用）。详见整改报告 §7.1.7。"
    )


def test_no_stale_unwired_markers_on_live_modules():
    """已经接线的模块不许还挂着 `未接线` 标记。

    标记本身也会变成谎言：模块接上了、标记还在，读者会以为它没跑。

    ⚠ 这里必须遍历**全部**引用（`_refs_in`），不能遍历 `_dormant_refs_in` ——
    后者只返回休眠模块，再判 `stem not in DORMANT_STEMS` 就是恒假，
    整条断言永远不会失败。第一版就是这么写的，
    是靠「给活模块注入过期标记」这个验红动作才发现它根本不转红。
    """
    violations = []
    for ln, row in _capability_rows():
        if MARKER not in row:
            continue
        for stem in _refs_in(row):
            if stem in DORMANT_STEMS:
                continue
            if _marked(row, stem):
                violations.append(f"README.md:{ln}  {stem} 已接线却仍标着「{MARKER}」")
    assert not violations, (
        "接线完成后请摘掉标记：\n  " + "\n  ".join(violations)
    )


def test_readme_legend_exists():
    """标记必须有图例，否则 `⚠未接线` 对读者是无意义的符号。"""
    text = README.read_text(encoding="utf-8")
    assert MARKER in text
    assert "生产代码里没有任何导入方" in text, (
        "README 里缺少「未接线」的解释 —— 读者不知道这个标记代表什么"
    )
    assert "test_dormant_modules_guard.py" in text, (
        "README 的图例没有指向守住接线状态的守卫文件"
    )
