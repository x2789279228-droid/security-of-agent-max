"""
指标骨干的**接线守卫**：`metrics.py` 与 `core_metrics.py` 的每个写入器
都必须在生产代码里被调用。

## 背景（一次真实的踩坑）

本轮修过一个缺陷：`metrics.inc_intel_ioc` 与 `metrics.inc_capture_packet`
都声明了计数器、都在 `/metrics` 上暴露，但**全仓零调用点**。后果不是
「少个数字」，而是

    soc_intel_ioc_total ≡ 0    恒成立

而 `/api/capabilities/status` 正是用它给 `threat_intel.count` 赋值 →
面板恒显示「已启用、0 条」。**0 与「没事件」完全同形**：
采集链路整个断了，看板读数却与一切正常无法区分。
这类缺陷不报错、不让测试变红，只会在出事时让人盯着一块永远不动的数字。

## 扫描口径上的一个坑（本文件第一版就踩了）

第一版扫描时把「正在被扫描的那个文件」整体排除，理由是避免自引用计数。
结果 `note_dlq_open`、`record_unexpected_drop`、
`set_eventbus_subscribers` 全被报成「零调用」——而它们分别由
`record_dlq_persisted`、`set_lifecycle_leftover`、
`metrics_endpoint` 在**同一个文件内**调用。

**排除被扫描文件 = 连它自己的内部调用点一起漏掉。**
这类「拉取时设置」的 gauge 尤其如此（`set_eventbus_subscribers` 与
`refresh_db_pool_gauges` 都在 `/metrics` 处理器里调用，是设计如此）。

因此本文件的口径是：**内部调用也算接线**，只统计「调用次数为 0」。

## 维护方式

若某个写入器确实无人调用（真的写错了，或已废弃待删），加进
`UNWIRED` 并写明理由与后续动作。
**不要为了让扫描通过而删断言** —— 新增一个没人调用的写入器
正是本文件要防的事故。
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

BACKEND = Path(__file__).resolve().parents[1]
MODULES = ("metrics.py", "core_metrics.py")

#: 写入器命名的前缀 —— 这些函数会真的写指标
WRITER_PREFIXES = ("inc_", "note_", "record_", "set_")

#: 确实无人调用的写入器（必须写明理由与后续动作；当前应为空）
UNWIRED: dict[str, str] = {}


def _public_writers(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8-sig"))
    return sorted(
        n.name for n in tree.body
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
        and not n.name.startswith("_")
        and n.name.startswith(WRITER_PREFIXES)
    )


def _call_sites(names: set[str], *, include_tests: bool) -> dict[str, set[str]]:
    """每个名字在生产代码里的调用位置（**包含定义文件自身**）。

    ``include_tests=False`` 时排除 ``tests/``。
    """
    found: dict[str, set[str]] = {n: set() for n in names}
    for py in BACKEND.rglob("*.py"):
        rel = py.relative_to(BACKEND).as_posix()
        if not include_tests and rel.startswith("tests"):
            continue
        try:
            tree = ast.parse(py.read_text(encoding="utf-8-sig"))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            ident = None
            if isinstance(node, ast.Call):
                ident = getattr(node.func, "id", None) or getattr(node.func, "attr", None)
            elif isinstance(node, ast.Name):
                ident = node.id
            elif isinstance(node, ast.Attribute):
                ident = node.attr
            if ident in found:
                found[ident].add(rel)
    return found


@pytest.fixture(scope="module")
def all_writers() -> dict[str, str]:
    """{函数名: 定义所在模块}"""
    out: dict[str, str] = {}
    for mod in MODULES:
        for name in _public_writers(BACKEND / mod):
            out[name] = mod
    return out


def test_scan_actually_found_writers(all_writers):
    """前提守卫：扫描器本身要真的扫到东西，否则后面的断言全是空跑。"""
    assert len(all_writers) >= 30, (
        f"只扫到 {len(all_writers)} 个写入器 —— "
        "两个指标模块的结构可能变了，本文件的扫描口径需要同步更新"
    )
    assert "inc_intel_ioc" in all_writers, "metrics.inc_intel_ioc 应在扫描范围内"
    assert "record_detection" in all_writers, "core_metrics.record_detection 应在扫描范围内"


def test_every_metric_writer_is_called_in_production(all_writers):
    """核心：任何写指标的助手都必须在生产代码里被调用过。

    未接线的写入器 = 它对应的计数器/仪表恒为初值 = 面板上的死数字。
    """
    sites = _call_sites(set(all_writers), include_tests=False)
    unwired = sorted(n for n in all_writers if not sites[n] and n not in UNWIRED)
    assert not unwired, (
        f"以下指标写入器在生产代码里零调用点：{unwired} —— "
        "它们对应的计数器将恒为初值，而初值与「没有事件」读数同形。"
        "请接到真实路径上，或在 UNWIRED 里写明理由与后续动作。"
    )


def test_internal_callers_count_as_wired(all_writers):
    """反向守卫：防止把扫描口径退回到「排除定义文件」。

    那会把 `set_eventbus_subscribers` / `refresh_db_pool_gauges` 这类
    **拉取时设置**的 gauge 误报成未接线 —— 它们本来就只在
    `/metrics` 处理器（同文件）里调用。
    """
    sites = _call_sites({"set_eventbus_subscribers", "refresh_db_pool_gauges",
                         "note_dlq_open", "record_unexpected_drop"},
                        include_tests=False)
    for name, paths in sites.items():
        assert paths, (
            f"{name} 在生产代码里没有调用点（连定义文件自身也没有）"
        )


def test_unwired_allowlist_has_no_stale_entries(all_writers):
    """反向检查：UNWIRED 不得有过期登记。"""
    vanished = sorted(set(UNWIRED) - set(all_writers))
    assert not vanished, (
        f"UNWIRED 登记了 {vanished}，但两个模块里已无此函数 —— 请删除过期登记"
    )
    wired = sorted(n for n in UNWIRED if n in all_writers
                   and _call_sites({n}, include_tests=False)[n])
    assert not wired, (
        f"{wired} 现在已经有生产调用方了，请从 UNWIRED 移除并重新归类"
    )


def test_every_unwired_entry_states_a_reason_and_action():
    """登记必须带理由，空串等于没登记 —— 否则退化成一张静默白名单。"""
    for name, reason in UNWIRED.items():
        assert reason.strip(), f"UNWIRED[{name}] 没写明理由与后续动作"


def test_the_two_accidentally_unwired_metrics_are_now_wired():
    """定向回归：本轮修掉的两个指标必须确实接上了线。

    修前 `inc_intel_ioc` / `inc_capture_packet` 全仓零调用点，
    导致 `/api/capabilities/status` 的 threat_intel.count 恒为 0。
    """
    sites = _call_sites({"inc_intel_ioc", "inc_capture_packet"},
                        include_tests=False)
    assert sites["inc_intel_ioc"], \
        "inc_intel_ioc 没有生产调用点 —— capabilities.status 的 threat_intel.count 会恒为 0"
    assert sites["inc_capture_packet"], \
        "inc_capture_packet 没有生产调用点 —— soc_capture_packets_total 恒为 0"


# ═══════════════════════════════════════════
# §7.1.14：本文件原先管不到的一类 —— 「声明了指标，但压根没有写入器」
# ═══════════════════════════════════════════

_OPS = {"inc", "dec", "set", "observe"}


def _declared_metrics() -> dict[str, str]:
    """{指标变量名: 指标名}，只认 **prometheus_client** 的 Counter/Histogram/Gauge。

    ⚠ `collections.Counter` 与 `prometheus_client.Counter` **同名但完全不是一回事**。
    `learn_loop/models_cluster.py:118-119` 的
    `types = Counter(<genexpr>)` 用的是前者。
    v1 的扫描器没区分，抽出了 2 个假「指标」，并让 `\.types\b` 之类的短名
    在全仓匹配出一堆无关命中，把结论带偏。
    """
    out: dict[str, str] = {}
    for mod in ("metrics.py", "core_metrics.py", "self_play/metrics.py",
                "learn_loop/models_cluster.py"):
        p = BACKEND / mod
        if not p.exists():
            continue
        src = p.read_text(encoding="utf-8-sig")
        if "prometheus_client" not in src:
            continue                      # 该文件根本没在用 Prometheus
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Assign)
                    and isinstance(node.value, ast.Call)
                    and isinstance(node.value.func, ast.Name)
                    and node.value.func.id in ("Counter", "Histogram", "Gauge")
                    and isinstance(node.targets[0], ast.Name)):
                continue
            name = next((a.value for a in node.value.args
                         if isinstance(a, ast.Constant) and isinstance(a.value, str)), None)
            out[node.targets[0].id] = name or node.targets[0].id
    return out


def _touched_vars(tree) -> set[str]:
    """在 AST 里找出被 `VAR.inc()` / `VAR.labels(...).inc()` 操作的变量名。

    两种形态都要覆盖（漏一种就把活的判成死的）：
        VAR.inc()
        VAR.labels(...).inc()
    """
    found: set[str] = set()
    for n in ast.walk(tree):
        if not (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                and n.func.attr in _OPS):
            continue
        base = n.func.value
        if isinstance(base, ast.Name):
            found.add(base.id)
        elif (isinstance(base, ast.Call) and isinstance(base.func, ast.Attribute)
              and base.func.attr == "labels" and isinstance(base.func.value, ast.Name)):
            found.add(base.func.value.id)
    return found


def test_metric_declaration_extraction_finds_the_known_metrics():
    """前提：声明提取口径本身可复现。"""
    decl = _declared_metrics()
    assert len(decl) >= 60, f"只扫到 {len(decl)} 个指标声明 —— 口径退化了"
    for var in ("HTTP_REQUESTS", "DETECTION_OUTCOMES"):
        assert var in decl, f"{var} 不在扫描范围内"
    assert "types" not in decl, (
        "`types` 是 collections.Counter 不是 Prometheus 指标 —— "
        "名字解析口径退化了（须按 import 来源区分同名类）"
    )


def test_every_declared_metric_has_at_least_one_write_path():
    """**声明了就必须有写入路径** —— 哪怕那个写入方只在休眠模块里。

    ## 本文件原先管不到这一类

    `_public_writers` 只收 `tree.body` 里以 `inc_/note_/record_/set_` 开头的
    **模块级函数**。所以下面两种情况它都看不见：

    * 指标被声明了，但**压根没有写入器函数** → 该指标永远只出现在
      `/metrics` 的 HELP 行里；
    * 写入器是**类方法**（如 `MetricsMiddleware.__call__`）——
      它由 `app.add_middleware(...)` 挂载后被框架调用，
      代码里没有任何直接调用点。

    ## 为什么这条必须存在

    实测当前 62 个指标里这一类是 **0 个**（唯一的失效指标
    `soc_intel_ioc_total` 有写入器、只是写入方在休眠模块，
    那是 §7.1.5/§7.1.6 管的另一件事）。
    **正因为现在是 0，才需要守卫** —— 否则下一个新加的指标
    可以毫无阻力地带着一个永远为 0 的读数进仓库。

    ## 判据

    只要求「有写入点」，不要求「写入点在活模块」——
    后者会把休眠模块的合法写入也算成无效，且会与 §7.1.5 的休眠清单重复判罚。
    """
    decl = _declared_metrics()
    dead = []
    for var in decl:
        found = False
        for py in BACKEND.rglob("*.py"):
            rel = py.relative_to(BACKEND).as_posix()
            if rel.startswith("tests"):
                continue
            try:
                t = ast.parse(py.read_text(encoding="utf-8-sig"))
            except SyntaxError:
                continue
            if var in _touched_vars(t):
                found = True
                break
        if not found:
            dead.append(f"{decl[var]}({var})")
    assert not dead, (
        f"这些指标声明了却没有任何写入点，永远只出现在 /metrics 的 HELP 行里："
        f"{sorted(dead)} —— 删掉它，或补上写入路径"
    )
