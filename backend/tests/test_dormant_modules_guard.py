"""
休眠模块守卫：backend 里「生产代码从未导入」的模块必须逐个登记。

## 为什么要有这个文件

2026-10-18 本轮查证发现：`zeroday_detect/behavior_analyzer.py` 与
`zeroday_detect/variant_cluster.py` 的**全部对外接口**在生产代码里
零调用方 —— 沙箱跑完了，报告拿到了，却没有任何东西去解读它。
详见 `test_zeroday_wiring_gap.py` 与验收报告 §7.1.4。

那个发现是手工 grep 出来的。本文件把同一件事**自动化**：
以后新增一个整块休眠的模块，会在这里被挡住。

## 三类登记，缺一不可

| 类别 | 含义 | 处理 |
|---|---|---|
| `entrypoint` | 进程入口（uvicorn / worker / `__main__`） | 天然零导入，正常 |
| `script` | 迁移 / 训练 / 一次性运维脚本 | 天然零导入，正常 |
| `dormant` | **整个文件**在生产零导入：文档声称的能力，生产从不调用 | 缺口，见 §7.1.4 的处理方式 |
| `partial` | 文件活着，但**对外能力**在生产零调用（活的部分是别的用途） | 缺口，且**不能整文件删** |
| `alias` | 零导入的**再导出门面**，实现已接线 | 不是缺口；**登记错了会把已接线的能力说成缺口** |

`dormant` / `partial` 一律配 strict xfail：现在标记为预期失败；
哪天有人接线让它真通过 → XPASS(strict) 转红，强制摘标记 + 改报告。
`alias` **不配** xfail —— 给别名配 xfail 就是个必炸的假信号。

## 为什么单列 `partial`（本文件写第一版时踩的坑）

第一版把 `zeroday_detect/variant_cluster.py` 登记成 `dormant`，
守卫生效把它判成「登记已过期」——因为 `learn_loop/models_cluster.py:22`
确实生产导入了它。查下去发现：

- 活的是纯函数 `jaccard_similarity`，被 `learn_loop` 用来聚类**模型**；
- 死的是 `VariantCluster` 这个聚类**恶意样本**的能力，生产零引用；
- `learn_loop` 本身是活的（`routers/ops.py:921`、`scheduler.py:469,580`）。

所以那不是「登记过期」，是**登记粒度错了**：模块级活着 ≠ 能力级活着。

两个后果，都不小：

1. 写成 `dormant` 会让人以为整文件可删 —— 删掉 `jaccard_similarity`
   就打断了 `learn_loop` 的生产链路。
2. 模块级的 strict xfail 是**假信号**：哪天有人为了任何理由 import 了这个模块
   （哪怕只为那个活着的纯函数），xfail 就 XPASS 转绿，等于宣布「零日聚类已接线」。

于是能力级判据单独一遍扫描，见 `PARTIALLY_DORMANT`。

5. **零导入 ≠ 没接线** —— `red_agent.py` 是个 8 行的再导出门面，
   `from self_play.red_agent import RedAgent`，docstring 自述「实现位于
   `self_play.red_agent`」。RED Agent 能力**是活的**（`self_play.red_agent`
   有生产导入方），这个文件只是没人用的对外入口。
   登记成 `dormant` 会让报告把一条**已接线的能力**说成缺口，
   而且给它配的 strict xfail 是个必炸的假信号 ——
   有人 import 一下这个别名就会 XPASS，等于宣布「RED Agent 未接线」。

   所以有 `alias` 这一类。**判据**：文件极小 + 只做再导出 + 真正的实现
   在别处且已接线。三条同时成立才算 alias。

## 扫描口径（本轮在这个扫描器上翻车五次，全部记在这里）

1. **不能只匹配方法名** —— `analyze()` 会命中 `anomaly_detector.analyze()`。
2. **不能排除被扫描对象自身** —— 包内自调用也是接线。
3. **必须处理 `from . import (a, b)`** —— 这时 `node.module` 是 `None`，
   被导入的名字本身就是子模块。第一版漏了这一支，
   把 `phishing_guard` 的 7 个检测器全误报成「零生产导入」
   （它们其实由 `routers/phishing.py` 通过 `phishing_guard` 门面调用）。
4. **模块级活着 ≠ 能力级活着** —— 见上面「为什么单列 `partial`」。
5. **零导入 ≠ 没接线** —— 别名/门面，见上面第 5 条。

第 3 条是本文件的血泪：扫描结果为空时，
**分不清是真没找到，还是根本没匹配上**。
所以本文件有一组「扫描器自检」用例（第 4 条），
用已知答案验证扫描精度，而不是靠结果为空来下结论。
能力级扫描同样配了一组自检 —— 它要区分
「`VariantCluster` 无人引用」和「`jaccard_similarity` 有人引用」，
只报前者为 0 的扫描器，可能两个都报 0。

## 一个已知的口径边界（未修，如实登记）

「零导入」不等于「不可达」。若模块 A 零导入、而模块 B 只被 A 导入，
B 在这套扫描里不算休眠（它有导入方），但 B 同样到不了生产。

本轮 33 个零导入模块里**没有出现这种链**（休眠模块之间互不导入，
已逐个核过导入图），所以结论不受影响。
但这不是扫描器保证的，是这一批文件碰巧的性质 —— 换一批就需要改成可达性分析。
"""
from __future__ import annotations

import ast
import functools
from pathlib import Path

import pytest

BACKEND = Path(__file__).resolve().parents[1]

#: 不参与「休眠」判定的目录：测试、评估脚本、一次性工具
SKIP_DIRS = ("tests", "eval_datasets", "tools")

#: rel_path -> (类别, 理由)
CLASSIFICATIONS: dict[str, tuple[str, str]] = {}


def _add(path: str, category: str, reason: str) -> None:
    CLASSIFICATIONS[path] = (category, reason)


# ── 入口点：天然无人导入 ──
for _p, _r in [
    ("app.py", "uvicorn ASGI 入口，由进程加载器引入，不被任何模块 import"),
    ("self_play/__main__.py", "python -m self_play 入口"),
    ("temporal/worker.py", "Temporal worker 独立进程入口"),
    # 2026-10-23: alembic 迁移 —— 由 alembic 命令/启动迁移加载, 天然零生产导入
    ("migrations/env.py", "alembic 迁移环境脚本, 由 alembic 命令加载"),
    ("migrations/versions/20261023_0001_baseline.py",
     "baseline 迁移脚本, 由 alembic upgrade 加载"),
    # 2026-10-27: ip2region 官方绑定 (vendored, Apache-2.0, 见 ip2region/LICENSE)
    # —— 由 geo_ip._get_searcher() 在函数体内动态导入, 静态扫描视为零导入;
    #    第三方检索器, 不纳入本仓库的覆盖度量。
    ("ip2region/searcher.py",
     "ip2region 官方 xdb 检索器 (vendored 第三方), 由 geo_ip 动态导入"),
]:
    _add(_p, "entrypoint", _r)

# ── 一次性脚本 / 迁移 / 训练 ──
for _p, _r in [
    ("migrate_pgvector_to_qdrant.py", "一次性迁移脚本"),
    ("migrate_qdrant_hybrid.py", "一次性迁移脚本"),
    ("fix_embeddings.py", "一次性修复脚本"),
    ("demo_seed_b.py", "演示数据播种脚本"),
    ("sigma_engine/dry_run_import.py", "Sigma 规则试导入工具"),
    ("sigma_engine/tools/fetch_sigma_p0.py", "Sigma 规则抓取工具"),
    ("sigma_engine/tools/make_sample_events.py", "Sigma 样例事件生成工具"),
    ("sigma_engine/tools/promote_to_shadow.py", "Sigma 规则影子模式提升工具"),
]:
    _add(_p, "script", _r)

# ── 休眠能力：文档声称有、生产从不调用 ──
DORMANT_CAPABILITIES = [
    ("zeroday_detect/behavior_analyzer.py",
     "沙箱报告行为分析：拿到 CAPE report 后没人调用它产出 clean/suspicious/malicious"),
    ("zeroday_detect/llm_behavior.py",
     "LLM 行为解读：前置 behavior_analyzer 已休眠，它自然更不会被调用"),
    # 2026-10-21: stix_taxii 已由 /api/intel/feeds/{id}/poll 调用，
    # 并从 dormant 清单移除；ioc_ingest 负责落库。
    ("threat_intel/intel_enricher.py", "情报富化：依赖已休眠的 stix_taxii"),
    ("threat_intel/llm_context.py", "LLM 情报上下文：依赖已休眠的 intel_enricher"),
    ("session_reconstruct/timeline.py", "会话时间线重建"),
    ("session_reconstruct/http_linker.py", "HTTP 会话串联"),
    ("session_reconstruct/tcp_reassembler.py", "TCP 流重组"),
    ("response_engine/containment/host_adapter.py", "主机处置适配器"),
    ("response_engine/containment/directory_adapter.py", "域账号处置适配器"),
    ("response_engine/containment/mail_adapter.py", "邮箱处置适配器"),
    ("traffic_baseline/traffic_profiler.py", "流量画像基线"),
    ("traffic_baseline/peer_group.py", "对等组基线"),
    ("ids_connector/suricata_connector.py", "Suricata IDS 接入"),
    ("encrypted_traffic/mitm_proxy.py", "加密流量 MITM"),
    ("edr_fusion/llm_correlation.py", "EDR LLM 跨源关联"),
    ("agents/audit_single.py", "单事件审计 Agent"),
    ("self_play/store.py", "SelfPlay 状态存储"),
]
for _p, _r in DORMANT_CAPABILITIES:
    _add(_p, "dormant", _r)

# ── 部分休眠：文件活着，对外能力死 ──
#: rel_path -> {"reason", "live": 生产确有引用方的符号, "dead": 生产零引用的能力符号}
#:
#: 这类文件**不能整文件删** —— 活着的符号在生产链路里。
PARTIALLY_DORMANT: dict[str, dict[str, object]] = {
    "zeroday_detect/variant_cluster.py": {
        "reason": (
            "文件被 learn_loop 生产导入，但只为纯函数 jaccard_similarity；"
            "零日变种聚类能力 VariantCluster 本体生产零引用，stats 恒为全零"
        ),
        "live": ["jaccard_similarity"],
        "dead": ["VariantCluster"],
    },
}
for _p in PARTIALLY_DORMANT:
    _add(_p, "partial", str(PARTIALLY_DORMANT[_p]["reason"]))

# ── 别名 / 门面：零导入，但能力本身是活的 ──
#: 这些文件不是「没接线的能力」，它们是**刻意的再导出门面** ——
#: 真正的实现在别处且已被生产调用。把它们登记成能力缺口是错的。
ALIASES: dict[str, str] = {
    "red_agent.py": (
        "8 行的再导出门面，`from self_play.red_agent import RedAgent`；"
        "docstring 自述「实现位于 self_play.red_agent」。"
        "**RED Agent 能力是活的**（self_play.red_agent 有生产导入方），"
        "这个文件只是没人用的对外入口 —— "
        "登记成 dormant 会让报告把一条已接线的能力说成缺口"
    ),
}
for _p, _r in ALIASES.items():
    _add(_p, "alias", _r)


def _module_name(rel: str) -> str:
    p = rel[:-3] if rel.endswith(".py") else rel
    if p.endswith("/__init__"):
        p = p[: -len("/__init__")]
    return p.replace("/", ".")


def _all_modules() -> dict[str, str]:
    out: dict[str, str] = {}
    for py in BACKEND.rglob("*.py"):
        rel = py.relative_to(BACKEND).as_posix()
        if rel.startswith(SKIP_DIRS) or "__init__" in rel:
            continue
        out[_module_name(rel)] = rel
    return out


@functools.lru_cache(maxsize=None)
def _importers() -> dict[str, frozenset[str]]:
    """每个模块被哪些**生产**文件导入。三种 import 写法都要认。

    带缓存：这条扫描是 O(文件数 × 模块数)，而 strict xfail 有二十多条，
    每条各扫一次会让这一个文件吃掉二十多秒（全量回归的 20%）。
    """
    mods = _all_modules()
    importers: dict[str, set[str]] = {m: set() for m in mods}
    for py in BACKEND.rglob("*.py"):
        rel = py.relative_to(BACKEND).as_posix()
        if rel.startswith(SKIP_DIRS):
            continue
        try:
            tree = ast.parse(py.read_text(encoding="utf-8-sig"))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            names: list[str] = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    names = [node.module]
                    if node.level:
                        pkg = _module_name(rel).rsplit(".", 1)[0]
                        names = [f"{pkg}.{node.module}"]
                elif node.level:
                    # from . import (a, b)：module 为 None，被导入的名字即子模块
                    pkg = _module_name(rel)
                    names = [f"{pkg}.{a.name}" for a in node.names]
            for n in names:
                for m in mods:
                    if n == m or n.startswith(m + "."):
                        importers[m].add(rel)
    return {m: frozenset(v) for m, v in importers.items()}


@pytest.fixture(scope="module")
def dormant() -> set[str]:
    imp = _importers()
    return {rel for m, rel in _all_modules().items() if not imp[m]}


# ── 能力级扫描：符号在生产代码里的引用方 ──

def _identifiers(tree: ast.AST) -> set[str]:
    """收集一个模块里出现的全部标识符。

    只认 AST 节点，不做文本匹配 —— 文本匹配会把 docstring 里
    「本文件实现 XXX」这类说明当成引用（`learn_loop/models_cluster.py:5`
    的模块 docstring 就写了 `zeroday_detect.variant_cluster.jaccard_similarity`）。
    """
    out: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            out.add(node.id)
        elif isinstance(node, ast.Attribute):
            out.add(node.attr)
        elif isinstance(node, ast.alias):
            out.add((node.asname or node.name).rsplit(".", 1)[-1])
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            out.add(node.name)
        elif isinstance(node, ast.arg):
            out.add(node.arg)
    return out


def _symbol_referents(symbol: str, owner_rel: str) -> set[str]:
    """`symbol` 在生产代码里被哪些**非定义文件**引用。

    必须排除 `owner_rel`：模块内部的 `xxx = Symbol()` 是自引用，
    不构成任何生产接线。
    """
    found: set[str] = set()
    for py in BACKEND.rglob("*.py"):
        rel = py.relative_to(BACKEND).as_posix()
        if rel.startswith(SKIP_DIRS) or rel == owner_rel:
            continue
        try:
            tree = ast.parse(py.read_text(encoding="utf-8-sig"))
        except SyntaxError:
            continue
        if symbol in _identifiers(tree):
            found.add(rel)
    return found


# ── 扫描器自检：精度不对，下面所有结论都不可信 ──

def test_scanner_detects_a_known_imported_module(dormant):
    """已知答案自检：`phishing_guard.email_detector` 有生产导入方。

    第一版漏了 `from . import (...)`，把 7 个检测器全误报成休眠。
    """
    assert "phishing_guard/email_detector.py" not in dormant, \
        "扫描器没认出 `from . import (...)` 这类相对子模块导入 —— 精度已退化"


def test_scanner_detects_a_known_dormant_module(dormant):
    """反向自检：`zeroday_detect.behavior_analyzer` 确实零生产导入。"""
    assert "zeroday_detect/behavior_analyzer.py" in dormant, \
        "扫描器连已知的休眠模块都没扫出来 —— 结果不可信"


# ── 主断言 ──

def test_every_dormant_module_is_explicitly_classified(dormant):
    """任何休眠模块都必须登记类别与理由。

    新增一个整块休眠的模块会在这里被挡住，逼人表态它是
    「入口/脚本（正常）」还是「能力缺口」。
    """
    unclassified = sorted(dormant - set(CLASSIFICATIONS))
    assert not unclassified, (
        f"以下模块在生产代码里零导入但未登记：{unclassified}\n"
        "请在 CLASSIFICATIONS 里登记为 entrypoint / script / dormant 并写明理由。"
    )


def test_every_classification_states_a_reason():
    """登记必须写理由，空串等于静默白名单。"""
    for path, (cat, reason) in CLASSIFICATIONS.items():
        assert cat in ("entrypoint", "script", "dormant", "partial", "alias"), \
            f"{path}: 未知类别 {cat}"
        assert reason.strip(), f"{path}: 没写明理由"


def test_classifications_have_no_stale_entries(dormant):
    """反向检查：登记为 `dormant` 的模块若已有人导入，必须摘掉登记。

    注意 `partial` **不在**这个检查范围内 —— 部分休眠的模块本来就有
    导入方（`variant_cluster.py` 被 `learn_loop` 导入），
    它由能力级那组用例守。
    """
    whole_file_dormant = {p for p, (c, _) in CLASSIFICATIONS.items() if c == "dormant"}
    stale = sorted(whole_file_dormant - dormant)
    assert not stale, (
        f"{stale} 现在已有生产导入方，整文件休眠的登记已过期 —— 请重新归类，"
        "别让失效说明留在文件里误导后人"
    )


@pytest.mark.parametrize("rel_path", [p for p, (c, _) in CLASSIFICATIONS.items()
                                      if c == "dormant"])
@pytest.mark.xfail(strict=True, raises=AssertionError, reason="已知缺口：文档声称的能力，生产从不调用；见验收报告 §7.1.4")
def test_dormant_capability_is_reachable_from_production(rel_path):
    """休眠能力必须能被生产代码到达。

    接线时请一并处理 `test_zeroday_wiring_gap.py` docstring 里列出的
    设计问题（内存无上界 / O(N²) 重建 / sample_hash 缺失 / 标注策略），
    然后摘掉本文件的 strict xfail —— strict 会在真的通过时转红提醒你。
    """
    imp = _importers()
    mod = _module_name(rel_path)
    assert imp[mod], f"{rel_path} 仍无生产导入方"


# ── 能力级自检：模块活着不代表能力活着 ──

def test_capability_scanner_finds_a_symbol_that_is_live():
    """阳性对照：`jaccard_similarity` 确实被 `learn_loop` 生产引用。

    没有这一条，「所有能力都零引用」和「扫描器什么都没匹配上」
    长得一模一样。
    """
    refs = _symbol_referents("jaccard_similarity", "zeroday_detect/variant_cluster.py")
    assert "learn_loop/models_cluster.py" in refs, (
        f"能力级扫描器没找到已知存在的生产引用，实际找到：{sorted(refs)}"
    )


def test_capability_scanner_reports_a_symbol_that_is_dead():
    """阴性对照：`VariantCluster` 生产零引用，且扫描器认得出这个 0。

    这一条同时钉住「排除定义文件自身」：
    `variant_cluster.py:438` 有 `variant_cluster = VariantCluster()`，
    若没排除自引用，这里会假绿。
    """
    refs = _symbol_referents("VariantCluster", "zeroday_detect/variant_cluster.py")
    assert not refs, (
        "zeroday_detect/variant_cluster.py：`VariantCluster` 已有生产引用方 "
        f"{sorted(refs)}；若这是刚接线的，请摘掉 partial 登记并改报告结论"
    )


@pytest.mark.parametrize("rel_path", sorted(PARTIALLY_DORMANT))
@pytest.mark.xfail(strict=True, raises=AssertionError, reason="已知缺口：模块活着，但对外能力生产零调用；见验收报告 §7.1.4")
def test_partially_dormant_capability_is_reachable_from_production(rel_path):
    """部分休眠文件里，死掉的能力必须能被生产代码到达。

    **接线时不要删整个文件** —— 同一文件里的活符号在生产链路中
    （`variant_cluster.py` 的 `jaccard_similarity` 被 `learn_loop` 用着）。

    接线时一并处理 `test_zeroday_wiring_gap.py` docstring 里列出的
    设计问题（内存无上界 / O(N²) 重建 / sample_hash 缺失 / 标注策略），
    然后摘掉本文件的 partial 登记与 strict xfail。
    """
    spec = PARTIALLY_DORMANT[rel_path]
    dead = list(spec["dead"])  # type: ignore[arg-type]
    assert dead, f"{rel_path} 没登记任何死能力，这条用例没有意义"
    for symbol in dead:
        refs = _symbol_referents(symbol, rel_path)
        assert refs, f"{rel_path} 的能力 {symbol} 仍无生产引用方"
