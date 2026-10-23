"""沙箱连接器的「结果回取半边」在生产代码里零调用（本轮新增登记）

## 链路现状

```
POST /api/sandbox/submit                ← routers/edr_intel.py（**有**生产入口）
   └─ sandbox.submit_url(url)            ✅ 真实提交给 CAPE/Cuckoo
   └─ SandboxTask(status="pending")      ✅ 写入 DB
                    ⋮
   └─ sandbox.poll_outcome(task_id)      ❌ 生产零调用
   └─ sandbox.fetch_report_outcome(...)  ❌ 生产零调用
   └─ sandbox.wait_outcome(...)          ❌ 生产零调用
```

## 与 `test_sandbox_task_dead_end.py` 的分工

那个守卫钉的是**写回**那半边（有没有代码把分析结果写回 `SandboxTask`）。
本文件钉的是**输入**那半边（有没有代码去轮询/取回结果）——
两半边都没有，才构成「提交进去就悬空」。

## 为什么用 strict xfail

要补上回取路径同样需要设计决策：谁负责轮询（router 协程 / scheduler /
连接器内部）？失败重试与超时怎么落？和 §7.1.4 的零日链接线一样，
不该由一次审计代拍。strict xfail 的作用是：一旦有人补上回取路径，
XPASS(strict) 立刻转红，强制回来改本文件与验收报告 §9.14。

## 前提守卫：扫描器本身不能有洞

本轮实测踩过一次：普查脚本用「符号前必须有 `.` 或 `(`」的正则，
于是 `inc_sandbox_submission("file")` 这种**裸函数调用**被漏掉，
差点把「沙箱提交指标无人自增」写成结论 —— 实际它在生产里是自增的。
所以本文件用 **AST**（不做文本匹配），并自带一个**正向对照**：
扫描器必须能同时发现裸调用与属性调用，否则判据无效。
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

BACKEND = Path(__file__).resolve().parents[1]

#: 「回取结果」这半边的公开入口 —— 生产代码里必须**一个都没有**（当前缺口）
RESULT_SYMBOLS = frozenset({
    "poll_outcome",
    "wait_outcome",
    "wait_for_completion",
    "fetch_report_outcome",
    "get_report",
    "get_task_status",
})

#: 「写入任务」这半边 —— 前提：它**有**生产入口（否则缺口就是另一种形态）
#:
#: 2026-10-20（整改报告 §9.64）：`POST /sandbox/submit` 改用
#: `submit_url_outcome()` —— 旧的 `submit_url()` **只回传 task_id**，
#: 样本指纹（SHA-256）会在那一步丢掉，而文档 §十.1 要求
#: 「用 SHA-256 的真实样本标识关联沙箱任务」。
#: ⇒ 这里的符号集必须**两种接法都认**，否则「写入半边有入口」这个前提
#: 会因为一次无关的接线升级而误判成「缺口形态变了」。
SUBMIT_SYMBOLS = frozenset({
    "submit_url", "submit_url_outcome", "submit_file", "submit_file_outcome",
})

#: 定义这些入口的模块本身**不算调用方** —— 它是实现，不是消费者。
#:
#: ⚠ 这一条是本文件第一版的**致命洞**：连接器内部本来就有
#: `get_task_status → self.poll_outcome(...)`、
#: `get_report → self.fetch_report_outcome(...)`、
#: `wait_outcome → self.poll_outcome(...)` 等 5 处调用，
#: 于是 `hits` **永远非空** → strict xfail **永远不可能转红** →
#: 这条守卫**结构性失效**（注入真缺陷也照样绿）。
#: 注入验证是当场发现这一点的：注入后 pytest 仍然报 "1 xfailed"。
IMPLEMENTATION_MODULE = "zeroday_detect/sandbox_connector.py"


def _prod_files() -> list:
    """生产 .py 文件（排除 tests/ 与 test_*.py）。"""
    out = []
    for p in sorted(BACKEND.rglob("*.py")):
        rel = p.relative_to(BACKEND).as_posix()
        if rel.startswith("tests/") or p.name.startswith("test_"):
            continue
        out.append((p, rel))
    return out


#: 解析结果按文件缓存 —— 一次会话里跑 4 条用例，不该把 310 个生产文件解析 4 遍。
_AST_CACHE: dict = {}


def _call_sites(names: frozenset) -> list:
    """用 AST 找出生产代码里对 `names` 的**真实调用**。

    刻意不用文本匹配：注释与 docstring 里的名字不是调用，
    文本匹配会把「有人在注释里提了一句 poll_outcome」误判成「回取路径已接线」。

    `IMPLEMENTATION_MODULE` 被排除：它是被审计的**实现**，
    把它的内部调用算成「消费者」会让判据永远非空（见该常量处的说明）。
    """
    hits = []
    for p, rel in _prod_files():
        if rel == IMPLEMENTATION_MODULE:
            continue
        tree = _AST_CACHE.get(rel)
        if tree is None:
            try:
                tree = ast.parse(p.read_text(encoding="utf-8"))
            except (OSError, SyntaxError):
                tree = False          # 解析不了的文件不当成「有调用」
            _AST_CACHE[rel] = tree
        if tree is False:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if isinstance(func, ast.Name) and func.id in names:
                hits.append((rel, node.lineno, func.id))
            elif isinstance(func, ast.Attribute) and func.attr in names:
                hits.append((rel, node.lineno, func.attr))
    return hits


class TestSandboxResultRetrievalGap:
    """回取半边零生产调用 —— 已知缺口，strict xfail 钉住。"""

    def test_scanner_finds_both_bare_and_attribute_calls(self):
        """前提守卫：扫描器不能漏掉**裸函数调用**。

        本轮实测踩过：普查脚本用「符号前必须有 `.` 或 `(`」的正则，
        `inc_sandbox_submission("file")` 这种裸调用被漏掉，
        差点把「沙箱提交指标无人自增」写成结论 —— 实际它是自增的。
        判据本身有洞时，它给出的任何结论都不可信。
        """
        # 属性调用：sandbox.submit_url_outcome(...) —— 必须找得到
        # （2026-10-20 §9.64：端点从 submit_url 换成 submit_url_outcome，
        #  这里跟着换 —— 前提守卫的**例子**必须指向当前真实接线，
        #  否则守卫会因为一次无关的接线升级而假红。）
        attr_hits = _call_sites(frozenset({"submit_url_outcome"}))
        assert attr_hits, (
            "扫描器连属性调用都找不到 —— 判据本身失效"
            "（若端点又换了接法，请同步本文件与验收报告 §9.14/§9.64）")

        # 裸调用：inc_sandbox_submission("file") —— 也必须找得到
        bare_hits = _call_sites(frozenset({"inc_sandbox_submission"}))
        assert bare_hits, (
            "扫描器漏掉了裸函数调用 —— 判据只认属性调用，"
            "会得出「指标无人自增」这类**反向**结论")

    def test_submit_half_is_wired_so_the_gap_is_precise(self):
        """前提守卫：写入半边**有**生产入口。

        缺口因此是精确的：「提交进得去、结果拿不回来」，
        而不是「整个沙箱模块都没接」。
        """
        hits = _call_sites(SUBMIT_SYMBOLS)
        assert hits, (
            "写入半边也没有生产入口 —— 缺口形态变了，本文件的登记需要改写")
        assert any(rel.startswith("routers/") for rel, _, _ in hits), \
            "写入半边的生产入口不在 router 层 —— 登记需要改写：%r" % hits

    def test_implementation_module_is_excluded_but_still_contains_internal_calls(self):
        """前提守卫：排除是**承重**的，而且排除的确实是实现模块。

        连接器内部本来就有 `get_task_status → self.poll_outcome(...)` 这类调用。
        把它算进「消费者」，判据就永远非空 → strict xfail 永远转不了红
        → 这条守卫结构性失效（第一版就是这样：注入真缺陷也照样绿）。
        """
        # 排除之后：模块外零命中
        assert _call_sites(RESULT_SYMBOLS) == [], \
            "排除实现模块后仍有命中：%r" % _call_sites(RESULT_SYMBOLS)
        # 但模块**内部**确实有这些调用 —— 说明排除的是实现，不是符号本身
        impl_path = BACKEND / IMPLEMENTATION_MODULE
        assert impl_path.exists(), "实现模块路径变了：%s" % IMPLEMENTATION_MODULE
        tree = ast.parse(impl_path.read_text(encoding="utf-8"))
        internal = [
            node.func.attr for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in RESULT_SYMBOLS
        ]
        assert internal, (
            "实现模块里已经没有 %s 的内部调用了 —— "
            "排除规则的前提变了，请回来改本文件与验收报告 §9.14"
            % sorted(RESULT_SYMBOLS))

    @pytest.mark.xfail(strict=True, reason=(
        "已知缺口：沙箱的「结果回取半边」（poll / wait / fetch_report / "
        "get_task_status）在生产代码里零调用 —— 提交进去的任务永远拿不到结果，"
        "SandboxTask 永远停在 pending。见验收报告 §9.14"))
    def test_result_retrieval_has_a_production_caller(self):
        """【缺口】生产代码里必须有人去轮询/取回沙箱结果。

        ⚠ 断言的**极性**很要紧：`strict=True` 的 xfail 期望这条用例**失败**。
        所以这里必须写成「**必须找得到**调用方」：
          · 缺口还在 → 找不到 → 断言失败 → xfail 成立（绿）
          · 有人接上了 → 找得到 → 断言通过 → XPASS(strict) → **红**，
            强制回来改本文件与验收报告 §9.14。
        写成 `assert not hits` 会把极性整个反过来：
        缺口存在时用例**通过** → 立刻 XPASS(strict) → 恒红。
        """
        hits = _call_sites(RESULT_SYMBOLS)
        assert hits, (
            "生产代码里仍然没有任何地方调用沙箱的回取入口 %r —— "
            "缺口还在（这是预期的 xfail）；若这条用例变成 XPASS(strict)，"
            "说明有人接上了回取路径，请回来改本文件与验收报告 §9.14"
            % sorted(RESULT_SYMBOLS))
