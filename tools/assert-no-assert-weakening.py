#!/usr/bin/env python3
"""断言工作区相对基线**没有把测试断言改弱**。

## 为什么需要这个脚本

整改方案 §十三「全量回归」行把验收标准写成：

> 全量测试通过，并且原有测试没有通过删除断言或放宽安全要求来人为变绿。

前半句（测试全绿）任何 CI 都能自动判；**后半句没有任何工具在判**。
于是一条断言从

    assert set(http_dict.keys()) == {"status", "event_id", ...}

被改成

    assert {"status", "event_id", ...}.issubset(http_dict.keys())

之后，全量测试照样全绿 —— 而「载荷里不得出现意外键」这条性质
已经不再有人守了。子集断言和相等断言看起来只差几个字符，
**在 CI 的输出里长得一模一样**。

2026-10-19 首次实测（§9.26）：工作区相对 HEAD 有 18 个测试文件被改过，
逐 hunk 比对后 16 条被删断言里有 **15 条是真加强或语义修正**、
**1 条是真弱化**（上面那条键集合等式）。真弱化只有 1 条，
但**没有任何机制会发现它** —— 它是被人工逐条读 diff 读出来的。

## 本工具判什么、不判什么

只判**能明确识别的弱化签名**，不做语义猜测：

| 弱化签名 | 例子 |
|---|---|
| 集合相等 → 子集 | `assert set(x) == {…}` → `assert {…}.issubset(x)` |
| 相等 → 存在性 | `assert x == 1` → `assert x is not None` / `assert x` |
| 精确长度 → 下界 | `assert len(x) == 3` → `assert len(x) >= 1` / `assert x` |
| 成员 → 存在性 | `assert a in b` → `assert a is not None` |
| 期望异常 → 取消 | `with pytest.raises(E):` 被删且同函数内没有新的 `pytest.raises` |

判不出来的（换了个写法但强度不明）一律归为 `REPLACED`，
**列进「需人工核对」清单，不自动判红**。
自动判红的误报会让人开始忽略这个门禁，那比没有门禁更糟。

比对单位是**文件**（再按**函数**归组），不是 diff hunk ——
弱化和它的替代形态完全可能被中间几行无关改动隔开，
逐 hunk 比对会把它们拆到两个 hunk 里，于是永远配不上对。

## 四类结论

* `WEAKENED`   —— 明确弱化。**判红**。
* `DELETED`    —— 断言被删且同函数内没有替代断言。**判红**。
* `TEST_REMOVED` —— 整个测试函数被删**或被改名**。**不判红**，但列出来
  （删测试是另一类决策，不与「弱化」混为一谈）。
* `MOVED`      —— 断言被挪到同文件的别处。**不判红**，但列出来。
* `REPLACED`   —— 有替代断言但强度自动判不准。列进人工核对清单。

## 自检（这个工具自己也可能恒绿）

判据写错了会出现两种形态：**该红不红**（工具坏了）和**恒红**（判据过严）。
所以工具每次运行都先拿**内置的 7 个已知答案**跑一遍分类器：

* 4 个已知弱化（集合相等→子集 / 相等→存在性 / 精确长度→下界 / 期望异常→取消）
  → 必须判成 `WEAKENED`
* 3 个已知加强（原样保留+新增 / 换成更强的断言 / 换了断言对象）
  → 必须判成 `REPLACED`

自检不过 → **退出码 2**，明确报「分类器自己坏了」，不给出「通过」结论。

## 用法

    python tools/assert-no-assert-weakening.py                  # 对比 HEAD
    python tools/assert-no-assert-weakening.py --base origin/main
    python tools/assert-no-assert-weakening.py --report-only     # 只列不判红

## 退出码

0 = 通过；1 = 发现弱化或删除（消息打印到 stdout，便于 CI 收集）；
2 = **本次运行没有结论** —— 分类器自检失败、基线 ref 不存在，
或工具自身异常（崩溃与「发现了弱化」必须能被区分开，
否则一次崩溃会被读成一次检测）。

## 边界

* **只能发现相对基线被改弱的断言。** 新增代码里的弱化没有基线可比。
* 只判**形式弱化**。「把 `== 1` 改成 `== 2`」是数值放宽，判不出来。
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import io
import json
import os
import re
import subprocess
import sys

# Windows 控制台默认可能是 GBK；工具输出里含 ✅ 等字符，直接 print 会
# 抛 UnicodeEncodeError 并以退出码 2 结束（“没有结论”），掩盖真实门禁结果。
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

TEST_DIR_RE = re.compile(r"(^|/)tests?/|(^|/)test_[^/]*\.py$|(^|/)conftest\.py$")
ASSERT_RE = re.compile(r"^\s*(assert\b|with\s+pytest\.raises\b)")
FUNC_RE = re.compile(r"^\s*(async\s+def|def)\s+(\w+)")


# ─────────────────────────────────────────────────────────────────────
# 断言解析：把一条 assert 拆成「被断言的表达式」+「断言形态」
# ─────────────────────────────────────────────────────────────────────

# 形态的强弱顺序（数字越大越强）。
# 同一表达式上，形态变弱 = 断言被放宽。
STRENGTH = {
    "bare": 1,        # assert x
    "notnone": 2,     # assert x is not None
    "none": 2,        # assert x is None
    "in": 3,          # assert x in y
    "cmp": 3,         # assert len(x) >= 1
    "subset": 4,      # assert {...}.issubset(x)
    "eq": 5,          # assert x == y
    "raises": 5,      # with pytest.raises(...)
    "called": 5,      # x.assert_called(...)
}


def parse_assert(stmt: str):
    """返回 (被断言的表达式, 形态)。解析不出来返回 (None, None)。

    为什么要解析到「表达式」这一层：
    只比对整行文本会误判 —— 把 `assert x == 1` 和 `assert x == 1` 并排放
    在同一个 hunk 里（一条加强、一条无关），整行比对看不出变化；
    而表达式级比对能确认「同一个 x 从 `== 1` 变成了 `is not None`」。

    也因此，「集合相等 → 子集」这条不要求两边表达式字面相同：
    `set(X) == {...}` 与 `{...}.issubset(X)` 的表达式写法不一样，
    但它们约束的是**同一个 X**，所以按内层参数匹配。
    """
    s = stmt.strip()
    if s.startswith("with pytest.raises"):
        return s, "raises"
    if not s.startswith("assert"):
        return None, None

    m = re.match(r"^assert\s+(.+?)\s*==\s*(.+)$", s)
    if m:
        return m.group(1).strip(), "eq"
    m = re.match(r"^assert\s+(.+?)\s+is\s+not\s+None$", s)
    if m:
        return m.group(1).strip(), "notnone"
    m = re.match(r"^assert\s+(.+?)\s+is\s+None$", s)
    if m:
        return m.group(1).strip(), "none"
    m = re.match(r"^assert\s+(.+?)\s+in\s+(.+)$", s)
    if m:
        return m.group(1).strip(), "in"
    m = re.match(r"^assert\s+(.+?)\s*(>=|<=|>|<)\s*(.+)$", s)
    if m:
        return m.group(1).strip(), "cmp"
    m = re.match(r"^assert\s+(.+)$", s)
    if m:
        expr = m.group(1).strip()
        if ".issubset(" in expr or ".isdisjoint(" in expr:
            return expr, "subset"
        return expr, "bare"
    return None, None


def _norm(expr: str) -> str:
    return re.sub(r"\s+", "", expr or "")


def find_weakening(removed_stmt: str, added_stmts: list[str]):
    """找出把 removed_stmt 放宽的那条新增断言。

    返回 (签名名, 新增断言文本) 或 None。
    只在「**同一个被断言对象**」上形态变弱时才判定 ——
    判不准的一律不判（宁可漏报也不要误报，误报会让人忽略这个门禁）。
    """
    expr_r, kind_r = parse_assert(removed_stmt)
    if expr_r is None:
        return None
    if kind_r == "raises":
        # 期望异常被取消：同 hunk 里一条 raises 都没有
        if not any(parse_assert(a)[1] == "raises" for a in added_stmts):
            return ("期望异常 → 取消", "<同 hunk 内没有任何 pytest.raises>")
        return None

    for a in added_stmts:
        expr_a, kind_a = parse_assert(a)
        if expr_a is None:
            continue
        if kind_a == kind_r:
            continue
        if STRENGTH.get(kind_a, 0) >= STRENGTH.get(kind_r, 0):
            continue
        # ── 到这里：形态确实更弱 ──────────────────────────────────
        # 还必须是「同一个被断言对象」
        if _norm(expr_a) == _norm(expr_r):
            return ("%s → %s" % (kind_r, kind_a), a)
        # 集合相等 → 子集：表达式写法不同但约束同一个 X
        m = re.match(r"^set\((.+)\)$", expr_r)
        if m and kind_r == "eq" and kind_a == "subset":
            inner = m.group(1).strip()
            if inner and inner in a and "issubset" in a:
                return ("集合相等 → 子集", a)
        # 精确长度 → 下界：expr_r 形如 len(X)，expr_a 形如 len(X)
        m = re.match(r"^len\((.+)\)$", expr_r)
        if m and kind_r == "eq" and kind_a == "cmp":
            inner = m.group(1).strip()
            if inner and inner in a:
                return ("精确长度 → 下界", a)
    return None


# ─────────────────────────────────────────────────────────────────────
# hunk 解析
# ─────────────────────────────────────────────────────────────────────

HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+\d+(?:,\d+)? @@")


def parse_hunks(diff_text: str):
    """把 unified diff 拆成 hunk 列表。

    每项 = {"removed": [(old_lineno, text), ...], "added": [(new_lineno, text), ...]}。

    ## 为什么带行号

    比对单位是「**同一个函数里的**被删断言 vs 新增断言」，
    行号是把它落到具体函数上的唯一依据。

    ## 为什么不能只按 hunk 比对（实测踩过的坑）

    第一版是逐 hunk 比的，结果一次注入就漏判：

        assert set(http_dict.keys()) == {      ← 被删
        # 中间隔了十来行注释
        assert {                                ← 新增（在另一个 hunk）
        }.issubset(http_dict.keys())

    `git diff -U0` 把这两处切成了**两个 hunk**（中间隔着注释块），
    于是「被删的强断言」和「新增的弱断言」永远碰不到一起 ——
    门禁判成「有替代断言」，放过去了。

    弱化和它的替代形态**完全可能被无关改动隔开**，
    所以比对单位必须是文件（再按函数归组），不是 hunk。
    """
    hunks = []
    cur = None
    old_no = 0
    new_no = 0
    for line in diff_text.splitlines():
        m = HUNK_RE.match(line)
        if m:
            spec = line.split("@@")[1].strip()
            old_part, new_part = spec.split(" ")
            old_no = int(old_part[1:].split(",")[0])
            new_no = int(new_part[1:].split(",")[0])
            cur = {"removed": [], "added": []}
            hunks.append(cur)
            continue
        if cur is None:
            continue
        if line.startswith("---") or line.startswith("+++"):
            continue
        if line.startswith("-"):
            cur["removed"].append((old_no, line[1:]))
            old_no += 1
        elif line.startswith("+"):
            cur["added"].append((new_no, line[1:]))
            new_no += 1
        elif line.startswith(" "):
            old_no += 1
            new_no += 1
    return hunks


def enclosing_functions(source: str) -> dict[int, str]:
    """行号 → 该行所在的最内层函数名。解析失败返回空表。"""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return {}
    spans = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            spans.append((node.lineno, node.end_lineno or node.lineno, node.name))
    spans.sort(key=lambda s: (s[1] - s[0]))
    out: dict[int, str] = {}
    for lineno, _text in enumerate(source.splitlines(), 1):
        for start, end, name in spans:
            if start <= lineno <= end:
                out[lineno] = name
                break
    return out


# ─────────────────────────────────────────────────────────────────────
# 分类
# ─────────────────────────────────────────────────────────────────────

def split_statements(lines: list[str], with_lineno: bool = False):
    """把代码行按**括号配平**切成逻辑语句。

    为什么不能按「行首是不是 assert」过滤：
    一条断言常被拆成多行，最要命的是这种形态 ——

        assert set(http_dict.keys()) == {      ← 旧
        assert {                               ← 新（第 1 行）
        }.issubset(http_dict.keys())          ← 新（第 2 行，续行！）

    第 2 行不以 assert 开头，按行首过滤会**把它整个丢掉**，
    于是弱化签名匹配不到，分类器把弱化判成「有替代断言」。
    （这个 bug 是工具自检当场抓出来的 —— 自检存在的意义就在这儿。）

    括号配平是可靠的切分信号：语句没闭合就说明还没结束。
    """
    out = []
    cur_parts: list[str] = []
    cur_line = None
    depth = 0
    for idx, raw in enumerate(lines):
        if with_lineno:
            lineno, text = raw
        else:
            lineno, text = None, raw
        s = text.strip()
        if not s or s.startswith("#"):
            # 注释不是语句。
            # 不跳过的话，「删掉一条断言 + 加一段注释」会被当成
            # 「有替代断言」→ DELETED 判不出来。
            continue
        starts_new = depth <= 0 and (s.startswith("assert") or s.startswith("with pytest.raises"))
        if starts_new and cur_parts:
            out.append((cur_line, " ".join(cur_parts)))
            cur_parts = []
            cur_line = None
        if cur_line is None:
            cur_line = lineno
        cur_parts.append(s)
        depth += s.count("(") + s.count("[") + s.count("{")
        depth -= s.count(")") + s.count("]") + s.count("}")
        if depth <= 0:
            out.append((cur_line, " ".join(cur_parts)))
            cur_parts = []
            cur_line = None
            depth = 0
    if cur_parts:
        out.append((cur_line, " ".join(cur_parts)))
    return out


# ─────────────────────────────────────────────────────────────────────
# 分类
# ─────────────────────────────────────────────────────────────────────

def collect_asserts(lines_with_lineno):
    """从代码行里挑出断言语句，返回 [(行号, 语句文本)]。"""
    out = []
    for lineno, text in split_statements(lines_with_lineno, with_lineno=True):
        s = text.strip()
        if ASSERT_RE.match(s):
            out.append((lineno, s))
    return out


def classify_removed(removed_stmt: str, candidates: list[str],
                     func_name, func_exists: bool,
                     new_all_assert_texts: set) -> dict:
    """判定「一条被删的断言」在新文件里被怎样对待了。

    candidates = 同一函数内的新增断言（函数内是合理的比对粒度：
    跨函数配对会把 A 函数的断言和 B 函数的断言乱配）。
    """
    if func_name and not func_exists:
        return {"kind": "TEST_REMOVED",
                "signature": "整个测试函数被删或被改名（%s）" % func_name,
                "removed": removed_stmt, "added": ""}

    weakened = find_weakening(removed_stmt, candidates)
    if weakened:
        sig, weakened_by = weakened
        return {"kind": "WEAKENED", "signature": sig,
                "removed": removed_stmt, "added": weakened_by}

    if not candidates:
        # 同函数里一条新增断言都没有。
        # 如果这条断言在文件别处原样出现，那是「挪走了」而不是「删了」。
        if removed_stmt in new_all_assert_texts:
            return {"kind": "MOVED",
                    "signature": "断言被挪到同文件的别处（不判红）",
                    "removed": removed_stmt, "added": ""}
        return {"kind": "DELETED",
                "signature": "断言被删且同函数内无替代",
                "removed": removed_stmt, "added": ""}

    return {"kind": "REPLACED",
            "signature": "有替代断言，强度自动判不准（需人工核对）",
            "removed": removed_stmt,
            "added": " | ".join(a[:160] for a in candidates[:3])}


def classify_file(old_src: str, new_src: str, diff_text: str) -> list[dict]:
    """对一个被改动的测试文件做分类。"""
    old_funcs = enclosing_functions(old_src)
    new_funcs = enclosing_functions(new_src)
    new_names = set(new_funcs.values())

    removed_all, added_all = [], []
    for hunk in parse_hunks(diff_text):
        removed_all.extend(hunk["removed"])
        added_all.extend(hunk["added"])

    removed_asserts = collect_asserts(removed_all)
    added_asserts = collect_asserts(added_all)

    new_all_assert_texts = {t for _n, t in collect_asserts(
        [(i, l) for i, l in enumerate(new_src.splitlines(), 1)])}

    findings = []
    for old_no, stmt in removed_asserts:
        fname = old_funcs.get(old_no)
        cands = [t for (n, t) in added_asserts
                 if fname is None or new_funcs.get(n) == fname]
        f = classify_removed(stmt, cands, fname, (fname in new_names) if fname else True,
                             new_all_assert_texts)
        findings.append(f)
    return findings


# ─────────────────────────────────────────────────────────────────────
# 自检：分类器必须先答对已知答案
# ─────────────────────────────────────────────────────────────────────

# 已知答案：每个样本都必须被判成指定形态。
# 判据写错了有两种形态 —— 「该红不红」（工具坏了）与「恒红」（判据过严）。
# 这组样本两个方向都钉住。
SELFCHECK_CASES = [
    # (说明, 被删断言, 新增断言们, 期望形态)
    ("集合相等 → 子集（跨行）",
     "        assert set(http_dict.keys()) == {",
     ["        assert {", "        }.issubset(http_dict.keys())"],
     "WEAKENED"),
    ("相等 → 存在性",
     "        assert result.status == 200",
     ["        assert result.status is not None"],
     "WEAKENED"),
    ("精确长度 → 下界",
     "        assert len(items) == 3",
     ["        assert len(items) >= 1"],
     "WEAKENED"),
    ("期望异常 → 取消",
     "        with pytest.raises(ValueError):",
     ["        do_something()"],
     "WEAKENED"),
    ("加强：原样保留 + 新增一条",
     "        assert x == 1",
     ["        assert x == 1", "        assert y == 2"],
     "REPLACED"),
    ("加强：换成更强的断言",
     "        assert x is not None",
     ["        assert x == 1"],
     "REPLACED"),
    ("加强：换了断言对象",
     "        assert a == 1",
     ["        assert b == 2"],
     "REPLACED"),
]


def selfcheck() -> list[str]:
    problems = []
    # 断言基线的自检（§9.65）：
    #   · 注释改动**不得**改变摘要（否则每次改注释都要复核）；
    #   · 断言被改弱**必须**改变摘要（否则漏看）。
    if assert_digest("assert x == 1\n") == assert_digest("assert x == 1  # 注释\n"):
        problems.append("断言摘要把注释也算进去了 —— 注释改动不该触发复核")
    if assert_digest("assert x == 1\n") == assert_digest("assert x is not None\n"):
        problems.append("断言摘要没区分断言强度 —— 断言被改弱时摘要必须变")
    for desc, removed, added, expect in SELFCHECK_CASES:
        # 走**与真实路径同一套**的语句切分 ——
        # 自检自己走另一条路，就自检不到真正的判据。
        cands = [t for _n, t in split_statements(
            [(i, l) for i, l in enumerate(added, 1)], with_lineno=True)]
        f = classify_removed(removed, cands, None, True, set())
        if f["kind"] != expect:
            problems.append("「%s」应判成 %s，实际 %s" % (desc, expect, f["kind"]))
    return problems


# ─────────────────────────────────────────────────────────────────────
# 主流程
# ─────────────────────────────────────────────────────────────────────

def git(repo: str, *args: str) -> tuple[int, str, str]:
    r = subprocess.run(["git"] + list(args), cwd=repo, capture_output=True,
                       text=True, encoding="utf-8", errors="replace")
    return r.returncode, r.stdout or "", r.stderr or ""


#: 未跟踪测试文件的**断言基线**（相对仓库根）。
#:
#: 为什么需要它（整改报告 §9.41 / §9.65）：
#: `git diff --name-only <base>` **只列已跟踪文件** → 未跟踪的新测试
#: 文件没有基线可比 → 完全不在本门禁覆盖范围内 → 它们的断言若被削弱，
#: CI 照样绿。实测规模：123 个未跟踪测试文件、**3942 条断言**。
#:
#: 本轮做法（**不改 git 索引**、不代 `git add`）：
#:   · 基线记每个未跟踪测试文件的**断言清单 sha256** + 断言条数；
#:   · 门禁比对：断言**变了** → 报「变更」并**判红**（人工核对）；
#:   · `--update-baseline` 重新生成基线（确认无误后再跑）。
#:
#: 为什么用「断言清单的摘要」而不是整文件：注释 / docstring 的改动
#: 不该触发复核（断言没变），而断言**一改**就一定会被看见。
#:
#: ⚠ 诚实的边界：基线只有摘要，**判不出「弱化」，只能报「变了」** ——
#: 与已跟踪路径的自动判定不等价，但至少**从「不可见」变成「必须被看见」**。
BASELINE_REL = "tools/guard_assert_baseline.json"


def assert_digest(src: str) -> str:
    """断言清单的 sha256（只认**断言语句**，注释与 docstring 不算）。"""
    asserts = [t for _n, t in
                collect_asserts(list(enumerate(src.splitlines(), 1)))]
    joined = "\n".join(asserts)
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()


def load_baseline(path: str):
    """读基线；读不到返回 None（调用方必须当成「不知道」）。"""
    if not os.path.exists(path):
        return None
    try:
        with io.open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def build_baseline(repo: str, untracked) -> dict:
    """从当前工作区生成断言基线。"""
    out = {}
    for rel in untracked:
        p = os.path.join(repo, rel.replace("/", os.sep))
        try:
            src = io.open(p, encoding="utf-8").read()
        except OSError:
            continue
        out[rel] = {
            "sha256": assert_digest(src),
            "asserts": len(collect_asserts(
                list(enumerate(src.splitlines(), 1)))),
        }
    return out


def compare_untracked_asserts(repo: str, untracked, baseline) -> tuple:
    """比对未跟踪测试文件的断言清单与基线。

    返回 `(changed, not_in_baseline, detail, total_asserts)`：
      · changed        —— [(文件, 现断言数, 基线断言数)]，断言**变了**；
      · not_in_baseline —— [(文件, 断言数)]，基线里没有它（新文件）；
      · detail         —— [(文件, 断言数)]，全部未跟踪文件；
      · total_asserts  —— 这些文件里的断言总数。

    抽成函数是为了**可测**：判据必须能对着「真实会发生的改动」跑一遍，
    而不是只能靠「跑一次门禁看输出」来间接验证。
    """
    changed = []
    not_in_baseline = []
    detail = []
    total_asserts = 0
    for rel in untracked:
        p = os.path.join(repo, rel.replace("/", os.sep))
        try:
            src = io.open(p, encoding="utf-8").read()
        except OSError:
            continue
        n = len(collect_asserts(list(enumerate(src.splitlines(), 1))))
        total_asserts += n
        detail.append((rel, n))
        if baseline is None:
            continue
        rec = baseline.get(rel)
        if not rec:
            not_in_baseline.append((rel, n))
            continue
        if rec.get("sha256") != assert_digest(src):
            changed.append((rel, n, rec.get("asserts", 0)))
    return changed, not_in_baseline, detail, total_asserts


def _untracked_test_files(repo: str):
    """列出**未跟踪**的测试文件。

    返回 `None` 表示枚举失败 —— 调用方必须把它当成「不知道」，
    绝不能当成「0 个」。

    为什么这一项重要：`git diff --name-only <base>` **只列已跟踪文件**，
    未跟踪的新测试文件没有基线可比 → 完全不在门禁覆盖范围内 →
    它们的断言若被削弱，CI 照样绿。
    """
    code, out, _ = git(repo, "ls-files", "--others", "--exclude-standard")
    if code != 0:
        return None
    return [f for f in out.splitlines()
            if f.strip() and TEST_DIR_RE.search(f.replace("\\", "/"))]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--base", default="HEAD", help="对比基线（默认 HEAD）")
    ap.add_argument("--repo", default=None,
                    help="仓库根目录（默认取本脚本的上上级目录）")
    ap.add_argument("--report-only", action="store_true",
                    help="只打印结论，不因 WEAKENED/DELETED 判红")
    ap.add_argument("--update-baseline", action="store_true",
                    help="重新生成未跟踪测试文件的断言基线（%s）" % BASELINE_REL)
    args = ap.parse_args(argv)

    here = os.path.dirname(os.path.abspath(__file__))
    repo = os.path.abspath(args.repo or os.path.dirname(here))

    # ── 自检先行：分类器自己坏了就没什么好判的了 ────────────────────
    problems = selfcheck()
    if problems:
        for p in problems:
            print("::error::分类器自检失败 —— %s" % p)
        print("::error::本工具此刻给出的任何「通过」结论都不可信")
        return 2
    print("[assert-no-assert-weakening] 分类器自检通过")

    code, out, err = git(repo, "rev-parse", "--verify", args.base)
    if code != 0:
        print("::error::基线 %s 不存在或不是合法 ref：%s" % (args.base, err.strip()[:200]))
        print("::error::查不到基线 ≠ 没有弱化 —— 此时不能给出「通过」结论")
        return 2

    code, changed, _ = git(repo, "diff", "--name-only", args.base, "--")
    if code != 0:
        print("::error::无法读取 diff")
        return 2
    files = [f for f in changed.splitlines() if f.strip() and TEST_DIR_RE.search(f.replace("\\", "/"))]
    print("[assert-no-assert-weakening] 基线 %s，改动的测试文件 %d 个" % (args.base, len(files)))

    # ── 覆盖边界：未跟踪的新测试文件**不在**本门禁覆盖范围内 ──
    # 枚举失败时判退出码 2：把「不知道」说成「没有」会让盲区再次隐形。
    untracked = _untracked_test_files(repo)
    if untracked is None:
        print("::error::无法枚举未跟踪的测试文件 —— 覆盖边界不可知，"
              "本次不给「通过」结论")
        return 2

    # ── 未跟踪测试文件：断言基线（整改报告 §9.65）────────────────
    baseline_path = os.path.join(repo, BASELINE_REL.replace("/", os.sep))
    if args.update_baseline:
        data = build_baseline(repo, untracked)
        # 显式 newline="\n"：Windows 上默认会把 \n 写成 \r\n，
        # 于是同一份基线在两个平台上内容不同 → 无谓的整文件 diff。
        with io.open(baseline_path, "w", encoding="utf-8", newline="\n") as f:
            json.dump(data, f, ensure_ascii=False, indent=1, sort_keys=True)
            f.write("\n")
        print("[assert-no-assert-weakening] 已更新断言基线 %s（%d 个未跟踪测试文件）"
              % (BASELINE_REL, len(data)))
        return 0

    baseline = load_baseline(baseline_path)
    if baseline is None:
        print("::warning::未找到断言基线 %s —— 未跟踪测试文件的断言变更"
              "**不在**本门禁覆盖范围内（跑一次 --update-baseline 即可纳入）"
              % BASELINE_REL)

    (changed_untracked, not_in_baseline, detail,
     total_asserts) = compare_untracked_asserts(repo, untracked, baseline)

    for rel, n, before_n in changed_untracked:
        print("::error::[UNTRACKED_CHANGED] %s 的**断言**已变更（%s → %s 条）"
              "—— 未跟踪文件没有 git 基线可比，本门禁只能报「变了」而判不了"
              "「弱化了」：请人工核对；确认无误后跑 --update-baseline"
              % (rel, before_n, n))

    if untracked:
        print("::warning::[assert-no-assert-weakening] 覆盖边界：另有 %d 个"
              "**未跟踪**的测试文件（git ??）—— git diff 比对**够不着**它们"
              % len(untracked))
        print("    规模：这些文件里共有 **%d 条断言**。" % total_asserts)
        for rel, n in sorted(detail, key=lambda x: -x[1])[:10]:
            print("      %-62s %4d 条断言" % (rel, n))
        if len(detail) > 10:
            print("      … 其余 %d 个" % (len(detail) - 10))
        if baseline is not None:
            if changed_untracked:
                print("    其中 **%d 个的断言已变更** → 已判红（需人工核对）"
                      % len(changed_untracked))
            else:
                print("    其中 **全部**断言与基线一致 ✅")
            if not_in_baseline:
                print("    另有 **%d 个未纳入基线**（新文件）：没有基线可比，"
                      "其断言变更本门禁判不出来" % len(not_in_baseline))
                for rel, n in sorted(not_in_baseline, key=lambda x: -x[1])[:8]:
                    print("      %-62s %4d 条断言" % (rel, n))
                print("      → 跑 --update-baseline 把它们纳入基线")
        print("    彻底处置：把新测试文件纳入 git 跟踪后，git diff 才能比对它们。")

    if not files:
        print("[assert-no-assert-weakening] 无**已跟踪**测试文件改动 —— 无可判内容")
        return 0

    findings = []
    for rel in files:
        path = os.path.join(repo, rel.replace("/", os.sep))
        rc, old_src, _ = git(repo, "show", "%s:%s" % (args.base, rel))
        if rc != 0:
            continue
        try:
            new_src = io.open(path, encoding="utf-8").read()
        except OSError:
            continue
        code, diff_text, _ = git(repo, "diff", "-U0", args.base, "--", rel)
        for f in classify_file(old_src, new_src, diff_text or ""):
            f["file"] = rel
            findings.append(f)

    counts = {}
    for f in findings:
        counts[f["kind"]] = counts.get(f["kind"], 0) + 1

    weak = [f for f in findings if f["kind"] in ("WEAKENED", "DELETED")]
    manual = [f for f in findings if f["kind"] in ("REPLACED", "TEST_REMOVED", "MOVED")]

    for f in weak:
        print("::error::[%s] %s\n    - %s\n    + %s" % (
            f["kind"], f["file"], f["removed"][:160], (f["added"] or "-")[:160]))

    if manual:
        print("[assert-no-assert-weakening] 需人工核对 %d 条（不自动判红）：" % len(manual))
        for f in manual:
            print("    [%s] %s\n        - %s\n        + %s" % (
                f["kind"], f["file"], f["removed"][:130], (f["added"] or "-")[:130]))

    summary = ", ".join("%s=%d" % (k, counts[k]) for k in sorted(counts)) or "无"
    print("[assert-no-assert-weakening] 结论：%s" % summary)

    if weak and not args.report_only:
        print("::error::发现 %d 处断言弱化或删除 —— "
              "整改方案 §十三「全量回归」行要求「原有测试没有通过删除断言或"
              "放宽安全要求来人为变绿」" % len(weak))
        return 1
    if changed_untracked and not args.report_only:
        print("::error::发现 %d 个未跟踪测试文件的**断言**已变更 —— "
              "整改方案 §十三「全量回归」行要求「原有测试没有通过删除断言或"
              "放宽安全要求来人为变绿」；这些文件不在 git 比对范围内"
              "（§9.41 盲区），故以「变更即复核」的方式兜住"
              % len(changed_untracked))
        return 1
    return 0


if __name__ == "__main__":
    # 崩溃的退出码必须与「检测到弱化」区分开。
    # 两者都是 1 的话，一次崩溃会被读成一次检测 ——
    # 门禁「红了」但没人知道红在哪，门禁就此失去意义。
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except BaseException as exc:  # noqa: BLE001 —— 门禁不能自己崩掉还给人结论
        import traceback
        traceback.print_exc()
        print("::error::门禁自身异常：%s: %s —— 本次运行**没有结论**" % (
            type(exc).__name__, exc))
        sys.exit(2)
