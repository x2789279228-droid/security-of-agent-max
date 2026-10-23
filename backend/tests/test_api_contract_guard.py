"""
前后端 API 契约守卫：前端 `api.ts` 调用的路径/方法，后端必须真的支持。

## 为什么要有

死代码 + 契约漂移在两个方向上都很便宜：定义一个客户端方法不用花成本，
后端不实现也不花成本，于是两边可以无声地分叉。本轮实测抓到一对：

    api.ts:647  opsFeedbackList   → GET  /feedback            （后端只有 POST）
    api.ts:654  opsFeedbackReview → POST /feedback/{id}/review （后端根本没有）

两条都是 `fetchJSON` 真的能发出的请求 —— 前者得到 405，后者得到 404。
**当前前端没有任何页面调用它们**（`FeedbackTab.tsx` 走的是
`opsFeedbackStats` / `opsFeedbackSuggestions` / `opsSubmitFeedback`），
所以线上无感；但它们就摆在共享 API 客户端里等着被接上。

这正是整改方案 §十一.2「删除或实现长期无人调用的死代码」的前端形态。

## 提取口径（本文件最大的成本都在这里，四轮才对）

TS 的模板字面量会**嵌套**、会**自己拼查询串**：

    fetchJSON<any[]>(`/logs/events${qs ? `?${qs}` : ''}`)

朴素正则会在这里连栽四次，每一种都**制造出假的断链**：

| 坑 | 症状 |
|---|---|
| `` `[^`]*` `` 截断在内层反引号 | `/logs/events${qs ` 被当成路径 |
| `split("?")` 先于插值归一 | 插值内部的 `?` 把路径腰斩 |
| `\$\{[^}]*\}` 不配对 | 内层 `${qs}` 的 `}` 提前收尾，尾部 `: ''}` 漏出 |
| 固定 500 字符前瞻找 `method:` | 吸到**下一个**调用的方法上，41/158 处误报方法不匹配 |

因此：字面量用**带配对深度**的读取器，方法用**配对括号**划界，
插值在读取阶段就换成哨兵（内部含 `?` 的判为查询串构造器、整段丢弃）。

`test_extractor_survives_every_known_template_shape` 把上面四种形态
固化成探针 —— 口径一旦退化，它当场转红，而不是让下游结论悄悄变样。
"""
from __future__ import annotations

import ast
import os
import re
from functools import lru_cache
from pathlib import Path

import pytest

BACKEND = Path(__file__).resolve().parents[1]
REPO = BACKEND.parent
ROUTERS = BACKEND / "routers"
FE = REPO / "frontend" / "src"

HTTP_METHODS = {"get", "post", "put", "delete", "patch", "head", "options", "websocket"}
SENT_EXPR = "\x00"   # 路径段插值
SENT_BASE = "\x01"   # `${BASE}` 前缀

#: 后端没有的路径 / 不支持的方法 —— 必须逐条登记理由。
#: 登记项清空时，`test_no_known_contract_breaks` 这条 strict xfail 就会 XPASS。
KNOWN_BREAKS: dict[str, str] = {
    "GET /api/feedback":
        "api.ts:647 opsFeedbackList 用 GET，ops.py:791 只有 POST → 405。"
        "该方法前端无调用方（FeedbackTab 走 stats/suggestions/submit），"
        "属死代码 + 契约漂移。处置（删除 / 补后端 GET）待用户决策。",
    "POST /api/feedback/{}/review":
        "api.ts:654 opsFeedbackReview，后端全仓无 /feedback/*/review 路由 → 404。"
        "同样无调用方。处置待用户决策。",
}


# ── 模板字面量读取（配对深度）─────────────────────────────
_CALLEE = (r"fetchJSON(?:<(?:[^<>]|<[^<>]*>)*>)?|fetch|EventSource"
           r"|api\.(?:get|post|put|patch|del\w*|upload|raw|send\w*)")
_CALL_RE = re.compile(rf"(?P<callee>{_CALLEE})\s*\(\s*(?P<q>['\"`])")


def _read_literal(txt: str, i: int):
    """i 指向起始引号；返回 (正文, 结束下标)。正文里插值已换成哨兵。"""
    q = txt[i]
    if q in ("'", '"'):
        j = i + 1
        while j < len(txt):
            if txt[j] == "\\":
                j += 2
                continue
            if txt[j] == q:
                return txt[i + 1:j], j + 1
            if txt[j] == "\n":
                break
            j += 1
        return None, i + 1
    j, out = i + 1, []
    while j < len(txt):
        c = txt[j]
        if c == "\\":
            j += 2
            continue
        if c == "`":
            return "".join(out), j + 1
        if c == "$" and j + 1 < len(txt) and txt[j + 1] == "{":
            depth, k = 1, j + 2
            while k < len(txt) and depth:
                if txt[k] == "{":
                    depth += 1
                elif txt[k] == "}":
                    depth -= 1
                k += 1
            inner = txt[j + 2:k - 1]
            # 内部含 '?' → 在拼查询串，不是路径段，整段丢弃
            if "?" not in inner:
                out.append(SENT_BASE if inner == "BASE" else SENT_EXPR)
            j = k
            continue
        out.append(c)
        j += 1
    return "".join(out), j + 1


def _norm(p: str) -> str:
    """先切查询串（此时插值已是哨兵，`?` 必为真分隔符），再抹平动态段。"""
    p = p.split("?")[0].split("#")[0].rstrip("/")
    p = p.replace(SENT_EXPR, "{}")
    p = re.sub(r"\{[^}]*\}", "{}", p)
    p = re.sub(r"//+", "/", p)
    return p or "/"


def _path_of(body: str) -> str:
    if body.startswith(SENT_BASE):
        body = body[1:] or "/"
    if not body.startswith("/"):
        return ""
    if not body.startswith("/api"):
        body = "/api" + body          # api.ts: BASE = '/api'
    return _norm(body)


def _call_span(txt: str, m) -> str:
    """本调用的实参文本：`(` 到配对 `)`。不能用固定窗口前瞻。"""
    open_idx = m.start() + m.group(0).rindex("(")
    depth, k = 0, open_idx
    while k < len(txt):
        c = txt[k]
        if c in "\"'`":
            _, k = _read_literal(txt, k)
            continue
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
            if depth == 0:
                return txt[open_idx:k]
        k += 1
    return txt[open_idx:open_idx + 2000]


# ── 后端路由 ──────────────────────────────────────────────
@lru_cache(maxsize=1)
def backend_routes() -> tuple:
    out = set()
    for py in sorted(ROUTERS.glob("*.py")):
        tree = ast.parse(py.read_text(encoding="utf-8-sig"))
        prefix = ""
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                for kw in node.value.keywords:
                    if kw.arg == "prefix" and isinstance(kw.value, ast.Constant):
                        prefix = kw.value.value
        for node in ast.walk(tree):
            for dec in getattr(node, "decorator_list", []) or []:
                if not (isinstance(dec, ast.Call)
                        and isinstance(dec.func, ast.Attribute)
                        and isinstance(dec.func.value, ast.Name)
                        and dec.func.value.id == "router"
                        and dec.func.attr.lower() in HTTP_METHODS
                        and dec.args
                        and isinstance(dec.args[0], ast.Constant)):
                    continue
                out.add((_norm(prefix + dec.args[0].value), dec.func.attr.upper()))
            if (isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "add_api_route"
                    and node.args and isinstance(node.args[0], ast.Constant)):
                mths = ["GET"]
                for kw in node.keywords:
                    if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple)):
                        mths = [e.value.upper() for e in kw.value.elts
                                if isinstance(e, ast.Constant)]
                for mth in mths:
                    out.add((_norm(prefix + node.args[0].value), mth))
    return tuple(sorted(out))


# ── 前端调用点 ────────────────────────────────────────────
@lru_cache(maxsize=1)
def frontend_calls() -> tuple:
    out = []
    for p in sorted(FE.rglob("*")):
        if p.suffix not in (".ts", ".tsx") or "node_modules" in p.parts:
            continue
        txt = p.read_text(encoding="utf-8-sig", errors="replace")
        for m in _CALL_RE.finditer(txt):
            body, _ = _read_literal(txt, m.end() - 1)
            if not body:
                continue
            path = _path_of(body)
            if not path:
                continue
            span = _call_span(txt, m)
            mm = re.search(r"method\s*:\s*['\"](\w+)['\"]", span)
            method = mm.group(1).upper() if mm else "GET"
            out.append((path, method, f"{p.relative_to(REPO)}:{txt[:m.start()].count(chr(10)) + 1}"))
    return tuple(out)


def _breaks() -> set:
    by_path: dict = {}
    for path, method in backend_routes():
        by_path.setdefault(path, set()).add(method)
    bad = set()
    for path, method, _where in frontend_calls():
        if path not in by_path:
            bad.add(f"{method} {path}")
        elif method not in by_path[path] | {"HEAD", "OPTIONS"}:
            bad.add(f"{method} {path}")
    return bad


# ── 判别力自检：口径退化必须当场转红 ──────────────────────
def test_extractor_survives_every_known_template_shape():
    """四种真实形态各给一个探针，外加方法抽取的括号划界。

    这几条是本文件的**前提守卫**。没有它，口径一旦退化，
    下游「对得上 / 断链」两组数字会一起变样，而没人知道。
    """
    shapes = {
        # 嵌套模板 + 自拼查询串（内层反引号 + 内层 `${}`）
        "`/logs/events${qs ? `?${qs}` : ''}`": "/api/logs/events",
        # 路径段插值 → 一个动态段
        "`/cases/${id}/detail`": "/api/cases/{}/detail",
        # 段插值 + 真查询串
        "`/a/${id}?x=1`": "/api/a/{}",
        # `${BASE}` 前缀
        "`${BASE}/events/stream`": "/api/events/stream",
    }
    for src, want in shapes.items():
        got = _path_of(_read_literal(src, 0)[0] or "")
        assert got == want, f"{src} → {got!r}，应为 {want!r}"

    # 方法必须按配对括号划界，不能吸到下一个调用
    txt = ("fetchJSON<any>('/x/a')\n"
           "render(() => null)\n"
           "fetchJSON<any>('/x/b', { method: 'POST' })")
    got_m = []
    for m in _CALL_RE.finditer(txt):
        g = re.search(r"method\s*:\s*['\"](\w+)['\"]", _call_span(txt, m))
        got_m.append(g.group(1).upper() if g else "GET")
    assert got_m == ["GET", "POST"], f"方法抽取串到相邻调用：{got_m}"

    # 手工核实的活样本必须同时出现在两侧
    paths = {p for p, _ in backend_routes()}
    fpaths = {p for p, _, _ in frontend_calls()}
    for anchor in ("/api/auth/login", "/api/causal/graph", "/api/logs/events"):
        assert anchor in paths, f"后端锚点缺失 {anchor} —— 静态解析口径失效"
        assert anchor in fpaths, f"前端锚点缺失 {anchor} —— 提取口径失效"
    assert len(paths) > 150, f"后端路径数偏少（{len(paths)}）"
    assert len(fpaths) > 100, f"前端路径数偏少（{len(fpaths)}）"


# ── 契约本体 ──────────────────────────────────────────────
def test_every_frontend_call_resolves_to_a_backend_route():
    """前端调的路径，后端必须存在（登记过的除外）。

    404 是最容易在联调前就发现的断链，所以这一层必须守死。
    """
    bad = _breaks()
    unregistered = sorted(bad - set(KNOWN_BREAKS))
    assert not unregistered, (
        "前端调用了后端没有的路径/方法：\n  " + "\n  ".join(unregistered)
    )


def test_known_breaks_are_still_accurately_described():
    """登记项不能与实测脱节 —— 修好一条却忘了删登记，同样是假账。"""
    bad = _breaks()
    stale = sorted(set(KNOWN_BREAKS) - bad)
    assert not stale, (
        f"KNOWN_BREAKS 里这些条目已不再复现，请核实后删除：{stale}"
    )
    undocumented = sorted(bad - set(KNOWN_BREAKS))
    assert not undocumented, f"新增断链未登记：{undocumented}"


@pytest.mark.xfail(
    strict=True, raises=AssertionError,
    reason="已知缺口 2 条：api.ts 的 opsFeedbackList(GET /feedback，"
           "后端只有 POST) 与 opsFeedbackReview(POST /feedback/{id}/review，"
           "后端无此路由)。二者前端均无调用方，线上无感，属死代码+契约漂移。"
           "处置需用户决策：删除这两个客户端方法，还是补后端实现。",
)
def test_no_known_contract_breaks():
    """[缺口] 前端不该存在必然失败的请求。

    断言的是**实测断链集合**而不是 `KNOWN_BREAKS` 登记表本身 ——
    盯登记表的话，代码修好后它永远不会 XPASS，这条守卫就成了摆设。
    盯事实的话，修好前端即 XPASS，强制同时销号，两步缺一不可。
    """
    bad = _breaks()
    assert not bad, (
        "前端存在必然失败的请求：\n"
        + "\n".join(f"  {k}: {KNOWN_BREAKS.get(k, '未登记')}" for k in sorted(bad))
    )


def test_dead_broken_client_methods_have_no_callers():
    """前提守卫：登记的断链方法若「其实有调用方」，严重级别要重估。

    本轮这两条之所以只是 xfail 而不是缺陷，正是因为它们零调用方。
    一旦有人接上，405/404 就变成线上故障，必须让这条转红提醒重估。
    """
    for method in ("opsFeedbackList", "opsFeedbackReview"):
        hits = []
        for p in sorted(FE.rglob("*")):
            if p.suffix not in (".ts", ".tsx") or p.name == "api.ts":
                continue
            if method in p.read_text(encoding="utf-8-sig", errors="replace"):
                hits.append(str(p.relative_to(REPO)))
        assert not hits, (
            f"{method} 已有调用方 {hits} —— "
            "它现在会真的发出 405/404 请求，KNOWN_BREAKS 的严重级别需上调为缺陷"
        )


# ════════════════════════════════════════════════════════════
# 反方向：后端声明了路由，有没有消费方
# ════════════════════════════════════════════════════════════
#: DLQ 的四个端点。逐条手工核实过：**整个 frontend/src 里没有一处
#: `dlq` 出现在 fetch / fetchJSON / EventSource / api.* 的实参里**。
DLQ_ROUTES = ("/api/dlq", "/api/dlq/{}", "/api/dlq/{}/replay", "/api/dlq/{}/dry-run")


def test_dlq_endpoints_all_exist_on_the_backend():
    """前提守卫：DLQ 四个端点确实都在，否则下面的「够不着」就没有意义。"""
    paths = {p for p, _ in backend_routes()}
    missing = [r for r in DLQ_ROUTES if r not in paths]
    assert not missing, f"DLQ 端点不存在，与实测不符：{missing}"


def test_dlq_has_exactly_one_reference_and_it_is_the_rate_limit_table():
    """前提守卫：钉住「DLQ 除了限流表没有别的消费方」这个判断的依据。

    逐个可执行文件扫过（排除 routers/ 定义处、tests/ 目录与本文件），
    `/api/dlq` 只在 `http_guards.py` 的限流点名表里出现过一次。
    排除 tests/ 是因为 `test_http_guards.py` / `test_route_classification.py`
    里也写着这个路径 —— 那是限流夹具，不是消费方。
    哪天有人给它接上 UI 或脚本，这条会转红提醒更新结论。
    """
    me = Path(__file__).resolve()
    hits = []
    for p in sorted(REPO.rglob("*")):
        if p.suffix not in (".py", ".ts", ".tsx"):
            continue
        if "node_modules" in p.parts or "routers" in p.parts or "tests" in p.parts:
            continue
        # 2026-10-23: OpenAPI 类型生成物是 schema 的机械投影 —— 它必然包含
        # 全部 211 个端点路径, 不是"消费方"。按后端端点接 UI 时本守卫仍会转红。
        if p.name == "api-generated.ts":
            continue
        if p.resolve() == me:
            continue
        if "/api/dlq" in p.read_text(encoding="utf-8-sig", errors="replace"):
            hits.append(str(p.relative_to(REPO)))
    assert hits == ["backend" + os.sep + "http_guards.py"], (
        f"DLQ 出现了新的引用方 {hits} —— 「无 UI 入口」的结论需要重新评估"
    )


@pytest.mark.xfail(
    strict=True, raises=AssertionError,
    reason="已知缺口：DLQ 四个端点（列表 / 详情 / replay / dry-run）后端齐全，"
           "但前端零入口 —— 死信重放是 DLQ 这套机制存在的理由，"
           "却是运维唯一做不了的操作。仓库内唯一提到 /api/dlq 的地方是 "
           "http_guards.py 的限流点名表。与 §7.1.5 的休眠能力清单同源，"
           "接线优先级待用户决策。",
)
def test_dlq_replay_is_reachable_from_the_ui():
    """[缺口] DLQ 必须有 UI 入口 —— 尤其是重放。"""
    fe = {p for p, _, _ in frontend_calls()}
    assert any(p.startswith("/api/dlq") for p in fe), (
        "前端没有任何 /api/dlq 调用 —— DLQ 在 UI 上完全不可达"
    )
