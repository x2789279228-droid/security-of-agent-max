"""沙箱任务记录是一条死胡同：创建之后没有任何东西更新它（本轮新增）

## 链路

```
POST /api/sandbox/submit
   └─ sandbox.submit_url(url)              ✅ 真实提交给 CAPE/Cuckoo
   └─ SandboxTask(status="pending")        ✅ 写入 DB —— 但到此为止
                     ⋮（沙箱异步分析完成）
   └─ sandbox_connector._finish()          ✅ 拿到报告，只在内存（line 501-518）
   └─ ？？？                               ❌ 无回调 / 无事件 / 无持久化桥
                     ↓
GET /api/sandbox/tasks  →  status 恒为 "pending"
                          verdict / score / behavior_summary /
                          mitre_techniques / network_iocs 恒为空
```

## 证据

* `SandboxTask` 在全仓（排除 tests）只有三处引用：
  `models.py:710` 类定义、`routers/edr_intel.py:178-181` 的 SELECT、
  `routers/edr_intel.py:223` 的一次性创建。
  **没有任何 UPDATE 路径**，原始 SQL 也搜不到（`UPDATE ... sandbox` 零命中）。
* `routers/edr_intel.py` 全文 229 行，路由到 `POST /sandbox/submit` 结束 ——
  不存在轮询协程。（整改报告 §7.1.4 曾把「轮询」标在 `routers/edr_intel.py:237`，
  该行号并不存在，已更正。）
* `sandbox_connector.py` 全文**零** `callback` / `on_complete` / `event_bus` /
  `publish` / `subscribe` / `notify` 出口 —— `_finish()` 拿到报告后无处可送。

## 与 Intel 那条是同一个形态（本会话发现的第二个实例）

| | Intel（§7.1.8） | 沙箱（本文件） |
|---|---|---|
| 写入方 | **完全没有** | 有，但只写一次 |
| 读接口冻结在 | `last_poll_status="idle"` | `status="pending"` |
| 前端 | **显示**冻结值 | **隐藏**空字段，只留永久 `pending` |

共同点：**完整搭好的 UI + API，建立在一层永远不会被完成的数据上。**
沙箱这条危险度略低 —— 前端是防御性的（`{t.verdict && ...}`、`{t.score > 0 && ...}`），
不会谎报「clean / 0 分」；但用户看到的是**永远的 pending**，
无法区分「正在排队」和「从没有被处理过」。

## 为什么用 strict xfail

把结果写回 `SandboxTask` 需要真实设计决策：谁负责轮询（router 协程 / scheduler /
连接器内部）？`sandbox_api_key` 等凭据怎么传？失败重试与超时怎么落？
这和 §7.1.4 的零日链接线一样，不该由一次审计代拍。

所以用 strict xfail 钉住：一旦有人补上更新路径，XPASS(strict) 立刻转红，
强制回来改本文件与报告 §7.1.9。
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

BACKEND = Path(__file__).resolve().parents[1]
ROUTER = BACKEND / "routers" / "edr_intel.py"
CONNECTOR = BACKEND / "zeroday_detect" / "sandbox_connector.py"
MODELS = BACKEND / "models.py"
SANDBOX_PAGE = BACKEND.parent / "frontend" / "src" / "pages" / "Sandbox.tsx"
SKIP_DIRS = ("tests", "eval_datasets", "tools")

ANALYSIS_FIELDS = ("verdict", "score", "behavior_summary",
                   "mitre_techniques", "network_iocs")


def _src(p: Path) -> str:
    return p.read_text(encoding="utf-8", errors="ignore")


def _prod_files():
    return [p for p in sorted(BACKEND.rglob("*.py"))
            if not p.relative_to(BACKEND).as_posix().startswith(SKIP_DIRS)]


# ═══════════════════════════════════════════
# 前提守卫 —— 每条都写明「转红意味着什么」
# ═══════════════════════════════════════════

def test_sandbox_task_is_really_created_by_the_submit_endpoint():
    """前提①：`POST /sandbox/submit` 确实会写 `SandboxTask`。

    若哪天改成不落库（只返回 task_id），本缺口的形状就变了，
    应当重新评估而不是继续引用本文件。
    """
    src = _src(ROUTER)
    assert re.search(r"SandboxTask\s*\(", src), (
        "POST /sandbox/submit 不再创建 SandboxTask —— "
        "「死胡同记录」的形态可能已变，请重新核实"
    )
    assert re.search(r'SandboxTask\([^)]*status\s*=\s*"pending"', src, re.S), (
        "新建记录不再是 status='pending'，请重新核实后续是否会被更新"
    )


def test_sandbox_connector_really_has_no_completion_callback():
    """前提②：连接器确实**没有**任何完成回调/事件出口。

    这是「报告无处可送」的基础。一旦有人加了回调或事件发布，
    本条转红，缺口的描述需要相应更新。
    """
    src = _src(CONNECTOR)
    outlets = re.findall(
        r"\b(callback|on_complete|on_report|event_bus|publish|subscribe|notify)\b", src)
    assert not outlets, (
        f"sandbox_connector 出现了出口 {set(outlets)} —— "
        "沙箱完成结果现在有地方可送了，请重新核实本缺口的形状"
    )


def test_analysis_fields_are_only_computed_in_the_dormant_analyzer():
    """前提③：沙箱分析字段**没有任何活跃的生产写入方**。

    这是「这些字段永远为空」的根因。若哪天活跃模块开始产出它们，
    本条转红，缺口需要重新评估。

    ## 判据为什么锚在「提到 SandboxTask 的那一行」

    第一版写成「扫描所有模块找 `<obj>.field = `」——
    那是**对象无关**的匹配，于是 `agents/agent_executor.py` 的
    `audit_result.verdict = ...`、`phishing_guard/scoring.py` 的 `.score = `
    全被判成「产出沙箱分析字段」。与 §8.3 那个文件级启发式是同一个错。

    正确的判据：**要写一行 `SandboxTask`，就必须提到 `SandboxTask`** ——
    无论是构造它，还是从查询里取出来。而 `SandboxTask` 在生产代码里
    只有 7 处出现（类定义 / 2 个 import / SELECT / WHERE 过滤 / 1 次构造 / 1 条
    docstring），**没有一处是「取出对象再改字段」的形态**。
    所以不需要类型推断就能判定：无更新路径。
    """
    offenders = []
    for py in _prod_files():
        rel = py.relative_to(BACKEND).as_posix()
        src = _src(py)
        for i, line in enumerate(src.splitlines(), 1):
            if "SandboxTask" not in line:
                continue
            # 同一行既提到 SandboxTask，又在做真实的字段赋值（排除 == 比较）
            for f in ("status",) + ANALYSIS_FIELDS:
                if re.search(rf"\.\s*{f}\s*=(?!=)", line):
                    offenders.append(f"{rel}:{i}  {line.strip()[:80]}")
    assert not offenders, (
        f"有代码在给 SandboxTask 写字段了：{offenders} —— "
        "「字段恒空」的说法已过时，请更新本文件与报告 §7.1.9"
    )


def _sandbox_task_mentions() -> list[tuple[str, int, str]]:
    out = []
    for py in _prod_files():
        rel = py.relative_to(BACKEND).as_posix()
        for i, line in enumerate(_src(py).splitlines(), 1):
            if "SandboxTask" in line:
                out.append((rel, i, line.strip()))
    return out


def test_frontend_sandbox_page_is_defensive_about_empty_fields():
    """前提④：前端确实**隐藏**空字段，而不是显示 0/空。

    这决定了本缺口的危险等级：防御性写法只是「永远 pending」，
    非防御性写法会**谎报 clean / 0 分**。若哪天改成后者，
    严重性要上调，本文件结论需改写。
    """
    assert SANDBOX_PAGE.exists(), "frontend/src/pages/Sandbox.tsx 不存在，前提需重估"
    src = _src(SANDBOX_PAGE)
    for f in ("verdict", "behavior_summary"):
        assert re.search(rf"\{{t\.{f}\s*&&\s*\(", src), (
            f"Sandbox.tsx 不再条件渲染 {f} —— 若改成无条件显示，"
            "空值会变成假数据，严重性要上调"
        )
    assert re.search(r"\{\s*t\.score\s*>\s*0\s*&&\s*\(", src), (
        "Sandbox.tsx 不再用 score>0 过滤，空 score 可能被显示为 0.0"
    )


# ═══════════════════════════════════════════
# 主断言：必须存在把结果写回 SandboxTask 的生产路径
# ═══════════════════════════════════════════

@pytest.mark.xfail(
    strict=True, raises=AssertionError,
    reason="已知缺口：SandboxTask 创建后没有任何生产路径更新它 —— "
           "verdict/score/behavior_summary 恒空、status 恒 pending。见整改报告 §7.1.9",
)
def test_sandbox_task_results_get_persisted_back():
    """沙箱完成后必须有人把 verdict/score/behavior_summary 写回 `SandboxTask`。

    **接线 `behavior_analyzer` 不足以让这条转绿** ——
    §7.1.4 已确认它零生产调用方；而且即便分析结果算出来，
    也没有任何通道把它送到这张表。

    判据用**必要条件**而非类型推断：能改一行 `SandboxTask` 的代码，
    必然（a）在某个提到 `SandboxTask` 的文件里，且（b）含一处对
    `status` / 分析字段的真实赋值（`==` 比较不算）。

    ## 断言方向（这里错过一次，值得写下来）

    `strict=True` 的 xfail 语义是：

    * **缺口修好** → 测试应当**通过** → XPASS(strict) → 转红，强制摘标记；
    * **缺口还在** → 测试**失败** → XFAIL。

    所以正文必须写成**正向断言**（`assert updaters, "<缺口描述>"`）。
    第一版写成了 `assert False, "出现了 .status = 赋值"` ——
    那是**反方向**：缺口修好时它失败，被当成「预期的失败」记成 XFAIL，
    于是**永远没人会被提醒**。它看起来一直正常，实际从不报警。
    """
    updaters = []
    for rel, _i, _line in _sandbox_task_mentions():
        if rel == "models.py":
            # 定义文件：它有全仓所有模型的 Column 默认值。
            # `status = Column(String(30), default="pending")` 是**列定义**，
            # 不是对某一行数据的写入。把它算进来会让这条用例因为
            # 别的模型而误报（第一版就栽在 `models.py:245` 上）。
            continue
        src = _src(BACKEND / rel)
        for f in ("status",) + ANALYSIS_FIELDS:
            for m in re.finditer(rf"\.\s*{f}\s*=(?!=)", src):
                line_no = src[: m.start()].count("\n") + 1
                updaters.append(f"{rel}:{line_no}:{f}")

    assert updaters, (
        "全仓找不到任何把沙箱分析结果写回 SandboxTask 的生产路径 —— "
        "`GET /sandbox/tasks` 返回的每一行都会是 "
        "status='pending' + verdict='' + score=0.0 + behavior_summary=''，"
        "而 `frontend/src/pages/Sandbox.tsx` 只会永远显示一个 pending 徽章"
    )


def test_sandbox_task_is_created_exactly_once_and_never_updated():
    """反向检查：`SandboxTask(...)` 在生产代码里只出现一次，且那一处不带分析字段。

    与上面那条互为对照 —— 正面断言「存在更新路径」，这里从
    「唯一的构造点长什么样」反向确认。两条不能互相替代。
    """
    sites = [m for m in _sandbox_task_mentions()
             if re.search(r"SandboxTask\s*\(", m[2]) and "class " not in m[2]]
    assert len(sites) == 1, (
        f"生产代码里有 {len(sites)} 处 SandboxTask(...) 构造（预期 1）："
        f"{[s[0] + ':' + str(s[1]) for s in sites]}"
    )
    rel, line_no, _ = sites[0]
    assert rel == "routers/edr_intel.py", (
        f"构造点换到了 {rel} —— 本缺口的形状可能变了，请重新核实"
    )
    # 该构造点的实参里不能有分析字段
    src = _src(BACKEND / rel)
    start = src.index("SandboxTask(")
    depth, end = 0, start
    for j in range(start, len(src)):
        if src[j] == "(":
            depth += 1
        elif src[j] == ")":
            depth -= 1
            if depth == 0:
                end = j + 1
                break
    ctor = src[start:end]
    for f in ANALYSIS_FIELDS:
        assert not re.search(rf"\b{f}\s*=", ctor), (
            f"创建时就会写入 {f} —— 「字段恒空」已不成立"
        )
