"""情报能力链缺了一整段：没有任何东西往 `threat_iocs` 写数据（本轮新增）

## 缺口

`threat_intel` 的链路应该是这样：

```
TAXII/MISP ──poll_feed──> IOC 列表 ──落库──> threat_iocs 表 ──ioc_matcher──> 事件匹配
```

本轮逐段核实（多路交叉验证）：

| 环节 | 状态 | 证据 |
|---|---|---|
| `TaxiiClient.poll_feed` 拉取 | ❌ 生产零调用方 | 全仓（排除 tests）只有 `stix_taxii.py` 自己的 docstring 提到它 |
| **落库** | ❌ **完全不存在** | `stix_taxii.py` 全文只有 4 处 `session`，全是 `aiohttp.ClientSession`（HTTP 客户端），**没有任何 DB 持久化** |
| `ioc_matcher` 匹配 | ⚠ 代码在、也接线了，但**读到的永远是空表** | `ioc_matcher.py:85` `select(ThreatIoc).where(is_active==True)` |

`threat_iocs` 这个表名在全仓（排除 tests / .git / node_modules / target）
只出现在三处：`models.py:666` 建表定义、`ioc_matcher.py` 的 SELECT、
`init.sql:294-320` 的 DDL 与索引。**零 INSERT。**

## 为什么这条比「休眠」严重

`test_dormant_modules_guard.py` 把 `stix_taxii` 登记成 `dormant`，
整改报告里也写过「接线 `threat_intel/stix_taxii.py` 即可解掉 §7.1.4 / §6.3.1 的缺口」。

**那是错的。** 就算把拉取侧接线，`poll_feed` 也只 `return` 一个 list，
不写库 —— 于是 `ioc_matcher` 依然读到空表，**匹配依然一次都不会命中**。

这不是「一段没被测过」，是**一段根本不存在**。
两者的区别很实际：前者补测试即可，后者要先定「谁负责落库」。

## 为什么用 strict xfail 而不是直接补

落库这件事有真实的设计决策，不是顺手能定的：

* 落库归 `poll_feed`（拉取即持久化）还是归调用方？
* 同一 `ioc_value` 重复拉取时 upsert 还是 skip？`stix_id` 冲突怎么办？
* `is_active` / `expires_at` 谁维护？过期 IOC 怎么淘汰？

和 §7.1.4 的零日链一样，这个决定该由用户做，不该由一次审计代拍。
所以用 strict xfail 把它钉成**可见**的缺口，接线即转红。

## 前提守卫（必须常绿）

* `ioc_matcher` 确实**读**这张表 —— 否则「没人写」可能是因为「没人读」；
* `poll_feed` 确实**不**落库 —— 否则这条缺口描述就过时了。
  这两条任一转红，本文件的结论都需要重新评估。
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

BACKEND = Path(__file__).resolve().parents[1]
STIX = BACKEND / "threat_intel" / "stix_taxii.py"
IOC_MATCHER = BACKEND / "threat_intel" / "ioc_matcher.py"
SKIP_DIRS = ("tests", "eval_datasets", "tools")


def _prod_files():
    return [p for p in sorted(BACKEND.rglob("*.py"))
            if not p.relative_to(BACKEND).as_posix().startswith(SKIP_DIRS)]


def _src(p: Path) -> str:
    return p.read_text(encoding="utf-8", errors="ignore")


# ═══════════════════════════════════════════
# 前提守卫
# ═══════════════════════════════════════════

def test_ioc_matcher_really_reads_the_threat_iocs_table():
    """前提①：匹配侧确实**读**这张表。

    没有这条，「没人写」可能只是因为「没人读」——
    那这张表压根不参与链路，缺口的性质就变了。
    """
    src = _src(IOC_MATCHER)
    assert "ThreatIoc" in src, "ioc_matcher 不再使用 ThreatIoc 模型，结论需重新评估"
    assert re.search(r"select\(\s*ThreatIoc\s*\)", src), (
        "ioc_matcher 不再从 threat_iocs 表 SELECT —— "
        "要么它换了数据源（那本文件整节作废），要么匹配侧断了（那是另一个缺口）"
    )
    assert "is_active" in src, "查询没有过滤 is_active，语义已变"


def test_poll_feed_really_does_not_persist():
    """前提②：`poll_feed` 确实**不**落库。

    这是本文件论断的基础。一旦有人给它加了落库，这条转红，
    意味着「缺一环」的说法过时了，缺口清单要改。
    """
    tree = ast.parse(_src(STIX))
    poll = None
    for node in ast.walk(tree):
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "poll_feed":
            poll = node
            break
    assert poll is not None, "poll_feed 不存在了，本文件的缺口描述已过时"

    body = _src(STIX).splitlines()[poll.lineno - 1: poll.end_lineno]
    body_src = "\n".join(body)
    persist_markers = (
        r"\badd\s*\(",          # Session.add
        r"\bcommit\s*\(",
        r"\bflush\s*\(",
        r"bulk_save_objects",
        r"INSERT\s+INTO",
        r"\bThreatIoc\b",
        r"async_session|get_session|SessionLocal",
    )
    hits = [p for p in persist_markers if re.search(p, body_src, re.IGNORECASE)]
    assert not hits, (
        f"poll_feed 现在会落库了（命中 {hits}）—— "
        "「链路缺一环」的说法已过时，请更新本文件与整改报告 §7.1.8，"
        "并把 test_dormant_modules_guard 里 stix_taxii 的理由改掉"
    )


def test_feed_registry_status_fields_have_a_writer():
    """2026-10-21：`last_poll_*` 现在由 `/api/intel/feeds/{id}/poll` 写入。

    此前它是只读冻结字段；现在拉取成功后更新 `last_poll_at/status/count`。
    本条从“缺口守卫”转为“接线守卫”。
    """
    src = _src(BACKEND / "routers" / "edr_intel.py")
    assert re.search(r"last_poll_(?:at|status|count)\s*=", src), (
        "情报源拉取端点不再写 last_poll_* —— 轮询状态会重新冻结"
    )


def test_frontend_intel_page_really_displays_that_frozen_field():
    """前提④：前端 `Intel.tsx` 确实把这个永远不变的字段显示出来。

    这是「最隐蔽的失效形态」的直接证据：
    页面存在、能请求、返回结构良好的 JSON，只是**每个数字都是冻结的**。
    若哪天前端不再展示它，本条转红，严重性需要重估（变成纯后端问题）。
    """
    page = BACKEND.parent / "frontend" / "src" / "pages" / "Intel.tsx"
    assert page.exists(), "frontend/src/pages/Intel.tsx 不存在了，前提需重新评估"
    src = page.read_text(encoding="utf-8", errors="ignore")
    assert "last_poll_status" in src, "前端不再展示 last_poll_status"
    assert "/intel/feeds" in src, "前端不再拉取 /intel/feeds"


# ═══════════════════════════════════════════
# 主断言：必须存在一个把 IOC 写进 threat_iocs 的生产路径
# ═══════════════════════════════════════════

def test_something_persists_iocs_into_the_threat_iocs_table():
    """必须存在一个把 IOC 写进 `threat_iocs` 的生产路径。

    2026-10-21：已实现 `threat_intel/ioc_ingest.py`（`ThreatIoc(...)`），
    并由 `/api/intel/iocs` 与 `/api/intel/feeds/{id}/poll` 调用。
    `poll_feed` 仍保持纯拉取，不直接落库。
    """
    writers = []
    for py in _prod_files():
        rel = py.relative_to(BACKEND).as_posix()
        if rel == "models.py":            # 只有表定义，不是写入方
            continue
        src = _src(py)
        if re.search(r"INSERT\s+INTO\s+[\"'`]?threat_iocs", src, re.IGNORECASE):
            writers.append(f"{rel}  (SQL INSERT)")
        # 构造器：ThreatIoc(...) / insert(ThreatIoc) / insert(ThreatIoc).values(...)
        if re.search(r"\bThreatIoc\s*\(", re.sub(r"^class\s+ThreatIoc.*$", "", src, flags=re.M)):
            writers.append(f"{rel}  (实例化 ThreatIoc)")
        elif re.search(r"insert\s*\(\s*ThreatIoc\b", src):
            writers.append(f"{rel}  (insert(ThreatIoc))")
    assert writers, (
        "全仓找不到任何把 IOC 写进 threat_iocs 的生产路径 —— "
        "`ioc_matcher` 读到的永远是空表，IOC 匹配在生产里一次都不会命中"
    )


@pytest.mark.parametrize("name", [
    "threat_intel/intel_enricher.py",
    "threat_intel/llm_context.py",
])
def test_intel_pipeline_modules_are_all_still_unwired(name):
    """守卫本文件的前提：这三块仍处于休眠状态。

    一旦它们被接线，本文件关于「链路缺一环」的描述需要重新评估
    （可能是修好了，也可能是缺口的形状变了）。
    """
    assert name in _dormant_paths(), (
        f"{name} 不再被登记为休眠 —— 若它刚被接线，请重新核实"
        f"「threat_iocs 没有写入方」这个结论是否依然成立"
    )


def _dormant_paths() -> set[str]:
    guard = Path(__file__).with_name("test_dormant_modules_guard.py")
    src = guard.read_text(encoding="utf-8")
    return set(re.findall(r'\("([a-z_]+/[a-z_]+\.py|[a-z_]+\.py)"', src))
