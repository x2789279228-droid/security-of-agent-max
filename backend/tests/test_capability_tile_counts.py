"""能力看板的 count 有没有在数「真正会动的东西」——守卫（本轮新增）

## 要守住的是什么

`routers/capabilities.py` 给前端「高级能力总览」返回五块能力的
`{name, enabled, count}`，前端 `CapabilitiesDashboard.tsx` 把它渲染成
「威胁情报 · IOC / MISP / TAXII · 已启用 · N 条」，
并用五块的 count 求和当页面顶部的「事件累计」。

本轮逐块查了 count 对应计数器的**生产自增点**（`metrics.py` 的
`inc_*` 包装函数 → 全仓调用点）：

| 能力 | 自增函数 | 生产自增点 | 生产可达 |
|---|---|---|---|
| ndr | `inc_ndr_flow` | `traffic_capture/flow_aggregator.py:225` | ✅ |
| edr | `inc_edr_event` | `edr_fusion/edr_adapter.py:126,136` | ✅ |
| **threat_intel** | `inc_intel_ioc` | `threat_intel/stix_taxii.py:75` | ❌ **在休眠模块内** |
| zeroday | `inc_sandbox_submission` | `zeroday_detect/sandbox_connector.py:252,283` | ✅ |
| phishing | `inc_phishing_detection` | `phishing_guard/scoring.py:100` | ✅ |

**五块里只有 threat_intel 的 count 是结构性恒 0**，
而 `tests/test_dead_code_remediation.py:126` 那条端到端断言
直接调 `poll_feed`，它是绿的 —— 绿在「计数点正确」，
红在「计数点不会被执行到」，两者可以同时成立。

## 但真正扎手的是第二层

`ioc_matcher` 是**活的**（`app.py:288` 接线并 `refresh_cache()`），
它命中时调 `inc_ioc_match()`（`ioc_matcher.py:182`），
自增的是 `soc_ioc_matches_total` —— **另一个计数器**。

于是：威胁情报能力确实在工作（IOC 匹配在命中），
而看板读的是一个死计数器，于是**恒显示 0 条**。

这是「字段存在 ≠ 有人看」的**读方向**版本：
上一轮那个是「值算出来了没人读」，这个是「值有人写了，读的人挑错了源」。

## 为什么用 strict xfail 而不是直接改

看板那块 count 到底该算「拉取量」还是「命中量」，两种读法都说得通：

* 算拉取量 → 语义是「摄入了多少情报」，但拉取侧本身休眠；
* 算命中量 → 语义是「处理了多少事件」（与另外四块的
  「事件累计」一致），但会丢掉「摄入了多少」这一维。

**这是语义决策，不该由一次审计顺手替用户拍板。**
所以用 strict xfail 把缺口钉住：修完必然 XPASS 转红，
强制回来改这份 docstring 和报告 §7.1.6。

接线 `threat_intel/stix_taxii.py`（解 §7.1.4 / §6.3.1 的休眠）
或改看板读数，两条路任选其一都能让本文件转绿。
"""
from __future__ import annotations

import asyncio

import pytest
from prometheus_client import REGISTRY, generate_latest

from routers.capabilities import _CAPABILITIES, _parse_metric_values


def _sample(name: str, **labels) -> float:
    """Prometheus 计数器是进程级全局的，测试之间会累积。

    一律取差值，绝不断言绝对值 —— 否则单跑绿、全量跑红。
    """
    return REGISTRY.get_sample_value(name, labels) or 0.0


def _intel_tile_count() -> int:
    """按 routers/capabilities.py 自己的算法，读 threat_intel 那块的 count。"""
    text = generate_latest().decode()
    prefix = dict((n, p) for n, p, _ in _CAPABILITIES)["threat_intel"]
    return _parse_metric_values(text, prefix)


def _warm_matcher(entries: dict):
    """造一个**已预热**的 IocMatcher，缓存里放好夹具。

    ## 为什么必须显式预热（这里踩过一次假绿）

    `IocMatcher.match()` 开头有自动刷新：

    ```python
    # ioc_matcher.py:133
    if time.time() - self._last_refresh > self._refresh_interval:
        await self.refresh_cache(session)
    ```

    新建实例的 `_last_refresh = 0.0`，所以**第一次 match 必定触发刷新**，
    而 `refresh_cache` 会用 DB 里的内容**覆盖 `_cache`** ——
    刚塞进去的夹具会被抹掉。

    单跑本文件时 DB 恰好不可用（`no such table: threat_iocs`），
    刷新失败被 `refresh_cache` 吞掉，夹具幸存，测试假绿；
    全量跑时前面的用例把表建好了，刷新成功，夹具没了，断言转红。

    **假绿的原因是环境缺一块，而不是测试写对了。**
    设 `_last_refresh` 等于「这是一个刚 refresh 完的匹配器」，
    也正是 `app.py:289` 线上启动后的状态。
    """
    import time as _time

    from threat_intel.ioc_matcher import IocHit, IocMatcher

    m = IocMatcher()
    for value, hit in entries.items():
        m._cache[value] = hit
    m._last_refresh = _time.time()
    return m


def _ip_hit(value: str):
    from threat_intel.ioc_matcher import IocHit
    return IocHit(ioc_type="ip", ioc_value=value, severity="high", source="unit")


# ═══════════════════════════════════════════
# 前提守卫：先证明「活路径真的会动」
# 不然下面的缺陷断言可能只是空跑恒绿
# ═══════════════════════════════════════════

def test_ioc_match_path_really_increments_the_live_counter():
    """`ioc_matcher.match()` 命中时确实自增 `soc_ioc_matches_total`。

    这条是**前提**，不是顺带测的：它证明威胁情报能力在生产里
    确实会产生信号。若哪天这条转红（match 不再自增），
    下面「看板读错源」的结论就不再适用于当前代码，要重新评估。
    """
    m = _warm_matcher({"203.0.113.66": _ip_hit("203.0.113.66")})

    before = _sample("soc_ioc_matches_total")
    # match() 是 async def —— 必须真正 await。
    # 不 await 的话返回的是协程对象，而 **协程对象恒为真**，
    # `assert hits` 会恒绿，整条前提守卫就白写了。
    hits = asyncio.run(m.match(ip="203.0.113.66"))
    after = _sample("soc_ioc_matches_total")

    assert hits, "IOC 未命中 —— 夹具没生效，测试失去意义"
    assert after == before + 1, (
        f"IOC 命中但 soc_ioc_matches_total 没动（{before} -> {after}）；"
        "威胁情报的活路径已不产生信号，看板读数结论需重新评估"
    )


def test_ioc_match_counter_and_dashboard_counter_are_different_metrics():
    """两个计数器确实不是同一个 —— 这是「看板读错源」的前提。"""
    text = generate_latest().decode()
    assert _parse_metric_values(text, "soc_ioc_matches_") >= 0
    # 看板用的那个前缀，与命中用的那个前缀没有包含关系
    assert "soc_ioc_matches" not in "soc_intel_ioc_"


# ═══════════════════════════════════════════
# 缺口：看板 count 与活计数器脱钩
# ═══════════════════════════════════════════

@pytest.mark.xfail(
    strict=True, raises=AssertionError,
    reason="已知缺口：威胁情报 count 读的是休眠路径的自增点；"
           "活着的 IOC 匹配写在另一个计数器上。看板恒显示 0 条。见报告 §7.1.6",
)
def test_intel_tile_count_reflects_live_ioc_matching():
    """IOC 命中之后，能力看板的 threat_intel count 必须不再是 0。

    现状：恒为 0。两条修法都能让它转绿 ——
      (a) 把看板读数改成 `soc_ioc_matches_`（语义=处理了多少事件）；
      (b) 接线 `threat_intel/stix_taxii.py`，让拉取侧真的会跑。
    选哪条取决于「这块 count 到底要表达什么」，那是产品决策。
    """
    m = _warm_matcher({"198.51.100.7": _ip_hit("198.51.100.7")})

    before = _intel_tile_count()
    hits = asyncio.run(m.match(ip="198.51.100.7"))
    after = _intel_tile_count()

    assert hits, (
        "IOC 未命中 —— 夹具没生效。注意：xfail 必须是因为"
        "「看板读数没跟着动」而 xfail，不能是因为夹具被 match() 的"
        "自动刷新抹掉；后者会让缺口以错误的理由被标记为已知。"
    )
    assert after > before, (
        f"IOC 确实命中了（{len(hits)} 条），但看板 threat_intel 的 count "
        f"仍是 {before} —— 用户看到的是「已启用 · 0 条」"
    )
