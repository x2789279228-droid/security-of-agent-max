"""MCP Guard 的签名/偏离是纯进程内状态，持久化脚手架铺了四层只差写入（本轮新增）

## 缺口

`tool_signatures` / `tool_anomalies` 两张表在 schema 里完整存在
（`models.py:1013/1024` + `init.sql:649/658`，含索引），
但**零生产写入方、零生产读取方**。

本轮把「找无写入方的 ORM 表」这个查法系统化（扫全仓 50 个模型）时发现的，
和 §7.1.8（`threat_iocs`）、§7.1.9（`SandboxTask`）同族。

## 关键：这不是「面板坏了」

`ToolSignaturePanel.tsx` 调的 4 个端点**都在**，且**不读这两张表**：

| 前端调用 | 后端端点 | 实际数据源 |
|---|---|---|
| `api.guardStatus()` | `routers/audit.py:52` | `mcp_guard.detector` + `log.stats()` |
| `api.guardSignatures()` | `routers/audit.py:147` | `det.list_signatures()` → `self._signatures`（进程内 dict） |
| `api.guardAnomalies(40)` | `routers/audit.py:155` | `det.recent_anomalies()` → `self._anomalies`（进程内 deque） |
| `api.guardCall(...)` | `http_guards.py:/api/guard/call` | 内存 + 审批队列 |

所以面板**正常工作**，只是它展示的东西活不过一次重启。
把这条写成「用户可见故障」会是夸大 —— 前提守卫①钉住这一点。

## 真正的问题是「声明了持久性但运行时没有」

持久化在**四个层面都铺好了**，只有写入那一层没写：

1. **表**：`models.py:1013/1024` + `init.sql:649/658`（含两个索引）
2. **配置**：`config.py:294-302` 共 9 个 `tool_signature_*` / `tool_call_log_persist` 开关，
   `.env.example:114-122` 逐个出货
3. **构造器钩子**：`behavior_detector.py:154` `persist: bool = False` 参数、
   `:172` `self.persist = persist`、`:173` `self._dirty: set[tuple[str,str]] = set()`、
   `:462` `self._dirty.add((rec.tool_name, caller_key))`、`:185` `reset()` 里 `self._dirty.clear()`
4. **保留期**：`tool_signature_log_retention_days: int = 180`

**缺的是**：把 `_dirty` 里的条目 flush 到 DB 的那段代码。

量出来的三处「铺好但没接线」：

* `self.persist` **存进去之后再没有被读过**（全文件仅 `:154` `:172` 两处，都是赋值/定义）
* `self._dirty` **只 `.add()` / `.clear()`，从不被读** —— 一个给持久化循环用的脏表，没人消费
* `tool_signature_log_retention_days` 是 9 个签名开关里**唯一零读点**的

而且全仓唯一的生产实例化 `guard_server.py:89` 是裸的 `BehaviorDetector()` ——
**连 `persist` 都没传**。全仓也**没有任何一处** `BehaviorDetector(..., persist=True)`：
测试里的实例化要么写死 `persist=False`，要么省略走默认值 `False`。

## 为什么用 strict xfail

接不接、要不要接，是产品决策：

* 签名要跨重启存活吗？（要，则需落库；不要，则该删表+删配置，别留着假装有）
* 偏离历史要留多久？（`log_retention_days=180` 已经承诺了 180 天）
* 冷启动窗口（需 `min_samples=30` 样本）期间该 fail-open 还是 fail-closed？

这些不该由一次审计代拍，用 strict xfail 钉成可见缺口，接线即转红。

## 前提守卫（必须常绿）

* ①面板端点读的是进程内存而非这两张表 —— 否则这条会从「持久化缺口」变成「面板故障」
* ②冷启动是**诚实**的（`cold_start=True` / `action="logged"` / `anomaly_score=None`）
  —— 这是**运行时**断言。这是本条与 §7.1.9 最大的区别：
  `Sandbox.tsx` 是「永远 pending」让人误以为在跑，而 guard 明确承认自己冷启动。
  如果哪天冷启动改成 `is_anomaly=False` 且**不再**标 `cold_start`，
  那才是真正的静默失效，本文件会红。
* ③`tool_call_log` **确实**落库了 —— 对照组。
  没有它，「mcp_guard 不碰 DB」这个更宽的说法会把 `ToolCallLog` 也牵连进来。
"""
from __future__ import annotations

import os
import re
import sys
from pathlib import Path

import pytest

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

DETECTOR = BACKEND / "mcp_guard" / "behavior_detector.py"
CALL_LOGGER = BACKEND / "mcp_guard" / "call_logger.py"
AUDIT_ROUTER = BACKEND / "routers" / "audit.py"
CONFIG = BACKEND / "config.py"
SKIP_DIRS = ("tests", "eval_datasets", "tools")


def _prod_files():
    return [p for p in sorted(BACKEND.rglob("*.py"))
            if not p.relative_to(BACKEND).as_posix().startswith(SKIP_DIRS)]


def _src(p: Path) -> str:
    return p.read_text(encoding="utf-8", errors="ignore")


def _rec(**kw):
    from mcp_guard.call_record import ToolCallRecord
    base = dict(
        user_role="security_operator",
        tool_name="block_ip",
        arguments={"ip": "8.8.8.8", "duration": 3600},
        decision="allow", reason="ok", checks=[],
        caller="ops", source="mcp_guard",
    )
    base.update(kw)
    return ToolCallRecord.from_kwargs(**base)


# ═══════════════════════════════════════════
# 前提守卫
# ═══════════════════════════════════════════

def test_panel_endpoints_read_process_memory_not_the_orphan_tables():
    """前提①：面板的 4 个端点读的是进程内状态，不是 `tool_signatures` / `tool_anomalies`。

    这是本条**严重级别的分界线**。若哪天端点改成读表，
    那两张空表就会让面板直接空白 —— 那是用户可见故障，不是持久化缺口。
    """
    src = _src(AUDIT_ROUTER)
    sig_ep = re.search(
        r'@router\.get\("/guard/signatures"\)\s*\n(?:.*\n){0,6}?', src)
    assert sig_ep, "routers/audit.py 不再提供 /guard/signatures，前端 ToolSignaturePanel 会 404"

    # 端点函数体内必须调用 detector 的内存方法
    body = src.split('@router.get("/guard/signatures")', 1)[1].split("@router.", 1)[0]
    assert "list_signatures()" in body, (
        "/guard/signatures 不再走 det.list_signatures() —— "
        "若改成读 tool_signatures 表，请重估本条的严重级别并更新整改报告 §7.1.10"
    )
    assert "ToolSignature" not in body, (
        "/guard/signatures 开始用 ToolSignature ORM 模型了 —— "
        "本条关于「空表不影响面板」的描述已过时"
    )

    body2 = src.split('@router.get("/guard/anomalies")', 1)[1].split("@router.", 1)[0]
    assert "recent_anomalies(" in body2, "/guard/anomalies 不再走 det.recent_anomalies()"
    assert "ToolAnomaly" not in body2, "/guard/anomalies 开始用 ToolAnomaly ORM 模型了"


def test_cold_start_after_restart_is_reported_honestly():
    """前提②：**运行时**断言 —— 重启后的冷启动被明确标注，不谎报「干净」。

    这是本条与 §7.1.9 最重要的区别。`Sandbox.tsx` 永远 pending，
    使用者会以为它在跑；而 guard 在样本不足时返回
    `cold_start=True` + `reasons=["学习中 (0/30)"]`，明确承认自己没有基线。

    重启后 `_signatures` 为空 ⇒ `dims` 全空 ⇒ 走 `behavior_detector.py:306`
    的冷启动分支。所以这里**不需要**模拟 DB，直接新建 detector 就是「重启后」。

    若哪天这条转红（冷启动改成不标 `cold_start` 却仍 `is_anomaly=False`），
    才是真正的静默失效 —— 安全控制在重启后无声降级。
    """
    from mcp_guard.behavior_detector import BehaviorDetector

    det = BehaviorDetector(min_samples=30, enabled=True, persist=True, mode="confirm")
    assert det._signatures == {}, "前提不成立：新 detector 的签名表本应为空（模拟刚重启）"

    rep = det.observe_pre_exec(_rec())

    assert rep is not None, "observe_pre_exec 返回 None（fail-open），前提失效"
    assert rep.cold_start is True, (
        f"重启后冷启动没有被标注 cold_start（拿到 {rep.cold_start!r}）—— "
        "若仍判 is_anomaly=False，这变成了「安全控制重启后静默失效」，"
        "严重级别需要上调，请更新整改报告 §7.1.10"
    )
    assert rep.anomaly_score is None, (
        f"冷启动时给出了具体分数 {rep.anomaly_score!r} —— "
        "没有任何样本时的分数不是可信的，应为 None"
    )
    assert rep.action == "logged", f"冷启动时的动作应为 logged，实际 {rep.action!r}"
    assert any("学习中" in r for r in rep.reasons), (
        f"冷启动原因未对使用者说明：reasons={rep.reasons!r}"
    )
    assert rep.sample_count == 0, f"冷启动样本数应为 0，实际 {rep.sample_count}"


def test_call_log_is_persisted_so_the_asymmetry_is_real():
    """前提③（对照组）：`tool_call_log` **确实**落库。

    没有这条，一个更宽的误判会成立：「mcp_guard 从不碰 DB」。
    事实是它碰 DB —— `call_logger.py:302` `session.add(ToolCallLog(...))`，
    `/guard/calls` 也优先读 PG 并有 `/guard/calls/flush` 冲刷接口。

    真实的不对称是**同一套 guard 里**，调用日志持久化了，
    而签名与偏离没有。
    """
    src = _src(CALL_LOGGER)
    assert re.search(r"session\.add\s*\(\s*ToolCallLog\s*\(", src), (
        "call_logger.py 不再 session.add(ToolCallLog(...)) —— "
        "若 tool_call_log 也改成内存了，本文件的不对称描述需要重写"
    )


def test_detector_state_containers_are_process_local():
    """前提④：detector 的签名/偏离容器确实是进程内结构。

    这是「不持久化」的物理载体证明，与 grep 模型名互相独立。
    """
    src = _src(DETECTOR)
    assert re.search(r"self\._signatures\s*:\s*dict\[", src), "签名容器不再是 dict"
    assert re.search(r"self\._anomalies\s*:\s*deque\s*=", src), "偏离容器不再是 deque"
    # 进程内容器 ≠ 落库：整个文件不应出现任何 DB 写入
    assert not re.search(r"session\.(add|execute|commit|flush)\s*\(", src), (
        "behavior_detector.py 开始直接写 DB 了 —— "
        "本文件关于「持久化脚手架只差写入那一层」的描述需要重估"
    )


# ═══════════════════════════════════════════
# 主断言（strict xfail）：接线即转红
# ═══════════════════════════════════════════

@pytest.mark.xfail(
    strict=True, raises=AssertionError,
    reason="已知缺口：`tool_signatures` / `tool_anomalies` 两张表零生产写入方 —— "
           "表、配置、构造器钩子（persist / _dirty）都铺好了，只差 flush 那一段。"
           "见整改报告 §7.1.10",
)
def test_signature_and_anomaly_tables_receive_production_writes():
    """必须存在一条把签名/偏离写进 `tool_signatures` / `tool_anomalies` 的生产路径。

    判据是**构造器级**（与 `test_threat_intel_pipeline_gap.py` 同一教训：
    文件里出现过模型名不等于写入方，同一文件可以「用 A 读、用 B 写」）。

    接通之后需要回答的设计问题（别急着接线）：
      * 签名要跨重启存活吗？不要的话该删表 + 删配置，而不是留着假装有
      * `_dirty` 的 flush 时机：定时？请求结束？进程退出？
      * `log_retention_days=180` 谁执行清理？
    """
    writers = []
    for py in _prod_files():
        rel = py.relative_to(BACKEND).as_posix()
        if rel == "models.py":
            continue
        src = _src(py)
        for model in ("ToolSignature", "ToolAnomaly"):
            stripped = re.sub(rf"^class\s+{model}\b.*$", "", src, flags=re.M)
            if re.search(rf"\b{model}\s*\(", stripped):
                writers.append(f"{rel}  (实例化 {model})")
            elif re.search(rf"insert\s*\(\s*{model}\b", src):
                writers.append(f"{rel}  (insert({model}))")
            if re.search(r"INSERT\s+INTO\s+[\"'`]?(tool_signatures|tool_anomalies)", src, re.I):
                writers.append(f"{rel}  (SQL INSERT)")
    assert writers, (
        "`tool_signatures` / `tool_anomalies` 仍然没有任何生产写入方 —— "
        "签名与偏离活不过一次重启；面板现在展示的东西，重启后要重新学 30 个样本"
    )


@pytest.mark.xfail(
    strict=True, raises=AssertionError,
    reason="已知缺口：`BehaviorDetector(persist=...)` 是死参数 —— "
           "`self.persist` 赋值后再无读点，`self._dirty` 只 add/clear 从不被读，"
           "且全仓唯一生产实例化 `guard_server.py:89` 连 persist 都没传。见整改报告 §7.1.10",
)
def test_persist_flag_actually_controls_persistence():
    """`persist=True` 必须真的让签名跨实例存活。

    当前实测：3 个静默失败点叠在一起 ——
      1. `self.persist` 存了但**从不被读**（`behavior_detector.py:154/172` 是仅有的两处）
      2. `self._dirty` 只 `.add()`/`.clear()`，**没有任何消费者**（`:173/185/462`）
      3. `guard_server.py:89` 裸 `BehaviorDetector()`，生产里 `persist` 恒为默认 `False`

    写法上留了钩子，却没有一个 `persist=True` 的用例断言过它 ——
    现有 20+ 处测试实例化**全部**写死 `persist=False`。
    """
    src = _src(DETECTOR)

    # ① persist 必须被真正读取（不是只赋值）
    reads = [m.group(0) for m in re.finditer(r"(?<![\w.])self\.persist\b", src)]
    assert len(reads) >= 3, (
        f"`self.persist` 只有 {len(reads)} 处出现（赋值+定义），"
        "说明它从未被任何逻辑读取 —— 持久化开关是摆设"
    )

    # ② _dirty 必须被消费（读出来去落库），而不是只写不清
    consumed = re.search(r"(?:for\s+\w+\s+in\s+self\._dirty|self\._dirty\s*&|list\(self\._dirty)", src)
    assert consumed, (
        "`self._dirty` 只被 `.add()` / `.clear()`，没有任何地方读它去落库 —— "
        "脏表没人消费"
    )

    # ③ 生产实例化必须真的传 persist
    srv = _src(BACKEND / "mcp_guard" / "guard_server.py")
    prod_init = re.search(r"BehaviorDetector\(([^)]*)\)", srv)
    assert prod_init and "persist" in prod_init.group(1), (
        f"guard_server.py 的生产实例化是 {prod_init.group(0) if prod_init else '（未找到）'}，"
        "没传 persist —— 即使接线了也不会生效"
    )


@pytest.mark.xfail(
    strict=True, raises=AssertionError,
    reason="已知缺口：`tool_signature_log_retention_days`（config.py:301 / .env.example:121，"
           "承诺 180 天）是 9 个签名开关里唯一零读点的，出货了但没人执行清理。见整改报告 §7.1.10",
)
def test_log_retention_days_switch_is_actually_read():
    """`tool_signature_log_retention_days` 必须有真实读点。

    普查结果（9 个开关，同一份 `config.py` 正则提取）：

    | 开关 | 读点数 |
    |---|---|
    | `tool_call_log_persist` | 2 |
    | `tool_signature_enabled` | 2 |
    | `tool_signature_mode` | 7 |
    | `tool_signature_min_samples` | 1 |
    | `tool_signature_warn_threshold` | 1 |
    | `tool_signature_confirm_threshold` | 1 |
    | `tool_signature_deny_threshold` | 1 |
    | `tool_signature_weights` | 1 |
    | **`tool_signature_log_retention_days`** | **0** ← 本条 |

    注意这个结论**不是**「mcp_guard 全都不读配置」——
    同目录的 8 个开关都有读点，所以是这一条单独失效，不是量具假全清。
    """
    key = "tool_signature_log_retention_days"
    hits = []
    for py in _prod_files():
        rel = py.relative_to(BACKEND).as_posix()
        if rel == "config.py":
            continue
        if re.search(rf"[\"']?{key}\b", _src(py)):
            hits.append(rel)
    assert hits, (
        f"`{key}` 仍然零读点 —— 配置与 .env.example 都承诺了 180 天保留期，"
        "但没有任何代码执行清理（真接了落库，这会变成无界增长）"
    )


def test_the_other_eight_signature_switches_are_still_live():
    """对照组：另外 8 个开关**必须**仍有读点。

    这条防止把结论写成「签名配置整体空转」—— 那是过度归因。
    同时它也守住量具：若哪天这 8 个也失效，说明普查口径本身退化了
    （就像本轮 `scan_models_without_writers.py` 的 BOM 静默降级那样）。
    """
    keys = re.findall(r"^\s*(tool_(?:signature|call_log)\w*)\s*:", _src(CONFIG), re.M)
    assert len(keys) == 9, f"签名开关数量从 9 变成 {len(keys)}，本文件的普查结论需重新核实"

    live = {}
    for k in keys:
        n = 0
        for py in _prod_files():
            rel = py.relative_to(BACKEND).as_posix()
            if rel == "config.py":
                continue
            n += len(re.findall(rf"[\"']?{k}\b", _src(py)))
        live[k] = n

    dead = sorted(k for k, n in live.items() if n == 0)
    assert dead == ["tool_signature_log_retention_days"], (
        f"零读点的开关变成了 {dead} —— "
        "若有新开关失效，请更新整改报告 §7.1.10 并新增对应守卫"
    )
