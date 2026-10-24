"""
sigma.engine — pySigma 封装（真 Sigma 规则引擎）

替代/增强原 sigma_detector 的“仿 Sigma”内存匹配：
  - 规则源改为 backend/sigma/rules/*.yml（标准 Sigma 1.x YAML，规则即证据，社区可复用）
  - 用 pySigma + SQLite backend 把每条规则编译成 SQL 谓词并缓存
  - 对单条事件（经字段规范化后的 dict）插入内存 sqlite 临时表逐规则求值命中
  - 返回与 sigma_detector 兼容的 DetectionResult 结构，log_ingestion/_sigma 不变

保底：若 pySigma 不可用(SHARED_MEMORY_SIGMA_ENGINE=legacy / import 失败)，自动降级到原
sigma_detector 纯 dict 匹配，保证检测链路不断。
"""
import hashlib
import json
import logging
import os
import re
import sqlite3
import threading
import time
from dataclasses import dataclass
from typing import Any, List, Optional

logger = logging.getLogger(__name__)

#: 已 CRITICAL 过的降级原因（进程级去重, 防止每次检测都刷 CRITICAL）
_DEGRADED_LOGGED: set = set()


def _mark_degraded(reason: str) -> None:
    """Sigma 引擎降级到 legacy 时显式留痕。

    修复前降级只有 WARNING 一条（且 import 期发生在日志装配之前）——
    检测语义从"真 Sigma"静默变成了"11 条自研 dict 匹配"，读指标的人
    完全无感。现在: Prometheus 计数器(每事件累计) + 进程内一次性 CRITICAL。
    """
    try:
        from metrics import SIGMA_ENGINE_DEGRADED
        SIGMA_ENGINE_DEGRADED.labels(reason=reason).inc()
    except Exception:
        pass
    if reason not in _DEGRADED_LOGGED:
        _DEGRADED_LOGGED.add(reason)
        logger.critical(
            "[Sigma] 引擎降级到 legacy dict 匹配 (reason=%s) —— 检测语义已改变, "
            "请尽快修复 pySigma/规则加载, 否则 Sigma 覆盖度报告失真",
            reason,
        )


#: 执行类动作 —— 这些动作会**实际阻断**流量或封禁资产。
#: 带 x-soc-aggregation 的规则在单事件阶段只满足前置筛选，
#: 阈值证据尚未产生，所以必须降级（见 _downgrade_enforcement_action）。
ENFORCEMENT_ACTIONS = frozenset({
    "block_ip", "block", "quarantine", "isolate", "deny", "drop", "kill",
})

#: Sigma 规则声明的 confidence 字符串 → 数值。
#:
#: ⚠️ 这不是新的一套刻度 —— ``audit_triage._fused_confidence`` 与
#: ``ingest_pipeline`` 里已有同样的 ``{"high":0.85,"medium":0.65,"low":0.45}``。
#: 聚合候选必须用**同一把尺**，否则同一条 Sigma 证据在审计链路算 0.85、
#: 在聚合链路算 0.9，两条路径的处置门槛就对不上了。
#: ``tests/test_sigma_aggregation_action_chain.py`` 会钉住这三处一致。
SIGMA_CONFIDENCE_NUM = {"high": 0.85, "medium": 0.65, "low": 0.45}

#: timeframe 解析失败时 Flink 侧的默认窗口宽度（毫秒）。
#: 两端默认必须一致，否则规则没写 timeframe 时两端窗口宽度对不上。
DEFAULT_TIMEFRAME_MS = 300_000

_TIMEFRAME_UNITS = {"ms": 1, "s": 1_000, "m": 60_000, "h": 3_600_000, "d": 86_400_000}


def _timeframe_ms(value: Any) -> int:
    """把 Sigma ``timeframe`` 声明归一成毫秒（``"5m"``/``"30s"``/``"1h"``/``250ms``）。

    P0-1：修复前发往 Flink 的候选只带 threshold，Flink 硬编码 5m 窗口 ——
    规则声明 ``timeframe: 1m`` 会在 5 分钟里凑数，阈值语义失真。
    Sigma 规范里**不带单位的数字按秒**解释（``timeframe: 300`` = 5 分钟）。
    解析失败返回 0，由调用方落到 ``DEFAULT_TIMEFRAME_MS``。
    """
    try:
        if isinstance(value, bool):
            return 0
        if isinstance(value, (int, float)):
            # Sigma 规范: 不带单位的数字按**秒**解释
            n = float(value) * 1_000
        else:
            import re as _re
            s = str(value or "").strip().lower()
            if not s:
                return 0
            m = _re.match(r"^(\d+(?:\.\d+)?)\s*(ms|s|m|h|d)?$", s)
            if not m:
                return 0
            n = float(m.group(1)) * _TIMEFRAME_UNITS.get(m.group(2) or "s", 1)
        return int(n) if n > 0 else 0
    except Exception:
        return 0


def _coerce_epoch_ms(value: Any) -> int:
    """把事件时间戳归一成 epoch 毫秒; 解析不了返回 0(调用方回退当前时间)。

    P1: 上游时间戳形态不一 — int/float 秒或毫秒、ISO8601 字符串
    (``2026-10-24T12:00:00Z``)。修复前 ``int(...)`` 遇 ISO 串直接抛
    ValueError, 聚合候选被静默丢弃, 阈值语义整条断供。
    """
    try:
        if isinstance(value, bool) or value is None:
            return 0
        if isinstance(value, (int, float)):
            ts = int(value)
        else:
            s = str(value).strip()
            if not s:
                return 0
            try:
                ts = int(float(s))
            except ValueError:
                from datetime import datetime, timezone
                iso = s.replace("Z", "+00:00")
                dt = datetime.fromisoformat(iso)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                ts = int(dt.timestamp())
        if ts <= 0:
            return 0
        if ts < 10_000_000_000:  # 秒级 → 毫秒
            ts *= 1000
        return ts
    except Exception:
        return 0


def _downgrade_enforcement_action(action: str) -> str:
    """把执行类动作降级为观察类（partial 阶段只能建议，不能执行）。

    修复前：规则声明 ``action: block_ip`` 且自带
    ``x-soc-aggregation: {func: count, threshold: 5, timeframe: 5m}``，
    但单事件命中时**照原样**输出 block_ip。于是「一次正常登录」
    就能产出封禁建议 —— 量化评估实测良性 ``/admin/login`` 命中
    SIG-001（brute_force / high / block_ip）。

    阈值触发后由聚合窗口（Flink）产出真正的告警，执行动作随之发生；
    单事件阶段的职责是**收集候选**，不是执行。
    """
    a = str(action or "").strip().lower()
    return "alert" if a in ENFORCEMENT_ACTIONS else (str(action) if action else "alert")

try:
    from sigma.collection import SigmaCollection
    from sigma.backends.sqlite import sqliteBackend as SQLiteBackend
    # keywords 兼容 backend(继承 SQLiteBackend, 支持 value-only 全文搜索)。若不可用则退回原 backend。
    try:
        from sigma_engine.backend_keywords import SigmaKeywordsBackend
        _BACKEND_FACTORY = lambda: SigmaKeywordsBackend()  # noqa: E731
        _BACKEND_NAME = "SigmaKeywordsBackend"
    except Exception as _be:  # noqa: BLE001
        logger.warning(f"SigmaKeywordsBackend unavailable ({_be}); fallback SQLiteBackend")
        _BACKEND_FACTORY = lambda: SQLiteBackend()  # noqa: E731
        _BACKEND_NAME = "SQLiteBackend"
    PY_SIGMA_AVAILABLE = True
except Exception as _e:  # noqa: BLE001
    PY_SIGMA_AVAILABLE = False
    logger.warning(f"pySigma unavailable ({_e}); sigma engine will fallback to legacy detector")
    _mark_degraded("pysigma_unavailable")


# 平台专有扩展字段前缀（写入 Sigma YAML）
SOC_EXT = "x-soc-"


def _severity_of(value: Any) -> str:
    """把规则级别归一化成字符串；**不知道**时显式返回 `"unknown"`。

    §六.2 要求「高风险规则不可用时应触发告警」——
    而 `load_errors` 里原来**没有 severity**，于是
    「一条 critical 没加载」与「一条 low 没加载」在数据上完全一样，
    这件事**根本无法判定**。

    「显式的 unknown」与「忘了记这个键」必须能区分开：
    前者是一个结论，后者是一个疏漏。
    """
    s = str(value or "").strip().lower()
    return s or "unknown"


def _ext(rule: Any, key: str, default: Any = None) -> Any:
    """从 pySigma SigmaRule 读取 x-soc-* 自定义扩展字段(custom_attributes)。"""
    if not rule:
        return default
    d = getattr(rule, "custom_attributes", None) or {}
    if isinstance(d, dict):
        return d.get(f"{SOC_EXT}{key}", default)
    return default


class _ConnLease:
    """快照连接的使用权凭证（整改方案 §六 第 5 条）。

    修复前释放判据是**代数**：`reload()` 立刻 close 上一代连接，在途检测
    仍持有它时抛 `sqlite3.ProgrammingError: Cannot operate on a closed
    database`；改成「延迟一代」之后判据**仍然是代数** —— 持有 retired
    快照的执行任务在两次 reload 后拿到的仍是已关闭的连接（实测复现）。

    现在释放判据是**引用**：
    只要还有执行任务持有这一代快照，它的连接就不关；
    最后一个引用释放、且已过宽限期后才关。

    宽限期保留一代是**沿用原有行为**（不让在途任务被突然断掉），
    但它现在只是**附加条件**，不再是唯一判据 ——
    「不再被引用」才是必要条件。
    """

    def __init__(self, conn, generation: int = 0):
        self.conn = conn
        self.generation = generation
        self._lock = threading.Lock()
        self._refs = 0
        self._retired = False
        self._closed = False

    def acquire(self) -> None:
        """声明「本执行任务正在用这一代快照」。

        已关闭的租约**不抛错**，只是拿不到保护：
        线程 A 取到快照、线程 B 连续两次 reload 把这一代退休并回收之后，
        A 才来 acquire —— 这时抛异常等于把一个**无害**的情况
        变成检测崩溃。

        为什么无害：检测路径**不使用**快照连接（走每事件私有的
        `:memory:` 连接），快照的 `compiled` 又是不可变 tuple ——
        租约失效不影响检测结果的正确性。
        """
        with self._lock:
            if self._closed:
                return
            self._refs += 1

    def release(self) -> None:
        """本执行任务用完了。引用归零且已退休 → 可以关。"""
        with self._lock:
            if self._refs > 0:
                self._refs -= 1
            if self._refs == 0 and self._retired:
                self._close_locked()

    def retire(self) -> None:
        """这一代不再是最新 —— 但**不等于**可以立刻关。"""
        with self._lock:
            self._retired = True

    def close_if_unused(self) -> None:
        """宽限期已过且无人引用 → 关。"""
        with self._lock:
            if self._retired and self._refs == 0:
                self._close_locked()

    def _close_locked(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self.conn is not None:
            try:
                self.conn.close()
            except Exception:
                pass

    @property
    def closed(self) -> bool:
        with self._lock:
            return self._closed

    @property
    def refs(self) -> int:
        with self._lock:
            return self._refs


@dataclass(frozen=True)
class _SigmaSnapshot:
    """不可变的规则快照 (整改方案 §六)。

    修复前 detect() 分别读 self._compiled 与 self._conn，reload() 在
    中途换掉这两个属性 → 一次检测可能混用两代规则；且 reload() 立刻
    close 旧连接，并发 detect 仍持有旧连接时抛
    `sqlite3.ProgrammingError: Cannot operate on a closed database`。

    现在一次检测在开始时抓一个快照引用，全程只用它。

    `lease` 是这一代连接的使用权凭证（整改方案 §六 第 5 条）：
    持有租约的执行任务期间，这一代的连接不会被关闭。
    """
    compiled: tuple = ()          # tuple[(meta, sql)]
    rules: tuple = ()
    field_index: frozenset = frozenset()
    conn: object = None
    generation: int = 0
    lease: object = None          # _ConnLease；手工构造的快照可为 None


class PySigmaDetector:
    """pySigma 单事件匹配引擎（返回与 sigma_detector 兼容结果）。"""

    TABLE = "events"

    # 最小字段桥接：平台归一化字段 → Sigma 规则可能引用的字段（后续接入 pipeline 再细化）
    FIELD_MAP = {
        "eventType": "event", "event_type": "event",
        "srcIp": "src_ip", "source_ip": "src_ip", "xffClientIp": "src_ip",
        "dstIp": "dst_ip", "dest_ip": "dst_ip", "host": "dst_ip",
        "msg": "message", "description": "message",
        "proto": "protocol",
        "sev": "severity", "level": "severity",
    }

    SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}

    def __init__(self, rules_dir: str, enforce: bool = False):
        self.rules_dir = rules_dir
        self._legacy = None       # 降级目标
        self._enforce = enforce   # True: 强制 pySigma(失败抛错)；False: 失败降级 legacy
        # 整改方案 §六: 单条规则执行失败不得被当作"未命中"。
        # detect() 每轮重置, detect_for_event() 据此产出 partial / error 状态。
        self._last_rule_errors: List[dict] = []
        self._load_errors: List[dict] = []   # 规则**加载**期错误(reload 累积, stats 暴露)
        self.detector_version = "pysigma-1.0"
        self._lock = threading.RLock()
        self._generation = 0
        self._retired_leases: List = []
        self._snapshot = _SigmaSnapshot()
        # 兼容属性：仍暴露 _compiled/_rules/_field_index/_conn 供既有调用方读取
        self._rules: List[dict] = []
        self._compiled: List = []
        self._field_index: set = set()
        self._conn = None
        self._table_columns: List[str] = []
        if PY_SIGMA_AVAILABLE:
            try:
                self._load_and_compile()
            except Exception as e:
                logger.error(f"[Sigma/pySigma] init failed: {e}")
                self._load_errors.append({
                    "phase": "init", "error": f"{type(e).__name__}: {e}",
                    "severity": "unknown"})
                if self._enforce:
                    raise

    # ── 加载与编译 ──
    def _publish_snapshot(self, compiled, rules, field_index, conn, load_errors) -> None:
        """原子替换当前规则快照（锁内只做指针替换）。"""
        self._generation += 1
        old = self._snapshot
        self._snapshot = _SigmaSnapshot(
            compiled=tuple(compiled), rules=tuple(rules),
            field_index=frozenset(field_index), conn=conn,
            generation=self._generation,
            lease=_ConnLease(conn, generation=self._generation),
        )
        self._compiled = self._snapshot.compiled
        self._rules = self._snapshot.rules
        self._field_index = set(self._snapshot.field_index)
        self._conn = conn
        self._load_errors = list(load_errors)
        if old.conn is not None and old.conn is not conn:
            # 旧代**退休**（不等于可关）—— 关的判据是「引用归零」，
            # 见 `_drain_leases`。
            old_lease = old.lease or _ConnLease(old.conn,
                                               generation=old.generation)
            old_lease.retire()
            self._retired_leases.append(old_lease)

    def _drain_leases(self) -> None:
        """释放已退休的快照连接（整改方案 §六 第 5 条）。

        释放判据是**引用**而不是代数：
        「旧快照只在不再被执行任务引用时释放」。

        修复前这里是**代数**判据（`len(self._retired_conns) > 1`
        就关掉更早的），于是持有 retired 快照的执行任务在两次 reload 后
        拿到的是**已关闭的连接**（实测复现：
        `sqlite3.ProgrammingError: Cannot operate on a closed database`）。

        现在：
        * 刚退休的那一代先留着（**宽限一代**，沿用原有行为，
          不让在途任务被突然断掉）；
        * 更早的每一代，只有在**引用归零**时才关；
        * 仍被引用的那几代**继续留在册**，等最后一个引用释放时再关。
        """
        if len(self._retired_leases) <= 1:
            return
        keep: List = []
        for lease in self._retired_leases[:-1]:
            if lease.refs > 0:
                keep.append(lease)       # 还有执行任务在用 → 继续留在册
            else:
                lease.close_if_unused()   # 无人引用 → 关
        self._retired_leases = keep + [self._retired_leases[-1]]

    def reload(self) -> int:
        """重载 rules 目录(CRUD 写回 YAML 后调用)。

        先编到临时结构,成功后再替换;失败保留上一份编译,避免一条坏 yml 把规则清掉。
        整改方案 §六：替换在锁内原子完成,旧连接延迟一代释放。
        """
        if not PY_SIGMA_AVAILABLE:
            return 0
        try:
            built = self._build_compiled()
        except Exception as e:
            logger.error(f"[Sigma/pySigma] reload failed: {e}")
            self._load_errors = [{
                "phase": "reload", "error": f"{type(e).__name__}: {e}",
                "severity": "unknown",
            }]
            if self._enforce:
                raise
            return len(self._compiled)
        with self._lock:
            self._publish_snapshot(*built)
            self._drain_leases()
        return len(self._snapshot.compiled)

    def _load_and_compile(self):
        built = self._build_compiled()
        with self._lock:
            self._publish_snapshot(*built)
        return len(self._snapshot.compiled)

    def _rule_files(self) -> list:
        import pathlib
        files: list = []
        p = pathlib.Path(self.rules_dir)
        if p.exists():
            files.extend(sorted(p.glob("*.yml")))
        parent = os.path.dirname(self.rules_dir)
        for extra in ("rules_community_active", "rules_selfplay_shadow"):
            d = os.path.join(parent, extra)
            if extra == "rules_selfplay_shadow":
                try:
                    from self_play.sigma_export import repair_selfplay_yaml
                    n = repair_selfplay_yaml(d)
                    if n:
                        logger.info(f"[Sigma/pySigma] repaired {n} self-play YAML ids under {d}")
                except Exception as e:
                    logger.warning(f"[Sigma/pySigma] self-play YAML repair skipped: {e}")
            if os.path.isdir(d):
                files.extend(sorted(pathlib.Path(d).glob("*.yml")))
        return files

    def _build_compiled(self):
        """按文件加载并编译。单文件失败只 skip,不拖垮整库。不改 self._compiled。

        整改方案 §六：同时收集每条加载/编译失败，装进 `load_errors`
        供 `stats()` 暴露 —— 修复前「哪些规则没加载上」完全不可知。
        """
        files = self._rule_files()
        load_errors: list[dict] = []
        if not files:
            logger.warning(f"[Sigma/pySigma] no rules under {self.rules_dir}; using legacy fallback")
            _mark_degraded("no_rules")
            return [], [], set(), None, [{
                "phase": "scan", "file": "", "rule_id": "",
                "error_code": "no_rule_files", "error": f"no rules under {self.rules_dir}",
            }]
        compiled: list = []
        rules: list = []
        field_index: set = set()
        be = _BACKEND_FACTORY()
        for fp in files:
            loaded, file_errors = self._load_file(fp)
            load_errors.extend(file_errors)
            if not loaded:
                continue
            for rule in loaded:
                meta = self._rule_meta(rule, fallback_n=len(compiled) + 1)
                try:
                    sql_list = be.convert_rule(rule)
                except Exception as e:
                    logger.warning(f"[Sigma/pySigma] compile {meta['rule_id']} failed: {e}; skipped")
                    load_errors.append({
                        "phase": "compile", "file": os.path.basename(fp),
                        "rule_id": meta["rule_id"], "rule_name": meta["name"],
                        "error_code": f"{type(e).__name__}:compile",
                        "error": str(e)[:200],
                        # meta 里已经有级别 → 填**真实**级别
                        "severity": _severity_of(meta.get("severity")),
                    })
                    continue
                if isinstance(sql_list, list) and len(sql_list) > 1:
                    # P1: pySigma 对多 selection/复合条件规则会产出**多条** SQL —
                    # 修复前只编译第一条, 其余静默丢弃 → 带 `1 of them` 类条件的
                    # 社区规则系统性漏报且无 load_errors 留痕。
                    # UNION ALL 合并: 单行表上任一子 SELECT 命中即算命中,
                    # 与 Sigma 多 selection 的 OR 语义一致。
                    sql = "\nUNION ALL\n".join(str(s) for s in sql_list)
                else:
                    sql = (sql_list[0] if isinstance(sql_list, list) and sql_list else str(sql_list))
                sql = sql.replace("<TABLE_NAME>", self.TABLE)
                for m in re.finditer(r"`([^`]+)`", sql):
                    field_index.add(m.group(1))
                for m in re.finditer(r"(?i)(?:\bWHERE\b|\bAND\b|\bOR\b|\()\s*([A-Za-z_][\w.\-]*)\s*(?:=|LIKE|IN|!=|<>)", sql):
                    col_name = m.group(1)
                    if col_name.upper() not in {"SELECT", "FROM", "WHERE", "AND", "OR", "LIKE", "IN", "NOT", "NULL"}:
                        field_index.add(col_name)
                compiled.append((meta, sql))
                rules.append(meta)
        conn = sqlite3.connect(":memory:") if compiled else None
        # ID 冲突消歧：稳定 ID 让不同来源的规则可能撞车（平台 x-soc-id 与
        # 社区规则 UUID 空间重叠时）。按出现顺序确定性加后缀，
        # 保证 list_rules()/delete_rule() 不会因重名而误删。
        seen_ids: dict[str, int] = {}
        fixed: list = []
        for meta, sql in compiled:
            rid = meta["rule_id"]
            if rid in seen_ids:
                seen_ids[rid] += 1
                meta = {**meta, "rule_id": f"{rid}#{seen_ids[rid]}"}
                logger.warning("[Sigma/pySigma] duplicate rule_id=%s -> %s",
                               rid, meta["rule_id"])
            else:
                seen_ids[rid] = 0
            fixed.append((meta, sql))
        compiled = fixed
        rules = [m for m, _ in compiled]
        logger.info(f"[Sigma/pySigma] compiled {len(compiled)} rules from "
                    f"{self.rules_dir} ({len(load_errors)} load/compile errors)")
        return compiled, rules, field_index, conn, load_errors

    def _load_file(self, fp) -> tuple:
        """返回 (rules, errors)。errors 供 stats() 暴露。"""
        errors: list[dict] = []
        name = os.path.basename(fp)
        try:
            with open(fp, "r", encoding="utf-8") as fh:
                text = fh.read()
        except Exception as e:
            logger.warning(f"[Sigma/pySigma] read {fp} failed: {e}; skipped")
            errors.append({"phase": "read", "file": name, "rule_id": "",
                           "error_code": f"{type(e).__name__}:read", "error": str(e)[:200],
                           "severity": "unknown"})
            return [], errors
        try:
            col = SigmaCollection.from_yaml(text, collect_errors=True)
        except Exception as e:
            logger.warning(f"[Sigma/pySigma] parse {fp} failed: {e}; skipped")
            errors.append({"phase": "parse", "file": name, "rule_id": "",
                           "error_code": f"{type(e).__name__}:parse", "error": str(e)[:200],
                           "severity": "unknown"})
            return [], errors
        out = []
        for rule in getattr(col, "rules", None) or []:
            errs = [e for e in (getattr(rule, "errors", None) or []) if e]
            if errs:
                logger.warning(f"[Sigma/pySigma] skip {fp}: {errs[0]}")
                errors.append({
                    "phase": "validate", "file": name,
                    "rule_id": str(getattr(rule, "title", "") or ""),
                    "error_code": "SigmaRuleError:invalid_rule",
                    "error": str(errs[0])[:200],
                    # 规则已经解析出来 → 级别是**已知**的
                    "severity": _severity_of(getattr(rule, "level", None)),
                })
                continue
            out.append(rule)
        return out, errors

    @staticmethod
    def _stable_rule_id(sigmarule: Any, title: str = "") -> str:
        """与位置无关的稳定规则 ID (整改方案 §六)。

        修复前的取值链是
            `_ext(rule,"id")` or `getattr(rule.id, "value", None)` or `SIG-{n:03d}`
        而 pySigma 1.5 里 `SigmaRule.id` 是 `uuid.UUID`，**没有 `.value` 属性**
        （实测 `id.value is None`）→ 恒回退到位置序号 `SIG-nnn`，
        YAML 增删/重排后所有无 `x-soc-id` 的规则会被重新编号，
        而 rule_id 会进 Kafka 载荷 / list_rules / detect_batch 的 hits。

        现在的优先级：
          1. `x-soc-id` 扩展字段（平台自有稳定 ID，16 条生产规则都用它）
          2. Sigma 自带的稳定 id（UUID 直接取字符串）
          3. 内容指纹 `SIG-<sha1(title|detection)[:10]>` —— 与文件顺序无关
        """
        ext = _ext(sigmarule, "id")
        if ext:
            return str(ext)
        raw_id = getattr(sigmarule, "id", None)
        if raw_id is not None:
            sid = str(raw_id).strip()
            if sid and sid.lower() != "none":
                return sid
        title = title or str(getattr(sigmarule, "title", "") or "")
        detection = getattr(sigmarule, "detection", None)
        payload = f"{title}|{json.dumps(detection, sort_keys=True, default=str)}"
        digest = hashlib.sha1(payload.encode("utf-8"), usedforsecurity=False).hexdigest()[:10]
        return f"SIG-{digest}"

    def _rule_meta(self, sigmarule: Any, fallback_n: int = 1) -> dict:
        title = getattr(sigmarule, "title", "") or ""
        rid = self._stable_rule_id(sigmarule, title)
        lvl = getattr(sigmarule, "level", None)
        lvl_str = getattr(lvl, "name", str(lvl)).lower() if lvl else "low"
        return {
            "rule_id": str(rid),
            "name": title,
            "description": getattr(sigmarule, "description", "") or "",
            "severity": str(_ext(sigmarule, "severity") or lvl_str),
            "attack_type": str(_ext(sigmarule, "attack_type", "custom")),
            "confidence": str(_ext(sigmarule, "confidence", "medium")),
            "action_recommend": str(_ext(sigmarule, "action", "alert")),
            "shadow_mode": bool(_ext(sigmarule, "shadow", False)),
            "enabled": _ext(sigmarule, "enabled", True),
            "mitre_attack_id": str(getattr(sigmarule, "tags", None) or "").replace("[", "").replace("]", "") or "",
            "yaml": _ext(sigmarule, "yaml", ""),
            "aggregation": _ext(sigmarule, "aggregation"),
            "boost": _ext(sigmarule, "boost"),
        }

    # ── 匹配 ──
    def _normalize(self, event: dict) -> dict:
        out = dict(event)
        for src, std in self.FIELD_MAP.items():
            if src in out and std not in out:
                out[std] = out[src]
        # 从 host:/ip:port 提取 dst_port(SIG-006/007 端口类规则)
        if "dst_port" not in out:
            dst = str(out.get("dst_ip", ""))
            if ":" in dst:
                host, _, port = dst.rpartition(":")
                if port.isdigit():
                    out["dst_ip"] = host
                    out["dst_port"] = int(port)
        return out

    def detect(self, event: dict) -> list:
        """命中返回列表(DetectionResult)。pySigma 不可用/无规则时降级 legacy。

        整改方案 §六：每次检测使用**独占的内存连接**执行。
        修复前所有事件共用 `self._conn` 上的一张固定名 `events` 表并做
        DROP → CREATE → INSERT，确定性交错下后一个事件会抹掉前一个事件的行，
        使前者的检测查询返回未命中；且 sqlite3.Connection 是线程亲和的，
        任何跨线程调用都在 `_ensure_table` 抛未捕获的 ProgrammingError。

        ⚠️ 本方法**只返回命中**；本轮的规则执行错误由 `_detect_with_errors`
        一并返回。判定 partial 的路径必须用那一对返回值，不能读实例属性
        （理由见 `_detect_with_errors` 的说明）。
        """
        hits, errors = self._detect_with_errors(event)
        # 兼容属性：保留「最近一次完成的检测」的错误，供调试与外部读取。
        # 它**不是**判定依据 —— 它是实例级共享状态，并发下会被别的线程冲掉。
        self._last_rule_errors = errors
        return hits

    def _detect_with_errors(self, event: dict) -> tuple:
        """执行一次检测，返回 `(命中列表, 本轮规则执行错误列表)`。

        整改方案 §六 / §二：**错误必须与「本轮检测」绑定返回**。

        修复前（2026-10-19 实测复现）：规则执行错误走实例属性
        `self._last_rule_errors` 传递 —— 而 `detect()` 与读取该属性的
        `_detect_for_event_inner()` 是**两次独立调用**，中间还隔着
        `hits = self.detect(log_data)` 的返回。线程 A 在自己的 detect()
        里记下了一条 Critical 规则执行失败，还未及读取，线程 B 的 detect()
        就把该属性重置成了新列表：A 的错误被整体丢弃，A 于是报
        `status=not_detected` / `rules_failed=0` ——
        **「单条规则 SQL 执行失败被当作完整阴性」这一 P0 缺陷在并发下复活**，
        而这恰恰是 §六 验收标准「并发不同事件时，检测结果相互独立」要防的。

        现在错误是本函数的局部变量，随本轮返回值一起交给调用方，
        跨线程、跨调用都不可能串扰。
        """
        snap = self._snapshot
        lease = snap.lease
        if lease is not None:
            # 持有这一代快照 → 本次检测期间它的连接不会被关掉
            # （整改方案 §六 第 5 条：旧快照只在不再被执行任务引用时释放）。
            lease.acquire()
        try:
            return self._detect_with_snapshot(snap, event)
        finally:
            if lease is not None:
                lease.release()

    def _detect_with_snapshot(self, snap, event: dict) -> tuple:
        """在**给定**快照上执行一次检测（租约由调用方持有）。

        快照显式传进来，而不是在这里再读一次 `self._snapshot` ——
        否则「捕获快照」与「拿租约」可能落在两代上，
        租约保护的就不是实际在用的那一代。
        """
        compiled = snap.compiled
        if not compiled:
            _mark_degraded("empty_compiled_snapshot")
            return self._legacy_detect(event), []
        # 用 apply_mapping 同时提供平台字段(url/event/...)与 Sigma 社区字段(cs-uri-query/...),
        # 使内置规则与 SigmaHQ 子集规则都能命中。
        from sigma_engine.mapping import apply_mapping
        ev = apply_mapping(event)
        cols = list(ev.keys())
        if not cols:
            return [], []
        # 本轮规则执行错误（局部变量，随返回值交给调用方）
        rule_errors: list = []
        # 每次检测一个私有 :memory: 库 → 事件之间零共享状态, 也天然线程安全
        conn = sqlite3.connect(":memory:")
        try:
            # 每事件重建单行表，避免历史行残留造成假命中
            self._ensure_table(cols, ev, conn=conn)
            results = []
            str(ev.get("url", ""))
            str(ev.get("src_ip", ""))
            str(ev.get("event", ""))
            cur = conn.cursor()
            for meta, sql in compiled:
                if not meta.get("enabled", True):
                    continue
                try:
                    row = cur.execute(sql)
                    hit = row.fetchone() is not None
                except Exception as rule_exc:
                    # 修复前: hit = False —— 单条规则 SQL 失败与「规则不匹配」
                    # 返回完全相同, 无日志无计数, 整轮被当成完整阴性。
                    hit = False
                    rule_errors.append({
                        "rule_id": meta.get("rule_id", ""),
                        "rule_name": meta.get("name", ""),
                        "severity": meta.get("severity", ""),
                        "error_code": f"{type(rule_exc).__name__}:rule_exec",
                        "error": str(rule_exc)[:200],
                    })
                    logger.warning(
                        "[Sigma] rule execution failed rule_id=%s error=%s",
                        meta.get("rule_id"), rule_exc)
                if hit:
                    sev = meta["severity"]
                    desc = meta["description"]
                    agg = meta.get("aggregation")
                    requires_agg = isinstance(agg, dict) and bool(agg)
                    if meta.get("shadow_mode"):
                        desc += " [SHADOW]"
                        act = "alert"
                    else:
                        act = meta["action_recommend"]
                    if requires_agg:
                        # 整改方案 §二 partial 语义
                        # （量化评估 §4.3 缺口 1 挖出的真实缺陷）：
                        #
                        # 带 x-soc-aggregation 的规则自己声明了
                        # 「count(src_ip) > 5 within 5m」才构成判定。
                        # 单条事件只满足它的**前置筛选**，不是结论。
                        #
                        # 修复前：SIG-001（SIG-007 同理）声明 action=block_ip，
                        # 于是一次正常的 /admin/login 就给出封 IP 的建议 ——
                        # 拿规则自己承认不充分的证据去做执行动作。
                        # 量化评估实测：良性 `/admin/login` → brute_force/high。
                        act = _downgrade_enforcement_action(act)
                        desc += " [PENDING-AGG]"
                    results.append(self._mk_result(
                        meta, ev, sev, act, desc,
                        requires_aggregation=requires_agg,
                        aggregation_spec=dict(agg) if isinstance(agg, dict) else {},
                    ))
                    # 命中聚合类规则(SIG-001/007 等带 x-soc-aggregation):
                    # 发布聚合候选 → Flink 阈值窗口。发布失败不影响本条结果。
                    if requires_agg:
                        try:
                            self._schedule_publish_agg(meta, ev, agg)
                        except Exception as pub_err:
                            logger.warning(
                                f"[Sigma/agg] publish skipped for {meta.get('rule_id')}: {pub_err}"
                            )
            return results, rule_errors
        finally:
            try:
                conn.close()
            except Exception:
                pass

    @staticmethod
    def _quote_ident(name: str) -> str:
        """安全引用 SQL 标识符。

        修复前 `coldef = ", ".join(f'"{c}" TEXT' ...)` 直接拼接事件字段名，
        字段名含双引号时生成 `CREATE TABLE "evil"col" TEXT` 抛
        sqlite3.OperationalError，且 CREATE 那一步没有 try 兜底 → 异常
        未受控外泄出 detect()。现在转义内部引号。
        """
        return '"' + str(name).replace('"', '""') + '"'

    def _ensure_table(self, cols: List[str], ev: dict, conn=None):
        """每次重建单行表：DROP → CREATE(当前事件列) → INSERT 当前事件。

        补齐所有已编译 SQL 引用的字段列(self._field_index), 事件缺省时值为空串,
        避免 SQL 引用不存在的列报错(空列不影响命中, 且 keywords 全文搜索需要这些列)。

        `conn` 为本次检测独占的连接(整改方案 §六: 检测执行所用连接与其他事件隔离)。
        """
        conn = conn if conn is not None else self._conn
        # 平台常用字段：即使 SQL 解析未抽到，也预建列，避免 OR 条件因缺列整句失败
        standard = {
            "event", "message", "src_ip", "dst_ip", "dst_port", "src_port", "port",
            "protocol", "url", "severity", "host", "user", "username",
        }
        # 整改方案 §六：keywords 覆盖的字段必须存在，否则整条 OR 条件报错。
        # 修复前这里只有 6 个字段，新增的载荷字段（user_agent / request_body …）
        # 不建列会导致 SQL 引用不存在的列。
        try:
            from sigma_engine.backend_keywords import (
                KEYWORD_FIELDS as _KW,
                NUMERIC_FIELDS as _NUM,
            )
            standard = standard | set(_KW) | set(_NUM)
        except Exception:  # pragma: no cover - backend 不可用时退回原集合
            pass
        needed = set(cols) | set(self._field_index) | standard
        cols = sorted(needed)
        cur = conn.cursor()
        try:
            cur.execute(f"DROP TABLE IF EXISTS {self._quote_ident(self.TABLE)}")
        except Exception:
            pass
        coldef = ", ".join(f"{self._quote_ident(c)} TEXT" for c in cols)
        try:
            cur.execute(f"CREATE TABLE {self._quote_ident(self.TABLE)} ({coldef})")
        except Exception as exc:
            # 表名/列名受控后仍失败 = 内部缺陷; 转成明确错误交给 detect 上层归类,
            # 而不是让 sqlite 的原始异常裸奔到 API 层。
            raise RuntimeError(f"sigma_exec_schema_invalid: {exc}") from exc
        ph = ", ".join("?" for _ in cols)
        quoted = ", ".join(self._quote_ident(c) for c in cols)
        # protocol=ssh 时补默认 dst_port=22，便于端口类规则在缺字段时仍可 OR 到 event 条件
        values = []
        for c in cols:
            v = ev.get(c, "")
            if (c == "dst_port" or c == "port") and (v is None or v == ""):
                proto = str(ev.get("protocol") or "").lower()
                if proto in ("ssh", "tcp/22"):
                    v = "22"
            values.append(str(v) if v is not None else "")
        cur.execute(f'INSERT INTO {self._quote_ident(self.TABLE)} ({quoted}) VALUES ({ph})', values)  # nosec B608
        conn.commit()

    @staticmethod
    def _rule_version(meta: dict, agg: dict) -> str:
        """规则语义版本的稳定指纹（8 hex）。

        聚合告警跨进程（Python → Flink → Kafka → backend）携带的是**结果**，
        复盘"这条告警是哪一版规则语义产出的"时没有别的依据。
        优先用 yaml 原文指纹；yaml 不可用时退回语义字段签名 ——
        两个来源对同一规则内容都给出稳定一致的值。
        """
        basis = str(meta.get("yaml") or "")
        if not basis:
            a = agg or {}
            basis = "|".join(str(x) for x in (
                meta.get("rule_id"), a.get("func"), a.get("field"),
                a.get("op"), a.get("threshold"), a.get("timeframe"),
                meta.get("action_recommend"), meta.get("severity"),
                meta.get("confidence"),
            ))
        return hashlib.sha1(
            basis.encode("utf-8"), usedforsecurity=False).hexdigest()[:8]

    @staticmethod
    def _agg_payload(meta: dict, ev: dict, agg: dict) -> dict:
        """构造发往 sigma-hit topic 的聚合候选载荷。

        独立成纯函数是为了可测：发布路径要 Kafka + 事件循环才能跑通，
        而这里承载的是**契约**——下游（Flink 阈值窗口）靠这些字段决定
        告警怎么处置，契约变了却测不到是最难发现的一类回归。

        ⚠️ 关键：``action_recommend`` 用的是规则**声明的**动作，不是单事件
        阶段降级后的 ``alert``。单事件阶段已经禁止处置了；若这里也发 alert，
        「窗口超阈值后才处置」这条路径就永远不会有执行动作 ——
        规则声明的 block_ip 会静默消失。

        ⚠️ P0-1：**完整的阈值语义必须随候选下发**。修复前只发 threshold，
        op/func/field/timeframe 全部丢在规则里 —— Flink 只能硬编码
        ``count >= threshold`` 和 5m 窗口：声明 ``op: '>'`` 的 SIG-001
        在第 5 条就告警（应为第 6 条），声明 ``threshold: 1`` 的 SIG-007
        第 1 条就告警（聚合退化成单事件告警）。

        ``shadow_mode`` 规则的例外：灰度期只出 alert，与 ``detect()`` 口径一致。
        """
        a = agg if isinstance(agg, dict) else {}
        op = str(a.get("op") or "").strip()
        func = str(a.get("func") or "").strip() or "count"
        field = str(a.get("field") or "").strip() or "src_ip"
        tf_raw = a.get("timeframe")
        tf_ms = _timeframe_ms(tf_raw) or DEFAULT_TIMEFRAME_MS
        # 残留修复: 事件时间戳秒→毫秒归一必须在**发布前**完成 ——
        # 秒级值(≈1.7e9)直达 Flink 会被当 1970 年事件时间, 晚于 watermark
        # 被事件时间窗口静默丢弃, 聚合永远凑不满阈值。
        # P1: 时间戳也可能是 ISO8601 字符串(上游规范化差异) — int() 直接抛
        # ValueError 让候选静默丢失, 必须容错解析, 失败回退当前时间。
        ts = _coerce_epoch_ms(ev.get("timestamp", ev.get("@timestamp", 0)))
        ts = ts or int(time.time() * 1000)
        return {
            "src_ip": str(ev.get("src_ip", "")),
            # 残留修复: 聚合分组键按规则声明的 field 取值 (默认 src_ip) ——
            # 修复前 Flink 只会按 src_ip 分组, 声明 field: dst_ip/user 的规则
            # 语义在窗口边界上被改写。
            "group_key": str(ev.get(field) or ev.get("src_ip", "")),
            "rule_id": meta["rule_id"],
            "threshold": int(a.get("threshold") or 0),
            # ── 阈值语义契约 (P0-1)：Flink 按 op 比较、按规则 timeframe 建窗 ──
            # op 缺省 ">="（与 Flink 旧硬编码一致，旧候选语义不变）；
            # 认不出的一律由 Flink 回退 ">="（向"更难告警"方向回退）。
            "op": op or ">=",
            "func": func,
            "field": field,
            "timeframe": str(tf_raw or ""),
            "timeframe_ms": tf_ms,
            "rule_version": PySigmaDetector._rule_version(meta, a),
            "event_id": str(ev.get("eventId") or ev.get("event_id")
                            or ev.get("uuid") or ""),
            "dst_ip": str(ev.get("dst_ip", "")),
            "timestamp": ts,
            "action_recommend": (
                "alert" if meta.get("shadow_mode")
                else str(meta.get("action_recommend") or "alert")
            ),
            "severity": str(meta.get("severity") or "medium"),
            "attack_type": str(meta.get("attack_type") or "custom"),
            # 数值置信度。**缺了它聚合告警永远匹配不到任何策略** ——
            # 消费端用 confidence 做策略门槛(`暴力破解自动阻断` 要求
            # min_confidence=0.5)，而 Sigma 聚合告警不带 anomalyScore，
            # 于是 confidence 实算 0.0 → NO_ACTION → 封禁链在策略匹配处断掉。
            # 用规则声明的 confidence 换算，与审计链路同一把尺。
            "confidence": SIGMA_CONFIDENCE_NUM.get(
                str(meta.get("confidence") or "").strip().lower(), 0.45),
        }

    def _schedule_publish_agg(self, meta, ev, agg: dict):
        """命中聚合类规则时, 若 Kafka 启用则异步发布聚合候选到 sigma-hit topic。
        仅调度(不阻塞检测)。

        残留修复(2026-10-24): 此前是彻底的 fire-and-forget —— producer 未启动
        静默丢、create_task 异常无留痕、发送结果无人检查。现在每条路径都有
        指标/日志: 候选丢失在 Prometheus 可见 (record_ingest source=sigma)。
        """
        def _metric(result: str, reason: str = "") -> None:
            try:
                from core_metrics import record_ingest
                record_ingest("sigma", result, reason=reason)
            except Exception:
                pass

        def _on_done(task) -> None:
            try:
                ok = task.result()
            except Exception as cb_err:
                _metric("candidate_dropped", reason=f"task_error:{type(cb_err).__name__}")
                logger.warning(f"[Sigma/agg] publish task failed: {cb_err}")
                return
            if not ok:
                _metric("candidate_dropped", reason="send_failed")

        try:
            import asyncio
            from config import settings
            if not getattr(settings, "kafka_enabled", False):
                _metric("candidate_dropped", reason="kafka_disabled")
                logger.info(f"[Sigma/agg] kafka disabled, skip publish {meta.get('rule_id')}")
                return
            from kafka_producer import kafka_producer
            # is_active 是 property(属性 bool), 非方法
            if not kafka_producer.is_active:
                _metric("candidate_dropped", reason="producer_inactive")
                logger.warning(
                    f"[Sigma/agg] producer inactive, candidate DROPPED "
                    f"rule={meta.get('rule_id')} —— 聚合窗口将凑不满阈值")
                return
        except Exception as e:
            _metric("candidate_dropped", reason="precheck_error")
            logger.warning(f"[Sigma/agg] pre-publish check err: {e}")
            return
        payload = self._agg_payload(meta, ev, agg)
        try:
            import asyncio
            # P1: detect() 是同步方法, 可能从任意线程调用 —
            # `get_event_loop()`+`create_task` 跨线程调度不是线程安全,
            # 且无运行循环时静默丢候选。改 run_coroutine_threadsafe 到主循环。
            coro = kafka_producer.publish_sigma_hit(payload)
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                loop = None
            if loop is not None and loop.is_running():
                # 记住主循环: 之后从工作线程调用 detect() 时可跨线程安全调度
                self._main_loop = loop
                task = loop.create_task(coro)
                task.add_done_callback(_on_done)
                return
            main_loop = getattr(self, "_main_loop", None)
            if main_loop is not None and not main_loop.is_closed():
                fut = asyncio.run_coroutine_threadsafe(coro, main_loop)
                fut.add_done_callback(_on_done)
                return
            _metric("candidate_dropped", reason="no_running_loop")
        except Exception:
            _metric("candidate_dropped", reason="schedule_error")
            raise

    def _mk_result(self, meta, ev, severity, action, description,
                   requires_aggregation: bool = False,
                   aggregation_spec: Optional[dict] = None):
        from sigma_detector import DetectionResult
        return DetectionResult(
            rule_id=meta["rule_id"],
            rule_name=meta["name"],
            severity=severity,
            attack_type=meta["attack_type"],
            confidence=meta["confidence"],
            action_recommend=action,
            matched_fields={
                "event_type": str(ev.get("event", "")),
                "src_ip": str(ev.get("src_ip", "")),
                "url": str(ev.get("url", ""))[:100],
                "shadow_mode": meta.get("shadow_mode", False),
                "mitre_attack_id": meta.get("mitre_attack_id", ""),
            },
            description=description,
            requires_aggregation=bool(requires_aggregation),
            aggregation_spec=dict(aggregation_spec or {}),
        )

    def _legacy_detect(self, event: dict) -> list:
        """降级：走原 sigma_detector 纯 dict 匹配(直接用 SigmaDetector 类，避免拿全局 pySigma 对象导致自递归)。"""
        if self._legacy is None:
            try:
                from sigma_detector import SigmaDetector
                self._legacy = SigmaDetector()
            except Exception as e:
                logger.warning(f"[Sigma] legacy fallback unavailable: {e}")
                return []
        return self._legacy.detect(event)

    # ── 对外兼容接口 ──
    def detect_batch(self, events: list[dict]) -> dict:
        """批量检测，返回与 sigma_detector.detect_batch 兼容的统计报告。"""
        by_attack, by_severity, hits = {}, {}, []
        detected = 0
        for i, ev in enumerate(events):
            ev_hits = self.detect(ev)
            if ev_hits:
                detected += 1
                for h in ev_hits:
                    by_attack[h.attack_type] = by_attack.get(h.attack_type, 0) + 1
                    by_severity[h.severity] = by_severity.get(h.severity, 0) + 1
                    hits.append({"event_index": i, "rule_id": h.rule_id,
                                 "attack_type": h.attack_type, "severity": h.severity})
        total = len(events)
        return {"total_events": total, "detected": detected,
                "detection_rate": round(detected / max(total, 1), 4),
                "by_attack_type": by_attack, "by_severity": by_severity, "hits": hits[:50]}

    def detect_for_event(self, log_data: dict) -> dict:
        """单事件检测 → 融合层载荷（**带耗时与五态埋点**的外层）。

        埋点放在外层而不是散进各个 return 分支：本函数有两个 return，
        而「给新分支漏埋点」这种错误不会让任何测试变红，只会让
        仪表盘悄悄少一类数据。抽一层 inner 后，加分支不会再漏。
        """
        import time as _time
        _t0 = _time.perf_counter()
        out = self._detect_for_event_inner(log_data)
        try:
            from core_metrics import record_detection
            record_detection("sigma", out.get("status", ""),
                             _time.perf_counter() - _t0)
        except Exception:
            pass
        return out

    def _detect_for_event_inner(self, log_data: dict) -> dict:
        """单事件检测 → 融合层载荷。

        整改方案 §六 / §二：`_status` 字段承载统一契约状态，
        区分「完整执行且未命中」与「有规则执行失败/引擎降级」。
        """
        # 命中与错误**同轮返回**（不读实例属性）：实例属性是跨线程共享的，
        # 并发下会被别的线程重置掉 —— 那会把真实的规则失败洗成完整阴性。
        hits, errs = self._detect_with_errors(log_data)
        # 兼容属性：仅供调试/外部读取，不参与上面的判定。
        self._last_rule_errors = list(errs)
        # 待聚合的命中：规则声明了阈值证据，单事件阶段只过了前置筛选
        pending = [h for h in hits if getattr(h, "requires_aggregation", False)]
        confirmed = [h for h in hits if not getattr(h, "requires_aggregation", False)]
        pending_ids = [h.rule_id for h in pending]
        if errs:
            status = "partial"
            err_code = f"rule_exec_failed:{len(errs)}"
            err_msg = "; ".join(f"{e['rule_id']}={e['error_code']}" for e in errs[:5])
        elif not self._compiled and self._rules:
            # 规则库存在但一份都没编译成功 → 引擎不可用
            status = "error"
            err_code = "no_compiled_rules"
            err_msg = "rule library present but nothing compiled"
        elif not self._rules:
            status = "error"
            err_code = "no_rules"
            err_msg = "no rules loaded"
        elif confirmed:
            status = "detected"
            err_code = err_msg = ""
        elif pending:
            # 只有待聚合命中 → 这是**部分结果**，不是确定结论。
            # 整改方案 §二：partial「不可以直接视为完整阴性」，
            # 同理也不可以直接视为确定的阳性并据此执行动作。
            status = "partial"
            err_code = f"pending_aggregation:{len(pending)}"
            err_msg = ("rules matched pre-filter only; threshold evidence "
                       f"not yet evaluated: {','.join(pending_ids[:5])}")
        else:
            status = "not_detected"
            err_code = err_msg = ""

        base = {
            "status": status,
            "status_errors": errs,
            "error_code": err_code,
            "error_message": err_msg,
            "rules_evaluated": len(self._compiled),
            "rules_failed": len(errs),
            "pending_aggregation": pending_ids,
            "confirmed_hits": len(confirmed),
        }
        if not hits:
            return {**base, "detected": False, "hits": [],
                    "max_severity": "", "attack_types": [],
                    "action_recommend": "", "rule_count": 0}
        # P0-2：detected 只反映**已确证**的命中。
        # 修复前 detected 由全部命中计算 —— 待聚合命中（阈值证据尚未产生，
        # 只是过了前置筛选）也把 detected 抬成 True，于是
        # ingest_pipeline 只看 detected 就把 anomaly score 抬到 Sigma severity
        # 下限、FastPath 接着用 `_fused_conf >= 0.7` 进入封禁决策，
        # 单个 /login 事件就这样绕过了「窗口超阈值后才处置」的设计。
        # 待聚合命中保留在 hits/pending_aggregation 里供审计，不参与判定。
        confirmed_max = (
            max(confirmed, key=lambda h: self.SEVERITY_ORDER.get(h.severity, 0))
            if confirmed else None
        )
        return {
            **base,
            "detected": bool(confirmed),
            "hits": [h.to_dict() for h in hits],
            "max_severity": confirmed_max.severity if confirmed_max else "",
            "attack_types": sorted({h.attack_type for h in confirmed}),
            "action_recommend": (
                confirmed_max.action_recommend if confirmed_max else "alert"),
            "rule_count": len(hits),
        }

    def stats(self) -> dict:
        """运行状态 + 加载诊断。

        整改方案 §六 / §十一：必须能判断"是否有规则未加载 / 被跳过"。
        """
        if not self._rules:
            return {"rules_count": 0, "enabled_count": 0, "shadow_count": 0,
                    "compiled_count": len(self._compiled),
                    "load_errors": list(self._load_errors),
                    "skipped_rules": self._skipped_rule_names(),
                    "run_mode": "unavailable",
                    # 两个分支都带这个键：normal/unavailable 为空，degraded 非空
                    "degraded_reasons": [],
                    "engine": "legacy" if not PY_SIGMA_AVAILABLE else "pySigma(no rules)"}
        # 整改方案 §六.2：degraded = 「启用了 Legacy 兜底**或部分规则未加载**」。
        # 修复前只看「有没有编译出规则」，于是「1 好 1 坏」也报 normal ——
        # 运维看到 normal 就以为规则库完好，而 load_errors 里明明记着失败。
        degraded_reasons: list = []
        if self._load_errors:
            degraded_reasons.append("load_errors")
        if self._skipped_rule_names():
            degraded_reasons.append("skipped_rules")
        if not self._compiled:
            mode = "degraded" if self._legacy is not None else "unavailable"
        elif degraded_reasons:
            mode = "degraded"
        else:
            mode = "normal"
        return {
            "rules_count": len(self._rules),
            "enabled_count": sum(1 for r in self._rules if r.get("enabled", True)),
            "shadow_count": sum(1 for r in self._rules if r.get("shadow_mode")),
            "compiled_count": len(self._compiled),
            "load_errors": list(self._load_errors),
            "skipped_rules": self._skipped_rule_names(),
            "run_mode": mode,
            "degraded_reasons": degraded_reasons,
            "attack_types": sorted({r["attack_type"] for r in self._rules}),
            "severity_distribution": {
                s: sum(1 for r in self._rules if r["severity"] == s)
                for s in ["critical", "high", "medium", "low"]
            },
            "engine": "pySigma" if self._compiled else "legacy-fallback",
            "rules_dir": self.rules_dir,
        }

    def _skipped_rule_names(self) -> list[str]:
        """声明了但没编译进谓词的规则（逐文件失败会被 _build_compiled 静默 skip）。"""
        compiled_ids = {m.get("rule_id") for m, _ in self._compiled}
        return sorted(
            r.get("name", "") for r in self._rules
            if r.get("rule_id") not in compiled_ids)

    def list_rules(self) -> list[dict]:
        return [{"rule_id": r["rule_id"], "name": r["name"], "description": r["description"],
                 "severity": r["severity"], "attack_type": r["attack_type"],
                 "confidence": r["confidence"], "action_recommend": r["action_recommend"],
                 "enabled": r.get("enabled", True), "type": "sigma",
                 "conditions": {"sigma_yaml": r.get("yaml", "")}}
                for r in self._rules]

    def rules(self):
        return self._rules
