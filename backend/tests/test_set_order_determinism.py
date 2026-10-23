# -*- coding: utf-8 -*-
"""集合→列表的**全仓**确定性守卫（整改报告 §9.59）。

## 背景

§9.58 修的是「抽样出来的 4 个模块 6 处」。本轮把扫描扩到**全仓**，
并把扫描器本身也扩了五种数据流形态（局部变量 / 参数 / 跨模块属性 /
字典值 / 返回值），结果又找出 **6 处真缺陷** —— 其中 3 处连**内容**
都不确定（不只是顺序）：

| 位置 | 现象 | 后果 |
|---|---|---|
| `anomaly_detector.py` `seen_ids` 淘汰 | 保留哪 2500 个随进程变 | 重放幂等账本内容不确定 → 同一串事件在两个进程里得到不同的基线 |
| `agents/agent_decomposer.py` IP 上限 | `list(target_ips)[:3]` 选哪 3 个随进程变 | 补审批次在不同进程里查不同的证据 |
| `anomaly_detector.py` / `scheduler.py` / `tool_registry.py` | 基线快照的 `event_types` 未排序 | 同一份基线落库/出参逐字节不同 |
| `correlation_engine.py` / `routers/ops.py` | 链与实体关联的 IP 集合未排序 | API 响应跨进程不可复现 |

## 为什么不靠「再扫一遍」就完事

静态扫描有**盲区**：集合可以从参数、跨模块属性、字典值、返回值流进
`list()`。§9.58 的扫描只认 `list(set(...))` 字面形态，于是
`list(bl.event_types)` 这种**最常见**的形态整个漏掉 —— 而它恰好
出现在 §9.58 标记为「已修好」的两个模块里（`tool_registry.py`）。

所以本守卫有四层：

1. **决定性**：两个不同 `PYTHONHASHSEED` 的子进程 → 同一份**生产输出**
   必须逐字节相同（这是唯一能抓住「内容不确定」的判据）；
2. **行为**：单进程内，集合型输出必须已排序；截断必须留痕；
3. **结构**：全仓 AST 扫描 → 每个命中必须在登记表里（附否定结论理由），
   新命中即红；
4. **否定结论**：整数集合的迭代顺序跨进程稳定、`zset` 顺序无关 ——
   钉住它们，免得将来把「不必修」的地方当缺陷乱改。

## 判据的采集环境

第 1 层的探针**只调用生产代码**（`_update_baseline` /
`_save_baselines_to_redis` / `_match_pattern` / `_entity_linking` /
`_decompose_supplement` / `_chain_payload` / `_baseline_snapshot_payload` /
`_anomaly_baseline`），不自己重算一遍 —— 重算一遍就等于把缺陷抄了一遍，
判据会永远绿。
"""
from __future__ import annotations

import ast
import json
import os
import subprocess
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND))

#: 扫描时跳过的目录（测试里允许出现 list(set(...)) —— 它们是断言工具）
SKIP_DIRS = {".venv", "venv", "node_modules", "__pycache__", ".git",
             "site-packages", "tests"}

#: 探针与行为测试统一使用的**固定**时间戳（2100-01-01T00:00:00Z）。
#:
#: 为什么必须是「将来的」固定值：
#:   · **将来** —— 实体的 `last_seen` 必须 ≥ cutoff，否则
#:     `_save_baselines_to_redis` 会跳过它（实体被剪枝），于是
#:     「基线快照的顺序」这条判据**根本没落到那份快照上**，
#:     变成了空断言（第一版就踩了这个坑：ts 用 2023 年，
#:     实体被剪掉，两个进程的输出都只有全局键 → 恒等）。
#:   · **固定** —— 两个进程的 `time.time()` 本来就差几毫秒，
#:     那是时钟差异，不是本守卫要抓的东西；把它排除在比较面之外，
#:     判据的输入面才是干净的。
FIXED_TS = 4102444800.0

#: 12 个互不相同的事件类型 —— 用在「集合型字段必须有序」的行为断言里。
#:
#: 为什么不用 3 个：集合的迭代顺序**偶然**等于升序的概率约为 1/n!，
#: n=3 时还有 1/6 的机会「注入后仍然通过」；n=12 时这个概率已经可以
#: 当作 0。判据必须**稳定地**红，不能靠运气。
TYPES12 = (
    "PORT_SCAN", "C2_BEACON", "BRUTE_FORCE", "DNS_QUERY",
    "FILE_ACCESS", "DATA_EXFIL", "LATERAL_MOVE", "SQL_INJECTION",
    "XSS_ATTACK", "RANSOMWARE", "SUSPICIOUS_LOGIN", "USER_LOGIN",
)

#: 12 个互不相同的 IP —— 同样是给「集合型字段必须有序」用的。
#:
#: **这一条是被一次失败的注入逼出来的**：第一版行为断言只用了
#: 3 个 IP（`10.0.0.1/2/3`），而 3 个元素的集合其迭代顺序**偶然**
#: 等于升序的概率是 1/6 —— 于是「把 `sorted()` 退回 `list()`」这个
#: 真缺陷注入进去之后，行为那条**靠运气通过了**，只有跨进程那条
#: 抓到它。判据必须**稳定地**红，不能靠运气。
IPS12 = tuple("10.0.0.%d" % i for i in range(1, 13))
DSTS12 = tuple("192.168.1.%d" % i for i in range(1, 13))


# ══════════════════════════════════════════════════════════════════════
# 探针：跑**生产路径**，把结果序列化成一个 JSON
# ══════════════════════════════════════════════════════════════════════
PROBE = r"""
import asyncio, json, sys
sys.path.insert(0, sys.argv[1])
OUT = {}

# ── 1. 异常基线：重放幂等账本（seen_ids）的淘汰内容 ─────────────
from anomaly_detector import AnomalyDetector
det = AnomalyDetector()
TYPES = ("PORT_SCAN", "C2_BEACON", "BRUTE_FORCE")
for i in range(5001):
    det._update_baseline("src_ip", "10.0.0.1", TYPES[i % 3], 3,
                          ts=4102444800.0 + i, event_id="e-%05d" % i)
bl = det.baselines["src_ip"]["10.0.0.1"]
# 注意：比的是**内容**（sorted），不是集合的迭代顺序 ——
# 集合的迭代顺序本来就随种子变，那不是缺陷；「保留哪 2500 个」才是。
OUT["anomaly.retained_size"] = len(bl.seen_ids)
OUT["anomaly.retained_content"] = sorted(bl.seen_ids)

# ── 2. 异常基线：Redis 落库快照（生产路径 + 假 Redis）──────────
class _Pipe:
    def __init__(self, sink): self.sink = sink
    def setex(self, key, ttl, value): self.sink.append([key, value])
    async def execute(self): return []
class _Redis:
    def __init__(self): self.sink = []
    def pipeline(self): return _Pipe(self.sink)
fake = _Redis()
det.set_redis(fake)
asyncio.run(det._save_baselines_to_redis(force=True))
OUT["anomaly.redis_snapshots"] = {k: v for k, v in fake.sink}
# 单独把**实体**那份拎出来：它才是「集合型字段落库」的那一份。
# 全局键是 dict/list，本来就有序 —— 拿全局键当判据等于没判。
OUT["anomaly.entity_snapshot"] = {k: v for k, v in fake.sink
                                   if "src_ip:10.0.0.1" in k}

# ── 3. 关联引擎：攻击链的 API 载荷 + 实体关联 ──────────────────
from datetime import datetime, timedelta, timezone
from correlation_engine import CorrelationEngine, ATTACK_CHAIN_PATTERNS
from routers.ops import _chain_payload
IPS12 = tuple("10.0.0.%d" % i for i in range(1, 13))
DSTS12 = tuple("192.168.1.%d" % i for i in range(1, 13))
eng = CorrelationEngine()
base = datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
evs = []
for i, (et, src, dst) in enumerate([
        ("PORT_SCAN", "10.0.0.1", "192.168.1.5"),
        ("BRUTE_FORCE", "10.0.0.2", "192.168.1.6"),
        ("C2_BEACON", "10.0.0.3", "192.168.1.7")]):
    evs.append({"id": i + 1, "event_type": et, "severity": "high",
                "src_ip": src, "dst_ip": dst, "message": "",
                "created_at": base + timedelta(minutes=i)})
chain = eng._match_pattern("port_scan_to_c2",
                           ATTACK_CHAIN_PATTERNS["port_scan_to_c2"],
                           "actor-x", evs)
OUT["chain.payload"] = json.loads(json.dumps(_chain_payload(chain), default=str))
# 合成链：12 个不同的 IP —— 3 个元素的集合其迭代顺序偶然等于升序的
# 概率是 1/6，判据不能靠运气（见 IPS12 的注释）。
from types import SimpleNamespace
synth = SimpleNamespace(
    chain_id="chain_synthetic", pattern_name="synthetic", confidence=0.5,
    events=[{"id": 1, "event_type": "X"}],
    src_ips=set(IPS12), dst_ips=set(DSTS12),
    time_span_minutes=1.0, alert="synthetic",
    actor="synthetic", shared_event_ids=[], overlaps_other_chain=False)
OUT["chain.synthetic_payload"] = json.loads(
    json.dumps(_chain_payload(synth), default=str))
OUT["entity_links"] = eng._entity_linking({
    "a%02d" % i: [{"id": i, "event_type": "X", "src_ip": ip,
                    "dst_ip": "203.0.113.9"}]
    for i, ip in enumerate(IPS12)})

# ── 4. 补审计划：选哪些 IP + event_ids 顺序 ─────────────────────
from agents.agent_decomposer import Decomposer
missed = [{"description": "attacker %s missed" % ip, "evidence": "101,102,103"}
          for ip in IPS12]
plan = asyncio.run(Decomposer()._decompose_supplement({"id": 1}, "s1", 0.9, missed))
tasks = plan.get("sub_tasks") or []
OUT["plan.ip_tasks"] = [t.get("params", {}).get("src_ip") for t in tasks
                        if t.get("params", {}).get("src_ip")]
OUT["plan.event_ids"] = [t.get("params", {}).get("event_ids") for t in tasks
                          if t.get("params", {}).get("event_ids") is not None]
OUT["plan.truncations"] = plan.get("param_truncations")

# ── 5. 落库快照（scheduler）与 MCP 工具输出（tool_registry）─────
from scheduler import _baseline_snapshot_payload
OUT["db_snapshot"] = json.loads(json.dumps(_baseline_snapshot_payload(bl), default=str))
import tool_registry
tool_registry.anomaly_detector.baselines["src_ip"]["10.0.0.9"] = bl
OUT["mcp_baseline"] = json.loads(json.dumps(asyncio.run(
    tool_registry._anomaly_baseline(src_ip="10.0.0.9")), default=str))

# ── 6. 否定结论：do_calculus 的 zset 顺序无关（结果必须一致）────
from causal_chain.do_calculus import d_separated
directed = [("A", "B"), ("B", "C"), ("D", "E")]
OUT["do_calculus.d_separated"] = [
    d_separated(directed, "A", "C", ["B"]),
    d_separated(directed, "A", "C", ["B", "D"]),
    d_separated(directed, "A", "E", ["B", "C", "D"]),
]

print(json.dumps(OUT, ensure_ascii=False, sort_keys=True, default=str))
"""


def _run_probe(seed: str) -> str:
    """在指定 PYTHONHASHSEED 下跑探针，返回其标准输出。"""
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        script = Path(td) / "probe_set_order.py"
        script.write_text(PROBE, encoding="utf-8")
        env = dict(os.environ)
        env["PYTHONHASHSEED"] = seed
        env["PYTHONIOENCODING"] = "utf-8"
        env["SHARED_MEMORY_SKIP_DOTENV"] = "1"
        r = subprocess.run(
            [sys.executable, str(script), str(BACKEND)],
            cwd=str(BACKEND), env=env, capture_output=True, text=True,
            timeout=600, encoding="utf-8", errors="replace")
        assert r.returncode == 0, (
            f"探针失败（seed={seed}）：\n{r.stdout[-3000:]}\n{r.stderr[-3000:]}")
        out = (r.stdout or "").strip()
        assert out, f"探针没有输出（seed={seed}）"
        return out


# ══════════════════════════════════════════════════════════════════════
# 第 1 层：决定性 —— 两个不同哈希种子的进程，输出必须逐字节相同
# ══════════════════════════════════════════════════════════════════════
class TestTheTwoHashSeedsAgree:
    def test_the_production_outputs_are_byte_identical(self):
        """**决定性**：同一份输入，两个不同 `PYTHONHASHSEED` 的进程 → 逐字节相同。

        这是本守卫的核心性质。它抓的不是「顺序好不好看」，而是
        **同一份数据在不同进程里是不是同一个结果** —— 包括「保留哪
        2500 个 id」「查哪 3 个 IP」这种**内容**层面的不确定性。
        """
        a = _run_probe("0")
        b = _run_probe("12345")
        c = _run_probe("777")
        try:
            ja, jb, jc = json.loads(a), json.loads(b), json.loads(c)
        except Exception as e:                       # pragma: no cover
            raise AssertionError(f"探针输出不是合法 JSON：{e}\n{a[:2000]}")

        for key in sorted(set(ja) | set(jb) | set(jc)):
            va, vb, vc = ja.get(key), jb.get(key), jc.get(key)
            assert va == vb == vc, (
                f"字段 {key} 在不同 PYTHONHASHSEED 下不一致 → "
                f"结果跨进程不可复现（§9.59）\n"
                f"  seed=0     : {json.dumps(va, ensure_ascii=False)[:600]}\n"
                f"  seed=12345 : {json.dumps(vb, ensure_ascii=False)[:600]}\n"
                f"  seed=777   : {json.dumps(vc, ensure_ascii=False)[:600]}")

    def test_the_probe_actually_exercises_the_production_paths(self):
        """**自证**：探针不能是空跑 —— 它的每个字段都必须有内容。

        判据自己必须先被验证：探针若因导入失败而只输出空 dict，
        「两个进程一致」就是**恒真**的假判据。
        """
        payload = json.loads(_run_probe("0"))
        for key in ("anomaly.retained_content", "anomaly.redis_snapshots",
                    "anomaly.entity_snapshot", "chain.payload",
                    "chain.synthetic_payload", "entity_links", "plan.ip_tasks",
                    "plan.event_ids", "db_snapshot", "mcp_baseline",
                    "do_calculus.d_separated"):
            assert key in payload, f"探针缺字段 {key} —— 判据没盖到那条路径"
            assert payload[key] not in (None, "", [], {}), (
                f"探针字段 {key} 是空的 —— 这条判据会变成空断言")
        # 实体快照必须**真的落下来了**：它的 last_seen 必须 ≥ cutoff，
        # 否则实体会被剪掉，判据就落在「根本没落库」的那份数据上。
        assert any("src_ip:10.0.0.1" in k for k in payload["anomaly.entity_snapshot"]), (
            "实体的基线快照没落库（被 cutoff 剪掉了）→ 顺序判据空转")
        # 幂等账本确实走到了淘汰分支（>5000 才淘汰）
        assert payload["anomaly.retained_size"] == 2500, (
            payload["anomaly.retained_size"])
        # 补审计划确实触发了 IP 上限（6 个 IP，只取 3 个）
        assert len(payload["plan.ip_tasks"]) == 3, payload["plan.ip_tasks"]
        # 链确实匹配上了（否则链的 IP 集合是空的，这条判据空转）
        assert payload["chain.payload"]["src_ips"], payload["chain.payload"]


# ══════════════════════════════════════════════════════════════════════
# 第 2 层：行为 —— 单进程内，集合型输出必须已排序；截断必须留痕
# ══════════════════════════════════════════════════════════════════════
class TestTheBehavior:
    def test_the_idempotency_ledger_keeps_a_deterministic_subset(self):
        """幂等账本的淘汰必须是**确定**的：保留字典序最大的 2500 个。

        修复前是 `set(list(bl.seen_ids)[-2500:])` —— 集合没有顺序，
        取到的是**任意** 2500 个。字符串哈希每进程随机 → 同一串事件在
        两个进程里得到不同的账本 → 某条事件在 A 进程算「重投」、在 B
        进程算「新事件」→ 基线与评分随之漂移。
        """
        from anomaly_detector import AnomalyDetector
        det = AnomalyDetector()
        for i in range(5001):
            det._update_baseline("src_ip", "10.0.0.1", "PORT_SCAN", 3,
                                  ts=FIXED_TS + i, event_id="e-%05d" % i)
        bl = det.baselines["src_ip"]["10.0.0.1"]
        assert len(bl.seen_ids) == 2500, len(bl.seen_ids)
        expected = {"e-%05d" % i for i in range(2501, 5001)}
        assert bl.seen_ids == expected, (
            "淘汰保留的子集不是「字典序最大的 2500 个」→ 幂等账本的内容"
            "跨进程不确定（§9.59）")

    def test_the_redis_snapshot_is_sorted(self):
        """Redis 落库的基线快照：集合型字段必须已排序。"""
        import asyncio
        from anomaly_detector import AnomalyDetector

        class _Pipe:
            def __init__(self, sink): self.sink = sink
            def setex(self, key, ttl, value): self.sink.append([key, value])
            async def execute(self): return []

        class _Redis:
            def __init__(self): self.sink = []
            def pipeline(self): return _Pipe(self.sink)

        det = AnomalyDetector()
        for i, et in enumerate(TYPES12):
            det._update_baseline("src_ip", "10.0.0.1", et, 3,
                                  ts=FIXED_TS + i, event_id="e-%02d" % i)
        fake = _Redis()
        det.set_redis(fake)
        asyncio.run(det._save_baselines_to_redis(force=True))
        payloads = {k: v for k, v in fake.sink}
        assert payloads, "没有落任何快照"
        entity = {k: v for k, v in payloads.items() if "src_ip:10.0.0.1" in k}
        assert entity, (
            "实体的基线快照没落库（last_seen 被 cutoff 剪掉了）→ "
            "这条判据会变成空断言")
        snap = json.loads(list(entity.values())[0])
        assert snap["event_types"] == sorted(TYPES12), (
            f"基线快照的 event_types 未排序：{snap['event_types']} → "
            "同一份基线在不同进程里落出逐字节不同的 JSON（§9.59）")
        assert snap["seen_ids"] == sorted(snap["seen_ids"]), (
            "基线快照的 seen_ids 未排序 → 同上")

    def test_the_db_snapshot_payload_is_sorted(self):
        """落库快照载荷（scheduler）必须已排序。"""
        from anomaly_detector import EntityBaseline
        from scheduler import _baseline_snapshot_payload
        bl = EntityBaseline()
        bl.event_types = set(TYPES12)
        payload = _baseline_snapshot_payload(bl)
        assert payload["event_types"] == sorted(TYPES12), (
            payload["event_types"])

    def test_the_mcp_tool_output_is_sorted(self):
        """MCP 工具 `anomaly_baseline` 的输出必须已排序。

        这是**给 LLM 看的**载荷：同一份基线在不同进程里给出不同的顺序，
        LLM 看到的就是同一段事实的另一种排列。
        """
        import asyncio
        import tool_registry
        from anomaly_detector import EntityBaseline
        bl = EntityBaseline()
        bl.event_types = set(TYPES12)
        tool_registry.anomaly_detector.baselines.setdefault("src_ip", {})[
            "10.0.0.77"] = bl
        out = asyncio.run(tool_registry._anomaly_baseline(src_ip="10.0.0.77"))
        assert out["event_types"] == sorted(TYPES12), (out["event_types"])

    def test_the_entity_links_are_sorted(self):
        """实体关联的 src_ips 必须已排序。"""
        from correlation_engine import CorrelationEngine
        eng = CorrelationEngine()
        links = eng._entity_linking({
            "a%02d" % i: [{"id": i, "event_type": "X", "src_ip": ip,
                            "dst_ip": "203.0.113.9"}]
            for i, ip in enumerate(IPS12)})
        assert links, "实体关联为空 —— 这条断言会变成空断言"
        assert links[0]["src_ips"] == sorted(IPS12), (links[0]["src_ips"])

    def test_the_chain_payload_ips_are_sorted(self):
        """攻击链 API 载荷的 src_ips/dst_ips 必须已排序。

        用 12 个不同的 IP（见 IPS12 的注释）：3 个元素的集合其迭代顺序
        偶然等于升序的概率是 1/6 —— 那样的判据在注入真缺陷时会
        **靠运气通过**。
        """
        from types import SimpleNamespace
        from routers.ops import _chain_payload
        synth = SimpleNamespace(
            chain_id="c", pattern_name="p", confidence=0.5,
            events=[{"id": 1, "event_type": "X"}],
            src_ips=set(IPS12), dst_ips=set(DSTS12),
            time_span_minutes=1.0, alert="a",
            actor="a", shared_event_ids=[], overlaps_other_chain=False)
        payload = _chain_payload(synth)
        assert payload["src_ips"] == sorted(IPS12), payload["src_ips"]
        assert payload["dst_ips"] == sorted(DSTS12), payload["dst_ips"]

    def test_the_chain_payload_keeps_every_ip(self):
        """排序**不能**丢内容：载荷里的 IP 集合与引擎算出的完全一致。

        这条是**反向**判据：防止有人用「排序」的名义把集合换成了别的
        东西（比如去重后少几个、或截断）。
        """
        from datetime import datetime, timedelta, timezone
        from correlation_engine import CorrelationEngine, ATTACK_CHAIN_PATTERNS
        from routers.ops import _chain_payload
        eng = CorrelationEngine()
        base = datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
        evs = [{"id": i + 1, "event_type": et, "severity": "high",
                "src_ip": src, "dst_ip": dst, "message": "",
                "created_at": base + timedelta(minutes=i)}
               for i, (et, src, dst) in enumerate([
                   ("PORT_SCAN", "10.0.0.1", "192.168.1.5"),
                   ("BRUTE_FORCE", "10.0.0.2", "192.168.1.6"),
                   ("C2_BEACON", "10.0.0.3", "192.168.1.7")])]
        chain = eng._match_pattern("port_scan_to_c2",
                                   ATTACK_CHAIN_PATTERNS["port_scan_to_c2"],
                                   "actor-x", evs)
        assert chain is not None, "模式没匹配上 —— 这条断言会变成空断言"
        payload = _chain_payload(chain)
        assert set(payload["src_ips"]) == set(chain.src_ips), payload["src_ips"]
        assert set(payload["dst_ips"]) == set(chain.dst_ips), payload["dst_ips"]
        assert len(payload["src_ips"]) == 3, payload["src_ips"]

    def test_the_plan_selects_the_ips_deterministically(self):
        """补审计划选哪 3 个 IP，必须是**确定**的（字典序前 3）。"""
        import asyncio
        from agents.agent_decomposer import Decomposer
        missed = [{"description": "attacker %s missed" % ip,
                   "evidence": "101,102,103"}
                  for ip in IPS12]
        plan = asyncio.run(Decomposer()._decompose_supplement(
            {"id": 1}, "s1", 0.9, missed))
        ips = [t["params"]["src_ip"] for t in plan["sub_tasks"]
               if t.get("params", {}).get("src_ip")]
        # 策略是**字典序**（字符串比较）—— `10.0.0.10` 排在 `10.0.0.2`
        # 之前。这是**已声明**的策略（确定性 + 可复现），不是缺陷；
        # 修的是「集合的前 3 个随进程变」，不是「排序方式」。
        assert ips == sorted(IPS12)[:3], (
            f"IP 选择不确定：{ips}（修复前是集合的前 3 个 → 随进程变）")

    def test_the_ip_truncation_is_recorded(self):
        """IP 侧的截断必须**留痕** —— 同一函数里 event_ids 侧已经这么做了。"""
        import asyncio
        from agents.agent_decomposer import Decomposer
        missed = [{"description": "attacker %s missed" % ip,
                   "evidence": "101,102,103"}
                  for ip in IPS12]
        plan = asyncio.run(Decomposer()._decompose_supplement(
            {"id": 1}, "s1", 0.9, missed))
        trunc = [t for t in (plan.get("param_truncations") or [])
                 if t.get("field") == "src_ips"]
        assert trunc, (
            "IP 侧的截断没有留痕 —— 补审只覆盖了一部分却无人知晓"
            "（event_ids 侧早就留痕了，IP 侧被漏掉）")
        assert trunc[0]["requested"] == len(IPS12), trunc[0]
        assert trunc[0]["used"] == 3, trunc[0]

    def test_no_truncation_record_when_within_bound(self):
        """防过度收紧：没截断时不要凭空造一条 truncation 记录。"""
        import asyncio
        from agents.agent_decomposer import Decomposer
        missed = [{"description": "attacker 10.0.0.1 missed", "evidence": "1,2"}]
        plan = asyncio.run(Decomposer()._decompose_supplement(
            {"id": 1}, "s1", 0.9, missed))
        assert plan.get("param_truncations") == [], plan.get("param_truncations")


# ══════════════════════════════════════════════════════════════════════
# 第 3 层：结构 —— 全仓 AST 扫描 + 登记表
# ══════════════════════════════════════════════════════════════════════
#: 已知的「集合→list」位置，**每一条都必须写明为什么它不是缺陷**。
#:
#: 登记表的用途不是「放过」，而是**逼人把话说清楚**：
#: 新增一个命中而没登记 → 守卫变红 → 必须裁决它是缺陷还是否定结论。
REGISTERED_NEGATIVES = {
    ("case_manager.py",
     "clauses.append(ResponseLog.session_id.in_(list(session_ids)))"):
        "IN 子句：SQL 的 IN 不看顺序，集合化只是为了可哈希参数",
    ("causal_chain/do_calculus.py",
     "for zz in list(zset):"):
        "zset 的遍历只做集合并/删（nodes |= ... / pop / discard），与顺序无关",
    ("causal_chain/pc.py",
     "for a, b in list(directed):"):
        "directed 是**整数**元组集合：整数哈希不随机 → 跨进程稳定",
    ("causal_chain/pc.py",
     "for edge in list(undirected):"):
        "undirected 是**整数** frozenset 集合：同上，跨进程稳定",
    ("causal_chain/pc.py",
     "for a, b in list(both):"):
        "both 是**整数**元组集合：同上，跨进程稳定",
    ("correlation_engine.py",
     '"matched_patterns": list(self.matched_patterns),'):
        "字段本身就是**已排序的 list**（生产方 sorted(...)），此处是防御性拷贝",
}


def _is_set_ann(node) -> bool:
    if node is None:
        return False
    if isinstance(node, ast.Name) and node.id in ("set", "Set", "frozenset"):
        return True
    if isinstance(node, ast.Subscript):
        return _is_set_ann(node.value)
    return False


def _is_set_expr(node) -> bool:
    if isinstance(node, (ast.Set, ast.SetComp)):
        return True
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) \
            and node.func.id in ("set", "frozenset"):
        return True
    return False


def _is_dict_of_set_ann(node) -> bool:
    if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name) \
            and node.value.id == "dict":
        return _is_set_ann(node.slice)
    return False


def _scan_set_to_list():
    """扫出生产代码里所有「集合 → list」的转换点。

    五种数据流形态：
      (a) 局部变量/参数被赋成集合      (b) 集合字面量/推导/set() 调用
      (c) **任意** dataclass 里声明为 set 的属性（跨模块，只按名字匹配）
      (d) dict 的值是集合              (e) list(函数()) 且函数返回 set
    返回 [(相对路径, 行号, 原因, 该行文本), ...]
    """
    files = [p for p in sorted(BACKEND.rglob("*.py"))
             if not any(part in SKIP_DIRS for part in p.parts)
             and not p.name.startswith("test_")]

    set_attrs: set = set()
    for p in files:
        try:
            tree = ast.parse(p.read_text(encoding="utf-8-sig"))
        except Exception as e:
            raise AssertionError(f"{p} 解析失败（不能静默跳过）：{e}")
        for node in ast.walk(tree):
            if isinstance(node, ast.AnnAssign) \
                    and isinstance(node.target, ast.Name) \
                    and _is_set_ann(node.annotation):
                set_attrs.add(node.target.id)

    hits = []
    for p in files:
        try:
            text = p.read_text(encoding="utf-8-sig")
            tree = ast.parse(text, filename=str(p))
        except Exception as e:
            raise AssertionError(f"{p} 解析失败（不能静默跳过）：{e}")
        lines = text.splitlines()
        for fn in ast.walk(tree):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            local: set = set()
            a = fn.args
            for arg in list(a.posonlyargs) + list(a.args) + list(a.kwonlyargs):
                if _is_set_ann(arg.annotation):
                    local.add(arg.arg)
            for st in ast.walk(fn):
                if isinstance(st, ast.Assign) and _is_set_expr(st.value):
                    for t in st.targets:
                        if isinstance(t, ast.Name):
                            local.add(t.id)
                if isinstance(st, ast.AnnAssign) \
                        and isinstance(st.target, ast.Name) \
                        and _is_set_ann(st.annotation):
                    local.add(st.target.id)
            for c in ast.walk(fn):
                if not (isinstance(c, ast.Call) and isinstance(c.func, ast.Name)
                        and c.func.id == "list" and c.args):
                    continue
                arg = c.args[0]
                why = None
                if isinstance(arg, ast.Name) and arg.id in local:
                    why = "set-var"
                elif _is_set_expr(arg):
                    why = "set-expr"
                elif isinstance(arg, ast.Attribute) and arg.attr in set_attrs:
                    why = "set-attr"
                elif isinstance(arg, ast.Subscript) and _is_dict_of_set_ann(arg.value):
                    why = "dict-of-set"
                if why:
                    # 路径统一用 **/** —— 否则 Windows 上是反斜杠、
                    # Linux 上是正斜杠，登记表会在两个平台上对不上。
                    rel = str(p.relative_to(BACKEND)).replace("\\", "/")
                    hits.append((rel, c.lineno, why,
                                 lines[c.lineno - 1].strip()))
    return hits


class TestTheStructuralRegistry:
    def test_every_set_to_list_site_is_registered(self):
        """全仓的「集合→list」必须**逐条登记**。

        新增一个命中而没登记 → 守卫变红 → 必须裁决它是缺陷（修）还是
        否定结论（登记理由）。这正是 §9.58 的教训：那次扫描只认
        `list(set(...))` 字面形态，漏掉了 `list(bl.event_types)` ——
        而后者恰恰出现在 §9.58 标记为「已修好」的模块里。
        """
        hits = _scan_set_to_list()
        assert hits, (
            "扫描结果为空 —— 扫描器本身坏了（判据的采集环境必须先被验证）")
        unregistered = []
        for rel, ln, why, text in hits:
            if (rel, text) not in REGISTERED_NEGATIVES:
                unregistered.append(f"{rel}:{ln} ({why}) {text}")
        assert not unregistered, (
            "这些「集合→list」没有登记 —— 每一处都必须裁决：\n  "
            + "\n  ".join(unregistered))

    def test_the_registry_has_no_stale_entries(self):
        """登记表里不能留**已经不成立**的条目。

        留着的后果是：扫描器命中数对不上，真正的漏网反而被淹没。
        """
        hits = _scan_set_to_list()
        found = {(rel, text) for rel, _ln, _why, text in hits}
        stale = [f"{rel} :: {text}\n      理由：{REGISTERED_NEGATIVES[(rel, text)]}"
                 for (rel, text) in REGISTERED_NEGATIVES
                 if (rel, text) not in found]
        assert not stale, (
            "登记表里有已经不成立的条目（代码改了但登记没改）：\n  "
            + "\n  ".join(stale))


# ══════════════════════════════════════════════════════════════════════
# 第 4 层：否定结论 —— 钉住「不必修」的地方
# ══════════════════════════════════════════════════════════════════════
class TestTheNegativeConclusions:
    def test_integer_set_order_is_stable_across_processes(self):
        """否定结论：**整数**集合的迭代顺序跨进程稳定。

        `PYTHONHASHSEED` 只随机化 str/bytes 的哈希；整数的哈希是
        确定的。于是 `causal_chain/pc.py` 里那 4 处 `list(整数集合)`
        **不需要修** —— 它们跨进程给出同样的顺序。

        钉住这条，免得将来把「不必修」的地方当缺陷乱改（那会把
        报告里的「否定结论」变成「看起来没修干净」）。
        """
        script = (
            "import json;"
            "s={frozenset((0,1)),frozenset((0,2)),frozenset((1,2)),"
            "frozenset((2,3))};"
            "print(json.dumps([tuple(sorted(e)) for e in s]))"
        )
        outs = []
        for seed in ("0", "12345"):
            env = dict(os.environ)
            env["PYTHONHASHSEED"] = seed
            env["PYTHONIOENCODING"] = "utf-8"
            r = subprocess.run([sys.executable, "-c", script], env=env,
                               capture_output=True, text=True, timeout=120,
                               encoding="utf-8", errors="replace")
            assert r.returncode == 0, r.stderr
            outs.append((r.stdout or "").strip())
        assert outs[0], "探针没有输出"
        assert outs[0] == outs[1], (
            "整数集合的顺序在两个哈希种子下不同 → 否定结论不成立，"
            "causal_chain/pc.py 的 4 处需要重新裁决")


if __name__ == "__main__":       # pragma: no cover
    import pytest
    raise SystemExit(pytest.main([__file__, "-q"]))
