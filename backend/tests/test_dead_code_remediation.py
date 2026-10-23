"""
§十一.2 死代码处置 —— 把「声明了却无人自增」的指标接回真实路径。

背景（全仓引用扫描查证，非推测）：

  metrics.inc_intel_ioc / metrics.inc_capture_packet 在 backend 内**零调用点**，
  但两者都被声明并暴露：

    * soc_intel_ioc_total       → routers/capabilities.py:20 用它给
                                  /api/capabilities/status 的 threat_intel.count 赋值
    * soc_capture_packets_total → /metrics 暴露给 Grafana

  零自增点意味着这两个数字**结构上恒为 0**。面板会显示
  「threat_intel: enabled=true, count=0」——而 0 看上去像
  「一切正常，只是暂时没数据」，这比压根没有这个字段更糟：
  采集链路断了，而读数与「没事件」完全同形。

  本文件把计数器接回真实路径，并对「接回去之后读数确实会动」端到端验证：
  走真实 poll_feed / 真实 _on_packet_scapy，再用 capabilities.py 自己的
  _parse_metric_values 去解析 generate_latest() 的输出——
  即前端真正看到的那条链路，而不是只看计数器对象。

对照项（§十一.2 查证后确认**不是**缺陷，据实钉住，避免后人重复排查）：

  * veto_gates.has_admitted_threat_claims —— 零引用，**刻意保持未接线**。
    生产判定用 `len(threat_claims) > 0`，与它在剥离不变式下恒等
    （strip_ungrounded_claims 的 admitted 只收 ADMITTED_VERDICTS）。
    但它判的是「grounding_verdict 注解在不在」而非 grounding 本身：
    实测接线会让 3 条既有用例转红（有证据的威胁被降级成 insufficient_evidence）。
    详见 veto_gates.has_admitted_threat_claims 的 docstring。
  * trace_hook.register_trace_recorder —— 覆盖钩子；模块末尾 (line 162)
    已把 _recorder 初始化为 _lazy_recorder，emit_trace 照常落 AgentTrace。
  * auth.TokenPayload / ingest_pipeline.PersistItem / memory_tree.CorrelationGroup /
    models.ToolSignature / models.ToolAnomaly —— ORM 模型与 dataclass，
    零引用是框架常态，删除会掉表。
"""
from __future__ import annotations

import asyncio

import pytest
from prometheus_client import REGISTRY, generate_latest

from routers.capabilities import _parse_metric_values


# ── 工具：Prometheus 计数器是进程级全局的，测试之间会累积 ──
# 因此一律取「测试前后差值」，绝不直接断言绝对值 —— 否则单跑绿、全量跑红。

def _sample(name: str, **labels) -> float:
    v = REGISTRY.get_sample_value(name, labels or None)
    return float(v) if v is not None else 0.0


# ═══════════════════════════════════════════
# 1. 威胁情报 IOC 计数 —— 修复 /api/capabilities/status 的恒 0
# ═══════════════════════════════════════════

_CSV = (
    "type,value,threat_type,severity\n"
    "ip,1.2.3.4,c2,high\n"
    "domain,evil.example.com,c2,high\n"
    "sha256," + "a" * 64 + ",malware,critical\n"
)


def _write_feed(tmp_path, name: str = "unit-csv"):
    p = tmp_path / f"{name}.csv"
    p.write_text(_CSV, encoding="utf-8")
    return {"feed_type": "csv", "url": str(p), "name": name}


def test_intel_counter_moves_on_real_poll_feed(tmp_path):
    """真实拉一次 CSV 情报源，soc_intel_ioc_total 必须按拉到的条数自增。

    修复前该计数器零调用点，无论拉多少次都恒为 0。
    """
    from threat_intel.stix_taxii import TaxiiClient

    cfg = _write_feed(tmp_path)
    before = _sample("soc_intel_ioc_total", source="unit-csv")

    iocs = asyncio.run(TaxiiClient().poll_feed(cfg))

    assert len(iocs) == 3, "前提：CSV 真的被解析出 3 条 IOC"
    after = _sample("soc_intel_ioc_total", source="unit-csv")
    assert after - before == 3, (
        "拉了 3 条 IOC，计数器却没有 +3 —— 埋点仍未接线"
    )


def test_intel_counter_labels_by_feed_source(tmp_path):
    """source 标签取自 feed 配置，两个源不能被合并成一个数字。

    否则「拉了 MISP 300 条 / CSV 2 条」显示成 302，
    定位不到是哪个源在跑还是哪个源挂了。
    """
    from threat_intel.stix_taxii import TaxiiClient

    client = TaxiiClient()
    b_csv = _sample("soc_intel_ioc_total", source="src-csv")
    b_otx = _sample("soc_intel_ioc_total", source="src-otx")

    asyncio.run(client.poll_feed(_write_feed(tmp_path, name="src-csv")))
    asyncio.run(client.poll_feed(_write_feed(tmp_path, name="src-otx")))

    assert _sample("soc_intel_ioc_total", source="src-csv") - b_csv == 3
    assert _sample("soc_intel_ioc_total", source="src-otx") - b_otx == 3


def test_intel_counter_not_incremented_when_feed_missing(tmp_path):
    """文件不存在的源拉不到 IOC —— 计数不能前进。

    否则「配置写错了路径」会被误读成「情报源在工作，只是没命中」。
    """
    from threat_intel.stix_taxii import TaxiiClient

    before = _sample("soc_intel_ioc_total", source="no-such-feed")
    iocs = asyncio.run(TaxiiClient().poll_feed(
        {"feed_type": "csv", "url": str(tmp_path / "missing.csv"), "name": "no-such-feed"}
    ))
    assert iocs == []
    assert _sample("soc_intel_ioc_total", source="no-such-feed") == before


def test_capabilities_endpoint_count_is_no_longer_structurally_zero(tmp_path):
    """端到端：走 capabilities.py 自己的解析器，证明 API 字段是真读数。

    这一条才是真正的验收点 —— 前端看的是 _parse_metric_values 的输出，
    不是 REGISTRY 的原始样本。只断言计数器自增，证明不了前端那个数字会动。
    """
    from threat_intel.stix_taxii import TaxiiClient

    asyncio.run(TaxiiClient().poll_feed(_write_feed(tmp_path, name="e2e-feed")))

    text = generate_latest().decode()
    total = _parse_metric_values(text, "soc_intel_ioc_")

    assert total >= 3, (
        f"/api/capabilities/status 会把 threat_intel.count 报成 {total}，"
        "而实际拉到了 3 条 —— 前端面板读数与真实采集量脱节"
    )


# ═══════════════════════════════════════════
# 2. NDR 抓包计数 —— 修复 /metrics 上恒 0 的导出指标
# ═══════════════════════════════════════════

def _pkt():
    from traffic_capture.capture_engine import PacketInfo

    return PacketInfo(
        timestamp=0.0, src_ip="10.0.0.1", dst_ip="10.0.0.2",
        src_port=1234, dst_port=80, protocol="TCP", length=150,
    )


def test_capture_counter_moves_on_real_ingest_path():
    """真实走 CaptureEngine._on_packet_scapy —— 全仓唯一的包摄入收敛点。

    AF_PACKET / DPDK 后端在 capture_engine.py 里是占位实现（只 sleep），
    不摄入任何包，所以这一处覆盖了全部真实抓包流量。
    """
    from traffic_capture.capture_engine import CaptureEngine

    eng = CaptureEngine()
    # 绕开 scapy 解析（依赖未必装），只桩掉「解析」这一步，
    # 被测的仍是真实摄入路径里的计数埋点位置。
    eng._parse_scapy_packet = lambda pkt: _pkt()
    eng._loop = None  # 无事件循环 → 不触发 handler 调度

    before = _sample("soc_capture_packets_total")
    eng._on_packet_scapy(object())
    after = _sample("soc_capture_packets_total")

    assert after - before == 1, "摄入了一个包，soc_capture_packets_total 没有 +1"
    assert eng.stats.packets_captured == 1


def test_capture_counter_ignores_unparsable_packet():
    """解析不出 PacketInfo 的包不计数。

    非 IP/非 TCP-UDP-ICMP 流量会走到 _parse_scapy_packet → None，
    把它们算进「抓包数」会让该指标虚高，且与 packets_captured 口径不一致。
    """
    from traffic_capture.capture_engine import CaptureEngine

    eng = CaptureEngine()
    eng._parse_scapy_packet = lambda pkt: None
    eng._loop = None

    before = _sample("soc_capture_packets_total")
    eng._on_packet_scapy(object())

    assert _sample("soc_capture_packets_total") == before
    assert eng.stats.packets_captured == 0


def test_capture_counter_tracks_stats_counter_over_many_packets():
    """指标与 CaptureStats.packets_captured 口径必须一致（多次摄入不漂移）。"""
    from traffic_capture.capture_engine import CaptureEngine

    eng = CaptureEngine()
    eng._parse_scapy_packet = lambda pkt: _pkt()
    eng._loop = None

    before = _sample("soc_capture_packets_total")
    n = 50
    for _ in range(n):
        eng._on_packet_scapy(object())

    assert _sample("soc_capture_packets_total") - before == n
    assert eng.stats.packets_captured == n


# ═══════════════════════════════════════════
# 3. P0-1 不变式显式化 —— has_admitted_threat_claims
# ═══════════════════════════════════════════

def test_has_admitted_threat_claims_rejects_unstripped_claims():
    """带 threat_claims 不等于「有已通过 grounding 的 claim」。

    这正是 agent_executor 原来 `admitted_count > 0` 的盲区：
    一条**未经 strip** 的原始 claim（无 grounding_verdict）会让计数为 1，
    而 P0-1 要求确认闸必须有已通过 grounding 的 claim 才放行。
    """
    from veto_gates import has_admitted_threat_claims

    raw = [{"type": "XSS", "summary": "注入", "evidence_ids": []}]
    assert len(raw) > 0, "前提：naive 计数会认为有 claim"
    assert has_admitted_threat_claims(raw) is False, \
        "未剥离的 claim 不得被当作已通过 grounding 的 claim"


def test_has_admitted_threat_claims_accepts_both_admitted_verdicts():
    from veto_gates import has_admitted_threat_claims

    grounded = [{"grounding_verdict": "grounded"}]
    partial = [{"grounding_verdict": "partially_grounded"}]
    ungrounded = [{"grounding_verdict": "ungrounded"}]

    assert has_admitted_threat_claims(grounded) is True
    assert has_admitted_threat_claims(partial) is True
    assert has_admitted_threat_claims(ungrounded) is False
    assert has_admitted_threat_claims([]) is False


def test_strip_output_makes_both_spellings_equivalent():
    """钉住「今天行为不变」：strip 后的 admitted 上，两种写法恒等。

    这是本次改动的诚实边界 —— agent_executor 的判定结果今天**不会**变，
    变的是它不再依赖「谁写 threat_claims」的隐式约定。
    """
    from veto_gates import has_admitted_threat_claims, strip_ungrounded_claims

    admitted, discarded = strip_ungrounded_claims([
        {"type": "C2", "summary": "回连", "evidence_ids": ["e1"], "evidence_quotes": ["q"]},
        {"type": "XSS", "summary": "无据"},
    ])

    assert len(admitted) == 1 and len(discarded) == 1
    assert (len(admitted) > 0) == has_admitted_threat_claims(admitted) is True


def test_verdict_check_diverges_from_production_count_on_unannotated_claims():
    """钉住一个**已查证的行为差异** —— 这正是该函数不接线的原因。

    生产判定用 `len(threat_claims) > 0`。对一个「带真实证据引用、只是没带
    grounding_verdict 注解」的 claim，两种写法给出**相反**答案。

    这本身不是缺陷：生产路径上 threat_claims 必由 strip_ungrounded_claims 写入，
    注解必然存在（见 test_strip_output_makes_both_spellings_equivalent）。
    但它意味着「把 has_admitted_threat_claims 接到确认闸」会**改写结论** ——
    有证据的威胁被降级成 insufficient_evidence 并强制人审。因此本次刻意不接线。

    真正的行为守卫在 test_p1a_evidence_and_recheck.py::
    TestRecheckMonotonicity::test_silence_is_not_contradiction
    —— 那里断言 res.verdict != "insufficient_evidence"，
    一旦有人接线，那条用例会红。本条只负责记录**为什么**。
    """
    from veto_gates import has_admitted_threat_claims

    well_evidenced_but_unannotated = [{
        "type": "C2", "summary": "周期性 beacon",
        "evidence_ids": [1], "evidence_quotes": ["beacon"],
    }]

    # 生产口径：有 claim 即算有据
    assert len(well_evidenced_but_unannotated) > 0
    # 注解口径：判的是 grounding_verdict 字段在不在，不是 grounding 本身
    assert has_admitted_threat_claims(well_evidenced_but_unannotated) is False


def test_strip_always_writes_the_annotation_so_the_two_agree_in_production():
    """生产不变式的正面证明：strip 产出的 claim 必带注解。

    确认闸用 `> 0` 是安全的，正因为这一条成立。
    """
    from veto_gates import strip_ungrounded_claims

    admitted, _ = strip_ungrounded_claims([
        {"type": "C2", "summary": "回连", "evidence_ids": ["e1"], "evidence_quotes": ["q"]},
    ])
    assert admitted, "前提：claim 应被 admitted"
    for c in admitted:
        assert c.get("grounding_verdict") in {"grounded", "partially_grounded"}, \
            "strip 产出的 claim 缺 grounding_verdict 注解 —— 确认闸的条数口径即不再安全"
