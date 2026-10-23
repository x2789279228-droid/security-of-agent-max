"""B 类高级能力 metrics — 验证指标定义与计数递增。"""
import pytest


def test_b_metrics_defined():
    """metrics.py 定义 NDR/EDR/intel/sandbox/phishing 指标。"""
    from metrics import (NDR_FLOWS, TLS_SESSIONS, CAPTURE_PACKETS, EDR_EVENTS,
                         INTEL_IOC, IOC_MATCHES, SANDBOX_SUBMISSIONS, PHISHING_DETECTIONS)
    assert NDR_FLOWS._name == "soc_ndr_flows"
    assert TLS_SESSIONS._name == "soc_tls_sessions"
    assert CAPTURE_PACKETS._name == "soc_capture_packets"
    assert EDR_EVENTS._name == "soc_edr_events"
    assert INTEL_IOC._name == "soc_intel_ioc"
    assert IOC_MATCHES._name == "soc_ioc_matches"
    assert SANDBOX_SUBMISSIONS._name == "soc_sandbox_submissions"
    assert PHISHING_DETECTIONS._name == "soc_phishing_detections"


def test_b_metrics_inc_correct():
    """inc_* 函数使指标递增且带正确 label。

    **断言的是「恰好 +1」，不是「值恰好是 1.0」。**

    这两者不一样，而原写法用的是后者：`assert "soc_ioc_matches_total 1.0" in out`
    要求这个进程级计数器从没被别的东西碰过。Prometheus 计数器是**进程级全局**的，
    于是这条断言只在「本文件恰好第一个跑到」时成立 ——
    单跑绿、全量里只要前面有别的用例动过同一个计数器就红
    （2026-10-18 由 `test_capability_tile_counts.py` 踩到：
    它的前提守卫走真实的 `ioc_matcher.match()`，会自增同一个计数器）。

    所以拆成两半守住它本来要守的东西：
      * **格式**（指标名 + label 在 /metrics 文本里长什么样）—— 仍在文本上断言；
      * **数值**（自增恰好 1）—— 取前后差值。

    两者都不放宽：label 写错照样红，函数不自增照样红。
    """
    import re

    from prometheus_client import generate_latest
    from metrics import (inc_ndr_flow, inc_tls_session, inc_edr_event,
                         inc_sandbox_submission, inc_ioc_match, inc_phishing_detection)

    def value(text, series):
        """从 exposition 文本里取某个 series 的浮点值（无 label 形式）。"""
        m = re.search(rf"^{re.escape(series)}(?:\{{[^}}]*\}})? ([0-9.eE+-]+)$",
                      text, re.M)
        return float(m.group(1)) if m else None

    base = generate_latest().decode()

    inc_ndr_flow("tcp")
    inc_edr_event("sysmon")
    inc_sandbox_submission("file")
    inc_ioc_match()
    inc_phishing_detection("email")
    inc_tls_session()

    out = generate_latest().decode()

    # ── 格式：指标确实以带 label 的形式暴露在 /metrics 里 ──
    assert "soc_ndr_flows_total" in out
    for series in (
        'soc_edr_events_total{source="sysmon"}',
        'soc_sandbox_submissions_total{kind="file"}',
        "soc_ioc_matches_total",
        'soc_phishing_detections_total{category="email"}',
        "soc_tls_sessions_total",
    ):
        assert series in out, f"{series} 没出现在 /metrics 文本里"

    # ── 数值：每个都恰好 +1 ──
    # series 必须写全 label：写成裸指标名时正则会匹配到「第一条带 label 的子线」，
    # 匹配到哪条取决于标签值的输出顺序 —— 那等于把一个顺序依赖
    # 换成了另一个顺序依赖。
    for series in (
        'soc_ndr_flows_total{protocol="tcp"}',
        'soc_edr_events_total{source="sysmon"}',
        'soc_sandbox_submissions_total{kind="file"}',
        "soc_ioc_matches_total",
        'soc_phishing_detections_total{category="email"}',
        "soc_tls_sessions_total",
    ):
        before_v, after_v = value(base, series), value(out, series)
        assert before_v is not None or after_v is not None, f"{series} 前值取不到"
        delta = (after_v or 0.0) - (before_v or 0.0)
        assert delta == 1.0, f"{series} 应恰好 +1，实际 {before_v} -> {after_v}"


def test_capabilities_parse_metric_values():
    """capabilities 接口的指标解析能提取 B 类计数。"""
    from routers.capabilities import _parse_metric_values
    text = (
        "# HELP soc_ndr_flows_total x\n"
        'soc_ndr_flows_total{protocol="tcp"} 3.0\n'
        'soc_ndr_flows_total{protocol="udp"} 2.0\n'
        "soc_edr_events_total{source=\"sysmon\"} 1.0\n"
        "soc_phishing_detections_total{category=\"email\"} 2.0\n"
    )
    assert _parse_metric_values(text, "soc_ndr_flows_") == 5
    assert _parse_metric_values(text, "soc_edr_events_") == 1
    assert _parse_metric_values(text, "soc_phishing_detections_") == 2
