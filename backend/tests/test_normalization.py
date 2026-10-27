# -*- coding: utf-8 -*-
"""检测输入规范化（normalization）回归：对抗向量、FP 守卫、引擎接线、L3 口径。

背景（2026-10-25 检测输入规范化升级）：
  * EVASION 基线对抗保持率 0.438 —— url_encode 击穿 6/8 家族；
  * 根因是接入/匹配路径只归一化字段名、不做值规范化；
  * 修复 = sigma 引擎匹配视图前置 canonical_matching_view（原始事件不改写）。

向量集与 flink-jobs UrlCanonicalizerTest 同步（镜像约定）：任何一侧
新增/修改向量，另一侧必须同改。
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))
os.environ.setdefault("SHARED_MEMORY_SKIP_DOTENV", "1")

from normalization import (  # noqa: E402
    MAX_DECODE_ROUNDS,
    canonical_matching_view,
    canonical_message,
    canonical_url,
    deep_decode,
)
from sigma_engine.engine import PySigmaDetector  # noqa: E402

RULES_DIR = BACKEND / "sigma_engine" / "rules"


# ══════════════════════════════════════════════════════════════
# 解码单元
# ══════════════════════════════════════════════════════════════

def test_deep_decode_single_round():
    assert deep_decode("%3Cscript%3E") == "<script>"


def test_deep_decode_double_encoding():
    assert deep_decode("%252e%252e%252f") == "../"


def test_deep_decode_legacy_unicode_escape():
    assert deep_decode("%u003cscript%u003e") == "<script>"


def test_deep_decode_bomb_capped():
    bomb = "a" + "%25" * 20
    out = deep_decode(bomb)
    assert len(out) <= len(bomb), "解码炸弹必须被轮数上限约束"


def test_decode_rounds_constant_covers_double():
    assert MAX_DECODE_ROUNDS >= 2, "double_encode 向量需要至少 2 轮"


# ══════════════════════════════════════════════════════════════
# canonical_url / canonical_message
# ══════════════════════════════════════════════════════════════

@pytest.mark.parametrize("raw,expected", [
    ("/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E",
     "/search?q=<script>alert(1)</script>"),
    ("%252e%252e%252f%252e%252e%252fetc%252fshadow", "../../etc/shadow"),
    ("/a?q=%u003cscript%u003e", "/a?q=<script>"),
    ("/files?name=..%5C..%5Cwindows", "/files?name=../../windows"),
    # 点段折叠刻意不做: ../ 子串必须保留(规则库对原始形式写)
    ("/files/download?name=../../../etc/passwd",
     "/files/download?name=../../../etc/passwd"),
    # 良性 URL 原样
    ("https://cdn.corp/static/app.9f2c.js?page=1",
     "https://cdn.corp/static/app.9f2c.js?page=1"),
    # '+' 不转空格(那是 form 编码语义)
    ("/a+b", "/a+b"),
    # 非法 hex 原样保留(与 unquote errors='replace' 一致)
    ("/x%zz", "/x%zz"),
])
def test_canonical_url_vectors(raw, expected):
    assert canonical_url(raw) == expected


def test_canonical_url_null_byte_stripped():
    assert canonical_url("/x%00y") == "/xy"


def test_canonical_message_decodes_but_keeps_backslash():
    assert canonical_message("CPU %32%35%25 load") == "CPU 25% load"
    assert canonical_message("C:\\Windows\\system32") == "C:\\Windows\\system32"


# ══════════════════════════════════════════════════════════════
# 匹配视图：原始不改写 / 惰性拷贝 / dst 补齐
# ══════════════════════════════════════════════════════════════

def test_view_overlays_canonical_and_keeps_raw():
    ev = {"url": "%2E%2E%2Fetc", "message": "x", "src_ip": "1.2.3.4"}
    view = canonical_matching_view(ev)
    assert view["url"] == "../etc"
    assert ev["url"] == "%2E%2E%2Fetc", "原始事件不得被改写"
    assert view is not ev, "有变化时必须是浅拷贝"


def test_view_no_change_returns_same_object():
    ev = {"url": "/plain", "a": 1}
    assert canonical_matching_view(ev) is ev


def test_view_fills_missing_dst_from_url_authority():
    ev = {"url": "http://10.30.30.30:9200/_cat/indices?v", "method": "GET"}
    view = canonical_matching_view(ev)
    assert view["dst_ip"] == "10.30.30.30"
    assert view["dst_port"] == 9200


def test_view_never_overrides_existing_dst():
    ev = {"url": "http://10.30.30.30:9200/_cat/indices?v",
          "dst_ip": "10.0.0.5"}
    view = canonical_matching_view(ev)
    assert view["dst_ip"] == "10.0.0.5", "dst_ip 已有权威值时不得覆盖"


def test_view_encoded_url_dst_fill():
    ev = {"url": "%68ttp%3A%2F%2F10.30.30.30%3A9200%2F_cat%2Findices%3Fv"}
    view = canonical_matching_view(ev)
    assert view["url"] == "http://10.30.30.30:9200/_cat/indices?v"
    assert view["dst_port"] == 9200


def test_view_non_string_and_missing_fields_safe():
    assert canonical_matching_view({"url": None})["url"] is None
    assert canonical_matching_view({}) == {}
    assert canonical_matching_view({"url": 123})["url"] == 123


# ══════════════════════════════════════════════════════════════
# 引擎接线：编码变体必须被检出（EVASION 家族代表向量）
# ══════════════════════════════════════════════════════════════

def _detector() -> PySigmaDetector:
    return PySigmaDetector(str(RULES_DIR), enforce=True)


def _enforced_hit(detector: PySigmaDetector, url: str) -> bool:
    from eval_datasets.evasion_retention import _enforced_hit
    return _enforced_hit(detector, url)


@pytest.mark.parametrize("family,variant", [
    ("traversal", "%2Ffiles%2Fdownload%3Fname%3D..%2F..%2F..%2Fetc%2Fpasswd"),
    ("traversal_encoded",
     "%252Ffiles%252Fdownload%253Fname%253D%252E%252E%252F%252E%252E%252Fetc%252Fpasswd"),
    ("xss", "%2Fsearch%3Fq%3D%3Cscript%3Ealert%281%29%3C%2Fscript%3E"),
    ("es_unauth", "%68ttp%3A%2F%2F10.30.30.30%3A9200%2F_cat%2Findices%3Fv"),
    ("env_probe", "%2F%2Eenv"),
    ("git_probe", "%2F%2Egit%2Fconfig"),
    ("actuator", "%2Factuator%2Fenv"),
    ("webshell_cmd", "%2Fdebug%2Ephp%3Fcmd%3Did"),
])
def test_engine_detects_encoded_variants(family, variant):
    """编码变体经规范化视图必须命中 —— 回归锚点 = EVASION 报告保持率。

    接线前这些向量全部漏检（保持率 0.438 的直接成分）。
    """
    assert _enforced_hit(_detector(), variant), (
        f"{family} 的编码变体漏检 —— 规范化视图被移除或语义回归"
    )


def test_engine_benign_still_clean():
    """FP 守卫：良性 URL（含合法 percent 编码）不得命中执行层规则。"""
    det = _detector()
    benign = [
        "https://app.corp/api/orders?page=1&size=20",
        "https://cdn.corp/static/app.9f2c.js",
        "https://app.corp/api/orders?q=%E8%AE%A2%E5%8D%95%E6%9F%A5%E8%AF%A2",
        "https://app.corp/download?file=%E6%8A%A5%E8%A1%A8.pdf",
    ]
    for u in benign:
        assert not _enforced_hit(det, u), f"良性 URL 误报: {u}"


def test_engine_baseline_cases_unchanged():
    """标定集良性/近似样本在规范化视图下仍零误报（L1 口径不回归）。"""
    from eval_datasets.detection_cases import sigma_cases
    det = _detector()
    for c in sigma_cases():
        if c["expect"] != "benign":
            continue
        hits = [h for h in det.detect(dict(c["event"]))
                if "[SHADOW]" not in (h.description or "")
                and not h.requires_aggregation]
        assert not hits, f"{c['id']} 在规范化视图下产生误报"


# ══════════════════════════════════════════════════════════════
# ablation L3 口径修复回归
# ══════════════════════════════════════════════════════════════

def test_ablation_layer3_vocabulary_aligned():
    """词表 bug 回归：修复前用 malicious/benign 数 detected/not_detected
    样本 → TP/FP/FN 恒 0。现在必须产出真实计数。

    阶段B（severity_shift）后：fixture 无 known_gap，全部正类进入
    二分类且真实检出 —— L3 测量面即全标定集。
    """
    from eval_datasets.ablation import layer3_anomaly
    r = layer3_anomaly()
    a = r["anomaly"]
    total_binary = a["tp"] + a["fp"] + a["fn"]
    assert total_binary > 0, (
        "L3 二分类计数为 0 —— 词表对齐回归（malicious/benign vs "
        "detected/not_detected）复发了"
    )
    assert a["tp"] + a["fn"] > 0, "正类计数缺失"
    assert a["tp"] == 3 and a["fn"] == 0, (
        f"L3 正类应 3 检出 0 漏报, 实际 TP={a['tp']} FN={a['fn']} —— "
        "severity_shift 维度回归")
    assert a["fp"] == 0, "L3 负类出现误报"
    # known_gap 已全部修复摘除；inconclusive 仍排除并单列
    assert r["known_gap_excluded"] == 0
    assert r["inconclusive_excluded"] >= 1


def test_anomaly_known_gaps_registered():
    """[FIXED 反向回归] 两条标定缺口已由 severity_shift 维度修复：
    fixture 不再登记 known_gap，原缺口样本必须真实检出。"""
    from eval_datasets.detection_cases import anomaly_cases
    from eval_datasets.evaluate_detection import run_anomaly
    gaps = {c["id"]: c["known_gap"] for c in anomaly_cases() if c.get("known_gap")}
    assert not gaps, f"已修复的缺口必须摘除登记, 实际仍有: {sorted(gaps)}"
    for r in run_anomaly():
        if r["id"] in ("ANO-P-02", "ANO-P-03"):
            assert r["status"] == "detected", (
                f"{r['id']} 回归为漏检 —— severity_shift 维度回归")


# ══════════════════════════════════════════════════════════════
# taxonomy / 策略补全回归
# ══════════════════════════════════════════════════════════════

def test_path_traversal_resolved_and_covered():
    """消融 L5 uncovered_type 回归：path_traversal 必须有叶子+专属策略。"""
    from response_engine.response_policies import policy_engine
    from response_engine.threat_taxonomy import classify
    cls = classify("path_traversal")
    assert cls.leaf == "PATH_TRAVERSAL"
    assert cls.category == "INTRUSION"
    m = policy_engine.match(threat_type=cls.leaf, confidence=0.85,
                            severity="high", src_ip="203.0.113.7",
                            category=cls.category)
    assert m.matched and m.match_status.value != "uncertain", (
        "PATH_TRAVERSAL 必须有专属策略命中, 而不是 UNCERTAIN 兜底"
    )


# ══════════════════════════════════════════════════════════════
# 评测器/引擎同源（防双实现漂移）+ mapping 健壮性
# ══════════════════════════════════════════════════════════════

def test_replay_decoder_equivalence():
    """replay 评测器的 deep_decode 已委托 normalization —— 在 CSIC fixture
    全量 URL 上与历史实现（固定 2 轮 unquote）逐条等价。

    双实现漂移的后果：REPLAY 报告的"规范化口径"与引擎匹配视图对不上，
    改前改后对比失去同口径前提。
    等价范围 = percent 编码（历史实现的能力面）；%uXXXX 是文档声明的
    **超集**能力（normalization 独有），单列钉住，不入等价断言。"""
    import urllib.parse
    import json
    from eval_datasets.replay_public_datasets import deep_decode as replay_decode

    fixture = BACKEND / "eval_datasets" / "fixtures" / "csic_sample.jsonl"
    if fixture.is_file():
        urls = []
        for ln in fixture.read_text(encoding="utf-8").splitlines():
            if ln.strip():
                urls.append(json.loads(ln).get("event", {}).get("url", ""))
    else:
        urls = []
    urls += [
        "%252e%252e%252fetc%252fpasswd", "%3Cscript%3E", "/plain?q=a+b",
        "%2E%2E%2F", "http://h:9200/_cat",
    ]
    for u in urls:
        legacy = u
        for _ in range(2):
            legacy = urllib.parse.unquote(legacy)
        assert replay_decode(u) == legacy, f"解码器漂移: {u!r}"
    # 超集能力（历史实现不解码 %u, 规范化解码器解码）—— 显式钉住
    assert replay_decode("%u003cscript%u003e") == "<script>"


def test_apply_mapping_port_split_is_ipv4_strict():
    """mapping 端口拆分健壮性：IPv4:port 才拆，IPv6/畸形值原样保留。

    修复前 rpartition(":") 会把 2001:db8::1 拆坏成 host=2001:db8: + port=1，
    目标地址从此匹配不上任何规则（宁可不拆端口，不可损坏地址）。"""
    from sigma_engine.mapping import apply_mapping
    r = apply_mapping({"dst_ip": "1.2.3.4:9200"})
    assert r["dst_ip"] == "1.2.3.4" and r["dst_port"] == 9200
    r6 = apply_mapping({"dst_ip": "2001:db8::1"})
    assert r6["dst_ip"] == "2001:db8::1" and "dst_port" not in r6
    rp = apply_mapping({"dst_ip": "10.0.0.5"})
    assert rp["dst_ip"] == "10.0.0.5" and "dst_port" not in rp
