# -*- coding: utf-8 -*-
"""B1 规则库扩容守卫 — SigmaHQ 批量导入的安全底线与映射通路。

锁定四件事:
  1. 规则库规模 ≥150 条且全部编译(run_mode=normal, 0 load_errors)
     —— 扩容成果不许悄悄缩水;
  2. 批量导入规则(hq_*/c_006+)全部 x-soc-shadow=true 且 action=alert
     —— 影子规则没有执行权, 转 enforcement 必须由回测数据驱动,
     任何人不能在导入器/手写规则里夹带"导入即封禁";
  3. 字段映射通路活着: 取一条 hq 规则的真实匹配值反推平台原生字段,
     构造事件必须命中 —— mapping.py 的别名表(c-uri/c-useragent/cs-host...)
     改坏时此处即红;
  4. 良性事件不触发批量规则(冒烟)。

数据来源: sigma_engine/SIGMAHQ_MANIFEST.json(importer 产物)。
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest
import yaml

os.environ.setdefault("SHARED_MEMORY_SKIP_DOTENV", "1")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sigma_engine.engine import PySigmaDetector  # noqa: E402

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES_DIR = os.path.join(BACKEND, "sigma_engine", "rules")
ACTIVE_DIR = os.path.join(BACKEND, "sigma_engine", "rules_community_active")

BULK_PREFIXES = ("hq_", "c_006", "c_007", "c_008", "c_009", "c_010",
                 "c_011", "c_012", "c_013", "c_014")
MIN_TOTAL_RULES = 150

# sigma 字段 → 平台原生字段(反向映射, 与 mapping.py 对齐)
REVERSE_FIELD = {
    "c-uri": "url", "cs-uri": "url", "cs-uri-query": "url", "c-uri-query": "url",
    "UriPath": "url", "UriQuery": "url", "url": "url",
    "c-useragent": "user_agent", "cs-user-agent": "user_agent",
    "UserAgent": "user_agent", "user_agent": "user_agent",
    "cs-method": "method", "c-method": "method", "method": "method",
    "sc-status": "status", "c-status": "status", "status": "status",
    "cs-host": "host", "c-host": "host", "host": "host",
    "source.ip": "src_ip", "client-ip": "src_ip",
    "destination.ip": "dst_ip", "message": "message",
}


@pytest.fixture(scope="module")
def detector() -> PySigmaDetector:
    det = PySigmaDetector(RULES_DIR, enforce=True)
    st = det.stats()
    assert st.get("run_mode") == "normal", f"规则库非 normal: {st}"
    assert not st.get("load_errors"), f"存在加载错误: {st['load_errors'][:3]}"
    return det


def _bulk_files() -> list[Path]:
    files = []
    for f in sorted(Path(ACTIVE_DIR).glob("*.yml")):
        if f.name.startswith(BULK_PREFIXES):
            files.append(f)
    return files


def test_library_size_at_least_150_all_compiled(detector: PySigmaDetector):
    st = detector.stats()
    assert st.get("rules_count", 0) >= MIN_TOTAL_RULES, (
        f"规则库缩水: {st.get('rules_count')} < {MIN_TOTAL_RULES}"
    )
    assert st.get("compiled_count") == st.get("rules_count")
    assert st.get("shadow_count", 0) >= 100, "影子层不应缩水(批量导入主体)"


def test_bulk_rules_are_shadow_alert_only():
    """批量导入规则默认影子 + 仅告警 —— 导入即封禁仍被禁止。

    唯一豁免（B3 终版 2026-11-01）：带**完整转正溯源**的规则可以是执法态 ——
    `x-soc-promoted-at` + `x-soc-promotion-fp` + `x-soc-promotion-hits`
    三字段齐全 = 经双门禁引擎(FP=0 + 攻击命中)合法转正；缺任一字段的
    非影子规则仍视为"直接翻标志"而失败。
    """
    bad = []
    promoted = 0
    for f in _bulk_files():
        d = yaml.safe_load(f.read_text(encoding="utf-8"))
        if d.get("x-soc-shadow") is not True:
            has_provenance = all(
                d.get(k) is not None for k in
                ("x-soc-promoted-at", "x-soc-promotion-fp", "x-soc-promotion-hits"))
            if has_provenance:
                promoted += 1
                continue  # 带溯源的合法转正(见 docstring)
            bad.append(f"{f.name}: x-soc-shadow={d.get('x-soc-shadow')}")
        if d.get("x-soc-action") not in (None, "alert"):
            bad.append(f"{f.name}: x-soc-action={d.get('x-soc-action')}")
        if not d.get("x-soc-sigmahq-id") and not d.get("x-soc-source"):
            bad.append(f"{f.name}: 缺溯源字段(sigmahq-id/source)")
    assert not bad, "影子安全底线被破坏:\n  " + "\n  ".join(bad[:10])


def _first_literal(d: dict):
    """取规则 selection 里第一个无通配符的标量值 + 其 sigma 字段名。"""
    for k, v in (d.get("detection") or {}).items():
        if k == "condition" or not isinstance(v, dict):
            continue
        for fk, fv in v.items():
            base = fk.split("|", 1)[0]
            plat = REVERSE_FIELD.get(base)
            if not plat:
                continue
            vals = fv if isinstance(fv, list) else [fv]
            for val in vals:
                if isinstance(val, str) and val and not any(
                        c in val for c in "*?[]"):
                    return plat, base, val
    return None, None, None


def test_mapping_path_alive_rule_value_hits_via_platform_field(detector: PySigmaDetector):
    """从 hq 规则取真实匹配值 → 平台原生字段构造事件 → 必须命中(影子)。"""
    hit_case = None
    for f in _bulk_files():
        d = yaml.safe_load(f.read_text(encoding="utf-8"))
        plat, sigma_field, val = _first_literal(d)
        if not plat:
            continue
        hit_case = (f.name, plat, sigma_field, val)
        break
    assert hit_case, "没有可用的字面量测试样例"
    fname, plat, sigma_field, val = hit_case

    ev = {
        "event": "REQ", "src_ip": "203.0.113.50", "dst_ip": "10.0.0.5",
        "severity": "info", "confidence": 50,
        plat: val,
        "message": f"mapping-path smoke {val}",
    }
    hits = [h for h in detector.detect(ev) if h.rule_id and h.matched_fields]
    shadow_hits = [h for h in hits if "[SHADOW]" in (h.description or "")]
    assert shadow_hits, (
        f"平台字段 {plat}={val!r} 未触发任何影子规则 —— mapping.py 别名或编译链被改坏"
        f" (样例规则 {fname}, sigma 字段 {sigma_field})"
    )


def test_benign_event_no_bulk_hits(detector: PySigmaDetector):
    ev = {
        "event": "REQ", "src_ip": "203.0.113.77", "dst_ip": "10.0.0.5",
        "url": "/index.html", "method": "GET", "status": 200,
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) smoke-test",
        "message": "benign page view", "severity": "info", "confidence": 50,
    }
    hits = [h for h in detector.detect(ev) if "[SHADOW]" in (h.description or "")]
    assert not hits, f"良性首页浏览触发了影子规则: {[h.rule_id for h in hits]}"
