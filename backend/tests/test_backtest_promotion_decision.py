"""B3 转正决策语义 + 一键回影子机制 —— REMEDIATION-PLAN 路线 B3 红线钉死。"""
from pathlib import Path

import yaml

from eval_datasets.backtest_promotion import (
    KEEP_FP,
    KEEP_NO_EVIDENCE,
    PROMOTE,
    _rewrite_rule,
    decide,
)


def test_fp_is_hard_gate():
    """良性误报是硬门禁：fp>0 时攻击命中再多也不转正。"""
    assert decide(fp=1, atk_hits=999) == KEEP_FP
    assert decide(fp=10, atk_hits=10) == KEEP_FP


def test_promote_requires_zero_fp_and_evidence():
    assert decide(fp=0, atk_hits=1) == PROMOTE
    assert decide(fp=0, atk_hits=42) == PROMOTE


def test_no_evidence_stays_shadow():
    """fp=0 且无攻击命中 = 无证据不转正（CSIC web 语料上进程面规则即此形态）。"""
    assert decide(fp=0, atk_hits=0) == KEEP_NO_EVIDENCE


def _tmp_rule(tmp_path: Path) -> Path:
    doc = {
        "title": "probe rule",
        "detection": {"selection": {"url": ["a", "b"]},
                      "condition": "selection"},
        "x-soc-id": "C-9999",
        "x-soc-shadow": True,
    }
    p = tmp_path / "hq_probe.yml"
    p.write_text(yaml.safe_dump(doc, allow_unicode=True, sort_keys=False),
                 encoding="utf-8")
    return p


def test_rewrite_rule_promote_then_demote_roundtrip(tmp_path):
    """转正/回影子幂等往返：shadow false←→true + 溯源字段增删。"""
    p = _tmp_rule(tmp_path)

    changed = _rewrite_rule(p, shadow=False,
                            promotion={"date": "2026-10-30", "fp": 0, "atk_hits": 7})
    assert changed is True
    d = yaml.safe_load(p.read_text(encoding="utf-8"))
    assert d["x-soc-shadow"] is False
    assert d["x-soc-promoted-at"] == "2026-10-30"
    assert d["x-soc-promotion-hits"] == 7

    # 再转正一次（幂等：changed=False）
    assert _rewrite_rule(p, shadow=False,
                         promotion={"date": "2026-10-30", "fp": 0, "atk_hits": 7}) is False

    # 一键回影子：shadow=true + 清除溯源字段
    assert _rewrite_rule(p, shadow=True) is True
    d = yaml.safe_load(p.read_text(encoding="utf-8"))
    assert d["x-soc-shadow"] is True
    assert "x-soc-promoted-at" not in d and "x-soc-promotion-hits" not in d
    # detection 原文保留（不许转正机制破坏规则体）
    assert d["detection"]["selection"]["url"] == ["a", "b"]
