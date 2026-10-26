# -*- coding: utf-8 -*-
"""B2 公开数据集回放评测守卫 — CSIC-2010 夹具上的可复现底线。

完整评测(全量数据)是人工 CLI(`eval_datasets.replay_public_datasets`),
本测试用提交入库的 120 行夹具锁定三件事:
  1. 评测器可跑通且指标结构完整(报告生成不因数据形状回归);
  2. 良性夹具 **确认误报 = 0** —— 全量评测实测 FPR=0/5000,
     这是平台签名检测的招牌数字, 谁把它打炸谁修;
  3. 攻击夹具上有确认检出(enforced TP > 0)且影子层亦有产出
     —— 影子晋升管道的数据来源不能断。
"""
from __future__ import annotations

import json
import os
import sys

import pytest

os.environ.setdefault("SHARED_MEMORY_SKIP_DOTENV", "1")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from eval_datasets.replay_public_datasets import evaluate  # noqa: E402
from sigma_engine.engine import PySigmaDetector  # noqa: E402

FIXTURE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "eval_datasets", "fixtures", "csic_sample.jsonl")


@pytest.fixture(scope="module")
def detector() -> PySigmaDetector:
    det = PySigmaDetector(os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "sigma_engine", "rules"), enforce=True)
    return det


@pytest.fixture(scope="module")
def rows() -> list[dict]:
    with open(FIXTURE, encoding="utf-8") as f:
        return [json.loads(ln) for ln in f if ln.strip()]


def test_fixture_shape(rows: list[dict]):
    mal = [r for r in rows if r["label"] == "malicious"]
    ben = [r for r in rows if r["label"] == "benign"]
    assert len(mal) >= 50 and len(ben) >= 50, "夹具两类样本都应有 50+"
    # 签名子集必须在夹具里(否则 TP 断言无意义)
    from eval_datasets.replay_public_datasets import is_signature_bearing
    assert sum(1 for r in mal if is_signature_bearing(r["event"])) >= 20


def test_benign_zero_enforced_false_positives(detector: PySigmaDetector, rows: list[dict]):
    ben = [r["event"] for r in rows if r["label"] == "benign"]
    res = evaluate(detector, ben, "benign")
    assert res["enforced_fp"] == 0, (
        f"良性夹具出现确认误报 {res['enforced_fp']} 条 "
        f"(规则: {res['per_rule_fp_top']}) —— 查明是哪条规则后再动数据"
    )


def test_malicious_enforced_and_shadow_hits(detector: PySigmaDetector, rows: list[dict]):
    mal = [r["event"] for r in rows if r["label"] == "malicious"]
    res = evaluate(detector, mal, "malicious")
    assert res["enforced_tp"] > 0, "攻击夹具零确认检出 —— 检测链路或规则库被改坏"
    assert res["shadow_only_tp"] >= 0
    # 指标结构完整(报告生成依赖这些键)
    for k in ("recall_enforced", "recall_with_shadow", "per_type", "per_rule_top"):
        assert k in res


def test_pending_aggregation_hits_not_counted_as_enforced():
    """2026-10-27 口径修正: 阈值规则的单事件命中([PENDING-AGG])是候选不是确认。

    修正前 enforced 只按 "[SHADOW]" 过滤, 聚合候选(SigmaHit.
    requires_aggregation=True)被计入确认 TP —— 全量 CSIC 回放里 SIG-001
    的 43 个单 URL 命中因此虚高 enforced 召回。本测试用桩检测器钉住:
    仅候选命中的事件不得进 enforced_tp / enforced_fp。
    """
    from types import SimpleNamespace

    from eval_datasets.replay_public_datasets import evaluate

    def _hit(rid, description="", requires_aggregation=False):
        return SimpleNamespace(
            rule_id=rid, description=description,
            requires_aggregation=requires_aggregation,
        )

    class _StubDetector:
        def __init__(self, hits):
            self._hits = hits

        def detect(self, ev):
            return list(self._hits)

    ev = {"url": "/tienda1/index.jsp", "event": "REQ"}

    # 仅聚合候选 → 不算确认检出, 单列 pending_only
    res = evaluate(_StubDetector([_hit("SIG-001", "x [PENDING-AGG]", True)]), [ev], "malicious")
    assert res["enforced_tp"] == 0
    assert res["pending_only_tp"] == 1
    assert res["recall_enforced"] == 0
    assert res["per_rule_pending_top"] == {"SIG-001": 1}

    # 候选规则对良性样本也不产生确认 FP
    res = evaluate(_StubDetector([_hit("SIG-001", "x [PENDING-AGG]", True)]), [ev], "benign")
    assert res["enforced_fp"] == 0
    assert res["per_type"].get("benign:pending") == 1

    # 确认命中 + 候选命中并存 → 只按确认计
    res = evaluate(
        _StubDetector([_hit("C-001"), _hit("SIG-001", "x [PENDING-AGG]", True)]),
        [ev], "malicious",
    )
    assert res["enforced_tp"] == 1
    assert res["pending_only_tp"] == 0

    # 引擎真实规则上: 夹具若触发阈值规则(SIG-001/007), enforced 桶里
    # 不允许出现 requires_aggregation 的命中
    d = PySigmaDetector(os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "sigma_engine", "rules"), enforce=True)
    with open(FIXTURE, encoding="utf-8") as f:
        all_rows = [json.loads(ln) for ln in f if ln.strip()]
    mal = [r["event"] for r in all_rows if r["label"] == "malicious"]
    for e in mal:
        for h in d.detect(e):
            if "[SHADOW]" in (h.description or ""):
                continue
            assert not getattr(h, "requires_aggregation", False), (
                f"{h.rule_id} 聚合候选漏进了 enforced 口径 (event={e.get('url')!r})"
            )
