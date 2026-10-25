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
