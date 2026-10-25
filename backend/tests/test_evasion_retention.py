# -*- coding: utf-8 -*-
"""B4 对抗保持率守卫 — 签名层的已知韧性与已知缺口都不许悄悄漂移。

锁定三件事(数字来自 2026-10-25 实测 EVASION.md, 留出波动余量):
  1. 全部种子族基线必须命中 —— 家族定义与规则覆盖的对齐不许烂;
  2. case_flip 保持率 = 1.0: 规则大小写不敏感是已锁定的强性质;
  3. 总体保持率 ≥ 0.35: 完整 URL 编码族(url_encode 0/8)是已知的
     ingest 规范化缺口(见 REPLAY 报告), 修复该缺口后此阈值只应上升;
     若下降说明有人在规则库回退了编码变体覆盖, 必须给说法。
"""
from __future__ import annotations

import os
import sys

os.environ.setdefault("SHARED_MEMORY_SKIP_DOTENV", "1")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from eval_datasets.evasion_retention import SEED_FAMILIES, run  # noqa: E402


def test_all_families_baseline_detected():
    res = run()
    bad = [f for f, d in res["families"].items() if not d["baseline_detected"]]
    assert not bad, f"基线未命中的家族(评测器与规则库失准): {bad}"


def test_case_flip_fully_retained():
    res = run()
    for fam, d in res["families"].items():
        assert d["per_operator"].get("case_flip") is True, (
            f"{fam} 大小写翻转后漏检 —— 规则的大小写不敏感性质被破坏"
        )


def test_overall_retention_floor():
    res = run()
    assert res["overall_retention"] >= 0.35, (
        f"总体保持率 {res['overall_retention']} < 0.35 —— "
        "编码变体覆盖被回退? 逐族看 per_operator 定位(已知缺口: 完整"
        "URL 编码族, 修复面在 ingest 解码规范化, 不在逐条规则)"
    )
    assert res["families"]["traversal"]["per_operator"]["double_encode"] is True, (
        "双重编码遍历(平台已显式覆盖的形态, SIG-P-02 对应用例)不得回退"
    )


def test_seed_families_cover_expected_surface():
    # 种子族集合本身的守卫: 覆盖遍历/XSS/端口型/敏感文件/命令执行五大面
    assert set(SEED_FAMILIES) >= {
        "traversal", "traversal_encoded", "xss", "es_unauth",
        "env_probe", "git_probe", "actuator", "webshell_cmd",
    }
