"""因果结果的可追溯性：算法版本、统计后端、依赖版本、检验参数。

## 这批测试为什么存在

整改方案 §九.1 与 §十一.2 各写了一次同一件事：

> 统一并记录统计后端、依赖版本和检验参数。
> 记录实际算法版本、统计后端和规则版本，确保结果可追溯。

这条此前**完全没有落地**：`learn_from_matrix()` 的返回里没有统计后端、
没有依赖版本，`max_cond` 甚至**不是参数**（固定走默认值，无法记录、
也无法在调用侧复现同一张图）。

为什么这条不是可有可无的整洁问题：修复前的 χ² 兜底对任意 df 都套用
df=1 的公式，它**改变 p 值**。也就是说同一份数据，在装了 scipy 的机器
和没装的机器上可能学出不同的图 —— 而两张图在输出里长得一模一样，
没有任何痕迹能解释差异。「结果可追溯」在这里是字面意义上的空话。

## 断言为什么钉在这里而不是文档里

文档里写「记录统计后端」没有任何强制力：下一次重构把那个字段挪走，
不会有任何东西变红。所以这里钉的是**输出里必须存在某个字段**，
以及**换掉后端时这个字段必须跟着变**。
"""
import os
import sys

import numpy as np
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from causal_chain import pc                                # noqa: E402
from causal_chain.learn import learn_from_matrix           # noqa: E402
from causal_chain.pc import pc_learn, stat_backend         # noqa: E402


def _data(n=900, seed=41):
    rng = np.random.default_rng(seed)
    a = (rng.random(n) < 0.3).astype(np.uint8)
    b = np.where(a == 1, rng.random(n) < 0.8, rng.random(n) < 0.1).astype(np.uint8)
    c = (rng.random(n) < 0.3).astype(np.uint8)
    names = ["A", "B", "NOISE"]
    return np.stack([a, b, c], axis=1), names


# ══════════════════════════════════════════════════════════════
# 1. 后端识别
# ══════════════════════════════════════════════════════════════

def test_stat_backend_reports_scipy_when_available():
    pytest.importorskip("scipy")
    info = stat_backend()
    assert info["chi2"] == "scipy.stats.chi2.sf", info
    assert info["scipy_version"], \
        "有 scipy 却没记版本 —— 「记录依赖版本」这条没落地"


def test_stat_backend_reports_fallback_when_scipy_missing(monkeypatch):
    monkeypatch.setattr(pc, "_chi2", None)
    monkeypatch.setattr(pc, "_scipy", None)
    info = stat_backend()
    assert info["chi2"] == "gammaincc_fallback", info
    assert info["scipy_version"] == ""


def test_stat_backend_is_json_serialisable():
    """必须能随图 JSON 落库 —— 不可序列化的字段等于没有这个字段。"""
    import json

    json.dumps(stat_backend())     # 不抛异常即可


# ══════════════════════════════════════════════════════════════
# 2. PC 层：stats 里必须带后端与检验参数
# ══════════════════════════════════════════════════════════════

def test_pc_stats_carry_backend_and_parameters():
    X, names = _data()
    out = pc_learn(X, names, alpha=0.05, max_cond=2)
    stats = out["stats"]
    assert stats["chi2"] == stat_backend()["chi2"], stats
    assert "scipy_version" in stats
    assert stats["test_parameters"] == {"alpha": 0.05, "max_cond": 2}, stats
    assert stats["max_cond"] == 2, "max_cond 没有进 stats"
    assert stats["alpha"] == 0.05


def test_pc_stats_backend_flips_with_the_backend(monkeypatch):
    """⚠️ 本用例是这套记录的意义所在。

    切到兜底后端，`chi2` 字段**必须跟着变**。
    只断言「字段存在」是不够的 —— 一个恒为常量、从不反映真实后端的
    字段会让两张来路不同的图看起来同样可信，正好毁掉可追溯性。
    """
    X, names = _data()
    with_scipy = pc_learn(X, names)["stats"].get("chi2", "")
    monkeypatch.setattr(pc, "_chi2", None)
    monkeypatch.setattr(pc, "_scipy", None)
    without = pc_learn(X, names)["stats"].get("chi2", "")
    assert with_scipy != without, \
        "切换统计后端后记录没有变化 —— 这是个恒为常量的假字段"
    assert without == "gammaincc_fallback"


# ══════════════════════════════════════════════════════════════
# 3. learn 层：provenance 必须出现在图里
# ══════════════════════════════════════════════════════════════

def test_learn_result_carries_provenance():
    X, names = _data()
    result = learn_from_matrix(X, names, alpha=0.05, max_cond=2)
    prov = result.get("provenance")
    assert prov, "learn_from_matrix 未返回 provenance —— §九.1/§十一.2 未落地"
    assert prov["chi2_backend"], prov
    assert prov["alpha"] == 0.05 and prov["max_cond"] == 2, prov
    assert prov["algorithms"] == ["pc", "ges"], prov


def test_provenance_backend_matches_pc_stats():
    """两层记录必须一致 —— 顶层抄错值等于没记录。"""
    X, names = _data()
    result = learn_from_matrix(X, names)
    assert result["provenance"]["chi2_backend"] == \
        result["pc"]["stats"]["chi2"]


def test_provenance_backend_flips_with_the_backend(monkeypatch):
    X, names = _data()
    with_scipy = learn_from_matrix(X, names)["provenance"]["chi2_backend"]
    monkeypatch.setattr(pc, "_chi2", None)
    monkeypatch.setattr(pc, "_scipy", None)
    without = learn_from_matrix(X, names)["provenance"]["chi2_backend"]
    assert with_scipy != without, "顶层 provenance 没跟着后端变"


def test_max_cond_is_callable_and_recorded():
    """`max_cond` 此前不是参数：既不能复现同一张图，也无法记录。"""
    X, names = _data()
    a = learn_from_matrix(X, names, max_cond=0)
    b = learn_from_matrix(X, names, max_cond=3)
    assert a["provenance"]["max_cond"] == 0
    assert b["provenance"]["max_cond"] == 3

    # 条件集越大，检验次数越多 —— 参数确实传到了 PC。
    # 必须用 4 列数据：只有 3 列时条件集最大只能是 1，max_cond 再大
    # 也枚举不出更多子集，计数当然相同 —— 那不是参数没传到位。
    rng = np.random.default_rng(43)
    n = 900
    p = (rng.random(n) < 0.3).astype(np.uint8)
    q = np.where(p == 1, rng.random(n) < 0.8, rng.random(n) < 0.1).astype(np.uint8)
    r = np.where(q == 1, rng.random(n) < 0.8, rng.random(n) < 0.1).astype(np.uint8)
    s = (rng.random(n) < 0.3).astype(np.uint8)
    W = np.stack([p, q, r, s], axis=1)
    wide_names = ["P", "Q", "R", "S"]

    shallow = learn_from_matrix(W, wide_names, max_cond=0)
    deep = learn_from_matrix(W, wide_names, max_cond=2)
    assert shallow["pc"]["stats"]["undecidable"]["tests_total"] < \
        deep["pc"]["stats"]["undecidable"]["tests_total"]


def test_provenance_is_json_serialisable():
    """随图落库是它的用途；不可序列化就等于没有。"""
    import json

    X, names = _data()
    result = learn_from_matrix(X, names)
    json.dumps(result["provenance"])
