"""
anomaly rarity 口径回归（#9 分母修复 + 整改方案 §七.2 标度重定义）

三代口径，测试同时锁住三代的行为：

1. **原始（缺陷）**：`rarity = 1 - ratio * 100`，其中 100 是没有依据的
   魔法数 —— 要主流计数超过稀有 **100 倍** rarity 才非零，10:1 这种
   明显不平衡直接判 0。而且分母误用单个小时桶 `global_hourly_counts[0]`，
   ratio 被放大约 24 倍 → rarity 几乎恒为 0，且随 UTC 钟点漂移。

2. **#9 分母修复**：分母改成 24 个小时桶合计，与分子同口径。
   修掉了「随钟点漂移」和「0 点桶为空则维度完全失效」。
   **本文件仍然锁住这一条**（test_independent_of_hour_zero_bucket）。

3. **§七.2 标度重定义**：把魔法数 100 换成**观测到的均匀占比**
   `uniform = 1 / 已观测类型数`：
       `rarity = 1 - ratio / uniform`（ratio < uniform 时）
   语义是「比均匀分布罕见多少」，与部署规模无关：
   10:1 → 0.82，100:1 → 0.98，从未见过 → 1.0。

4. **§七.3 冷启动语义**：样本不足返回 **None**（inconclusive）
   而不是 `0.0`。`0.0` 等于宣称「该事件类型确定不罕见」——
   「没有证据 ≠ 没有威胁」，下游融合层必须能区分这两者。
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from anomaly_detector import RARITY_MIN_SAMPLES, AnomalyDetector


def _detector_with(total: int, type_count: int, n_other: int = 1) -> AnomalyDetector:
    """构造全局统计。

    `n_other` = 除 "T" 之外的其它类型条数（平均分配）。
    「已观测类型数」决定 uniform = 1/n_types，**必须显式给出**：
    真实部署里类型数 ≥ 2，而只造一个类型的构造会让 rarity 判
    inconclusive（那是正确行为，但测不到标度本身）。
    """
    per_hour = total // 24
    det = AnomalyDetector()
    det.global_hourly_counts = [per_hour] * 24
    det.global_hourly_counts[0] += total - per_hour * 24   # 余数放到 0 点桶
    det.global_event_types.clear()
    if type_count:
        det.global_event_types["T"] = type_count
    rest = max(0, total - type_count)
    for i in range(n_other):
        det.global_event_types[f"OTHER_{i}"] = rest // n_other
    return det


class TestEventRarity:
    def test_common_type_near_zero(self):
        """占比 50%（正好等于均匀分布）→ rarity = 0。

        这条自 #9 修复起就没变过：与均匀分布一样常见的事件，
        不该因为「分母小了一圈」而被误判为罕见。
        """
        det = _detector_with(total=24000, type_count=12000)
        assert det._calc_event_rarity("T") == 0.0

    def test_share_below_one_percent_scores(self):
        """0.9% 占比 → rarity ≈ 0.98（比均匀分布罕见约 55 倍）。

        修复前 `1 - 100*ratio` 给出 0.1 —— 一个「从未见过的类型」
        和一个「十万分之一的类型」得分几乎一样，没有区分度。
        """
        det = _detector_with(total=10000, type_count=90)
        rarity = det._calc_event_rarity("T")
        assert rarity > 0.9, f"0.9% 占比应得到高 rarity, 实际 {rarity}"

    def test_moderate_imbalance_is_not_dead(self):
        """§七.2：10:1 的不平衡必须非零。

        修复前 `1 - 100*ratio` 在 10:1 下得到 0 —— 需要主流超过
        稀有 100 倍该维度才活过来，小规模部署下 20% 权重恒为 0。
        """
        det = _detector_with(total=11, type_count=1)
        rarity = det._calc_event_rarity("T")
        assert rarity > 0.8, f"10:1 的不平衡被判为不罕见: {rarity}"

    def test_rarity_is_scale_free(self):
        """同样 100:1 的不平衡，不管总样本是 110 还是 110000，分数相同。

        这是「标度是否依赖部署规模」的直接判据：修复前的
        `1 - 100*ratio` 只看 ratio 本身，恰好也满足这一条，
        但它的 ratio 是被放大的分母算出来的；这里锁住的是
        **新的 uniform 相对口径**在两个量级上都给出同一个值。
        """
        small = _detector_with(total=110, type_count=1)
        large = _detector_with(total=110000, type_count=1000)
        assert small._calc_event_rarity("T") == \
            pytest.approx(large._calc_event_rarity("T"), abs=1e-9)

    def test_unknown_type_max_rarity(self):
        det = _detector_with(total=1000, type_count=0, n_other=2)
        assert det._calc_event_rarity("NEVER_SEEN") == 1.0

    def test_cold_start_is_inconclusive_not_zero(self):
        """样本不足 → None（inconclusive），不是 0.0。

        修复前 `total < 10 → return 0.0`，与「该类型确实不罕见」
        完全同值。整改方案 §七.3 要求统一为 inconclusive。
        """
        det = _detector_with(total=RARITY_MIN_SAMPLES - 2, type_count=1)
        assert det._calc_event_rarity("T") is None
        det2 = _detector_with(total=RARITY_MIN_SAMPLES, type_count=1)
        assert det2._calc_event_rarity("T") is not None

    def test_single_observed_type_is_inconclusive(self):
        """只观测到一种事件类型时，均匀分布无从谈起 → inconclusive。

        此时 uniform=1.0、ratio=1.0，算出来是 0 —— 但「只见过一种
        类型」恰恰说明我们**不知道**还有多少种没出现，
        报 0 等于把无知当成确定性。
        """
        det = AnomalyDetector()
        det.global_hourly_counts = [10] * 24
        det.global_event_types = {"ONLY": 240}
        assert det._calc_event_rarity("ONLY") is None

    def test_independent_of_hour_zero_bucket(self):
        """rarity 不应依赖 0 点桶：0 点桶为 0 时维度依然有效（#9 回归）。"""
        det = AnomalyDetector()
        det.global_hourly_counts = [0] + [417] * 23   # 0 点桶空, 其余均摊
        det.global_event_types.clear()
        det.global_event_types["T"] = 90             # 90 / 9583 ≈ 0.94%
        det.global_event_types["OTHER_0"] = 9493
        rarity = det._calc_event_rarity("T")
        assert rarity > 0, "0 点桶为空不应导致 rarity 恒 0"

    def test_event_type_share_helper(self):
        det = _detector_with(total=1000, type_count=100)
        assert abs(det._event_type_share("T") - 0.1) < 1e-9
        assert det._event_type_share("MISSING") == 0.0
