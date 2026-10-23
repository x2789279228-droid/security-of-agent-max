# -*- coding: utf-8 -*-
"""信誉**先验**的 fail-open 必须**可见**（整改报告 §9.57）。

## 背景

`threat_intel/reputation.py::_get_prior_delta` 的失败路径原本是：

```python
except Exception as e:
    logger.debug("prior delta lookup skipped: %s", e)
    return 0.0
```

两处问题：

1. **debug 级日志 → 生产默认 INFO 下根本看不见**；
2. 旁边的注释写「fail-open, **不影响主评分**」—— **不准确**：
   delta 就在下一行**加到主评分上**（`score = clip(score + delta)`，
   clip 幅度 = `learn_loop_prior_clip` = ±0.2），
   它决定 `clean/suspicious/malicious` 的档位。
   一次 DB 抖动 → 评分**少掉**一个先验修正 → 可能跨档 → 处置降级，而没人知道。

## 本守卫盯什么

1. **失败被计数**（可数）；
2. **失败被 warning 级记录**（不是 debug）；
3. **前提**：delta **确实**影响主评分（所以那条旧注释是错的）；
4. **反向判据**：正常路径行为不变；
5. 源码里**不再**声称「不影响主评分」。
"""
from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND))

import pytest  # noqa: E402


class _BoomSession:
    async def execute(self, *a, **k):
        raise RuntimeError("db down")


def _count() -> int:
    from prometheus_client import REGISTRY
    v = REGISTRY.get_sample_value(
        "soc_reputation_prior_lookup_failed_total")
    return 0 if v is None else v


class TestTheFailureIsVisible:
    @pytest.mark.asyncio
    async def test_the_failure_is_counted(self):
        from threat_intel.reputation import ReputationEngine
        before = _count()
        eng = ReputationEngine()
        await eng.score_ip("8.8.8.8", session=_BoomSession())
        assert _count() == before + 1, "先验读取失败没有被计数"

    @pytest.mark.asyncio
    async def test_the_failure_is_logged_at_warning_level(self, caplog):
        """**不是 debug** —— 生产默认 INFO，debug 等于没有。"""
        from threat_intel.reputation import ReputationEngine
        eng = ReputationEngine()
        with caplog.at_level(logging.DEBUG, logger="threat_intel.reputation"):
            await eng.score_ip("8.8.8.8", session=_BoomSession())
        warnings = [r for r in caplog.records
                    if r.levelno >= logging.WARNING
                    and "threat_intel.reputation" in (r.name or "")]
        assert warnings, (
            "先验读取失败没有 warning 级记录 —— 生产默认 INFO，"
            f"只有 debug 的话等于没记录：{[r.levelname for r in caplog.records]}")


class TestThePremise:
    @pytest.mark.asyncio
    async def test_the_delta_really_affects_the_score(self):
        """**前提守卫**：delta 确实加到主评分上 —— 所以旧注释是错的。

        （若哪天先验不再影响评分，这条会红 → 那时「不影响主评分」就成立，
         但那属于**设计变更**，需要同步更新注释与本守卫。）
        """
        from threat_intel import reputation as rep
        from threat_intel.reputation import ReputationEngine

        eng = ReputationEngine()
        # 用缓存路径构造一个确定的先验：先测 base，再测带 +0.2 的
        rep._PRIOR_CACHE.clear()
        try:
            base = await eng.score_ip("9.9.9.9")
            rep.set_prior_cache("ip", "9.9.9.9", 0.2)
            with_prior = await eng.score_ip("9.9.9.9")
        finally:
            rep._PRIOR_CACHE.clear()
        assert with_prior.score >= base.score, (
            "先验 delta 没有影响评分 —— 若这是设计变更，请同步更新注释与本守卫")
        assert any(f.startswith("learn_prior:") for f in with_prior.factors), (
            f"先验修正没有记进 factors：{with_prior.factors}")

    def test_the_source_no_longer_claims_the_prior_does_not_affect_the_score(self):
        """注释不许再撒谎。

        判据：那句错话**只允许**出现在带更正标记的行里
        （说明性注释里合法地引用旧话是文档，不是缺陷 —— §9.54 同款教训）。
        """
        src = (BACKEND / "threat_intel" / "reputation.py").read_text(encoding="utf-8")
        offenders = []
        for i, line in enumerate(src.splitlines(), 1):
            if "不影响主评分" not in line:
                continue
            if any(k in line for k in ("原注释", "不准确", "更正", "§9.57")):
                continue
            offenders.append((i, line.strip()))
        assert not offenders, (
            "注释还在声称先验「不影响主评分」—— 它**确实**加到评分上（§9.57）：\n  "
            + "\n  ".join("%d: %s" % o for o in offenders))


if __name__ == "__main__":       # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
