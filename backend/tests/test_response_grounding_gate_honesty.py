# -*- coding: utf-8 -*-
"""SafeExecutor 的 grounding 硬门控必须**如实**记录「有没有评估过」（整改报告 §9.51）。

## 背景

`response_engine/safe_executor.py` 里有一道写着「⓪ Grounding 硬门控」的检查：
「无证据支撑的审计结论不允许触发响应动作」。实测（2026-10-20）：

1. 整个 `response_engine` 包里，`grounding_score` **只出现在闸门自己**
   —— **没有任何生产代码传它**；
2. 动作函数（`_block_ip` 等）**不转发 `**kwargs`** → 就算调用方传了，
   也会在到达闸门之前被丢掉；
3. 没有任何测试覆盖它。

于是这道闸门**永远不会触发**，而它写进审计的是：

```python
audit["checks"]["grounding"] = {"passed": True, "score": grounding_score}
```

`grounding_score` 的缺省值是 **1.0**（最宽松）→ **一道从没跑过的检查，
在审计里被记成「通过、满分」** —— 这是**虚假保障**（整改方案 §十一.1：
「如果这些状态最终都被压成一个 not_detected 计数，那么新增多少仪表盘也
无法真正帮助排障」的同族形态）。

> 注：平台**并非**没有「证据不足不许响应」的保护 ——
> 活的那道是 `veto_gates.evaluate_auto_response_gate`
> （`needs_human_review` / `response_blocked` / `supervision_failed` /
> `schema_invalid` / CAD 断路器）。本节说的是**另一道**写着 P0 硬门控、
> 却**从来没跑过**的重复检查，以及它给出的**虚假保障**。

## 本守卫盯什么

1. **没评估过 ≠ 评估通过**：审计里必须写 `state="not_evaluated"` + `passed=None`；
2. **给了分数就要真评估**：低分被拦、高分通过、`state="evaluated"`；
3. **畸形分数**（非数字）不得把动作变成「通过」；
4. **计数**：`not_evaluated` 状态要被计数（§十一.1：依据不足要单独计数）；
5. **事实钉住**：这道闸门**当前没有被接线**（`response_engine` 包里
   `grounding_score` 只出现在闸门自己）—— 一旦有人把它接上，
   本守卫转红，要求同步更新**待决项 33** 与报告 §9.51 的结论。
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND))

import pytest  # noqa: E402

CMD = ("iptables -I INPUT -s 10.0.0.5 -j DROP "
       "-m comment --comment 'FW-RULE-11111'")


async def _live_fn(cmd):
    return {"success": True, "stdout": "", "stderr": "", "returncode": 0}


def _executor():
    from response_engine.safe_executor import SafeExecutor
    se = SafeExecutor()
    se.initialize()
    return se


class TestTheAuditMustNotClaimAPassWhenNothingWasEvaluated:
    pytestmark = pytest.mark.asyncio

    async def test_without_a_score_the_audit_says_not_evaluated(self):
        """**核心**：没评估过 → 不得记成「通过、满分」。"""
        se = _executor()
        result = await se.execute(
            action_name="block_ip", command=CMD,
            params={"src_ip": "10.0.0.5"},
            platform="linux", live_fn=_live_fn,
        )
        g = result["audit"]["checks"]["grounding"]
        assert g["state"] == "not_evaluated", g
        assert g["passed"] is None, f"没评估过却记成通过：{g}"
        assert g["score"] is None, g
        assert g.get("reason"), "必须说明为什么没评估"

    async def test_the_action_still_executes(self):
        """**反向判据**：本次只改**诚实性**，不改变拦截行为。

        把闸门接上属**收紧型**改动（非审计来源的响应根本没有 grounding 分数，
        一旦按缺省拒绝，整个响应能力会瘫）→ 待决项 33。
        """
        se = _executor()
        result = await se.execute(
            action_name="block_ip", command=CMD,
            params={"src_ip": "10.0.0.5"},
            platform="linux", live_fn=_live_fn,
        )
        assert result.get("success") is True, result


class TestTheGateWorksWhenItIsActuallyFed:
    pytestmark = pytest.mark.asyncio

    async def test_a_low_score_is_evaluated_and_blocks(self):
        se = _executor()
        result = await se.execute(
            action_name="block_ip", command=CMD,
            params={"src_ip": "10.0.0.5", "grounding_score": 0.1},
            platform="linux", live_fn=_live_fn,
        )
        g = result["audit"]["checks"]["grounding"]
        assert g["state"] == "evaluated_block", g
        assert g["passed"] is False, g
        assert result.get("blocked") is True, result
        assert result.get("blocked_by") == "grounding_gate", result

    async def test_a_high_score_is_evaluated_and_passes(self):
        se = _executor()
        result = await se.execute(
            action_name="block_ip", command=CMD,
            params={"src_ip": "10.0.0.5", "grounding_score": 0.9},
            platform="linux", live_fn=_live_fn,
        )
        g = result["audit"]["checks"]["grounding"]
        assert g["state"] == "evaluated_pass", g
        assert g["passed"] is True, g
        assert g["score"] == pytest.approx(0.9)

    async def test_a_malformed_score_is_treated_as_not_evaluated(self):
        """畸形分数**不得**变成「通过」——也不该把动作变成异常。"""
        se = _executor()
        result = await se.execute(
            action_name="block_ip", command=CMD,
            params={"src_ip": "10.0.0.5", "grounding_score": "不是数字"},
            platform="linux", live_fn=_live_fn,
        )
        g = result["audit"]["checks"]["grounding"]
        assert g["state"] == "not_evaluated", g
        assert g["passed"] is None, g


class TestTheNotEvaluatedStateIsCounted:
    pytestmark = pytest.mark.asyncio

    async def test_the_counter_records_the_state(self):
        """§十一.1：「依据不足」必须**单独计数**，不能混进别的档。"""
        from prometheus_client import REGISTRY

        def _val(state):
            return REGISTRY.get_sample_value(
                "soc_response_grounding_gate_total", {"state": state})

        before = _val("not_evaluated")
        se = _executor()
        await se.execute(
            action_name="block_ip", command=CMD,
            params={"src_ip": "10.0.0.5"},
            platform="linux", live_fn=_live_fn,
        )
        after = _val("not_evaluated")
        assert before is not None, "指标没被注册"
        assert after == before + 1, f"not_evaluated 没有被计数：{before} → {after}"


class TestTheWiringFactIsPinned:
    def test_the_gate_is_now_fed_by_the_response_path(self):
        """接线守卫：响应动作必须能把 grounding 分数传给 SafeExecutor。

        2026-10-21 起，`block_ip` / `isolate_host` / `dns_sinkhole` 会从
        kwargs 提取 `grounding_score` 并放进 params；SafeExecutor 的 ⓪ 闸门
        因此不再是“永远没被喂过分数”的摆设。
        """
        hits = {}
        pkg = BACKEND / "response_engine"
        for p in sorted(pkg.rglob("*.py")):
            if "__pycache__" in p.parts:
                continue
            src = p.read_text(encoding="utf-8", errors="replace")
            n = src.count("grounding_score")
            if n:
                hits[str(p.relative_to(pkg))] = n
        assert "safe_executor.py" in hits, "SafeExecutor 的 grounding 闸门消失了"
        assert "response_registry.py" in hits, (
            "response_registry 没有把 grounding_score 转发给 SafeExecutor —— "
            "这道闸门会重新变成“永远未评估”"
        )
