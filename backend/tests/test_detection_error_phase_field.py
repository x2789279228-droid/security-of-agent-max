# -*- coding: utf-8 -*-
"""整改方案 §二 验收要求 3：「在哪个阶段失败」必须是**结构化**字段。

## 文档原文

> 对任意单一检测器注入异常，融合层都能够记录是哪个检测器、
> 哪个版本、**在哪个阶段**失败。

## 缺陷（2026-10-20，§9.33）

「哪个检测器」「哪个版本」都有**结构化字段**，
「哪个阶段」却只以 `error_message` 的方括号前缀（`"[detect] ..."`）存在：

* `DetectionResult` **没有** phase 字段；
* `AnalysisStatus.error_summary()` 的 docstring 写着
  「可落库 / 可上报的失败明细：**哪个检测器、哪个版本、哪个阶段**」，
  而它返回的字典里**没有 phase**；
* 唯一能把 phase 放进消息里的 `DetectionResult.from_error(..., phase=...)`
  **生产零调用方**；
* 既有守卫用 `assert "detect" in err["error_message"]` 断言 ——
  **子串匹配**：消息里出现 "detect" 就算过（措辞、别的检测器名、
  错误类型名都可能含这个词）。

后果：下游要回答「在哪个阶段失败」只能**解析字符串**，
而消息格式一改，阶段信息就**静默**丢失。

## 本守卫盯什么

阶段必须能从**结构化字段**取到，
且**不能**被消息里的字面量混淆。
"""
from __future__ import annotations

import asyncio
import os
import sys

import pytest

os.environ.setdefault("SHARED_MEMORY_SKIP_DOTENV", "1")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ingest_pipeline as ip  # noqa: E402
from detection_contract import (  # noqa: E402
    STATUS_ERROR,
    AnalysisStatus,
    DetectionResult,
)

BENIGN_EVENT = {
    "event": "BENIGN",
    "url": "http://x/?q=hello",
    "message": "hello",
    "src_ip": "1.1.1.1",
    "dst_ip": "2.2.2.2",
    "severity": "info",
}

#: 阶段词表（登记制）
KNOWN_PHASES = {"detect", "persist", "dispatch"}


class _AnomalyDown:
    """异常引擎挂掉 —— 注入「单一检测器异常」。"""

    version = "anomaly-9.9.9"

    async def analyze(self, event):
        raise RuntimeError("anomaly engine down")


def _run(coro):
    return asyncio.run(coro)


def _detector_errors(monkeypatch):
    monkeypatch.setattr(ip, "anomaly_detector", _AnomalyDown())
    log_data = dict(BENIGN_EVENT)
    _run(ip.detect(log_data))
    return log_data["_anomaly"]["detector_errors"]


class TestThePhaseIsAStructuredField:
    def test_the_real_path_records_the_phase_structurally(self, monkeypatch):
        """核心：融合层的失败明细里必须有**结构化的** phase。"""
        errs = _detector_errors(monkeypatch)
        assert errs, "失败明细未落库"
        err = errs[0]
        assert "phase" in err, (
            f"失败明细里没有 phase 字段：{sorted(err)} —— "
            f"「在哪个阶段失败」只能靠解析消息拿到，"
            f"而 error_summary() 的 docstring 承诺的就是这个字段")
        assert err["phase"], f"phase 是空串：{err}"
        assert err["phase"] in KNOWN_PHASES, (
            f"phase 用了未登记的值 {err['phase']!r}（登记：{sorted(KNOWN_PHASES)}）")

    def test_the_phase_does_not_depend_on_parsing_the_message(self, monkeypatch):
        """阶段必须能从**字段**取到。

        模拟「消息格式被改写」：把方括号前缀抠掉，
        阶段仍然必须拿得到 —— 否则「在哪个阶段失败」就只是
        碰巧被消息格式带出来的副产品。
        """
        errs = _detector_errors(monkeypatch)
        err = errs[0]
        msg = err["error_message"]
        if msg.startswith("["):
            msg = msg.split("]", 1)[1].strip()
        assert "[detect]" not in msg, (
            f"消息里已没有带括号的形式了：{msg!r}")
        # 阶段仍在字段里
        assert err["phase"] == "detect", err

    def test_the_structured_phase_is_not_derived_from_the_message(self):
        """⚠ 反向判据：消息里写着 "detect"、字段却写着 "persist" 时，
        **以字段为准**。

        这条挡住「实现退化成从消息里正则抠阶段」——
        那种实现会让「消息被改写 → 阶段静默变错」。
        """
        r = DetectionResult(
            detector="anomaly", detector_version="anomaly-2.0", event_id="e1",
            status=STATUS_ERROR, score=None,
            error_code="RuntimeError:anomaly_analyze",
            error_message="detect failed on purpose",
            phase="persist",
        )
        summary = AnalysisStatus.build([r]).error_summary()
        assert len(summary) == 1, summary
        assert summary[0]["phase"] == "persist", (
            f"phase 被消息里的字面量带偏了：{summary[0]}")

    def test_from_error_puts_the_phase_in_the_field(self):
        """`from_error` 也要把阶段放进字段（它此前只进消息）。"""
        r = DetectionResult.from_error(
            "anomaly", "e1", error_code="x:y",
            error_message="boom", detector_version="anomaly-2.0",
            phase="persist",
        )
        assert r.phase == "persist", r
        # 向后兼容：消息里的前缀**保持不变**（既有消费者靠它）
        assert r.error_message.startswith("[persist]"), r.error_message


class TestTheMessagePrefixIsKept:
    """消息里的方括号前缀**保持不变** —— 这是向后兼容，不是修复目标。

    修复是「**加**一个结构化字段」，不是「改消息」。
    既有消费者（以及既有守卫 `assert "detect" in err["error_message"]`）
    必须继续绿。
    """

    def test_the_message_prefix_is_still_there(self, monkeypatch):
        errs = _detector_errors(monkeypatch)
        err = errs[0]
        assert err["error_message"].startswith("[detect]"), err["error_message"]
        assert "detect" in err["error_message"], err["error_message"]

    def test_the_existing_field_set_is_not_shrunk(self, monkeypatch):
        """既有字段一个都不能少（新增字段不得破坏既有契约）。"""
        errs = _detector_errors(monkeypatch)
        err = errs[0]
        for key in ("detector", "detector_version", "status",
                    "error_code", "error_message"):
            assert key in err, f"既有字段 {key} 丢失了"


if __name__ == "__main__":       # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
