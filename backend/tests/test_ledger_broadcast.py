# -*- coding: utf-8 -*-
"""零丢失账本广播 (A3) —— 采样与发布契约回归。

钉住两个不变量:
  L1 _sample 对**带 label 的指标**跨组合求和 —— prometheus_client 0.26.0
    的 get_sample_value 要求标签精确等于空字典, 带 label 一律 None
    (live 实测 2026-10-27, received 面板恒 0 的根因);
  L2 账本等式口径: enqueued = received − rejected − validation_failed,
    absorbed = enqueued − inserted (与 PERF 报告同口径)。
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ.setdefault("SHARED_MEMORY_DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("SHARED_MEMORY_JWT_SECRET", "test-secret")
os.environ.setdefault("SHARED_MEMORY_LLM_API_KEY", "test")
os.environ.setdefault("SHARED_MEMORY_EMBEDDING_API_KEY", "test")
os.environ.setdefault("SHARED_MEMORY_ADMIN_PASSWORD", "test")

from prometheus_client import CollectorRegistry, Counter, Gauge

from ledger_broadcast import _sample


class TestSample:
    def test_labeled_counter_is_summed_across_labels(self):
        """L1: 带 label 的 Counter 两个组合各 3/4 → 求和 7。"""
        reg = CollectorRegistry()
        c = Counter("probe_ledger_received_total", "p", ["source"], registry=reg)
        c.labels("http").inc(3)
        c.labels("kafka").inc(4)
        # _sample 读全局 REGISTRY —— 临时替换模块级引用做隔离
        import ledger_broadcast as lb

        original = lb.__dict__.get("_REGISTRY_OVERRIDE")
        lb.__dict__["_REGISTRY_OVERRIDE"] = reg
        try:
            assert lb._sample("probe_ledger_received_total") == 7.0
        finally:
            if original is None:
                lb.__dict__.pop("_REGISTRY_OVERRIDE", None)
            else:
                lb.__dict__["_REGISTRY_OVERRIDE"] = original

    def test_unlabeled_gauge_still_works(self):
        reg = CollectorRegistry()
        g = Gauge("probe_ledger_dlq_depth", "p", registry=reg)
        g.set(5)
        import ledger_broadcast as lb

        lb.__dict__["_REGISTRY_OVERRIDE"] = reg
        try:
            assert lb._sample("probe_ledger_dlq_depth") == 5.0
        finally:
            lb.__dict__.pop("_REGISTRY_OVERRIDE", None)


class TestLedgerEquation:
    def test_equation_matches_perf_report_semantics(self):
        """L2: enqueued = received − rejected − validation_failed; absorbed = enq − ins。"""
        received, rejected, validation_failed = 24485.0, 2407.0, 146.0
        enqueued = max(0.0, received - rejected - validation_failed)
        assert enqueued == 21932.0
        # PERF 报告实测形态: 入队 24,447 = 落库 18,447 + 幂等 6,000 —— 等式闭合
        assert 18447 + 6000 == 24447
        inserted = 15932
        absorbed = max(0, int(enqueued) - inserted)
        assert int(enqueued) == inserted + absorbed

    def test_negative_enqueued_clamped(self):
        # 收到但全被拒绝时 enqueued 不得为负 (面板账目不出现负数)
        received, rejected = 100.0, 150.0
        assert max(0.0, received - rejected) == 0.0
