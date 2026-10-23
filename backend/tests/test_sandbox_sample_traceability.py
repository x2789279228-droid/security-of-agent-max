# -*- coding: utf-8 -*-
"""URL 提交的**样本指纹**（整改报告 §9.64）。

## 背景

整改方案 §十.1 明确要求：

> 使用 SHA-256 对应的真实样本标识关联沙箱任务，持久化 sample_hash、
> 外部 task_id、提交时间、当前状态、最近错误和报告引用。

§十三 的验收行也写着「零日与聚类：…**任务与样本可以追踪**」。

**修复前**：**文件**提交路径有指纹（`submit_file_outcome` 算 sha256），
**URL** 提交路径**完全没有**：

* `submit_url_outcome` 的 outcome 里**没有** `sample_hash`；
* 于是 `_by_hash` 里**没有**它 → `lookup_by_hash` 回连不到；
* `POST /sandbox/submit` 落库的 `SandboxTask.sample_hash` 也**永远是空的**
  —— 而那一列是**建了索引**的（`models.py:716`，显然就是为这个准备的）。

而 URL 提交正是**活的**生产入口（`routers/edr_intel.py:206`）→
沙箱任务落库了，却**回连不到样本**。

## 本守卫盯什么

1. **行为**：URL 提交的 outcome 必须带 64 位十六进制的 `sample_hash`
   （且等于 URL 的 SHA-256）；
2. **失败路径也要带**：被拒 / 提交失败 / 拿不到 task_id 时，指纹同样要留痕
   （否则「失败的提交」在样本维度上彻底不可追）；
3. **可回连**：`lookup_by_hash` 能按指纹找回这次提交；
4. **接线**（源码级）：落库记录必须带 `sample_hash=`，且端点必须用
   `submit_url_outcome`（旧的 `submit_url()` 只回传 task_id，指纹会丢）；
5. **反向**：文件路径的指纹行为不受影响。
"""
from __future__ import annotations

import hashlib
import re
import sys
from pathlib import Path

import pytest

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND))

#: 用 **IP 字面量**而不是域名：域名会触发 DNS 解析（依赖实时 DNS）。
URL = "http://93.184.216.34/sample.exe"
OTHER_URL = "http://93.184.216.35/sample.exe"


def run(coro):
    import asyncio
    return asyncio.new_event_loop().run_until_complete(coro)


def _mk_connector(**over):
    from config import settings
    from zeroday_detect.sandbox_connector import SandboxConnector
    settings.sandbox_enabled = True
    settings.sandbox_api_url = "http://127.0.0.1:1"
    settings.sandbox_api_key = ""
    settings.sandbox_timeout = 5
    settings.sandbox_auto_submit = True
    settings.sandbox_auto_threshold = 0.8
    settings.sandbox_type = "cape"
    if "allow_internal_url" in over:
        settings.sandbox_allow_internal_url = over["allow_internal_url"]
    return SandboxConnector()


def _stub_request(conn, monkeypatch, status=200, payload=None, err_code="", err_msg=""):
    async def _fake_request(method, url, **kw):
        return (status, payload if payload is not None else {"task_id": "abc-123"},
                err_code, err_msg)
    monkeypatch.setattr(conn, "_request", _fake_request)


class TestTheUrlSubmissionCarriesTheHash:
    def test_the_outcome_carries_the_sample_hash(self, monkeypatch):
        conn = _mk_connector()
        _stub_request(conn, monkeypatch)
        out = run(conn.submit_url_outcome(URL))
        assert out.status == "pending", out
        assert out.sample_hash, "URL 提交的 outcome 里没有样本指纹"
        assert len(out.sample_hash) == 64, out.sample_hash
        assert re.fullmatch(r"[0-9a-f]{64}", out.sample_hash), out.sample_hash

    def test_the_hash_is_the_sha256_of_the_url(self, monkeypatch):
        conn = _mk_connector()
        _stub_request(conn, monkeypatch)
        out = run(conn.submit_url_outcome(URL))
        expect = hashlib.sha256(URL.strip().encode("utf-8")).hexdigest()
        assert out.sample_hash == expect, (
            f"指纹不是 URL 的 SHA-256：{out.sample_hash} != {expect}")

    def test_the_hash_is_stable_and_distinct(self, monkeypatch):
        conn = _mk_connector()
        _stub_request(conn, monkeypatch)
        a = run(conn.submit_url_outcome(URL))
        b = run(conn.submit_url_outcome(URL))
        c = run(conn.submit_url_outcome(OTHER_URL))
        assert a.sample_hash == b.sample_hash, "同一 URL 的指纹不稳定"
        assert a.sample_hash != c.sample_hash, "不同 URL 的指纹撞了"


class TestTheFailurePathsAlsoCarryTheHash:
    def test_a_rejected_url_still_leaves_a_fingerprint(self, monkeypatch):
        """被 URL 校验拒掉时也要留指纹 —— 否则「失败的提交」彻底不可追。"""
        conn = _mk_connector()
        out = run(conn.submit_url_outcome("http://127.0.0.1/admin"))
        assert out.status == "failed", out
        assert out.sample_hash, "被拒的提交没有留下指纹"
        assert len(out.sample_hash) == 64, out.sample_hash

    def test_a_failed_submit_still_leaves_a_fingerprint(self, monkeypatch):
        conn = _mk_connector()
        _stub_request(conn, monkeypatch, status=500, payload=None,
                      err_code="server_error", err_msg="boom")
        out = run(conn.submit_url_outcome(URL))
        assert out.status == "failed", out
        assert out.sample_hash, "提交失败没有留下指纹"

    def test_a_missing_task_id_still_leaves_a_fingerprint(self, monkeypatch):
        conn = _mk_connector()
        _stub_request(conn, monkeypatch, status=200, payload={"task_id": None})
        out = run(conn.submit_url_outcome(URL))
        assert out.error_code == "missing_task_id", out
        assert out.sample_hash, "拿不到 task_id 时没有留下指纹"


class TestTheHashIsLookupable:
    def test_lookup_by_hash_finds_the_submission(self, monkeypatch):
        conn = _mk_connector()
        _stub_request(conn, monkeypatch)
        out = run(conn.submit_url_outcome(URL))
        found = conn.lookup_by_hash(out.sample_hash)
        assert found is not None, "按指纹回连不到这次提交"
        assert found.task_id == out.task_id, found

    def test_tracked_samples_counts_it(self, monkeypatch):
        conn = _mk_connector()
        _stub_request(conn, monkeypatch)
        before = conn.get_status()["tracked_samples"]
        out = run(conn.submit_url_outcome(URL))
        after = conn.get_status()["tracked_samples"]
        assert after == before + 1, (before, after)
        assert out.sample_hash


class TestTheRecordIsWired:
    """**接线**（源码级）：落库记录必须带指纹。

    行为层已经证明「连接器会算指纹」，但**记录**那一半在端点里 ——
    端点要 DB 会话，测不了；所以这里查源码。

    ⚠ 判据用 **AST** 而不是正则：第一版用正则找 `submit_url(`，
    结果**匹配到了我自己写的注释**（「旧的 submit_url() 只回传 task_id」）
    → 假红。正则不认识注释，AST 认识。
    """

    @staticmethod
    def _router_calls():
        """端点里对 sandbox 的方法调用（按名字）。"""
        import ast
        src = (BACKEND / "routers" / "edr_intel.py").read_text(encoding="utf-8")
        tree = ast.parse(src)
        calls = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                calls.append(node.func.attr)
        return calls

    @staticmethod
    def _sandbox_task_kwargs():
        """`SandboxTask(...)` 构造里的关键字参数名。"""
        import ast
        src = (BACKEND / "routers" / "edr_intel.py").read_text(encoding="utf-8")
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) \
                    and node.func.id == "SandboxTask":
                return {kw.arg for kw in node.keywords if kw.arg}
        return None

    def test_the_router_writes_the_sample_hash(self):
        kwargs = self._sandbox_task_kwargs()
        assert kwargs is not None, "找不到 SandboxTask(...) 的构造 —— 落库那一半可能变了"
        assert "sample_hash" in kwargs, (
            "落库的 SandboxTask 没有写 sample_hash —— "
            f"文档 §十.1「用 SHA-256 关联沙箱任务」未落地（关键字：{sorted(kwargs)}）")

    def test_the_router_uses_the_outcome_api(self):
        """端点必须用 `submit_url_outcome` —— 旧的 `submit_url()` 只回传 task_id，指纹会丢。"""
        calls = self._router_calls()
        assert "submit_url_outcome" in calls, (
            "端点不再用 submit_url_outcome —— 样本指纹会在这一步丢掉")
        assert "submit_url" not in calls, (
            "端点里仍有 sandbox.submit_url(...) 调用 —— 指纹会被丢掉")


class TestTheFilePathIsUnaffected:
    def test_the_file_path_still_leaves_its_fingerprint(self, monkeypatch):
        """**反向**：文件路径的行为不受本轮改动影响。"""
        conn = _mk_connector()
        out = run(conn.submit_file_outcome(b"MZ-fake-pe", filename="x.exe"))
        assert out.sample_hash, out
        assert len(out.sample_hash) == 64, out.sample_hash


if __name__ == "__main__":       # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
