# -*- coding: utf-8 -*-
"""Sigma 快照连接的**释放判据**必须是「引用」，不是「代数」
（整改方案 §六 第 5 条，§9.39）。

## 缺陷（实测复现）

§六 的实现建议第 5 条写的是：

> 旧快照只在不再被执行任务引用时释放。

而修复前的实现是**代数**判据：

```python
if len(self._retired_conns) > 1:
    stale, self._retired_conns = self._retired_conns[:-1], [self._retired_conns[-1]]
    for c in stale:
        c.close()
```

「延迟一代」听起来像是在解决这个问题，但它仍然是**代数**：
跟「有没有执行任务还在用这一代快照」毫无关系。

实测（修复前）：抓一个快照引用，连续 reload 两次之后 ——
该快照的连接**已被关闭**：

```
reload #1 -> generation=2, _retired_conns=1
   snap1.conn: 可用
reload #2 -> generation=3, _retired_conns=1
   snap1.conn: 已关闭/不可用: ProgrammingError: Cannot operate on a closed database.
```

而机制自己的 docstring 写的是「旧快照只在不再被执行任务引用时释放」——
**它声称自己实现了它没有实现的东西**。

## 今天为什么没出事（必须写清楚，否则会把严重级别说错）

`detect()` 走的是**每次检测一个私有 `:memory:` 连接**（§六 第 4 条的真正隔离），
**从不持有快照连接**。
也就是说：**第 4 条的隔离设计顺带掩盖了第 5 条的缺失** ——
安全性来自「另一个设计」，不是来自释放机制本身。

所以这不是「线上正在丢检测」，而是「要求没有落地 + 注释在说谎」。
修它属于**消除隐患**，不改变任何检测结果。

## 本守卫盯什么

1. 被引用的快照，其连接在多次 reload 后**必须仍然可用**（引用判据）；
2. 最后一个引用释放后，连接**必须被关闭**（不能改成永不释放）；
3. 无人引用的旧代连接**仍要按宽限期被回收**（防泄漏）；
4. 检测路径**确实**在执行期间持有租约、结束后释放（否则 1~3 都是空话）；
5. 检测结果**不受影响**（回归）。

⚠ 判据用**行为**（连接能不能用、计数是不是 0），不用源码文本。
"""
from __future__ import annotations

import os
import sys

import pytest

os.environ.setdefault("SHARED_MEMORY_SKIP_DOTENV", "1")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sigma_engine.engine import PySigmaDetector  # noqa: E402

RULE = """
title: Lease Probe Rule
id: 22222222-0000-0000-0000-0000000000aa
status: experimental
description: lease probe
logsource:
  category: webserver
detection:
  keywords:
    - "UNION SELECT"
  condition: keywords
level: high
"""


def _mk_detector(tmp_path):
    d = tmp_path / "rules"
    d.mkdir(parents=True, exist_ok=True)
    (d / "probe.yml").write_text(RULE, encoding="utf-8")
    return PySigmaDetector(str(d), enforce=True)


def _base_event(**over):
    ev = {
        "event": "WEB_ATTACK",
        "url": "http://x/search?q=1",
        "message": "GET /search",
        "src_ip": "10.0.0.9",
        "dst_ip": "10.0.0.5",
        "protocol": "http",
        "severity": "medium",
        "details": "",
        "http.url": "http://x/search?q=1",
        "cs-uri-query": "q=1",
    }
    ev.update(over)
    return ev


def _conn_usable(conn) -> bool:
    """连接还能不能执行 —— 比 `closed` 标志更实在。"""
    if conn is None:
        return False
    try:
        conn.execute("SELECT 1").fetchone()
        return True
    except Exception:
        return False


class TestTheLeaseIsThePrecondition:
    """前提守卫：没有租约，下面所有断言都会恒绿。"""

    def test_the_snapshot_carries_a_lease(self, tmp_path):
        det = _mk_detector(tmp_path)
        assert det._snapshot.lease is not None, (
            "快照没有租约 —— 「按引用释放」无从谈起，下面的用例会全部恒绿")

    def test_the_lease_knows_its_own_connection(self, tmp_path):
        det = _mk_detector(tmp_path)
        assert det._snapshot.lease.conn is det._snapshot.conn, (
            "租约与快照持有的不是同一个连接 —— 引用计数保护错了对象")

    def test_a_fresh_lease_has_no_references(self, tmp_path):
        det = _mk_detector(tmp_path)
        assert det._snapshot.lease.refs == 0, det._snapshot.lease.refs


class TestTheReleaseIsByReference:
    def test_a_referenced_snapshot_survives_repeated_reloads(self, tmp_path):
        """【核心性质】被引用的快照，连续 reload 后连接**仍然可用**。

        修复前：两次 reload 之后 `snap.conn` 已关闭 →
        `sqlite3.ProgrammingError: Cannot operate on a closed database`。
        """
        det = _mk_detector(tmp_path)
        snap = det._snapshot
        lease = snap.lease
        lease.acquire()
        try:
            for _ in range(3):
                det.reload()
            assert not lease.closed, (
                "仍被引用的快照连接被关掉了 —— 释放判据是代数，不是引用")
            assert _conn_usable(snap.conn), (
                "仍被引用的快照连接已经不可用 —— 在途执行任务会被打断")
        finally:
            lease.release()

    def test_the_connection_closes_when_the_last_reference_is_released(self, tmp_path):
        """引用归零 → 关闭。不能改成「永不释放」（那是把缺陷换成泄漏）。"""
        det = _mk_detector(tmp_path)
        snap = det._snapshot
        lease = snap.lease
        lease.acquire()
        det.reload()
        det.reload()
        assert not lease.closed, "还没释放引用就关了"
        lease.release()
        assert lease.closed, (
            "最后一个引用释放后连接没有关闭 —— 引用计数泄漏")
        assert not _conn_usable(snap.conn), (
            "连接标记为已关闭但实际还能用 —— 关闭语义不一致")

    def test_an_unreferenced_old_snapshot_is_still_reclaimed(self, tmp_path):
        """没人引用的旧代连接**仍要**按宽限期被回收（防泄漏）。

        这是与上一条配对的**反向**判据：
        只钉「不提前关」而不钉「该关的要关」，
        守卫会放过一个把连接永远留着的实现。
        """
        det = _mk_detector(tmp_path)
        snap = det._snapshot
        lease = snap.lease
        for _ in range(3):
            det.reload()
        assert lease.closed, (
            "无人引用的旧代连接永不关闭 —— 每次热更新泄漏一个内存库")
        assert not _conn_usable(snap.conn), (
            "标记为已关闭但连接实际仍可用")

    def test_the_grace_period_still_holds_for_one_generation(self, tmp_path):
        """**宽限一代**的原有行为保留：刚退休的那一代先不关。

        这条不是为了「保留旧行为」而钉的 ——
        它钉的是「不会在发布快照的同一瞬间把在途任务断掉」。
        """
        det = _mk_detector(tmp_path)
        snap = det._snapshot
        det.reload()
        assert not snap.lease.closed, (
            "刚退休一代就被关闭 —— 在途任务会被发布动作当场打断")
        assert _conn_usable(snap.conn)

    def test_acquiring_an_already_reclaimed_lease_does_not_raise(self, tmp_path):
        """已被回收的租约再 `acquire()` **不抛错**。

        竞态场景：线程 A 取到快照，线程 B 连续两次 reload 把这一代回收，
        A 才来 acquire。此时抛异常等于把一个**无害**的情况变成检测崩溃 ——
        检测路径并不使用快照连接（它走每事件私有的 `:memory:` 连接），
        快照的 `compiled` 又是不可变 tuple，租约失效不影响检测结果的正确性。
        """
        det = _mk_detector(tmp_path)
        snap = det._snapshot
        lease = snap.lease
        for _ in range(3):
            det.reload()
        assert lease.closed, "前提失效：这一代没有被回收"
        lease.acquire()      # 不得抛
        lease.release()      # 也不得抛


class TestTheDetectionPathActuallyHoldsALease:
    def test_the_detection_holds_a_lease_while_it_runs(self, tmp_path):
        """执行任务**确实**在跑的时候持有租约。

        没有这条，「按引用释放」只是机制上的一个字段，
        检测路径根本不用它 —— 性质就落空了。
        """
        det = _mk_detector(tmp_path)
        seen = []
        orig = det._detect_with_snapshot

        def spy(snap, event):
            seen.append(snap.lease.refs)
            return orig(snap, event)

        det._detect_with_snapshot = spy
        det.detect(_base_event(url="http://x/?q=UNION SELECT"))
        assert seen, "探针没被调用到 —— 检测路径没走 _detect_with_snapshot"
        assert seen[0] >= 1, (
            f"检测执行期间没有持有租约（refs={seen[0]}）—— "
            "「执行任务引用」这句话落空了")

    def test_the_lease_is_released_after_the_detection(self, tmp_path):
        det = _mk_detector(tmp_path)
        det.detect(_base_event(url="http://x/?q=UNION SELECT"))
        assert det._snapshot.lease.refs == 0, (
            "检测结束后租约没有释放 —— 引用计数只增不减")

    def test_detection_results_are_unchanged_by_the_lease(self, tmp_path):
        """回归：这次修复**不改变任何检测结果**。"""
        det = _mk_detector(tmp_path)
        hits = det.detect(_base_event(url="http://x/?q=UNION SELECT"))
        assert hits, "规则没有命中 —— 修复把检测改坏了"
        assert hits[0].rule_id == "22222222-0000-0000-0000-0000000000aa", hits[0].rule_id
        miss = det.detect(_base_event(url="http://x/?q=benign"))
        assert not miss, "良性事件被误报"


if __name__ == "__main__":       # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
