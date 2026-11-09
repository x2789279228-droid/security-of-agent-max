"""A3 多进程三件套单测：选主 / 共享压力 Gauge / 认领仲裁决策。"""
import asyncio
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import capacity
from scheduler_leader import LeaderElection


class _FakeRedis:
    """极简 aioredis 假件：SET NX EX / EVAL(token 续约与释放) / HSET-HGETALL-EXPIRE pipeline。"""

    def __init__(self):
        self.kv: dict = {}
        self.hash: dict = {}
        self.expired: dict = {}

    def _awaitable(self, v):
        return v

    # —— 分布式锁语义 ——
    async def set(self, key, value, ex=None, nx=False):
        if nx and key in self.kv:
            return None
        self.kv[key] = value
        if ex:
            self.expired[key] = ex
        return True

    async def get(self, key):
        return self.kv.get(key)

    async def delete(self, key):
        self.kv.pop(key, None)

    def eval(self, lua, numkeys, key, *args):
        # 与真 Lua 同判：token 匹配才 EXPIRE / DEL
        token = args[0]
        async def _run():
            if self.kv.get(key) != token:
                return 0
            if "EXPIRE" in lua:
                self.expired[key] = int(args[1])
                return 1
            if "DEL" in lua:
                self.kv.pop(key, None)
                return 1
            return 0
        return _run()

    # —— 共享 Gauge ——
    class _Pipe:
        def __init__(self, outer):
            self.outer = outer
            self.ops = []

        def hset(self, key, field, value):
            self.ops.append(("hset", key, field, value))
            return self

        def expire(self, key, ttl):
            self.ops.append(("expire", key, ttl))
            return self

        async def execute(self):
            for op in self.ops:
                if op[0] == "hset":
                    self.outer.hash.setdefault(op[1], {})[op[2]] = op[3]
                elif op[0] == "expire":
                    self.outer.expired[op[1]] = op[2]
            self.ops.clear()

    def pipeline(self):
        return _FakeRedis._Pipe(self)

    async def hgetall(self, key):
        raw = dict(self.hash.get(key, {}))
        return {k.encode() if isinstance(k, str) else k: v for k, v in raw.items()}


# ───────────────────────── 选主 ─────────────────────────

@pytest.mark.asyncio
async def test_leader_election_two_workers_single_leader():
    w1, w2 = _FakeRedis(), _FakeRedis()

    # 共享同一 Redis 才有意义 —— 用同一个实例
    shared = _FakeRedis()
    l1 = LeaderElection(client=shared, ttl_s=6, identity="w1")
    l2 = LeaderElection(client=shared, ttl_s=6, identity="w2")

    assert await l1.try_become_leader_once() is True
    assert await l2.try_become_leader_once() is False  # follower
    assert l1.is_leader and not l2.is_leader

    # w1 释放后 w2 可接任
    await l1.release()
    assert await l2.try_become_leader_once() is True


@pytest.mark.asyncio
async def test_leader_renew_extends_and_detects_loss():
    import distributed_lock
    shared = _FakeRedis()
    le = LeaderElection(client=shared, ttl_s=6, identity="w1")
    assert await le.try_become_leader_once() is True
    shared.kv[le.key] = "other-token"  # 租约被夺
    assert await le.renew() is False
    assert le.is_leader is False


@pytest.mark.asyncio
async def test_supervise_redis_none_runs_loops_directly(monkeypatch):
    """Redis 不可用 → 退回单进程语义（直接启动调度循环），不停摆。"""
    le = LeaderElection(client=None)
    started = {"n": 0}

    async def fake_acquire(key, ttl, client=None):
        return None
    monkeypatch.setattr("scheduler_leader.try_acquire", fake_acquire)

    async def start():
        started["n"] += 1

    async def stop():
        started["n"] -= 1

    task = asyncio.create_task(le.supervise(start, stop))
    await asyncio.sleep(0.1)
    assert started["n"] == 1  # 直接启动
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)


# ───────────────────────── 共享 Gauge ─────────────────────────

@pytest.mark.asyncio
async def test_publish_worker_gauges_merges_remote_max(monkeypatch):
    shared = _FakeRedis()
    # 远端 worker 已发布更深的 lag
    shared.hash["soc:gauge:kafka_lag"] = {"other-host-1": "42000"}

    monkeypatch.setattr(capacity, "audit_queue_ratio", lambda: 0.1)
    monkeypatch.setattr("audit_pq.pq_depth_snapshot", lambda: 5)

    # 跑一轮（interval 最小 2s —— 直接调内部一轮逻辑：手动执行一次循环体）
    pub = capacity.publish_worker_gauges(shared, interval_s=2)
    task = asyncio.create_task(pub)
    await asyncio.sleep(0.3)  # 第一轮完成
    assert "kafka_lag" in capacity._CLUSTER_GAUGES
    assert capacity._CLUSTER_GAUGES["kafka_lag"] == 42000.0  # 远端 max 已合并
    # 本地读数已发布（hash 有自己的 field）
    own = shared.hash["soc:gauge:audit_queue_ratio"]
    assert capacity._WORKER_ID in own
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)


def test_cluster_max_takes_remote():
    capacity._CLUSTER_GAUGES.clear()
    capacity._CLUSTER_GAUGES["kafka_lag"] = 500.0
    assert capacity._cluster_max("kafka_lag", 100.0) == 500.0
    assert capacity._cluster_max("kafka_lag", 900.0) == 900.0
    capacity._CLUSTER_GAUGES.clear()
    assert capacity._cluster_max("kafka_lag", 300.0) == 300.0  # 单进程语义不变


# ───────────────────────── 认领仲裁 ─────────────────────────

def test_pg_advisory_claim_returns_none_without_db(monkeypatch):
    """models.engine 不可导入 → None（退回 fail-open，语义与文档一致）。"""
    import distributed_lock as dl

    async def _boom():
        raise ImportError("no engine")
    monkeypatch.setattr("models.engine", None, raising=False)
    # 连接失败路径：engine.connect 抛错 → None
    class _E:
        async def connect(self):
            raise RuntimeError("db down")
    monkeypatch.setattr("models.engine", _E(), raising=False)
    assert asyncio.run(dl.pg_advisory_claim(1, 30)) is None
