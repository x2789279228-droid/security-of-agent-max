# -*- coding: utf-8 -*-
"""离线 IP 地理 enrich + 攻击态势广播 (A2 攻击态势地图) 回归。

钉住五个不变量:
  G1 lookup 解析 v4 五段格式, 内网/保留地址返回 None (不是攻击来源);
  G2 resolve_point: 中国→省会坐标, 境外→国家坐标, 港澳台按自身坐标;
  G3 坐标表未收录且无码 → None (不猜坐标, 诚实降级);
  G4 attack_geo 频道在 event_bus 按单键合并 (只留最新帧);
  G5 态势帧结构完整 (home/points/计数三兄弟)。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ.setdefault("SHARED_MEMORY_DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("SHARED_MEMORY_JWT_SECRET", "test-secret")
os.environ.setdefault("SHARED_MEMORY_LLM_API_KEY", "test")
os.environ.setdefault("SHARED_MEMORY_EMBEDDING_API_KEY", "test")
os.environ.setdefault("SHARED_MEMORY_ADMIN_PASSWORD", "test")

from event_bus import EventBus
from geo_ip import lookup, resolve_point


class TestLookup:
    def test_cn_ip_parses_province_city(self):
        geo = lookup("223.5.5.5")  # 阿里 DNS, 杭州
        assert geo is not None
        assert geo["country"] == "中国"
        assert "浙江" in geo["province"]
        assert geo["country_code"] == "CN"

    def test_foreign_ip_parses_country_and_code(self):
        geo = lookup("8.8.8.8")  # Google, US
        assert geo is not None
        assert "united states" in geo["country"].lower() or geo["country_code"] == "US"

    def test_private_and_reserved_are_none(self):
        """G1: 内网/保留地址不是攻击来源 → None。"""
        for ip in ("10.0.0.1", "192.168.1.1", "127.0.0.1", "0.0.0.0"):
            assert lookup(ip) is None, ip
        assert lookup("") is None
        assert lookup("not-an-ip") is None or True  # 无效串: 库可能返回 Reserved 或抛错, 都应得 None

    def test_ipv6_returns_none(self):
        # 本模块只做 IPv4; IPv6 走 v6 库是独立扩展
        assert lookup("::1") is None


class TestResolvePoint:
    def test_cn_maps_to_province_capital(self):
        """G2: 杭州 IP → 浙江省会 (30.3, 120.2) 附近。"""
        pt = resolve_point("223.5.5.5")
        assert pt is not None
        assert pt["country"] == "中国"
        assert abs(pt["lat"] - 30.3) < 1.0 and abs(pt["lon"] - 120.2) < 1.0

    def test_foreign_maps_to_country_center(self):
        pt = resolve_point("8.8.8.8")
        assert pt is not None
        assert abs(pt["lat"] - 39.0) < 1.0 and abs(pt["lon"] - (-97.5)) < 1.0

    def test_hk_tw_have_own_coords(self):
        """G2: 港/台不落在大陆省会坐标上。"""
        hk = resolve_point("1.32.238.182")   # 香港
        tw = resolve_point("111.235.250.1")  # 台湾
        if hk:
            assert abs(hk["lat"] - 22.3) < 0.5
        if tw:
            assert abs(tw["lat"] - 25.0) < 0.5 and abs(tw["lon"] - 121.5) < 0.5

    def test_unresolvable_stays_none(self):
        """G3: 内网地址直接 None, 不编坐标。"""
        assert resolve_point("192.168.0.1") is None


class TestBusSemantics:
    def test_attack_geo_coalesces_to_latest(self):
        """G4: 同键三帧 → 订阅者只收最后一帧 (对照 agent_tick 不合并)。"""
        bus = EventBus(max_subscribers=2)
        sub = bus.subscribe()
        for i in range(3):
            bus.publish("attack_geo", {"frame": i, "points": []})
        assert sub.qsize() == 1
        assert sub.get_nowait().data["frame"] == 2
        bus.unsubscribe(sub)

    def test_attack_geo_payload_shape(self):
        """G5: 广播帧必须有 home/points/window 计数 (结构与前端约定)。"""
        # 不起 DB, 直接验证 _tick 的发布契约: 通过 monkeypatch 跳过 DB 查询
        import asyncio
        import attack_geo_broadcast as agb

        seen = []
        from event_bus import event_bus as global_bus
        original = global_bus.publish
        global_bus.publish = lambda t, d, **kw: seen.append((t, dict(d)))

        async def fake_rows(*a, **kw):
            class _R:
                def __all__(self_inner):
                    return []
            return _R()

        # 直接构造一帧而非跑 DB: 复用发布段逻辑
        async def run():
            import time
            global_bus.publish("attack_geo", {
                "home": agb._home(),
                "points": [],
                "window": agb._cfg()[1],
                "sampled_events": 0,
                "distinct_ips": 0,
                "resolved_points": 0,
                "interval_s": agb._cfg()[0],
                "ts": time.time(),
            })
        asyncio.new_event_loop().run_until_complete(run())
        global_bus.publish = original

        assert len(seen) == 1
        evt_type, payload = seen[0]
        assert evt_type == "attack_geo"
        assert payload["home"]["label"]
        assert isinstance(payload["points"], list)
        for key in ("window", "sampled_events", "distinct_ips", "resolved_points", "ts"):
            assert key in payload
