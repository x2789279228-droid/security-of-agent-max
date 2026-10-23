"""Q7 / Q8 关联引擎（correlation_engine.py）正确性审查。

断言匹配**实测到的真实行为**，docstring 里写清是「正向结论」还是
「固化缺陷行为」。缺陷编号 C7-xx / C8-xx 对应审查报告的发现清单。

`_match_pattern` / `_temporal_grouping` / `_entity_linking` / `_dedup_chains`
都是纯函数或只吃 dict，不依赖 DB，所以本文件不需要 session。
"""
from datetime import datetime, timedelta, timezone

import pytest

from correlation_engine import (
    ATTACK_CHAIN_PATTERNS,
    CorrelationEngine,
    UNATTRIBUTED_PREFIX,
    actor_key,
    actor_label,
    normalize_event_type,
)

T0 = datetime(2026, 10, 18, 12, 0, 0, tzinfo=timezone.utc)


def ev(eid, etype, minutes=0, src="1.1.1.1", dst="2.2.2.2", severity="high"):
    return {
        "id": eid,
        "event_type": etype,
        "severity": severity,
        "src_ip": src,
        "dst_ip": dst,
        "message": "",
        "created_at": T0 + timedelta(minutes=minutes),
    }


ENGINE = CorrelationEngine()


def match(pattern_key, events, src_ip="1.1.1.1"):
    return ENGINE._match_pattern(
        pattern_key, ATTACK_CHAIN_PATTERNS[pattern_key], src_ip, events)


# ══════════════════════════════════════════════════════════════
# Q7 · 四条关联路径的正反案例
# ══════════════════════════════════════════════════════════════

class TestQ7PatternPath:
    def test_q7_1_arbitrary_step_skipping_is_off_by_default(self):
        """[FIXED] 没有任何模式打开「任意跳步」，默认必须是关的。

        修复前：跳步条件是
            all(m in skippable for m in middle) or pattern.get("allow_skip_missing", True)
        默认值 True 让整个条件恒成立，「只有 skippable 里配过的中间步才能跳」
        这个意图从未生效：任何中间步都可被静默跳过。

        现在 `allow_skip_missing` 默认 False（要放宽必须显式打开），
        且 11 个内置模式一个都没打开它 —— 所以「可跳过的步骤」只有
        `skippable` 里显式声明的那些。
        """
        offenders = [k for k, p in ATTACK_CHAIN_PATTERNS.items()
                     if p.get("allow_skip_missing")]
        assert offenders == [], f"有模式打开了任意跳步: {offenders}"
        # 唯一被声明可跳过的步骤是 classic_killchain 的 LATERAL_MOVE
        skippable = {k: tuple(p.get("skippable") or ())
                     for k, p in ATTACK_CHAIN_PATTERNS.items()
                     if p.get("skippable")}
        assert skippable == {"classic_killchain": ("LATERAL_MOVE",)}, skippable

    def test_q7_2_killchain_requires_the_declared_steps(self):
        """[FIXED] classic_killchain 在缺 C2 回连 / 缺横向移动时**不再**命中。

        修复前：steps=[PORT_SCAN, BRUTE_FORCE, LATERAL_MOVE, C2_BEACON,
        DATA_EXFIL]、min_match=3，但任意步骤都能被跳过，于是
        [端口扫描, 暴力破解, 数据外泄] 三条即命中，告警文案仍然是
        「经典杀伤链」—— 而 C2 回连正是判定「已失陷」的关键环节。
        跳过 LATERAL_MOVE 是配置允许的；跳过 C2_BEACON 不是。

        现在：`skippable=[LATERAL_MOVE]` 只允许跳 LATERAL_MOVE，
        跳过 C2_BEACON 被拒绝 → 3 条不够 min_match → 不命中。
        """
        assert match("classic_killchain",
                     [ev(1, "PORT_SCAN", 0), ev(2, "BRUTE_FORCE", 5),
                      ev(3, "DATA_EXFIL", 10)]) is None, \
            "缺 C2 回连仍然命中经典杀伤链"

        # 声明可跳过的 LATERAL_MOVE 确实可以缺
        chain = match("classic_killchain",
                      [ev(1, "PORT_SCAN", 0), ev(2, "BRUTE_FORCE", 5),
                       ev(4, "C2_BEACON", 10), ev(5, "DATA_EXFIL", 12)])
        assert chain is not None
        assert chain.partial is True
        assert chain.skipped_steps == ["LATERAL_MOVE"]
        assert chain.required_steps == ["PORT_SCAN", "BRUTE_FORCE",
                                        "C2_BEACON", "DATA_EXFIL"]

    def test_q7_3_lateral_movement_needs_a_real_lateral_step(self):
        """[FIXED] 缺步骤时不再被冠以「横向移动」，且缺口必须写进结果。

        该模式没有配置 `skippable`，本意是四步按序都要；修复前
        min_match=2 + 无条件跳步让 [SUSPICIOUS_LOGIN, C2_BEACON]
        就被冠以「横向移动」之名。

        现在：C2_BEACON 不能靠跳过 FILE_ACCESS / LATERAL_MOVE 来命中，
        一条都不剩 → 不命中。而只凑够前两步时仍会命中（那是作者写的
        min_match=2），但**必须**把没命中的步骤显式报出来。
        """
        assert "skippable" not in ATTACK_CHAIN_PATTERNS["lateral_movement"]
        assert match("lateral_movement",
                     [ev(1, "SUSPICIOUS_LOGIN", 0),
                      ev(2, "C2_BEACON", 10)]) is None, \
            "没有任何横向移动事件却命中「横向移动」"

        # 只凑够前两步：命中，但必须自报缺口
        partial = match("lateral_movement",
                        [ev(1, "SUSPICIOUS_LOGIN", 0), ev(2, "FILE_ACCESS", 5),
                         ev(3, "C2_BEACON", 10)])
        assert partial is not None
        assert [e["event_type"] for e in partial.events] == \
            ["SUSPICIOUS_LOGIN", "FILE_ACCESS"]
        assert partial.partial is True
        assert partial.skipped_steps == ["LATERAL_MOVE", "C2_BEACON"]

        # 四步齐全才是完整链
        full = match("lateral_movement",
                     [ev(1, "SUSPICIOUS_LOGIN", 0), ev(2, "FILE_ACCESS", 5),
                      ev(3, "LATERAL_MOVE", 10), ev(4, "C2_BEACON", 15)])
        assert full is not None
        assert full.partial is False and full.skipped_steps == []

    def test_q7_4_step_order_is_still_enforced(self):
        """【正向结论·否证假设】跳过**中间**步不等于放弃顺序约束。

        反序序列 [C2 → 端口扫描 → 暴力破解] 不会命中 port_scan_to_c2，
        因为单个事件只能消费一个 step，step_idx 单调推进。
        （审查初稿曾假设「方向性反转」，此处实测否证。）
        """
        ordered = [ev(1, "PORT_SCAN", 0), ev(2, "BRUTE_FORCE", 1),
                   ev(3, "C2_BEACON", 2)]
        assert match("port_scan_to_c2", ordered) is not None
        reversed_seq = [ev(1, "C2_BEACON", 0), ev(2, "PORT_SCAN", 1),
                        ev(3, "BRUTE_FORCE", 2)]
        assert match("port_scan_to_c2", reversed_seq) is None, \
            "反序开始命中 —— 请更新结论"

    def test_q7_5_patterns_without_min_match_need_every_step(self):
        """【正向结论】未配 min_match 的模式取 min_match=n，仍需全部步骤按序出现。"""
        assert "min_match" not in ATTACK_CHAIN_PATTERNS["ransomware"]
        assert match("ransomware", [ev(1, "PHISHING", 0),
                                    ev(2, "SUSPICIOUS_LOGIN", 1),
                                    ev(3, "FILE_ACCESS", 2),
                                    ev(4, "RANSOMWARE", 3)]) is not None
        assert match("ransomware", [ev(1, "PHISHING", 0),
                                    ev(2, "SUSPICIOUS_LOGIN", 1),
                                    ev(3, "FILE_ACCESS", 2)]) is None
        assert match("data_exfil", [ev(1, "FILE_ACCESS", 0)]) is None

    def test_q7_6_skippable_config_now_has_an_observable_effect(self):
        """[FIXED] `skippable` 配置真的构成约束了。

        修复前：classic_killchain 配了 `skippable=["LATERAL_MOVE"]`，
        但**未**配置的 C2_BEACON 同样能被跳过 —— 因为 `allow_skip_missing`
        默认 True 短路了整个条件，配置项形同虚设。

        现在：同一段事件流，去掉 `skippable` 就**不再命中**。
        """
        events = [ev(1, "PORT_SCAN", 0), ev(2, "BRUTE_FORCE", 1),
                  ev(3, "C2_BEACON", 2), ev(4, "DATA_EXFIL", 3)]
        with_cfg = match("classic_killchain", events)
        assert with_cfg is not None
        assert with_cfg.skipped_steps == ["LATERAL_MOVE"]

        stripped = dict(ATTACK_CHAIN_PATTERNS["classic_killchain"])
        stripped.pop("skippable")
        without = ENGINE._match_pattern("classic_killchain", stripped,
                                        "1.1.1.1", events)
        assert without is None, \
            "去掉 skippable 后仍命中 —— 配置项依然不构成约束"

    def test_q7_6b_total_duration_is_checked_separately_from_gap(self):
        """[FIXED] 相邻间隔与**整条链的总跨度**是两个独立约束。

        修复前只有相邻间隔上限，于是「每步间隔 29 分钟」的链
        可以跨越 58 分钟，而 `port_scan_to_c2` 声明的语义是
        「30 分钟内的一次攻击」—— 一条拖了近一小时的链照样报警。

        上界必须**严于** `gap × (步数-1)`，否则这条约束永远不会
        独立生效（本轮第一版就把 3 步 × 30 分钟的端口扫描链设成 60 分钟，
        恰好等于两个间隔之和，于是测试根本区分不出有没有这条约束）。
        """
        p = ATTACK_CHAIN_PATTERNS["port_scan_to_c2"]
        assert p["max_gap_minutes"] == 30
        assert p["max_chain_duration_minutes"] == 45
        assert p["max_chain_duration_minutes"] < p["max_gap_minutes"] * (
            len(p["steps"]) - 1), "总跨度上界必须严于间隔上界之和，否则约束无效"

        # 每步间隔 20 分钟、总跨度 40 → 命中
        ok = match("port_scan_to_c2",
                   [ev(1, "PORT_SCAN", 0), ev(2, "BRUTE_FORCE", 20),
                    ev(3, "C2_BEACON", 40)])
        assert ok is not None and ok.time_span_minutes == 40.0

        # 每步间隔 29 分钟（都 < 30），但总跨度 58 > 45 → 拒绝
        far = match("port_scan_to_c2",
                    [ev(1, "PORT_SCAN", 0), ev(2, "BRUTE_FORCE", 29),
                     ev(3, "C2_BEACON", 58)])
        assert far is None, "总跨度超限仍然命中"

        # 对照：单步间隔超限也拒绝（原有约束仍然有效）
        assert match("port_scan_to_c2",
                     [ev(1, "PORT_SCAN", 0), ev(2, "BRUTE_FORCE", 31),
                      ev(3, "C2_BEACON", 32)]) is None

    def test_q7_5_gap_constraint_is_enforced(self, ):
        """【正向结论】时间间隔约束是有效的，超过 max_gap_minutes 不命中。"""
        ok = match("port_scan_to_c2",
                   [ev(1, "PORT_SCAN", 0), ev(2, "BRUTE_FORCE", 10),
                    ev(3, "C2_BEACON", 20)])       # gap 10 <= 30
        assert ok is not None
        bad = match("port_scan_to_c2",
                    [ev(1, "PORT_SCAN", 0), ev(2, "BRUTE_FORCE", 31),
                     ev(3, "C2_BEACON", 62)])       # gap 31 > 30
        assert bad is None

    def test_q7_6_min_match_guards_short_sequences(self):
        """【正向结论】min_match 门槛有效，事件数不足直接返回 None。"""
        assert match("port_scan_to_c2", [ev(1, "PORT_SCAN", 0)]) is None
        assert match("port_scan_to_c2",
                     [ev(1, "PORT_SCAN", 0), ev(2, "BRUTE_FORCE", 1)]) is None

    def test_q7_7_chinese_event_names_normalize(self):
        """【正向结论】中文事件名经 normalize_event_type 归一后可参与匹配。"""
        assert normalize_event_type("端口扫描") == "PORT_SCAN"
        assert normalize_event_type("暴力破解") == "BRUTE_FORCE"
        assert normalize_event_type("LATERAL_MOVEMENT") == "LATERAL_MOVE"
        assert normalize_event_type("") == "UNKNOWN"
        chain = match("port_scan_to_c2",
                      [ev(1, "端口扫描", 0), ev(2, "暴力破解", 1),
                       ev(3, "C2通信", 2)])
        assert chain is not None


class TestQ7TemporalPath:
    def test_q7_8_temporal_window_is_chained_not_fixed(self):
        """【P1】时间分组按「组内最后一条」比较，组跨度可远超 window_minutes。

        09:00 / 09:09 / 09:18 三条，window=10：
        相邻 gap 均为 9 分钟 → 全部并入同一组，
        但整组跨度 18 分钟 > 10 分钟窗口。
        若语义是「10 分钟窗口」，第三条不应在组内。
        """
        events = [ev(1, "A", 0), ev(2, "B", 9), ev(3, "C", 18)]
        groups = ENGINE._temporal_grouping("1.1.1.1", events, window_minutes=10)
        assert len(groups) == 1, "分组结果变了"
        assert groups[0]["count"] == 3
        span = (datetime.fromisoformat(groups[0]["end"])
                - datetime.fromisoformat(groups[0]["start"])).total_seconds() / 60
        assert span == 18.0, f"组跨度变了: {span}"

    def test_q7_9_single_event_groups_are_dropped(self):
        """【正向结论】只有 1 条事件的组不产出（避免噪声）。"""
        events = [ev(1, "A", 0), ev(2, "B", 60)]
        assert ENGINE._temporal_grouping("1.1.1.1", events, 10) == []


class TestQ7EntityLinkPath:
    def test_q7_11_empty_src_ip_is_never_merged_into_one_fake_attacker(self):
        """[FIXED] src_ip 缺失的事件不再被并进同一个虚拟攻击者。

        整改方案 §八：
        > 「如果没有 src_ip，也没有其他能够关联攻击者身份的字段，
        > 不能把所有未知来源事件都当成同一个攻击者的行为。」

        修复前：`correlation_engine` 用 `evt.src_ip or "unknown"` 分组，
        **全部**无 src_ip 的事件被塞进同一个虚拟攻击者「unknown」，
        随后 `_match_pattern` 把它们当成同一个 IP 的事件序列做攻击链匹配 ——
        来源完全无关的三条事件能被串成一条完整「攻击链」，
        且链的 `src_ips` 里躺着一个并不存在的「unknown」IP
        （API 会把它当地址吐给下游）。

        现在：无 src_ip 且无身份字段时，每条事件一个独立键，永不合并；
        `_match_pattern` 在**断言点**再挡一次 —— 绕过分组直接调用
        （旧测试就是这么干的）也拿不到链。
        """
        merged = [ev(1, "PORT_SCAN", 0, src=None),
                  ev(2, "BRUTE_FORCE", 5, src=None),
                  ev(3, "C2_BEACON", 9, src=None)]

        # 「unknown」与空串都是「我不知道这个行为体是谁」的标记，不是身份。
        # 拿它们断言一条攻击链，等于凭空造出一个攻击者。
        for fake in ("unknown", ""):
            assert match("port_scan_to_c2", merged, src_ip=fake) is None, (
                f"行为体 {fake!r} 不是身份，却断言出了一条攻击链")

    def test_q7_12_entity_linking_does_not_false_positive_on_unknown(self):
        """【否证假设】全部 src_ip 缺失时 _entity_linking 不产生误报。

        只有一个虚拟源，len(srcs)>=2 不成立。真正的问题在 pattern 路径
        （见 test_q7_11），不在这里。
        """
        events_by_ip = {"unknown": [
            ev(1, "A", 0, src=None, dst="2.2.2.2"),
            ev(2, "B", 1, src=None, dst="2.2.2.2"),
        ]}
        assert ENGINE._entity_linking(events_by_ip) == []

    def test_q7_13_real_distinct_sources_do_link(self):
        """【正向结论】两个真实源 IP 打同一目标 → 产出实体关联。"""
        events_by_ip = {
            "1.1.1.1": [ev(1, "A", 0, src="1.1.1.1", dst="2.2.2.2")],
            "3.3.3.3": [ev(2, "B", 1, src="3.3.3.3", dst="2.2.2.2")],
        }
        links = ENGINE._entity_linking(events_by_ip)
        assert len(links) == 1
        assert sorted(links[0]["src_ips"]) == ["1.1.1.1", "3.3.3.3"]

    def test_q7_14_single_source_no_link(self):
        """【正向结论】只有一个源时不产出关联。"""
        events_by_ip = {"1.1.1.1": [ev(1, "A", 0)]}
        assert ENGINE._entity_linking(events_by_ip) == []


class _Evt:
    """`actor_key` 吃的是 ORM 对象（evt.id / evt.src_ip / evt.raw_data）。"""

    def __init__(self, eid, src_ip="", raw_data=None):
        self.id = eid
        self.src_ip = src_ip
        self.raw_data = raw_data or {}


class TestQ8ActorBinding:
    """整改方案 §八：「来源实体的绑定必须清晰。」

    行为体绑定分三档，缺哪一档都必须是**诚实的**：

    · 有 src_ip                 → 按 IP（正常路径，行为不变）
    · 无 src_ip 但有身份字段    → 按身份（文档允许：确实是同一行为体）
    · 两者都没有               → **每条事件一个独立键**，永不与他人合并
    """

    def test_real_src_ip_binds_by_ip(self):
        assert actor_key(_Evt(1, "1.1.1.1")) == "1.1.1.1"

    def test_blank_src_ip_falls_back_to_an_identity_field(self):
        key = actor_key(_Evt(2, "", {"user": "alice"}))
        assert key == "ident:user=alice", key
        assert actor_label(key) == "user:alice"

    def test_ambiguous_host_field_is_deliberately_not_used(self):
        """`host` 在 web 日志里通常是**被访问的目标**，不是攻击者。

        按它分组会把「很多不同攻击者打同一个站点」并成一个行为体 ——
        那是用一个误报换另一个误报。所以刻意不收 host/hostname。
        """
        key = actor_key(_Evt(3, "", {"host": "www.example.com"}))
        assert key.startswith(UNATTRIBUTED_PREFIX), (
            f"host 被当成了攻击者身份：{key}")

    def test_unattributable_events_never_share_a_key(self):
        a = actor_key(_Evt(4, "", {}))
        b = actor_key(_Evt(5, "", {}))
        assert a != b, "两条无法归因的事件被并成了同一个行为体"
        assert a.startswith(UNATTRIBUTED_PREFIX)
        assert b.startswith(UNATTRIBUTED_PREFIX)

    def test_three_sourceless_events_still_cannot_form_a_chain(self):
        """三条无源事件凑齐三种类型 —— 仍然不得成链。"""
        merged = [ev(1, "PORT_SCAN", 0, src=None),
                  ev(2, "BRUTE_FORCE", 5, src=None),
                  ev(3, "C2_BEACON", 9, src=None)]
        for key in (actor_key(_Evt(1, "", {})), "unknown", ""):
            assert match("port_scan_to_c2", merged, src_ip=key) is None, (
                f"行为体 {key!r} 断言出了一条攻击链")

    def test_a_real_identity_can_still_form_a_chain(self):
        """文档允许的情况：无 src_ip 但有身份字段时，它们**确实是**同一行为体。

        这条同时钉住「修归因没有把真实检测能力一起修掉」——
        修归因很容易顺手写成「无 src_ip 一律不成链」，那是把误报换成漏报。
        """
        merged = [ev(1, "PORT_SCAN", 0, src=None),
                  ev(2, "BRUTE_FORCE", 5, src=None),
                  ev(3, "C2_BEACON", 9, src=None)]
        chain = match("port_scan_to_c2", merged, src_ip="ident:user=alice")
        assert chain is not None, "有身份字段时不得丢掉真实检测能力"
        assert chain.src_ips == set(), (
            "src_ips 只放真实 IP —— 塞一个非 IP 进去就是谎报")
        assert chain.actor == "user:alice"
        assert chain.alert.startswith("[端口扫描→漏洞利用→C2回连] user:alice")

    def test_normal_ip_chain_keeps_its_src_ips_unchanged(self):
        """正常路径必须**逐位不变** —— 修归因不该动到有 src_ip 的链。"""
        merged = [ev(1, "PORT_SCAN", 0), ev(2, "BRUTE_FORCE", 5),
                  ev(3, "C2_BEACON", 9)]
        chain = match("port_scan_to_c2", merged, src_ip="1.1.1.1")
        assert chain is not None
        assert chain.src_ips == {"1.1.1.1"}
        assert chain.actor == "1.1.1.1"
        assert chain.alert.startswith("[端口扫描→漏洞利用→C2回连] 1.1.1.1")

    def test_entity_linking_ignores_events_without_a_real_src_ip(self):
        """实体关联的输出字段叫 `src_ips`，所以只能装真实 IP。

        修复前这里加的是**分组键**（可能是并不存在的「unknown」）。
        分组修好之后若无源事件各占一个键，两条无源事件打同一目标反而会
        凑出 len(srcs)>=2 的一条「协同攻击」关联 —— 用一个误报换另一个。
        """
        events_by_ip = {
            "unattributed:1": [ev(1, "A", 0, src=None, dst="2.2.2.2")],
            "unattributed:2": [ev(2, "B", 1, src=None, dst="2.2.2.2")],
        }
        assert ENGINE._entity_linking(events_by_ip) == [], (
            "两条无源事件打同一目标被判成了协同攻击")


# ══════════════════════════════════════════════════════════════
# 端到端：跑真实的 analyze()，验**接线**而不是只验方法
# ══════════════════════════════════════════════════════════════

class _OrmRow:
    """`_analyze_inner` 吃的是 ORM 对象，不是 dict。"""

    def __init__(self, d):
        self.id = d["id"]
        self.event_type = d["event_type"]
        self.severity = d["severity"]
        self.src_ip = d["src_ip"]
        self.dst_ip = d["dst_ip"]
        self.message = d["message"]
        self.created_at = d["created_at"]
        self.raw_data = d.get("raw_data") or {}


class _Scalars:
    def __init__(self, rows):
        self._rows = rows

    def all(self):
        return self._rows


class _Res:
    def __init__(self, rows):
        self._rows = rows

    def scalars(self):
        return _Scalars(self._rows)


class _Session:
    """只实现 `execute()` —— `_analyze_inner` 只用它做一次 select。"""

    def __init__(self, rows):
        self._rows = rows

    async def execute(self, stmt):
        return _Res(self._rows)


#: 端到端夹具的基准时刻。
#:
#: 刻意用「基准 + minutes」而不是「now - minutes」—— 后者会让时间序**反过来**
#: （minutes=0 变成最新的一条），模式的有序子序列匹配于是必然失败，
#: 用例就会因为**错误的原因**变绿：断言「没有链」在「链本来就匹配不上」
#: 时同样成立。基准取一小时前，保证所有事件都落在分析回溯窗口内。
_E2E_BASE = datetime.now(timezone.utc) - timedelta(hours=1)


def _row(eid, etype, minutes=0, src="1.1.1.1", dst="2.2.2.2",
         severity="high", raw_data=None):
    return _OrmRow({
        "id": eid, "event_type": etype, "severity": severity,
        "src_ip": src, "dst_ip": dst, "message": "",
        "created_at": _E2E_BASE + timedelta(minutes=minutes),
        "raw_data": raw_data or {},
    })


class TestQ8ActorBindingEndToEnd:
    """端到端跑真实的 `analyze()`。

    只测 `actor_key` / `_match_pattern` 是不够的 —— **分组**发生在
    `_analyze_inner` 里。守卫没连到它声称保护的东西时，纯函数测试会全绿
    而生产路径照旧出误报（本仓库 `test_anomaly_timezone_fallback.py`
    记录过这个教训：「方法对、接线错」）。
    """

    def _analyze(self, rows):
        import asyncio
        return asyncio.run(ENGINE.analyze(_Session(rows), "sess-x"))

    def test_sourceless_events_do_not_produce_a_chain(self):
        """修复前这三条会被并进「unknown」并串成一条完整攻击链。"""
        rows = [_row(1, "PORT_SCAN", 0, src=""),
                _row(2, "BRUTE_FORCE", 5, src=""),
                _row(3, "C2_BEACON", 9, src="")]
        r = self._analyze(rows)
        assert r.chains == [], (
            f"三条无源事件被串成了一条攻击链：{[c.alert for c in r.chains]}")

    def test_unattributable_events_are_counted_not_silently_dropped(self):
        """归因不了的事件要**留痕** —— 否则「没攻击」与「归因不了」同形。"""
        rows = [_row(1, "PORT_SCAN", 0, src=""),
                _row(2, "BRUTE_FORCE", 5, src=""),
                _row(3, "C2_BEACON", 9, src="")]
        r = self._analyze(rows)
        assert r.unattributed_source_events == 3, r.unattributed_source_events
        assert r.observability["unattributed_source_events"] == 3

    def test_virtual_unknown_source_is_not_counted_as_a_source_ip(self):
        rows = [_row(1, "PORT_SCAN", 0, src=""),
                _row(2, "BRUTE_FORCE", 5, src="1.1.1.1"),
                _row(3, "C2_BEACON", 9, src="1.1.1.1")]
        r = self._analyze(rows)
        assert r.source_ip_count == 1, (
            f"源 IP 数被虚拟的「unknown」灌了水：{r.source_ip_count}")

    def test_a_real_source_still_produces_its_chain(self):
        """修归因不能顺手把真实检测能力也修掉。"""
        rows = [_row(1, "PORT_SCAN", 0, src="1.1.1.1"),
                _row(2, "BRUTE_FORCE", 5, src="1.1.1.1"),
                _row(3, "C2_BEACON", 9, src="1.1.1.1")]
        r = self._analyze(rows)
        assert len(r.chains) == 1, [c.alert for c in r.chains]
        chain = r.chains[0]
        assert chain.src_ips == {"1.1.1.1"}
        assert chain.actor == "1.1.1.1"
        assert r.unattributed_source_events == 0

    def test_an_identity_backed_chain_still_forms_end_to_end(self):
        """有身份字段时，同一行为体的无源事件仍能成链（文档允许的情况）。"""
        rows = [_row(1, "PORT_SCAN", 0, src="", raw_data={"user": "alice"}),
                _row(2, "BRUTE_FORCE", 5, src="", raw_data={"user": "alice"}),
                _row(3, "C2_BEACON", 9, src="", raw_data={"user": "alice"})]
        r = self._analyze(rows)
        assert len(r.chains) == 1, [c.alert for c in r.chains]
        chain = r.chains[0]
        assert chain.actor == "user:alice", chain.actor
        assert chain.src_ips == set(), "src_ips 里塞假 IP 就是谎报"
        assert r.unattributed_source_events == 0

    def test_two_different_identities_do_not_merge_into_one_chain(self):
        """两个不同账号的无源事件不得被当成同一个行为体。"""
        rows = [_row(1, "PORT_SCAN", 0, src="", raw_data={"user": "alice"}),
                _row(2, "BRUTE_FORCE", 5, src="", raw_data={"user": "bob"}),
                _row(3, "C2_BEACON", 9, src="", raw_data={"user": "bob"}),
                _row(4, "DATA_EXFIL", 12, src="", raw_data={"user": "alice"})]
        r = self._analyze(rows)
        actors = sorted(c.actor for c in r.chains)
        assert "user:alice" not in actors or "user:bob" not in actors, (
            f"两个不同账号被并成了一条链：{actors}")


class _Row:
    """_match_hub_hosts 吃的是 ORM 对象（evt.id / evt.src_ip ...），不是 dict。"""

    def __init__(self, d):
        self.id = d["id"]
        self.event_type = d["event_type"]
        self.severity = d["severity"]
        self.src_ip = d["src_ip"]
        self.dst_ip = d["dst_ip"]
        self.message = d["message"]
        self.created_at = d["created_at"]


class TestQ7HubPath:
    def test_q7_15_hub_chain_id_is_content_addressed(self):
        """[FIXED] chain_id 由**链内容**决定，与无关的前置事件无关。

        修复前：`chain_id = f"chain_hub_{hub}_{deduped[0]['id']}"`，
        取的是时间轴首条事件（本例 id=1 的 DNS_QUERY），而不是链首事件
        （id=2 的 PORT_SCAN）。于是往时间轴前面插一条无关的 DNS_QUERY
        就会改变整条链的 chain_id —— ID 与内容脱钩，去重与追踪都失效。

        现在：chain_id 取匹配事件 ID 的排序指纹（`stable_chain_id`），
        所以「插入无关前置事件 → chain_id 变化」这个缺陷消失了。
        """
        base = [
            ev(2, "PORT_SCAN", 1, src="9.9.9.9", dst="HUB"),
            ev(3, "BRUTE_FORCE", 2, src="9.9.9.9", dst="HUB"),
            ev(4, "C2_BEACON", 3, src="HUB", dst="8.8.8.8"),
            ev(5, "DATA_EXFIL", 4, src="HUB", dst="8.8.8.8"),
        ]
        with_noise = [ev(1, "DNS_QUERY", 0, src="9.9.9.9", dst="HUB")] + base

        c_clean = ENGINE._match_hub_hosts([_Row(d) for d in base])
        c_noisy = ENGINE._match_hub_hosts([_Row(d) for d in with_noise])
        assert len(c_clean) == 1 and len(c_noisy) == 1
        assert c_clean[0].chain_id == c_noisy[0].chain_id, (
            "插入一条无关事件就改变了 chain_id —— 仍然与内容脱钩")
        assert c_clean[0].chain_id.startswith("chain_hub_killchain_HUB_")

        # 内容确实变了（少一个事件）时，ID 必须跟着变
        shorter = ENGINE._match_hub_hosts([_Row(d) for d in base[:3]])
        assert shorter and shorter[0].chain_id != c_clean[0].chain_id

        c = c_clean[0]
        assert [e["id"] for e in c.events][0] == 2
        assert c.src_ips == {"9.9.9.9", "HUB"}, c.src_ips
        assert c.dst_ips == {"HUB", "8.8.8.8"}, c.dst_ips

    def test_q7_16_only_dst_never_becomes_hub(self):
        """【正向结论】只作为目标的 IP 不会被当成枢纽（需同时出现在 src 集）。"""
        rows = [_Row(d) for d in (
            ev(1, "PORT_SCAN", 0, src="9.9.9.9", dst="HUB"),
            ev(2, "BRUTE_FORCE", 1, src="9.9.9.9", dst="HUB"),
            ev(3, "C2_BEACON", 2, src="9.9.9.9", dst="HUB"),
        )]
        assert ENGINE._match_hub_hosts(rows) == []

    def test_q7_17_hub_keeps_only_first_hit_per_host(self):
        """【正向结论·设计意图】同一枢纽只保留优先级最高的一条链（break）。"""
        rows = [_Row(d) for d in (
            ev(1, "PORT_SCAN", 0, src="9.9.9.9", dst="HUB"),
            ev(2, "BRUTE_FORCE", 1, src="9.9.9.9", dst="HUB"),
            ev(3, "C2_BEACON", 2, src="9.9.9.9", dst="HUB"),
            ev(4, "DATA_EXFIL", 3, src="HUB", dst="8.8.8.8"),
        )]
        chains = ENGINE._match_hub_hosts(rows)
        assert len(chains) == 1
        assert chains[0].pattern_name.startswith("外部入侵→失陷外联")


# ══════════════════════════════════════════════════════════════
# Q8 · 关联的组合与去重
# ══════════════════════════════════════════════════════════════

class TestQ8Dedup:
    def test_q8_1_shared_events_are_marked_not_silently_duplicated(self):
        """[FIXED] 共享事件被**显式标注**，下游不会无声重复计数。

        修复前：`_dedup_chains` 用「完全包含」判定去重
        （`if event_ids - used_event_ids:`），只要有一条独有事件就整条保留。
        两条链共享 id=1 但各有独有事件 → 两条都保留，同一个事件 id
        出现在两条链里，下游会对它重复告警/重复计数，而且**报告里看不出来**。

        现在：不改成「重叠即丢」（那会误删两条真实的不同攻击链），
        而是把共享事件写进 `shared_event_ids` 并置
        `overlaps_other_chain=True`，让「不能按链累加」成为可读的事实。
        """
        a = match("port_scan_to_c2",
                  [ev(1, "PORT_SCAN", 0), ev(2, "BRUTE_FORCE", 1),
                   ev(3, "C2_BEACON", 2)])
        # b 与 a 共享 id=1（PORT_SCAN），其余事件各不相同；
        # LATERAL_MOVE 是 classic_killchain 显式声明可跳过的步骤
        b = match("classic_killchain",
                  [ev(1, "PORT_SCAN", 0), ev(6, "BRUTE_FORCE", 3),
                   ev(4, "C2_BEACON", 4), ev(5, "DATA_EXFIL", 5)])
        assert a is not None and b is not None
        kept = ENGINE._dedup_chains([a, b])
        assert len(kept) == 2, f"只剩 {len(kept)} 条 —— 独立的链被误删"
        ids = [e["id"] for c in kept for e in c.events]
        assert ids.count(1) == 2
        for c in kept:
            assert c.overlaps_other_chain is True
            assert c.shared_event_ids == [1], c.shared_event_ids

    def test_q8_1b_non_overlapping_chains_are_marked_clean(self):
        """[FIXED] 不重叠的链不会被误标成重叠。"""
        a = match("port_scan_to_c2",
                  [ev(1, "PORT_SCAN", 0), ev(2, "BRUTE_FORCE", 1),
                   ev(3, "C2_BEACON", 2)])
        b = match("port_scan_to_c2",
                  [ev(7, "PORT_SCAN", 40), ev(8, "BRUTE_FORCE", 41),
                   ev(9, "C2_BEACON", 42)])
        kept = ENGINE._dedup_chains([a, b])
        assert len(kept) == 2
        assert all(c.overlaps_other_chain is False for c in kept)
        assert all(c.shared_event_ids == [] for c in kept)

    def test_q8_2_full_subset_chain_is_dropped(self):
        """【正向结论】真子集的链会被丢掉。"""
        big = match("classic_killchain",
                    [ev(1, "PORT_SCAN", 0), ev(2, "BRUTE_FORCE", 1),
                     ev(3, "LATERAL_MOVE", 2), ev(4, "C2_BEACON", 3),
                     ev(5, "DATA_EXFIL", 4)])
        small = match("port_scan_to_c2",
                      [ev(1, "PORT_SCAN", 0), ev(2, "BRUTE_FORCE", 1),
                       ev(3, "C2_BEACON", 2)])
        assert len(small.events) < len(big.events)
        kept = ENGINE._dedup_chains([small, big])
        assert len(kept) == 1 and len(kept[0].events) == 5

    def test_q8_3_dedup_result_is_independent_of_input_order(self):
        """[FIXED] 去重结果与输入顺序无关（确定性排序）。

        修复前：只按 `len(events)` 排序，Python 稳定排序让并列项保持
        输入序；而输入序来自 `events_by_ip` 的遍历序 + 模式字典定义序，
        两者都不是「更完整/更严重优先」的显式规则 —— 同样的链集合换个
        输入顺序就得到不同的保留顺序。

        现在排序键是显式的：事件数多 → 完整链 → 置信度高 → chain_id。
        """
        def mk(ids):
            types = ["PORT_SCAN", "BRUTE_FORCE", "LATERAL_MOVE",
                     "C2_BEACON", "DATA_EXFIL"]
            return match("classic_killchain",
                         [ev(i, t, j) for j, (i, t) in enumerate(zip(ids, types))])

        c1 = mk([1, 2, 3, 4, 5])
        c2 = mk([1, 6, 7, 8, 9])
        first = ENGINE._dedup_chains([c1, c2])
        second = ENGINE._dedup_chains([c2, c1])
        ids_first = [sorted(e["id"] for e in c.events) for c in first]
        ids_second = [sorted(e["id"] for e in c.events) for c in second]
        assert ids_first == ids_second, \
            f"输入顺序仍然影响去重结果: {ids_first} vs {ids_second}"
        assert ids_first == [[1, 2, 3, 4, 5], [1, 6, 7, 8, 9]], ids_first
        # 不改调用方传进来的列表
        src = [c1, c2]
        ENGINE._dedup_chains(src)
        assert src == [c1, c2], "_dedup_chains 就地修改了调用方的列表"

    def test_q8_4_dropped_subset_is_recorded_via_shared_events(self):
        """[FIXED] 被丢弃的链与保留链共享事件 → 保留链上会标出来。

        a、b 各 5 条事件、共享 id=5 → 因「各有独有事件」双双保留；
        c 是 a 的真子集 → 被丢弃。修复前 id=5 同时归属两条保留链，
        下游若按链累加会重复计数，而且报告里**完全看不出来**。
        现在 `shared_event_ids` 把这件事写进结果。
        """
        a = match("classic_killchain",
                  [ev(1, "PORT_SCAN", 0), ev(2, "BRUTE_FORCE", 1),
                   ev(3, "LATERAL_MOVE", 2), ev(4, "C2_BEACON", 3),
                   ev(5, "DATA_EXFIL", 4)])
        b = match("classic_killchain",
                  [ev(5, "PORT_SCAN", 0), ev(6, "BRUTE_FORCE", 1),
                   ev(7, "LATERAL_MOVE", 2), ev(8, "C2_BEACON", 3),
                   ev(9, "DATA_EXFIL", 4)])
        c = match("port_scan_to_c2",
                  [ev(1, "PORT_SCAN", 0), ev(2, "BRUTE_FORCE", 1),
                   ev(3, "C2_BEACON", 2)])
        assert a is not None and b is not None and c is not None
        kept = ENGINE._dedup_chains([a, b, c])
        got = [sorted(e["id"] for e in ch.events) for ch in kept]
        assert got == [[1, 2, 3, 4, 5], [5, 6, 7, 8, 9]], \
            f"去重结果变了: {got}"
        # 事件 id=5 仍同时归属两条保留链 —— 现在必须被显式标注
        for ch in kept:
            assert ch.overlaps_other_chain is True
            assert ch.shared_event_ids == [5], ch.shared_event_ids

    def test_q8_5_empty_input(self):
        """【正向结论】空列表返回空列表。"""
        assert ENGINE._dedup_chains([]) == []
