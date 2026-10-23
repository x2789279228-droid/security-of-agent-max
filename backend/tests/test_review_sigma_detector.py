"""
Detection Engine Correctness Review —— 第一阶段：Sigma + Legacy 规则引擎

本文件是**审查证据**，不是修复测试。每个测试的 docstring 直接引用审查要求，
断言基于「实际执行结果」而非源码字符串。

审查要求来源：Q1 规则语义矩阵 / Q2 _ensure_table 并发 / Q3 reload 原子性 /
Q4 Legacy 兜底语义。
"""
import os
import sqlite3
import threading

import pytest

os.environ.setdefault("SHARED_MEMORY_SKIP_DOTENV", "1")

from sigma_engine.engine import PySigmaDetector  # noqa: E402

RULES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                         "sigma_engine", "rules")

SIGMA_KEYWORD_RULE = """
title: Review SQLi Keyword Probe
id: 11111111-0000-0000-0000-000000000001
status: experimental
description: review probe for keywords(value-only) semantics
logsource:
  category: webserver
detection:
  keywords:
    - "UNION SELECT"
  condition: keywords
level: high
"""

SIGMA_EXACT_RULE = """
title: Review Exact Field Probe
id: 11111111-0000-0000-0000-000000000002
status: experimental
description: review probe for exact field match
logsource:
  category: webserver
detection:
  selection:
    url|contains: "/admin/panel.php"
    event: WEB_ATTACK
  condition: selection
level: high
"""


def _mk_detector(tmp_path, rules: dict):
    """把给定 YAML 规则写进临时目录并编译成 PySigmaDetector。"""
    d = tmp_path / "rules"
    d.mkdir(parents=True, exist_ok=True)
    for name, text in rules.items():
        (d / f"{name}.yml").write_text(text, encoding="utf-8")
    return PySigmaDetector(str(d), enforce=True)


SIGMA_NUM_RULE = """
title: Review Numeric Keyword Probe
id: 11111111-0000-0000-0000-000000000003
status: experimental
description: review probe for numeric keywords semantics
logsource:
  category: webserver
detection:
  keywords:
    - 12
  condition: keywords
level: low
"""


class _NumCond:
    """最小 ConditionValueExpression 替身（只需 .value）。"""

    def __init__(self, value):
        self.value = value


def _sqlite_conn():
    """测试专用：与 detect() 相同形态的独立内存连接。"""
    return sqlite3.connect(":memory:")


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


# ══════════════════════════════════════════════════════════════
# Q1 · pySigma → SQL 的语义是否保持一致
# ══════════════════════════════════════════════════════════════

class TestQ1KeywordsSemantics:
    """Q1：审查重点是「转换后的 SQL 与原规则的匹配语义是否一致」，
    而不是「SQL 能否成功生成」。"""

    def test_q1_1_exact_match_hits(self, tmp_path):
        det = _mk_detector(tmp_path, {"kw": SIGMA_KEYWORD_RULE})
        hits = det.detect(_base_event(url="http://x/?q=1 UNION SELECT a,b FROM t"))
        assert [h.rule_id for h in hits], "完全匹配却未命中"

    def test_q1_2_case_variation(self, tmp_path):
        """大小写变化。SQLite LIKE 对 ASCII 默认不敏感，
        Sigma keywords 语义也是不敏感 —— 两侧应当一致。"""
        det = _mk_detector(tmp_path, {"kw": SIGMA_KEYWORD_RULE})
        hits = det.detect(_base_event(url="http://x/?q=1 union select a,b"))
        assert [h.rule_id for h in hits], \
            "大小写变化后未命中 —— 自定义 backend 改变了 Sigma 的大小写语义"

    def test_q1_3_partial_substring_hits(self, tmp_path):
        """只匹配其中一部分：Sigma keywords 是子串搜索，应当命中。"""
        det = _mk_detector(tmp_path, {"kw": SIGMA_KEYWORD_RULE})
        hits = det.detect(_base_event(url="http://x/?q=PRE UNION SELECT POST"))
        assert [h.rule_id for h in hits], "子串未命中"

    def test_q1_4_keyword_in_web_payload_fields_now_hits(self, tmp_path):
        """【已修复】关键字落在 Web 载荷字段上必须命中。

        修复前（P1-6）：自定义 backend 只对 6 个字段做 OR LIKE
        （url / cs-uri-query / message / details / http.url / event），
        关键字落在 `user_agent` / `request_body` 等字段时**必然漏报**。
        修复后：`KEYWORD_FIELDS` 覆盖 Web 日志常见载荷字段。
        """
        from sigma_engine.backend_keywords import KEYWORD_FIELDS

        det = _mk_detector(tmp_path, {"kw": SIGMA_KEYWORD_RULE})

        for field, value in (
            ("user_agent", "sqlmap/1.7 UNION SELECT probe"),
            ("request_body", "q=1 UNION SELECT a,b"),
            ("http.request.body", "x=1&y=UNION SELECT"),
            ("referer", "http://ref/?q=UNION SELECT"),
            ("cookie", "sid=1; k=UNION SELECT"),
        ):
            assert field in KEYWORD_FIELDS, f"{field} 未纳入关键词匹配字段"
            hits = det.detect(_base_event(**{field: value}))
            assert [h.rule_id for h in hits], \
                f"关键字落在 {field} 上仍然漏报（{value!r}）"

        # 对照：老字段仍然命中
        assert [h.rule_id for h in det.detect(
            _base_event(url="http://x/?q=UNION SELECT"))]

    def test_q1_4b_numeric_keyword_uses_numeric_semantics(self, tmp_path):
        """【已修复】数值 keywords 不得退化成字符串子串匹配。

        修复前：`convert_condition_val_num` 走 `_keyword_like_expr(str(v))`，
        「数值 12」会命中任何含字符 "2" 的文本（语义被静默改变）。
        """
        from sigma_engine.backend_keywords import SigmaKeywordsBackend

        be = SigmaKeywordsBackend()
        expr = be.convert_condition_val_num(_NumCond(12), None)
        assert "LIKE" not in expr.upper(), f"数值仍是子串匹配: {expr}"
        assert "CAST" in expr.upper(), expr
        assert "12" in expr

        det = _mk_detector(tmp_path, {"num": SIGMA_NUM_RULE})
        # 端口 12 → 命中
        assert [h.rule_id for h in det.detect(_base_event(src_port=12))]
        # 端口 123 ≠ 12（修复前会因含 "2" 而误命中）
        assert not det.detect(_base_event(src_port=123)), \
            "数值 12 误命中了 123 —— 仍是子串语义"
        # 端口 312 同理
        assert not det.detect(_base_event(src_port=312))

    def test_q1_5_sql_special_characters_are_data_not_structure(self, tmp_path):
        """含 SQL 特殊字符的值：必须作为**数据**处理，不能改变 SQL 结构。"""
        rule = SIGMA_KEYWORD_RULE.replace(
            '"UNION SELECT"', r'''"' OR '1'='1 UNION SELECT--"''')
        det = _mk_detector(tmp_path, {"kw": rule})
        assert det.rules(), "规则未编译成功"
        # 命中含引号/注释符的载荷 → 证明它被当数据处理
        hits = det.detect(_base_event(url="http://x/?q=' OR '1'='1 UNION SELECT--"))
        assert [h.rule_id for h in hits], "含单引号的载荷未被处理为数据"

        # 反向：不含该载荷的事件**不得**因为注入而被命中
        clean = det.detect(_base_event(url="http://x/?q=normal"))
        assert not [h for h in clean if h.rule_id.startswith("11111111")], \
            "不含关键字的事件被命中了 —— 特殊字符破坏了 SQL 结构"

    def test_q1_6_like_wildcards_in_value_are_escaped(self, tmp_path):
        """值本身含 % 或 _ 时必须被转义，否则 LIKE 会把它当通配符。"""
        rule = """
title: Review Wildcard Probe
id: 11111111-0000-0000-0000-000000000003
status: experimental
logsource:
  category: webserver
detection:
  keywords:
    - "50%_off"
  condition: keywords
level: high
"""
        det = _mk_detector(tmp_path, {"wc": rule})
        # 字面量 50%_off → 命中
        assert det.detect(_base_event(url="http://x/?p=50%_off")), \
            "字面量 50%_off 未命中"
        # 若未转义，"50XoYff" 会被 % 和 _ 当通配符误命中
        wrong = det.detect(_base_event(url="http://x/?p=50XoYff"))
        assert not [h for h in wrong if h.rule_id.endswith("0003")], \
            "未转义 LIKE 通配符 —— '50XoYff' 被误命中"

    def test_q1_7_missing_and_null_fields_do_not_falsely_hit(self, tmp_path):
        """字段缺失 / NULL / 空串：不得因 SQL 三值逻辑产生意外命中。"""
        det = _mk_detector(tmp_path, {"kw": SIGMA_KEYWORD_RULE})
        for ev in (
            _base_event(url=None),
            _base_event(url=""),
            {k: v for k, v in _base_event().items() if k != "url"},
        ):
            hits = det.detect(ev)
            assert not [h for h in hits if h.rule_id.startswith("11111111")], \
                f"字段缺失/NULL/空串导致意外命中: {ev!r}"

    def test_q1_8_exact_field_rule_matches_its_own_field_only(self, tmp_path):
        """对照组：普通字段精确匹配的语义没有被自定义 backend 改坏。"""
        det = _mk_detector(tmp_path, {"ex": SIGMA_EXACT_RULE})
        assert det.detect(_base_event(url="http://x/admin/panel.php?a=1")), \
            "精确字段规则未命中"

    def test_q1_9_unsupported_syntax_is_reported_not_silently_approximated(self, tmp_path):
        """【已修复】不支持的规则语法必须**明确报告**，不能静默编译成近似规则。

        修复前：`stats()` 返回 7 个字段里没有任何 skipped / load_errors，
        「哪些规则没加载上」完全不可知。
        修复后（提交 C）：`stats()` 暴露 `load_errors` / `skipped_rules` /
        `compiled_count` / `run_mode`，坏 YAML 逐条留痕。
        """
        det = _mk_detector(tmp_path, {
            "ok": SIGMA_KEYWORD_RULE,
            "bad": "title: [unclosed\n  detection: {{{\n",
        })
        ids = {r["rule_id"] for r in det.rules()}
        assert len(ids) == 1, f"坏 YAML 未被隔离，加载结果异常: {ids}"
        st = det.stats()
        assert "load_errors" in st and "skipped_rules" in st, \
            f"stats 未暴露加载诊断: {sorted(st)}"
        assert st["compiled_count"] == 1, st
        # ⚠ 更正（§9.40）：这一行原先断言 `run_mode == "normal"` ——
        # 而**同一个 st 里** `load_errors` 记着「一个规则文件没加载上」。
        # 整改方案 §六.2：normal = 「pySigma 规则按预期加载和运行」；
        # degraded = 「**或部分规则未加载**」。
        # 「1 好 1 坏」就是部分规则未加载 → 必须是 degraded。
        #
        # 这是**更正 + 加强**，不是放宽：两条断言在「有坏规则」这个场景下互斥，
        # 改完之后能通过的实现更少、要求更高。
        assert st["run_mode"] == "degraded", st
        assert st["degraded_reasons"], st
        assert len(st["load_errors"]) == 1, st["load_errors"]
        err = st["load_errors"][0]
        assert err["phase"] == "parse" and err["file"] == "bad.yml", err
        assert err["error_code"].endswith(":parse"), err

    def test_q1_10_field_name_injection_is_escaped(self, tmp_path):
        """【已修复】字段名含引号不得拼坏 DDL。

        修复前：`CREATE TABLE "evil"col" TEXT` 是语法错误，DROP 那步有
        try/except 兜着、CREATE 那步没有 → sqlite3.OperationalError 未受控
        冒出 detect()。
        修复后：标识符统一经 `_quote_ident()` 转义内部引号。
        """
        ev = _base_event()
        ev['evil"col'] = "x"
        det = _mk_detector(tmp_path, {"kw": SIGMA_KEYWORD_RULE})
        # 不再抛异常；该事件只是不命中关键词规则
        hits = det.detect(ev)
        assert isinstance(hits, list)
        assert det._quote_ident('a"b') == '"a""b"'
        # 引号字段不得影响正常事件检测
        assert det.detect(_base_event(url="http://x/?q=UNION SELECT")), \
            "转义后正常事件反而检测不到了"

    def test_q1_11_rule_id_is_stable_and_position_independent(self, tmp_path):
        """【已修复】规则 ID 必须与文件顺序无关。

        修复前：`getattr(getattr(sigmarule,"id",None),"value",None)` 在
        pySigma 1.5 里恒为 None（`sigmarule.id` 是 `uuid.UUID`，没有 `.value`），
        回退到**位置序号** `SIG-nnn` → YAML 增删/重排会让规则重新编号，
        而 ID 会进 Kafka 载荷 / list_rules() / detect_batch 的 hits。
        修复后：x-soc-id → Sigma 稳定 id → 内容指纹，顺序无关。
        """
        det = _mk_detector(tmp_path, {"kw": SIGMA_KEYWORD_RULE})
        before = [r["rule_id"] for r in det.rules()]
        assert before == ["11111111-0000-0000-0000-000000000001"], \
            f"规则 ID 来源变了: {before}"
        assert not any(rid.startswith("SIG-0") for rid in before), \
            f"仍在使用位置序号: {before}"

        # 在前面插入一个文件，**已有规则的 ID 不得改变**
        (tmp_path / "rules" / "0_new.yml").write_text(
            SIGMA_KEYWORD_RULE.replace("Probe", "New")
                   .replace("0001", "0007"), encoding="utf-8")
        det.reload()
        after = [r["rule_id"] for r in det.rules()]
        assert "11111111-0000-0000-0000-000000000001" in after, \
            f"插入文件后原规则 ID 变了: {after}"
        assert len(after) == 2, after

    def test_q1_12_rule_id_falls_back_to_content_fingerprint(self, tmp_path):
        """【已修复】既无 x-soc-id 也无 Sigma id 时用内容指纹，不退回位置序号。

        Sigma `id` 是必填字段，因此构造方式：把 yml 的 id 去掉后由
        pySigma 解析 → 若无 id 则引擎用 title+detection 的 sha1 指纹。
        这里直接测 `_stable_rule_id` 的三层优先级。
        """
        class _NoId:
            title = "Fingerprint Probe"
            detection = {"keywords": ["X"], "condition": "keywords"}

        rid = PySigmaDetector._stable_rule_id(_NoId())
        assert rid.startswith("SIG-") and not rid.startswith("SIG-0"), rid
        # 同内容 → 同 ID
        assert PySigmaDetector._stable_rule_id(_NoId()) == rid

        class _Other:
            title = "Different"
            detection = {"keywords": ["Y"], "condition": "keywords"}
        assert PySigmaDetector._stable_rule_id(_Other()) != rid


# ══════════════════════════════════════════════════════════════
# Q2 · _ensure_table 的 DROP → CREATE 并发安全
# ══════════════════════════════════════════════════════════════

class TestQ2ConcurrentTableIsolation:
    """Q2：确认表名是否固定、是否独立连接、是否在同一事务边界、
    是否有明确并发保护。"""

    def test_q2_1_each_detection_uses_a_private_database(self, tmp_path):
        """【已修复】每次检测用独占的内存连接，事件之间零共享状态。

        修复前：所有事件共用 `self._conn` 上的一张固定名 `events` 表。
        """
        import sqlite3 as _s3

        det = _mk_detector(tmp_path, {"kw": SIGMA_KEYWORD_RULE})
        det.detect(_base_event(url="http://x/a"))
        assert det.TABLE
        # 快照连接存在但不承载事件数据；事件表建在每次 detect 自建的连接上
        seen = []
        orig = PySigmaDetector._ensure_table

        def _spy(self, cols, ev, conn=None):
            seen.append(conn)
            return orig(self, cols, ev, conn=conn)

        PySigmaDetector._ensure_table = _spy
        try:
            det.detect(_base_event(url="http://x/a"))
            det.detect(_base_event(url="http://x/b"))
        finally:
            PySigmaDetector._ensure_table = orig
        assert len(seen) == 2
        assert seen[0] is not None and seen[1] is not None
        assert seen[0] is not seen[1], "两次检测仍共用同一连接"

    def test_q2_2_interleaved_events_do_not_cross_contaminate(self, tmp_path):
        """【已修复】交错写入不再互相抹除。

        修复前：A 写入 → B DROP 重建共享表 → A 查询 → A 丢失命中。
        现在每次检测在自己的库里，DROP 只影响自己。
        """
        rule_a = SIGMA_KEYWORD_RULE.replace("UNION SELECT", "SECRETALPHA")
        rule_b = SIGMA_KEYWORD_RULE.replace("UNION SELECT", "SECRETBETA").replace("0001", "0002")
        det = _mk_detector(tmp_path, {"a": rule_a, "b": rule_b})

        ev_a = _base_event(url="http://x/?q=SECRETALPHA")
        ev_b = _base_event(url="http://x/?q=SECRETBETA")

        solo_a = {h.rule_id for h in det.detect(ev_a)}
        solo_b = {h.rule_id for h in det.detect(ev_b)}
        assert solo_a and solo_b, "前置失效：单跑就没命中"
        assert solo_a != solo_b

        # 确定性交错：A 建表 → B 建表 → 再跑 A 的查询（用 A 自己的连接语义）
        from sigma_engine.mapping import apply_mapping
        ea, eb = apply_mapping(ev_a), apply_mapping(ev_b)
        conn_a = _sqlite_conn()
        conn_b = _sqlite_conn()
        try:
            det._ensure_table(list(ea.keys()), ea, conn=conn_a)
            det._ensure_table(list(eb.keys()), eb, conn=conn_b)
            sql = [s for m, s in det._compiled if "SECRETALPHA" in s][0]
            hit_a_after_interleave = conn_a.execute(sql).fetchone() is not None
            assert hit_a_after_interleave is True, \
                "交错后 A 丢失命中 —— 隔离已失效，请更新结论"
        finally:
            conn_a.close()
            conn_b.close()

        # 端到端：反复交替检测，结果稳定
        for _ in range(20):
            assert {h.rule_id for h in det.detect(ev_a)} == solo_a
            assert {h.rule_id for h in det.detect(ev_b)} == solo_b

    @staticmethod
    def _detection_path_source():
        """收齐**整条检测执行路径**的源码（从 detect 出发沿 self.xxx() 调用展开）。

        为什么不能只看 `detect()` 自己的源码：原守卫用
        `inspect.getsource(PySigmaDetector.detect)` 找 `sqlite3.connect`。
        2026-10-19 修「规则执行错误通道并发串扰」时，`detect()` 被拆成
        「薄封装 + `_detect_with_errors()`」，建连接随之搬进辅助方法，
        守卫立刻变红 —— 但**性质并没有变**：每次检测仍然自建独立连接、
        路径上仍然没有全局锁。那是**判据失配**（守卫只覆盖了某一种写法），
        不是性质被破坏；按「为变绿而放宽安全要求」处理是不对的。

        改法：沿 `self.xxx(...)` 调用把整条路径的源码收齐再判。
        重构搬家不会误报，而「加了全局锁」「不再自建连接」这类真回归仍会红。
        """
        import inspect
        import re

        seen = set()
        chunks = []
        stack = [("detect", PySigmaDetector.detect)]
        while stack:
            name, fn = stack.pop()
            if name in seen:
                continue
            seen.add(name)
            try:
                src = inspect.getsource(fn)
            except (OSError, TypeError):
                continue
            chunks.append(src)
            for callee in set(re.findall(r"self\.([A-Za-z_]\w*)\s*\(", src)):
                if callee in seen:
                    continue
                attr = getattr(PySigmaDetector, callee, None)
                if attr is None or not callable(attr):
                    continue
                stack.append((callee, attr))
        return "\n".join(chunks)

    def test_q2_3_detection_needs_no_global_lock(self, tmp_path):
        """【正向结论·整改后】并发安全靠「每次检测独立执行上下文」，
        而不是给整条检测路径加全局锁（整改方案 §六 明确不推荐全局锁）。

        判据覆盖的是**整条检测执行路径**（见 `_detection_path_source`
        的说明：只看 `detect()` 会因重构搬家而误报）。
        """
        src = self._detection_path_source()
        assert src, "前提守卫：没能取到检测执行路径的源码"
        assert "self._lock" not in src, \
            "检测路径上又用回全局锁了 —— 整改方案 §六 要求用隔离而非串行化"
        assert "sqlite3.connect" in src, \
            "检测路径不再自建连接 —— 隔离已失效，请更新结论"

    def test_q2_4_threaded_parallel_detection_is_isolated(self, tmp_path):
        """【已修复】真实线程并发：两条不同事件同时检测，结果互不干扰。

        修复前：共享连接是线程亲和的，跨线程调用在 `_ensure_table` 抛
        `sqlite3.ProgrammingError: SQLite objects created in a thread can only
        be used in that same thread`，且该步无 try 兜底 → 异常外泄。
        """
        rule_a = SIGMA_KEYWORD_RULE.replace("UNION SELECT", "THREADALPHA")
        rule_b = SIGMA_KEYWORD_RULE.replace("UNION SELECT", "THREADBETA").replace("0001", "0002")
        det = _mk_detector(tmp_path, {"a": rule_a, "b": rule_b})

        ev_a = _base_event(url="http://x/?q=THREADALPHA")
        ev_b = _base_event(url="http://x/?q=THREADBETA")

        solo_a = det.detect(ev_a)
        solo_b = det.detect(ev_b)
        assert solo_a and solo_b, "前置失效：单跑就没命中"
        ids_a = {h.rule_id for h in solo_a}
        ids_b = {h.rule_id for h in solo_b}
        assert ids_a != ids_b, "前置失效：两条事件命中规则无法区分"

        wrong = []
        barrier = threading.Barrier(2)
        rounds = 30

        def run(ev, expect):
            barrier.wait()
            for _ in range(rounds):
                got = {h.rule_id for h in det.detect(ev)}
                if got != expect:
                    wrong.append((sorted(expect), sorted(got)))
                    return

        ta = threading.Thread(target=run, args=(ev_a, ids_a))
        tb = threading.Thread(target=run, args=(ev_b, ids_b))
        ta.start()
        tb.start()
        ta.join(timeout=30)
        tb.join(timeout=30)

        assert not wrong, (
            f"线程并发下检测结果串扰: {wrong[0]}（期望 {wrong[0][0]} 实得 {wrong[0][1]}）"
        )

    def test_q2_5_repeated_detection_is_stable(self, tmp_path):
        """同一事件连续执行两次，结果必须稳定（审查要求「稳定复现」）。"""
        det = _mk_detector(tmp_path, {"kw": SIGMA_KEYWORD_RULE})
        ev = _base_event(url="http://x/?q=UNION SELECT")
        first = {h.rule_id for h in det.detect(ev)}
        for _ in range(10):
            again = {h.rule_id for h in det.detect(ev)}
            assert again == first, f"同一事件重复检测结果漂移: {first} → {again}"

    def test_q2_6_hit_then_miss_does_not_keep_hitting(self, tmp_path):
        """先检测命中事件，再检测不命中事件 —— 不得因旧数据残留继续命中。"""
        det = _mk_detector(tmp_path, {"kw": SIGMA_KEYWORD_RULE})
        assert det.detect(_base_event(url="http://x/?q=UNION SELECT"))
        assert not det.detect(_base_event(url="http://x/?q=benign")), \
            "DROP→CREATE 未清掉历史行：不命中事件被误命中"


# ══════════════════════════════════════════════════════════════
# Q3 · reload() 的原子性
# ══════════════════════════════════════════════════════════════

class TestQ3ReloadAtomicity:
    def test_q3_1_good_reload_switches_completely(self, tmp_path):
        """【已修复】成功 reload 后规则集完全切换，且 ID 与位置无关。"""
        det = _mk_detector(tmp_path, {"kw": SIGMA_KEYWORD_RULE})
        before = {r["rule_id"] for r in det.rules()}
        assert before == {"11111111-0000-0000-0000-000000000001"}, \
            f"前置失效: {before}"
        (tmp_path / "rules" / "kw2.yml").write_text(
            SIGMA_KEYWORD_RULE.replace("Probe", "Second")
                   .replace("0001", "0009"), encoding="utf-8")
        det.reload()
        after = {r["rule_id"] for r in det.rules()}
        assert after == {"11111111-0000-0000-0000-000000000001",
                         "11111111-0000-0000-0000-000000000009"}, \
            f"reload 后规则集异常: {after}"

    def test_q3_2_bad_yaml_keeps_old_rules(self, tmp_path):
        """【正向结论】坏 YAML 不清空旧规则，且现在会记录加载错误。"""
        det = _mk_detector(tmp_path, {"kw": SIGMA_KEYWORD_RULE})
        before = {r["rule_id"] for r in det.rules()}
        (tmp_path / "rules" / "broken.yml").write_text(
            "title: [unclosed\n  detection: {{{\n", encoding="utf-8")
        n = det.reload()
        after = {r["rule_id"] for r in det.rules()}
        assert after == before, "坏 YAML 导致旧规则被清空"
        assert n == len(after)
        assert len(det.stats()["load_errors"]) == 1, det.stats()["load_errors"]

    def test_q3_3_detect_during_reload_is_safe(self, tmp_path):
        """【已修复】热更新不再关闭可能仍在被使用的连接。

        修复前：`reload()` 立刻 `old_conn.close()`，并发 detect 仍持有
        旧连接时抛 `sqlite3.ProgrammingError: Cannot operate on a closed
        database`，且会被 `except Exception: hit = False` 吞成「未命中」
        → 并发热更新可静默丢检测。
        修复后：旧连接延迟一代释放。
        """
        det = _mk_detector(tmp_path, {"kw": SIGMA_KEYWORD_RULE})
        ev = _base_event(url="http://x/?q=UNION SELECT")
        assert det.detect(ev), "前置失效"

        old_conn = det._conn
        det.reload()
        # 一次 reload 后旧连接仍可用（在途检测可以完成）
        old_conn.execute("SELECT 1").fetchone()
        # 第二次 reload 后上一代才被回收
        det.reload()
        det.reload()
        assert old_conn is not det._conn
        # 检测结果不受影响
        assert {h.rule_id for h in det.detect(ev)} == {
            "11111111-0000-0000-0000-000000000001"}

    def test_q3_4_reload_is_lock_protected(self, tmp_path):
        """【已修复】快照替换在锁内完成。"""
        import inspect

        src = inspect.getsource(PySigmaDetector.reload)
        assert "self._lock" in src, "reload 未加锁 —— 请更新结论"
        snap_src = inspect.getsource(PySigmaDetector._publish_snapshot)
        assert "self._lock" not in snap_src, \
            "指针替换不应在 _publish_snapshot 内部再加锁"

    def test_q3_5_failed_compile_is_isolated_and_reported(self, tmp_path):
        """【已修复】全部规则编译失败 → 引擎降级状态可见。"""
        det = _mk_detector(tmp_path, {"kw": SIGMA_KEYWORD_RULE})
        # 全部规则文件都变成不可解析
        for f in (tmp_path / "rules").glob("*.yml"):
            f.write_text("::: not yaml :::\n\t- [", encoding="utf-8")
        det.reload()
        assert len(det._compiled) == 0, "坏 YAML 未被隔离"
        st = det.stats()
        assert st["compiled_count"] == 0
        assert st["load_errors"], "编译全失败却没有加载诊断"
        assert st["run_mode"] in ("degraded", "unavailable"), st["run_mode"]
        # 引擎必须明确报不可用，而不是返回普通阴性
        r = det.detect_for_event(_base_event(url="http://x/?q=UNION SELECT"))
        assert r["status"] in ("error", "partial"), r["status"]


# ══════════════════════════════════════════════════════════════
# Q4 · Legacy 兜底是否悄悄改变了检测语义
# ══════════════════════════════════════════════════════════════

class TestQ4LegacyFallback:
    def test_q4_1_legacy_triggers_only_when_no_rules_compiled(self, tmp_path):
        """【正向结论】Legacy 只在无规则编译成功时触发（整改后仍成立）。"""
        det = _mk_detector(tmp_path, {"kw": SIGMA_KEYWORD_RULE})
        assert len(det._compiled) == 1, "前置失效"
        det.detect(_base_event(url="http://x/?q=UNION SELECT"))

        empty = PySigmaDetector(str(tmp_path / "nothing"), enforce=False)
        assert len(empty._compiled) == 0
        # 无规则时 stats 明确报 unavailable 而不是伪装 normal
        assert empty.stats()["run_mode"] == "unavailable"
        assert empty.detect(_base_event(url="http://x/?q=UNION SELECT")) is not None

    def test_q4_2_per_rule_sql_error_is_reported_as_partial(self, tmp_path):
        """【已修复】单条规则 SQL 执行失败必须被上报为 partial。

        修复前：`except Exception: hit = False` —— 引擎故障被记成「未命中」，
        与「规则不匹配」返回值完全相同，整轮被当成完整阴性收口。
        """
        det = _mk_detector(tmp_path, {"kw": SIGMA_KEYWORD_RULE})
        meta = det._compiled[0][0]
        # 换成必然报错的 SQL（表不存在）
        object.__setattr__(det._snapshot, "compiled",
                           ((meta, "SELECT * FROM no_such_table_xyz"),))
        r = det.detect_for_event(_base_event(url="http://x/?q=UNION SELECT"))
        assert r["detected"] is False
        assert r["status"] == "partial", r["status"]
        assert r["rules_failed"] == 1, r
        assert r["status_errors"][0]["rule_id"] == meta["rule_id"]
        assert r["error_code"].startswith("rule_exec_failed:")
        assert r["error_message"]

    def test_q4_3_partial_rule_failure_survives_alongside_hits(self, tmp_path):
        """【已修复】一条规则挂掉 + 另一条命中 → 整体 partial，但保留正向证据。"""
        rule_a = SIGMA_KEYWORD_RULE.replace("UNION SELECT", "GOODALPHA")
        rule_b = SIGMA_KEYWORD_RULE.replace("UNION SELECT", "BROKENBETA") \
                                    .replace("Probe", "Broken")
        det = _mk_detector(tmp_path, {"a": rule_a, "b": rule_b})
        assert len(det._compiled) == 2
        good_meta = [m for m, _ in det._compiled if "GOODALPHA" in _][0]

        from detection_contract import combine_status
        assert combine_status(["partial", "detected"]) == "partial"

        det._snapshot = type(det._snapshot)(
            compiled=((good_meta, "SELECT * FROM no_such_table_xyz"),),
            rules=det._snapshot.rules,
            field_index=det._snapshot.field_index,
            conn=det._snapshot.conn,
            generation=det._snapshot.generation,
        )
        r = det.detect_for_event(_base_event(url="http://x/?q=GOODALPHA"))
        assert r["status"] == "partial", r["status"]
        assert r["rules_failed"] == 1

    def test_q4_4_detect_for_event_carries_contract_fields(self, tmp_path):
        """【已修复】融合载荷携带契约字段。"""
        det = _mk_detector(tmp_path, {"kw": SIGMA_KEYWORD_RULE})
        r = det.detect_for_event(_base_event(url="http://x/?q=UNION SELECT"))
        for field in ("status", "error_code", "error_message",
                      "rules_evaluated", "rules_failed"):
            assert field in r, f"缺少契约字段 {field}: {sorted(r)}"
        assert r["status"] == "detected"
        assert r["rules_evaluated"] == 1 and r["rules_failed"] == 0

    def test_q4_5_no_hit_returns_explicit_negative(self, tmp_path):
        """【已修复】无命中必须显式标记 not_detected，而不是只有 detected=False。"""
        det = _mk_detector(tmp_path, {"kw": SIGMA_KEYWORD_RULE})
        out = det.detect_for_event(_base_event(url="http://x/?q=benign"))
        assert out["detected"] is False
        assert out["status"] == "not_detected", out["status"]
        assert out["rules_failed"] == 0
# ══════════════════════════════════════════════════════════════
# Q5 · 规则执行错误的「通道」必须与本轮检测绑定
# ══════════════════════════════════════════════════════════════

class TestQ5RuleErrorChannelIsolation:
    """Q5：单条规则执行失败的上报，会不会串到别的检测轮次去。

    整改方案 §六 的两条验收标准同时约束这里：

      · 「单条规则 SQL 执行失败被当作 hit=False → 单独记录规则执行错误，
         整轮标记为 partial 或 error，不能返回完整阴性」
      · 「并发不同事件时，检测结果相互独立」

    修复前两者是**互相打架**的：错误走实例属性 `self._last_rule_errors`
    传递（`detect()` 写、`_detect_for_event_inner()` 读，是两次独立调用），
    而该属性是跨线程共享的。
    """

    @staticmethod
    def _hook_sqlite(monkeypatch, entered, release, order):
        """把 engine 模块内的 sqlite3.connect 换成带阻塞钩子的版本。

        编排点故意选在 **SQL 执行层**（自定义 SQLite 函数），
        而不是 `detect()` / `_detect_with_errors` 这类内部方法名：
        新旧实现都必经 SQL 执行，所以同一支测试能同时判定
        「旧行为红 / 新行为绿」，可用于注入验红。
        插桩若落在内部方法名上，换个实现就失效 —— 那种守卫测不出回归。
        """
        import sigma_engine.engine as engine_mod

        real_module = sqlite3

        def _probe_block():
            if not order:          # 只在第一次调用时阻塞
                order.append("block")
                entered.set()
                release.wait(timeout=15)
            return 0

        class _Shim:
            def __init__(self, real):
                self._real = real

            def connect(self, *a, **k):
                conn = self._real.connect(*a, **k)
                conn.create_function("probe_block", 0, _probe_block)
                return conn

            def __getattr__(self, name):
                return getattr(self._real, name)

        monkeypatch.setattr(engine_mod, "sqlite3", _Shim(real_module))

    @staticmethod
    def _force_compiled(det, compiled):
        """把检测器的已编译规则换成给定内容（快照 + 兼容属性一起换）。"""
        det._snapshot = type(det._snapshot)(
            compiled=tuple(compiled),
            rules=det._snapshot.rules,
            field_index=det._snapshot.field_index,
            conn=det._snapshot.conn,
            generation=det._snapshot.generation,
        )
        det._compiled = list(compiled)

    def test_q5_1_concurrent_detection_does_not_swallow_a_rule_failure(
            self, tmp_path, monkeypatch):
        """【已修复】并发检测不得把另一轮的规则失败洗成完整阴性。

        修复前（2026-10-19 实测复现）：线程 A 记下自己的规则失败后，
        还未来得及读取，线程 B 的 detect() 就把 `self._last_rule_errors`
        重置成新列表 —— A 的错误被整体丢弃：

            A: status=not_detected  rules_evaluated=1  rules_failed=0
            B: status=detected      rules_evaluated=1  rules_failed=0

        即 §六 点名的 P0 缺陷「规则失败被当作完整阴性」在并发下复活。
        """
        det = _mk_detector(tmp_path, {"kw": SIGMA_KEYWORD_RULE})
        assert det._rules, "前提守卫：临时规则目录必须至少加载一条规则"
        assert det._compiled, "前提守卫：必须至少编译出一条规则"

        meta = dict(det._compiled[0][0])
        # 规则1：事件表没有 probe_missing 列时**真实报错**
        # 规则2：首次调用阻塞，把线程 A 钉在检测过程中间
        self._force_compiled(det, [
            (meta, "SELECT probe_missing FROM events"),
            (meta, "SELECT probe_block()"),
        ])

        entered = threading.Event()
        release = threading.Event()
        order = []
        self._hook_sqlite(monkeypatch, entered, release, order)

        results = {}

        def _run_a():
            # 事件里**没有** probe_missing 列 → 规则1 执行失败
            results["A"] = det.detect_for_event(_base_event(url="http://x/a"))

        def _run_b():
            # 事件里**有** probe_missing 列 → 同一条规则正常执行，不产生错误
            results["B"] = det.detect_for_event(
                _base_event(url="http://x/b", probe_missing="1"))

        ta = threading.Thread(target=_run_a, name="sigma-A")
        ta.start()
        assert entered.wait(timeout=15), "前提失效：线程 A 未进入阻塞点"

        _run_b()                        # B 抢在 A 读取错误之前完成
        order.append("B-done")
        release.set()
        ta.join(timeout=15)
        assert not ta.is_alive(), "前提失效：线程 A 未结束"

        # 前提守卫：编排真的发生了 —— B 是在 A 被钉住期间完成的
        assert order == ["block", "B-done"], order

        a = results["A"]
        assert a["rules_failed"] == 1, (
            "线程 A 的单条规则执行失败被并发检测吞掉：%r" % a)
        assert a["status"] == "partial", a["status"]
        assert a["status_errors"], a
        assert a["status_errors"][0]["rule_id"] == meta["rule_id"]
        assert a["error_code"].startswith("rule_exec_failed:"), a["error_code"]

        b = results["B"]
        assert b["rules_failed"] == 0, (
            "线程 B 被线程 A 的错误污染：%r" % b)

    def test_q5_2_stale_rule_errors_do_not_leak_into_the_next_detection(
            self, tmp_path):
        """【已修复】上一轮的错误不得被下一轮原样继承。

        修复前 `self._last_rule_errors` 只在 `detect()` 的 try 块内重置，
        两条早退路径（无已编译规则 / 事件没有任何字段）绕过了重置 ——
        上一轮的规则失败会被下一轮继承，于是 B 轮报出一条**它自己从未
        执行过**的规则失败，§二 要求的「在哪个阶段失败」被记错。
        """
        det = _mk_detector(tmp_path, {"kw": SIGMA_KEYWORD_RULE})
        assert det._rules, "前提守卫：临时规则目录必须至少加载一条规则"
        meta = dict(det._compiled[0][0])
        self._force_compiled(det, [(meta, "SELECT probe_missing FROM events")])

        # 第 1 轮：规则执行失败（事件没有 probe_missing 列）
        first = det.detect_for_event(_base_event(url="http://x/a"))
        assert first["rules_failed"] == 1, first
        assert first["status"] == "partial", first["status"]

        # 第 2 轮：空事件 → 一个字段都没有 → 早退，一条规则都没执行
        second = det.detect_for_event({})
        assert second["rules_failed"] == 0, (
            "上一轮的规则失败泄漏到了本轮（本次一条规则都没执行）：%r" % second)
        assert second["status_errors"] == [], second["status_errors"]
        assert second["status"] == "not_detected", second["status"]
# ══════════════════════════════════════════════════════════════
# Q6 · DDL 字段名的标识符转义（整改方案 §六）
# ══════════════════════════════════════════════════════════════

class TestQ6IdentifierQuoting:
    """恶意字段名不得破坏建表，异常也不得无保护地泄漏。

    整改方案 §六 的验收标准：
      「DDL 字段名直接通过 f-string 拼接 → 优先将外部字段映射成可信的内部列名；
        否则严格校验和引用 SQL 标识符，值继续采用参数绑定」
      验收：「**恶意字段名不能破坏建表**，异常不会无保护地泄漏到 API」

    修复前 `coldef = ", ".join(f'"{c}" TEXT' ...)` 直接拼接字段名，
    字段名含双引号时生成 `CREATE TABLE "evil"col" TEXT` → sqlite 语法错误，
    而那一步没有 try 兜底 → 异常裸奔出 `detect()`。

    这一组性质的**核心**已由 `test_q1_10_field_name_injection_is_escaped` 覆盖
    （不抛异常 + `_quote_ident` 转义 + 不影响正常检测）。
    本组补的是**另外四条更细的、此前没有回归**的性质：
      ① 列名必须**原样保留**（被正确转义，而不是被截断或改写）；
      ② 注入串**惰性** —— 不得凭空多出列、表也不得被删；
      ③ 值**仍走参数绑定** —— 值里的引号不得影响 schema 或数据；
      ④ 建表真失败时，异常必须被包成带 `sigma_exec_schema_invalid` 的
         RuntimeError，而不是裸的 `sqlite3.OperationalError` 泄漏出去。

    > 记一次**测量错误**：写这一节时我曾断言「全仓 `tests/` 搜 `_quote_ident`
    > → 零命中」，据此写下「此前没有任何回归」——
    > 而实际上 `test_q1_10` 早就覆盖了核心。错因是**检索输出被 100 条上限
    > 截断**，后面的行没看见，于是把「有覆盖」误判成「零命中」。
    > 改成逐行计数扫描后才真相大白。**「零命中」这种否定结论，
    > 必须用不会被截断的扫描来下。**
    """

    MALICIOUS = (
        'evil"col',
        'x"; DROP TABLE events; --',
        'a"b"c',
        'col" , "injected" TEXT, "x',
        '"; DELETE FROM events; --',
    )

    def _detector(self):
        det = PySigmaDetector(rules_dir=str(RULES_DIR))
        assert det._rules, "前提守卫：规则目录必须有规则"
        return det

    def test_malicious_field_name_does_not_break_detection(self):
        """【已修复】恶意字段名不得让整条检测路径抛异常。"""
        det = self._detector()
        for name in self.MALICIOUS:
            ev = _base_event(url="http://x/a")
            ev[name] = "payload-value"
            try:
                hits = det.detect(ev)
            except Exception as e:      # noqa: BLE001 - 这里就是要抓住任何异常
                raise AssertionError(
                    f"字段名 {name!r} 让检测路径抛异常 "
                    f"{type(e).__name__}: {e}") from e
            assert isinstance(hits, list)

    def test_malicious_field_name_is_preserved_verbatim(self):
        """【已修复】列名必须**原样保留**（被正确转义，而不是被截断或改写）。"""
        det = self._detector()
        conn = sqlite3.connect(":memory:")
        try:
            det._ensure_table(list(self.MALICIOUS),
                              {k: "v" for k in self.MALICIOUS}, conn=conn)
            cols = [r[1] for r in conn.execute("PRAGMA table_info(events)").fetchall()]
        finally:
            conn.close()
        for name in self.MALICIOUS:
            assert name in cols, f"列名被改写或丢失：{name!r}（实际 {cols}）"

    def test_injection_string_is_inert(self):
        """【已修复】注入串不得生效：不得凭空多出列，表也不得被删。"""
        det = self._detector()
        conn = sqlite3.connect(":memory:")
        try:
            det._ensure_table(list(self.MALICIOUS),
                              {k: "v" for k in self.MALICIOUS}, conn=conn)
            cols = [r[1] for r in conn.execute("PRAGMA table_info(events)").fetchall()]
            assert "injected" not in cols, (
                f"注入串生效了 —— 多出了名为 injected 的列：{cols}")
            rows = conn.execute("SELECT count(*) FROM events").fetchone()[0]
            assert rows == 1, f"events 表行数 {rows}（期望 1）"
        finally:
            conn.close()

    def test_values_still_go_through_parameter_binding(self):
        """【已修复】值继续走参数绑定：值里的引号不得影响 schema 或数据。

        注意：`_ensure_table` 总会**额外**预建一批标准字段（body / bytes /
        cookie …），所以表里的列远多于事件自带的那些 ——
        断言的是「事件自带的列名**原样**在表里」「行数正确」「值原样存回」，
        而不是「表里只有这些列」。
        """
        det = self._detector()
        payload = 'va"lue\'; DROP TABLE events; --'
        ev = _base_event(url="http://x/a")
        ev['weird"col'] = payload
        det.detect(ev)
        conn = sqlite3.connect(":memory:")
        try:
            det._ensure_table(['weird"col'], {'weird"col': payload}, conn=conn)
            cols = [r[1] for r in conn.execute("PRAGMA table_info(events)").fetchall()]
            assert 'weird"col' in cols, cols
            got = conn.execute("SELECT count(*) FROM events").fetchone()[0]
            assert got == 1, got
            stored = conn.execute('SELECT "weird""col" FROM events').fetchone()[0]
            assert stored == payload, stored
        finally:
            conn.close()

    def test_schema_failure_is_wrapped_not_leaked(self, monkeypatch):
        """【已修复】建表真失败时，异常必须被包成带错误码的 RuntimeError。

        「异常不会无保护地泄漏到 API」—— 裸的 sqlite3.OperationalError
        不该直接冒到调用方。
        """
        det = self._detector()
        monkeypatch.setattr(
            PySigmaDetector, "_quote_ident",
            staticmethod(lambda name: '"' + str(name) + '"'),   # 退回修复前：不转义
        )
        with pytest.raises(RuntimeError) as ei:
            det.detect(_base_event(url="http://x/a", **{'evil"col': "v"}))
        assert "sigma_exec_schema_invalid" in str(ei.value), str(ei.value)
