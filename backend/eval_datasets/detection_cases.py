"""
检测引擎量化评估的标定集（整改方案 §十三「量化评估」维度）。

与 :mod:`eval_datasets.behavior_cases` / :mod:`eval_datasets.grounding_cases`
同构：``<domain>_cases.py`` 只放**标注**，判定逻辑一律在
``evaluate_detection.py`` 里调用**真检测器**执行。

## 与前两套标定集的关键差异：防循环论证

行为/grounding 标定集的目标是「给几个常数定阈值」。检测引擎标定集
要多防一件事 —— **循环论证**：

    如果正样本是「照着 Sigma 规则反推出来的事件」，
    那测出的 Precision=1.0 只证明规则和样例是同一份东西写的。

所以每条 Sigma 用例都带 ``evidence_kind``：

    ``raw_indicator``  只有原始指标（URL / 端口 / 载荷）能定性，
                        不依赖上游 event_type 预判 → 测的是 Sigma 本身
    ``event_type_only`` 只有 event_type 带攻击语义 → 测的是
                        「Sigma 是否只是复述上游分类器」
    ``lookalike``      良性但含攻击特征词（/api/status 巡检、/export 报表）
                        → 测误报
    ``benign``         普通良性事件 → 测误报

报告会把前两类分开统计。若 ``event_type_only`` 占了命中的绝大多数，
说明当前规则库对上游分类器没有增量价值 —— 这是一个结论，不是缺陷断言。

## 误报率必须随基准率报告

误报率 = FP / (FP + TN)，而 TN 的数量完全取决于**注入多少良性事件**。
把 3 条良性塞进 10 条样本里，误报率天然虚高。

所以评估器提供 :func:`fp_rate_by_base_rate` —— 在
attack:benign = 1:1 / 1:9 / 1:99 三档下分别报告，
并明确标注「绝对误报率不可跨数据集迁移」。

## 维护约定

与前两套一致：新增样本**先写 expect，再看实现算出的结果**。
实现与标注冲突时是实现的问题，不要为了让脚本变绿去改 expect。
确实检不出的类别用 ``known_gap`` 显式登记，由评估器单独记账。

⚠️ 时间戳全部显式指定。异常检测的时序维度直接读事件时间 + 配置时区，
不给固定时间戳则结果随运行时刻漂移，标定集就不可复现。

⚠️ 基线必须**跨 5 个以上小时桶**。异常检测的 ``recent`` 是按小时桶
合并的滚动窗口，样本数取 ``len(recent)``；把所有基线事件挤在一个
小时里会得到 1 个桶 → 冷启动 → 统计维度判 inconclusive，
基线根本不成立。这条在第一版标定集里踩过一次。
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

try:
    from zoneinfo import ZoneInfo
    _TZ = ZoneInfo("Asia/Shanghai")
except Exception:                                   # pragma: no cover
    _TZ = timezone(timedelta(hours=8))

# 基线锚点：2026-10-19 是周一。固定值 = 可复现。
BASE_DT = datetime(2026, 10, 19, 2, 0, 0, tzinfo=_TZ)

#: 异常检测冷启动门槛（anomaly_detector.COLD_START_MIN_SAMPLES）
#: 基线小时桶数必须 >= 该值，否则统计维度判 inconclusive
MIN_BASELINE_BUCKETS = 8

#: 基线长度：每小时一条，共 12 个小时桶
BASELINE_HOURS = 12


def _ts(hours: float) -> float:
    """相对 BASE_DT 的 epoch 秒。hours 可为小数。"""
    return (BASE_DT + timedelta(hours=hours)).timestamp()


# ══════════════════════════════════════════════════════════════
# Sigma 标定集
# ══════════════════════════════════════════════════════════════

def _ev(**kw) -> dict:
    """构造一条标定用事件。

    ⚠️ 这里**同时**写 ``event`` 和 ``event_type`` 两个键，原因是两个引擎
    读的键不一样，而且这一点很容易踩：

        · ``AnomalyDetector.analyze()`` 读 ``event.get("event",
          event.get("type", "UNKNOWN"))`` —— 只认 ``event``；
        · Sigma 规则的 ``event|contains`` 走事件表的 ``event_type`` 列。

    第一版标定集只写了 ``event_type``，结果 600 条基线全部落进
    ``global_event_types["UNKNOWN"]`` → ``n_types < 2`` → rarity 维度
    恒为 inconclusive → 三条「应检出」全判 inconclusive。
    报告里看起来像异常检测大面积漏检，实际是标定集写错了字段名。
    生产路径由 ``ingest_pipeline._normalize_event()`` 保证 ``event``
    存在，所以这个键名不一致只在**直接构造事件的场景**里暴露。

    维护约定：不要「顺手」删掉其中一个键，除非先确认消费方不用它。
    """
    base = {
        "event_id": kw.pop("event_id", 1),
        "event_type": "UNKNOWN",
        "event": "UNKNOWN",
        "src_ip": "10.10.10.10",
        "dst_ip": "10.20.20.20",
        "dst_port": 443,
        "severity": "medium",
        "url": "",
        "message": "",
    }
    etype = kw.pop("event_type", None)
    if etype is not None:
        base["event_type"] = etype
        base["event"] = etype
    base.update(kw)
    return base


def sigma_cases() -> list:
    """Sigma 单事件标定集。"""
    C = []

    def case(cid, expect, kind, note, **ev):
        C.append({"id": cid, "expect": expect, "evidence_kind": kind,
                  "note": note, "event": _ev(event_id=cid.split("-")[-1], **ev)})

    # ── 正样本 · raw_indicator：只有原始指标，不靠 event_type 预判 ──
    case("SIG-P-01", "malicious", "raw_indicator",
         "经典路径遍历载荷，URL 里直接带 /../",
         url="https://portal/files/download?name=../../../../etc/passwd")
    case("SIG-P-02", "malicious", "raw_indicator",
         "URL 编码的路径遍历，绕过明文过滤",
         url="https://portal/files?name=%2e%2e%2f%2e%2e%2fetc%2fshadow")
    case("SIG-P-03", "malicious", "raw_indicator",
         "Elasticsearch 未授权读集群索引（9200 无鉴权）",
         url="http://10.30.30.30:9200/_cat/indices?v", dst_port=9200)
    case("SIG-P-04", "suspicious", "raw_indicator",
         ("SSH 端口 + 登录失败事件，SIG-007 的 AND 条件两侧都满足。"
          "但 SIG-007 自己声明了 x-soc-aggregation（阈值判定），"
          "单条登录失败**不构成**暴力破解 —— 归为 suspicious 而非 malicious："
          "它是候选，不是结论。把它标成 malicious 会逼着人去调规则，"
          "而真正该修的是「用不充分的证据下执行动作」。"),
         dst_port=22, event_type="LOGIN_FAIL")
    case("SIG-P-05", "suspicious", "raw_indicator",
         "同上，改用中文表述验证中文判据是否生效；同为候选而非结论",
         dst_port=22, event_type="登录失败")
    case("SIG-P-06", "malicious", "raw_indicator",
         "直接读取 access.log，典型信息收集",
         url="http://10.40.40.40/var/log/nginx/access.log")

    # ── 正样本 · event_type_only：只有上游分类器带攻击语义 ──
    case("SIG-P-07", "malicious", "event_type_only",
         "上游已判为 C2 回连；这条测的是 Sigma 是否只是复述上游",
         event_type="C2_BEACON")
    case("SIG-P-08", "malicious", "event_type_only",
         "上游已判为横向移动", event_type="LATERAL_MOVE")
    case("SIG-P-09", "malicious", "event_type_only",
         "上游已判为恶意软件落地", event_type="MALWARE")
    case("SIG-P-10", "malicious", "event_type_only",
         "上游已判为端口扫描", event_type="PORT_SCAN")

    # ── 负样本 · lookalike：良性但含攻击特征词 ──
    case("SIG-N-01", "benign", "lookalike",
         "监控探针打 /api/status 做健康巡检 —— 应命中 info_disclosure",
         url="https://mon.internal/api/status", event_type="HEALTH_CHECK",
         severity="info")
    case("SIG-N-02", "benign", "lookalike",
         "BI 报表按日期导出 —— 命中 /export 子串",
         url="https://bi.corp/export?date=2026-10-18&fmt=csv",
         event_type="REPORT_EXPORT", severity="info")
    case("SIG-N-03", "benign", "lookalike",
         "员工正常访问管理后台登录页 —— 命中 /admin/login",
         url="https://app.corp/admin/login", event_type="USER_LOGIN",
         severity="info")
    case("SIG-N-04", "benign", "lookalike",
         "运维工单里讨论 /etc/passwd 轮换策略",
         url="https://cm.corp/tickets/T-10293",
         message="user asked to rotate /etc/passwd per security policy",
         event_type="CHANGE_REQUEST", severity="info")
    case("SIG-N-05", "benign", "lookalike",
         "正常 SSH 运维登录（22 端口 + 登录成功）—— SIG-007 应不命中",
         dst_port=22, event_type="USER_LOGIN", severity="info")

    # ── 负样本 · benign：普通良性 ──
    case("SIG-N-06", "benign", "benign", "普通 HTTPS 业务请求",
         url="https://app.corp/api/orders?page=1", event_type="API_CALL",
         severity="info")
    case("SIG-N-07", "benign", "benign", "数据库只读查询",
         dst_port=5432, event_type="DB_QUERY", severity="info")
    case("SIG-N-08", "benign", "benign", "DNS 解析",
         dst_port=53, event_type="DNS_QUERY", severity="info")
    case("SIG-N-09", "benign", "benign", "内部服务间调用",
         dst_port=8080, event_type="SERVICE_CALL", severity="info")
    case("SIG-N-10", "benign", "benign", "静态资源下载",
         url="https://cdn.corp/static/app.9f2c.js", event_type="HTTP_GET",
         severity="info")
    return C


# ══════════════════════════════════════════════════════════════
# 异常检测标定集
# ══════════════════════════════════════════════════════════════

def _baseline(src_ip="10.50.0.1", per_bucket=50, hours=BASELINE_HOURS):
    """构造跨 hours 个小时桶的稳态基线事件（每小时 per_bucket 条）。

    必须跨小时桶：``recent`` 是按小时合并的，样本数取 len(recent)。
    把所有基线事件挤在一个小时里会得到 1 个桶 → 冷启动 → 统计维度
    判 inconclusive，基线根本不成立。这条在第一版标定集里踩过一次。

    必须含 **≥2 种事件类型**：``_calc_event_rarity`` 在
    ``n_types < 2`` 时返回 None（inconclusive）。只有一种类型时
    「应判正常」的用例根本达不到 not_detected —— 那是**标定集构造**
    问题，不是检测器缺陷，所以基线里掺入少量次要类型。
    """
    out = []
    eid = 1
    for h in range(hours):
        for k in range(per_bucket):
            out.append(_ev(
                event_id=f"bl-{src_ip}-{eid}",
                event_type="BENIGN" if k % 5 else "HEALTH_CHECK",
                severity="info", src_ip=src_ip,
                event_time=_ts(h),
            ))
            eid += 1
    return out


def anomaly_cases() -> list:
    """异常检测标定集。每条 = 基线 + 探针。

    ⚠️ 基线的 ``src_ip`` 必须与探针**同一个实体**。第一版标定集里
    基线喂 10.50.0.1、探针打 10.50.0.2，于是统计维度永远 inconclusive，
    三条「应检出」全被判 inconclusive —— 那是标定集写错了，不是
    检测器漏报。这类错误必须靠「基线实体 == 探针实体」这条不变量挡住。
    """
    C = []

    def case(cid, expect, probe, note, baseline, known_gap=None):
        assert baseline, f"{cid} 缺基线"
        C.append({"id": cid, "expect": expect, "note": note,
                  "baseline": list(baseline),
                  "probe": probe, "known_gap": known_gap})

    # ── 应判异常 ──
    src1 = "10.50.0.1"
    bl1 = _baseline(src_ip=src1)
    # 突发：同一小时内再灌 300 条，把速率从 50/h 拉到 350/h
    burst = bl1 + [
        _ev(event_id=f"burst-{i}", event_type="BENIGN", severity="info",
            src_ip=src1, event_time=_ts(BASELINE_HOURS + i * 0.002))
        for i in range(300)]
    case("ANO-P-01", "detected",
         _ev(event_id="p1", event_type="BENIGN", severity="info",
             src_ip=src1, event_time=_ts(BASELINE_HOURS + 0.5)),
         "稳态实体在最后一小时速率突增 7 倍（350 vs 50/h）",
         baseline=burst)

    src2 = "10.50.0.2"
    case("ANO-P-02", "detected",
         _ev(event_id="p2", event_type="RARE_ATTACK_TYPE", severity="critical",
             src_ip=src2, event_time=_ts(BASELINE_HOURS + 0.1)),
         "已建立基线的实体出现罕见事件类型 + critical + 非活跃时段",
         baseline=_baseline(src_ip=src2))

    src3 = "10.50.0.3"
    case("ANO-P-03", "detected",
         _ev(event_id="p3", event_type="RARE_ATTACK_TYPE", severity="critical",
             src_ip=src3, event_time=_ts(3.5)),
         "已建立基线的实体在凌晨 3 点半活动（时序 + 罕见度双证据）",
         baseline=_baseline(src_ip=src3))

    # ── 应判正常 ──
    case("ANO-N-01", "not_detected",
         _ev(event_id="n1", event_type="BENIGN", severity="info",
             src_ip=src1, event_time=_ts(BASELINE_HOURS + 0.1)),
         "稳态实体速率与基线一致（无突增）", baseline=bl1)

    src4 = "10.50.0.4"
    case("ANO-N-02", "not_detected",
         _ev(event_id="n2", event_type="HEALTH_CHECK", severity="info",
             src_ip=src4, event_time=_ts(BASELINE_HOURS + 0.1)),
         "有基线的实体，工作时间正常速率的常见事件",
         baseline=_baseline(src_ip=src4))

    # ── 结构性不可判：新实体 / 基线不足 / 无时间戳 ──
    case("ANO-I-01", "inconclusive",
         _ev(event_id="i1", event_type="ATTACK_BRUTEFORCE", severity="critical",
             src_ip="10.99.99.99", event_time=_ts(3.5)),
         "全新源 IP + critical + 凌晨：结构上无法判定，不能当完整阴性",
         baseline=_baseline(src_ip=src1))
    case("ANO-I-02", "inconclusive",
         _ev(event_id="i2", event_type="ATTACK_BRUTEFORCE", severity="critical",
             src_ip="10.99.99.99"),
         "全新源 IP 且事件无时间戳：时序维度也不可判",
         baseline=_baseline(src_ip=src1))
    case("ANO-I-03", "inconclusive",
         _ev(event_id="i3", event_type="BENIGN", severity="info",
             src_ip="10.77.77.77", event_time=_ts(BASELINE_HOURS + 0.1)),
         "该实体基线只有 2 个小时桶（冷启动）：统计维度样本不足",
         baseline=_baseline(src_ip="10.77.77.77", hours=2))
    return C


# ══════════════════════════════════════════════════════════════
# 关联引擎标定集
# ══════════════════════════════════════════════════════════════

def _cev(i, etype, minutes, src="10.60.0.1", dst="10.60.0.2", sev="high"):
    return {"id": i, "event_type": etype, "severity": sev,
            "src_ip": src, "dst_ip": dst, "message": "",
            "created_at": datetime(2026, 10, 19, 14, 0, 0,
                                   tzinfo=timezone.utc) + timedelta(minutes=minutes)}


def correlation_cases() -> list:
    """关联引擎标定集：expect = 是否应当产生攻击链。"""
    return [
        {"id": "COR-P-01", "expect": "chain",
         "note": "完整经典杀伤链（跳过声明可跳过的 LATERAL_MOVE）",
         "events": [_cev(1, "PORT_SCAN", 0), _cev(2, "BRUTE_FORCE", 2),
                    _cev(3, "C2_BEACON", 4), _cev(4, "DATA_EXFIL", 6)]},
        {"id": "COR-P-02", "expect": "chain",
         "note": "四步齐全的横向移动",
         "events": [_cev(1, "SUSPICIOUS_LOGIN", 0), _cev(2, "FILE_ACCESS", 3),
                    _cev(3, "LATERAL_MOVE", 6), _cev(4, "C2_BEACON", 9)]},
        {"id": "COR-N-01", "expect": "no_chain",
         "note": "缺 C2 回连，不得冠以经典杀伤链（整改前会命中）",
         "events": [_cev(1, "PORT_SCAN", 0), _cev(2, "BRUTE_FORCE", 5),
                    _cev(3, "DATA_EXFIL", 10)]},
        {"id": "COR-N-02", "expect": "no_chain",
         "note": "只有扫描 + 破解，不足以成链",
         "events": [_cev(1, "PORT_SCAN", 0), _cev(2, "BRUTE_FORCE", 5)]},
        {"id": "COR-N-03", "expect": "no_chain",
         "note": "高频良性 DNS 查询（dns_anomaly 需 C2_BEACON 收尾）",
         "events": [_cev(i, "DNS_QUERY", i * 0.5) for i in range(1, 8)]},
        {"id": "COR-N-04", "expect": "no_chain",
         "note": "普通业务调用序列",
         "events": [_cev(1, "API_CALL", 0), _cev(2, "DB_QUERY", 1),
                    _cev(3, "SERVICE_CALL", 2), _cev(4, "HTTP_GET", 3)]},
        {"id": "COR-N-05", "expect": "no_chain",
         "note": "端口扫描与 C2 之间隔 3 小时：单步间隔超限",
         "events": [_cev(1, "PORT_SCAN", 0), _cev(2, "BRUTE_FORCE", 40),
                    _cev(3, "C2_BEACON", 180)]},
        {"id": "COR-N-06", "expect": "no_chain",
         "note": ("每步间隔 20 分钟、总跨度 60 分钟：port_scan_to_c2 的"
                  "总时长上界是 45 分钟，应被拒"),
         "events": [_cev(1, "PORT_SCAN", 0), _cev(2, "BRUTE_FORCE", 20),
                    _cev(3, "C2_BEACON", 60)],
         # 这条只在 port_scan_to_c2 上判定：classic_killchain 的上界是
         # 150 分钟且允许跳过 LATERAL_MOVE，同一段序列它会命中。
         # 第一版标定集把它当成「任何模式都不该成链」，标注本身有歧义 ——
         # 引擎挑了更宽松的模式，报告只能记 MISS，看起来像缺陷其实是标注错。
         "only_pattern": "port_scan_to_c2"},
    ]


def cases_by_detector() -> dict:
    return {"sigma": sigma_cases(), "anomaly": anomaly_cases(),
            "correlation": correlation_cases()}
