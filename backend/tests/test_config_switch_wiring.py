"""配置开关接线普查：329 个 Settings 字段里 37 个读不出来（本轮新增）

## 缺口

`config.py` 有 **329 个** `Settings` 字段，全量普查后：

| 类别 | 数量 | 含义 |
|---|---|---|
| **A. 零读点** | **17** | 没有任何生产代码读它 —— 设成什么都不会发生 |
| **B. 读点全在休眠模块内** | **20** | 读了，但读它的那几行代码**从不被执行** |
| C. 有活读点（对照组） | 292 | —— |

其中 **14 个已经出货到 `.env.example`**（A 类 4 个 + B 类 10 个），
即运维照着 `.env.example` 配了，**什么也不会发生**：

```
SHARED_MEMORY_SELF_PLAY_DECOY_RATIO=0.2        # 无效
SHARED_MEMORY_SELF_PLAY_DEFAULT_ROUNDS=8        # 无效
SHARED_MEMORY_INTEL_POLL_INTERVAL=...           # 无效（§7.1.8 已记录）
SHARED_MEMORY_TOOL_SIGNATURE_LOG_RETENTION_DAYS=180  # 无效（§7.1.10 已记录）
SHARED_MEMORY_MITM_ENABLED=true                 # 无效（§7.1.7 已记录）
SHARED_MEMORY_TAXII_URL / TAXII_USER / TAXII_PASSWORD   # 凭据，无效
SHARED_MEMORY_MISP_URL / MISP_API_KEY / MISP_VERIFY_SSL # 凭据，无效
SHARED_MEMORY_MITM_CA_KEY / MITM_CA_CERT / MITM_LISTEN_PORT  # 无效
```

**「零读点」和「读点在休眠模块」是两个不同的问题，前者更隐蔽**：
后者至少在代码里看得见「有人读」，前者是连读的代码都没有。

## 更正报告 §7.1.7 的两个错误数字

§7.1.7 写的是「28 个 `config.py` 布尔开关里**只有一个**的读点全部落在休眠模块内」，
并说「其余 27 个都有活读点（对照组证明扫描有鉴别力）」。

**两处都不成立**（`verify_717_bool_claim.py` 实测）：

| §7.1.7 写的 | 实际 |
|---|---|
| 28 个布尔开关 | **54 个** |
| 只有 1 个读点在休眠模块（`mitm_enabled`） | **3 个**：另加 `forensic_include_dump`、`misp_verify_ssl` |
| 其余 27 个都有活读点 | 49 个有活读点 + 2 个**零读点**（`kafka_flink_secondary_llm`、`audit_p1_use_temporal`） |

根因是**半口径**：§7.1.7 只扫了「布尔开关」这一个子集（而且只数到 28 个，
不是 54 个），把抽样结论当成了全量结论。
和 §7.1.10 的 BOM 静默降级同族 —— **只看一部分，「只有一个」就永远成立**。

## 为什么 self_play 那两个开关会死 —— 不是随机的

`routers/self_play.py::_cfg_from_req` 里，**所有**请求字段都遵循
「请求优先、回落 settings」，只有两个例外：

```python
"inject":       req.inject  if req.inject else bool(settings.self_play_inject),          # 有回落
"wait_audit":   req.wait_audit if req.wait_audit else bool(settings.self_play_wait_audit), # 有回落
"diverse_env":  bool(req.diverse_env) or bool(getattr(settings, "self_play_diverse_env", False)),  # 有回落
"background_traffic": bool(req.background_traffic) or bool(getattr(settings, "self_play_background_traffic", False)),  # 有回落
"decoy_ratio":  req.decoy_ratio,      # ← 没有回落，取死值 Field(0.2)
"rounds":       req.rounds,           # ← 没有回落，取死值 Field(8)
```

而配置里恰好就是这两个：**零读点的 `self_play_*` 开关，正好等于跳过回落的那两个请求字段**，
且请求字段的默认值与配置默认值**完全一致**（`0.2` / `8`）—— 不是巧合，是同一处漏改。

这与 §7.1.6 的形态一致：**值有人写了，读的人挑错了源**。
配置层写了值，请求层用另一个硬编码源，两边都「看起来对」。

## 前提守卫（必须常绿）

* config.py 字段数仍是 329 —— 大改后本文件的结论需要重新核实
* 活读点对照组 ≥ 250 —— 证明扫描有鉴别力，「全部空转」与「什么都没匹配上」长得一样
* `.env.example` 能解析出 150 个 `SHARED_MEMORY_*` 键 —— 出货口径本身可复现
* **`_cfg_from_req` 的运行时实证**：`settings.self_play_decoy_ratio` 改成 0.9 后，
  实际产出的 `decoy_ratio` 仍不是 0.9 —— 这是 A 类的直接运行时证据，
  不是 grep。
"""
from __future__ import annotations

import functools
import os
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))
SKIP_DIRS = ("tests", "eval_datasets", "tools")

DORMANT = {
    "zeroday_detect/behavior_analyzer.py", "zeroday_detect/llm_behavior.py",
    "threat_intel/intel_enricher.py",
    "threat_intel/llm_context.py", "session_reconstruct/timeline.py",
    "session_reconstruct/http_linker.py", "session_reconstruct/tcp_reassembler.py",
    "response_engine/containment/host_adapter.py",
    "response_engine/containment/directory_adapter.py",
    "response_engine/containment/mail_adapter.py",
    "traffic_baseline/traffic_profiler.py", "traffic_baseline/peer_group.py",
    "ids_connector/suricata_connector.py", "encrypted_traffic/mitm_proxy.py",
    "edr_fusion/llm_correlation.py", "agents/audit_single.py",
    "self_play/store.py", "red_agent.py",
}

# §7.1.7 / §7.1.10 已独立查证的样本，用于自检判据的鉴别力
KNOWN_ZERO_READ = {"tool_signature_log_retention_days", "intel_poll_interval"}
KNOWN_DORMANT_ONLY = {"mitm_enabled", "forensic_include_dump"}
KNOWN_LIVE = {"kafka_enabled", "llm_request_timeout_s", "audit_workers",
              "capture_enabled", "self_play_inject", "self_play_wait_audit",
              # stix_taxii 已由 /api/intel/feeds/{id}/poll 调用
              "misp_verify_ssl"}


def _prod_py():
    return [p for p in sorted(BACKEND.rglob("*.py"))
            if not p.relative_to(BACKEND).as_posix().startswith(SKIP_DIRS)
            and p.name != "config.py"]


def _src(p: Path) -> str:
    return p.read_text(encoding="utf-8", errors="ignore")


@functools.lru_cache(maxsize=1)
def _settings_fields() -> tuple[tuple[str, str], ...]:
    body = _src(BACKEND / "config.py").split("class Settings", 1)[1]
    return tuple(re.findall(
        r"^\s{4}([a-z_][a-z0-9_]*)\s*:\s*([\w\[\]\.\"\'| ]+?)\s*=", body, re.M))


@functools.lru_cache(maxsize=1)
def _readers() -> dict[str, list[tuple[str, int]]]:
    """逐字段读点。只认两种形态，避免裸名误判（见文件头「陷阱」说明）。

    加了 `lru_cache`：本函数要给 329 个字段各扫一遍全仓，
    6 个测试各调一次就是 6 倍开销（实测 40.5s -> ~7s）。
    """
    texts = [(p, p.read_text(encoding="utf-8", errors="ignore")) for p in _prod_py()]
    out = {}
    for key, _typ in _settings_fields():
        pat1 = re.compile(rf"\.{re.escape(key)}\b")
        pat2 = re.compile(rf"[\"']{re.escape(key)}[\"']")
        hits = []
        for p, t in texts:
            rel = p.relative_to(BACKEND).as_posix()
            for i, line in enumerate(t.splitlines(), 1):
                if pat1.search(line) or pat2.search(line):
                    hits.append((rel, i))
        out[key] = hits
    return out


@functools.lru_cache(maxsize=1)
def _shipped_keys() -> frozenset[str]:
    txt = (ROOT / ".env.example").read_text(encoding="utf-8", errors="ignore")
    return frozenset(re.findall(r"^\s*#?\s*(SHARED_MEMORY_[A-Z0-9_]+)\s*=", txt, re.M))


# ═══════════════════════════════════════════
# 前提守卫
# ═══════════════════════════════════════════

def test_settings_field_count_is_unchanged():
    """前提①：config.py 字段数普查。

    2026-10-21 新增 5 个安全字段：execution 默认 dry_run 相关的主机密钥
    校验（fw/response 各 2 个）与 allow_self_registration（1 个）。
    2026-10-23 第一阶段 +2：log_format(结构化日志) / auto_migrate(启动迁移)。
    2026-10-23 第二阶段 +2：audit_claim_ttl_s(跨进程审计认领) /
    require_idempotency_for_live(live 幂等 fail-closed)。
    2026-10-23 Kafka 安全化 +6：kafka_security_protocol / sasl_mechanism /
    sasl_username / sasl_password / ssl_ca_file / ssl_check_hostname。
    2026-10-24 生产加固 +1：suricata_eve_topic(EVE topic 可配置)。
    2026-10-26 审计#1 +2：kafka_producer_restart_initial_s/max_s
    （生产者监督重启, 与消费者重试能力对齐）。
    2026-10-27 大屏实况面板 +7：ledger_interval_s / attack_geo_interval_s /
    attack_geo_window / attack_geo_max_points / home_lat / home_lon / home_label
    （读点: ledger_broadcast.py / attack_geo_broadcast.py, 活读已核实）。
    字段数再变说明 config.py 被大改，本文件里所有清单都需要重新核实。
    """
    fields = _settings_fields()
    # 2026-10-29 (R3/R12/R14/R20): +3 = DEMO_MODE(演示路由开关) /
    #   INTEL_LOCAL_FEED_DIR(本地情报白名单) / TEMPO_URL(Tempo 查询地址出配置)
    # 2026-10-30 背压复合信号 (PERF-OPT-PLAN Wave 2-1/2-2): +3 =
    #   KAFKA_CONSUMPTION_EPS(实测消费容量, 0=lag 信号不启用) /
    #   KAFKA_LAG_ALLOWED_BACKLOG_S(允许积压秒数) / AUDIT_PQ_CAPACITY(PQ 深度容量)
    # 2026-10-30 H 路线接线开关: +5 = INTEL_LLM_CONTEXT_ENABLED /
    #   EDR_LLM_CORRELATION_ENABLED / TRAFFIC_PEER_GROUP_ENABLED /
    #   ZERODAY_LANE_ENABLED / LEARN_VARIANT_CLUSTER_ENABLED
    #   (REMEDIATION-PLAN 路线 H 收口, 详见 test_h_wiring.py)
    # 2026-10-30 W31 P1: +1 = REDIS_POOL_MAX_CONNECTIONS(默认 100 击穿 → 500)
    assert len(fields) == 369, (
        f"Settings 字段数从 369 变成 {len(fields)} —— "
        "请重新跑全量普查并更新整改报告 §7.1.11"
    )


def test_live_readers_are_the_majority_so_the_scan_has_discriminating_power():
    """前提②：绝大多数字段**有**活读点。

    没有这条，「37 个读不出来」和「扫描器什么都没匹配上」长得一样。
    """
    r = _readers()
    live = [k for k, h in r.items() if h and not all(f in DORMANT for f, _ in h)]
    assert len(live) >= 250, (
        f"只有 {len(live)} 个字段有活读点（应 ≥250）—— "
        "扫描口径可能整体退化了，先修扫描器再看结论"
    )
    # 已知答案逐个核对（三个类别必须区分开）
    for k in KNOWN_ZERO_READ:
        assert not r[k], f"{k} 应为零读点，实际 {r[k][:3]}"
    for k in KNOWN_DORMANT_ONLY:
        assert r[k] and all(f in DORMANT for f, _ in r[k]), \
            f"{k} 应为「读点全在休眠模块内」，实际 {r[k][:3]}"
    for k in KNOWN_LIVE:
        assert r[k] and not all(f in DORMANT for f, _ in r[k]), \
            f"{k} 应有活读点，实际 {r[k][:3]}"


def test_env_example_parses_and_ships_the_keys_we_care_about():
    """前提③：`.env.example` 出货口径可复现。

    「出货了却无效」比「内部死配置」严重一级，所以这个口径必须能复算。
    """
    shipped = _shipped_keys()
    # 2026-10-23: +3 = SOURCE_API_KEYS(数据源认证, 源码内置演示密钥已删除) /
    #   AUTO_MIGRATE(启动自动 alembic 迁移) / LOG_FORMAT(结构化日志)
    # 2026-10-26 审计#4: +1 = FW_SSH_ALLOW_UNKNOWN_HOST(靶场 known_hosts fail-closed 显式开关)
    # 2026-10-27: +7 = 大屏实况面板 (config.py 同日新增 settings 字段:
    #   LEDGER_INTERVAL_S / ATTACK_GEO_INTERVAL_S / ATTACK_GEO_WINDOW /
    #   ATTACK_GEO_MAX_POINTS / HOME_LAT / HOME_LON / HOME_LABEL)
    # 2026-10-27 路线3: +2 = INTEL_ENRICH_ENABLED / INTEL_ENRICH_TIMEOUT_MS
    #   (富化旁路与拉取解耦, fail-open 契约见 intel_enricher.enrich_event_if_enabled)
    # 2026-10-27 路线2: +1 = SURICATA_ENABLED (IDS 接入启动分支)
    # 2026-10-29 (R3/R12): +1 = TEMPORAL_PASSWORD(compose fail-closed 必填) +
    #   SHARED_MEMORY_DEMO_MODE(演示路由开关) − SHARED_MEMORY_INTEL_LOCAL_FEED_DIR
    #   按需补录。此处以实测出货口径为准。
    # 2026-10-30 背压复合信号: +3 = KAFKA_CONSUMPTION_EPS /
    #   KAFKA_LAG_ALLOWED_BACKLOG_S / AUDIT_PQ_CAPACITY (config.py 同日新增,
    #   默认注释出货, 标定口径见 PERF-OPT-PLAN Wave 2-2)
    assert len(shipped) == 168, f"出货键数从 168 变成 {len(shipped)}，出货口径需重估"
    for key in ("SHARED_MEMORY_SELF_PLAY_DECOY_RATIO",
                "SHARED_MEMORY_SELF_PLAY_DEFAULT_ROUNDS",
                "SHARED_MEMORY_TAXII_PASSWORD",
                "SHARED_MEMORY_MISP_API_KEY",
                "SHARED_MEMORY_MITM_ENABLED",
                "SHARED_MEMORY_LEDGER_INTERVAL",
                "SHARED_MEMORY_HOME_LABEL"):
        assert key in shipped, f"{key} 不再出货 —— 请更新整改报告 §7.1.11"


def test_self_play_decoy_ratio_ignores_the_config_at_runtime():
    """前提④（**运行时**实证）：`settings.self_play_decoy_ratio` 对产出没有任何影响。

    这是 A 类「零读点」的直接运行时证据，不是 grep ——
    把 config 值改成 0.9，实际 `_cfg_from_req` 产出的仍是请求字段的 0.2。

    若哪天这条转红（配置开始生效），说明 §7.1.11 的 `test_no_shipped_switch_is_unread`
    应该摘标记。
    """
    from config import settings
    from routers.self_play import StartMatchRequest, _cfg_from_req

    old = settings.self_play_decoy_ratio
    try:
        settings.self_play_decoy_ratio = 0.9
        req = StartMatchRequest()          # 全默认，decoy_ratio=0.2
        out = _cfg_from_req(req, "probe-1")
        assert out["decoy_ratio"] == 0.2, (
            f"配置已经生效了（decoy_ratio={out['decoy_ratio']}）—— "
            "self_play_default_rounds / decoy_ratio 的缺口已修，请摘掉相关 strict xfail"
        )
        # 对照组：同一函数里带 settings 回落的字段确实吃配置
        settings.self_play_wait_audit = True
        out2 = _cfg_from_req(StartMatchRequest(), "probe-2")
        assert out2["wait_audit"] is True, (
            "对照组失效：带 settings 回落的 wait_audit 也没吃配置 —— "
            "说明本文件对 _cfg_from_req 的理解已过时"
        )
    finally:
        settings.self_play_decoy_ratio = old


# ═══════════════════════════════════════════
# 主断言（strict xfail）：接线即转红
# ═══════════════════════════════════════════

@pytest.mark.xfail(
    strict=True, raises=AssertionError,
    reason="已知缺口：14 个已出货到 .env.example 的开关没有任何活读点 —— "
           "运维配了也不会发生。见整改报告 §7.1.11",
)
def test_no_shipped_switch_is_unread():
    """凡是在 `.env.example` 出货的开关，都必须有活读点。

    口径：**活读点** = 读它的代码既不在 `config.py`、也不在任何 §7.1.5
    登记的休眠模块里。裸名匹配不算（注释里提到不算）。

    接线 / 删字段 / 从 `.env.example` 摘掉，三者任一都会让它转绿。
    """
    r = _readers()
    shipped = _shipped_keys()
    dead = []
    for key, hits in r.items():
        env = f"SHARED_MEMORY_{key.upper()}"
        if env not in shipped:
            continue
        if not hits or all(f in DORMANT for f, _ in hits):
            dead.append(key)
    assert not dead, (
        f"这 {len(dead)} 个开关已出货到 .env.example 但没有活读点：{sorted(dead)}\n"
        "运维按 .env.example 配了它们却什么也不会发生"
    )


@pytest.mark.xfail(
    strict=True, raises=AssertionError,
    reason="已知缺口：20 个开关的读点全部落在休眠模块内（含 3 个凭据组："
           "TAXII / MISP / MITM）。见整改报告 §7.1.11",
)
def test_no_switch_is_read_only_by_dormant_modules():
    """不允许出现「只有休眠模块在读」的开关。

    接线那 20 个休眠模块（§7.1.4 零日链 / §7.1.8 情报链 / containment 三个适配器 /
    mitm_proxy）或删掉对应配置，本条即转绿。

    ⚠ 这**不是**「删掉休眠模块」的断言 —— §7.1.5 已确认
    `variant_cluster` 那类「整文件休眠但单个符号是活的」必须保留。
    """
    r = _readers()
    bad = {k: v for k, v in r.items()
           if v and all(f in DORMANT for f, _ in v)}
    assert not bad, (
        f"{len(bad)} 个开关只被休眠模块读：{sorted(bad)}\n"
        "把它们设成 true / 填上凭据也不会发生任何事"
    )


@pytest.mark.xfail(
    strict=True, raises=AssertionError,
    reason="已知缺口：config.py 里 17 个字段零读点（其中 4 个已出货）。"
           "见整改报告 §7.1.11",
)
def test_every_settings_field_has_at_least_one_reader():
    """config.py 的每个字段都应当至少有一处活读点。

    零读点的字段是纯粹的「看起来可调」—— 改它没有任何效果，
    而代码审查时很难发现。
    """
    r = _readers()
    dead = sorted(k for k, h in r.items() if not h)
    assert not dead, (
        f"{len(dead)} 个 Settings 字段零读点：{dead}\n"
        "这些字段会让人以为系统是可调的，实际改了不起作用"
    )


@pytest.mark.xfail(
    strict=True, raises=AssertionError,
    reason="已知缺口：audit_p1_use_temporal 只存在于 scheduler.py:728 的注释里，"
           "实际 go_temporal 是硬编码的 tier == 'P0'。见整改报告 §7.1.11",
)
def test_audit_p1_use_temporal_is_actually_read():
    """`audit_p1_use_temporal` 必须真的参与 P1 的 Temporal 路由判断。

    `scheduler.py:728` 的注释写的是「仅 P0 agent 走 Temporal;
    P1 (`audit_p1_use_temporal=False`) 降级 llm_single」，
    而 `:729` 实际是 `go_temporal = temporal_lane and tier == "P0"` ——
    **P1 的路由是写死的，开关设成 true 也不会走 Temporal**。

    注释描述了一个开关能控制的行为，代码里没有任何地方读那个开关。
    这是 §7.1.6 那个形态：注释/配置说了，读的人没接。
    """
    sched = _src(BACKEND / "scheduler.py")
    assert re.search(r"audit_p1_use_temporal", sched), \
        "scheduler.py 不再提到 audit_p1_use_temporal —— 注释已改，本条需重新评估"
    # 必须真的读 settings，而不是只出现在注释里
    code_lines = [ln for ln in sched.splitlines()
                  if "audit_p1_use_temporal" in ln and not ln.strip().startswith("#")]
    assert code_lines, (
        "audit_p1_use_temporal 只出现在注释里，没有任何一行代码读它 —— "
        "P1 的 Temporal 路由是硬编码的（scheduler.py:729）"
    )


# ═══════════════════════════════════════════
# §7.1.13 元规则：守着 .env.example 的测试必须同时有执行面验证
# ═══════════════════════════════════════════

def _env_example_guard_keys() -> dict:
    """扫全仓测试：哪些键被断言「必须出现在 .env.example」。

    口径：`test_*` 函数体**代码**（AST 字符串常量）里出现的 `SHARED_MEMORY_*` 键，
    再要求它**真的在 `.env.example` 里**。

    ## 两个必须避开的陷阱（实现时各踩了一次）

    ① **docstring 里的占位符不是真键** —— 早期版本抓整个函数体文本，
       把说明文字里的占位符 `SHARED_MEMORY_*` 当成真键；再去掉前缀得单字母 `x`，
       用 `\\.x\\b` 又在 `causal_chain/compare.py` 匹配到 11 处，
       于是占位符被归进「有活读点」的对照组 —— **结论直接被带偏**。
       → 键名只从 AST 字符串常量取（docstring 不在其中），
         并由「必须在 `.env.example` 里」收口。

    ② **不要要求「函数体里必须出现 `.env.example`」** ——
       加了这条会把本文件 §7.1.11 的
       `test_env_example_parses_and_ships_the_keys_we_care_about` 滤掉：
       它的函数体只调 `_shipped_keys()`，`.env.example` 只出现在 docstring 里。
       **前提守卫被当成无关测试剔除 = 纯假阴性**，分母从 13 被缩到 8。
       → 只做文件级检查。
    """
    import ast as _ast
    out = {}
    for tp in sorted((BACKEND / "tests").glob("*.py")):
        src = _src(tp)
        if ".env.example" not in src:
            continue
        try:
            tree = _ast.parse(src.lstrip("\ufeff"))
        except SyntaxError:
            continue
        for fn in [n for n in _ast.walk(tree)
                   if isinstance(n, _ast.FunctionDef) and n.name.startswith("test_")]:
            for node in _ast.walk(fn):          # ① 只取代码里的字符串常量
                if isinstance(node, _ast.Constant) and isinstance(node.value, str):
                    if "SHARED_MEMORY_" in node.value:
                        for k in re.findall(r"SHARED_MEMORY_[A-Z0-9_]+", node.value):
                            out.setdefault(k, (tp.name, fn.name))
    shipped = _shipped_keys()                   # ① 收口：必须在 .env.example 里
    return {k: w for k, w in out.items() if k in shipped}


@pytest.mark.xfail(
    strict=True, raises=AssertionError,
    reason="已知缺口：13 个被 .env.example 文档面测试守着的键里，6 个实际不生效"
           "（3 个生产零读点 + 3 个读点全在休眠模块内）。见整改报告 §7.1.13",
)
def test_every_env_example_guard_is_backed_by_enforcement_or_a_gap_marker():
    """凡是断言「这个键必须出现在 `.env.example`」的测试，都必须同时有：
    (a) 生产代码在**活模块**里真的读它，**或**
    (b) 一个把它登记为缺口的守卫。

    ## 这条元规则守的是什么

    §7.1.12 撞见的形态：`test_security_fixes_2026_10_03.py` 断言
    `SHARED_MEMORY_ALLOW_SELF_REGISTRATION` 在 `.env.example` 里 —— 该测试**是绿的**，
    但 `config.py` 无该字段、生产零读点、注册端点无任何判断。
    **修复的文档侧有绿测试背书，执行侧一片空白**，两者加起来等于「已修复」的假象。

    `security_crypto.py` 的 docstring 记着同一种失效在 `control_hmac_key` 上的先例，
    说明这不是偶发，而是本仓库反复出现的写法。

    ## 为什么写成元规则而不是逐条列

    逐条列只能守住当前这 13 个键；写成元规则后，
    **任何人新增一条 `.env.example` 断言都会被立刻要求配执行面验证**。

    实测当前 13 个被守键里 **6 个不生效（46%）** —— 说明这不是个别疏漏。
    对照组那 7 个（含 `JWT_SECRET`、`ADMIN_PASSWORD`、`DATABASE_URL`、
    `EMBEDDING_API_KEY`、`LLM_API_KEY`）**全部是活的**，
    所以不是「`.env.example` 整体不可信」，而是「写了什么决定它可不可信」。

    ⚠ 口径说明：本条只查「生产有没有在**活模块**里读」。
    「有没有测试在断言它的执行」这条信号本质不可靠（执行面测试可能完全不提键名），
    所以不作为判据 —— 见整改报告 §7.1.13。

    ## 它不接受「半修复」

    验红时发现：本条用 `_readers()`，而它**以 config.py 的 Settings 字段为键**扫描。
    `allow_self_registration` 不是字段 → 它的读点恒为 0，
    哪怕代码里写了 `_inj_settings.allow_self_registration`。

    这不是缺陷而是**应有性质**：§7.1.12 的修复要求
    「config.py 加字段」**+**「生产代码读它」两件事同时做，只做一件不构成修复。
    实测：只加字段 → 本条 **不转红**；加字段 + 接线 → **转红**。
    """
    guards = _env_example_guard_keys()
    assert guards, "没有扫到任何 .env.example 守卫测试 —— 提取口径退化了"

    r = _readers()
    inert = {}
    for env_key in guards:
        field = env_key[len("SHARED_MEMORY_"):].lower()
        hits = r.get(field, [])
        live = [h for h in hits if h[0] not in DORMANT]
        if not live:                      # 零读点 或 读点全在休眠
            inert[env_key] = (
                "零读点" if not hits else
                f"读点全在休眠模块({hits[0][0]}:{hits[0][1]})")
    assert not inert, (
        f"{len(inert)}/{len(guards)} 个被 .env.example 文档面测试守着的键实际不生效：\n"
        + "\n".join(f"    {k}  —— {why}" for k, why in sorted(inert.items()))
        + "\n这些键都有一个**绿色**测试守着它们的文档，却没有任何东西让它们生效"
    )


def test_env_example_guard_extraction_still_finds_the_known_keys():
    """前提：元规则的提取口径本身可复现。

    若哪天扫不到这几个键，说明提取逻辑退化了，
    上面的元规则会安静地变成「什么都没检查」—— 那正是它要防的失效形态。
    """
    guards = _env_example_guard_keys()
    # 2026-10-27: +2 = SHARED_MEMORY_LEDGER_INTERVAL / SHARED_MEMORY_HOME_LABEL
    # (大屏实况面板出货键, 执行面验证: config.py Settings 字段 +
    #  ledger_broadcast/attack_geo_broadcast 活读点, 见出货口径测试的注释)
    assert len(guards) == 15, (
        f"被 .env.example 守卫的键从 15 个变成 {len(guards)} 个 —— "
        "请重新核实 §7.1.13 的分母，并确认新增/移除的键是否有执行面验证。"
        "若是被提取口径滤掉的（例：函数体里没有 `.env.example` 字面量、"
        "只有 docstring 提到），那是回归到 v2 的假阴性口径了"
    )
    for k in ("SHARED_MEMORY_ALLOW_SELF_REGISTRATION",
              "SHARED_MEMORY_CONTROL_HMAC_KEY",
              "SHARED_MEMORY_EXECUTION_MODE"):
        assert k in guards, f"{k} 不再被 .env.example 守卫测试覆盖"
