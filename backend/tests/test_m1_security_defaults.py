# -*- coding: utf-8 -*-
"""M1 安全默认值回归：默认 dry_run、MISP 证书校验、注册闸门、admit 字段。

这些断言刻意选择“行为/语义”而非宽泛的文本匹配：
  * 默认执行模式必须是 dry_run（失败关闭）；
  * MISP verify=True 时不得关闭证书校验；
  * 注册开关默认关闭；
  * admit() 只调整车道，不得丢掉分析完整性字段。
"""
from __future__ import annotations

import re
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
REPO = BACKEND.parent


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="ignore")


def test_config_default_execution_mode_is_dry_run():
    src = _read(BACKEND / "config.py")
    m = re.search(r"^\s{4}execution_mode\s*:\s*str\s*=\s*[\"'](\w+)[\"']", src, re.M)
    assert m, "config.py 没有 execution_mode 字段"
    assert m.group(1) == "dry_run", (
        f"execution_mode 默认值必须是 dry_run（失败关闭），当前 {m.group(1)!r}"
    )


def test_execution_router_defaults_to_dry_run_not_live():
    from response_engine.execution_modes import ExecutionModeRouter, MODE_DRY_RUN

    router = ExecutionModeRouter()
    assert router.mode == MODE_DRY_RUN, (
        "ExecutionModeRouter() 默认必须是 dry_run；"
        "live 只能由部署环境显式开启"
    )


def test_prod_compose_pins_execution_mode():
    src = _read(REPO / "docker-compose.prod.yml")
    assert re.search(
        r"SHARED_MEMORY_EXECUTION_MODE:\s*[\"']?\$\{SHARED_MEMORY_EXECUTION_MODE:-dry_run\}[\"']?",
        src,
    ), "prod compose 必须显式 pin SHARED_MEMORY_EXECUTION_MODE（默认 dry_run）"


def test_app_startup_initializes_safe_executor_and_ttl():
    src = _read(BACKEND / "app.py")
    assert "safe_executor.initialize()" in src, "app lifespan 没有初始化 SafeExecutor"
    assert "ttl_manager.start_scanner()" in src, "app lifespan 没有启动 TTL 扫描器"
    assert "ttl_manager.set_rollback_callback" in src, "TTL 没有接回滚回调"


def test_misp_verify_ssl_does_not_invert():
    src = _read(BACKEND / "threat_intel" / "stix_taxii.py")
    # aiohttp: None=默认校验证书；False=关闭校验。
    assert "ssl_ctx = None if self.misp_verify_ssl else False" in src, (
        "MISP 证书校验逻辑必须保持 verify=True → ssl=None（校验证书）"
    )
    assert "None if not self.misp_verify_ssl else False" not in src, (
        "检测到旧的证书校验反转写法"
    )


def test_ssh_firewall_defaults_to_rejecting_unknown_host_keys():
    src = _read(BACKEND / "response_engine" / "ssh_firewall.py")
    assert "paramiko.RejectPolicy()" in src, (
        "SSH 防火墙必须对未知主机密钥使用 RejectPolicy"
    )
    assert "known_hosts 不存在" in src, (
        "known_hosts 缺失时必须明确失败，而不是静默 AutoAddPolicy"
    )
    # 显式放开必须是一个独立开关，且默认 False。
    cfg = _read(BACKEND / "config.py")
    assert re.search(r"fw_ssh_allow_unknown_host\s*:\s*bool\s*=\s*False", cfg)
    assert re.search(r"response_ssh_allow_unknown_host\s*:\s*bool\s*=\s*False", cfg)


def test_allow_self_registration_defaults_to_false():
    cfg = _read(BACKEND / "config.py")
    assert re.search(r"allow_self_registration\s*:\s*bool\s*=\s*False", cfg), (
        "公开自助注册必须默认关闭"
    )
    auth = _read(BACKEND / "routers" / "auth.py")
    assert "自助注册已关闭" in auth and "status_code=403" in auth, (
        "register handler 必须读取开关并在关闭时返回 403"
    )


def test_python_ingest_topic_is_schema_validated():
    from schema_registry import SchemaRegistryClient, TOPIC_SCHEMA_MAP

    assert "security-events-ingest" in TOPIC_SCHEMA_MAP, (
        "Python 权威检测主通道未绑定 schema，生产/消费侧校验会同时失效"
    )
    client = SchemaRegistryClient()
    errors = client.validate("security-events-ingest", {"bad": object()})
    assert errors, "security-events-ingest 仍未真正执行 schema 校验"


def test_admit_preserves_analysis_completeness_fields():
    from audit_triage import TriageResult, admit, LANE_LLM_SINGLE

    original = TriageResult(
        priority=99,
        tier="P0",
        lane="llm_agent",
        fused_conf=0.91,
        strong_count=3,
        analysis_status="error",
        analysis_complete=False,
    )
    out = admit(original, usage_pct=99.0, hard_pct=95.0)
    assert out.analysis_status == "error", (
        "admit() 不得把检测器故障折叠成 not_detected"
    )
    assert out.analysis_complete is False, (
        "admit() 不得把未完成分析折叠成已完成"
    )
    assert out.strong_count == 3, "admit() 不得丢掉强信号计数"
    assert out.lane == LANE_LLM_SINGLE, "hard 水位下 P0 应降为 llm_single"
