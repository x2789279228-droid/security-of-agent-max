# -*- coding: utf-8 -*-
"""Kafka 客户端安全接线守卫 —— "所有构造点都必须展开 aiokafka_security_kwargs"。

背景（P0-5/P0-3 修复遗留的守卫缺口）：kafka_security.py 明确要求
**每一个** AIOKafkaProducer/AIOKafkaConsumer 构造点都展开
``**aiokafka_security_kwargs()``，漏一处就会出现"一半连接加密、一半明文"——
EDR/Suricata 两条接入链路正是这样漏掉的（2026-10-24 评审 §四.3）。

本守卫是**静态源码扫描**（不依赖 aiokafka 可用、不连 broker）：
找出 backend 全部 `AIOKafkaProducer(`/`AIOKafkaConsumer(` 构造调用，
断言其构造参数里出现 `aiokafka_security_kwargs()`；同时钉住构造点总数，
新增连接点时本文件转红，逼开发者表态。
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]

#: 排除的路径（测试自身 / mock 用途）
EXCLUDE = ("tests", "test_", "inc_mock")

#: 构造点白名单计数 —— 新增/减少连接点时更新这里并在模块 docstring 登记
EXPECTED_CONSTRUCTOR_SITES = 7

SECURITY_TOKEN = "aiokafka_security_kwargs"


def _iter_backend_py() -> list[Path]:
    out = []
    for p in sorted(BACKEND.rglob("*.py")):
        rel = str(p.relative_to(BACKEND))
        if any(x in rel for x in EXCLUDE):
            continue
        out.append(p)
    return out


def _find_constructor_calls() -> list[tuple[Path, ast.Call]]:
    """AST 扫描：所有 AIOKafkaProducer/AIOKafkaConsumer(...) 调用点。"""
    hits: list[tuple[Path, ast.Call]] = []
    for p in _iter_backend_py():
        try:
            tree = ast.parse(p.read_text(encoding="utf-8"), filename=str(p))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            fn = node.func
            name = getattr(fn, "id", "") or getattr(fn, "attr", "")
            if name in ("AIOKafkaProducer", "AIOKafkaConsumer"):
                hits.append((p, node))
    return hits


def test_every_kafka_constructor_expands_security_kwargs():
    sites = _find_constructor_calls()
    lines: list[str] = []
    missing: list[str] = []
    for p, call in sites:
        rel = p.relative_to(BACKEND)
        has_kw = any(
            isinstance(kw, ast.keyword)
            and kw.arg is None  # **kwargs 展开
            and SECURITY_TOKEN in ast.unparse(kw.value)
            for kw in call.keywords
        )
        lines.append(f"{rel}:{call.lineno} {'OK' if has_kw else 'MISSING'}")
        if not has_kw:
            missing.append(f"{rel}:{call.lineno}")

    detail = "\n".join(lines)
    assert not missing, (
        "以下 Kafka 构造点未展开 **aiokafka_security_kwargs() —— "
        f"SASL_SSL 模式下会认证失败或保持明文:\n{detail}"
    )
    assert lines, "未找到任何 Kafka 构造点 —— 扫描逻辑可能已失效"


def test_constructor_site_count_is_pinned():
    """钉住构造点数量：新增连接点必须在本文件登记并接线安全参数。"""
    n = len(_find_constructor_calls())
    assert n == EXPECTED_CONSTRUCTOR_SITES, (
        f"Kafka 构造点数量变为 {n} (期望 {EXPECTED_CONSTRUCTOR_SITES})。"
        "若是新增: 请展开 **aiokafka_security_kwargs() 并更新 EXPECTED_CONSTRUCTOR_SITES;"
        "若是删除: 同步更新清单，别让过期数字误导后人。")


def test_security_kwargs_default_is_inert():
    """默认 PLAINTEXT 下 kwargs 必须为空 dict —— 保证零行为变化。"""
    import os
    os.environ.setdefault("SHARED_MEMORY_SKIP_DOTENV", "1")
    import sys
    sys.path.insert(0, str(BACKEND))
    # 注意: 严禁 importlib.reload(config) —— reload 会替换 settings 实例,
    # 而 temporal/client 等模块持有旧引用, 造成跨测试污染 (实测踩坑)。
    import config  # noqa: F401
    from kafka_security import aiokafka_security_kwargs

    assert config.settings.kafka_security_protocol.upper() == "PLAINTEXT"
    assert aiokafka_security_kwargs() == {}, (
        "PLAINTEXT 默认下不应产生任何安全参数 —— 这会改变历史行为")


def test_security_kwargs_sasl_ssl_sets_credentials():
    """SASL_SSL 下必须带 protocol/mechanism/凭据/SSL 上下文。"""
    import os
    os.environ.setdefault("SHARED_MEMORY_SKIP_DOTENV", "1")
    import sys
    sys.path.insert(0, str(BACKEND))
    import config
    from kafka_security import aiokafka_security_kwargs

    config.settings.kafka_security_protocol = "SASL_SSL"  # noqa: test-local mutation, finally 里还原
    config.settings.kafka_sasl_username = "soc-app"
    config.settings.kafka_sasl_password = "pw"
    config.settings.kafka_ssl_ca_file = ""  # 走 self-signed 降级分支
    try:
        kw = aiokafka_security_kwargs()
    finally:
        config.settings.kafka_security_protocol = "PLAINTEXT"
        config.settings.kafka_sasl_username = ""
        config.settings.kafka_sasl_password = ""

    assert kw["security_protocol"] == "SASL_SSL"
    assert kw["sasl_mechanism"] == "SCRAM-SHA-512"
    assert kw["sasl_plain_username"] == "soc-app"
    import ssl as _ssl
    assert isinstance(kw["ssl_context"], _ssl.SSLContext)
