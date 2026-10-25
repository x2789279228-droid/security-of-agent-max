# -*- coding: utf-8 -*-
"""RBAC 变更端点守卫 — 每个 POST/PUT/DELETE/PATCH 端点必须声明角色要求。

背景(2026-10-25 RBAC 补齐): 认证由 app.py 全局中间件强制(全部 /api/* 需要
JWT), 但此前 12 处变更型端点只认证不授权 —— 任何登录用户(含只读 viewer)
都能下发 iptables 预览/切换 CEP 灰度/发起钓鱼演练/触发复核等。
本轮逐个补上 RequireRole; 本测试用 AST 静态扫描把这件事锁成不变量:

    变更型端点必须满足以下之一, 否则测试红:
      a) 函数签名(含依赖)中出现 RequireRole;
      b) 函数体内出现显式 role 校验(如 dlq.replay 的 user.role == "admin");
      c) 位于下方显式 allowlist(有其它认证通道或刻意开放, 逐条注释理由)。

只读(GET)端点不在本守卫范围 —— viewer 可读是预期设计。
"""
from __future__ import annotations

import ast
import os
import pathlib
import sys

os.environ.setdefault("SHARED_MEMORY_SKIP_DOTENV", "1")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

ROUTERS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "routers")

# ── 显式豁免清单: 变更型端点但不走 JWT 角色体系 ──
# 每条必须写理由; 新增豁免需要评审。
_ALLOWLIST_AUTH_ENTRY = {
    # 登录/注册本身是认证入口(无 token 可言), 暴力破解由独立的限流/锁定机制守
    ("auth.py", "post", "/auth/login"),
    ("auth.py", "post", "/auth/register"),
    # 日志接入网关: 认证走 source_registry 的 API Key(非 JWT), 与 syslog/Kafka 同源
    ("logs.py", "post", "/logs/ingest"),
    ("logs.py", "post", "/logs/ingest/batch"),
    # EDR 连接器接入: 同为 API Key 认证的数据面入口
    ("edr_intel.py", "post", "/edr/ingest"),
    # 登出: 撤销自己的 token, 天然只作用于调用者本人
    ("auth.py", "post", "/auth/logout"),
}
# 语义只读的分析类 POST (RPC 风格: POST 承载的是查询/计算, 无状态变更) ——
# viewer 可调用是设计意图, 与 GET 同权; 带成本的后缀(email-llm)由 LLM 全局
# 预算/限流兜底, 不另设角色门槛。
_ALLOWLIST_READ_LIKE = {
    ("causal.py", "post", "/query"),
    ("edr_intel.py", "post", "/intel/match"),
    ("phishing.py", "post", "/phishing/detect/email"),
    ("phishing.py", "post", "/phishing/detect/web"),
    ("phishing.py", "post", "/phishing/detect/domain"),
    ("phishing.py", "post", "/phishing/detect/attachment"),
    ("phishing.py", "post", "/phishing/detect/sms"),
    ("phishing.py", "post", "/phishing/detect/qrcode"),
    ("phishing.py", "post", "/phishing/detect/bec"),
    ("phishing.py", "post", "/phishing/detect/email-llm"),
    ("rag.py", "post", "/rag/search"),
}
ALLOWLIST = _ALLOWLIST_AUTH_ENTRY | _ALLOWLIST_READ_LIKE

_WRITE_METHODS = {"post", "put", "delete", "patch"}


def _iter_write_endpoints():
    for f in sorted(pathlib.Path(ROUTERS_DIR).glob("*.py")):
        tree = ast.parse(f.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for dec in node.decorator_list:
                if not (isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute)):
                    continue
                method = dec.func.attr.lower()
                if method not in _WRITE_METHODS:
                    continue
                path = dec.args[0].value if (dec.args and isinstance(dec.args[0], ast.Constant)) else "?"
                yield f.name, method, path, node


def test_every_write_endpoint_declares_role_or_is_allowlisted():
    violations = []
    for fname, method, path, node in _iter_write_endpoints():
        if (fname, method, path) in ALLOWLIST:
            continue
        src = ast.unparse(node)
        if "RequireRole" in src:
            continue
        # 函数体内显式 role 校验也算(如 dlq.replay 的 admin 硬校验 + 拒绝审计);
        # ast.unparse 统一产出单引号, 两种写法都认
        if ('user.role' in src or "getattr(user, 'role'" in src
                or 'getattr(user, "role"' in src):
            continue
        violations.append(f"{fname}: {method.upper()} {path} -> {node.name}")

    assert not violations, (
        "以下变更型端点未声明角色要求(viewer 即可调用), 请加 RequireRole "
        "或入 ALLOWLIST 并写明理由:\n  " + "\n  ".join(violations)
    )


def test_allowlist_entries_all_exist():
    """豁免清单里的条目必须真实存在 —— 防止端点改名后豁免变死条目、
    也防止有人借"清单里有"的名义给新端点放水。"""
    existing = {(f, m, p) for f, m, p, _ in _iter_write_endpoints()}
    stale = [e for e in ALLOWLIST if e not in existing]
    assert not stale, f"ALLOWLIST 含不存在的端点(改名后请同步): {stale}"


def _required_roles(node) -> set:
    """从函数 AST 中提取全部 RequireRole(...) 的角色实参。"""
    roles: set = set()
    for sub in ast.walk(node):
        if (isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name)
                and sub.func.id == "RequireRole"):
            for a in sub.args:
                if isinstance(a, ast.Constant) and isinstance(a.value, str):
                    roles.add(a.value)
    return roles


def test_sensitive_endpoints_use_expected_roles():
    """抽查最高危端点的角色档位 —— 防止"补齐时全用 admin 一把梭"或全放 operator。"""
    expected = {
        ("response.py", "put", "/response/policies"): {"admin"},
        ("kafka.py", "post", "/cep/patterns/{pattern_id}/toggle"): {"admin"},
        # RequireRole("operator"): admin 角色在 RequireRole 内部恒通过(auth.py),
        # 所以声明 operator 即"operator+admin"
        ("response.py", "post", "/response/execute"): {"operator"},
        ("logs.py", "post", "/logs/reset-stuck"): {"operator"},
    }
    found = {}
    for fname, method, path, node in _iter_write_endpoints():
        key = (fname, method, path)
        if key in expected:
            found[key] = _required_roles(node)
    missing = {
        k: {"expected": sorted(v), "actual": sorted(found.get(k, set()))}
        for k, v in expected.items()
        if not v.issubset(found.get(k, set()))
    }
    assert not missing, f"高危端点角色档位不符: {missing}"
