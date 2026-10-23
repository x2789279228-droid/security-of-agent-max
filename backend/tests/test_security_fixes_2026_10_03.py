"""
2026-10-03 全量审计修复的回归测试 (批次 0 / 批次 2 / 提交 1.1)。

这些测试针对【修复前会失败】的缺陷, 因此它们同时是"漏洞存在"的证明。
设计约束: 不依赖 PostgreSQL / Kafka / Redis —— sqlite 无 jsonb,
故 SQL 注入用"载荷必须被绑定、不得出现在 SQL 文本中"来断言(与数据库方言无关);
鉴权与中间件顺序用路由签名 / 源码位置做确定性契约断言。

覆盖:
  1. P0-22 rag/knowledge_base.py SQL 注入 (载荷必须走 bindparams)
  2. P0-22 /rag/* 端点鉴权契约 (任何端点都不得缺少 UserInfo 依赖)
  3. P0-19 CORS 中间件层级 (必须最后注册 = 最外层)
  4. P0-21 泄密门禁 (release.sh 规则 / .gitignore 覆盖)
"""
import ast
import re
from pathlib import Path

import pytest

BACKEND = Path(__file__).resolve().parent.parent
REPO = BACKEND.parent

# 注入载荷: 闭合单引号的 jsonb 过滤字面量
SQLI_PAYLOAD = "x']::jsonb OR 1=1--"


# ═══════════════════════════════════════════════════════════════
# 1. P0-22  SQL 注入
# ═══════════════════════════════════════════════════════════════

class _CaptureSession:
    """记录 execute() 收到的 statement 与 params, 返回空结果。"""

    def __init__(self):
        self.statements = []
        self.params = []

    async def execute(self, stmt, params=None):
        self.statements.append(stmt)
        self.params.append(params or {})
        scal = _EmptyScalars()
        return _Result(scal)

    # 便于直接取 compile 后的 SQL 文本
    def sql_texts(self):
        out = []
        for s in self.statements:
            try:
                out.append(str(s.compile(compile_kwargs={"literal_binds": False})))
            except Exception:
                out.append(str(s))
        return out


class _EmptyScalars:
    def all(self):
        return []


class _Result:
    def __init__(self, scal):
        self._scal = scal

    def scalars(self):
        return self._scal


def _is_text_with_bindparams(stmt) -> bool:
    """判断该 SQLAlchemy 表达式是否携带 bindparams(即值被参数化绑定)。"""
    try:
        compiled = stmt.compile(compile_kwargs={"literal_binds": False})
    except Exception:
        return False
    return bool(getattr(compiled, "params", None))


@pytest.mark.asyncio
async def test_threat_type_is_bound_not_interpolated():
    """P0-22: threat_type 含注入载荷时, 载荷不得出现在 SQL 文本里。"""
    from rag.knowledge_base import kb_manager

    sess = _CaptureSession()
    await kb_manager.search_documents(sess, threat_type=SQLI_PAYLOAD, limit=5)

    assert sess.statements, "search_documents 未执行任何语句"
    sql_blob = "\n".join(sess.sql_texts())

    assert SQLI_PAYLOAD not in sql_blob, (
        "注入载荷出现在编译后的 SQL 文本中 —— 仍存在 SQL 注入。"
        f"\nSQL: {sql_blob[:400]}"
    )
    # 正确实现应当使用命名占位符
    assert ":tt" in sql_blob or re.search(r":\w+", sql_blob), (
        f"未发现绑定参数, 疑似回退到字符串拼接。SQL: {sql_blob[:400]}"
    )


@pytest.mark.asyncio
async def test_tags_are_bound_not_interpolated():
    """P0-22: tags 列表同样必须走 bindparams。"""
    from rag.knowledge_base import kb_manager

    sess = _CaptureSession()
    await kb_manager.search_documents(sess, tags=[SQLI_PAYLOAD], limit=5)

    sql_blob = "\n".join(sess.sql_texts())
    assert SQLI_PAYLOAD not in sql_blob, (
        f"tags 注入载荷出现在 SQL 文本中。SQL: {sql_blob[:400]}"
    )


def test_no_fstring_sql_in_knowledge_base():
    """P0-22 静态守卫: 禁止把【值】拼进 jsonb 过滤的 text()。

    注: 正确实现仍需用 f-string 生成带序号的占位符名(如 :tag_0) —— 那是常量,
    不是用户值。因此这里只针对"把 json.dumps(...) 的结果插进 SQL"这一形态。
    """
    src = (BACKEND / "rag" / "knowledge_base.py").read_text(encoding="utf-8")
    # 去掉注释行(本文件含一段说明旧漏洞形态的注释, 不应触发守卫),
    # 同时用 ast 确保只看真实代码而非字符串字面量。
    code_lines = [
        ln for ln in src.splitlines()
        if not ln.lstrip().startswith("#")
    ]
    offenders = [
        ln.strip() for ln in code_lines
        if "json.dumps" in ln and "text(f" in ln
    ]
    assert not offenders, f"knowledge_base.py 中仍有把值拼进 SQL 的写法: {offenders}"

    tree = ast.parse(src)
    injected = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
            continue
        if node.func.id != "text" or not node.args:
            continue
        a = node.args[0]
        if isinstance(a, ast.JoinedStr):
            has_dumps = any(
                isinstance(v, ast.Call)
                and isinstance(v.func, ast.Attribute)
                and v.func.attr == "dumps"
                for v in ast.walk(a)
            )
            if has_dumps:
                injected.append(f"knowledge_base.py:{node.lineno}")
    assert not injected, f"存在把 json.dumps 结果拼进 text() 的调用: {injected}"


# ═══════════════════════════════════════════════════════════════
# 2. P0-22  /rag/* 鉴权契约
# ═══════════════════════════════════════════════════════════════

def _routes_of(node):
    """提取一个函数上的 (METHOD, path) 列表。"""
    out = []
    for d in node.decorator_list:
        if (
            isinstance(d, ast.Call)
            and isinstance(d.func, ast.Attribute)
            and d.func.attr in ("get", "post", "put", "delete", "patch")
            and d.args
            and isinstance(d.args[0], ast.Constant)
        ):
            out.append((d.func.attr.upper(), d.args[0].value))
    return out


def _arg_default_pairs(node):
    """正确配对 (参数, 默认值)。

    Python 的 `def f(a, b, c=1, d=2)` 中 args.defaults 只覆盖【后 N 个】位置参数,
    直接 zip(args.args, args.defaults) 会错位 —— 必须按偏移量对齐。
    """
    n_pos = len(node.args.args)
    n_def = len(node.args.defaults)
    offset = n_pos - n_def
    pairs = []
    for i, arg in enumerate(node.args.args):
        default = node.args.defaults[i - offset] if i >= offset else None
        pairs.append((arg, default))
    # 关键字参数
    for arg, default in zip(node.args.kwonlyargs, node.args.kw_defaults):
        pairs.append((arg, default))
    return pairs


def _auth_info(node):
    """返回 (has_auth, role_expr) —— 签名中是否存在 UserInfo 依赖。"""
    has_auth = False
    role_expr = ""
    for arg, default in _arg_default_pairs(node):
        ann = ast.unparse(arg.annotation) if arg.annotation else ""
        if "UserInfo" not in ann:
            continue
        has_auth = True
        if default is not None:
            role_expr = ast.unparse(default)
    return has_auth, role_expr


def _rag_endpoint_auth_status():
    """返回 [(method, path, has_userinfo_dep, role_expr)] for all /rag + /eval routes."""
    tree = ast.parse((BACKEND / "routers" / "rag.py").read_text(encoding="utf-8"))
    rows = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef)):
            continue
        routes = _routes_of(node)
        if not routes:
            continue
        has_auth, role_expr = _auth_info(node)
        for m, p in routes:
            rows.append((m, p, has_auth, role_expr))
    return rows


def test_rag_endpoints_all_require_auth():
    """P0-22: /rag/* 与 /eval/* 端点必须全部声明 UserInfo 依赖。"""
    rows = _rag_endpoint_auth_status()
    assert rows, "未解析到任何 /rag 路由 —— 测试本身可能失效"
    missing = [f"{m} {p}" for m, p, ok, _ in rows if not ok]
    assert not missing, f"以下端点缺少鉴权依赖: {missing}"


def test_rag_write_endpoints_require_admin():
    """P0-22: reseed / import 属写操作, 必须限 admin。"""
    tree = ast.parse((BACKEND / "routers" / "rag.py").read_text(encoding="utf-8"))
    must_be_admin = {
        ("POST", "/rag/reseed"),
        ("POST", "/rag/import/mitre"),
        ("POST", "/rag/import/capec"),
        ("POST", "/rag/import/all"),
    }
    found = {}
    for node in ast.walk(tree):
        if not isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef)):
            continue
        has_auth, role_expr = _auth_info(node)
        # ast.unparse 用单引号: Depends(RequireRole('admin'))
        is_admin = has_auth and re.search(r"RequireRole\(\s*['\"]admin['\"]\s*\)", role_expr)
        for r in _routes_of(node):
            found[r] = bool(is_admin)

    for key in must_be_admin:
        assert key in found, f"未找到路由 {key} —— 测试可能失效"
        assert found[key], f"{key[1]} 是写操作, 必须限 RequireRole('admin')"


# ═══════════════════════════════════════════════════════════════
# 3. P0-19  CORS 中间件层级
# ═══════════════════════════════════════════════════════════════

def test_cors_registered_last():
    """P0-19: CORS 必须最后注册(Starlette insert(0) → 最后注册 = 最外层)。

    若 CORS 先于 auth/rate_limit 注册, 它落在最内层;
    auth/rate_limit 用 return JSONResponse 直接返回 401/403/429(不经过 call_next),
    这些响应就不会带 Access-Control-Allow-Origin。
    """
    src = (BACKEND / "app.py").read_text(encoding="utf-8-sig")
    lines = src.splitlines()

    cors_line = None
    other_reg_lines = []
    for i, ln in enumerate(lines, start=1):
        # add_middleware(...) 是多行调用, 参数在下一行 —— 必须看下一行
        if re.match(r"^\s*app\.add_middleware\(", ln):
            nxt = lines[i] if i < len(lines) else ""
            if "CORSMiddleware" in nxt or "CORSMiddleware" in ln:
                cors_line = i
            else:
                other_reg_lines.append(i)
        if re.match(r"^\s*@app\.middleware\(", ln):
            other_reg_lines.append(i)

    assert cors_line is not None, "未找到 CORSMiddleware 注册"
    assert other_reg_lines, "未找到其他中间件注册 —— 测试可能失效"

    last_other = max(other_reg_lines)
    assert cors_line > last_other, (
        f"CORS 注册在 L{cors_line}, 但其他中间件注册到了 L{last_other} —— "
        "CORS 未处于最外层, 401/403/429 将缺少 Access-Control-Allow-Origin"
    )


def test_cors_actually_outermost_at_runtime():
    """P0-19 运行时验证(比源码行号断言更强)。

    直接检查 app.user_middleware 的实际顺序: index 0 = 最外层 = 最先执行。
    期望: [0] CORSMiddleware → [1] Metrics → [2] HttpTrace →
          [3] rate_limit → [4] auth
    """
    import os
    os.environ.setdefault("SHARED_MEMORY_DATABASE_URL", "sqlite+aiosqlite:///:memory:")
    os.environ.setdefault("SHARED_MEMORY_JWT_SECRET", "test-secret")
    os.environ.setdefault("SHARED_MEMORY_ADMIN_PASSWORD", "test")
    os.environ.setdefault("SHARED_MEMORY_LLM_API_KEY", "test")
    os.environ.setdefault("SHARED_MEMORY_EMBEDDING_API_KEY", "test")

    from app import app  # noqa: E402

    names = [mw.cls.__name__ for mw in app.user_middleware]
    assert "CORSMiddleware" in names, f"未注册 CORSMiddleware: {names}"
    idx = names.index("CORSMiddleware")
    assert idx == 0, (
        f"CORS 未处于最外层 —— 实际顺序 {names}。"
        "auth/rate_limit 用 return JSONResponse 直接返回 401/403/429, "
        "不经过 call_next, 因此不会被 CORS 包装。"
    )


def test_cors_headers_preserved():
    """回归: 移动 CORS 时不能丢掉原有配置项。"""
    src = (BACKEND / "app.py").read_text(encoding="utf-8-sig")
    for token in (
        "CORSMiddleware",
        "allow_origins=json.loads(settings.allowed_origins)",
        "allow_credentials=True",
        "allow_headers",
    ):
        assert token in src, f"CORS 配置项丢失: {token}"


# ═══════════════════════════════════════════════════════════════
# 4. P0-21  泄密门禁
# ═══════════════════════════════════════════════════════════════

def test_release_script_covers_known_leaked_paths():
    """P0-21: release.sh 必须能拦住 2026-10-03 实际检出的全部泄露类型。"""
    script = (REPO / "tools" / "release.sh").read_text(encoding="utf-8")
    patterns_line = next(
        (ln for ln in script.splitlines() if ln.startswith("SECRET_PATTERNS=")), ""
    )
    assert patterns_line, "未找到 SECRET_PATTERNS 定义"
    for token in (r"\.env", r"certs/", r"\.pem$", r"\.p12$", "firewall_key",
                  "htpasswd$", "flink-credentials", "-creds$"):
        assert token in patterns_line, f"泄密规则缺失: {token}"


def test_release_script_allows_example_templates():
    """.env.example / .env.demo.example 是文档模板, 已被逐条核对无真实凭证, 必须放行。"""
    script = (REPO / "tools" / "release.sh").read_text(encoding="utf-8")
    assert "ALLOW_PATTERNS=" in script, "缺少白名单定义"
    allow_line = next(
        (ln for ln in script.splitlines() if ln.startswith("ALLOW_PATTERNS=")), ""
    )
    assert r"\.example" in allow_line, "白名单未放行 *.example 模板"


def test_gitignore_covers_keystores():
    """P0-21: .gitignore 必须覆盖 keystore / truststore / 口令文件。"""
    gi = (REPO / ".gitignore").read_text(encoding="utf-8")
    for token in ("certs/", "*.p12", "*.jks", "*-creds",
                  "config/nginx/flink-credentials.txt", "config/ssh/"):
        assert token in gi, f".gitignore 未覆盖: {token}"


def test_env_example_documents_security_defaults():
    """P0-21/批次3: 安全默认必须出现在 .env.example, 否则部署会静默用危险代码默认值。"""
    env = (REPO / ".env.example").read_text(encoding="utf-8")
    for token in (
        "SHARED_MEMORY_CONTROL_HMAC_KEY",
        "SHARED_MEMORY_EXECUTION_MODE",
        "SHARED_MEMORY_ALLOW_SELF_REGISTRATION",
    ):
        assert token in env, f".env.example 缺少 {token} —— 部署将回落到代码默认值"


# ═══════════════════════════════════════════════════════════════
# 5. 依赖健康探针 —— 修掉"前端绿色硬编码，但数据源根本不存在"
# ═══════════════════════════════════════════════════════════════

def test_health_stays_a_liveness_probe_only():
    """/health 是静态存活探针，**不得**改造成依赖探测。

    保持它公开、无依赖、开销恒定，是 LB/k8s 探针的正确用法；
    依赖可达性放在 /health/dependencies（需鉴权）。
    """
    src = (BACKEND / "routers" / "auth.py").read_text(encoding="utf-8-sig")
    m = re.search(r'@router\.get\("/health"\)\s*\nasync def health\(\):(.*?)\n\n\n', src, re.S)
    assert m, "未找到 /health 端点"
    body = m.group(1)
    for forbidden in ("probe_dependencies", "SELECT 1", "ping()"):
        assert forbidden not in body, f"/health 不应包含 {forbidden} —— 它必须保持恒定开销"


def test_dependencies_endpoint_is_auth_gated():
    """依赖探测的 detail 含内部地址/错误原文，必须鉴权，不得进 _PUBLIC_PATHS。"""
    src = (BACKEND / "routers" / "auth.py").read_text(encoding="utf-8-sig")
    m = re.search(
        r'@router\.get\("/health/dependencies"\)\s*\nasync def health_dependencies\((.*?)\):',
        src, re.S,
    )
    assert m, "未找到 /health/dependencies 端点"
    assert "get_current_user" in m.group(1), "依赖探针端点必须要求鉴权"

    app_src = (BACKEND / "app.py").read_text(encoding="utf-8-sig")
    pub = re.search(r"_PUBLIC_PATHS\s*=\s*frozenset\(\{(.*?)\}\)", app_src, re.S)
    assert pub, "未找到 _PUBLIC_PATHS"
    assert "/api/health/dependencies" not in pub.group(1), "依赖探针不得公开"


def test_frontend_health_gauge_no_longer_hardcoded_ok():
    """前端初值不得再是 'ok' —— 否则探测未返回时就显示绿色 NOMINAL。"""
    fe = REPO / "frontend" / "src" / "stores" / "serviceStore.ts"
    src = fe.read_text(encoding="utf-8")
    assert not re.search(r"services:\s*\{[^}]*'ok'", src), "serviceStore 初值不得含 'ok'"
    assert "'unknown'" in src, "必须存在 unknown 态"
    assert "setUnprobed" in src, "探测请求失败时需能回落 unknown"


def test_frontend_routes_no_longer_bypass_guard():
    """App.tsx 不得再有 page(<X />, false) 形式的鉴权绕过。"""
    src = (REPO / "frontend" / "src" / "App.tsx").read_text(encoding="utf-8")
    code = "\n".join(
        ln for ln in src.splitlines()
        if not ln.strip().startswith(("//", "*"))
    )
    bypasses = re.findall(r"page\(<[^>]+\/>\s*,\s*false\s*\)", code)
    assert not bypasses, f"仍有路由绕过 Guard: {bypasses}"
    assert "<Guard>" in code, "Guard 未被使用"


def test_destructive_response_actions_require_confirm():
    """威胁模拟/手动执行/回滚必须经确认弹窗（对应后端 P0-3 的前端侧防线）。"""
    src = (REPO / "frontend" / "src" / "pages" / "Response.tsx").read_text(encoding="utf-8")
    code = "\n".join(
        ln for ln in src.splitlines()
        if not ln.strip().startswith(("//", "*"))
    )
    assert not re.search(r"onClick=\{\(\) => simulateThreat\(", code), "仍有按钮直连 simulateThreat"
    assert "requestSimulate" in code and "requestExecResponse" in code and "requestRollback" in code
    assert "<ConfirmDialog" in code, "未挂载 ConfirmDialog"

    dialog = (REPO / "frontend" / "src" / "components" / "ui" / "ConfirmDialog.tsx").read_text(encoding="utf-8")
    assert 'role="alertdialog"' in dialog and "aria-modal" in dialog
    assert "Escape" in dialog, "确认弹窗需支持 Esc 关闭"


# ═══════════════════════════════════════════════════════════════
# 6. 替代失效的 ccs-lint —— 用可版本控制的真实测试守住同一不变量
# ═══════════════════════════════════════════════════════════════
# 原 CI job 调 `npx -y ccs-lint` 并配 `continue-on-error: true` + `|| echo`，
# 使它**恒绿且不可能失败**（工具 1.0.2 缺 src/lint.js）。
# 它真正要守的不变量是「MCP 工具参数不接受嵌套/多余字段注入」——
# 这条不变量在 mcp_guard/validator.py 里由 ConfigDict(extra="forbid") 真正实现，
# 因此可以、也应该用一条真实的测试来守，而不是依赖一个坏掉的 npm 包。

def test_mcp_arg_models_forbid_extra_fields():
    """每个工具参数模型都必须 extra='forbid' —— 嵌套字段注入的第一道闸。"""
    from mcp_guard.validator import TOOL_ARG_MODELS

    assert TOOL_ARG_MODELS, "未找到任何工具参数模型"
    for name, model_cls in TOOL_ARG_MODELS.items():
        assert model_cls.model_config.get("extra") == "forbid", (
            f"工具 {name} 的参数模型未禁止多余字段 —— 协议级字段注入可绕过校验"
        )


def test_mcp_validator_rejects_injected_fields():
    """伪造字段 / 嵌套走私字段 / 越界值都必须被拒。"""
    from mcp_guard.validator import ParamValidator

    v = ParamValidator()

    # 1) 顶层多余字段
    ok, msg, _ = v.validate("block_ip", {"ip": "1.2.3.4", "escalate": True})
    assert ok is False, f"多余字段被接受: {msg}"

    # 2) 嵌套走私：把真正的参数藏进子对象
    ok, msg, _ = v.validate("block_ip", {"ip": "1.2.3.4", "meta": {"escalate": True}})
    assert ok is False, f"嵌套走私字段被接受: {msg}"

    # 3) 越界值（duration 超出 le=86400）
    ok, msg, _ = v.validate("block_ip", {"ip": "1.2.3.4", "duration": 10 ** 9})
    assert ok is False, f"越界 duration 被接受: {msg}"

    # 4) 非法 IP（自定义 field_validator）
    ok, msg, _ = v.validate("block_ip", {"ip": "not-an-ip"})
    assert ok is False, f"非法 IP 被接受: {msg}"

    # 5) 未知工具名
    ok, msg, _ = v.validate("__proto__", {"x": 1})
    assert ok is False, f"未知工具名被接受: {msg}"

    # 6) 正常参数仍应通过（防止把闸门修成"永远拒绝"）
    ok, msg, norm = v.validate("block_ip", {"ip": "203.0.113.9"})
    assert ok is True, f"合法参数被误拒: {msg}"
    assert norm.get("duration") == 3600, f"默认值未补齐: {norm}"


def test_hmac_key_fails_closed_when_unconfigured(monkeypatch):
    """P0-6: 缺密钥必须抛异常，绝不能回退到源码内的公开常量。

    这条测试在修复前**无法通过**：原实现回退到 b"dev-hmac-unconfigured"，
    而 test_control_plane_security.py 从不固定密钥，因此永远绿。
    """
    from config import settings
    from security_crypto import control_hmac_key, hmac_hex

    monkeypatch.setattr(settings, "control_hmac_key", "")
    monkeypatch.setattr(settings, "jwt_secret", "")

    with pytest.raises(RuntimeError, match="control_hmac_key"):
        control_hmac_key()
    with pytest.raises(RuntimeError):
        hmac_hex("anything")

    # 兜底: 源码里不得再残留该公开常量（只看【可执行】代码 ——
    #        排除注释与 docstring，本模块的 docstring 正是为记录这段历史而提到它）
    import ast as _ast

    tree = _ast.parse((BACKEND / "security_crypto.py").read_text(encoding="utf-8"))

    docstring_nodes = set()
    for parent in _ast.walk(tree):
        body = getattr(parent, "body", None)
        if isinstance(parent, (_ast.Module, _ast.ClassDef, _ast.FunctionDef, _ast.AsyncFunctionDef)):
            if body and isinstance(body[0], _ast.Expr) and isinstance(body[0].value, _ast.Constant):
                docstring_nodes.add(id(body[0].value))

    for node in _ast.walk(tree):
        if id(node) in docstring_nodes:
            continue
        val = getattr(node, "value", None) if isinstance(node, _ast.Constant) else None
        if isinstance(val, (str, bytes)) and b"dev-hmac-unconfigured" in (
            val if isinstance(val, bytes) else val.encode()
        ):
            raise AssertionError(
                f"security_crypto.py:{getattr(node, 'lineno', '?')} 仍含公开兜底常量（可执行代码中）"
            )
