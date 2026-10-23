"""
sigma_engine.backend_keywords — keywords 全文搜索兼容的 SQLite backend

背景:
    pySigma-backend-sqlite 的 SQLiteBackend 对 Sigma `keywords`(即 ConditionValueExpression,
    "value-only" 全文搜索)直接抛 SigmaFeatureNotSupportedByBackendError, 导致 SQLi/XSS/SSTI
    等大量使用 keywords 的 SigmaHQ web 规则无法编译接入。

本模块继承 SQLiteBackend, 重写 convert_condition_val_str/num:
  - 把 value-only 的 keywords 转成对"平台通用文本字段"的 OR LIKE 匹配,
    近似 Sigma "在所有字符串字段中搜索" 的语义, 又能在平台 web 事件上实际命中。
  - 匹配字段集合可用 KEYWORD_FIELDS 类常量配置(平台字段扩充时在此追加), 与
    sigma_engine/engine.py 的 _ensure_table 补列保持一致(字段列必须存在, 否则 SQL 报错)。

用法:
    在 sigma_engine/engine.py 中把 SQLiteBackend() 替换为 SigmaKeywordsBackend()。
"""

from sigma.backends.sqlite import sqliteBackend as SQLiteBackend
from sigma.conditions import ConditionValueExpression

# 平台 web 事件中承载文本内容的通用字段(keywords 匹配目标)。
# 必须与 engine._ensure_table 补齐的列集合一致。
#
# 整改方案 §六（P1-6）：修复前只有 6 个字段，关键字落在
# `user_agent` / `request_body` / `http.request.body` 等字段时**必然漏报**。
# 现在覆盖 Web 日志的常见载荷承载字段，并保留可配置入口。
KEYWORD_FIELDS = [
    # 平台字段
    "url",
    "cs-uri-query",
    "message",
    "details",
    "event",
    "http.url",
    # Web 载荷（原先缺失 → 关键字落在这里必然漏报）
    "user_agent",
    "user-agent",
    "http.user_agent",
    "request_body",
    "request-body",
    "http.request.body",
    "body",
    "http.body",
    "response_body",
    "http.response.body",
    "referer",
    "http.referer",
    "cookie",
    "http.cookie",
    "requestline",
    "http.request.line",
    "path",
    "uri",
    "query",
    "filename",
    "file",
    "command_line",
    "process",
    "host",
    "domain",
]


def _escape_like(value: str) -> str:
    """转义 LIKE 模式中的特殊字符(配合 ESCAPE '\\'): 反斜杠→\\\\, %→\\%, _→\\_。"""
    return (
        value
        .replace("\\", "\\\\")
        .replace("%", "\\%")
        .replace("_", "\\_")
        .replace("'", "''")  # SQL 字符串引号转义
    )

#: 数值字段的**数值语义**集合。
#:
#: 整改方案 §六（P1）：修复前 `convert_condition_val_num` 把数字也转成
#: 字符串 LIKE，于是「数值 12」会命中任何包含字符 "2" 的文本 ——
#: 语义被静默改成子串匹配。这里改为真正的数值相等/比较。
NUMERIC_FIELDS = [
    "src_port", "dst_port", "port", "status", "status_code", "http_status",
    "bytes", "bytes_in", "bytes_out", "size", "length", "duration",
]


def _unwrap_number(value):
    """pySigma 1.5 把条件值包成 SigmaNumber / SigmaString 等类型。

    取回原始标量；不认识的类型直接抛错（让规则编译失败并被记录），
    不做静默近似 —— 整改方案 §六要求「不支持时显式报错」。
    """
    for attr in ("number", "value", "original_value"):
        inner = getattr(value, attr, None)
        if isinstance(inner, (int, float)) and not isinstance(inner, bool):
            return inner
    if isinstance(value, bool):
        raise TypeError(f"boolean is not a valid numeric keyword: {value!r}")
    if isinstance(value, (int, float)):
        return value
    if isinstance(value, str):
        return value            # 数字字符串由上层解析
    raise TypeError(
        f"unsupported numeric keyword type: {type(value).__name__} ({value!r})")


class SigmaKeywordsBackend(SQLiteBackend):
    """SQLite backend 扩展: 支持 Sigma keywords(value-only)全文搜索。"""

    #: 可通过子类/实例覆盖, 用于平台字段扩充。
    KEYWORD_FIELDS = KEYWORD_FIELDS
    #: 数值语义字段（不参与文本 LIKE）
    NUMERIC_FIELDS = NUMERIC_FIELDS

    def _keyword_like_expr(self, value: str) -> str:
        """为每个文本字段生成 `f LIKE '%value%' ESCAPE '\\'`, 用 OR 连接。"""
        escaped = _escape_like(value)
        parts = []
        for field in self.KEYWORD_FIELDS:
            qf = f"{self.field_quote}{field}{self.field_quote}"
            parts.append(f"{qf} LIKE '%{escaped}%' ESCAPE '\\'")
        return "(" + " OR ".join(parts) + ")"

    def convert_condition_val_str(
        self, cond: ConditionValueExpression, state
    ):
        """value-only 字符串(keywords) → 对文本字段的 OR LIKE。"""
        value = cond.value
        return self._keyword_like_expr(str(value))

    def convert_condition_val_num(
        self, cond: ConditionValueExpression, state
    ):
        """value-only 数字(keywords) → **数值相等**, 不再是字符串子串匹配。

        整改方案 §六：原实现 `self._keyword_like_expr(str(cond.value))` 让
        「数值 12」命中任何含字符 "2" 的文本。改为对数值语义字段做
        精确相等，并保留文本字段的 LIKE 作为兜底（Sigma keywords 本身
        允许在文本里出现数字）。

        值的绑定仍走 backend 既有的字面量机制，与字符串分支保持一致。
        """
        raw = _unwrap_number(cond.value)
        num = float(raw)
        # 整数不做浮点表示，避免 12.0 这种字面量
        literal = str(int(num)) if float(num).is_integer() else repr(num)
        parts = []
        for field in self.NUMERIC_FIELDS:
            qf = f"{self.field_quote}{field}{self.field_quote}"
            # SQLite 的 TEXT 列存的是字符串，用 CAST 做数值比较
            parts.append(f"CAST({qf} AS REAL) = {literal}")
        if parts:
            return "(" + " OR ".join(parts) + ")"
        # 没有配置数值字段时退回文本匹配（保持可编译）
        return self._keyword_like_expr(str(raw))
