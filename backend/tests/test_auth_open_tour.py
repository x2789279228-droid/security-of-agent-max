"""开放体验模式(auth_open_tour)测试 —— 评审直通开关的双态守卫。

语义:
  - on:  无 token 访问任何受保护端点 → 200, 身份一律 admin/Visitor;
        治理语义不因直通而放松(以 MCP guard RBAC 为证: 协议层角色映射
        仍生效, 只不过 Visitor 是 admin)
  - off: 认证行为与历史完全一致(无 token → 401/403)

无需 pytest-asyncio: TestClient 同步驱动。
"""
from fastapi.testclient import TestClient


def _client():
    from app import app
    return TestClient(app)


def test_mode_endpoint_reports_off_by_default():
    r = _client().get("/api/auth/mode")
    assert r.status_code == 200
    assert r.json() == {"open_tour": False}


def test_off_requires_token(monkeypatch):
    from config import settings
    monkeypatch.setattr(settings, "auth_open_tour", False)
    # 受保护端点(RequireRole): 无 token 不得通过
    r = _client().post("/api/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "ping"})
    assert r.status_code in (401, 403), f"关闭态必须拦: {r.status_code}"


def test_on_grants_admin_visitor_without_token(monkeypatch):
    from config import settings
    monkeypatch.setattr(settings, "auth_open_tour", True)

    c = _client()
    # 1) 模式端点如实上报
    assert c.get("/api/auth/mode").json() == {"open_tour": True}
    # 2) 无 token 通过 RequireRole 端点(MCP 协议层, admin/operator)
    r = c.post("/api/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "ping"})
    assert r.status_code == 200
    assert r.json()["result"] == {}
    # 3) 无 token 的 MCP tools/call 走 guard —— Visitor=admin 角色, allow 类工具可调
    r = c.post("/api/mcp", json={
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": "alert_only", "arguments": {"message": "open-tour probe"}},
    })
    assert r.status_code == 200
    assert r.json()["result"]["isError"] is False, "直通身份应为 admin(全工具可用)"


def test_on_identity_is_admin_visitor(monkeypatch):
    from config import settings
    monkeypatch.setattr(settings, "auth_open_tour", True)
    from auth import get_current_user
    import asyncio
    user = asyncio.run(get_current_user(credentials=None))
    assert user.role == "admin"
    assert user.username == "Visitor"
