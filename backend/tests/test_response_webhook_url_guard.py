# -*- coding: utf-8 -*-
"""告警 webhook 的 URL 安全边界 + 动作参数审计（整改报告 §9.61）。

## 背景

整改方案 §五 给沙箱入口定了 URL 安全边界（只允许 http/https；拒绝
loopback / link-local / 私有地址 / 云元数据地址；重定向目标重新校验）。
**同一个平台还有第二个接受 URL 的面** —— 响应引擎的告警 webhook
（`send_alert` 的 `webhook_url` 参数）—— 而它**完全没有这套限制**。

实测（2026-10-20，修复前）：

* 平台**真的**把请求发到了 `http://127.0.0.1:<port>/internal-only`
  （本地监听器收到了），并把 `status_code` 带回来（= 内网探测 oracle）；
* 同一个 URL 被平台**自己**的 `validate_submittable_url` 拒绝
  （`loopback_not_allowed`）—— **同一平台、两个面，一个拦一个不拦**；
* 到达路径：真实 SecurityGuard（`send_alert` 的 severity 是 **low**，
  不是 critical → 手动执行端点**不拦**它）+ `operator` 角色即可。

另一条独立的缺陷：响应日志的 `action_params` 只有
`{execution_mode, verified, error}` —— **动作的实际参数全都不在里面**
（`webhook_url` / `src_ip` / `duration_minutes` …）。于是「这个动作到底
对什么做了什么」在审计里查不到（参数只存在于回滚存储里，那是回滚用的，
不是审计面）。

## 本守卫盯什么

1. **决定性（网络层）**：loopback 目标**收不到任何请求**；
2. **决定性（调用层）**：禁止目标**根本不会走到 HTTP 调用**；
   合法目标**会**走到（防过度收紧）；
3. **审计**：动作参数必须进 `action_params`，敏感键必须脱敏；
4. **诚实性**：未实现的通知渠道必须**明确失败**并给出原因，
   且不得在 `params_schema` 里宣传。

> **为什么「合法目标收到请求」不在网络层断言**：本机（Windows + 私有
> profile 防火墙）连**自己的私有 IP**都会被拦（实测 ReadTimeout），
> 而 loopback 又恰好是被禁的那一类 → 网络层没有「既合法又可达」的
> 本地目标。正向证明改在**调用层**（HTTP 客户端是否被调用）。
> 网络层的负向证明（loopback 收不到）仍然是真网络证据。
"""
from __future__ import annotations

import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND))


class _Recorder(BaseHTTPRequestHandler):
    """记录收到的请求（证明「请求到底有没有发出去」）。"""

    received: list = []

    def do_POST(self):                        # noqa: N802
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n) if n else b""
        _Recorder.received.append(
            {"path": self.path, "body": body.decode("utf-8", "replace")})
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"ok":true}')

    def log_message(self, *a):
        pass


@pytest.fixture(scope="module")
def listener():
    srv = HTTPServer(("0.0.0.0", 0), _Recorder)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield srv
    srv.shutdown()


@pytest.fixture
def http_calls(monkeypatch):
    """把 `httpx.AsyncClient.post` 换成记录器 —— 断言「有没有走到 HTTP 调用」。"""
    import httpx

    calls: list = []

    class _Resp:
        status_code = 200

        def raise_for_status(self):
            pass

    async def _fake_post(self, url, **kw):
        calls.append({"url": str(url), "json": kw.get("json")})
        return _Resp()

    monkeypatch.setattr(httpx.AsyncClient, "post", _fake_post, raising=True)
    yield calls


@pytest.fixture(autouse=True)
def _clear_received():
    _Recorder.received.clear()
    yield
    _Recorder.received.clear()


def _run(coro):
    import asyncio
    return asyncio.run(coro)


class TestTheLoopbackIsRejected:
    def test_the_request_never_reaches_a_loopback_listener(self, listener):
        """**决定性（网络层）**：loopback 目标**收不到任何请求**。

        这一条是「真的没发出去」，不是「返回了一个错误」——
        监听器里没有记录，才是证据。
        """
        from response_engine.response_registry import _send_webhook
        port = listener.server_address[1]
        url = f"http://127.0.0.1:{port}/internal-only"
        res = _run(_send_webhook("t", "m", "high", url))
        assert not _Recorder.received, (
            f"平台把请求发到了 loopback！收到：{_Recorder.received}")
        assert res.get("success") is False, res
        assert res.get("rejected") is True, res
        assert "loopback_not_allowed" in (res.get("error") or ""), res

    def test_a_forbidden_target_never_reaches_the_http_client(self, http_calls):
        """**决定性（调用层）**：禁止目标**根本不会走到 HTTP 调用**。"""
        from response_engine.response_registry import _send_webhook
        res = _run(_send_webhook(
            "t", "m", "high", "http://169.254.169.254/latest/meta-data/"))
        assert http_calls == [], f"仍然发起了请求：{http_calls}"
        assert res.get("rejected") is True, res

    @pytest.mark.parametrize("url,expect", [
        ("http://169.254.169.254/latest/meta-data/", "cloud_metadata_blocked"),
        ("http://metadata.google.internal/computeMetadata/v1/", "cloud_metadata_blocked"),
        ("file:///etc/passwd", "scheme_not_allowed"),
        ("gopher://127.0.0.1:6379/_INFO", "scheme_not_allowed"),
        ("http://[::1]:8080/x", "loopback_not_allowed"),
        ("http://169.254.10.1/x", "link_local_not_allowed"),
    ])
    def test_the_forbidden_targets_are_rejected(self, url, expect):
        """禁止目标必须被拒，且拒绝原因要说清是哪一条。"""
        from response_engine.response_registry import _check_webhook_url
        ok, reason = _check_webhook_url(url)
        assert ok is False, f"{url} 被放行了（reason={reason}）"
        assert reason == expect, f"{url} 的拒绝原因不对：{reason} != {expect}"


class TestTheLegitTargetStillWorks:
    """**反向**判据：修复不得把正常部署形态一起拒掉。"""

    def test_a_private_address_is_accepted(self):
        """内网告警接收方（私有地址）必须**放行**。

        沙箱那侧的口径是 `allow_private=True` 只放开 RFC1918 私有段，
        webhook 沿用同一口径 —— 否则所有内网告警部署都会被打断。
        """
        from response_engine.response_registry import _check_webhook_url
        ok, reason = _check_webhook_url("http://10.0.0.5:8080/alerts")
        assert ok is True, f"私有地址被拒了（reason={reason}）—— 正常部署会断"

    def test_a_https_public_target_is_accepted(self):
        from response_engine.response_registry import _check_webhook_url
        ok, reason = _check_webhook_url("https://alerts.example.com/hook")
        assert ok is True, f"公网 https 目标被拒了（reason={reason}）"

    def test_a_private_target_reaches_the_http_client(self, http_calls):
        """**正向**：私有地址目标**确实走到了 HTTP 调用**（证明没被误杀）。"""
        from response_engine.response_registry import _send_webhook
        url = "http://10.0.0.5:8080/alerts"
        res = _run(_send_webhook("t", "m", "high", url))
        assert len(http_calls) == 1, f"合法目标没有走到 HTTP 调用：{http_calls}"
        assert http_calls[0]["url"] == url, http_calls
        assert res.get("success") is True, res
        assert res.get("rejected") is not True, res


class TestTheAuditSeesTheTarget:
    def test_the_action_params_reach_the_response_log(self):
        """动作的**实际参数**必须进 `action_params`（审计面）。

        ⚠ 2026-10-20（§9.63）**契约更正**：本断言原先要求审计里出现
        **原样的** `webhook_url` —— 而告警 webhook 的 URL **通常内嵌密钥**
        （`?key=` / `?access_token=` / 路径段里的 token），
        响应日志又是**任何登录用户**可读的 → 那条断言**强制**了泄漏。
        现在改成**更强**的形式：既要求目标**可定位**（主机在），
        又要求**密钥不在**。
        """
        from response_engine.response_orchestrator import action_rows_from_batch
        from response_engine.response_executor import (
            ActionResult, BatchActionResult, redact_action_params,
        )
        secret = "SUPERSECRETKEY"
        params = {"channel": "webhook",
                  "webhook_url": f"https://alerts.example.com/hook/{secret}?k=1",
                  "title": "t", "message": "m"}
        batch = BatchActionResult(
            total=1, succeeded=1, failed=0,
            results=[ActionResult(action_name="send_alert", success=True,
                                  result={"mode": "webhook"},
                                  params=redact_action_params(params))],
        )
        rows = action_rows_from_batch(batch, {"src_ip": "1.2.3.4"}, "p", True)
        assert rows, "没有生成日志行"
        got = rows[0]["action_params"].get("params") or {}
        recorded = got.get("webhook_url") or ""
        assert recorded, f"审计里没有动作的目标：{rows[0]['action_params']}"
        assert "alerts.example.com" in recorded, (
            f"审计里的目标认不出来了（要能回答「发到哪台机器」）：{recorded}")
        assert secret not in recorded, (
            f"密钥落进审计行了：{recorded}")
        # 既有字段不能被挤掉
        assert rows[0]["action_params"]["execution_mode"] == "webhook", (
            rows[0]["action_params"])

    def test_sensitive_params_are_redacted(self):
        """敏感键的值必须脱敏（但**键名保留**）。"""
        from response_engine.response_executor import redact_action_params
        out = redact_action_params({
            "src_ip": "10.0.0.1",
            "ssh_password": "hunter2",
            "api_token": "abc123",
            "message": "x" * 900,
        })
        assert out["src_ip"] == "10.0.0.1", out
        assert out["ssh_password"] == "***", out
        assert out["api_token"] == "***", out
        assert "ssh_password" in out, "键名必须保留 —— 它本身就是信息"
        assert len(out["message"]) < 900, "超长值必须截断"

    def test_the_executor_carries_the_params_all_the_way(self, http_calls):
        """**端到端**：执行器 → ActionResult → 日志行，参数一路都在。

        这条是**补**上一条漏掉的：上面那条是自己**造**一个带参数的
        `ActionResult` 再喂给 `action_rows_from_batch` ——
        于是「执行器压根没把参数挂到结果上」这种真缺陷**测不出来**
        （第一次注入验红就撞上了：Z6 注入后守卫**没红**）。
        真正会漏的地方在**接线**上，所以必须走真实执行器。
        """
        from response_engine.response_executor import (
            BatchActionResult, ResponseExecutor,
        )
        from response_engine.response_orchestrator import action_rows_from_batch
        secret = "SUPERSECRETKEY"
        url = f"https://alerts.example.com/hook/{secret}"
        res = _run(ResponseExecutor()._execute_one(
            {"name": "send_alert",
             "params": {"channel": "webhook", "webhook_url": url,
                        "title": "t", "message": "m"}},
            {"src_ip": "1.2.3.4", "threat_type": "X", "confidence": 1.0}))
        recorded = res.params.get("webhook_url") or ""
        assert recorded, f"执行器没有把参数挂到结果上：{res.params}"
        # §9.63：目标要**可定位**，但密钥不得跟进来
        assert "alerts.example.com" in recorded, recorded
        assert secret not in recorded, f"密钥跟着进了结果：{recorded}"
        rows = action_rows_from_batch(
            BatchActionResult(total=1, succeeded=1, failed=0, results=[res]),
            {"src_ip": "1.2.3.4"}, "p", True)
        got = rows[0]["action_params"].get("params") or {}
        assert "alerts.example.com" in (got.get("webhook_url") or ""), (
            rows[0]["action_params"])


class TestTheUnsupportedChannelFailsLoudly:
    def test_an_unimplemented_channel_fails_with_a_reason(self):
        """未实现的渠道必须**明确失败**并给出原因（不再静默降级）。"""
        from response_engine.response_registry import _send_alert
        res = _run(_send_alert(title="t", message="m", severity="high",
                               channel="dingtalk"))
        assert res.get("success") is False, res
        assert "unsupported_channel" in (res.get("error") or ""), res

    def test_the_schema_does_not_advertise_unimplemented_channels(self):
        """`params_schema` 是给调用方看的声明 —— 不得宣传没实现的渠道。"""
        from response_engine.response_registry import response_registry
        schema = response_registry.get_action("send_alert").params_schema or {}
        blob = str(schema)
        for channel in ("dingtalk", "wework", "wechat"):
            assert channel not in blob, (
                f"params_schema 仍在宣传未实现的渠道 {channel}：{blob}")
        assert "webhook" in blob, blob
