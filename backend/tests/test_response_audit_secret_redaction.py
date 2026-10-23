# -*- coding: utf-8 -*-
"""审计与日志里的 URL 必须**脱敏**（整改报告 §9.63）。

## 背景

§9.61 把动作的**实际参数**写进了响应日志 —— 这是对的：审计要能回答
「这个动作对什么做了什么」。但告警 webhook 的 URL **通常内嵌密钥**：

    Slack    https://hooks.slack.com/services/T00/B00/<SECRET>
    钉钉     https://oapi.dingtalk.com/robot/send?access_token=<SECRET>
    企业微信  https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=<SECRET>

而 `GET /response/logs` 只要**任何登录用户**（`get_current_user`，无角色门槛）
→ URL 原样落盘 = **把告警通道的钥匙发给全体登录用户**（他们可以往
SOC 的告警通道里注入任意消息）。

⇒ URL 一律记成 `scheme://host[:port]/<路径首段>#sha256:<完整URL哈希前12位>`：
仍能回答「发到哪台机器、哪条通道」，同一个目标在不同日志里仍**可关联**，
但密钥不落盘。

## 本守卫盯什么

1. **审计面**：动作参数里的 URL 不得含密钥（路径尾段 / 查询串 / userinfo）；
2. **应用日志**：发送/拒绝的日志行同样不得含密钥；
3. **可关联性**：脱敏后仍能定位主机，且同一 URL 的脱敏结果**稳定**；
4. **不过度脱敏**：非 URL 的参数照旧可见（别把审计变成一串 `***`）。
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND))

from response_engine.response_executor import redact_action_params  # noqa: E402
from response_engine.response_registry import redact_url_for_log   # noqa: E402

SECRET = "SUPERSECRETKEY"

#: 三种常见的「URL 内嵌密钥」形态
SECRET_URLS = [
    f"https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key={SECRET}",
    f"https://oapi.dingtalk.com/robot/send?access_token={SECRET}",
    f"https://hooks.slack.com/services/T00/B00/{SECRET}",
    f"https://user:{SECRET}@alerts.example.com/hook",
]


def _run(coro):
    import asyncio
    return asyncio.run(coro)


class TestTheAuditDoesNotLeakTheSecret:
    @pytest.mark.parametrize("url", SECRET_URLS)
    def test_the_redacted_url_has_no_secret(self, url):
        out = redact_url_for_log(url)
        assert SECRET not in out, f"密钥泄漏在脱敏结果里：{out}"

    def test_the_audit_row_has_no_secret(self):
        """**端到端**：审计行（`action_params`）里不得含密钥。"""
        from response_engine.response_executor import (
            ActionResult, BatchActionResult,
        )
        from response_engine.response_orchestrator import action_rows_from_batch
        url = f"https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key={SECRET}"
        params = {"channel": "webhook", "webhook_url": url,
                  "title": "t", "message": "m"}
        batch = BatchActionResult(
            total=1, succeeded=1, failed=0,
            results=[ActionResult(action_name="send_alert", success=True,
                                  result={"mode": "webhook"},
                                  params=redact_action_params(params))],
        )
        rows = action_rows_from_batch(batch, {"src_ip": "1.2.3.4"}, "p", True)
        blob = str(rows)
        assert SECRET not in blob, f"密钥落进审计行了：{blob}"

    def test_the_query_string_is_dropped(self):
        out = redact_url_for_log(
            f"https://alerts.example.com/hook?key={SECRET}&x=1")
        assert "key=" not in out, out
        assert "x=1" not in out, out


class TestTheLogsDoNotLeakTheSecret:
    def test_the_send_log_has_no_secret(self, monkeypatch, caplog):
        """应用日志（发送成功那行）同样不得含密钥。"""
        import httpx
        from response_engine.response_registry import _send_webhook

        class _Resp:
            status_code = 200

            def raise_for_status(self):
                pass

        async def _fake_post(self, url, **kw):
            return _Resp()

        monkeypatch.setattr(httpx.AsyncClient, "post", _fake_post, raising=True)
        url = f"https://hooks.slack.com/services/T00/B00/{SECRET}"
        with caplog.at_level("INFO"):
            _run(_send_webhook("t", "m", "high", url))
        blob = "\n".join(r.getMessage() for r in caplog.records)
        assert SECRET not in blob, f"密钥泄漏进日志了：{blob}"

    def test_the_rejection_log_has_no_secret(self, monkeypatch, caplog):
        """被安全校验拒绝时，日志与结果里的 URL 同样要脱敏。"""
        from response_engine.response_registry import _send_webhook
        url = f"http://127.0.0.1:9/hook?key={SECRET}"
        with caplog.at_level("ERROR"):
            res = _run(_send_webhook("t", "m", "high", url))
        blob = "\n".join(r.getMessage() for r in caplog.records)
        assert SECRET not in blob, f"密钥泄漏进日志了：{blob}"
        assert SECRET not in str(res), f"密钥留在结果里了：{res}"


class TestTheCorrelationIsPreserved:
    def test_the_same_url_gives_the_same_form(self):
        url = f"https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key={SECRET}"
        assert redact_url_for_log(url) == redact_url_for_log(url)

    def test_different_urls_give_different_forms(self):
        a = redact_url_for_log("https://a.example.com/hook?key=1")
        b = redact_url_for_log("https://b.example.com/hook?key=1")
        assert a != b, "不同的目标脱敏后无法区分 —— 审计就失去了可关联性"

    def test_the_host_is_still_visible(self):
        """脱敏不能把审计变成一串无用的 `***`。"""
        out = redact_url_for_log(
            f"https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key={SECRET}")
        assert "qyapi.weixin.qq.com" in out, out
        assert out.startswith("https://"), out


class TestTheOtherParamsAreNotOverRedacted:
    def test_a_plain_value_is_untouched(self):
        out = redact_action_params({"src_ip": "10.0.0.1", "reason": "扫描"})
        assert out["src_ip"] == "10.0.0.1", out
        assert out["reason"] == "扫描", out

    def test_a_sensitive_key_is_still_masked(self):
        out = redact_action_params({"ssh_password": "hunter2"})
        assert out["ssh_password"] == "***", out
        assert "hunter2" not in str(out), out

    def test_a_non_url_string_is_not_mangled(self):
        out = redact_action_params({"note": "not a url"})
        assert out["note"] == "not a url", out


if __name__ == "__main__":       # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
