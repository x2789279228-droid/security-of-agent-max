# -*- coding: utf-8 -*-
"""Windows 响应动作必须**真的能下发到 SSH**（整改方案 §9.45）。

## 缺陷

`response_registry._live_fn` 调 `ssh_transport.run()` 时**没传 `platform`**，
而 `transport.run()` 的默认值是 `platform="linux"`：

```python
# response_registry.py（修复前）
result = await ssh_transport.run(command, powershell=use_powershell)
```

于是本路径（windows）的命令被拿 **linux 规则**去查 ——
linux 规则里**没有任何一条**能匹配 `powershell ... -EncodedCommand <b64>`：

```
第一道（safe_executor, platform="windows"）→ allowed, WIN-004 ✓
第二道（transport.run,  platform="linux"）  → REJECTED ✗
```

**每一个** Windows 响应动作（block_ip / isolate_host / rate_limit /
remove_rate_limit / kill_session / send_alert / 桌面通知）都被白名单拒绝。

后果（`response_transport_mode` 默认 "auto"）：退化成**桩**，
而日志里写的是「SSH transport requires RESPONSE_SSH_HOST config」——
**真实原因被丢掉**，运维会去查一个根本没问题的方向。

## 本守卫盯什么

1. **核心性质**：windows 命令在 `run(cmd, powershell=False, platform="windows")`
   下**必须过白名单并到达 SSH**；
2. **反向**：平台不匹配的形态**必须被拒**（钉住「白名单是按平台生效的」）；
3. **调用方必须转发 platform**（否则第 1 条随时会回归）；
4. **不得二次编码** —— 下发的命令必须与被校验的命令**逐字相同**
   （双层 powershell 会把内层脚本的 `exit N` 吞掉，失败被报成 success）；
5. linux 路径**不受影响**；
6. 白名单拒绝时**原因不能是空串**（原来的 `result['stderr']` 是空的）。

⚠ 判据用**行为**（白名单判定 / 实际下发的命令 / 实际调用参数），不用源码文本。

⚠ `response_engine` 包的 `__init__` 把 `response_registry` 这个名字
**绑成了实例**（`from .response_registry import response_registry`），
所以 `from response_engine import response_registry` 拿到的是**实例**不是模块 ——
要用 `importlib.import_module(...)` 才拿得到模块。
"""
from __future__ import annotations

import asyncio
import importlib
import os
import sys

import pytest

os.environ.setdefault("SHARED_MEMORY_SKIP_DOTENV", "1")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import response_engine.transport as tr  # noqa: E402
from response_engine.command_whitelist import command_whitelist  # noqa: E402

rr = importlib.import_module("response_engine.response_registry")

PS_SCRIPT = (
    '$name = "RE_Block_1_2_3_4"\n'
    'New-NetFirewallRule -DisplayName $name -Direction Inbound '
    '-Action Block -RemoteAddress 1.2.3.4 -ErrorAction Stop\n'
    'Write-Output "rule created"'
)
LINUX_CMD = "iptables -I INPUT -s 1.2.3.4 -j DROP"


def _ps_cmd(script: str) -> str:
    """与 response_registry._ps_cmd 同形态（避免直接依赖私有函数）。"""
    import base64
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    return f"powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand {encoded}"


class _FakeProc:
    def __init__(self):
        self.returncode = 0

    async def communicate(self):
        return (b"ok", b"")

    def kill(self):
        pass


@pytest.fixture()
def ssh_capture(monkeypatch):
    """捕获真正下发到远端的命令（不真的连 SSH）。"""
    captured = []

    async def _fake_exec(*args, **kwargs):
        captured.append(list(args))
        return _FakeProc()

    monkeypatch.setattr(tr.asyncio, "create_subprocess_exec", _fake_exec)
    # 主机密钥校验默认失败关闭：测试提供一个存在的 known_hosts 文件。
    import tempfile
    from config import settings as _settings
    fd, kh = tempfile.mkstemp(prefix="known_hosts_", text=True)
    os.close(fd)
    monkeypatch.setattr(_settings, "response_ssh_known_hosts", kh)
    monkeypatch.setattr(_settings, "response_ssh_allow_unknown_host", False)
    ssh = tr.ssh_transport
    old = (ssh._enabled, ssh._host, ssh._user, ssh._key_file, ssh._port)
    ssh._enabled = True
    ssh._host = "10.0.0.1"
    ssh._user = "u"
    ssh._key_file = "/tmp/ssh/id_rsa"
    try:
        yield captured
    finally:
        (ssh._enabled, ssh._host, ssh._user, ssh._key_file, ssh._port) = old
        try:
            os.unlink(kh)
        except OSError:
            pass


@pytest.fixture()
def spy_on_transport(monkeypatch):
    """捕获 `_live_fn` 实际调用 `transport.run` 时的参数。"""
    seen = {}

    async def spy(command, **kwargs):
        seen["command"] = command
        seen["kwargs"] = kwargs
        return {"success": True, "stdout": "", "stderr": "", "returncode": 0}

    monkeypatch.setattr(tr.ssh_transport, "run", spy)
    return seen


@pytest.fixture()
def executor_passthrough(monkeypatch):
    """把 SafeExecutor 换成直通：只跑 live_fn，绕开 Redis / 资产白名单等。

    ⚠ `_exec` 里是 `from .safe_executor import safe_executor` —— **函数内局部导入**，
    所以模块上没有 `safe_executor` 属性；得去 `response_engine.safe_executor` 模块里
    取那个**单例实例**，再替换它的 `execute` 方法。
    """
    calls = []
    se = importlib.import_module("response_engine.safe_executor").safe_executor

    async def fake_execute(*, action_name, command, live_fn, platform, **kw):
        calls.append({"action": action_name, "command": command, "platform": platform})
        return await live_fn(command)

    monkeypatch.setattr(se, "execute", fake_execute)
    return calls


class TestTheWindowsCommandReachesTheHost:
    def test_it_passes_the_whitelist_for_its_own_platform(self):
        """【核心性质】windows 命令按 **windows** 规则查 → 放行。

        修复前它被拿 linux 规则查 → 必然被拒 → 一个都下发不出去。
        """
        cmd = _ps_cmd(PS_SCRIPT)
        allowed, rule_id, _reason = command_whitelist.check(cmd, "windows")
        assert allowed, f"windows 规则拒绝了本路径的命令：{rule_id}"
        assert rule_id == "WIN-004", rule_id

    def test_it_actually_reaches_ssh(self, ssh_capture):
        async def scenario():
            return await tr.ssh_transport.run(
                _ps_cmd(PS_SCRIPT), powershell=False, platform="windows")

        out = asyncio.run(scenario())
        assert out.get("success") is True, out
        assert ssh_capture, "命令没有到达 SSH"
        assert out.get("blocked_by") is None, out

    def test_the_command_sent_is_exactly_the_validated_one(self, ssh_capture):
        """**不得二次编码**。

        双层 powershell 会把内层脚本的 `exit N` 吞掉 ——
        失败的动作会被报成 success。
        """
        cmd = _ps_cmd(PS_SCRIPT)

        async def scenario():
            return await tr.ssh_transport.run(
                cmd, powershell=False, platform="windows")

        asyncio.run(scenario())
        remote = ssh_capture[-1][-1]
        assert remote == cmd, (
            "下发的命令与被白名单校验的不是同一条 —— "
            "要么被二次编码，要么被改写；前者会吞掉退出码")


class TestThePlatformMustMatch:
    def test_the_same_command_is_rejected_for_the_wrong_platform(self):
        """**反向判据**：同一条命令按 linux 规则查 → 必须被拒。

        钉住「白名单是按平台生效的」——
        否则「修复」可能只是把检查放松了。
        """
        cmd = _ps_cmd(PS_SCRIPT)
        allowed, _rule_id, reason = command_whitelist.check(cmd, "linux")
        assert not allowed, (
            "windows 命令竟然过了 linux 规则 —— 白名单的按平台生效性没了")
        assert "linux" in reason, reason

    def test_the_pre_fix_call_shape_is_rejected(self, ssh_capture):
        """修复前的调用形态（不传 platform）**必须**到不了 SSH。

        这条把「缺陷长什么样」钉住：将来有人把 platform 去掉，这条会转红。
        """
        async def scenario():
            return await tr.ssh_transport.run(_ps_cmd(PS_SCRIPT), powershell=True)

        out = asyncio.run(scenario())
        assert out.get("success") is False, out
        assert not ssh_capture, "命令到了 SSH —— 说明白名单没在按平台生效"


class TestTheCallerMustForwardThePlatform:
    def test_live_fn_forwards_the_platform(self, spy_on_transport,
                                           executor_passthrough, monkeypatch):
        """`_live_fn` 必须把 platform 转发给 transport。

        用**行为**判定（捕获实际调用），不用源码文本 ——
        源码里有 `platform` 这个词不代表它被转发给了下游。
        """
        monkeypatch.setattr(rr, "_mode", lambda: "ssh")

        async def scenario():
            return await rr._exec(_ps_cmd(PS_SCRIPT), "block_ip", src_ip="1.2.3.4")

        asyncio.run(scenario())
        assert spy_on_transport, "live_fn 没有调用 transport.run"
        assert spy_on_transport["kwargs"].get("platform") == "windows", (
            f"platform 没有转发给 transport：{spy_on_transport['kwargs']}")

    def test_live_fn_does_not_double_encode(self, spy_on_transport,
                                            executor_passthrough, monkeypatch):
        """`_live_fn` 不得让 transport 二次编码（powershell 必须为 False）。"""
        monkeypatch.setattr(rr, "_mode", lambda: "ssh")

        async def scenario():
            return await rr._exec(_ps_cmd(PS_SCRIPT), "block_ip", src_ip="1.2.3.4")

        asyncio.run(scenario())
        assert spy_on_transport.get("kwargs", {}).get("powershell") is False, (
            f"powershell 必须是 False（命令已是最终形态）：{spy_on_transport}")

    def test_the_executor_receives_the_windows_platform(self,
                                                        executor_passthrough,
                                                        monkeypatch):
        """前提：`_exec` 交给 SafeExecutor 的 platform 也是 windows。"""
        monkeypatch.setattr(rr, "_mode", lambda: "ssh")

        async def scenario():
            return await rr._exec(_ps_cmd(PS_SCRIPT), "block_ip", src_ip="1.2.3.4")

        asyncio.run(scenario())
        assert executor_passthrough, "executor 没被调用"
        assert executor_passthrough[0]["platform"] == "windows", executor_passthrough


class TestTheLinuxPathIsUnaffected:
    def test_the_linux_command_still_reaches_ssh(self, ssh_capture):
        async def scenario():
            return await tr.ssh_transport.run(
                LINUX_CMD, powershell=False, platform="linux")

        out = asyncio.run(scenario())
        assert out.get("success") is True, out
        assert ssh_capture, "linux 命令没有到达 SSH"

    def test_the_linux_command_is_still_whitelisted(self):
        allowed, rule_id, _reason = command_whitelist.check(LINUX_CMD, "linux")
        assert allowed and rule_id == "LX-001", (allowed, rule_id)


class TestTheFailureReasonIsVisible:
    def test_a_whitelist_rejection_carries_a_reason(self, ssh_capture):
        """白名单拒绝时**原因不能是空串**。

        修复前 `_live_fn` 用 `result['stderr']` 记原因，
        而白名单拒绝时 `stderr` 是**空串** → 日志里原因被打成空。
        """
        async def scenario():
            return await tr.ssh_transport.run(
                _ps_cmd(PS_SCRIPT), powershell=True)   # 不传 platform → 被拒

        out = asyncio.run(scenario())
        assert out.get("success") is False, out
        assert out.get("error"), "拒绝原因丢失（error 为空）"
        assert "白名单" in out["error"], out["error"]

    def test_the_failure_result_carries_the_reason_to_the_caller(
            self, spy_on_transport, executor_passthrough, monkeypatch):
        """失败结果**必须**把原因带给调用方。

        修复前 ssh 模式分支返回 `{"mode": "ssh", "success": False, **fields, **result}`
        —— 原因在 `result["error"]` 里；但**桩回退**分支
        （`_stub_fallback`）**完全不带原因**，
        调用方只看到「mode=stub」，无从知道是被白名单拒了还是 SSH 没配。
        """
        async def _rejecting_run(command, **kwargs):
            return {"success": False, "error": "命令白名单拒绝: 测试",
                    "stderr": "", "returncode": -1,
                    "blocked_by": "command_whitelist"}

        monkeypatch.setattr(tr.ssh_transport, "run", _rejecting_run)
        monkeypatch.setattr(rr, "_mode", lambda: "auto")

        async def scenario():
            return await rr._exec(_ps_cmd(PS_SCRIPT), "block_ip", src_ip="1.2.3.4")

        out = asyncio.run(scenario())
        assert out.get("mode") == "stub", out
        assert out.get("error") or out.get("reason") or out.get("blocked_by"), (
            f"桩回退**没有带任何原因** —— 调用方无从判断是白名单拒了还是 SSH 没配：{out}")


class TestHostContainmentLivePath:
    def test_scripts_are_encoded_before_whitelist_and_reach_ssh(
            self, ssh_capture, monkeypatch):
        """主机遏制脚本必须先编码再查白名单，否则 live 路径 100% 被拒。"""
        from config import settings as _settings
        from response_engine.containment import host_adapter

        monkeypatch.setattr(_settings, "execution_mode", "live")

        async def scenario():
            kill = await host_adapter.kill_process(pid=1234)
            quar = await host_adapter.quarantine_file(path=r"C:\Users\Public\evil.exe")
            clean = await host_adapter.clean_persistence(
                kind="service", name_or_path="Spooler")
            return kill, quar, clean

        kill, quar, clean = asyncio.run(scenario())
        for result in (kill, quar, clean):
            assert result["success"] is True, result
            assert result.get("blocked_by") is None, result
        assert len(ssh_capture) == 3, ssh_capture
        for call in ssh_capture:
            sent = call[-1]
            assert sent.startswith("powershell "), sent
            assert "-EncodedCommand" in sent, sent


class TestThePremises:
    def test_the_default_transport_mode_is_auto(self):
        """前提守卫：默认是 auto —— 也就是会**静默**退化成桩的那条路。"""
        from config import settings
        assert getattr(settings, "response_transport_mode", "auto") == "auto", (
            "默认模式变了 —— 本节结论（静默降级为桩）要重估")

    def test_every_response_action_goes_through_exec(self):
        """前提守卫：response_registry 的动作**都**走 `_exec` → 全部受影响。"""
        with open(rr.__file__, "rb") as fh:
            src = fh.read().decode("utf-8")
        n = src.count("await _exec(")
        assert n >= 5, f"只有 {n} 个动作走 _exec —— 影响面结论要重估"


if __name__ == "__main__":       # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
