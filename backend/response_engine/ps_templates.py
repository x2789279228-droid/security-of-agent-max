"""
ps_templates.py — Windows PowerShell 响应动作脚本模板指纹库 (R13 / 复审 P1-1)

背景: WIN-004 白名单只匹配 `powershell ... -EncodedCommand <base64>` 的**编码后
形态**, `[A-Za-z0-9+/=]+` 对解码内容零约束 —— 任意 PowerShell 脚本编码后都能
通过白名单(修复 Q62"形态一致"时引入的结构弱点)。

本模块维护"解码后必须逐字命中"的脚本骨架模板:
  - 模板由 host_adapter 各响应动作的实际生成脚本参数化而来(变量部分换成
    {int}/{hex64}/{q} 占位), 命令集被模板钉死, 模板外脚本一律拒绝;
  - GLOBAL_FORBIDDEN 不能直接用于解码文本 —— 合法脚本本就含 `|`、换行等;
    骨架匹配本身就是更强的内容约束。

新增 powershell=True 动作时必须:
  1. 在本文件登记对应模板;
  2. 跑 tests/test_windows_whitelist_decoded.py 的守卫断言(动作标记 ↔ 模板一一对齐)。
"""
from __future__ import annotations

import base64
import re
from dataclasses import dataclass

# 占位符类型(调用点已消毒: pid=int、sha256=hex64、路径/名称=去引号)
_P_INT = r"\d+"
_P_HEX64 = r"[0-9a-f]{64}"
# 单引号安全段: 不含单引号/换行(host_adapter 生成时已剥离单引号)
_P_Q = r"[^'\r\n]*"
# 双引号安全段: 不含双引号/换行(response_registry 经 _sanitize_powershell_string)
_P_QQ = r'[^"\r\n]*'
# 字母数字段(_validate_alphanumeric)
_P_ALNUM = r"[A-Za-z0-9]+"

_PLACEHOLDERS = {
    "{int}": _P_INT,
    "{hex64}": _P_HEX64,
    "{q}": _P_Q,
    "{qq}": _P_QQ,
    "{alnum}": _P_ALNUM,
}


def _expand(skeleton: str) -> str:
    """骨架 → 正则: 占位符展开, 其余字符 re.escape 逐字锚定。"""
    out = []
    i = 0
    tokens = tuple(_PLACEHOLDERS)
    while i < len(skeleton):
        for t in tokens:
            if skeleton.startswith(t, i):
                out.append(_PLACEHOLDERS[t])
                i += len(t)
                break
        else:
            out.append(re.escape(skeleton[i]))
            i += 1
    return "".join(out)


@dataclass
class PsTemplate:
    rule_id: str
    action: str
    skeleton: str
    marker: str  # 输出标记, 用于动作↔模板守卫断言
    _re: re.Pattern = None  # type: ignore[assignment]

    def __post_init__(self):
        object.__setattr__(self, "_re", re.compile("^" + _expand(self.skeleton) + "$", re.S))

    def matches(self, decoded: str) -> bool:
        return bool(self._re.match(decoded))


# ── 模板登记表(host_adapter 各 powershell=True 动作的实际脚本形状) ──

WINDOWS_PS_TEMPLATES: list[PsTemplate] = [
    PsTemplate(
        rule_id="PS-KILL-PID", action="kill_process", marker="KILLED",
        skeleton="$p = Get-Process -Id {int} -ErrorAction SilentlyContinue\n"
                 "if ($null -eq $p) { Write-Output 'NOT_FOUND'; exit 2 }\n"
                 "Stop-Process -Id {int} -Force\n"
                 "Write-Output 'KILLED {int}'",
    ),
    PsTemplate(
        rule_id="PS-KILL-HASH", action="kill_process", marker="KILLED_COUNT",
        skeleton="$t = '{hex64}'\n"
                 "$n = 0; $max = {int}\n"
                 "Get-CimInstance Win32_Process | ForEach-Object {\n"
                 "  if ($n -ge $max) { return }\n"
                 "  $path = $_.ExecutablePath\n"
                 "  if (-not $path) { return }\n"
                 "  try { $h = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLower() } catch { return }\n"
                 "  if ($h -eq $t) { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue; $n++ }\n"
                 "}\n"
                 'Write-Output "KILLED_COUNT $n"',
    ),
    PsTemplate(
        rule_id="PS-QUARANTINE", action="quarantine_file", marker="QUARANTINED",
        skeleton="$src = '{q}'\n"
                 "$dst = '{q}'\n"
                 "New-Item -ItemType Directory -Force -Path (Split-Path $dst) | Out-Null\n"
                 "Move-Item -LiteralPath $src -Destination $dst -Force\n"
                 'Write-Output "QUARANTINED $dst"',
    ),
    PsTemplate(
        rule_id="PS-RESTORE", action="restore_file", marker="RESTORED",
        skeleton="Move-Item -LiteralPath '{q}' -Destination '{q}' -Force\n"
                 "Write-Output 'RESTORED'",
    ),
    PsTemplate(
        rule_id="PS-PERSIST-RUN", action="clean_persistence", marker="REMOVED",
        skeleton="$k = '{q}'\n"
                 "$n = '{q}'\n"
                 "Remove-ItemProperty -Path $k -Name $n -ErrorAction SilentlyContinue\n"
                 "Write-Output 'REMOVED'",
    ),
    PsTemplate(
        rule_id="PS-PERSIST-SERVICE", action="clean_persistence", marker="SERVICE_DISABLED",
        skeleton="Stop-Service -Name '{q}' -Force -ErrorAction SilentlyContinue\n"
                 "Set-Service -Name '{q}' -StartupType Disabled -ErrorAction SilentlyContinue\n"
                 "Write-Output 'SERVICE_DISABLED'",
    ),
    PsTemplate(
        rule_id="PS-PERSIST-LNK", action="clean_persistence", marker="LNK_REMOVED",
        skeleton="$p = '{q}'\n"
                 "if (Test-Path -LiteralPath $p) { Copy-Item $p \"$p.bak.soc\"; Remove-Item -LiteralPath $p -Force }\n"
                 "Write-Output 'LNK_REMOVED'",
    ),
    PsTemplate(
        rule_id="PS-FORENSIC-SNAPSHOT", action="forensic_snapshot", marker="---NET---",
        skeleton="Get-Process | Select-Object -First 80 Id,ProcessName,Path | ConvertTo-Json -Compress\n"
                 "Write-Output '---NET---'\n"
                 "Get-NetTCPConnection -ErrorAction SilentlyContinue | "
                 "Select-Object -First 80 LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess,State | "
                 "ConvertTo-Json -Compress",
    ),
    # ── response_registry 动作(经 _ps_cmd → WIN-004 的其余形状) ──
    PsTemplate(
        rule_id="PS-RATELIMIT", action="rate_limit", marker="QoS policy",
        skeleton='$name = "{qq}"\n'
                 '$ip = "{qq}"\n'
                 "$rate = {int}\n"
                 "New-NetQosPolicy -Name $name -IPSourceAddress $ip "
                 "-IPProtocol TCP -ThrottleRateInBits $rate "
                 '-Description "ResponseEngine rate-limit: {qq}" '
                 "-ErrorAction Stop\n"
                 'Write-Output "QoS policy $name created"',
    ),
    PsTemplate(
        rule_id="PS-RATELIMIT-REMOVE", action="remove_rate_limit", marker="QoS policy",
        skeleton='$name = "{qq}"\n'
                 "Remove-NetQosPolicy -Name $name -Confirm:$false -ErrorAction SilentlyContinue\n"
                 'Write-Output "QoS policy $name removed"',
    ),
    PsTemplate(
        rule_id="PS-LOGOFF", action="kill_session", marker="logged off",
        skeleton="logoff {alnum} /server:localhost 2>$null\n"
                 'Write-Output "Session {alnum} logged off"',
    ),
    PsTemplate(
        rule_id="PS-KILL-USER", action="kill_session", marker="terminated",
        skeleton="Get-Process -IncludeUserName | "
                 'Where-Object {$_.UserName -eq "{qq}"} | '
                 "Stop-Process -Force\n"
                 'Write-Output "Processes for {qq} terminated"',
    ),
    PsTemplate(
        rule_id="PS-KILL-NAME", action="kill_session", marker="terminated",
        skeleton='Stop-Process -Name "{qq}" -Force -ErrorAction SilentlyContinue\n'
                 'taskkill /F /IM "{qq}" /T 2>$null\n'
                 'Write-Output "Process {qq} terminated"',
    ),
    PsTemplate(
        rule_id="PS-EVENTLOG-ALERT", action="send_alert", marker="Write-EventLog",
        skeleton='Write-EventLog -LogName Application -Source "ResponseEngine" '
                 "-EntryType {alnum} -EventId 1000 "
                 '-Message "{qq}: {qq}" '
                 "-ErrorAction SilentlyContinue",
    ),
    PsTemplate(
        rule_id="PS-DISPLAY-NOTIFY", action="send_alert", marker="ShowBalloonTip",
        skeleton='[System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null\n'
                 "$n = New-Object System.Windows.Forms.NotifyIcon\n"
                 "$n.Icon = [System.Drawing.SystemIcons]::Warning\n"
                 '$n.BalloonTipTitle = "{qq}"\n'
                 '$n.BalloonTipText = "{qq}"\n'
                 "$n.Visible = $true\n"
                 "$n.ShowBalloonTip(10000)",
    ),
    # post_validator._verify_rate_limit 的查询脚本
    PsTemplate(
        rule_id="PS-QOS-VERIFY", action="verify_rate_limit", marker="Get-NetQosPolicy",
        skeleton="Get-NetQosPolicy -Name '{q}' -ErrorAction SilentlyContinue",
    ),
]


def decode_encoded_command(encoded_b64: str) -> tuple[bool, str, str]:
    """base64(UTF-16LE) → 脚本文本。失败返回 (False, reason, "")。"""
    try:
        raw = base64.b64decode(encoded_b64, validate=True)
        return True, "", raw.decode("utf-16-le")
    except Exception as e:
        return False, f"decode_failed: {e}", ""


def match_decoded_script(decoded: str) -> tuple[bool, str, str]:
    """解码文本必须逐字命中任一已登记模板。返回 (allowed, rule_id, reason)。"""
    for t in WINDOWS_PS_TEMPLATES:
        if t.matches(decoded):
            return True, t.rule_id, ""
    return False, "WIN-004-DECODED", "decoded_mismatch: 脚本不匹配任何已登记响应动作模板"
