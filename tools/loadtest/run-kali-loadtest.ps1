<#
.SYNOPSIS
    第三方压测编排器 — 从 Kali 攻击机向守望 SOC 注入攻击事件, 并校验真实入库量。

.DESCRIPTION
    端到端流程:
      1. 从 .env 取管理员口令, 现铸一枚 JWT(有效期约 2h, 压测前重铸, 不要复用旧 token)
      2. 确保 kali-pentest 攻击容器在跑(没有就按 9/10 口径重建)
      3. 在攻击机内跑 tools/attack-large-scale-2026-09-10.py(8 类威胁 / IP 池同 9/2 基线)
      4. 回查 PostgreSQL 该 session_id 的真实落库行数
      5. 落一份 JSON 报告到 .tmp_kali-loadtest/

    关键: 报告里的 landed 才是真话。请求 202/200 + fail=0 不等于入库 ——
    event_id 前缀撞了会被唯一索引幂等去重(请求全成功, 入库 0 行)。
    本脚本每次运行自动换 event_id 前缀, 并强制回查落地数。

.EXAMPLE
    .\run-kali-loadtest.ps1 -Total 100 -Rate 5
    .\run-kali-loadtest.ps1 -Total 3000 -Rate 2 -Mode baseline
#>
[CmdletBinding()]
param(
    [ValidateSet('smoke', 'baseline', 'stress')]
    [string]$Mode = 'smoke',

    [int]$Total = 0,
    [double]$Rate = 0,
    [string]$Session = '',
    [switch]$Single,
    [switch]$SkipContainerCheck
)

$ErrorActionPreference = 'Stop'

# ── 规模档位 (9/10 报告口径: 3000 条 @ 2 req/s, 8 类威胁) ─────────────────────
$Profiles = @{
    smoke   = @{ Total = 100;  Rate = 5.0;  Note = '连通性+真实入库冒烟' }
    baseline = @{ Total = 3000; Rate = 2.0;  Note = '复现 9/10 large-scale 基线, 便于横向对比' }
    stress  = @{ Total = 10000; Rate = 10.0; Note = '加压找瓶颈(约 17 min)' }
}
$prof = $Profiles[$Mode]
if ($Total -le 0) { $Total = $prof.Total }
if ($Rate -le 0)  { $Rate  = $prof.Rate }

# ── 路径 ─────────────────────────────────────────────────────────────────────
$Root        = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$EnvFile     = Join-Path $Root '.env'
$Harness     = Join-Path $Root 'tools\attack-large-scale-2026-09-10.py'
$OutDir      = Join-Path $Root '.tmp_kali-loadtest'
$Container   = 'kali-pentest'
$ApiInside   = 'http://host.docker.internal:8001'

if (-not $Session) {
    $Session = "kali-load-{0}-{1}" -f (Get-Date -Format 'yyyyMMdd-HHmmss'), $Mode
}
$IdPrefix = "klt-{0}" -f (Get-Date -Format 'yyyyMMddHHmmss')

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

Write-Host "=============================================================="
Write-Host " 守望 SOC · 第三方压测编排器"
Write-Host " 模式     : $Mode  ($($prof.Note))"
Write-Host "规模     : $Total 条 @ $Rate req/s"
Write-Host "Session  : $Session"
Write-Host "event 前缀: $IdPrefix"
Write-Host "=============================================================="

# ── 1. 现铸 JWT ─────────────────────────────────────────────────────────────
Write-Host "`n[1/5] 铸造访问令牌 ..."
if (-not (Test-Path $EnvFile)) { throw "找不到 .env: $EnvFile" }
$envLine = (Select-String -Path $EnvFile -Pattern '^SHARED_MEMORY_ADMIN_PASSWORD=' | Select-Object -First 1).Line
if (-not $envLine) { throw ".env 里没有 SHARED_MEMORY_ADMIN_PASSWORD" }
$adminPass = ($envLine -replace '^SHARED_MEMORY_ADMIN_PASSWORD=', '').Trim()
$loginBody = @{ username = 'admin'; password = $adminPass } | ConvertTo-Json
try {
    $login = Invoke-RestMethod -Uri 'http://localhost:8001/api/auth/login' -Method Post `
        -Body $loginBody -ContentType 'application/json' -TimeoutSec 30
} catch {
    throw "登录失败(后端在跑吗?): $($_.Exception.Message)"
}
$token = $login.access_token
if (-not $token) { throw "登录返回里没有 access_token" }
Write-Host "      OK  token 长度 $($token.Length)"

# ── 2. 确认攻击容器 ─────────────────────────────────────────────────────────
Write-Host "`n[2/5] 确认攻击机容器 ..."
if (-not $SkipContainerCheck) {
    $state = docker inspect $Container --format '{{.State.Running}}' 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $state) {
        Write-Host "      容器不存在, 正在按 9/10 口径重建 ..."
        docker run -d --name $Container --hostname $Container `
            --add-host host.docker.internal:host-gateway `
            --cap-add NET_RAW --cap-add NET_ADMIN `
            -v "${Root}\tools:/workspace/tools:ro" `
            -v "${Root}\.tmp_kali-loadtest:/workspace/reports" `
            --restart unless-stopped `
            kalilinux/kali-rolling:latest sleep infinity | Out-Null
        Start-Sleep -Seconds 3
        Write-Host "      安装攻击工具(nmap/hydra/curl/jq/python3) ..."
        docker exec $Container bash -c "export DEBIAN_FRONTEND=noninteractive; apt-get update -qq && apt-get install -y -qq --no-install-recommends nmap hydra curl jq python3 netcat-openbsd socat procps" | Out-Null
    } elseif ($state -ne 'true') {
        Write-Host "      容器已存在但未运行, 启动 ..."
        docker start $Container | Out-Null
        Start-Sleep -Seconds 2
    } else {
        Write-Host "      已在运行"
    }
}

# 攻击机到平台的连通性(不通就别开压, 否则量的是自己)
$health = docker exec $Container curl -s -m 10 -o /dev/null -w '%{http_code}' "$ApiInside/api/health" 2>$null
if ($health -ne '200') { throw "攻击机到平台不通 (health=$health)。先确认 host.docker.internal 可达。" }
Write-Host "      攻击机 -> 平台 /api/health = 200"

# ── 3. 跑压测 ───────────────────────────────────────────────────────────────
Write-Host "`n[3/5] 注入攻击事件 ..."
$jsonlInside = "/workspace/reports/$Session.jsonl"
$jsonlHost   = Join-Path $OutDir "$Session.jsonl"

$execArgs = @(
    '-e', "SOC_TOKEN=$token",
    '-e', "SOC_API=$ApiInside",
    '-e', "SOC_SESSION=$Session",
    $Container, 'python3', '/workspace/tools/attack-large-scale-2026-09-10.py',
    '--total', "$Total",
    '--rate', "$Rate",
    '--session', $Session,
    '--id-prefix', $IdPrefix,
    '--out', $jsonlInside
)
if ($Single) { $execArgs += '--single' }

$raw = docker exec @execArgs 2>&1 | Out-String
$raw | Set-Content -Path (Join-Path $OutDir "$Session.stdout.txt") -Encoding UTF8
$raw -split "`n" | Where-Object { $_ -match '\[DONE\]|\[PROGRESS\]|\[CONFIG\]' } | ForEach-Object { Write-Host "      $_" }

$summary = $null
if ($raw -match '\[DONE\]\s*(\{.*\})') { $summary = $Matches[1] | ConvertFrom-Json }

# ── 4. 回查真实入库 ─────────────────────────────────────────────────────────
Write-Host "`n[4/5] 回查 PostgreSQL 真实落库 ..."
# 两个坑都在这儿:
#   a) psql 用 -t(对齐模式) 会在结果后面多吐一行空行 —— 直接 Select-Object -Last 1
#      取到的是那行空行, int('') = 0 ⇒ 平台明明入库了, 量具却报 0。
#      办法: 加 -A(不对齐) 并且只认纯数字行。
#   b) SQL 走 -c 而不是 stdin: PowerShell 5.1 往原生命令管道写文本会带 UTF-8 BOM,
#      psql 会报 "syntax error at or near '﻿select'"。
$sql = "select count(*) from security_events where session_id='$Session';"
$raw = @(docker exec shared-memory-pg psql -U admin -d shared_memory -t -A -c $sql 2>$null)
$landed = 0
foreach ($line in $raw) {
    $t = "$line".Trim()
    if ($t -match '^\d+$') { $landed = [int]$t }
}

# ── 5. 出报告 ───────────────────────────────────────────────────────────────
Write-Host "`n[5/5] 生成报告 ..."
$report = [ordered]@{
    started_at      = (Get-Date).ToUniversalTime().ToString('o')
    mode            = $Mode
    note            = $prof.Note
    session_id      = $Session
    event_id_prefix = $IdPrefix
    target          = "$ApiInside (host.docker.internal:8001)"
    requested_total = $Total
    target_rate     = $Rate
    sent_ok         = if ($summary) { $summary.sent_ok } else { $null }
    sent_fail       = if ($summary) { $summary.sent_fail } else { $null }
    actual_rate     = if ($summary) { $summary.actual_rate_per_sec } else { $null }
    p50_ms          = if ($summary) { $summary.latency_p50_ms } else { $null }
    p95_ms          = if ($summary) { $summary.latency_p95_ms } else { $null }
    p99_ms          = if ($summary) { $summary.latency_p99_ms } else { $null }
    batch_count     = if ($summary) { $summary.batch_count } else { $null }
    landed_rows     = $landed
    landing_ratio   = if ($Total -gt 0) { [math]::Round($landed / $Total, 4) } else { $null }
    raw_jsonl       = $jsonlHost
}
$reportPath = Join-Path $OutDir "$Session.report.json"
$report | ConvertTo-Json -Depth 5 | Set-Content -Path $reportPath -Encoding UTF8

try { docker cp "${Container}:${jsonlInside}" $jsonlHost 2>$null | Out-Null } catch {}

Write-Host ""
Write-Host "--------------------------------------------------------------"
Write-Host (" 请求成功(sent_ok) : {0}" -f $report.sent_ok)
Write-Host (" 真实入库(landed)  : {0} / {1}" -f $landed, $Total)
Write-Host (" 落地率            : {0}" -f $report.landing_ratio)
Write-Host (" 报告              : {0}" -f $reportPath)
Write-Host "--------------------------------------------------------------"

# 入库数才是结论 —— 请求全 200 但落地 0 的情况真实发生过(前缀撞唯一索引被去重)
if ($landed -lt [math]::Floor($Total * 0.9)) {
    Write-Warning "入库率低于 90% —— 本轮压测结论无效, 不要拿它当性能数据。详见 tools/loadtest/README.md 的『已知堵点』。"
    exit 2
}
exit 0
