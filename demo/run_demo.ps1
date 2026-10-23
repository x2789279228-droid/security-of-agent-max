param(
    [string]$Api = "http://localhost:8001",
    [string]$Frontend = "http://localhost:3001",
    [switch]$OpenBrowser
)

$ErrorActionPreference = "Stop"

# Windows PowerShell 5.1 默认控制台可能是 GBK；统一 UTF-8 避免中文乱码。
try {
    $null = chcp 65001
    [Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
} catch { }

function Fail([string]$Message) {
    Write-Host "[FAIL] $Message" -ForegroundColor Red
    exit 1
}

Write-Host "== 守望平台 5 分钟演示 ==" -ForegroundColor Cyan
Write-Host "API: $Api"
Write-Host "Frontend: $Frontend"

try {
    $health = Invoke-RestMethod -Uri "$Api/api/health" -TimeoutSec 5
    Write-Host "[OK] 后端健康: $($health.status)" -ForegroundColor Green
} catch {
    Fail "后端不可达（$Api）。请先启动 docker compose，或检查端口。"
}

$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    Write-Host "`n[1/3] 注入确定性攻击场景（暴力破解 / C2 / web 攻击 / 良性噪声）..." -ForegroundColor Yellow
    $output = & python tools/generate_test_feed.py --inject --api $Api 2>&1 | Out-String
    Write-Host $output

    $session = ""
    $m = [regex]::Match($output, "session_id=([^\s]+)")
    if ($m.Success) { $session = $m.Groups[1].Value }

    Write-Host "`n[2/3] 验证清单" -ForegroundColor Yellow
    Write-Host "  - Monitor: 实时事件带应出现注入事件"
    Write-Host "  - SecurityAudit: Session ID = $session"
    Write-Host "  - Operations -> 案例: 应自动建案并派生工单"
    Write-Host "  - Response: 手动执行 block_ip 应返回 403（HIGH 必须审批）"
    Write-Host "  - Capabilities: 应看到 verified / experimental / disabled 三档"

    Write-Host "`n[3/3] 演示链路" -ForegroundColor Yellow
    Write-Host "  1) 打开 $Frontend/monitor 查看实时告警"
    Write-Host "  2) 打开 $Frontend/security-audit 输入 Session ID，查看四阶段审计与证据"
    Write-Host "  3) 打开 $Frontend/operations 查看案例、工单、复盘"
    Write-Host "  4) 打开 $Frontend/response 验证审批闸门与回滚"
    Write-Host "  5) 打开 $Frontend/capabilities 查看能力状态与证据路径"

    if ($OpenBrowser) {
        Start-Process $Frontend
    }
} finally {
    Pop-Location
}

Write-Host "`n提示：默认 execution_mode=dry_run，真实封禁/隔离不会执行。" -ForegroundColor DarkYellow
Write-Host "      只在隔离靶场显式设置 SHARED_MEMORY_EXECUTION_MODE=live 并配置 known_hosts。" -ForegroundColor DarkYellow
