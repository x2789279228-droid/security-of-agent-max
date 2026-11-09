# install-sysmon-baseline.ps1 - B3 benign Sysmon baseline collector (one-click elevated)
# Usage (in an ADMIN PowerShell):
#   powershell -ExecutionPolicy Bypass -File tools\install-sysmon-baseline.ps1 -Install
#   ... use the machine normally for 24h ...
#   powershell -ExecutionPolicy Bypass -File tools\install-sysmon-baseline.ps1 -Export
# Output: tools\datasets-cache\benign-sysmon-24h\Microsoft-Windows-Sysmon%4Operational.evtx
# Then run the 3 B3 commands in docs/upgrade/REMEDIATION-PLAN-2026-10-30.md appendix.
param(
    [switch]$Install,
    [switch]$Export,
    [switch]$Status
)
$ErrorActionPreference = 'Stop'
$kit = Join-Path $PSScriptRoot 'datasets-cache\sysmon-kit'
$cfg = Join-Path $kit 'sysmonconfig-export.xml'
$outDir = Join-Path $PSScriptRoot 'datasets-cache\benign-sysmon-24h'

if (-not ($Install -or $Export -or $Status)) { $Status = $true }

if ($Status) {
    $svc = Get-Service Sysmon64 -ErrorAction SilentlyContinue
    if ($svc) {
        Write-Output "Sysmon installed: $($svc.Status)"
        $log = Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' -ErrorAction SilentlyContinue
        if ($log) { Write-Output "Event count: $($log.RecordCount)" }
    } else { Write-Output 'Sysmon NOT installed (run with -Install)' }
}

if ($Install) {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
        ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) { throw 'Install requires admin: re-run this script in an elevated PowerShell' }
    if (-not (Test-Path $cfg)) { throw "Config missing: $cfg (should ship with the repo)" }
    & (Join-Path $kit 'Sysmon64.exe') -accepteula -i $cfg
    Write-Output 'Sysmon installed with SwiftOnSecurity config.'
    Write-Output '>>> Now use this machine NORMALLY for 24 hours. <<<'
    Write-Output '>>> After 24h, re-run this script with -Export.'
}

if ($Export) {
    New-Item -ItemType Directory -Force -Path $outDir | Out-Null
    $src = "$env:SystemRoot\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx"
    if (-not (Test-Path $src)) { throw "Sysmon log not found (run -Install first and let it collect): $src" }
    Copy-Item $src (Join-Path $outDir 'Microsoft-Windows-Sysmon%4Operational.evtx') -Force
    $n = (Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational').RecordCount
    Write-Output "Exported $n events to $outDir"
    Write-Output 'Next (from repo root):'
    Write-Output '  cd backend'
    Write-Output '  python -m eval_datasets.replay_edr_public --root ../tools/datasets-cache/benign-sysmon-24h'
    Write-Output '  python -m eval_datasets.backtest_promotion --root ../tools/datasets-cache --out ../docs/benchmark/RULE-PROMOTION-v2.json --apply'
}
