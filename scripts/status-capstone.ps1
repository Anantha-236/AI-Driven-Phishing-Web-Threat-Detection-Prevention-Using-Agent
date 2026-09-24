$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$StateFile = Join-Path $ProjectRoot ".runtime\capstone-state.json"

Write-Host "========================================="
Write-Host "CAPSTONE-1 STATUS"
Write-Host "========================================="

$backendPid = $null
$manualPid = $null

if (Test-Path $StateFile) {
    try {
        $state = Get-Content $StateFile -Raw | ConvertFrom-Json
        if ($null -ne $state.backend -and $null -ne $state.backend.pid) {
            try { $backendPid = [int]$state.backend.pid } catch { $backendPid = $null }
        }
        if ($null -ne $state.manualServer -and $null -ne $state.manualServer.pid) {
            try { $manualPid = [int]$state.manualServer.pid } catch { $manualPid = $null }
        }
    } catch {
        Write-Host "State file exists but is unreadable: $StateFile"
    }
}

$backendRunning = $false
$manualRunning = $false

$backendConnections = Get-NetTCPConnection -State Listen -LocalPort 8000 -ErrorAction SilentlyContinue
if ($backendConnections) { $backendRunning = $true }
if ($backendPid) {
    $backendProcess = Get-Process -Id $backendPid -ErrorAction SilentlyContinue
    if ($backendProcess) { $backendRunning = $true }
}

$manualConnections = Get-NetTCPConnection -State Listen -LocalPort 41731 -ErrorAction SilentlyContinue
if ($manualConnections) { $manualRunning = $true }
if ($manualPid) {
    $manualProcess = Get-Process -Id $manualPid -ErrorAction SilentlyContinue
    if ($manualProcess) { $manualRunning = $true }
}

$backendHealth = $false
$scenarioHealth = $false

try {
    $backendResp = Invoke-WebRequest -Uri "http://127.0.0.1:8000/api/v1/health" -UseBasicParsing -TimeoutSec 5
    if ($backendResp.StatusCode -eq 200) { $backendHealth = (($backendResp.Content | ConvertFrom-Json).database -eq "CONNECTED") }
} catch {
    $backendHealth = $false
}

try {
    $scenarioResp = Invoke-WebRequest -Uri "http://127.0.0.1:41731/" -UseBasicParsing -TimeoutSec 5
    if ($scenarioResp.StatusCode -ge 200 -and $scenarioResp.StatusCode -lt 400) { $scenarioHealth = $true }
} catch {
    $scenarioHealth = $false
}

Write-Host "Backend PID: $backendPid  ProcessRunning=$backendRunning  Healthy=$backendHealth"
Write-Host "Scenario PID: $manualPid  ProcessRunning=$manualRunning  Healthy=$scenarioHealth"

if ($backendRunning -and $manualRunning -and $backendHealth -and $scenarioHealth) {
    Write-Host "Status: READY"
} elseif ($backendRunning -or $manualRunning) {
    Write-Host "Status: STARTING_OR_DEGRADED"
} else {
    Write-Host "Status: NOT_RUNNING"
}
Write-Host "========================================="
