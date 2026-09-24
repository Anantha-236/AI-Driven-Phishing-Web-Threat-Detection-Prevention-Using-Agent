$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$StateFile = Join-Path $ProjectRoot ".runtime\capstone-state.json"

Write-Host "========================================="
Write-Host "CAPSTONE-1 STOP"
Write-Host "========================================="

if (Test-Path $StateFile) {
    try {
        $state = Get-Content $StateFile -Raw | ConvertFrom-Json
        foreach ($key in @("backend", "manualServer")) {
            $entry = $state.$key
            if ($null -ne $entry -and $null -ne $entry.pid) {
                $procId = [int]$entry.pid
                $proc = Get-Process -Id $procId -ErrorAction SilentlyContinue
                $details = Get-CimInstance Win32_Process -Filter "ProcessId = $procId" -ErrorAction SilentlyContinue
                $expectedCommand = if ($key -eq 'backend') { 'backend.main:app' } else { 'scripts/manual-browser-acceptance-server.mjs' }
                if ($proc -and $details.CommandLine -like "*$expectedCommand*" -and $proc.StartTime -ge ([datetime]$state.startedAt).AddSeconds(-10)) {
                    Stop-Process -Id $procId -Force -ErrorAction SilentlyContinue
                    Write-Host "Stopped $key (PID $procId)"
                }
            }
        }
    } catch {
        Write-Host "State file unreadable; removing stale tracking."
    }
}

Remove-Item $StateFile -Force -ErrorAction SilentlyContinue
Write-Host "Status: STOPPED"
Write-Host "========================================="
