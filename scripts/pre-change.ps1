<#
.SYNOPSIS
    Pre-change checklist: inspect repo, validate, backup, record state.
.PARAMETER ChangeId
    Identifier for the change being made.
.PARAMETER Description
    Description of the planned change.
#>
param(
    [Parameter(Mandatory=$true)]
    [string]$ChangeId,
    [Parameter(Mandatory=$true)]
    [string]$Description
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$ScriptsDir = $PSScriptRoot

Write-Output "========================================="
Write-Output "PRE-CHANGE CHECKLIST"
Write-Output "========================================="
Write-Output "Change ID:    $ChangeId"
Write-Output "Description:  $Description"
Write-Output "Timestamp:    $(Get-Date -Format 'o')"
Write-Output ""

# Step 1: Inspect repository status
Write-Output "[1/5] Inspecting repository status..."
& "$ScriptsDir\check-changes.ps1"
Write-Output ""

# Step 2: Validate project structure
Write-Output "[2/5] Validating project structure..."
& "$ScriptsDir\validate-project.ps1"
Write-Output ""

# Step 3: Create backup snapshot
Write-Output "[3/5] Creating backup..."
& "$ScriptsDir\backup.ps1" -Reason "$ChangeId - $Description"
Write-Output ""

# Step 4: Record Git state
Write-Output "[4/5] Recording Git state..."
$gitPath = "$env:LOCALAPPDATA\Programs\Git\cmd\git.exe"
if (-not (Test-Path $gitPath)) { $gitPath = "git" }
try {
    $commit = & $gitPath -C $ProjectRoot rev-parse HEAD 2>$null
    $branch = & $gitPath -C $ProjectRoot branch --show-current 2>$null
    Write-Output "  Branch: $branch"
    Write-Output "  Commit: $commit"
} catch {
    Write-Output "  Git state: unavailable or no commits"
}
Write-Output ""

# Step 5: Record change ID in change log
Write-Output "[5/5] Recording change in log..."
$changeLogPath = Join-Path (Join-Path $ProjectRoot ".project") "change-log"
$timestamp = Get-Date -Format "o"
$entry = "$ChangeId | $timestamp | $Description | pending"
Add-Content -Path $changeLogPath -Value $entry -Encoding utf8
Write-Output "  Logged: $entry"

Write-Output ""
Write-Output "========================================="
Write-Output "PRE-CHANGE COMPLETE - Safe to proceed"
Write-Output "========================================="
