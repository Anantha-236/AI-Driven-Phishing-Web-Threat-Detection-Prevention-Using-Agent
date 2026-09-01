<#
.SYNOPSIS
    Post-change checklist: detect changes, validate, run tests, typecheck, lint, secret scan, report.
.PARAMETER ChangeId
    Identifier for the change that was made.
#>
param(
    [Parameter(Mandatory=$true)]
    [string]$ChangeId
)

$ErrorActionPreference = "Continue"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$ScriptsDir = $PSScriptRoot
$allPassed = $true

Write-Output "========================================="
Write-Output "POST-CHANGE CHECKLIST"
Write-Output "========================================="
Write-Output "Change ID:  $ChangeId"
Write-Output "Timestamp:  $(Get-Date -Format 'o')"
Write-Output ""

# Step 1: Detect changes
Write-Output "[1/6] Detecting changes..."
& "$ScriptsDir\check-changes.ps1"
Write-Output ""

# Step 2: Validate project structure
Write-Output "[2/6] Validating project structure..."
& "$ScriptsDir\validate-project.ps1"
if ($LASTEXITCODE -ne 0) { $allPassed = $false }
Write-Output ""

# Step 3: Run tests (if npm available)
Write-Output "[3/6] Running tests..."
$npmCmd = Get-Command npm.cmd -ErrorAction SilentlyContinue
if (-not $npmCmd) { $npmCmd = Get-Command npm -ErrorAction SilentlyContinue }
if ($npmCmd) {
    try {
        & $npmCmd.Path run test 2>$null
        if ($LASTEXITCODE -ne 0) {
            Write-Output "  Tests: SOME FAILURES"
            $allPassed = $false
        } else {
            Write-Output "  Tests: PASSED"
        }
    } catch {
        Write-Output "  Tests: SKIPPED (npm test not configured)"
    }
} else {
    Write-Output "  Tests: SKIPPED (npm not available)"
}
Write-Output ""

# Step 4: Type checking
Write-Output "[4/6] Type checking..."
if ($npmCmd) {
    try {
        & $npmCmd.Path run typecheck 2>$null
        if ($LASTEXITCODE -ne 0) {
            Write-Output "  Typecheck: FAILED"
            $allPassed = $false
        } else {
            Write-Output "  Typecheck: PASSED"
        }
    } catch {
        Write-Output "  Typecheck: SKIPPED (not configured)"
    }
} else {
    Write-Output "  Typecheck: SKIPPED (npm not available)"
}
Write-Output ""

# Step 5: Lint (if configured)
Write-Output "[5/6] Linting..."
if ($npmPath) {
    try {
        & npm run lint --prefix $ProjectRoot 2>$null
        if ($LASTEXITCODE -ne 0) {
            Write-Output "  Lint: WARNINGS/ERRORS"
        } else {
            Write-Output "  Lint: PASSED"
        }
    } catch {
        Write-Output "  Lint: SKIPPED (not configured)"
    }
} else {
    Write-Output "  Lint: SKIPPED (npm not available)"
}
Write-Output ""

# Step 6: Secret scan (reuse validation)
Write-Output "[6/6] Secret scan..."
# The validate-project script already includes secret scanning
Write-Output "  (Covered by step 2 validation)"
Write-Output ""

# Final report
Write-Output "========================================="
if ($allPassed) {
    Write-Output "POST-CHANGE RESULT: PASS"
} else {
    Write-Output "POST-CHANGE RESULT: ISSUES DETECTED"
}
Write-Output "========================================="
