param(
  [string]$RepoRoot = (Get-Location).Path
)

$ErrorActionPreference = "Stop"

Set-Location $RepoRoot

if (-not (Test-Path "package.json")) {
  throw "RepoRoot does not look like CAPSTONE-1: $RepoRoot"
}

$reportDir = Join-Path $RepoRoot "Upgrades\Stage-A-Agentic-Control-Plane"
New-Item -ItemType Directory -Force -Path $reportDir | Out-Null

$started = Get-Date
$results = New-Object System.Collections.Generic.List[object]

function Invoke-StageACheck {
  param(
    [string]$Name,
    [string]$File,
    [string[]]$Arguments
  )

  Write-Host ""
  Write-Host "============================================================"
  Write-Host $Name
  Write-Host "============================================================"

  $start = Get-Date
  & $File @Arguments
  $exitCode = $LASTEXITCODE
  $end = Get-Date

  $results.Add([pscustomobject]@{
    Name = $Name
    Command = "$File $($Arguments -join ' ')"
    ExitCode = $exitCode
    StartedAt = $start.ToString("o")
    FinishedAt = $end.ToString("o")
    DurationSeconds = [math]::Round(($end - $start).TotalSeconds, 3)
  })

  if ($exitCode -ne 0) {
    throw "$Name failed with exit code $exitCode"
  }
}

try {
  Invoke-StageACheck `
    -Name "TypeScript typecheck" `
    -File "npm.cmd" `
    -Arguments @("run", "typecheck")

  Invoke-StageACheck `
    -Name "Production extension build" `
    -File "npm.cmd" `
    -Arguments @("run", "build")

  Invoke-StageACheck `
    -Name "Unit tests" `
    -File "npm.cmd" `
    -Arguments @("run", "test:unit")

  Invoke-StageACheck `
    -Name "TypeScript integration tests" `
    -File "npm.cmd" `
    -Arguments @("run", "test:integration")

  Invoke-StageACheck `
    -Name "Python event contract integration" `
    -File "python" `
    -Arguments @("-m", "pytest", "tests/integration/test_event_contract.py", "-q")

  Invoke-StageACheck `
    -Name "Full Chromium browser suite" `
    -File "npm.cmd" `
    -Arguments @("run", "test:browser")

  Invoke-StageACheck `
    -Name "TSFEG Chromium/FastAPI/PostgreSQL restart and privacy verification" `
    -File "node" `
    -Arguments @("scripts/verify-tsfeg.mjs")

  Invoke-StageACheck `
    -Name "Git whitespace check" `
    -File "git" `
    -Arguments @("diff", "--check")

  $finished = Get-Date

  $summary = [pscustomobject]@{
    schema_version = "stage-a-verification-1"
    status = "PASS"
    branch = (git branch --show-current).Trim()
    commit = (git rev-parse HEAD).Trim()
    started_at = $started.ToString("o")
    finished_at = $finished.ToString("o")
    duration_seconds = [math]::Round(($finished - $started).TotalSeconds, 3)
    checks = $results
    git_status = @(git status --short)
    limitations = @(
      "This verifies the controlled local test environment and implemented contracts.",
      "It does not establish real-world phishing recall, false-positive rate, model calibration, or zero-day generalization.",
      "Closed Shadow DOM remains outside declared coverage.",
      "Unknown first-time navigation cannot be truthfully described as pre-request blocked unless a DNR rule already existed before the request.",
      "The current contextual model remains advisory until independent Stage B data/calibration work is complete."
    )
  }

  $jsonPath = Join-Path $reportDir "STAGE-A-VERIFICATION.json"
  $summary | ConvertTo-Json -Depth 8 | Set-Content -Path $jsonPath -Encoding UTF8

  $md = @"
# Stage A Verification Result

**Status:** PASS  
**Branch:** $($summary.branch)  
**Commit:** $($summary.commit)  
**Started:** $($summary.started_at)  
**Finished:** $($summary.finished_at)  
**Duration:** $($summary.duration_seconds) seconds

## Fresh verification checks

| Check | Exit code | Duration (s) |
|---|---:|---:|
$(
  ($results | ForEach-Object {
    "| $($_.Name) | $($_.ExitCode) | $($_.DurationSeconds) |"
  }) -join "`n"
)

## Git status after verification

````text
$(@($summary.git_status) -join "`n")
````

## Scope and limitations

- Controlled local verification only.
- This does not establish real-world phishing recall, false-positive rate, model calibration, or zero-day generalization.
- Closed Shadow DOM remains outside declared coverage.
- Unknown first-time navigation is not called pre-request blocked unless a DNR rule existed before the request.
- The current contextual model remains advisory until independent Stage B data/calibration work is complete.

## Machine-readable record

See `STAGE-A-VERIFICATION.json`.
"@

  $mdPath = Join-Path $reportDir "TEST-RESULTS.md"
  Set-Content -Path $mdPath -Value $md -Encoding UTF8

  Write-Host ""
  Write-Host "============================================================"
  Write-Host "STAGE A VERIFICATION PASSED"
  Write-Host "============================================================"
  Write-Host "JSON: $jsonPath"
  Write-Host "Markdown: $mdPath"
}
catch {
  $finished = Get-Date

  $failure = [pscustomobject]@{
    schema_version = "stage-a-verification-1"
    status = "FAIL"
    branch = (git branch --show-current).Trim()
    commit = (git rev-parse HEAD).Trim()
    started_at = $started.ToString("o")
    finished_at = $finished.ToString("o")
    checks = $results
    error = $_.Exception.Message
  }

  $failurePath = Join-Path $reportDir "STAGE-A-VERIFICATION-FAILED.json"
  $failure | ConvertTo-Json -Depth 8 | Set-Content -Path $failurePath -Encoding UTF8

  Write-Host ""
  Write-Host "STAGE A VERIFICATION FAILED"
  Write-Host "Failure record: $failurePath"
  throw
}
