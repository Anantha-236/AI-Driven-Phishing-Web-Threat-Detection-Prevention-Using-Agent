param(
  [string]$RepoRoot = (Get-Location).Path,
  [string]$Task20Root = ".runtime\stage-b\scale-v1",
  [string]$Task21Root = ".runtime\stage-b\scale-replay-v1",
  [string]$Task22Root = ".runtime\stage-b\scale-benchmark-v1",
  [string]$Task23Root = ".runtime\stage-b\scale-final-v1",
  [string]$LockRoot = ".runtime\stage-b\research-final-test-locks",
  [string]$OutputRoot = ".runtime\stage-b\scale-verification-v1"
)

$ErrorActionPreference = "Stop"
Set-Location $RepoRoot

$started = Get-Date
$results = New-Object System.Collections.Generic.List[object]

function Invoke-Check {
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
  $task20Report = Join-Path $Task20Root "scaled-assembly-report.json"
  $task21Report = Join-Path $Task21Root "task21-run-report.json"
  $task21Readiness = Join-Path $Task21Root "research-readiness.json"
  $task22Report = Join-Path $Task22Root "research-benchmark-calibration.json"
  $task23Report = Join-Path $Task23Root "research-final-evaluation.json"

  foreach ($required in @(
    $task20Report,
    $task21Report,
    $task21Readiness,
    $task22Report,
    $task23Report
  )) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
      throw "Required frozen Stage B artifact is missing: $required"
    }
  }

  $task23 = Get-Content -LiteralPath $task23Report -Raw | ConvertFrom-Json
  $datasetHash = [string]$task23.feature_dataset_sha256
  if ($datasetHash.Length -ne 64) {
    throw "Task 23 feature dataset hash is invalid."
  }

  $lockPath = Join-Path $LockRoot "$datasetHash.json"
  if (-not (Test-Path -LiteralPath $lockPath -PathType Leaf)) {
    throw "Task 23 finalized test lock is missing: $lockPath"
  }

  New-Item -ItemType Directory -Force -Path $OutputRoot | Out-Null
  $evidencePath = Join-Path $OutputRoot "STAGE-B-RESEARCH-EVIDENCE.json"
  if (Test-Path -LiteralPath $evidencePath) {
    throw "Refusing to overwrite existing Stage B research evidence: $evidencePath"
  }

  Invoke-Check `
    -Name "Python ML regression suite" `
    -File "python" `
    -Arguments @("-m", "pytest", "tests/ml", "-q")

  Invoke-Check `
    -Name "Python compileall" `
    -File "python" `
    -Arguments @("-m", "compileall", "-q", "ml/data", "ml/training", "ml/evaluation")

  Invoke-Check `
    -Name "TypeScript typecheck" `
    -File "npm.cmd" `
    -Arguments @("run", "typecheck")

  Invoke-Check `
    -Name "Unit tests" `
    -File "npm.cmd" `
    -Arguments @("run", "test:unit")

  Invoke-Check `
    -Name "Production extension build" `
    -File "npm.cmd" `
    -Arguments @("run", "build")

  Invoke-Check `
    -Name "Full Chromium browser suite" `
    -File "npm.cmd" `
    -Arguments @("run", "test:browser")

  Invoke-Check `
    -Name "Git whitespace check" `
    -File "git" `
    -Arguments @("diff", "--check")

  Invoke-Check `
    -Name "Frozen research evidence chain" `
    -File "python" `
    -Arguments @(
      "-m", "ml.evaluation.verify_stage_b_research_evidence",
      "--task20-report", $task20Report,
      "--task21-report", $task21Report,
      "--task21-readiness", $task21Readiness,
      "--task22-report", $task22Report,
      "--task23-report", $task23Report,
      "--task23-lock", $lockPath,
      "--output", $evidencePath
    )

  $finished = Get-Date
  $summary = [pscustomobject]@{
    schema_version = "stage-b-scaled-research-verification-1"
    status = "PASS"
    research_only = $true
    deployment_authorized = $false
    integration_eligible = $false
    production_readiness_equivalent = $false
    branch = (git branch --show-current).Trim()
    commit = (git rev-parse HEAD).Trim()
    started_at = $started.ToString("o")
    finished_at = $finished.ToString("o")
    duration_seconds = [math]::Round(($finished - $started).TotalSeconds, 3)
    evidence_manifest = $evidencePath
    final_test_lock = $lockPath
    checks = $results
    git_status = @(git status --short)
    limitations = @(
      "PASS verifies the frozen single-source archived-browser-replay research protocol only.",
      "PASS does not authorize production deployment, autonomous browser blocking authority, or release-candidate promotion.",
      "The research dataset comes from one archived source and source independence is relaxed.",
      "Archived browser replay does not recreate live network, server, user, or adversarial context.",
      "The final research test has been consumed and cannot be reopened for tuning."
    )
  }

  $summaryPath = Join-Path $OutputRoot "STAGE-B-VERIFICATION.json"
  $summary | ConvertTo-Json -Depth 10 | Set-Content -Path $summaryPath -Encoding UTF8

  Write-Host ""
  Write-Host "============================================================"
  Write-Host "STAGE B SCALED RESEARCH VERIFICATION PASSED"
  Write-Host "============================================================"
  Write-Host "Verification: $summaryPath"
  Write-Host "Evidence:     $evidencePath"
  Write-Host ""
  Write-Host "Research-only: TRUE"
  Write-Host "Deployment authorized: FALSE"
}
catch {
  $finished = Get-Date
  New-Item -ItemType Directory -Force -Path $OutputRoot | Out-Null
  $failure = [pscustomobject]@{
    schema_version = "stage-b-scaled-research-verification-1"
    status = "FAIL"
    research_only = $true
    deployment_authorized = $false
    started_at = $started.ToString("o")
    finished_at = $finished.ToString("o")
    checks = $results
    error = $_.Exception.Message
  }
  $failurePath = Join-Path $OutputRoot "STAGE-B-VERIFICATION-FAILED.json"
  $failure | ConvertTo-Json -Depth 10 | Set-Content -Path $failurePath -Encoding UTF8
  Write-Host ""
  Write-Host "STAGE B SCALED RESEARCH VERIFICATION FAILED"
  Write-Host "Failure record: $failurePath"
  throw
}
