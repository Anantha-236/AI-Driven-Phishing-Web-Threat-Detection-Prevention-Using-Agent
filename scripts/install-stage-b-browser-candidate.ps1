param(
  [string]$CandidateDir = ".runtime\stage-b\release-candidate",
  [switch]$AllowResearchOnlyCandidate
)

$ErrorActionPreference = "Stop"
$RepoRoot = (Get-Location).Path
$Source = Join-Path $RepoRoot $CandidateDir
$ManifestPath = Join-Path $Source "stage-b-release-manifest.json"
$ModelPath = Join-Path $Source "stage-b-contextual-candidate.onnx"
$ParityPath = Join-Path $Source "stage-b-parity-vectors.json"

foreach ($required in @($ManifestPath, $ModelPath, $ParityPath)) {
  if (-not (Test-Path $required)) {
    throw "Missing frozen Stage B candidate file: $required"
  }
}

$manifest = Get-Content $ManifestPath -Raw | ConvertFrom-Json
if ($manifest.schema_version -ne "stage-b-release-candidate-1" -or $manifest.status -ne "PASS") {
  throw "Invalid Stage B release manifest."
}
if ($manifest.release_gate.deploy -ne $false -or $manifest.release_gate.autonomous_blocking -ne $false) {
  throw "Task 12 only installs non-deploying candidates."
}
if ($manifest.parity.status -ne "PASS" -or $manifest.parity.test_partition_used -ne $false) {
  throw "Frozen candidate parity gate is not valid."
}
if ($manifest.release_gate.integration_eligible -ne $true -and -not $AllowResearchOnlyCandidate) {
  throw "Candidate is research-only. Re-run with -AllowResearchOnlyCandidate only for controlled parity work."
}

$actualSha = (Get-FileHash $ModelPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualSha -ne [string]$manifest.onnx.sha256) {
  throw "ONNX SHA-256 does not match frozen manifest."
}

Write-Host "Verifying native ONNX Runtime parity..."
& node (Join-Path $RepoRoot "scripts\verify-stage-b-onnx-parity.mjs") `
  --manifest $ManifestPath `
  --model $ModelPath `
  --parity $ParityPath
if ($LASTEXITCODE -ne 0) {
  throw "Native ONNX Runtime parity failed."
}

Write-Host "Verifying onnxruntime-web WASM parity..."
& node (Join-Path $RepoRoot "scripts\verify-stage-b-wasm-parity.mjs") `
  --manifest $ManifestPath `
  --model $ModelPath `
  --parity $ParityPath
if ($LASTEXITCODE -ne 0) {
  throw "onnxruntime-web WASM parity failed."
}

$Target = Join-Path $RepoRoot "browser-extension\assets\stage-b-candidate"
if (Test-Path $Target) {
  Remove-Item $Target -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $Target | Out-Null
Copy-Item $ManifestPath (Join-Path $Target "stage-b-release-manifest.json") -Force
Copy-Item $ModelPath (Join-Path $Target "stage-b-contextual-candidate.onnx") -Force
Copy-Item $ParityPath (Join-Path $Target "stage-b-parity-vectors.json") -Force

Write-Host ""
Write-Host "Stage B browser candidate installed locally:"
Write-Host "  $Target"
Write-Host ""
Write-Host "IMPORTANT:"
Write-Host "  - candidate remains disabled"
Write-Host "  - service-worker decision path was not changed"
Write-Host "  - autonomous blocking remains false"
Write-Host "  - candidate directory is gitignored"
