param(
  [string]$RepoRoot = (Get-Location).Path,
  [switch]$AcknowledgeLargeDownload
)

$ErrorActionPreference = "Stop"

$downloadRoot = Join-Path $RepoRoot "Upgrades\Downloads\Zenodo-8041387-Pilot"
$extractRoot = Join-Path $RepoRoot "Upgrades\Development\Zenodo-8041387-Pilot"
$runtimeReportRoot = Join-Path $RepoRoot ".runtime\stage-b\zenodo8041387-extraction"

$files = @(
  @{ Name="brands.csv"; Md5="4194175e26f89582dd0a641b34f897de" },
  @{ Name="phishing.csv"; Md5="513962464c413fc30b2030547a12868a" },
  @{ Name="not-phishing.csv"; Md5="f5d218eb67f5d7bd0571e8089a8fc392" },
  @{ Name="phishing_5001-5151.zip"; Md5="50970df93524466719b61b24f48679e3" },
  @{ Name="not-phishing_5001-5244.zip"; Md5="fbc1035a63b8bf84b6945e1449e94359" }
)

New-Item -ItemType Directory -Force -Path $downloadRoot | Out-Null
New-Item -ItemType Directory -Force -Path $extractRoot | Out-Null
New-Item -ItemType Directory -Force -Path $runtimeReportRoot | Out-Null

function Test-VerifiedDownload {
  param(
    [Parameter(Mandatory=$true)][string]$Path,
    [Parameter(Mandatory=$true)][string]$ExpectedMd5
  )

  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
    return $false
  }

  $actual = (Get-FileHash -Algorithm MD5 -LiteralPath $Path).Hash.ToLowerInvariant()
  if ($actual -ne $ExpectedMd5.ToLowerInvariant()) {
    throw "MD5 mismatch for $Path`: expected $ExpectedMd5, got $actual"
  }

  return $true
}

foreach ($entry in $files) {
  $target = Join-Path $downloadRoot $entry.Name

  if (Test-VerifiedDownload -Path $target -ExpectedMd5 $entry.Md5) {
    Write-Host "Reusing verified $($entry.Name)"
    continue
  }

  if (-not $AcknowledgeLargeDownload) {
    throw "Missing $($entry.Name). Re-run with -AcknowledgeLargeDownload only if a download is actually required."
  }

  $url = "https://zenodo.org/records/8041387/files/$($entry.Name)?download=1"
  Write-Host "Downloading $($entry.Name)..."
  & curl.exe -L --fail --retry 3 --retry-delay 5 --output $target $url
  if ($LASTEXITCODE -ne 0) {
    throw "Download failed: $($entry.Name)"
  }

  if (-not (Test-VerifiedDownload -Path $target -ExpectedMd5 $entry.Md5)) {
    throw "Download verification failed unexpectedly: $($entry.Name)"
  }
}

$extractor = Join-Path $RepoRoot "scripts\extract-stage-b-html-only.py"
if (-not (Test-Path -LiteralPath $extractor -PathType Leaf)) {
  throw "Selective extractor is missing: $extractor"
}

$jobs = @(
  @{
    Zip = Join-Path $downloadRoot "phishing_5001-5151.zip"
    Destination = Join-Path $extractRoot "phishing_5001-5151"
    Report = Join-Path $runtimeReportRoot "phishing_5001-5151-extraction.json"
  },
  @{
    Zip = Join-Path $downloadRoot "not-phishing_5001-5244.zip"
    Destination = Join-Path $extractRoot "not-phishing_5001-5244"
    Report = Join-Path $runtimeReportRoot "not-phishing_5001-5244-extraction.json"
  }
)

foreach ($job in $jobs) {
  if (Test-Path -LiteralPath $job.Destination) {
    Write-Host "Removing partial extraction: $($job.Destination)"
    cmd.exe /d /c "rd /s /q `"$($job.Destination)`""
    if ($LASTEXITCODE -ne 0 -and (Test-Path -LiteralPath $job.Destination)) {
      throw "Could not remove partial extraction directory: $($job.Destination)"
    }
  }

  New-Item -ItemType Directory -Force -Path $job.Destination | Out-Null

  Write-Host "Extracting safe HTML/HTM only from $(Split-Path -Leaf $job.Zip)..."
  & python $extractor $job.Zip $job.Destination --report $job.Report
  if ($LASTEXITCODE -ne 0) {
    throw "Selective HTML extraction failed for: $($job.Zip)"
  }
}

Write-Host ""
Write-Host "Stage B Task 18 selective HTML extraction completed."
Write-Host "Downloads reused from: $downloadRoot"
Write-Host "HTML captures extracted under: $extractRoot"
Write-Host "Extraction reports: $runtimeReportRoot"
Write-Host ""
Write-Host "Next run the dataset inspector."
