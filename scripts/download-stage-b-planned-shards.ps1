param(
  [Parameter(Mandatory=$true)]
  [string]$Plan,

  [string]$Destination = ".\Upgrades\Downloads\Zenodo-8041387-Scale",

  [switch]$AcknowledgeLargeDownload,

  [int]$Timeout = 120,

  [int]$Retries = 8
)

$ErrorActionPreference = "Stop"

$argsList = @(
  "-m", "scripts.download_stage_b_planned_shards",
  "--plan", $Plan,
  "--destination", $Destination,
  "--timeout", "$Timeout",
  "--retries", "$Retries"
)

if ($AcknowledgeLargeDownload) {
  $argsList += "--acknowledge-large-download"
}

& python @argsList
if ($LASTEXITCODE -ne 0) {
  throw "Task 19 range-safe planned shard download failed."
}
