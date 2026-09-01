<#
.SYNOPSIS
    Restores a CAPSTONE-1 project from a backup snapshot.
.PARAMETER BackupId
    The backup ID to restore from (e.g., backup-20260813-171200-abc12345).
.PARAMETER DryRun
    If set, shows what would be restored without making changes.
#>
param(
    [Parameter(Mandatory=$true)]
    [string]$BackupId,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$BackupDir = Join-Path (Join-Path $ProjectRoot ".backups") $BackupId

if (-not (Test-Path $BackupDir)) {
    Write-Error "Backup not found: $BackupDir"
    exit 1
}

# Read and display manifest
$manifestPath = Join-Path $BackupDir "backup-manifest.txt"
if (-not (Test-Path $manifestPath)) {
    Write-Error "Invalid backup: missing manifest"
    exit 1
}

Write-Output "========================================="
Write-Output "RESTORE FROM BACKUP"
Write-Output "========================================="
Get-Content $manifestPath | ForEach-Object { Write-Output $_ }
Write-Output "========================================="

# Validate checksums
$checksumFile = Join-Path $BackupDir "checksums-sha256.txt"
$checksums = @{}
if (Test-Path $checksumFile) {
    Get-Content $checksumFile | ForEach-Object {
        if ($_ -match "^([A-Fa-f0-9]{64})\s+(.+)$") {
            $checksums[$Matches[2]] = $Matches[1]
        }
    }
}

$filesDir = Join-Path $BackupDir "files"
if (-not (Test-Path $filesDir)) {
    Write-Error "Invalid backup: missing files directory"
    exit 1
}

$backupFiles = Get-ChildItem -Path $filesDir -Recurse -File
$validationErrors = @()

foreach ($file in $backupFiles) {
    $relativePath = $file.FullName.Substring($filesDir.Length + 1).Replace("\", "/")
    $hash = (Get-FileHash -Path $file.FullName -Algorithm SHA256).Hash

    if ($checksums.ContainsKey($relativePath)) {
        if ($hash -ne $checksums[$relativePath]) {
            $validationErrors += "CHECKSUM MISMATCH: $relativePath"
        }
    }
}

if ($validationErrors.Count -gt 0) {
    Write-Output ""
    Write-Output "VALIDATION ERRORS:"
    $validationErrors | ForEach-Object { Write-Output "  ERROR: $_" }
    Write-Error "Backup validation failed. Aborting restore."
    exit 1
}

Write-Output "Checksum validation: PASSED ($($backupFiles.Count) files)"

if ($DryRun) {
    Write-Output ""
    Write-Output "DRY RUN - Files that would be restored:"
    foreach ($file in $backupFiles) {
        $relativePath = $file.FullName.Substring($filesDir.Length + 1).Replace("\", "/")
        $destPath = Join-Path $ProjectRoot $relativePath
        $status = if (Test-Path $destPath) { "OVERWRITE" } else { "CREATE" }
        Write-Output "  [$status] $relativePath"
    }
    Write-Output ""
    Write-Output "No changes made (dry run)."
    return
}

# Perform restore
$restored = 0
foreach ($file in $backupFiles) {
    $relativePath = $file.FullName.Substring($filesDir.Length + 1)
    $destPath = Join-Path $ProjectRoot $relativePath
    $destDir = Split-Path -Parent $destPath
    if (-not (Test-Path $destDir)) {
        New-Item -ItemType Directory -Path $destDir -Force | Out-Null
    }
    Copy-Item -Path $file.FullName -Destination $destPath -Force
    $restored++
}

Write-Output ""
Write-Output "========================================="
Write-Output "RESTORE COMPLETE"
Write-Output "========================================="
Write-Output "Restored: $restored files"
Write-Output "========================================="
