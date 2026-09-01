<#
.SYNOPSIS
    Creates a timestamped backup snapshot of the CAPSTONE-1 project.
.DESCRIPTION
    Backs up source, tests, models, schemas, documentation, configuration,
    scripts, and project metadata. Excludes node_modules, coverage, dist, cache,
    and temporary files per backup-config.
.PARAMETER Reason
    A description of why this backup is being created (change ID or description).
#>
param(
    [Parameter(Mandatory=$true)]
    [string]$Reason
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
if (-not (Test-Path (Join-Path $ProjectRoot ".project\manifest"))) {
    Write-Error "Cannot find .project/manifest from $ProjectRoot"
    exit 1
}

$BackupId = "backup-" + (Get-Date -Format "yyyyMMdd-HHmmss") + "-" + ([guid]::NewGuid().ToString().Substring(0,8))
$Timestamp = Get-Date -Format "o"
$BackupDir = Join-Path (Join-Path $ProjectRoot ".backups") $BackupId

# Read backup config
$ExcludePatterns = @("node_modules", "coverage", "dist", ".cache", "__pycache__", "*.pyc", "*.tmp", "*.temp", ".backups", ".git", "venv", ".venv", "*.log")
$BackupConfigPath = Join-Path (Join-Path $ProjectRoot ".project") "backup-config"
if (Test-Path $BackupConfigPath) {
    Get-Content $BackupConfigPath | ForEach-Object {
        if ($_ -match "^exclude=(.+)$") {
            $pattern = $Matches[1].Trim()
            if ($ExcludePatterns -notcontains $pattern) {
                $ExcludePatterns += $pattern
            }
        }
    }
}

# Get git state
$gitState = "no-git"
$gitPath = "$env:LOCALAPPDATA\Programs\Git\cmd\git.exe"
if (-not (Test-Path $gitPath)) { $gitPath = "git" }
try {
    $gitState = & $gitPath -C $ProjectRoot rev-parse HEAD 2>$null
    if (-not $gitState) { $gitState = "no-commits" }
    $gitBranch = & $gitPath -C $ProjectRoot branch --show-current 2>$null
    $gitDirty = & $gitPath -C $ProjectRoot status --porcelain 2>$null
    $gitState = "branch=$gitBranch commit=$gitState dirty=$($gitDirty.Count -gt 0)"
} catch {
    $gitState = "git-unavailable"
}

# Create backup directory
New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null

# Collect files to backup
$allFiles = Get-ChildItem -Path $ProjectRoot -Recurse -File -ErrorAction SilentlyContinue
$filesToBackup = @()

foreach ($file in $allFiles) {
    $relativePath = $file.FullName.Substring($ProjectRoot.Length + 1).Replace("\", "/")
    $skip = $false
    foreach ($pattern in $ExcludePatterns) {
        if ($relativePath -like "*$pattern*" -or $file.Name -like $pattern) {
            $skip = $true
            break
        }
    }
    if (-not $skip) {
        $filesToBackup += $file
    }
}

# Copy files preserving structure
$checksums = @()
foreach ($file in $filesToBackup) {
    $relativePath = $file.FullName.Substring($ProjectRoot.Length + 1)
    $destPath = Join-Path (Join-Path $BackupDir "files") $relativePath
    $destDir = Split-Path -Parent $destPath
    if (-not (Test-Path $destDir)) {
        New-Item -ItemType Directory -Path $destDir -Force | Out-Null
    }
    Copy-Item -Path $file.FullName -Destination $destPath -Force
    $hash = (Get-FileHash -Path $file.FullName -Algorithm SHA256).Hash
    $checksums += "$hash  $($relativePath.Replace('\', '/'))"
}

# Write manifest
$manifestContent = @"
backup_id=$BackupId
timestamp=$Timestamp
git_state=$gitState
reason=$Reason
file_count=$($filesToBackup.Count)
"@
$manifestContent | Out-File -FilePath (Join-Path $BackupDir "backup-manifest.txt") -Encoding utf8

# Write checksums
$checksums | Out-File -FilePath (Join-Path $BackupDir "checksums-sha256.txt") -Encoding utf8

# Write file list
$filesToBackup | ForEach-Object {
    $_.FullName.Substring($ProjectRoot.Length + 1).Replace("\", "/")
} | Out-File -FilePath (Join-Path $BackupDir "file-list.txt") -Encoding utf8

Write-Output "========================================="
Write-Output "BACKUP CREATED"
Write-Output "========================================="
Write-Output "Backup ID:  $BackupId"
Write-Output "Timestamp:  $Timestamp"
Write-Output "Location:   $BackupDir"
Write-Output "Files:      $($filesToBackup.Count)"
Write-Output "Reason:     $Reason"
Write-Output "Git State:  $gitState"
Write-Output "========================================="
