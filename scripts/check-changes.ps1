<#
.SYNOPSIS
    Detects created, modified, and deleted files since last check.
.DESCRIPTION
    Compares current project state against git status and reports changes.
#>

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot

Write-Output "========================================="
Write-Output "CHANGE DETECTION"
Write-Output "========================================="
Write-Output "Timestamp: $(Get-Date -Format 'o')"
Write-Output ""

$gitPath = "$env:LOCALAPPDATA\Programs\Git\cmd\git.exe"
if (-not (Test-Path $gitPath)) { $gitPath = "git" }

try {
    $status = & $gitPath -C $ProjectRoot status --porcelain 2>$null
    if ($LASTEXITCODE -ne 0) { throw "git failed" }

    $created = @()
    $modified = @()
    $deleted = @()
    $untracked = @()

    foreach ($line in $status) {
        if (-not $line) { continue }
        $code = $line.Substring(0, 2)
        $filePath = $line.Substring(3).Trim().Trim('"')

        switch -Regex ($code) {
            "^\?\?" { $untracked += $filePath }
            "^A"    { $created += $filePath }
            "^M|^ M" { $modified += $filePath }
            "^D|^ D" { $deleted += $filePath }
            "^R"    { $modified += $filePath }
            default { $modified += $filePath }
        }
    }

    if ($created.Count -gt 0) {
        Write-Output "CREATED ($($created.Count)):"
        $created | ForEach-Object { Write-Output "  + $_" }
        Write-Output ""
    }
    if ($modified.Count -gt 0) {
        Write-Output "MODIFIED ($($modified.Count)):"
        $modified | ForEach-Object { Write-Output "  ~ $_" }
        Write-Output ""
    }
    if ($deleted.Count -gt 0) {
        Write-Output "DELETED ($($deleted.Count)):"
        $deleted | ForEach-Object { Write-Output "  - $_" }
        Write-Output ""
    }
    if ($untracked.Count -gt 0) {
        Write-Output "UNTRACKED ($($untracked.Count)):"
        $untracked | ForEach-Object { Write-Output "  ? $_" }
        Write-Output ""
    }

    $totalChanges = $created.Count + $modified.Count + $deleted.Count + $untracked.Count
    if ($totalChanges -eq 0) {
        Write-Output "No changes detected."
    } else {
        Write-Output "Total changes: $totalChanges"
    }
} catch {
    Write-Output "Git not available. Falling back to file system scan."
    Write-Output "All files currently in project:"
    $skipDirs = @(".git", "node_modules", "dist", "coverage", ".cache", "__pycache__", ".backups")
    Get-ChildItem -Path $ProjectRoot -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
        $rel = $_.FullName.Substring($ProjectRoot.Length + 1).Replace("\", "/")
        $skip = $false
        foreach ($sd in $skipDirs) { if ($rel.StartsWith("$sd/")) { $skip = $true; break } }
        if (-not $skip) { Write-Output "  $rel" }
    }
}

Write-Output "========================================="
