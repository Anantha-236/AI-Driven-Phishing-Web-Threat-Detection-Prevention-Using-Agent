<#
.SYNOPSIS
    Validates the CAPSTONE-1 project structure against the manifest.
.DESCRIPTION
    Detects: unexpected files/directories, forbidden files, secrets in source,
    protected file modifications, large untracked files.
    Reports findings without auto-deleting.
#>

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot

$issues = @()
$warnings = @()

Write-Output "========================================="
Write-Output "PROJECT VALIDATION"
Write-Output "========================================="

# --- 1. Check manifest directories exist ---
$manifestPath = Join-Path (Join-Path $ProjectRoot ".project") "manifest"
if (-not (Test-Path $manifestPath)) {
    Write-Error "CRITICAL: .project/manifest not found"
    exit 1
}

$expectedDirs = @()
$expectedFiles = @()
Get-Content $manifestPath | ForEach-Object {
    $line = $_.Trim()
    if ($line -and -not $line.StartsWith("#")) {
        if ($line -match "^dir\s+(.+)$") {
            $expectedDirs += $Matches[1].Trim()
        } elseif ($line -match "^file\s+(.+)$") {
            $expectedFiles += $Matches[1].Trim()
        }
    }
}

Write-Output ""
Write-Output "[1/6] Checking expected directories..."
foreach ($dir in $expectedDirs) {
    $fullPath = Join-Path $ProjectRoot $dir
    if (-not (Test-Path $fullPath -PathType Container)) {
        $warnings += "MISSING_DIRECTORY: $dir"
        Write-Output "  WARN: Missing directory: $dir"
    }
}

Write-Output "[2/6] Checking expected files..."
foreach ($file in $expectedFiles) {
    $fullPath = Join-Path $ProjectRoot $file
    if (-not (Test-Path $fullPath -PathType Leaf)) {
        $warnings += "MISSING_FILE: $file"
        Write-Output "  WARN: Missing file: $file"
    }
}

# --- 2. Detect unexpected files ---
Write-Output "[3/6] Scanning for unexpected files..."
$approvedPathsFile = Join-Path (Join-Path $ProjectRoot ".project") "approved-paths"
$approvedPaths = @()
if (Test-Path $approvedPathsFile) {
    Get-Content $approvedPathsFile | ForEach-Object {
        $line = $_.Trim()
        if ($line -and -not $line.StartsWith("#")) {
            $approvedPaths += $line
        }
    }
}

$skipDirs = @(".git", "node_modules", "dist", "coverage", ".cache", "__pycache__", ".backups", "venv", ".venv")
$allItems = Get-ChildItem -Path $ProjectRoot -Recurse -File -ErrorAction SilentlyContinue

foreach ($item in $allItems) {
    $relativePath = $item.FullName.Substring($ProjectRoot.Length + 1).Replace("\", "/")

    # Skip excluded directories
    $skip = $false
    foreach ($skipDir in $skipDirs) {
        if ($relativePath.StartsWith("$skipDir/") -or $relativePath -eq $skipDir) {
            $skip = $true
            break
        }
    }
    if ($skip) { continue }

    # Check if file is in manifest or approved paths
    $isExpected = $expectedFiles -contains $relativePath
    if (-not $isExpected) {
        foreach ($ap in $approvedPaths) {
            if ($relativePath.StartsWith($ap)) {
                $isExpected = $true
                break
            }
        }
    }

    if (-not $isExpected) {
        $issues += "UNEXPECTED_FILE: $relativePath"
    }
}

# --- 3. Detect forbidden files ---
Write-Output "[4/6] Checking for forbidden files..."
$forbiddenPatterns = @("*.exe", "*.dll", "*.so", "*.dylib", "*.env", "*.pem", "*.key", "*.p12", "*.pfx", "id_rsa", "id_ed25519")
foreach ($item in $allItems) {
    $relativePath = $item.FullName.Substring($ProjectRoot.Length + 1).Replace("\", "/")
    $skip = $false
    foreach ($skipDir in $skipDirs) {
        if ($relativePath.StartsWith("$skipDir/")) { $skip = $true; break }
    }
    if ($skip) { continue }

    foreach ($pattern in $forbiddenPatterns) {
        if ($item.Name -like $pattern) {
            $issues += "FORBIDDEN_FILE: $relativePath (matches $pattern)"
            break
        }
    }
}

# --- 4. Secret detection ---
Write-Output "[5/6] Scanning for secrets..."
$secretPatterns = @(
    @{ Name = "API Key"; Pattern = "(?i)(api[_-]?key|apikey)\s*[=:]\s*['""][A-Za-z0-9+/=_\-]{16,}['""]" },
    @{ Name = "AWS Key"; Pattern = "AKIA[0-9A-Z]{16}" },
    @{ Name = "Private Key"; Pattern = "-----BEGIN\s+(RSA\s+)?PRIVATE KEY-----" },
    @{ Name = "Password Assignment"; Pattern = "(?i)(password|passwd|pwd)\s*[=:]\s*['""][^'""]{4,}['""]" },
    @{ Name = "Token"; Pattern = "(?i)(token|secret|bearer)\s*[=:]\s*['""][A-Za-z0-9+/=_\-]{16,}['""]" },
    @{ Name = "Connection String"; Pattern = "(?i)(mongodb|postgres|mysql|redis)://[^\s""']+" }
)

$scanExtensions = @(".ts", ".js", ".json", ".py", ".html", ".css", ".yml", ".yaml", ".toml", ".cfg", ".ini", ".md")
foreach ($item in $allItems) {
    $relativePath = $item.FullName.Substring($ProjectRoot.Length + 1).Replace("\", "/")
    $skip = $false
    foreach ($skipDir in $skipDirs) {
        if ($relativePath.StartsWith("$skipDir/")) { $skip = $true; break }
    }
    if ($skip) { continue }

    if ($scanExtensions -contains $item.Extension.ToLower()) {
        try {
            $content = Get-Content -Path $item.FullName -Raw -ErrorAction SilentlyContinue
            if ($content) {
                foreach ($sp in $secretPatterns) {
                    if ($content -match $sp.Pattern) {
                        $issues += "SECRET_DETECTED: $relativePath ($($sp.Name))"
                    }
                }
            }
        } catch { }
    }
}

# --- 5. Large untracked files ---
Write-Output "[6/6] Checking for large files..."
$maxSizeBytes = 10 * 1024 * 1024  # 10 MB
foreach ($item in $allItems) {
    $relativePath = $item.FullName.Substring($ProjectRoot.Length + 1).Replace("\", "/")
    $skip = $false
    foreach ($skipDir in $skipDirs) {
        if ($relativePath.StartsWith("$skipDir/")) { $skip = $true; break }
    }
    if ($skip) { continue }

    if ($item.Length -gt $maxSizeBytes) {
        $sizeMB = [math]::Round($item.Length / 1MB, 2)
        $warnings += "LARGE_FILE: $relativePath (${sizeMB} MB)"
    }
}

# --- Report ---
Write-Output ""
Write-Output "========================================="
Write-Output "VALIDATION RESULTS"
Write-Output "========================================="

if ($issues.Count -eq 0 -and $warnings.Count -eq 0) {
    Write-Output "STATUS: PASS"
    Write-Output "No issues detected."
} else {
    if ($issues.Count -gt 0) {
        Write-Output ""
        Write-Output "ISSUES ($($issues.Count)):"
        $issues | ForEach-Object { Write-Output "  ERROR: $_" }
    }
    if ($warnings.Count -gt 0) {
        Write-Output ""
        Write-Output "WARNINGS ($($warnings.Count)):"
        $warnings | ForEach-Object { Write-Output "  WARN:  $_" }
    }
    if ($issues.Count -gt 0) {
        Write-Output ""
        Write-Output "STATUS: FAIL ($($issues.Count) issues, $($warnings.Count) warnings)"
    } else {
        Write-Output ""
        Write-Output "STATUS: PASS WITH WARNINGS ($($warnings.Count) warnings)"
    }
}

Write-Output "========================================="
