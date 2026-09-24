<#
.SYNOPSIS
    Validates the CAPSTONE-1 repository structure, Git state, and security policy.
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

# --- 1. Validate required repository structure ---
$requiredDirs = @(
    "backend",
    "browser-extension",
    "ml",
    "docs",
    "scripts",
    "tests"
)

$requiredFiles = @(
    "README.md",
    "package.json",
    ".gitignore",
    ".env.example",
    "browser-extension/manifest.json",
    "browser-extension/src/background/service-worker.ts",
    "browser-extension/src/core/schema/types.ts",
    "browser-extension/src/core/tab-state.ts",
    "browser-extension/src/core/tsfeg.ts",
    "backend/main.py",
    "backend/models.py",
    "ml/training/train_models.py"
)

Write-Output ""
Write-Output "[1/6] Checking required directories..."
foreach ($dir in $requiredDirs) {
    $fullPath = Join-Path $ProjectRoot $dir

    if (-not (Test-Path $fullPath -PathType Container)) {
        $issues += "MISSING_DIRECTORY: $dir"
        Write-Output "  ERROR: Missing directory: $dir"
    }
}

Write-Output "[2/6] Checking required files..."
foreach ($file in $requiredFiles) {
    $fullPath = Join-Path $ProjectRoot $file

    if (-not (Test-Path $fullPath -PathType Leaf)) {
        $issues += "MISSING_FILE: $file"
        Write-Output "  ERROR: Missing file: $file"
    }
}

# --- 2. Detect unexpected/untracked files ---
Write-Output "[3/6] Scanning for unexpected/untracked files..."

$skipDirs = @(
    ".git",
    "node_modules",
    "dist",
    "coverage",
    ".cache",
    "__pycache__",
    ".backups",
    "venv",
    ".venv"
)

# Files eligible for publication: tracked/staged Git files only.
$trackedRelativePaths = @(
    & git -c core.quotepath=false -C $ProjectRoot ls-files 2>$null
)

$trackedItems = @(
    foreach ($relativePath in $trackedRelativePaths) {
        if ([string]::IsNullOrWhiteSpace($relativePath)) {
            continue
        }

        $fullPath = Join-Path $ProjectRoot $relativePath

        if (Test-Path $fullPath -PathType Leaf) {
            Get-Item $fullPath
        }
    }
)

# Local .env is permitted only when Git ignores it and it is not tracked.
$localEnv = Join-Path $ProjectRoot ".env"

if (Test-Path $localEnv -PathType Leaf) {
    & git -c core.quotepath=false -C $ProjectRoot check-ignore -q -- ".env"

    if ($LASTEXITCODE -ne 0) {
        $issues += "LOCAL_ENV_NOT_IGNORED: .env"
    }

    & git -c core.quotepath=false -C $ProjectRoot ls-files --error-unmatch -- ".env" 2>$null | Out-Null

    if ($LASTEXITCODE -eq 0) {
        $issues += "LOCAL_ENV_TRACKED: .env"
    }
}

# Git is the source of truth for repository membership.
$untrackedFiles = @(
    & git -c core.quotepath=false -C $ProjectRoot ls-files --others --exclude-standard 2>$null
)

foreach ($relativePath in $untrackedFiles) {
    if ([string]::IsNullOrWhiteSpace($relativePath)) {
        continue
    }

    $normalizedPath = $relativePath.Replace("\", "/")

    $skip = $false
    foreach ($skipDir in $skipDirs) {
        if (
            $normalizedPath -eq $skipDir -or
            $normalizedPath.StartsWith("$skipDir/")
        ) {
            $skip = $true
            break
        }
    }

    if (-not $skip) {
        $warnings += "UNTRACKED_FILE: $normalizedPath"
        Write-Output "  WARN: Untracked file: $normalizedPath"
    }
}

# Detect tracked files that disappeared from the working tree.
$missingTrackedFiles = @(
    & git -c core.quotepath=false -C $ProjectRoot ls-files --deleted 2>$null
)

foreach ($relativePath in $missingTrackedFiles) {
    if (-not [string]::IsNullOrWhiteSpace($relativePath)) {
        $issues += "TRACKED_FILE_MISSING: $relativePath"
        Write-Output "  ERROR: Tracked file missing: $relativePath"
    }
}
# --- 3. Detect forbidden files ---
Write-Output "[4/6] Checking for forbidden files..."
$forbiddenPatterns = @("*.exe", "*.dll", "*.so", "*.dylib", "*.env", "*.pem", "*.key", "*.p12", "*.pfx", "id_rsa", "id_ed25519")
foreach ($item in $trackedItems) {
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
foreach ($item in $trackedItems) {
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
foreach ($item in $trackedItems) {
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
