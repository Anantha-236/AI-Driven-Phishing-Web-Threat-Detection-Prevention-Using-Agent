param([switch]$Verify)
$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$PlaywrightConfig = Join-Path $ProjectRoot "playwright.config.ts"
$RuntimeRoot = Join-Path $ProjectRoot ".runtime"
$LogDir = Join-Path $RuntimeRoot "logs"
$StateFile = Join-Path $RuntimeRoot "capstone-state.json"
$BackendLog = Join-Path $LogDir "backend.log"
$BackendErr = Join-Path $LogDir "backend.err.log"
$ScenarioLog = Join-Path $LogDir "manual-scenario.log"
$ScenarioErr = Join-Path $LogDir "manual-scenario.err.log"
$BuildLog = Join-Path $LogDir "build.log"
$VerifyLog = Join-Path $LogDir "verify.log"

function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host "[CAPSTONE] $Message" -ForegroundColor Cyan
}

function Load-EnvFile {
    param([string]$EnvPath)
    if (-not (Test-Path $EnvPath)) { return }
    Get-Content $EnvPath | ForEach-Object {
        $line = $_.Trim()
        if (-not $line -or $line.StartsWith("#")) { return }
        if ($line -match "^([^=]+)=(.*)$") {
            $name = $Matches[1].Trim()
            $value = $Matches[2].Trim()
            if (-not [string]::IsNullOrEmpty($name)) {
                [Environment]::SetEnvironmentVariable($name, $value, "Process")
            }
        }
    }
}

function Test-Command {
    param([string]$Name)
    return $null -ne (Get-Command $Name -ErrorAction SilentlyContinue)
}

function Test-DatabaseConnection {
    $dbHost = [Environment]::GetEnvironmentVariable("DB_HOST", "Process")
    $dbPort = [Environment]::GetEnvironmentVariable("DB_PORT", "Process")
    $dbName = [Environment]::GetEnvironmentVariable("DB_NAME", "Process")
    $dbUser = [Environment]::GetEnvironmentVariable("DB_USER", "Process")
    $dbPassword = [Environment]::GetEnvironmentVariable("DB_PASSWORD", "Process")

    if (-not $dbHost -or -not $dbPort -or -not $dbName -or -not $dbUser) {
        return $false
    }

    try {
        $cmd = @"
import os
import sys
import psycopg
host = os.getenv('DB_HOST') or os.getenv('HOST') or 'localhost'
port = int(os.getenv('DB_PORT') or os.getenv('PORT') or '5432')
dbname = os.getenv('DB_NAME') or os.getenv('DATABASE') or 'capstone1'
user = os.getenv('DB_USER') or os.getenv('USER') or 'postgres'
password = os.getenv('DB_PASSWORD') or os.getenv('POSTGRES_PASSWORD') or ''
try:
    conn = psycopg.connect(host=host, port=port, dbname=dbname, user=user, password=password, connect_timeout=5)
    conn.close()
    print('OK')
except Exception as exc:
    print(f'FAIL:{exc}')
    sys.exit(1)
"@
        $output = & python -c $cmd 2>&1
        return ($LASTEXITCODE -eq 0) -and ($output -match 'OK')
    } catch {
        return $false
    }
}

function Ensure-Postgres {
    $dbOk = Test-DatabaseConnection
    if ($dbOk) {
        Write-Step "PostgreSQL connection validated."
        return
    }

    $service = Get-Service -Name "postgresql-x64-18" -ErrorAction SilentlyContinue
    if ($service) {
        if ($service.Status -ne "Running") {
            Write-Step "Starting PostgreSQL Windows service."
            Start-Service -Name "postgresql-x64-18"
        }
        if (Test-DatabaseConnection) {
            return
        }
    }

    $dockerCmd = Get-Command docker -ErrorAction SilentlyContinue
    if ($dockerCmd) {
        Write-Step "Starting PostgreSQL via Docker Compose fallback."
        Push-Location $ProjectRoot
        try {
            docker compose up -d postgres
        } finally {
            Pop-Location
        }
        if (Test-DatabaseConnection) {
            return
        }
    }

    throw "Unable to reach PostgreSQL. Verify .env credentials or start the local postgres service."
}

function Wait-ForHttp {
    param(
        [string]$Url,
        [int]$TimeoutSeconds = 45
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        try {
            $response = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 5
            if ($response.StatusCode -ge 200 -and $response.StatusCode -lt 400) {
                return
            }
        } catch {
            Start-Sleep -Seconds 2
        }
    }

    throw "Timed out waiting for service health at $Url"
}

function Persist-State {
    param([hashtable]$State)
    $State | ConvertTo-Json -Depth 10 | Set-Content -Path $StateFile -Encoding UTF8
}

New-Item -ItemType Directory -Path $RuntimeRoot -Force | Out-Null
New-Item -ItemType Directory -Path $LogDir -Force | Out-Null

Load-EnvFile -EnvPath (Join-Path $ProjectRoot ".env")

Write-Step "Validating required local tooling"
foreach ($tool in @("node", "npm.cmd", "npx.cmd", "python")) {
    if (-not (Test-Command $tool)) {
        throw "Required tool not found: $tool"
    }
}

if (-not (Test-Path -LiteralPath $PlaywrightConfig -PathType Leaf)) {
    throw "Playwright configuration not found: $PlaywrightConfig"
}

$pythonExe = (Get-Command python).Source
$pythonCheck = & $pythonExe -c "import fastapi, uvicorn, psycopg, dotenv; print('OK')" 2>$null
if ($LASTEXITCODE -ne 0) {
    throw "Python runtime dependencies are not installed. Install the backend requirements before starting CAPSTONE-1."
}

Write-Step "Checking database readiness"
Ensure-Postgres

Push-Location -LiteralPath $ProjectRoot
try {
    foreach ($servicePort in @(8000, 41731)) {
        if (Get-NetTCPConnection -State Listen -LocalPort $servicePort -ErrorAction SilentlyContinue) {
            throw "Port $servicePort is already in use. Use the existing running service, or stop the tracked CAPSTONE processes before starting again."
        }
    }
    Write-Step "Starting backend API on http://127.0.0.1:8000"
    $backendArgs = @("-m", "uvicorn", "backend.main:app", "--host", "127.0.0.1", "--port", "8000", "--log-level", "warning", "--no-access-log")
    $backendProc = Start-Process -FilePath $pythonExe -ArgumentList $backendArgs -WorkingDirectory $ProjectRoot -WindowStyle Hidden -PassThru -RedirectStandardOutput $BackendLog -RedirectStandardError $BackendErr

    Write-Step "Starting manual browser scenario server on http://127.0.0.1:41731"
    $scenarioArgs = @("scripts/manual-browser-acceptance-server.mjs")
    $scenarioProc = Start-Process -FilePath "node" -ArgumentList $scenarioArgs -WorkingDirectory $ProjectRoot -WindowStyle Hidden -PassThru -RedirectStandardOutput $ScenarioLog -RedirectStandardError $ScenarioErr

    $state = @{
        startedAt = (Get-Date).ToString("o")
        backend = @{ pid = $backendProc.Id; port = 8000; log = $BackendLog }
        manualServer = @{ pid = $scenarioProc.Id; port = 41731; log = $ScenarioLog }
    }
    Persist-State -State $state

    Write-Step "Waiting for backend and scenario-server health checks"
    Wait-ForHttp -Url "http://127.0.0.1:8000/api/v1/health" -TimeoutSeconds 45
    Wait-ForHttp -Url "http://127.0.0.1:41731/" -TimeoutSeconds 30

    function Invoke-LoggedTool {
        param([string]$Executable, [string[]]$ToolArguments, [string]$LogPath)
        # Windows PowerShell otherwise promotes ordinary native stderr warnings to terminating errors.
        $ErrorActionPreference = 'Continue'
        & $Executable @ToolArguments *> $LogPath
        return $LASTEXITCODE
    }
    Write-Step "Building the browser extension"
    $buildExitCode = Invoke-LoggedTool -Executable 'npm.cmd' -ToolArguments @('run', 'build') -LogPath $BuildLog
    if ($buildExitCode -ne 0) {
        throw "Extension build failed. Review $BuildLog"
    }

    if ($Verify) {
        Write-Step "Running browser verification against the real extension path"
        $verificationExitCode = Invoke-LoggedTool -Executable 'npx.cmd' -ToolArguments @('playwright', 'test', 'tests/browser/debug-extension.spec.ts', '--config', $PlaywrightConfig, '--reporter=line', '--project=chromium-extension') -LogPath $VerifyLog
        if ($verificationExitCode -ne 0) {
            throw "Live browser verification failed. Review $VerifyLog"
        }
    }

    Write-Host ""
    Write-Host "=========================================" -ForegroundColor Green
    Write-Host "CAPSTONE-1 READY" -ForegroundColor Green
    Write-Host "=========================================" -ForegroundColor Green
    Write-Host "Backend: http://127.0.0.1:8000/api/v1/health"
    Write-Host "Scenario server: http://127.0.0.1:41731/"
    Write-Host "Build output: $ProjectRoot\dist"
    Write-Host "Load or reload this dist folder in chrome://extensions, then reload the pages to observe."
    Write-Host "READY means local services are running. Use -Verify to also run controlled browser checks."
    Write-Host "Runtime state: $StateFile"
    Write-Host "=========================================" -ForegroundColor Green
} finally {
    Pop-Location
}
