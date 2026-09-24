# CAPSTONE-1 One-Command Local Startup

## Script usage

From the repository root, run:

```powershell
./scripts/start-capstone.ps1
```

Useful companion commands:

```powershell
./scripts/status-capstone.ps1
./scripts/stop-capstone.ps1
```

## What the startup script does

1. Loads `.env` values into the current process.
2. Verifies local Node and Python tools are present.
3. Validates PostgreSQL connectivity.
4. Starts the backend API if it is not already running.
5. Starts the manual browser scenario server.
6. Waits for both services to become healthy.
7. Runs `npm run build` for the extension bundle.
8. Executes the real browser verification test in Chromium.
9. Prints `CAPSTONE-1 READY` only after all checks pass.

## Port contract

- Backend: `127.0.0.1:8000`
- Manual scenario server: `127.0.0.1:41731`
- PostgreSQL: `127.0.0.1:5432`

## Typical expected result

The script should end with a success summary similar to:

```text
=========================================
CAPSTONE-1 READY
=========================================
Backend: http://127.0.0.1:8000/api/v1/health
Scenario server: http://127.0.0.1:41731/
Build output: C:\...\dist
Runtime state: C:\...\.runtime\capstone-state.json
=========================================
```

## Troubleshooting

- If PostgreSQL is not reachable, the script tries the local Windows service first and then the Docker Compose fallback.
- If the backend fails health checks, review `.runtime/logs/backend.log`.
- If the scenario server fails, review `.runtime/logs/manual-scenario.log`.
- If the extension verification fails, review `.runtime/logs/verify.log` and `.runtime/logs/build.log`.
