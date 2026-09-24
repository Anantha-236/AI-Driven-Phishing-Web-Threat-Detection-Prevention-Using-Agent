# STAGE 0 SECURITY AND RUNTIME BASELINE

SECURITY_GATE=PASS
ENV_IGNORED=YES
ENV_TRACKED=NO
ENV_IN_HEAD=NO
ENV_IN_GIT_HISTORY=NO
SECRET_HISTORY_STATUS=CLEAN

POSTGRES_SERVICE=PASS
POSTGRES_PORT=PASS
POSTGRES_AUTHENTICATION=PASS
DATABASE_EXISTS=PASS
REQUIRED_TABLES=5/5
OBSERVATION_SCHEMA=PASS
OBSERVATION_COUNT=63

FASTAPI_STATUS=PASS
DATABASE_STATUS_FROM_FASTAPI=PASS
DATABASE_RUNTIME=POSTGRESQL
BACKEND_TO_POSTGRESQL=PASS

BROWSER_TO_BACKEND_IMPLEMENTED=YES
BROWSER_TO_DATABASE_IMPLEMENTED=YES
BROWSER_TO_DATABASE_RUNTIME=NOT_VERIFIED

AUTHORITATIVE_DATABASE_RUNTIME=PostgreSQL
OUTDATED_DOCUMENTS=docs/GITHUB-READY-REPORT.md; docs/PROJECT-FILE-AUDIT.md; docs/integration/BASELINE-RECOVERY-REPORT.md
STARTUP_SCRIPT_STATUS=PASS

CURRENT_BLOCKER=TypeScript typecheck fails in browser-extension/src/content/observer.ts at the existing HTMLElement versus Document comparison. This is an engineering blocker, not a security-gate blocker; no application source was changed during this baseline.
NEXT_STAGE=FASTAPI to PostgreSQL observation persistence verification, after resolving the typecheck blocker under a separate change scope.

## Evidence

- The local .env exists, is ignored by .gitignore, is untracked, and is absent from HEAD and reachable Git history. Its contents were not printed.
- The reachable repository history contains no .env path and no real credential assignment; configuration-key history hits are attributable to non-secret configuration/template text.
- PostgreSQL 18 service and port 5432 were reachable. Authentication to capstone1 as postgres passed using the protected local environment.
- capstone1 reported all five required tables: service_profiles, service_domains, model_versions, policy_versions, and observations.
- The required observation metadata columns were present. The read-only observation count was 63; no test row was inserted.
- The actual FastAPI health route returned HTTP 200 and database CONNECTED.
- Source inspection confirms backend/database.py imports psycopg and connects to PostgreSQL; store_observation() inserts into observations. The browser service worker posts sanitized observation metadata to /api/v1/observations.
- Browser-to-database runtime was not tested in this Stage 0 run. No browser E2E was run.
- scripts/start-capstone.ps1 contains the current PostgreSQL preflight and FastAPI startup, but its full workflow also launches the manual scenario server, builds the extension, and runs browser verification. It was inspected, not executed, for this Stage 0 baseline.
- npm run build passed. npm run typecheck failed with one existing TypeScript diagnostic in observer.ts.

## Constraints observed

No browser extension logic, ML, database schema, FastAPI architecture, or feature behavior was modified. No browser E2E was run and no GitHub push was performed.
