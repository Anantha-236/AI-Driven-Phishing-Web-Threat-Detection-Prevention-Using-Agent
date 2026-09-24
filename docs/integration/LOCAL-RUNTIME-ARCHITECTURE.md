# CAPSTONE-1 Local Runtime Architecture

## Purpose

This runtime is the local-first development prototype for the CAPSTONE-1 browser-based privacy-preserving assessment flow. It is intentionally kept small and deterministic so the browser extension can be validated end-to-end without beginning ML model training work.

## Runtime chain

1. PostgreSQL database
   - Read from .env or local Windows service.
   - Required for observation persistence and health checks.
   - Default connection: localhost:5432 / capstone1

2. Backend API
   - Command: `python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000`
   - Health endpoint: `/api/v1/health`
   - Observation endpoint: `/api/v1/observations`

3. Manual scenario server
   - Command: `node scripts/manual-browser-acceptance-server.mjs`
   - Host: `http://127.0.0.1:41731/`
   - Provides controlled pages for `/benign`, `/suspicious`, `/high-risk`, `/dynamic`, and `/privacy`

4. Extension build
   - Command: `npm run build`
   - Build output: `dist/`
   - Manifest v3 bundle includes content script, service worker, popup, and offscreen assets

5. Browser verification
   - Command: `npx playwright test tests/browser/debug-extension.spec.ts --project=chromium-extension`
   - Validates the real extension path loads in Chromium and the content script executes

## Health gates

The start script waits for these gates before declaring READY:

- PostgreSQL connection succeeds
- Backend health responds at `http://127.0.0.1:8000/api/v1/health`
- Scenario server responds at `http://127.0.0.1:41731/`
- Extension build exits with code 0
- Browser verification passes in real Chromium

## State files

The runtime writes lifecycle tracking under `.runtime/`:

- `.runtime/capstone-state.json` for process IDs and timestamps
- `.runtime/logs/*.log` for backend, scenario, build, and verify output

## Safety notes

- The project does not collect raw form values, passwords, or OTPs.
- Browser evidence remains structural and privacy-preserving.
- The orchestration script only controls CAPSTONE-1-owned processes and does not modify unrelated services.
