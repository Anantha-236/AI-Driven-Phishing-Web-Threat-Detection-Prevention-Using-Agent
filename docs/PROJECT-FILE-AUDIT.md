# Project File Audit — CAPSTONE-1 GitHub-Ready

## Objective

This audit documents the classification of every file in the clean GitHub-ready project. It ensures only active source, configuration, documentation, and assets are committed, while excluding test, debug, prototype, and generated material.

## Full File Inventory

### ACTIVE_SOURCE (Core Implementation)

#### Browser Extension
- `browser-extension/src/background/service-worker.ts` — Runtime event listener and evidence processor
- `browser-extension/src/background/offscreen.ts` — Offscreen document for ONNX runtime isolation
- `browser-extension/src/background/offscreen.html` — Offscreen document markup
- `browser-extension/src/content/collector.ts` — DOM evidence extraction (privacy-safe)
- `browser-extension/src/content/observer.ts` — DOM mutation observer with debouncing
- `browser-extension/src/core/assessment.ts` — Score-to-threat conversion
- `browser-extension/src/core/enforcement.ts` — Policy action enforcement (UI warnings)
- `browser-extension/src/core/policy.ts` — Threat-to-policy action mapping
- `browser-extension/src/core/service-worker-onnx-adapter.ts` — ONNX runtime adapter (service worker context)
- `browser-extension/src/core/offscreen-onnx-adapter.ts` — ONNX runtime adapter (offscreen context)
- `browser-extension/src/core/evidence/artifact-manager.ts` — Evidence artifact persistence and retrieval
- `browser-extension/src/core/evidence/data-type-classifier.ts` — Detected data type classification
- `browser-extension/src/core/schema/index.ts` — Schema root export
- `browser-extension/src/core/schema/types.ts` — All TypeScript type definitions
- `browser-extension/src/core/schema/version.ts` — Schema version constant
- `browser-extension/src/core/profiles/service-profiles.ts` — Service identity profile registry
- `browser-extension/src/core/profiles/observed-behavior.ts` — Observed behavior tracking
- `browser-extension/src/core/profiles/comparator.ts` — Behavior comparison logic
- `browser-extension/src/features/extractor.ts` — Feature extraction (deterministic, 5-dimensional)
- `browser-extension/src/messaging/index.ts` — Message routing between content script and service worker
- `browser-extension/src/ui/popup.ts` — Extension UI popup logic
- `browser-extension/src/ui/popup.html` — Extension UI popup markup
- `browser-extension/vite.config.ts` — Build configuration for extension
- `browser-extension/tsconfig.json` — TypeScript configuration for extension

#### ML Pipeline
- `ml/data/build_dataset_v0_1.py` — Dataset generation script (baseline)
- `ml/data/build_dataset_v0_2.py` — Dataset generation script (improved)
- `ml/data/dataset_v0_1.csv` — Dataset baseline
- `ml/data/dataset_v0_2.csv` — Dataset improved
- `ml/features/extractor.py` — Python feature extraction matching browser logic
- `ml/training/train_baseline_model.py` — Baseline model training
- `ml/training/train_models.py` — Multi-model training pipeline
- `ml/evaluation/generalization_eval.py` — Generalization evaluation
- `ml/evaluation/dataset_quality_audit.py` — Dataset quality analysis
- `ml/evaluation/split_generator.py` — Train/test split generation

#### Backend
- `backend/main.py` — FastAPI application and endpoint definitions
- `backend/app.py` — Stdlib fallback HTTP server implementation
- `backend/database.py` — Database abstraction layer (PostgreSQL)
- `backend/models.py` — Pydantic request/response schemas
- `backend/schema.sql` — SQL table definitions

#### Configuration & Build
- `package.json` — Node dependencies and build scripts
- `package-lock.json` — Locked dependency versions
- `tsconfig.json` — Root TypeScript configuration
- `vitest.config.ts` — Unit/integration test configuration
- `playwright.config.ts` — Browser E2E test configuration

### ACTIVE_CONFIGURATION (Setup & Safety)

- `.env.example` — Environment variable template (no secrets)
- `.gitignore` — Secret and build output exclusion rules
- `docker-compose.yml` — Optional PostgreSQL container definition

### ACTIVE_DOCUMENTATION (Guides & Notes)

- `README.md` — Project overview, setup, and status
- `docs/PROJECT-FILE-AUDIT.md` — This file
- `docs/research/CAPSTONE-1-MANUAL-BROWSER-ACCEPTANCE-RUNBOOK.md` — Manual testing guide

### ACTIVE_ASSET (Model & Static Files)

- `browser-extension/assets/model.onnx` — Exported ONNX logistic regression model
- `ml/data/dataset_v0_2_metadata.json` — Dataset metadata
- `ml/export/baseline_metrics_v0_1.json` — Baseline model performance metrics
- `ml/training/training_results.json` — Training execution results
- `ml/evaluation/dataset_quality_audit_report.json` — Dataset quality report
- `ml/evaluation/splits/split_manifest.json` — Train/test split manifest

### SCRIPTS (Utility & Operational)

- `scripts/validate-project.ps1` — PowerShell project validation
- `scripts/validate-project.sh` — Shell project validation
- `scripts/check-changes.ps1` — Change detection (PowerShell)
- `scripts/check-changes.sh` — Change detection (Shell)
- `scripts/pre-change.ps1` — Pre-change hooks (PowerShell)
- `scripts/pre-change.sh` — Pre-change hooks (Shell)
- `scripts/post-change.ps1` — Post-change hooks (PowerShell)
- `scripts/post-change.sh` — Post-change hooks (Shell)
- `scripts/restore.ps1` — State restoration (PowerShell)
- `scripts/restore.sh` — State restoration (Shell)
- `scripts/gen-toy-model.js` — ONNX toy model generator
- `scripts/manual-browser-acceptance-server.mjs` — Manual acceptance test server
- `scripts/playwright-chromium-chain-probe.mjs` — Browser chain probe diagnostic
- `scripts/playwright-chromium-version.cjs` — Chromium version check
- `scripts/playwright-content-script-proof.mjs` — Content script proof of execution
- `scripts/playwright-feature-vector-check.mjs` — Feature vector validation
- `scripts/backup.ps1` — Project backup (PowerShell) — **ARCHIVE**
- `scripts/backup.sh` — Project backup (Shell) — **ARCHIVE**

### GENERATED OUTPUT (Excluded via .gitignore)

- `backend/__pycache__/` — Python bytecode cache
- `ml/features/__pycache__/` — Python bytecode cache
- `node_modules/` — NPM dependencies
- `dist/` — Built extension bundle
- `coverage/` — Test coverage reports
- `playwright-report/` — Browser test reports
- `test-results/` — Test execution results
- `.cache/` — Build cache

### LOCAL RUNTIME DATA (Excluded via .gitignore)

- `backend/capstone.db` — SQLite database file (local runtime)
- `*.log` — Runtime logs
- `.env` — Real environment secrets (only `.env.example` tracked)

## Classification Decision: Tests and Prototypes

### Status
Tests and old prototype scripts exist in the original project but are **intentionally excluded** from the public GitHub-ready tree for cleanliness.

### Rationale
1. Public GitHub repository should contain only active source and documentation.
2. Test suites can be added to a separate testing branch or CI system later.
3. This ensures the main repo stays focused on the core implementation.

### Note
The original project retains complete test suites in the backup. No test code was deleted.

## Build Artifacts & Dist

### Decision: `.dist/` is Generated Build Output
- **Status**: Excluded from version control
- **Reason**: Generated dynamically by `npm run build`
- **Workflow**: Source → `browser-extension/` → [build] → `dist/` → Extension loaded
- **GitHub**: Only source tracked; builds happen on-demand

## Secret & Environment Protection

### .env Handling
- **Committed**: `.env.example` (placeholder only)
- **NOT Committed**: `.env` (never, any secrets protected)
- **Verification**: `.gitignore` enforces this; `.env` is ignored

### Secrets Search
The active source was scanned for hardcoded secrets:
- ✅ No real credentials in source code
- ✅ No DB passwords in source code  
- ✅ No API keys in source code
- ✅ No tokens in source code

### Current Database Runtime
- **Active Runtime**: SQLite (`backend/capstone.db`)
- **PostgreSQL Status**: Prepared as optional integration target only; not the active runtime in this snapshot
- **Backend Code**: Updated toward psycopg/Postgres logic (migration-ready but not active)

## Validation Checklist

| Goal | Status |
|------|--------|
| Original project backed up | ✅ PASS |
| Clean copy created | ✅ PASS |
| All files classified | ✅ PASS |
| Active source identified | ✅ PASS |
| No secrets in committed tree | ✅ PASS |
| `.gitignore` verified | ✅ PASS |
| New Git repo initialized | ✅ PASS |
| README updated with real status | ✅ PASS |
| `.env.example` safe (no secrets) | ✅ PASS |

## Summary

**GitHub-Ready Status**: The cleaned project contains only:
- ✅ Active browser extension source
- ✅ Active ML pipeline and training assets
- ✅ Active backend service
- ✅ Active build and test configuration
- ✅ Public documentation and guides
- ✅ Model and dataset assets
- ✅ Utility scripts (operational only)

**Excluded Intentionally** (preserved in backup):
- Test suites (for later CI/test branch)
- Backup/restore scripts (not needed in public repo)
- Generated build output (regenerated on-demand)
- Local database file (runtime artifact)
- Environment secrets (never committed)

**Ready for GitHub**: YES
