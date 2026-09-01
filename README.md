# CAPSTONE-1

Privacy-preserving browser threat detection prototype for Chromium-based web pages.

## Project purpose

This repository contains the active development source for:

- Browser extension detection pipeline
- Local feature extraction and ML inference
- Supporting backend and metadata services
- Privacy-safe evidence collection

## Current major components

- Browser Extension: Manifest V3 service worker and content script pipeline
- ML: Python-based feature and evaluation assets
- Backend: FastAPI API plus metadata persistence layer
- Database: SQLite runtime database in the current active implementation

## Current status

This project is a working local-first prototype and is not production-ready.

- Database runtime: SQLite
- PostgreSQL: prepared as an integration target only; not the active runtime database in this project snapshot
- Browser extension remains local-first and does not directly write to the database

## Repository layout

```text
browser-extension/   Active extension source
ml/                  Active ML assets and training/evaluation workflow
backend/             Active backend implementation
docs/                Architecture and project documentation
scripts/             Utility scripts
.env.example         Safe environment template
.gitignore           Secret and local artifact exclusions
```

## Privacy boundary

The content script and evidence collector intentionally avoid reading raw user input values. They collect structural metadata only and never send or store raw form values, passwords, OTPs, CVVs, tokens, or session secrets.

## Build and validation

```bash
npm install
npm run typecheck
npm run build
```

## Notes

- The active runtime database is SQLite.
- PostgreSQL is not the active runtime database in the current repository state.
- This project is intentionally curated for GitHub readiness and does not include local-only experiments, test archives, or secret material in the public tree.
