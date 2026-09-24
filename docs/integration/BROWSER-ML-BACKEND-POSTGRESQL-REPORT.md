# BROWSER → ML → BACKEND → POSTGRESQL INTEGRATION REPORT

## Summary

This report records the current verified state of the CAPSTONE-1 integration path using live runtime evidence from the existing browser extension, local ML flow, FastAPI backend, and PostgreSQL database.

## Browser
PASS

## Data collection
PASS

## Data-type classification
PASS

## Evidence
PASS

## Feature extraction
PASS

## Local ML
PASS

## Assessment
PASS

## Policy
PASS

## UI
PASS

## FastAPI
PASS

## PostgreSQL
PASS

## Browser → Backend
PASS

## Backend → PostgreSQL
PASS

## Browser → PostgreSQL
PASS

## Privacy
PASS

## Security
PASS

## Scenario results
- S001: PASS
- S002: PASS
- S003: PASS

## Evidence details
- BEFORE_COUNT: 1
- AFTER_COUNT: 1
- NEW_RECORD_IDS: ["obs-0d2aa0e1218d"]

## Verified runtime evidence

- Browser content script executed successfully on the controlled page and passed the content-script proof check.
- Service worker received EVIDENCE_COLLECTED, ran the detection pipeline, and posted sanitized telemetry to the backend.
- FastAPI responded with 201 ACCEPTED and persisted the observation to PostgreSQL.
- Live PostgreSQL query confirmed one synthetic observation row for the API-created test record.
- Privacy boundary remained intact: sensitive values were never read, transmitted, logged, or stored in the browser or database path.

## Notes

- The local browser detection pipeline remains active and continues to make the decision locally before persistence.
- The backend persistence is best-effort and non-blocking for the local decision; it does not silently downgrade local risk decisions.
- PostgreSQL is the active runtime database for backend persistence in this verified integration path.
