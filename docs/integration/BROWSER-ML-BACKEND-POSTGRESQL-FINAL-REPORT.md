# CAPSTONE-1 FINAL INTEGRATION REPORT

## Architecture

Browser
→ Evidence
→ Features
→ Local ML
→ Assessment
→ Policy
→ UI

Sanitized Observation
→ FastAPI
→ PostgreSQL

## Component status

- BROWSER: PASS
- DATA_COLLECTION: PASS
- DATA_TYPE_CLASSIFICATION: PASS
- EVIDENCE: PASS
- FEATURE_EXTRACTION: PASS
- LOCAL_ML: PASS
- ASSESSMENT: PASS
- POLICY: PASS
- UI: PASS
- FASTAPI: PASS
- POSTGRESQL: PASS
- BROWSER_TO_BACKEND: PASS
- BACKEND_TO_POSTGRESQL: PASS
- BROWSER_TO_POSTGRESQL: FAIL

## Scenario results

### S001

Status: FAIL (not fully proven with browser-generated PostgreSQL row)

### S002

Status: FAIL (not fully proven with browser-generated PostgreSQL row)

### S003

Status: FAIL (not fully proven with browser-generated PostgreSQL row)

## Database evidence

The following database functionality was verified:

- FastAPI health endpoint returned HTTP 200 with database status CONNECTED.
- Synthetic API observation was accepted and returned `isStored = True`.
- PostgreSQL row existed for observation ID `obs-0d2aa0e1218d`.
- That row was created through the API path, not by manual database insertion.

Observed row evidence:

- observation_id: `obs-0d2aa0e1218d`
- collection_id: `synthetic-backend-check-001`
- page_domain: `accounts.example.invalid`
- page_url_sanitized: `https://accounts.example.invalid/login`
- is_https: `true`
- form_count: `1`
- input_count: `2`
- script_count: `1`
- requested_data_types: `["EMAIL", "PASSWORD"]`
- threat_level: `benign`
- model_score: `0.12`
- policy_action: `ALLOW`

## Privacy

- SECRET_VALUES_READ=NO
- SECRET_VALUES_SENT=NO
- SECRET_VALUES_STORED=NO
- SECRET_VALUES_LOGGED=NO

The browser collector intentionally reads structural DOM metadata only and never reads input values. The backend model rejects payloads containing forbidden secret fields.

## Limitations

This is not yet production-ready or research-complete. The outstanding limitations are:

- final production ML model is not yet the final deployment model
- final dataset completeness is not validated for production use
- leakage-safe evaluation is not complete
- statistical analysis beyond the prototype is not complete
- real-world evaluation is not complete
- service behavior comparison is not fully validated

## Final status

Integration status remains PARTIAL. The browser-to-backend and backend-to-database path is verified for the API path, but full real browser-generated PostgreSQL rows for S001/S002/S003 were not demonstrated within this verification cycle and no final git checkpoint commit hash was produced.
