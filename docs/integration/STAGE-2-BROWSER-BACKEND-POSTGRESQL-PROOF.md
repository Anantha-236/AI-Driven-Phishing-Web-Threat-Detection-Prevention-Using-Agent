# STAGE 2 BROWSER -> FASTAPI -> POSTGRESQL PROOF

STAGE=2
TYPECHECK=PASS
BUILD=PASS
UNIT=PASS

FASTAPI=PASS
POSTGRESQL=PASS
BROWSER_COLLECTION=PASS
DATA_CLASSIFICATION=PASS
FEATURE_EXTRACTION=PASS
LOCAL_ML=PASS
ASSESSMENT=PASS
POLICY=PASS
CONTENT_SCRIPT_TO_WORKER=PASS
BROWSER_TO_FASTAPI=PASS
BROWSER_TO_POSTGRESQL=PASS
BROWSER_GENERATED_ROW=PASS
API_READBACK=PASS
REPEATABILITY=PASS

SYNTHETIC_INSERT_USED=NO
RAW_PASSWORD_SENT=NO
RAW_OTP_SENT=NO
RAW_CVV_SENT=NO
RAW_FORM_VALUES_SENT=NO
REQUEST_BODY_SENT=NO

BEFORE_COUNT=67
AFTER_COUNT=71
ROW_DELTA=4

OBSERVATION_ID=obs-8e4d3100fca4
COLLECTION_ID=coll-mtl1lsjr-20

SECOND_BEFORE_COUNT=71
SECOND_AFTER_COUNT=75
SECOND_ROW_DELTA=4

## 1. Browser scenario

The existing controlled Chromium scenario was `http://127.0.0.1:41731/suspicious`, loaded with the existing built extension from `dist`. The supported startup script started PostgreSQL preflight, FastAPI on port 8000, and the controlled scenario server. No browser source or schema changes were made.

## 2. Browser evidence

The real browser reported one form and three inputs: email, password, and one-time-code. The extension emitted collection IDs and the page diagnostics reported `send_ok` for the evidence handoff. Feature metadata reported email, password, and OTP fields, one form, three inputs, cross-origin submission, and credential-request indicators. The local result was malicious with model score 0.95 and policy action BLOCK.

## 3. Service-worker handoff and API

The content script collected evidence and the service worker logged handoffs for the generated collection IDs. The service worker used the existing POST endpoint:

`http://127.0.0.1:8000/api/v1/observations`

The successful `send_ok` handoff, followed by new PostgreSQL rows with matching collection/page metadata, proves the browser-originated path reached FastAPI. The browser test output did not expose the raw POST status code; the endpoint contract is HTTP 201 for accepted observations.

## 4. PostgreSQL evidence

A direct read-only count immediately before the first debug scenario was 67. After that browser run, the count was 71, giving a delta of 4. The newest matching row was:

- observation_id: `obs-8e4d3100fca4`
- collection_id: `coll-mtl1lsjr-20`
- page_domain: `127.0.0.1`
- page_url_sanitized: `http://127.0.0.1:41731/suspicious`
- is_https: `false`
- form_count: `1`
- input_count: `3`
- script_count: `0`
- requested_data_types: `EMAIL`, `PASSWORD`, `OTP`
- threat_level: `malicious`
- model_score: `0.95`
- policy_action: `BLOCK`
- observed_at: `2026-09-03 10:16:24.560465+05:30`

The row metadata matches the actual browser page and browser-reported collection evidence.

## 5. Repeatability

The same controlled browser scenario was repeated once. The second baseline was 71 and the second result was 75, giving a second row delta of 4. The newest repeated row also matched `/suspicious`, one form, three inputs, and EMAIL/PASSWORD/OTP metadata.

## 6. API readback

`GET /api/v1/observations?limit=20` returned HTTP 200 and included the newest PostgreSQL observation row.

## 7. Privacy and synthetic-data checks

The browser payload path contains structural metadata and classification fields only. Source inspection and the browser payload evidence show no access to raw password, OTP, CVV, private form values, request bodies, cookies, or authorization values. No script manually inserted an observation; all new rows were generated through the extension handoff path.

## 8. Caveat

The existing `tests/browser/data-collection.spec.ts` database helper is not reliable in this Windows environment: it printed `NaN` and later failed parsing empty helper output. It was not used as the database proof. The direct read-only PostgreSQL counts, newest-row metadata, browser diagnostics, service-worker handoff logs, and API readback were used instead. No additional browser E2E or later stage was started after the required repeat.
