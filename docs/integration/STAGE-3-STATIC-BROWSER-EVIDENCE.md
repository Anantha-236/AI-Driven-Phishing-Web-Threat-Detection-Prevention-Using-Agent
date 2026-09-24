# STAGE 3 STATIC BROWSER EVIDENCE

STAGE=3
STATIC_BROWSER=BLOCKED

TYPECHECK=PASS
BUILD=PASS
UNIT=PASS

PAGE_EVIDENCE=PASS
FORM_EVIDENCE=PASS
INPUT_EVIDENCE=PASS
SCRIPT_EVIDENCE=PARTIAL
RELATIONSHIP_EVIDENCE=PASS
DATA_TYPE_EVIDENCE=PARTIAL

RAW_SECRET_READ=NO
RAW_SECRET_STORED=NO
RAW_SECRET_SENT=NO
RAW_SECRET_LOGGED=NO

BROWSER_FEATURE_COUNT=44
FEATURE_NAMES=Observed browser feature metadata includes has_password_field, has_otp_field, cross_domain_form, form_count, input_count, has_email_field, has_username_field, has_phone_field, has_card_field, has_cvv_field, has_identity_field, has_bank_field, has_file_upload, URL lexical features, DOM/script counts, login and sensitive-data indicators, origin relationship indicators, and requested-data indicators.

LOCAL_ML=PASS
MODEL_TYPE=TOY/PROTOTYPE
MODEL_FILE=dist/assets/model.onnx (browser deployment artifact)
MODEL_VERSION=deterministic-toy-v1.1.0
INPUT_COUNT=5
OUTPUT=Browser debug evidence produced modelScore=0.95 for the suspicious scenario.
LATENCY=UNKNOWN

ASSESSMENT=PASS
POLICY=PASS
BROWSER_DB_CORRELATION=NOT_RUN_IN_STAGE_3

## Static scenario evidence

| Scenario | Forms | Inputs | Scripts | Data Types | ML | Threat | Policy | DB |
|---|---:|---:|---:|---|---:|---|---|---|
| /benign | UNKNOWN | UNKNOWN | UNKNOWN | NOT_VERIFIED | NOT_VERIFIED | NOT_VERIFIED | NOT_VERIFIED | NOT_RUN |
| /suspicious | 1 | 3 | 0 | EMAIL, PASSWORD, OTP | 0.95 | malicious | BLOCK | Existing Stage 2 path verified |
| /high-risk | UNKNOWN | UNKNOWN | UNKNOWN | NOT_VERIFIED | NOT_VERIFIED | NOT_VERIFIED | NOT_VERIFIED | NOT_RUN |
| /privacy | UNKNOWN | UNKNOWN | UNKNOWN | NOT_VERIFIED | NOT_VERIFIED | NOT_VERIFIED | NOT_VERIFIED | NOT_RUN |

## Verified browser path

The existing real-Chromium debug scenario loaded the built extension from `dist` and navigated to `/suspicious`. Browser evidence reported one form and three inputs: email, password, and OTP. The content script set the evidence handoff diagnostic to `send_ok`. Feature metadata reported 44 browser feature fields, including cross-domain submission and sensitive-data request indicators. The Stage 2 database row for the corresponding browser run reported malicious threat level, model score 0.95, and BLOCK policy action.

## Data-type coverage

| Category | Code present | Unit tested | Browser verified |
|---|---|---|---|
| EMAIL | YES | NO | YES |
| USERNAME | YES | NO | NOT_VERIFIED |
| PASSWORD | YES | NO | YES |
| OTP | YES | NO | YES |
| PHONE | YES | NO | NOT_VERIFIED |
| PAYMENT_CARD | YES | NO | NOT_VERIFIED |
| CVV | YES | NO | NOT_VERIFIED |
| BANK_ACCOUNT | YES | NO | NOT_VERIFIED |
| FILE_UPLOAD | YES | NO | NOT_VERIFIED |
| LOCATION | YES | NO | NOT_VERIFIED |
| CAMERA | YES | NO | NOT_VERIFIED |
| MICROPHONE | YES | NO | NOT_VERIFIED |

Enum or source presence was not counted as browser verification.

## Privacy result

Source inspection of the static collector and browser evidence confirms structural attributes and metadata are used; raw input values, password values, OTP values, CVV values, request bodies, cookies, authorization headers, and tokens were not read, stored, sent, or logged in this verification.

## Limitations and blocker

- The controlled local `/suspicious` page proves only the observed scenario, not global detection.
- The current browser model is identified by the implementation as `deterministic-toy-v1.1.0`; it is a prototype/development model, not a research-trained model.
- Dynamic DOM behavior is excluded from Stage 3.
- Network and data-flow intelligence are excluded from Stage 3.
- Domain/RDAP/DNS intelligence is excluded from Stage 3.
- The four-route matrix probe could not complete reliably in this Windows terminal environment: the checked-in helper conflicts with the already-running scenario server, while the temporary runner returned without completion output. Therefore `/benign`, `/high-risk`, and `/privacy` remain unverified here.
- Existing baseline gates passed: typecheck exit 0, build exit 0, and unit suite 2/2 passed.

CURRENT_BLOCKER=Reliable fresh browser execution and capture for all four static routes, especially /benign, /high-risk, and /privacy. No Stage 4 work should begin until the complete matrix is captured.
NEXT_STAGE=STAGE 4 - DYNAMIC DOM COLLECTION AND REAL-TIME RECOLLECTION, after the Stage 3 matrix blocker is resolved.
