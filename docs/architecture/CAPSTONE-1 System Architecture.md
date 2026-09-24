# CAPSTONE-1 System Architecture

> Current implementation update, 2026-09-10: The verified runtime is collector/observer and browser metadata -> strict events -> shared browser session with tab/document/frame identities -> flat local model plus relationship evidence -> assessment/report/submit guard; telemetry independently reaches FastAPI/PostgreSQL. The detailed enrichment catalog below describes the larger target, not a claim that every intelligence family is implemented. See [CURRENT-STATUS](../../CURRENT-STATUS.md) and [implementation blueprint](../../implementation_plan.md).

## 1. Purpose

CAPSTONE-1 is a local-first browser security system designed to assess browser-observable evidence associated with webpages, sensitive-data requests, deceptive identity, suspicious behavior, and potential data-flow risks.

The architecture is designed around:

- privacy preservation
- local-first analysis
- evidence-based decisions
- explainability
- modular detection signals
- measurable research evaluation

The system does not claim universal malicious-website detection. A URL, password field, domain property, or machine-learning score alone is insufficient to establish maliciousness.

---

# 2. High-Level Architecture

```text
                         USER
                          │
                          ▼
                 ┌─────────────────┐
                 │  CHROMIUM /     │
                 │  CHROME BROWSER │
                 └────────┬────────┘
                          │
                          ▼
                ┌──────────────────┐
                │  BROWSER         │
                │  CONTENT SCRIPT  │
                ├──────────────────┤
                │ DOM              │
                │ Forms            │
                │ Inputs           │
                │ Scripts          │
                │ Navigation       │
                │ Dynamic Changes  │
                └────────┬─────────┘
                         │
                         ▼
              ┌──────────────────────┐
              │ EVIDENCE COLLECTION  │
              │ + NORMALIZATION      │
              └──────────┬───────────┘
                         │
                         ▼
              ┌──────────────────────┐
              │ DATA-REQUEST         │
              │ CLASSIFICATION       │
              ├──────────────────────┤
              │ Credential           │
              │ Financial            │
              │ Identity             │
              │ Personal             │
              │ Device               │
              │ Authentication       │
              └──────────┬───────────┘
                         │
                         ▼
              ┌──────────────────────┐
              │ FEATURE ENGINE       │
              │ + EVIDENCE MODEL     │
              └──────────┬───────────┘
                         │
          ┌──────────────┼─────────────────┐
          │              │                 │
          ▼              ▼                 ▼
     PAGE/URL        DOMAIN CONTEXT    BEHAVIOR
      SIGNALS          [PLANNED]       SIGNALS
          │              │                 │
          └──────────────┼─────────────────┘
                         ▼
              ┌──────────────────────┐
              │ LOCAL ML INFERENCE   │
              │ ONNX Runtime Web     │
              └──────────┬───────────┘
                         │
                         ▼
              ┌──────────────────────┐
              │ EVIDENCE CORRELATION │
              │ + RISK FUSION        │
              └──────────┬───────────┘
                         │
                         ▼
              ┌──────────────────────┐
              │ THREAT ASSESSMENT    │
              ├──────────────────────┤
              │ BENIGN               │
              │ SUSPICIOUS           │
              │ MALICIOUS            │
              │ INSUFFICIENT EVIDENCE│
              └──────────┬───────────┘
                         │
                         ▼
              ┌──────────────────────┐
              │ POLICY ENGINE        │
              ├──────────────────────┤
              │ ALLOW                │
              │ WARN                 │
              │ CONFIRM              │
              │ BLOCK / CONTAIN      │
              └──────────┬───────────┘
                         │
             ┌───────────┴────────────┐
             │                        │
             ▼                        ▼
      ┌──────────────┐        ┌────────────────┐
      │ USER UI      │        │ SANITIZED      │
      │ WARNING /    │        │ TELEMETRY      │
      │ STATUS       │        └───────┬────────┘
      └──────────────┘                │
                                      ▼
                             ┌─────────────────┐
                             │ FASTAPI         │
                             │ BACKEND         │
                             └────────┬────────┘
                                      │
                                      ▼
                             ┌─────────────────┐
                             │ POSTGRESQL      │
                             │ OBSERVATIONS    │
                             └─────────────────┘
```

---

# 3. Browser Layer

The browser is the untrusted execution environment.

The extension operates inside Chromium using Manifest V3.

Primary browser components:

- content script
- service worker
- browser UI
- optional offscreen/local inference environment

The browser layer provides the raw observable context from which security evidence is derived.

---

# 4. Content Script

The content script observes browser-page structure and behavior.

Current evidence types include:

- URL/page information
- forms
- inputs
- form attributes
- scripts
- navigation
- page relationships
- sensitive-data field categories

Dynamic DOM observation is a separate capability and must be independently runtime-verified before being considered complete.

The content script does NOT collect:

- password values
- OTP values
- CVV values
- raw form values
- cookies
- authorization headers
- request bodies
- authentication tokens

---

# 5. Evidence Layer

The evidence layer converts browser observations into structured security evidence.

Example:

```text
OBSERVED:
Password input detected

OBSERVED:
OTP input detected

OBSERVED:
Form destination differs from page origin

OBSERVED:
External request associated with page activity

INFERRED:
Destination mismatch may indicate suspicious collection

UNKNOWN:
Actual server-side purpose of the destination
```

Evidence is classified by status:

- OBSERVED
- VERIFIED
- INFERRED
- UNKNOWN
- NOT_OBSERVABLE

Evidence IDs and timestamps are used for traceability.

---

# 6. Sensitive-Data Classification

The system identifies the type of information requested by the page without reading the actual value.

Example categories:

```text
CREDENTIAL
  USERNAME
  PASSWORD
  OTP

FINANCIAL
  PAYMENT_CARD
  CARD_EXPIRY
  CVV
  BANKING_INFORMATION

IDENTITY
  ID_DOCUMENT
  PERSONAL_IDENTITY

PERSONAL
  EMAIL
  PHONE
  ADDRESS
  DATE_OF_BIRTH

DEVICE / PERMISSION
  LOCATION
  CAMERA
  MICROPHONE
  FILE_UPLOAD
```

A sensitive-data request alone is not classified as malicious.

The classification becomes one evidence source in the later assessment process.

---

# 7. Feature Engine

The feature engine transforms normalized evidence into a deterministic feature representation.

Feature groups may include:

```text
URL FEATURES
DOMAIN FEATURES
PAGE FEATURES
FORM FEATURES
INPUT FEATURES
SCRIPT FEATURES
DATA-REQUEST FEATURES
BEHAVIOR FEATURES
DESTINATION FEATURES
CONTEXT FEATURES
```

The authoritative feature specification must eventually be shared between:

- browser inference
- Python training pipeline
- evaluation
- ONNX model

---

# 8. Domain Intelligence

Domain intelligence is a planned contextual layer.

Potential sources:

- domain age
- registration date
- registrar
- nameservers
- DNS information
- IP information
- DNSSEC
- domain status
- domain similarity

Domain information is advisory.

It must not independently determine maliciousness.

Missing, redacted, stale, or unavailable registration information must be represented explicitly.

---

# 9. Network and Destination Intelligence

The target architecture includes privacy-preserving network metadata.

Potential signals:

- destination domain
- request type
- initiator
- relationship between page and destination
- cross-origin relationship
- redirect relationship
- server/IP context where safely available

Raw payloads must not be collected.

The purpose is to determine whether:

```text
PAGE
  ↓
requests sensitive information
  ↓
submission/request
  ↓
unexpected destination
```

The network/data-flow layer is a research capability and is not considered complete until experimentally validated.

---

# 10. Local ML Layer

The browser uses local inference to reduce dependence on remote data processing.

Target runtime:

ONNX Runtime Web

The model receives the authoritative feature vector and produces a risk-related output.

The ML score is NOT the final security decision.

---

# 11. Evidence Correlation and Risk Fusion

Risk is derived from multiple independent signals.

Example:

```text
DOMAIN_RISK
DATA_REQUEST_RISK
BEHAVIOR_RISK
NETWORK_RISK
IDENTITY_RISK
ML_SCORE
```

These are correlated to produce:

```text
OVERALL_RISK
```

The system also generates reason codes so that the decision is explainable.

Example:

```text
PASSWORD_REQUESTED
OTP_REQUESTED
CROSS_DOMAIN_SUBMISSION
NEW_DOMAIN
IDENTITY_MISMATCH
EXTERNAL_DESTINATION
```

---

# 12. Threat Assessment

The assessment layer converts evidence into:

```text
BENIGN
SUSPICIOUS
MALICIOUS
INSUFFICIENT_EVIDENCE
```

The assessment must preserve uncertainty.

The system must be able to say:

```text
INSUFFICIENT_EVIDENCE
```

rather than forcing a malicious/benign decision.

---

# 13. Policy Layer

The policy engine converts assessment into an action:

```text
ALLOW
WARN
CONFIRM
BLOCK
CONTAIN
```

The policy decision must not be confused with actual enforcement.

A real prevention claim requires demonstration that the browser actually prevents or contains the targeted action.

---

# 14. User Interface

The user-facing layer communicates:

- risk level
- domain
- requested data categories
- relevant evidence
- reason codes
- policy decision

It must never expose sensitive values.

---

# 15. Research Backend

The research backend provides persistence and inspection.

```text
Extension
   ↓
FastAPI
   ↓
PostgreSQL
```

The backend stores sanitized observations rather than secret payloads.

The database supports:

- observations
- service profiles
- service domains
- model versions
- policy versions

---

# 16. Research / ML Pipeline

The separate research pipeline is:

```text
BROWSER-DERIVED DATA
        ↓
DATASET
        ↓
DATA QUALITY AUDIT
        ↓
LEAKAGE AUDIT
        ↓
FEATURE ENGINEERING
        ↓
BASELINE MODELS
        ↓
MODEL SELECTION
        ↓
ROBUSTNESS EVALUATION
        ↓
ONNX EXPORT
        ↓
BROWSER DEPLOYMENT
        ↓
PYTHON/BROWSER PARITY
```

---

# 17. Trust Boundaries

The architecture contains the following trust boundaries:

1. Untrusted webpage DOM, scripts, frames, redirects, and resource origins.
2. Browser extension content-script boundary.
3. Extension service worker and local feature/inference pipeline.
4. External domain/DNS/registration intelligence providers.
5. FastAPI backend.
6. PostgreSQL database.
7. Research dataset and model-training boundary.

Each boundary must have explicit validation and privacy controls.

---

# 18. Privacy Architecture

The core principle is:

```text
OBSERVE BEHAVIOR
WITHOUT COLLECTING THE SECRET
```

Collected:

- structural metadata
- data categories
- domain/destination metadata
- redirect/form behavior
- evidence IDs
- timestamps
- model/policy results

Not collected:

- passwords
- OTP values
- CVV
- raw form values
- authentication tokens
- cookies
- authorization headers
- request bodies
- private page content

---

# 19. Research Status Classification

Each architecture component must be marked:

CURRENT
= implemented and currently supported

VERIFIED
= demonstrated by runtime evidence

PLANNED
= architecture exists but not yet experimentally validated

FUTURE
= possible extension outside the current MVP

This prevents the architecture diagram from being mistaken for evidence that every component is already operational.