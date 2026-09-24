# CAPSTONE-1 Component Responsibilities and Boundaries

> Current implementation update, 2026-09-10: Existing content typed-events owns safe event emission and the synchronous form guard; the existing worker typed-events owns recording, browser correlation and report delivery; assessment.ts owns event evidence fusion; tsfeg.ts owns both representations; train_models.py owns the controlled comparison/export. The older snapshot/ONNX path is retained separately. Target intelligence modules listed below are not all implemented. See [CURRENT-STATUS](../../CURRENT-STATUS.md) and [implementation blueprint](../../implementation_plan.md).

## 1. Component Map

| Component | Technology | Responsibility | Status |
|---|---|---|---|
| Browser | Chromium / Chrome | Execute webpage and extension | CURRENT |
| Content Script | TypeScript | Observe page/DOM evidence | CURRENT |
| Service Worker | TypeScript | Coordinate extension processing | CURRENT |
| Evidence Engine | TypeScript | Normalize and structure evidence | CURRENT |
| Data Classifier | TypeScript | Identify requested data categories | CURRENT |
| Feature Engine | TypeScript/Python | Convert evidence to features | CURRENT / RESEARCH |
| Local ML | ONNX Runtime Web | Local inference | PROTOTYPE |
| Assessment | TypeScript | Interpret evidence + ML | CURRENT |
| Policy | TypeScript | Determine action | CURRENT |
| User UI | Extension UI | Explain risk/action | CURRENT |
| Domain Intelligence | RDAP/DNS/IP | Infrastructure context | PLANNED |
| Network Intelligence | Browser request metadata | Destination/flow context | PLANNED |
| FastAPI | Python | Backend API | CURRENT |
| PostgreSQL | PostgreSQL | Persistent sanitized observations | CURRENT |
| ML Research | Python | Dataset/training/evaluation | RESEARCH |
| ONNX Export | Python/ONNX | Deploy selected model | RESEARCH |
| Browser E2E | Playwright | Runtime verification | TESTING |

---

# 2. Browser

## Responsibility

The browser provides:

- webpage execution
- navigation
- DOM
- extension execution context
- browser APIs
- user-visible security controls

## Trust level

```text
UNTRUSTED PAGE
```

Webpage scripts, frames, redirects and resource origins are treated as potentially hostile.

---

# 3. Content Script

## Responsibility

Observe safe browser-visible webpage evidence.

### Allowed

```text
URL
DOM structure
forms
input metadata
form attributes
script metadata
navigation
safe page relationships
```

### Forbidden

```text
password values
OTP values
CVV
raw form values
cookies
authorization headers
request bodies
authentication tokens
```

---

# 4. Service Worker

## Responsibility

The service worker:

- receives evidence from the content script
- coordinates model/policy processing
- maintains browser/session context
- communicates with extension components
- submits sanitized observations to the backend

It must not become a storage location for secret user values.

---

# 5. Evidence Engine

## Responsibility

Convert observations into structured evidence.

Each evidence item should support:

```text
evidence_id
source
status
confidence
artifact
timestamp
```

Possible statuses:

```text
OBSERVED
VERIFIED
INFERRED
UNKNOWN
NOT_OBSERVABLE
```

---

# 6. Data Classification

## Responsibility

Identify requested information categories.

Example:

```text
<input type="password">
        ↓
PASSWORD
```

The system identifies the category without reading:

```text
<input>.value
```

---

# 7. Feature Engine

## Responsibility

Provide deterministic model inputs.

Requirements:

- stable ordering
- versioning
- missing-value handling
- documented semantics
- browser/Python compatibility

Future requirement:

```text
FEATURE_SPEC_VERSION
=
TRAINING_FEATURE_SPEC
=
BROWSER_FEATURE_SPEC
=
MODEL_INPUT_SPEC
```

---

# 8. Local ML

## Responsibility

Perform local inference.

Input:

```text
feature vector
```

Output:

```text
risk score
```

The ML model is not the final authority.

---

# 9. Assessment

## Responsibility

Combine:

```text
ML
+
evidence
+
rules
+
context
```

and determine:

```text
BENIGN
SUSPICIOUS
MALICIOUS
INSUFFICIENT_EVIDENCE
```

---

# 10. Policy

## Responsibility

Map assessment to action:

```text
ALLOW
WARN
CONFIRM
BLOCK
CONTAIN
```

Policy should be independently testable.

A policy decision does not automatically prove browser enforcement.

---

# 11. Domain Intelligence

## Responsibility

Provide external contextual information.

Potential data:

```text
domain age
registration date
registrar
nameservers
DNS
IP
DNSSEC
domain status
```

Constraints:

- advisory only
- cache results
- handle unavailable data
- handle redaction
- avoid treating age as proof of maliciousness

---

# 12. Network Intelligence

## Responsibility

Determine relationships among:

```text
page
form
request
destination
initiator
redirect
origin
```

The layer should use metadata rather than sensitive payload contents.

---

# 13. FastAPI

## Responsibility

Provide the backend interface for sanitized observations.

Primary responsibilities:

```text
validate
receive
store
retrieve
```

The API must not accept unnecessary sensitive payloads.

---

# 14. PostgreSQL

## Responsibility

Persist normalized research/security observations.

Important data:

```text
observation_id
collection_id
page_domain
page_url_sanitized
is_https
form_count
input_count
script_count
requested_data_types
threat_level
model_score
policy_action
observed_at
```

---

# 15. Research Dataset

## Responsibility

Provide data for ML experimentation.

Every sample must have documented provenance:

```text
REAL
CONTROLLED
SYNTHETIC
```

These categories must not be silently mixed.

---

# 16. Model Training

## Responsibility

Compare candidate models fairly.

Baseline examples:

```text
Logistic Regression
Random Forest
XGBoost / suitable gradient-boosted model
```

The final research model must be selected using predefined evaluation criteria.

---

# 17. Research Evaluation

Required dimensions:

```text
PRECISION
RECALL
F1
ROC-AUC
PR-AUC
FPR
FNR
LATENCY
CPU
MEMORY
```

Robustness:

```text
TEMPORAL
UNSEEN DOMAIN
CROSS DOMAIN
ADVERSARIAL
```

---

# 18. Privacy Boundary

The privacy boundary is:

```text
CATEGORY OF DATA = ALLOWED
VALUE OF DATA    = PROHIBITED
```

Example:

```text
PASSWORD FIELD EXISTS
        ↓
ALLOWED

PASSWORD_VALUE = [PROHIBITED_RAW_USER_SECRET]
        ↓
PROHIBITED
```

This distinction is fundamental to the system.

---

# 19. Security Boundary

The system must protect:

- user credentials
- one-time codes
- financial data
- identity information
- cookies
- authorization headers
- request bodies
- model integrity
- feature specification
- backend/database credentials
- telemetry integrity

---

# 20. Current vs Target Architecture

### CURRENTLY VALIDATED

```text
Browser
 ↓
Content Script
 ↓
Evidence
 ↓
Classification
 ↓
Feature Processing
 ↓
Prototype Local ML
 ↓
Assessment
 ↓
Policy
 ↓
FastAPI
 ↓
PostgreSQL
```

### TARGET RESEARCH ARCHITECTURE

```text
Browser
 ↓
DOM + URL + Data Request
 ↓
Dynamic Behavior
 ↓
Domain Intelligence
 ↓
Network/Destination Context
 ↓
Identity Context
 ↓
Authoritative Feature Engine
 ↓
Research-selected Local ML
 ↓
Evidence Correlation
 ↓
Risk Fusion
 ↓
Explainable Assessment
 ↓
Verified Enforcement
 ↓
Sanitized Telemetry
 ↓
FastAPI
 ↓
PostgreSQL
```

The target architecture must not be presented as fully implemented until the corresponding runtime experiments are completed.