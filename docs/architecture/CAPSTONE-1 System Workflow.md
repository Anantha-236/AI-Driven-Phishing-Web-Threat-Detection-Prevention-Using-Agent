# CAPSTONE-1 System Workflow

> Current implementation update, 2026-09-10: The event workflow now drives the user report locally. PostgreSQL is not on the decision critical path. A policy request is distinct from a displayed warning, cancelled submit event or DNR fixture block. The broader workflow below includes target research stages; see current status for their actual evidence boundaries. See [CURRENT-STATUS](../../CURRENT-STATUS.md) and [implementation blueprint](../../implementation_plan.md).

## 1. Core Workflow

The fundamental workflow is:

```text
USER VISITS WEBPAGE
        ↓
BROWSER LOADS PAGE
        ↓
CONTENT SCRIPT STARTS
        ↓
COLLECT BROWSER-OBSERVABLE EVIDENCE
        ↓
NORMALIZE EVIDENCE
        ↓
CLASSIFY REQUESTED DATA TYPES
        ↓
GENERATE FEATURES
        ↓
LOCAL ML INFERENCE
        ↓
CORRELATE EVIDENCE + CONTEXT
        ↓
THREAT ASSESSMENT
        ↓
POLICY DECISION
        ↓
USER ACTION / ENFORCEMENT
        ↓
SANITIZED TELEMETRY
        ↓
FASTAPI
        ↓
POSTGRESQL
```

---

# 2. Step 1 — Page Arrival

The user navigates to a webpage.

Example:

```text
https://example-site.com/login
```

The browser extension becomes active on the page.

---

# 3. Step 2 — Browser Evidence Collection

The content script observes browser-visible structures.

Example:

```text
URL
HTTPS
forms = 1
inputs = 3
scripts = 5
password field = detected
OTP field = detected
```

The extension does not inspect the actual values entered into those fields.

---

# 4. Step 3 — Sensitive-Data Classification

The extension determines what categories of information the webpage appears to request.

Example:

```text
requested_data_types =

[
  EMAIL,
  PASSWORD,
  OTP
]
```

This answers:

> What type of information is the page requesting?

It does NOT answer whether the page is malicious by itself.

---

# 5. Step 4 — Context Collection

The system associates additional contextual information.

Current/target examples:

```text
page_domain
page_origin
form_action
is_https
script_metadata
navigation
service_identity
```

Future research context:

```text
domain_age
registrar
DNS
IP
redirect_chain
network_destination
cross_origin_relationship
brand_identity
```

---

# 6. Step 5 — Feature Generation

Evidence is transformed into an ordered feature vector.

Example:

```text
URL FEATURES
+
PAGE FEATURES
+
FORM FEATURES
+
INPUT FEATURES
+
DATA-REQUEST FEATURES
+
BEHAVIOR FEATURES
+
CONTEXT FEATURES
```

The final model must receive a deterministic feature representation.

---

# 7. Step 6 — Local ML Inference

The feature vector is provided to the local ONNX model.

```text
FEATURE VECTOR
       ↓
ONNX MODEL
       ↓
RISK SCORE
```

Example:

```text
model_score = 0.91
```

This is only model output.

It is not automatically equivalent to:

```text
MALICIOUS
```

---

# 8. Step 7 — Evidence Correlation

The system combines:

```text
ML output
+
browser evidence
+
domain context
+
behavior
+
identity
+
destination relationships
```

Example:

```text
PASSWORD_REQUESTED
+
OTP_REQUESTED
+
BRAND_MISMATCH
+
CROSS_DOMAIN_SUBMISSION
+
NEW_DOMAIN
```

This produces stronger contextual evidence than any individual signal.

---

# 9. Step 8 — Threat Assessment

The evidence is interpreted using the threat taxonomy.

Possible result:

```text
THREAT_LEVEL =
BENIGN
SUSPICIOUS
MALICIOUS
INSUFFICIENT_EVIDENCE
```

The reason codes are preserved.

Example:

```text
Threat:
MALICIOUS

Reasons:
PASSWORD_REQUESTED
OTP_REQUESTED
IDENTITY_MISMATCH
CROSS_DOMAIN_SUBMISSION
```

---

# 10. Step 9 — Policy

Assessment is passed to policy.

```text
BENIGN
   ↓
ALLOW

SUSPICIOUS
   ↓
WARN / CONFIRM

MALICIOUS
   ↓
BLOCK / CONTAIN
```

The actual enforcement mechanism must be separately verified.

---

# 11. Step 10 — User Explanation

The extension UI explains the result.

Example:

```text
HIGH RISK

This page requests:
• Email
• Password
• One-time code

Observed:
• Cross-domain submission
• Identity mismatch

Action:
BLOCKED
```

No secret values are displayed.

---

# 12. Step 11 — Sanitized Telemetry

Only sanitized metadata is sent to the backend.

Example:

```json
{
  "page_domain": "example.com",
  "form_count": 1,
  "input_count": 3,
  "requested_data_types": [
    "EMAIL",
    "PASSWORD",
    "OTP"
  ],
  "threat_level": "malicious",
  "model_score": 0.91,
  "policy_action": "BLOCK"
}
```

Never send:

```text
password_value
otp_value
cvv
raw_form_value
request_body
cookie
authorization_header
token
```

---

# 13. Step 12 — FastAPI

The extension sends the sanitized observation to the backend:

```text
POST /api/v1/observations
```

FastAPI validates the observation contract and passes it to the database layer.

---

# 14. Step 13 — PostgreSQL

The backend stores the sanitized observation.

Logical path:

```text
FastAPI
  ↓
database layer
  ↓
observations table
```

The database is used for:

- research evidence
- debugging
- observation history
- evaluation
- model/policy traceability

---

# 15. Dynamic Webpage Workflow

For dynamically changing pages:

```text
PAGE LOAD
   ↓
INITIAL COLLECTION
   ↓
DOM MUTATION
   ↓
DYNAMIC COLLECTION
   ↓
UPDATED FEATURES
   ↓
RE-ASSESSMENT
   ↓
UPDATED POLICY
```

Examples:

```text
form appears later
input appears later
password field inserted
form action changes
script inserted
iframe appears
redirect occurs
```

Dynamic collection is a separate verification stage and must not be assumed complete merely because the observer code exists.

---

# 16. Browser-to-Database Proof Workflow

The correct experimental proof is:

```text
POSTGRES COUNT BEFORE
        ↓
FRESH CHROMIUM
        ↓
REAL TEST PAGE
        ↓
EXTENSION COLLECTION
        ↓
SERVICE WORKER HANDOFF
        ↓
FASTAPI REQUEST
        ↓
POSTGRES INSERT
        ↓
POSTGRES COUNT AFTER
        ↓
MATCH NEW ROW
```

Required evidence:

```text
BEFORE_COUNT = N
AFTER_COUNT = N + delta
ROW_DELTA > 0
```

The new row must correspond to the browser scenario.

---

# 17. Research Evaluation Workflow

For research evaluation:

```text
REAL + CONTROLLED DATA
        ↓
DATA QUALITY CONTROL
        ↓
LEAKAGE CHECK
        ↓
TRAIN/VALIDATION/TEST SPLIT
        ↓
BASELINE MODELS
        ↓
PROPOSED MODEL
        ↓
TEMPORAL TEST
        ↓
UNSEEN-DOMAIN TEST
        ↓
ADVERSARIAL TEST
        ↓
ABLATION
        ↓
PERFORMANCE MEASUREMENT
        ↓
STATISTICAL ANALYSIS
```

---

# 18. Development Philosophy

The architecture follows:

```text
OBSERVE
   ↓
VERIFY
   ↓
CORRELATE
   ↓
ASSESS
   ↓
EXPLAIN
   ↓
PREVENT
```

Privacy is maintained throughout the workflow.

The project should never evolve into a system that collects user secrets merely to improve its own security analysis.