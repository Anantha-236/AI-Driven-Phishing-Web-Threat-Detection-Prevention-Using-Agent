# CAPSTONE-1 Security and Privacy Architecture

> Current implementation update, 2026-09-10: Current contracts whitelist event/report keys and origins, blank legacy title/name/autocomplete fields and separate observations from inferences. Tested sentinels cover field values, website-authored bodies/cookies/headers versus extension telemetry, storage and exact-session PostgreSQL rows. Unit throwing getters verify no value reads in the exercised collector. Hostile-page interference and unobserved submission paths remain limitations; current confidence is uncalibrated. See [CURRENT-STATUS](../../CURRENT-STATUS.md) and [implementation blueprint](../../implementation_plan.md).

## 1. Security Objective

CAPSTONE-1 is intended to protect users from phishing and suspicious web data collection without becoming an additional source of sensitive-data exposure.

The core principle is:

```text
OBSERVE THE REQUEST
WITHOUT COLLECTING THE SECRET
```

---

# 2. Protected Assets

The system protects:

- user credentials
- OTPs
- payment information
- identity information
- private form values
- cookies
- authorization headers
- request bodies
- authentication tokens
- browser context
- model integrity
- policy integrity
- database integrity
- telemetry integrity

---

# 3. Trust Boundaries

```text
UNTRUSTED WEBPAGE
       ↓
CONTENT SCRIPT
       ↓
SERVICE WORKER
       ↓
LOCAL FEATURE / ML
       ↓
EXTERNAL INTELLIGENCE
       ↓
FASTAPI
       ↓
POSTGRESQL
       ↓
RESEARCH DATASET
```

Every transition is a security boundary.

---

# 4. Data Minimization

The system should collect only what is necessary for detection.

### Collect

```text
URL metadata
domain metadata
DOM structure
form metadata
input metadata
script metadata
data categories
navigation relationships
destination metadata
evidence identifiers
risk results
policy results
timestamps
```

### Do not collect

```text
password values
OTP values
CVV
raw form values
cookies
authorization headers
request bodies
authentication tokens
private page contents
```

---

# 5. Example

The following observation is allowed:

```json
{
  "requested_data_types": [
    "EMAIL",
    "PASSWORD",
    "OTP"
  ],
  "form_count": 1,
  "input_count": 3
}
```

The following is prohibited:

```json
{
  "email": "user@example.com",
  "password": "actual-secret",
  "otp": "123456"
}
```

---

# 6. Evidence Privacy

Evidence should describe behavior rather than reproduce user information.

Good:

```text
PASSWORD_FIELD_DETECTED
```

Bad:

```text
PASSWORD_VALUE_DETECTED=actual-password
```

Good:

```text
CROSS_DOMAIN_FORM_SUBMISSION
```

Bad:

```text
RAW_REQUEST_BODY=...
```

---

# 7. URL Sanitization

Persist only a sanitized URL representation.

Remove or protect sensitive URL components such as:

```text
query strings
tokens
session identifiers
embedded credentials
other sensitive parameters
```

The purpose is to preserve useful security context without retaining unnecessary browsing information.

---

# 8. Backend Security

FastAPI must:

- validate request structure
- reject unexpected fields
- enforce allowed data types
- avoid logging secrets
- restrict database access
- sanitize persisted values

---

# 9. Database Security

PostgreSQL credentials must remain:

```text
LOCAL_ONLY
IGNORED_BY_GIT
UNTRACKED
ABSENT_FROM_REPOSITORY_HISTORY
```

The database should contain security metadata rather than raw secrets.

---

# 10. Model Security

Protect:

- model artifact
- model hash
- model version
- feature schema
- model configuration
- thresholds

A changed model must not silently change browser security behavior.

---

# 11. Policy Security

Policy decisions must be traceable to:

```text
evidence
+
model
+
rules
+
context
```

The policy engine must not rely on an unexplained opaque score.

---

# 12. Privacy Test Requirements

Before release, prove:

```text
RAW_PASSWORD_READ=NO
RAW_PASSWORD_STORED=NO
RAW_PASSWORD_SENT=NO
RAW_PASSWORD_LOGGED=NO

RAW_OTP_READ=NO
RAW_OTP_STORED=NO
RAW_OTP_SENT=NO
RAW_OTP_LOGGED=NO

RAW_CVV_READ=NO
RAW_CVV_STORED=NO
RAW_CVV_SENT=NO
RAW_CVV_LOGGED=NO
```

Equivalent checks should be performed for:

- cookies
- authorization headers
- request bodies
- authentication tokens
- raw form values

---

# 13. Threat Coverage

The architecture is intended to investigate:

```text
credential phishing
financial-data harvesting
identity-data harvesting
data exfiltration
dynamic phishing
identity deception
redirect attacks
suspicious scripts
domain infrastructure risk
adversarial/evasion behavior
```

Each threat class requires its own evidence and experiment.

---

# 14. Security Limitations

The architecture cannot automatically guarantee detection of:

- every malicious website
- every future attack
- encrypted payload contents
- server-side behavior invisible to the browser
- cloaked content never exposed during observation
- unavailable/redacted domain information
- attacks outside the browser observation boundary

These limitations are part of the research scope, not failures to be hidden.

---

# 15. Security Decision Principle

Never use:

```text
ONE SIGNAL
    ↓
MALICIOUS
```

Prefer:

```text
URL
+
DOM
+
DATA REQUEST
+
IDENTITY
+
BEHAVIOR
+
DESTINATION
+
DOMAIN CONTEXT
+
ML
        ↓
CORRELATED EVIDENCE
        ↓
RISK
        ↓
POLICY
```

Whether this multi-signal approach actually improves detection must be established experimentally.

---

# 16. Final Principle

CAPSTONE-1 should aim to become:

```text
PRIVACY-PRESERVING
LOCAL-FIRST
EVIDENCE-BASED
EXPLAINABLE
MEASURABLE
REPRODUCIBLE
```

The system should protect the user without itself becoming a collector of sensitive user information.