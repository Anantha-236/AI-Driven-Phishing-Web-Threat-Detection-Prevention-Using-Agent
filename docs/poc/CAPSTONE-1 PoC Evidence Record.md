# CAPSTONE-1 PoC Evidence Record

## Purpose

This document is the standard template for recording one proof-of-concept experiment.

---

# Experiment Identity

```text
EXPERIMENT_ID=
DATE=
OPERATOR=
BUILD_ID=
GIT_COMMIT=
BROWSER_VERSION=
```

---

# Scenario

```text
SCENARIO_ID=
PAGE=
PURPOSE=
```

---

# Browser Evidence

```text
FORM_COUNT=
INPUT_COUNT=
SCRIPT_COUNT=

REQUESTED_DATA_TYPES=

DYNAMIC_EVENT=
NAVIGATION_EVENT=
DESTINATION_EVENT=
```

---

# ML

```text
MODEL_VERSION=
FEATURE_SPEC_VERSION=
MODEL_SCORE=
MODEL_CONFIDENCE=
INFERENCE_LATENCY=
```

---

# Assessment

```text
THREAT_LEVEL=
CONFIDENCE=
REASON_CODES=
```

---

# Policy

```text
POLICY_ACTION=
ENFORCEMENT_STATE=
```

---

# Backend

```text
FASTAPI_STATUS=
DATABASE_STATUS=
HTTP_STATUS=
```

---

# PostgreSQL

```text
BEFORE_COUNT=
AFTER_COUNT=
ROW_DELTA=
OBSERVATION_ID=
```

---

# Privacy

```text
RAW_PASSWORD_READ=
RAW_PASSWORD_SENT=
RAW_PASSWORD_STORED=

RAW_OTP_READ=
RAW_OTP_SENT=
RAW_OTP_STORED=

RAW_CVV_READ=
RAW_CVV_SENT=
RAW_CVV_STORED=

RAW_FORM_VALUES_SENT=
REQUEST_BODY_SENT=
```

---

# Evidence Attachments

Record references to:

```text
browser screenshot
browser console evidence
Playwright result
API response
database query
test result
log file
commit hash
```

Do not attach or record secret values.

---

# Conclusion

```text
RESULT=
PASS / FAIL / PARTIAL / NOT_VERIFIED

LIMITATION=

NEXT_ACTION=
```

Never convert PARTIAL or NOT_VERIFIED into PASS.