# CAPSTONE-1 Proof-of-Concept Overview

## 1. Purpose

The PoC documentation records experimentally demonstrated behavior of CAPSTONE-1.

It must never be used to claim capabilities that have not been tested.

---

# 2. PoC Philosophy

```text
IMPLEMENTED
    ≠
VERIFIED
```

A source-code implementation becomes a verified capability only after appropriate runtime evidence exists.

---

# 3. PoC Pipeline

```text
CONTROLLED / REAL WEBPAGE
        ↓
BROWSER EXTENSION
        ↓
EVIDENCE COLLECTION
        ↓
CLASSIFICATION
        ↓
FEATURE EXTRACTION
        ↓
LOCAL ML
        ↓
ASSESSMENT
        ↓
POLICY
        ↓
FASTAPI
        ↓
POSTGRESQL
```

---

# 4. Current PoC Categories

## Static Browser

Tests:

- forms
- inputs
- data categories
- scripts
- page metadata

## Dynamic Browser

Tests:

- late-created forms
- late-created inputs
- changed form actions
- DOM mutations

This requires independent runtime verification.

## Backend

Tests:

- API health
- observation validation
- database persistence
- API readback

## Privacy

Tests:

- no secret-value collection
- no secret persistence
- no secret transmission
- no secret logging

## ML

Tests:

- feature-vector generation
- model inference
- model output
- prediction consistency

---

# 5. Evidence Levels

```text
CODE_ONLY
TEST_VERIFIED
RUNTIME_VERIFIED
END_TO_END_VERIFIED
RESEARCH_VALIDATED
```

A higher level requires evidence from the preceding level.

---

# 6. Result Language

Use:

IMPLEMENTED

for code that exists.

Use:

VERIFIED

for behavior demonstrated by appropriate tests.

Use:

NOT_VERIFIED

when runtime evidence is missing.

Use:

UNKNOWN

when the property cannot currently be determined.