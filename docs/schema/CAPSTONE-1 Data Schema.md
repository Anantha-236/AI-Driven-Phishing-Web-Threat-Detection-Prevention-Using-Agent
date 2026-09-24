# CAPSTONE-1 Data Schema

> Current implementation update, 2026-09-10: PostgreSQL retains observations, events_sanitized and adds assessments_sanitized keyed by session/tab/event sequence. Reports include document, model ID and SHA-256, analysis/policy versions, numeric parameters, evidence sequence references, uncertainty and observed outcome. Session/document relationships are represented by indexed identifiers rather than duplicated tables. Raw event model_version is pending until a derived assessment identifies its actual inference artifact. See [CURRENT-STATUS](../../CURRENT-STATUS.md) and [implementation blueprint](../../implementation_plan.md).

## Purpose

This document defines the logical data model used throughout CAPSTONE-1.

The authoritative implementation is maintained in the browser schema source.

Documentation must remain synchronized with the implementation.

---

# 1. Data Flow

```text
WEBPAGE
   ↓
RAW BROWSER OBSERVATION
   ↓
NORMALIZED EVIDENCE
   ↓
FEATURE VECTOR
   ↓
ML INPUT
   ↓
ML OUTPUT
   ↓
THREAT ASSESSMENT
   ↓
POLICY DECISION
   ↓
SANITIZED TELEMETRY
   ↓
POSTGRESQL
```

---

# 2. Core Objects

## Observation

Represents one browser collection event.

```text
Observation
├── observation_id
├── collection_id
├── page metadata
├── structural metadata
├── requested data categories
├── model result
├── threat assessment
├── policy result
└── timestamp
```

---

# 3. Evidence

Evidence represents an observable security fact.

```text
Evidence
├── evidence_id
├── source
├── status
├── confidence
├── artifact
└── timestamp
```

Statuses:

```text
OBSERVED
VERIFIED
INFERRED
UNKNOWN
NOT_OBSERVABLE
```

---

# 4. Feature Vector

A deterministic numerical representation derived from normalized evidence.

Requirements:

- stable ordering
- versioned definition
- documented semantics
- consistent missing-value handling
- Python/browser compatibility

---

# 5. Model Output

```text
ModelOutput
├── model_version
├── score
├── confidence
└── inference metadata
```

---

# 6. Threat Assessment

```text
ThreatAssessment
├── threat_level
├── confidence
├── reason_codes
└── supporting evidence
```

Threat levels:

```text
BENIGN
SUSPICIOUS
MALICIOUS
INSUFFICIENT_EVIDENCE
```

---

# 7. Policy Result

```text
PolicyResult
├── action
├── reason
├── enforcement_state
└── timestamp
```

Actions:

```text
ALLOW
WARN
CONFIRM
BLOCK
CONTAIN
```

---

# 8. Privacy Boundary

The schema must never contain:

```text
password values
OTP values
CVV
raw form values
request bodies
cookies
authorization headers
authentication tokens
```

The schema stores metadata about the existence/category/relationship of sensitive data, not the sensitive data itself.