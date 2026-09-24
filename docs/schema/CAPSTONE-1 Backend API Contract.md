# CAPSTONE-1 Backend API Contract

> Current implementation update, 2026-09-10: Current FastAPI adds POST /api/v1/assessments with strict event-report-1 fields. POST /api/v1/events/batch accepts 1-100 strict 1.1.0/1.2.0 events. New emitted events are 1.2.0. Exact retry identity is session/tab/sequence; conflicting event contents return 409, invalid input 422 without echo, storage failures 503. The standard-library compatibility server retains its legacy observation scope; startup uses backend.main:app. See [CURRENT-STATUS](../../CURRENT-STATUS.md) and [implementation blueprint](../../implementation_plan.md).

## 1. Purpose

Defines the contract between the browser extension and FastAPI backend.

---

# 2. Architecture

```text
BROWSER EXTENSION
        ↓
HTTP API
        ↓
FASTAPI
        ↓
DATABASE LAYER
        ↓
POSTGRESQL
```

---

# 3. Health Endpoint

```text
GET /api/v1/health
```

Purpose:

- verify backend availability
- verify database connectivity

Expected conceptual response:

```json
{
  "status": "HEALTHY",
  "database": "CONNECTED"
}
```

---

# 4. Observation Endpoint

```text
POST /api/v1/observations
```

Purpose:

Receive one sanitized browser observation.

---

# 5. Observation Readback

```text
GET /api/v1/observations
```

Purpose:

Retrieve recent sanitized research observations.

---

# 6. Request Requirements

A valid request must contain only fields required by the observation schema.

The backend must reject unexpected or unsafe values where appropriate.

---

# 7. Privacy

The API must never be used to transmit:

```text
password
OTP
CVV
raw form value
request body
cookie
authorization header
authentication token
```

---

# 8. Error Handling

The backend should distinguish:

```text
VALIDATION_ERROR
DATABASE_ERROR
AUTHENTICATION_ERROR
TIMEOUT
INTERNAL_ERROR
```

Backend failure must not silently create false security claims.

---

# 9. API-to-Database Path

```text
POST /api/v1/observations
        ↓
request validation
        ↓
observation normalization
        ↓
store_observation()
        ↓
PostgreSQL observations
```

---

# 10. Verification Requirement

A successful API response is not sufficient to prove end-to-end browser persistence.

The research proof must correlate:

browser scenario
+
service-worker handoff
+
API request
+
PostgreSQL row

under a real browser execution.