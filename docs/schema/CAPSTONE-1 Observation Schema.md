# CAPSTONE-1 Observation Schema

> Current implementation update, 2026-09-10: The existing snapshot contract remains schema 3.0.0. The continuous recorder emits strict events 1.2.0 with browser document/frame IDs, sequence, categories, origins and timestamps; historical 1.1.0 remains accepted. Lifecycle/form/submission categories extend the earlier vocabulary. Frame navigation is observed through browser navigation metadata; enum presence alone does not prove an event category is emitted. Reports distinguish OBSERVED, INFERRED, UNKNOWN and NOT_OBSERVABLE semantics. See [CURRENT-STATUS](../../CURRENT-STATUS.md) and [implementation blueprint](../../implementation_plan.md).

## Purpose

Defines the persistent PostgreSQL representation of a browser observation.

---

## Observation Record

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

## Field Definitions

| Field | Meaning |
|---|---|
| observation_id | Unique observation identifier |
| collection_id | Browser collection/session identifier |
| page_domain | Sanitized page domain |
| page_url_sanitized | Sanitized URL without sensitive components |
| is_https | Whether the page uses HTTPS |
| form_count | Number of observed forms |
| input_count | Number of observed inputs |
| script_count | Number of observed scripts |
| requested_data_types | Classified requested information categories |
| threat_level | Assessment result |
| model_score | Local model output |
| policy_action | Resulting policy decision |
| observed_at | Observation timestamp |

---

## Privacy Rules

The observation schema MUST NOT contain:

- input values
- password values
- OTP values
- CVV values
- cookies
- request bodies
- authorization headers
- authentication tokens

---

## Example Safe Observation

```json
{
  "observation_id": "obs-example",
  "collection_id": "coll-example",
  "page_domain": "example.com",
  "page_url_sanitized": "https://example.com/login",
  "is_https": true,
  "form_count": 1,
  "input_count": 3,
  "script_count": 4,
  "requested_data_types": [
    "EMAIL",
    "PASSWORD",
    "OTP"
  ],
  "threat_level": "SUSPICIOUS",
  "model_score": 0.81,
  "policy_action": "WARN",
  "observed_at": "2026-09-04T00:00:00Z"
}
```

This example contains metadata only.

---

## Database Integrity

The database schema must enforce:

- required identifiers
- valid types
- valid threat states
- valid policy actions
- timestamp consistency

The SQL implementation is authoritative for physical database details.