# ADR-003 — Privacy Boundary: No Sensitive Payload Collection

## Status

ACCEPTED

## Decision

CAPSTONE-1 classifies sensitive-data requests using metadata and structure without collecting the actual user-entered values.

## Allowed Evidence

Examples:

```text
PASSWORD_FIELD_DETECTED
OTP_FIELD_DETECTED
EMAIL_FIELD_DETECTED
FORM_COUNT=1
INPUT_COUNT=3
CROSS_DOMAIN_FORM
DESTINATION_DOMAIN
SCRIPT_METADATA
NAVIGATION_METADATA
```

## Prohibited Data

The system must not intentionally collect:

- passwords
- OTP values
- CVV
- raw form values
- cookies
- authorization headers
- authentication tokens
- request bodies
- private page content

The threat model explicitly establishes this boundary.

## Example

Allowed:

```text
<input type="password">
        ↓
PASSWORD
```

Prohibited:

```text
password = <PROHIBITED_RAW_USER_SECRET>
```

## Rationale

The system is itself a security product.

Collecting the secret to detect whether another party may collect it would create an unacceptable secondary privacy risk.

## Consequences

### Positive

- lower privacy exposure
- safer research telemetry
- lower breach impact
- easier auditing

### Negative

Some attacks cannot be established without information unavailable to the browser metadata-only boundary.

## Research Principle

The detector must answer:

> What type of data is being requested?

without answering by:

> What is the actual value?

## Stop Condition

Any feature requiring intentional access to sensitive values must stop and be redesigned as a metadata-only feature.