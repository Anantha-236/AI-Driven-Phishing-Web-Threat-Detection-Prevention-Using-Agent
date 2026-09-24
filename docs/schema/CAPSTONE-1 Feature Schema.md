# CAPSTONE-1 Feature Schema

> Current implementation update, 2026-09-10: The current event-features-1 schema has 14 flat numeric parameters plus 8 relationship parameters. FLAT_FEATURES and RELATIONSHIP_FEATURES in tsfeg.ts define the order; both receive identical events. The selected controlled linear predictor uses flat features. The older five-input ONNX and 20-row research feature spaces remain separate and are not interchangeable. See [CURRENT-STATUS](../../CURRENT-STATUS.md) and [implementation blueprint](../../implementation_plan.md).

## Purpose

Defines the conceptual feature groups used for machine-learning inputs.

---

# 1. URL Features

Examples:

```text
URL length
host length
path length
character distribution
entropy
host structure
```

---

# 2. Domain Features

Potential features:

```text
domain age
registration context
DNS context
IP context
domain similarity
```

These are contextual features and must be treated as unavailable when intelligence cannot be obtained.

---

# 3. Page Features

Examples:

```text
form_count
input_count
script_count
iframe_count
page structure
```

---

# 4. Data-Request Features

Examples:

```text
email_requested
username_requested
password_requested
otp_requested
payment_card_requested
cvv_requested
identity_requested
file_upload_requested
location_requested
microphone_requested
camera_requested
```

---

# 5. Behavior Features

Potential features:

```text
redirect_count
cross_origin_form
form_action_change
dynamic_form_created
dynamic_input_created
script_insertion
navigation_change
```

---

# 6. Destination Features

Potential features:

```text
destination_domain
same_origin
cross_origin
destination_type
relationship_strength
```

---

# 7. Identity Features

Potential features:

```text
claimed_service
official_domain_match
domain_identity_match
brand_similarity
identity_confidence
```

Visual identity features remain a future research extension unless experimentally integrated.

---

# 8. Context Features

Examples:

```text
service_category
declared_purpose
expected_data_category
purpose_match
unexpected_request
```

---

# 9. Feature Versioning

Every released feature specification must have:

```text
FEATURE_SPEC_VERSION
MODEL_VERSION
```

The browser and training pipeline must agree on:

```text
feature order
feature meaning
normalization
missing-value representation
```

---

# 10. Privacy Rule

No feature may encode a raw sensitive value.

For example:

```text
password_field_present = 1
```

is acceptable.

```text
password_value_hash = ...
```

is not part of the default privacy-preserving design.