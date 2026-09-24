# CAPSTONE-1 PoC Scenario Matrix

## Purpose

This matrix defines the controlled scenarios used to verify individual system capabilities.

| Scenario | Purpose | Expected Evidence | Expected Assessment | Expected Policy |
|---|---|---|---|---|
| Benign | Normal webpage behavior | Low-risk structural evidence | Benign | Allow |
| Suspicious | Sensitive request / suspicious context | Data-request + contextual evidence | Suspicious/Malicious depending on evidence | Warn/Block |
| High-Risk | Strong malicious indicators | Multiple correlated signals | Malicious | Block |
| Privacy | Privacy boundary | Sensitive category without value | Security result independent of secret value | Policy-dependent |
| Dynamic | Late DOM mutation | New form/input evidence | Depends on evidence | Policy-dependent |

---

# Scenario Record

For every run record:

```text
scenario_id
date
browser_version
extension_build
page_url
collection_id
observation_id

form_count
input_count
script_count
requested_data_types

model_version
model_score
threat_level
policy_action

backend_status
database_status
privacy_status
```

---

# Database Proof

Record:

```text
BEFORE_COUNT
AFTER_COUNT
ROW_DELTA
```

The newly created row must correspond to the browser scenario.

---

# Privacy Proof

Record:

```text
RAW_PASSWORD_SENT=NO
RAW_OTP_SENT=NO
RAW_CVV_SENT=NO
RAW_FORM_VALUES_SENT=NO
REQUEST_BODY_SENT=NO
```

---

# Interpretation

A scenario is COMPLETE only when its required evidence is observed at the appropriate level.

A passing unit test does not replace a required browser runtime test.