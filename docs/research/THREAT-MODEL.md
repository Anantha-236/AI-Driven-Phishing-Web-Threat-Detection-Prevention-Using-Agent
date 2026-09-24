# CAPSTONE-1 Threat Model

## Scope

CAPSTONE-1 is a local-first browser security system that assesses browser-observable evidence about webpages and their behavior. It is intended to detect defined classes of phishing, sensitive-data harvesting, suspicious data flow, deceptive identity, and related web behavior. It does not claim to detect every malicious website or every future attack.

The system must make decisions from multiple independent signals. A URL, a password field, domain metadata, or an ML score alone is insufficient to establish maliciousness.

## Protected assets

- User credentials and one-time codes.
- Financial and identity information.
- Private form values, cookies, authorization headers, request bodies, and tokens.
- Browser navigation and page context.
- Local model and policy integrity.
- Sanitized telemetry and backend database integrity.

## Trust boundaries

1. Untrusted webpage DOM, scripts, frames, redirects, and resource origins.
2. Browser extension content-script boundary.
3. Extension service worker and local feature/inference pipeline.
4. Optional domain, DNS, and registration intelligence providers.
5. FastAPI service boundary.
6. PostgreSQL persistence boundary.
7. Research dataset, model-training, and evaluation boundary.

## Threat taxonomy

### T1 Credential phishing

- Username or password harvesting.
- OTP harvesting.
- Credential forms that impersonate a trusted service.

### T2 Financial-data harvesting

- Payment card or expiry requests.
- CVV requests.
- Banking-information requests.

### T3 Identity-data harvesting

- Identity-document requests.
- Personal identity-information requests.

### T4 Data exfiltration

- Sensitive information sent to unexpected destinations.
- Cross-domain form submission.
- Hidden or indirect submission mechanisms.

### T5 Dynamic phishing

- JavaScript-created forms or inputs.
- Late-loaded sensitive fields.
- Form-action modification after initial load.
- DOM mutation attacks.

### T6 Identity deception

- Brand impersonation.
- Brand and domain mismatch.
- Punycode or homograph-like domains.

### T7 Redirect and deception behavior

- Suspicious redirects.
- Multi-step phishing flows.
- Login redirection chains.

### T8 Suspicious scripts and resources

- Dynamically inserted scripts.
- Suspicious external script dependencies.
- Script-triggered collection behavior.

### T9 Domain infrastructure risk

- Newly registered or suspicious domains.
- Suspicious registration, DNS, or IP context.
- Registration-owner information that is unavailable or redacted.

### T10 Adversarial and evasion behavior

- Cloaking or CAPTCHA-gated content.
- Changing DOM structures.
- Unseen domains.
- Manipulated or missing features.

## Privacy requirements

The browser pipeline must classify sensitive-data requests without reading their values. It must not collect, store, send, or log password values, OTP values, CVVs, private form values, request bodies, cookies, authorization headers, or tokens.

Telemetry must contain sanitized metadata only. URL query strings and other sensitive components must be removed before persistence. Persistent identifiers must be minimized and documented.

## Security assumptions

- Browser extension permissions are reviewed and limited to required behavior.
- The local model and feature specification are protected from unauthorized modification.
- Backend access is authenticated or restricted appropriately for the deployment context.
- PostgreSQL credentials remain local-only, ignored by Git, untracked, and absent from repository history.
- External domain intelligence is treated as advisory and may be unavailable, stale, or incomplete.

## Out of scope

- Universal malicious-site detection.
- Inspection of encrypted payload contents, cookies, authorization headers, or raw form values.
- Claims about proprietary implementation details of commercial systems.
- Unmeasured claims of global coverage, optimality, patentability, or adversarial robustness.

## Required evidence

A threat class is not considered complete from source code alone. Each claimed capability requires implementation, integration, automated testing, real runtime evidence, security review, privacy review, documentation, and regression results. Unknown or unmeasured properties remain `UNKNOWN`.

## Known limitations

- Browser-observable evidence cannot establish all server-side or post-exfiltration behavior.
- Domain and registration intelligence can be unavailable, delayed, privacy-protected, or misleading.
- Dynamic and cloaked content may require interaction to become observable.
- Unseen brands, languages, domains, and attack techniques require explicit evaluation before coverage claims.
- Detection thresholds involve a tradeoff between false alarms and missed threats and must be measured on leakage-audited data.
