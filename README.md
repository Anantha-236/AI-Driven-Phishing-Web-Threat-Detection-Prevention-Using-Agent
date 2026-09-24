# AI-Driven Phishing (Web-Threat) Detection and Prevention Using Machine Learning

CAPSTONE-1 is a Chromium Manifest V3 browser-security research prototype. It observes security-relevant structure and events, derives sanitized evidence, runs local contextual assessment with advisory ML, explains its decisions, and stores sanitized research records through FastAPI and PostgreSQL.

**Current checkpoint: 2026-09-18.** The final approach is authoritative; contextual-agent implementation and candidate training are tracked separately from real-world validation. The complete research objective remains limited by missing independent domain/brand evaluation data. See [current status and measured results](CURRENT-STATUS.md) and the [implementation blueprint](implementation_plan.md).

## Current workflow

```text
Existing content collector + MutationObserver + browser metadata
    -> strict sanitized events -> browser session / tab / document / frame
    -> identical-event flat parameters + relationship evidence / graph export
    -> local contextual agent: purpose + contradictions + positive evidence + advisory ML
    -> risk, uncertainty, supporting events and user security report
    -> warning / confirmation / supported submit-event cancellation

Sanitized events and reports -> FastAPI -> PostgreSQL
```

The browser agent selects ALLOW/WARN/CONFIRM without waiting for FastAPI. Sanitized events and reports are delivered independently; backend outage does not change decision ownership. The historical backend assessment endpoint remains available only for research replay and is marked deprecated. Legacy snapshot observations remain compatible but no longer publish a competing security decision.

The contextual flat representation has 27 features. Page-authored titles/headings/button labels are categorized locally; only a coarse purpose category leaves the page. Claimed purpose is an inference, never a verified statement about intent. Reports separate contradictions, positive consistency evidence, observation coverage, model scores and uncalibrated confidence. Unknown identity, password/OTP fields, a stable cross-origin target or a redirect alone do not establish phishing. Relationship graphs remain supporting evidence; predictive graph superiority is not established.

The historical controlled event LR remains bundled as an advisory model. New contextual LR/RF/GB candidates are trained and exported separately; synthetic calibration or ONNX parity alone does not authorize deployment. The old five-input ONNX model is only a compatibility artifact, not the new contextual detector. See the status report for the exact selected candidate and release gates.

The popup displays local decision ownership, purpose with uncertainty, positive evidence, contradictions, coverage, model provenance, form destinations and independently refreshed telemetry health. Reports can be downloaded as JSON. The synchronous submit guard rechecks the effective target, including submit-button overrides. Changed destinations after interaction, effective-target mismatches, HTTPS downgrades or a contextual confirmation decision can prompt confirmation. Direct programmatic submission and arbitrary JavaScript requests remain outside this guard's coverage.

An independent DNR layer downloads [OpenPhish Community indicators](https://openphish.com/phishing_feeds.html) and installs up to 1,000 exact, case-sensitive HTTP(S) URL rules for navigation and resource requests. It refreshes every 12 hours, retains unexpired rules during a download failure, and removes rules older than 48 hours on the next startup/hourly check. Query-bearing, credential-bearing, wildcard and invalid indicators are excluded; fragments are removed because they are not transmitted. Other paths, query variants and newly discovered attacks are not automatically covered. Browsing URLs are never sent to this provider. Downloaded indicators remain in the local browser, not in the repository or exported reports. Use is scoped to this personal/academic research prototype under the [provider's terms](https://openphish.com/terms.html); commercial deployment needs an appropriately licensed source. The original static DNR fixture remains separate.

## Privacy

The collector does not access field values, cookies, authorization headers, request bodies or clipboard data. Structural names/labels are used locally for category classification and are excluded from telemetry. Origin metadata excludes paths, queries, fragments and userinfo. Strict event/report schemas reject unknown fields and free-text metadata; validation responses do not echo rejected input.

Unit tests use throwing value getters. Controlled Chromium tests check dummy sentinels in extension telemetry, storage, sampled console messages and exact-session PostgreSQL evidence. These scoped checks do not prove every possible hostile-page or lifecycle case.

## Run locally

From this project directory, with Node.js, Python and PostgreSQL installed:

```powershell
npm.cmd ci
python -m pip install -r requirements.txt
# Configure local database values in .env, using .env.example as the template.
powershell -ExecutionPolicy Bypass -File scripts/start-capstone.ps1
```

The startup script checks PostgreSQL, starts loopback services, and builds `dist/`. Add `-Verify` to run controlled browser verification as well. In Chromium, open `chrome://extensions`, enable Developer mode, choose **Load unpacked**, and select this project's `dist` folder. Use `http://127.0.0.1:41731/` for controlled scenarios. Reload the unpacked extension after rebuilding and reload already-open webpages so their content scripts match the new build.

**Historical September 10 observation (recheck your current profile):** Chrome's Default-profile registration pointed to `C:\Users\anant\OneDrive\Desktop\Capstone-1\dist`, an older checkout. The repaired build is `C:\Users\anant\OneDrive\Desktop\Capstone-1-GitHub-Ready\dist` and shows version **1.2.0**. Disable the old CAPSTONE entry and load the repaired directory; reloading an extension from the older directory does not load this build. Backend and scenario services were initially stopped, although PostgreSQL itself was healthy.

```powershell
powershell -ExecutionPolicy Bypass -File scripts/status-capstone.ps1
powershell -ExecutionPolicy Bypass -File scripts/stop-capstone.ps1
```

## Validate and reproduce the engineering comparison

```powershell
npm.cmd run typecheck
npm.cmd run build
npm.cmd run test:unit
npm.cmd run test:integration
python -m pytest tests/integration/test_event_contract.py -q
npm.cmd run test:browser
# Historical graph/flat experiment (do not use this command to select a production model):
# python ml/training/train_models.py --events .runtime/event-model-training-dataset.json
# Current contextual candidate training: see CURRENT-STATUS.md for the reproducible command.
# Run with port 8000 free:
node scripts/verify-tsfeg.mjs
```

Browser/integration tests create controlled PostgreSQL records. Playwright manages loopback test servers when they are not already running. Restart an existing backend after schema/source changes. The standalone proof starts its own backend and writes `.runtime/tsfeg-verification.json`; historical Stage/M0/M1 reports remain unchanged.

The historical comparison reports Logistic Regression, Random Forest and Gradient Boosting on identical flat/relationship inputs, template-family holdout, a limited chronological layout holdout, precision, recall, F1, average precision, PR-AUC, ROC-AUC, FPR and FNR. Missing meaningful domain/brand groups are reported as unavailable. The 24 authored episodes do not establish real-world accuracy or calibration.

The bundled model's exact training input is preserved locally as `.runtime/event-model-training-dataset.json`; its SHA-256 matches the model artifact's `dataset_sha256`. Browser test runs replace `event-dataset-latest.json` with a new collection, so that file need not match the bundled model. To reproduce the recorded comparison, pass the preserved training input to the training command. These ignored local artifacts must be included separately when sharing experiment evidence.

## Repository ownership

- `browser-extension/`: existing extension, event engine, local model and UI.
- `backend/`: FastAPI, strict schemas and PostgreSQL persistence.
- `ml/`: existing training/evaluation tools and research artifacts.
- `tests/`: unit, integration and persistent-Chromium tests.
- `scripts/`: startup, controlled scenario server and verification tools.
- `docs/`: architecture, schemas, research protocols and preserved historical evidence.

[Master specification](docs/MASTER-SPECIFICATION.md) defines the research target. [CURRENT-STATUS.md](CURRENT-STATUS.md) identifies what is implemented, verified, prototype-scale and still missing. The project is not a production security product.
