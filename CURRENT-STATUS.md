# CAPSTONE-1 current status

Status date: 2026-09-11. **Working controlled research prototype; full research completion is not established.**

The active implementation scope is [implementation_plan.md](implementation_plan.md). Historical Stage and M0/M1 evidence files remain unchanged. The current checks write ordinary generated artifacts under `.runtime/` and `test-results/`.

## September 11 complete workflow recheck

The current database -> FastAPI -> ML agent -> extension workflow passed typecheck/build, 21 unit tests, 2 JavaScript integration tests, 12 Python contract tests and 16 Chromium tests (51 total). Three added browser regressions verify agent timeout fallback with continuing PostgreSQL delivery, wrong-document response rejection, and backend CONFIRM/ALLOW actuator transitions. The action-transition test overrides a backend response to isolate browser enforcement; it does not measure classifier accuracy. The report export additionally passed content checks for session/tab, backend source, model checksum, identity sources and limitations.

The live health, model, service-profile and observation-list endpoints returned HTTP 200. PostgreSQL was CONNECTED; the source, bundled model and active registry checksum matched. The standalone worker-restart check passed with 49 pre-restart events and session continuity. Services were restarted and left healthy. No product-code failure was exposed by these checks; existing tests and this status record were extended. The current aggregate is `.runtime/browser-audit-latest.json`, which preserves the older version 1.2 audit under `previous_browser_audit`. Older bypass findings are not represented as freshly rerun probes.

## September 11 backend ML agent (extension 1.3.0)

The primary assessment now uses `POST /api/v1/agent/assess`. FastAPI validates sanitized single-document event streams, reconstructs the 14 flat features and relationship evidence, runs the existing `controlled-event-lr-1` Logistic Regression export, chooses ALLOW/WARN/CONFIRM, and persists the report in the existing assessment table. Reports identify BACKEND_ML_AGENT, agent version, model checksum, feature contributions, reasons and measured processing time. This integrates the existing trained model; it does not establish a new independently validated training dataset or DL/RL model.

Corroborated suspicious patterns require confirmation. A model score of at least 0.8 can also escalate an existing concerning pattern to confirmation when observations are complete. A high score alone does not label ordinary pages malicious or authorize automatic blocking. This threshold is a prototype policy choice, not a calibrated safety guarantee.

The extension enforces returned decisions in the current top document, retains synchronous destination checks and independent exact-URL DNR protection, and uses its existing local assessment if the backend fails or exceeds the 1,500 ms response deadline. The popup explicitly labels LOCAL FALLBACK and separates backend computation from request round-trip time. Per-tab analysis is coalesced and replies are checked against the current document. The API can return an assessment if database storage fails; pending delivery remains visible and retryable.

Current validation passed typecheck, build, 21 unit tests, 2 JavaScript integration tests, 12 Python contract tests and all 13 Chromium scenarios. Python checks cover 24-episode feature/score parity, strict rejection, storage failure and model-sensitive policy escalation. Browser checks cover backend reports, exact PostgreSQL persistence and outage recovery. The standalone worker-restart proof also passed with 49 events in Chromium 151.0.7922.34. September 10 measurements below are historical. Shadow-root discovery, full-browser-shutdown queue durability, direct JavaScript submission and unlisted-request interception gaps remain open. Personal Chrome still needs the corrected unpacked `dist` directory loaded.

## September 10 operational repair (extension 1.2.0)

The API and scenario services were NOT_RUNNING at inspection; PostgreSQL itself was healthy. Chrome's saved Default-profile registration referenced the older `Desktop/Capstone-1/dist`, whose manifest lacked the current storage/network permissions. The repaired build is `Desktop/Capstone-1-GitHub-Ready/dist`. Personal Chrome registration was not changed: the Windows-control connection was unavailable. Load the corrected directory, disable the old CAPSTONE entry, and reload webpages. Code/test success does not establish that a personal browser has loaded this build.

The popup now exposes backend health, event/report backlog, explicit event acknowledgements, loss counts and manual retry. Controlled outage recovery was verified against matching PostgreSQL session/tab rows. A detailed JSON export includes model provenance, identity-registry sources, form destinations, event references, delivery and list-protection status. Neither telemetry nor the report contains entered secrets.

The compatibility snapshot model no longer maps ordinary password/OTP presence or its uncalibrated score to a malicious decision. The event policy no longer warns from a cross-origin form plus unrelated nearby requests and model score alone. Such temporal associations remain available as evidence. Existing eight-case authored negatives still produce no policy warning; this is not a real-world FPR.

The separate exact-origin registry is limited to `https://accounts.google.com`, `https://www.paypal.com` and `https://login.microsoftonline.com`, with primary login-page sources checked September 10. It does not reuse example service profiles as verified identity. Possible brand-word hostname impersonation is an inference; unmatched hosts remain UNKNOWN. Registry membership is not a certificate of page safety or destination authorization.

Sensitive forms now require confirmation at submit time for initially unverified cross-origin targets, effective submit-button overrides, HTTPS downgrades, unsupported targets and possible brand-lookalike origins, as well as the previous changed-target case. Ordinary sensitive-field discovery alone does not display a danger warning. Known login-origin targets and same-origin targets are not automatically considered proof of authorized handling. The guard still does not universally stop early hostile handlers, direct `form.submit()`, fetch/XHR, or server-side forwarding.

An independent OpenPhish Community DNR layer installs up to 1,000 exact case-sensitive URLs for navigation and resource requests. The browser suite uses a controlled feed-shaped fixture and verifies blocked navigation/fetch, zero matching receiver requests, permitted other paths/case variants, and retention of unexpired rules during feed outage. This proves the enforcement mechanism, not OpenPhish accuracy or coverage. Queries, credentials, wildcard and malformed indicators are excluded, not broadened to whole domains. Refresh interval is 12 hours; 48-hour expiry is enforced on startup/hourly checks. Personal/academic use is subject to the provider's terms, linked in README; downloaded indicators are not redistributed in project artifacts.

Final isolated Chromium check on version 1.2.0 downloaded the live provider feed and installed **282 exact URL rules**, excluding **18 indicators**; no live phishing page was opened. Aggregate evidence is `.runtime/phishing-feed-status.json`. This is a dated runtime count, not a detection score. The final build also displayed its database-connected benign-page report in `.runtime/repaired-live-report.png`. Backend and scenario services were started and left healthy for local use; the personal Chrome registration still needs the directory correction above.

## Current runtime

Latest independent browser check (September 10, extension 1.2.0, Chromium 151.0.7922.34): rebuild succeeded and all 13 browser regression tests passed again. Additional isolated local dummy-page probes reproduced the prevention limits: native submit cancellation produced zero receiver requests; direct `HTMLFormElement.prototype.submit.call(form)` and an unlisted `fetch()` each produced one receiver request; the exact listed URL was blocked with zero receipts, but its query-string variant produced one receipt. An unfamiliar same-origin form retained UNKNOWN identity with a benign/no-elevated-pattern decision. These findings show supported mechanics, not complete authenticity or data-loss protection. Probe results and the built worker SHA-256 are in `.runtime/browser-audit-latest.json`. Chrome's saved Default-profile entry still points to the old checkout; personal-window control remained unavailable. No product source was changed during this check.

Extended probes also found one rendered password field inside an open shadow root but zero recorded password discoveries. In a separate offline test, nine events were pending before a full browser shutdown and zero matching streams survived reopening the same temporary browser profile. This confirms the durability gap rather than a PostgreSQL connection failure. Same-tab navigation correctly changed the report document ID and removed the previous page's password category. All probes used controlled dummy pages/data; no live phishing site or real credentials were used.

Chromium MV3 content scripts reuse the existing collector and MutationObserver. Sanitized events are validated and correlated with browser tab/document/frame identifiers. New tab streams share a browser-session identifier in `chrome.storage.session`; retained older sessions remain readable. The recorder provides both flat parameters and typed relationship evidence/graph exports from the same event arrays.

The primary event assessment now runs in the loopback backend, with a local fallback, using a trained, controlled-data Logistic Regression model exported as numeric coefficients, feature order, scaling, provenance and checksum metadata. The selected model uses **flat features**. Relationship joins remain available for evidence explanations and conservative policy rules. The old five-input ONNX model remains a separate compatibility/snapshot path; it is not the model powering the new security report.

The popup reads the current active tab and browser document, preserves reasons and uncertainty, and distinguishes a decision, a displayed warning, a cancelled submit event, and explicit user confirmation. Form-target protection and the exact-URL feed layer have separate coverage, described above. The original fixed DNR fixture remains separate from both learned decisions and downloaded indicators.

Event delivery is independently retryable; the backend assessment endpoint also stores its decision, and the extension retries final report delivery. FastAPI stores strict sanitized events in `events_sanitized`, legacy summaries in `observations`, and versioned reports/parameters/evidence references in `assessments_sanitized`. The event model's actual SHA-256 is recorded in reports and the model registry. Events carry their observation/analysis/policy versions; `model_version: pending` means inference has not yet been attached to that raw event. The subsequent report identifies the model used and the event sequence analyzed.

## Capability classification

| Component | State | Verified boundary |
|---|---|---|
| Build and TypeScript | VERIFIED | Current extension build and both TypeScript configurations |
| Collector and existing MutationObserver | VERIFIED | Static page, dynamic page and 200-field controlled burst |
| Strict typed event schema | VERIFIED | New events use 1.2.0; backend accepts historical 1.1.0 and current 1.2.0; no generic payload field |
| Session/document/frame correlation | VERIFIED | Controlled frames, opaque origins, per-tab sequences, shared session, worker restart; not every lifecycle |
| Queue retries | VERIFIED | Lost/missing acknowledgements, never-settling message, overflow accounting and backend outage regressions |
| Local event-model inference | VERIFIED / PROTOTYPE | Python-to-TypeScript numerical parity; trained only on 24 controlled episodes |
| Flat and relationship representations | VERIFIED | Same recorded event inputs; relationship predictive superiority not established |
| Explainable report and PostgreSQL report readback | VERIFIED | Exact controlled report/session/tab/sequence and privacy checks |
| Confirmation/cancellation | VERIFIED | Controlled form request absent after cancellation; not universal request interception |
| Legitimate-flow false-positive check | VERIFIED | Eight authored authentication/payment metadata approximations; zero policy warnings in this set |
| Privacy | VERIFIED, scoped | Throwing value getters in unit tests; browser sentinels absent from extension telemetry, sampled logs/storage and exact-session PostgreSQL rows |
| Performance | VERIFIED, scoped | Local analysis timings and renderer measurements for one controlled 200-field burst |
| Independent domain/brand evaluation | MISSING | One loopback domain group; no independently verified brand labels |
| Full proposed RQ1 pilot/generalization/calibration | PLANNED | The separate 144-episode protocol has not been executed; shakedown results do not satisfy it |
| Broad automatic threat containment | PLANNED | Controlled model has no authority for autonomous blocking |
| Known phishing URL rules | VERIFIED mechanism / limited external coverage | Exact controlled navigation/fetch blocking; independent of model; no claim of universal detection |
| Login-origin association | IMPLEMENTED / limited | Three sourced exact origins; hostname clues are inferred; broader identity remains unknown |

## Validation commands and results

Repair validation passed **21 unit tests**, **2 JavaScript integration tests**, **8 Python contract tests**, and **13 Chromium tests**, including controlled downloaded-rule blocking and database retry/export. Typecheck and build passed. The standalone restart proof passed again with **49 pre-restart events** in Chromium **151.0.7922.34**. A harmless warning-text/manifest revision was subsequently built and passed the standalone proof; the personal Chrome profile has not been runtime-verified.

```powershell
npm.cmd run typecheck
npm.cmd run build
npm.cmd run test:unit
npm.cmd run test:integration
python -m pytest tests/integration/test_event_contract.py -q
npm.cmd run test:browser
# Requires port 8000 free; starts its own backend and temporary Chromium profile:
node scripts/verify-tsfeg.mjs
```

Playwright starts loopback services if absent and uses a temporary persistent Chromium profile. PostgreSQL must be configured via the ignored `.env`. Checks insert controlled database records. Tests now query exact collection/session identities rather than assuming the latest database row belongs to the current test.

Generated evidence: `.runtime/tsfeg-verification.json`, `.runtime/security-acceptance.json`, `.runtime/security-report.png`, `.runtime/phishing-rule-acceptance.json`, `.runtime/false-positive-performance.json`, `.runtime/burst-performance.json`, `.runtime/event-dataset-latest.json`, and `.runtime/event-model-evaluation.json`. These are local artifacts, not historical Stage reports or published research results.

The exact input for the bundled model and metrics below is preserved at `.runtime/event-model-training-dataset.json`, SHA-256 `b23a763b73248542a49e0d51081dedf5402742b741fded8a357990e1db0bdba9`, matching `event-model.json`'s `dataset_sha256`. Later browser checks replace `event-dataset-latest.json` with new traces. Ignored runtime evidence must be shared separately to reproduce this exact run.

## Controlled model comparison

The final engineering collection uses 24 episodes: six authored families, two intended labels, and two dependent layouts. It applies the same 500 ms post-action horizon and requires empty content and backend queues with no counted loss. Template-family holdout keeps a family's layouts together. The chronological layout holdout is explicitly not an independent-template temporal study. Domain/brand split routines return UNAVAILABLE when meaningful groups are missing.

Scores below are pooled template-family holdout results at a fixed **0.5** classifier threshold. PR-AUC uses trapezoidal integration; average precision is separately recorded. These are classifier metrics, not the conservative policy's eight-case false-positive result.

| Features / model | Precision | Recall | F1 | PR-AUC | ROC-AUC | FPR | FNR |
| flat / LogisticRegression | 0.714 | 0.833 | 0.769 | 0.873 | 0.806 | 0.333 | 0.167 |
| flat / RandomForest | 0.800 | 0.667 | 0.727 | 0.858 | 0.806 | 0.167 | 0.333 |
| flat / GradientBoosting | 0.857 | 0.500 | 0.632 | 0.792 | 0.708 | 0.083 | 0.500 |
| relationship / LogisticRegression | 0.800 | 0.667 | 0.727 | 0.880 | 0.819 | 0.167 | 0.333 |
| relationship / RandomForest | 1.000 | 0.667 | 0.800 | 0.876 | 0.806 | 0.000 | 0.333 |
| relationship / GradientBoosting | 1.000 | 0.333 | 0.500 | 0.735 | 0.625 | 0.000 | 0.667 |

The preselected Logistic Regression contrast is within the 0.02 exploratory engineering margin, so the simpler flat predictor is retained. The margin is not a significance test. Other model comparisons differ, and development runs varied; graph necessity or stable superiority is unverified. The relationship implementation uses explicit event/entity joins; this does not prove that storing a graph is necessary. Current model scores must not be presented as calibrated real-world phishing probabilities.

## Remaining completion gate and practical limits

Full domain/brand generalization requires independently labelled sanitized sessions with defensible domain, brand, template/kit and time groups, provenance and adequate class coverage. Creating additional aliases for the same authored fixture cannot supply that evidence. The current dataset's missing groups are an external evidence limitation, not a passing result.

Queues retain at most 2,000 content events per live document, 2,000 history/pending records per tab and 256 receipt streams per tab. Browser-session storage survives worker suspension but not browser shutdown. Unacknowledged content can be lost on document destruction. Identity is UNKNOWN, temporal proximity is INFERRED association, and payload transmission/server processing are unknown or not observable. Shadow DOM coverage, adversarial page interference, broad interception, long-duration load and production calibration remain outside the verified scope.

The minimum direct Python dependencies from the tested environment are captured in `requirements.txt`. The startup script uses `npm.cmd`, hidden helper processes and native exit codes; the stop script only stops matching tracked processes, not arbitrary port occupants. No commit or publication is part of this implementation run.
