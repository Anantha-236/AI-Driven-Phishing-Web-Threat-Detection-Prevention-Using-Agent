# CAPSTONE-1 implementation blueprint

## Final-approach comparison and active implementation - 2026-09-18

The supplied final approach in `docs/MASTER-SPECIFICATION.md` is authoritative. All earlier dated stages below are historical. The official title is **AI-Driven Phishing (Web-Threat) Detection and Prevention Using Machine Learning**.

| Area | Inspected baseline | Current implementation direction / acceptance |
|---|---|---|
| Immediate decision | Backend ML endpoint, 1,500 ms fallback; legacy snapshot decision also published | Local contextual agent is the sole event decision owner; telemetry cannot overwrite it; outage/browser tests |
| Features | 14 flat counts plus 8 experimental relationships; no independent purpose category | Versioned contextual flat features, independently inferred static page-purpose category, explicit contradictions and positive evidence; shared training/runtime extraction |
| Sensitive workflows | Password/OTP shortcuts removed from compatibility verdict, but cross-origin alone forced confirmation | Stable cross-origin SSO/login remains monitor/allow absent contradictions; guard verifies changed effective destinations |
| Report | Risk/confidence mixed with count coverage; inconsistent benign/high result possible | Purpose uncertainty, positive evidence, contradictions and coverage are separate; bounded enum-only database schema |
| Training | 20-row prototype plus 24 authored loopback episodes; graph comparison was exploratory | Compare LR/RF/GB, partition fit/selection/calibration/test, preserve provenance and label authority, candidate exports and immutable hashes |
| Generalization | One loopback domain, no verified brand labels | Report unavailable tests explicitly; synthetic group isolation exercises code but cannot prove unseen real website accuracy |
| Model release | Historical controlled LR and separate five-feature toy ONNX | Preserve active historical model; new ONNX candidates need parity plus independent data/false-positive release gates |
| Research | Graph experiment prominent | Context/generalization first; graph remains secondary negative/neutral engineering result |
| Prevention | Controlled submit cancellation and DNR; limited interception coverage | Retain supported gates, separate detection/early detection/prevention; no universal prevention claim |

Acceptance records and training commands are maintained in `CURRENT-STATUS.md`. No automatic retraining from browsing/predictions. Missing validated real-world labels and independent cohorts are a data gate, not something extra synthetic rows resolve.


Active scope: attached implementation requirements, 2026-09-09. Preserve existing uncommitted work and historical Stage/evidence reports. No replacement application.

## September 11 scope update

User-selected implementation: ML, using the existing trained Logistic Regression export. The existing backend now owns the primary event assessment endpoint, feature reconstruction, evidence policy and report persistence. The existing extension calls that endpoint, applies top-document decisions and exposes explicit local fallback after backend failure or a 1,500 ms deadline. Existing Python and browser tests cover parity, policy, storage, privacy and outage integration. Earlier baseline classifications below are historical; current acceptance is tracked in CURRENT-STATUS.md. Broader detection accuracy remains unverified.

## Historical baseline and component classification

- VERIFIED: TypeScript checks, Vite build, 10 unit tests, 7 Python integration tests including PostgreSQL readback (this run).
- BROKEN: default Playwright suite assumes running servers and two tests use nonpersistent contexts; JavaScript integration startup exceeded its five-second timeout.
- IMPLEMENTED_NOT_VERIFIED in this run: continuous collector/observer, acknowledged typed recorder, browser document/frame correlation, graph/flat export, integrated Chromium-to-PostgreSQL path.
- PROTOTYPE: five-input ONNX model, snapshot-only assessment, heuristic confidence, static profiles, 20-row research dataset.
- BROKEN: policy outcomes claim prevention before enforcement; popup loses reasons and can display another tab's result.
- PLANNED: same-event research evaluation, trained event model deployment, evidence-linked contradictions, explainable persistent report, verified submission guard, broader privacy/false-positive/performance acceptance.

## Dependencies and exact implementation owners

| Order | Existing responsibility and required modification | Files | Acceptance |
|---|---|---|---|
| 0–1 | Reproduce baseline, repair runnable test setup, retain this blueprint | `playwright.config.ts`, `tests/browser/data-collection.spec.ts`, `tests/browser/dynamic-dom.spec.ts`, `tests/browser/debug-extension.spec.ts`, `tests/integration/backend-contracts.test.ts`, `scripts/verify-tsfeg.mjs` | Real persistent Chromium, managed loopback servers, exact collection/session readback; historical reports unchanged |
| 2–4 | Extend strict event vocabulary and existing observer/collector lifecycle | `browser-extension/src/core/tsfeg.ts`, `browser-extension/src/content/typed-events.ts`, `browser-extension/src/content/collector.ts`, `browser-extension/src/content/observer.ts`, `backend/events.py`, `tests/unit/typed-events.test.ts` | Dynamic discoveries, target changes, submission/lifecycle events; unknown fields rejected; no secret reads |
| 5–6 | Correlate canonical browser IDs, independent local analysis, bounded persistence and version metadata | `browser-extension/src/background/typed-events.ts`, `browser-extension/src/background/service-worker.ts`, `backend/main.py`, `backend/database.py`, `backend/schema.sql`, `tests/unit/tsfeg.test.ts`, `tests/integration/test_event_contract.py` | Suspension/outage recovery, idempotent matching evidence, explicit coverage loss |
| 7–9 | Deterministic flat and relationship features from identical events; controlled comparison | `browser-extension/src/core/tsfeg.ts`, `scripts/verify-tsfeg.mjs`, `scripts/manual-browser-acceptance-server.mjs`, `ml/evaluation/generalization_eval.py`, `docs/research/RQ1-GRAPH-VS-FLAT.md` | Frozen feature schema, shared event hashes, grouped holdouts; report ties/losses honestly |
| 10 | Evidence-supported contradictions and uncertainty | `browser-extension/src/core/assessment.ts`, `browser-extension/src/core/enforcement.ts`, `browser-extension/src/core/schema/types.ts` | Cross-origin alone does not imply malicious; supporting event references and unknowns retained |
| 11–13 | Provenance-labelled dataset; LR/RF/GB comparisons; selected local model | `ml/training/train_models.py`, `ml/evaluation/generalization_eval.py`, `ml/evaluation/split_generator.py`, `browser-extension/src/core/service-worker-onnx-adapter.ts`, `browser-extension/vite.config.ts` | Group/temporal split integrity, precision/recall/F1/PR-AUC/ROC-AUC/FPR/FNR, browser parity; controlled data does not establish real-world performance |
| 14–15 | Explainable report, honest policy status, supported submission guard | `browser-extension/src/core/tab-state.ts`, `browser-extension/src/core/policy.ts`, `browser-extension/src/content/collector.ts`, `browser-extension/src/ui/popup.ts`, `browser-extension/src/ui/popup.html`, `tests/unit/tab-state.test.ts` | Current tab/document only; actual warning/cancel receipt distinct from decision; backend primary decision with explicit local fallback |
| 16–19 | Controlled legitimate flows, canary privacy, performance, complete chain | Existing unit/integration/browser suites and manual scenario server | Typecheck/build/unit/integration/browser pass; exact evidence in PostgreSQL; measured latency; defined false-positive threshold |
| 20 | Align current documentation to evidence | `README.md`, `CURRENT-STATUS.md`, existing architecture/schema/privacy documents and this plan | No promotion of prototype, controlled results, or requested enforcement to stronger claims |

New files only where no owner exists: this requested blueprint; a shared browser fixture if required to load the extension consistently; dataset/model artifacts only for actual measured experiments. No per-stage Markdown reports.

## Research and completion gates

Controlled fixtures can verify mechanics and exploratory model comparisons. They cannot establish independently sourced REAL domain/brand generalization. Missing labels, independent provenance, or meaningful group coverage must be reported as unknown rather than synthesized into purported verification. No graph superiority or production readiness claim is authorized by implementation alone.

Completion requires the working extension-to-local-analysis-to-PostgreSQL chain plus the requested validation. Status below must be updated from tests actually run, not from code presence.

## Execution record

Current checkpoint, 2026-09-10:

- Stages 0-8: existing architecture inspected; baseline failures reproduced and repaired; strict 1.2.0 events, preserved collector/observer, acknowledged queues, shared browser session, canonical document/frame scopes, PostgreSQL events/reports and identical-stream representations implemented. Runtime checks verify the exercised static/dynamic/iframe/restart/outage paths. This is not a universal lifecycle guarantee.
- Stage 9: a 24-episode controlled engineering comparison ran. The full separate RQ1 pilot remains PLANNED. The final preselected LR relationship-minus-flat PR-AUC is +0.0071, within the 0.02 engineering margin; graph superiority is not established. Flat remains selected. Development traces varied, so this is not confirmatory evidence.
- Stages 10-15: evidence references, conservative assessment, controlled dataset/model comparison, portable local LR inference, checksum/parity checks, persistent explainable UI, warning/confirmation and supported form cancellation implemented. The old ONNX snapshot path remains separate. The model is PROTOTYPE, not calibrated for autonomous blocking.
- Stages 16-19: controlled legitimate cases, sentinel checks, backend outage, exact database readback, worker restart and 200-field burst measured. Validation passed typecheck, build, 16 unit, 2 JavaScript integration, 8 Python contract and the final consolidated 10 browser tests (53.4 seconds), including actual static DNR blocking. Standalone worker-restart proof passed with 49 pre-restart events. The exact bundled-model training dataset was preserved separately from subsequent browser collections, with matching SHA-256 verified.
- Stage 20: README/current status, master specification and existing architecture/schema/privacy documents aligned; historical Stage/M0/M1 reports unchanged.

Additional necessary new owner: root requirements.txt records the direct Python dependencies because no requirements/pyproject manifest existed. Existing startup/status/stop scripts were repaired for Windows command resolution, native warning handling, database health and matching tracked processes.

Final operational check: `start-capstone.ps1` completed its build and six browser verification tests and reported CAPSTONE-1 READY. `status-capstone.ps1` confirmed both tracked services running and healthy, including PostgreSQL health. Services were left running for local review. `git diff --check` found no whitespace errors. No commit or publication was performed.

**Outstanding research gate:** independent labelled sanitized sessions with meaningful domain and brand groups, template/kit provenance and time coverage. The current dataset has one loopback domain and no verified brand labels; split code reports UNAVAILABLE. More aliases of the same authored fixture cannot satisfy this gate. Full research completion, production calibration and broad adversarial/lifecycle coverage are not claimed.

## Eight-problem operational repair, 2026-09-10

Preserved prior work and upgraded existing owners. Inspection found a stopped backend/scenario server, healthy PostgreSQL, and Chrome Default-profile registration pointing at the old `Desktop/Capstone-1/dist` checkout. The repaired `Capstone-1-GitHub-Ready/dist` is extension 1.2.0. Windows-control initialization failed because the native pipe was unavailable, so the personal Chrome registration remains unchanged.

- `assessment.ts`, `service-profiles.ts`: isolate three sourced exact login origins from historical/example profiles; keep identity association and page safety separate; remove uncalibrated snapshot-score and unrelated-request warning triggers; include per-form origins, categories and evidence references.
- `typed-events.ts` in content: confirm initially unverified cross-origin targets and native submitter overrides before a supported submission; retain no-value-read privacy and explicit programmatic/early-handler limits.
- `enforcement.ts`, worker: independent OpenPhish Community exact-URL DNR refresh, bounded rules, invalid/query/credential indicator exclusions, unexpired fallback and expiry. No browsing URLs sent to feed provider. Controlled browser test caught missing main-frame resource coverage, which was fixed and retested with receiver-side counts.
- Worker recorder, popup and backend report schema: explicit last acknowledged event, health/backlog/loss status, retry, strict destination metadata and JSON report export. Queue durability across full browser shutdown remains outstanding.
- Startup now builds and starts services normally, with controlled browser tests available through `-Verify`; it prints the actual extension directory and does not imply a personal browser has loaded it.

Validation: 21 unit, 2 JavaScript integration, 8 Python contract and 13 Chromium tests passed; typecheck/build passed. Standalone restart proof again passed with 49 pre-restart events. Final v1.2 isolated browser downloaded 282 live feed rules with 18 excluded indicators and rendered a database-connected report; no live phishing page opened. Source/example source data never substitutes for independently labelled evaluation. Services were left healthy. README, master specification and current status describe the repair and the outstanding limits. No commit or publication performed.
