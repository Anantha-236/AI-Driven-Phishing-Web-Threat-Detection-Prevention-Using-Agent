# CAPSTONE-1 Agentic Defense V2 — Stage A Design

**Date:** 2026-09-24  
**Baseline:** `baseline/current-local-state` at commit `fca862ac5382a1dec6c9f7f28e14086bfbcfb598`  
**Status:** Design for review — implementation has not started.

## 1. Purpose

Stage A upgrades the existing CAPSTONE-1 browser-security prototype into a safer, explicit, bounded agent control plane without replacing working subsystems already present in the baseline.

The baseline already provides:

- Chromium Manifest V3 extension.
- Typed privacy-safe browser events.
- Per-tab/document/frame correlation.
- Local contextual assessment.
- Flat and relationship evidence representations.
- Local Logistic Regression event-model execution.
- PostgreSQL research persistence.
- OpenPhish exact-URL DNR protection.
- Native form-submit confirmation/cancellation.
- Browser/unit/integration tests.
- Local-first decision ownership.
- Backend-independent immediate browser assessment.

Stage A therefore does **not** rebuild these components. It addresses the highest-value gaps that remain in the current baseline:

1. no explicit bounded agent state machine;
2. browser-shutdown loss of pending sanitized events/reports;
3. incomplete open Shadow DOM coverage;
4. high-risk decisions do not yet produce tab-scoped network containment;
5. current action vocabulary is too small (`ALLOW/WARN/CONFIRM`);
6. enforcement outcome and security decision are not modeled as separate state transitions;
7. model/reputation/context signals do not yet enter a versioned fusion contract;
8. initial navigation of an unknown URL cannot truthfully be called “blocked before load” under MV3.

## 2. Safety and Research Principles

The following are non-negotiable.

### 2.1 Privacy boundary

The extension may collect structural/security metadata such as:

- origins;
- form destinations;
- input categories;
- page-purpose categories;
- frame relationships;
- request destination origins;
- browser navigation metadata;
- event ordering.

It must never collect:

- passwords;
- OTPs;
- CVVs;
- card numbers;
- raw typed values;
- cookies;
- request bodies;
- authorization headers;
- authentication/session tokens;
- arbitrary page text.

All new event and state schemas remain closed/typed. Unknown keys are rejected.

### 2.2 Local decision ownership

The local browser agent owns immediate safety decisions.

Backend services, future Jev integration, semantic models, and external intelligence may return **evidence or advisory assessments**. They may not directly execute browser actions.

### 2.3 Bounded autonomy

The agent may choose only from an explicit action vocabulary. It cannot execute arbitrary JavaScript, generate browser commands, or invent new tools.

### 2.4 Evidence before automatic blocking

Model score alone is not sufficient to authorize destructive/high-impact actions until the model is independently validated and calibrated.

Known threat-intelligence matches and directly corroborated browser evidence can have stronger authority because their provenance is explicit.

## 3. Stage A Architecture

```text
                 Navigation / DOM / Request Sensors
                              |
                              v
                    Sanitized Typed Events
                              |
                              v
                    Evidence State Builder
                              |
           +------------------+------------------+
           |                  |                  |
           v                  v                  v
   Reputation Signal    Context Engine      Local ML Signal
           |                  |                  |
           +------------------+------------------+
                              |
                              v
                    Versioned Risk Fusion
                              |
                              v
                  Bounded Agent State Machine
                              |
          +---------+---------+----------+---------+
          |         |         |          |         |
          v         v         v          v         v
        ALLOW     WARN     CONFIRM     SHIELD   CONTAIN
                                                    |
                                                    v
                                          Tab-scoped DNR rules
                                                    |
                                                    v
                                               RE-OBSERVE
```

Stage A does not add a cloud-critical path.

## 4. Agent State Machine

Create an explicit state machine separate from the classifier.

### States

```text
OBSERVING
LOW_RISK
UNCERTAIN
SUSPICIOUS
HIGH_RISK
CONTAINED
USER_OVERRIDDEN
ENDED
```

### Allowed transitions

- `OBSERVING -> LOW_RISK`
- `OBSERVING -> UNCERTAIN`
- `OBSERVING -> SUSPICIOUS`
- `OBSERVING -> HIGH_RISK`
- `LOW_RISK -> UNCERTAIN | SUSPICIOUS | HIGH_RISK`
- `UNCERTAIN -> LOW_RISK | SUSPICIOUS | HIGH_RISK`
- `SUSPICIOUS -> LOW_RISK | HIGH_RISK | CONTAINED`
- `HIGH_RISK -> CONTAINED`
- `CONTAINED -> USER_OVERRIDDEN | LOW_RISK | ENDED`
- any live state -> `ENDED`

The transition engine must be deterministic for the same ordered evidence and model/reputation inputs.

### Action vocabulary

```text
ALLOW
WARN
CONFIRM
SHIELD_SENSITIVE_ACTION
CONTAIN_TAB
ADD_SESSION_BLOCK
REMOVE_SESSION_BLOCK
REDIRECT_INTERSTITIAL
RELEASE_CONTAINMENT
```

Not every state transition requires an action.

### Action authority

| Signal | Authority |
|---|---|
| OpenPhish/external exact known-malicious URL hit | May block via DNR |
| Direct same-form sensitive destination replacement after interaction | May shield/confirm and contain |
| HTTPS downgrade for sensitive submission | May shield/confirm |
| Possible brand impersonation + sensitive workflow | Warn/confirm; no automatic origin-wide block by itself |
| Uncalibrated ML score alone | Advisory only |
| Jev/LLM advisory alone | Advisory only |
| Unknown identity alone | No negative action |
| Stable cross-origin SSO without contradiction | Allow/monitor |

## 5. Versioned Risk-Fusion Contract

Introduce a typed `RiskSignalSet` and `RiskDecision`.

### RiskSignalSet

The fusion layer consumes only normalized signals:

```ts
interface RiskSignalSet {
  schemaVersion: "risk-signals-1";
  documentId: string | null;
  eventSeq: number;

  reputation: {
    status: "KNOWN_MALICIOUS" | "NO_MATCH" | "UNAVAILABLE";
    source: string | null;
  };

  identity: {
    status: "KNOWN_LOGIN_ORIGIN" | "POSSIBLE_IMPERSONATION" | "UNKNOWN";
  };

  context: {
    contradictions: string[];
    positiveEvidence: string[];
    completeness: "SUFFICIENT" | "MEDIUM" | "LOW";
  };

  model: {
    score: number | null;
    calibrated: boolean;
    modelId: string | null;
    provenance: string;
  };

  collection: {
    incomplete: boolean;
    droppedEvents: number;
  };
}
```

### RiskDecision

```ts
interface RiskDecision {
  schemaVersion: "risk-decision-1";
  state: AgentRiskState;
  action: AgentAction;
  reasons: string[];
  automaticBlockAuthorized: boolean;
}
```

The fusion layer must not read DOM objects or call Chrome APIs. It is pure and unit-testable.

## 6. Enforcement Executor

The executor is separate from decision logic.

### Responsibilities

- apply warning/UI state;
- enable/disable content-script sensitive-action shield;
- add/remove tab-scoped `declarativeNetRequest` session rules;
- optionally redirect the tab to an extension interstitial for high-confidence containment;
- report the actual enforcement outcome;
- never claim an action occurred unless the relevant API/receiver acknowledges it.

### New outcome vocabulary

```text
DECISION_ONLY
WARNING_DISPLAYED
SUBMIT_EVENT_CANCELLED
SESSION_RULE_INSTALLED
SESSION_RULE_REMOVED
TAB_REDIRECTED_TO_INTERSTITIAL
USER_CONFIRMED
USER_OVERRIDE_APPLIED
ENFORCEMENT_FAILED
```

Decision and outcome remain distinct.

## 7. MV3 Navigation Semantics

The implementation must use accurate terminology.

### Truly pre-request blocking

Only a rule already present in DNR before the request can reliably block the initial request.

Examples:

- static known-malicious rules;
- previously installed dynamic/session rules;
- cached threat-intelligence rules.

### Navigation-start analysis

`webNavigation.onBeforeNavigate` can start local scoring early, but an asynchronous ML decision must **not** be described as guaranteed “blocked before load” for the first unknown navigation.

If a high-risk result arrives after request start, the system may:

1. install a tab-scoped session rule for subsequent matching requests;
2. redirect the tab to an extension interstitial;
3. mark the result as `EARLY_NAVIGATION_CONTAINMENT`, not pre-request blocking.

This distinction is mandatory in UI, reports, tests, and the paper.

## 8. Tab-Scoped Network Containment

Use `chrome.declarativeNetRequest.updateSessionRules()` for short-lived containment rules.

### Rule properties

- reserved ID range separate from OpenPhish dynamic rules;
- tied to the affected `tabId` where supported;
- limited to explicit malicious/high-risk destination origin/URL evidence;
- short TTL managed by agent state;
- automatically removed on:
  - tab close;
  - document change;
  - user-approved release;
  - TTL expiry.

Do not convert one suspicious shared-host URL into a domain-wide permanent block.

### Resource coverage

For a contained page, block only the destination(s) justified by evidence across relevant resource types such as:

- `main_frame`;
- `sub_frame`;
- `xmlhttprequest`;
- `script`;
- `ping`;
- `websocket`;
- other supported request types when required.

Same-origin server-side forwarding remains outside browser observability.

## 9. Durable Sanitized Delivery

The current `chrome.storage.session` queue does not survive full browser shutdown.

Stage A introduces two storage layers:

### Ephemeral state

Continue using `chrome.storage.session` for:

- current tab state;
- current report;
- current document identity;
- agent state;
- temporary receipts.

### Durable pending-delivery store

Use bounded `chrome.storage.local` only for sanitized unsent data:

```text
durable-events:<session/tab/document>
durable-report:<session/tab/document>
```

Requirements:

- maximum count/bytes;
- TTL;
- no secrets/raw values;
- idempotency key;
- replay-safe acknowledgements;
- purge after successful backend acknowledgement;
- purge expired records;
- migration/version field;
- corruption handling.

The local-first safety decision must continue even if durable storage fails.

## 10. Open Shadow DOM Coverage

Current collection misses fields inside open shadow roots.

Stage A adds recursive structural scanning for:

- `Document`;
- ordinary DOM;
- every reachable **open** `ShadowRoot`.

Mutation observation must attach to discovered open roots and attach to new open roots discovered later.

Constraints:

- do not read input values;
- do not export shadow text;
- preserve existing field/form structural categories;
- closed shadow roots remain a documented limitation;
- no claim of universal closed-root visibility.

## 11. Sensitive-Action Shield

The current submit listener protects native submit events but does not universally cover:

- direct `HTMLFormElement.prototype.submit.call(form)`;
- arbitrary `fetch`;
- arbitrary XHR;
- server-side forwarding.

Stage A will not claim universal interception.

Instead:

1. keep the synchronous native submit guard;
2. add agent-controlled shielding of sensitive UI when state is `HIGH_RISK` or `CONTAINED`;
3. add session DNR containment for justified external destinations;
4. preserve a documented limitation for same-origin or unobserved programmatic exfiltration.

A page-world monkeypatch of `fetch`/XHR is **not** the primary security boundary because hostile page code can race, replace, or bypass it.

## 12. Reputation Layer

Keep the existing OpenPhish DNR feed implementation as Tier 0.

Refactor it behind a provider-neutral interface:

```ts
interface ReputationProvider {
  id: string;
  refresh(): Promise<ReputationSnapshot>;
  lookup(url: string): Promise<ReputationResult>;
}
```

Initial provider remains OpenPhish.

Stage A adds:

- provider-neutral types;
- exact-match lookup state;
- provenance in `RiskSignalSet`;
- no extra live provider dependency required for immediate local operation.

Future providers (Safe Browsing-style hash prefix, PhishTank, URLhaus where applicable) plug into this interface in later stages.

## 13. Model Boundary

Stage A does **not** replace the contextual model yet.

The existing contextual LR remains advisory because:

- training data is controlled/small;
- independent brand/domain generalization is not established;
- calibration is not established.

The model adapter must expose:

```text
model id
feature version
artifact hash
provenance
calibrated flag
score
```

A future calibrated model can gain additional policy authority only through an explicit policy-version change and tests.

## 14. Jev / Generative Decision Support

Jev or any LLM-like model is excluded from the Stage A critical path.

Later integration must use an adapter such as:

```ts
interface AdvisoryDecisionProvider {
  assess(input: SanitizedAdvisoryContext): Promise<AdvisoryDecision>;
}
```

Rules:

- sanitized typed context only;
- no raw page HTML/text;
- no password/OTP/card values;
- strict timeout;
- shadow-mode first;
- result cannot directly call enforcement APIs;
- disagreement with local policy is logged for research, not silently adopted.

This preserves determinism and prevents prompt-injection-driven browser control.

## 15. Error Handling

### Model unavailable

Continue contextual evidence assessment without model score.

### Reputation unavailable

Use local contextual assessment; do not downgrade a known active containment merely because refresh failed.

### Storage failure

Continue local decision/enforcement; expose degraded persistence state.

### DNR rule failure

Return `ENFORCEMENT_FAILED`; keep warning/shield active.

### Stale document response

Reject it. Existing document-ID checks remain mandatory.

### Incomplete evidence

Risk may remain `UNCERTAIN`; automatic blocking authority is reduced unless an independent known-malicious reputation hit exists.

## 16. Testing Requirements

Stage A must be test-driven.

### Unit tests

Add tests for:

- every valid and invalid state transition;
- risk-fusion monotonicity;
- model-alone cannot authorize block when uncalibrated;
- reputation known-malicious can authorize block;
- stable unknown SSO remains allowed;
- shadow-root structural discovery;
- closed-root limitation is not falsely reported as covered;
- durable queue serialization/TTL/corruption/idempotency;
- session-rule lifecycle;
- outcome differs from decision until enforcement acknowledgement.

### Integration tests

Add tests for:

- browser restart durable replay;
- storage failure fallback;
- DNR session-rule install/remove;
- stale document response rejection;
- report persistence after containment.

### Browser tests

Controlled pages only:

1. exact threat-intelligence URL blocked by pre-existing DNR rule;
2. unknown high-risk page loaded then contained/interstitialed without claiming pre-request block;
3. open-shadow-root password field discovered;
4. native submit cancelled in contained state;
5. cross-origin fetch to contained destination blocked by session DNR;
6. unrelated destination remains permitted;
7. user override removes only the tab/document-scoped containment;
8. new navigation removes stale containment and stale report;
9. full browser shutdown/reopen replays sanitized pending delivery without duplication.

## 17. Files Expected to Change in Stage A

Existing files likely modified:

- `browser-extension/src/core/tsfeg.ts`
- `browser-extension/src/core/assessment.ts`
- `browser-extension/src/core/enforcement.ts`
- `browser-extension/src/background/typed-events.ts`
- `browser-extension/src/content/typed-events.ts`
- `browser-extension/src/core/tab-state.ts`
- `browser-extension/src/core/schema/types.ts`
- `browser-extension/src/messaging/index.ts`
- `browser-extension/src/ui/popup.ts`
- `browser-extension/src/ui/popup.html`
- `tests/unit/tsfeg.test.ts`
- `tests/unit/typed-events.test.ts`
- `tests/browser/data-collection.spec.ts`
- related browser fixtures/integration tests.

New focused modules expected:

- `browser-extension/src/core/agent/state-machine.ts`
- `browser-extension/src/core/agent/risk-fusion.ts`
- `browser-extension/src/core/agent/types.ts`
- `browser-extension/src/core/enforcement/session-containment.ts`
- `browser-extension/src/core/storage/durable-queue.ts`
- `browser-extension/src/core/reputation/types.ts`
- `browser-extension/src/core/reputation/openphish.ts`

Exact file decomposition may be adjusted during implementation planning if existing file boundaries require it.

## 18. Stage A Success Criteria

Stage A is complete only when fresh verification demonstrates:

1. typecheck passes;
2. extension build passes;
3. all pre-existing tests pass;
4. all new unit/integration/browser tests pass;
5. full-browser-restart durable replay works;
6. open shadow-root sensitive field discovery works;
7. a known malicious pre-existing DNR rule blocks before request;
8. an unknown high-risk page is accurately labeled as post-start containment, not pre-request blocking;
9. tab-scoped DNR containment blocks a controlled cross-origin exfiltration request;
10. removal/override does not leak containment into other tabs/documents;
11. no raw sensitive value appears in telemetry/storage/database;
12. uncalibrated ML alone cannot authorize autonomous blocking.

## 19. What Stage A Deliberately Does Not Solve

Deferred to later V2 stages:

- independent large-scale real-world dataset acquisition;
- model calibration on sufficient independent data;
- LightGBM/XGBoost/CatBoost comparison;
- compact semantic transformer;
- WebGPU/WebNN semantic/vision inference;
- visual brand recognition;
- QR-phishing vision path;
- cloaking/anti-bot active exploration;
- Safe-Browsing-style hash-prefix backend;
- Jev production integration;
- automatic blocking based solely on learned model probability;
- closed shadow-root universal visibility;
- full same-origin/server-side exfiltration prevention;
- OS/network-wide protection.

## 20. Follow-on V2 Stages

After Stage A:

### Stage B — Independent Data and Calibration
Real phishing + hard legitimate data, provenance, domain/brand/time splits, calibration, FPR-targeted thresholding.

### Stage C — Fast URL / Reputation Cascade
Ultra-light navigation-start URL classifier, expanded provider-neutral reputation, cache/early-exit design.

### Stage D — Advanced Context and Identity
Broader identity registry, Unicode/IDN confusables, redirect-chain reasoning, OAuth/AiTM research signals.

### Stage E — Semantic / Visual Escalation
Compact semantic model and optional visual phishing model, benchmarked before adoption.

### Stage F — Jev / Alternative Agent Research
Shadow-mode typed advisory decision comparison against deterministic fusion/state machine.

---

## Design decision

The project will use **hybrid deterministic + ML bounded autonomy**:

- deterministic browser safety constraints and action permissions;
- local ML as one evidence source;
- reputation as an independent high-authority source for known threats;
- contextual contradictions and positive evidence;
- explicit agent state transitions;
- deterministic enforcement executor;
- optional advanced models only as advisory/escalation layers until independently validated.

This is preferred over an unrestricted LLM/Jev controller because it provides lower latency, offline operation, reproducibility, privacy, and a smaller prompt-injection/action-abuse surface while still permitting advanced AI research as a separate evidence source.
