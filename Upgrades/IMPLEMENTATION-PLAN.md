# Agentic Defense V2 Stage A Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a deterministic bounded browser-security agent control plane, durable sanitized delivery, open Shadow DOM coverage, and tab-scoped session containment while preserving the verified local-first/privacy properties of the current branch.

**Architecture:** Existing typed events and contextual assessment remain the evidence foundation. New pure `agent` modules normalize signals and make bounded deterministic state/action decisions; a separate enforcement executor performs browser actions and reports the actual outcome. OpenPhish is refactored behind a provider-neutral reputation boundary, while local durable storage persists only sanitized unsent events/reports across full browser shutdown.

**Tech Stack:** TypeScript 5.7, Chromium Manifest V3, `chrome.declarativeNetRequest`, `chrome.storage.session`, `chrome.storage.local`, Vitest 3, Playwright, Vite 6, existing FastAPI/PostgreSQL research backend.

**Spec:** `Upgrades/Stage-A-Agentic-Control-Plane/DESIGN.md`

## Global Constraints

- Immediate browser safety decisions remain local.
- Backend/Jev/LLM outputs cannot directly execute browser actions.
- Never collect raw password, OTP, CVV, card number, cookies, request bodies, authorization headers, tokens, or arbitrary page text.
- Unknown service identity alone is never malicious.
- Stable cross-origin SSO without contextual contradiction must remain allowed/monitored.
- An uncalibrated ML score alone cannot authorize autonomous blocking.
- Only pre-existing DNR rules may be described as true pre-request blocking.
- New unknown-page decisions that arrive after navigation begins must be described as containment, not pre-request blocking.
- All event/message/risk contracts remain closed and versioned.
- Production code stays outside `Upgrades/`.
- Existing verified tests must remain green.

## Review Focus

1. **Stale document race:** a high-risk result for a prior document must never contain the current document.
2. **Shared-host overblocking:** containment must scope to justified URL/origin and affected tab/document, never automatically broaden one URL to an unrelated tenant/domain.
3. **Privacy regression through durability:** persisted retry records must contain only already-sanitized typed events/reports and must reject arbitrary extra keys.
4. **Uncalibrated model escalation:** a high model score without independent corroboration must remain non-blocking.
5. **Browser restart replay:** pending events/reports must replay idempotently after shutdown without duplicate PostgreSQL records.

---

## Task 1: Agent types and deterministic state machine

**Files:**
- Create: `browser-extension/src/core/agent/types.ts`
- Create: `browser-extension/src/core/agent/state-machine.ts`
- Create: `tests/unit/agent-state-machine.test.ts`

**Interfaces:**
- Produces `AgentRiskState`, `AgentAction`, `AgentTransition`, `RiskSignalSet`, `RiskDecision`, `EnforcementOutcome`.
- Produces `transitionAgent(current, requested): AgentTransition`.

- [ ] **Step 1: Write failing transition tests**

Create `tests/unit/agent-state-machine.test.ts` with cases equivalent to:

```ts
import { describe, expect, it } from 'vitest';
import { transitionAgent } from '../../browser-extension/src/core/agent/state-machine';

describe('bounded agent state machine', () => {
  it('allows OBSERVING -> HIGH_RISK -> CONTAINED', () => {
    expect(transitionAgent('OBSERVING', 'HIGH_RISK').accepted).toBe(true);
    expect(transitionAgent('HIGH_RISK', 'CONTAINED').accepted).toBe(true);
  });

  it('rejects CONTAINED -> OBSERVING because release must be explicit', () => {
    expect(transitionAgent('CONTAINED', 'OBSERVING')).toMatchObject({
      accepted: false,
      from: 'CONTAINED',
      to: 'CONTAINED',
    });
  });

  it('allows every live state to end', () => {
    for (const state of ['OBSERVING','LOW_RISK','UNCERTAIN','SUSPICIOUS','HIGH_RISK','CONTAINED','USER_OVERRIDDEN'] as const) {
      expect(transitionAgent(state, 'ENDED').accepted).toBe(true);
    }
  });
});
```

- [ ] **Step 2: Verify RED**

Run:

```powershell
npm.cmd run test:unit -- tests/unit/agent-state-machine.test.ts
```

Expected: failure because the new agent modules do not exist.

- [ ] **Step 3: Implement closed agent types**

`types.ts` must define exact string unions:

```ts
export type AgentRiskState =
  | 'OBSERVING'
  | 'LOW_RISK'
  | 'UNCERTAIN'
  | 'SUSPICIOUS'
  | 'HIGH_RISK'
  | 'CONTAINED'
  | 'USER_OVERRIDDEN'
  | 'ENDED';

export type AgentAction =
  | 'ALLOW'
  | 'WARN'
  | 'CONFIRM'
  | 'SHIELD_SENSITIVE_ACTION'
  | 'CONTAIN_TAB'
  | 'ADD_SESSION_BLOCK'
  | 'REMOVE_SESSION_BLOCK'
  | 'REDIRECT_INTERSTITIAL'
  | 'RELEASE_CONTAINMENT';

export type EnforcementOutcome =
  | 'DECISION_ONLY'
  | 'WARNING_DISPLAYED'
  | 'SUBMIT_EVENT_CANCELLED'
  | 'SESSION_RULE_INSTALLED'
  | 'SESSION_RULE_REMOVED'
  | 'TAB_REDIRECTED_TO_INTERSTITIAL'
  | 'USER_CONFIRMED'
  | 'USER_OVERRIDE_APPLIED'
  | 'ENFORCEMENT_FAILED';
```

Also define the exact `RiskSignalSet` / `RiskDecision` contract from the design.

- [ ] **Step 4: Implement the transition table**

`state-machine.ts` must use a literal allowed-transition map, not free-form branching. An invalid transition returns the unchanged state and `accepted:false`.

- [ ] **Step 5: Verify GREEN**

Run the focused test, then:

```powershell
npm.cmd run typecheck
npm.cmd run test:unit
```

Expected: all current unit tests plus new state-machine tests pass.

- [ ] **Step 6: Commit**

```powershell
git add browser-extension/src/core/agent tests/unit/agent-state-machine.test.ts
git commit -m "feat(agent): add bounded security state machine"
```

---

## Task 2: Pure versioned risk fusion

**Files:**
- Create: `browser-extension/src/core/agent/risk-fusion.ts`
- Create: `tests/unit/risk-fusion.test.ts`
- Modify: `browser-extension/src/core/assessment.ts`

**Interfaces:**
- Consumes `RiskSignalSet`.
- Produces `fuseRiskSignals(signals: RiskSignalSet): RiskDecision`.
- Assessment produces normalized risk signals before producing the report.

- [ ] **Step 1: Write failing risk-fusion tests**

Required cases:

```ts
it('authorizes blocking for exact known-malicious reputation', () => {
  const decision = fuseRiskSignals(signals({
    reputation: { status: 'KNOWN_MALICIOUS', source: 'OpenPhish Community' },
  }));
  expect(decision).toMatchObject({
    state: 'HIGH_RISK',
    automaticBlockAuthorized: true,
  });
});

it('does not authorize blocking from an uncalibrated model alone', () => {
  const decision = fuseRiskSignals(signals({
    model: { score: 0.999, calibrated: false, modelId: 'controlled-event-lr-1', provenance: 'CONTROLLED' },
  }));
  expect(decision.automaticBlockAuthorized).toBe(false);
  expect(decision.action).not.toBe('CONTAIN_TAB');
});

it('allows stable unknown SSO without contradiction', () => {
  const decision = fuseRiskSignals(signals({
    identity: { status: 'UNKNOWN' },
    context: { contradictions: [], positiveEvidence: ['AUTHENTICATION_SEQUENCE_CONSISTENT','REPEATED_STABLE_SENSITIVE_TARGET'], completeness: 'SUFFICIENT' },
  }));
  expect(decision.state).toBe('LOW_RISK');
  expect(decision.action).toBe('ALLOW');
});

it('contains corroborated changed sensitive destination', () => {
  const decision = fuseRiskSignals(signals({
    context: { contradictions: ['INTERACTED_SENSITIVE_SUBMISSION_REDIRECTED'], positiveEvidence: [], completeness: 'SUFFICIENT' },
  }));
  expect(decision.state).toBe('HIGH_RISK');
  expect(decision.action).toBe('CONTAIN_TAB');
});
```

- [ ] **Step 2: Verify RED**

```powershell
npm.cmd run test:unit -- tests/unit/risk-fusion.test.ts
```

- [ ] **Step 3: Implement deterministic fusion**

Rules:

1. `KNOWN_MALICIOUS` reputation:
   - `HIGH_RISK`
   - `CONTAIN_TAB`
   - `automaticBlockAuthorized = true`.

2. `INTERACTED_SENSITIVE_SUBMISSION_REDIRECTED` with sufficient evidence:
   - `HIGH_RISK`
   - `CONTAIN_TAB`
   - automatic block may be authorized only for the directly evidenced destination, not the entire origin family.

3. Any other contradiction:
   - `SUSPICIOUS`
   - `WARN` or `CONFIRM` depending on sensitive-action context already represented by the assessment.

4. Incomplete/low completeness without independent known-malicious hit:
   - `UNCERTAIN`
   - no automatic blocking.

5. No contradiction, adequate completeness:
   - `LOW_RISK`
   - `ALLOW`.

6. Model score:
   - calibrated models may modify confidence/risk ordering in later versions;
   - current uncalibrated artifact may add reason codes only;
   - it never flips a contextually benign result into automatic blocking.

- [ ] **Step 4: Integrate into `assessment.ts`**

Preserve:
- contextual feature extraction;
- identity;
- destinations;
- model contributions;
- privacy unknowns.

Replace the final hand-coded `corroborated ? ...` decision block with a normalized `RiskSignalSet` + `fuseRiskSignals()` result. Existing report fields may remain for compatibility but must be derived from the new decision.

- [ ] **Step 5: Verify GREEN**

```powershell
npm.cmd run typecheck
npm.cmd run test:unit
```

- [ ] **Step 6: Commit**

```powershell
git add browser-extension/src/core/agent/risk-fusion.ts browser-extension/src/core/assessment.ts tests/unit/risk-fusion.test.ts
git commit -m "feat(agent): add deterministic risk fusion"
```

---

## Task 3: Provider-neutral reputation and tab-scoped containment

**Files:**
- Create: `browser-extension/src/core/reputation/types.ts`
- Create: `browser-extension/src/core/reputation/openphish.ts`
- Create: `browser-extension/src/core/enforcement/session-containment.ts`
- Create: `tests/unit/session-containment.test.ts`
- Modify: `browser-extension/src/core/enforcement.ts`
- Modify: `browser-extension/src/background/service-worker.ts`

**Interfaces:**
- `ReputationProvider.refresh(): Promise<ReputationSnapshot>`
- `ReputationProvider.lookup(url: string): Promise<ReputationResult>`
- `SessionContainment.install(input): Promise<EnforcementOutcome>`
- `SessionContainment.release(input): Promise<EnforcementOutcome>`

- [ ] **Step 1: Extract reputation tests without changing behavior**

Move `compilePhishingRules` and feed constants behind the OpenPhish provider while keeping existing exact URL behavior.

Write tests proving:
- query-bearing indicators remain excluded;
- malformed/wildcard/credential URLs remain excluded;
- exact case-sensitive behavior remains unchanged.

- [ ] **Step 2: Verify extraction tests fail before module creation**

Run focused unit test.

- [ ] **Step 3: Implement provider-neutral types and OpenPhish provider**

The provider must expose provenance and current status, but must not receive arbitrary browsing telemetry.

- [ ] **Step 4: Write failing containment lifecycle tests**

Mock only the Chrome DNR boundary and assert arguments:

```ts
it('installs a tab-scoped session rule for the evidenced destination', async () => {
  const outcome = await containment.install({
    tabId: 42,
    documentId: 'doc-1',
    destination: 'https://collector.test',
    expiresAt: 123456789,
  });
  expect(outcome).toBe('SESSION_RULE_INSTALLED');
  expect(updateSessionRules).toHaveBeenCalledWith(expect.objectContaining({
    addRules: [expect.objectContaining({
      condition: expect.objectContaining({ tabIds: [42] }),
    })],
  }));
});
```

Also test:
- unrelated tab not blocked;
- rule removal;
- document change cleanup;
- expiry cleanup;
- DNR failure returns `ENFORCEMENT_FAILED`;
- no domain broadening.

- [ ] **Step 5: Implement `session-containment.ts`**

Use a reserved session-rule ID range that cannot overlap static/OpenPhish rule IDs.

Store rule metadata in `chrome.storage.session` for lifecycle cleanup.

- [ ] **Step 6: Rewire `enforcement.ts`**

`enforcement.ts` becomes orchestration/export surface:
- legacy snapshot pipeline remains telemetry-only;
- OpenPhish provider is imported rather than implemented inline;
- session containment executor is exported separately.

- [ ] **Step 7: Verify**

```powershell
npm.cmd run typecheck
npm.cmd run test:unit
npm.cmd run build
```

- [ ] **Step 8: Commit**

```powershell
git add browser-extension/src/core/reputation browser-extension/src/core/enforcement browser-extension/src/core/enforcement.ts browser-extension/src/background/service-worker.ts tests/unit/session-containment.test.ts
git commit -m "feat(enforcement): add provider-neutral reputation and session containment"
```

---

## Task 4: Durable sanitized replay across browser shutdown

**Files:**
- Create: `browser-extension/src/core/storage/durable-queue.ts`
- Create: `tests/unit/durable-queue.test.ts`
- Modify: `browser-extension/src/core/tsfeg.ts`
- Modify: `browser-extension/src/background/typed-events.ts`

**Interfaces:**
- `createDurableQueue(storage, options)`
- `put(record)`
- `ack(key)`
- `listReady(now)`
- `purgeExpired(now)`
- `stats()`

- [ ] **Step 1: Write failing queue tests**

Required tests:
- accepts only a closed sanitized event/report envelope;
- rejects unknown keys and unsafe raw fields;
- enforces TTL;
- enforces byte/count bounds;
- survives reconstructed queue instance;
- same idempotency key does not duplicate;
- corrupted record is quarantined/dropped rather than parsed loosely.

- [ ] **Step 2: Verify RED**

```powershell
npm.cmd run test:unit -- tests/unit/durable-queue.test.ts
```

- [ ] **Step 3: Implement bounded durable queue**

Use `chrome.storage.local` through an injected storage interface to keep unit tests independent from Chrome.

Do not persist:
- arbitrary DOM snapshots;
- raw URLs containing query/fragment values;
- secrets;
- non-validated reports/events.

- [ ] **Step 4: Integrate in `typed-events.ts` background worker**

Before/while attempting backend delivery:
- keep immediate local recording in `storage.session`;
- mirror only sanitized pending delivery records into durable queue;
- remove durable record only after matching backend acknowledgement;
- replay ready records on worker startup and alarm;
- local analysis never waits for durable replay.

- [ ] **Step 5: Verify current retry semantics**

Existing lost-ack, pending, and PostgreSQL idempotency tests must remain green.

- [ ] **Step 6: Add browser restart integration test**

Use a persistent test profile path for this scenario, close Chromium, reopen it, and assert:
- sanitized pending item survives;
- backend receives it once;
- durable record is removed after acknowledgement.

- [ ] **Step 7: Verify**

```powershell
npm.cmd run typecheck
npm.cmd run test:unit
npm.cmd run test:integration
npm.cmd run test:browser
```

- [ ] **Step 8: Commit**

```powershell
git add browser-extension/src/core/storage browser-extension/src/core/tsfeg.ts browser-extension/src/background/typed-events.ts tests
git commit -m "feat(storage): persist sanitized delivery across browser restarts"
```

---

## Task 5: Open Shadow DOM structural coverage

**Files:**
- Modify: `browser-extension/src/content/typed-events.ts`
- Modify: `browser-extension/src/content/observer.ts`
- Create: `tests/unit/shadow-dom.test.ts`
- Modify: `tests/browser/dynamic-dom.spec.ts`

**Interfaces:**
- Add focused helpers such as:
  - `collectReachableRoots(doc): Array<Document | ShadowRoot>`
  - `queryAcrossOpenRoots(selector)`
  - observer root registration methods.

- [ ] **Step 1: Write failing unit test**

Create an element with an open shadow root containing a password input.

Assert:
- exactly one `FIELD_DISCOVERED`;
- category is `PASSWORD`;
- no value/text content is read;
- a closed root is not claimed as visible.

- [ ] **Step 2: Verify RED**

```powershell
npm.cmd run test:unit -- tests/unit/shadow-dom.test.ts
```

- [ ] **Step 3: Implement root traversal**

Traverse the normal document plus reachable open shadow roots.

Deduplicate roots and elements using `WeakSet`.

Never monkeypatch `attachShadow`.

- [ ] **Step 4: Extend observer**

Attach `MutationObserver` to:
- document;
- all currently reachable open shadow roots;
- newly discovered open roots after relevant host insertion.

`stop()` disconnects every observer.

- [ ] **Step 5: Add real Chromium regression**

In `dynamic-dom.spec.ts`, create an open shadow root after page load, insert a password/OTP field, and assert typed evidence records it.

- [ ] **Step 6: Verify privacy regressions**

Run throwing-value-getter tests and ensure no secret sentinel appears.

- [ ] **Step 7: Verify**

```powershell
npm.cmd run typecheck
npm.cmd run test:unit
npm.cmd run test:browser
```

- [ ] **Step 8: Commit**

```powershell
git add browser-extension/src/content tests/unit/shadow-dom.test.ts tests/browser/dynamic-dom.spec.ts
git commit -m "feat(collection): add open shadow DOM coverage"
```

---

## Task 6: Agent-controlled shield and enforcement orchestration

**Files:**
- Modify: `browser-extension/src/content/typed-events.ts`
- Modify: `browser-extension/src/background/typed-events.ts`
- Modify: `browser-extension/src/messaging/index.ts`
- Modify: `browser-extension/src/core/tab-state.ts`
- Modify: `tests/unit/typed-events.test.ts`
- Modify: `tests/unit/tab-state.test.ts`

**Interfaces:**
- Content script receives a closed message carrying one allowed action/state for the current document.
- Background stores current agent state per tab/document.
- Enforcement results are written back to the security report.

- [ ] **Step 1: Write failing message/action tests**

Required behaviors:
- stale/wrong document action rejected;
- `SHIELD_SENSITIVE_ACTION` requires confirmation at native sensitive submit;
- `ALLOW` releases shield;
- unknown action rejected;
- user confirmation recorded separately from decision;
- uncalibrated high model score alone never sends `CONTAIN_TAB`.

- [ ] **Step 2: Verify RED**

Run focused unit tests.

- [ ] **Step 3: Implement typed enforcement messaging**

Do not accept arbitrary strings or executable payloads.

- [ ] **Step 4: Integrate background state transitions**

In analysis:
1. build report/risk signals;
2. transition state;
3. verify current document ID;
4. execute only allowed action;
5. record real `EnforcementOutcome`;
6. persist/report asynchronously.

- [ ] **Step 5: Integrate session containment**

For `CONTAIN_TAB`:
- select only destinations justified by decision evidence;
- install tab-scoped session rule;
- optionally redirect to interstitial only if explicitly implemented/tested;
- do not infer that rule installation equals pre-request block for current first navigation.

- [ ] **Step 6: Navigation cleanup**

On new top-document commit:
- clear stale report;
- release stale document-specific containment;
- initialize new state as `OBSERVING`.

On tab close:
- release session rules;
- flush/replay state as appropriate;
- end state.

- [ ] **Step 7: Verify**

```powershell
npm.cmd run typecheck
npm.cmd run test:unit
npm.cmd run build
```

- [ ] **Step 8: Commit**

```powershell
git add browser-extension/src/background browser-extension/src/content browser-extension/src/core/tab-state.ts browser-extension/src/messaging tests/unit
git commit -m "feat(agent): orchestrate bounded browser enforcement"
```

---

## Task 7: Browser enforcement regressions and honest timing semantics

**Files:**
- Modify: `tests/browser/fixtures.ts`
- Modify: `tests/browser/data-collection.spec.ts`
- Modify: `tests/browser/dynamic-dom.spec.ts`
- Add or extend controlled scenario routes in `scripts/manual-browser-acceptance-server.mjs`
- Modify UI:
  - `browser-extension/src/ui/popup.ts`
  - `browser-extension/src/ui/popup.html`

**Interfaces:**
- Browser tests observe actual request receipts, DNR behavior, report state, and popup text.

- [ ] **Step 1: Add failing browser scenarios**

Required controlled scenarios:

1. Pre-existing OpenPhish fixture rule blocks navigation/request before server receipt.
2. Unknown high-risk scenario starts loading and is later contained; report does **not** say “blocked before load”.
3. Contained tab blocks a controlled cross-origin fetch to the evidenced destination.
4. Same destination from another tab remains allowed unless independently contained.
5. Unrelated destination in same tab remains allowed.
6. New navigation removes stale document containment.
7. Open shadow-root sensitive field is discovered.
8. Browser restart replays sanitized pending delivery without duplication.

- [ ] **Step 2: Run browser suite and observe failures**

```powershell
npm.cmd run build
npm.cmd run test:browser
```

Expected: newly added scenarios fail before production changes are complete.

- [ ] **Step 3: Update popup**

Render separate fields:

```text
Agent state
Decision
Enforcement outcome
Containment
Known-threat pre-request protection
Durable delivery backlog
```

Use exact language:
- `PRE-REQUEST RULE BLOCK` only for a rule already installed before the request.
- `EARLY NAVIGATION CONTAINMENT` for an unknown page contained after navigation began.
- `SUBMIT EVENT CANCELLED` for native submit prevention.

- [ ] **Step 4: Verify browser suite**

Run complete browser tests.

- [ ] **Step 5: Commit**

```powershell
git add browser-extension/src/ui tests/browser scripts/manual-browser-acceptance-server.mjs
git commit -m "test(browser): verify agent containment and timing semantics"
```

---

## Task 8: Full Stage A verification and upgrade records

**Files:**
- Create/update:
  - `Upgrades/Stage-A-Agentic-Control-Plane/CHANGELOG.md`
  - `Upgrades/Stage-A-Agentic-Control-Plane/TEST-RESULTS.md`
  - `Upgrades/Stage-A-Agentic-Control-Plane/MIGRATION-NOTES.md`
- Modify `CURRENT-STATUS.md` only after fresh verification.
- Modify README/docs only for claims actually proven by verification.

- [ ] **Step 1: Run complete verification**

```powershell
npm.cmd run typecheck
npm.cmd run build
npm.cmd run test:unit
npm.cmd run test:integration
python -m pytest tests/integration/test_event_contract.py -q
npm.cmd run test:browser
node scripts/verify-tsfeg.mjs
```

If any test fails, Stage A is not complete.

- [ ] **Step 2: Run privacy search on generated evidence**

Verify test/runtime output contains no injected secret sentinels.

- [ ] **Step 3: Record exact results**

`TEST-RESULTS.md` must include:
- command;
- date;
- exit code;
- test count;
- failures;
- Chromium version when browser tests run;
- known limitations.

Never copy old counts as if they were fresh.

- [ ] **Step 4: Record migration notes**

Document:
- new modules;
- state/action schema versions;
- DNR session rule ID range;
- durable storage keys and TTL;
- upgrade/rollback steps.

- [ ] **Step 5: Final commit**

```powershell
git add Upgrades CURRENT-STATUS.md README.md docs
git commit -m "docs(upgrade): record Agentic Defense V2 Stage A verification"
```

---

# Execution Order

```text
Task 1  Agent types/FSM
  ↓
Task 2  Risk fusion
  ↓
Task 3  Reputation + session containment
  ↓
Task 4  Durable sanitized replay
  ↓
Task 5  Open Shadow DOM
  ↓
Task 6  Agent enforcement orchestration
  ↓
Task 7  Browser regressions/UI semantics
  ↓
Task 8  Full verification/documentation
```

# Rollback Boundary

Each task ends in a separate commit. If a later task fails, reset/revert only that task's commit instead of discarding the earlier verified layers.

# Stage A Completion Definition

Do not call Stage A complete unless fresh evidence demonstrates all of the following:

- TypeScript typecheck passes.
- Extension build passes.
- Existing tests remain green.
- New agent/unit/integration/browser tests pass.
- Open Shadow DOM sensitive field discovery works.
- Full-browser-restart durable replay works without duplication.
- Exact known-malicious pre-existing rule blocks before request.
- Unknown high-risk page is described as post-start containment, not pre-request blocking.
- Tab-scoped DNR containment blocks the justified controlled destination.
- Another tab/unrelated destination is not accidentally blocked.
- Stale document decisions cannot execute against the current document.
- No raw sensitive value appears in telemetry/durable storage/database.
- Uncalibrated ML alone cannot authorize autonomous blocking.
