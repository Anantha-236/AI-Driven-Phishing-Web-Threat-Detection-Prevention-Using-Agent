# Stage A Replacement Manifest

**Branch:** `upgrade/agentic-defense-v2`  
**Baseline:** `fca862ac5382a1dec6c9f7f28e14086bfbcfb598`  
**Purpose:** Exact file map for Agentic Defense V2 Stage A.

## New production modules

These files will be added:

1. `browser-extension/src/core/agent/types.ts`
   - Typed agent states, actions, risk-signal contract, risk decision, enforcement outcome.

2. `browser-extension/src/core/agent/state-machine.ts`
   - Deterministic allowed transitions and transition validation.

3. `browser-extension/src/core/agent/risk-fusion.ts`
   - Pure risk-fusion logic. No Chrome APIs and no DOM access.

4. `browser-extension/src/core/enforcement/session-containment.ts`
   - Tab/document-scoped `declarativeNetRequest` session rules with TTL and removal.

5. `browser-extension/src/core/storage/durable-queue.ts`
   - Bounded sanitized pending-delivery persistence using `chrome.storage.local`.

6. `browser-extension/src/core/reputation/types.ts`
   - Provider-neutral reputation interfaces.

7. `browser-extension/src/core/reputation/openphish.ts`
   - OpenPhish provider implementation extracted from the existing enforcement module.

## Existing production files to replace/update

1. `browser-extension/src/core/assessment.ts`
   - Preserve contextual analysis.
   - Produce normalized `RiskSignalSet`.
   - Route the final decision through `risk-fusion.ts`.
   - Preserve evidence/reason reporting.

2. `browser-extension/src/core/enforcement.ts`
   - Remove direct OpenPhish implementation after extraction.
   - Keep legacy snapshot pipeline as telemetry-only.
   - Export enforcement executor and provider-neutral protection wiring.

3. `browser-extension/src/background/typed-events.ts`
   - Integrate agent state and enforcement executor.
   - Add durable replay.
   - Add containment lifecycle on navigation/tab close.
   - Keep document-ID stale-response checks.
   - Keep backend persistence non-authoritative.

4. `browser-extension/src/content/typed-events.ts`
   - Accept richer agent actions.
   - Add sensitive-action shield state.
   - Preserve native submit-time synchronous guard.
   - Never read field values.

5. `browser-extension/src/content/observer.ts`
   - Observe reachable open ShadowRoots.
   - Discover new open ShadowRoots.
   - Preserve current relevant-mutation filtering.

6. `browser-extension/src/core/tsfeg.ts`
   - Add durable-storage-friendly serialization helpers if required.
   - Preserve closed event schema and privacy validation.
   - Preserve existing graph/flat behavior.

7. `browser-extension/src/core/tab-state.ts`
   - Upgrade simple decision store into document-aware agent/enforcement state helpers or deprecate in favor of agent state types while preserving public behavior used by tests.

8. `browser-extension/src/ui/popup.ts`
   - Render agent state separately from decision and enforcement outcome.
   - Show containment status, durable backlog, and accurate MV3 timing terminology.

9. `browser-extension/src/ui/popup.html`
   - Add agent-state/containment sections without changing core security semantics.

10. `browser-extension/src/messaging/index.ts`
    - Add closed typed message contracts for enforcement state/override if needed.

11. `browser-extension/manifest.json`
    - Version bump only if required by the implementation.
    - No new permissions unless a test demonstrates necessity.

## Tests to add/replace

New unit tests:

- `tests/unit/agent-state-machine.test.ts`
- `tests/unit/risk-fusion.test.ts`
- `tests/unit/session-containment.test.ts`
- `tests/unit/durable-queue.test.ts`
- `tests/unit/shadow-dom.test.ts`

Existing test files extended:

- `tests/unit/tsfeg.test.ts`
- `tests/unit/typed-events.test.ts`
- `tests/browser/data-collection.spec.ts`
- `tests/browser/dynamic-dom.spec.ts`
- `tests/browser/fixtures.ts`
- integration tests as required for durable report/event replay.

## Upgrade artifacts

All engineering records for this stage live under:

`Upgrades/Stage-A-Agentic-Control-Plane/`

Files:
- `DESIGN.md`
- `IMPLEMENTATION-PLAN.md`
- `REPLACEMENT-MANIFEST.md`
- `CHANGELOG.md` (created during implementation)
- `TEST-RESULTS.md` (created only from fresh verification)
- `MIGRATION-NOTES.md` (created during implementation)

## Files deliberately NOT replaced in Stage A

- `backend/main.py` — browser-local decision ownership remains authoritative.
- `backend/events.py` — no new backend decision engine in Stage A.
- `backend/database.py` — only touched if durable replay introduces a proven schema requirement.
- `ml/training/*` — real dataset/model-calibration work belongs to Stage B.
- `browser-extension/assets/event-model.json` — current contextual model remains advisory in Stage A.
- legacy `model.onnx` — remains compatibility telemetry until a later model migration.

## Replacement policy

Do not bulk-delete the current project. Apply only the files listed above.

Production code stays in normal project directories. `Upgrades/` stores only design, plan, migration, and verification records.
