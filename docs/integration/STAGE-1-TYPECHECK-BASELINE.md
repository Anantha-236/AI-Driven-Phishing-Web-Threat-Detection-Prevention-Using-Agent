# STAGE 1 TYPECHECK BASELINE

TYPECHECK_ERROR=TS2367 in browser-extension/src/content/observer.ts:40:24: comparison appears to be unintentional because the types HTMLElement and Document have no overlap.

ROOT_CAUSE=The existing fallback expression was inferred as HTMLElement, while the code compared it with the Document instance. The comparison was rejected by strict TypeScript DOM typing even though MutationObserver.observe accepts a Node target.

MINIMAL_FIX=Declared the existing target expression as Node: `const targetNode: Node = this.doc.body || this.doc.documentElement || this.doc;`. No observer target, callback, collection, lifecycle, or privacy behavior was changed.

TYPECHECK=PASS
BUILD=PASS
UNIT_REGRESSION=PASS
UNRELATED_FILES_CHANGED=NO

## Verification evidence

- `npm.cmd run typecheck` passed with exit code 0.
- `npm.cmd run build` passed with exit code 0.
- `npm.cmd run test:unit` passed: 1 test file and 2 tests.
- The Stage 1 edit is one type annotation in browser-extension/src/content/observer.ts.
- The working tree contains other pre-existing modified and untracked files; they were not changed as part of this Stage 1 fix.
- No browser E2E, backend, database, ML, schema, or feature-development work was performed.

NEXT_STAGE=STAGE 2 - REAL BROWSER -> FASTAPI -> POSTGRESQL PERSISTENCE
