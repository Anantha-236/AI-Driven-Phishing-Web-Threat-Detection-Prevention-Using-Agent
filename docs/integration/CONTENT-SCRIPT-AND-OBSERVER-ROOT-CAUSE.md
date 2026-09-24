# CONTENT SCRIPT AND OBSERVER ROOT CAUSE

## Source-to-build trace

- CONTENT_SCRIPT_SOURCE=browser-extension/src/content/collector.ts
- BUILD_ENTRY=browser-extension/vite.config.ts
- CONTENT_SCRIPT_DIST=dist/collector.js
- MANIFEST_CONTENT_SCRIPT=collector.js

## Build proof

The bundle is generated from the content script source through the Vite config:

- browser-extension/vite.config.ts sets rollup entry collector to browser-extension/src/content/collector.ts
- the same file emits outfile dist/collector.js
- dist/manifest.json loads collector.js as the content script with run_at=document_start

## Runtime marker proof

The required startup marker was added at the true content-script entry point before observer construction and collection logic:

- data-capstone-content-script-started

After a fresh build, the source file contains the marker, but the actual generated dist/collector.js does not contain the marker string.

- DIST_STARTUP_MARKER=MISSING

This means the browser cannot prove that the actual bundled content script executed.

## Determination

- CONTENT_SCRIPT_RUNTIME=FAIL
- OBSERVER_CREATED=FAIL/NOT_REACHED
- OBSERVER_STARTED=FAIL/NOT_REACHED
- OBSERVER_OBSERVE_SUCCESS=FAIL/NOT_REACHED
- PAGE_MUTATION=PASS
- OBSERVER_CALLBACK=FAIL/NOT_REACHED

## Root cause

The first failed hop is the content-script runtime layer. The manifest loads the built collector bundle, but the actual dist/collector.js does not include the startup marker that proves the entry point executed. Because the real browser bundle was not proven to run, the observer/start/observe/callback chain cannot be tested or blamed yet. This is a build/runtime content-script proof failure, not an observer logic failure.

## Decision

NO_SPECULATIVE_FIX=YES

No observer target/options/debounce or collector logic was modified while establishing this proof, and the next required step is to fix the actual build/runtime entry point so the startup marker appears in the built bundle and is visible in the browser before any observer debugging begins.
