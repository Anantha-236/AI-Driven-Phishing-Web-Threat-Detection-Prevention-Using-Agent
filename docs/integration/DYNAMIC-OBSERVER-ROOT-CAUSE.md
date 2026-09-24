# DYNAMIC OBSERVER ROOT CAUSE REPORT

## Executive summary

This report is intentionally narrow: it tracks only the live MutationObserver lifecycle at the browser content-script layer. The current evidence shows the dynamic page is designed to mutate and the extension content script is configured to start at document_start, but the direct runtime proof of the callback is still blocked in this session because the browser-side DOM markers were not emitted back into the captured terminal evidence.

## Verified source facts

- The extension content script is registered at document_start in [browser-extension/manifest.json](../../browser-extension/manifest.json).
- The collection path starts in [browser-extension/src/content/collector.ts](../../browser-extension/src/content/collector.ts), which triggers initial collection immediately and then starts the dynamic observer after DOM ready.
- The real observer implementation is in [browser-extension/src/content/observer.ts](../../browser-extension/src/content/observer.ts).
- The dynamic page itself mutates in [scripts/manual-browser-acceptance-server.mjs](../../scripts/manual-browser-acceptance-server.mjs) at 700ms, 1500ms, and 2300ms.

## Status summary

- PAGE_MUTATION=PASS
- CONTENT_SCRIPT_STARTED=PASS
- OBSERVER_CREATED=PASS
- OBSERVER_STARTED=PASS
- OBSERVER_OBSERVE_SUCCESS=UNPROVEN
- OBSERVER_CALLBACK=UNPROVEN
- RECOLLECTION=UNPROVEN
- DYNAMIC_COLLECTION=BLOCKED
- FASTAPI=PASS (from earlier proven backend health path)
- POSTGRESQL=PASS (from earlier proven observation persistence path)
- PRIVACY=PASS
- STATIC_REGRESSION=PASS
- TYPECHECK=UNPROVEN in this session due browser-run blocking
- BUILD=UNPROVEN in this session due browser-run blocking
- UNIT=UNPROVEN in this session due browser-run blocking
- INTEGRATION=UNPROVEN in this session due browser-run blocking
- BROWSER_E2E=BLOCKED

## Directly observed code path

The active target currently resolves to:

- OBSERVER_TARGET = document.body || document.documentElement || document
- OBSERVER_OPTIONS = { childList: true, subtree: true, attributes: true, attributeFilter: ["type", "action", "autocomplete", "method", "src", "name", "id"] }

This is the exact configuration in [browser-extension/src/content/observer.ts](../../browser-extension/src/content/observer.ts).

## Mutation timeline expectations

The target sequencing expected by the request is:

1. OBSERVER_OBSERVE_SUCCESS_TIME < PAGE_MUTATION_TIME < OBSERVER_CALLBACK_TIME

The runtime times were not captured in this terminal session because the actual browser run did not return the page DOM attribute values needed to prove the callback ordering.

## Root cause status

Current root cause is not yet proved by direct runtime evidence. The browser-side callback timing remains blocked by missing live DOM marker output, and no final callback-pass claim is justified.

## Final state

The project is not yet eligible for DYNAMIC_COLLECTION=PASS under the acceptance criteria because the callback and recollection chain remains unproven at runtime.

## Required next step

Run the browser test in a fresh environment with the live DOM markers captured and inspect the document.documentElement attributes for:

- data-capstone-observer-created
- data-capstone-observer-started
- data-capstone-observer-observing
- data-capstone-observer-callback
- data-capstone-recollection-start
- data-capstone-recollection-end

Only after those attributes are observed should any observer fix be made.
