# ADR-001 — Chromium Manifest V3

## Status

ACCEPTED

## Decision

CAPSTONE-1 uses the Chromium Extension Manifest V3 architecture.

## Context

CAPSTONE-1 operates inside the browser and requires controlled access to:

- webpage DOM
- navigation context
- content-script execution
- service-worker processing
- browser security APIs
- extension UI

## Decision Rationale

Manifest V3 provides the browser extension architecture required for:

- content scripts
- background service workers
- controlled permissions
- browser messaging
- local processing
- policy/enforcement integration

## Architecture

```text
WEBPAGE
   ↓
CONTENT SCRIPT
   ↓
SERVICE WORKER
   ↓
LOCAL ANALYSIS
   ↓
ASSESSMENT
   ↓
POLICY
   ↓
USER / ENFORCEMENT
```

## Alternatives Considered

### Browser userscript

Rejected because it does not provide the same controlled extension architecture and lifecycle.

### Manifest V2

Rejected because the project targets the current Chromium extension architecture.

### Standalone desktop application

Rejected because detection must occur close to the browser event being analyzed.

## Consequences

### Positive

- native browser integration
- browser-visible evidence
- local processing
- extension-level policy control

### Negative

- browser API limitations
- service-worker lifecycle constraints
- permission/security complexity
- browser-version compatibility requirements

## Security Considerations

Extension permissions must remain minimal.

Content-script input is untrusted.

Sensitive user values must never be intentionally collected.

## Research Implication

The architecture is suitable for evaluating browser-local security evidence under realistic extension constraints.

## Status Boundary

This ADR records the architectural decision.

It does not claim that every planned browser capability is currently implemented or verified.