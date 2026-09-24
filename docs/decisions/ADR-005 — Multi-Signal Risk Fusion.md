# ADR-005 — Multi-Signal Risk Fusion

## Status

ACCEPTED

## Decision

CAPSTONE-1 does not treat any single signal as sufficient proof of maliciousness.

Risk assessment combines independent evidence sources.

## Signals

Potential signal groups:

```text
URL
DOMAIN
PAGE / DOM
FORM
SENSITIVE-DATA REQUEST
IDENTITY
BEHAVIOR
DESTINATION
NETWORK
ML
```

## Concept

```text
URL SIGNAL
     +
DOM SIGNAL
     +
DATA REQUEST
     +
IDENTITY
     +
BEHAVIOR
     +
DESTINATION
     +
DOMAIN CONTEXT
     +
ML
       ↓
EVIDENCE CORRELATION
       ↓
RISK ASSESSMENT
```

## Rationale

A password field is not inherently malicious.

A new domain is not inherently malicious.

A cross-origin request is not inherently malicious.

An ML score is not inherently authoritative.

The meaningful question is whether the combination of evidence supports a threat classification.

## Assessment States

```text
BENIGN
SUSPICIOUS
MALICIOUS
INSUFFICIENT_EVIDENCE
```

## Consequences

### Positive

- richer explanations
- lower dependence on one fragile signal
- better research flexibility
- supports ablation experiments

### Negative

- higher implementation complexity
- possible conflicting signals
- calibration challenges
- higher false-positive risk if correlation is poorly designed

## Research Requirement

The claim that multi-signal fusion improves detection must be experimentally demonstrated.

This ADR establishes architecture, not experimental proof.