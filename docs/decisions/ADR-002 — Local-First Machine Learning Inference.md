# ADR-002 — Local-First Machine Learning Inference

## Status

ACCEPTED

## Decision

CAPSTONE-1 performs security inference locally in the browser where technically practical.

Target runtime:

ONNX Runtime Web

## Motivation

The project handles security-relevant browser observations and therefore should minimize transmission of page information to external services.

Local inference provides:

- reduced network dependency
- lower data exposure
- lower cloud-processing requirements
- faster local decision opportunities
- improved privacy

## Architecture

```text
FEATURE VECTOR
      ↓
LOCAL ONNX MODEL
      ↓
MODEL SCORE
      ↓
EVIDENCE + RULES + CONTEXT
      ↓
THREAT ASSESSMENT
```

## Important Boundary

The ML model is not the final decision authority.

A model score must be interpreted together with:

- browser evidence
- rules
- contextual information
- confidence
- policy

## Alternatives

### Cloud ML

Rejected as the default because it increases data-transmission and availability dependencies.

### Large LLM inference

Not selected as the default because of cost, latency, reproducibility, browser resource limitations, and possible page-data exposure.

### Rule-only detection

Rejected as the sole detection mechanism because the research requires measurable machine-learning comparison.

## Consequences

### Positive

- privacy-friendly
- offline-capable
- low transmission dependency
- suitable for browser deployment

### Negative

- limited local CPU/memory
- model-size constraints
- model update complexity
- model drift
- calibration requirements

## Research Boundary

The current browser model is treated as a prototype until a research-trained model is selected, evaluated, exported and shown to have Python/browser prediction parity.

## Verification Requirement

A final model is not considered complete until:

training model
→ export
→ ONNX
→ browser inference
→ parity test

is demonstrated.