# IEEE Figure and Table Specification

No experimental graph is fabricated. These are publication-planning specifications.

## Figures

### Figure 1: Overall architecture

- Caption: CAPSTONE-1 browser-local evidence, assessment, policy, and sanitized persistence architecture.
- Purpose: Show boundaries from webpage observation to local inference and optional backend persistence.
- Inputs: Browser-observable structural evidence and policy configuration.
- Outputs: Assessment, policy decision, explanation, and sanitized telemetry.
- Data flow: Webpage -> content script -> evidence -> features -> local model -> risk fusion -> policy -> explanation/telemetry.

### Figure 2: Browser evidence workflow

- Caption: Static and dynamic browser evidence collection boundaries.
- Purpose: Distinguish page metadata, forms, inputs, scripts, relationships, and later dynamic events.
- Inputs: DOM and browser lifecycle events.
- Outputs: Versioned evidence collection without field values.
- Data flow: DOM/lifecycle -> collector -> evidence schema -> service worker.

### Figure 3: Sensitive-data classification

- Caption: Structural classification of requested data categories without reading values.
- Purpose: Show how attributes such as type, name, autocomplete, and accept map to categories.
- Inputs: Structural element attributes only.
- Outputs: Category labels and evidence status.
- Data flow: Attributes -> classifier -> requested category set.

### Figure 4: Domain/network correlation

- Caption: Proposed relationship between sensitive-data requests, destinations, initiators, and domain context.
- Purpose: State the proposed research factor without implying implementation or novelty.
- Inputs: Form action, browser-visible request metadata, hostname, and optional registration context.
- Outputs: Relationship features such as cross-origin or unexpected destination.
- Data flow: Page -> request -> destination -> context -> correlation feature.

### Figure 5: ML training-to-browser deployment

- Caption: Leakage-audited training, model selection, ONNX export, and browser parity workflow.
- Purpose: Separate research training from prototype deployment.
- Inputs: Provenance-labeled browser-derived dataset.
- Outputs: Selected model, manifest, hash, and parity evidence.
- Data flow: Dataset -> audit -> splits -> baselines/ablations -> selection -> ONNX -> browser.

### Figure 6: Risk fusion and prevention

- Caption: Component risks, reason codes, policy decision, and measured enforcement boundary.
- Purpose: Prevent conflating an assessment with actual browser enforcement.
- Inputs: ML score and independent evidence components.
- Outputs: Explainable risk decision and tested policy action.
- Data flow: Components -> fusion -> reason codes -> policy -> enforcement experiment.

## Tables

| Table | Contents | Current status |
|---|---|---|
| I | Literature comparison | Partial; see LITERATURE-MATRIX.md |
| II | Detection technique comparison | Prepared conceptually; quantitative cost fields remain UNKNOWN |
| III | Threat model | Prepared in THREAT-MODEL.md |
| IV | CAPSTONE feature groups | TO BE FILLED FROM authoritative feature specification |
| V | Dataset composition | Current metadata: 20 samples, 11 legitimate, 9 phishing, 98 features; external validity UNKNOWN |
| VI | Model comparison | Prototype artifacts exist; final research selection NOT_AVAILABLE |
| VII | Ablation results | TO BE FILLED FROM EXPERIMENT |
| VIII | Robustness evaluation | TO BE FILLED FROM EXPERIMENT |
| IX | Runtime performance | TO BE FILLED FROM EXPERIMENT |
