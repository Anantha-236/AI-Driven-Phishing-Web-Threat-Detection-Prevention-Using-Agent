# CAPSTONE-1 Research Gap

## Status

RESEARCH_GAP_STATUS=SUPPORTED_AS_A_RESEARCH_QUESTION
NOVELTY_STATUS=UNKNOWN

Final target (2026-09-18): accurately distinguish legitimate sensitive-data workflows from deceptive ones across previously unseen websites using privacy-preserving browser-observable evidence, maintain low false positives, and eventually decide early enough for supported pre-action intervention. This is a research objective; global novelty remains unknown.

The gap below is a synthesis of verified literature themes and repository evidence. It is not a claim that no prior system has combined these mechanisms.

## 1. Existing problem

Web phishing and deceptive data collection can be expressed through different observable layers: URL identity, page structure, requested data categories, visual brand identity, dynamic behavior, and destination/network relationships. A detector that uses only one layer can miss attacks that manipulate or hide that layer.

## 2. What prior systems already solve

Prior work demonstrates substantial solutions for individual families. Phishpedia addresses visual brand identification with explainable target-brand output. PhishIntention addresses phishing intent using webpage appearance and dynamics. Leaky Forms measures credential leakage before form submission. WebGraph demonstrates graph-based capture of browser information flows. Google Safe Browsing publicly documents warning users about dangerous sites and downloads, with Enhanced Protection adding real-time and previously unknown-attack protections.

These systems prevent the claim that CAPSTONE-1 is the first to use visual, dynamic, network, or reputation evidence individually.

## 3. What remains difficult

The unresolved research question is whether a browser-local, privacy-preserving system can correlate a page's sensitive-data request with its form destination, browser-visible request relationship, identity context, and compact local model without collecting payloads, while maintaining acceptable false alarms and runtime cost.

## 4. Why the difficulty exists

Signals have different timing, visibility, reliability, and privacy costs. Dynamic content may not exist at initial load. Domain intelligence can be unavailable. Network metadata may not reveal application intent. Visual and semantic methods can be expensive. Small or biased datasets can make apparent gains unreliable.

## 5. What CAPSTONE-1 proposes

CAPSTONE-1 proposes a measurable architecture that keeps sensitive-data classification structural, derives authoritative features, performs local inference, fuses independent risk components, produces reason codes, and transmits sanitized telemetry only. The proposed contribution is the correlation and evaluation protocol, not an asserted novel algorithm.

## 6. What must be demonstrated

- Leakage-safe datasets with real, controlled, and synthetic provenance separated.
- Baselines and ablations for URL, DOM, data-request, domain, network, and behavior groups.
- Temporal and unseen-domain evaluation.
- Privacy tests proving no raw values, bodies, cookies, or authorization headers are collected.
- Browser/runtime latency and resource measurements.
- Python-to-browser model parity after a research-trained model is selected.
- Comparison against relevant prior methods under a comparable protocol.

## 7. Current limitations

Current contextual implementation and candidate-training results are recorded in `../../CURRENT-STATUS.md`. The original 20-sample tabular prototype and 24 controlled loopback episodes cannot establish real-world accuracy. New synthetic paired workflows support implementation and training-pipeline checks only. Independently validated real-domain/brand cohorts, prospective temporal evaluation, production calibration and broad pre-action protection remain unverified.
