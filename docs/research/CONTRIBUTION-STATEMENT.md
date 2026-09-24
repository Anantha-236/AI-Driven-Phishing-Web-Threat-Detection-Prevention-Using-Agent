# Contribution Statement

STATUS=DRAFT
NOVELTY_STATUS=UNKNOWN
PATENTABILITY=REQUIRES_PROFESSIONAL_REVIEW

## KNOWN_PRIOR_WORK

- URL, HTML, DOM, login-form, and webpage-feature phishing detection are established research directions.
- CANTINA+ establishes a feature-rich, layered webpage phishing baseline.
- Phishpedia establishes visual brand identification with explainable target-brand output.
- PhishIntention establishes appearance/dynamics-based phishing-intention analysis.
- KnowPhish establishes multimodal brand knowledge and LLM-assisted webpage brand extraction.
- PhishDecloaker establishes CAPTCHA-cloaking as a detector-evasion problem and evaluates interactive visual recovery.
- Leaky Forms establishes measurement of pre-submit email/password leakage.
- WebGraph establishes action/information-flow graphing for robust tracker blocking.
- Public commercial systems already document reputation-based warnings and related protection features.

## PROPOSED_CAPSTONE_CONTRIBUTION

A testable browser-local protocol for correlating structural sensitive-data request categories with page context and, in future experiments, browser-visible destination/network and domain context, while excluding raw values from collection and telemetry. The defensible contribution at this stage is the privacy-constrained correlation hypothesis and reproducible evaluation design, not an asserted new algorithm.

## EXPERIMENTALLY_UNVERIFIED

- Whether correlation improves precision, recall, F1, false-positive rate, or robustness.
- Whether domain intelligence improves unseen-domain generalization.
- Whether dynamic signals justify their runtime cost.
- Whether the privacy boundary holds under all browser paths.
- Whether a research-trained model can be exported with browser prediction parity.

## POTENTIAL_PATENT_AREA

The potential area is privacy-preserving correlation of sensitive-data request categories with destination, domain, and behavior context. This is only a search target. Prior-art searches are incomplete and no novelty or patentability conclusion is made.

## NON-NOVEL_SUPPORTING_COMPONENTS

URL features, DOM/form observation, local ML inference, ONNX deployment, MutationObserver use, policy scoring, browser extensions, PostgreSQL persistence, and standard domain metadata are supporting components with substantial prior art.

## Distinguishing experiment

Compare URL/DOM-only, URL/DOM plus sensitive-data categories, and full context models on domain-disjoint and temporal data. Measure privacy leakage, calibration, false alarms, resource cost, and parity. A contribution claim is supportable only if the protocol is reproducible and the result survives these controls.
