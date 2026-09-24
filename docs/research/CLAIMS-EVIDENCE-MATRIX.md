# Claims and Evidence Matrix

| Claim | Source | Type | Evidence | Status |
|---|---|---|---|---|
| The prototype collects structural page/form/input metadata without raw form values | Repository collector source and Stage 2 report | FACT | Source inspection and runtime privacy checks | PROVEN_BY_EXPERIMENT for tested path |
| The prototype can send sanitized observations through FastAPI to PostgreSQL | Stage 2 browser/backend/PostgreSQL report | EXPERIMENTAL RESULT | Browser handoff, row-count deltas, row correlation, API readback | PROVEN_BY_EXPERIMENT for controlled scenario |
| The current browser model is a deterministic toy/prototype | Browser adapter and Stage 3 report | FACT | Model identifier and feature contract | PROVEN_BY_EXPERIMENT |
| Phishpedia provides visual brand identification and official page reports large-scale discovery results | Official USENIX page | LITERATURE FACT | Publisher/venue page | SUPPORTED_BY_LITERATURE |
| PhishIntention studies phishing intention from webpage appearance and dynamics | Official USENIX proceedings entry | LITERATURE FACT | Publisher/venue page | SUPPORTED_BY_LITERATURE |
| Google Safe Browsing warns about dangerous sites/downloads and documents Enhanced Protection capabilities | Google Safe Browsing official page | INDUSTRY FACT | Official product documentation | SUPPORTED_BY_LITERATURE |
| Correlating sensitive-data requests with destinations is novel | No conclusion yet | PROPOSED CLAIM | Requires complete academic and patent prior-art search | UNKNOWN |
| CAPSTONE-1 improves recall or false-positive rate over baselines | No completed comparable experiment | EXPERIMENTAL RESULT | Required ablation and evaluation not complete | UNKNOWN |
| CAPSTONE-1 detects advanced phishing broadly | None | CLAIM | Dynamic, visual, domain, network, and adversarial coverage incomplete | UNKNOWN |
| The system is globally optimal or universally effective | None | CLAIM | No valid evidence | UNKNOWN |
