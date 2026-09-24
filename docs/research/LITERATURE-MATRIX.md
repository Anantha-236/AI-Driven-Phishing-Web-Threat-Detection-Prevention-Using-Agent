# Literature Matrix

Status: PARTIAL. Each record uses `UNKNOWN` where the primary source was not verified in this pass. No search-result snippet is treated as evidence.

| Paper/System | Year | Technique | Signals | Dataset | Model | Main result | Limitation | Privacy | CAPSTONE relevance |
|---|---:|---|---|---|---|---|---|---|---|
| CANTINA+ | UNKNOWN in this pass | Feature-rich webpage phishing detection | URL and webpage features | UNKNOWN | ML framework | UNKNOWN; primary bibliographic page was not reliably verified | Requires complete source verification before claims | Feature collection may expose page metadata; details UNKNOWN | Motivates combining webpage evidence rather than URL alone |
| Phishpedia: A Hybrid Deep Learning Based Approach to Visually Identify Phishing Webpages | 2021 | Visual brand identification | Screenshot/logo and legitimate references | Real phishing data, exact composition UNKNOWN | Hybrid deep learning | Official USENIX page reports 1,704 newly discovered real phishing sites in 30 days, including 1,113 not reported by VirusTotal | Visual processing and reference coverage; exact runtime/cost and false-alarm details require paper-level extraction | Screenshot/visual collection has broader exposure than structural metadata | Prior art for brand identity and explainable target-brand output |
| Inferring Phishing Intention via Webpage Appearance and Dynamics: A Deep Vision Based Approach | 2022 | Appearance plus interaction/dynamics | Webpage appearance and dynamic behavior | UNKNOWN in this pass | Deep vision approach | Official USENIX proceedings page verifies title and venue; quantitative claims not extracted | Exact interaction protocol and costs require paper verification | Appearance and interaction capture implications require review | Relevant to intent and dynamic analysis; not equivalent to this prototype |
| KnowPhish | UNKNOWN in this pass | Multimodal brand knowledge and webpage semantics | HTML/text and visual identity | UNKNOWN | Multimodal/LLM-assisted system details UNKNOWN | Not claimed until the primary paper page is verified | Brand coverage, model cost, and privacy require primary-source review | Potentially high page-content exposure | Candidate comparison for multimodal identity analysis |
| PhishDecloaker | UNKNOWN in this pass | CAPTCHA/cloaking exposure | Interactive browser/CV behavior | UNKNOWN | UNKNOWN | Not claimed until the primary paper page is verified | Cloaking countermeasures can be expensive and incomplete | Interaction with pages may increase collection | Defines an adversarial limitation for static detectors |
| Arcanum | UNKNOWN in this pass | Browser information-flow/privacy analysis | Dynamic content flows | UNKNOWN | Dynamic taint tracking details UNKNOWN | Not claimed until the primary paper page is verified | Taint tracking overhead and browser coverage require verification | Directly relevant to raw-data protection | Useful privacy/information-flow comparison, not a phishing detector by itself |
| Leaky Forms: A Study of Email and Password Exfiltration Before Form Submission | 2022 | Measurement of pre-submit credential leakage | Browser form and network behavior | UNKNOWN in this pass | Measurement system | Official USENIX page verifies title, venue, and problem area | Measurement scope and sampled population require paper extraction | Directly concerns credential exposure | Strong motivation for destination-aware, payload-free telemetry |
| WebGraph: Capturing Advertising and Tracking Information Flows for Robust Blocking | 2022 | Information-flow graphing | Browser request and flow relationships | UNKNOWN in this pass | Graph-based system | Official USENIX page verifies system and flow-capture focus | Tracking-focused, not phishing-intent detection | Flow metadata and graph privacy need review | Informs relationship modeling while remaining distinct |

## Verified source pages

1. Phishpedia official USENIX page: https://www.usenix.org/conference/usenixsecurity21/presentation/lin
2. PhishIntention official USENIX Security 2022 technical-sessions entry: https://www.usenix.org/conference/usenixsecurity22/technical-sessions
3. Leaky Forms official USENIX page: https://www.usenix.org/conference/usenixsecurity22/presentation/senol
4. WebGraph official USENIX page: https://www.usenix.org/conference/usenixsecurity22/presentation/siby
5. Google Safe Browsing official documentation: https://safebrowsing.google.com/

## Required field status

The compact comparison table above is a navigation summary. Detailed source records are intentionally not expanded with unverified author, DOI, dataset, metric, or runtime claims. The following sources have complete safe metadata in the table: Phishpedia, PhishIntention, Leaky Forms, WebGraph, and Google Safe Browsing. CANTINA+, KnowPhish, PhishDecloaker, Arcanum, recent SoKs, current Microsoft documentation, current McAfee documentation, and patent records remain `UNKNOWN` until their primary pages and claims are directly verified.

## Detailed records

The following records satisfy the required fields for every source currently admitted to the matrix. `UNKNOWN` and `NOT_AVAILABLE` are deliberate values, not omitted fields.

### SOURCE-001: Phishpedia

- TITLE: Phishpedia: A Hybrid Deep Learning Based Approach to Visually Identify Phishing Webpages
- AUTHORS: Yun Lin; Ruofan Liu; Dinil Mon Divakaran; Jun Yang Ng; Qing Zhou Chan; Yiwen Lu; Yuxuan Si; Fan Zhang; Jin Song Dong
- YEAR: 2021
- VENUE: USENIX Security Symposium
- DOI: UNKNOWN
- PUBLISHER: USENIX Association
- URL: https://www.usenix.org/conference/usenixsecurity21/presentation/lin
- PROBLEM: Explainable visual phishing identification and target-brand recognition.
- THREAT_MODEL: Visually impersonating phishing webpages.
- INPUT_DATA: Webpage screenshots and legitimate brand references.
- FEATURES: Visual webpage and logo features.
- METHOD: Hybrid deep-learning visual identification.
- MODEL: Deep learning components; exact architecture UNKNOWN in this pass.
- DATASET: Real phishing data; composition UNKNOWN.
- EVALUATION_PROTOCOL: Extensive experiments plus 30-day CertStream deployment.
- METRICS: Exact metric values UNKNOWN.
- RESULTS: Official page reports 1,704 new real phishing sites in 30 days, 1,113 not reported by VirusTotal.
- LIMITATIONS: Reference coverage, visual variation, and exact runtime tradeoffs require paper extraction.
- PRIVACY: Visual collection may expose more page content than structural metadata; formal analysis UNKNOWN.
- RUNTIME_COST: Low runtime overhead is stated; exact value UNKNOWN.
- ADVERSARIAL_WEAKNESS: Visual changes and reference gaps.
- CAPSTONE_RELEVANCE: Identity/visual prior art; not evidence for CAPSTONE performance.

### SOURCE-002: PhishIntention

- TITLE: Inferring Phishing Intention via Webpage Appearance and Dynamics: A Deep Vision Based Approach
- AUTHORS: Ruofan Liu; Yun Lin; Xianglin Yang; Siang Hwee Ng; Dinil Mon Divakaran; Jin Song Dong
- YEAR: 2022
- VENUE: USENIX Security Symposium
- DOI: UNKNOWN
- PUBLISHER: USENIX Association
- URL: https://www.usenix.org/conference/usenixsecurity22/technical-sessions
- PROBLEM: Infer phishing intention from appearance and dynamics.
- THREAT_MODEL: Pages whose appearance and behavior indicate phishing intent.
- INPUT_DATA: Appearance and dynamic webpage evidence.
- FEATURES: Visual and dynamic features; exact list UNKNOWN.
- METHOD: Deep vision-based intention inference.
- MODEL: Deep vision; exact architecture UNKNOWN.
- DATASET: UNKNOWN.
- EVALUATION_PROTOCOL: UNKNOWN in this pass.
- METRICS: UNKNOWN.
- RESULTS: Title, authors, venue, and research focus verified; numerical results NOT_AVAILABLE.
- LIMITATIONS: Interaction coverage, visibility, and computation require primary-paper review.
- PRIVACY: Visual and interaction implications UNKNOWN.
- RUNTIME_COST: UNKNOWN.
- ADVERSARIAL_WEAKNESS: Appearance and dynamic manipulation.
- CAPSTONE_RELEVANCE: Intent/dynamic comparison; no novelty claim.

### SOURCE-003: Leaky Forms

- TITLE: Leaky Forms: A Study of Email and Password Exfiltration Before Form Submission
- AUTHORS: Asuman Senol; Gunes Acar; Mathias Humbert; Frederik Zuiderveen Borgesius
- YEAR: 2022
- VENUE: USENIX Security Symposium
- DOI: UNKNOWN
- PUBLISHER: USENIX Association
- URL: https://www.usenix.org/conference/usenixsecurity22/presentation/senol
- PROBLEM: Measure email/password collection before submission.
- THREAT_MODEL: Third-party scripts or trackers collecting form data prematurely.
- INPUT_DATA: Filled test fields, network traffic, and script access.
- FEATURES: Form access, network destinations, script access, consent/browser/location conditions.
- METHOD: Large-scale browser measurement with network and script interception.
- MODEL: Measurement system, not a phishing classifier.
- DATASET: Top 100,000 websites; EU/US and desktop/mobile conditions.
- EVALUATION_PROTOCOL: Two vantage points, two browser configurations, three consent modes.
- METRICS: Count of sites with observed leakage.
- RESULTS: 1,844 EU and 2,950 US sites exfiltrated email; 41 tracker domains were absent from popular blocklists; 52 sites showed incidental password collection.
- LIMITATIONS: Measurement does not itself establish phishing intent.
- PRIVACY: Uses controlled sensitive test inputs; CAPSTONE must not collect user payloads.
- RUNTIME_COST: Crawler/interception cost UNKNOWN.
- ADVERSARIAL_WEAKNESS: Timing/instrumentation evasion.
- CAPSTONE_RELEVANCE: Motivation for payload-free destination correlation.

### SOURCE-004: WebGraph

- TITLE: WebGraph: Capturing Advertising and Tracking Information Flows for Robust Blocking
- AUTHORS: Sandra Siby; Umar Iqbal; Steven Englehardt; Zubair Shafiq; Carmela Troncoso
- YEAR: 2022
- VENUE: USENIX Security Symposium
- DOI: UNKNOWN
- PUBLISHER: USENIX Association
- URL: https://www.usenix.org/conference/usenixsecurity22/presentation/siby
- PROBLEM: Robust ad/tracker blocking against mutable content and evasion.
- THREAT_MODEL: Advertising/tracking actors that evade content-based blockers.
- INPUT_DATA: Browser actions and information-flow relationships.
- FEATURES: Identifier storage and sharing actions.
- METHOD: Action-based graph representation with ML blocking.
- MODEL: ML blocker; exact model UNKNOWN.
- DATASET: UNKNOWN.
- EVALUATION_PROTOCOL: AdGraph comparison and adversarial evasion experiments.
- METRICS: Accuracy comparison and adversary success rate.
- RESULTS: Official page reports comparable accuracy and adversary success around 8% for WebGraph versus near-perfect for AdGraph.
- LIMITATIONS: Tracking task is not phishing-intent detection.
- PRIVACY: Flow capture requires careful identifier handling.
- RUNTIME_COST: UNKNOWN.
- ADVERSARIAL_WEAKNESS: Tested evasions do not cover all future attacks.
- CAPSTONE_RELEVANCE: Informs action/destination correlation.

### SOURCE-005: Google Safe Browsing

- TITLE: Google Safe Browsing
- AUTHORS: Google
- YEAR: 2005-present documentation
- VENUE: Official product documentation
- DOI: Not applicable
- PUBLISHER: Google
- URL: https://safebrowsing.google.com/
- PROBLEM: Warn users about dangerous sites and downloads.
- THREAT_MODEL: Publicly documented malware, unwanted software, and social engineering/phishing.
- INPUT_DATA: Threat-list and service interactions; complete signals UNKNOWN.
- FEATURES: Known-site checks and Enhanced Protection real-time/unknown-attack checks are publicly documented.
- METHOD: Reputation and warning service; internal method UNKNOWN.
- MODEL: UNKNOWN/PROPRIETARY.
- DATASET: UNKNOWN/PROPRIETARY.
- EVALUATION_PROTOCOL: Product transparency materials; not CAPSTONE-comparable.
- METRICS: Product-level claims only.
- RESULTS: Warnings and Enhanced Protection capabilities are documented.
- LIMITATIONS: Internal models and thresholds are not public.
- PRIVACY: Enhanced Protection documentation states additional security-related information may be shared.
- RUNTIME_COST: UNKNOWN.
- ADVERSARIAL_WEAKNESS: UNKNOWN.
- CAPSTONE_RELEVANCE: Industry baseline; no superiority claim.

### SOURCE-006: CANTINA+

- TITLE: CANTINA+: A Feature-Rich Machine Learning Framework for Detecting Phishing Web Sites
- AUTHORS: Guang Xiang; Jason Hong; Carolyn Penstein Rosé; Lorrie Faith Cranor
- YEAR: 2011
- VENUE: ACM Transactions on Information and System Security, 14(2)
- DOI: 10.1145/2019599.2019606
- PUBLISHER: Association for Computing Machinery
- URL: https://doi.org/10.1145/2019599.2019606
- PROBLEM: Reduce false positives while detecting phishing pages with rich features.
- THREAT_MODEL: Phishing webpages that evade simple blacklists or URL-only methods.
- INPUT_DATA: URL, HTML/DOM, search-engine, and third-party-service evidence.
- FEATURES: Eight feature families, including HTML/DOM and login-form signals.
- METHOD: Layered anti-phishing system with near-duplicate and login-form filters.
- MODEL: CANTINA+ feature-based detector plus filters.
- DATASET: 8,118 pages, including 4,883 legitimate pages, as reported in the indexed abstract.
- EVALUATION_PROTOCOL: Randomized and time-based evaluations, including a two-week sliding window.
- METRICS: True-positive and false-positive rates.
- RESULTS: Indexed abstract reports over 92% true positives with unique testing, about 99% with randomized testing, about 0.4% false positives, and 1.4% false positives in the time-based setting.
- LIMITATIONS: Feature extraction and filters depend on observable page content and assumptions about login pages; exact operational coverage requires full-paper review.
- PRIVACY: Page and third-party-service features may expose more content than CAPSTONE structural metadata; formal privacy analysis UNKNOWN.
- RUNTIME_COST: Filters are intended to improve runtime speed; exact cost UNKNOWN.
- ADVERSARIAL_WEAKNESS: Near-duplicate and login-form assumptions can be manipulated; cloaking/dynamic limits require separate testing.
- CAPSTONE_RELEVANCE: Strong webpage-feature baseline and direct motivation for leakage-safe ablations.

### SOURCE-007: KnowPhish

- TITLE: KnowPhish
- AUTHORS: Yuexin Li; Chengyu Huang; Shumin Deng; Mei Lin Lock; Tri Cao; Nay Oo; Hoon Wei Lim; Bryan Hooi
- YEAR: 2024
- VENUE: 33rd USENIX Security Symposium, pp. 793-810; arXiv version 2
- DOI: 10.48550/arXiv.2403.02253
- PUBLISHER: USENIX Association for the accepted venue version; arXiv for the verified record
- URL: https://arxiv.org/abs/2403.02253
- PROBLEM: Limited brand coverage and image-only reference-based phishing detection.
- THREAT_MODEL: Phishing webpages that impersonate brands, including pages without logos.
- INPUT_DATA: Multimodal brand knowledge and webpage HTML/text/images.
- FEATURES: Brand/logo knowledge and textual brand information extracted from HTML.
- METHOD: Automated knowledge collection plus KnowPhish Detector (KPD).
- MODEL: LLM-assisted text extraction combined with reference-based multimodal detection.
- DATASET: KnowPhish knowledge base contains 20k brands; evaluation uses a manually validated dataset and a Singapore field study.
- EVALUATION_PROTOCOL: Comparison with state-of-the-art reference-based baselines, including logo and no-logo conditions.
- METRICS: Effectiveness and efficiency improvements are claimed; exact metric values UNKNOWN in this pass.
- RESULTS: The arXiv abstract reports substantial effectiveness and efficiency improvements over state-of-the-art baselines.
- LIMITATIONS: Brand knowledge maintenance, model/data exposure, and generalization outside evaluated settings require review.
- PRIVACY: HTML and visual analysis expose richer page content than structural-only collection; privacy guarantees UNKNOWN.
- RUNTIME_COST: Efficiency improvement is reported relative to baselines; exact browser cost UNKNOWN.
- ADVERSARIAL_WEAKNESS: Missing/altered logos and text manipulation remain relevant risks.
- CAPSTONE_RELEVANCE: Establishes that multimodal identity is prior art and should not be claimed as a CAPSTONE novelty.

### SOURCE-008: PhishDecloaker

- TITLE: PhishDecloaker
- AUTHORS: X. Teoh; Y. Lin; R. Liu; Z. Huang; J. S. Dong
- YEAR: 2024
- VENUE: Venue/publisher not directly verified; indexed as conference output
- DOI: UNKNOWN
- PUBLISHER: UNKNOWN
- URL: https://hdl.handle.net/10072/434367
- PROBLEM: CAPTCHA-cloaked phishing pages defeat static detectors.
- THREAT_MODEL: CAPTCHA-cloaked phishing websites and detector-evasion adversaries.
- INPUT_DATA: Interactive CAPTCHA page behavior and visual content.
- FEATURES: CAPTCHA existence/type/challenge and visual page features.
- METHOD: Human-behavior mimicry and orchestration of five computer-vision models.
- MODEL: Hybrid vision-based interactive models.
- DATASET: Diverse CAPTCHA-cloaked websites; exact sample count UNKNOWN.
- EVALUATION_PROTOCOL: Effectiveness, efficiency, robustness, unseen-CAPTCHA, adversarial, and 30-day field experiments.
- METRICS: Recovery rate, precision, recall, and discovery lift.
- RESULTS: Indexed abstract reports average 74.25% recovery, 86% precision and 69% recall on unseen CAPTCHAs, and 7.6% more cloaked-site discovery in a field comparison.
- LIMITATIONS: Interactive coverage, CAPTCHA evolution, and cost may limit deployment.
- PRIVACY: Interactive visual analysis can expose page content; formal privacy guarantees UNKNOWN.
- RUNTIME_COST: Five vision models and browser interaction imply higher cost; exact values UNKNOWN.
- ADVERSARIAL_WEAKNESS: Evaluated adversaries include FGSM, JSMA, PGD, DeepFool, and DPatch; future cloaking remains open.
- CAPSTONE_RELEVANCE: Strong evidence that static-only validation cannot support broad evasion claims.

### SOURCE-009: Arcanum

- TITLE: Arcanum
- AUTHORS: UNKNOWN for the requested Arcanum work
- YEAR: UNKNOWN
- VENUE: UNKNOWN
- DOI: UNKNOWN
- PUBLISHER: UNKNOWN
- URL: UNKNOWN; exact primary record not located
- PROBLEM: Browser extension privacy/content-flow analysis is the requested scope, but the exact Arcanum source is unresolved.
- THREAT_MODEL: UNKNOWN.
- INPUT_DATA: UNKNOWN.
- FEATURES: UNKNOWN.
- METHOD: Dynamic taint-tracking is a hypothesis, not a verified attribution for Arcanum.
- MODEL: Not applicable/UNKNOWN.
- DATASET: UNKNOWN.
- EVALUATION_PROTOCOL: UNKNOWN.
- METRICS: UNKNOWN.
- RESULTS: NOT_AVAILABLE.
- LIMITATIONS: Do not cite this record as established literature until the exact primary source is found.
- PRIVACY: UNKNOWN.
- RUNTIME_COST: UNKNOWN.
- ADVERSARIAL_WEAKNESS: UNKNOWN.
- CAPSTONE_RELEVANCE: Unresolved privacy/information-flow reference.

- Full primary-paper extraction for CANTINA+, KnowPhish, PhishDecloaker, and Arcanum remains pending.
- The earlier attempted CANTINA+ DOI was rejected because it resolved to an unrelated ACM article; no DOI is retained for that source.
- DOI, complete author lists, datasets, exact metrics, and computational costs are not filled unless verified from the primary source.
- This matrix does not establish novelty or superiority.

## SOURCE-010: Mitigation strategies review

- TITLE: Mitigation strategies against the phishing attacks: A systematic literature review
- AUTHORS: Bilal Naqvi; Kseniia Perova; Ali Farooq; Imran Makhdoom; Shola Oyedeji; Jari Porras
- YEAR: 2023
- VENUE: Computers & Security, volume 132, article 103387
- DOI: 10.1016/j.cose.2023.103387
- PUBLISHER: Elsevier
- URL: https://doi.org/10.1016/j.cose.2023.103387
- PROBLEM: Systematically review phishing mitigation strategies and gaps.
- THREAT_MODEL: Phishing attacks and mitigation technologies.
- INPUT_DATA: Published literature from major digital libraries.
- FEATURES: Review taxonomy, attack vectors, technologies, and guidance.
- METHOD: Systematic literature review.
- MODEL: Not applicable.
- DATASET: 248 articles from 2018 through March 2023.
- EVALUATION_PROTOCOL: Review selection and synthesis; complete inclusion details UNKNOWN.
- METRICS: Article count and thematic synthesis, not detector metrics.
- RESULTS: Identifies mitigation strategies, attack vectors, guidance, and open issues.
- LIMITATIONS: Review cutoff predates current work and cannot replace primary studies.
- PRIVACY: Privacy treatment varies across reviewed approaches; exact synthesis UNKNOWN.
- RUNTIME_COST: Not applicable at review level.
- ADVERSARIAL_WEAKNESS: Evolving attack vectors are identified but not tested on CAPSTONE.
- CAPSTONE_RELEVANCE: Supports explicit evaluation of privacy, users, evolution, and reproducibility.

## SOURCE-011: Staying ahead of phishers review

- TITLE: Staying ahead of phishers: a review of recent advances and emerging methodologies in phishing detection
- AUTHORS: S. Kavya; D. Sumathi
- YEAR: 2024
- VENUE: Artificial Intelligence Review, volume 58, issue 2
- DOI: 10.1007/s10462-024-11055-z
- PUBLISHER: Springer Nature
- URL: https://doi.org/10.1007/s10462-024-11055-z
- PROBLEM: Review recent phishing detection methods and emerging methodologies.
- THREAT_MODEL: Evolving phishing and adversarial detection conditions.
- INPUT_DATA: Published research literature.
- FEATURES: Static, dynamic, graph, network-embedding, generative, and adversarial approaches.
- METHOD: Review and synthesis.
- MODEL: Not applicable.
- DATASET: Reviewed studies; aggregate composition UNKNOWN.
- EVALUATION_PROTOCOL: UNKNOWN in this pass.
- METRICS: Not a detector evaluation.
- RESULTS: Highlights static speed, dynamic cost, obfuscation, evasive behavior, and dataset-quality risks.
- LIMITATIONS: Full inclusion protocol and count require direct article review.
- PRIVACY: Aggregate privacy synthesis UNKNOWN.
- RUNTIME_COST: Highlights dynamic computational cost; exact values UNKNOWN.
- ADVERSARIAL_WEAKNESS: Obfuscation and anti-analysis are identified risks.
- CAPSTONE_RELEVANCE: Supports leakage audit, ablation, and robustness planning.

## SOURCE-012: CodeX

- TITLE: CodeX: Contextual Flow Tracking for Browser Extensions
- AUTHORS: Mohammad M. Ahmadpanah; Matías F. Gobbi; Daniel Hedin; Johannes Kinder; Andrei Sabelfeld
- YEAR: 2024
- VENUE: Proceedings of the Fifteenth ACM Conference on Data and Application Security and Privacy
- DOI: 10.1145/3714393.3726495
- PUBLISHER: Association for Computing Machinery
- URL: https://doi.org/10.1145/3714393.3726495
- PROBLEM: Detect privacy-violating browser-extension flows missed by conservative analysis.
- THREAT_MODEL: Extensions misusing sensitive sources and suspicious sinks.
- INPUT_DATA: Extension code and contextual source-to-sink flows.
- FEATURES: Browser-specific sources, network sinks, and contextual flow relationships.
- METHOD: CodeQL-based contextual flow tracking.
- MODEL: Static/data-flow analysis, not phishing ML.
- DATASET: Chrome Web Store extensions published March 2021 to March 2024.
- EVALUATION_PROTOCOL: Large-scale analysis plus manual verification.
- METRICS: 1,588 risky flows, 339 manually verified, 212 flagged privacy-violating, and up to 3.6M users affected.
- RESULTS: Values above are reported in the indexed abstract metadata.
- LIMITATIONS: Extension privacy analysis is not webpage phishing classification.
- PRIVACY: Directly addresses sensitive browser sources and network sinks.
- RUNTIME_COST: Primarily offline/static analysis; exact costs UNKNOWN.
- ADVERSARIAL_WEAKNESS: Obfuscation and unmodeled APIs may reduce coverage.
- CAPSTONE_RELEVANCE: Adjacent privacy-flow prior art; not a substitute for Arcanum.

## SOURCE-013: Modern URL/HTML/DOM ML baseline

- TITLE: Phishing Detection System Through Hybrid Machine Learning Based on URL
- AUTHORS: Abdul Karim; Mobeen Shahroz; Khabib Mustofa; Samir Brahim Belhaouari; S. Ramana Kumar Joga
- YEAR: 2023
- VENUE: IEEE Access, volume 11, pages 36805-36822
- DOI: 10.1109/ACCESS.2023.3252366
- PUBLISHER: IEEE
- URL: https://doi.org/10.1109/ACCESS.2023.3252366
- PROBLEM: URL-based phishing detection with hybrid feature selection and classifiers.
- THREAT_MODEL: URL-level phishing attacks.
- INPUT_DATA: URLs and URL-derived attributes.
- FEATURES: URL features; exact list requires article review.
- METHOD: Hybrid feature selection and classifier comparison.
- MODEL: Decision tree, logistic regression, random forest, naive Bayes, gradient boosting, KNN, SVC, and voting variants.
- DATASET: More than 11,000 URLs are described in indexed metadata; exact provenance requires article review.
- EVALUATION_PROTOCOL: Cross-validation and grid-search comparisons are described.
- METRICS: Accuracy, precision, recall, F1, specificity, and efficiency.
- RESULTS: Indexed metadata reports best-model accuracy around 97%; confidence intervals UNKNOWN.
- LIMITATIONS: URL-only evidence cannot observe page intent, dynamic behavior, or destination flow.
- PRIVACY: Hostname/URL collection has lower content exposure but reveals browsing destinations.
- RUNTIME_COST: Intended as fast URL classification; exact cost UNKNOWN.
- ADVERSARIAL_WEAKNESS: URL mutation and shared infrastructure.
- CAPSTONE_RELEVANCE: Modern URL baseline for future ablation.
