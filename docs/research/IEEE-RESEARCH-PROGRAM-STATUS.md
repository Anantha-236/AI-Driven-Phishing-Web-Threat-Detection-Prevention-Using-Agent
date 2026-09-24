# IEEE Research Program Status

LITERATURE_STATUS=PARTIAL
PAPERS_PLANNED=2
PAPER_1_TOPIC=System, security, privacy, browser evidence, and explainable risk assessment
PAPER_2_TOPIC=Local machine learning, dataset quality, leakage, robustness, and browser deployment
TOTAL_LITERATURE_SOURCES=8 matrix entries
PEER_REVIEWED_SOURCES=4 verified venue entries
PRIMARY_SOURCES=5 verified official publisher/product pages
INDUSTRY_SOURCES=1 verified official product source
PATENT_SOURCES=0 verified in this pass
RESEARCH_GAP_STATUS=SUPPORTED_AS_A_RESEARCH_QUESTION
PAPER_1_STATUS=OUTLINE
PAPER_2_STATUS=OUTLINE
PATENT_PRIOR_ART_STATUS=INCOMPLETE
IEEE_TEMPLATE_STATUS=IEEEtran_CLASS_VERIFIED; SUPPLIED_TEMPLATE_FILE_NOT_LOCATED
REFERENCE_AUDIT=PARTIAL
FABRICATION_CHECK=PASS

## Source boundary

The literature matrix contains eight scoped entries. Four peer-reviewed venue entries were verified from official USENIX pages or proceedings pages during this pass: Phishpedia, PhishIntention, Leaky Forms, and WebGraph. Google Safe Browsing was verified as one official industry source. CANTINA+, KnowPhish, PhishDecloaker, and Arcanum remain matrix entries requiring direct primary-paper verification before detailed claims are published.

## Manuscripts

[paper1.tex](../../paper1.tex) uses `\\documentclass[journal]{IEEEtran}` and focuses on system architecture, security, privacy, evidence boundaries, and risk assessment.

[paper2.tex](../../paper2.tex) uses the same required IEEEtran journal class and focuses on dataset provenance, leakage auditing, model selection, robustness, ONNX deployment, and runtime measurement. The manuscripts are intentionally separate and contain no invented results.

## Unverified claims

- Any claim of novelty or patentability.
- Any claim that multi-signal fusion improves performance.
- Any global, universal, optimal, or production-grade detection claim.
- Any final model-performance claim beyond the repository's small prototype artifacts.
- Any complete claim about commercial or proprietary internal implementations.

## Missing experiments

- Complete static browser matrix.
- Dynamic DOM and interaction evaluation.
- Network/destination and information-flow evaluation.
- Domain/RDAP/DNS evaluation.
- Leakage-safe repeated evaluation with uncertainty.
- Temporal, unseen-domain, cross-domain, and adversarial tests.
- Ablations for each feature family.
- Research-model selection, ONNX export, and Python/browser parity.
- Browser P50/P95 latency, memory, CPU, and network-call measurements.
- Independent diverse data and comparable baseline evaluation.

## Missing literature

- Primary verification and full metadata extraction for CANTINA+.
- Primary verification and full metadata extraction for KnowPhish.
- Primary verification and full metadata extraction for PhishDecloaker.
- Primary verification and full metadata extraction for Arcanum.
- Current official Microsoft Defender SmartScreen documentation.
- Current official McAfee WebAdvisor documentation.
- Separate patent searches in Google Patents, WIPO Patentscope, Espacenet, and USPTO.
- Recent systematic reviews/SoKs and recent URL/DOM, privacy, and LLM studies.

## Validation limitation

The IEEEtran class structure, required title/author/abstract/keywords elements, citation keys, and reference numbering were inspected textually. PDF/LaTeX compilation was not performed because no local `pdflatex` or `latexmk` executable is available. Workspace search found no supplied template file, `IEEEtran.cls`, `.sty`, or prior `.bib` file; the manuscripts preserve the required `\\documentclass[journal]{IEEEtran}` convention but cannot be called byte-equivalent to an unavailable external template. This is a tooling/provenance limitation, not a claim that the PDFs compile.

## Next research task

Complete primary-source verification for the remaining required literature and the patent search before expanding either manuscript beyond its current evidence-bounded outline.
