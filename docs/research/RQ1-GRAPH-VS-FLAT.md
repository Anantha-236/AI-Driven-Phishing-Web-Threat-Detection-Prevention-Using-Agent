# RQ1: graph versus flat controlled browser pilot

> Engineering update, 2026-09-10: a separate 24-episode implementation shakedown now runs in the existing browser suite and train_models.py. It uses 14 flat counts and 8 direct entity/temporal relationship parameters, a 500 ms post-action horizon, authored family holdout and a chronological layout holdout. This is not the 144-episode protocol below, does not implement its full B0/B1/B2/G/P comparison and does not establish graph necessity. Final measured results and missing domain/brand evidence are in [CURRENT-STATUS](../../CURRENT-STATUS.md). The selected local predictor remains flat; the final LR PR-AUC difference is within the declared exploratory margin.

**Status: PROPOSED protocol. No experiment results are recorded in this document.**

**Protocol version:** proposed-1, 2026-09-08.

This document specifies an exploratory experiment against the integrated TSFEG implementation. It is not evidence that the experiment has run, that a graph improves phishing detection, or that the full TSFEG-CGE mechanism works. Full RQ1 remains unresolved without independently sourced evaluation samples. The current implementation must pass the ongoing M1 correctness review before collection starts.

The research question is whether relationship features derived from the same sanitized browser observations add measurable predictive value beyond a capable temporal flat representation. A graph is one implementation of those relationships; this experiment does not assume that storing a graph is necessary.

## 1. Scope and assumptions

- Use only local, controlled browser fixtures and loopback collectors. Use dummy canaries, never real credentials, OTPs, payment information, or live malicious destinations.
- Labels describe the fixture author's intended simulated collection behavior. They are not independent real-world phishing adjudications.
- Freeze the fixture and label manifest independently of feature implementation: reviewers assign labels from the fixture behavior specification, not from model features, graph predicates, or observed scores.
- Current identity nodes are `UNKNOWN`. Identity verification, authorization of delegated authentication, visual detection, and contradiction-gated enrichment are outside this pilot.
- A nearby request is temporal evidence, not proof that a sensitive field caused a request or that its value was transmitted. Same-origin server-side forwarding can be invisible to the extension.
- Performance on these fixtures cannot establish real-world generalization, zero-day detection, unseen-brand performance, calibrated deployment risk, or operationally low false positive rates.
- Episode scoring is offline after a fixed observation window. Do not describe it as prevention before submission or an interactive warning-latency result.

The source research program is `Tech-research/EXPERIMENTAL-VALIDATION-PLAN.md` and `Tech-research/FINAL-RESEARCH-MECHANISM.md`. This smaller pilot does not satisfy their full evidence gate.

## 2. Frozen collection matrix: 144 episodes

Use six scenario families, two intended labels per family, four layout variants, and three browser repeats:

`6 families x 2 cases x 4 layouts x 3 repeats = 144 browser episodes`.

Within each family, layouts and repeats are dependent variants of the same authored scenario. They are never counted as independent templates or independently sourced samples.

| ID | Family | Simulated collection case and benign counterpart | Evidence being challenged |
|---|---|---|---|
| F1 | Multiple forms | Both cases contain sensitive and non-sensitive fields and same/cross-origin targets. Bind the external collector to the sensitive form in the simulated collection case and to an unrelated non-sensitive form in the benign case. | Field, form, and target binding with matched marginal observations where feasible. |
| F2 | Action mutation | Preserve target observations and interaction counts where feasible; compare a collection target introduced after sensitive interaction with a benign target transition completed before interaction. | Order and the effective target at a particular event. |
| F3 | Delayed insertion | Insert the same sensitive field types dynamically, with the external target associated with their form or an unrelated form. | Discovery after mutation and form association. |
| F4 | Frame scoping | Compare an external request associated with the sensitive document/frame with the same request from an unrelated sibling frame. | Scope-sensitive temporal association, without a payload-flow claim. |
| F5 | Multi-step collection | Compare password and OTP interaction in one simulated collection flow with those interactions separated by an unrelated document transition. | Sensitive-event sequence and document boundaries. |
| F6 | Ambiguity stress | Include legitimate delegated authentication/payment and an observably equivalent simulated collector; also include a same-origin endpoint with an invisible simulated server-side forwarding distinction. | Limits of metadata-only classification and false positives. |

F6 uses layouts 1 and 2 for delegated authentication/payment pairs, and layouts 3 and 4 for same-origin pairs. Preserve opposite labels for observably equivalent cases. Never add an unobserved authorization or forwarding flag to the event file or model inputs to make these cases separable. Server-side forwarding may be represented by the local fixture's documented behavior; the extension is not assumed to observe it.

Layout variants are fixed DOM arrangements, not separate mechanisms: direct children, neutral wrapper containers, reordered non-functional siblings, and an equivalent accessible arrangement. Keep field semantics and intended action sequence unchanged within the relevant pair. Record any unavoidable differences in event counts; never edit event logs to manufacture matched counts.

Before the evaluation run, a separate shakedown run may test fixture execution and collection. Its outputs are development data. Freeze the protocol, fixture source, manifest, feature definitions, model configuration, and integrity checks before inspecting evaluation predictions. If these change afterward, retain the earlier artifacts and give the next experiment a new version.

## 3. Exact observation horizon and collection validity

Reuse the integrated Chromium extension and local fixture/server approach in `scripts/verify-tsfeg.mjs`. The evaluator must consume integrated recorder exports, not hand-constructed successful traces.

1. Start each episode in a fresh tab/session, using the same extension build and browser configuration for all cases. Reuse the browser process only if session isolation is verified.
2. Establish fixture readiness and record the action start. All scripted actions must finish within **2,000 ms** of that start. A timeout is a collection failure, not a negative example.
3. After the last scripted action completes, record `last_action_ms` on the browser worker clock. Set `cutoff_ms = last_action_ms + 3000`.
4. The observation horizon is exactly **3,000 ms after the last scripted action**. Export recorder state and retain events with `received_ms <= cutoff_ms`. Waits for delivery or export completion do not extend this cutoff. Record export time separately.
5. Use the identical retained event array for every representation. Archive its hash and the unmodified sanitized export with the run manifest. The endpoint is observation receipt, not inferred physical event occurrence.
6. Record pending delivery, dropped-event count, retained event count, missing document IDs, execution failures, and origin/context coverage. The backend copy and exported snapshot must agree for the retained event IDs before a collection result is accepted.

Do not collect real field values in research telemetry. A fixture collector may receive a dummy canary solely to execute the scenario and must discard its body. Scan exported sanitized events and persisted sanitized records for canary values. A failed canary check invalidates the run and blocks detection reporting until repaired and rerun.

An episode is invalid if actions exceed the limit, expected fixture actions fail, export is incomplete, any event was dropped, the 2,000-event retained-history limit truncates the episode, or required collection evidence is missing. Required evidence must be declared per scenario action in the frozen manifest independently of labels and detector output. Log every invalid attempt. Do not silently replace failures, shorten episodes, infer missing events, or discard difficult valid cases. An incomplete 144-episode matrix may be published as a collection report, but not as this protocol's completed detection result.

Missing document IDs are not automatically imputed. Report their frequency and mark affected relationships unknown. Unknown scope must never be treated as a confirmed match. Clock reversals or inconsistent cutoff ordering invalidate timing features and require investigation before completing the pilot.

## 4. Frozen split and fitting procedure

Group by the entire scenario family F1-F6, keeping both labels, all four layouts, and all three repeats in the same group. The four layouts share scenario source and are not independent holdout templates.

Use six `LeaveOneGroupOut` folds. Each fold trains on 120 browser episodes from five families and predicts 24 episodes from the remaining family. Every episode receives exactly one out-of-fold prediction. No family ID enters the predictor.

- Use fixed settings; no parameter search, threshold tuning, feature selection from holdout scores, or selection of a best-performing fold.
- Keep repeat counts equal. Give each of an episode case/layout's three repeats a training weight of `1/3` so repeated runs do not triple that case/layout's weight in the logistic objective.
- Fit preprocessing and the model only on the current fold's training episodes.
- Average the three held-out predicted probabilities for each family/case/layout before primary metric calculation. This yields 48 case/layout predictions, eight per family. Report repeat variability separately.
- The six families remain the largest independent design units for uncertainty reporting; averaging repeats does not make the 48 case/layouts independent.
- Randomize browser execution order using one frozen seed, `20260908`. Record that order; do not use it as a feature.
- Do not use the existing 20-row CSV, its models, or its split files for training, tuning, or holdout scoring in this pilot.

Use disjoint fixture origin aliases between families where practical, without encoding a label in the alias. Exclude literal aliases from predictors. Call these held-out **scripted scenario families**, not unseen real-world domains or brands.

## 5. Observation-identical representations

Every extractor receives the same immutable retained event array. Verify its hash before and after extraction. No representation may request extra browser evidence, use different cutoff times, filter difficult episodes separately, or inspect labels.

Use enum-defined bins and explicitly specified numeric fields. Count missing or unknown values explicitly rather than guessing them. Origins and entity IDs may be used to test equality or join related observations, but their literal strings and assigned numbers may not become learned predictors.

| Representation | Prespecified contents | Interpretation |
|---|---|---|
| B0: existing flat | `buildFlatControl` event/type/request counts. | Weak reference baseline only. |
| B1: enriched flat | B0 plus counts for every event type; direct form-target same/cross/unknown-origin counts; distinct form, field, document, and frame counts; unknown origin/document counts; confidence and trust-category summaries. | Available non-temporal marginals with coverage indicators. |
| B2: temporal flat | B1 plus event-type transition counts within known document/frame scopes; sensitive-type transition counts within those scopes; counts of requests within the last sensitive interaction's 2,500 ms window; lag bins `0-100`, `101-500`, `501-2500`, `>2500` ms and unknown; target-origin transitions before/after the latest scoped sensitive interaction. | A capable event-history control computed directly from events. Target history here is scoped by document/frame and does not join a particular field or form. |
| G: graph-derived | B2 plus field/form/destination joins: sensitive fields associated with same/cross/unknown-origin effective form targets, target changes after interaction with that same form, submit target differing from that form's previous target, and scoped sensitive interactions associated with those form-target relationships. | Incremental value of explicit entity relationships, not simply of timestamps or additional observations. |
| P: direct-event parity | Independently calculate exactly G's additional relationship features from the event array without constructing a graph; combine with B2. | Test that graph feature construction agrees with direct event joins and that a graph data structure is not being mistaken for new information. |

Freeze the complete ordered feature list and numeric definitions in the evaluator's manifest before scoring. This table defines the allowed feature families; no holdout-driven expansion is permitted. The smallest implementation should omit an unsupported feature from every relevant control and record that narrowing before collection, rather than manufacture a missing relationship.

For G, derive graph relationships from `buildGraph` and the evidence events referenced by its nodes/edges. Historical `TARGETS` edges are not all simultaneously effective: use their evidence event sequence to recover the target applicable at the observation being scored. Repeated edges must not accidentally count as distinct forms or fields.

Temporal order uses the implementation's documented worker-arrival sequence within a document/frame. `OBSERVED_NEAR_REQUEST` remains a capped-confidence temporal relation. When a relationship depends on unavailable provenance or unresolved frame ownership, expose unknown status consistently across B2, G, and P. Do not parse arbitrary node IDs into undocumented security semantics.

Prohibited predictors include label, fixture/family name, source filename, seed, repeat number, tab/session/document IDs, raw field/form IDs, literal origins, absolute epoch timestamps, browser execution order, and any server-only authorization or forwarding marker. Context IDs remain legal internal join keys only.

For all independently reproducible relationship features, assert `G == P` numerically before fitting. With the same columns, model settings, and folds, their predictions must agree within numerical tolerance. If parity holds and performance matches, report that direct event joins reproduce the graph summary; do not claim graph necessity.

## 6. Fixed model and metrics

Use the already installed scikit-learn dependency; no graph-learning dependency or deep model is needed. Record exact package versions in the run report. The environment inspected while drafting this proposal had scikit-learn 1.9.0 and SciPy 1.18.0; the actual run must verify its own versions.

Use a fixed numeric feature schema, `StandardScaler`, and `LogisticRegression(C=1.0, solver="lbfgs", max_iter=2000, random_state=20260908)`. Fit the scaler and classifier inside each training fold. Pass the declared repeat weights to the classifier. Use the same fixed model settings for B0, B1, B2, G, and P. Check convergence; a convergence failure requires diagnosis before accepting a completed result.

A scikit-learn [Pipeline](https://scikit-learn.org/stable/modules/generated/sklearn.pipeline.Pipeline.html) fits transformation and prediction steps together within training. The split uses [LeaveOneGroupOut](https://scikit-learn.org/stable/modules/generated/sklearn.model_selection.LeaveOneGroupOut.html), with family IDs supplied only as split groups.

**Primary metric:** average precision (AP) on the 48 aggregated out-of-fold predictions.

**Primary contrast:** `AP(G) - AP(B2)`.

**Secondary contrasts:** G minus B1 and G minus B0. P is an integrity and interpretation control, not an additional superiority hypothesis.

Use `average_precision_score`. AP is the recall-increment-weighted precision summary; it is not trapezoidal precision-recall AUC. Name it AP in all output tables. See the [official AP definition](https://scikit-learn.org/stable/modules/generated/sklearn.metrics.average_precision_score.html).

At a fixed probability threshold of `0.5`, report precision, recall, F1, false positive rate, and the four confusion counts. Include every denominator. Report all metrics pooled and for each family, especially F6. An undefined denominator must produce an explicit unavailable metric, not a silently favorable number. Report class prevalence; this designed balanced corpus is not deployment prevalence.

Report repeat variability, count of exact or equivalent feature vectors with opposing labels, feature count by representation, event/graph sizes, feature-extraction runtime, and collection failures. Measure extraction using a monotonic timer on the same frozen exports; report distributions without describing them as browser prevention latency or isolated total extension overhead.

## 7. Statistical and reporting limits

This pilot has only six authored scenario groups. It is exploratory, not a powered confirmatory test.

- Report the paired AP effect and every held-out family's result; do not select only positive families.
- If interval estimates are produced, use 4,000 paired bootstrap resamples of entire families, seed `20260908`, retaining all eight case/layout predictions and both models' scores together within each sampled family. Report percentile 95% intervals as conditional exploratory summaries with only six source groups; their nominal coverage is not established here.
- Do not bootstrap individual repeats as independent observations. Do not present ordinary McNemar significance on correlated repeated runs as confirmatory evidence.
- No confirmatory p-value, multiplicity-adjusted success declaration, operational effect-size threshold, or full-RQ1 pass/fail is specified for this small pilot. Secondary contrasts are descriptive. A later sufficiently supported protocol must preregister its own meaningful-effect and operational-FPR criteria.
- Zero false positives on these fixtures is not evidence of a low production FPR. AP depends on the designed mixture of cases; it is not a forecast of deployment precision.
- A model fitted on researcher-authored scenarios may learn their construction conventions. Group exclusion and identifier controls reduce particular leakage paths but do not establish realism or external validity.

## 8. Integrity checks and rejection rules

Before reporting detection metrics, leave one runnable integrity check covering:

1. Each episode belongs to exactly one family; each fold has disjoint family sets; counterpart layouts and repeats stay together; every episode has one held-out prediction.
2. The matrix has exactly 144 valid episodes with the declared labels/layouts/repeats and no duplicate event-export identity accidentally counted twice.
3. Every representation consumes identical event hashes and uses identical cutoffs; retained exports remain unmodified.
4. Permuting arbitrary session/document/frame/field/form identifiers consistently, while preserving equality, containment, and top-frame meaning, leaves permitted features and scores unchanged.
5. Bijective origin-alias renaming that preserves origin equality leaves features and scores unchanged.
6. Graph and direct-event relationship features agree; contradictory-label feature-equivalent cases receive identical scores from the same fitted model.
7. Unknown document scope never creates a confirmed temporal link; temporal-window boundary checks use the frozen inclusive `0 <= delta <= 2500` definition. Such unit checks are integrity evidence, not additional browser detection samples.
8. No canary value appears in sanitized exports or persisted sanitized events; dropped events and missing required observations cannot silently pass collection.

Interpret results using these rules:

| Observation | Required conclusion or action |
|---|---|
| G beats only B0 | A richer encoding beat a weak count baseline. RQ1 is not established. |
| B2 matches G | No measured gain beyond the specified temporal flat features. |
| P matches G | Direct event joins reproduce the graph summary. Graph necessity is unsupported. |
| Destination-only relationships explain all gain | Narrow the contribution to destination relationships and revisit the identified prior-art overlap. |
| Identifiers, origin aliases, execution order, fixture artifacts, or post-cutoff evidence affect the result improperly | Reject the affected evaluation, repair the leakage path, version the protocol, and recollect where needed. |
| Opposing-label cases with equivalent observable features are apparently separable | Investigate label/harness leakage before trusting any detector metric. |
| Legitimate delegation/payment produces false positives | State the present representation's inability to establish authorization; do not relabel the benign cases. |
| Same-origin server forwarding is missed | Report the browser observability limit; do not infer the second hop. |
| Privacy, event retention, export parity, or required provenance fails | Publish the collection failure; withhold a completed detection comparison until corrected. |
| Controlled fixtures improve | Report controlled-fixture performance only. Full RQ1, real-world generalization, and CGE benefit remain unresolved. |

## 9. Reproducibility artifacts and implementation plan

The proposed implementation extends existing project files and is deferred until M1 review is resolved. Do not create a parallel collector, evaluator, or pipeline:

1. Extend `scripts/verify-tsfeg.mjs` with the experiment mode, reusing its integrated fixture/server and extension export path. Extend the existing manual scenario server only where useful. Read the frozen manifest, execute the 144 episodes, enforce the action/cutoff rules, and save sanitized exports plus all failed attempts.
2. Extend `ml/evaluation/generalization_eval.py` with a clearly selected controlled-pilot mode using the installed scikit-learn stack. Load immutable exports, validate the matrix, construct B0/B1/B2/G/P, run the fixed family-held-out folds, and write all predictions and metric outputs. Keep existing evaluation behavior available, but do not import old dataset models or split files into the pilot.
3. Generate the necessary frozen fixture/label/feature manifest and actual result data files as reproducibility outputs, independently of score computation. Include explicit provenance for intended labels and paired cases, with protocol/source/manifest hashes alongside the run. Do not add placeholder documents or duplicate configuration sources.
4. Extend existing tests and runnable assertions with the collection, split, parity, invariance, and privacy checks above. Reuse the existing framework and runner; do not add a new test framework or parallel test pipeline.

Each run must record: code commit and dirty-tree/source hashes; protocol version/hash; fixture and manifest hashes; sanitized event hashes; browser/extension versions; manifest permissions; Python/Node/package versions; model parameters; split membership; run seed/order; hardware; action and cutoff times; timing method; raw prediction/metric files; privacy checks; collection failures; and any protocol deviation.

No artifact from this proposal is an experimental result. Do not fabricate, hand-edit, or selectively replace metric outputs. Subsequent independent samples, stronger negative cases, and external-validity evaluation are required before the full research mechanism can be claimed to have a demonstrated detection benefit.
