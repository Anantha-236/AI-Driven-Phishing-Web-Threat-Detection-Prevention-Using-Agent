# Research Hypotheses

These hypotheses are preregistration-style statements. They do not imply that any alternative hypothesis will be supported.

## H1: Sensitive-data request signal

- H0: Adding structural sensitive-data request features does not improve the selected detection metric over URL/DOM-only baselines.
- H1: Adding structural sensitive-data request features improves the selected detection metric over URL/DOM-only baselines.
- Test: Paired evaluation on leakage-audited, provenance-separated samples with confidence intervals.

## H2: Destination correlation

- H0: Adding form-destination and browser-visible network relationship features does not improve detection of suspicious data collection over structural features alone.
- H1: Adding form-destination and browser-visible network relationship features improves detection of suspicious data collection over structural features alone.
- Test: Domain-disjoint and scenario-controlled comparison; raw payloads are never collected.

## H3: Domain context

- H0: Adding domain-registration and infrastructure context does not improve performance on newly registered or unseen domains.
- H1: Adding domain-registration and infrastructure context improves performance on newly registered or unseen domains.
- Test: Temporal and unseen-domain splits with missing-intelligence cases reported separately.

## H4: Dynamic behavior

- H0: Adding dynamic DOM and interaction features does not improve detection of dynamically generated phishing pages.
- H1: Adding dynamic DOM and interaction features improves detection of dynamically generated phishing pages.
- Test: Event-driven controlled scenarios and an independently sourced dynamic set.

## H5: Privacy and cost

- H0: The proposed privacy boundary cannot be maintained while meeting the predefined browser latency/resource budget.
- H1: The proposed privacy boundary can be maintained while meeting the predefined browser latency/resource budget.
- Test: Negative privacy tests plus P50/P95 latency, memory, CPU, and network-call measurements.

## Statistical caution

Significance testing requires sufficient independent samples and a predeclared analysis plan. The current 20-sample prototype dataset is not sufficient to support strong generalization or significance claims.
