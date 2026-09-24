# Detection Technique Comparison

This comparison separates established capabilities from proposed CAPSTONE-1 directions. It is not a superiority claim.

| Technique | Strength | Weakness/evasion | Cost | Privacy risk | CAPSTONE position |
|---|---|---|---|---|---|
| URL lexical/reputation | Cheap and broad first-pass signal | New or mutated domains; benign shared infrastructure | Low to moderate | Low if hostname only | Existing feature family; never sole decision signal |
| HTML/DOM structure | Observes forms, fields, and page structure | Can miss late-created or cloaked content | Low to moderate | Low if values are excluded | Implemented structural evidence |
| Sensitive-data request classification | Directly describes what a page asks for | Labels can be ambiguous; does not prove malicious intent | Low | Low when values are never read | Central privacy-preserving signal |
| Dynamic DOM/interaction | Exposes late-loaded fields and behavior | Timing, coverage, and interaction limitations | Moderate | Low to moderate | Planned/evaluated separately |
| Network/destination metadata | Connects collection intent to destinations | Browser API visibility and attribution limits | Moderate | Metadata can still be sensitive | Proposed research direction; not validated here |
| Domain age/RDAP/DNS/IP | Infrastructure context | Incomplete, stale, privacy-protected, and not decisive alone | Moderate and network-dependent | External queries reveal hostnames | Future context only |
| Brand/visual identity | Explainable target-brand evidence | Reference coverage, visual changes, cost | High | Screenshots/page visuals expose more content | Prior-art comparison; not in validated prototype |
| Semantic/LLM analysis | Can generalize textual identity | Cost, nondeterminism, prompt/data exposure | High | Page text may leave device | Not justified for current prototype |
| Information-flow tracking | Strong relation between sensitive sources and sinks | Instrumentation overhead and implementation complexity | High | Taint labels and flows require careful handling | Privacy research reference; not implemented |
| Local ML | Offline operation and reduced cloud exposure | Model drift, calibration, and local resource limits | Low to moderate for compact models | Lower transmission exposure | Current browser artifact is prototype/toy |
| Cloud inference | Potentially larger models and centralized updates | Latency, availability, data disclosure | Network-dependent | Highest page-data exposure | Not assumed by CAPSTONE |
| Prevention/policy | Converts assessment into user action | Policy errors can block benign pages or fail to stop server-side actions | Depends on enforcement mechanism | User-facing explanations must remain safe | Current policy decision is not yet broad enforcement proof |

## Synthesis

Complementary evidence is preferable to any single signal. The strongest research direction for CAPSTONE-1 is an experimentally measured combination of structural sensitive-data requests with destination relationships and contextual risk, under a strict no-payload collection boundary. Whether that combination improves detection, false alarms, or latency is an open experimental question.
