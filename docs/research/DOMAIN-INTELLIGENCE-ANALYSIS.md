# Domain Intelligence Analysis

Domain intelligence is contextual evidence, not a standalone maliciousness decision.

| Signal | Detection value | False-positive risk | Availability | Privacy cost | Runtime cost |
|---|---|---|---|---|---|
| Registrable domain and subdomain | Helps compare page identity and destination relationships | Shared hosting and legitimate delegated subdomains | Usually available from hostname parsing | Low | Low |
| Domain age | Can identify very new infrastructure as a risk factor | Legitimate new domains and old compromised domains | Registration data can be delayed, redacted, or unavailable | External lookup reveals hostname | Moderate/high if remote |
| RDAP registration metadata | Adds registration dates, status, registrar, and nameserver context | Ownership and status do not prove intent | Provider and registry dependent | Query disclosure and retention risk | Moderate; cache required |
| WHOIS | Historical registration context | Inconsistent schemas, privacy redaction, stale records | Variable and increasingly limited | Remote query disclosure | Moderate |
| DNS records/nameservers | Infrastructure clustering and resolution context | CDNs, shared providers, and dynamic hosting create ambiguity | Often available but transient | DNS/query metadata exposure | Low/moderate |
| DNSSEC | Integrity/context signal | Absence is not evidence of phishing | Availability depends on domain deployment | Low | Low |
| IP reputation | Known abusive infrastructure can raise risk | Shared IPs and compromised legitimate hosts | Reputation feeds vary | External lookup and identifier exposure | Moderate |
| Domain similarity | Brand/typosquat context | Homographs and legitimate similar names create false alarms | Local computation possible | Low if hostname only | Low/moderate |
| Nameserver/registrar reputation | Campaign/infrastructure correlation | Provider-level aggregation can overflag benign domains | Registry/provider dependent | External query disclosure | Moderate |

## CAPSTONE boundary

Collect hostname-derived context and cache remote intelligence. Represent owner state as `OWNER_PUBLIC`, `OWNER_REDACTED`, or `OWNER_UNAVAILABLE`; never infer identity. Report missing intelligence separately. Evaluate incremental value with ablations and unseen-domain tests before including any signal in a final model.
