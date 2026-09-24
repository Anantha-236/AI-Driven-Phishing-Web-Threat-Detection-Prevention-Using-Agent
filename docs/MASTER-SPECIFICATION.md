# Authoritative final approach - 2026-09-18

The supplied final approach below supersedes conflicting earlier architectural descriptions. It defines requirements, not proof of completed implementation. Consult `../CURRENT-STATUS.md` for current execution evidence and `../implementation_plan.md` for the baseline comparison. Historical experiment files and presentation snapshots retain their dated results.

Status vocabulary: IMPLEMENTED means source exists; EXPERIMENTALLY VERIFIED means a scoped repeatable result; PROPOSED means pending work; NOT VERIFIED means the claim lacks evidence; HISTORICAL means superseded or dated evidence. No status implies production readiness.

# Final Project Approach

## Official Project Title

**AI-Driven Phishing (Web-Threat) Detection and Prevention Using Machine Learning**

### Final project objective

> **Develop a privacy-preserving browser security extension that continuously analyzes browser-observable activity, distinguishes legitimate web interactions from deceptive or data-stealing behavior using contextual evidence and local machine learning, and warns or prevents supported high-risk actions before sensitive information is released.**

The project is **not just a phishing URL classifier**.

It is a **browser-side behavioral and contextual threat-detection and prevention system**.

---

# 1. Final Scope

The project is restricted to **browser-side threats**.

It will target:

| Target area                           | Final scope                                            |
| ------------------------------------- | ------------------------------------------------------ |
| Phishing websites                     | Yes                                                    |
| Fake login pages                      | Yes                                                    |
| Credential harvesting                 | Yes                                                    |
| One-time-password harvesting          | Yes                                                    |
| Payment/card phishing                 | Yes                                                    |
| Lookalike/impersonation pages         | Yes                                                    |
| Unknown phishing websites             | Yes, through general behavioral/context analysis       |
| Redirect phishing                     | Yes                                                    |
| Formjacking                           | Yes                                                    |
| Dynamic form manipulation             | Yes                                                    |
| Suspicious iframe authentication      | Yes                                                    |
| Suspicious runtime destinations       | Yes                                                    |
| JavaScript-driven suspicious behavior | Detect observable effects                              |
| Pre-submit data collection            | Protect where evidence is available before interaction |
| Dangerous known destinations          | Browser-supported network blocking                     |
| Contextually suspicious downloads     | Supporting detection                                   |
| Browser zero-day exploits             | No                                                     |
| Operating-system malware              | No                                                     |
| Server-side forwarding                | Not observable from browser                            |
| Deep executable/PDF malware analysis  | Future native-security scope                           |

This keeps the project substantial but technically defensible.

---

# 2. Core Problem We Are Solving

The old interpretation was wrong:

```text
PASSWORD detected
+
OTP detected
=
RISK
```

A legitimate bank can request exactly those things.

The final project asks:

> **Does the activity make sense for what this webpage appears to be doing?**

The detector evaluates:

```text
WHO / WHAT TYPE OF SERVICE?
          +
WHAT IS THE PAGE PURPOSE?
          +
WHAT DATA IS REQUESTED?
          +
WHERE IS THE PAGE RUNNING?
          +
WHERE WILL THE ACTION GO?
          +
WHAT IS HAPPENING AT RUNTIME?
          +
ARE THESE THINGS CONSISTENT?
          ↓
      THREAT ASSESSMENT
```

The central concept is therefore **contextual consistency versus contradiction**.

---

# 3. Final Frozen Architecture

```text
                     USER OPENS WEBSITE
                             │
                             ▼
                 ┌──────────────────────┐
                 │ NAVIGATION PRE-CHECK │
                 │ URL / origin         │
                 │ redirect state       │
                 └──────────┬───────────┘
                            ▼
                 ┌──────────────────────┐
                 │ PAGE CONTEXT SCANNER │
                 │ DOM / forms / inputs │
                 │ frames / targets     │
                 │ page purpose         │
                 └──────────┬───────────┘
                            ▼
              ┌─────────────────────────────┐
              │ CONTINUOUS RUNTIME MONITOR  │
              │ mutations                   │
              │ dynamic sensitive fields    │
              │ form-target changes         │
              │ redirects / frame changes   │
              └──────────────┬──────────────┘
                             ▼
               ┌───────────────────────────┐
               │ DESTINATION MONITOR       │
               │ request destinations      │
               │ initiators                │
               │ source ↔ destination      │
               │ timing                    │
               └─────────────┬─────────────┘
                             ▼
                  SANITIZED EVENT ENGINE
                             │
                             ▼
                    FEATURE EXTRACTION
                             │
               ┌─────────────┴──────────────┐
               ▼                            ▼
        LOCAL MACHINE                 CONTEXT /
        LEARNING MODEL                EVIDENCE ENGINE
               │                            │
               │                     contradictions
               │                     positive evidence
               │                     evidence coverage
               └─────────────┬──────────────┘
                             ▼
                    SECURITY ASSESSMENT
                             │
                  risk + uncertainty
                             │
             ┌───────────────┼───────────────┐
             ▼               ▼               ▼
           ALLOW            WARN       CONFIRM / PREVENT
                                               │
                            ┌──────────────────┼───────────────┐
                            ▼                  ▼               ▼
                     Sensitive-action     Submission       Browser-supported
                          gate               gate          network blocking
```

Separately:

```text
SANITIZED EVIDENCE
       ↓
FastAPI
       ↓
PostgreSQL
       ↓
Validated research dataset
       ↓
Offline model training
       ↓
Model evaluation
       ↓
ONNX export
       ↓
Extension update
```

The backend is **never required for the immediate browser decision**.

---

# 4. Privacy Boundary

This remains non-negotiable.

The extension may detect:

```text
PASSWORD_FIELD_PRESENT
OTP_FIELD_PRESENT
CARD_FIELD_PRESENT
PASSWORD_INTERACTION_OCCURRED
FORM_DESTINATION
REQUEST_DESTINATION
```

It must never collect:

```text
actual password
actual OTP
actual card number
actual CVV
raw form values
cookies
authorization headers
authentication tokens
request bodies
```

Example:

```json
{
  "event_type": "SENSITIVE_INTERACTION",
  "sensitive_type": "PASSWORD",
  "page_origin": "https://example.com",
  "frame_id": 0
}
```

Not:

```json
{
  "password": "ActualPassword123"
}
```

This is both a privacy property and part of the research question.

---

# 5. Generalized Detection — Not Website-Specific Detection

The model must **not depend on knowing SBI, Google, Microsoft, Amazon, etc.**

Known-service identity information may strengthen evidence, but generic detection is the foundation.

The same model must work for:

```text
bank
university
government portal
e-commerce site
email service
payment site
social network
small startup
unknown login portal
completely new website
```

The system learns:

> **What differentiates legitimate web behavior from deceptive sensitive-data collection?**

not:

> “What does SBI phishing look like?”

---

# 6. Final Feature Families

The model should use these major feature groups.

| Feature family                | Examples                                                                                               |
| ----------------------------- | ------------------------------------------------------------------------------------------------------ |
| **Origin / URL**              | protocol, origin structure, redirects, registrable-domain changes, suspicious lexical indicators       |
| **Page purpose**              | login, signup, payment, recovery, identity verification, informational, download, unknown              |
| **Sensitive-data context**    | username, password, OTP, payment data, identity data, recovery information                             |
| **Destination relationships** | same origin, cross origin, expected/unknown destination, changed destination                           |
| **Runtime behavior**          | dynamic field insertion, form-target changes, redirects, new iframes                                   |
| **Frame relationships**       | top origin vs child-frame origin, sensitive field inside foreign frame                                 |
| **Context consistency**       | requested data appropriate for apparent purpose, authentication/payment workflow consistency           |
| **Contradictions**            | identity-origin mismatch, unexpected sensitive request, destination mismatch, runtime-purpose mismatch |

The strongest features should be **relationships and contextual contradictions**, not merely raw field counts.

---

# 7. Legitimate Evidence Matters Too

Our detector must learn evidence supporting legitimacy.

For example:

```text
EXPECTED LOGIN CONTEXT
EXPECTED PASSWORD REQUEST
EXPECTED OTP SEQUENCE
STABLE FORM TARGET
EXPECTED DESTINATION
NORMAL REDIRECT SEQUENCE
NO RUNTIME CONTRADICTIONS
```

Without legitimate evidence, every security system naturally drifts toward excessive warnings.

So conceptually:

```text
THREAT EVIDENCE
       +
LEGITIMATE EVIDENCE
       +
UNCERTAINTY
       ↓
ASSESSMENT
```

---

# 8. Known vs Unknown Services

Use:

```text
VERIFIED
LIKELY
UNKNOWN
MISMATCH
```

Never:

```text
KNOWN = SAFE
UNKNOWN = MALICIOUS
```

Example unknown legitimate portal:

```text
Identity:
UNKNOWN

Purpose:
LOGIN

Requested:
USERNAME + PASSWORD

Destination:
same origin

Dynamic anomaly:
none

Contradictions:
none
```

Expected result:

```text
LOW RISK / MONITOR

not enough evidence to claim maliciousness
```

This is essential for real-world usability.

---

# 9. Machine-Learning Role

The machine-learning model is **one contributor**, not the authority.

Current practical pipeline:

```text
Browser evidence
       ↓
Features
       ↓
Local ONNX Model
       ↓
ML risk score
       +
Context
       +
Contradictions
       +
Positive evidence
       +
Evidence completeness
       ↓
Final assessment
```

We should initially compare:

```text
Logistic Regression
Random Forest
Gradient Boosting
```

and let experiments choose the best model.

Because the data is structured/tabular, there is no reason to jump immediately to large neural networks.

---

# 10. Relationship Graph Status

This is now settled.

Your initial experiment found approximately:

```text
Flat PR-AUC          = 0.873
Relationship PR-AUC  = 0.880

Difference           ≈ 0.007
Engineering margin   = 0.020
```

Therefore:

> **Graph superiority has not been demonstrated.**

So the final implementation should use:

```text
FLAT REPRESENTATION
→ primary ML representation
```

while keeping relationships for:

```text
evidence correlation
contradictions
explanations
research visualization
```

This avoids unnecessary complexity.

---

# 11. Dataset Strategy

Accuracy now becomes the first priority.

Training data must contain both **realistic phishing** and **hard legitimate cases**.

Bad dataset:

```text
PHISHING
password pages

BENIGN
news homepages
```

That teaches:

```text
PASSWORD = PHISHING
```

Instead use paired cases:

```text
legitimate bank login
vs
fake bank login

legitimate password → OTP
vs
phishing password → OTP

legitimate payment gateway
vs
fake payment gateway

legitimate cross-origin SSO
vs
malicious credential collector

legitimate university login
vs
phishing university login

legitimate iframe authentication
vs
malicious iframe authentication
```

The model must be forced to learn **context**.

---

# 12. Dataset Provenance

Every sample should record where it came from:

```text
REAL
CONTROLLED
SYNTHETIC
ARCHIVED
```

Never silently merge them.

Each session should contain:

```text
session identifier
ground-truth label
service category
event timeline
feature vector
domain group
brand group
template group
time group
provenance
```

No secret values.

---

# 13. Train on One Set of Services, Test on Others

This is mandatory if we want generalization.

Example:

```text
TRAIN

Bank A
Bank B
University A
Email Provider A
Store A

TEST

Bank C
University B
Email Provider B
Store B
Unknown service
```

Required evaluation splits:

```text
domain-group
brand-group
template-group
temporal
```

A random 80/20 split alone is insufficient.

---

# 14. Accuracy Comes Before Speed

The development order is now fixed:

```text
DATA QUALITY
      ↓
FEATURE QUALITY
      ↓
MODEL COMPARISON
      ↓
GENERALIZATION
      ↓
FALSE-POSITIVE REDUCTION
      ↓
CALIBRATION
      ↓
EARLY DETECTION
      ↓
PREVENTION
      ↓
LATENCY OPTIMIZATION
```

A wrong answer in 5 milliseconds is worthless.

First prove:

> **Can the detector correctly distinguish legitimate from phishing across unseen websites?**

Then optimize:

> **How early can it know?**

Then:

> **How quickly can it prevent?**

---

# 15. Uncertainty Is Part of the Model

Never force:

```text
LEGITIMATE
or
PHISHING
```

for every session.

Support:

```text
LOW RISK

SUSPICIOUS

HIGH RISK

INSUFFICIENT EVIDENCE
```

And separately:

```text
Risk
Confidence
Evidence completeness
```

They are different concepts.

For example:

```text
Risk:
High

Confidence:
Medium

Reason:
Destination behavior is suspicious,
but service identity could not be independently verified.
```

That's much more trustworthy than a fake “94% certain.”

---

# 16. Calibration

After model selection, calibrate its outputs using a held-out calibration dataset.

The purpose is to ensure:

```text
0.90 model output
```

doesn't automatically become:

```text
90% certainty
```

Evaluate model discrimination separately from probability calibration.

This matters because prevention decisions have higher consequences than simple classification.

---

# 17. Final Prevention Architecture

Once detection accuracy is strong, prevention operates at three levels.

### Sensitive-action gate

```text
PASSWORD / OTP / CARD action
        ↓
read current SecurityState
        ↓
LOW → ALLOW
UNCERTAIN → CONFIRM
HIGH + strong evidence → PREVENT
```

### Submission gate

```text
Form/action attempt
       ↓
pause where supported
       ↓
local decision
       ↓
ALLOW / CANCEL
```

### Browser network policy

```text
known/session-confirmed dangerous destination
       ↓
declarative blocking rule
       ↓
matching request blocked
```

This is defense in depth.

---

# 18. Real-Time Design

The detector should not begin analysis when the user clicks Submit.

Instead:

```text
PAGE OPENS
   ↓
security analysis begins
   ↓
page loads
   ↓
risk state updates
   ↓
runtime event
   ↓
risk state updates
   ↓
runtime event
   ↓
risk state updates
   ↓
sensitive action
   ↓
current decision already available
```

This is how the eventual prevention becomes fast.

---

# 19. Early-Detection Dataset

For prevention research, each session should later contain temporal snapshots:

```text
T0 navigation begins

T1 origin committed

T2 initial DOM available

T3 sensitive fields discovered

T4 immediately before sensitive interaction

T5 pre-submission

T6 final session
```

Then determine when the model first reached a correct threat decision.

This allows us to distinguish:

```text
accurate detector
```

from:

```text
accurate but too-late detector
```

---

# 20. Final Metrics

We should report more than accuracy.

| Category        | Metrics                                                                               |
| --------------- | ------------------------------------------------------------------------------------- |
| Classification  | Precision, Recall, F1                                                                 |
| Ranking         | Precision-Recall Area Under Curve, Receiver Operating Characteristic Area Under Curve |
| Safety          | False Positive Rate, False Negative Rate                                              |
| Generalization  | unseen domain, brand, template, temporal results                                      |
| Calibration     | calibration error / probability quality                                               |
| Early detection | percentage detected before sensitive release                                          |
| Prevention      | prevention success rate                                                               |
| Performance     | p50 / p95 / p99 latency                                                               |
| Resources       | CPU, RAM, event volume                                                                |
| Privacy         | secret-value leakage violations                                                       |
| Reliability     | backend outage, worker restart, burst handling                                        |

---

# 21. Detection, Early Detection and Prevention Are Separate

This distinction should be permanent.

```text
DETECTED
```

means:

> correct threat classification.

```text
DETECTED EARLY
```

means:

> correct threat classification before sensitive release.

```text
PREVENTED
```

means:

> the dangerous supported action was actually stopped.

Do not report one as another.

---

# 22. Evidence Semantics

Every explanation should distinguish:

```text
OBSERVED
INFERRED
UNKNOWN
NOT_OBSERVABLE
```

Example:

```text
OBSERVED
Password field exists.

OBSERVED
Request to another origin occurred
shortly after interaction.

INFERRED
The relationship contributes to suspicious behavior.

UNKNOWN
Whether the password itself was in that request.

NOT_OBSERVABLE
Whether the destination server later forwarded data.
```

This keeps the system scientifically honest.

---

# 23. JavaScript Handling

The project does **not** attempt to classify every JavaScript program.

Instead:

```text
SCRIPT EXECUTES
      ↓
WHAT SECURITY-RELEVANT EFFECT OCCURRED?
```

Monitor effects such as:

```text
sensitive field inserted
form target changed
hidden form created
new iframe
redirect
new destination
download
permission request
```

Behavior is more useful than merely detecting that JavaScript exists.

---

# 24. Download Handling

Browser-side download context can be included:

```text
page risk
+
download source
+
file type
+
browser danger metadata
+
context
```

Example:

```text
Fake account verification page
+
security_update.exe
→ strong suspicious evidence
```

Deep file malware analysis remains future/native scope.

---

# 25. Backend and Database

PostgreSQL is not the detector.

Its purposes are:

```text
sanitized evidence history
research
experiments
ground-truth labels
model development
audit
```

Runtime:

```text
Browser
→ Local security decision

and independently:

Browser
→ sanitized telemetry
→ FastAPI
→ PostgreSQL
```

If FastAPI is offline, local protection should remain active.

---

# 26. Continuous Model Improvement

Do **not** automatically retrain on user activity.

Correct process:

```text
Collected browser evidence
        ↓
Validation
        ↓
Trusted ground-truth label
        ↓
Training dataset
        ↓
Offline training
        ↓
Unseen-group evaluation
        ↓
Calibration
        ↓
Security review
        ↓
ONNX export
        ↓
Extension update
```

This prevents poisoned or incorrect predictions from becoming training truth.

---

# 27. Current Implementation Baseline

Based on the development results you reported, we currently already have:

| Component                          | Status                               |
| ---------------------------------- | ------------------------------------ |
| Chromium extension                 | Working controlled prototype         |
| Sanitized event collection         | Implemented                          |
| Dynamic observation                | Verified in current controlled suite |
| Document/frame/session correlation | Implemented                          |
| PostgreSQL persistence             | Verified                             |
| Local ML                           | Working prototype                    |
| Flat features                      | Current selected representation      |
| Relationship features              | Implemented experimentally           |
| Explainable popup                  | Implemented                          |
| Confirmation/form cancellation     | Verified controlled case             |
| Declarative network blocking       | Verified controlled case             |
| Backend outage tolerance           | Implemented/tested                   |
| Worker restart                     | Verified controlled test             |
| Privacy sentinel tests             | Passed tested paths                  |
| Real-world accuracy                | **Not established**                  |
| Broad generalization               | **Not established**                  |
| Calibration                        | **Not completed**                    |
| Universal pre-action prevention    | **Not established**                  |

So the next work is **not building the architecture again**.

It is improving **detection quality**.

---

# 28. Immediate Development Priority

From here, development should proceed as:

```text
CURRENT WORKING PROTOTYPE
        ↓
Replace sensitive-field risk shortcuts
        ↓
Add contextual features
        ↓
Add legitimate/positive evidence
        ↓
Build hard-negative dataset
        ↓
Expand phishing diversity
        ↓
Train model candidates
        ↓
Unseen-domain / brand / template tests
        ↓
Reduce false positives
        ↓
Calibrate model
        ↓
Freeze accurate detector
        ↓
Add temporal/early-detection training
        ↓
Optimize prevention timing
        ↓
Measure prevention success
        ↓
Final validation
```

That is the roadmap.

---

# 29. Final Research Gap

I would freeze the research gap as:

> **Existing browser phishing defenses use reputation, URL characteristics, visual identity, interaction analysis, behavioral signals, and machine learning in different ways, but a practical challenge remains in accurately distinguishing legitimate sensitive-data workflows from deceptive ones across previously unseen websites using privacy-preserving browser-observable evidence, while maintaining low false positives and ultimately reaching the decision early enough for pre-action intervention.**

This is the gap our project is trying to investigate.

---

# 30. Final Research Questions

The project should now answer:

```text
RQ1
Can privacy-preserving contextual browser evidence
distinguish legitimate and phishing activity across
unseen websites?

RQ2
Which evidence families contribute most to accuracy?

RQ3
How well does the model generalize to unseen domains,
brands and templates?

RQ4
Can legitimate login/payment/SSO workflows be handled
with acceptably low false positives?

RQ5
How early in the browser session can a reliable threat
decision be reached?

RQ6
For threats detected early enough, how often can the
extension actually prevent the dangerous action?

RQ7
What accuracy/privacy trade-off results from refusing
to inspect secret values and request bodies?
```

The earlier graph question can remain a secondary completed experiment, but should no longer dominate the project.

---

# 31. Final Candidate Innovation

Do not claim global novelty until prior-art work is complete.

The **candidate contribution** is:

> **A local-first, privacy-preserving, context-aware browser threat-detection and prevention mechanism that learns whether sensitive web activity is behaviorally consistent or deceptive across both known and previously unseen services, combining sanitized browser evidence, destination relationships, runtime behavior, lightweight machine learning, explicit uncertainty, and supported pre-action intervention.**

The particularly important combination is:

```text
GENERALIZED CONTEXT
       +
SENSITIVE-DATA EXPECTATION
       +
DESTINATION CONSISTENCY
       +
RUNTIME BEHAVIOR
       +
LOCAL ML
       +
UNCERTAINTY
       +
PRE-ACTION PROTECTION
```

---

# 32. Final Project Philosophy

The extension should **never** think:

```text
Password = threat
OTP = threat
Cross-origin = threat
Unknown website = threat
Redirect = threat
```

It should think:

```text
Password
+
Purpose
+
Origin
+
Destination
+
Runtime Behavior
+
Context
+
Evidence Quality
        ↓
Does this interaction make sense?
```

That is the fundamental change.

---

# 33. Final One-Sentence System Description

> **AI-Driven Phishing (Web-Threat) Detection and Prevention Using Machine Learning is a privacy-preserving, local-first Chromium browser extension that continuously analyzes contextual webpage behavior, sensitive-data request categories, origins, destinations, frames, redirects and runtime changes; uses lightweight machine learning together with explicit evidence and uncertainty to distinguish legitimate activity from deceptive browser threats across known and previously unseen services; and ultimately intervenes before supported high-risk sensitive actions complete.**

---

## Final decision

From this point:

**Architecture is frozen.**

**Browser-side scope is frozen.**

**Privacy boundary is frozen.**

**Flat representation remains the current ML baseline.**

**Graph/relationships remain supporting evidence unless larger research later proves predictive value.**

**Accuracy and generalization are now Priority 1.**

**False-positive reduction is Priority 2.**

**Calibration is Priority 3.**

**Early detection and prevention are Priority 4.**

**Latency optimization comes after the detector is trustworthy.**

That is the final version I would use consistently across the **implementation, report, presentation, research methodology and final demonstration**.
