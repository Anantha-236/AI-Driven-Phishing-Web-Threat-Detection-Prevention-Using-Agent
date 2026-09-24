# Stage A Verification Result

**Status:** PASS  
**Branch:** upgrade/agentic-defense-v2  
**Commit:** 3ec3fc73675f36759398112eae1e26b3c12d170a  
**Started:** 2026-09-24T22:35:13.3469063+05:30  
**Finished:** 2026-09-24T22:36:51.6466925+05:30  
**Duration:** 98.3 seconds

## Fresh verification checks

| Check | Exit code | Duration (s) |
|---|---:|---:|
| TypeScript typecheck | 0 | 3.107 |
| Production extension build | 0 | 1.915 |
| Unit tests | 0 | 2.826 |
| TypeScript integration tests | 0 | 2.977 |
| Python event contract integration | 0 | 2.028 |
| Full Chromium browser suite | 0 | 79.286 |
| TSFEG Chromium/FastAPI/PostgreSQL restart and privacy verification | 0 | 5.991 |
| Git whitespace check | 0 | 0.107 |

## Git status after verification

``text
?? Upgrades/
?? scripts/verify-stage-a.ps1
``

## Scope and limitations

- Controlled local verification only.
- This does not establish real-world phishing recall, false-positive rate, model calibration, or zero-day generalization.
- Closed Shadow DOM remains outside declared coverage.
- Unknown first-time navigation is not called pre-request blocked unless a DNR rule existed before the request.
- The current contextual model remains advisory until independent Stage B data/calibration work is complete.

## Machine-readable record

See STAGE-A-VERIFICATION.json.
