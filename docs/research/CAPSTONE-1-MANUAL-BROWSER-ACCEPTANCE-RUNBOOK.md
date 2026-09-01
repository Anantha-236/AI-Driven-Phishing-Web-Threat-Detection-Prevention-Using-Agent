# CAPSTONE-1 Manual Browser Acceptance Runbook

Date: 2026-08-18
Scope: Phase 1, Phase 2, Phase 3 manual browser verification using dist only.

## 1. Preconditions

- dist must already exist from current frozen baseline build.
- Use only this extension path:
  - C:/Users/anant/OneDrive/Desktop/Capstone-1/dist
- Do not load browser-extension, src, or assets directly.

## 2. Start controlled scenario server

From repository root, run:

- C:/Program Files/nodejs/node.exe scripts/manual-browser-acceptance-server.mjs

Expected startup output:

- CAPSTONE_MANUAL_SERVER_READY
- URL=http://127.0.0.1:41731/
- DNR_TARGET=http://test-phish-dnr-blocked.example.com/

## 3. Manual extension load (real Chrome)

1. Open chrome://extensions
2. Enable Developer mode
3. Click Load unpacked
4. Select C:/Users/anant/OneDrive/Desktop/Capstone-1/dist

Record:

- CAPSTONE-1 appears: PASS/FAIL
- Manifest errors: PASS/FAIL
- Service worker shown: PASS/FAIL
- Service worker opens: PASS/FAIL
- Service worker startup exception: PASS/FAIL

## 4. Manual E2E scenarios

Open each page from http://127.0.0.1:41731/ and record behavior from extension UI/service-worker logs.

Scenario matrix:

- BENIGN PAGE: /benign, expected ALLOWED
- SUSPICIOUS PAGE: /suspicious, expected WARNED
- HIGH-RISK SYNTHETIC PAGE: /high-risk, expected CONTAINED_AFTER_LOAD
- DYNAMIC PASSWORD FIELD: /dynamic, expected DETECTED
- DYNAMIC OTP FIELD: /dynamic, expected DETECTED
- DYNAMIC FORM ACTION CHANGE: /dynamic, expected DETECTED
- PRIVACY TEST: /privacy, expected no input.value access by extension
- DNR TARGET: http://test-phish-dnr-blocked.example.com/, expected BLOCKED_BEFORE_LOAD

## 5. Service-worker restart check

1. Trigger one inference on any scenario page.
2. Wait for worker idle suspension or reload extension.
3. Trigger inference again.
4. Record whether reinitialization succeeds.

Expected:

- SERVICE-WORKER RESTART: PASS

## 6. Evidence capture format

For each scenario capture:

- Scenario ID
- Expected
- Actual
- Evidence source (UI text, service-worker console, chrome://extensions state)
- PASS/FAIL/BLOCKED

## 7. Stop rule

If manual service worker startup fails, stop phase progression and classify as browser startup blocker.
