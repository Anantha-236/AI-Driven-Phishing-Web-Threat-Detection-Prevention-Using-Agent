import { test, expect } from './fixtures';
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';

for (const failure of ['timeout', 'wrong-document'] as const) {
  test(`local agent never calls the backend decision endpoint (${failure}) while telemetry reaches PostgreSQL`, async ({ context, page }) => {
    const worker = context.serviceWorkers()[0] || await context.waitForEvent('serviceworker');
    await worker.evaluate(mode => {
      const nativeFetch = globalThis.fetch;
      (globalThis as any).backendDecisionCalls = 0;
      globalThis.fetch = async (input, init) => {
        if (!String(input).endsWith('/api/v1/agent/assess')) return nativeFetch(input, init);
        (globalThis as any).backendDecisionCalls++;
        if (mode === 'timeout') return new Promise<Response>((_resolve, reject) => {
          if (init?.signal?.aborted) reject(new Error('Controlled timeout'));
          else init?.signal?.addEventListener('abort', () => reject(new Error('Controlled timeout')), { once: true });
        });
        const result = { report: { document_id: 'WRONG_CONTROLLED_DOCUMENT', action: 'ALLOW', decision_source: 'BACKEND_ML_AGENT' } };
        return new Response(JSON.stringify(result), { status: 200 });
      };
    }, failure);
    await page.goto('http://127.0.0.1:41731/research?family=2&label=1&layout=0');
    await page.evaluate(async () => { await (window as any).runScenario(); });
    const tab = await worker.evaluate(async url => (await chrome.tabs.query({})).find(t => t.url === url)!.id!, page.url());
    const read = () => worker.evaluate(async id => (await chrome.storage.session.get(`security-report:${id}`))[`security-report:${id}`], tab);
    await expect.poll(async () => (await read())?.action, { timeout: 10000 }).toBe('WARN');
    expect((await read()).decision_source).toBe('LOCAL_ML_AGENT');
    expect((await read()).agent_version).toBe('local-context-agent-1');
    expect((await read()).agent_roundtrip_ms).toBeNull();
    expect(await worker.evaluate(() => (globalThis as any).backendDecisionCalls)).toBe(0);
    expect((await read()).document_id).not.toBe('WRONG_CONTROLLED_DOCUMENT');
    await expect(page.locator('#capstone-security-warning')).toBeVisible();
    await expect.poll(async () => (await worker.evaluate(async id => (await chrome.storage.session.get(`tsfeg:${id}`))[`tsfeg:${id}`], tab)).pending.length).toBe(0);
    const report = await read();
    const count = execFileSync('python', ['-c', `
import sys
from backend.database import db_instance
with db_instance.get_connection() as conn:
 print(conn.execute('SELECT COUNT(*) FROM events_sanitized WHERE session_id=%s AND tab_id=%s', (sys.argv[1],int(sys.argv[2]))).fetchone()[0])
`, report.session_id, String(tab)], { encoding: 'utf8', windowsHide: true });
    expect(Number(count.trim())).toBeGreaterThan(0);
  });
}

test('local document action gate confirms same-origin submissions and clears on ALLOW', async ({ context, page }) => {
  const worker = context.serviceWorkers()[0] || await context.waitForEvent('serviceworker');
  await page.goto('http://127.0.0.1:41731/benign');
  const tab = await worker.evaluate(async url => (await chrome.tabs.query({})).find(t => t.url === url)!.id!, page.url());
  const read = () => worker.evaluate(async id => (await chrome.storage.session.get(`security-report:${id}`))[`security-report:${id}`], tab);
  await expect.poll(async () => (await read())?.action).toBe('ALLOW');
  expect((await read()).decision_source).toBe('LOCAL_ML_AGENT');
  // Inject the worker-to-document action message to isolate the actuator
  // contract. This does not claim that the classifier flags this benign page.
  await worker.evaluate(async id => {
    const nativeSend = chrome.tabs.sendMessage.bind(chrome.tabs);
    (globalThis as any).restoreLocalGate = () => { chrome.tabs.sendMessage = nativeSend; };
    chrome.tabs.sendMessage = ((target: number, message: any, ...args: any[]) =>
      (nativeSend as any)(target, message?.type === 'SECURITY_REPORT' && target === id
        ? { ...message, action: 'CONFIRM' } : message, ...args)) as typeof chrome.tabs.sendMessage;
    const frame = await chrome.webNavigation.getFrame({ tabId: id, frameId: 0 });
    return chrome.tabs.sendMessage(id, { type: 'SECURITY_REPORT', action: 'CONFIRM' }, { documentId: frame!.documentId });
  }, tab);
  await expect(page.locator('#capstone-security-warning')).toBeVisible();
  let dialogs = 0;
  page.on('dialog', dialog => { dialogs++; expect(dialog.message()).toContain('security assessment requires confirmation'); void dialog.dismiss(); });
  await page.locator('button').click();
  await expect.poll(async () => (await read())?.outcome).toBe('SUBMIT_EVENT_CANCELLED');
  expect(dialogs).toBe(1);
  await worker.evaluate(async id => {
    (globalThis as any).restoreLocalGate();
    const frame = await chrome.webNavigation.getFrame({ tabId: id, frameId: 0 });
    return chrome.tabs.sendMessage(id, { type: 'SECURITY_REPORT', action: 'ALLOW' }, { documentId: frame!.documentId });
  }, tab);
  await page.locator('input[type=password]').fill('CONTROLLED_DUMMY');
  await expect.poll(async () => (await read())?.action).toBe('ALLOW');
  await expect(page.locator('#capstone-security-warning')).toHaveCount(0);
  // A page receipt proves the extension stopped cancelling; avoid navigating away.
  await page.evaluate(() => document.querySelector('form')!.addEventListener('submit', event => {
    event.preventDefault(); document.documentElement.dataset.controlledSubmitReceipt = 'received';
  }));
  await page.locator('button').click();
  await expect(page.locator('html')).toHaveAttribute('data-controlled-submit-receipt', 'received');
  expect(dialogs).toBe(1);
});

test('downloaded exact URL rules block navigation and fetch while preserving other shared-host paths', async ({ context, page }) => {
  test.setTimeout(60000);
  const worker = context.serviceWorkers()[0] || await context.waitForEvent('serviceworker');
  const control = await context.newPage();
  await control.goto(`chrome-extension://${worker.url().split('/')[2]}/src/ui/popup.html`);
  // The fixture supplies a public-feed-shaped response containing only loopback-resolved test URLs.
  await control.evaluate(() => chrome.runtime.sendMessage({ type: 'REFRESH_PHISHING_FEED' }));
  await control.evaluate(() => chrome.runtime.sendMessage({ type: 'REFRESH_PHISHING_FEED' }));
  await expect.poll(() => worker.evaluate(async () => (await chrome.declarativeNetRequest.getDynamicRules()).map(r => r.condition.urlFilter))).toContain('|http://feed-fixture.example.test:41731/blocked|');
  const receiverCount = async () => (await (await context.request.get('http://127.0.0.1:41731/test-receiver-count')).json()).blocked_probe_receipts;
  const before = await receiverCount();
  await expect(page.goto('http://feed-fixture.example.test:41731/blocked')).rejects.toThrow('ERR_BLOCKED_BY_CLIENT');
  const allowed = await context.newPage();
  await allowed.goto('http://feed-fixture.example.test:41731/benign');
  expect(await allowed.title()).toBe('Benign Scenario');
  expect(await allowed.evaluate(async () => { try { await fetch('/blocked', { method: 'POST', body: 'CONTROLLED_DUMMY' }); return 'sent'; } catch { return 'blocked'; } })).toBe('blocked');
  expect(await receiverCount()).toBe(before);
  await allowed.goto('http://feed-fixture.example.test:41731/Blocked');
  expect(await allowed.title()).toBe('Not Found');
  const installed = await worker.evaluate(() => chrome.declarativeNetRequest.getDynamicRules());
  await worker.evaluate(() => {
    const nativeFetch = globalThis.fetch;
    globalThis.fetch = (input, init) => String(input).includes('raw.githubusercontent.com/openphish/') ? Promise.reject(new Error('Feed outage')) : nativeFetch(input, init);
  });
  await control.evaluate(() => chrome.runtime.sendMessage({ type: 'REFRESH_PHISHING_FEED' }));
  expect(await worker.evaluate(() => chrome.declarativeNetRequest.getDynamicRules())).toEqual(installed);
  writeFileSync('.runtime/phishing-rule-acceptance.json', JSON.stringify({ status: 'PASS', provenance: 'CONTROLLED_FEED_FIXTURE', navigation_blocked: true, fetch_blocked: true, receiver_requests: (await receiverCount()) - before, other_path_allowed: true, case_sensitive: true, feed_outage_retained_rules: true }, null, 2));
});

test('initial cross-origin sensitive submitter target is confirmed and cancellation reaches no receiver', async ({ context, page }) => {
  const worker = context.serviceWorkers()[0] || await context.waitForEvent('serviceworker');
  await page.goto('http://127.0.0.1:41731/benign');
  await page.evaluate(() => document.querySelector('button')!.setAttribute('formaction', 'http://localhost:41731/sink'));
  await page.locator('input[type=password]').fill('DUMMY_SECRET_DO_NOT_EXPORT');
  let reached = 0;
  page.on('request', request => { if (new URL(request.url()).pathname === '/sink') reached++; });
  const dialog = page.waitForEvent('dialog');
  const clicking = page.locator('button').click();
  const prompt = await dialog;
  expect(prompt.message()).toContain('http://localhost:41731');
  await prompt.dismiss(); await clicking;
  const tab = await worker.evaluate(async url => (await chrome.tabs.query({})).find(t => t.url === url)!.id!, page.url());
  await expect.poll(async () => (await worker.evaluate(async id => (await chrome.storage.session.get(`security-report:${id}`))[`security-report:${id}`], tab))?.outcome).toBe('SUBMIT_EVENT_CANCELLED');
  expect(reached).toBe(0);
});

test('stable unknown cross-origin login remains allowed without a confirmation dialog', async ({ context, page }) => {
  const worker = context.serviceWorkers()[0] || await context.waitForEvent('serviceworker');
  await page.goto('http://127.0.0.1:41731/benign');
  await page.evaluate(() => document.querySelector('form')!.setAttribute('action', 'http://localhost:41731/sink'));
  const tab = await worker.evaluate(async url => (await chrome.tabs.query({})).find(t => t.url === url)!.id!, page.url());
  const read = () => worker.evaluate(async id => (await chrome.storage.session.get(`security-report:${id}`))[`security-report:${id}`], tab);
  await expect.poll(async () => (await read())?.form_destinations.some((form: any) => form.target_origin === 'http://localhost:41731')).toBe(true);
  await page.locator('input[type=password]').fill('CONTROLLED_CROSS_ORIGIN_LOGIN');
  await expect.poll(async () => (await read())?.action).toBe('ALLOW');
  let dialogs = 0;
  page.on('dialog', dialog => { dialogs++; void dialog.dismiss(); });
  // A website listener provides a local receipt without sending fixture values.
  await page.evaluate(() => document.querySelector('form')!.addEventListener('submit', event => {
    event.preventDefault(); document.documentElement.dataset.controlledSubmitReceipt = 'received';
  }));
  await page.locator('button').click();
  await expect(page.locator('html')).toHaveAttribute('data-controlled-submit-receipt', 'received');
  expect(dialogs).toBe(0);
  expect((await read()).decision_source).toBe('LOCAL_ML_AGENT');
});

test('snapshot telemetry cannot publish or replace the current document local assessment', async ({ context, page }) => {
  const worker = context.serviceWorkers()[0] || await context.waitForEvent('serviceworker');
  const snapshots: string[] = [];
  context.on('request', request => {
    if (request.url().endsWith('/api/v1/observations')) snapshots.push(JSON.parse(request.postData() || '{}').collectionId);
  });
  await worker.evaluate(() => {
    const nativeSend = chrome.runtime.sendMessage.bind(chrome.runtime);
    (globalThis as any).legacyDecisionPublications = 0;
    chrome.runtime.sendMessage = ((message: any, ...args: any[]) => {
      if (message?.type === 'POLICY_DECISION') (globalThis as any).legacyDecisionPublications++;
      return (nativeSend as any)(message, ...args);
    }) as typeof chrome.runtime.sendMessage;
  });
  await page.goto('http://127.0.0.1:41731/benign');
  const tab = await worker.evaluate(async url => (await chrome.tabs.query({})).find(t => t.url === url)!.id!, page.url());
  const read = () => worker.evaluate(async id => (await chrome.storage.session.get(`security-report:${id}`))[`security-report:${id}`], tab);
  await expect.poll(async () => (await read())?.decision_source).toBe('LOCAL_ML_AGENT');
  const before = await page.getAttribute('html', 'data-capstone-evidence-meta');
  await worker.evaluate(id => chrome.tabs.sendMessage(id, { type: 'REQUEST_COLLECTION' }), tab);
  await expect.poll(() => page.getAttribute('html', 'data-capstone-evidence-meta')).not.toBe(before);
  const collection = JSON.parse((await page.getAttribute('html', 'data-capstone-evidence-meta'))!).collectionId;
  await expect.poll(() => snapshots.includes(collection)).toBe(true);
  const popup = await context.newPage();
  await popup.goto(`chrome-extension://${worker.url().split('/')[2]}/src/ui/popup.html`);
  await page.bringToFront();
  const latest = await popup.evaluate(() => chrome.runtime.sendMessage({ type: 'GET_LATEST_DECISION' }));
  expect(latest.detection.decision_source).toBe('LOCAL_ML_AGENT');
  expect(latest.detection.agent_version).toBe('local-context-agent-1');
  expect(latest.detection.action).toBe((await read()).action);
  expect(await worker.evaluate(() => (globalThis as any).legacyDecisionPublications)).toBe(0);
});

test('popup exposes an outage and retry acknowledges the exact queued events in PostgreSQL', async ({ context, page }) => {
  const worker = context.serviceWorkers()[0] || await context.waitForEvent('serviceworker');
  await worker.evaluate(() => {
    const nativeFetch = globalThis.fetch;
    (globalThis as any).capstoneRestoreFetch = () => { globalThis.fetch = nativeFetch; };
    globalThis.fetch = (input, init) => String(input).startsWith('http://127.0.0.1:8000/')
      ? Promise.reject(new Error('Controlled outage')) : nativeFetch(input, init);
  });
  await page.goto('http://127.0.0.1:41731/benign');
  const control = await context.newPage();
  await control.goto(`chrome-extension://${worker.url().split('/')[2]}/src/ui/popup.html`);
  await page.bringToFront();
  await expect(control.locator('#delivery')).toContainText('Backend unavailable');
  await expect(control.locator('#agent')).toContainText('LOCAL PRIMARY');
  await expect(control.locator('#form-destinations')).toContainText('SAME ORIGIN');
  await worker.evaluate(() => (globalThis as any).capstoneRestoreFetch());
  const response = await control.evaluate(() => chrome.runtime.sendMessage({ type: 'RETRY_DELIVERY' }));
  expect(response.delivery.backend_connected).toBe(true);
  await expect.poll(async () => (await control.evaluate(() => chrome.runtime.sendMessage({ type: 'GET_SECURITY_REPORT' }))).delivery.pending_events).toBe(0);
  await expect.poll(async () => (await control.evaluate(() => chrome.runtime.sendMessage({ type: 'GET_SECURITY_REPORT' }))).report?.decision_source).toBe('LOCAL_ML_AGENT');
  const report = response.report;
  const stored = execFileSync('python', ['-c', `
import sys
from backend.database import db_instance
with db_instance.get_connection() as conn:
 print(conn.execute('SELECT COUNT(*) FROM events_sanitized WHERE session_id=%s AND tab_id=%s', (sys.argv[1],int(sys.argv[2]))).fetchone()[0])
`, report.session_id, String(report.tab_id)], { encoding: 'utf8', windowsHide: true });
  expect(Number(stored.trim())).toBeGreaterThan(0);
  const downloadEvent = control.waitForEvent('download');
  await control.locator('#btn-export').click();
  const download = await downloadEvent;
  expect(download.suggestedFilename()).toMatch(/^capstone-report-.*\.json$/);
  const exported = JSON.parse(readFileSync((await download.path())!, 'utf8'));
  expect(exported.report.session_id).toBe(report.session_id);
  expect(exported.report.tab_id).toBe(report.tab_id);
  expect(exported.report.decision_source).toBe('LOCAL_ML_AGENT');
  expect(exported.report.model_sha256).toMatch(/^[a-f0-9]{64}$/);
  expect(exported.identity_registry_sources.length).toBeGreaterThan(0);
  expect(exported.limitations.length).toBeGreaterThan(0);
});

test('the supported static DNR fixture is actually blocked by Chromium', async ({ context, page }) => {
  const worker = context.serviceWorkers()[0] || await context.waitForEvent('serviceworker');
  expect(await worker.evaluate(() => chrome.declarativeNetRequest.getEnabledRulesets())).toContain('dnr_rules');
  // Fixture DNS resolves only to loopback even if the rule regresses.
  await expect(page.goto('http://test-phish-dnr-blocked.example.com:41731/')).rejects.toThrow('ERR_BLOCKED_BY_CLIENT');
});
test('shipped extension starts its worker, content script and observer', async ({ context, page }) => {
  const worker = context.serviceWorkers()[0] || await context.waitForEvent('serviceworker');
  expect(await worker.evaluate(() => chrome.runtime.getManifest().manifest_version)).toBe(3);
  await page.goto('http://127.0.0.1:41731/benign');
  await expect(page.locator('html')).toHaveAttribute('data-capstone-observer-observing', 'success');
  await expect.poll(() => page.getAttribute('html', 'data-capstone-evidence-handoff')).toBe('send_ok');
});

test('controlled legitimate authentication/payment metadata has no warnings at the fixed policy threshold', async ({ context }) => {
  test.setTimeout(60000);
  const worker = context.serviceWorkers()[0] || await context.waitForEvent('serviceworker');
  const timings: number[] = [];
  for (const path of ['benign', 'oauth', 'sso', 'federated', 'payment', 'banking', 'embedded', 'cross-origin']) {
    const page = await context.newPage();
    await page.goto(`http://127.0.0.1:41731/${path}`);
    const password = page.locator('input[type=password]');
    if (['oauth', 'sso', 'federated', 'cross-origin'].includes(path)) await page.evaluate(async () => { await (window as any).runScenario(); });
    if (await password.count()) await password.fill('CONTROLLED_LOGIN_SENTINEL');
    const tab = await worker.evaluate(async url => (await chrome.tabs.query({})).find(t => t.url === url)!.id!, page.url());
    const read = () => worker.evaluate(async id => (await chrome.storage.session.get(`security-report:${id}`))[`security-report:${id}`], tab);
    await expect.poll(async () => Number.isFinite((await read())?.model_score)).toBe(true);
    expect((await read()).action, path).toBe('ALLOW');
    timings.push((await read()).analysis_latency_ms);
    await page.close();
  }
  writeFileSync('.runtime/false-positive-performance.json', JSON.stringify({ provenance: 'CONTROLLED', cases: 8, warnings: 0,
    acceptance_threshold: 'No WARN/CONFIRM/BLOCK on these eight controlled metadata approximations',
    analysis_latency_ms: timings, limitation: 'Not live OAuth/SSO/payment interoperability or population FPR.' }, null, 2));
});

test('backend outage preserves local warnings and queued sanitized evidence', async ({ context, page }) => {
  const worker = context.serviceWorkers()[0] || await context.waitForEvent('serviceworker');
  // Test-only replacement in the worker's own context; local model fetch still works.
  await worker.evaluate(() => {
    const nativeFetch = globalThis.fetch;
    globalThis.fetch = (input, init) => String(input).startsWith('http://127.0.0.1:8000/')
      ? Promise.reject(new Error('Controlled backend outage')) : nativeFetch(input, init);
  });
  await page.goto('http://127.0.0.1:41731/research?family=2&label=1&layout=0');
  await page.evaluate(async () => { await (window as any).runScenario(); });
  const tab = await worker.evaluate(async url => (await chrome.tabs.query({})).find(t => t.url === url)!.id!, page.url());
  await expect.poll(async () => (await worker.evaluate(async id => (await chrome.storage.session.get(`security-report:${id}`))[`security-report:${id}`], tab))?.action).toBe('WARN');
  await expect(page.locator('#capstone-security-warning')).toBeVisible();
  expect((await worker.evaluate(async id => (await chrome.storage.session.get(`security-report:${id}`))[`security-report:${id}`], tab)).decision_source).toBe('LOCAL_ML_AGENT');
  const state = await worker.evaluate(async id => (await chrome.storage.session.get(`tsfeg:${id}`))[`tsfeg:${id}`], tab);
  expect(state.pending.length).toBeGreaterThan(0);
});

test('pending backend telemetry and health requests do not stall the local report or popup', async ({ context, page }) => {
  const worker = context.serviceWorkers()[0] || await context.waitForEvent('serviceworker');
  await worker.evaluate(() => {
    const nativeFetch = globalThis.fetch;
    (globalThis as any).pendingBackendRequests = [];
    globalThis.fetch = (input, init) => {
      if (!String(input).startsWith('http://127.0.0.1:8000/')) return nativeFetch(input, init);
      (globalThis as any).pendingBackendRequests.push(String(input));
      // Keep the test transport unresolved: any dependency on its completion
      // would prevent this test from obtaining a page warning or popup report.
      return new Promise<Response>(() => {});
    };
  });
  await page.goto('http://127.0.0.1:41731/research?family=2&label=1&layout=0');
  await page.evaluate(async () => { await (window as any).runScenario(); });
  await expect(page.locator('#capstone-security-warning')).toBeVisible();
  const popup = await context.newPage();
  await popup.goto(`chrome-extension://${worker.url().split('/')[2]}/src/ui/popup.html`);
  await page.bringToFront();
  const response = await popup.evaluate(() => chrome.runtime.sendMessage({ type: 'GET_SECURITY_REPORT' }));
  expect(response.report.decision_source).toBe('LOCAL_ML_AGENT');
  expect(response.report.action).toBe('WARN');
  expect(response.delivery.pending_events).toBeGreaterThan(0);
  await expect(popup.locator('#agent')).toContainText('LOCAL PRIMARY');
  const pending = await worker.evaluate(() => (globalThis as any).pendingBackendRequests as string[]);
  expect(pending.some(url => url.endsWith('/health'))).toBe(true);
  expect(pending.some(url => url.endsWith('/agent/assess'))).toBe(false);
});

test('sentinels in field values, page bodies, cookies and headers stay outside extension telemetry', async ({ context, page }) => {
  const worker = context.serviceWorkers()[0] || await context.waitForEvent('serviceworker');
  const telemetry: string[] = [], logs: string[] = [];
  const canary = 'PRIVATE_BOUNDARY_SENTINEL_837';
  context.on('request', request => { if (request.url().startsWith('http://127.0.0.1:8000/api/')) telemetry.push(request.postData() || ''); });
  context.on('console', msg => logs.push(msg.text()));
  await page.goto('http://127.0.0.1:41731/privacy');
  await page.evaluate(value => {
    for (const autocomplete of ['cc-number', 'cc-csc', 'one-time-code'] as const) {
      const input = document.createElement('input'); input.autocomplete = autocomplete; input.value = value; document.querySelector('form')!.append(input);
    }
    document.cookie = `controlled=${value}; SameSite=Lax`;
    // Website-authored requests contain dummy values; extension-origin telemetry must not.
    void fetch('/sink', { method: 'POST', headers: { Authorization: `Bearer ${value}` }, body: value });
    const xhr = new XMLHttpRequest(); xhr.open('POST', '/sink'); xhr.send(value);
  }, canary);
  await page.locator('#p').fill(canary);
  await page.locator('#o').fill(canary);
  const tab = await worker.evaluate(async url => (await chrome.tabs.query({})).find(t => t.url === url)!.id!, page.url());
  const read = () => worker.evaluate(async id => (await chrome.storage.session.get(`tsfeg:${id}`))[`tsfeg:${id}`], tab);
  await expect.poll(async () => { const state = await read(); return state?.events.some((e: any) => e.sensitive_type === 'CVV') && state.pending.length === 0; }).toBe(true);
  const state = await read();
  const database = execFileSync('python', ['-c', `
import json,sys
from backend.database import db_instance
with db_instance.get_connection() as conn:
 events=conn.execute('SELECT event FROM events_sanitized WHERE session_id=%s AND tab_id=%s', (sys.argv[1],int(sys.argv[2]))).fetchall()
 reports=conn.execute('SELECT report FROM assessments_sanitized WHERE session_id=%s AND tab_id=%s', (sys.argv[1],int(sys.argv[2]))).fetchall()
 print(json.dumps([events,reports]))
`, state.session_id, String(tab)], { encoding: 'utf8', windowsHide: true });
  for (const secret of [canary, 'SuperSecretPassword123!', '998877', 'victim_user']) {
    expect(JSON.stringify({ state, database, telemetry, logs })).not.toContain(secret);
  }
});

test('local contextual ML report, honest confirmation receipt and sanitized PostgreSQL assessment', async ({ context, page }) => {
  const worker = context.serviceWorkers()[0] || await context.waitForEvent('serviceworker');
  const secrets = ['PW_SENTINEL_729', 'OTP_SENTINEL_729', 'CVV_SENTINEL_729'];
  const telemetry: string[] = [], logs: string[] = [];
  context.on('request', request => { if (request.url().startsWith('http://127.0.0.1:8000/api/')) telemetry.push(request.postData() || ''); });
  context.on('console', msg => logs.push(msg.text()));
  await page.goto('http://127.0.0.1:41731/research?family=2&label=1&layout=0');
  await page.locator('input[type=password]').fill(secrets[0]);
  await page.evaluate(async () => { await (window as any).runScenario(); });
  const tab = await worker.evaluate(async url => (await chrome.tabs.query({})).find(t => t.url === url)!.id!, page.url());
  const report = () => worker.evaluate(async id => (await chrome.storage.session.get(`security-report:${id}`))[`security-report:${id}`], tab);
  await expect.poll(async () => (await report())?.action).toBe('WARN');
  await expect.poll(async () => (await report())?.decision_source).toBe('LOCAL_ML_AGENT');
  await expect(page.locator('#capstone-security-warning')).toBeVisible();
  let sent = 0;
  page.on('request', req => { if (new URL(req.url()).pathname === '/sink') sent++; });
  page.once('dialog', dialog => void dialog.dismiss());
  await page.locator('#auth button').click();
  await expect.poll(async () => (await report())?.outcome).toBe('SUBMIT_EVENT_CANCELLED');
  expect(sent).toBe(0);
  const result = await report();
  expect(result.model_id).not.toBe('unavailable');
  expect(result.model_score).toBeGreaterThanOrEqual(0);
  expect(result.agent_version).toBe('local-context-agent-1');
  expect(result.contextual_parameters).toHaveLength(27);
  expect(result.contradictions).toContain('SENSITIVE_TARGET_CHANGED_AFTER_INTERACTION');
  expect(result.agent_roundtrip_ms).toBeNull();
  const readDatabase = () => JSON.parse(execFileSync('python', ['-c', `
import json,sys
from backend.database import db_instance
with db_instance.get_connection() as conn:
 row=conn.execute('SELECT report FROM assessments_sanitized WHERE session_id=%s AND tab_id=%s AND event_seq=%s', (sys.argv[1],int(sys.argv[2]),int(sys.argv[3]))).fetchone()
 print(json.dumps(row[0] if row else None))
`, result.session_id, String(tab), String(result.event_seq)], { encoding: 'utf8', windowsHide: true }).trim());
  await expect.poll(readDatabase).not.toBeNull();
  expect(readDatabase()).toEqual(result);
  const storage = JSON.stringify(await worker.evaluate(() => chrome.storage.session.get(null)));
  for (const secret of secrets) expect(JSON.stringify({ storage, telemetry, logs, database: readDatabase() })).not.toContain(secret);
  // Read popup for the real active page, not whichever tab last delivered evidence.
  const popup = await context.newPage();
  await popup.goto(`chrome-extension://${worker.url().split('/')[2]}/src/ui/popup.html`);
  await page.bringToFront();
  await expect(popup.locator('#model')).toContainText(result.model_id);
  await expect(popup.locator('#purpose')).not.toBeEmpty();
  await expect(popup.locator('#completeness')).toContainText('coverage');
  await expect(popup.locator('#agent')).toContainText('LOCAL PRIMARY');
  await expect(popup.locator('#outcome')).toContainText('SUBMIT EVENT CANCELLED');
  await popup.screenshot({ path: '.runtime/security-report.png', fullPage: true });
  writeFileSync('.runtime/security-acceptance.json', JSON.stringify({ status: 'PASS', actual_controlled_form_request_prevented: sent === 0,
    raw_values_absent: true, assessment_database_match: true, decision_source: result.decision_source,
    agent_version: result.agent_version, model_id: result.model_id, model_sha256: result.model_sha256,
    agent_roundtrip_ms: result.agent_roundtrip_ms, analysis_latency_ms: result.analysis_latency_ms, browser: context.browser()!.version() }, null, 2));
});
