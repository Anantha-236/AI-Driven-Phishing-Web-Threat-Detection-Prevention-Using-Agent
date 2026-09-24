// Real Chromium -> existing FastAPI -> PostgreSQL check, using only local fixtures.
// Run from repository root: node scripts/verify-tsfeg.mjs
import assert from 'node:assert/strict';
import { chromium } from 'playwright';
import { spawn, spawnSync } from 'node:child_process';
import { createServer } from 'node:http';
import { resolve } from 'node:path';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { cpus, platform, arch, totalmem } from 'node:os';
const wait = ms => new Promise(r => setTimeout(r, ms));
async function until(fn, timeout = 15000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) { const value = await fn(); if (value) return value; await wait(100); }
  throw new Error('Timed out waiting for verified state');
}
const backend = spawn('python', ['-m', 'uvicorn', 'backend.main:app', '--host', '127.0.0.1', '--port', '8000', '--log-level', 'error'], { windowsHide: true, stdio: 'ignore' });
let context;
const legacyPayloads = [];
const legacyReceipts = new Set();
const server = createServer((req, res) => {
  if (req.url === '/redirect') { res.writeHead(302, { Location: '/frame' }); res.end(); return; }
  if (req.url === '/sink') { res.end('ok'); return; }
  res.setHeader('Content-Type', 'text/html');
  if (req.url === '/frame') { res.end('<!doctype html><input type="email">'); return; }
  if (req.url === '/opaque') { res.end('<!doctype html><input type="tel">'); return; }
  res.end('<!doctype html><html><head><title>AUDIT_CANARY</title></head><body><form action="/initial?token=AUDIT_CANARY"><input type="password" name="AUDIT_CANARY"></form><input autocomplete="one-time-code"><iframe src="/redirect"></iframe><iframe sandbox="allow-scripts" src="/opaque"></iframe></body></html>');
});
let result = { status: 'FAIL', started_at: new Date().toISOString(), fixture_version: 'm1-controlled-v2',
  hardware: { os: platform(), arch: arch(), cpu: cpus()[0]?.model, logical_cpus: cpus().length, memory_bytes: totalmem() },
  source_hashes: Object.fromEntries(['dist/manifest.json', 'dist/collector.js', 'dist/service-worker.js', 'dist/assets/model.onnx', 'backend/events.py', 'backend/main.py', 'scripts/verify-tsfeg.mjs'].map(file =>
    [file, createHash('sha256').update(readFileSync(file)).digest('hex')])),
};
try {
  await until(async () => {
    if (backend.exitCode !== null) throw new Error('Test backend failed to start; port may be in use');
    try { const r = await fetch('http://127.0.0.1:8000/api/v1/health'); return r.ok && (await r.json()).database === 'CONNECTED'; } catch { return false; }
  });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  const extension = resolve('dist');
  context = await chromium.launchPersistentContext('', { channel: 'chromium', headless: true,
    args: [`--disable-extensions-except=${extension}`, `--load-extension=${extension}`] });
  result.runtime_warnings = [];
  context.on('console', msg => { if (['error', 'warning'].includes(msg.type())) result.runtime_warnings.push(msg.text().slice(0, 300)); });
  context.on('request', request => {
    if (request.url() === 'http://127.0.0.1:8000/api/v1/observations' && request.method() === 'POST') legacyPayloads.push(request.postDataJSON());
  });
  context.on('response', response => {
    if (response.url() === 'http://127.0.0.1:8000/api/v1/observations' && response.status() === 201) {
      void response.json().then(body => { if (body.isStored === true) legacyReceipts.add(body.collectionId); }).catch(() => {});
    }
  });
  const sw = context.serviceWorkers()[0] || await context.waitForEvent('serviceworker');
  result.permissions = await sw.evaluate(() => chrome.permissions.getAll());
  result.listeners = await sw.evaluate(() => ({ request: chrome.webRequest.onBeforeRequest.hasListeners(), navigation: chrome.webNavigation.onCommitted.hasListeners() }));
  assert(result.listeners.request && result.listeners.navigation, 'Browser listeners not installed');
  const page = await context.newPage();
  await page.goto(`http://127.0.0.1:${server.address().port}/?token=AUDIT_CANARY`);
  await page.locator('input[type=password]').fill('AUDIT_CANARY');
  await page.evaluate(() => {
    for (let i = 0; i < 20; i++) {
      const field = document.createElement('input'); field.autocomplete = 'one-time-code';
      document.querySelector('form').append(field);
    }
    document.querySelector('form').action = 'http://localhost:' + location.port + '/changed?token=AUDIT_CANARY';
    history.pushState({}, '', '/history?token=AUDIT_CANARY');
    void fetch('/sink', { method: 'POST' });
  });
  const read = () => sw.evaluate(() => chrome.storage.session.get(null));
  const state = await until(async () => {
    const states = Object.values(await read());
    return states.find(s => s.events?.filter(e => e.event_type === 'FIELD_DISCOVERED' && e.sensitive_type === 'OTP').length === 21 && s.pending.length === 0 && s.events.some(e => e.event_type === 'REQUEST_OBSERVED' && e.request_type === 'xmlhttprequest'));
  });
  const events = state.events;
  assert.equal(new Set(events.map(e => e.event_seq)).size, events.length);
  assert(!JSON.stringify(events).includes('AUDIT_CANARY'));
  assert(events.some(e => e.frame_id !== 0 && e.sensitive_type === 'EMAIL'));
  assert(events.some(e => e.frame_id !== 0 && e.sensitive_type === 'PHONE' && e.frame_origin === null), 'Opaque frame origin was promoted to its URL origin');
  assert(events.some(e => e.event_type === 'SENSITIVE_INTERACTION' && e.interaction_type === 'input'));
  assert(events.some(e => e.event_type === 'FORM_TARGET_OBSERVED' && e.target_origin?.includes('localhost')));
  assert(events.some(e => e.event_type === 'REQUEST_OBSERVED' && e.request_type === 'xmlhttprequest'));
  assert(events.some(e => e.event_type === 'REDIRECT_OBSERVED'));
  assert(events.some(e => e.event_type === 'HISTORY_UPDATED'));
  const legacy = await until(() => legacyPayloads.findLast(p => legacyReceipts.has(p.collectionId) && p.requestedDataTypes?.includes('PASSWORD') && p.requestedDataTypes?.includes('OTP')));
  assert(!JSON.stringify(legacyPayloads).includes('AUDIT_CANARY'), 'Legacy transport leaked test canary');
  const python = spawnSync('python', ['-c', `
import json, sys
from backend.database import db_instance
with db_instance.get_connection() as conn:
    rows=conn.execute('SELECT event FROM events_sanitized WHERE session_id = %s ORDER BY event_seq', (sys.argv[1],)).fetchall()
    events=[r[0] for r in rows]
    assert len(events)==int(sys.argv[2]), (len(events),sys.argv[2])
    assert 'AUDIT_CANARY' not in json.dumps(events)
    assert len({e['event_seq'] for e in events})==len(events)
    row=conn.execute('SELECT requested_data_types, threat_level, model_score, policy_action FROM observations WHERE collection_id = %s', (sys.argv[3],)).fetchone()
    assert row is not None, 'Exact legacy collection missing'
    assert 'PASSWORD' in row[0] and 'OTP' in row[0]
    assert row[1] and row[2] is not None and row[3]
    print(json.dumps({'stored_events':len(events),'privacy_canary_absent':True,'legacy_collection_id':sys.argv[3], 'legacy_pipeline_stored':True}))
`, state.session_id, String(events.length), legacy.collectionId], { encoding: 'utf8', windowsHide: true });
  assert.equal(python.status, 0, python.stderr || python.stdout);
  // Terminate the actual MV3 worker through CDP, then trigger a fresh DOM event.
  const cdp = await context.newCDPSession(page);
  await cdp.send('ServiceWorker.enable');
  const workers = [];
  cdp.on('ServiceWorker.workerVersionUpdated', event => workers.push(...event.versions));
  await cdp.send('ServiceWorker.disable'); await cdp.send('ServiceWorker.enable');
  await until(() => workers.find(w => w.scriptURL === sw.url() && w.runningStatus === 'running'));
  const worker = workers.find(w => w.scriptURL === sw.url() && w.runningStatus === 'running');
  await cdp.send('ServiceWorker.stopWorker', { versionId: worker.versionId });
  await page.evaluate(() => { const field = document.createElement('input'); field.type = 'password'; document.body.append(field); });
  // Reacquire through context: Playwright versions differ in worker-handle restart behavior.
  const restored = await until(async () => {
    try {
      const current = context.serviceWorkers().find(w => w.url() === sw.url()) || sw;
      const states = await current.evaluate(() => chrome.storage.session.get(null));
      return Object.values(states).find(s => s.session_id === state.session_id && s.next_seq > state.next_seq && s.pending.length === 0);
    } catch { return false; }
  });
  assert(restored.events.some(e => e.event_seq > state.events.at(-1).event_seq));
  // Native submitter override semantics; prevent the test page from navigating.
  await page.evaluate(() => {
    const form = document.querySelector('form');
    const button = document.createElement('button');
    button.setAttribute('formaction', ''); form.append(button);
    form.addEventListener('submit', event => event.preventDefault(), { once: true });
    form.requestSubmit(button);
  });
  const afterSubmit = await until(async () => {
    const current = context.serviceWorkers().find(w => w.url() === sw.url()) || sw;
    const states = Object.values(await current.evaluate(() => chrome.storage.session.get(null)));
    return states.find(s => s.events?.some(e => e.interaction_type === 'submit') && s.pending.length === 0);
  });
  assert.equal(afterSubmit.events.findLast(e => e.interaction_type === 'submit').target_origin, new URL(page.url()).origin);
  result = { ...result, status: 'PASS', browser: context.browser().version(), node: process.version,
    otp_discoveries: 21, inserted_otp_fields: 20, initial_orphan_otp: 1, events_before_restart: events.length,
    events_after_restart: restored.events.length, session_preserved: true, privacy_canary_absent: true, empty_submitter_action: 'PASS',
    database: JSON.parse(python.stdout.trim()), events: restored.events,
    limits: 'Controlled loopback fixture only; does not establish detection quality, calibration, comprehensive privacy, or generalization.' };
} catch (error) {
  result.error = error.message;
  if (context) {
    const sw = context.serviceWorkers()[0];
    try { result.debug_state = await sw?.evaluate(() => chrome.storage.session.get(null)); } catch {}
  }
  process.exitCode = 1;
} finally {
  await context?.close();
  if (server.listening) await new Promise(r => server.close(r));
  backend.kill();
  // Historical evidence is immutable; current verification is an ordinary test artifact.
  mkdirSync('.runtime', { recursive: true });
  writeFileSync(process.env.CAPSTONE_VERIFY_OUTPUT || '.runtime/tsfeg-verification.json', JSON.stringify(result, null, 2));
  console.log(JSON.stringify({ status: result.status, error: result.error, events: result.events_before_restart, browser: result.browser }));
}
