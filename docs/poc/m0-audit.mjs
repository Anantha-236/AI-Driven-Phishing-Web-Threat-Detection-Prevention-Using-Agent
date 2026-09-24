// Audit only: executes existing M1 code without changing application sources.
// Usage: node docs/poc/m0-audit.mjs <M1 directory> [--browser]
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import crypto from 'node:crypto';
import { createRequire } from 'node:module';
import { createServer } from 'node:http';
const root = path.resolve(process.argv[2]);
const source = name => fs.readFileSync(path.join(root, 'extension/src', name), 'utf8');
const store = {};
const context = vm.createContext({ URL, crypto, structuredClone, console, fetch: async () => ({ ok: true }), chrome: {
  storage: { session: {
    get: async key => structuredClone({ [key]: store[key] }),
    set: async value => Object.assign(store, structuredClone(value)),
  } },
  runtime: { onMessage: { addListener() {} } },
  webRequest: { onBeforeRequest: { addListener() {} } },
  webNavigation: { onCommitted: { addListener() {} } },
} });
context.importScripts = (...names) => names.forEach(name => vm.runInContext(source(name), context));
vm.runInContext(source('service_worker.js'), context);
const event = (seq, type, sensitive = null) => ({ session_id: 'audit', tab_id: 1, document_id: 'doc', frame_id: 0,
  event_seq: seq, timestamp_ms: seq * 100, event_type: type, sensitive_type: sensitive,
  frame_origin: 'https://example.test', trust: 'ISOLATED_CONTENT_SCRIPT' });
const burst = Array.from({ length: 20 }, (_, i) => event(i + 1, 'FIELD_DISCOVERED', 'PASSWORD'));
await Promise.all(burst.map(ev => context.appendEvent(ev)));
const recorded = Object.values(store)[0].events;
const graph = context.TSFEG.buildGraph([event(1, 'FIELD_DISCOVERED', 'PASSWORD'), event(2, 'DOM_MUTATION'), event(3, 'FIELD_DISCOVERED', 'PASSWORD')]);
const precedence = graph.edges.filter(e => e.type === 'PRECEDES');
const cycle = precedence.some(a => precedence.some(b => a.from === b.to && a.to === b.from));
const repeated = context.TSFEG.buildGraph([event(1, 'SENSITIVE_INTERACTION', 'PASSWORD'), { ...event(1, 'SENSITIVE_INTERACTION', 'PASSWORD'), session_id: 'other' }]);
const forward = [event(1, 'SENSITIVE_INTERACTION', 'PASSWORD'), { ...event(2, 'REQUEST_OBSERVED'), destination_origin: 'https://sink.test' }];
const reverse = [{ ...forward[1], event_seq: 1, timestamp_ms: 100 }, { ...forward[0], event_seq: 2, timestamp_ms: 200 }];
assert.equal(context.TSFEG.buildFlatControl(forward).event_count, forward.length);
const result = {
  audit_time: new Date().toISOString(), node: process.version,
  source_hashes: Object.fromEntries(['shared.js', 'tsfeg.js', 'service_worker.js', 'content.js'].map(n => [n, crypto.createHash('sha256').update(source(n)).digest('hex')])),
  controlled_checks: {
    concurrent_append: { sent: burst.length, stored: recorded.length, status: recorded.length === burst.length ? 'PASS' : 'FAIL' },
    temporal_cycle: { found: cycle, status: cycle ? 'FAIL' : 'PASS' },
    session_isolation: { expected_interactions: 2, actual: repeated.nodes.filter(n => n.type === 'INTERACTION').length },
    flat_order_collision: JSON.stringify(context.TSFEG.buildFlatControl(forward)) === JSON.stringify(context.TSFEG.buildFlatControl(reverse)),
  },
};
if (process.argv.includes('--browser')) {
  const require = createRequire(path.join(process.cwd(), 'package.json'));
  const { chromium } = require('playwright');
  const server = createServer((_req, res) => {
    res.setHeader('Content-Type', 'text/html');
    res.end('<!doctype html><html><head><title>Controlled audit</title></head><body><form action="/submit"><input type="password"></form></body></html>');
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  let browserContext;
  try {
    const extension = path.join(root, 'extension');
    browserContext = await chromium.launchPersistentContext('', { channel: 'chromium', headless: true,
      args: [`--disable-extensions-except=${extension}`, `--load-extension=${extension}`] });
    const sw = browserContext.serviceWorkers()[0] || await browserContext.waitForEvent('serviceworker', { timeout: 15000 });
    const page = await browserContext.newPage();
    await page.goto(`http://127.0.0.1:${server.address().port}/`);
    await page.locator('input').focus();
    // Bounded settling time for this audit; no production timing assumption.
    await page.waitForTimeout(500);
    await page.evaluate(() => {
      document.querySelector('form').action = '/changed';
      for (let i = 0; i < 20; i++) {
        const input = document.createElement('input');
        input.autocomplete = 'one-time-code';
        document.querySelector('form').append(input);
      }
    });
    await page.waitForTimeout(1000);
    const state = await sw.evaluate(() => chrome.storage.session.get(null));
    const events = Object.values(state).flatMap(s => s.events || []);
    result.browser = {
      version: browserContext.browser().version(),
      event_counts: events.reduce((out, e) => { const key = `${e.event_type}:${e.sensitive_type || ''}`; out[key] = (out[key] || 0) + 1; return out; }, {}),
      expected_otp_discoveries: 20,
      actual_otp_discoveries: events.filter(e => e.event_type === 'FIELD_DISCOVERED' && e.sensitive_type === 'OTP').length,
      document_keys: Object.keys(state), events,
      limitations: 'One controlled page; no restart, backend ingestion, privacy canaries, iframe, or RQ1 quality validation.',
    };
  } finally {
    await browserContext?.close();
    await new Promise(resolve => server.close(resolve));
  }
}
console.log(JSON.stringify(result, null, 2));
if (result.controlled_checks.concurrent_append.status === 'FAIL' || cycle || (result.browser && result.browser.actual_otp_discoveries !== 20)) process.exitCode = 1;
