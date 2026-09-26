import { createHash } from 'node:crypto';
import { createServer } from 'node:http';
import {
  existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync, mkdirSync,
} from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { createInterface } from 'node:readline';
import { chromium } from '@playwright/test';

const EPISODE_SCHEMA = 'stage-b-event-episodes-1';
const COLLECTOR_VERSION = 'stage-c-memory-replay-1';
const PLAN_SCHEMA = 'stage-c-memory-replay-plan-1';
const LOOPBACK_HOSTS = new Set(['127.0.0.1', 'localhost', '::1']);
const ALLOWED_EVENT_FIELDS = new Set([
  'event_type', 'sensitive_type', 'field_id', 'form_id', 'frame_origin',
  'target_origin', 'destination_origin', 'initiator_origin', 'request_type',
  'interaction_type', 'page_purpose', 'purpose_source', 'timestamp_ms',
  'schema_version', 'evidence_status', 'analysis_version', 'model_version',
  'policy_version', 'session_id', 'tab_id', 'document_id', 'frame_id',
  'parent_frame_id', 'event_seq', 'received_ms', 'trust', 'confidence',
]);

function parseArgs(argv) {
  const args = { plan: null, output: null, dist: 'dist', headless: true };
  for (let i = 0; i < argv.length; i++) {
    const value = argv[i];
    if (value === '--plan') args.plan = argv[++i];
    else if (value === '--output') args.output = argv[++i];
    else if (value === '--dist') args.dist = argv[++i];
    else if (value === '--headed') args.headless = false;
    else throw new Error(`Unknown argument: ${value}`);
  }
  for (const key of ['plan', 'output']) {
    if (!args[key]) throw new Error(`Missing --${key}`);
  }
  return args;
}

function canonicalJson(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
}

function sha256Text(value) {
  return createHash('sha256').update(value).digest('hex');
}

function sha256Buffer(value) {
  return createHash('sha256').update(value).digest('hex');
}

function sha256File(path) {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

function closedSanitizedEvents(events) {
  if (!Array.isArray(events) || events.length === 0) {
    throw new Error('No sanitized typed events were collected');
  }
  const seen = new Set();
  for (const event of events) {
    if (!event || typeof event !== 'object' || Array.isArray(event)) {
      throw new Error('Invalid typed event');
    }
    const unexpected = Object.keys(event).filter(key => !ALLOWED_EVENT_FIELDS.has(key));
    if (unexpected.length) {
      throw new Error(`Unexpected typed event fields: ${unexpected.join(', ')}`);
    }
    if (!Number.isSafeInteger(event.event_seq) || event.event_seq <= 0 || seen.has(event.event_seq)) {
      throw new Error('Invalid or duplicate event sequence');
    }
    seen.add(event.event_seq);
  }
  return [...events].sort((a, b) => a.event_seq - b.event_seq);
}

function validatePlan(plan) {
  if (!plan || typeof plan !== 'object' || Array.isArray(plan)) {
    throw new Error('memory replay plan must be an object');
  }
  const expectedRoot = new Set(['schema_version', 'plan_id', 'items']);
  const extraRoot = Object.keys(plan).filter(key => !expectedRoot.has(key));
  if (extraRoot.length || plan.schema_version !== PLAN_SCHEMA ||
      typeof plan.plan_id !== 'string' || !plan.plan_id) {
    throw new Error('invalid memory replay plan');
  }
  if (!Array.isArray(plan.items) || plan.items.length === 0 || plan.items.length > 512) {
    throw new Error('memory replay plan item count invalid');
  }
  const seen = new Set();
  for (const item of plan.items) {
    if (!item || typeof item !== 'object' || Array.isArray(item)) {
      throw new Error('invalid memory replay item');
    }
    const expected = new Set(['sample_id', 'ground_truth', 'artifact_sha256', 'wait_ms']);
    const extra = Object.keys(item).filter(key => !expected.has(key));
    if (extra.length) throw new Error(`unexpected memory replay item fields: ${extra.join(', ')}`);
    if (typeof item.sample_id !== 'string' || !item.sample_id || seen.has(item.sample_id)) {
      throw new Error('invalid or duplicate sample_id');
    }
    seen.add(item.sample_id);
    if (![0, 1].includes(item.ground_truth)) throw new Error('invalid ground_truth');
    if (typeof item.artifact_sha256 !== 'string' ||
        !/^[0-9a-f]{64}$/.test(item.artifact_sha256)) {
      throw new Error('invalid artifact_sha256');
    }
    if (!Number.isSafeInteger(item.wait_ms) || item.wait_ms < 250 || item.wait_ms > 10000) {
      throw new Error('invalid wait_ms');
    }
  }
  return plan;
}

async function startReplayServer(plan) {
  let active = null;
  const server = createServer((request, response) => {
    try {
      const url = new URL(request.url || '/', 'http://127.0.0.1');
      const match = /^\/sample\/([a-f0-9]{32})\/?$/.exec(url.pathname);
      if (!match || !active || match[1] !== active.token) {
        response.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' });
        response.end('Not found');
        return;
      }
      if (!['GET', 'HEAD'].includes(request.method || 'GET')) {
        response.writeHead(405, { allow: 'GET, HEAD' });
        response.end();
        return;
      }
      response.setHeader('content-type', 'text/html; charset=utf-8');
      response.setHeader('x-content-type-options', 'nosniff');
      response.setHeader('cache-control', 'no-store, max-age=0');
      response.setHeader('pragma', 'no-cache');
      response.setHeader('referrer-policy', 'no-referrer');
      response.setHeader(
        'content-security-policy',
        [
          "default-src 'none'",
          "script-src 'none'",
          "connect-src 'none'",
          "frame-src 'none'",
          "child-src 'none'",
          "object-src 'none'",
          "form-action 'none'",
          "base-uri 'none'",
          "img-src data: blob:",
          "style-src 'unsafe-inline'",
          "font-src data:",
        ].join('; ')
      );
      response.writeHead(200);
      if (request.method !== 'HEAD') response.end(active.html);
      else response.end();
    } catch {
      response.writeHead(500, { 'content-type': 'text/plain; charset=utf-8' });
      response.end('Replay error');
    }
  });

  await new Promise((resolvePromise, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolvePromise);
  });
  const address = server.address();
  if (!address || typeof address === 'string') {
    throw new Error('Replay server address unavailable');
  }

  return {
    server,
    port: address.port,
    activate(item, html) {
      if (active) throw new Error('memory replay sample already active');
      active = {
        sample_id: item.sample_id,
        token: sha256Text(`${plan.plan_id}\0${item.sample_id}`).slice(0, 32),
        html,
      };
    },
    deactivate() {
      if (active?.html) active.html.fill(0);
      active = null;
    },
    tokenFor(sampleId) {
      return sha256Text(`${plan.plan_id}\0${sampleId}`).slice(0, 32);
    },
  };
}

async function waitForQueueDrain(
  worker,
  tabId,
  {
    totalTimeoutMs = 90_000,
    stallTimeoutMs = 30_000,
    pollMs = 100,
  } = {},
) {
  const start = Date.now();
  let lastProgressAt = start;
  let lastQueued = null;
  let lastStatus = null;

  while (Date.now() - start < totalTimeoutMs) {
    const status = await worker.evaluate(async id => {
      try {
        return await chrome.tabs.sendMessage(id, { type: 'GET_TYPED_EVENT_STATUS' });
      } catch {
        return null;
      }
    }, tabId);

    const now = Date.now();
    if (status && Number.isSafeInteger(status.queued_events) && status.queued_events >= 0) {
      lastStatus = status;
      if (Number.isSafeInteger(status.dropped_events) && status.dropped_events > 0) {
        throw new Error(`typed event queue dropped events: dropped_events=${status.dropped_events}`);
      }
      if (status.queued_events === 0) return status;
      if (lastQueued === null || status.queued_events < lastQueued) lastProgressAt = now;
      lastQueued = status.queued_events;
      if (now - lastProgressAt >= stallTimeoutMs) {
        throw new Error(
          `typed event queue stalled: queued_events=${status.queued_events}, ` +
          `delivery_errors=${Number(status.delivery_errors || 0)}, ` +
          `last_delivery_error_code=${String(status.last_delivery_error_code || 'NONE')}, ` +
          `stall_ms=${now - lastProgressAt}`,
        );
      }
    } else if (now - lastProgressAt >= stallTimeoutMs) {
      throw new Error(`typed event queue status unavailable for ${now - lastProgressAt} ms`);
    }
    await new Promise(resolveDelay => setTimeout(resolveDelay, pollMs));
  }
  throw new Error(
    `typed event queue did not drain within ${totalTimeoutMs} ms; ` +
    `last_status=${JSON.stringify(lastStatus)}`,
  );
}

async function readTabState(worker, pageUrl) {
  return worker.evaluate(async url => {
    const tabs = await chrome.tabs.query({});
    const tab = tabs.find(candidate => candidate.url === url) ??
      (await chrome.tabs.query({ active: true, currentWindow: true }))[0];
    if (!tab?.id) return null;
    const key = `tsfeg:${tab.id}`;
    const state = (await chrome.storage.session.get(key))[key];
    return { tabId: tab.id, state };
  }, pageUrl);
}

async function chromeSessionReset(worker) {
  return worker.evaluate(async () => {
    await chrome.storage.session.clear();
    return chrome.storage.session.getBytesInUse(null).catch(() => null);
  });
}

async function clearReplaySessionState(worker) {
  return worker.evaluate(async () => {
    await new Promise(resolveDelay => setTimeout(resolveDelay, 750));
    const beforeBytes = await chrome.storage.session.getBytesInUse(null).catch(() => null);
    await chrome.storage.session.clear();
    const afterBytes = await chrome.storage.session.getBytesInUse(null).catch(() => null);
    return { beforeBytes, afterBytes };
  });
}

async function collectItem(context, worker, replay, item) {
  const page = await context.newPage();
  page.on('dialog', dialog => void dialog.dismiss());
  page.on('download', download => void download.cancel());
  page.on('popup', popup => void popup.close());

  let externalRequestsBlocked = 0;
  await page.route('**/*', async route => {
    const request = route.request();
    const url = new URL(request.url());
    const method = request.method().toUpperCase();
    const isReplay = LOOPBACK_HOSTS.has(url.hostname) && Number(url.port) === replay.port;
    if (!isReplay || !['GET', 'HEAD'].includes(method)) {
      externalRequestsBlocked++;
      await route.abort('blockedbyclient');
      return;
    }
    await route.continue();
  });

  try {
    const token = replay.tokenFor(item.sample_id);
    const target = `http://127.0.0.1:${replay.port}/sample/${token}/`;
    await page.goto(target, { waitUntil: 'domcontentloaded', timeout: 15_000 });
    await page.waitForTimeout(item.wait_ms);
    await page.bringToFront();

    const first = await readTabState(worker, page.url());
    if (!first?.tabId) throw new Error('unable to resolve replay browser tab');
    await waitForQueueDrain(worker, first.tabId);

    const snapshot = await readTabState(worker, page.url());
    if (!snapshot?.state) throw new Error('typed event recorder state unavailable');
    const state = snapshot.state;
    const droppedEvents = Number(state.dropped || 0) + Number(state.content_dropped || 0);
    const deliveryErrors = Number(state.content_delivery_errors || 0);
    if (droppedEvents !== 0) throw new Error('replay episode contains dropped events');

    const events = closedSanitizedEvents(state.events);
    return {
      sample_id: item.sample_id,
      events_sha256: sha256Text(canonicalJson(events)),
      collection_provenance: 'ARCHIVED_BROWSER_REPLAY',
      observation_horizon_ms: item.wait_ms,
      dropped_events: droppedEvents,
      delivery_errors: deliveryErrors,
      external_requests_blocked: externalRequestsBlocked,
      events,
    };
  } finally {
    await page.close().catch(() => {});
    await clearReplaySessionState(worker).catch(error => {
      console.warn(
        '[Stage C memory replay] session cleanup failed:',
        error instanceof Error ? error.message : String(error),
      );
    });
  }
}

function decodeEnvelope(line, item) {
  let value;
  try {
    value = JSON.parse(line);
  } catch {
    throw new Error(`invalid memory stream JSON for ${item.sample_id}`);
  }
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).sort().join(',') !== 'html_base64,sample_id' ||
      value.sample_id !== item.sample_id ||
      typeof value.html_base64 !== 'string' || !value.html_base64) {
    throw new Error(`memory stream identity/schema mismatch for ${item.sample_id}`);
  }
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(value.html_base64)) {
    throw new Error(`invalid base64 payload for ${item.sample_id}`);
  }
  const html = Buffer.from(value.html_base64, 'base64');
  if (sha256Buffer(html) !== item.artifact_sha256) {
    html.fill(0);
    throw new Error(`memory stream artifact SHA-256 mismatch for ${item.sample_id}`);
  }
  return html;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const dist = resolve(args.dist);
  if (!existsSync(join(dist, 'manifest.json'))) {
    throw new Error('Built extension not found. Run npm.cmd run build first.');
  }

  const planPath = resolve(args.plan);
  const plan = validatePlan(JSON.parse(readFileSync(planPath, 'utf8')));
  const tempRoot = mkdtempSync(join(tmpdir(), 'capstone-stage-c-memory-replay-'));
  const userDataDir = join(tempRoot, 'chromium-profile');
  const replay = await startReplayServer(plan);

  const context = await chromium.launchPersistentContext(userDataDir, {
    channel: 'chromium',
    headless: args.headless,
    acceptDownloads: false,
    args: [
      `--disable-extensions-except=${dist}`,
      `--load-extension=${dist}`,
      '--no-sandbox',
      '--disable-background-networking',
      '--disable-component-update',
      '--disable-sync',
      '--metrics-recording-only',
      '--no-first-run',
      '--disk-cache-size=1',
      '--media-cache-size=1',
    ],
  });

  const episodes = [];
  const failures = [];
  const rl = createInterface({ input: process.stdin, crlfDelay: Infinity });
  const iterator = rl[Symbol.asyncIterator]();

  try {
    const worker = context.serviceWorkers()[0] || await context.waitForEvent('serviceworker');
    await chromeSessionReset(worker);

    for (const item of plan.items) {
      const next = await iterator.next();
      if (next.done) throw new Error(`memory stream ended before ${item.sample_id}`);
      let html = null;
      try {
        html = decodeEnvelope(next.value, item);
        replay.activate(item, html);
        episodes.push(await collectItem(context, worker, replay, item));
      } catch (error) {
        console.error(`[Stage C memory replay] ${item.sample_id}:`, error);
        failures.push({
          sample_id: item.sample_id,
          code: 'MEMORY_REPLAY_FAILED',
          message: 'Replay failed; inspect local console output for details.',
        });
      } finally {
        replay.deactivate();
        if (html) html.fill(0);
      }
    }

    const extra = await iterator.next();
    if (!extra.done && String(extra.value).trim()) {
      throw new Error('memory stream contains more samples than the frozen plan');
    }
  } finally {
    rl.close();
    await context.close().catch(() => {});
    await new Promise(resolvePromise => replay.server.close(resolvePromise));
    rmSync(userDataDir, { recursive: true, force: true });
  }

  const output = {
    schema_version: EPISODE_SCHEMA,
    collector_version: COLLECTOR_VERSION,
    plan_sha256: sha256File(planPath),
    collected_at: new Date().toISOString(),
    source_hashes: {
      collector_js_sha256: sha256File(join(dist, 'collector.js')),
      service_worker_js_sha256: sha256File(join(dist, 'service-worker.js')),
      tsfeg_source_sha256: sha256File(resolve('browser-extension/src/core/tsfeg.ts')),
    },
    safety_policy: {
      archived_local_files_only: true,
      replay_origin_loopback_only: true,
      page_scripts_disabled_by_csp: true,
      form_submission_disabled_by_csp: true,
      frames_and_objects_disabled_by_csp: true,
      external_network_requests_aborted: true,
      interaction_or_submission_automation: false,
      raw_html_persisted_in_episode_output: false,
      target_urls_persisted: false,
      raw_html_materialized_to_disk: false,
      raw_html_received_via_stdin_memory_stream: true,
      browser_response_cache_control_no_store: true,
    },
    episodes,
    failures,
  };

  mkdirSync(dirname(resolve(args.output)), { recursive: true });
  writeFileSync(resolve(args.output), `${JSON.stringify(output, null, 2)}\n`, 'utf8');
  rmSync(tempRoot, { recursive: true, force: true });

  if (failures.length) {
    process.exitCode = 2;
  } else {
    console.log(JSON.stringify({
      status: 'PASS',
      episodes: episodes.length,
      collection_provenance: 'ARCHIVED_BROWSER_REPLAY',
      raw_html_materialized_to_disk: false,
      output: resolve(args.output),
    }));
  }
}

main().catch(error => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
