import { createHash } from 'node:crypto';
import { createServer } from 'node:http';
import {
  existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync, mkdirSync,
} from 'node:fs';
import { dirname, join, resolve, sep } from 'node:path';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';
import { chromium } from '@playwright/test';

const EPISODE_SCHEMA = 'stage-b-event-episodes-1';
const COLLECTOR_VERSION = 'stage-b-archive-replay-1';
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
  const args = {
    plan: null,
    archiveRoot: null,
    output: null,
    dist: 'dist',
    headless: true,
  };
  for (let i = 0; i < argv.length; i++) {
    const value = argv[i];
    if (value === '--plan') args.plan = argv[++i];
    else if (value === '--archive-root') args.archiveRoot = argv[++i];
    else if (value === '--output') args.output = argv[++i];
    else if (value === '--dist') args.dist = argv[++i];
    else if (value === '--headed') args.headless = false;
    else throw new Error(`Unknown argument: ${value}`);
  }
  for (const key of ['plan', 'archiveRoot', 'output']) {
    if (!args[key]) throw new Error(`Missing --${key === 'archiveRoot' ? 'archive-root' : key}`);
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

function sha256File(path) {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

function closedSanitizedEvents(events) {
  if (!Array.isArray(events) || events.length === 0) {
    throw new Error('No sanitized typed events were collected');
  }
  const seen = new Set();
  for (const event of events) {
    if (!event || typeof event !== 'object' || Array.isArray(event)) throw new Error('Invalid typed event');
    const unexpected = Object.keys(event).filter(key => !ALLOWED_EVENT_FIELDS.has(key));
    if (unexpected.length) throw new Error(`Unexpected typed event fields: ${unexpected.join(', ')}`);
    if (!Number.isSafeInteger(event.event_seq) || event.event_seq <= 0 || seen.has(event.event_seq)) {
      throw new Error('Invalid or duplicate event sequence');
    }
    seen.add(event.event_seq);
  }
  return [...events].sort((a, b) => a.event_seq - b.event_seq);
}

function validatePlan(args, normalizedPath) {
  const python = process.env.PYTHON || 'python';
  const result = spawnSync(python, [
    '-m', 'ml.data.validate_stage_b_archive_replay',
    '--plan', resolve(args.plan),
    '--archive-root', resolve(args.archiveRoot),
    '--normalized-output', normalizedPath,
  ], {
    cwd: process.cwd(),
    encoding: 'utf8',
    windowsHide: true,
  });
  if (result.status !== 0) {
    const details = (result.stderr || result.stdout || 'archive replay plan validation failed').trim();
    throw new Error(details);
  }
}

function safeFile(root, relative) {
  const rootPath = resolve(root);
  const candidate = resolve(rootPath, ...String(relative).split('/'));
  if (candidate !== rootPath && !candidate.startsWith(rootPath + sep)) {
    throw new Error('archive file escaped replay root');
  }
  return candidate;
}

async function startReplayServer(plan, archiveRoot) {
  const byToken = new Map();
  for (const item of plan.items) {
    const token = sha256Text(`${plan.plan_id}\0${item.sample_id}`).slice(0, 32);
    byToken.set(token, item);
  }

  const server = createServer((request, response) => {
    try {
      const url = new URL(request.url || '/', 'http://127.0.0.1');
      const match = /^\/sample\/([a-f0-9]{32})\/?$/.exec(url.pathname);
      if (!match || !byToken.has(match[1])) {
        response.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' });
        response.end('Not found');
        return;
      }
      if (!['GET', 'HEAD'].includes(request.method || 'GET')) {
        response.writeHead(405, { allow: 'GET, HEAD' });
        response.end();
        return;
      }

      const item = byToken.get(match[1]);
      const file = safeFile(archiveRoot, item.html_path);
      const html = readFileSync(file);

      response.setHeader('content-type', 'text/html; charset=utf-8');
      response.setHeader('x-content-type-options', 'nosniff');
      response.setHeader('cache-control', 'no-store');
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
      if (request.method !== 'HEAD') response.end(html);
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
  if (!address || typeof address === 'string') throw new Error('Replay server address unavailable');

  return {
    server,
    port: address.port,
    tokenFor(sampleId) {
      return sha256Text(`${plan.plan_id}\0${sampleId}`).slice(0, 32);
    },
  };
}

async function waitForQueueDrain(worker, tabId, timeoutMs = 8000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const status = await worker.evaluate(async id => {
      try {
        return await chrome.tabs.sendMessage(id, { type: 'GET_TYPED_EVENT_STATUS' });
      } catch {
        return null;
      }
    }, tabId);
    if (status?.queued_events === 0) return status;
    await new Promise(resolveDelay => setTimeout(resolveDelay, 100));
  }
  throw new Error('typed event queue did not drain');
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
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const dist = resolve(args.dist);
  if (!existsSync(join(dist, 'manifest.json'))) {
    throw new Error('Built extension not found. Run npm.cmd run build first.');
  }

  const tempRoot = mkdtempSync(join(tmpdir(), 'capstone-stage-b-archive-replay-'));
  const normalizedPlanPath = join(tempRoot, 'normalized-plan.json');
  const userDataDir = join(tempRoot, 'chromium-profile');
  validatePlan(args, normalizedPlanPath);
  const plan = JSON.parse(readFileSync(normalizedPlanPath, 'utf8'));
  const replay = await startReplayServer(plan, resolve(args.archiveRoot));

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
    ],
  });

  const episodes = [];
  const failures = [];
  try {
    const worker = context.serviceWorkers()[0] || await context.waitForEvent('serviceworker');
    for (const item of plan.items) {
      try {
        episodes.push(await collectItem(context, worker, replay, item));
      } catch (error) {
        console.error(`[Stage B archive replay] ${item.sample_id}:`, error);
        failures.push({
          sample_id: item.sample_id,
          code: 'ARCHIVE_REPLAY_FAILED',
          message: 'Replay failed; inspect local console output for details.',
        });
      }
    }
  } finally {
    await context.close().catch(() => {});
    await new Promise(resolvePromise => replay.server.close(resolvePromise));
    rmSync(userDataDir, { recursive: true, force: true });
  }

  const output = {
    schema_version: EPISODE_SCHEMA,
    collector_version: COLLECTOR_VERSION,
    plan_sha256: sha256File(resolve(args.plan)),
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
      output: resolve(args.output),
    }));
  }
}

main().catch(error => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
