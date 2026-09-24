import { chromium } from '@playwright/test';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { tmpdir } from 'node:os';

const COLLECTOR_VERSION = 'stage-b-passive-collector-1';
const EPISODE_SCHEMA = 'stage-b-event-episodes-1';
const ALLOWED_EVENT_FIELDS = new Set([
  'event_type', 'sensitive_type', 'field_id', 'form_id', 'frame_origin',
  'target_origin', 'destination_origin', 'initiator_origin', 'request_type',
  'interaction_type', 'page_purpose', 'purpose_source', 'timestamp_ms',
  'schema_version', 'evidence_status', 'analysis_version', 'model_version',
  'policy_version', 'session_id', 'tab_id', 'document_id', 'frame_id',
  'parent_frame_id', 'event_seq', 'received_ms', 'trust', 'confidence',
]);

function parseArgs(argv) {
  const args = { allowLivePassive: false, headless: true };
  for (let i = 0; i < argv.length; i++) {
    const token = argv[i];
    if (token === '--allow-live-passive') {
      args.allowLivePassive = true;
      continue;
    }
    if (token === '--headless') {
      const value = argv[++i];
      if (!['true', 'false'].includes(value)) throw new Error('--headless expects true or false');
      args.headless = value === 'true';
      continue;
    }
    if (['--plan', '--splits', '--output', '--dist'].includes(token)) {
      const value = argv[++i];
      if (!value) throw new Error(`${token} requires a value`);
      args[token.slice(2)] = value;
      continue;
    }
    throw new Error(`Unknown argument: ${token}`);
  }
  for (const required of ['plan', 'splits', 'output']) {
    if (!args[required]) throw new Error(`--${required} is required`);
  }
  args.dist ??= 'dist';
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
  if (!Array.isArray(events) || events.length === 0) throw new Error('No sanitized typed events were collected');
  for (const event of events) {
    if (!event || typeof event !== 'object' || Array.isArray(event)) throw new Error('Invalid typed event');
    const unexpected = Object.keys(event).filter(key => !ALLOWED_EVENT_FIELDS.has(key));
    if (unexpected.length) throw new Error(`Unexpected typed event fields: ${unexpected.join(', ')}`);
    if (!Number.isSafeInteger(event.event_seq) || event.event_seq <= 0) throw new Error('Invalid event sequence');
  }
  return [...events].sort((a, b) => a.event_seq - b.event_seq);
}

function validatePlanWithPython(args, normalizedPath) {
  const python = process.env.PYTHON || 'python';
  const cli = [
    '-m', 'ml.data.validate_stage_b_acquisition_plan',
    '--plan', resolve(args.plan),
    '--splits', resolve(args.splits),
    '--normalized-output', normalizedPath,
  ];
  if (args.allowLivePassive) cli.push('--allow-live-passive');
  const result = spawnSync(python, cli, {
    cwd: process.cwd(),
    encoding: 'utf8',
    windowsHide: true,
  });
  if (result.status !== 0) {
    const details = (result.stderr || result.stdout || 'acquisition plan validation failed').trim();
    throw new Error(details);
  }
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

async function collectItem(context, worker, item) {
  const page = await context.newPage();
  page.on('dialog', dialog => void dialog.dismiss());
  page.on('download', download => void download.cancel());
  page.on('popup', popup => void popup.close());

  if (item.mode === 'LIVE_PASSIVE') {
    await page.route('**/*', async route => {
      const request = route.request();
      const method = request.method().toUpperCase();
      const resourceType = request.resourceType();
      if (!['GET', 'HEAD', 'OPTIONS'].includes(method) || ['media', 'object', 'websocket', 'eventsource'].includes(resourceType)) {
        await route.abort();
        return;
      }
      await route.continue();
    });
  }

  try {
    await page.goto(item.target_url, {
      waitUntil: 'domcontentloaded',
      timeout: 15_000,
    });
    await page.waitForTimeout(item.wait_ms);
    await page.bringToFront();

    const first = await readTabState(worker, page.url());
    if (!first?.tabId) throw new Error('unable to resolve browser tab');
    await waitForQueueDrain(worker, first.tabId);

    const snapshot = await readTabState(worker, page.url());
    if (!snapshot?.state) throw new Error('typed event recorder state unavailable');
    const state = snapshot.state;
    const droppedEvents = Number(state.dropped || 0) + Number(state.content_dropped || 0);
    const deliveryErrors = Number(state.content_delivery_errors || 0);
    if (droppedEvents !== 0) throw new Error('episode contains dropped events');

    const events = closedSanitizedEvents(state.events);
    return {
      sample_id: item.sample_id,
      events_sha256: sha256Text(canonicalJson(events)),
      collection_provenance: item.collection_provenance,
      observation_horizon_ms: item.wait_ms,
      dropped_events: droppedEvents,
      delivery_errors: deliveryErrors,
      events,
    };
  } finally {
    await page.close().catch(() => {});
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const dist = resolve(args.dist);
  if (!existsSync(join(dist, 'manifest.json'))) throw new Error('Built extension not found. Run npm.cmd run build first.');

  const tempRoot = mkdtempSync(join(tmpdir(), 'capstone-stage-b-acq-'));
  const normalizedPlanPath = join(tempRoot, 'normalized-plan.json');
  const userDataDir = join(tempRoot, 'chromium-profile');
  validatePlanWithPython(args, normalizedPlanPath);
  const plan = JSON.parse(readFileSync(normalizedPlanPath, 'utf8'));

  const context = await chromium.launchPersistentContext(userDataDir, {
    channel: 'chromium',
    headless: args.headless,
    acceptDownloads: false,
    args: [
      `--disable-extensions-except=${dist}`,
      `--load-extension=${dist}`,
      '--no-sandbox',
    ],
  });

  const episodes = [];
  const failures = [];
  try {
    const worker = context.serviceWorkers()[0] || await context.waitForEvent('serviceworker');
    for (const item of plan.items) {
      try {
        episodes.push(await collectItem(context, worker, item));
      } catch (error) {
        console.error(`[Stage B acquisition] ${item.sample_id}:`, error);
        failures.push({
          sample_id: item.sample_id,
          code: 'COLLECTION_FAILED',
          message: 'Collection failed; inspect local console output for details.',
        });
      }
    }
  } finally {
    await context.close().catch(() => {});
    rmSync(userDataDir, { recursive: true, force: true });
  }

  const artifactPaths = {
    collector_js_sha256: join(dist, 'collector.js'),
    service_worker_js_sha256: join(dist, 'service-worker.js'),
    tsfeg_source_sha256: resolve('browser-extension/src/core/tsfeg.ts'),
  };
  const sourceHashes = {};
  for (const [name, path] of Object.entries(artifactPaths)) {
    sourceHashes[name] = existsSync(path) ? sha256File(path) : null;
  }

  const output = {
    schema_version: EPISODE_SCHEMA,
    collector_version: COLLECTOR_VERSION,
    plan_sha256: sha256File(resolve(args.plan)),
    collected_at: new Date().toISOString(),
    source_hashes: sourceHashes,
    safety_policy: {
      controlled_local_loopback_only: true,
      live_passive_requires_explicit_flag: true,
      live_non_get_head_options_requests_blocked: true,
      interaction_or_submission_automation: false,
      target_urls_persisted: false,
    },
    episodes,
    failures,
  };

  mkdirSync(dirname(resolve(args.output)), { recursive: true });
  writeFileSync(resolve(args.output), `${JSON.stringify(output, null, 2)}\n`, 'utf8');
  rmSync(tempRoot, { recursive: true, force: true });

  if (failures.length) process.exitCode = 2;
  else console.log(JSON.stringify({ status: 'PASS', episodes: episodes.length, output: resolve(args.output) }));
}

main().catch(error => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
