import { test, expect, storedCollection } from './fixtures';
import { writeFileSync, readFileSync, mkdirSync } from 'node:fs';
import { createHash } from 'node:crypto';
test('static collection reaches PostgreSQL under its exact collection ID', async ({ page }) => {
  await page.goto('http://127.0.0.1:41731/suspicious');
  await expect.poll(() => page.getAttribute('html', 'data-capstone-evidence-handoff')).toBe('send_ok');
  const meta = JSON.parse((await page.getAttribute('html', 'data-capstone-evidence-meta'))!);
  await expect.poll(() => storedCollection(meta.collectionId)).not.toBeNull();
  const row = storedCollection(meta.collectionId);
  expect(row.form_count).toBeGreaterThanOrEqual(1);
  expect(row.input_count).toBeGreaterThanOrEqual(3);
  expect(row.categories).toEqual(expect.arrayContaining(['EMAIL', 'PASSWORD', 'OTP']));
});

test('collect authored event episodes with identical flat and relationship inputs', async ({ context }) => {
  test.setTimeout(180000);
  const worker = context.serviceWorkers()[0] || await context.waitForEvent('serviceworker');
  const control = await context.newPage();
  await control.goto(`chrome-extension://${worker.url().split('/')[2]}/src/ui/popup.html`);
  const episodes: unknown[] = [];
  for (let layout = 0; layout < 2; layout++) for (let family = 1; family <= 6; family++) for (const label of [0, 1]) {
    const page = await context.newPage();
    await page.goto(`http://127.0.0.1:41731/research?family=${family}&label=${label}&layout=${layout}`);
    await page.evaluate(async () => { await (window as any).runScenario(); });
    const tab = await worker.evaluate(async url => (await chrome.tabs.query({})).find(t => t.url === url)!.id!, page.url());
    // Fixed collection horizon, identical for both representations and both labels.
    await page.waitForTimeout(500);
    await expect.poll(async () => (await worker.evaluate(id => chrome.tabs.sendMessage(id, { type: 'GET_TYPED_EVENT_STATUS' }), tab)).queued_events).toBe(0);
    const read = () => control.evaluate(tabId => chrome.runtime.sendMessage({ type: 'EXPORT_TSFEG', tabId }), tab);
    await expect.poll(async () => { const s = await read(); return { types: [...new Set(s.events?.map((e: any) => e.event_type))], pending: s.pending?.length }; }, { timeout: 15000 }).toMatchObject({ types: expect.arrayContaining(['SENSITIVE_INTERACTION']), pending: 0 });
    const state = await read();
    expect(state.dropped + state.content_dropped).toBe(0);
    const serialized = JSON.stringify(state.events);
    episodes.push({ provenance: 'CONTROLLED', family: String(family), template_group: String(family),
      brand_group: null, domain_group: 'loopback', label, layout, collected_at: Date.now(),
      session_id: state.session_id, observation_horizon_ms: 500, events: state.events, representations: state.representations,
      events_sha256: createHash('sha256').update(serialized).digest('hex'), dropped: 0 });
    await page.close();
  }
  mkdirSync('.runtime', { recursive: true });
  writeFileSync('.runtime/event-dataset-latest.json', JSON.stringify({ protocol: 'implementation-shakedown-1',
    provenance: 'CONTROLLED', limitation: '24 authored episodes, six families, two layouts; no independent brands or domains.',
    source_hashes: Object.fromEntries(['dist/collector.js', 'dist/service-worker.js', 'scripts/manual-browser-acceptance-server.mjs'].map(p => [p, createHash('sha256').update(readFileSync(p)).digest('hex')])), episodes }, null, 2));
});
