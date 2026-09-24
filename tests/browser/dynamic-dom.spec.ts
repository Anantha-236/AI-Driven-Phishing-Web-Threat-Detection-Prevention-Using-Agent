import { test, expect, storedCollection } from './fixtures';
import { writeFileSync } from 'node:fs';
test('existing MutationObserver recollects inserted fields in shipped Chromium bundle', async ({ page }) => {
  await page.goto('http://127.0.0.1:41731/dynamic');
  await expect.poll(async () => {
    const value = await page.getAttribute('html', 'data-capstone-feature-meta');
    return value ? JSON.parse(value).has_otp_field : false;
  }, { timeout: 20000 }).toBe(true);
  await expect(page.locator('html')).toHaveAttribute('data-capstone-observer-observing', 'success');
  const meta = JSON.parse((await page.getAttribute('html', 'data-capstone-evidence-meta'))!);
  await expect.poll(() => storedCollection(meta.collectionId)).not.toBeNull();
  expect(storedCollection(meta.collectionId).categories).toEqual(expect.arrayContaining(['EMAIL', 'PASSWORD', 'OTP']));
});

test('measures controlled burst collection and reports retained evidence without loss', async ({ context, page }) => {
  const worker = context.serviceWorkers()[0] || await context.waitForEvent('serviceworker');
  await page.goto('http://127.0.0.1:41731/benign');
  const tab = await worker.evaluate(async url => (await chrome.tabs.query({})).find(t => t.url === url)!.id!, page.url());
  const cdp = await context.newCDPSession(page);
  await cdp.send('Performance.enable');
  const before = await cdp.send('Performance.getMetrics');
  const start = Date.now();
  await page.evaluate(async () => {
    for (let burst = 0; burst < 10; burst++) {
      for (let i = 0; i < 20; i++) {
        const field = document.createElement('input'); field.autocomplete = 'one-time-code'; document.querySelector('form')!.append(field);
      }
      await new Promise(resolve => setTimeout(resolve, 50));
    }
  });
  const read = () => worker.evaluate(async id => (await chrome.storage.session.get(`tsfeg:${id}`))[`tsfeg:${id}`], tab);
  await expect.poll(async () => { const state = await read(); return state?.events.filter((e: any) => e.event_type === 'FIELD_DISCOVERED' && e.sensitive_type === 'OTP').length === 200 && state.pending.length === 0; }, { timeout: 15000 }).toBe(true);
  const state = await read();
  expect(state.dropped + state.content_dropped).toBe(0);
  const after = await cdp.send('Performance.getMetrics');
  const names = ['JSHeapUsedSize', 'TaskDuration', 'ScriptDuration', 'Nodes'];
  const pick = (metrics: typeof before.metrics) => Object.fromEntries(metrics.filter(m => names.includes(m.name)).map(m => [m.name, m.value]));
  writeFileSync('.runtime/burst-performance.json', JSON.stringify({ provenance: 'CONTROLLED', inserted_fields: 200,
    retained_otp_discoveries: 200, dropped: 0, pending: 0, elapsed_including_fixture_and_polling_ms: Date.now() - start,
    renderer_before: pick(before.metrics), renderer_after: pick(after.metrics),
    limitation: 'One controlled renderer; includes fixture work and GC effects, not isolated extension CPU or a population performance bound.' }, null, 2));
});
