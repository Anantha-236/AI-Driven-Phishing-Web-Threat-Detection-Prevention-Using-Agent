import { test, expect } from './fixtures';
import { mkdirSync, writeFileSync } from 'node:fs';

test('collect controlled labeled shadow observations without reusing Stage B final-test evidence', async ({ context }) => {
  test.setTimeout(180000);
  const worker = context.serviceWorkers()[0] || await context.waitForEvent('serviceworker');
  const control = await context.newPage();
  await control.goto(`chrome-extension://${worker.url().split('/')[2]}/src/ui/popup.html`);

  const records: any[] = [];
  for (let layout = 0; layout < 2; layout++) {
    for (let family = 1; family <= 6; family++) {
      for (const label of [0, 1]) {
        const page = await context.newPage();
        await page.goto(`http://127.0.0.1:41731/research?family=${family}&label=${label}&layout=${layout}`);
        await page.evaluate(async () => { await (window as any).runScenario(); });

        const tab = await worker.evaluate(
          async url => (await chrome.tabs.query({})).find(candidate => candidate.url === url)!.id!,
          page.url(),
        );

        const read = () =>
          control.evaluate(tabId => chrome.runtime.sendMessage({ type: 'GET_SECURITY_REPORT', tabId }), tab);

        await expect.poll(async () => (await read())?.report?.decision_source, { timeout: 15000 })
          .toBe('LOCAL_ML_AGENT');
        await expect.poll(async () => (await read())?.stage_b_shadow?.decision_authority, { timeout: 15000 })
          .toBe('SHADOW_ONLY');

        const response = await read();
        const shadow = response.stage_b_shadow;
        records.push({
          case_id: `family-${family}-label-${label}-layout-${layout}`,
          family: String(family),
          layout,
          label,
          baseline_action: response.report.action,
          baseline_intervention: response.report.action !== 'ALLOW',
          stage_b_status: shadow.status,
          stage_b_score: shadow.stage_b_score,
          stage_b_intervention: shadow.would_cross_frozen_threshold,
          stage_b_threshold: shadow.threshold,
          stage_b_latency_ms: shadow.latency_ms,
          stage_b_model_id: shadow.model_id,
          stage_b_integration_eligible: shadow.integration_eligible,
        });

        await page.close();
      }
    }
  }

  const dataset = {
    schema_version: 'stage-b-controlled-shadow-dataset-1',
    protocol: 'CONTROLLED_NON_FINAL',
    fixture_protocol: 'authored-research-v1',
    final_test_reused: false,
    limitation: '24 authored loopback cases; families 1-5 controlled correctness, family 6 observational ambiguity stress only.',
    privacy_contract: {
      stores_urls: false,
      stores_origins: false,
      stores_document_ids: false,
      stores_form_ids: false,
      stores_event_payloads: false,
    },
    records,
  };

  const containsExactKey = (value: unknown, forbiddenKey: string): boolean => {
    if (Array.isArray(value)) return value.some(item => containsExactKey(item, forbiddenKey));
    if (value && typeof value === 'object') {
      const record = value as Record<string, unknown>;
      if (Object.prototype.hasOwnProperty.call(record, forbiddenKey)) return true;
      return Object.values(record).some(item => containsExactKey(item, forbiddenKey));
    }
    return false;
  };
  for (const key of ['url', 'target_url', 'frame_origin', 'document_id', 'form_id', 'event_payload', 'events', 'session_id', 'tab_id']) {
    expect(containsExactKey(dataset.records, key)).toBe(false);
  }

  mkdirSync('.runtime', { recursive: true });
  writeFileSync(
    '.runtime/stage-b-controlled-shadow-latest.json',
    JSON.stringify(dataset, null, 2),
  );

  expect(records).toHaveLength(24);
  expect(records.filter(record => ['1','2','3','4','5'].includes(record.family))).toHaveLength(20);
  expect(records.filter(record => record.family === '6')).toHaveLength(4);
});
