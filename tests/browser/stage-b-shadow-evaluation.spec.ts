import { test, expect } from './fixtures';

test('Stage B shadow evaluation remains privacy-safe and non-authoritative', async ({ context, page }) => {
  const worker = context.serviceWorkers()[0] || await context.waitForEvent('serviceworker');

  await page.goto('http://127.0.0.1:41731/research?family=3&label=1&layout=0');
  await page.evaluate(async () => { await (window as any).runScenario(); });

  const popup = await context.newPage();
  await popup.goto(`chrome-extension://${worker.url().split('/')[2]}/src/ui/popup.html`);
  await page.bringToFront();

  await expect.poll(async () => {
    const response = await popup.evaluate(() => chrome.runtime.sendMessage({ type: 'GET_SECURITY_REPORT' }));
    return response?.stage_b_shadow_evaluation?.retained_observations ?? 0;
  }).toBeGreaterThan(0);

  const response = await popup.evaluate(() => chrome.runtime.sendMessage({ type: 'GET_SECURITY_REPORT' }));
  const evaluation = response.stage_b_shadow_evaluation;

  expect(evaluation.decision_authority).toBe('SHADOW_ONLY');
  expect(evaluation.promotion_decision).toBe('NOT_EVALUATED');
  expect(evaluation.privacy_contract).toEqual({
    stores_urls: false,
    stores_origins: false,
    stores_document_ids: false,
    stores_form_ids: false,
    stores_event_payloads: false,
  });

  const containsExactKey = (value: unknown, forbiddenKey: string): boolean => {
    if (Array.isArray(value)) {
      return value.some(item => containsExactKey(item, forbiddenKey));
    }
    if (value && typeof value === 'object') {
      const record = value as Record<string, unknown>;
      if (Object.prototype.hasOwnProperty.call(record, forbiddenKey)) return true;
      return Object.values(record).some(item => containsExactKey(item, forbiddenKey));
    }
    return false;
  };

  for (const forbidden of ['target_url', 'frame_origin', 'document_id', 'form_id', 'event_payload', 'events']) {
    expect(containsExactKey(evaluation, forbidden)).toBe(false);
  }

  expect(evaluation.privacy_contract.stores_urls).toBe(false);
  expect(evaluation.privacy_contract.stores_origins).toBe(false);
  expect(evaluation.privacy_contract.stores_document_ids).toBe(false);
  expect(evaluation.privacy_contract.stores_form_ids).toBe(false);
  expect(evaluation.privacy_contract.stores_event_payloads).toBe(false);

  expect(response.report.decision_source).toBe('LOCAL_ML_AGENT');
  expect(response.stage_b_shadow.decision_authority).toBe('SHADOW_ONLY');
  expect(response.stage_b_shadow.deployment_enabled).toBe(false);
  expect(response.stage_b_shadow.autonomous_blocking).toBe(false);
});
