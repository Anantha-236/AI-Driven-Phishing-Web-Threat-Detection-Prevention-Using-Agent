import { test, expect } from './fixtures';

test('Stage B shadow observer cannot replace the current local security decision', async ({ context, page }) => {
  const worker = context.serviceWorkers()[0] || await context.waitForEvent('serviceworker');

  await page.goto('http://127.0.0.1:41731/research?family=2&label=1&layout=0');
  await page.evaluate(async () => { await (window as any).runScenario(); });

  const tab = await worker.evaluate(
    async url => (await chrome.tabs.query({})).find(candidate => candidate.url === url)!.id!,
    page.url(),
  );

  const readReport = () =>
    worker.evaluate(
      async id => (await chrome.storage.session.get(`security-report:${id}`))[`security-report:${id}`],
      tab,
    );

  await expect.poll(async () => (await readReport())?.decision_source).toBe('LOCAL_ML_AGENT');
  const before = await readReport();

  const popup = await context.newPage();
  await popup.goto(`chrome-extension://${worker.url().split('/')[2]}/src/ui/popup.html`);
  await page.bringToFront();

  const response = await popup.evaluate(() => chrome.runtime.sendMessage({ type: 'GET_SECURITY_REPORT' }));
  expect(response.report.decision_source).toBe('LOCAL_ML_AGENT');
  expect(response.report.action).toBe(before.action);
  expect(response.report.model_score).toBe(before.model_score);

  expect(response.stage_b_shadow).not.toBeNull();
  expect(response.stage_b_shadow.decision_authority).toBe('SHADOW_ONLY');
  expect(response.stage_b_shadow.deployment_enabled).toBe(false);
  expect(response.stage_b_shadow.autonomous_blocking).toBe(false);
  expect(['NOT_INSTALLED', 'READY', 'OBSERVED', 'ERROR']).toContain(response.stage_b_shadow.status);

  const after = await readReport();
  expect(after.decision_source).toBe('LOCAL_ML_AGENT');
  expect(after.action).toBe(before.action);
  expect(after.model_score).toBe(before.model_score);
});
