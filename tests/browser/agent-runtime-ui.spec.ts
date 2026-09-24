import { test, expect } from './fixtures';

test('popup exposes bounded agent state separately from legacy report fields', async ({ context, page }) => {
  const worker = context.serviceWorkers()[0] || await context.waitForEvent('serviceworker');

  await page.goto('http://127.0.0.1:41731/research?family=2&label=1&layout=0');
  await page.evaluate(async () => {
    await (window as any).runScenario();
  });

  const tab = await worker.evaluate(
    async url => (await chrome.tabs.query({})).find(candidate => candidate.url === url)!.id!,
    page.url(),
  );

  const readReport = () =>
    worker.evaluate(
      async id =>
        (await chrome.storage.session.get(`security-report:${id}`))[
          `security-report:${id}`
        ],
      tab,
    );

  const readRuntime = () =>
    worker.evaluate(
      async id =>
        (await chrome.storage.session.get(`agent-runtime:${id}`))[
          `agent-runtime:${id}`
        ],
      tab,
    );

  await expect.poll(async () => (await readReport())?.action).toBe('WARN');
  await expect.poll(async () => (await readRuntime())?.state).toBe('SUSPICIOUS');

  const control = await context.newPage();
  await control.goto(
    `chrome-extension://${worker.url().split('/')[2]}/src/ui/popup.html`,
  );

  // GET_SECURITY_REPORT intentionally resolves the active protected tab.
  await page.bringToFront();

  await expect(control.locator('#agent-runtime-container')).toBeVisible();
  await expect(control.locator('#agent-state')).toContainText('SUSPICIOUS');
  await expect(control.locator('#requested-action')).toContainText('WARN');
  await expect(control.locator('#effective-action')).toContainText('WARN');
  await expect(control.locator('#enforcement-outcome')).toContainText('WARNING DISPLAYED');
  await expect(control.locator('#enforcement-mode')).toContainText('WARNING ONLY');
  await expect(control.locator('#automatic-block-authorized')).toHaveText('NO');
  await expect(control.locator('#containment-origin')).toHaveText('None');

  // The compatibility report remains visible separately.
  await expect(control.locator('#action')).toHaveText('WARN');
  await expect(control.locator('#agent')).toContainText('LOCAL PRIMARY');

  // Durable delivery status is now visible rather than hidden in storage.
  await expect(control.locator('#delivery')).toContainText('Durable restart queue:');
});
