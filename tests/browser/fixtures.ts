import { test as base, chromium } from '@playwright/test';
import { resolve } from 'node:path';
import { execFileSync } from 'node:child_process';

export const test = base.extend({
  context: async ({}, use) => {
    const extension = resolve('dist');
    const context = await chromium.launchPersistentContext('', {
      channel: 'chromium', headless: true,
      args: [`--disable-extensions-except=${extension}`, `--load-extension=${extension}`,
        '--host-resolver-rules=MAP test-phish-dnr-blocked.example.com 127.0.0.1, MAP feed-fixture.example.test 127.0.0.1'],
    });
    const worker = context.serviceWorkers()[0] || await context.waitForEvent('serviceworker');
    await worker.evaluate(() => {
      const nativeFetch = globalThis.fetch;
      globalThis.fetch = (input, init) => String(input).startsWith('https://raw.githubusercontent.com/openphish/')
        ? Promise.resolve(new Response('http://feed-fixture.example.test:41731/blocked', { status: 200 })) : nativeFetch(input, init);
    });
    try { await use(context); } finally { await context.close(); }
  },
});
export { expect } from '@playwright/test';

export function storedCollection(collectionId: string) {
  const output = execFileSync('python', ['-c', `
import json, sys
from backend.database import db_instance
with db_instance.get_connection() as conn:
    row = conn.execute('SELECT form_count, input_count, requested_data_types, threat_level, policy_action FROM observations WHERE collection_id = %s ORDER BY observed_at DESC LIMIT 1', (sys.argv[1],)).fetchone()
print(json.dumps(dict(form_count=row[0], input_count=row[1], categories=json.loads(row[2]), threat=row[3], action=row[4]) if row else None))
`, collectionId], { encoding: 'utf8', windowsHide: true });
  return JSON.parse(output.trim());
}
