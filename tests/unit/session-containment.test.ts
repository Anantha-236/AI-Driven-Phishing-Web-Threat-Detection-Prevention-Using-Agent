import { describe, expect, it } from 'vitest';
import {
  createSessionContainment,
  SESSION_CONTAINMENT_RULE_START,
} from '../../browser-extension/src/core/enforcement/session-containment';

type Rule = chrome.declarativeNetRequest.Rule;
type Update = chrome.declarativeNetRequest.UpdateRuleOptions;

function createHarness(options: { failWrite?: boolean } = {}) {
  const rules: Rule[] = [];
  const updates: Update[] = [];
  const storage: Record<string, unknown> = {};
  let now = 1_000;

  const containment = createSessionContainment({
    async getSessionRules() {
      return rules.map(rule => structuredClone(rule));
    },
    async updateSessionRules(update) {
      updates.push(structuredClone(update));

      for (const id of update.removeRuleIds ?? []) {
        const index = rules.findIndex(rule => rule.id === id);
        if (index >= 0) rules.splice(index, 1);
      }

      for (const rule of update.addRules ?? []) {
        rules.push(structuredClone(rule));
      }
    },
    async readStorage(key) {
      return storage[key];
    },
    async writeStorage(key, value) {
      if (options.failWrite) throw new Error('storage unavailable');
      storage[key] = structuredClone(value);
    },
    async removeStorage(key) {
      delete storage[key];
    },
    now() {
      return now;
    },
  });

  return {
    containment,
    rules,
    updates,
    storage,
    advance(ms: number) {
      now += ms;
    },
  };
}

describe('tab-scoped session containment', () => {
  it('installs a tab-scoped rule only for the evidenced canonical origin', async () => {
    const harness = createHarness();

    const outcome = await harness.containment.install({
      tabId: 42,
      documentId: 'doc-1',
      destinationOrigin: 'https://collector.test',
      ttlMs: 5_000,
    });

    expect(outcome).toBe('SESSION_RULE_INSTALLED');
    expect(harness.rules).toHaveLength(1);
    expect(harness.rules[0]).toMatchObject({
      id: SESSION_CONTAINMENT_RULE_START,
      action: { type: 'block' },
      condition: {
        tabIds: [42],
        urlFilter: '|https://collector.test/',
        isUrlFilterCaseSensitive: true,
      },
    });
  });

  it('rejects path-level input instead of silently broadening it to an origin block', async () => {
    const harness = createHarness();

    await expect(harness.containment.install({
      tabId: 42,
      documentId: 'doc-1',
      destinationOrigin: 'https://shared-host.test/tenant-a',
    })).rejects.toThrow('Containment accepts origins only');

    expect(harness.rules).toHaveLength(0);
  });

  it('does not duplicate an existing live rule for the same tab document and origin', async () => {
    const harness = createHarness();
    const input = {
      tabId: 42,
      documentId: 'doc-1',
      destinationOrigin: 'https://collector.test',
      ttlMs: 5_000,
    };

    expect(await harness.containment.install(input)).toBe('SESSION_RULE_INSTALLED');
    expect(await harness.containment.install(input)).toBe('SESSION_RULE_INSTALLED');

    expect(harness.rules).toHaveLength(1);
    expect(harness.updates.filter(update => update.addRules?.length)).toHaveLength(1);
  });

  it('releases only the requested tab/document containment', async () => {
    const harness = createHarness();

    await harness.containment.install({
      tabId: 42,
      documentId: 'doc-a',
      destinationOrigin: 'https://collector-a.test',
    });
    await harness.containment.install({
      tabId: 43,
      documentId: 'doc-b',
      destinationOrigin: 'https://collector-b.test',
    });

    expect(await harness.containment.release({
      tabId: 42,
      documentId: 'doc-a',
    })).toBe('SESSION_RULE_REMOVED');

    expect(harness.rules).toHaveLength(1);
    expect(harness.rules[0].condition.tabIds).toEqual([43]);
  });

  it('removes expired rules without touching still-live containment', async () => {
    const harness = createHarness();

    await harness.containment.install({
      tabId: 42,
      documentId: 'short',
      destinationOrigin: 'https://short.test',
      ttlMs: 1_000,
    });
    await harness.containment.install({
      tabId: 43,
      documentId: 'long',
      destinationOrigin: 'https://long.test',
      ttlMs: 10_000,
    });

    harness.advance(2_000);

    expect(await harness.containment.cleanupExpired()).toBe(1);
    expect(harness.rules).toHaveLength(1);
    expect(harness.rules[0].condition.tabIds).toEqual([43]);
  });

  it('rolls back an installed session rule if metadata persistence fails', async () => {
    const harness = createHarness({ failWrite: true });

    const outcome = await harness.containment.install({
      tabId: 42,
      documentId: 'doc-1',
      destinationOrigin: 'https://collector.test',
    });

    expect(outcome).toBe('ENFORCEMENT_FAILED');
    expect(harness.rules).toHaveLength(0);
    expect(harness.updates.some(update =>
      update.removeRuleIds?.includes(SESSION_CONTAINMENT_RULE_START)
    )).toBe(true);
  });
});
