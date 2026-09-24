import { describe, expect, it } from 'vitest';
import { createDurableQueue } from '../../browser-extension/src/core/storage/durable-queue';

class MemoryStorage {
  data: Record<string, unknown> = {};

  async get(key: string) {
    return { [key]: structuredClone(this.data[key]) };
  }

  async set(value: Record<string, unknown>) {
    Object.assign(this.data, structuredClone(value));
  }

  async remove(key: string) {
    delete this.data[key];
  }
}

describe('durable sanitized delivery queue', () => {
  it('persists across queue reconstruction and deduplicates the same idempotency key', async () => {
    const storage = new MemoryStorage();
    const queue = createDurableQueue(storage, {
      storageKey: 'q',
      ttlMs: 1000,
      maxRecords: 10,
      maxBytes: 10000,
      now: () => 1000,
    });

    expect(await queue.put({
      kind: 'EVENT_BATCH',
      idempotencyKey: 'events:test:1',
      payload: { events: [{ event_type: 'DOCUMENT_STARTED' }] },
    })).toBe('STORED');

    expect(await queue.put({
      kind: 'EVENT_BATCH',
      idempotencyKey: 'events:test:1',
      payload: { events: [{ event_type: 'DOCUMENT_STARTED' }] },
    })).toBe('DUPLICATE');

    const reconstructed = createDurableQueue(storage, {
      storageKey: 'q',
      ttlMs: 1000,
      maxRecords: 10,
      maxBytes: 10000,
      now: () => 1000,
    });

    expect(await reconstructed.listReady()).toHaveLength(1);
  });

  it('rejects identity reuse with a different payload', async () => {
    const storage = new MemoryStorage();
    const queue = createDurableQueue(storage, { storageKey: 'q' });

    await queue.put({
      kind: 'EVENT_BATCH',
      idempotencyKey: 'events:test:1',
      payload: { events: [{ event_type: 'DOCUMENT_STARTED' }] },
    });

    await expect(queue.put({
      kind: 'EVENT_BATCH',
      idempotencyKey: 'events:test:1',
      payload: { events: [{ event_type: 'FIELD_DISCOVERED' }] },
    })).rejects.toThrow(/identity conflict/i);
  });

  it('rejects raw-value and secret-shaped payload keys while allowing the closed purpose.value enum', async () => {
    const queue = createDurableQueue(new MemoryStorage(), {
      storageKey: 'q',
    });

    await expect(queue.put({
      kind: 'EVENT_BATCH',
      idempotencyKey: 'unsafe-value',
      payload: { events: [{ value: 'secret' }] },
    })).rejects.toThrow(/unsafe/i);

    await expect(queue.put({
      kind: 'ASSESSMENT_REPORT',
      idempotencyKey: 'unsafe-password',
      payload: { password: 'secret' },
    })).rejects.toThrow(/unsafe/i);

    expect(await queue.put({
      kind: 'ASSESSMENT_REPORT',
      idempotencyKey: 'safe-purpose',
      payload: { purpose: { value: 'LOGIN' } },
    })).toBe('STORED');
  });

  it('expires old records and enforces bounded record count', async () => {
    const storage = new MemoryStorage();
    let now = 1000;
    const queue = createDurableQueue(storage, {
      storageKey: 'q',
      ttlMs: 100,
      maxRecords: 2,
      maxBytes: 10000,
      now: () => now,
    });

    for (const key of ['a', 'b', 'c']) {
      await queue.put({
        kind: 'ASSESSMENT_REPORT',
        idempotencyKey: key,
        payload: { report: { action: 'ALLOW', key } },
      });
    }

    expect(await queue.stats()).toMatchObject({
      count: 2,
      dropped: 1,
    });

    now = 1201;
    expect(await queue.listReady()).toHaveLength(0);
  });

  it('rejects a single record that cannot fit the configured byte budget', async () => {
    const queue = createDurableQueue(new MemoryStorage(), {
      storageKey: 'tiny',
      maxBytes: 120,
    });

    await expect(queue.put({
      kind: 'ASSESSMENT_REPORT',
      idempotencyKey: 'too-large',
      payload: {
        report: {
          action: 'ALLOW',
          reason: 'x'.repeat(200),
        },
      },
    })).rejects.toThrow(/byte limit/i);
  });

  it('drops corrupted persisted records instead of replaying them loosely', async () => {
    const storage = new MemoryStorage();
    storage.data.q = {
      schemaVersion: 'durable-store-1',
      records: [{ bad: true }],
      dropped: 0,
      corrupt: 0,
    };

    const queue = createDurableQueue(storage, {
      storageKey: 'q',
    });

    expect(await queue.stats()).toMatchObject({
      count: 0,
      corrupt: 1,
    });
  });
});
