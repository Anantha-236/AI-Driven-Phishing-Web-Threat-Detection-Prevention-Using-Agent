export type DurableDeliveryKind = 'EVENT_BATCH' | 'ASSESSMENT_REPORT';

export interface DurableStorage {
  get(key: string): Promise<Record<string, unknown>>;
  set(value: Record<string, unknown>): Promise<void>;
  remove?(key: string): Promise<void>;
}

export interface DurableDeliveryRecord {
  schemaVersion: 'durable-delivery-1';
  kind: DurableDeliveryKind;
  idempotencyKey: string;
  createdAt: number;
  expiresAt: number;
  payload: unknown;
}

export interface DurableQueueOptions {
  storageKey?: string;
  ttlMs?: number;
  maxRecords?: number;
  maxBytes?: number;
  now?: () => number;
}

export interface DurableQueueStats {
  count: number;
  bytes: number;
  dropped: number;
  corrupt: number;
}

interface DurableStore {
  schemaVersion: 'durable-store-1';
  records: DurableDeliveryRecord[];
  dropped: number;
  corrupt: number;
}

const DEFAULT_STORAGE_KEY = 'capstone-durable-delivery-v1';
const DEFAULT_TTL_MS = 24 * 60 * 60 * 1000;
const DEFAULT_MAX_RECORDS = 256;
const DEFAULT_MAX_BYTES = 1_000_000;
const ID_PATTERN = /^[A-Za-z0-9:._-]{1,220}$/;
const KINDS: readonly DurableDeliveryKind[] = ['EVENT_BATCH', 'ASSESSMENT_REPORT'];
const UNSAFE_KEYS = new Set([
  'rawvalue',
  'password',
  'otp',
  'cvv',
  'cookie',
  'cookies',
  'authorization',
  'requestbody',
  'requestheaders',
  'responseheaders',
  'pagetext',
  'html',
  'innerhtml',
  'outerhtml',
]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function jsonBytes(value: unknown): number {
  return new TextEncoder().encode(JSON.stringify(value)).byteLength;
}

function containsUnsafeKey(
  value: unknown,
  kind: DurableDeliveryKind,
  path: readonly string[] = [],
  seen = new WeakSet<object>(),
): boolean {
  if (!value || typeof value !== 'object') return false;
  if (seen.has(value as object)) return false;
  seen.add(value as object);

  if (Array.isArray(value)) {
    return value.some(item => containsUnsafeKey(item, kind, path, seen));
  }

  for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
    const lower = key.toLowerCase();
    if (UNSAFE_KEYS.has(lower)) return true;
    // Sensitive browser events have no `value` field. Security reports do use
    // purpose.value for a closed enum, so that one exact location is allowed.
    if (lower === 'value' && !(kind === 'ASSESSMENT_REPORT' && path.length === 1 && path[0] === 'purpose')) return true;
    if (containsUnsafeKey(child, kind, [...path, key], seen)) return true;
  }

  return false;
}

function samePayload(a: unknown, b: unknown): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}

function validRecord(value: unknown): value is DurableDeliveryRecord {
  if (!isRecord(value)) return false;
  const expected = ['schemaVersion', 'kind', 'idempotencyKey', 'createdAt', 'expiresAt', 'payload'];
  if (Object.keys(value).length !== expected.length || expected.some(key => !(key in value))) return false;
  if (value.schemaVersion !== 'durable-delivery-1') return false;
  if (!KINDS.includes(value.kind as DurableDeliveryKind)) return false;
  if (typeof value.idempotencyKey !== 'string' || !ID_PATTERN.test(value.idempotencyKey)) return false;
  if (!Number.isSafeInteger(value.createdAt) || Number(value.createdAt) < 0) return false;
  if (!Number.isSafeInteger(value.expiresAt) || Number(value.expiresAt) <= Number(value.createdAt)) return false;
  if (containsUnsafeKey(value.payload, value.kind as DurableDeliveryKind)) return false;
  try {
    JSON.stringify(value.payload);
  } catch {
    return false;
  }
  return true;
}

function emptyStore(): DurableStore {
  return {
    schemaVersion: 'durable-store-1',
    records: [],
    dropped: 0,
    corrupt: 0,
  };
}

export function createDurableQueue(storage: DurableStorage, options: DurableQueueOptions = {}) {
  const storageKey = options.storageKey ?? DEFAULT_STORAGE_KEY;
  const ttlMs = options.ttlMs ?? DEFAULT_TTL_MS;
  const maxRecords = options.maxRecords ?? DEFAULT_MAX_RECORDS;
  const maxBytes = options.maxBytes ?? DEFAULT_MAX_BYTES;
  const now = options.now ?? Date.now;
  let tail: Promise<unknown> = Promise.resolve();

  function serial<T>(fn: () => Promise<T>): Promise<T> {
    const result = tail.then(fn);
    tail = result.catch(() => {});
    return result;
  }

  async function save(store: DurableStore): Promise<void> {
    await storage.set({ [storageKey]: store });
  }

  async function read(): Promise<DurableStore> {
    const raw = (await storage.get(storageKey))[storageKey];
    if (raw === undefined) return emptyStore();
    if (!isRecord(raw) || raw.schemaVersion !== 'durable-store-1' || !Array.isArray(raw.records)) {
      const reset = emptyStore();
      reset.corrupt = 1;
      await save(reset);
      return reset;
    }

    const dropped = Number.isSafeInteger(raw.dropped) && Number(raw.dropped) >= 0 ? Number(raw.dropped) : 0;
    const priorCorrupt = Number.isSafeInteger(raw.corrupt) && Number(raw.corrupt) >= 0 ? Number(raw.corrupt) : 0;
    const valid: DurableDeliveryRecord[] = [];
    let corrupt = priorCorrupt;

    for (const candidate of raw.records) {
      if (validRecord(candidate)) valid.push(candidate);
      else corrupt++;
    }

    const normalized: DurableStore = {
      schemaVersion: 'durable-store-1',
      records: valid,
      dropped,
      corrupt,
    };

    if (valid.length !== raw.records.length || corrupt !== priorCorrupt) {
      await save(normalized);
    }

    return normalized;
  }

  function trim(store: DurableStore): void {
    while (store.records.length > maxRecords) {
      store.records.shift();
      store.dropped++;
    }

    while (store.records.length && jsonBytes(store) > maxBytes) {
      store.records.shift();
      store.dropped++;
    }
  }

  return {
    put(input: {
      kind: DurableDeliveryKind;
      idempotencyKey: string;
      payload: unknown;
      ttlMs?: number;
    }): Promise<'STORED' | 'DUPLICATE'> {
      return serial(async () => {
        if (!KINDS.includes(input.kind)) throw new Error('Invalid durable delivery kind');
        if (!ID_PATTERN.test(input.idempotencyKey)) throw new Error('Invalid durable idempotency key');
        if (containsUnsafeKey(input.payload, input.kind)) throw new Error('Unsafe durable payload');

        let serialized: string;
        try {
          serialized = JSON.stringify(input.payload);
        } catch {
          throw new Error('Durable payload must be JSON serializable');
        }

        if (new TextEncoder().encode(serialized).byteLength > maxBytes) {
          throw new Error('Durable record exceeds byte limit');
        }

        const store = await read();
        const duplicate = store.records.find(record => record.idempotencyKey === input.idempotencyKey);

        if (duplicate) {
          if (duplicate.kind !== input.kind || !samePayload(duplicate.payload, input.payload)) {
            throw new Error('Durable identity conflict');
          }
          return 'DUPLICATE';
        }

        const createdAt = now();
        const recordTtl = input.ttlMs ?? ttlMs;
        if (!Number.isSafeInteger(recordTtl) || recordTtl <= 0) throw new Error('Invalid durable TTL');

        const record: DurableDeliveryRecord = {
          schemaVersion: 'durable-delivery-1',
          kind: input.kind,
          idempotencyKey: input.idempotencyKey,
          createdAt,
          expiresAt: createdAt + recordTtl,
          payload: structuredClone(input.payload),
        };

        const singleRecordStore: DurableStore = {
          schemaVersion: 'durable-store-1',
          records: [record],
          dropped: store.dropped,
          corrupt: store.corrupt,
        };
        if (jsonBytes(singleRecordStore) > maxBytes) {
          throw new Error('Durable record exceeds byte limit');
        }

        store.records.push(record);
        trim(store);
        await save(store);
        return 'STORED';
      });
    },

    ack(idempotencyKey: string): Promise<boolean> {
      return serial(async () => {
        const store = await read();
        const before = store.records.length;
        store.records = store.records.filter(record => record.idempotencyKey !== idempotencyKey);
        const changed = before !== store.records.length;
        if (changed) await save(store);
        return changed;
      });
    },

    listReady(at = now()): Promise<DurableDeliveryRecord[]> {
      return serial(async () => {
        const store = await read();
        const before = store.records.length;
        store.records = store.records.filter(record => record.expiresAt > at);
        if (before !== store.records.length) await save(store);
        return store.records
          .slice()
          .sort((a, b) => a.createdAt - b.createdAt)
          .map(record => structuredClone(record));
      });
    },

    purgeExpired(at = now()): Promise<number> {
      return serial(async () => {
        const store = await read();
        const before = store.records.length;
        store.records = store.records.filter(record => record.expiresAt > at);
        const removed = before - store.records.length;
        if (removed) await save(store);
        return removed;
      });
    },

    stats(): Promise<DurableQueueStats> {
      return serial(async () => {
        const store = await read();
        return {
          count: store.records.length,
          bytes: jsonBytes(store),
          dropped: store.dropped,
          corrupt: store.corrupt,
        };
      });
    },
  };
}
