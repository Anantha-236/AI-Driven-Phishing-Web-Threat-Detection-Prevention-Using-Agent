import type { EnforcementOutcome } from '../agent/types';

export const SESSION_CONTAINMENT_RULE_START = 2_000_000;
export const SESSION_CONTAINMENT_RULE_LIMIT = 1_000;
const STORAGE_KEY = 'session-containment-records-v1';
const DEFAULT_TTL_MS = 5 * 60 * 1000;

const RESOURCE_TYPES = [
  'main_frame',
  'sub_frame',
  'xmlhttprequest',
  'script',
  'ping',
  'websocket',
  'webtransport',
  'other',
] as chrome.declarativeNetRequest.ResourceType[];

export interface ContainmentRecord {
  schemaVersion: 'session-containment-1';
  ruleId: number;
  tabId: number;
  documentId: string;
  destinationOrigin: string;
  createdAt: number;
  expiresAt: number;
}

export interface InstallContainmentInput {
  tabId: number;
  documentId: string;
  destinationOrigin: string;
  ttlMs?: number;
}

export interface ReleaseContainmentInput {
  tabId: number;
  documentId?: string;
}

export interface SessionContainmentDependencies {
  getSessionRules(): Promise<chrome.declarativeNetRequest.Rule[]>;
  updateSessionRules(options: chrome.declarativeNetRequest.UpdateRuleOptions): Promise<void>;
  readStorage(key: string): Promise<unknown>;
  writeStorage(key: string, value: unknown): Promise<void>;
  removeStorage(key: string): Promise<void>;
  now(): number;
}

function defaultDependencies(): SessionContainmentDependencies {
  return {
    getSessionRules: () => chrome.declarativeNetRequest.getSessionRules(),
    updateSessionRules: options => chrome.declarativeNetRequest.updateSessionRules(options),
    async readStorage(key) {
      return (await chrome.storage.session.get(key))[key];
    },
    async writeStorage(key, value) {
      await chrome.storage.session.set({ [key]: value });
    },
    async removeStorage(key) {
      await chrome.storage.session.remove(key);
    },
    now: () => Date.now(),
  };
}

function canonicalOrigin(value: string): string {
  const url = new URL(value);
  if (!['http:', 'https:'].includes(url.protocol)) {
    throw new Error('Containment requires an http(s) origin');
  }
  if (url.username || url.password || url.search || url.hash) {
    throw new Error('Containment requires a canonical origin');
  }
  if (value !== url.origin) {
    throw new Error('Containment accepts origins only');
  }
  return url.origin;
}

function isRecord(value: unknown): value is ContainmentRecord {
  if (!value || typeof value !== 'object') return false;
  const record = value as Partial<ContainmentRecord>;
  return record.schemaVersion === 'session-containment-1' &&
    Number.isInteger(record.ruleId) &&
    Number.isInteger(record.tabId) &&
    typeof record.documentId === 'string' &&
    typeof record.destinationOrigin === 'string' &&
    typeof record.createdAt === 'number' &&
    typeof record.expiresAt === 'number';
}

export function createSessionContainment(
  overrides: Partial<SessionContainmentDependencies> = {},
) {
  const base = defaultDependencies();
  const deps: SessionContainmentDependencies = {
    ...base,
    ...overrides,
  };

  let tail: Promise<unknown> = Promise.resolve();
  function serial<T>(operation: () => Promise<T>): Promise<T> {
    const result = tail.then(operation);
    tail = result.catch(() => {});
    return result;
  }

  async function readRecords(): Promise<ContainmentRecord[]> {
    const raw = await deps.readStorage(STORAGE_KEY);
    if (!Array.isArray(raw)) return [];
    return raw.filter(isRecord);
  }

  async function writeRecords(records: ContainmentRecord[]): Promise<void> {
    if (!records.length) {
      await deps.removeStorage(STORAGE_KEY);
      return;
    }
    await deps.writeStorage(STORAGE_KEY, records);
  }

  async function allocateRuleId(): Promise<number> {
    const rules = await deps.getSessionRules();
    const used = new Set(rules.map(rule => rule.id));
    for (let offset = 0; offset < SESSION_CONTAINMENT_RULE_LIMIT; offset++) {
      const candidate = SESSION_CONTAINMENT_RULE_START + offset;
      if (!used.has(candidate)) return candidate;
    }
    throw new Error('Session containment rule limit reached');
  }

  async function installInternal(input: InstallContainmentInput): Promise<EnforcementOutcome> {
    if (!Number.isInteger(input.tabId) || input.tabId < 0) {
      throw new Error('Invalid tabId');
    }
    if (!input.documentId) throw new Error('documentId is required');
    const destinationOrigin = canonicalOrigin(input.destinationOrigin);
    const ttlMs = input.ttlMs ?? DEFAULT_TTL_MS;
    if (!Number.isFinite(ttlMs) || ttlMs <= 0 || ttlMs > 60 * 60 * 1000) {
      throw new Error('Invalid containment TTL');
    }

    const records = await readRecords();
    const existing = records.find(record =>
      record.tabId === input.tabId &&
      record.documentId === input.documentId &&
      record.destinationOrigin === destinationOrigin &&
      record.expiresAt > deps.now()
    );
    if (existing) return 'SESSION_RULE_INSTALLED';

    const ruleId = await allocateRuleId();
    const createdAt = deps.now();
    const record: ContainmentRecord = {
      schemaVersion: 'session-containment-1',
      ruleId,
      tabId: input.tabId,
      documentId: input.documentId,
      destinationOrigin,
      createdAt,
      expiresAt: createdAt + ttlMs,
    };

    const rule: chrome.declarativeNetRequest.Rule = {
      id: ruleId,
      priority: 10,
      action: {
        type: 'block' as chrome.declarativeNetRequest.RuleActionType,
      },
      condition: {
        urlFilter: `|${destinationOrigin}/`,
        isUrlFilterCaseSensitive: true,
        resourceTypes: RESOURCE_TYPES,
        tabIds: [input.tabId],
      },
    };

    let ruleInstalled = false;
    try {
      await deps.updateSessionRules({ addRules: [rule] });
      ruleInstalled = true;
      await writeRecords([...records, record]);
      return 'SESSION_RULE_INSTALLED';
    } catch {
      if (ruleInstalled) {
        try {
          await deps.updateSessionRules({ removeRuleIds: [ruleId] });
        } catch {
          // The caller receives ENFORCEMENT_FAILED. A later lifecycle sweep can
          // reconcile any rule that Chrome accepted but could not be rolled back.
        }
      }
      return 'ENFORCEMENT_FAILED';
    }
  }

  async function releaseInternal(input: ReleaseContainmentInput): Promise<EnforcementOutcome> {
    const records = await readRecords();
    const matching = records.filter(record =>
      record.tabId === input.tabId &&
      (input.documentId === undefined || record.documentId === input.documentId)
    );

    if (!matching.length) return 'DECISION_ONLY';

    try {
      await deps.updateSessionRules({
        removeRuleIds: matching.map(record => record.ruleId),
      });
      const ids = new Set(matching.map(record => record.ruleId));
      await writeRecords(records.filter(record => !ids.has(record.ruleId)));
      return 'SESSION_RULE_REMOVED';
    } catch {
      return 'ENFORCEMENT_FAILED';
    }
  }

  async function cleanupExpiredInternal(): Promise<number> {
    const now = deps.now();
    const records = await readRecords();
    const expired = records.filter(record => record.expiresAt <= now);
    if (!expired.length) return 0;

    await deps.updateSessionRules({
      removeRuleIds: expired.map(record => record.ruleId),
    });
    const ids = new Set(expired.map(record => record.ruleId));
    await writeRecords(records.filter(record => !ids.has(record.ruleId)));
    return expired.length;
  }

  return {
    install(input: InstallContainmentInput) {
      return serial(() => installInternal(input));
    },
    release(input: ReleaseContainmentInput) {
      return serial(() => releaseInternal(input));
    },
    cleanupExpired() {
      return serial(() => cleanupExpiredInternal());
    },
    async list(): Promise<ContainmentRecord[]> {
      await tail;
      return readRecords();
    },
  };
}
