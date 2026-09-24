import type {
  ReputationProvider,
  ReputationResult,
  ReputationSnapshot,
} from './types';

export const PHISHING_FEED_URL = 'https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt';
export const OPENPHISH_RULE_START = 10_000;
export const OPENPHISH_RULE_LIMIT = 1_000;
const FEED_REFRESH_MS = 12 * 60 * 60 * 1000;
const FEED_RETRY_MS = 60 * 60 * 1000;
const FEED_MAX_AGE_MS = 48 * 60 * 60 * 1000;
const STATUS_KEY = 'phishing-feed-status';

const RESOURCE_TYPES = [
  'main_frame', 'sub_frame', 'xmlhttprequest', 'script', 'image',
  'stylesheet', 'font', 'object', 'ping', 'csp_report', 'media',
  'websocket', 'webtransport', 'webbundle', 'other',
] as chrome.declarativeNetRequest.ResourceType[];

export interface ProtectionStatus {
  source: 'OpenPhish Community';
  updated_at: number | null;
  checked_at: number;
  rule_count: number;
  excluded_count: number;
  state: 'ACTIVE' | 'UNAVAILABLE' | 'EXPIRED';
}

export interface CompiledPhishingRules {
  rules: chrome.declarativeNetRequest.Rule[];
  excluded: number;
}

export function compilePhishingRules(text: string): CompiledPhishingRules {
  if (text.length > 2_000_000) throw new Error('Feed exceeds size limit');

  const urls = new Set<string>();
  let excluded = 0;

  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line) continue;

    try {
      const url = new URL(line);
      const invalid =
        !['https:', 'http:'].includes(url.protocol) ||
        Boolean(url.username) ||
        Boolean(url.password) ||
        Boolean(url.search) ||
        /[\s*|^]/.test(line) ||
        line.length > 1800 ||
        !url.hostname.includes('.') ||
        url.hostname.endsWith('.localhost') ||
        /^[\d.]+$/.test(url.hostname) ||
        url.hostname.includes(':');

      if (invalid) {
        excluded++;
        continue;
      }

      url.hash = '';

      if (urls.size >= OPENPHISH_RULE_LIMIT && !urls.has(url.href)) {
        excluded++;
        continue;
      }

      urls.add(url.href);
    } catch {
      excluded++;
    }
  }

  return {
    rules: [...urls].map((url, index) => ({
      id: OPENPHISH_RULE_START + index,
      priority: 1,
      action: {
        type: 'block' as chrome.declarativeNetRequest.RuleActionType,
      },
      condition: {
        urlFilter: `|${url}|`,
        isUrlFilterCaseSensitive: true,
        resourceTypes: RESOURCE_TYPES,
      },
    })),
    excluded,
  };
}

function snapshotToLegacy(snapshot: ReputationSnapshot): ProtectionStatus {
  return {
    source: 'OpenPhish Community',
    updated_at: snapshot.updatedAt,
    checked_at: snapshot.checkedAt,
    rule_count: snapshot.indicatorCount,
    excluded_count: snapshot.excludedCount,
    state: snapshot.state,
  };
}

export function createOpenPhishProvider(): ReputationProvider & {
  legacyStatus(): Promise<ProtectionStatus>;
  legacyRefresh(force?: boolean): Promise<ProtectionStatus>;
} {
  let active: Promise<ReputationSnapshot> | null = null;

  async function getFeedRules(): Promise<chrome.declarativeNetRequest.Rule[]> {
    const rules = await chrome.declarativeNetRequest.getDynamicRules();
    return rules.filter(rule =>
      rule.id >= OPENPHISH_RULE_START &&
      rule.id < OPENPHISH_RULE_START + OPENPHISH_RULE_LIMIT
    );
  }

  async function status(): Promise<ReputationSnapshot> {
    const saved = (await chrome.storage.local.get(STATUS_KEY))[STATUS_KEY] as ProtectionStatus | undefined;
    const rules = await getFeedRules();
    const updatedAt = saved?.updated_at ?? null;
    const state: ReputationSnapshot['state'] =
      updatedAt && Date.now() - updatedAt <= FEED_MAX_AGE_MS
        ? 'ACTIVE'
        : updatedAt
          ? 'EXPIRED'
          : 'UNAVAILABLE';

    return {
      providerId: 'openphish-community',
      source: 'OpenPhish Community',
      updatedAt,
      checkedAt: saved?.checked_at ?? 0,
      indicatorCount: rules.length,
      excludedCount: saved?.excluded_count ?? 0,
      state,
    };
  }

  function refresh(force = false): Promise<ReputationSnapshot> {
    if (active) return active;

    active = (async () => {
      let prior = await status();

      if (prior.state === 'EXPIRED') {
        const oldRules = await getFeedRules();
        if (oldRules.length) {
          await chrome.declarativeNetRequest.updateDynamicRules({
            removeRuleIds: oldRules.map(rule => rule.id),
          });
        }
        prior = await status();
      }

      const minInterval = prior.state === 'ACTIVE'
        ? FEED_REFRESH_MS
        : FEED_RETRY_MS;

      if (!force && Date.now() - prior.checkedAt < minInterval) {
        return prior;
      }

      try {
        const response = await fetch(PHISHING_FEED_URL, {
          credentials: 'omit',
          cache: 'no-store',
          signal: AbortSignal.timeout(15_000),
        });

        if (!response.ok) throw new Error('Feed unavailable');

        const compiled = compilePhishingRules(await response.text());
        if (!compiled.rules.length) throw new Error('No valid indicators');

        const oldRules = await getFeedRules();
        await chrome.declarativeNetRequest.updateDynamicRules({
          removeRuleIds: oldRules.map(rule => rule.id),
          addRules: compiled.rules,
        });

        prior = {
          providerId: 'openphish-community',
          source: 'OpenPhish Community',
          updatedAt: Date.now(),
          checkedAt: Date.now(),
          indicatorCount: compiled.rules.length,
          excludedCount: compiled.excluded,
          state: 'ACTIVE',
        };
      } catch {
        prior = {
          ...prior,
          checkedAt: Date.now(),
        };
      }

      await chrome.storage.local.set({
        [STATUS_KEY]: snapshotToLegacy(prior),
      });

      return prior;
    })().finally(() => {
      active = null;
    });

    return active;
  }

  async function lookup(urlValue: string): Promise<ReputationResult> {
    const checkedAt = Date.now();

    try {
      const current = await status();
      if (current.state !== 'ACTIVE') {
        return {
          providerId: 'openphish-community',
          source: 'OpenPhish Community',
          status: 'UNAVAILABLE',
          checkedAt,
          matchedUrl: null,
        };
      }

      const url = new URL(urlValue);
      url.hash = '';
      const exactFilter = `|${url.href}|`;
      const rules = await getFeedRules();
      const matched = rules.some(rule =>
        rule.condition.urlFilter === exactFilter &&
        rule.condition.isUrlFilterCaseSensitive === true
      );

      return {
        providerId: 'openphish-community',
        source: 'OpenPhish Community',
        status: matched ? 'KNOWN_MALICIOUS' : 'NO_MATCH',
        checkedAt,
        matchedUrl: matched ? url.href : null,
      };
    } catch {
      return {
        providerId: 'openphish-community',
        source: 'OpenPhish Community',
        status: 'UNAVAILABLE',
        checkedAt,
        matchedUrl: null,
      };
    }
  }

  return {
    id: 'openphish-community',
    source: 'OpenPhish Community',
    status,
    refresh,
    lookup,
    async legacyStatus() {
      return snapshotToLegacy(await status());
    },
    async legacyRefresh(force = false) {
      return snapshotToLegacy(await refresh(force));
    },
  };
}

export function installOpenPhishProtection() {
  const provider = createOpenPhishProvider();

  chrome.alarms.create('phishing-feed-refresh', { periodInMinutes: 60 });
  chrome.alarms.onAlarm.addListener(alarm => {
    if (alarm.name === 'phishing-feed-refresh') {
      void provider.refresh().catch(() => {});
    }
  });

  void provider.refresh().catch(() => {});

  return {
    status: () => provider.legacyStatus(),
    refresh: (force = false) => provider.legacyRefresh(force),
    lookup: (url: string) => provider.lookup(url),
  };
}
