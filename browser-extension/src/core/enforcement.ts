/**
 * CAPSTONE-1 Enforcement Module
 *
 * Orchestrates the complete detection pipeline:
 * Evidence → Features → ML Score → Assessment → Policy → Enforcement
 *
 * Responsible for:
 * - Coordinating adapter selection
 * - Running complete inference pipeline
 * - Generating enforcement decisions
 * - Messaging UI with results
 */

import { EvidenceCollection, FeatureVector, ModelResult, ExtensionMessage } from "../core/schema/types";
import { assessThreat, AssessmentContext } from "../core/assessment";
import { makePolicy, PolicyContext } from "../core/policy";
import { extractFeatureVector } from "../features/extractor";

export const PHISHING_FEED_URL = 'https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt';
const FEED_RULE_START = 10000;
const FEED_RULE_LIMIT = 1000;
const FEED_REFRESH_MS = 12 * 60 * 60 * 1000;
const FEED_MAX_AGE_MS = 48 * 60 * 60 * 1000;
export interface ProtectionStatus {
  source: 'OpenPhish Community'; updated_at: number | null; checked_at: number;
  rule_count: number; excluded_count: number; state: 'ACTIVE' | 'UNAVAILABLE' | 'EXPIRED';
}
// External threat indicators only, never URLs collected from browsing. Exact,
// case-sensitive URL matches avoid blocking unrelated tenants on shared hosting.
// Query-bearing indicators are excluded instead of retaining token-like data or
// silently broadening a match to an entire origin. Hash fragments are not sent.
export function compilePhishingRules(text: string): { rules: chrome.declarativeNetRequest.Rule[]; excluded: number } {
  if (text.length > 2_000_000) throw new Error('Feed exceeds size limit');
  const urls = new Set<string>(); let excluded = 0;
  for (const line of text.split(/\r?\n/).filter(line => line.trim())) {
    try {
      const url = new URL(line.trim());
      if (!['https:', 'http:'].includes(url.protocol) || url.username || url.password || url.search ||
        /[\s*|^]/.test(line) || line.length > 1800 || !url.hostname.includes('.') ||
        url.hostname.endsWith('.localhost') || /^[\d.]+$/.test(url.hostname) || url.hostname.includes(':')) { excluded++; continue; }
      url.hash = '';
      if (urls.size >= FEED_RULE_LIMIT && !urls.has(url.href)) { excluded++; continue; }
      urls.add(url.href);
    } catch { excluded++; }
  }
  return { rules: [...urls].map((url, i) => ({ id: FEED_RULE_START + i, priority: 1,
    action: { type: 'block' as chrome.declarativeNetRequest.RuleActionType },
    condition: { urlFilter: `|${url}|`, isUrlFilterCaseSensitive: true,
      resourceTypes: ['main_frame', 'sub_frame', 'xmlhttprequest', 'script', 'image', 'stylesheet', 'font', 'object', 'ping', 'csp_report', 'media', 'websocket', 'webtransport', 'webbundle', 'other'] as chrome.declarativeNetRequest.ResourceType[] } })), excluded };
}

export function installThreatBlocking() {
  let active: Promise<ProtectionStatus> | null = null;
  async function status(): Promise<ProtectionStatus> {
    const saved = (await chrome.storage.local.get('phishing-feed-status'))['phishing-feed-status'];
    const rules = await chrome.declarativeNetRequest.getDynamicRules();
    return { source: 'OpenPhish Community', updated_at: saved?.updated_at ?? null, checked_at: saved?.checked_at ?? 0,
      rule_count: rules.filter(r => r.id >= FEED_RULE_START && r.id < FEED_RULE_START + FEED_RULE_LIMIT).length,
      excluded_count: saved?.excluded_count ?? 0,
      state: saved?.updated_at && Date.now() - saved.updated_at <= FEED_MAX_AGE_MS ? 'ACTIVE' : saved?.updated_at ? 'EXPIRED' : 'UNAVAILABLE' };
  }
  function refresh(force = false): Promise<ProtectionStatus> {
    if (active) return active;
    active = (async () => {
      let prior = await status();
      if (prior.state === 'EXPIRED') {
        const rules = await chrome.declarativeNetRequest.getDynamicRules();
        await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: rules.filter(r => r.id >= FEED_RULE_START && r.id < FEED_RULE_START + FEED_RULE_LIMIT).map(r => r.id) });
        prior = await status();
      }
      if (!force && Date.now() - prior.checked_at < (prior.state === 'ACTIVE' ? FEED_REFRESH_MS : 60 * 60 * 1000)) return prior;
      try {
        const response = await fetch(PHISHING_FEED_URL, { credentials: 'omit', cache: 'no-store', signal: AbortSignal.timeout(15000) });
        if (!response.ok) throw new Error('Feed unavailable');
        const { rules, excluded } = compilePhishingRules(await response.text());
        if (!rules.length) throw new Error('No valid indicators');
        const old = await chrome.declarativeNetRequest.getDynamicRules();
        await chrome.declarativeNetRequest.updateDynamicRules({
          removeRuleIds: old.filter(r => r.id >= FEED_RULE_START && r.id < FEED_RULE_START + FEED_RULE_LIMIT).map(r => r.id), addRules: rules });
        prior = { source: 'OpenPhish Community', updated_at: Date.now(), checked_at: Date.now(), rule_count: rules.length, excluded_count: excluded, state: 'ACTIVE' };
      } catch { prior = { ...prior, checked_at: Date.now() }; }
      await chrome.storage.local.set({ 'phishing-feed-status': prior });
      return prior;
    })().finally(() => { active = null; });
    return active;
  }
  chrome.alarms.create('phishing-feed-refresh', { periodInMinutes: 60 });
  chrome.alarms.onAlarm.addListener(alarm => { if (alarm.name === 'phishing-feed-refresh') void refresh().catch(() => {}); });
  void refresh().catch(() => {});
  return { status, refresh };
}

export interface DetectionResult {
  evidence: EvidenceCollection;
  features: FeatureVector;
  modelResult: ModelResult;
  threat: Awaited<ReturnType<typeof assessThreat>>;
  policy: Awaited<ReturnType<typeof makePolicy>>;
}

/**
 * Execute the complete detection pipeline for collected evidence.
 *
 * This is the main orchestration function that coordinates all
 * detection components into one cohesive system.
 */
export async function runDetectionPipeline(
  evidence: EvidenceCollection,
  adapter: { infer: (features: FeatureVector) => Promise<ModelResult> }
): Promise<DetectionResult> {
  // Step 1: Extract features from evidence
  const features = extractFeatureVector(evidence);

  // Step 2: Run ML inference
  const modelResult = await adapter.infer(features);

  // Step 3: Assess threat
  const assessmentContext: AssessmentContext = {
    modelResult,
    evidence,
    features,
  };
  const threat = assessThreat(assessmentContext);

  // Step 4: Make policy decision
  const policyContext: PolicyContext = {
    assessment: threat,
    pageDomain: evidence.page.domain,
    // could check if page is sensitive context (login, payment, etc)
  };
  const policy = makePolicy(policyContext);

  return {
    evidence,
    features,
    modelResult,
    threat,
    policy,
  };
}

/**
 * Convert a detection result into a message for UI.
 *
 * The UI needs:
 * - Threat level
 * - Score
 * - Confidence
 * - Reasons why
 * - Recommended action
 */
export function createDetectionMessage(
  result: DetectionResult
): ExtensionMessage<{
  threatLevel: string;
  score: number;
  confidence: number;
  reasons: string[];
  action: string;
  outcome: string;
  domain: string;
  requestedDataTypes: string[];
}> {
  return {
    type: "POLICY_DECISION",
    source: "service-worker",
    target: "content-script",
    payload: {
      threatLevel: result.threat.threatLevel,
      score: result.modelResult.rawScore,
      confidence: result.threat.confidence,
      reasons: result.threat.reasons,
      action: result.policy.action,
      outcome: result.policy.outcome,
      domain: result.evidence.page.domain,
      requestedDataTypes: result.evidence.requestedDataTypes || [],
    },
    timestamp: Date.now(),
  };
}
