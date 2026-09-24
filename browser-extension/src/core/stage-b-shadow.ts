import { buildContextFeatures, type SensitiveEvent } from './tsfeg';
import type { StageBInferenceResult } from './stage-b-onnx-adapter';

export type StageBShadowStatus = 'NOT_INSTALLED' | 'READY' | 'OBSERVED' | 'ERROR';

export interface StageBShadowSnapshot {
  schema_version: 'stage-b-shadow-1';
  tab_id: number;
  document_id: string | null;
  event_seq: number;
  status: StageBShadowStatus;
  decision_authority: 'SHADOW_ONLY';
  deployment_enabled: false;
  autonomous_blocking: false;
  model_id: string | null;
  integration_eligible: boolean | null;
  baseline_score: number | null;
  stage_b_score: number | null;
  score_delta: number | null;
  threshold: number | null;
  would_cross_frozen_threshold: boolean | null;
  latency_ms: number | null;
  error_code: string | null;
  updated_at: number;
}

export interface StageBShadowAdapter {
  loadInstalledCandidate(): Promise<void>;
  inferVector(values: readonly number[]): Promise<StageBInferenceResult>;
  healthCheck():
    | { available: true; model_id: string; integration_eligible: boolean }
    | { available: false; error: 'candidate_not_loaded' };
}

export interface ShadowStorage {
  get(key: string): Promise<Record<string, unknown>>;
  set(items: Record<string, unknown>): Promise<void>;
  remove(key: string): Promise<void>;
}

type ObserveInput = {
  tabId: number;
  documentId: string | null;
  eventSeq: number;
  events: SensitiveEvent[];
  incomplete: boolean;
  baselineScore: number | null;
};

const PREFIX = 'stage-b-shadow:';

function key(tabId: number): string {
  return `${PREFIX}${tabId}`;
}

function finiteScore(value: number | null): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

function errorCode(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  if (/manifest unavailable:\s*404|candidate_not_loaded/i.test(message)) return 'CANDIDATE_NOT_INSTALLED';
  if (/sha-256 mismatch/i.test(message)) return 'CANDIDATE_HASH_MISMATCH';
  if (/feature|contract|input|output|probability/i.test(message)) return 'CANDIDATE_CONTRACT_ERROR';
  return 'CANDIDATE_RUNTIME_ERROR';
}

export function createStageBShadowController(
  adapter: StageBShadowAdapter,
  storage: ShadowStorage,
) {
  let loadStatus: StageBShadowStatus = 'NOT_INSTALLED';
  let loadError: string | null = 'CANDIDATE_NOT_INSTALLED';

  async function initialize(): Promise<StageBShadowStatus> {
    try {
      await adapter.loadInstalledCandidate();
      const health = adapter.healthCheck();
      if (!health.available) throw new Error(health.error);
      loadStatus = 'READY';
      loadError = null;
    } catch (error) {
      loadError = errorCode(error);
      loadStatus = loadError === 'CANDIDATE_NOT_INSTALLED' ? 'NOT_INSTALLED' : 'ERROR';
    }
    return loadStatus;
  }

  async function write(snapshot: StageBShadowSnapshot): Promise<void> {
    await storage.set({ [key(snapshot.tab_id)]: snapshot });
  }

  async function observe(input: ObserveInput): Promise<StageBShadowSnapshot> {
    const base: StageBShadowSnapshot = {
      schema_version: 'stage-b-shadow-1',
      tab_id: input.tabId,
      document_id: input.documentId,
      event_seq: input.eventSeq,
      status: loadStatus,
      decision_authority: 'SHADOW_ONLY',
      deployment_enabled: false,
      autonomous_blocking: false,
      model_id: null,
      integration_eligible: null,
      baseline_score: finiteScore(input.baselineScore),
      stage_b_score: null,
      score_delta: null,
      threshold: null,
      would_cross_frozen_threshold: null,
      latency_ms: null,
      error_code: loadError,
      updated_at: Date.now(),
    };

    if (loadStatus !== 'READY') {
      await write(base);
      return base;
    }

    try {
      const context = buildContextFeatures(input.events, input.incomplete);
      const result = await adapter.inferVector(context.vector);
      const baseline = finiteScore(input.baselineScore);
      const snapshot: StageBShadowSnapshot = {
        ...base,
        status: 'OBSERVED',
        model_id: result.model_id,
        integration_eligible: result.integration_eligible,
        baseline_score: baseline,
        stage_b_score: result.score,
        score_delta: baseline === null ? null : result.score - baseline,
        threshold: result.threshold,
        would_cross_frozen_threshold: result.would_cross_frozen_threshold,
        latency_ms: result.latency_ms,
        error_code: null,
        updated_at: Date.now(),
      };
      await write(snapshot);
      return snapshot;
    } catch (error) {
      const snapshot: StageBShadowSnapshot = {
        ...base,
        status: 'ERROR',
        error_code: errorCode(error),
        updated_at: Date.now(),
      };
      await write(snapshot);
      return snapshot;
    }
  }

  async function read(tabId: number): Promise<StageBShadowSnapshot | null> {
    const stored = (await storage.get(key(tabId)))[key(tabId)] as StageBShadowSnapshot | undefined;
    return stored?.schema_version === 'stage-b-shadow-1' ? stored : null;
  }

  async function clear(tabId: number): Promise<void> {
    await storage.remove(key(tabId));
  }

  return {
    initialize,
    observe,
    read,
    clear,
    status: () => ({ status: loadStatus, error_code: loadError }),
  };
}
