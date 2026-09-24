import type { EventSecurityReport } from './assessment';
import type { StageBShadowSnapshot, ShadowStorage } from './stage-b-shadow';

export type BaselineAction = EventSecurityReport['action'];

export interface StageBShadowEvidenceRecord {
  schema_version: 'stage-b-shadow-evidence-record-1';
  captured_at: number;
  status: StageBShadowSnapshot['status'];
  baseline_action: BaselineAction;
  baseline_intervention: boolean;
  baseline_score: number | null;
  stage_b_score: number | null;
  score_delta: number | null;
  stage_b_intervention: boolean | null;
  threshold: number | null;
  latency_ms: number | null;
  integration_eligible: boolean | null;
  model_id: string | null;
  error_code: string | null;
}

interface StageBShadowEvidenceState {
  schema_version: 'stage-b-shadow-evidence-state-1';
  records: StageBShadowEvidenceRecord[];
  dropped_due_to_capacity: number;
}

export interface StageBShadowEvaluation {
  schema_version: 'stage-b-shadow-evaluation-1';
  decision_authority: 'SHADOW_ONLY';
  promotion_decision: 'NOT_EVALUATED';
  total_observations: number;
  retained_observations: number;
  dropped_due_to_capacity: number;
  status_counts: Record<StageBShadowSnapshot['status'], number>;
  scored_observations: number;
  score_pairs: number;
  candidate_availability_rate: number | null;
  runtime_error_rate: number | null;
  not_installed_rate: number | null;
  baseline_intervention_count: number;
  stage_b_intervention_count: number;
  comparable_intervention_count: number;
  intervention_disagreement_count: number;
  intervention_disagreement_rate: number | null;
  baseline_only_intervention_count: number;
  stage_b_only_intervention_count: number;
  mean_score_delta: number | null;
  mean_absolute_score_delta: number | null;
  score_correlation_pearson: number | null;
  mean_latency_ms: number | null;
  p95_latency_ms: number | null;
  integration_eligible_observations: number;
  distinct_model_ids: string[];
  privacy_contract: {
    stores_urls: false;
    stores_origins: false;
    stores_document_ids: false;
    stores_form_ids: false;
    stores_event_payloads: false;
  };
  limitations: string[];
}

const STORAGE_KEY = 'stage-b-shadow-evidence';
const MAX_RECORDS = 512;

function emptyState(): StageBShadowEvidenceState {
  return {
    schema_version: 'stage-b-shadow-evidence-state-1',
    records: [],
    dropped_due_to_capacity: 0,
  };
}

function mean(values: number[]): number | null {
  if (!values.length) return null;
  return values.reduce((sum, value) => sum + value, 0) / values.length;
}

function percentile95(values: number[]): number | null {
  if (!values.length) return null;
  const ordered = [...values].sort((a, b) => a - b);
  const index = Math.min(ordered.length - 1, Math.max(0, Math.ceil(ordered.length * 0.95) - 1));
  return ordered[index];
}

function pearson(xs: number[], ys: number[]): number | null {
  if (xs.length !== ys.length || xs.length < 2) return null;
  const mx = mean(xs);
  const my = mean(ys);
  if (mx === null || my === null) return null;

  let numerator = 0;
  let xVariance = 0;
  let yVariance = 0;
  for (let i = 0; i < xs.length; i++) {
    const dx = xs[i] - mx;
    const dy = ys[i] - my;
    numerator += dx * dy;
    xVariance += dx * dx;
    yVariance += dy * dy;
  }
  if (xVariance === 0 || yVariance === 0) return null;
  return numerator / Math.sqrt(xVariance * yVariance);
}

function finiteOrNull(value: number | null): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

function baselineIntervention(action: BaselineAction): boolean {
  return action !== 'ALLOW';
}

function evidenceFromSnapshot(
  snapshot: StageBShadowSnapshot,
  action: BaselineAction,
): StageBShadowEvidenceRecord {
  return {
    schema_version: 'stage-b-shadow-evidence-record-1',
    captured_at: snapshot.updated_at,
    status: snapshot.status,
    baseline_action: action,
    baseline_intervention: baselineIntervention(action),
    baseline_score: finiteOrNull(snapshot.baseline_score),
    stage_b_score: finiteOrNull(snapshot.stage_b_score),
    score_delta: finiteOrNull(snapshot.score_delta),
    stage_b_intervention: snapshot.would_cross_frozen_threshold,
    threshold: finiteOrNull(snapshot.threshold),
    latency_ms: finiteOrNull(snapshot.latency_ms),
    integration_eligible: snapshot.integration_eligible,
    model_id: snapshot.model_id,
    error_code: snapshot.error_code,
  };
}

function evaluate(state: StageBShadowEvidenceState): StageBShadowEvaluation {
  const records = state.records;
  const status_counts: StageBShadowEvaluation['status_counts'] = {
    NOT_INSTALLED: 0,
    READY: 0,
    OBSERVED: 0,
    ERROR: 0,
  };
  for (const record of records) status_counts[record.status]++;

  const scored = records.filter(
    record => record.status === 'OBSERVED' && record.stage_b_score !== null,
  );
  const pairs = scored.filter(
    record => record.baseline_score !== null && record.stage_b_score !== null,
  );
  const comparable = scored.filter(record => record.stage_b_intervention !== null);
  const disagreements = comparable.filter(
    record => record.baseline_intervention !== record.stage_b_intervention,
  );
  const baselineOnly = comparable.filter(
    record => record.baseline_intervention && record.stage_b_intervention === false,
  );
  const stageBOnly = comparable.filter(
    record => !record.baseline_intervention && record.stage_b_intervention === true,
  );

  const total = records.length;
  const latencies = scored
    .map(record => record.latency_ms)
    .filter((value): value is number => value !== null);
  const deltas = pairs.map(record => record.stage_b_score! - record.baseline_score!);
  const baselineScores = pairs.map(record => record.baseline_score!);
  const stageBScores = pairs.map(record => record.stage_b_score!);

  return {
    schema_version: 'stage-b-shadow-evaluation-1',
    decision_authority: 'SHADOW_ONLY',
    promotion_decision: 'NOT_EVALUATED',
    total_observations: total + state.dropped_due_to_capacity,
    retained_observations: total,
    dropped_due_to_capacity: state.dropped_due_to_capacity,
    status_counts,
    scored_observations: scored.length,
    score_pairs: pairs.length,
    candidate_availability_rate: total ? status_counts.OBSERVED / total : null,
    runtime_error_rate: total ? status_counts.ERROR / total : null,
    not_installed_rate: total ? status_counts.NOT_INSTALLED / total : null,
    baseline_intervention_count: records.filter(record => record.baseline_intervention).length,
    stage_b_intervention_count: comparable.filter(record => record.stage_b_intervention === true).length,
    comparable_intervention_count: comparable.length,
    intervention_disagreement_count: disagreements.length,
    intervention_disagreement_rate: comparable.length ? disagreements.length / comparable.length : null,
    baseline_only_intervention_count: baselineOnly.length,
    stage_b_only_intervention_count: stageBOnly.length,
    mean_score_delta: mean(deltas),
    mean_absolute_score_delta: mean(deltas.map(value => Math.abs(value))),
    score_correlation_pearson: pearson(baselineScores, stageBScores),
    mean_latency_ms: mean(latencies),
    p95_latency_ms: percentile95(latencies),
    integration_eligible_observations: scored.filter(record => record.integration_eligible === true).length,
    distinct_model_ids: [...new Set(scored.map(record => record.model_id).filter((value): value is string => !!value))].sort(),
    privacy_contract: {
      stores_urls: false,
      stores_origins: false,
      stores_document_ids: false,
      stores_form_ids: false,
      stores_event_payloads: false,
    },
    limitations: [
      'Shadow observations are repeated operational measurements and are not statistically independent samples.',
      'No ground-truth labels are stored in the shadow ledger, so this report cannot estimate accuracy, recall, precision, ROC-AUC, or real-world false-positive rate.',
      'Intervention disagreement compares the current ALLOW/WARN/CONFIRM boundary with the frozen Stage B threshold; it is not a correctness judgment.',
      'Evidence is session-local and bounded to the most recent 512 observations.',
      'Stage B remains shadow-only and this report makes no promotion or deployment decision.',
    ],
  };
}

export function createStageBShadowEvidenceLedger(storage: ShadowStorage) {
  let tail: Promise<unknown> = Promise.resolve();

  function serial<T>(fn: () => Promise<T>): Promise<T> {
    const result = tail.then(fn);
    tail = result.catch(() => {});
    return result;
  }

  async function readState(): Promise<StageBShadowEvidenceState> {
    const stored = (await storage.get(STORAGE_KEY))[STORAGE_KEY] as StageBShadowEvidenceState | undefined;
    if (!stored || stored.schema_version !== 'stage-b-shadow-evidence-state-1' || !Array.isArray(stored.records)) {
      return emptyState();
    }
    return stored;
  }

  return {
    record(snapshot: StageBShadowSnapshot, action: BaselineAction): Promise<void> {
      return serial(async () => {
        const state = await readState();
        state.records.push(evidenceFromSnapshot(snapshot, action));
        if (state.records.length > MAX_RECORDS) {
          const overflow = state.records.length - MAX_RECORDS;
          state.records.splice(0, overflow);
          state.dropped_due_to_capacity += overflow;
        }
        await storage.set({ [STORAGE_KEY]: state });
      });
    },

    readEvaluation(): Promise<StageBShadowEvaluation> {
      return serial(async () => evaluate(await readState()));
    },

    clear(): Promise<void> {
      return serial(async () => {
        await storage.remove(STORAGE_KEY);
      });
    },
  };
}
