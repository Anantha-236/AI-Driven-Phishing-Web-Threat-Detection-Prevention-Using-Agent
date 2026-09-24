import { describe, expect, it } from 'vitest';
import {
  createStageBShadowEvidenceLedger,
} from '../../browser-extension/src/core/stage-b-shadow-evaluation';
import type {
  ShadowStorage,
  StageBShadowSnapshot,
} from '../../browser-extension/src/core/stage-b-shadow';

function storage(): ShadowStorage & { state: Record<string, unknown> } {
  const state: Record<string, unknown> = {};
  return {
    state,
    async get(key) { return key in state ? { [key]: state[key] } : {}; },
    async set(items) { Object.assign(state, items); },
    async remove(key) { delete state[key]; },
  };
}

function snapshot(overrides: Partial<StageBShadowSnapshot> = {}): StageBShadowSnapshot {
  return {
    schema_version: 'stage-b-shadow-1',
    tab_id: 99,
    document_id: 'doc-secret-not-for-ledger',
    event_seq: 10,
    status: 'OBSERVED',
    decision_authority: 'SHADOW_ONLY',
    deployment_enabled: false,
    autonomous_blocking: false,
    model_id: 'stage-b-test',
    integration_eligible: false,
    baseline_score: 0.2,
    stage_b_score: 0.8,
    score_delta: 0.6,
    threshold: 0.7,
    would_cross_frozen_threshold: true,
    latency_ms: 4,
    error_code: null,
    updated_at: 123,
    ...overrides,
  };
}

describe('Stage B shadow evidence ledger', () => {
  it('records only privacy-safe comparison evidence', async () => {
    const mem = storage();
    const ledger = createStageBShadowEvidenceLedger(mem);
    await ledger.record(snapshot(), 'ALLOW');

    const serialized = JSON.stringify(mem.state);
    expect(serialized).not.toContain('doc-secret-not-for-ledger');
    expect(serialized).not.toContain('"tab_id"');
    expect(serialized).not.toContain('"document_id"');
    expect(serialized).not.toContain('"events"');

    const report = await ledger.readEvaluation();
    expect(report.privacy_contract).toEqual({
      stores_urls: false,
      stores_origins: false,
      stores_document_ids: false,
      stores_form_ids: false,
      stores_event_payloads: false,
    });
  });

  it('measures score delta, latency and intervention disagreement descriptively', async () => {
    const mem = storage();
    const ledger = createStageBShadowEvidenceLedger(mem);

    await ledger.record(snapshot({
      baseline_score: 0.2, stage_b_score: 0.8, score_delta: 0.6,
      would_cross_frozen_threshold: true, latency_ms: 4,
    }), 'ALLOW');
    await ledger.record(snapshot({
      baseline_score: 0.8, stage_b_score: 0.7, score_delta: -0.1,
      would_cross_frozen_threshold: true, latency_ms: 8,
    }), 'WARN');

    const report = await ledger.readEvaluation();
    expect(report.scored_observations).toBe(2);
    expect(report.score_pairs).toBe(2);
    expect(report.intervention_disagreement_count).toBe(1);
    expect(report.intervention_disagreement_rate).toBe(0.5);
    expect(report.baseline_only_intervention_count).toBe(0);
    expect(report.stage_b_only_intervention_count).toBe(1);
    expect(report.mean_latency_ms).toBe(6);
    expect(report.p95_latency_ms).toBe(8);
    expect(report.mean_score_delta).toBeCloseTo(0.25);
    expect(report.mean_absolute_score_delta).toBeCloseTo(0.35);
    expect(report.promotion_decision).toBe('NOT_EVALUATED');
  });

  it('reports candidate absence and runtime errors without inventing scores', async () => {
    const mem = storage();
    const ledger = createStageBShadowEvidenceLedger(mem);
    await ledger.record(snapshot({
      status: 'NOT_INSTALLED', model_id: null, stage_b_score: null,
      score_delta: null, threshold: null, would_cross_frozen_threshold: null,
      latency_ms: null, error_code: 'CANDIDATE_NOT_INSTALLED',
    }), 'ALLOW');
    await ledger.record(snapshot({
      status: 'ERROR', model_id: null, stage_b_score: null,
      score_delta: null, threshold: null, would_cross_frozen_threshold: null,
      latency_ms: null, error_code: 'CANDIDATE_RUNTIME_ERROR',
    }), 'WARN');

    const report = await ledger.readEvaluation();
    expect(report.status_counts.NOT_INSTALLED).toBe(1);
    expect(report.status_counts.ERROR).toBe(1);
    expect(report.scored_observations).toBe(0);
    expect(report.score_correlation_pearson).toBeNull();
    expect(report.mean_latency_ms).toBeNull();
  });

  it('bounds retained evidence instead of growing session storage indefinitely', async () => {
    const mem = storage();
    const ledger = createStageBShadowEvidenceLedger(mem);
    for (let index = 0; index < 520; index++) {
      await ledger.record(snapshot({ updated_at: index }), 'ALLOW');
    }
    const report = await ledger.readEvaluation();
    expect(report.retained_observations).toBe(512);
    expect(report.dropped_due_to_capacity).toBe(8);
    expect(report.total_observations).toBe(520);
  });

  it('clears evaluation evidence independently of per-tab shadow state', async () => {
    const mem = storage();
    const ledger = createStageBShadowEvidenceLedger(mem);
    await ledger.record(snapshot(), 'ALLOW');
    expect((await ledger.readEvaluation()).retained_observations).toBe(1);
    await ledger.clear();
    expect((await ledger.readEvaluation()).retained_observations).toBe(0);
  });
});
