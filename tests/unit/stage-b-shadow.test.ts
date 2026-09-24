import { describe, expect, it } from 'vitest';
import { CONTEXT_FEATURES, type SensitiveEvent } from '../../browser-extension/src/core/tsfeg';
import { createStageBShadowController, type ShadowStorage } from '../../browser-extension/src/core/stage-b-shadow';

function memoryStorage(): ShadowStorage & { state: Record<string, unknown> } {
  const state: Record<string, unknown> = {};
  return {
    state,
    async get(key) { return key in state ? { [key]: state[key] } : {}; },
    async set(items) { Object.assign(state, items); },
    async remove(key) { delete state[key]; },
  };
}

function event(): SensitiveEvent {
  return {
    schema_version: '1.2.0',
    evidence_status: 'OBSERVED',
    analysis_version: 'event-analysis-1',
    model_version: 'pending',
    policy_version: 'evidence-policy-1',
    session_id: 'session',
    tab_id: 7,
    document_id: 'doc-1',
    frame_id: 0,
    parent_frame_id: null,
    event_seq: 1,
    received_ms: 1,
    trust: 'ISOLATED_CONTENT_SCRIPT',
    confidence: 1,
    event_type: 'DOCUMENT_STARTED',
    sensitive_type: null,
    field_id: null,
    form_id: null,
    frame_origin: 'https://example.test',
    target_origin: null,
    destination_origin: null,
    initiator_origin: null,
    request_type: null,
    interaction_type: null,
    page_purpose: null,
    purpose_source: null,
    timestamp_ms: 1,
  };
}

describe('Stage B shadow controller', () => {
  it('records NOT_INSTALLED without invoking inference', async () => {
    const storage = memoryStorage();
    let inferCalls = 0;
    const controller = createStageBShadowController({
      async loadInstalledCandidate() { throw new Error('Stage B candidate manifest unavailable: 404'); },
      async inferVector() { inferCalls++; throw new Error('must not run'); },
      healthCheck() { return { available: false, error: 'candidate_not_loaded' as const }; },
    }, storage);

    expect(await controller.initialize()).toBe('NOT_INSTALLED');
    const result = await controller.observe({
      tabId: 7, documentId: 'doc-1', eventSeq: 1, events: [event()],
      incomplete: false, baselineScore: 0.2,
    });

    expect(inferCalls).toBe(0);
    expect(result.status).toBe('NOT_INSTALLED');
    expect(result.decision_authority).toBe('SHADOW_ONLY');
    expect(result.deployment_enabled).toBe(false);
    expect(result.autonomous_blocking).toBe(false);
  });

  it('scores the exact production contextual vector but returns only shadow metadata', async () => {
    const storage = memoryStorage();
    let seen: readonly number[] = [];
    const controller = createStageBShadowController({
      async loadInstalledCandidate() {},
      async inferVector(values) {
        seen = values;
        return {
          score: 0.75, threshold: 0.8, would_cross_frozen_threshold: false,
          model_id: 'stage-b-test', runtime: 'onnxruntime-web-wasm',
          latency_ms: 3, integration_eligible: false,
          deployment_enabled: false, autonomous_blocking: false,
        };
      },
      healthCheck() { return { available: true, model_id: 'stage-b-test', integration_eligible: false }; },
    }, storage);

    expect(await controller.initialize()).toBe('READY');
    const result = await controller.observe({
      tabId: 7, documentId: 'doc-1', eventSeq: 1, events: [event()],
      incomplete: false, baselineScore: 0.25,
    });

    expect(seen).toHaveLength(CONTEXT_FEATURES.length);
    expect(result.status).toBe('OBSERVED');
    expect(result.stage_b_score).toBe(0.75);
    expect(result.score_delta).toBeCloseTo(0.5);
    expect(result.would_cross_frozen_threshold).toBe(false);
    expect(result.decision_authority).toBe('SHADOW_ONLY');
    expect(result.deployment_enabled).toBe(false);
    expect(result.autonomous_blocking).toBe(false);
  });

  it('preserves an unavailable authoritative baseline score as null', async () => {
    const storage = memoryStorage();
    const controller = createStageBShadowController({
      async loadInstalledCandidate() {},
      async inferVector() {
        return {
          score: 0.6, threshold: 0.8, would_cross_frozen_threshold: false,
          model_id: 'stage-b-test', runtime: 'onnxruntime-web-wasm',
          latency_ms: 2, integration_eligible: false,
          deployment_enabled: false, autonomous_blocking: false,
        };
      },
      healthCheck() { return { available: true, model_id: 'stage-b-test', integration_eligible: false }; },
    }, storage);
    await controller.initialize();

    const result = await controller.observe({
      tabId: 7, documentId: 'doc-1', eventSeq: 1, events: [event()],
      incomplete: false, baselineScore: null,
    });

    expect(result.status).toBe('OBSERVED');
    expect(result.baseline_score).toBeNull();
    expect(result.score_delta).toBeNull();
    expect(result.stage_b_score).toBe(0.6);
  });

  it('contains candidate failures instead of throwing them into the decision path', async () => {
    const storage = memoryStorage();
    const controller = createStageBShadowController({
      async loadInstalledCandidate() {},
      async inferVector() { throw new Error('Stage B candidate returned an invalid probability tensor'); },
      healthCheck() { return { available: true, model_id: 'stage-b-test', integration_eligible: true }; },
    }, storage);
    await controller.initialize();

    const result = await controller.observe({
      tabId: 7, documentId: 'doc-1', eventSeq: 1, events: [event()],
      incomplete: false, baselineScore: 0.4,
    });
    expect(result.status).toBe('ERROR');
    expect(result.error_code).toBe('CANDIDATE_CONTRACT_ERROR');
    expect(result.stage_b_score).toBeNull();
  });

  it('clears per-tab shadow state independently', async () => {
    const storage = memoryStorage();
    const controller = createStageBShadowController({
      async loadInstalledCandidate() { throw new Error('Stage B candidate manifest unavailable: 404'); },
      async inferVector() { throw new Error('not used'); },
      healthCheck() { return { available: false, error: 'candidate_not_loaded' as const }; },
    }, storage);
    await controller.initialize();
    await controller.observe({
      tabId: 7, documentId: 'doc-1', eventSeq: 1, events: [event()],
      incomplete: false, baselineScore: 0.1,
    });
    expect(await controller.read(7)).not.toBeNull();
    await controller.clear(7);
    expect(await controller.read(7)).toBeNull();
  });
});
