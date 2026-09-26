import { afterEach, describe, it, expect, vi } from 'vitest';
import { buildGraph, buildFlatControl, createRecorder, createContentEventQueue, observation, safeOrigin, validateObservation, validateContentBatch, ContentBatch, SensitiveEvent } from '../../browser-extension/src/core/tsfeg';
import { buildEventRepresentations, buildContextFeatures, CONTEXT_FEATURES, Observation } from '../../browser-extension/src/core/tsfeg';
import { assessEventStream } from '../../browser-extension/src/core/assessment';
import { inferEventModel, EventModelArtifact } from '../../browser-extension/src/core/service-worker-onnx-adapter';
import { readFileSync } from 'node:fs';
import { compilePhishingRules } from '../../browser-extension/src/core/enforcement';
import { identifyOrigin } from '../../browser-extension/src/core/profiles/service-profiles';
const context = { tab_id: 1, document_id: 'a'.repeat(32), frame_id: 0, parent_frame_id: -1, trust: 'ISOLATED_CONTENT_SCRIPT' as const };

it('uses exact sourced login origins and never treats example profiles or lookalike suffixes as verified', () => {
  expect(identifyOrigin('https://accounts.google.com').status).toBe('KNOWN_LOGIN_ORIGIN');
  expect(identifyOrigin('https://accounts.google.com.attacker.test')).toMatchObject({ status: 'POSSIBLE_IMPERSONATION', service: 'google' });
  expect(identifyOrigin('https://paypal-login.test').status).toBe('POSSIBLE_IMPERSONATION');
  for (const origin of ['https://bankone.com', 'https://secure-bank.example.com', 'https://tenant.google.com', 'http://accounts.google.com', 'https://accounts.google.com:8443']) {
    expect(identifyOrigin(origin).status).toBe('UNKNOWN');
  }
});

it('compiles exact case-sensitive feed URLs without broadening shared-host paths or retaining query secrets', () => {
  const compiled = compilePhishingRules('https://tenant.example.test/Phish\nhttps://tenant.example.test/Phish#section\nhttps://tenant.example.test/?token=SECRET\nhttps://user:SECRET@host.test/\nhttps://evil.test/*\nnot a URL');
  expect(compiled.rules).toHaveLength(1);
  expect(compiled.rules[0].condition).toMatchObject({ urlFilter: '|https://tenant.example.test/Phish|', isUrlFilterCaseSensitive: true, resourceTypes: expect.arrayContaining(['main_frame', 'xmlhttprequest']) });
  expect(compiled.excluded).toBe(4);
  expect(JSON.stringify(compiled)).not.toContain('SECRET');
});

it('keeps sensitive fields and unrelated nearby requests from independently triggering warnings', async () => {
  const { recorder } = setup();
  const base = { frame_origin: 'https://shop.test', form_id: 'f-1' };
  for (const ev of [observation({ event_type: 'DOCUMENT_STARTED', frame_origin: base.frame_origin }),
    observation({ event_type: 'FIELD_DISCOVERED', ...base, field_id: 'e-1', sensitive_type: 'PASSWORD' }),
    observation({ event_type: 'FORM_TARGET_OBSERVED', ...base, target_origin: 'https://payments.test' }),
    observation({ event_type: 'SENSITIVE_INTERACTION', ...base, field_id: 'e-1', sensitive_type: 'PASSWORD' }),
    observation({ event_type: 'REQUEST_OBSERVED', initiator_origin: base.frame_origin, destination_origin: 'https://analytics.test' })]) await recorder.append(ev, context);
  const report = assessEventStream((await recorder.snapshot(1)).events, null)!;
  expect(report.action).toBe('ALLOW');
  expect(report.form_destinations[0]).toMatchObject({ target_origin: 'https://payments.test', status: 'UNVERIFIED_CROSS_ORIGIN', sensitive_types: ['PASSWORD'] });
  expect(report.identity.status).toBe('UNKNOWN');
});

it('shares a browser session across tabs without merging tab sequences', async () => {
  const { recorder } = setup();
  const [first, second] = await Promise.all([
    recorder.append(observation({ event_type: 'DOCUMENT_STARTED' }), context),
    recorder.append(observation({ event_type: 'DOCUMENT_STARTED' }), { ...context, tab_id: 2 }),
  ]);
  expect(first.session_id).toBe(second.session_id);
  expect(first.event_seq).toBe(1); expect(second.event_seq).toBe(1);
  expect((await recorder.snapshot(1)).events).toHaveLength(1);
});

it('recovers from a message promise that never settles', async () => {
  vi.useFakeTimers();
  let attempts = 0;
  const queue = createContentEventQueue(async batch => {
    if (++attempts === 1) return new Promise(() => {});
    return { ok: true, source_id: batch.source_id, batch_seq: batch.batch_seq, accepted: batch.events.length };
  });
  queue.enqueue([observation({ event_type: 'DOCUMENT_STARTED' })]);
  await vi.advanceTimersByTimeAsync(3000);
  expect(queue.snapshot()).toMatchObject({ queued_events: 1, delivery_errors: 1 });
  await vi.advanceTimersByTimeAsync(1000);
  expect(queue.snapshot().queued_events).toBe(0);
});

it('allows a replay-scoped acknowledgement window without changing queue semantics', async () => {
  vi.useFakeTimers();
  const queue = createContentEventQueue(
    async batch => {
      await new Promise(resolve => setTimeout(resolve, 4000));
      return {
        ok: true,
        source_id: batch.source_id,
        batch_seq: batch.batch_seq,
        accepted: batch.events.length,
      };
    },
    { acknowledgementTimeoutMs: 10_000, retryDelayMs: 250 },
  );

  queue.enqueue([observation({ event_type: 'DOCUMENT_STARTED' })]);
  await vi.advanceTimersByTimeAsync(3999);
  expect(queue.snapshot()).toMatchObject({
    queued_events: 1,
    delivery_errors: 0,
  });
  await vi.advanceTimersByTimeAsync(1);
  expect(queue.snapshot()).toMatchObject({
    queued_events: 0,
    delivery_errors: 0,
    dropped_events: 0,
  });
});

it('keeps local recording available during an unresolved backend request', async () => {
  let release!: () => void;
  const blocked = new Promise<void>(resolve => { release = resolve; });
  const { recorder } = setup(() => blocked);
  await recorder.append(observation({ event_type: 'DOCUMENT_STARTED' }), context);
  const flushing = recorder.flush(1);
  await recorder.append(observation({ event_type: 'DOM_MUTATION' }), context);
  expect((await recorder.snapshot(1)).events).toHaveLength(2);
  release(); await flushing;
  expect((await recorder.snapshot(1)).pending).toHaveLength(0);
});

it('derives both representations from unchanged events and does not warn on cross-origin authentication alone', async () => {
  const { recorder } = setup();
  for (const ev of [observation({ event_type: 'DOCUMENT_STARTED', frame_origin: 'https://login.test' }),
    observation({ event_type: 'FIELD_DISCOVERED', form_id: 'f-1', field_id: 'e-2', sensitive_type: 'PASSWORD', frame_origin: 'https://login.test' }),
    observation({ event_type: 'FORM_TARGET_OBSERVED', form_id: 'f-1', frame_origin: 'https://login.test', target_origin: 'https://idp.test' })]) await recorder.append(ev, context);
  const events = (await recorder.snapshot(1)).events, before = JSON.stringify(events);
  const features = buildEventRepresentations(events);
  expect(features.flat_vector).toHaveLength(14);
  expect(features.relationship_vector).toHaveLength(22);
  expect(features.relationship.sensitive_cross_target).toBe(1);
  expect(assessEventStream(events, null)?.action).toBe('ALLOW');
  expect(JSON.stringify(events)).toBe(before);
});

it('matches Python trained logistic predictions and refuses incompatible feature vectors', () => {
  const model = JSON.parse(readFileSync('browser-extension/assets/event-model.json', 'utf8')) as EventModelArtifact;
  const evaluation = JSON.parse(readFileSync('browser-extension/assets/event-model.json', 'utf8'));
  for (const row of evaluation.parity_cases) expect(inferEventModel(model, row.features)).toBeCloseTo(row.score, 12);
  expect(() => inferEventModel(model, [0])).toThrow('mismatch');
});

function contextTimeline(rows: Array<Partial<Observation> & Pick<Observation, 'event_type'> & Partial<typeof context>>): SensitiveEvent[] {
  return rows.map((row, index) => ({ ...observation(row), ...context, ...row, schema_version: '1.2.0',
    session_id: 'context-unit-session', event_seq: index + 1, received_ms: 1000 + index * 100,
    timestamp_ms: 1000 + index * 100, confidence: row.document_id === null ? 0.5 : 1 })) as SensitiveEvent[];
}
function contextualModel(intercept = 0): EventModelArtifact {
  return { model_id: 'context-unit-model', feature_version: 'context-features-1', representation: 'contextual-flat',
    feature_names: [...CONTEXT_FEATURES], provenance: 'SYNTHETIC', calibrated: false, autonomous_blocking: false,
    mean: CONTEXT_FEATURES.map(() => 0), scale: CONTEXT_FEATURES.map(() => 1), coefficients: CONTEXT_FEATURES.map(() => 0), intercept };
}
describe('local contextual agent', () => {
  const form = { frame_origin: 'https://unknown-portal.test', form_id: 'f-1' };
  const login = (): SensitiveEvent[] => contextTimeline([
    { event_type: 'DOCUMENT_STARTED', frame_origin: form.frame_origin },
    { event_type: 'PAGE_CONTEXT_OBSERVED', frame_origin: form.frame_origin, page_purpose: 'LOGIN', purpose_source: 'STATIC_SEMANTICS' },
    { event_type: 'FIELD_DISCOVERED', ...form, field_id: 'e-1', sensitive_type: 'PASSWORD' },
    { event_type: 'FORM_TARGET_OBSERVED', ...form, target_origin: 'https://unfamiliar-sso.test' },
    { event_type: 'SENSITIVE_INTERACTION', ...form, field_id: 'e-1', sensitive_type: 'PASSWORD' },
    { event_type: 'DOM_MUTATION', frame_origin: form.frame_origin },
    { event_type: 'FIELD_DISCOVERED', ...form, field_id: 'e-2', sensitive_type: 'OTP' },
    { event_type: 'SENSITIVE_INTERACTION', ...form, field_id: 'e-2', sensitive_type: 'OTP' },
    { event_type: 'REQUEST_OBSERVED', frame_origin: form.frame_origin, initiator_origin: form.frame_origin, destination_origin: 'https://analytics.test' },
    { event_type: 'FORM_SUBMISSION_ATTEMPT', ...form, target_origin: 'https://unfamiliar-sso.test' },
  ]);
  it('allows hard legitimate unknown SSO with dynamic OTP and unrelated cross-origin traffic even against a high synthetic score', () => {
    const report = assessEventStream(login(), contextualModel(20))!;
    expect(report).toMatchObject({ action: 'ALLOW', risk: 'LOW', threatLevel: 'benign', decision_source: 'LOCAL_ML_AGENT', agent_version: 'local-context-agent-1', model_provenance: 'SYNTHETIC' });
    expect(report.purpose).toMatchObject({ value: 'LOGIN', evidence_status: 'INFERRED', confidence: 'MEDIUM' });
    expect(report.contradictions).toEqual([]);
    expect(report.positive_evidence).toContain('AUTHENTICATION_SEQUENCE_CONSISTENT');
    expect(report.positive_evidence).toContain('REPEATED_STABLE_SENSITIVE_TARGET');
    expect(report.decision_reasons).toContain('MODEL_DISAGREES_WITH_CONTEXT');
    expect(report.evidence_completeness.level).toBe('SUFFICIENT');
    expect(report.contextual_parameters).toHaveLength(27);
  });
  it('keeps collection completeness, risk and confidence separate', () => {
    const complete = assessEventStream(login(), null)!;
    const incomplete = assessEventStream(login(), contextualModel(-20), true)!;
    expect(complete.risk).toBe('LOW');
    expect(incomplete).toMatchObject({ action: 'ALLOW', risk: 'UNKNOWN', threatLevel: 'insufficient_evidence', confidence: 'LOW' });
    expect(incomplete.evidence_completeness.score).toBeLessThan(complete.evidence_completeness.score);
    expect(incomplete.evidence_completeness.missing).toContain('COLLECTION_LOSS');
  });
  it('detects a purpose contradiction without pretending that field-derived purpose was independently observed', () => {
    const events = login();
    events[1] = { ...events[1], page_purpose: 'DOWNLOAD' };
    const report = assessEventStream(events, null)!;
    expect(report.action).toBe('WARN');
    expect(report.contradictions).toContain('SENSITIVE_REQUEST_PURPOSE_MISMATCH');
    const structural = buildContextFeatures(events.filter(e => e.event_type !== 'PAGE_CONTEXT_OBSERVED'));
    expect(structural.purpose).toMatchObject({ value: 'LOGIN', confidence: 'LOW', basis: ['STRUCTURAL_FIELD_TYPES'] });
    expect(structural.features.purpose_observed).toBe(0);
    expect(structural.contradictions).toEqual([]);
  });
  it('clears a stale semantic category when the page context becomes unknown', () => {
    const events = login();
    events.push({ ...events[1], event_seq: 20, page_purpose: 'UNKNOWN', purpose_source: 'UNKNOWN' });
    const result = buildContextFeatures(events);
    expect(result.features.purpose_observed).toBe(0);
    expect(result.positive_evidence).not.toContain('REQUEST_MATCHES_APPARENT_PURPOSE');
    expect(result.purpose.limitations).toContain('NO_INDEPENDENT_PURPOSE_OBSERVATION');
  });
  it('confirms a sensitive submission target replacement using same-form evidence, and never pairs HIGH with benign', () => {
    const events = login();
    events[events.length - 1].target_origin = 'https://collector.test';
    const report = assessEventStream(events, contextualModel(-20))!;
    expect(report).toMatchObject({ action: 'CONFIRM', risk: 'HIGH' });
    expect(report.threatLevel).not.toBe('benign');
    expect(report.contradictions).toContain('INTERACTED_SENSITIVE_SUBMISSION_REDIRECTED');
    expect(report.unknowns).toContain('VALUE_TRANSMISSION_UNKNOWN');
  });
  it('does not merge separate documents, frames or forms to manufacture a target-swap contradiction', () => {
    for (const separation of [{ document_id: 'b'.repeat(32) }, { frame_id: 2 }, { form_id: 'f-2' }, { document_id: null }]) {
      const events = login();
      events[events.length - 1] = { ...events[events.length - 1], target_origin: 'https://collector.test', ...separation };
      const report = assessEventStream(events, null)!;
      expect(report.contradictions).not.toContain('INTERACTED_SENSITIVE_SUBMISSION_REDIRECTED');
      expect(report.action).toBe('ALLOW');
    }
  });
  it('rejects unsupported, reordered, nonfinite and falsely calibrated models while retaining evidence decisions', () => {
    const good = contextualModel();
    const bad: EventModelArtifact[] = [
      { ...good, feature_version: 'future-version' },
      { ...good, feature_names: [...CONTEXT_FEATURES].reverse() },
      { ...good, coefficients: [NaN, ...good.coefficients.slice(1)] },
      { ...good, calibrated: true },
    ];
    for (const model of bad) {
      expect(() => inferEventModel(model, CONTEXT_FEATURES.map(() => 0))).toThrow();
      expect(assessEventStream(login(), model)).toMatchObject({ model_score: null, model_id: 'unavailable', action: 'ALLOW' });
    }
    expect(inferEventModel({ ...good, intercept: 2, calibrated: true, calibration: { method: 'sigmoid', coefficient: 0.5, intercept: -1 } }, CONTEXT_FEATURES.map(() => 0))).toBe(0.5);
  });
  it('accepts only purpose categories and never raw semantic strings in the privacy boundary', () => {
    expect(validateObservation(observation({ event_type: 'PAGE_CONTEXT_OBSERVED', page_purpose: 'LOGIN', purpose_source: 'STATIC_SEMANTICS' }))).toBe(true);
    expect(validateObservation({ ...observation({ event_type: 'PAGE_CONTEXT_OBSERVED', purpose_source: 'STATIC_SEMANTICS' }), page_purpose: 'secret page text' })).toBe(false);
    expect(validateObservation(observation({ event_type: 'FIELD_DISCOVERED', page_purpose: 'LOGIN', purpose_source: 'STATIC_SEMANTICS' }))).toBe(false);
    expect(validateObservation(observation({ event_type: 'PAGE_CONTEXT_OBSERVED', page_purpose: 'LOGIN', purpose_source: 'UNKNOWN' }))).toBe(false);
  });
});
function setup(deliver: (events: SensitiveEvent[]) => Promise<void> = async () => {}) {
  const state: Record<string, unknown> = {};
  const storage = { get: async (key: string) => structuredClone({ [key]: state[key] }),
    set: async (value: Record<string, unknown>) => { Object.assign(state, structuredClone(value)); } };
  return { storage, recorder: createRecorder(storage, deliver) };
}
afterEach(() => { vi.clearAllTimers(); vi.useRealTimers(); });
function batch(count = 20): ContentBatch {
  return { type: 'TYPED_EVENTS', source_id: crypto.randomUUID(), batch_seq: 1, dropped_events: 0, delivery_errors: 0,
    events: Array.from({ length: count }, () => observation({ event_type: 'FIELD_DISCOVERED', sensitive_type: 'OTP' })) };
}
describe('M1 shared root-cause regressions', () => {
  it('commits a batch atomically, deduplicates concurrent/restarted delivery, and binds receipts to the browser document', async () => {
    const { recorder, storage } = setup();
    const input = batch();
    expect(validateContentBatch(input)).toBe(true);
    expect(validateContentBatch({ ...input, raw: 'AUDIT_CANARY' })).toBe(false);
    const save = storage.set;
    storage.set = async () => { throw new Error('storage unavailable'); };
    await expect(recorder.appendBatch(input, context)).rejects.toThrow('storage unavailable');
    storage.set = save;
    expect((await recorder.snapshot(1)).events).toHaveLength(0);
    await Promise.all([recorder.appendBatch(input, context), recorder.appendBatch(input, context)]);
    const restarted = createRecorder(storage, async () => {});
    const receipt = await restarted.appendBatch(input, context);
    expect(receipt).toEqual({ ok: true, source_id: input.source_id, batch_seq: 1, accepted: 20 });
    expect((await restarted.snapshot(1)).events).toHaveLength(20);
    await expect(restarted.appendBatch({ ...input, events: [observation({ event_type: 'DOM_MUTATION' })] }, context)).rejects.toThrow('different events');
    await restarted.appendBatch(input, { ...context, document_id: 'b'.repeat(32) });
    expect((await restarted.snapshot(1)).events.map(e => e.event_seq)).toEqual(Array.from({ length: 40 }, (_, i) => i + 1));
  });
  it('retries a lost acknowledgement after worker restart without duplicating a committed batch', async () => {
    vi.useFakeTimers();
    const { recorder, storage } = setup();
    let worker = recorder;
    let attempts = 0;
    const identities: string[] = [];
    const queue = createContentEventQueue(async input => {
      identities.push(`${input.source_id}:${input.batch_seq}`);
      const receipt = await worker.appendBatch(input, context);
      if (++attempts === 1) { worker = createRecorder(storage, async () => {}); throw new Error('Acknowledgement lost'); }
      return receipt;
    });
    queue.enqueue(batch(120).events);
    await queue.flush();
    expect(queue.snapshot()).toMatchObject({ queued_events: 120, delivery_errors: 1, dropped_events: 0 });
    expect((await worker.snapshot(1)).events).toHaveLength(100);
    await vi.advanceTimersByTimeAsync(1000);
    await queue.flush();
    expect(identities[0]).toBe(identities[1]);
    expect(queue.snapshot().queued_events).toBe(0);
    const state = await worker.snapshot(1);
    expect(state.events).toHaveLength(120);
    expect(state.next_seq).toBe(121);
    expect(state.content_delivery_errors).toBe(1);
  });
  it('bounds the content buffer and reports overflow and rejected acknowledgements', async () => {
    vi.useFakeTimers();
    const { recorder } = setup();
    let offline = true;
    const queue = createContentEventQueue(async input => offline ? { ok: false } : recorder.appendBatch(input, context));
    queue.enqueue(batch(2500).events);
    await queue.flush();
    queue.enqueue(batch(200).events);
    expect(queue.snapshot()).toMatchObject({ queued_events: 2000, dropped_events: 700, delivery_errors: 1 });
    offline = false;
    await queue.flush();
    expect(queue.snapshot().queued_events).toBe(0);
    const state = await recorder.snapshot(1);
    expect(state.events).toHaveLength(2000);
    expect(state.content_dropped).toBe(700);
    expect(state.content_delivery_errors).toBe(1);
  });
  it('retains concurrent events, retries failed delivery, and resumes sequence after restart', async () => {
    let offline = true;
    const received: number[] = [];
    const deliver = async (events: SensitiveEvent[]) => { if (offline) throw new Error('offline'); received.push(...events.map(e => e.event_seq)); };
    const { recorder, storage } = setup(deliver);
    await Promise.all(Array.from({ length: 20 }, () => recorder.append(observation({ event_type: 'FIELD_DISCOVERED', sensitive_type: 'OTP' }), context)));
    expect((await recorder.snapshot(1)).events.map(e => e.event_seq)).toEqual(Array.from({ length: 20 }, (_, i) => i + 1));
    await expect(recorder.flush(1)).rejects.toThrow('offline');
    expect((await recorder.snapshot(1)).pending).toHaveLength(20);
    const restarted = createRecorder(storage, deliver);
    offline = false;
    await restarted.flush(1);
    const event = await restarted.append(observation({ event_type: 'DOM_MUTATION' }), context);
    expect(event.event_seq).toBe(21);
    await restarted.flush(1);
    expect(received).toEqual(Array.from({ length: 21 }, (_, i) => i + 1));
    expect((await restarted.snapshot(1)).pending).toHaveLength(0);
  });
  it('uses event instances for temporal edges and separates sessions/documents', async () => {
    const { recorder } = setup();
    for (const type of ['FIELD_DISCOVERED', 'DOM_MUTATION', 'FIELD_DISCOVERED'] as const) {
      await recorder.append(observation({ event_type: type, sensitive_type: type === 'FIELD_DISCOVERED' ? 'PASSWORD' : null }), context);
    }
    const events = (await recorder.snapshot(1)).events;
    const graph = buildGraph(events);
    const temporal = graph.edges.filter(e => e.type === 'PRECEDES');
    expect(temporal).toHaveLength(2);
    expect(temporal.some(a => temporal.some(b => a.from === b.to && a.to === b.from))).toBe(false);
    expect(graph.nodes.filter(n => n.type === 'FIELD_DISCOVERED')).toHaveLength(2);
    expect(buildGraph([...events, ...events.map(e => ({ ...e, session_id: 'other-session' }))]).nodes.filter(n => n.type === 'FIELD_DISCOVERED')).toHaveLength(4);
    expect(buildFlatControl(events).event_count).toBe(events.length);
    expect(graph.edges.every(e => Array.isArray(e.evidence_events) && typeof e.confidence === 'number')).toBe(true);
  });
  it('forbids arbitrary metadata and non-origin URLs; temporal proximity is never causal', async () => {
    expect(validateObservation({ ...observation({ event_type: 'FIELD_DISCOVERED' }), value: 'AUDIT_CANARY' })).toBe(false);
    expect(validateObservation(observation({ event_type: 'DOCUMENT_STARTED', frame_origin: 'https://user:secret@example.test' }))).toBe(false);
    expect(safeOrigin('https://user:secret@example.test/path?token=secret')).toBe('https://example.test');
    expect(safeOrigin('http://foo_bar.test')).toBeNull();
    expect(safeOrigin('http://foo!bar.test')).toBeNull();
    expect(safeOrigin('http://127.1:0/path')).toBe('http://127.0.0.1:0');
    expect(safeOrigin('http://[::1]:0/path')).toBe('http://[::1]:0');
    expect(validateObservation({ ...observation({ event_type: 'DOCUMENT_STARTED' }), request_type: ['script'] })).toBe(false);
    const { recorder } = setup();
    await recorder.append(observation({ event_type: 'SENSITIVE_INTERACTION', sensitive_type: 'PASSWORD', timestamp_ms: 1000 }), context);
    await recorder.append(observation({ event_type: 'REQUEST_OBSERVED', timestamp_ms: 1200 }), context);
    let graph = buildGraph((await recorder.snapshot(1)).events);
    expect(graph.edges.find(e => e.type === 'OBSERVED_NEAR_REQUEST')?.relation_strength).toBe('temporal_only');
    const other = (await recorder.snapshot(1)).events.map((e, i) => i ? { ...e, document_id: null } : e);
    graph = buildGraph(other);
    expect(graph.edges.some(e => e.type === 'OBSERVED_NEAR_REQUEST')).toBe(false);
  });
  it('keeps event provenance separate while enriching a frame from later browser evidence', async () => {
    const { recorder } = setup();
    await recorder.append(observation({ event_type: 'FIELD_DISCOVERED', field_id: 'e-1', sensitive_type: 'PASSWORD' }), { ...context, frame_id: 1, parent_frame_id: null });
    await recorder.append(observation({ event_type: 'REQUEST_OBSERVED', request_type: 'script' }), { ...context, frame_id: 1, parent_frame_id: 0, trust: 'WEBREQUEST_METADATA' });
    const graph = buildGraph((await recorder.snapshot(1)).events);
    const first = graph.nodes.find(n => n.type === 'FIELD_DISCOVERED')!;
    expect(first.evidence_events).toHaveLength(1);
    expect(graph.edges.filter(e => e.evidence_events === first.evidence_events)).toHaveLength(0);
    expect(graph.nodes.find(n => n.type === 'IDENTITY')?.confidence).toBe(0);
    const frame = graph.nodes.find(n => n.type === 'FRAME')!;
    expect(frame.parent_frame_id).toBe(0);
    expect(frame.evidence_events).toHaveLength(2);
    expect(frame.trust_sources).toEqual(['ISOLATED_CONTENT_SCRIPT', 'WEBREQUEST_METADATA']);
  });
});
