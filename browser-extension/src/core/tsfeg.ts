// Adapted from Tech-research/TSFEG-M1-FOUNDATION: same event/graph/flat foundation,
// with event-instance identity and serialized storage instead of concurrent overwrites.
export const EVENT_TYPES = ['DOCUMENT_STARTED', 'FIELD_DISCOVERED', 'SENSITIVE_INTERACTION', 'DOM_MUTATION', 'FORM_TARGET_OBSERVED', 'REQUEST_OBSERVED', 'NAVIGATION_COMMITTED', 'REDIRECT_OBSERVED', 'HISTORY_UPDATED', 'DOCUMENT_ENDED', 'FORM_DISCOVERED', 'FORM_TARGET_CHANGED', 'FORM_SUBMISSION_ATTEMPT', 'SUBMISSION_PREVENTED', 'SUBMISSION_CONFIRMED', 'NAVIGATION_STARTED', 'FRAME_CREATED', 'FRAME_NAVIGATED', 'PAGE_CONTEXT_OBSERVED'] as const;
export const PAGE_PURPOSES = ['LOGIN', 'SIGNUP', 'PAYMENT', 'RECOVERY', 'IDENTITY_VERIFICATION', 'INFORMATIONAL', 'DOWNLOAD', 'UNKNOWN'] as const;
export type PagePurpose = typeof PAGE_PURPOSES[number];
export const SENSITIVE_TYPES = ['PASSWORD', 'OTP', 'CARD', 'CVV', 'EMAIL', 'PHONE', 'USERNAME', 'ID', 'RECOVERY', 'OTHER_SENSITIVE', 'NON_SENSITIVE', 'UNKNOWN'] as const;
export type SensitiveType = typeof SENSITIVE_TYPES[number];
export type Trust = 'ISOLATED_CONTENT_SCRIPT' | 'WEBREQUEST_METADATA' | 'WEBNAVIGATION_METADATA';
export interface Observation {
  event_type: typeof EVENT_TYPES[number];
  sensitive_type: SensitiveType | null;
  field_id: string | null;
  form_id: string | null;
  frame_origin: string | null;
  target_origin: string | null;
  destination_origin: string | null;
  initiator_origin: string | null;
  request_type: string | null;
  interaction_type: 'focus' | 'input' | 'submit' | null;
  page_purpose?: PagePurpose | null;
  purpose_source?: 'STATIC_SEMANTICS' | 'UNKNOWN' | null;
  timestamp_ms: number;
}
export interface SensitiveEvent extends Observation {
  schema_version: '1.1.0' | '1.2.0';
  evidence_status?: 'OBSERVED';
  analysis_version?: 'event-analysis-1';
  model_version?: 'pending';
  policy_version?: 'evidence-policy-1';
  session_id: string;
  tab_id: number;
  document_id: string | null;
  frame_id: number;
  parent_frame_id: number | null;
  event_seq: number;
  received_ms: number;
  trust: Trust;
  confidence: number; // Heuristic provenance of document correlation, not a calibrated threat probability.
}
const REQUEST_TYPES = ['main_frame', 'sub_frame', 'stylesheet', 'script', 'image', 'font', 'object', 'xmlhttprequest', 'ping', 'csp_report', 'media', 'websocket', 'webtransport', 'webbundle', 'other'];
export function safeOrigin(input: unknown, base?: string): string | null {
  if (typeof input !== 'string' || !input) return null;
  // Non-DNS hostname forms are unknown so transport and backend accept the same origins.
  try { const url = new URL(input, base); return ['http:', 'https:'].includes(url.protocol) && /^([a-z0-9.-]+|\[[0-9a-f:]+\])$/i.test(url.hostname) ? url.origin : null; }
  catch { return null; }
}
export function observation(input: Partial<Observation> & Pick<Observation, 'event_type'>): Observation {
  return { sensitive_type: null, field_id: null, form_id: null, frame_origin: null, target_origin: null,
    destination_origin: null, initiator_origin: null, request_type: null, interaction_type: null,
    page_purpose: null, purpose_source: null, timestamp_ms: Date.now(), ...input };
}
export function validateObservation(input: unknown): input is Observation {
  if (!input || typeof input !== 'object' || Array.isArray(input)) return false;
  const obj = input as Record<string, unknown>;
  const keys = Object.keys(observation({ event_type: 'DOCUMENT_STARTED' }));
  // Older queued events may omit both new category fields; arbitrary metadata is still rejected.
  const legacy = !('page_purpose' in obj) && !('purpose_source' in obj);
  const expected = legacy ? keys.filter(k => !['page_purpose', 'purpose_source'].includes(k)) : keys;
  if (Object.keys(obj).length !== expected.length || expected.some(k => !(k in obj))) return false;
  if (!EVENT_TYPES.includes(obj.event_type as Observation['event_type'])) return false;
  if (obj.event_type === 'PAGE_CONTEXT_OBSERVED') {
    if (!PAGE_PURPOSES.includes(obj.page_purpose as PagePurpose) || !['STATIC_SEMANTICS', 'UNKNOWN'].includes(obj.purpose_source as string)) return false;
    if (obj.purpose_source === 'UNKNOWN' && obj.page_purpose !== 'UNKNOWN') return false;
  } else if (!legacy && (obj.page_purpose !== null || obj.purpose_source !== null)) return false;
  if (obj.sensitive_type !== null && !SENSITIVE_TYPES.includes(obj.sensitive_type as SensitiveType)) return false;
  if (!Number.isSafeInteger(obj.timestamp_ms) || Number(obj.timestamp_ms) < 0) return false;
  for (const key of ['field_id', 'form_id']) if (obj[key] !== null && (typeof obj[key] !== 'string' || !(key === 'field_id' ? /^e-\d{1,8}$/ : /^f-\d{1,8}$/).test(obj[key] as string))) return false;
  for (const key of ['frame_origin', 'target_origin', 'destination_origin', 'initiator_origin']) {
    if (obj[key] !== null && safeOrigin(obj[key]) !== obj[key]) return false;
  }
  return (obj.request_type === null || (typeof obj.request_type === 'string' && REQUEST_TYPES.includes(obj.request_type))) &&
    (obj.interaction_type === null || (typeof obj.interaction_type === 'string' && ['focus', 'input', 'submit'].includes(obj.interaction_type)));
}
export interface ContentBatch {
  type: 'TYPED_EVENTS'; source_id: string; batch_seq: number; events: Observation[];
  dropped_events: number; delivery_errors: number;
}
interface BatchReceipt { batch_seq: number; accepted: number; digest: string; dropped_events: number; delivery_errors: number; }
interface State {
  session_id: string; next_seq: number; events: SensitiveEvent[]; pending: SensitiveEvent[]; dropped: number;
  last_ack_seq?: number;
  batch_receipts: Record<string, BatchReceipt>; content_dropped: number; content_delivery_errors: number;
}
type EventContext = Pick<SensitiveEvent, 'tab_id' | 'document_id' | 'frame_id' | 'parent_frame_id' | 'trust'>;
export function validateContentBatch(input: unknown): input is ContentBatch {
  if (!input || typeof input !== 'object' || Array.isArray(input)) return false;
  const batch = input as ContentBatch;
  return Object.keys(batch).length === 6 && batch.type === 'TYPED_EVENTS' &&
    typeof batch.source_id === 'string' && /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(batch.source_id) &&
    Number.isSafeInteger(batch.batch_seq) && batch.batch_seq > 0 &&
    Number.isSafeInteger(batch.dropped_events) && batch.dropped_events >= 0 &&
    Number.isSafeInteger(batch.delivery_errors) && batch.delivery_errors >= 0 &&
    Array.isArray(batch.events) && batch.events.length > 0 && batch.events.length <= 100 && batch.events.every(validateObservation);
}
export interface ContentEventQueueOptions {
  acknowledgementTimeoutMs?: number;
  retryDelayMs?: number;
}
export function createContentEventQueue(
  send: (batch: ContentBatch) => Promise<unknown>,
  options: ContentEventQueueOptions = {},
) {
  const source_id = crypto.randomUUID();
  const queue: Array<Pick<ContentBatch, 'batch_seq' | 'events'>> = [];
  const acknowledgementTimeoutMs =
    Number.isFinite(options.acknowledgementTimeoutMs) &&
    Number(options.acknowledgementTimeoutMs) > 0
      ? Number(options.acknowledgementTimeoutMs)
      : 3000;
  const retryDelayMs =
    Number.isFinite(options.retryDelayMs) &&
    Number(options.retryDelayMs) >= 0
      ? Number(options.retryDelayMs)
      : 1000;
  let nextBatch = 1, queued = 0, dropped = 0, errors = 0;
  let lastDeliveryErrorCode: string | null = null;
  let active: Promise<void> | null = null;
  let retry: ReturnType<typeof setTimeout> | undefined;
  // ponytail: 2000 events per live document; overflow drops newest events and is counted.
  // Navigation destroys an unacknowledged buffer. Durable cross-navigation recovery needs browser storage.
  function flush(): Promise<void> {
    if (active) return active;
    if (retry !== undefined) { clearTimeout(retry); retry = undefined; }
    active = (async () => {
      while (queue.length) {
        const batch = queue[0];
        try {
          let deadline: ReturnType<typeof setTimeout> | undefined;
          const reply = await Promise.race([
            send({ type: 'TYPED_EVENTS', source_id, ...batch, dropped_events: dropped, delivery_errors: errors }),
            new Promise((_, reject) => {
              deadline = setTimeout(
                () => reject(new Error('Acknowledgement timeout')),
                acknowledgementTimeoutMs,
              );
            }),
          ]).finally(() => clearTimeout(deadline));
          const ack = reply as {
            ok?: unknown;
            source_id?: unknown;
            batch_seq?: unknown;
            accepted?: unknown;
            error_code?: unknown;
          } | null;
          if (
            !ack ||
            ack.ok !== true ||
            ack.source_id !== source_id ||
            ack.batch_seq !== batch.batch_seq ||
            ack.accepted !== batch.events.length
          ) {
            const failure = new Error('Missing batch acknowledgement') as Error & {
              replayCode?: string;
            };
            failure.replayCode =
              typeof ack?.error_code === 'string' &&
              /^[A-Z0-9_]{1,64}$/.test(ack.error_code)
                ? ack.error_code
                : 'ACK_REJECTED';
            throw failure;
          }
          lastDeliveryErrorCode = null;
          queue.shift(); queued -= batch.events.length;
        } catch (error) {
          errors++;
          const coded = error as Error & { replayCode?: string };
          lastDeliveryErrorCode =
            coded.replayCode ||
            (coded.message === 'Acknowledgement timeout'
              ? 'ACK_TIMEOUT'
              : 'MESSAGE_SEND_FAILED');
          return;
        }
      }
    })().finally(() => {
      active = null;
      if (queue.length) {
        retry = setTimeout(() => {
          retry = undefined;
          void flush();
        }, retryDelayMs);
      }
    });
    return active;
  }
  return {
    enqueue(events: Observation[]) {
      const accepted = events.slice(0, Math.max(0, 2000 - queued));
      dropped += events.length - accepted.length;
      for (let i = 0; i < accepted.length; i += 100) {
        const chunk = accepted.slice(i, i + 100).map(event => ({ ...event }));
        queue.push({ batch_seq: nextBatch++, events: chunk }); queued += chunk.length;
      }
      if (retry === undefined) void flush();
    },
    flush,
    snapshot: () => ({
      source_id,
      queued_events: queued,
      dropped_events: dropped,
      delivery_errors: errors,
      last_delivery_error_code: lastDeliveryErrorCode,
    }),
  };
}
export interface SessionStorage {
  get(key: string): Promise<Record<string, unknown>>;
  set(value: Record<string, unknown>): Promise<void>;
}
export function createRecorder(storage: SessionStorage, deliver: (events: SensitiveEvent[]) => Promise<void>) {
  let tail: Promise<unknown> = Promise.resolve();
  const deliveries = new Map<number, Promise<void>>();
  // Storage commits are serialized; backend network waits run outside this queue.
  // History and pending delivery are capped at 2000 events each per tab.
  function serial<T>(fn: () => Promise<T>): Promise<T> {
    const result = tail.then(fn); tail = result.catch(() => {}); return result;
  }
  async function read(tab: number): Promise<State> {
    let session = (await storage.get('browser-session'))['browser-session'] as string | undefined;
    if (!session) { session = crypto.randomUUID(); await storage.set({ 'browser-session': session }); }
    const state = (await storage.get(`tsfeg:${tab}`))[`tsfeg:${tab}`] as State ||
      { session_id: session, next_seq: 1, events: [], pending: [], dropped: 0 };
    state.batch_receipts ||= {}; state.content_dropped ||= 0; state.content_delivery_errors ||= 0;
    return state;
  }
  async function save(tab: number, state: State) { await storage.set({ [`tsfeg:${tab}`]: state }); }
  function appendEvents(state: State, inputs: Observation[], context: EventContext) {
    const events = inputs.map(input => ({ ...input, ...context, schema_version: '1.2.0' as const, session_id: state.session_id,
      evidence_status: 'OBSERVED' as const, analysis_version: 'event-analysis-1' as const, model_version: 'pending' as const, policy_version: 'evidence-policy-1' as const,
      event_seq: state.next_seq++, received_ms: Date.now(), confidence: context.document_id ? 1 : 0.5 }));
    state.events.push(...events); state.pending.push(...events);
    state.events = state.events.slice(-2000);
    if (state.pending.length > 2000) { state.dropped += state.pending.length - 2000; state.pending = state.pending.slice(-2000); }
    return events;
  }
  return {
    append(input: Observation, context: EventContext) {
      return serial(async () => {
        if (!validateObservation(input) || !Number.isInteger(context.tab_id) || context.tab_id < 0) throw new Error('Invalid sanitized event');
        const state = await read(context.tab_id);
        const [event] = appendEvents(state, [input], context);
        await save(context.tab_id, state);
        return event;
      });
    },
    appendBatch(batch: ContentBatch, context: EventContext) {
      return serial(async () => {
        if (!validateContentBatch(batch) || !Number.isInteger(context.tab_id) || context.tab_id < 0) throw new Error('Invalid sanitized batch');
        const state = await read(context.tab_id);
        // Source nonce is a transport identity only; absent browser document IDs remain null in events.
        const key = `${context.document_id ?? 'unknown'}:${context.frame_id}:${batch.source_id}`;
        const previous = state.batch_receipts[key];
        const digest = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(JSON.stringify(batch.events)))), byte => byte.toString(16).padStart(2, '0')).join('');
        if (previous && batch.batch_seq === previous.batch_seq) {
          if (digest !== previous.digest) throw new Error('Batch identity reused with different events');
        } else {
          if (batch.batch_seq !== (previous?.batch_seq ?? 0) + 1) throw new Error('Out of order content batch');
          // ponytail: retain 256 source receipts per tab until tab close, rejecting new streams at capacity.
          // Never evict a receipt and silently accept a retry twice; upgrade to durable receipt storage for longer sessions.
          if (!previous && Object.keys(state.batch_receipts).length >= 256) throw new Error('Content receipt capacity reached');
          appendEvents(state, batch.events, context);
        }
        state.content_dropped += Math.max(0, batch.dropped_events - (previous?.dropped_events ?? 0));
        state.content_delivery_errors += Math.max(0, batch.delivery_errors - (previous?.delivery_errors ?? 0));
        state.batch_receipts[key] = { batch_seq: batch.batch_seq, accepted: batch.events.length, digest,
          dropped_events: Math.max(batch.dropped_events, previous?.dropped_events ?? 0),
          delivery_errors: Math.max(batch.delivery_errors, previous?.delivery_errors ?? 0) };
        // Events, sequence, and receipt commit in one storage write before an acknowledgement is sent.
        await save(context.tab_id, state);
        return { ok: true, source_id: batch.source_id, batch_seq: batch.batch_seq, accepted: batch.events.length };
      });
    },
    flush(tab: number) {
      const active = deliveries.get(tab);
      if (active) return active;
      // Network waits must never hold the local recording/analysis storage queue.
      const delivery = (async () => {
        while (true) {
          const batch = await serial(async () => (await read(tab)).pending.slice(0, 100));
          if (!batch.length) return;
          await deliver(batch);
          await serial(async () => {
            const state = await read(tab);
            const acknowledged = new Set(batch.map(event => event.event_seq));
            state.pending = state.pending.filter(event => !acknowledged.has(event.event_seq));
            state.last_ack_seq = Math.max(state.last_ack_seq ?? 0, ...acknowledged);
            await save(tab, state);
          });
        }
      })().finally(() => deliveries.delete(tab));
      deliveries.set(tab, delivery);
      return delivery;
    },
    snapshot(tab: number) { return serial(() => read(tab)); },
  };
}
export function buildFlatControl(events: SensitiveEvent[]) {
  const out = { event_count: events.length, field_discovered_count: 0, sensitive_interaction_count: 0,
    mutation_count: 0, request_count: 0, cross_origin_request_count: 0, navigation_count: 0,
    form_target_count: 0, sensitive_type_counts: {} as Record<string, number>, request_type_counts: {} as Record<string, number> };
  for (const ev of events) {
    if (ev.event_type === 'FIELD_DISCOVERED') out.field_discovered_count++;
    if (ev.event_type === 'SENSITIVE_INTERACTION') out.sensitive_interaction_count++;
    if (ev.event_type === 'DOM_MUTATION') out.mutation_count++;
    if (ev.event_type === 'FORM_TARGET_OBSERVED') out.form_target_count++;
    if (['NAVIGATION_COMMITTED', 'REDIRECT_OBSERVED', 'HISTORY_UPDATED'].includes(ev.event_type)) out.navigation_count++;
    if (ev.sensitive_type) out.sensitive_type_counts[ev.sensitive_type] = (out.sensitive_type_counts[ev.sensitive_type] || 0) + 1;
    if (ev.event_type === 'REQUEST_OBSERVED') {
      out.request_count++; const type = ev.request_type || 'unknown';
      out.request_type_counts[type] = (out.request_type_counts[type] || 0) + 1;
      if (ev.initiator_origin && ev.destination_origin && ev.initiator_origin !== ev.destination_origin) out.cross_origin_request_count++;
    }
  }
  return out;
}
export function buildGraph(events: SensitiveEvent[], nearWindowMs = 2500) {
  const nodes: Array<Record<string, unknown> & { id: string; type: string }> = [];
  const edges: Array<Record<string, unknown> & { type: string; from: string; to: string }> = [];
  const seen = new Map<string, typeof nodes[number]>();
  const previous = new Map<string, string>();
  const interaction = new Map<string, { id: string; timestamp: number }>();
  for (const ev of [...events].sort((a, b) => a.event_seq - b.event_seq)) {
    const eventId = `${ev.session_id}:${ev.tab_id}:${ev.event_seq}`;
    const scope = `${ev.session_id}:${ev.tab_id}:${ev.document_id ?? `unknown-${ev.event_seq}`}:${ev.frame_id}`;
    const provenance = { evidence_events: [eventId], confidence: ev.confidence, confidence_kind: 'provenance_heuristic', trust: ev.trust };
    function node(type: string, key: string, attrs: Record<string, unknown> = {}) {
      const id = `${type}:${key}`;
      const existing = seen.get(id);
      if (!existing) {
        const entry = { id, type, ...provenance, evidence_events: [eventId], trust_sources: [ev.trust], ...attrs };
        seen.set(id, entry); nodes.push(entry);
      } else {
        const support = existing.evidence_events as string[];
        if (!support.includes(eventId)) support.push(eventId);
        const trusts = existing.trust_sources as Trust[];
        if (!trusts.includes(ev.trust)) trusts.push(ev.trust);
        for (const [key, value] of Object.entries(attrs)) if (existing[key] == null && value != null) existing[key] = value;
      }
      return id;
    }
    function edge(type: string, from: string, to: string, attrs: Record<string, unknown> = {}) { edges.push({ type, from, to, ...provenance, ...attrs }); }
    const doc = node('DOCUMENT', scope, { document_id: ev.document_id });
    const frame = node('FRAME', scope, { frame_id: ev.frame_id, parent_frame_id: ev.parent_frame_id });
    edge('CONTAINS', doc, frame);
    const identity = node('IDENTITY', scope, { status: 'UNKNOWN', confidence: 0 });
    edge('CLAIMS', doc, identity, { confidence: 0, status: 'UNKNOWN' });
    if (ev.frame_origin) edge('HAS_ORIGIN', frame, node('ORIGIN', ev.frame_origin));
    const eventNode = node(ev.event_type, eventId, { event_seq: ev.event_seq, timestamp_ms: ev.timestamp_ms, received_ms: ev.received_ms,
      request_type: ev.request_type, interaction_type: ev.interaction_type });
    edge('CONTAINS', frame, eventNode);
    const prior = previous.get(scope);
    if (prior) edge('PRECEDES', prior, eventNode, { ordering: 'worker_arrival', relation_strength: 'temporal_only' });
    if (ev.event_type === 'DOM_MUTATION' && prior) edge('MUTATED_AFTER', eventNode, prior, { relation_strength: 'temporal_only' });
    previous.set(scope, eventNode);
    const form = ev.form_id ? node('FORM', `${scope}:${ev.form_id}`) : null;
    const field = ev.field_id ? node('FIELD', `${scope}:${ev.field_id}`) : null;
    if (form) edge('CONTAINS', frame, form);
    if (field) edge('CONTAINS', form || frame, field);
    if (form) edge('OBSERVES_FORM', eventNode, form);
    if (field) edge('OBSERVES_FIELD', eventNode, field);
    if (ev.initiator_origin) edge('HAS_INITIATOR', eventNode, node('ORIGIN', ev.initiator_origin));
    if (ev.sensitive_type) edge('REQUESTS_TYPE', field || eventNode, node('SENSITIVE_TYPE', ev.sensitive_type));
    if (ev.event_type === 'SENSITIVE_INTERACTION') {
      if (field) edge('TRIGGERED_BY', eventNode, field, { relation_strength: 'direct_dom_event' });
      interaction.set(scope, { id: eventNode, timestamp: ev.timestamp_ms });
    }
    const destination = ev.target_origin || ev.destination_origin;
    if (destination) {
      const dest = node('DESTINATION', destination);
      const direct = ['FORM_TARGET_OBSERVED', 'FORM_SUBMISSION_ATTEMPT'].includes(ev.event_type) && form;
      edge(ev.event_type === 'NAVIGATION_COMMITTED' ? 'NAVIGATES_TO' : 'TARGETS', eventNode, dest,
        { relation_strength: direct ? 'DIRECT_FORM_TARGET' : ev.initiator_origin ? 'REQUEST_INITIATOR_ASSOCIATION' : 'UNKNOWN' });
      if (direct) edge('TARGETS', form, dest, { relation_strength: 'DIRECT_FORM_TARGET' });
      const origin = direct ? ev.frame_origin : ev.initiator_origin;
      if (origin) edge(origin === destination ? 'SAME_ORIGIN' : 'CROSS_ORIGIN', node('ORIGIN', origin), dest);
    }
    if (ev.event_type === 'REQUEST_OBSERVED' && ev.document_id) {
      const near = interaction.get(scope);
      const delta = near ? ev.timestamp_ms - near.timestamp : -1;
      if (near && delta >= 0 && delta <= nearWindowMs) edge('OBSERVED_NEAR_REQUEST', near.id, eventNode,
        { relation_strength: 'temporal_only', delta_ms: delta, confidence: Math.min(0.5, ev.confidence) });
    }
  }
  return { nodes, edges };
}

// Frozen numeric predictors. Literal origins, IDs and labels never enter the model.
export const FLAT_FEATURES = ['event_count', 'form_count', 'input_count', 'password_count', 'otp_count',
  'interaction_count', 'mutation_count', 'request_count', 'same_origin_requests', 'cross_origin_requests',
  'navigation_count', 'redirect_count', 'destination_count', 'unknown_document_count'] as const;
export const RELATIONSHIP_FEATURES = ['sensitive_cross_target', 'target_changed_after_interaction',
  'request_near_interaction', 'cross_request_near_interaction', 'password_then_otp',
  'dynamic_sensitive_field', 'submission_target_mismatch', 'frame_origin_mismatch'] as const;
export type RelationshipCode = typeof RELATIONSHIP_FEATURES[number];
export interface RelationshipEvidence {
  code: RelationshipCode;
  evidence_status: 'OBSERVED' | 'INFERRED';
  event_seqs: number[];
}
export function buildEventRepresentations(events: SensitiveEvent[]) {
  const flat: Record<typeof FLAT_FEATURES[number], number> = Object.fromEntries(FLAT_FEATURES.map(k => [k, 0])) as never;
  const relationship: Record<RelationshipCode, number> = Object.fromEntries(RELATIONSHIP_FEATURES.map(k => [k, 0])) as never;
  const support: RelationshipEvidence[] = [];
  const forms = new Set<string>(), fields = new Map<string, SensitiveType | null>(), destinations = new Set<string>();
  const targets = new Map<string, SensitiveEvent>(), interactions = new Map<string, SensitiveEvent>();
  const scopedInteractions = new Map<string, SensitiveEvent>(), passwords = new Map<string, SensitiveEvent>();
  const mutations = new Map<string, SensitiveEvent>();
  const topOrigins = new Map<string, string>();
  const scopedFields = new Map<string, SensitiveEvent>();
  const add = (code: RelationshipCode, records: SensitiveEvent[], inferred = false) => {
    relationship[code]++;
    support.push({ code, evidence_status: inferred ? 'INFERRED' : 'OBSERVED', event_seqs: [...new Set(records.map(e => e.event_seq))] });
  };
  const sensitive = (e: SensitiveEvent) => !!e.sensitive_type && !['NON_SENSITIVE', 'UNKNOWN'].includes(e.sensitive_type);
  for (const ev of [...events].sort((a, b) => a.event_seq - b.event_seq)) {
    flat.event_count++;
    if (!ev.document_id) flat.unknown_document_count++;
    // Unknown documents never join by a guessed identifier.
    const scope = `${ev.session_id}:${ev.tab_id}:${ev.document_id ?? `unknown-${ev.event_seq}`}:${ev.frame_id}`;
    const tab = `${ev.session_id}:${ev.tab_id}`;
    const form = ev.form_id ? `${scope}:${ev.form_id}` : null;
    if (form) forms.add(form);
    if (ev.target_origin) destinations.add(ev.target_origin);
    if (ev.destination_origin) destinations.add(ev.destination_origin);
    if (ev.frame_id === 0 && ev.frame_origin) topOrigins.set(tab, ev.frame_origin);
    if (ev.event_type === 'FIELD_DISCOVERED') {
      if (ev.field_id) fields.set(`${scope}:${ev.field_id}`, ev.sensitive_type);
      if (form && sensitive(ev)) scopedFields.set(form, ev);
      if (sensitive(ev) && mutations.has(scope)) add('dynamic_sensitive_field', [mutations.get(scope)!, ev]);
      if (sensitive(ev) && ev.frame_id !== 0 && ev.frame_origin && topOrigins.has(tab) && ev.frame_origin !== topOrigins.get(tab)) add('frame_origin_mismatch', [ev]);
    }
    if (ev.event_type === 'DOM_MUTATION') { flat.mutation_count++; mutations.set(scope, ev); }
    if (ev.event_type === 'SENSITIVE_INTERACTION') {
      flat.interaction_count++;
      scopedInteractions.set(scope, ev);
      if (form) interactions.set(form, ev);
      if (ev.sensitive_type === 'OTP' && passwords.has(scope)) add('password_then_otp', [passwords.get(scope)!, ev]);
      if (ev.sensitive_type === 'PASSWORD') passwords.set(scope, ev);
    }
    if (form && ['FORM_TARGET_OBSERVED', 'FORM_SUBMISSION_ATTEMPT'].includes(ev.event_type)) {
      const prior = targets.get(form), interacted = interactions.get(form);
      if (prior?.target_origin && ev.target_origin && prior.target_origin !== ev.target_origin) {
        if (interacted && interacted.event_seq > prior.event_seq && ev.timestamp_ms >= interacted.timestamp_ms) add('target_changed_after_interaction', [prior, interacted, ev]);
        if (ev.event_type === 'FORM_SUBMISSION_ATTEMPT') add('submission_target_mismatch', [prior, ev]);
      }
      targets.set(form, ev);
    }
    if (ev.event_type === 'REQUEST_OBSERVED') {
      flat.request_count++;
      if (ev.initiator_origin && ev.destination_origin) {
        flat[ev.initiator_origin === ev.destination_origin ? 'same_origin_requests' : 'cross_origin_requests']++;
      }
      const near = scopedInteractions.get(scope);
      if (near && ev.timestamp_ms >= near.timestamp_ms && ev.timestamp_ms - near.timestamp_ms <= 2500) {
        add('request_near_interaction', [near, ev], true);
        if (ev.initiator_origin && ev.destination_origin && ev.initiator_origin !== ev.destination_origin) add('cross_request_near_interaction', [near, ev], true);
      }
    }
    if (ev.event_type === 'NAVIGATION_COMMITTED') flat.navigation_count++;
    if (ev.event_type === 'REDIRECT_OBSERVED') flat.redirect_count++;
  }
  for (const [form, field] of scopedFields) {
    const target = targets.get(form);
    if (target?.target_origin && target.frame_origin && target.target_origin !== target.frame_origin) add('sensitive_cross_target', [field, target]);
  }
  flat.form_count = forms.size; flat.input_count = fields.size; flat.destination_count = destinations.size;
  flat.password_count = [...fields.values()].filter(t => t === 'PASSWORD').length;
  flat.otp_count = [...fields.values()].filter(t => t === 'OTP').length;
  return { version: 'event-features-1' as const, flat, relationship, support,
    flat_vector: FLAT_FEATURES.map(k => flat[k]),
    relationship_vector: [...FLAT_FEATURES.map(k => flat[k]), ...RELATIONSHIP_FEATURES.map(k => relationship[k])] };
}

// Primary contextual model contract. Origins, identifiers, text and labels never enter this vector.
// Boolean features are 0/1, ratios 0..1 and counts saturate at 10. The same extractor is used in training.
export const CONTEXT_FEATURE_VERSION = 'context-features-1' as const;
export const CONTEXT_FEATURES = ['document_started', 'has_password', 'has_otp', 'has_payment', 'has_identity',
  'purpose_authentication', 'purpose_payment', 'purpose_unknown', 'sensitive_form_count',
  'same_origin_sensitive_target', 'cross_origin_sensitive_target', 'stable_sensitive_target',
  'sensitive_target_changed', 'target_changed_after_interaction', 'submission_target_mismatch',
  'https_downgrade_sensitive_target', 'password_then_otp', 'dynamic_sensitive_field',
  'foreign_frame_sensitive_field', 'cross_request_near_interaction', 'unknown_document_ratio',
  'known_target_ratio', 'contradiction_count', 'positive_evidence_count', 'purpose_sensitive_mismatch',
  'purpose_context_consistent', 'purpose_observed'] as const;
export interface PurposeEvidence {
  value: PagePurpose; evidence_status: 'INFERRED' | 'UNKNOWN'; confidence: 'LOW' | 'MEDIUM';
  basis: string[]; limitations: string[];
}
export interface EvidenceCompleteness {
  level: 'LOW' | 'PARTIAL' | 'SUFFICIENT'; score: number; observed: string[]; missing: string[];
}
export function buildContextFeatures(events: SensitiveEvent[], incomplete = false) {
  const features = Object.fromEntries(CONTEXT_FEATURES.map(key => [key, 0])) as Record<typeof CONTEXT_FEATURES[number], number>;
  const positive = new Set<string>(), contradictions = new Set<string>();
  const scopeOf = (e: SensitiveEvent) => `${e.session_id}:${e.tab_id}:${e.document_id ?? `unknown-${e.event_seq}`}:${e.frame_id}`;
  const ordered = [...events].sort((a, b) => a.event_seq - b.event_seq);
  type FormContext = { types: Set<SensitiveType>; targets: SensitiveEvent[]; interactions: SensitiveEvent[]; scope: string };
  const forms = new Map<string, FormContext>(), purposes = new Map<string, PagePurpose>();
  const mutations = new Map<string, SensitiveEvent>(), passwords = new Map<string, SensitiveEvent>();
  const interactions = new Map<string, SensitiveEvent>(), topOrigins = new Map<string, string>();
  let hasFields = false;
  for (const event of ordered) {
    const scope = scopeOf(event), tab = `${event.session_id}:${event.tab_id}`;
    if (event.frame_id === 0 && event.frame_origin) topOrigins.set(tab, event.frame_origin);
    if (event.event_type === 'DOCUMENT_STARTED') features.document_started = 1;
    if (event.event_type === 'PAGE_CONTEXT_OBSERVED' && event.document_id) {
      if (event.purpose_source === 'STATIC_SEMANTICS' && event.page_purpose && event.page_purpose !== 'UNKNOWN') purposes.set(scope, event.page_purpose);
      else purposes.delete(scope);
    }
    if (event.event_type === 'DOM_MUTATION') mutations.set(scope, event);
    const secret = !!event.sensitive_type && ['PASSWORD', 'OTP', 'CARD', 'CVV', 'ID', 'RECOVERY', 'OTHER_SENSITIVE'].includes(event.sensitive_type);
    let form: FormContext | undefined;
    // No joining uncorrelated documents, frames, tabs or sessions by reused form identifiers.
    if (event.document_id && event.form_id) {
      const key = `${scope}:${event.form_id}`;
      form = forms.get(key) ?? { types: new Set(), targets: [], interactions: [], scope };
      forms.set(key, form);
      if (event.event_type === 'FIELD_DISCOVERED' && secret) form.types.add(event.sensitive_type!);
      if (['FORM_TARGET_OBSERVED', 'FORM_TARGET_CHANGED', 'FORM_SUBMISSION_ATTEMPT'].includes(event.event_type) && event.target_origin) form.targets.push(event);
      if (event.event_type === 'SENSITIVE_INTERACTION' && secret) form.interactions.push(event);
    }
    if (event.event_type === 'FIELD_DISCOVERED') {
      hasFields = true;
      if (event.sensitive_type === 'PASSWORD') features.has_password = 1;
      if (event.sensitive_type === 'OTP') features.has_otp = 1;
      if (['CARD', 'CVV'].includes(event.sensitive_type ?? '')) features.has_payment = 1;
      if (event.sensitive_type === 'ID') features.has_identity = 1;
      if (secret && event.document_id && mutations.has(scope) && mutations.get(scope)!.timestamp_ms <= event.timestamp_ms) features.dynamic_sensitive_field++;
      if (secret && event.frame_id !== 0 && event.frame_origin && topOrigins.has(tab) && event.frame_origin !== topOrigins.get(tab)) features.foreign_frame_sensitive_field++;
    }
    if (event.event_type === 'SENSITIVE_INTERACTION' && secret && event.document_id) {
      interactions.set(scope, event);
      if (event.sensitive_type === 'OTP' && passwords.has(scope) && passwords.get(scope)!.timestamp_ms <= event.timestamp_ms) features.password_then_otp++;
      if (event.sensitive_type === 'PASSWORD') passwords.set(scope, event);
    }
    if (event.event_type === 'REQUEST_OBSERVED' && event.document_id) {
      const near = interactions.get(scope);
      if (near && event.timestamp_ms >= near.timestamp_ms && event.timestamp_ms - near.timestamp_ms <= 2500 && event.initiator_origin && event.destination_origin && event.initiator_origin !== event.destination_origin) features.cross_request_near_interaction++;
    }
  }
  const topContext = [...ordered].reverse().find(e => e.frame_id === 0 && purposes.has(scopeOf(e)));
  const claimedPurpose = topContext ? purposes.get(scopeOf(topContext)) : undefined;
  const fallback: PagePurpose = features.has_payment ? 'PAYMENT' : features.has_password || features.has_otp ? 'LOGIN' : features.has_identity ? 'IDENTITY_VERIFICATION' : 'UNKNOWN';
  const value = claimedPurpose ?? fallback;
  const purpose: PurposeEvidence = { value, evidence_status: value === 'UNKNOWN' ? 'UNKNOWN' : 'INFERRED',
    confidence: claimedPurpose ? 'MEDIUM' : 'LOW',
    basis: claimedPurpose ? ['STATIC_SEMANTIC_CATEGORY'] : value === 'UNKNOWN' ? [] : ['STRUCTURAL_FIELD_TYPES'],
    limitations: claimedPurpose ? ['PAGE_CLAIM_NOT_INDEPENDENTLY_VERIFIED'] : ['NO_INDEPENDENT_PURPOSE_OBSERVATION', 'FIELD_TYPES_DO_NOT_ESTABLISH_INTENT'] };
  features.purpose_authentication = Number(['LOGIN', 'SIGNUP', 'RECOVERY'].includes(value));
  features.purpose_payment = Number(value === 'PAYMENT');
  features.purpose_unknown = Number(value === 'UNKNOWN');
  features.purpose_observed = Number(!!claimedPurpose);
  let targetsKnown = 0;
  for (const form of forms.values()) {
    if (!form.types.size) continue;
    features.sensitive_form_count++;
    const target = form.targets.at(-1);
    if (target?.target_origin) {
      targetsKnown++;
      if (target.frame_origin && target.target_origin === target.frame_origin) {
        features.same_origin_sensitive_target++;
        positive.add('SENSITIVE_TARGET_SAME_ORIGIN');
      } else if (target.frame_origin) features.cross_origin_sensitive_target++;
      if (target.frame_origin?.startsWith('https:') && target.target_origin.startsWith('http:')) {
        features.https_downgrade_sensitive_target++;
        contradictions.add('SENSITIVE_HTTPS_DOWNGRADE');
      }
    }
    let changed = false;
    for (let index = 1; index < form.targets.length; index++) {
      const prior = form.targets[index - 1], next = form.targets[index];
      if (prior.target_origin === next.target_origin) continue;
      changed = true;
      features.sensitive_target_changed++;
      const afterInteraction = form.interactions.some(e => e.event_seq > prior.event_seq && e.event_seq < next.event_seq && e.timestamp_ms >= prior.timestamp_ms && e.timestamp_ms <= next.timestamp_ms);
      if (afterInteraction) {
        features.target_changed_after_interaction++;
        contradictions.add('SENSITIVE_TARGET_CHANGED_AFTER_INTERACTION');
      }
      if (next.event_type === 'FORM_SUBMISSION_ATTEMPT') {
        features.submission_target_mismatch++;
        contradictions.add('SENSITIVE_SUBMISSION_TARGET_CHANGED');
        if (afterInteraction) contradictions.add('INTERACTED_SENSITIVE_SUBMISSION_REDIRECTED');
      }
    }
    // One observation says only that a destination was observed, not that it remained stable.
    if (!changed && form.targets.length >= 2) { features.stable_sensitive_target++; positive.add('REPEATED_STABLE_SENSITIVE_TARGET'); }
    const claim = purposes.get(form.scope);
    const hasAuth = form.types.has('PASSWORD') || form.types.has('OTP') || form.types.has('RECOVERY');
    const hasPayment = form.types.has('CARD') || form.types.has('CVV');
    if (claim && (['INFORMATIONAL', 'DOWNLOAD'].includes(claim) && (hasAuth || hasPayment || form.types.has('ID')) || ['LOGIN', 'SIGNUP', 'RECOVERY'].includes(claim) && hasPayment)) {
      features.purpose_sensitive_mismatch++;
      contradictions.add('SENSITIVE_REQUEST_PURPOSE_MISMATCH');
    } else if (claim && (['LOGIN', 'SIGNUP', 'RECOVERY'].includes(claim) && hasAuth || claim === 'PAYMENT' && hasPayment || claim === 'IDENTITY_VERIFICATION' && form.types.has('ID'))) {
      features.purpose_context_consistent++;
      positive.add('REQUEST_MATCHES_APPARENT_PURPOSE');
    }
  }
  // Normal authentication sequencing is a consistency cue only when an independent category supports it.
  if (features.password_then_otp && features.purpose_context_consistent && features.purpose_authentication) positive.add('AUTHENTICATION_SEQUENCE_CONSISTENT');
  features.unknown_document_ratio = events.length ? events.filter(e => !e.document_id).length / events.length : 1;
  features.known_target_ratio = features.sensitive_form_count ? targetsKnown / features.sensitive_form_count : 0;
  features.contradiction_count = contradictions.size;
  features.positive_evidence_count = positive.size;
  const checks: Array<[string, boolean]> = [['DOCUMENT_START', !!features.document_started], ['FIELD_SCAN', hasFields],
    ['DOCUMENT_CORRELATION', events.length > 0 && features.unknown_document_ratio === 0], ['APPARENT_PURPOSE', !!claimedPurpose],
    ['SENSITIVE_DESTINATIONS', features.sensitive_form_count > 0 && features.known_target_ratio === 1]];
  const observed = checks.filter(([, present]) => present).map(([name]) => name);
  const missing = checks.filter(([, present]) => !present).map(([name]) => name);
  if (incomplete) missing.push('COLLECTION_LOSS');
  const score = observed.length / checks.length * (incomplete ? 0.5 : 1);
  const evidence_completeness: EvidenceCompleteness = { level: score >= 0.8 ? 'SUFFICIENT' : score >= 0.4 ? 'PARTIAL' : 'LOW', score, observed, missing };
  for (const key of CONTEXT_FEATURES) features[key] = Math.min(10, features[key]);
  return { version: CONTEXT_FEATURE_VERSION, features, vector: CONTEXT_FEATURES.map(key => features[key]), purpose,
    positive_evidence: [...positive], contradictions: [...contradictions], evidence_completeness };
}
