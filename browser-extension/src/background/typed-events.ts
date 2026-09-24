import {
  buildEventRepresentations,
  buildFlatControl,
  buildGraph,
  createRecorder,
  observation,
  Observation,
  safeOrigin,
  SensitiveEvent,
  validateContentBatch,
} from '../core/tsfeg';
import { assessEventStream, EventSecurityReport } from '../core/assessment';
import { EventModelArtifact } from '../core/service-worker-onnx-adapter';
import { createDurableQueue } from '../core/storage/durable-queue';

const EVENTS_ENDPOINT = 'http://127.0.0.1:8000/api/v1/events/batch';
const ASSESSMENTS_ENDPOINT = 'http://127.0.0.1:8000/api/v1/assessments';

function isObject(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function isDurableEventBatch(payload: unknown): payload is { events: SensitiveEvent[] } {
  if (!isObject(payload) || Object.keys(payload).length !== 1 || !Array.isArray(payload.events)) return false;
  return payload.events.length > 0 && payload.events.length <= 100 && payload.events.every(event =>
    isObject(event) &&
    (event.schema_version === '1.1.0' || event.schema_version === '1.2.0') &&
    typeof event.session_id === 'string' &&
    Number.isInteger(event.tab_id) && Number(event.tab_id) >= 0 &&
    Number.isInteger(event.event_seq) && Number(event.event_seq) > 0 &&
    typeof event.event_type === 'string' &&
    typeof event.trust === 'string'
  );
}

function isDurableReport(payload: unknown): payload is EventSecurityReport {
  return isObject(payload) &&
    payload.schema_version === 'event-report-1' &&
    typeof payload.session_id === 'string' &&
    Number.isInteger(payload.tab_id) && Number(payload.tab_id) >= 0 &&
    Number.isInteger(payload.event_seq) && Number(payload.event_seq) > 0 &&
    typeof payload.action === 'string' &&
    typeof payload.outcome === 'string';
}

export function installTypedEvents() {
  let model: EventModelArtifact | null = null;
  void fetch(chrome.runtime.getURL('assets/event-model.json')).then(async response => {
    if (!response.ok) return;
    const raw = await response.text();
    const hash = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(raw))), b => b.toString(16).padStart(2, '0')).join('');
    model = { ...JSON.parse(raw), artifact_sha256: hash };
    for (const tab of await chrome.tabs.query({})) if (tab.id !== undefined) scheduleAnalysis(tab.id);
  }).catch(() => {});

  const durable = createDurableQueue(chrome.storage.local, {
    storageKey: 'capstone-durable-delivery-v1',
    ttlMs: 24 * 60 * 60 * 1000,
    maxRecords: 256,
    maxBytes: 1_000_000,
  });

  async function postEventBatch(payload: { events: SensitiveEvent[] }): Promise<void> {
    const response = await fetch(EVENTS_ENDPOINT, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(3000),
    });
    if (!response.ok) throw new Error('Typed event storage unavailable');
    const receipt = await response.json();
    if (receipt.isStored !== true || receipt.accepted !== payload.events.length) throw new Error('Typed event acknowledgement mismatch');
  }

  async function postReport(report: EventSecurityReport): Promise<void> {
    const response = await fetch(ASSESSMENTS_ENDPOINT, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(report),
      signal: AbortSignal.timeout(3000),
    });
    if (!response.ok || (await response.json()).isStored !== true) throw new Error('Assessment storage unavailable');
  }

  function eventBatchKey(events: SensitiveEvent[]): string {
    const first = events[0];
    const last = events[events.length - 1];
    return `events:${first.session_id}:${first.tab_id}:${first.event_seq}-${last.event_seq}`;
  }

  function reportKey(report: EventSecurityReport): string {
    return `report:${report.session_id}:${report.tab_id}:${report.event_seq}:${report.outcome}`;
  }

  async function deliverEventBatch(events: SensitiveEvent[]): Promise<void> {
    const payload = { events };
    const key = eventBatchKey(events);
    let durableStored = false;
    try {
      await durable.put({ kind: 'EVENT_BATCH', idempotencyKey: key, payload });
      durableStored = true;
    } catch (error) {
      console.warn('[CAPSTONE-1] Durable event mirror unavailable; session retry remains active.', error);
    }

    await postEventBatch(payload);
    if (durableStored) await durable.ack(key).catch(() => {});
  }

  const recorder = createRecorder(chrome.storage.session, deliverEventBatch);

  const scheduled = new Set<number>();
  const analysisScheduled = new Set<number>();
  const analysisActive = new Map<number, Promise<void>>();
  const analysisDirty = new Set<number>();
  let health: { checked_at: number; connected: boolean } = { checked_at: 0, connected: false };
  let healthRequest: Promise<void> | null = null;

  async function checkHealth() {
    if (healthRequest) return healthRequest;
    if (Date.now() - health.checked_at < 10000) return;
    healthRequest = (async () => {
      try {
        const response = await fetch('http://127.0.0.1:8000/api/v1/health', { signal: AbortSignal.timeout(2000) });
        health = { checked_at: Date.now(), connected: response.ok && (await response.json()).database === 'CONNECTED' };
      } catch { health = { checked_at: Date.now(), connected: false }; }
    })().finally(() => { healthRequest = null; });
    return healthRequest;
  }

  let reportTail: Promise<unknown> = Promise.resolve();
  function reportSerial<T>(fn: () => Promise<T>): Promise<T> {
    const result = reportTail.then(fn); reportTail = result.catch(() => {}); return result;
  }

  function acknowledgeReport(report: EventSecurityReport) {
    return reportSerial(async () => {
      const key = `assessment-pending:${report.tab_id}`;
      const pending = (await chrome.storage.session.get(key))[key];
      if (pending?.session_id === report.session_id && pending?.event_seq === report.event_seq) await chrome.storage.session.remove(key);
    });
  }

  function saveReport(report: EventSecurityReport, pending = false) {
    return reportSerial(async () => {
      const key = `security-report:${report.tab_id}`;
      const prior = (await chrome.storage.session.get(key))[key];
      if (prior?.session_id === report.session_id && prior.event_seq > report.event_seq) return false;
      await chrome.storage.session.set({ [key]: report, ...(pending ? { [`assessment-pending:${report.tab_id}`]: report } : {}) });
      return true;
    });
  }

  async function persistReport(report: EventSecurityReport) {
    const key = reportKey(report);
    let durableStored = false;
    try {
      await durable.put({ kind: 'ASSESSMENT_REPORT', idempotencyKey: key, payload: report });
      durableStored = true;
    } catch (error) {
      console.warn('[CAPSTONE-1] Durable report mirror unavailable; session retry remains active.', error);
    }

    await postReport(report);
    if (durableStored) await durable.ack(key).catch(() => {});
  }

  let durableReplayActive: Promise<void> | null = null;
  function replayDurableDelivery(): Promise<void> {
    if (durableReplayActive) return durableReplayActive;
    durableReplayActive = (async () => {
      const records = await durable.listReady();
      for (const record of records) {
        try {
          if (record.kind === 'EVENT_BATCH') {
            if (!isDurableEventBatch(record.payload)) {
              console.warn('[CAPSTONE-1] Discarding invalid durable event batch', record.idempotencyKey);
              await durable.ack(record.idempotencyKey);
              continue;
            }
            await postEventBatch(record.payload);
          } else {
            if (!isDurableReport(record.payload)) {
              console.warn('[CAPSTONE-1] Discarding invalid durable report', record.idempotencyKey);
              await durable.ack(record.idempotencyKey);
              continue;
            }
            await postReport(record.payload);
          }
          await durable.ack(record.idempotencyKey);
        } catch {
          // Keep this and later records for the next retry. Preserve ordering.
          break;
        }
      }
    })().finally(() => { durableReplayActive = null; });
    return durableReplayActive;
  }

  function analyze(tab: number): Promise<void> {
    analysisDirty.add(tab);
    const active = analysisActive.get(tab);
    if (active) return active;
    const task = (async () => { while (analysisDirty.delete(tab)) await analyzeOnce(tab); })()
      .finally(() => analysisActive.delete(tab));
    analysisActive.set(tab, task);
    return task;
  }

  async function analyzeOnce(tab: number) {
    const state = await recorder.snapshot(tab);
    const committed = [...state.events].reverse().find(e => e.frame_id === 0 && e.event_type === 'NAVIGATION_COMMITTED');
    const started = [...state.events].reverse().find(e => e.frame_id === 0 && e.event_type === 'NAVIGATION_STARTED');
    if (started && (!committed || started.event_seq > committed.event_seq)) return;
    const frames = await chrome.webNavigation.getAllFrames({ tabId: tab }).catch(() => null);
    if (!frames) return;
    const documents = new Set(frames.map(frame => frame.documentId));
    const events = state.events.filter(e => (!committed || e.event_seq >= committed.event_seq) && (!e.document_id || documents.has(e.document_id)));
    const incomplete = state.dropped > 0 || state.content_dropped > 0 || state.next_seq > state.events.length + 1;
    // The browser owns the immediate decision. Backend requests below only
    // persist sanitized research evidence and cannot replace this assessment.
    const report = assessEventStream(events, model, incomplete);
    if (!report) return;
    const current = await chrome.webNavigation.getFrame({ tabId: tab, frameId: 0 }).catch(() => null);
    if (!current || current.documentId !== report.document_id) return;
    if (!await saveReport(report)) return;
    if (report.document_id) {
      try {
        const reason = report.identity.status === 'POSSIBLE_IMPERSONATION' ? 'HOSTNAME_RESEMBLES_BRAND' :
          report.form_destinations.some(form => form.status === 'HTTPS_DOWNGRADE' && form.sensitive_types.length) ? 'HTTPS_DOWNGRADE' : 'DESTINATION_CHANGED';
        const receipt = await chrome.tabs.sendMessage(tab, { type: 'SECURITY_REPORT', action: report.action, reason }, { documentId: report.document_id });
        if (receipt?.outcome === 'WARNING_DISPLAYED' && report.outcome === 'DECISION_ONLY') report.outcome = 'WARNING_DISPLAYED';
      } catch { /* A decision does not prove that the page received a warning. */ }
    }
    if (!await saveReport(report, true)) return;
    const finalReport = report;
    void persistReport(finalReport).then(() => acknowledgeReport(finalReport)).catch(() => {});
  }

  function scheduleAnalysis(tab: number) {
    if (analysisScheduled.has(tab)) return;
    analysisScheduled.add(tab);
    setTimeout(() => { analysisScheduled.delete(tab); void analyze(tab).catch(() => {}); }, 100);
  }

  function flush(tab: number) {
    void recorder.flush(tab).catch(() => console.warn('[CAPSTONE-1] Typed events pending; backend unavailable'));
  }

  function schedule(tab: number) {
    scheduleAnalysis(tab);
    if (scheduled.has(tab)) return;
    scheduled.add(tab);
    setTimeout(() => { scheduled.delete(tab); flush(tab); }, 500);
  }

  chrome.alarms.create('tsfeg-retry', { periodInMinutes: 1 });
  chrome.alarms.onAlarm.addListener(alarm => {
    if (alarm.name !== 'tsfeg-retry') return;
    void replayDurableDelivery().catch(() => {});
    void chrome.storage.session.get(null).then(states => {
      for (const key of Object.keys(states)) if (key.startsWith('tsfeg:')) { const tab = Number(key.slice(6)); flush(tab); scheduleAnalysis(tab); }
      for (const key of Object.keys(states)) if (key.startsWith('assessment-pending:')) {
        void persistReport(states[key]).then(() => acknowledgeReport(states[key])).catch(() => {});
      }
    });
  });

  chrome.tabs.onRemoved.addListener(tab => {
    void chrome.storage.session.remove(`security-report:${tab}`);
    void recorder.flush(tab).then(() => chrome.storage.session.remove(`tsfeg:${tab}`)).catch(() => {});
  });

  chrome.runtime.onMessage.addListener((message, sender, respond) => {
    if (message?.type === 'GET_SECURITY_REPORT' || message?.type === 'RETRY_DELIVERY') {
      if (!sender.url?.startsWith(chrome.runtime.getURL(''))) { respond({ ok: false }); return false; }
      void chrome.tabs.query({ active: true, currentWindow: true }).then(async tabs => {
        const tab = tabs[0]?.id;
        if (tab === undefined) { respond({ ok: true, report: null }); return; }
        if (message.type === 'RETRY_DELIVERY') {
          health.checked_at = 0;
          await recorder.flush(tab).catch(() => {});
          const key = `assessment-pending:${tab}`;
          const pending = (await chrome.storage.session.get(key))[key];
          if (pending) await persistReport(pending).then(() => acknowledgeReport(pending)).catch(() => {});
          await replayDurableDelivery().catch(() => {});
          await analyze(tab).catch(() => {});
          await checkHealth();
        }
        // A slow or unavailable research backend must not delay the popup's
        // current local assessment. Health updates arrive on the next refresh.
        void checkHealth();
        const report = (await chrome.storage.session.get(`security-report:${tab}`))[`security-report:${tab}`];
        const state = await recorder.snapshot(tab);
        const pendingReport = (await chrome.storage.session.get(`assessment-pending:${tab}`))[`assessment-pending:${tab}`];
        const durableStats = await durable.stats().catch(() => ({ count: 0, bytes: 0, dropped: 0, corrupt: 0 }));
        const frame = await chrome.webNavigation.getFrame({ tabId: tab, frameId: 0 }).catch(() => null);
        respond({ ok: true, report: frame && report?.document_id === frame.documentId ? report : null,
          delivery: { backend_connected: health.connected, checked_at: health.checked_at,
            pending_events: state.pending.length, pending_report: !!pendingReport,
            dropped_events: state.dropped + state.content_dropped, content_delivery_errors: state.content_delivery_errors,
            last_acknowledged_event: state.last_ack_seq ?? 0,
            durable_pending: durableStats.count, durable_bytes: durableStats.bytes,
            durable_dropped: durableStats.dropped, durable_corrupt: durableStats.corrupt },
          extension_version: chrome.runtime.getManifest().version });
      }).catch(() => respond({ ok: false }));
      return true;
    }
    if (message?.type === 'TYPED_EVENTS') {
      const tab = sender.tab?.id;
      if (typeof tab !== 'number' || !validateContentBatch(message) ||
        message.events.some(ev => !['DOCUMENT_STARTED', 'PAGE_CONTEXT_OBSERVED', 'FIELD_DISCOVERED', 'SENSITIVE_INTERACTION', 'DOM_MUTATION', 'FORM_TARGET_OBSERVED', 'DOCUMENT_ENDED', 'FORM_DISCOVERED', 'FORM_TARGET_CHANGED', 'FORM_SUBMISSION_ATTEMPT', 'SUBMISSION_PREVENTED', 'SUBMISSION_CONFIRMED'].includes(ev.event_type))) {
        respond({ ok: false, error: 'Invalid typed event batch' }); return false;
      }
      void recorder.appendBatch({ ...message, events: message.events.map(ev => ({ ...ev,
        frame_origin: safeOrigin(sender.origin === undefined ? sender.url : sender.origin), initiator_origin: null,
        destination_origin: null, request_type: null })) }, {
        tab_id: tab, document_id: sender.documentId || null, frame_id: sender.frameId ?? 0, parent_frame_id: null, trust: 'ISOLATED_CONTENT_SCRIPT',
      }).then(receipt => { schedule(tab); respond(receipt); }).catch(() => respond({ ok: false, error: 'Event storage failed' }));
      return true;
    }
    if (message?.type === 'EXPORT_TSFEG') {
      // Only extension pages (test harness/popup), never content-script callers.
      if (!sender.url?.startsWith(chrome.runtime.getURL('')) || !Number.isInteger(message.tabId)) { respond({ ok: false }); return false; }
      void recorder.snapshot(message.tabId).then(state => respond({ ok: true, ...state,
        representations: buildEventRepresentations(state.events), graph: buildGraph(state.events), flat_control: buildFlatControl(state.events) }));
      return true;
    }
    return false;
  });

  function network(details: (chrome.webRequest.WebRequestBodyDetails | chrome.webRequest.WebRedirectionResponseDetails) & { documentId?: string }, event_type: Observation['event_type']) {
    if (details.tabId < 0) return;
    void recorder.append(observation({ event_type, destination_origin: safeOrigin('redirectUrl' in details ? details.redirectUrl : details.url),
      initiator_origin: safeOrigin(details.initiator), request_type: details.type, timestamp_ms: Math.floor(details.timeStamp),
    }), { tab_id: details.tabId, document_id: details.documentId || null, frame_id: details.frameId,
      parent_frame_id: details.parentFrameId, trust: 'WEBREQUEST_METADATA' }).then(() => schedule(details.tabId)).catch(() => console.warn('[CAPSTONE-1] Request event rejected or storage unavailable'));
  }

  // Metadata only: no requestBody, requestHeaders, responseHeaders or extraHeaders.
  chrome.webRequest.onBeforeRequest.addListener(details => network(details, 'REQUEST_OBSERVED'), { urls: ['<all_urls>'] });
  chrome.webRequest.onBeforeRedirect.addListener(details => network(details, 'REDIRECT_OBSERVED'), { urls: ['<all_urls>'] });

  function navigation(details: chrome.webNavigation.WebNavigationFramedCallbackDetails, event_type: Observation['event_type']) {
    if (!safeOrigin(details.url)) return;
    void recorder.append(observation({ event_type, frame_origin: safeOrigin(details.url), destination_origin: safeOrigin(details.url), timestamp_ms: Math.floor(details.timeStamp) }),
      { tab_id: details.tabId, document_id: details.documentId || null, frame_id: details.frameId, parent_frame_id: null, trust: 'WEBNAVIGATION_METADATA' })
      .then(() => schedule(details.tabId)).catch(() => console.warn('[CAPSTONE-1] Navigation event rejected or storage unavailable'));
  }

  chrome.webNavigation.onBeforeNavigate.addListener(details => navigation(details, 'NAVIGATION_STARTED'));
  chrome.webNavigation.onCommitted.addListener(details => navigation(details, 'NAVIGATION_COMMITTED'));
  chrome.webNavigation.onHistoryStateUpdated.addListener(details => navigation(details, 'HISTORY_UPDATED'));
  chrome.webNavigation.onReferenceFragmentUpdated.addListener(details => navigation(details, 'HISTORY_UPDATED'));

  // storage.local survives service-worker and full-browser restarts. Replays are
  // backend-idempotent; local detection never waits for this research delivery.
  void replayDurableDelivery().catch(() => {});

  return recorder;
}
