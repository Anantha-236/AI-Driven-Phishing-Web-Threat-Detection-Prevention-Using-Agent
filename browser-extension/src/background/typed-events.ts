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
import { assessEventStreamDetailed, EventSecurityReport } from '../core/assessment';
import { EventModelArtifact } from '../core/service-worker-onnx-adapter';
import { createDurableQueue } from '../core/storage/durable-queue';
import { createSessionContainment } from '../core/enforcement/session-containment';
import { createAgentEnforcementPlan } from '../core/agent/enforcement-plan';
import { transitionAgent } from '../core/agent/state-machine';
import type { AgentAction, AgentRiskState, EnforcementOutcome, RiskDecision } from '../core/agent/types';
import { StageBOnnxAdapter } from '../core/stage-b-onnx-adapter';
import { createStageBShadowController } from '../core/stage-b-shadow';

const EVENTS_ENDPOINT = 'http://127.0.0.1:8000/api/v1/events/batch';
const ASSESSMENTS_ENDPOINT = 'http://127.0.0.1:8000/api/v1/assessments';
const AGENT_RUNTIME_PREFIX = 'agent-runtime:';

export interface AgentRuntimeSnapshot {
  schema_version: 'agent-runtime-1';
  tab_id: number;
  document_id: string | null;
  event_seq: number;
  state: AgentRiskState;
  requested_action: AgentAction;
  effective_action: AgentAction;
  enforcement_outcome: EnforcementOutcome;
  content_outcome: EventSecurityReport['outcome'];
  containment_origin: string | null;
  automatic_block_authorized: boolean;
  updated_at: number;
}

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
  const stageBShadowController = createStageBShadowController(
    new StageBOnnxAdapter(),
    chrome.storage.session,
  );
  void stageBShadowController.initialize();
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

  const containment = createSessionContainment();

  async function readAgentRuntime(tab: number): Promise<AgentRuntimeSnapshot | null> {
    const key = `${AGENT_RUNTIME_PREFIX}${tab}`;
    const value = (await chrome.storage.session.get(key))[key] as AgentRuntimeSnapshot | undefined;
    return value?.schema_version === 'agent-runtime-1' ? value : null;
  }

  async function writeAgentRuntime(snapshot: AgentRuntimeSnapshot): Promise<void> {
    await chrome.storage.session.set({ [`${AGENT_RUNTIME_PREFIX}${snapshot.tab_id}`]: snapshot });
  }

  async function clearAgentRuntime(tab: number): Promise<void> {
    await chrome.storage.session.remove(`${AGENT_RUNTIME_PREFIX}${tab}`);
  }

  function reportReason(report: EventSecurityReport): string {
    if (report.identity.status === 'POSSIBLE_IMPERSONATION') return 'HOSTNAME_RESEMBLES_BRAND';
    if (report.form_destinations.some(form => form.status === 'HTTPS_DOWNGRADE' && form.sensitive_types.length)) return 'HTTPS_DOWNGRADE';
    return 'DESTINATION_CHANGED';
  }

  async function executeAgentDecision(
    tab: number,
    report: EventSecurityReport,
    riskDecision: RiskDecision,
  ): Promise<AgentRuntimeSnapshot> {
    const prior = await readAgentRuntime(tab);
    let state: AgentRiskState = prior?.document_id === report.document_id ? prior.state : 'OBSERVING';

    let transitionAccepted = true;
    if (!(state === 'CONTAINED' && riskDecision.state === 'HIGH_RISK')) {
      const transition = transitionAgent(state, riskDecision.state);
      transitionAccepted = transition.accepted;
      if (transition.accepted) state = transition.to;
    }

    const requestedPlan = createAgentEnforcementPlan(report, riskDecision);
    const plan = !transitionAccepted
      ? {
          ...requestedPlan,
          contentAction: 'CONFIRM' as const,
          containmentOrigin: null,
          releaseContainment: false,
        }
      : requestedPlan;
    let effectiveAction: AgentAction = transitionAccepted
      ? plan.requestedAction
      : 'SHIELD_SENSITIVE_ACTION';
    let enforcementOutcome: EnforcementOutcome = 'DECISION_ONLY';
    let containmentOrigin: string | null = null;

    if (plan.releaseContainment) {
      enforcementOutcome = await containment.release({
        tabId: tab,
        documentId: report.document_id ?? undefined,
      });
    }

    if (plan.containmentOrigin && report.document_id) {
      containmentOrigin = plan.containmentOrigin;
      enforcementOutcome = await containment.install({
        tabId: tab,
        documentId: report.document_id,
        destinationOrigin: plan.containmentOrigin,
      });

      if (enforcementOutcome === 'SESSION_RULE_INSTALLED') {
        const contained = transitionAgent(state, 'CONTAINED');
        if (contained.accepted) state = contained.to;
      } else {
        effectiveAction = 'SHIELD_SENSITIVE_ACTION';
      }
    } else if (plan.requestedAction === 'CONTAIN_TAB' || plan.requestedAction === 'ADD_SESSION_BLOCK') {
      effectiveAction = 'SHIELD_SENSITIVE_ACTION';
    }

    if (report.document_id) {
      try {
        const receipt = await chrome.tabs.sendMessage(
          tab,
          { type: 'SECURITY_REPORT', action: plan.contentAction, reason: reportReason(report) },
          { documentId: report.document_id },
        );
        if (receipt?.outcome === 'WARNING_DISPLAYED' && report.outcome === 'DECISION_ONLY') {
          report.outcome = 'WARNING_DISPLAYED';
          if (enforcementOutcome === 'DECISION_ONLY') enforcementOutcome = 'WARNING_DISPLAYED';
        }
      } catch {
        // The local decision or installed DNR rule remains valid.
      }
    }

    const snapshot: AgentRuntimeSnapshot = {
      schema_version: 'agent-runtime-1',
      tab_id: tab,
      document_id: report.document_id,
      event_seq: report.event_seq,
      state,
      requested_action: plan.requestedAction,
      effective_action: effectiveAction,
      enforcement_outcome: enforcementOutcome,
      content_outcome: report.outcome,
      containment_origin: containmentOrigin,
      automatic_block_authorized: riskDecision.automaticBlockAuthorized,
      updated_at: Date.now(),
    };
    await writeAgentRuntime(snapshot);
    return snapshot;
  }

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
    const assessment = assessEventStreamDetailed(events, model, incomplete);
    if (!assessment) return;
    const { report, riskDecision } = assessment;
    // Stage B remains observational only. It receives the same sanitized event
    // episode and contextual extractor but cannot return or replace report/riskDecision.
    void stageBShadowController.observe({
      tabId: tab,
      documentId: report.document_id,
      eventSeq: report.event_seq,
      events,
      incomplete,
      baselineScore: report.model_score,
    }).catch(() => {});
    const current = await chrome.webNavigation.getFrame({ tabId: tab, frameId: 0 }).catch(() => null);
    if (!current || current.documentId !== report.document_id) return;
    if (!await saveReport(report)) return;

    const beforeEnforcement = await chrome.webNavigation.getFrame({ tabId: tab, frameId: 0 }).catch(() => null);
    if (!beforeEnforcement || beforeEnforcement.documentId !== report.document_id) return;
    await executeAgentDecision(tab, report, riskDecision);

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
    void containment.cleanupExpired().catch(() => {});
    void replayDurableDelivery().catch(() => {});
    void chrome.storage.session.get(null).then(states => {
      for (const key of Object.keys(states)) if (key.startsWith('tsfeg:')) { const tab = Number(key.slice(6)); flush(tab); scheduleAnalysis(tab); }
      for (const key of Object.keys(states)) if (key.startsWith('assessment-pending:')) {
        void persistReport(states[key]).then(() => acknowledgeReport(states[key])).catch(() => {});
      }
    });
  });

  chrome.tabs.onRemoved.addListener(tab => {
    void containment.release({ tabId: tab }).catch(() => {});
    void chrome.storage.session.remove([`security-report:${tab}`, `${AGENT_RUNTIME_PREFIX}${tab}`]);
    void stageBShadowController.clear(tab).catch(() => {});
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
        const agentRuntime = await readAgentRuntime(tab);
        const stageBShadow = await stageBShadowController.read(tab);
        respond({ ok: true, report: frame && report?.document_id === frame.documentId ? report : null,
          agent_runtime: frame && agentRuntime?.document_id === frame.documentId ? agentRuntime : null,
          stage_b_shadow: frame && stageBShadow?.document_id === frame.documentId ? stageBShadow : null,
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

  const navigationReset = new Map<number, Promise<void>>();

  function navigation(details: chrome.webNavigation.WebNavigationFramedCallbackDetails, event_type: Observation['event_type']) {
    const frameOrigin = safeOrigin(details.url);
    if (!frameOrigin) return;

    // Queue the sanitized navigation event immediately so Chromium callback order
    // is preserved by the recorder's serialized append queue. Cleanup must never
    // delay NAVIGATION_STARTED behind a later NAVIGATION_COMMITTED event.
    const append = recorder.append(
      observation({
        event_type,
        frame_origin: frameOrigin,
        destination_origin: frameOrigin,
        timestamp_ms: Math.floor(details.timeStamp),
      }),
      {
        tab_id: details.tabId,
        document_id: details.documentId || null,
        frame_id: details.frameId,
        parent_frame_id: null,
        trust: 'WEBNAVIGATION_METADATA',
      },
    );

    if (details.frameId === 0 && event_type === 'NAVIGATION_STARTED') {
      const reset = append.then(async () => {
        await containment.release({ tabId: details.tabId }).catch(() => 'ENFORCEMENT_FAILED' as const);
        await clearAgentRuntime(details.tabId).catch(() => {});
        await chrome.storage.session.remove(`security-report:${details.tabId}`).catch(() => {});
      });
      navigationReset.set(details.tabId, reset);
      void reset.finally(() => {
        if (navigationReset.get(details.tabId) === reset) navigationReset.delete(details.tabId);
      });
    }

    void (async () => {
      await append;
      // A top-level commit may arrive while the start-event cleanup is still
      // running. Wait for that reset before scheduling analysis so it cannot
      // delete a freshly generated report or leave stale containment in place.
      if (details.frameId === 0 && event_type === 'NAVIGATION_COMMITTED') {
        await navigationReset.get(details.tabId)?.catch(() => {});
      }
      schedule(details.tabId);
    })().catch(() => console.warn('[CAPSTONE-1] Navigation event rejected or storage unavailable'));
  }

  chrome.webNavigation.onBeforeNavigate.addListener(details => navigation(details, 'NAVIGATION_STARTED'));
  chrome.webNavigation.onCommitted.addListener(details => navigation(details, 'NAVIGATION_COMMITTED'));
  chrome.webNavigation.onHistoryStateUpdated.addListener(details => navigation(details, 'HISTORY_UPDATED'));
  chrome.webNavigation.onReferenceFragmentUpdated.addListener(details => navigation(details, 'HISTORY_UPDATED'));

  void containment.cleanupExpired().catch(() => {});

  // storage.local survives service-worker and full-browser restarts. Replays are
  // backend-idempotent; local detection never waits for this research delivery.
  void replayDurableDelivery().catch(() => {});

  return recorder;
}
