import type { EventSecurityReport } from '../core/assessment';
import { LOGIN_ORIGINS } from '../core/profiles/service-profiles';

interface AgentRuntimeSnapshot {
  schema_version: 'agent-runtime-1';
  tab_id: number;
  document_id: string | null;
  event_seq: number;
  state:
    | 'OBSERVING'
    | 'LOW_RISK'
    | 'UNCERTAIN'
    | 'SUSPICIOUS'
    | 'HIGH_RISK'
    | 'CONTAINED'
    | 'USER_OVERRIDDEN'
    | 'ENDED';
  requested_action:
    | 'ALLOW'
    | 'WARN'
    | 'CONFIRM'
    | 'SHIELD_SENSITIVE_ACTION'
    | 'CONTAIN_TAB'
    | 'ADD_SESSION_BLOCK'
    | 'REMOVE_SESSION_BLOCK'
    | 'REDIRECT_INTERSTITIAL'
    | 'RELEASE_CONTAINMENT';
  effective_action:
    | 'ALLOW'
    | 'WARN'
    | 'CONFIRM'
    | 'SHIELD_SENSITIVE_ACTION'
    | 'CONTAIN_TAB'
    | 'ADD_SESSION_BLOCK'
    | 'REMOVE_SESSION_BLOCK'
    | 'REDIRECT_INTERSTITIAL'
    | 'RELEASE_CONTAINMENT';
  enforcement_outcome:
    | 'DECISION_ONLY'
    | 'WARNING_DISPLAYED'
    | 'SUBMIT_EVENT_CANCELLED'
    | 'SESSION_RULE_INSTALLED'
    | 'SESSION_RULE_REMOVED'
    | 'TAB_REDIRECTED_TO_INTERSTITIAL'
    | 'USER_CONFIRMED'
    | 'USER_OVERRIDE_APPLIED'
    | 'ENFORCEMENT_FAILED';
  content_outcome:
    | 'DECISION_ONLY'
    | 'WARNING_DISPLAYED'
    | 'SUBMIT_EVENT_CANCELLED'
    | 'USER_CONFIRMED';
  containment_origin: string | null;
  automatic_block_authorized: boolean;
  updated_at: number;
}

let latestResponse: any = null;
let protectionStatus: any = null;

const labels: Record<string, string> = {
  sensitive_cross_target: 'A sensitive field is associated with a form targeting another origin.',
  target_changed_after_interaction: 'The form destination changed after sensitive-field interaction.',
  request_near_interaction: 'A request occurred shortly after interaction; this is temporal association only.',
  cross_request_near_interaction: 'A cross-origin request occurred near interaction; its body was not inspected.',
  password_then_otp: 'Password interaction was followed by one-time-password interaction.',
  dynamic_sensitive_field: 'A sensitive field was discovered after a DOM mutation.',
  submission_target_mismatch: 'The submission target differed from the previously observed form target.',
  frame_origin_mismatch: 'A sensitive field appeared in a frame with a different origin.',
};

function set(id: string, value: string) {
  const el = document.getElementById(id);
  if (el) el.textContent = value;
}

function human(value: string): string {
  return value.replaceAll('_', ' ');
}

function renderCodes(id: string, codes: string[], empty: string) {
  const list = document.getElementById(id)!;
  list.replaceChildren();

  for (const code of codes.length ? codes : [empty]) {
    const item = document.createElement('li');
    item.textContent = human(code);
    list.append(item);
  }
}

function enforcementMode(runtime: AgentRuntimeSnapshot): string {
  switch (runtime.enforcement_outcome) {
    case 'SESSION_RULE_INSTALLED':
      return 'POST-START TAB CONTAINMENT (session DNR)';
    case 'TAB_REDIRECTED_TO_INTERSTITIAL':
      return 'POST-START INTERSTITIAL CONTAINMENT';
    case 'SUBMIT_EVENT_CANCELLED':
      return 'SENSITIVE SUBMISSION BLOCKED';
    case 'WARNING_DISPLAYED':
      return 'WARNING ONLY';
    case 'USER_CONFIRMED':
      return 'USER CONFIRMED';
    case 'USER_OVERRIDE_APPLIED':
      return 'USER OVERRIDE APPLIED';
    case 'SESSION_RULE_REMOVED':
      return 'CONTAINMENT RELEASED';
    case 'ENFORCEMENT_FAILED':
      return 'ENFORCEMENT FAILED; SENSITIVE-ACTION SHIELD RETAINED';
    case 'DECISION_ONLY':
      return 'DECISION ONLY';
  }
}

function renderAgentRuntime(runtime: AgentRuntimeSnapshot | null) {
  const container = document.getElementById('agent-runtime-container');
  if (!container) return;

  container.style.display = runtime ? 'block' : 'none';
  if (!runtime) return;

  set('agent-state', human(runtime.state));
  set('requested-action', human(runtime.requested_action));
  set('effective-action', human(runtime.effective_action));
  set('enforcement-outcome', human(runtime.enforcement_outcome));
  set('enforcement-mode', enforcementMode(runtime));
  set('containment-origin', runtime.containment_origin ?? 'None');
  set('automatic-block-authorized', runtime.automatic_block_authorized ? 'YES' : 'NO');
  set('agent-event-seq', String(runtime.event_seq));
  set('agent-updated-at', new Date(runtime.updated_at).toLocaleString());
}

function render(report: EventSecurityReport | null) {
  document.getElementById('threat-container')!.style.display = report ? 'block' : 'none';
  document.getElementById('status-idle')!.style.display = report ? 'none' : 'block';

  if (!report) return;

  set(
    'threat-level',
    report.threatLevel === 'benign'
      ? 'No elevated pattern observed'
      : human(report.threatLevel),
  );

  document.getElementById('threat-level')!.className =
    `threat-level ${report.threatLevel}`;

  set('score', report.risk);
  set(
    'confidence',
    `${report.confidence} (evidence heuristic; not a calibrated probability)`,
  );

  set(
    'purpose',
    `${human(report.purpose.value)} (${report.purpose.evidence_status.toLowerCase()}, ${report.purpose.confidence.toLowerCase()} confidence). ` +
      `${report.purpose.basis.map(human).join('; ')}. ${report.purpose.limitations.join(' ')}`,
  );

  set(
    'completeness',
    `${report.evidence_completeness.level}: ${Math.round(report.evidence_completeness.score * 100)}% of defined observation categories. ` +
      `This measures coverage, not website safety. Missing: ${
        report.evidence_completeness.missing.map(human).join(', ') ||
        'none in the defined categories'
      }.`,
  );

  renderCodes(
    'positive-evidence',
    report.positive_evidence,
    'No supporting consistency evidence observed',
  );

  renderCodes(
    'contradictions',
    report.contradictions,
    'No contextual contradictions observed',
  );

  set('domain', report.page_origin || 'Origin unknown');
  set('data-categories', report.requestedDataTypes.join(', ') || 'None observed');
  set('action', report.action);
  set('outcome', human(report.outcome));

  set(
    'model',
    report.model_score === null
      ? 'Unavailable; local context analysis remains active.'
      : `${report.model_id}: ${report.model_score.toFixed(3)}. Training provenance: ${report.model_provenance}. ${
          report.model_calibrated
            ? 'Calibration was evaluated on the artifact dataset; real-world probability calibration is unverified.'
            : 'Uncalibrated model output; not a probability of real-world phishing.'
        }`,
  );

  set('destinations', report.destinations.join(', ') || 'No destination observed');

  set(
    'agent',
    `${report.agent_version}: LOCAL PRIMARY assessment. The browser combines model output and contextual evidence; ` +
      `backend availability does not control this decision. ${report.decision_reasons.map(human).join('; ')}. ` +
      'Confirmation is not proof of phishing.',
  );

  const identity = report.identity;
  const source = LOGIN_ORIGINS.find(entry => entry.origin === report.page_origin);

  set(
    'identity',
    identity?.status === 'KNOWN_LOGIN_ORIGIN'
      ? `${identity.service}: exact known login origin. Source: ${source?.source}; checked ${source?.checked}. ` +
        'This does not verify every page or authorize every destination.'
      : identity?.status === 'POSSIBLE_IMPERSONATION'
        ? `Hostname resembles ${identity.service}, but is outside the known login registry. Possible impersonation; not a confirmed finding.`
        : 'Unknown. No matching entry in the limited login-origin registry. HTTPS alone does not establish authenticity.',
  );

  const destinations = document.getElementById('form-destinations')!;
  destinations.replaceChildren();

  for (const form of report.form_destinations ?? []) {
    const row = document.createElement('li');
    row.textContent =
      `Frame ${form.frame_id}, form ${form.form_id}: ${form.sensitive_types.join(', ') || 'no classified sensitive fields'} ` +
      `→ ${form.target_origin || 'unknown target'} (${human(form.status)}). ` +
      `Page: ${form.page_origin || 'unknown'}. Evidence event ${form.event_seq}.`;
    destinations.append(row);
  }

  if (!destinations.childElementCount) {
    const row = document.createElement('li');
    row.textContent =
      'No form destination available. Script-generated destinations may not be knowable before a request.';
    destinations.append(row);
  }

  const list = document.getElementById('reasons-list')!;
  list.replaceChildren();

  for (const evidence of report.evidence.slice(-30)) {
    const item = document.createElement('li');
    item.textContent =
      `${evidence.evidence_status}: ${labels[evidence.code]} Supporting events: ${evidence.event_seqs.join(', ')}.`;
    list.append(item);
  }

  if (!report.evidence.length) {
    const item = document.createElement('li');
    item.textContent =
      'No elevated relationship evidence observed. This does not establish that the website is safe.';
    list.append(item);
  }

  set(
    'unknowns',
    'UNKNOWN: destination authorization and whether a sensitive value was transmitted. ' +
      'NOT OBSERVABLE: remote server processing. Form targets are structural observations, not proof of value transmission. ' +
      'Submit-button overrides are rechecked at submission. Direct programmatic submissions and arbitrary fetch/XHR requests ' +
      'are not universally prevented.' +
      (report.unknowns.includes('COLLECTION_INCOMPLETE')
        ? ' Collection is incomplete.'
        : ''),
  );

  set(
    'recommendation',
    report.action === 'ALLOW'
      ? 'Use your normal verification steps before sharing sensitive information.'
      : 'Verify the website and destination before submitting. A changed sensitive-form destination may require confirmation.',
  );

  set(
    'performance',
    `Local analysis: ${report.analysis_latency_ms.toFixed(2)} ms. Evidence through event ${report.event_seq}. ` +
      'This measures assessment computation, not time from page interaction to prevention.',
  );
}

async function refresh() {
  try {
    const [response, protection] = await Promise.all([
      chrome.runtime.sendMessage({ type: 'GET_SECURITY_REPORT' }),
      chrome.runtime.sendMessage({ type: 'GET_PROTECTION_STATUS' }),
    ]);

    latestResponse = response;
    protectionStatus = protection?.protection;

    render(response?.report ?? null);
    renderAgentRuntime(response?.agent_runtime ?? null);

    const d = response?.delivery;

    set(
      'runtime-status',
      response?.ok
        ? `v${response.extension_version || '?'} · LOCAL AGENT`
        : 'UNAVAILABLE',
    );

    set(
      'delivery',
      d
        ? `${
            !d.checked_at
              ? 'Checking research backend.'
              : d.backend_connected
                ? 'Backend and PostgreSQL reachable.'
                : 'Backend unavailable; local protection continues.'
          } ` +
          `${d.pending_events} events queued; report ${d.pending_report ? 'pending' : 'not pending'}. ` +
          `Last acknowledged event: ${d.last_acknowledged_event}. ` +
          `Dropped events: ${d.dropped_events}. Content delivery errors: ${d.content_delivery_errors}. ` +
          `Durable restart queue: ${d.durable_pending ?? 0} records / ${d.durable_bytes ?? 0} bytes; ` +
          `durable dropped: ${d.durable_dropped ?? 0}; corrupt rejected: ${d.durable_corrupt ?? 0}.`
        : 'No delivery status available.',
    );

    set(
      'protection',
      protectionStatus
        ? `${protectionStatus.state}: ${protectionStatus.rule_count} exact URL rules. ` +
          `Updated: ${
            protectionStatus.updated_at
              ? new Date(protectionStatus.updated_at).toLocaleString()
              : 'never'
          }. Excluded indicators: ${protectionStatus.excluded_count}.`
        : 'Protection status unavailable.',
    );
  } catch {
    render(null);
    renderAgentRuntime(null);
    set('runtime-status', 'UNAVAILABLE');
  }
}

document.getElementById('btn-refresh')?.addEventListener('click', () => void refresh());

document.getElementById('btn-retry')?.addEventListener('click', async () => {
  const button = document.getElementById('btn-retry') as HTMLButtonElement;
  button.disabled = true;

  try {
    await chrome.runtime.sendMessage({ type: 'RETRY_DELIVERY' });
    await refresh();
  } finally {
    button.disabled = false;
  }
});

document.getElementById('btn-feed')?.addEventListener('click', async () => {
  const button = document.getElementById('btn-feed') as HTMLButtonElement;
  button.disabled = true;

  try {
    await chrome.runtime.sendMessage({ type: 'REFRESH_PHISHING_FEED' });
    await refresh();
  } finally {
    button.disabled = false;
  }
});

document.getElementById('btn-export')?.addEventListener('click', () => {
  if (!latestResponse?.report) return;

  const data = {
    exported_at: new Date().toISOString(),
    ...latestResponse,
    protection: protectionStatus,
    identity_registry_sources: LOGIN_ORIGINS,
    limitations: [
      'Training provenance is reported separately; real-world calibration and generalization require independent validation.',
      'Purpose is inferred from structural observations, not verified service intent.',
      'Identity association does not prove page safety.',
      'Destinations do not establish payload flow.',
      'Known-feed URL blocking and post-start agent containment have different timing semantics.',
      'A session DNR rule installed after navigation began is not a pre-request block of that first unknown navigation.',
    ],
  };

  const url = URL.createObjectURL(
    new Blob([JSON.stringify(data, null, 2)], {
      type: 'application/json',
    }),
  );

  const link = document.createElement('a');
  link.href = url;
  link.download =
    `capstone-report-${latestResponse.report.tab_id}-${latestResponse.report.event_seq}.json`;
  link.click();

  setTimeout(() => URL.revokeObjectURL(url), 1000);
});

void refresh();
setInterval(() => void refresh(), 1000);
