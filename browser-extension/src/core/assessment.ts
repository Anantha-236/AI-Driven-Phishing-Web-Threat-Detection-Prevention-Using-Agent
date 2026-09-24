/**
 * CAPSTONE-1 Threat Assessment Module
 *
 * The current event path combines privacy-safe contextual evidence with the
 * local model through a versioned risk-fusion contract. The existing snapshot
 * assessment remains for compatibility telemetry.
 */

import {
  ModelResult,
  EvidenceCollection,
  FeatureVector,
  ThreatAssessment,
  ThreatLevel,
} from "./schema/types";
import { extractObservedEvents } from "./profiles/observed-behavior";
import { compareBehavior } from "./profiles/comparator";
import {
  buildContextFeatures,
  buildEventRepresentations,
  SensitiveEvent,
  RelationshipEvidence,
  SensitiveType,
  PurposeEvidence,
  EvidenceCompleteness,
} from './tsfeg';
import {
  EventModelArtifact,
  inferEventModel,
} from './service-worker-onnx-adapter';
import {
  identifyOrigin,
  destinationStatus,
  OriginIdentity,
} from './profiles/service-profiles';
import type {
  AgentRiskState,
  RiskDecision,
  RiskSignalSet,
} from './agent/types';
import { fuseRiskSignals } from './agent/risk-fusion';

export interface FormDestination {
  document_id: string | null;
  frame_id: number;
  form_id: string;
  page_origin: string | null;
  target_origin: string | null;
  status: ReturnType<typeof destinationStatus>;
  sensitive_types: SensitiveType[];
  event_seq: number;
}

export interface EventSecurityReport {
  schema_version: 'event-report-1';
  analysis_version: 'event-analysis-1';
  policy_version: 'evidence-policy-1';
  session_id: string;
  tab_id: number;
  document_id: string | null;
  event_seq: number;
  timestamp_ms: number;
  destinations: string[];
  page_origin: string | null;
  threatLevel: ThreatLevel;
  risk: 'LOW' | 'MEDIUM' | 'HIGH' | 'UNKNOWN';
  confidence: 'LOW' | 'MEDIUM';
  confidence_kind: 'uncalibrated_evidence_coverage';
  action: 'ALLOW' | 'WARN' | 'CONFIRM';
  outcome:
    | 'DECISION_ONLY'
    | 'WARNING_DISPLAYED'
    | 'SUBMIT_EVENT_CANCELLED'
    | 'USER_CONFIRMED';
  requestedDataTypes: SensitiveType[];
  evidence: RelationshipEvidence[];
  model_sha256: string | null;
  model_id: string;
  model_score: number | null;
  model_provenance:
    | 'CONTROLLED'
    | 'SYNTHETIC'
    | 'REAL'
    | 'ARCHIVED'
    | 'MIXED'
    | 'UNAVAILABLE';
  model_calibrated: boolean;
  unknowns: Array<
    | 'VALUE_TRANSMISSION_UNKNOWN'
    | 'SERVER_BEHAVIOR_NOT_OBSERVABLE'
    | 'IDENTITY_UNKNOWN'
    | 'MODEL_UNCALIBRATED'
    | 'COLLECTION_INCOMPLETE'
    | 'PROGRAMMATIC_SUBMISSION_NOT_COVERED'
  >;
  flat_parameters: number[];
  relationship_parameters: number[];
  analysis_latency_ms: number;
  context_feature_version: 'context-features-1';
  contextual_parameters: number[];
  purpose: PurposeEvidence;
  positive_evidence: string[];
  contradictions: string[];
  evidence_completeness: EvidenceCompleteness;
  identity: OriginIdentity;
  form_destinations: FormDestination[];
  decision_source:
    | 'LOCAL_ML_AGENT'
    | 'BACKEND_ML_AGENT'
    | 'LOCAL_FALLBACK';
  agent_version:
    | 'local-context-agent-1'
    | 'backend-ml-agent-1'
    | null;
  decision_reasons: string[];
  model_contributions: number[];
  agent_roundtrip_ms: number | null;
}

function mapCompleteness(
  level: EvidenceCompleteness['level'],
): RiskSignalSet['context']['completeness'] {
  if (level === 'SUFFICIENT') return 'SUFFICIENT';
  if (level === 'PARTIAL') return 'MEDIUM';
  return 'LOW';
}

/**
 * Keep the existing persisted/browser enforcement contract stable during
 * Task 2. Later Stage A tasks will execute the richer AgentAction directly.
 */
export function legacyActionFromRiskDecision(
  decision: RiskDecision,
): EventSecurityReport['action'] {
  switch (decision.action) {
    case 'ALLOW':
      return 'ALLOW';
    case 'WARN':
      return 'WARN';
    case 'CONFIRM':
    case 'SHIELD_SENSITIVE_ACTION':
    case 'CONTAIN_TAB':
    case 'ADD_SESSION_BLOCK':
    case 'REMOVE_SESSION_BLOCK':
    case 'REDIRECT_INTERSTITIAL':
    case 'RELEASE_CONTAINMENT':
      return 'CONFIRM';
  }
}

function classificationFromAgentState(
  state: AgentRiskState,
): Pick<EventSecurityReport, 'threatLevel' | 'risk'> {
  switch (state) {
    case 'HIGH_RISK':
    case 'CONTAINED':
      return { threatLevel: 'malicious', risk: 'HIGH' };

    case 'SUSPICIOUS':
      return { threatLevel: 'suspicious', risk: 'MEDIUM' };

    case 'UNCERTAIN':
    case 'OBSERVING':
      return {
        threatLevel: 'insufficient_evidence',
        risk: 'UNKNOWN',
      };

    case 'LOW_RISK':
    case 'USER_OVERRIDDEN':
      return { threatLevel: 'benign', risk: 'LOW' };

    case 'ENDED':
      return {
        threatLevel: 'insufficient_evidence',
        risk: 'UNKNOWN',
      };
  }
}

export interface EventAssessmentResult {
  report: EventSecurityReport;
  riskDecision: RiskDecision;
  riskSignals: RiskSignalSet;
}

export function assessEventStreamDetailed(
  events: SensitiveEvent[],
  model: EventModelArtifact | null,
  incomplete = false,
): EventAssessmentResult | null {
  if (!events.length) return null;

  const start = performance.now();
  const features = buildEventRepresentations(events);
  const contextual = buildContextFeatures(events, incomplete);
  const latest = events[events.length - 1];
  const top = [...events]
    .reverse()
    .find(event => event.frame_id === 0 && event.frame_origin);
  const identity = identifyOrigin(top?.frame_origin ?? null);

  const forms = new Map<string, FormDestination>();

  for (const event of events) {
    if (!event.form_id || !event.document_id) continue;

    const key =
      `${event.session_id}:${event.tab_id}:${event.document_id}:` +
      `${event.frame_id}:${event.form_id}`;

    const form = forms.get(key) ?? {
      document_id: event.document_id,
      frame_id: event.frame_id,
      form_id: event.form_id,
      page_origin: event.frame_origin,
      target_origin: null,
      status: 'UNKNOWN' as const,
      sensitive_types: [],
      event_seq: event.event_seq,
    };

    if (
      event.event_type === 'FIELD_DISCOVERED' &&
      event.sensitive_type &&
      !['UNKNOWN', 'NON_SENSITIVE'].includes(event.sensitive_type) &&
      !form.sensitive_types.includes(event.sensitive_type)
    ) {
      form.sensitive_types.push(event.sensitive_type);
    }

    if (
      [
        'FORM_TARGET_OBSERVED',
        'FORM_TARGET_CHANGED',
        'FORM_SUBMISSION_ATTEMPT',
      ].includes(event.event_type)
    ) {
      form.target_origin = event.target_origin;
      form.event_seq = event.event_seq;
      form.status = destinationStatus(
        event.frame_origin,
        event.target_origin,
      );
    }

    forms.set(key, form);
  }

  const form_destinations = [...forms.values()].slice(0, 200);

  let score: number | null = null;

  const parameters =
    model?.representation === 'contextual-flat'
      ? contextual.vector
      : model?.representation === 'flat'
        ? features.flat_vector
        : features.relationship_vector;

  try {
    if (model) score = inferEventModel(model, parameters);
  } catch {
    // Explicit unknown; contextual evidence remains active.
  }

  const contradictions = [...contextual.contradictions];

  if (
    identity.status === 'POSSIBLE_IMPERSONATION' &&
    form_destinations.some(form => form.sensitive_types.length > 0)
  ) {
    contradictions.push('POSSIBLE_IDENTITY_ORIGIN_MISMATCH');
  }

  const hasCoverage =
    contextual.evidence_completeness.level !== 'LOW';

  const provenance =
    score !== null &&
    ['CONTROLLED', 'SYNTHETIC', 'REAL', 'ARCHIVED', 'MIXED']
      .includes(model!.provenance)
      ? model!.provenance as EventSecurityReport['model_provenance']
      : 'UNAVAILABLE';

  /*
   * Reputation is intentionally UNAVAILABLE here during Task 2.
   * Task 3 wires the existing OpenPhish protection layer into this
   * provider-neutral signal contract.
   */
  const riskSignals: RiskSignalSet = {
    schemaVersion: 'risk-signals-1',
    documentId: top?.document_id ?? null,
    eventSeq: latest.event_seq,

    reputation: {
      status: 'UNAVAILABLE',
      source: null,
    },

    identity: {
      status: identity.status,
    },

    context: {
      contradictions,
      positiveEvidence: contextual.positive_evidence,
      completeness: mapCompleteness(
        contextual.evidence_completeness.level,
      ),
    },

    model: {
      score,
      calibrated:
        score !== null &&
        model?.calibrated === true,
      modelId:
        score !== null
          ? model?.model_id ?? null
          : null,
      provenance,
    },

    collection: {
      incomplete,
      /*
       * assessEventStream currently receives a boolean loss signal.
       * The exact dropped count remains in recorder state and is wired
       * into the richer agent state in the later orchestration task.
       */
      droppedEvents: 0,
    },
  };

  const riskDecision = fuseRiskSignals(riskSignals);
  const classification =
    classificationFromAgentState(riskDecision.state);

  /*
   * Keep the persisted legacy reason vocabulary unchanged during Task 2.
   * The richer RiskDecision reasons stay inside the new fusion layer
   * until the backend schema is intentionally versioned.
   */
  const decision_reasons = [
    'LOCAL_CONTEXT_ASSESSMENT',
    ...contradictions,
    ...contextual.positive_evidence,
  ];

  if (score === null) {
    decision_reasons.push('MODEL_UNAVAILABLE');
  } else {
    if (score >= 0.7 && contradictions.length > 0) {
      decision_reasons.push('MODEL_SUPPORTS_CONCERN');
    } else if (
      score < 0.3 &&
      contradictions.length === 0
    ) {
      decision_reasons.push('MODEL_SUPPORTS_LOW_RISK');
    } else if (
      (score >= 0.7 && contradictions.length === 0) ||
      (score < 0.3 && contradictions.length > 0)
    ) {
      decision_reasons.push('MODEL_DISAGREES_WITH_CONTEXT');
    }

    if (
      provenance === 'CONTROLLED' ||
      provenance === 'SYNTHETIC' ||
      provenance === 'MIXED'
    ) {
      decision_reasons.push('MODEL_ADVISORY_ONLY');
    }
  }

  if (!hasCoverage) {
    decision_reasons.push('INSUFFICIENT_CONTEXT');
  }

  if (incomplete) {
    decision_reasons.push('COLLECTION_INCOMPLETE');
  }

  const unknowns: EventSecurityReport['unknowns'] = [
    'VALUE_TRANSMISSION_UNKNOWN',
    'SERVER_BEHAVIOR_NOT_OBSERVABLE',
    'IDENTITY_UNKNOWN',
    'PROGRAMMATIC_SUBMISSION_NOT_COVERED',
  ];

  if (score === null || !model!.calibrated) {
    unknowns.push('MODEL_UNCALIBRATED');
  }

  if (incomplete) {
    unknowns.push('COLLECTION_INCOMPLETE');
  }

  const report: EventSecurityReport = {
    schema_version: 'event-report-1',
    analysis_version: 'event-analysis-1',
    policy_version: 'evidence-policy-1',

    session_id: latest.session_id,
    tab_id: latest.tab_id,
    document_id: top?.document_id ?? null,
    event_seq: latest.event_seq,
    timestamp_ms: Date.now(),

    destinations: [
      ...new Set(
        events
          .flatMap(event => [
            event.target_origin,
            event.destination_origin,
          ])
          .filter(
            (origin): origin is string => !!origin,
          ),
      ),
    ].slice(0, 100),

    identity,
    form_destinations,

    decision_source: 'LOCAL_ML_AGENT',
    agent_version: 'local-context-agent-1',

    decision_reasons,

    model_contributions:
      score !== null
        ? parameters.map(
            (value, index) =>
              (
                (value - model!.mean[index]) /
                model!.scale[index]
              ) * model!.coefficients[index],
          )
        : [],

    agent_roundtrip_ms: null,

    context_feature_version: contextual.version,
    contextual_parameters: contextual.vector,
    purpose: contextual.purpose,
    positive_evidence: contextual.positive_evidence,
    contradictions,
    evidence_completeness:
      contextual.evidence_completeness,

    page_origin: top?.frame_origin ?? null,
    threatLevel: classification.threatLevel,
    risk: classification.risk,

    confidence:
      incomplete ||
      contextual.evidence_completeness.level !== 'SUFFICIENT'
        ? 'LOW'
        : 'MEDIUM',

    confidence_kind:
      'uncalibrated_evidence_coverage',

    action:
      legacyActionFromRiskDecision(riskDecision),

    outcome:
      events.some(
        event =>
          event.event_type === 'SUBMISSION_PREVENTED',
      )
        ? 'SUBMIT_EVENT_CANCELLED'
        : events.some(
              event =>
                event.event_type === 'SUBMISSION_CONFIRMED',
            )
          ? 'USER_CONFIRMED'
          : 'DECISION_ONLY',

    requestedDataTypes: [
      ...new Set(
        events
          .filter(
            event =>
              event.event_type === 'FIELD_DISCOVERED',
          )
          .map(event => event.sensitive_type)
          .filter(
            (type): type is SensitiveType =>
              !!type &&
              !['UNKNOWN', 'NON_SENSITIVE'].includes(type),
          ),
      ),
    ],

    evidence: features.support,

    model_id:
      score !== null
        ? model!.model_id
        : 'unavailable',

    model_score: score,

    model_sha256:
      score !== null
        ? model!.artifact_sha256 ?? null
        : null,

    model_provenance: provenance,

    model_calibrated:
      score !== null &&
      model!.calibrated === true,

    unknowns,

    flat_parameters: features.flat_vector,
    relationship_parameters:
      features.relationship_vector,

    analysis_latency_ms:
      performance.now() - start,
  };

  return { report, riskDecision, riskSignals };
}

export function assessEventStream(
  events: SensitiveEvent[],
  model: EventModelArtifact | null,
  incomplete = false,
): EventSecurityReport | null {
  return assessEventStreamDetailed(events, model, incomplete)?.report ?? null;
}

export interface AssessmentContext {
  modelResult: ModelResult;
  evidence: EvidenceCollection;
  features: FeatureVector;
}

/**
 * Legacy snapshot-score mapping retained only for compatibility helpers.
 */
export function scoreToThreatLevel(
  score: number,
): ThreatLevel {
  if (
    typeof score !== "number" ||
    isNaN(score) ||
    score < 0
  ) {
    return "insufficient_evidence";
  }

  if (score < 0.3) return "benign";
  if (score < 0.7) return "suspicious";

  return "malicious";
}

/**
 * Legacy snapshot confidence helper.
 *
 * This is not a calibrated threat probability.
 */
export function calculateConfidence(
  context: AssessmentContext,
): number {
  const {
    modelResult,
    features,
    evidence,
  } = context;

  let confidence = 0.5;

  if (
    modelResult.rawScore < 0.2 ||
    modelResult.rawScore > 0.8
  ) {
    confidence += 0.2;
  }

  const signalCount =
    (features.has_password_field ? 1 : 0) +
    (features.has_otp_field ? 1 : 0) +
    (features.cross_domain_form ? 1 : 0);

  confidence += signalCount * 0.1;

  if (features.form_count > 1) {
    confidence += 0.1;
  }

  if (features.input_count > 3) {
    confidence += 0.1;
  }

  if (
    evidence.forms.length === 0 &&
    evidence.scripts.length === 0 &&
    evidence.requests.length === 0
  ) {
    confidence -= 0.2;
  }

  return Math.max(
    0.1,
    Math.min(1.0, confidence),
  );
}

/**
 * Generate compatibility reason codes for snapshot telemetry.
 */
export function generateReasons(
  context: AssessmentContext,
): string[] {
  const reasons: string[] = [];
  const {
    modelResult,
    features,
    evidence,
  } = context;

  if (modelResult.rawScore > 0.8) {
    reasons.push("HIGH_ML_SCORE");
  } else if (modelResult.rawScore > 0.6) {
    reasons.push("ELEVATED_ML_SCORE");
  } else if (modelResult.rawScore < 0.2) {
    reasons.push("LOW_ML_SCORE");
  }

  if (features.has_password_field) {
    reasons.push("PASSWORD_FIELD_DETECTED");
  }

  if (features.has_otp_field) {
    reasons.push("OTP_FIELD_DETECTED");
  }

  if (features.has_card_field) {
    reasons.push("PAYMENT_CARD_FIELD_DETECTED");
  }

  if (features.has_cvv_field) {
    reasons.push("CVV_FIELD_DETECTED");
  }

  if (features.has_identity_field) {
    reasons.push("IDENTITY_DOCUMENT_FIELD_DETECTED");
  }

  if (features.has_bank_field) {
    reasons.push("BANK_ACCOUNT_FIELD_DETECTED");
  }

  if (features.cross_domain_form) {
    reasons.push("CROSS_DOMAIN_FORM");
  }

  if (features.form_count > 2) {
    reasons.push(
      `MULTIPLE_FORMS_${features.form_count}`,
    );
  }

  if (features.input_count > 5) {
    reasons.push(
      `MANY_INPUT_FIELDS_${features.input_count}`,
    );
  }

  if (evidence.scripts.length > 3) {
    reasons.push(
      `MULTIPLE_SCRIPTS_${evidence.scripts.length}`,
    );
  }

  const crossDomainScripts =
    evidence.scripts.filter(
      script => script.isCrossDomain,
    );

  if (crossDomainScripts.length > 0) {
    reasons.push(
      `CROSS_DOMAIN_SCRIPTS_${crossDomainScripts.length}`,
    );
  }

  const events = extractObservedEvents(evidence);
  const comparison =
    compareBehavior(evidence, events);

  if (
    comparison.matchedProfile &&
    comparison.reasons &&
    comparison.reasons.length > 0
  ) {
    comparison.reasons.forEach(reason => {
      if (!reasons.includes(reason)) {
        reasons.push(reason);
      }
    });
  }

  return reasons.length > 0
    ? reasons
    : ["INSUFFICIENT_DATA"];
}

/**
 * Compatibility snapshot assessment.
 *
 * The uncalibrated snapshot model cannot authorize a threat verdict by score
 * alone. The event-based contextual path above owns current browser decisions.
 */
export function assessThreat(
  context: AssessmentContext,
): ThreatAssessment {
  const confidence =
    calculateConfidence(context);

  const reasons =
    generateReasons(context);

  const identity =
    identifyOrigin(context.evidence.page.url);

  const sensitive =
    context.features.has_password_field ||
    context.features.has_otp_field ||
    context.features.has_card_field;

  const downgrade =
    context.evidence.page.isHTTPS &&
    context.evidence.forms.some(
      form => form.action.startsWith('http:'),
    );

  const threatLevel: ThreatLevel =
    sensitive &&
    (
      identity.status ===
        'POSSIBLE_IMPERSONATION' ||
      downgrade
    )
      ? 'suspicious'
      : 'insufficient_evidence';

  return {
    threatLevel,
    score: context.modelResult.rawScore,
    confidence,
    evaluatedAt: Date.now(),
    reasons,
  };
}
