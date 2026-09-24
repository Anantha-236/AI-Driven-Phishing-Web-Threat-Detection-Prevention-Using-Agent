/**
 * CAPSTONE-1 Threat Assessment Module
 *
 * Converts ML model score + evidence context + declared service comparison into explainable threat assessments.
 *
 * Score mapping:
 *  - 0.0 to 0.3  → BENIGN (low risk)
 *  - 0.3 to 0.7  → SUSPICIOUS (medium risk, warrants user attention)
 *  - 0.7 to 1.0  → MALICIOUS (high risk, enforcement recommended)
 *
 * Assessment considers:
 *  - ML model score (primary signal)
 *  - Evidence structure & clarity
 *  - Declared service profile comparator
 *  - Explainable reason codes
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
import { buildContextFeatures, buildEventRepresentations, SensitiveEvent, RelationshipEvidence, SensitiveType, PurposeEvidence, EvidenceCompleteness } from './tsfeg';
import { EventModelArtifact, inferEventModel } from './service-worker-onnx-adapter';
import { identifyOrigin, destinationStatus, OriginIdentity } from './profiles/service-profiles';

export interface FormDestination {
  document_id: string | null; frame_id: number; form_id: string;
  page_origin: string | null; target_origin: string | null;
  status: ReturnType<typeof destinationStatus>; sensitive_types: SensitiveType[]; event_seq: number;
}

export interface EventSecurityReport {
  schema_version: 'event-report-1'; analysis_version: 'event-analysis-1'; policy_version: 'evidence-policy-1';
  session_id: string; tab_id: number; document_id: string | null; event_seq: number; timestamp_ms: number;
  destinations: string[]; page_origin: string | null; threatLevel: ThreatLevel; risk: 'LOW' | 'MEDIUM' | 'HIGH' | 'UNKNOWN';
  confidence: 'LOW' | 'MEDIUM'; confidence_kind: 'uncalibrated_evidence_coverage';
  action: 'ALLOW' | 'WARN' | 'CONFIRM'; outcome: 'DECISION_ONLY' | 'WARNING_DISPLAYED' | 'SUBMIT_EVENT_CANCELLED' | 'USER_CONFIRMED';
  requestedDataTypes: SensitiveType[]; evidence: RelationshipEvidence[];
  model_sha256: string | null; model_id: string; model_score: number | null; model_provenance: 'CONTROLLED' | 'SYNTHETIC' | 'REAL' | 'ARCHIVED' | 'MIXED' | 'UNAVAILABLE';
  model_calibrated: boolean;
  unknowns: Array<'VALUE_TRANSMISSION_UNKNOWN' | 'SERVER_BEHAVIOR_NOT_OBSERVABLE' | 'IDENTITY_UNKNOWN' | 'MODEL_UNCALIBRATED' | 'COLLECTION_INCOMPLETE' | 'PROGRAMMATIC_SUBMISSION_NOT_COVERED'>;
  flat_parameters: number[]; relationship_parameters: number[]; analysis_latency_ms: number;
  context_feature_version: 'context-features-1'; contextual_parameters: number[];
  purpose: PurposeEvidence; positive_evidence: string[]; contradictions: string[]; evidence_completeness: EvidenceCompleteness;
  identity: OriginIdentity;
  form_destinations: FormDestination[];
  decision_source: 'LOCAL_ML_AGENT' | 'BACKEND_ML_AGENT' | 'LOCAL_FALLBACK';
  agent_version: 'local-context-agent-1' | 'backend-ml-agent-1' | null;
  decision_reasons: string[];
  model_contributions: number[];
  agent_roundtrip_ms: number | null;
}
export function assessEventStream(events: SensitiveEvent[], model: EventModelArtifact | null, incomplete = false): EventSecurityReport | null {
  if (!events.length) return null;
  const start = performance.now();
  const features = buildEventRepresentations(events);
  const contextual = buildContextFeatures(events, incomplete);
  const latest = events[events.length - 1];
  const top = [...events].reverse().find(e => e.frame_id === 0 && e.frame_origin);
  const identity = identifyOrigin(top?.frame_origin ?? null);
  const forms = new Map<string, FormDestination>();
  for (const ev of events) {
    if (!ev.form_id || !ev.document_id) continue;
    const key = `${ev.session_id}:${ev.tab_id}:${ev.document_id}:${ev.frame_id}:${ev.form_id}`;
    const form = forms.get(key) ?? { document_id: ev.document_id, frame_id: ev.frame_id, form_id: ev.form_id,
      page_origin: ev.frame_origin, target_origin: null, status: 'UNKNOWN', sensitive_types: [], event_seq: ev.event_seq };
    if (ev.event_type === 'FIELD_DISCOVERED' && ev.sensitive_type && !['UNKNOWN', 'NON_SENSITIVE'].includes(ev.sensitive_type) && !form.sensitive_types.includes(ev.sensitive_type)) form.sensitive_types.push(ev.sensitive_type);
    if (['FORM_TARGET_OBSERVED', 'FORM_TARGET_CHANGED', 'FORM_SUBMISSION_ATTEMPT'].includes(ev.event_type)) {
      form.target_origin = ev.target_origin; form.event_seq = ev.event_seq;
      form.status = destinationStatus(ev.frame_origin, ev.target_origin);
    }
    forms.set(key, form);
  }
  const form_destinations = [...forms.values()].slice(0, 200);
  let score: number | null = null;
  const parameters = model?.representation === 'contextual-flat' ? contextual.vector : model?.representation === 'flat' ? features.flat_vector : features.relationship_vector;
  try { if (model) score = inferEventModel(model, parameters); } catch { /* Explicit unknown; contextual evidence remains active. */ }
  const contradictions = [...contextual.contradictions];
  if (identity.status === 'POSSIBLE_IMPERSONATION' && form_destinations.some(f => f.sensitive_types.length > 0)) contradictions.push('POSSIBLE_IDENTITY_ORIGIN_MISMATCH');
  const concerning = contradictions.length > 0;
  // Same-form observations support this gate; nearby analytics, password->OTP and cross-origin alone never do.
  const corroborated = contradictions.includes('INTERACTED_SENSITIVE_SUBMISSION_REDIRECTED');
  const hasCoverage = contextual.evidence_completeness.level !== 'LOW';
  const provenance = score !== null && ['CONTROLLED', 'SYNTHETIC', 'REAL', 'ARCHIVED', 'MIXED'].includes(model!.provenance)
    ? model!.provenance as EventSecurityReport['model_provenance'] : 'UNAVAILABLE';
  const decision_reasons = ['LOCAL_CONTEXT_ASSESSMENT', ...contradictions, ...contextual.positive_evidence];
  if (score === null) decision_reasons.push('MODEL_UNAVAILABLE');
  else {
    if (score >= 0.7 && concerning) decision_reasons.push('MODEL_SUPPORTS_CONCERN');
    else if (score < 0.3 && !concerning) decision_reasons.push('MODEL_SUPPORTS_LOW_RISK');
    else if (score >= 0.7 && !concerning || score < 0.3 && concerning) decision_reasons.push('MODEL_DISAGREES_WITH_CONTEXT');
    if (provenance === 'CONTROLLED' || provenance === 'SYNTHETIC' || provenance === 'MIXED') decision_reasons.push('MODEL_ADVISORY_ONLY');
  }
  if (!hasCoverage) decision_reasons.push('INSUFFICIENT_CONTEXT');
  if (incomplete) decision_reasons.push('COLLECTION_INCOMPLETE');
  const unknowns: EventSecurityReport['unknowns'] = ['VALUE_TRANSMISSION_UNKNOWN', 'SERVER_BEHAVIOR_NOT_OBSERVABLE', 'IDENTITY_UNKNOWN', 'PROGRAMMATIC_SUBMISSION_NOT_COVERED'];
  if (score === null || !model!.calibrated) unknowns.push('MODEL_UNCALIBRATED');
  if (incomplete) unknowns.push('COLLECTION_INCOMPLETE');
  return { schema_version: 'event-report-1', analysis_version: 'event-analysis-1', policy_version: 'evidence-policy-1',
    session_id: latest.session_id, tab_id: latest.tab_id, document_id: top?.document_id ?? null, event_seq: latest.event_seq, timestamp_ms: Date.now(),
    destinations: [...new Set(events.flatMap(e => [e.target_origin, e.destination_origin]).filter((o): o is string => !!o))].slice(0, 100),
    identity, form_destinations, decision_source: 'LOCAL_ML_AGENT', agent_version: 'local-context-agent-1',
    decision_reasons, model_contributions: score !== null ? parameters.map((value, index) => (value - model!.mean[index]) / model!.scale[index] * model!.coefficients[index]) : [], agent_roundtrip_ms: null,
    context_feature_version: contextual.version, contextual_parameters: contextual.vector, purpose: contextual.purpose,
    positive_evidence: contextual.positive_evidence, contradictions, evidence_completeness: contextual.evidence_completeness,
    page_origin: top?.frame_origin ?? null, threatLevel: corroborated ? 'malicious' : concerning ? 'suspicious' : hasCoverage && !incomplete ? 'benign' : 'insufficient_evidence',
    risk: corroborated ? 'HIGH' : concerning ? 'MEDIUM' : !hasCoverage || incomplete ? 'UNKNOWN' : 'LOW',
    confidence: incomplete || contextual.evidence_completeness.level !== 'SUFFICIENT' ? 'LOW' : 'MEDIUM', confidence_kind: 'uncalibrated_evidence_coverage',
    action: corroborated ? 'CONFIRM' : concerning ? 'WARN' : 'ALLOW', outcome: events.some(e => e.event_type === 'SUBMISSION_PREVENTED') ? 'SUBMIT_EVENT_CANCELLED' : events.some(e => e.event_type === 'SUBMISSION_CONFIRMED') ? 'USER_CONFIRMED' : 'DECISION_ONLY',
    requestedDataTypes: [...new Set(events.filter(e => e.event_type === 'FIELD_DISCOVERED').map(e => e.sensitive_type).filter((t): t is SensitiveType => !!t && !['UNKNOWN', 'NON_SENSITIVE'].includes(t)))],
    evidence: features.support, model_id: score !== null ? model!.model_id : 'unavailable', model_score: score,
    model_sha256: score !== null ? model!.artifact_sha256 ?? null : null,
    model_provenance: provenance, model_calibrated: score !== null && model!.calibrated === true, unknowns,
    flat_parameters: features.flat_vector, relationship_parameters: features.relationship_vector,
    analysis_latency_ms: performance.now() - start };
}

export interface AssessmentContext {
  modelResult: ModelResult;
  evidence: EvidenceCollection;
  features: FeatureVector;
}

/**
 * Convert model score to threat level using calibrated thresholds.
 */
export function scoreToThreatLevel(score: number): ThreatLevel {
  if (typeof score !== "number" || isNaN(score) || score < 0) {
    return "insufficient_evidence";
  }
  if (score < 0.3) return "benign";
  if (score < 0.7) return "suspicious";
  return "malicious";
}

/**
 * Determine confidence score based on evidence quality and clarity.
 */
export function calculateConfidence(context: AssessmentContext): number {
  const { modelResult, features, evidence } = context;
  let confidence = 0.5; // baseline

  // Boost confidence for extreme scores
  if (modelResult.rawScore < 0.2 || modelResult.rawScore > 0.8) {
    confidence += 0.2;
  }

  // Boost confidence for multiple evidence signals
  const signalCount =
    (features.has_password_field ? 1 : 0) +
    (features.has_otp_field ? 1 : 0) +
    (features.cross_domain_form ? 1 : 0);

  confidence += signalCount * 0.1; // +0.1 per signal, max +0.3

  // Boost confidence for significant form/input counts
  if (features.form_count > 1) confidence += 0.1;
  if (features.input_count > 3) confidence += 0.1;

  // Reduce confidence if evidence is sparse
  if (
    evidence.forms.length === 0 &&
    evidence.scripts.length === 0 &&
    evidence.requests.length === 0
  ) {
    confidence -= 0.2;
  }

  return Math.max(0.1, Math.min(1.0, confidence));
}

/**
 * Generate human-readable reason codes explaining the assessment.
 */
export function generateReasons(context: AssessmentContext): string[] {
  const reasons: string[] = [];
  const { modelResult, features, evidence } = context;

  // Score-based reasons
  if (modelResult.rawScore > 0.8) {
    reasons.push("HIGH_ML_SCORE");
  } else if (modelResult.rawScore > 0.6) {
    reasons.push("ELEVATED_ML_SCORE");
  } else if (modelResult.rawScore < 0.2) {
    reasons.push("LOW_ML_SCORE");
  }

  // Evidence-based reasons
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
    reasons.push(`MULTIPLE_FORMS_${features.form_count}`);
  }

  if (features.input_count > 5) {
    reasons.push(`MANY_INPUT_FIELDS_${features.input_count}`);
  }

  // Evidence structure reasons
  if (evidence.scripts.length > 3) {
    reasons.push(`MULTIPLE_SCRIPTS_${evidence.scripts.length}`);
  }

  const crossDomainScripts = evidence.scripts.filter((s) => s.isCrossDomain);
  if (crossDomainScripts.length > 0) {
    reasons.push(`CROSS_DOMAIN_SCRIPTS_${crossDomainScripts.length}`);
  }

  // Service behavior comparison reasons
  const events = extractObservedEvents(evidence);
  const comparison = compareBehavior(evidence, events);
  if (comparison.matchedProfile && comparison.reasons && comparison.reasons.length > 0) {
    comparison.reasons.forEach((r) => {
      if (!reasons.includes(r)) {
        reasons.push(r);
      }
    });
  }

  return reasons.length > 0 ? reasons : ["INSUFFICIENT_DATA"];
}

/**
 * Perform comprehensive threat assessment.
 */
export function assessThreat(context: AssessmentContext): ThreatAssessment {
  const confidence = calculateConfidence(context);
  const reasons = generateReasons(context);
  // The compatibility model is uncalibrated; fields or its score alone cannot
  // authorize a threat verdict. Keep snapshots consistent with the event report.
  const identity = identifyOrigin(context.evidence.page.url);
  const sensitive = context.features.has_password_field || context.features.has_otp_field || context.features.has_card_field;
  const downgrade = context.evidence.page.isHTTPS && context.evidence.forms.some(form => form.action.startsWith('http:'));
  const threatLevel: ThreatLevel = sensitive && (identity.status === 'POSSIBLE_IMPERSONATION' || downgrade)
    ? 'suspicious' : 'insufficient_evidence';

  return {
    threatLevel,
    score: context.modelResult.rawScore,
    confidence,
    evaluatedAt: Date.now(),
    reasons,
  };
}
