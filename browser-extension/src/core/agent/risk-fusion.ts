import type { RiskDecision, RiskSignalSet } from './types';

const CORROBORATED_CONTRADICTIONS = new Set([
  'INTERACTED_SENSITIVE_SUBMISSION_REDIRECTED',
]);

function baseReasons(signals: RiskSignalSet): string[] {
  const reasons = [
    ...signals.context.contradictions,
    ...signals.context.positiveEvidence,
  ];

  if (signals.reputation.status === 'KNOWN_MALICIOUS') {
    reasons.unshift('KNOWN_MALICIOUS_REPUTATION');
  } else if (signals.reputation.status === 'UNAVAILABLE') {
    reasons.push('REPUTATION_UNAVAILABLE');
  }

  if (signals.collection.incomplete || signals.collection.droppedEvents > 0) {
    reasons.push('COLLECTION_INCOMPLETE');
  }

  if (signals.model.score === null) {
    reasons.push('MODEL_UNAVAILABLE');
  } else if (!signals.model.calibrated) {
    reasons.push('MODEL_ADVISORY_ONLY');
  }

  return [...new Set(reasons)];
}

export function fuseRiskSignals(signals: RiskSignalSet): RiskDecision {
  const reasons = baseReasons(signals);

  if (signals.reputation.status === 'KNOWN_MALICIOUS') {
    return {
      schemaVersion: 'risk-decision-1',
      state: 'HIGH_RISK',
      action: 'CONTAIN_TAB',
      reasons,
      automaticBlockAuthorized: true,
    };
  }

  const corroborated = signals.context.contradictions.some(code =>
    CORROBORATED_CONTRADICTIONS.has(code)
  );

  if (
    corroborated &&
    signals.context.completeness === 'SUFFICIENT' &&
    !signals.collection.incomplete
  ) {
    return {
      schemaVersion: 'risk-decision-1',
      state: 'HIGH_RISK',
      action: 'CONTAIN_TAB',
      reasons,
      automaticBlockAuthorized: true,
    };
  }

  if (
    signals.collection.incomplete ||
    signals.context.completeness === 'LOW'
  ) {
    return {
      schemaVersion: 'risk-decision-1',
      state: 'UNCERTAIN',
      action: 'ALLOW',
      reasons,
      automaticBlockAuthorized: false,
    };
  }

  if (signals.context.contradictions.length > 0) {
    return {
      schemaVersion: 'risk-decision-1',
      state: 'SUSPICIOUS',
      action: 'WARN',
      reasons,
      automaticBlockAuthorized: false,
    };
  }

  return {
    schemaVersion: 'risk-decision-1',
    state: 'LOW_RISK',
    action: 'ALLOW',
    reasons,
    automaticBlockAuthorized: false,
  };
}
