export type AgentRiskState =
  | 'OBSERVING'
  | 'LOW_RISK'
  | 'UNCERTAIN'
  | 'SUSPICIOUS'
  | 'HIGH_RISK'
  | 'CONTAINED'
  | 'USER_OVERRIDDEN'
  | 'ENDED';

export type AgentAction =
  | 'ALLOW'
  | 'WARN'
  | 'CONFIRM'
  | 'SHIELD_SENSITIVE_ACTION'
  | 'CONTAIN_TAB'
  | 'ADD_SESSION_BLOCK'
  | 'REMOVE_SESSION_BLOCK'
  | 'REDIRECT_INTERSTITIAL'
  | 'RELEASE_CONTAINMENT';

export type EnforcementOutcome =
  | 'DECISION_ONLY'
  | 'WARNING_DISPLAYED'
  | 'SUBMIT_EVENT_CANCELLED'
  | 'SESSION_RULE_INSTALLED'
  | 'SESSION_RULE_REMOVED'
  | 'TAB_REDIRECTED_TO_INTERSTITIAL'
  | 'USER_CONFIRMED'
  | 'USER_OVERRIDE_APPLIED'
  | 'ENFORCEMENT_FAILED';

export interface RiskSignalSet {
  schemaVersion: 'risk-signals-1';
  documentId: string | null;
  eventSeq: number;

  reputation: {
    status: 'KNOWN_MALICIOUS' | 'NO_MATCH' | 'UNAVAILABLE';
    source: string | null;
  };

  identity: {
    status: 'KNOWN_LOGIN_ORIGIN' | 'POSSIBLE_IMPERSONATION' | 'UNKNOWN';
  };

  context: {
    contradictions: string[];
    positiveEvidence: string[];
    completeness: 'SUFFICIENT' | 'MEDIUM' | 'LOW';
  };

  model: {
    score: number | null;
    calibrated: boolean;
    modelId: string | null;
    provenance: string;
  };

  collection: {
    incomplete: boolean;
    droppedEvents: number;
  };
}

export interface RiskDecision {
  schemaVersion: 'risk-decision-1';
  state: AgentRiskState;
  action: AgentAction;
  reasons: string[];
  automaticBlockAuthorized: boolean;
}

export interface AgentTransition {
  from: AgentRiskState;
  requested: AgentRiskState;
  to: AgentRiskState;
  accepted: boolean;
}
