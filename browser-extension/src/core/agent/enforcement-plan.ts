import type { EventSecurityReport } from '../assessment';
import type { AgentAction, RiskDecision } from './types';

export interface AgentEnforcementPlan {
  requestedAction: AgentAction;
  contentAction: 'ALLOW' | 'WARN' | 'CONFIRM';
  containmentOrigin: string | null;
  releaseContainment: boolean;
}

function latestContainableOrigin(report: EventSecurityReport): string | null {
  const candidates = report.form_destinations
    .filter(form =>
      form.sensitive_types.length > 0 &&
      !!form.target_origin &&
      ['HTTPS_DOWNGRADE', 'UNVERIFIED_CROSS_ORIGIN'].includes(form.status)
    )
    .sort((a, b) => b.event_seq - a.event_seq);

  return candidates[0]?.target_origin ?? null;
}

export function createAgentEnforcementPlan(
  report: EventSecurityReport,
  decision: RiskDecision,
): AgentEnforcementPlan {
  switch (decision.action) {
    case 'ALLOW':
      return {
        requestedAction: decision.action,
        contentAction: 'ALLOW',
        containmentOrigin: null,
        releaseContainment: true,
      };

    case 'WARN':
      return {
        requestedAction: decision.action,
        contentAction: 'WARN',
        containmentOrigin: null,
        releaseContainment: false,
      };

    case 'CONFIRM':
    case 'SHIELD_SENSITIVE_ACTION':
      return {
        requestedAction: decision.action,
        contentAction: 'CONFIRM',
        containmentOrigin: null,
        releaseContainment: false,
      };

    case 'CONTAIN_TAB':
    case 'ADD_SESSION_BLOCK':
      return {
        requestedAction: decision.action,
        contentAction: 'CONFIRM',
        containmentOrigin: decision.automaticBlockAuthorized
          ? latestContainableOrigin(report)
          : null,
        releaseContainment: false,
      };

    case 'REMOVE_SESSION_BLOCK':
    case 'RELEASE_CONTAINMENT':
      return {
        requestedAction: decision.action,
        contentAction: 'ALLOW',
        containmentOrigin: null,
        releaseContainment: true,
      };

    case 'REDIRECT_INTERSTITIAL':
      // Interstitial navigation is deliberately deferred. Until a dedicated,
      // tested extension page exists, keep the page shielded instead of
      // pretending that a redirect occurred.
      return {
        requestedAction: decision.action,
        contentAction: 'CONFIRM',
        containmentOrigin: null,
        releaseContainment: false,
      };
  }
}
