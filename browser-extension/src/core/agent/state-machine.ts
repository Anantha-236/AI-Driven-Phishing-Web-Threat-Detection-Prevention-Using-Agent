import type { AgentRiskState, AgentTransition } from './types';

const LIVE_STATES: readonly AgentRiskState[] = [
  'OBSERVING',
  'LOW_RISK',
  'UNCERTAIN',
  'SUSPICIOUS',
  'HIGH_RISK',
  'CONTAINED',
  'USER_OVERRIDDEN',
];

const ALLOWED_TRANSITIONS: Readonly<Record<AgentRiskState, readonly AgentRiskState[]>> = {
  OBSERVING: ['LOW_RISK', 'UNCERTAIN', 'SUSPICIOUS', 'HIGH_RISK', 'ENDED'],
  LOW_RISK: ['LOW_RISK', 'UNCERTAIN', 'SUSPICIOUS', 'HIGH_RISK', 'ENDED'],
  UNCERTAIN: ['LOW_RISK', 'UNCERTAIN', 'SUSPICIOUS', 'HIGH_RISK', 'ENDED'],
  SUSPICIOUS: ['LOW_RISK', 'SUSPICIOUS', 'HIGH_RISK', 'CONTAINED', 'ENDED'],
  HIGH_RISK: ['HIGH_RISK', 'CONTAINED', 'ENDED'],
  CONTAINED: ['CONTAINED', 'USER_OVERRIDDEN', 'LOW_RISK', 'ENDED'],
  USER_OVERRIDDEN: ['USER_OVERRIDDEN', 'LOW_RISK', 'SUSPICIOUS', 'HIGH_RISK', 'CONTAINED', 'ENDED'],
  ENDED: ['ENDED'],
};

export function transitionAgent(
  current: AgentRiskState,
  requested: AgentRiskState,
): AgentTransition {
  const allowed = ALLOWED_TRANSITIONS[current];

  if (!allowed.includes(requested)) {
    return {
      from: current,
      requested,
      to: current,
      accepted: false,
    };
  }

  return {
    from: current,
    requested,
    to: requested,
    accepted: true,
  };
}

export function isLiveAgentState(state: AgentRiskState): boolean {
  return LIVE_STATES.includes(state);
}
