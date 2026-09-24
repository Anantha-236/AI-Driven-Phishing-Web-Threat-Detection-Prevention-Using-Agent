import { describe, expect, it } from 'vitest';
import {
  isLiveAgentState,
  transitionAgent,
} from '../../browser-extension/src/core/agent/state-machine';

describe('bounded agent state machine', () => {
  it('allows OBSERVING -> HIGH_RISK -> CONTAINED', () => {
    expect(transitionAgent('OBSERVING', 'HIGH_RISK')).toMatchObject({
      accepted: true,
      from: 'OBSERVING',
      requested: 'HIGH_RISK',
      to: 'HIGH_RISK',
    });

    expect(transitionAgent('HIGH_RISK', 'CONTAINED')).toMatchObject({
      accepted: true,
      from: 'HIGH_RISK',
      requested: 'CONTAINED',
      to: 'CONTAINED',
    });
  });

  it('rejects CONTAINED -> OBSERVING because release must be explicit', () => {
    expect(transitionAgent('CONTAINED', 'OBSERVING')).toMatchObject({
      accepted: false,
      from: 'CONTAINED',
      requested: 'OBSERVING',
      to: 'CONTAINED',
    });
  });

  it('allows every live state to end', () => {
    const states = [
      'OBSERVING',
      'LOW_RISK',
      'UNCERTAIN',
      'SUSPICIOUS',
      'HIGH_RISK',
      'CONTAINED',
      'USER_OVERRIDDEN',
    ] as const;

    for (const state of states) {
      expect(isLiveAgentState(state)).toBe(true);
      expect(transitionAgent(state, 'ENDED')).toMatchObject({
        accepted: true,
        from: state,
        requested: 'ENDED',
        to: 'ENDED',
      });
    }

    expect(isLiveAgentState('ENDED')).toBe(false);
  });
});
