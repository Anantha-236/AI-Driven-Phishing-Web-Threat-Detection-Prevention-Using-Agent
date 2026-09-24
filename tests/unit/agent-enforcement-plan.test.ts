import { describe, expect, it } from 'vitest';
import type { EventSecurityReport } from '../../browser-extension/src/core/assessment';
import { createAgentEnforcementPlan } from '../../browser-extension/src/core/agent/enforcement-plan';
import type { RiskDecision } from '../../browser-extension/src/core/agent/types';

function report(forms: EventSecurityReport['form_destinations'] = []): EventSecurityReport {
  return {
    form_destinations: forms,
  } as EventSecurityReport;
}

function decision(
  action: RiskDecision['action'],
  automaticBlockAuthorized = false,
): RiskDecision {
  return {
    schemaVersion: 'risk-decision-1',
    state: action === 'CONTAIN_TAB' ? 'HIGH_RISK' : action === 'WARN' ? 'SUSPICIOUS' : 'LOW_RISK',
    action,
    reasons: [],
    automaticBlockAuthorized,
  };
}

describe('agent enforcement plan', () => {
  it('selects only the most recent sensitive containable destination', () => {
    const plan = createAgentEnforcementPlan(report([
      {
        document_id: 'doc', frame_id: 0, form_id: 'f-1', page_origin: 'https://page.test',
        target_origin: 'https://first.test', status: 'UNVERIFIED_CROSS_ORIGIN', sensitive_types: ['PASSWORD'], event_seq: 4,
      },
      {
        document_id: 'doc', frame_id: 0, form_id: 'f-2', page_origin: 'https://page.test',
        target_origin: 'https://latest.test', status: 'HTTPS_DOWNGRADE', sensitive_types: ['OTP'], event_seq: 9,
      },
      {
        document_id: 'doc', frame_id: 0, form_id: 'f-3', page_origin: 'https://page.test',
        target_origin: 'https://same.test', status: 'SAME_ORIGIN', sensitive_types: ['PASSWORD'], event_seq: 99,
      },
    ]), decision('CONTAIN_TAB', true));

    expect(plan).toEqual({
      requestedAction: 'CONTAIN_TAB',
      contentAction: 'CONFIRM',
      containmentOrigin: 'https://latest.test',
      releaseContainment: false,
    });
  });

  it('never installs containment when automatic blocking is not authorized', () => {
    const plan = createAgentEnforcementPlan(report([{
      document_id: 'doc', frame_id: 0, form_id: 'f-1', page_origin: 'https://page.test',
      target_origin: 'https://sink.test', status: 'UNVERIFIED_CROSS_ORIGIN', sensitive_types: ['PASSWORD'], event_seq: 1,
    }]), decision('CONTAIN_TAB', false));

    expect(plan.containmentOrigin).toBeNull();
    expect(plan.contentAction).toBe('CONFIRM');
  });

  it('maps warning and allow decisions to the existing content-script contract', () => {
    expect(createAgentEnforcementPlan(report(), decision('WARN'))).toMatchObject({
      contentAction: 'WARN', releaseContainment: false,
    });
    expect(createAgentEnforcementPlan(report(), decision('ALLOW'))).toMatchObject({
      contentAction: 'ALLOW', releaseContainment: true,
    });
  });

  it('does not pretend an interstitial exists before that action is implemented', () => {
    expect(createAgentEnforcementPlan(report(), decision('REDIRECT_INTERSTITIAL'))).toEqual({
      requestedAction: 'REDIRECT_INTERSTITIAL',
      contentAction: 'CONFIRM',
      containmentOrigin: null,
      releaseContainment: false,
    });
  });
});
