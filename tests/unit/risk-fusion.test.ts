import { describe, expect, it } from 'vitest';
import { fuseRiskSignals } from '../../browser-extension/src/core/agent/risk-fusion';
import type { RiskSignalSet } from '../../browser-extension/src/core/agent/types';

function signals(overrides: Partial<RiskSignalSet> = {}): RiskSignalSet {
  const base: RiskSignalSet = {
    schemaVersion: 'risk-signals-1',
    documentId: 'a'.repeat(32),
    eventSeq: 1,
    reputation: { status: 'NO_MATCH', source: null },
    identity: { status: 'UNKNOWN' },
    context: {
      contradictions: [],
      positiveEvidence: [],
      completeness: 'SUFFICIENT',
    },
    model: {
      score: null,
      calibrated: false,
      modelId: null,
      provenance: 'UNAVAILABLE',
    },
    collection: {
      incomplete: false,
      droppedEvents: 0,
    },
  };

  return {
    ...base,
    ...overrides,
    reputation: { ...base.reputation, ...(overrides.reputation ?? {}) },
    identity: { ...base.identity, ...(overrides.identity ?? {}) },
    context: { ...base.context, ...(overrides.context ?? {}) },
    model: { ...base.model, ...(overrides.model ?? {}) },
    collection: { ...base.collection, ...(overrides.collection ?? {}) },
  };
}

describe('versioned risk fusion', () => {
  it('authorizes containment for exact known-malicious reputation', () => {
    const decision = fuseRiskSignals(signals({
      reputation: {
        status: 'KNOWN_MALICIOUS',
        source: 'OpenPhish Community',
      },
    }));

    expect(decision).toMatchObject({
      schemaVersion: 'risk-decision-1',
      state: 'HIGH_RISK',
      action: 'CONTAIN_TAB',
      automaticBlockAuthorized: true,
    });
    expect(decision.reasons).toContain('KNOWN_MALICIOUS_REPUTATION');
  });

  it('does not authorize blocking from an uncalibrated model alone', () => {
    const decision = fuseRiskSignals(signals({
      model: {
        score: 0.999,
        calibrated: false,
        modelId: 'controlled-event-lr-1',
        provenance: 'CONTROLLED',
      },
    }));

    expect(decision).toMatchObject({
      state: 'LOW_RISK',
      action: 'ALLOW',
      automaticBlockAuthorized: false,
    });
    expect(decision.reasons).toContain('MODEL_ADVISORY_ONLY');
  });

  it('allows stable unknown SSO without contextual contradiction', () => {
    const decision = fuseRiskSignals(signals({
      identity: { status: 'UNKNOWN' },
      context: {
        contradictions: [],
        positiveEvidence: [
          'AUTHENTICATION_SEQUENCE_CONSISTENT',
          'REPEATED_STABLE_SENSITIVE_TARGET',
        ],
        completeness: 'SUFFICIENT',
      },
    }));

    expect(decision).toMatchObject({
      state: 'LOW_RISK',
      action: 'ALLOW',
      automaticBlockAuthorized: false,
    });
  });

  it('authorizes containment for a corroborated sensitive destination replacement', () => {
    const decision = fuseRiskSignals(signals({
      context: {
        contradictions: ['INTERACTED_SENSITIVE_SUBMISSION_REDIRECTED'],
        positiveEvidence: [],
        completeness: 'SUFFICIENT',
      },
    }));

    expect(decision).toMatchObject({
      state: 'HIGH_RISK',
      action: 'CONTAIN_TAB',
      automaticBlockAuthorized: true,
    });
  });

  it('keeps incomplete evidence uncertain without autonomous blocking', () => {
    const decision = fuseRiskSignals(signals({
      collection: {
        incomplete: true,
        droppedEvents: 4,
      },
    }));

    expect(decision).toMatchObject({
      state: 'UNCERTAIN',
      action: 'ALLOW',
      automaticBlockAuthorized: false,
    });
    expect(decision.reasons).toContain('COLLECTION_INCOMPLETE');
  });

  it('warns on a contextual contradiction that is not yet corroborated', () => {
    const decision = fuseRiskSignals(signals({
      context: {
        contradictions: ['POSSIBLE_IDENTITY_ORIGIN_MISMATCH'],
        positiveEvidence: [],
        completeness: 'SUFFICIENT',
      },
    }));

    expect(decision).toMatchObject({
      state: 'SUSPICIOUS',
      action: 'WARN',
      automaticBlockAuthorized: false,
    });
  });
});
