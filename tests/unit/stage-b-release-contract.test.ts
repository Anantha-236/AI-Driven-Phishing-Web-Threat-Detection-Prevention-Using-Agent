import { describe, expect, it } from 'vitest';
import { CONTEXT_FEATURES } from '../../browser-extension/src/core/tsfeg';
import {
  positiveProbabilityFromTensor,
  validateStageBReleaseManifest,
} from '../../browser-extension/src/core/stage-b-release-contract';

function manifest() {
  return {
    schema_version: 'stage-b-release-candidate-1',
    status: 'PASS',
    model_id: 'stage-b-test',
    representation: 'contextual-flat',
    feature_version: 'context-features-1',
    feature_names: [...CONTEXT_FEATURES],
    feature_contract_sha256: 'a'.repeat(64),
    extractor_source_sha256: 'b'.repeat(64),
    onnx: {
      filename: 'candidate.onnx',
      sha256: 'c'.repeat(64),
      input_name: 'contextual_features',
      probability_output_name: 'probabilities',
      positive_class_index: 1,
      opsets: { 'ai.onnx': 22 },
    },
    parity: {
      status: 'PASS',
      test_partition_used: false,
      tolerance: 1e-5,
      maximum_absolute_probability_error: 1e-7,
    },
    operating_point: {
      threshold: 0.8,
      primary_fpr_cap: 0.01,
      calibration_deployment_authorized: false,
    },
    release_gate: {
      integration_eligible: false,
      deploy: false,
      autonomous_blocking: false,
      reasons: ['Task 12 pending'],
    },
  };
}

describe('Stage B release contract', () => {
  it('accepts the exact production contextual feature ordering', () => {
    expect(validateStageBReleaseManifest(manifest()).feature_names).toEqual([...CONTEXT_FEATURES]);
  });

  it('rejects reordered or truncated contextual features', () => {
    const reordered = manifest();
    reordered.feature_names = [...CONTEXT_FEATURES].reverse();
    expect(() => validateStageBReleaseManifest(reordered)).toThrow('ordering');
    const truncated = manifest();
    truncated.feature_names = [...CONTEXT_FEATURES].slice(0, -1);
    expect(() => validateStageBReleaseManifest(truncated)).toThrow('ordering');
  });

  it('rejects a Task 11 manifest that claims deployment or failed parity', () => {
    const deploying = manifest();
    deploying.release_gate.deploy = true;
    expect(() => validateStageBReleaseManifest(deploying)).toThrow('non-deploying');
    const failed = manifest();
    failed.parity.maximum_absolute_probability_error = 0.1;
    expect(() => validateStageBReleaseManifest(failed)).toThrow('parity');
  });

  it('extracts only a valid binary positive-class probability tensor', () => {
    expect(positiveProbabilityFromTensor([0.2, 0.8], [1, 2])).toBeCloseTo(0.8);
    expect(() => positiveProbabilityFromTensor([0.8], [1, 1])).toThrow('tensor');
    expect(() => positiveProbabilityFromTensor([1.2, -0.2], [1, 2])).toThrow('probability');
  });
});
