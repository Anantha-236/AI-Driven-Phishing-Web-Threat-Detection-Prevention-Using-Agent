import { describe, expect, it } from 'vitest';
import { CONTEXT_FEATURES } from '../../browser-extension/src/core/tsfeg';
import {
  STAGE_B_CANDIDATE_PATHS,
  validateStageBContextVector,
} from '../../browser-extension/src/core/stage-b-onnx-adapter';

describe('Stage B ONNX browser adapter contract', () => {
  it('requires exactly the current contextual feature width', () => {
    const values = CONTEXT_FEATURES.map((_, index) => index / 10);
    const vector = validateStageBContextVector(values);
    expect(vector).toBeInstanceOf(Float32Array);
    expect(vector).toHaveLength(CONTEXT_FEATURES.length);
  });

  it('rejects truncated, expanded and non-finite contextual vectors', () => {
    expect(() => validateStageBContextVector(CONTEXT_FEATURES.slice(0, -1).map(() => 0))).toThrow('count');
    expect(() => validateStageBContextVector([...CONTEXT_FEATURES.map(() => 0), 0])).toThrow('count');
    const bad = CONTEXT_FEATURES.map(() => 0);
    bad[4] = Number.NaN;
    expect(() => validateStageBContextVector(bad)).toThrow('non-finite');
  });

  it('uses a dedicated candidate namespace rather than the legacy model.onnx path', () => {
    expect(STAGE_B_CANDIDATE_PATHS.model).toBe(
      'assets/stage-b-candidate/stage-b-contextual-candidate.onnx',
    );
    expect(STAGE_B_CANDIDATE_PATHS.model).not.toBe('assets/model.onnx');
  });
});
