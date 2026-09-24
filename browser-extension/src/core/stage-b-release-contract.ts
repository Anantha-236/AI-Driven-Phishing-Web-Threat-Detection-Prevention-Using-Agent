import { CONTEXT_FEATURES, CONTEXT_FEATURE_VERSION } from './tsfeg';

export interface StageBReleaseManifest {
  schema_version: 'stage-b-release-candidate-1';
  status: 'PASS';
  model_id: string;
  representation: 'contextual-flat';
  feature_version: typeof CONTEXT_FEATURE_VERSION;
  feature_names: string[];
  feature_contract_sha256: string;
  extractor_source_sha256: string;
  onnx: {
    filename: string;
    sha256: string;
    input_name: string;
    probability_output_name: string;
    positive_class_index: 1;
    opsets: Record<string, number>;
  };
  parity: {
    status: 'PASS';
    test_partition_used: false;
    tolerance: number;
    maximum_absolute_probability_error: number;
  };
  operating_point: {
    threshold: number;
    primary_fpr_cap: number;
    calibration_deployment_authorized: boolean;
  };
  release_gate: {
    integration_eligible: boolean;
    deploy: false;
    autonomous_blocking: false;
    reasons: string[];
  };
}

function isObject(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function isSha256(value: unknown): value is string {
  return typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
}

export function validateStageBReleaseManifest(value: unknown): StageBReleaseManifest {
  if (!isObject(value) || value.schema_version !== 'stage-b-release-candidate-1' || value.status !== 'PASS') {
    throw new Error('Stage B release manifest schema mismatch');
  }
  if (value.representation !== 'contextual-flat' || value.feature_version !== CONTEXT_FEATURE_VERSION) {
    throw new Error('Stage B release feature contract mismatch');
  }
  const featureNames = value.feature_names;
  if (!Array.isArray(featureNames) ||
      featureNames.length !== CONTEXT_FEATURES.length ||
      CONTEXT_FEATURES.some((name, index) => featureNames[index] !== name)) {
    throw new Error('Stage B release feature ordering mismatch');
  }
  if (!isSha256(value.feature_contract_sha256) || !isSha256(value.extractor_source_sha256)) {
    throw new Error('Stage B release hashes are invalid');
  }
  if (!isObject(value.onnx) || !isSha256(value.onnx.sha256) ||
      typeof value.onnx.input_name !== 'string' || !value.onnx.input_name ||
      typeof value.onnx.probability_output_name !== 'string' || !value.onnx.probability_output_name ||
      value.onnx.positive_class_index !== 1) {
    throw new Error('Stage B ONNX contract is invalid');
  }
  if (!isObject(value.parity) || value.parity.status !== 'PASS' ||
      value.parity.test_partition_used !== false ||
      typeof value.parity.tolerance !== 'number' || !Number.isFinite(value.parity.tolerance) ||
      typeof value.parity.maximum_absolute_probability_error !== 'number' ||
      !Number.isFinite(value.parity.maximum_absolute_probability_error) ||
      value.parity.maximum_absolute_probability_error > value.parity.tolerance) {
    throw new Error('Stage B ONNX parity gate is invalid');
  }
  if (!isObject(value.operating_point) ||
      typeof value.operating_point.threshold !== 'number' ||
      !Number.isFinite(value.operating_point.threshold) ||
      value.operating_point.threshold < 0 || value.operating_point.threshold > 1) {
    throw new Error('Stage B operating point is invalid');
  }
  if (!isObject(value.release_gate) || value.release_gate.deploy !== false ||
      value.release_gate.autonomous_blocking !== false ||
      !Array.isArray(value.release_gate.reasons)) {
    throw new Error('Stage B release gate must remain non-deploying in Task 11');
  }
  return value as unknown as StageBReleaseManifest;
}

export function positiveProbabilityFromTensor(
  data: ArrayLike<number>,
  dims: readonly number[],
  positiveClassIndex = 1,
): number {
  if (dims.length !== 2 || dims[0] !== 1 || dims[1] !== 2 || positiveClassIndex !== 1 || data.length !== 2) {
    throw new Error('Stage B ONNX probability tensor mismatch');
  }
  const value = Number(data[positiveClassIndex]);
  if (!Number.isFinite(value) || value < 0 || value > 1) {
    throw new Error('Stage B ONNX probability is invalid');
  }
  return value;
}
