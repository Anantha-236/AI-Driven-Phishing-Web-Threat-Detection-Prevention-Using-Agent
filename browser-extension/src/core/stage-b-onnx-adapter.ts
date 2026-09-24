import * as ort from 'onnxruntime-web/wasm';
import { CONTEXT_FEATURES, CONTEXT_FEATURE_VERSION } from './tsfeg';
import {
  positiveProbabilityFromTensor,
  validateStageBReleaseManifest,
  type StageBReleaseManifest,
} from './stage-b-release-contract';

export const STAGE_B_CANDIDATE_PATHS = {
  manifest: 'assets/stage-b-candidate/stage-b-release-manifest.json',
  model: 'assets/stage-b-candidate/stage-b-contextual-candidate.onnx',
  parity: 'assets/stage-b-candidate/stage-b-parity-vectors.json',
} as const;

export interface StageBInferenceResult {
  score: number;
  threshold: number;
  would_cross_frozen_threshold: boolean;
  model_id: string;
  runtime: 'onnxruntime-web-wasm';
  latency_ms: number;
  integration_eligible: boolean;
  deployment_enabled: false;
  autonomous_blocking: false;
}

function configureWasmRuntime(): void {
  // MV3 extension pages are CSP-restricted. Keep this candidate runtime simple:
  // no Blob proxy worker and no cross-origin-isolation dependency.
  ort.env.wasm.numThreads = 1;
  ort.env.wasm.proxy = false;
}

export function validateStageBContextVector(values: readonly number[]): Float32Array {
  if (values.length !== CONTEXT_FEATURES.length) {
    throw new Error(`Stage B contextual feature count mismatch: expected ${CONTEXT_FEATURES.length}, got ${values.length}`);
  }
  if (!values.every(Number.isFinite)) {
    throw new Error('Stage B contextual vector contains non-finite values');
  }
  return Float32Array.from(values);
}

export async function sha256Hex(buffer: ArrayBuffer): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', buffer);
  return [...new Uint8Array(digest)].map(value => value.toString(16).padStart(2, '0')).join('');
}

export class StageBOnnxAdapter {
  readonly runtime = 'onnxruntime-web-wasm' as const;
  private session: ort.InferenceSession | null = null;
  private manifest: StageBReleaseManifest | null = null;

  async load(model: ArrayBuffer, manifestValue: unknown): Promise<void> {
    const manifest = validateStageBReleaseManifest(manifestValue);
    if (manifest.feature_version !== CONTEXT_FEATURE_VERSION ||
        manifest.feature_names.length !== CONTEXT_FEATURES.length ||
        CONTEXT_FEATURES.some((name, index) => manifest.feature_names[index] !== name)) {
      throw new Error('Stage B candidate does not match the production contextual feature contract');
    }

    const actualHash = await sha256Hex(model);
    if (actualHash !== manifest.onnx.sha256) {
      throw new Error('Stage B candidate ONNX SHA-256 mismatch');
    }

    configureWasmRuntime();
    const session = await ort.InferenceSession.create(model, {
      executionProviders: ['wasm'],
      graphOptimizationLevel: 'all',
    });

    if (session.inputNames.length !== 1 || session.inputNames[0] !== manifest.onnx.input_name) {
      throw new Error('Stage B candidate ONNX input contract mismatch');
    }
    if (!session.outputNames.includes(manifest.onnx.probability_output_name)) {
      throw new Error('Stage B candidate ONNX probability output is missing');
    }

    this.session = session;
    this.manifest = manifest;
  }

  async loadInstalledCandidate(): Promise<void> {
    if (typeof chrome === 'undefined' || !chrome.runtime || typeof chrome.runtime.getURL !== 'function') {
      throw new Error('chrome.runtime.getURL is unavailable in this runtime');
    }

    const manifestResponse = await fetch(chrome.runtime.getURL(STAGE_B_CANDIDATE_PATHS.manifest));
    if (!manifestResponse.ok) {
      throw new Error(`Stage B candidate manifest unavailable: ${manifestResponse.status}`);
    }
    const manifest = await manifestResponse.json();

    const modelResponse = await fetch(chrome.runtime.getURL(STAGE_B_CANDIDATE_PATHS.model));
    if (!modelResponse.ok) {
      throw new Error(`Stage B candidate model unavailable: ${modelResponse.status}`);
    }
    await this.load(await modelResponse.arrayBuffer(), manifest);
  }

  async inferVector(values: readonly number[]): Promise<StageBInferenceResult> {
    if (!this.session || !this.manifest) throw new Error('stage_b_candidate_not_loaded');

    const vector = validateStageBContextVector(values);
    const manifest = this.manifest;
    const start = performance.now();
    const input = new ort.Tensor('float32', vector, [1, vector.length]);
    const outputs = await this.session.run({ [manifest.onnx.input_name]: input });
    const output = outputs[manifest.onnx.probability_output_name];

    if (!output || !['float32', 'float64'].includes(output.type)) {
      throw new Error('Stage B candidate returned an invalid probability tensor type');
    }

    const score = positiveProbabilityFromTensor(
      output.data as ArrayLike<number>,
      output.dims,
      manifest.onnx.positive_class_index,
    );
    const latency = performance.now() - start;
    const threshold = manifest.operating_point.threshold;

    return {
      score,
      threshold,
      would_cross_frozen_threshold: score >= threshold,
      model_id: manifest.model_id,
      runtime: this.runtime,
      latency_ms: latency,
      integration_eligible: manifest.release_gate.integration_eligible,
      deployment_enabled: false,
      autonomous_blocking: false,
    };
  }

  healthCheck():
    | { available: true; model_id: string; integration_eligible: boolean }
    | { available: false; error: 'candidate_not_loaded' } {
    if (!this.session || !this.manifest) {
      return { available: false, error: 'candidate_not_loaded' };
    }
    return {
      available: true,
      model_id: this.manifest.model_id,
      integration_eligible: this.manifest.release_gate.integration_eligible,
    };
  }
}
