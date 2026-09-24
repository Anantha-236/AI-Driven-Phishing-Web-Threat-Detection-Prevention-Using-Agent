import * as ort from "onnxruntime-web";
import { FeatureVector, ModelResult } from "./schema/types";
import { CONTEXT_FEATURES, CONTEXT_FEATURE_VERSION, FLAT_FEATURES, RELATIONSHIP_FEATURES } from './tsfeg';

export interface EventModelArtifact {
  model_id: string; feature_version: string; representation: 'flat' | 'relationship' | 'contextual-flat';
  provenance: string; calibrated: boolean; autonomous_blocking: boolean;
  feature_names?: string[];
  calibration?: { method: 'sigmoid'; coefficient: number; intercept: number };
  artifact_sha256?: string;
  mean: number[]; scale: number[]; coefficients: number[]; intercept: number;
}
export function inferEventModel(model: EventModelArtifact, values: number[]): number {
  const contextual = model.feature_version === CONTEXT_FEATURE_VERSION && model.representation === 'contextual-flat';
  const legacy = model.feature_version === 'event-features-1' && ['flat', 'relationship'].includes(model.representation);
  const names = contextual ? [...CONTEXT_FEATURES] : model.representation === 'flat' ? [...FLAT_FEATURES] : [...FLAT_FEATURES, ...RELATIONSHIP_FEATURES];
  if ((!contextual && !legacy) || !Array.isArray(model.coefficients) || !Array.isArray(model.mean) || !Array.isArray(model.scale) ||
      values.length !== names.length || values.length !== model.coefficients.length || model.mean.length !== values.length || model.scale.length !== values.length ||
      (contextual && (!Array.isArray(model.feature_names) || names.some((name, index) => model.feature_names![index] !== name) || model.feature_names.length !== names.length)) ||
      !values.every(Number.isFinite) || !Number.isFinite(model.intercept) || !model.mean.every(Number.isFinite) || !model.coefficients.every(Number.isFinite) ||
      !model.scale.every(v => Number.isFinite(v) && v > 0)) throw new Error('Event model feature mismatch');
  let logit = model.intercept + values.reduce((sum, value, i) => sum + ((value - model.mean[i]) / model.scale[i]) * model.coefficients[i], 0);
  if (model.calibrated) {
    const calibration = model.calibration;
    if (!calibration || calibration.method !== 'sigmoid' || !Number.isFinite(calibration.coefficient) || !Number.isFinite(calibration.intercept)) throw new Error('Unsupported model calibration');
    logit = calibration.coefficient * logit + calibration.intercept;
  }
  if (!Number.isFinite(logit)) throw new Error('Invalid event model output');
  return 1 / (1 + Math.exp(-logit));
}

export interface LocalModelAdapter {
  readonly runtime: "service-worker" | "offscreen" | "content-script";
  load(model: ArrayBuffer): Promise<void>;
  infer(features: FeatureVector): Promise<ModelResult & {
    score: number;
    label: "benign" | "malicious";
    version: string;
    latency_ms: number;
  }>;
  healthCheck():
    | { available: true; latency_ms: number }
    | { available: false; error: "model_not_loaded" };
}

export class ServiceWorkerOnnxAdapter implements LocalModelAdapter {
  readonly runtime = "service-worker" as const;
  private session: ort.InferenceSession | null = null;
  readonly version = "deterministic-toy-v1.1.0";

  async loadFromRuntimeUrl(): Promise<void> {
    if (typeof chrome === "undefined" || !chrome.runtime || typeof chrome.runtime.getURL !== "function") {
      throw new Error("chrome.runtime.getURL is unavailable in this runtime");
    }

    const modelUrl = chrome.runtime.getURL("assets/model.onnx");
    const response = await fetch(modelUrl);
    if (!response.ok) {
      throw new Error(`Failed to fetch ONNX model: ${response.status} ${response.statusText}`);
    }

    const model = await response.arrayBuffer();
    await this.load(model);
  }

  async load(model: ArrayBuffer): Promise<void> {
    this.session = await ort.InferenceSession.create(model);
  }

  async infer(features: FeatureVector): Promise<ModelResult & {
    score: number;
    label: "benign" | "malicious";
    version: string;
    latency_ms: number;
  }> {
    if (!this.session) {
      throw new Error("model_not_loaded");
    }

    const values = new Float32Array(5);
    values[0] = Number(features.has_password_field);
    values[1] = Number(features.has_otp_field);
    values[2] = Number(features.cross_domain_form);
    values[3] = Number(features.form_count);
    values[4] = Number(features.input_count);

    const start = performance.now();
    const input = new ort.Tensor("float32", values, [1, 5]);
    const outputs = await this.session.run({ X: input });
    const outputTensor = outputs.Y ?? outputs.output ?? Object.values(outputs)[0];
    const rawScore = Number(outputTensor?.data?.[0] ?? 0);
    const latency_ms = performance.now() - start;

    return {
      rawScore,
      inferenceLatencyMs: latency_ms,
      runtimeUsed: "service-worker",
      modelId: this.version,
      score: rawScore,
      label: rawScore >= 0.5 ? "malicious" : "benign",
      version: this.version,
      latency_ms,
    };
  }

  healthCheck():
    | { available: true; latency_ms: number }
    | { available: false; error: "model_not_loaded" } {
    if (!this.session) {
      return { available: false, error: "model_not_loaded" };
    }

    return { available: true, latency_ms: 0 };
  }
}
