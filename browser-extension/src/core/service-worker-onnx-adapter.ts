import * as ort from "onnxruntime-web";
import { FeatureVector, ModelResult } from "./schema/types";

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
