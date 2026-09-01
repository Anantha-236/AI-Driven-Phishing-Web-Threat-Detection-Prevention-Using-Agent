import { createExtensionMessage, isSchemaV3EvidenceCollection } from "../messaging/index";
import { runDetectionPipeline, createDetectionMessage, DetectionResult } from "../core/enforcement";
import { ServiceWorkerOnnxAdapter } from "../core/service-worker-onnx-adapter";
import { FeatureVector, ModelResult } from "../core/schema/types";

console.log("[CAPSTONE-1] Service Worker initializing...");

const adapter = new ServiceWorkerOnnxAdapter();
let isAdapterLoaded = false;
let latestDetectionResult: DetectionResult | null = null;

// Fallback rule-based adapter if ONNX is loading or unavailable
const fallbackAdapter = {
  infer: async (features: FeatureVector): Promise<ModelResult> => {
    const score =
      (features.has_password_field ? 0.35 : 0) +
      (features.has_otp_field ? 0.25 : 0) +
      (features.cross_domain_form ? 0.35 : 0) +
      (features.brand_impersonation_indicator ? 0.3 : 0);

    return {
      rawScore: Math.min(score, 0.99),
      inferenceLatencyMs: 1,
      runtimeUsed: "service-worker",
      modelId: "rule-fallback-v1.1",
    };
  },
};

// Attempt to load model at startup
void adapter.loadFromRuntimeUrl()
  .then(() => {
    isAdapterLoaded = true;
    console.log("[CAPSTONE-1] Service Worker ONNX model loaded successfully");
  })
  .catch((err) => {
    console.warn("[CAPSTONE-1] ONNX load notice (will use deterministic engine until ready):", err);
  });

chrome.runtime.onInstalled.addListener(() => {
  console.log("[CAPSTONE-1] Extension installed/updated");
});

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  try {
    const runtimeMessage = message as { type?: string; payload?: unknown };

    if (runtimeMessage.type === "EVIDENCE_COLLECTED") {
      if (!isSchemaV3EvidenceCollection(runtimeMessage.payload)) {
        sendResponse({ ok: false, error: "Invalid EvidenceCollection payload" });
        return false;
      }

      const evidence = runtimeMessage.payload;
      console.log("[CAPSTONE-1] Evidence received from content script", evidence.collectionId);

      const activeAdapter = isAdapterLoaded ? adapter : fallbackAdapter;

      void runDetectionPipeline(evidence, activeAdapter)
        .then((detection) => {
          latestDetectionResult = detection;
          console.log("[CAPSTONE-1] Detection completed:", detection.threat.threatLevel, `(score=${detection.modelResult.rawScore.toFixed(2)})`);

          const uiMessage = createDetectionMessage(detection);
          // Broadcast to extension views (popup, tabs)
          try {
            chrome.runtime.sendMessage(uiMessage).catch(() => {});
          } catch {
            // Popup may not be open
          }

          sendResponse({
            ok: true,
            schemaVersion: evidence.schemaVersion,
            threatLevel: detection.threat.threatLevel,
            action: detection.policy.action,
            outcome: detection.policy.outcome,
          });
        })
        .catch((pipelineErr) => {
          console.warn("[CAPSTONE-1] Pipeline processing error:", pipelineErr);
          sendResponse({ ok: true, schemaVersion: evidence.schemaVersion, error: String(pipelineErr) });
        });

      return true; // Keep channel open for async response
    }

    if (runtimeMessage.type === "GET_LATEST_DECISION") {
      sendResponse({
        ok: true,
        detection: latestDetectionResult ? {
          threatLevel: latestDetectionResult.threat.threatLevel,
          score: latestDetectionResult.modelResult.rawScore,
          confidence: latestDetectionResult.threat.confidence,
          reasons: latestDetectionResult.threat.reasons,
          action: latestDetectionResult.policy.action,
          outcome: latestDetectionResult.policy.outcome,
          domain: latestDetectionResult.evidence.page.domain,
          requestedDataTypes: latestDetectionResult.evidence.requestedDataTypes || [],
        } : null,
      });
      return false;
    }

    if (runtimeMessage.type === "PING") {
      const pong = createExtensionMessage("PING", { ok: true, modelReady: isAdapterLoaded }, "service-worker", "content-script");
      sendResponse({ ok: true, message: pong });
      return false;
    }
  } catch (error) {
    const details = error instanceof Error ? error.message : "Unknown runtime message error";
    sendResponse({ ok: false, error: details });
  }

  return false;
});
