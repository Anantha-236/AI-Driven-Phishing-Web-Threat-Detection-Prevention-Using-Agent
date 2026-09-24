import { installTypedEvents } from "./typed-events";
installTypedEvents();
import { createExtensionMessage, isSchemaV3EvidenceCollection } from "../messaging/index";
import { runDetectionPipeline, DetectionResult } from "../core/enforcement";
import { installThreatBlocking } from '../core/enforcement';
const protection = installThreatBlocking();
import { ServiceWorkerOnnxAdapter } from "../core/service-worker-onnx-adapter";
import { FeatureVector, ModelResult } from "../core/schema/types";
import type { EventSecurityReport } from '../core/assessment';

function createObservationPayload(evidence: any, detection: DetectionResult) {
  return {
    schemaVersion: evidence.schemaVersion,
    collectionId: evidence.collectionId,
    timestamp: evidence.timestamp,
    deviceId: evidence.deviceId || "",
    devicePlatform: "",
    page: {
      id: evidence.page.id,
      url: evidence.page.url,
      domain: evidence.page.domain,
      title: "",
      formIds: evidence.page.formIds,
      scriptCount: evidence.page.scriptCount,
      isHTTPS: evidence.page.isHTTPS,
      privacyPolicyUrl: evidence.page.privacyPolicyUrl || "",
      termsUrl: evidence.page.termsUrl || "",
    },
    forms: evidence.forms.map((form: any) => ({
      id: form.id,
      action: form.action,
      isCrossDomain: form.isCrossDomain,
      method: form.method,
      inputIds: form.inputIds,
      hasPasswordField: form.hasPasswordField,
      hasOtpField: form.hasOtpField,
      autocompleteAttributes: [],
      detectedDataTypes: form.detectedDataTypes || [],
      target: "",
    })),
    inputs: evidence.inputs.map((input: any) => ({
      id: input.id,
      inputType: input.inputType,
      name: "",
      idAttribute: "",
      autocomplete: "",
      isPassword: input.isPassword,
      isOtp: input.isOtp,
      detectedDataTypes: input.detectedDataTypes || [],
      isRequired: Boolean(input.isRequired),
    })),
    scripts: evidence.scripts.map((script: any) => ({
      id: script.id,
      src: script.src || null,
      isInline: Boolean(script.isInline),
      isCrossDomain: Boolean(script.isCrossDomain),
    })),
    requests: evidence.requests.map((request: any) => ({
      id: request.id,
      url: request.url,
      method: request.method,
      isCrossDomain: Boolean(request.isCrossDomain),
    })),
    requestedDataTypes: evidence.requestedDataTypes || [],
    threatLevel: detection.threat.threatLevel,
    modelScore: detection.modelResult.rawScore,
    policyAction: detection.policy.action,
  };
}

async function persistObservationToBackend(evidence: any, detection: DetectionResult): Promise<void> {
  const payload = createObservationPayload(evidence, detection);
  const backendUrl = "http://127.0.0.1:8000/api/v1/observations";

  try {
    const response = await fetch(backendUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const result = await response.json();
    console.log("[CAPSTONE-1] Observation persisted to backend", result);
  } catch (error) {
    const details = error instanceof Error ? error.message : String(error);
    console.warn("[CAPSTONE-1] Backend persistence unavailable; local decision preserved.", details);
  }
}

console.log("[CAPSTONE-1] Service Worker initializing...");

const adapter = new ServiceWorkerOnnxAdapter();
let isAdapterLoaded = false;

function requestCollectionForTab(tabId: number | undefined): void {
  if (typeof tabId !== "number") return;

  chrome.tabs.sendMessage(tabId, { type: "REQUEST_COLLECTION" }, () => {
    if (chrome.runtime.lastError) {
      // Ignore pages without a CAPSTONE content script or where the tab is still loading.
    }
  });
}

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

chrome.tabs.onActivated.addListener((activeInfo) => {
  requestCollectionForTab(activeInfo.tabId);
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.url) {
    requestCollectionForTab(tabId);
  }
});

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  try {
    const runtimeMessage = message as { type?: string; payload?: unknown };

    if (runtimeMessage.type === 'GET_PROTECTION_STATUS' || runtimeMessage.type === 'REFRESH_PHISHING_FEED') {
      if (!_sender.url?.startsWith(chrome.runtime.getURL(''))) { sendResponse({ ok: false }); return false; }
      void (runtimeMessage.type === 'REFRESH_PHISHING_FEED' ? protection.refresh(true) : protection.status())
        .then(status => sendResponse({ ok: true, protection: status })).catch(() => sendResponse({ ok: false }));
      return true;
    }

    if (runtimeMessage.type === "EVIDENCE_COLLECTED") {
      if (!isSchemaV3EvidenceCollection(runtimeMessage.payload)) {
        sendResponse({ ok: false, error: "Invalid EvidenceCollection payload" });
        return false;
      }

      const evidence = runtimeMessage.payload;
      if (_sender.frameId !== 0) { sendResponse({ ok: true }); return false; }
      const senderTabId = _sender.tab?.id ?? null;
      console.log("[CAPSTONE-1] Evidence received from content script", evidence.collectionId, "tab", senderTabId);

      const activeAdapter = isAdapterLoaded ? adapter : fallbackAdapter;

      void runDetectionPipeline(evidence, activeAdapter)
        .then((detection) => {
          // Preserve historical snapshot telemetry, but never publish its
          // five-feature score as the current browser security decision.
          void persistObservationToBackend(evidence, detection);

          sendResponse({
            ok: true,
            schemaVersion: evidence.schemaVersion,
            telemetry_only: true,
          });
        })
        .catch((pipelineErr) => {
          console.warn("[CAPSTONE-1] Pipeline processing error:", pipelineErr);
          sendResponse({ ok: true, schemaVersion: evidence.schemaVersion, error: String(pipelineErr) });
        });

      return true; // Keep channel open for async response
    }

    if (runtimeMessage.type === "GET_LATEST_DECISION") {
      // This query is intended for extension-owned UI/status surfaces. If an
      // extension page is opened as a normal browser tab, sender.tab refers to
      // the extension page itself, not the protected page. Resolve the active
      // browser tab instead.
      if (!_sender.url?.startsWith(chrome.runtime.getURL(''))) {
        sendResponse({ ok: false, detection: null });
        return false;
      }

      void (async () => {
        const tabId = (await chrome.tabs.query({
          active: true,
          currentWindow: true,
        }))[0]?.id;

        if (tabId === undefined) {
          sendResponse({ ok: true, detection: null });
          return;
        }

        const key = `security-report:${tabId}`;
        const report: EventSecurityReport | undefined =
          (await chrome.storage.session.get(key))[key];

        const frame = await chrome.webNavigation
          .getFrame({ tabId, frameId: 0 })
          .catch(() => null);

        sendResponse({
          ok: true,
          detection:
            report && frame?.documentId === report.document_id
              ? {
                  threatLevel: report.threatLevel,
                  score: report.model_score,
                  confidence: report.confidence,
                  confidence_kind: report.confidence_kind,
                  reasons: report.decision_reasons,
                  action: report.action,
                  outcome: report.outcome,
                  domain: report.page_origin,
                  requestedDataTypes: report.requestedDataTypes,
                  decision_source: report.decision_source,
                  agent_version: report.agent_version,
                  event_seq: report.event_seq,
                }
              : null,
        });
      })().catch(() => sendResponse({ ok: false, detection: null }));

      return true;
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
