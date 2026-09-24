import { SCHEMA_V3_VERSION } from "../core/schema/version";
import {
  EvidenceCollection,
  RuntimeEnvironment,
  ExtensionMessage,
  RuntimeMessageType
} from "../core/schema/types";

export function createExtensionMessage<T>(
  type: RuntimeMessageType,
  payload: T,
  source: RuntimeEnvironment,
  target: RuntimeEnvironment
): ExtensionMessage<T> {
  return {
    type,
    source,
    target,
    payload,
    timestamp: Date.now()
  };
}

export function isSchemaV3EvidenceCollection(value: unknown): value is EvidenceCollection {
  if (!value || typeof value !== "object") {
    return false;
  }

  const candidate = value as Record<string, unknown>;
  return (
    candidate.schemaVersion === SCHEMA_V3_VERSION &&
    typeof candidate.collectionId === "string" &&
    typeof candidate.timestamp === "number" &&
    !!candidate.page && typeof candidate.page === "object" &&
    Array.isArray(candidate.forms) &&
    Array.isArray(candidate.inputs) &&
    Array.isArray(candidate.scripts) &&
    Array.isArray(candidate.requests) &&
    Array.isArray(candidate.relationships)
  );
}

export function sendRuntimeMessage<T>(
  type: RuntimeMessageType,
  payload: T,
  source: RuntimeEnvironment,
  target: RuntimeEnvironment
): Promise<unknown> {
  const message = createExtensionMessage(type, payload, source, target);

  if (typeof chrome !== "undefined" && chrome.runtime && typeof chrome.runtime.sendMessage === "function") {
    return new Promise((resolve, reject) => {
      chrome.runtime.sendMessage(message, (response) => {
        if (chrome.runtime.lastError) {
          reject(new Error(chrome.runtime.lastError.message));
          return;
        }
        resolve(response);
      });
    });
  }

  return Promise.resolve({ ok: true, message });
}

export function sendEvidenceToServiceWorker(collection: EvidenceCollection): Promise<unknown> {
  if (!isSchemaV3EvidenceCollection(collection)) {
    return Promise.reject(new Error("Invalid EvidenceCollection payload"));
  }

  return sendRuntimeMessage("EVIDENCE_COLLECTED", collection, "content-script", "service-worker");
}
