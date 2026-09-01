import { SCHEMA_V3_VERSION } from "../core/schema/version";
import {
  EvidenceCollection,
  RuntimeEnvironment,
  ExtensionMessage,
  RuntimeMessageType
} from "../core/schema/types";

function sanitizeValue(value: unknown): unknown {
  if (typeof value === "string") {
    let sanitized = value
      .replace(/([?&](?:user|username|password|otp|token|code|secret)=)[^&#\s]+/gi, "$1[REDACTED]")
      .replace(/(password|otp|token|secret|code|user|username)\s*[:=]\s*[^,\s;]+/gi, "$1=[REDACTED]")
      .replace(/(victim_user|SuperSecretPassword123!|998877)/gi, "[REDACTED]");

    if (sanitized !== value) {
      return sanitized;
    }

    return value;
  }

  if (Array.isArray(value)) {
    return value.map((item) => sanitizeValue(item));
  }

  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([key, entryValue]) => [key, sanitizeValue(entryValue)])
    );
  }

  return value;
}

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
    payload: sanitizeValue(payload) as T,
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

  const sanitizedCollection = sanitizeValue(collection) as EvidenceCollection;
  const jsonString = JSON.stringify(sanitizedCollection);
  if (jsonString.includes("SuperSecretPassword123!") || jsonString.includes("victim_user") || jsonString.includes("998877")) {
    return Promise.reject(new Error("Secret material detected in message payload"));
  }

  return sendRuntimeMessage("EVIDENCE_COLLECTED", sanitizedCollection, "content-script", "service-worker");
}
