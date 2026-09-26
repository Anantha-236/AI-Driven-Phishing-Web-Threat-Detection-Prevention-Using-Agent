import { ArtifactManager } from "../core/evidence/artifact-manager";
import { EvidenceCollection } from "../core/schema/types";
import { sendEvidenceToServiceWorker } from "../messaging/index";
import { extractFeatureVector } from "../features/extractor";
import { DynamicDOMObserver } from "./observer";
import { createTypedEvents } from "./typed-events";
import { createContentEventQueue } from "../core/tsfeg";

if (typeof window !== "undefined" && typeof document !== "undefined" && (location.hostname === "127.0.0.1" || location.hostname === "localhost")) {
  document.documentElement?.setAttribute(
    "data-capstone-module-loaded",
    JSON.stringify({
      timestamp: Date.now(),
      readyState: document.readyState,
    })
  );
}

function setContentScriptStartupMarker(): void {
  if (typeof document === "undefined" || typeof location === "undefined") {
    return;
  }

  if (location.hostname !== "127.0.0.1" && location.hostname !== "localhost") {
    return;
  }

  document.documentElement?.setAttribute(
    "data-capstone-content-script-started",
    JSON.stringify({
      timestamp: Date.now(),
      readyState: document.readyState,
    })
  );
}

function setLocalDiagnostic(name: string, value: string): void {
  if (typeof document === "undefined" || typeof location === "undefined") {
    return;
  }

  // Diagnostics are limited to the controlled local verification origin.
  if (!(location.hostname === "127.0.0.1" && location.port === "41731")) {
    return;
  }

  document.documentElement?.setAttribute(name, value);
}

const runtimeDeviceId = crypto.randomUUID();
function getStableDeviceId(): string { return runtimeDeviceId; }

export class DOMContentCollector {
  /**
   * Safe observation of DOM elements to extract EvidenceCollection.
   * STRICT PRIVACY GUARANTEE:
   * This collector NEVER accesses element.value, innerText, textContent, or raw user inputs.
   */
  public static collectFromDocument(doc: Document = document, pageUrl: string = location.href, deviceId: string = getStableDeviceId()): EvidenceCollection {
    const manager = new ArtifactManager();
    manager.createPageArtifact(pageUrl, "");

    // Collect Forms and Inputs
    const forms = doc.querySelectorAll("form");
    if (forms.length > 0) {
      forms.forEach((formEl) => {
        const action = formEl.action;
        const method = formEl.getAttribute("method") || "GET";
        const target = formEl.getAttribute("target") || "";

        const inputElements = formEl.querySelectorAll("input, select, textarea");
        const inputsData: Array<{
          inputType: string;
          name: string;
          idAttribute: string;
          autocomplete: string;
          placeholder?: string;
          ariaLabel?: string;
          accept?: string;
          capture?: string;
          isRequired?: boolean;
        }> = [];

        inputElements.forEach((inputEl) => {
          // SAFE ACCESS: ONLY read structural attributes, NEVER value or text content
          const inputType = inputEl.getAttribute("type") || inputEl.tagName.toLowerCase();
          const name = inputEl.getAttribute("name") || "";
          const idAttribute = inputEl.getAttribute("id") || "";
          const autocomplete = inputEl.getAttribute("autocomplete") || "";
          const placeholder = inputEl.getAttribute("placeholder") || "";
          const ariaLabel = inputEl.getAttribute("aria-label") || inputEl.getAttribute("aria-labelledby") || "";
          const accept = inputEl.getAttribute("accept") || "";
          const capture = inputEl.getAttribute("capture") || "";
          const isRequired = inputEl.hasAttribute("required");

          inputsData.push({
            inputType,
            name,
            idAttribute,
            autocomplete,
            placeholder,
            ariaLabel,
            accept,
            capture,
            isRequired
          });
        });

        manager.createFormArtifact(action, method, inputsData, target);
      });
    }
    {
      // Orphan inputs outside forms (e.g. dynamic single-input fields)
      const orphanInputs = doc.querySelectorAll("body input, input");
      if (orphanInputs.length > 0) {
        const inputsData: Array<{
          inputType: string;
          name: string;
          idAttribute: string;
          autocomplete: string;
          placeholder?: string;
          ariaLabel?: string;
          accept?: string;
          capture?: string;
          isRequired?: boolean;
        }> = [];

        orphanInputs.forEach((inputEl) => {
          if (!inputEl.closest("form")) {
            inputsData.push({
              inputType: inputEl.getAttribute("type") || "text",
              name: inputEl.getAttribute("name") || "",
              idAttribute: inputEl.getAttribute("id") || "",
              autocomplete: inputEl.getAttribute("autocomplete") || "",
              placeholder: inputEl.getAttribute("placeholder") || "",
              ariaLabel: inputEl.getAttribute("aria-label") || inputEl.getAttribute("aria-labelledby") || "",
              accept: inputEl.getAttribute("accept") || "",
              capture: inputEl.getAttribute("capture") || "",
              isRequired: inputEl.hasAttribute("required")
            });
          }
        });

        if (inputsData.length > 0) {
          manager.createFormArtifact("", "GET", inputsData);
        }
      }
    }

    // Collect Scripts
    const scripts = doc.querySelectorAll("script");
    scripts.forEach((scriptEl) => {
      const src = scriptEl.getAttribute("src") || undefined;
      const isInline = !src;
      manager.createScriptArtifact(src, isInline);
    });

    const collection = manager.exportCollection();
    collection.deviceId = deviceId;
    collection.devicePlatform = "";
    return collection;
  }
}

/**
 * Handle evidence collection, feature extraction, diagnostics recording,
 * and service worker handoff.
 */
export function handleCollectionCycle(doc: Document = document): EvidenceCollection {
  setLocalDiagnostic("data-capstone-evidence-handoff", "collector_started");

  const collection = DOMContentCollector.collectFromDocument(doc, location.href, getStableDeviceId());
  setLocalDiagnostic("data-capstone-evidence-handoff", "evidence_created");

  const features = extractFeatureVector(collection);
  setLocalDiagnostic(
    "data-capstone-evidence-meta",
    JSON.stringify({
      collectionId: collection.collectionId,
      schemaVersion: collection.schemaVersion,
      pageId: collection.page.id,
      domain: collection.page.domain,
      formCount: collection.forms.length,
      inputCount: collection.inputs.length,
    })
  );
  setLocalDiagnostic("data-capstone-feature-meta", JSON.stringify(features));

  console.log("[CAPSTONE-1] Collected DOM Evidence:", collection.collectionId, `forms=${collection.forms.length} inputs=${collection.inputs.length}`);

  setLocalDiagnostic("data-capstone-evidence-handoff", "send_attempted");
  void sendEvidenceToServiceWorker(collection)
    .then(() => {
      setLocalDiagnostic("data-capstone-evidence-handoff", "send_ok");
      console.log("[CAPSTONE-1] Evidence handoff sent", collection.collectionId);
    })
    .catch((error) => {
      const details = error instanceof Error ? error.message : String(error);
      setLocalDiagnostic("data-capstone-evidence-handoff", `send_error:${details}`);
      console.warn("[CAPSTONE-1] Evidence handoff failed:", details);
    });

  return collection;
}

// Auto-run and attach lifecycle observers in browser content script environment
const isTestingEnvironment = typeof process !== "undefined" && !!process.env?.VITEST;

if (typeof window !== "undefined" && typeof document !== "undefined" && !isTestingEnvironment) {
  try {
    setContentScriptStartupMarker();
    const archiveReplayPage =
      location.hostname === '127.0.0.1' &&
      /^\/sample\/[a-f0-9]{32}\/?$/.test(location.pathname);
    const archiveReplayAcknowledgementTimeoutMs = 10_000;
    const transport = createContentEventQueue(
      batch => chrome.runtime.sendMessage(batch),
      archiveReplayPage
        ? {
            acknowledgementTimeoutMs: archiveReplayAcknowledgementTimeoutMs,
            retryDelayMs: 250,
          }
        : undefined,
    );
    const typed = createTypedEvents(document, transport.enqueue);
    typed.start();

    if (typeof chrome !== "undefined" && chrome.runtime?.onMessage) {
      chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
        try {
            const runtimeMessage = message as { type?: string; payload?: unknown };
            if (runtimeMessage.type === 'SECURITY_REPORT' && ['ALLOW', 'WARN', 'CONFIRM'].includes(message.action)) typed.setAgentAction(message.action);
            if (runtimeMessage.type === 'SECURITY_REPORT' && message.action === 'ALLOW') {
              document.getElementById('capstone-security-warning')?.remove();
              sendResponse({ outcome: 'DECISION_ONLY' }); return false;
            }
          if (runtimeMessage.type === 'SECURITY_REPORT' && ['WARN', 'CONFIRM'].includes(message.action)) {
            let warning = document.getElementById('capstone-security-warning');
            if (!warning) {
              warning = document.createElement('aside'); warning.id = 'capstone-security-warning';
              warning.setAttribute('role', 'alert');
              warning.style.cssText = 'position:relative;display:block;z-index:2147483647;padding:16px;background:#fff3cd;color:#302400;font:16px sans-serif;border-bottom:2px solid #9b7000';
              warning.textContent = message.reason === 'HOSTNAME_RESEMBLES_BRAND'
                ? 'CAPSTONE-1: This hostname resembles a known brand but is outside the verified login registry. Verify its identity before sharing information. This is not a confirmed phishing verdict.'
                : message.reason === 'HTTPS_DOWNGRADE'
                  ? 'CAPSTONE-1: A sensitive form on this HTTPS page targets unencrypted HTTP. Review the destination before submitting.'
                  : 'CAPSTONE-1: A sensitive-form destination changed after interaction. Verify the destination before submitting. Open the extension for supporting evidence.';
              (document.body || document.documentElement).prepend(warning);
            }
            sendResponse({ outcome: 'WARNING_DISPLAYED' }); return false;
          }
          if (runtimeMessage.type === "GET_TYPED_EVENT_STATUS") {
            // Archive replay polling is also an explicit retry signal. This is
            // safe because flush() is idempotent while a send is active and
            // merely cancels the delayed retry timer when one is pending.
            void transport.flush();
            sendResponse({ ok: true, ...transport.snapshot() });
            return false;
          }
          if (runtimeMessage.type === "REQUEST_COLLECTION") {
            handleCollectionCycle(document);
            sendResponse({ ok: true });
            return true;
          }
        } catch (error) {
          console.warn("[CAPSTONE-1] Message request collector error:", error);
        }
        return false;
      });
    }

    // 1. Initial collection at document_start
    handleCollectionCycle(document);

    // 2. Event-driven collection when DOM is parsed
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", () => {
        handleCollectionCycle(document);
      });
      window.addEventListener("load", () => {
        handleCollectionCycle(document);
      });
    }

    // 3. Re-collect when the user navigates in-place or loads a new page
    window.addEventListener("pageshow", () => {
      handleCollectionCycle(document);
    });
    window.addEventListener("hashchange", () => {
      handleCollectionCycle(document);
    });

    // 4. Dynamic DOM mutation observation for runtime changes
    const observer = new DynamicDOMObserver(() => {
      typed.scan(true);
      handleCollectionCycle(document);
    }, 0, document);

    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", () => {
        typed.scan();
        observer.start();
      }, { once: true });
    } else {
      observer.start();
    }

  } catch (err) {
    const details = err instanceof Error ? err.message : String(err);
    setLocalDiagnostic("data-capstone-evidence-handoff", `collector_error:${details}`);
    console.warn("[CAPSTONE-1] Content Collector execution:", err);
  }
}
