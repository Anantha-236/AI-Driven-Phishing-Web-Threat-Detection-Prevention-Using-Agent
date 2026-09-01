import { ArtifactManager } from "../core/evidence/artifact-manager";
import { EvidenceCollection } from "../core/schema/types";
import { sendEvidenceToServiceWorker } from "../messaging/index";
import { extractFeatureVector } from "../features/extractor";
import { DynamicDOMObserver } from "./observer";

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

export class DOMContentCollector {
  /**
   * Safe observation of DOM elements to extract EvidenceCollection.
   * STRICT PRIVACY GUARANTEE:
   * This collector NEVER accesses element.value, innerText, textContent, or raw user inputs.
   */
  public static collectFromDocument(doc: Document = document, pageUrl: string = location.href): EvidenceCollection {
    const manager = new ArtifactManager();
    const pageTitle = doc.title || "";
    manager.createPageArtifact(pageUrl, pageTitle);

    // Collect Forms and Inputs
    const forms = doc.querySelectorAll("form");
    if (forms.length > 0) {
      forms.forEach((formEl) => {
        const action = formEl.getAttribute("action") || "";
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
    } else {
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

    return manager.exportCollection();
  }
}

/**
 * Handle evidence collection, feature extraction, diagnostics recording,
 * and service worker handoff.
 */
export function handleCollectionCycle(doc: Document = document): EvidenceCollection {
  setLocalDiagnostic("data-capstone-evidence-handoff", "collector_started");

  const collection = DOMContentCollector.collectFromDocument(doc);
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

    // 3. Dynamic DOM mutation observation for runtime changes
    const observer = new DynamicDOMObserver(() => {
      handleCollectionCycle(document);
    }, 80, document);
    observer.start();

  } catch (err) {
    const details = err instanceof Error ? err.message : String(err);
    setLocalDiagnostic("data-capstone-evidence-handoff", `collector_error:${details}`);
    console.warn("[CAPSTONE-1] Content Collector execution:", err);
  }
}
