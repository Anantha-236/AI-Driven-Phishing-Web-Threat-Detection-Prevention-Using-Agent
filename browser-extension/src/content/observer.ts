import { DOMContentCollector } from "./collector";
import { EvidenceCollection } from "../core/schema/types";

export type OnEvidenceCallback = (evidence: EvidenceCollection) => void;

export class DynamicDOMObserver {
  private observer: MutationObserver | null = null;
  private debounceTimer: ReturnType<typeof setTimeout> | null = null;
  private debounceMs: number;
  private onEvidence: OnEvidenceCallback;
  private doc: Document;

  constructor(onEvidence: OnEvidenceCallback, debounceMs: number = 150, doc: Document = typeof document !== "undefined" ? document : ({} as Document)) {
    this.onEvidence = onEvidence;
    this.debounceMs = debounceMs;
    this.doc = doc;
  }

  public start(): void {
    if (this.observer || !this.doc) return;

    const MutationObserverImpl =
      typeof window !== "undefined" && window.MutationObserver
        ? window.MutationObserver
        : typeof MutationObserver !== "undefined"
          ? MutationObserver
          : null;

    if (!MutationObserverImpl) return;

    this.observer = new MutationObserverImpl((mutations) => {
      let isRelevant = false;

      for (const mutation of mutations) {
        if (mutation.type === "childList") {
          mutation.addedNodes.forEach((node) => {
            if (node.nodeType === 1) { // ELEMENT_NODE
              const el = node as HTMLElement;
              const tagName = el.tagName ? el.tagName.toLowerCase() : "";
              if (
                ["form", "input", "select", "textarea"].includes(tagName) ||
                (el.querySelector && el.querySelector("form, input, select, textarea"))
              ) {
                isRelevant = true;
              }
            }
          });

          mutation.removedNodes.forEach((node) => {
            if (node.nodeType === 1) { // ELEMENT_NODE
              const el = node as HTMLElement;
              const tagName = el.tagName ? el.tagName.toLowerCase() : "";
              if (["form", "input", "select", "textarea"].includes(tagName)) {
                isRelevant = true;
              }
            }
          });
        } else if (mutation.type === "attributes") {
          const attr = mutation.attributeName ? mutation.attributeName.toLowerCase() : "";
          if (["type", "action", "autocomplete", "method", "src", "name", "id"].includes(attr)) {
            isRelevant = true;
          }
        }

        if (isRelevant) break;
      }

      if (isRelevant) {
        this.scheduleTrigger();
      }
    });

    const targetNode = this.doc.body || this.doc.documentElement || this.doc;
    if (targetNode && typeof targetNode.nodeType !== "undefined") {
      this.observer.observe(targetNode, {
        childList: true,
        subtree: true,
        attributes: true,
        attributeFilter: ["type", "action", "autocomplete", "method", "src", "name", "id"]
      });
    }
  }

  public triggerImmediate(): void {
    try {
      const evidence = DOMContentCollector.collectFromDocument(this.doc);
      this.onEvidence(evidence);
    } catch (err) {
      console.warn("[CAPSTONE-1] DOM collection trigger error:", err);
    }
  }

  private scheduleTrigger(): void {
    if (this.debounceTimer) {
      clearTimeout(this.debounceTimer);
    }

    this.debounceTimer = setTimeout(() => {
      this.triggerImmediate();
    }, this.debounceMs);
  }

  public stop(): void {
    if (this.observer) {
      this.observer.disconnect();
      this.observer = null;
    }
    if (this.debounceTimer) {
      clearTimeout(this.debounceTimer);
      this.debounceTimer = null;
    }
  }
}
