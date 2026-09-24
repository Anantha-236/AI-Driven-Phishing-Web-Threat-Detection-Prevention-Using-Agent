export type OnEvidenceCallback = () => void;

function setObserverMarker(name: string, value: Record<string, unknown> | string): void {
  if (typeof document === "undefined") return;
  if (!(location.hostname === "127.0.0.1" && location.port === "41731")) return;

  const root = document.documentElement;
  if (!root) return;

  const payload = typeof value === "string" ? value : JSON.stringify(value);
  root.setAttribute(name, payload);
}

export class DynamicDOMObserver {
  private observer: MutationObserver | null = null;
  private onEvidence: OnEvidenceCallback;
  private doc: Document;

  constructor(onEvidence: OnEvidenceCallback, _debounceMs: number = 150, doc: Document = typeof document !== "undefined" ? document : ({} as Document)) {
    this.onEvidence = onEvidence;
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

    const targetNode: Node = this.doc;
    const targetName = targetNode === this.doc ? "document" : targetNode.nodeName;
    const targetExists = !!targetNode;
    const targetNodeName = targetNode && targetNode.nodeName ? targetNode.nodeName : "";

    setObserverMarker("data-capstone-observer-created", {
      timestamp: Date.now(),
      targetName,
      targetExists,
      targetNodeName,
    });

    this.observer = new MutationObserverImpl((mutations) => {
      const addedNodeCount = mutations.reduce((sum, mutation) => sum + Array.from(mutation.addedNodes).filter((node) => node.nodeType === 1).length, 0);
      const formCount = this.doc.querySelectorAll("form").length;
      const inputCount = this.doc.querySelectorAll("input").length;
      const callbackPayload = {
        timestamp: Date.now(),
        mutationRecordCount: mutations.length,
        addedNodeCount,
        formCount,
        inputCount,
      };

      setObserverMarker("data-capstone-observer-callback", callbackPayload);

      let isRelevant = false;

      for (const mutation of mutations) {
        if (mutation.type === "childList") {
          if ((mutation.target as Element).closest?.('title,h1,h2,button')) isRelevant = true;
          const nodes = [...mutation.addedNodes, ...mutation.removedNodes];
          for (const node of nodes) {
            if (node.nodeType !== 1) continue;

            const el = node as HTMLElement;
            const tagName = el.tagName ? el.tagName.toLowerCase() : "";
            if (
              ["form", "input", "select", "textarea", "base", "title", "h1", "h2", "button"].includes(tagName) ||
              (el.querySelector && el.querySelector("form, input, select, textarea, base, title, h1, h2, button"))
            ) {
              isRelevant = true;
              break;
            }
          }
        } else if (mutation.type === "characterData") {
          isRelevant = !!mutation.target.parentElement?.closest('title,h1,h2,button') &&
            !mutation.target.parentElement?.closest('input,textarea,select,[contenteditable]');
        } else if (mutation.type === "attributes") {
          const attr = mutation.attributeName ? mutation.attributeName.toLowerCase() : "";
          if (["type", "action", "autocomplete", "method", "src", "name", "id", "form", "formaction", "aria-label", "placeholder", "href"].includes(attr)) {
            isRelevant = true;
          }
        }

        if (isRelevant) break;
      }

      if (isRelevant) {
        this.triggerImmediate();
      }
    });

    if (targetNode && typeof targetNode.nodeType !== "undefined") {
      setObserverMarker("data-capstone-observer-observing", "before");

      try {
        this.observer.observe(targetNode, {
          childList: true,
          characterData: true,
          subtree: true,
          attributes: true,
          attributeFilter: ["type", "action", "autocomplete", "method", "src", "name", "id", "form", "formaction", "aria-label", "placeholder", "href"]
        });

        setObserverMarker("data-capstone-observer-started", {
          timestamp: Date.now(),
          targetName,
          targetExists,
          targetNodeName,
          observerOptions: {
            childList: true,
            subtree: true,
            attributes: true,
            attributeFilter: ["type", "action", "autocomplete", "method", "src", "name", "id", "form", "formaction", "aria-label", "placeholder", "href"],
          },
        });
        setObserverMarker("data-capstone-observer-observing", "success");
      } catch (error) {
        const msg = error instanceof Error ? error.name : "UNKNOWN_ERROR";
        setObserverMarker("data-capstone-observer-observing", `failure:${msg}`);
      }
    }
  }

  public triggerImmediate(): void {
    try {
      const formCount = this.doc.querySelectorAll("form").length;
      const inputCount = this.doc.querySelectorAll("input").length;
      setObserverMarker("data-capstone-recollection-start", {
        timestamp: Date.now(),
        formCount,
        inputCount,
      });

      this.onEvidence();
      setObserverMarker("data-capstone-recollection-end", {
        timestamp: Date.now(),
        formCount,
        inputCount,
      });
    } catch (err) {
      const details = err instanceof Error ? err.name : "UNKNOWN_ERROR";
      setObserverMarker("data-capstone-recollection-end", `failure:${details}`);
      console.warn("[CAPSTONE-1] DOM collection trigger error:", err);
    }
  }

  public stop(): void {
    if (this.observer) {
      this.observer.disconnect();
      this.observer = null;
    }
  }
}
