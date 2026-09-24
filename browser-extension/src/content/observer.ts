import { collectOpenRoots, queryAcrossOpenRoots, type ObservableRoot } from './shadow-roots';

export type OnEvidenceCallback = () => void;

const RELEVANT_SELECTOR = 'form,input,select,textarea,base,title,h1,h2,button';
const ATTRIBUTE_FILTER = ['type', 'action', 'autocomplete', 'method', 'src', 'name', 'id', 'form', 'formaction', 'aria-label', 'placeholder', 'href'];

function setObserverMarker(name: string, value: Record<string, unknown> | string): void {
  if (typeof document === 'undefined') return;
  if (!(location.hostname === '127.0.0.1' && location.port === '41731')) return;

  const root = document.documentElement;
  if (!root) return;

  const payload = typeof value === 'string' ? value : JSON.stringify(value);
  root.setAttribute(name, payload);
}

function nodeContainsRelevantEvidence(node: Node): boolean {
  if (node.nodeType !== Node.ELEMENT_NODE) return false;
  const element = node as Element;
  const tagName = element.tagName.toLowerCase();
  if (['form', 'input', 'select', 'textarea', 'base', 'title', 'h1', 'h2', 'button'].includes(tagName)) return true;
  if (element.querySelector(RELEVANT_SELECTOR)) return true;
  return !!element.shadowRoot;
}

export class DynamicDOMObserver {
  private observers = new Map<ObservableRoot, MutationObserver>();
  private onEvidence: OnEvidenceCallback;
  private doc: Document;

  constructor(
    onEvidence: OnEvidenceCallback,
    _debounceMs: number = 150,
    doc: Document = typeof document !== 'undefined' ? document : ({} as Document),
  ) {
    this.onEvidence = onEvidence;
    this.doc = doc;
  }

  private mutationObserverConstructor(): typeof MutationObserver | null {
    return this.doc.defaultView?.MutationObserver ??
      (typeof MutationObserver !== 'undefined' ? MutationObserver : null);
  }

  private observeReachableRoots(): number {
    const MutationObserverImpl = this.mutationObserverConstructor();
    if (!MutationObserverImpl || typeof this.doc.querySelectorAll !== 'function') return 0;

    let added = 0;
    for (const root of collectOpenRoots(this.doc)) {
      if (this.observers.has(root)) continue;

      const observer = new MutationObserverImpl(mutations => this.handleMutations(mutations));
      observer.observe(root, {
        childList: true,
        characterData: true,
        subtree: true,
        attributes: true,
        attributeFilter: ATTRIBUTE_FILTER,
      });
      this.observers.set(root, observer);
      added++;
    }
    return added;
  }

  private handleMutations(mutations: MutationRecord[]): void {
    const discoveredRoots = this.observeReachableRoots();
    const addedNodeCount = mutations.reduce(
      (sum, mutation) => sum + Array.from(mutation.addedNodes).filter(node => node.nodeType === Node.ELEMENT_NODE).length,
      0,
    );

    setObserverMarker('data-capstone-observer-callback', {
      timestamp: Date.now(),
      mutationRecordCount: mutations.length,
      addedNodeCount,
      observedRootCount: this.observers.size,
      formCount: queryAcrossOpenRoots(this.doc, 'form').length,
      inputCount: queryAcrossOpenRoots(this.doc, 'input').length,
    });

    let isRelevant = discoveredRoots > 0;

    for (const mutation of mutations) {
      if (mutation.type === 'childList') {
        if ((mutation.target as Element).closest?.('title,h1,h2,button')) isRelevant = true;
        for (const node of [...mutation.addedNodes, ...mutation.removedNodes]) {
          if (nodeContainsRelevantEvidence(node)) {
            isRelevant = true;
            break;
          }
        }
      } else if (mutation.type === 'characterData') {
        isRelevant = !!mutation.target.parentElement?.closest('title,h1,h2,button') &&
          !mutation.target.parentElement?.closest('input,textarea,select,[contenteditable]');
      } else if (mutation.type === 'attributes') {
        const attribute = mutation.attributeName?.toLowerCase() ?? '';
        if (ATTRIBUTE_FILTER.includes(attribute)) isRelevant = true;
      }

      if (isRelevant) break;
    }

    if (isRelevant) this.triggerImmediate();
  }

  public start(): void {
    if (this.observers.size || typeof this.doc.querySelectorAll !== 'function') return;

    setObserverMarker('data-capstone-observer-created', {
      timestamp: Date.now(),
      targetName: 'document+open-shadow-roots',
      targetExists: true,
      targetNodeName: this.doc.nodeName,
    });
    setObserverMarker('data-capstone-observer-observing', 'before');

    try {
      this.observeReachableRoots();
      setObserverMarker('data-capstone-observer-started', {
        timestamp: Date.now(),
        targetName: 'document+open-shadow-roots',
        observedRootCount: this.observers.size,
        observerOptions: {
          childList: true,
          subtree: true,
          attributes: true,
          attributeFilter: ATTRIBUTE_FILTER,
        },
      });
      setObserverMarker('data-capstone-observer-observing', 'success');
    } catch (error) {
      const message = error instanceof Error ? error.name : 'UNKNOWN_ERROR';
      setObserverMarker('data-capstone-observer-observing', `failure:${message}`);
    }
  }

  public triggerImmediate(): void {
    try {
      this.observeReachableRoots();
      const formCount = queryAcrossOpenRoots(this.doc, 'form').length;
      const inputCount = queryAcrossOpenRoots(this.doc, 'input').length;
      setObserverMarker('data-capstone-recollection-start', {
        timestamp: Date.now(),
        formCount,
        inputCount,
        observedRootCount: this.observers.size,
      });

      this.onEvidence();
      setObserverMarker('data-capstone-recollection-end', {
        timestamp: Date.now(),
        formCount,
        inputCount,
        observedRootCount: this.observers.size,
      });
    } catch (error) {
      const details = error instanceof Error ? error.name : 'UNKNOWN_ERROR';
      setObserverMarker('data-capstone-recollection-end', `failure:${details}`);
      console.warn('[CAPSTONE-1] DOM collection trigger error:', error);
    }
  }

  public stop(): void {
    for (const observer of this.observers.values()) observer.disconnect();
    this.observers.clear();
  }
}
