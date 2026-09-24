export type ObservableRoot = Document | ShadowRoot;

export function collectOpenRoots(doc: Document): ObservableRoot[] {
  const roots: ObservableRoot[] = [];
  const seen = new WeakSet<Node>();

  function visit(root: ObservableRoot): void {
    if (seen.has(root)) return;
    seen.add(root);
    roots.push(root);

    for (const element of Array.from(root.querySelectorAll('*'))) {
      const shadow = element.shadowRoot;
      if (shadow && shadow.mode === 'open') visit(shadow);
    }
  }

  visit(doc);
  return roots;
}

export function queryAcrossOpenRoots<T extends Element>(
  doc: Document,
  selector: string,
): T[] {
  const results: T[] = [];
  const seen = new WeakSet<Element>();

  for (const root of collectOpenRoots(doc)) {
    for (const element of Array.from(root.querySelectorAll<T>(selector))) {
      if (seen.has(element)) continue;
      seen.add(element);
      results.push(element);
    }
  }

  return results;
}
