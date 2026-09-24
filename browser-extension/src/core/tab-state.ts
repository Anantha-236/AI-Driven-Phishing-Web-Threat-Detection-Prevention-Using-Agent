export interface TabDecisionSnapshot {
  threatLevel: string;
  score: number;
  action: string;
  domain: string;
  requestedDataTypes: string[];
}

export type TabDecisionStore = {
  byTab: Map<number, TabDecisionSnapshot>;
  activeTabId: number | null;
  lastKnown: TabDecisionSnapshot | null;
};

export function createTabDecisionStore(): TabDecisionStore {
  return {
    byTab: new Map<number, TabDecisionSnapshot>(),
    activeTabId: null,
    lastKnown: null,
  };
}

export function setTabDecision(
  store: TabDecisionStore,
  tabId: number,
  decision: TabDecisionSnapshot
): void {
  store.byTab.set(tabId, decision);
  store.activeTabId = tabId;
  store.lastKnown = decision;
}

export function getTabDecision(
  store: TabDecisionStore,
  tabId: number
): TabDecisionSnapshot | null {
  return store.byTab.get(tabId) ?? null;
}

export function getActiveTabDecision(
  store: TabDecisionStore,
  tabId: number | null
): TabDecisionSnapshot | null {
  if (tabId !== null) {
    const exact = getTabDecision(store, tabId);
    return exact;
  }


  return null;
}
