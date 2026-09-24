import { describe, it, expect } from "vitest";
import {
  createTabDecisionStore,
  setTabDecision,
  getTabDecision,
  getActiveTabDecision,
} from "../../browser-extension/src/core/tab-state";

describe("tab decision tracking", () => {
  it("keeps decisions isolated by tab and returns the active tab result", () => {
    const store = createTabDecisionStore();

    setTabDecision(store, 10, {
      threatLevel: "suspicious",
      score: 0.81,
      action: "WARN",
      domain: "example.com",
      requestedDataTypes: ["EMAIL", "PASSWORD"],
    });

    setTabDecision(store, 11, {
      threatLevel: "benign",
      score: 0.12,
      action: "ALLOW",
      domain: "example.org",
      requestedDataTypes: ["USERNAME"],
    });

    expect(getTabDecision(store, 10)?.domain).toBe("example.com");
    expect(getTabDecision(store, 11)?.domain).toBe("example.org");
    expect(getActiveTabDecision(store, 10)?.action).toBe("WARN");
    expect(getActiveTabDecision(store, 11)?.action).toBe("ALLOW");
  });

  it("does not show another tab decision when the active tab is missing", () => {
    const store = createTabDecisionStore();

    setTabDecision(store, 3, {
      threatLevel: "malicious",
      score: 0.97,
      action: "BLOCK",
      domain: "phish.test",
      requestedDataTypes: ["PASSWORD", "OTP"],
    });

    expect(getTabDecision(store, 99)).toBeNull();
    expect(getActiveTabDecision(store, 99)).toBeNull();
  });
});
