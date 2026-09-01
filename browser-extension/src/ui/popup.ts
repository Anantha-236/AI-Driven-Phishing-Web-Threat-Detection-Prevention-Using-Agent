/**
 * CAPSTONE-1 Popup UI Logic
 *
 * Receives and renders threat assessment messages from the background service worker
 * with clear explainability reasons, confidence, and action controls.
 */

console.log("[CAPSTONE-1] Popup initialized");

interface ThreatMessage {
  threatLevel: "benign" | "suspicious" | "malicious" | "insufficient_evidence";
  score: number;
  confidence: number;
  reasons: string[];
  action: string;
  outcome: string;
  domain: string;
  requestedDataTypes?: string[];
}

/**
 * Display threat assessment in the UI.
 */
function displayThreat(msg: ThreatMessage) {
  const container = document.getElementById("threat-container");
  const statusIdle = document.getElementById("status-idle");

  if (!container || !statusIdle) return;

  container.style.display = "block";
  statusIdle.style.display = "none";

  const levelEl = document.getElementById("threat-level");
  if (levelEl) {
    const formatted = msg.threatLevel.replace(/_/g, " ").toUpperCase();
    levelEl.textContent = formatted;
    levelEl.className = `threat-level ${msg.threatLevel}`;
  }

  const scoreEl = document.getElementById("score");
  if (scoreEl) {
    scoreEl.textContent = msg.score.toFixed(2);
  }

  const confidenceEl = document.getElementById("confidence");
  if (confidenceEl) {
    confidenceEl.textContent = String(Math.round(msg.confidence * 100));
  }

  const barEl = document.getElementById("confidence-bar") as HTMLElement;
  if (barEl) {
    barEl.style.width = `${Math.max(5, msg.confidence * 100)}%`;
  }

  const domainEl = document.getElementById("domain");
  if (domainEl) {
    domainEl.textContent = msg.domain || "Unknown Domain";
  }

  const dataCatEl = document.getElementById("data-categories");
  if (dataCatEl) {
    if (msg.requestedDataTypes && msg.requestedDataTypes.length > 0) {
      dataCatEl.textContent = msg.requestedDataTypes.join(", ");
    } else {
      dataCatEl.textContent = "None detected";
    }
  }

  const actionEl = document.getElementById("action");
  if (actionEl) {
    actionEl.textContent = msg.action;
  }

  const outcomeEl = document.getElementById("outcome");
  if (outcomeEl) {
    outcomeEl.textContent = msg.outcome;
  }

  const reasonsList = document.getElementById("reasons-list");
  if (reasonsList) {
    reasonsList.innerHTML = msg.reasons
      .map((r) => `<li>${htmlEscape(r.replace(/_/g, " "))}</li>`)
      .join("");
  }
}

/**
 * Escape HTML to prevent XSS.
 */
function htmlEscape(text: string): string {
  const div = document.createElement("div");
  div.textContent = text;
  return div.innerHTML;
}

// 1. Listen for real-time messages from the service worker
if (typeof chrome !== "undefined" && chrome.runtime?.onMessage) {
  chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
    try {
      if (message.type === "POLICY_DECISION" && message.payload) {
        console.log("[CAPSTONE-1 Popup] Received real-time threat decision:", message.payload);
        displayThreat(message.payload as ThreatMessage);
      }
    } catch (error) {
      console.error("[CAPSTONE-1 Popup] Error processing message:", error);
    }
    sendResponse({ ok: true });
  });

  // 2. Query latest decision on popup opening
  chrome.runtime.sendMessage({ type: "GET_LATEST_DECISION" }, (response) => {
    if (response && response.ok && response.detection) {
      displayThreat(response.detection as ThreatMessage);
    }
  });
}

const allowBtn = document.getElementById("btn-allow");
if (allowBtn) {
  allowBtn.addEventListener("click", () => {
    console.log("[CAPSTONE-1 Popup] User acknowledged allow action");
  });
}

const reportBtn = document.getElementById("btn-report");
if (reportBtn) {
  reportBtn.addEventListener("click", () => {
    console.log("[CAPSTONE-1 Popup] User reported site");
  });
}

console.log("[CAPSTONE-1] Popup UI ready");
