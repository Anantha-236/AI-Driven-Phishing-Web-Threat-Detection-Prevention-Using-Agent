import { chromium } from "playwright";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawn } from "node:child_process";

const repoRoot = resolve(process.cwd());
const extensionPath = resolve(repoRoot, "dist");
const serverScript = resolve(repoRoot, "scripts", "manual-browser-acceptance-server.mjs");
const serverUrl = "http://127.0.0.1:41731/";

function startScenarioServer() {
  return new Promise((resolveServer, rejectServer) => {
    const child = spawn(process.execPath, [serverScript], {
      cwd: repoRoot,
      stdio: ["ignore", "pipe", "pipe"],
    });

    let settled = false;

    const onStdout = (data) => {
      const text = data.toString();
      process.stdout.write(`[scenario-server] ${text}`);
      if (!settled && text.includes("CAPSTONE_MANUAL_SERVER_READY")) {
        settled = true;
        resolveServer(child);
      }
    };

    const onStderr = (data) => {
      process.stderr.write(`[scenario-server:err] ${data.toString()}`);
    };

    child.stdout.on("data", onStdout);
    child.stderr.on("data", onStderr);

    child.on("exit", (code) => {
      if (!settled) {
        rejectServer(new Error(`Scenario server exited before ready. code=${code ?? "null"}`));
      }
    });

    setTimeout(() => {
      if (!settled) {
        settled = true;
        rejectServer(new Error("Scenario server readiness timeout after 10s"));
      }
    }, 10000);
  });
}

async function waitForServiceWorker(context, timeoutMs) {
  const existing = context.serviceWorkers();
  if (existing.length > 0) return existing[0];

  return await context.waitForEvent("serviceworker", { timeout: timeoutMs });
}

(async () => {
  const result = {
    extension: "FAIL",
    service_worker: "FAIL",
    content_script: "FAIL",
    evidence_creation: "FAIL",
    evidence_to_worker: "FAIL",
    message_send: {
      send_attempted: false,
      send_completed: false,
      send_error: "",
    },
    evidence_meta: null,
    first_failed_component: "extension",
    exact_error: "",
  };

  let context;
  let server;

  try {
    server = await startScenarioServer();

    const userDataDir = mkdtempSync(join(tmpdir(), "capstone1-pw-profile-"));

    context = await chromium.launchPersistentContext(userDataDir, {
      channel: "chromium",
      headless: true,
      args: [
        `--disable-extensions-except=${extensionPath}`,
        `--load-extension=${extensionPath}`,
      ],
    });

    const worker = await waitForServiceWorker(context, 15000);
    const extensionId = worker.url().split("/")[2] || "";
    result.extension = "PASS";
    result.service_worker = "PASS";

    let workerEvidenceSeen = false;
    worker.on("console", (msg) => {
      const text = msg.text();
      if (text.includes("[CAPSTONE-1] Evidence received from content script")) {
        workerEvidenceSeen = true;
      }
    });

    const page = context.pages()[0] ?? (await context.newPage());
    const cdp = await context.newCDPSession(page);
    const isolatedContexts = [];

    cdp.on("Runtime.executionContextCreated", (evt) => {
      const ctx = evt.context || {};
      const origin = ctx.origin || "";
      const auxType = ctx.auxData?.type || "";
      if (origin.startsWith(`chrome-extension://${extensionId}`) || auxType === "isolated") {
        isolatedContexts.push({ id: ctx.id, origin, auxType, name: ctx.name || "" });
      }
    });

    await cdp.send("Runtime.enable");

    await page.goto(serverUrl, { waitUntil: "domcontentloaded", timeout: 15000 });
    await page.waitForTimeout(1800);

    const isolatedContext = isolatedContexts.find((c) =>
      c.origin.startsWith(`chrome-extension://${extensionId}`),
    );

    if (!isolatedContext) {
      result.first_failed_component = "content_script";
      result.exact_error = "Extension isolated execution context was not observed on controlled page";
      throw new Error(result.exact_error);
    }

    const handshakeEval = await cdp.send("Runtime.evaluate", {
      contextId: isolatedContext.id,
      expression: `new Promise((resolve) => {
        try {
          chrome.runtime.sendMessage(
            { type: "PING", payload: { probe: "content-script-chain" } },
            (response) => resolve({ ok: true, response, lastError: chrome.runtime.lastError ? chrome.runtime.lastError.message : null })
          );
        } catch (error) {
          resolve({ ok: false, error: String(error) });
        }
      })`,
      awaitPromise: true,
      returnByValue: true,
    });

    const handshake = handshakeEval.result?.value;
    if (!handshake || !handshake.ok || !handshake.response || handshake.response.ok !== true) {
      result.first_failed_component = "content_script";
      result.exact_error = "Content-script runtime handshake to service worker failed";
      throw new Error(result.exact_error);
    }

    result.content_script = "PASS";

    const diag = await page.evaluate(() => {
      const marker = document.documentElement.getAttribute("data-capstone-evidence-handoff") || "";
      const meta = document.documentElement.getAttribute("data-capstone-evidence-meta") || "";
      return { marker, meta };
    });

    if (diag.marker.includes("evidence_created") || diag.marker.includes("send_")) {
      result.evidence_creation = "PASS";
    }

    if (diag.marker.includes("send_attempted") || diag.marker.includes("send_ok") || diag.marker.startsWith("send_error:")) {
      result.message_send.send_attempted = true;
    }
    if (diag.marker === "send_ok") {
      result.message_send.send_completed = true;
    }
    if (diag.marker.startsWith("send_error:")) {
      result.message_send.send_completed = false;
      result.message_send.send_error = diag.marker.slice("send_error:".length);
    }

    if (diag.meta) {
      try {
        result.evidence_meta = JSON.parse(diag.meta);
      } catch {
        result.evidence_meta = { parse_error: true, raw: diag.meta };
      }
    }

    await page.reload({ waitUntil: "domcontentloaded" });
    await page.waitForTimeout(1800);

    if (!workerEvidenceSeen) {
      result.first_failed_component = "evidence_handoff";
      result.exact_error = result.message_send.send_error
        ? `Evidence send failed before worker receipt: ${result.message_send.send_error}`
        : "No service-worker console evidence of EVIDENCE_COLLECTED message after content script collection";
      throw new Error(result.exact_error);
    }

    result.evidence_creation = "PASS";
    result.evidence_to_worker = "PASS";
    result.first_failed_component = "none";
    result.exact_error = "";
  } catch (error) {
    if (!result.exact_error) {
      result.exact_error = error instanceof Error ? error.message : String(error);
      if (result.first_failed_component === "extension") {
        result.first_failed_component = "extension_or_service_worker";
      }
    }
  } finally {
    if (context) {
      await context.close();
    }
    if (server) {
      server.kill("SIGTERM");
    }

    console.log("CAPSTONE_CHAIN_PROBE_RESULT_START");
    console.log(JSON.stringify(result, null, 2));
    console.log("CAPSTONE_CHAIN_PROBE_RESULT_END");

    if (result.first_failed_component !== "none") {
      process.exitCode = 1;
    }
  }
})();
