import { chromium } from "playwright";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, "..");
const extensionPath = resolve(repoRoot, "dist");
const serverScript = resolve(repoRoot, "scripts", "manual-browser-acceptance-server.mjs");
const base = "http://127.0.0.1:41731";

const scenarios = [
  {
    id: "benign",
    path: "/benign",
    expected: {
      has_password_field: true,
      has_otp_field: false,
      cross_domain_form: false,
      form_count: 1,
      input_count: 2,
    },
  },
  {
    id: "suspicious",
    path: "/suspicious",
    expected: {
      has_password_field: true,
      has_otp_field: true,
      cross_domain_form: true,
      form_count: 1,
      input_count: 3,
    },
  },
  {
    id: "high-risk",
    path: "/high-risk",
    expected: {
      has_password_field: true,
      has_otp_field: true,
      cross_domain_form: true,
      form_count: 1,
      input_count: 4,
    },
  },
];

function startScenarioServer() {
  return new Promise((resolveServer, rejectServer) => {
    const child = spawn(process.execPath, [serverScript], {
      cwd: repoRoot,
      stdio: ["ignore", "pipe", "pipe"],
    });

    let ready = false;
    child.stdout.on("data", (data) => {
      const text = String(data);
      process.stdout.write(`[scenario-server] ${text}`);
      if (!ready && text.includes("CAPSTONE_MANUAL_SERVER_READY")) {
        ready = true;
        resolveServer(child);
      }
    });
    child.stderr.on("data", (data) => process.stderr.write(`[scenario-server:err] ${String(data)}`));
    child.on("exit", (code) => {
      if (!ready) rejectServer(new Error(`Scenario server exited before ready (code=${code ?? "null"})`));
    });
    setTimeout(() => {
      if (!ready) rejectServer(new Error("Scenario server readiness timeout after 10s"));
    }, 10000);
  });
}

async function waitForServiceWorker(context, timeoutMs = 15000) {
  const existing = context.serviceWorkers();
  if (existing.length > 0) return existing[0];
  return await context.waitForEvent("serviceworker", { timeout: timeoutMs });
}

(async () => {
  const result = {
    feature_generation: "PASS",
    scenarios: [],
    first_failed_component: "none",
    exact_error: "",
  };

  let context;
  let server;

  try {
    server = await startScenarioServer();

    const userDataDir = mkdtempSync(join(tmpdir(), "capstone1-feature-check-"));
    context = await chromium.launchPersistentContext(userDataDir, {
      channel: "chromium",
      headless: true,
      args: [
        `--disable-extensions-except=${extensionPath}`,
        `--load-extension=${extensionPath}`,
      ],
    });

    await waitForServiceWorker(context, 15000);

    const page = context.pages()[0] ?? (await context.newPage());

    for (const scenario of scenarios) {
      await page.goto(`${base}${scenario.path}`, { waitUntil: "domcontentloaded", timeout: 15000 });
      await page.waitForTimeout(1200);

      const diag = await page.evaluate(() => {
        return {
          handoff: document.documentElement.getAttribute("data-capstone-evidence-handoff") || "",
          featureMeta: document.documentElement.getAttribute("data-capstone-feature-meta") || "",
          evidenceMeta: document.documentElement.getAttribute("data-capstone-evidence-meta") || "",
        };
      });

      if (!diag.featureMeta) {
        result.feature_generation = "FAIL";
        result.first_failed_component = "feature_generation";
        result.exact_error = `Missing feature diagnostics on ${scenario.id}`;
        throw new Error(result.exact_error);
      }

      const actual = JSON.parse(diag.featureMeta);
      const checks = {
        has_password_field: actual.has_password_field === scenario.expected.has_password_field,
        has_otp_field: actual.has_otp_field === scenario.expected.has_otp_field,
        cross_domain_form: actual.cross_domain_form === scenario.expected.cross_domain_form,
        form_count: actual.form_count === scenario.expected.form_count,
        input_count: actual.input_count === scenario.expected.input_count,
      };

      const ok = Object.values(checks).every(Boolean);
      result.scenarios.push({
        scenario: scenario.id,
        expected: scenario.expected,
        actual,
        checks,
        handoff: diag.handoff,
        evidenceMeta: diag.evidenceMeta ? JSON.parse(diag.evidenceMeta) : null,
        status: ok ? "PASS" : "FAIL",
      });

      if (!ok) {
        result.feature_generation = "FAIL";
        result.first_failed_component = "feature_generation";
        result.exact_error = `Feature mismatch on ${scenario.id}`;
        throw new Error(result.exact_error);
      }
    }
  } catch (error) {
    if (!result.exact_error) {
      result.feature_generation = "FAIL";
      result.first_failed_component = "feature_generation";
      result.exact_error = error instanceof Error ? error.message : String(error);
    }
  } finally {
    if (context) await context.close();
    if (server) server.kill("SIGTERM");

    console.log("CAPSTONE_FEATURE_VECTOR_CHECK_START");
    console.log(JSON.stringify(result, null, 2));
    console.log("CAPSTONE_FEATURE_VECTOR_CHECK_END");

    if (result.feature_generation !== "PASS") {
      process.exitCode = 1;
    }
  }
})();
