import { chromium } from "playwright";
import { spawn, spawnSync } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const repoRoot = process.cwd();
const distDir = resolve(repoRoot, "dist");
const serverScript = resolve(repoRoot, "scripts", "manual-browser-acceptance-server.mjs");
const psqlPath = "C:\\Program Files\\PostgreSQL\\18\\bin\\psql.exe";

function runSql(sql) {
  const result = spawnSync(psqlPath, [
    "-h", "127.0.0.1",
    "-U", "postgres",
    "-d", "capstone1",
    "-tAc",
    sql,
  ], {
    encoding: "utf8",
    env: { ...process.env, PGPASSWORD: "54862" },
  });
  if (result.status !== 0) {
    throw new Error(result.stderr || `psql failed: ${sql}`);
  }
  return (result.stdout || "").trim();
}

function countObservations() {
  return Number(runSql("SELECT COUNT(*) FROM observations;")) || 0;
}

function readLatestRecords(limit = 10) {
  const sql = `SELECT observation_id, collection_id, page_domain, page_url_sanitized, is_https, form_count, input_count, script_count, requested_data_types, threat_level, model_score, policy_action, observed_at FROM observations ORDER BY observed_at DESC LIMIT ${limit};`;
  const output = runSql(sql).replace(/\r/g, "");
  return output ? output.split("\n").filter(Boolean) : [];
}

function startScenarioServer() {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [serverScript], {
      cwd: repoRoot,
      stdio: ["ignore", "pipe", "pipe"],
    });

    let ready = false;
    child.stdout.on("data", (data) => {
      const text = String(data);
      if (!ready && text.includes("CAPSTONE_MANUAL_SERVER_READY")) {
        ready = true;
        resolve(child);
      }
    });
    child.stderr.on("data", (data) => process.stderr.write(String(data)));
    child.on("exit", (code) => {
      if (!ready) reject(new Error(`Scenario server exited before ready (code=${code ?? "null"})`));
    });
    setTimeout(() => {
      if (!ready) reject(new Error("Scenario server readiness timeout after 10s"));
    }, 10000);
  });
}

(async () => {
  const beforeCount = countObservations();
  const server = await startScenarioServer();
  const userDataDir = mkdtempSync(join(tmpdir(), "capstone-scenario-proof-"));
  const context = await chromium.launchPersistentContext(userDataDir, {
    channel: "chromium",
    headless: true,
    args: [
      `--disable-extensions-except=${distDir}`,
      `--load-extension=${distDir}`,
    ],
  });

  const scenarios = ["/benign", "/suspicious", "/dynamic"];
  const results = [];

  for (const path of scenarios) {
    const page = await context.newPage();
    await page.goto(`http://127.0.0.1:41731${path}`, { waitUntil: "domcontentloaded", timeout: 30000 });
    await page.waitForTimeout(3000);
    const title = await page.title();
    const currentCount = countObservations();
    results.push({ path, title, observationsAfter: currentCount });
    await page.close();
  }

  const finalCount = countObservations();
  const latestRecords = readLatestRecords(10);

  console.log(JSON.stringify({ beforeCount, finalCount, delta: finalCount - beforeCount, scenarios: results, latestRecords }, null, 2));

  await context.close();
  server.kill("SIGTERM");
})();
