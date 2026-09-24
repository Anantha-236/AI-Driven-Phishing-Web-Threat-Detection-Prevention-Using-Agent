import { defineConfig, devices } from "@playwright/test";
import { resolve } from "node:path";

const distPath = resolve(process.cwd(), "dist");

export default defineConfig({
  testDir: "./tests/browser",
  timeout: 30000,
  expect: {
    timeout: 5000,
  },
  fullyParallel: false,
  workers: 1,
  reporter: [["list"]],
  webServer: [
    { command: 'python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --log-level warning --no-access-log', url: 'http://127.0.0.1:8000/api/v1/health', reuseExistingServer: true, timeout: 30000 },
    { command: 'node scripts/manual-browser-acceptance-server.mjs', url: 'http://127.0.0.1:41731', reuseExistingServer: true, timeout: 30000 },
  ],
  use: {
    headless: false,
    trace: "on-first-retry",
  },
  projects: [
    {
      name: "chromium-extension",
      use: {
        ...devices["Desktop Chrome"],
        launchOptions: {
          args: [
            `--disable-extensions-except=${distPath}`,
            `--load-extension=${distPath}`,
            "--no-sandbox",
          ],
        },
      },
    },
  ],
});
