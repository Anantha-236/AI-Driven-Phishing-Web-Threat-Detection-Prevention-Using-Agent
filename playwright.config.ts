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
  use: {
    headless: true,
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
