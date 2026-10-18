import { existsSync } from "node:fs";
import { defineConfig, devices } from "@playwright/test";

// The e2e tests run against the built site (npm run build) served by scripts/serve.mjs.
// PW_CHROMIUM_PATH points at a preinstalled Chromium where the bundled one is missing.
const executablePath = process.env.PW_CHROMIUM_PATH && existsSync(process.env.PW_CHROMIUM_PATH) ? process.env.PW_CHROMIUM_PATH : undefined;

export default defineConfig({
  testDir: "test/e2e",
  use: { baseURL: "http://127.0.0.1:4290", launchOptions: executablePath ? { executablePath } : {} },
  projects: [
    { name: "desktop", use: { ...devices["Desktop Chrome"] }, grepInvert: /@firefox/ },
    { name: "phone", use: { ...devices["Pixel 7"] }, grepInvert: /@firefox/ },
    // Firefox cannot animate between documents; the tests tagged @firefox check theme.ts plays the
    // slide by hand there.
    { name: "firefox", use: { ...devices["Desktop Firefox"], launchOptions: {} }, grep: /@firefox/ },
  ],
  webServer: { command: "node scripts/serve.mjs --port 4290", url: "http://127.0.0.1:4290/lab/", reuseExistingServer: !process.env.CI },
});
