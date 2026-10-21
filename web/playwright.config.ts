import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
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
    // The diagram tests again with other generic fonts (Liberation for sans, mono and system-ui): the
    // drawings ship their own fonts, so a phone or a desktop with other fonts draws what is tested.
    // PW_FONTCONFIG points at another setup (Android's Roboto and Droid Sans Mono, say) for a local run.
    ...(["desktop", "phone"] as const).map((n) => ({
      name: `${n}-fonts`,
      use: { ...devices[n === "desktop" ? "Desktop Chrome" : "Pixel 7"], launchOptions: { ...(executablePath ? { executablePath } : {}), env: { ...process.env, FONTCONFIG_FILE: process.env.PW_FONTCONFIG ?? fileURLToPath(new URL("./test/e2e/fonts/liberation.conf", import.meta.url)) } } },
      grep: /@fonts/,
    })),
  ],
  webServer: { command: "node scripts/serve.mjs --port 4290 --e2e", url: "http://127.0.0.1:4290/lab/", reuseExistingServer: !process.env.CI },
});
