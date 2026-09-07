import { defineConfig, devices } from "@playwright/test";

const port = 3789;

export default defineConfig({
  testDir: "./e2e",
  timeout: 60_000,
  retries: 0,
  reporter: [["list"]],
  use: {
    baseURL: `http://localhost:${port}`,
    trace: "retain-on-failure",
  },
  webServer: {
    command: `SKP_E2E_ECHO=1 SKP_ALLOW_CLIENT_LAYOUT=1 PORT=${port} node server.mjs`,
    port,
    reuseExistingServer: false,
    timeout: 30_000,
  },
  projects: [
    { name: "iphone-webkit", use: { ...devices["iPhone 13"] } },
    { name: "pixel-chromium", use: { ...devices["Pixel 7"] } },
    { name: "desktop-chromium", use: { ...devices["Desktop Chrome"] } },
  ],
});
