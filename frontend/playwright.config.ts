import { defineConfig } from "@playwright/test";
import { fileURLToPath } from "url";
import path from "path";

const here = path.dirname(fileURLToPath(import.meta.url));
const runtime = path.join(here, "e2e", ".runtime");
const port = process.env.NEXUS_E2E_PORT || "4508";
const baseURL = `http://127.0.0.1:${port}`;

/**
 * Phase 4f L3 — UI flow E2E.
 *
 * Uses the installed Chrome (no bundled browser download). The web server is
 * a real `nexus serve --http --dev` with an isolated case store under
 * `e2e/.runtime`, so UI runs never touch the examiner's real cases.
 */
export default defineConfig({
  testDir: "./e2e",
  outputDir: path.join(runtime, "test-results"),
  timeout: 90_000,
  expect: { timeout: 15_000 },
  fullyParallel: false,
  workers: 1,
  reporter: [["list"]],
  use: {
    baseURL,
    channel: "chrome",
    headless: true,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  webServer: {
    command: `npm run build && python -m nexus serve --http --dev --port ${port}`,
    cwd: here,
    url: `${baseURL}/health`,
    reuseExistingServer: false,
    timeout: 240_000,
    env: {
      NEXUS_CASES_ROOT: path.join(runtime, "cases"),
      NEXUS_DATA_ROOT: path.join(runtime, "data"),
      NEXUS_ACTIVE_CASE_FILE: path.join(runtime, "active_case"),
      NEXUS_DEBUG_AUTOCLEAN: "1",
      NEXUS_SIFT_SYNC: "0",
      NEXUS_ES_AUTOINDEX: "0",
      NEXUS_N4_BACKEND: "csv",
      NEXUS_RAG_PRELOAD: "0",
      NEXUS_REPO_EXPORT: "0",
      NEXUS_PORTAL_RATE_LIMIT: "100000",
      NEXUS_PORTAL_AUTH_RATE_LIMIT: "100000",
    },
  },
});
