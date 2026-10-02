/**
 * Phase 4f L3 — UI flow E2E (design vs the actual SPA).
 *
 * Each test sets up its own state through the API (`request`), so the suite
 * is order-independent. The server runs with an isolated case store under
 * `e2e/.runtime` (see playwright.config.ts).
 */
import { test, expect, type APIRequestContext } from "@playwright/test";
import fs from "fs";
import os from "os";
import path from "path";

const APP = "/portal/app";

function makeEvidenceFile(label: string): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "nexus-e2e-"));
  const file = path.join(dir, `${label}.txt`);
  fs.writeFileSync(file, `e2e evidence ${label}\n`);
  return file;
}

async function deactivate(request: APIRequestContext): Promise<void> {
  await request.post("/portal/api/case/deactivate");
}

/** Enter the cockpit through the UI and open a page by its nav label. */
async function openPage(page: import("@playwright/test").Page, linkName: string) {
  await page.goto(`${APP}/`);
  await page.getByRole("button", { name: "Continue" }).first().click();
  // Nav links carry a stage prefix (e.g. "N2 Evidence").
  await page.getByRole("link", { name: linkName }).first().click();
  // Not every surface has an h2 (Steer Chat on a Mode 2 case does not).
  await expect(page.getByRole("navigation")).toBeVisible();
}

test.beforeEach(async ({ request }) => {
  await deactivate(request);
});

test("cockpit route guard redirects to the dashboard without an active case", async ({ page }) => {
  await page.goto(`${APP}/explore`);
  await expect(page).toHaveURL(/\/portal\/app\/?$/);
  await expect(page.getByRole("heading", { name: "Case Dashboard" })).toBeVisible();
  // no cockpit spine without a case
  await expect(page.getByRole("link", { name: "Evidence" })).toHaveCount(0);
});

test("seed demo never activates until Enter; Exit detaches", async ({ page }) => {
  await page.goto(`${APP}/`);

  await page.getByRole("button", { name: /Seed Demo Investigation/i }).click();
  await expect(page.getByText(/Seeded CASE-DEMO-001/)).toBeVisible({ timeout: 30_000 });

  // The demo is labelled synthetic (mock evidence, no parsers ran).
  await expect(
    page.locator("tr", { hasText: "CASE-DEMO-001" }).getByText("synthetic")
  ).toBeVisible();

  // Seeded but NOT active — no Exit control anywhere.
  await expect(page.getByRole("button", { name: /Exit to Dashboard/i })).toHaveCount(0);

  // Preview the row, then Enter explicitly.
  await page.locator("tr", { hasText: "CASE-DEMO-001" }).first().click();
  await expect(page.getByText(/Preview:/)).toBeVisible();
  await page.getByRole("button", { name: /Enter Investigation/i }).click();

  await expect(page).toHaveURL(/\/case\/CASE-DEMO-001\/[a-z-]+$/);
  await expect(page.getByRole("link", { name: "Evidence" })).toBeVisible();

  // Exit to Dashboard clears the active case.
  await page.getByRole("button", { name: /Exit to Dashboard/i }).first().click();
  await expect(page).toHaveURL(/\/portal\/app\/?$/);
  await expect(page.getByRole("heading", { name: "Case Dashboard" })).toBeVisible();
});

test("registered evidence appears immediately in the Evidence page", async ({ page, request }) => {
  const seed = await request.post("/portal/api/case/seed-demo", { data: { activate: true } });
  expect(seed.ok()).toBeTruthy();

  const file = makeEvidenceFile("alpha");
  await openPage(page, "Evidence");
  await expect(page.getByRole("heading", { name: "Evidence Registry" })).toBeVisible();
  await expect(page.getByText("4 registered items")).toBeVisible();

  await page.getByRole("button", { name: /\+ Add evidence/i }).first().click();
  const pathInput = page.getByPlaceholder(/Type or paste a path/i);
  await pathInput.fill(file);
  await pathInput.press("Enter");
  await page.getByRole("button", { name: "Add This File" }).click();

  // The regression: evidence vanishes because the list read a dead registry.
  await expect(page.getByText(file, { exact: false })).toBeVisible({ timeout: 20_000 });
  await expect(page.getByText("5 registered items")).toBeVisible();
});

test("switching cases changes the data on screen", async ({ page, request }) => {
  await request.post("/portal/api/case/seed-demo", { data: { activate: true } });

  const created = await request.post("/portal/api/case/create", {
    data: { name: `E2E Switch ${Date.now()}` },
  });
  expect(created.ok()).toBeTruthy();
  const otherCase = (await created.json()).case_id as string;
  const otherFile = makeEvidenceFile("bravo");
  await request.post("/portal/api/evidence", {
    data: { path: otherFile, case_id: otherCase },
  });
  await request.post("/portal/api/case/mode", {
    data: { mode: "1", case_id: otherCase },
  });

  await openPage(page, "Evidence");
  await expect(page.getByText("4 registered items")).toBeVisible();

  // Explicit switch via the sidebar dropdown (selection switches directly).
  await page.getByLabel("Active case").selectOption(otherCase);

  await expect(page.getByText("1 registered item")).toBeVisible();
  await expect(page.getByText(otherFile, { exact: false })).toBeVisible();
});

test("the surfaces follow the case mode", async ({ page, request }) => {
  const created = await request.post("/portal/api/case/create", {
    data: { name: `E2E Mode ${Date.now()}`, activate: true },
  });
  expect(created.ok()).toBeTruthy();
  const caseId = (await created.json()).case_id as string;
  await request.post("/portal/api/case/mode", { data: { mode: "2", case_id: caseId } });

  // Steer Chat is the Mode 1 surface, so a Mode 2 case's nav carries the
  // Mode 2 entry point instead; the sidebar says which mode this case runs.
  await openPage(page, "Evidence");
  await expect(page.getByRole("link", { name: /Mode 2 ·/ })).toBeVisible();
});

test("wizard creates, registers, runs the lane, and enters the cockpit", async ({ page }) => {
  test.setTimeout(240_000);
  const file = makeEvidenceFile("wizard");
  const caseName = `E2E Wizard ${Date.now()}`;

  await page.goto(`${APP}/case-setup`);

  // Step 1 — details
  await page.getByPlaceholder(/Campaign H/i).fill(caseName);
  await page.getByRole("button", { name: /Create Case/i }).click();

  // Step 2 — register evidence by explicit path
  const pathInput = page.getByPlaceholder(/paste an absolute path/i);
  await pathInput.fill(file);
  await page.getByRole("button", { name: "Add path" }).click();
  await expect(page.getByText(/1 item\(s\) registered/i)).toBeVisible();
  await page.getByRole("button", { name: /Continue/i }).click();

  // Step 3 — mode
  await page.getByText(/Mode 1 — LLM/i).click();
  await page.getByRole("button", { name: /Confirm Mode/i }).click();

  // Step 4 — with evidence registered, cockpit entry is gated on the lane.
  await expect(page.getByRole("button", { name: /Enter Cockpit/i })).toHaveCount(0);
  await page.getByRole("button", { name: /Run N2 Pipeline/i }).click();
  await expect(page.getByText(/Parser lane:/i)).toBeVisible({ timeout: 180_000 });
  // The ledger shows what ran (a bare .txt honestly yields a discovery SKIP).
  await expect(page.locator("table").getByText("(discovery)")).toBeVisible();
  await page.getByRole("button", { name: /Enter Cockpit/i }).click();
  await expect(page).toHaveURL(/\/case\/[^/]+\/[a-z-]+$/);

  // The wizard's explicit-case registration is visible in the cockpit.
  await page.getByRole("link", { name: "Evidence" }).click();
  await expect(page.getByText("1 registered item")).toBeVisible();

  // Leave the store detached for the next test.
  await page.getByRole("button", { name: /Exit to Dashboard/i }).first().click();
  await expect(page.getByRole("heading", { name: "Case Dashboard" })).toBeVisible();
});
