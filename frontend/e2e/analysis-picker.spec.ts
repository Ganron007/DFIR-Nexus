/**
 * WO-1C item 5 - the mode picker on the case cockpit, as the examiner uses it.
 *
 * The server is the real `nexus serve --http --dev` with an isolated case store. No LLM is
 * configured for the test server, so a run that needs a model is refused or fails, and the page
 * must say so: the journey checks what the examiner sees, not a canned success.
 */
import fs from "fs";
import os from "os";
import path from "path";

import { expect, test, type APIRequestContext, type Page } from "@playwright/test";

const APP = "/portal/app";

function makeEvidenceFile(label: string): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "nexus-e2e-"));
  const file = path.join(dir, `${label}.txt`);
  fs.writeFileSync(file, `e2e evidence ${label}\n`);
  return file;
}

/** A case with one registered item, mode 1 as the UI default, activated. */
async function freshCase(request: APIRequestContext, label: string): Promise<string> {
  const created = await request.post("/portal/api/case/create", {
    data: { name: `E2E ${label} ${Date.now()}`, activate: true },
  });
  expect(created.ok()).toBeTruthy();
  const caseId = (await created.json()).case_id as string;
  await request.post("/portal/api/evidence", {
    data: { path: makeEvidenceFile(label), case_id: caseId },
  });
  await request.post("/portal/api/case/mode", { data: { mode: "1", case_id: caseId } });
  return caseId;
}

/** Enter the cockpit through the Overview, then open the Analysis page from the nav. */
async function openAnalysis(page: Page) {
  await page.goto(`${APP}/`);
  await page.getByRole("button", { name: "Continue" }).first().click();
  await page.getByRole("link", { name: /Analysis/ }).first().click();
  await expect(page.getByRole("heading", { name: "Analysis" })).toBeVisible();
}

test.beforeEach(async ({ request }) => {
  await request.post("/portal/api/case/deactivate");
});

test("the picker offers the three modes and both contexts, and Run waits for a choice", async ({ page, request }) => {
  await freshCase(request, "picker");
  await openAnalysis(page);

  for (const mode of ["Mode 1", "Mode 2", "Mode 3"]) {
    await expect(page.getByRole("checkbox", { name: new RegExp(mode) })).toBeVisible();
  }
  await expect(page.getByRole("radio", { name: /Independent/ })).toBeChecked();
  await expect(page.getByRole("radio", { name: /Informed/ })).not.toBeChecked();

  const run = page.getByRole("button", { name: /^Run/ });
  await expect(run).toBeDisabled();
  await page.getByRole("checkbox", { name: /Mode 2/ }).check();
  await expect(run).toBeEnabled();
  await expect(run).toHaveText("Run");

  await page.getByRole("checkbox", { name: /Mode 1/ }).check();
  await page.getByRole("checkbox", { name: /Mode 3/ }).check();
  await expect(run).toHaveText("Run all three (1 → 2 → 3)");
});

test("running one mode sends the chosen context and shows that run's own outcome", async ({ page, request }) => {
  await freshCase(request, "one-mode");
  await openAnalysis(page);

  await page.getByRole("checkbox", { name: /Mode 2/ }).check();
  await page.getByRole("radio", { name: /Informed/ }).check();
  const sent = page.waitForRequest(
    (req) => req.method() === "POST" && req.url().endsWith("/portal/api/mode2/run"),
  );
  await page.getByRole("button", { name: /^Run$/ }).click();

  const request2 = await sent;
  expect(request2.postDataJSON()).toMatchObject({ context: "informed" });

  // The row names the mode and says what happened: refused at the start, or a run that ended.
  const row = page.getByTestId("analysis-row-2");
  await expect(row).toBeVisible();
  await expect(row).toContainText(/refused|failed|complete|still running|running/);
});

test("running all three stops at the first mode that does not complete and starts no later mode", async ({ page, request }) => {
  test.setTimeout(180_000);
  await freshCase(request, "all-three");
  await openAnalysis(page);

  for (const mode of ["Mode 1", "Mode 2", "Mode 3"]) {
    await page.getByRole("checkbox", { name: new RegExp(mode) }).check();
  }

  const starts: string[] = [];
  page.on("request", (req) => {
    if (req.method() !== "POST") return;
    const url = req.url();
    if (/\/portal\/api\/(pipeline\/run|mode2\/run|mode3\/run)$/.test(url)) starts.push(url);
  });

  await page.getByRole("button", { name: /Run all three/ }).click();

  // This case has no lane run, so Mode 1 has nothing to interpret: the server refuses it at the
  // start, with the reason. The sequence then starts no later mode.
  const first = page.getByTestId("analysis-row-1");
  await expect(first.getByText("refused", { exact: true })).toBeVisible({ timeout: 30_000 });
  await expect(first).toContainText("No completed tools run in this case");
  await expect(page.getByTestId("analysis-row-2")).toContainText("not started");
  await expect(page.getByTestId("analysis-row-3")).toContainText("not started");
  expect(starts.filter((u) => /\/(mode2|mode3)\/run$/.test(u))).toEqual([]);
});
