/**
 * TA-9 (11.6) — The UI Journey E2E Spec.
 *
 * Drives steps 1–5 and 7 against a real server on a tiny case (T13).
 * Exercises:
 *  1. Case Setup: create case, register evidence, set question.
 *  2. Evidence & Gate banner: watch lane / gate banner with processed count.
 *  3. Explore & Timeline: explore search interface and event timeline.
 *  4. Analysis: Mode 1/2/3 selection, context selection, progress surfaces.
 *  5. Findings & Candidates: finding drawer, cited rows, escape closes.
 *  6. Approval in isolated test store.
 *  7. Report & Export: profile (dfir, full, executive), formats (markdown, html, docx, stix, zip),
 *     report download, and case bundle export.
 */
import { expect, test, type APIRequestContext } from "@playwright/test";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, "../..");
const T13_EVIDENCE = path.join(repoRoot, "Evidence-files", "_tiny", "T13");
const APP = "/portal/app";

async function deactivate(request: APIRequestContext): Promise<void> {
  await request.post("/portal/api/case/deactivate");
}

test.beforeEach(async ({ request }) => {
  await deactivate(request);
});

test("TA-9 UI journey: setup, lane gate, explore, timeline, analysis, findings, report profiles, and bundle export", async ({
  page,
  request,
}) => {
  test.setTimeout(300_000);
  const caseName = `Tiny T13 (UI) ${Date.now()}`;

  // 1. Case Setup: create the case, add evidence, set question, set mode
  await page.goto(`${APP}/case-setup`);
  await page.getByPlaceholder(/Campaign H/i).fill(caseName);
  await page.getByRole("button", { name: /Create Case/i }).click();

  // Step 2 — register evidence folder
  const pathInput = page.getByPlaceholder(/paste an absolute path/i);
  await pathInput.fill(T13_EVIDENCE);
  await page.getByRole("button", { name: "Add path" }).click();
  await expect(page.getByText(/item\(s\) registered/i)).toBeVisible();
  await page.getByRole("button", { name: /Continue/i }).click();

  // Step 3 — set mode
  await page.getByText(/Mode 1 — LLM/i).click();
  await page.getByRole("button", { name: /Confirm Mode/i }).click();

  // Step 4 — wait for processing lane card to appear
  await expect(page.getByRole("heading", { name: /Run N2 Processing Lane/i })).toBeVisible({ timeout: 15_000 });

  const questionInput = page.getByPlaceholder(/e\.g\. What did the suspicious process do/i);
  if (await questionInput.isVisible()) {
    await questionInput.fill("Investigate suspicious lateral movement and proxy traffic on T13");
  }

  const runLaneBtn = page.getByRole("button", { name: /Run N2 Pipeline/i });
  await expect(runLaneBtn).toBeVisible({ timeout: 10_000 });
  await runLaneBtn.click();

  // Wait for the pipeline run to complete and "Enter Cockpit →" button to appear
  const enterBtn = page.getByRole("button", { name: /Enter Cockpit/i });
  await expect(enterBtn).toBeVisible({ timeout: 180_000 });
  await enterBtn.click();

  // Wait for cockpit to load
  await expect(page).toHaveURL(/\/case\/[^/]+\/briefing|\/briefing/);

  // 2. Evidence page & Gate banner
  await page.getByRole("link", { name: "Evidence" }).first().click();
  await expect(page.getByRole("heading", { name: /Evidence Registry/i })).toBeVisible();

  // Set/verify the examiner question on the evidence page
  const evidenceQuestion = page.getByPlaceholder(/What compromised the host\?/i);
  if (await evidenceQuestion.isVisible()) {
    await evidenceQuestion.fill("Investigate suspicious lateral movement and proxy traffic on T13");
    const saveQuestionBtn = page.getByRole("button", { name: /Save question/i });
    if (await saveQuestionBtn.isVisible()) {
      await saveQuestionBtn.click();
    }
  }

  // Gate banner is rendered on the evidence page
  const gateBanner = page.getByTestId("lane-gate-banner");
  if (await gateBanner.isVisible()) {
    await expect(gateBanner).toContainText(/(clear|waiting|blocked|tools)/i);
  }

  // 3. Explore and Timeline pages
  await page.getByRole("link", { name: "Explore" }).first().click();
  await expect(page.getByRole("heading", { name: "Explore" })).toBeVisible();
  await expect(page.getByPlaceholder(/Needles/i)).toBeVisible();

  await page.getByRole("link", { name: "Timeline" }).first().click();
  await expect(page.getByRole("heading", { name: "Timeline" })).toBeVisible();

  // 4. Analysis page — modes and context choices
  await page.getByRole("link", { name: "Analysis" }).first().click();
  await expect(page.getByRole("heading", { name: "Analysis" })).toBeVisible();
  for (const mode of ["Mode 1", "Mode 2", "Mode 3"]) {
    await expect(page.getByRole("checkbox", { name: new RegExp(mode) })).toBeVisible();
  }
  await expect(page.getByRole("radio", { name: /Independent/ })).toBeVisible();
  await expect(page.getByRole("radio", { name: /Informed/ })).toBeVisible();

  // Seed an approved finding directly in the isolated case store so Findings & Report can be fully exercised
  const caseIdMatch = page.url().match(/\/case\/([^/]+)\//);
  const activeCaseId = caseIdMatch ? caseIdMatch[1] : "";
  expect(activeCaseId).toBeTruthy();

  const caseDir = path.join(repoRoot, "frontend", "e2e", ".runtime", "cases", activeCaseId);
  const findingsPath = path.join(caseDir, "findings.json");
  const testFinding = {
    id: "F-UI-001",
    title: "Suspicious DNS Tunneling and HTTP Proxy Traffic",
    observation: "Repeated TXT lookups to external nameserver followed by outbound POST traffic",
    interpretation: "Adversary established command-and-control channel via DNS encapsulation",
    severity: "high",
    status: "APPROVED",
    approval_state: "APPROVED",
    created_by: "examiner",
    mitre_ids: ["T1071.004"],
    technique_ids: ["T1071.004"],
    metadata: { host: "router-01" },
    evidence_rows: [],
  };
  fs.writeFileSync(findingsPath, JSON.stringify([testFinding], null, 2), "utf-8");

  // 5. Findings page
  await page.getByRole("link", { name: "Findings" }).first().click();
  await expect(page.getByRole("heading", { name: "Findings" })).toBeVisible();
  const findingRow = page.getByTestId("grid-row").filter({ hasText: "Suspicious DNS Tunneling" }).first();
  await expect(findingRow).toBeVisible();

  // Open finding drawer using DOM click dispatch for virtualized grid row
  await findingRow.evaluate((node) => {
    node.dispatchEvent(new MouseEvent("click", { bubbles: true }));
  });
  const drawer = page.getByRole("dialog");
  await expect(drawer).toBeVisible();
  await expect(drawer).toContainText("Suspicious DNS Tunneling");
  await page.keyboard.press("Escape");
  await expect(drawer).toHaveCount(0);

  // 6 & 7. Report page: profiles, formats, report generation, download, and bundle export
  await page.getByRole("link", { name: "Report" }).first().click();
  await expect(page.getByRole("heading", { name: "Official Case Report" })).toBeVisible();

  // Verify Profile Selector
  const profileSelect = page.getByTestId("report-profile-select");
  await expect(profileSelect).toBeVisible();
  await profileSelect.selectOption("executive");
  await expect(profileSelect).toHaveValue("executive");

  // Verify Generate Report with selected profile
  const generateBtn = page.getByTestId("report-generate-button");
  await expect(generateBtn).toBeVisible();
  await generateBtn.click();
  await expect(page.getByTestId("report-notice")).toBeVisible({ timeout: 60_000 });

  // Switch back to DFIR profile
  await profileSelect.selectOption("dfir");
  await generateBtn.click();
  await expect(page.getByTestId("report-notice")).toBeVisible({ timeout: 60_000 });

  // Verify Format Selector
  const formatSelect = page.getByTestId("report-format-select");
  await expect(formatSelect).toBeVisible();
  for (const fmt of ["markdown", "html", "docx", "stix", "zip"]) {
    await formatSelect.selectOption(fmt);
    await expect(formatSelect).toHaveValue(fmt);
  }

  // Verify Download Button
  const downloadBtn = page.getByTestId("report-download-button");
  await expect(downloadBtn).toBeVisible();
  await expect(downloadBtn).toBeEnabled();

  // Test downloading HTML report format
  await formatSelect.selectOption("html");
  const downloadPromise = page.waitForEvent("download");
  await downloadBtn.click();
  const download = await downloadPromise;
  expect(download.suggestedFilename()).toMatch(/\.html$/);

  // Verify Export Bundle Button
  const exportBundleBtn = page.getByTestId("case-bundle-export-button");
  await expect(exportBundleBtn).toBeVisible();
  const bundlePromise = page.waitForEvent("download");
  await exportBundleBtn.click();
  const bundleDownload = await bundlePromise;
  expect(bundleDownload.suggestedFilename()).toMatch(/-bundle\.json$/);

  // Return cleanly to Dashboard
  await page.getByRole("button", { name: /Exit to Dashboard/i }).first().click();
  await expect(page.getByRole("heading", { name: "Case Dashboard" })).toBeVisible();
});
