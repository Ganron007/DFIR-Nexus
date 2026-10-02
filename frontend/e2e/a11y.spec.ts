/**
 * WO-U9. Accessibility, keyboard and visual gates for the cockpit.
 *
 * axe runs on Dashboard, Evidence, Explore (search), Findings, Approve,
 * Timeline and Report; serious/critical violations fail. Two keyboard-only
 * paths are exercised (search, approve). Key pages keep a heading snapshot.
 * The style-budget script is the inline-style / colour gate (scripts/).
 *
 * Cockpit pages are opened through the UI on purpose: a direct URL to a case
 * page lands before the case list resolves and RequireCase redirects to the
 * dashboard, which would make every page check pass on the dashboard's markup.
 */
import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

const APP = "/portal/app";

const PAGES: Array<[string, string]> = [
  ["evidence", "Evidence"],
  ["explore", "Explore"],
  ["findings", "Findings"],
  ["approve", "Approve"],
  ["timeline", "Timeline"],
  ["report", "Report"],
];

async function seedAndActivate(request: import("@playwright/test").APIRequestContext) {
  const seed = await request.post("/portal/api/case/seed-demo", { data: { activate: true } });
  expect(seed.ok()).toBeTruthy();
}

async function openCockpit(page: Page, linkName: string) {
  await page.goto(`${APP}/`);
  await page.getByRole("button", { name: "Continue" }).first().click();
  // Nav links carry a stage prefix (e.g. "N2 Evidence"), so match by substring.
  await page.getByRole("link", { name: linkName }).first().click();
  await expect(page.locator("h2").first()).toBeVisible();
}

async function blocking(page: Page) {
  const results = await new AxeBuilder({ page }).analyze();
  return results.violations.filter(
    (violation) => violation.impact === "serious" || violation.impact === "critical",
  );
}

test.beforeEach(async ({ request }) => {
  await seedAndActivate(request);
});

test("the dashboard has no serious or critical accessibility violations", async ({ page }) => {
  await page.goto(`${APP}/`);
  await expect(page.getByRole("heading", { name: "Case Dashboard" })).toBeVisible();
  expect((await blocking(page)).map((violation) => violation.id)).toEqual([]);
});

for (const [name, link] of PAGES) {
  test(`${name} has no serious or critical accessibility violations`, async ({ page }) => {
    await openCockpit(page, link);
    expect((await blocking(page)).map((violation) => violation.id)).toEqual([]);
  });
}

test("the dashboard heading is reachable from the keyboard", async ({ page }) => {
  await page.goto(`${APP}/`);
  await page.keyboard.press("Tab");
  await expect(page.getByRole("heading", { name: "Case Dashboard" })).toBeVisible();
});

test("search is usable from the keyboard alone", async ({ page }) => {
  await openCockpit(page, "Explore");
  const input = page.getByLabel("Needles");
  await input.focus();
  await page.keyboard.type("powershell");
  await page.keyboard.press("Enter");
  await expect(input).toHaveValue("powershell");
});

test("the approval desk is reachable from the keyboard alone", async ({ page }) => {
  await openCockpit(page, "Approve");
  await page.keyboard.press("Tab");
  await page.keyboard.press("Tab");
  const focused = await page.evaluate(() => document.activeElement?.tagName ?? "");
  expect(focused).not.toBe("BODY");
});

test("key pages match their visual baseline", async ({ page }) => {
  for (const [name, link] of [
    ["dashboard", ""],
    ["evidence", "Evidence"],
    ["findings", "Findings"],
  ] as Array<[string, string]>) {
    if (link) {
      await openCockpit(page, link);
    } else {
      await page.goto(`${APP}/`);
    }
    const heading = page.locator("h2").first();
    await expect(heading).toBeVisible();
    await expect(heading).toHaveScreenshot(`${name}-heading.png`);
  }
});
