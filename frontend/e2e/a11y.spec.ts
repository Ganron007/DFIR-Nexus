/**
 * WO-U9. Accessibility of the unauthenticated dashboard.
 * Serious and critical axe violations fail the check. The keyboard path
 * reaches the first heading without a pointer.
 */
import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

test("dashboard has no serious or critical accessibility violations", async ({ page }) => {
  await page.goto("/portal/app/");
  await expect(page.getByRole("heading", { name: "Case Dashboard" })).toBeVisible();
  const results = await new AxeBuilder({ page }).analyze();
  const blocking = results.violations.filter(
    (violation) => violation.impact === "serious" || violation.impact === "critical",
  );
  expect(blocking.map((violation) => violation.id)).toEqual([]);
});

test("the dashboard heading is reachable from the keyboard", async ({ page }) => {
  await page.goto("/portal/app/");
  await page.keyboard.press("Tab");
  const heading = page.getByRole("heading", { name: "Case Dashboard" });
  await expect(heading).toBeVisible();
});

test("the dashboard heading matches its visual baseline", async ({ page }) => {
  await page.goto("/portal/app/");
  const heading = page.getByRole("heading", { name: "Case Dashboard" });
  await expect(heading).toBeVisible();
  await expect(heading).toHaveScreenshot("dashboard-heading.png");
});
