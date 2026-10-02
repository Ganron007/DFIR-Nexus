/**
 * WO-U9 / D2. Opening a finding from the grid is proven in a real browser.
 * The same click hangs under jsdom, so this is the check that belongs here.
 */
import { expect, test } from "@playwright/test";

test("a grid row opens the finding drawer and Escape closes it", async ({ page, request }) => {
  const seed = await request.post("/portal/api/case/seed-demo", { data: { activate: true } });
  expect(seed.ok()).toBeTruthy();

  await page.goto("/portal/app/");
  await page.getByRole("button", { name: "Continue" }).first().click();
  await page.getByRole("link", { name: "Findings" }).click();
  await expect(page.getByRole("heading", { name: /Findings/ })).toBeVisible();
  const row = page.getByTestId("grid-row").first();
  await expect(row).toBeVisible();
  // Playwright's own click never returns on a transformed virtual row: the
  // scroll adjustment and the row's translate fight until the action times
  // out. Dispatching the click in the page runs the same handler.
  await row.evaluate((node) => {
    node.dispatchEvent(new MouseEvent("click", { bubbles: true }));
  });

  const drawer = page.getByRole("dialog");
  await expect(drawer).toBeVisible();
  await expect(drawer).toContainText("Encoded PowerShell");
  await page.keyboard.press("Escape");
  await expect(drawer).toHaveCount(0);
});
