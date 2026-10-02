/**
 * D3 / D7. The print guarantee, asserted where it can actually be read.
 *
 * The style-budget script already enforces this at build time, but it lives in
 * Python. `?raw` CSS imports do not resolve CSS modules under vitest, so this
 * reads the stylesheet from disk instead of re-importing it. Keeping a second,
 * independent assertion here means a change that removes the print block fails
 * the unit suite and not only the build gate.
 */
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

const here = path.dirname(fileURLToPath(import.meta.url));
const pages = path.resolve(here, "..", "pages");

function sheet(name: string): string {
  return readFileSync(path.join(pages, name), "utf-8");
}

describe("print guarantee", () => {
  it("the report ships a print block that inverts to ink on paper", () => {
    const css = sheet("Report.module.css");
    expect(css).toContain("@media print");
    const block = css.slice(css.indexOf("@media print"));
    expect(block).toMatch(/#000|color: #000|background: #fff/);
  });

  it("the report renders its provenance block", () => {
    const tsx = readFileSync(path.join(pages, "Report.tsx"), "utf-8");
    expect(tsx).toContain("report-provenance");
    expect(tsx).toContain("noPrint");
  });
});
