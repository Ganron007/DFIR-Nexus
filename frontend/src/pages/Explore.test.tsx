/**
 * Frontend unit tests (WP 4.2 gap closure — the plan's "6 tests" claim was
 * stale; this is the real test runner + suite).
 *
 * Covers: Histogram downsampling, VirtualTable virtualization + rendering,
 * and the WP 4d.1 type-aware column picker.
 */
import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";

import Histogram from "../components/Histogram";
import VirtualTable from "../components/VirtualTable";
import { pickHitColumns } from "../lib/hitColumns";
import type { N4Hit } from "../api/client";

describe("Histogram", () => {
  it("renders nothing for empty buckets", () => {
    const { container } = render(<Histogram buckets={{}} />);
    expect(container.querySelector("div")).toBeNull();
  });

  it("renders one bar per bucket", () => {
    const { container } = render(
      <Histogram buckets={{ "2026-01-01T00:00": 3, "2026-01-01T01:00": 5 }} />,
    );
    expect(container.querySelectorAll("[title]").length).toBe(2);
  });

  it("downsamples long series by summing (no dropped events)", () => {
    const buckets: Record<string, number> = {};
    for (let i = 0; i < 100; i++) buckets[`h${String(i).padStart(3, "0")}`] = 1;
    const { container } = render(<Histogram buckets={buckets} maxBars={50} />);
    const bars = container.querySelectorAll("[title]");
    expect(bars.length).toBeLessThanOrEqual(50);
    // every displayed bar must carry a nonzero height — no silently dropped events
    const zeroBars = Array.from(bars).filter(
      (el) => (el as HTMLElement).style.height === "0%",
    );
    expect(zeroBars.length).toBe(0);
  });
});

describe("VirtualTable", () => {
  interface Row {
    id: number;
    name: string;
  }
  const rows: Row[] = Array.from({ length: 500 }, (_, i) => ({ id: i, name: `row-${i}` }));

  it("renders header + only the visible window of rows", () => {
    const { container } = render(
      <VirtualTable
        rows={rows}
        columns={[{ key: "name", header: "Name", render: (r: Row) => r.name }]}
        rowKey={(r: Row) => String(r.id)}
        maxHeight="280px"
      />,
    );
    expect(screen.getByText("Name")).toBeTruthy();
    const rendered = container.querySelectorAll("tbody tr").length;
    expect(rendered).toBeLessThan(100);
  });

  it("renders cell content via the column renderer", () => {
    render(
      <VirtualTable
        rows={[{ id: 1, name: "alpha" }]}
        columns={[{ key: "name", header: "Name", render: (r: Row) => r.name }]}
        rowKey={(r: Row) => String(r.id)}
      />,
    );
    expect(screen.getByText("alpha")).toBeTruthy();
  });
});

describe("pickHitColumns (WP 4d.1 type-aware columns)", () => {
  it("prefers family-specific parsed fields", () => {
    const hits: N4Hit[] = [
      { family: "evtx", file: "a", line: "1", terms: "", text: "", fields: { TimeCreated: "t", EventID: "4688", Computer: "WS01", Message: "x" } },
      { family: "evtx", file: "a", line: "2", terms: "", text: "", fields: { TimeCreated: "t2", EventID: "1102", Computer: "WS01" } },
    ];
    const cols = pickHitColumns(hits);
    expect(cols).toContain("TimeCreated");
    expect(cols).toContain("EventID");
    expect(cols.length).toBeLessThanOrEqual(4);
  });

  it("falls back to first available fields for unknown families", () => {
    const hits: N4Hit[] = [
      { family: "weirdfamily", file: "f", line: "1", terms: "", text: "", fields: { Alpha: "1", Beta: "2", Gamma: "3", Delta: "4", Epsilon: "5" } },
    ];
    const cols = pickHitColumns(hits);
    expect(cols.length).toBeGreaterThan(0);
    expect(cols.length).toBeLessThanOrEqual(4);
  });
});
