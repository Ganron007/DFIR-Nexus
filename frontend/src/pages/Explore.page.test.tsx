/**
 * WP 4j.5: Explore page behaviour — needle rotation and interpretation drawer.
 *
 * Regression cover for the manual-test findings:
 *  - a needles-only briefing link (?needles=X) must fire a search for X
 *  - clicking a suggested needle / field value ROTATES the active needle —
 *    it never appends terms into an unmatchable blob
 *  - the Hit Explanation panel always resolves: empty or failed
 *    interpretations render an honest note instead of a silent gap
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

const { mockApi, mockUseCase } = vi.hoisted(() => ({
  mockApi: {
    aggregate: vi.fn(),
    workbench: vi.fn(),
    playbookNeedles: vi.fn(),
    search: vi.fn(),
    histogram: vi.fn(),
    hitInterpret: vi.fn(),
    workbenchAdd: vi.fn(),
    workbenchRemove: vi.fn(),
    needleFeedback: vi.fn(),
  },
  mockUseCase: vi.fn(),
}));

vi.mock("../api/client", async () => {
  const actual = await vi.importActual("../api/client");
  return { ...actual, api: mockApi };
});

vi.mock("../context/CaseContext", () => ({
  useCase: mockUseCase,
}));

import Explore from "./Explore";

const HIT = {
  family: "evtx",
  host: "WS01",
  file: "sec.csv",
  line: "12",
  terms: "rundll32",
  text: "raw row",
  fields: { EventID: "4688", CommandLine: "rundll32.exe x.dll" },
};

const EMPTY_INTERP = {
  meaning: "",
  skills: [],
  techniques: [],
  look_for: [],
  corroborate: [],
  next_queries: [],
  pivots: [],
  negative: [],
  caveats: [],
  confidence_rules: {},
  sources: [],
};

function setup() {
  mockUseCase.mockReturnValue({ activeCase: "CASE-T" });
  mockApi.aggregate.mockResolvedValue({ buckets: { evtx: 5 } });
  mockApi.workbench.mockResolvedValue({ bookmarks: [] });
  mockApi.playbookNeedles.mockResolvedValue({
    suggestions: [
      { slug: "pb", playbook: "PB", needles: ["regsvr32"], strong_needles: [], caveats: [], source: "playbook" },
    ],
  });
  mockApi.search.mockResolvedValue({ hits: [HIT], count: 1, backend: "csv" });
  mockApi.histogram.mockResolvedValue({ buckets: {}, count: 0 });
  mockApi.hitInterpret.mockResolvedValue(EMPTY_INTERP);
}

function renderExplore(entry = "/explore") {
  return render(
    <MemoryRouter initialEntries={[entry]}>
      <Explore />
    </MemoryRouter>,
  );
}

describe("Explore page (WP 4j.5)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    setup();
  });

  it("fires a search for a needles-only briefing link", async () => {
    renderExplore("/explore?needles=rundll32");
    await waitFor(() =>
      expect(mockApi.search).toHaveBeenCalledWith(
        expect.objectContaining({ needles: "rundll32" }),
      ),
    );
    expect(screen.getByDisplayValue("rundll32")).toBeTruthy();
  });

  it("rotates the needle on a playbook suggestion — never appends", async () => {
    renderExplore("/explore?needles=rundll32");
    await waitFor(() => expect(mockApi.search).toHaveBeenCalled());
    fireEvent.click(screen.getByText(/Show playbook suggestions/i));
    fireEvent.click(await screen.findByText("regsvr32"));
    await waitFor(() =>
      expect(mockApi.search).toHaveBeenLastCalledWith(
        expect.objectContaining({ needles: "regsvr32" }),
      ),
    );
    // the box shows exactly the active needle — no piled-up terms
    expect((screen.getByDisplayValue("regsvr32") as HTMLInputElement).value).toBe("regsvr32");
  });

  it("rotates the needle on a field-value pivot — never appends", async () => {
    renderExplore("/explore?needles=rundll32");
    await waitFor(() => screen.getByText("4688"));
    fireEvent.click(screen.getByText("4688"));
    await waitFor(() =>
      expect(mockApi.search).toHaveBeenLastCalledWith(
        expect.objectContaining({ needles: "4688" }),
      ),
    );
  });

  it("shows a fallback note when a hit has no skill coverage", async () => {
    renderExplore("/explore?needles=rundll32");
    await waitFor(() => screen.getByText("evtx"));
    const row = document.querySelector("tbody tr");
    expect(row).toBeTruthy();
    fireEvent.click(row!);
    await screen.findByText(/No skill procedure covers this row yet/i);
  });

  it("shows an honest note when interpretation fails outright", async () => {
    mockApi.hitInterpret.mockRejectedValue(new Error("backend 500"));
    renderExplore("/explore?needles=rundll32");
    await waitFor(() => screen.getByText("evtx"));
    fireEvent.click(document.querySelector("tbody tr")!);
    await screen.findByText(/Interpretation unavailable for this row/i);
  });
});
