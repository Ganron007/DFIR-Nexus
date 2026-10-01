/**
 * Timeline lanes on one shared scale (WO-U8a).
 *
 * This is the gain the WO deferred from U6, and the property worth pinning is
 * the one the old hand-drawn lanes broke: two families whose data covers
 * wildly different spans must still share one range, so a mark at one instant
 * lines up vertically and one brush means one instant range for the stack.
 */
import "@testing-library/jest-dom/vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import Timeline from "./Timeline";
import { api } from "../api/client";
import * as caseContext from "../context/CaseContext";

/**
 * Two families on DIFFERENT spans: evtx starts 2026-09-29T13, sysmon starts
 * 2026-09-30T09. Under per-lane scales those 13:00 marks would land at
 * different pixels; under one shared scale they cannot.
 */
const LANES = {
  total: 120,
  default_needles: 0,
  families: [
    {
      family: "evtx",
      buckets: {
        "2026-09-29T13": 4,
        "2026-09-29T14": 9,
      },
      buckets_sev: { "2026-09-29T13": "high" },
    },
    {
      family: "sysmon",
      buckets: {
        "2026-09-30T09": 7,
        "2026-09-30T10": 2,
      },
      buckets_sev: { "2026-09-30T09": "critical" },
    },
  ],
};

function withCase(caseId: string) {
  vi.spyOn(caseContext, "useCase").mockReturnValue({
    activeCase: caseId,
    cases: [caseId],
    caseSummaries: {},
    previewCase: caseId,
    booting: false,
    mode: "1",
    health: "ok",
    es: { configured: true, reachable: true },
    sift: { selected: false, reachable: false },
    setActiveCase: vi.fn(),
    setPreviewCase: vi.fn(),
    exitToDashboard: vi.fn(),
    refreshCases: vi.fn(),
    refreshMode: vi.fn(),
    refreshStages: vi.fn(),
    setMode: vi.fn(),
    stages: {},
  } as unknown as ReturnType<typeof caseContext.useCase>);
}

function renderPage(node: React.ReactNode) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: 0 } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>{node}</MemoryRouter>
    </QueryClientProvider>,
  );
}

function stubReads() {
  vi.spyOn(api, "timelineLanes").mockResolvedValue(LANES as never);
  vi.spyOn(api, "search").mockResolvedValue({ hits: [], count: 0 } as never);
}

beforeEach(() => {
  vi.restoreAllMocks();
  localStorage.clear();
});

describe("Timeline lanes (migrated)", () => {
  it("draws every family as a lane", async () => {
    withCase("CASE-TL0001");
    stubReads();
    renderPage(<Timeline />);
    await waitFor(() => expect(screen.getByTestId("time-lanes")).toBeInTheDocument());
    expect(screen.getByTestId("lane-evtx")).toBeInTheDocument();
    expect(screen.getByTestId("lane-sysmon")).toBeInTheDocument();
  });

  it("puts both families on ONE shared range spanning both spans", async () => {
    withCase("CASE-TL0002");
    stubReads();
    renderPage(<Timeline />);
    const caption = await screen.findByTestId("timeline-lane-caption");
    // the range must cover 2026-09-29T13 through 2026-09-30T11 - if each lane
    // kept its own range, evtx would end on the 29th
    expect(caption).toHaveTextContent("2026-09-29");
    expect(caption).toHaveTextContent("2026-09-30");
  });

  it("carries the peak severity on the lane, so the tone is not lost", async () => {
    withCase("CASE-TL0003");
    stubReads();
    renderPage(<Timeline />);
    await waitFor(() => expect(screen.getByTestId("lane-evtx")).toBeInTheDocument());
    // U6's model is one tone per lane, so the peak is on the label where an
    // examiner can read it instead of only in a bar colour
    expect(screen.getByTestId("lane-evtx")).toHaveTextContent("max high");
    expect(screen.getByTestId("lane-sysmon")).toHaveTextContent("max critical");
  });

  it("brushing gives one instant range, not a per-lane index window", async () => {
    withCase("CASE-TL0004");
    stubReads();
    renderPage(<Timeline />);
    await waitFor(() => expect(screen.getByTestId("time-lanes")).toBeInTheDocument());
    const svg = screen.getByTestId("time-lanes-svg");
    // the brush starts as a pointer gesture on the shared scale
    const { fireEvent } = await import("@testing-library/react");
    // the brush hook listens for MOUSE events, which is what a drag produces
    fireEvent.mouseDown(svg, { clientX: 100, clientY: 10, button: 0 });
    fireEvent.mouseMove(svg, { clientX: 400, clientY: 10 });
    fireEvent.mouseUp(svg, { clientX: 400, clientY: 10 });
    await waitFor(() => expect(screen.getByTestId("timeline-brush")).toBeInTheDocument());
    const brush = screen.getByTestId("timeline-brush");
    // both endpoints are instants, not hour indices
    expect(brush).toHaveTextContent(/Brushed \d{4}-\d{2}-\d{2}T.*Z → \d{4}-\d{2}-\d{2}T.*Z/);
  });

  it("hands the brushed instants to Explore, scoped to the case", async () => {
    withCase("CASE-TL0005");
    stubReads();
    renderPage(<Timeline />);
    await waitFor(() => expect(screen.getByTestId("time-lanes")).toBeInTheDocument());
    const { fireEvent } = await import("@testing-library/react");
    fireEvent.click(screen.getByTestId("lane-evtx"));
    const svg = screen.getByTestId("time-lanes-svg");
    // the brush hook listens for MOUSE events, which is what a drag produces
    fireEvent.mouseDown(svg, { clientX: 100, clientY: 10, button: 0 });
    fireEvent.mouseMove(svg, { clientX: 400, clientY: 10 });
    fireEvent.mouseUp(svg, { clientX: 400, clientY: 10 });
    await waitFor(() => expect(screen.getByTestId("timeline-brush")).toBeInTheDocument());
    fireEvent.click(screen.getByText("Search in Explore →"));
    // the Explore query must carry the instants and the family
    const search = api.search as unknown as { mock: { calls: unknown[][] } };
    const last = search.mock.calls.at(-1)?.[0] as { start?: string; end?: string };
    expect(last?.start).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    expect(last?.end).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });

  it("says there is no timeline data instead of drawing an empty stack", async () => {
    withCase("CASE-TL0006");
    vi.spyOn(api, "timelineLanes").mockResolvedValue({
      total: 0,
      families: [],
    } as never);
    renderPage(<Timeline />);
    await waitFor(() =>
      expect(screen.getByText("No timeline data")).toBeInTheDocument(),
    );
    expect(screen.queryByTestId("time-lanes")).not.toBeInTheDocument();
  });

  it("keeps the A10 events grid on its own tab", async () => {
    withCase("CASE-TL0007");
    stubReads();
    renderPage(<Timeline />);
    await waitFor(() => expect(screen.getByTestId("time-lanes")).toBeInTheDocument());
    const { fireEvent } = await import("@testing-library/react");
    fireEvent.click(screen.getByTestId("timeline-tab-events"));
    await waitFor(() =>
      expect(screen.getByTestId("timeline-events")).toBeInTheDocument(),
    );
    expect(screen.queryByTestId("time-lanes")).not.toBeInTheDocument();
  });

  it("surfaces a failed lane read", async () => {
    withCase("CASE-TL0008");
    vi.spyOn(api, "timelineLanes").mockRejectedValue(new Error("lane index missing"));
    renderPage(<Timeline />);
    await waitFor(() =>
      expect(screen.getByRole("alert")).toHaveTextContent("lane index missing"),
    );
  });
});
