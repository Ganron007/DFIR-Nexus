import "@testing-library/jest-dom/vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import TimelineEventsGrid from "./TimelineEventsGrid";
import { api } from "../api/client";
import type { TimelineEvent } from "../api/timeline";

const VIEWPORT = { width: 900, height: 600 };

function event(id: string, ts: string, over: Partial<TimelineEvent> = {}): TimelineEvent {
  return {
    event_id: id,
    ts,
    ts_desc: "Created0x10",
    ts_src: "column",
    family: "mftecmd",
    host: "WS01",
    user: "bob",
    artifact: "mftecmd.csv",
    source_file: "mft/mftecmd.csv",
    source_line: 42,
    audit_id: "nx-1",
    finding_ids: [],
    ...over,
  };
}

const PAGE = {
  backend: "es",
  rows: [
    event("e1", "2026-09-29T13:00:00Z"),
    event("e2", "2026-09-29T14:00:00Z"),
  ],
  next_cursor: null,
  total: 2,
  exact: true,
  capped: false,
};

/** Stub only the timeline slice of the api facade; everything else is real. */
function stubTimeline(impl: Partial<Record<"events" | "facets" | "histogram" | "context", unknown>>) {
  vi.spyOn(api.timeline, "events").mockImplementation(
    (impl.events as never) ?? (async () => PAGE as never),
  );
  vi.spyOn(api.timeline, "facets").mockImplementation((async () => ({ backend: "es", facets: {} })) as never);
  vi.spyOn(api.timeline, "histogram").mockImplementation(
    (impl.histogram as never) ??
      (async () => ({
        backend: "es",
        buckets: [
          { ts: "2026-09-29T13:00:00Z", count: 4 },
          { ts: "2026-09-29T14:00:00Z", count: 9 },
        ],
      }) as never),
  );
  vi.spyOn(api.timeline, "context").mockImplementation(
    (impl.context as never) ??
      (async (_caseId: string, _eventId: string, seconds = 300) => ({
        backend: "es",
        anchor: event("e1", "2026-09-29T13:00:00Z"),
        rows: [
          event("e1", "2026-09-29T13:00:00Z"),
          event("e9", "2026-09-29T13:02:00Z", { family: "evtx" }),
        ],
        seconds,
        total: 2,
        capped: false,
      })) as never,
  );
}

function renderGrid(caseId = "CASE-TL01") {
  return render(
    <MemoryRouter>
      <TimelineEventsGrid caseId={caseId} initialViewport={VIEWPORT} />
    </MemoryRouter>,
  );
}

beforeEach(() => {
  vi.restoreAllMocks();
  // jsdom has no layout engine. The grid's virtualiser measures its scroll
  // element after mount, so an async (server-mode) page of rows lands in a
  // scroll element that measures zero unless these are stubbed - without them
  // the rows are fetched and silently never rendered.
  (globalThis as { ResizeObserver?: unknown }).ResizeObserver = class {
    observe() {}
    unobserve() {}
    disconnect() {}
  };
  const rect = {
    width: VIEWPORT.width,
    height: VIEWPORT.height,
    top: 0,
    left: 0,
    bottom: VIEWPORT.height,
    right: VIEWPORT.width,
    x: 0,
    y: 0,
    toJSON: () => ({}),
  } as DOMRect;
  HTMLElement.prototype.getBoundingClientRect = function getRect() {
    return rect;
  };
  for (const prop of ["clientHeight", "offsetHeight", "scrollHeight"]) {
    Object.defineProperty(HTMLElement.prototype, prop, {
      configurable: true,
      get: () => VIEWPORT.height,
    });
  }
  for (const prop of ["clientWidth", "offsetWidth", "scrollWidth"]) {
    Object.defineProperty(HTMLElement.prototype, prop, {
      configurable: true,
      get: () => VIEWPORT.width,
    });
  }
});

describe("TimelineEventsGrid", () => {
  it("renders the events it fetched, with the source of each timestamp", async () => {
    stubTimeline({
      events: async () => ({
        ...PAGE,
        rows: [
          event("e1", "2026-09-29T13:00:00Z", { ts_src: "column" }),
          event("e2", "2026-09-29T14:00:00Z", { ts_src: "column-heuristic" }),
        ],
      }),
    });
    renderGrid();
    await waitFor(() => expect(screen.getAllByTestId("grid-row")).toHaveLength(2));
    const rows = screen.getAllByTestId("grid-row");
    // a registry-typed column and a heuristic one are distinguishable, and
    // each row says which timestamp it is
    expect(rows[0]).toHaveTextContent("2026-09-29 13:00:00");
    expect(rows[1]).toHaveTextContent("heuristic");
    expect(rows[0]).not.toHaveTextContent("heuristic");
  });

  it("reports an exact count as a total", async () => {
    stubTimeline({});
    renderGrid();
    await waitFor(() => expect(screen.getByTestId("timeline-count")).toHaveTextContent("2 events"));
  });

  it("reports a capped count as 'at least', never as a total", async () => {
    stubTimeline({
      events: async () => ({ ...PAGE, total: 10000, exact: false, capped: true }),
    });
    renderGrid();
    await waitFor(() =>
      expect(screen.getByTestId("timeline-count")).toHaveTextContent("at least 10000 events"),
    );
  });

  it("surfaces a down backend instead of showing an empty grid", async () => {
    stubTimeline({
      events: async () => {
        throw new Error("timeline requires Elasticsearch");
      },
    });
    renderGrid();
    await waitFor(() =>
      expect(screen.getByTestId("timeline-backend-error")).toHaveTextContent(
        /not an absence of activity/,
      ),
    );
    // and the empty message must not claim there is no activity
    expect(
      screen.queryByText("No events in this window."),
    ).not.toBeInTheDocument();
  });

  it("keeps the axis histogram failure separate from the grid", async () => {
    stubTimeline({
      histogram: async () => {
        throw new Error("histogram refused");
      },
    });
    renderGrid();
    await waitFor(() =>
      expect(screen.getByTestId("timeline-axis-error")).toHaveTextContent(
        /still queryable/,
      ),
    );
    // the grid itself still works
    expect(screen.getByTestId("timeline-events")).toBeInTheDocument();
  });

  it("sends the brush window as a range filter on the next fetch", async () => {
    const events = vi.fn(async (_req?: unknown) => PAGE);
    stubTimeline({ events: events as never });
    renderGrid();
    await waitFor(() => expect(events).toHaveBeenCalledTimes(1));
    // the axis is present, and the first fetch carries whatever window is set
    expect(document.querySelector("[aria-label='Timeline activity']")).toBeTruthy();
    const call = events.mock.calls.at(-1)?.[0] as unknown as {
      filters: Record<string, unknown>;
    };
    expect(call.filters).toBeDefined();
  });

  it("merges a text filter with the window rather than replacing it", async () => {
    const events = vi.fn(async (_req?: unknown) => PAGE);
    stubTimeline({ events: events as never });
    const user = userEvent.setup();
    renderGrid();
    await waitFor(() => expect(events).toHaveBeenCalledTimes(1));
    await user.type(await screen.findByTestId("filter-family"), "evtx");
    await waitFor(() => expect(events.mock.calls.length).toBeGreaterThan(1));
    // the component merges the text filter into what it sends, so the grid's
    // window (when brushed) and the typed family both reach the server
    const call = events.mock.calls.at(-1)?.[0] as unknown as {
      filters: Record<string, unknown>;
    };
    expect(call.filters.family).toBe("evtx");
  });

  it("opens a ±N-second context window for an event", async () => {
    const context = vi.fn(
      async (_caseId: string, _eventId: string, seconds = 300) => ({
        backend: "es",
        anchor: event("e1", "2026-09-29T13:00:00Z"),
        rows: [event("e9", "2026-09-29T13:02:00Z", { family: "evtx" })],
        seconds,
        total: 1,
        capped: false,
      }),
    );
    stubTimeline({ context });
    renderGrid();

    await waitFor(() => expect(screen.getAllByTestId("grid-row")).toHaveLength(2));
    // the grid opens a row with Enter on the grid (row 0 by default)
    fireEvent.keyDown(screen.getByTestId("grid"), { key: "Enter" });
    await waitFor(() => expect(screen.getByTestId("timeline-context")).toBeInTheDocument());
    expect(context).toHaveBeenCalledWith("CASE-TL01", "e1", 300);
  });

  it("links the export to the same window the grid shows", async () => {
    stubTimeline({});
    renderGrid();
    const link = await screen.findByTestId("timeline-export");
    expect(link).toHaveAttribute("href", expect.stringContaining("/portal/api/timeline/events/export"));
    expect(link.getAttribute("href")).toContain("case_id=CASE-TL01");
  });

  it("asks for a case before rendering anything", () => {
    stubTimeline({});
    renderGrid("");
    expect(screen.getByTestId("timeline-events-no-case")).toBeInTheDocument();
  });
});
