import "@testing-library/jest-dom/vitest";
import { act, fireEvent, render, renderHook, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { DataGrid } from "./DataGrid";
import { loadLayout } from "./query";
import { useFacetPanel } from "./facets";
import type { DataGridColumn, GridFetchRequest, GridPage, GridQuery } from "./types";

interface Row {
  id: string;
  host: string;
  severity: string;
}

const COLUMNS: DataGridColumn<Row>[] = [
  { id: "id", header: "ID", accessorFn: (r) => r.id, filterable: true, pinnable: true, width: 140 },
  { id: "host", header: "Host", accessorFn: (r) => r.host, filterable: true, width: 180 },
  { id: "severity", header: "Severity", accessorFn: (r) => r.severity, width: 120 },
];

const ROWS: Row[] = [
  { id: "F-01", host: "WEB-01", severity: "HIGH" },
  { id: "F-02", host: "WEB-02", severity: "LOW" },
  { id: "F-03", host: "DB-01", severity: "MEDIUM" },
];

const VIEWPORT = { width: 900, height: 400 };

function rows(n: number, prefix = "F"): Row[] {
  return Array.from({ length: n }, (_, i) => ({
    id: `${prefix}-${String(i + 1).padStart(5, "0")}`,
    host: `WEB-${String((i % 7) + 1).padStart(2, "0")}`,
    severity: ["LOW", "MEDIUM", "HIGH"][i % 3],
  }));
}

beforeEach(() => {
  window.localStorage.clear();
  vi.restoreAllMocks();
  // jsdom has no layout engine and always reports 0, which would make the
  // virtual window empty. TanStack measures the scroller with offsetWidth /
  // offsetHeight, so report a viewport for the scroller and 0 for everything
  // else - the same shape a browser gives it.
  Object.defineProperty(HTMLElement.prototype, "offsetWidth", {
    configurable: true,
    get(this: HTMLElement) {
      return this.dataset?.testid === "grid-scroller" ? 900 : 0;
    },
  });
  Object.defineProperty(HTMLElement.prototype, "offsetHeight", {
    configurable: true,
    get(this: HTMLElement) {
      return this.dataset?.testid === "grid-scroller" ? 400 : 0;
    },
  });
});

describe("DataGrid", () => {
  it("keeps the DOM bounded at 100k rows", () => {
    render(
      <DataGrid
        columns={COLUMNS}
        rows={rows(100_000)}
        getRowId={(row) => row.id}
        initialViewport={VIEWPORT}
      />,
    );
    const rendered = screen.getAllByTestId("grid-row");
    // the whole point of virtualising: a 100k-row data set is a short DOM
    expect(rendered.length).toBeGreaterThan(0);
    expect(rendered.length).toBeLessThan(50);
    expect(screen.getByTestId("row-count")).toHaveTextContent("100000");
  });

  it("filters in the browser and emits the query object", async () => {
    const onQueryChange = vi.fn();
    render(
      <DataGrid
        columns={COLUMNS}
        rows={ROWS}
        getRowId={(row) => row.id}
        initialViewport={VIEWPORT}
        onQueryChange={onQueryChange}
      />,
    );

    fireEvent.change(screen.getByTestId("filter-host"), { target: { value: "web-0" } });
    expect(onQueryChange).toHaveBeenCalledWith({ filters: { host: "web-0" }, sort: null });
    // substring match, in the browser: WEB-01 and WEB-02, not DB-01
    await waitFor(() => expect(screen.getAllByTestId("grid-row")).toHaveLength(2));

    // a blank filter is not a filter
    fireEvent.change(screen.getByTestId("filter-host"), { target: { value: "   " } });
    expect(onQueryChange).toHaveBeenLastCalledWith({ filters: {}, sort: null });
  });

  it("cycles a sort through asc, desc and off", () => {
    const onQueryChange = vi.fn();
    render(
      <DataGrid
        columns={COLUMNS}
        rows={ROWS}
        getRowId={(row) => row.id}
        initialViewport={VIEWPORT}
        onQueryChange={onQueryChange}
      />,
    );
    fireEvent.click(screen.getByTestId("sort-severity"));
    expect(onQueryChange).toHaveBeenLastCalledWith({
      filters: {},
      sort: { by: "severity", dir: "asc" },
    });
    fireEvent.click(screen.getByTestId("sort-severity"));
    expect(onQueryChange).toHaveBeenLastCalledWith({
      filters: {},
      sort: { by: "severity", dir: "desc" },
    });
    fireEvent.click(screen.getByTestId("sort-severity"));
    expect(onQueryChange).toHaveBeenLastCalledWith({ filters: {}, sort: null });
    expect(screen.getByTestId("header-severity")).toHaveAttribute("aria-sort", "none");
  });

  it("moves the cursor, opens the row and copies the cell from the keyboard", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", {
      value: { writeText },
      configurable: true,
    });
    const onOpenRow = vi.fn();
    const onCopy = vi.fn();
    render(
      <DataGrid
        columns={COLUMNS}
        rows={ROWS}
        getRowId={(row) => row.id}
        initialViewport={VIEWPORT}
        onOpenRow={onOpenRow}
        onCopy={onCopy}
      />,
    );
    const grid = screen.getByTestId("grid");

    fireEvent.keyDown(grid, { key: "ArrowDown" });
    fireEvent.keyDown(grid, { key: "ArrowRight" });
    fireEvent.keyDown(grid, { key: "Enter" });
    expect(onOpenRow).toHaveBeenCalledWith(ROWS[1]);

    fireEvent.keyDown(grid, { key: "c", ctrlKey: true });
    expect(writeText).toHaveBeenCalledWith("WEB-02");
    expect(onCopy).toHaveBeenCalledWith("WEB-02");

    fireEvent.keyDown(grid, { key: "Home" });
    fireEvent.keyDown(grid, { key: "ArrowLeft" });
    fireEvent.keyDown(grid, { key: "End" });
    fireEvent.keyDown(grid, { key: "End" });
    const active = screen.getAllByTestId("grid-row").filter(
      (el) => el.getAttribute("data-active") === "true",
    );
    expect(active).toHaveLength(1);
  });

  it("selects rows without touching the data", () => {
    const onChange = vi.fn();
    render(
      <DataGrid
        columns={COLUMNS}
        rows={ROWS}
        getRowId={(row) => row.id}
        initialViewport={VIEWPORT}
        selection={{ selected: new Set<string>(), onChange }}
      />,
    );
    fireEvent.click(screen.getByTestId("select-1"));
    expect(onChange).toHaveBeenCalledTimes(1);
    expect([...onChange.mock.calls[0][0]]).toEqual(["F-02"]);
  });

  it("remembers the column layout per view, and drops it gracefully", () => {
    render(
      <DataGrid
        columns={COLUMNS}
        rows={ROWS}
        getRowId={(row) => row.id}
        viewId="findings"
        initialViewport={VIEWPORT}
      />,
    );
    fireEvent.click(screen.getByTestId("visibility-severity"));
    expect(loadLayout("findings").visibility?.severity).toBe(false);

    fireEvent.click(screen.getByTestId("pin-id"));
    expect(loadLayout("findings").pinned?.id).toBe(true);

    // a view's layout never leaks into another view
    expect(loadLayout("explore").visibility?.severity).toBeUndefined();
  });

  it("refetches page one with the query in server mode", async () => {
    const fetchPage = vi.fn(
      async (_req: GridFetchRequest): Promise<GridPage<Row>> => ({
        rows: ROWS,
        nextCursor: null,
        total: 3,
      }),
    );
    render(
      <DataGrid
        mode="server"
        fetchPage={fetchPage}
        columns={COLUMNS}
        getRowId={(row) => row.id}
        initialViewport={VIEWPORT}
      />,
    );
    await waitFor(() => expect(fetchPage).toHaveBeenCalledTimes(1));
    expect(fetchPage.mock.calls[0][0].cursor).toBeNull();

    fireEvent.change(screen.getByTestId("filter-host"), { target: { value: "WEB-01" } });
    await waitFor(() => expect(fetchPage).toHaveBeenCalledTimes(2));
    expect(fetchPage.mock.calls[1][0].query).toEqual({ filters: { host: "WEB-01" }, sort: null });
  });

  it("renders the rows a server page returned", async () => {
    // Server mode resolves AFTER mount, so the rows arrive into a virtualiser
    // that has already re-measured. Without a measurable scroll element the
    // page is fetched and silently renders nothing - this asserts it renders.
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

    const fetchPage = vi.fn(
      async (_req: GridFetchRequest): Promise<GridPage<Row>> => ({
        rows: ROWS,
        nextCursor: null,
        total: 3,
      }),
    );
    render(
      <DataGrid
        mode="server"
        fetchPage={fetchPage}
        columns={COLUMNS}
        getRowId={(row) => row.id}
        initialViewport={VIEWPORT}
      />,
    );
    await waitFor(() => expect(screen.getAllByTestId("grid-row")).toHaveLength(ROWS.length));
    expect(screen.getByText("WEB-01")).toBeInTheDocument();
    expect(screen.getByTestId("row-count")).toHaveTextContent("3");
  });

  it("fetches the next page on scroll", async () => {
    const first = rows(30, "P1");
    const second = rows(5, "P2");
    const fetchPage = vi.fn(
      async (req: GridFetchRequest): Promise<GridPage<Row>> =>
        req.cursor === null
          ? { rows: first, nextCursor: "page-2", total: 35 }
          : { rows: second, nextCursor: null, total: 35 },
    );

    render(
      <DataGrid
        mode="server"
        fetchPage={fetchPage}
        columns={COLUMNS}
        getRowId={(row) => row.id}
        initialViewport={VIEWPORT}
        height={320}
      />,
    );
    await waitFor(() => expect(fetchPage).toHaveBeenCalledTimes(1));
    // the window never reaches the end of page one, so only a scroll asks
    expect(screen.getByTestId("row-count")).toHaveTextContent("30 of 35");

    const scroller = screen.getByTestId("grid-scroller");
    Object.defineProperty(scroller, "scrollHeight", { value: 960, configurable: true });
    Object.defineProperty(scroller, "clientHeight", { value: 320, configurable: true });
    Object.defineProperty(scroller, "scrollTop", { value: 640, writable: true, configurable: true });
    fireEvent.scroll(scroller);

    await waitFor(() => expect(fetchPage).toHaveBeenCalledTimes(2));
    expect(fetchPage.mock.calls[1][0].cursor).toBe("page-2");
    await waitFor(() => expect(screen.getByTestId("row-count")).toHaveTextContent("35 of 35"));
  });

  it("shows the empty state instead of an empty table", () => {
    render(
      <DataGrid
        columns={COLUMNS}
        rows={[]}
        getRowId={(row) => row.id}
        initialViewport={VIEWPORT}
        emptyMessage="Nothing matched."
      />,
    );
    expect(screen.getByTestId("grid-empty")).toHaveTextContent("Nothing matched.");
    expect(screen.queryAllByTestId("grid-row")).toHaveLength(0);
  });
});

describe("useFacetPanel", () => {
  it("counts values and toggles into the same query object", () => {
    const onQueryChange = vi.fn();
    const query: GridQuery = { filters: {}, sort: null };
    const { result } = renderHook(() =>
      useFacetPanel<Row>({ rows: ROWS, columns: COLUMNS, query, onQueryChange }),
    );

    expect(result.current.facets.map((f) => f.columnId)).toEqual(["id", "host", "severity"]);
    const host = result.current.facets.find((f) => f.columnId === "host");
    // busiest first, then alphabetical
    expect(host?.values).toEqual([
      { value: "DB-01", count: 1 },
      { value: "WEB-01", count: 1 },
      { value: "WEB-02", count: 1 },
    ]);

    act(() => result.current.toggle("host", "DB-01"));
    expect(onQueryChange).toHaveBeenCalledWith({
      filters: { host: "DB-01" },
      sort: null,
    });

    act(() => result.current.clear());
    expect(onQueryChange).toHaveBeenLastCalledWith({ filters: {}, sort: null });
  });
});