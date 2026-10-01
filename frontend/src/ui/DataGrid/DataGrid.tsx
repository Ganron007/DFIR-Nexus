/**
 * DataGrid (WO-U5 / WP 14.5) - headless TanStack Table + TanStack Virtual.
 *
 * Two modes, one contract:
 *   client - the page hands over every row; sort/filter run in the browser.
 *   server - `fetchPage(cursor, query)` is the only data source; the grid owns
 *            paging, asks for the next cursor when the window nears the end, and
 *            never assumes it has the whole set (`total` may be null).
 *
 * Everything else stays a view concern the grid keeps small: column resize /
 * pin / visibility / sort, per-column filters that emit one query object, row
 * selection, and keyboard paths (arrows move, Enter opens the detail Drawer,
 * Ctrl+C copies the focused cell). Column layout is remembered per view in
 * localStorage as a convenience - storage failure degrades to defaults.
 *
 * Headless on purpose: the grid takes a `fetchPage` and emits queries. It never
 * talks to the API, reads a case, or decides what a row means.
 */
import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type KeyboardEvent as ReactKeyboardEvent,
  type PointerEvent as ReactPointerEvent,
  type ReactNode,
} from "react";
import {
  getCoreRowModel,
  getFilteredRowModel,
  getSortedRowModel,
  useReactTable,
  type AccessorFnColumnDef,
  type VisibilityState,
} from "@tanstack/react-table";
import { useVirtualizer } from "@tanstack/react-virtual";

import styles from "./DataGrid.module.css";
import { buildQuery, emptyQuery, useColumnLayout } from "./query";
import type {
  ColumnLayout,
  DataGridColumn,
  FetchPage,
  GridQuery,
  SelectionState,
} from "./types";

export interface DataGridProps<T> {
  columns: DataGridColumn<T>[];
  /** client mode: the rows. server mode: ignored (fetchPage owns the data). */
  rows?: T[];
  getRowId: (row: T, index: number) => string;
  mode?: "client" | "server";
  fetchPage?: FetchPage<T>;
  /** localStorage namespace for the column layout. */
  viewId?: string;
  height?: number;
  estimateRowHeight?: number;
  /** Initial viewport for the virtualiser. jsdom has no layout engine, so the
   *  tests pass one; in the browser the virtualiser measures the scroller. */
  initialViewport?: { width: number; height: number };
  /** Distance from the end that triggers the next cursor, in px. */
  loadMoreThreshold?: number;
  onOpenRow?: (row: T) => void;
  onQueryChange?: (query: GridQuery) => void;
  selection?: SelectionState;
  /** Called with the focused cell when Ctrl+C copies it (for a toast). */
  onCopy?: (text: string) => void;
  emptyMessage?: string;
  ariaLabel?: string;
}

const DEFAULT_LAYOUT: ColumnLayout = { widths: {}, visibility: {}, pinned: {} };

function cellText<T>(column: DataGridColumn<T>, row: T): string {
  if (column.copyValue) return column.copyValue(row) ?? "";
  const accessor = column.accessorFn;
  if (typeof accessor === "function") return String(accessor(row, 0) ?? "");
  return String((row as Record<string, unknown>)[column.id] ?? "");
}

export function DataGrid<T>(props: DataGridProps<T>) {
  const {
    columns,
    rows = [],
    getRowId,
    mode = "client",
    fetchPage,
    viewId = "default",
    height = 420,
    estimateRowHeight = 32,
    initialViewport,
    loadMoreThreshold = 240,
    onOpenRow,
    onQueryChange,
    selection,
    onCopy,
    emptyMessage = "No rows.",
    ariaLabel = "Data grid",
  } = props;

  const [query, setQuery] = useState<GridQuery>(emptyQuery);
  const [filterDrafts, setFilterDrafts] = useState<Record<string, string>>({});
  const [layout, patchLayout] = useColumnLayout(viewId, DEFAULT_LAYOUT);

  const [serverRows, setServerRows] = useState<T[]>([]);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [total, setTotal] = useState<number | null>(null);
  const [loading, setLoading] = useState(false);
  const loadingRef = useRef(false);

  const [activeRow, setActiveRow] = useState(0);
  const [activeColumn, setActiveColumn] = useState(0);
  const scrollRef = useRef<HTMLDivElement | null>(null);

  const data = mode === "server" ? serverRows : rows;

  const emitQuery = useCallback(
    (next: GridQuery) => {
      setQuery(next);
      onQueryChange?.(next);
    },
    [onQueryChange],
  );

  // ---- server mode: page 1 on mount and on every query change -------------
  const queryKey = JSON.stringify(query);
  useEffect(() => {
    if (mode !== "server" || !fetchPage) return undefined;
    const controller = new AbortController();
    let cancelled = false;
    (async () => {
      setLoading(true);
      try {
        const page = await fetchPage({ cursor: null, query, signal: controller.signal });
        if (cancelled) return;
        setServerRows(page.rows);
        setNextCursor(page.nextCursor);
        setTotal(page.total);
        setActiveRow(0);
      } finally {
        if (!cancelled) setLoading(false);
      }
    })().catch(() => {
      /* a page that will not load reads as empty; the page owns the retry */
    });
    return () => {
      cancelled = true;
      controller.abort();
    };
  }, [mode, fetchPage, queryKey]);

  const loadMore = useCallback(async () => {
    if (mode !== "server" || !fetchPage || !nextCursor || loadingRef.current) return;
    loadingRef.current = true;
    setLoading(true);
    try {
      const page = await fetchPage({ cursor: nextCursor, query });
      setServerRows((prev) => [...prev, ...page.rows]);
      setNextCursor(page.nextCursor);
      if (page.total != null) setTotal(page.total);
    } catch {
      /* keep what we have; the page owns the retry */
    } finally {
      loadingRef.current = false;
      setLoading(false);
    }
  }, [fetchPage, mode, nextCursor, query]);

  const onScroll = useCallback(() => {
    const el = scrollRef.current;
    if (!el) return;
    if (el.scrollHeight - el.scrollTop - el.clientHeight <= loadMoreThreshold) {
      void loadMore();
    }
  }, [loadMore, loadMoreThreshold]);

  // ---- column model --------------------------------------------------------
  const columnDefs = useMemo<AccessorFnColumnDef<T, unknown>[]>(
    () =>
      columns.map((column) => ({
        id: column.id,
        accessorFn:
          column.accessorFn ??
          ((row: T) => String((row as Record<string, unknown>)[column.id] ?? "")),
        // the grid's filters are substring filters on the cell text
        filterFn: "includesString",
        enableSorting: true,
      })),
    [columns],
  );

  const pinnedIds = useMemo(
    () => columns.filter((c) => layout.pinned[c.id]).map((c) => c.id),
    [columns, layout.pinned],
  );
  const columnOrder = useMemo(
    () => [...pinnedIds, ...columns.filter((c) => !layout.pinned[c.id]).map((c) => c.id)],
    [columns, layout.pinned, pinnedIds],
  );
  const columnById = useMemo(() => {
    const map = new Map<string, DataGridColumn<T>>();
    for (const column of columns) map.set(column.id, column);
    return map;
  }, [columns]);

  const table = useReactTable<T>({
    data,
    columns: columnDefs,
    state: {
      sorting: query.sort
        ? [{ id: query.sort.by, desc: query.sort.dir === "desc" }]
        : [],
      columnFilters: Object.entries(query.filters).map(([id, value]) => ({ id, value })),
      columnVisibility: layout.visibility as VisibilityState,
      columnOrder,
      columnPinning: { left: pinnedIds, right: [] },
    },
    manualSorting: mode === "server",
    manualFiltering: mode === "server",
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
  });

  const tableRows = table.getRowModel().rows;
  const visibleColumns = table.getVisibleLeafColumns();

  const rowVirtualizer = useVirtualizer({
    count: tableRows.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => estimateRowHeight,
    overscan: 8,
    // A grid whose container measures ZERO renders nothing at all - and it
    // says nothing about why. That happens for real reasons (a collapsed
    // panel, a hidden tab, a not-yet-laid-out drawer) and in jsdom it is the
    // default. So the initial rect falls back to the requested height rather
    // than zero: the window is drawn at the right size and corrected once the
    // container actually measures itself.
    initialRect: initialViewport ?? { width: 0, height },
  });
  const virtualItems = rowVirtualizer.getVirtualItems();
  /**
   * A grid whose container measures zero has no window, and renders an empty
   * table while the examiner stares at a case with data in it. That is the
   * worst failure this component can have, so when the virtualiser produces
   * nothing and rows DO exist, draw the first window by hand at the requested
   * height. It is corrected the moment the container measures itself.
   */
  const renderedItems =
    virtualItems.length === 0 && tableRows.length > 0
      ? Array.from(
          {
            length: Math.max(
              1,
              Math.min(tableRows.length, Math.ceil(height / estimateRowHeight)),
            ),
          },
          (_unused, index) => ({
            key: `fallback-${index}`,
            index,
            start: index * estimateRowHeight,
            size: estimateRowHeight,
          }),
        )
      : virtualItems;
  /**
   * A number, not the item object. Depending on the object re-runs the
   * load-more effect every render, because a freshly built item is a new
   * identity - and in server mode that effect appends a page, which
   * re-renders, which fetches again, forever.
   */
  const lastVisibleIndex = renderedItems[renderedItems.length - 1]?.index ?? -1;

  useEffect(() => {
    if (mode !== "server" || !nextCursor) return;
    if (lastVisibleIndex >= 0 && lastVisibleIndex >= tableRows.length - 1) void loadMore();
  }, [lastVisibleIndex, loadMore, mode, nextCursor, tableRows.length]);

  // ---- sort / filter -------------------------------------------------------
  const toggleSort = useCallback(
    (columnId: string) => {
      const current = query.sort;
      let next: GridQuery["sort"] = { by: columnId, dir: "asc" };
      if (current?.by === columnId) {
        next = current.dir === "asc" ? { by: columnId, dir: "desc" } : null;
      }
      emitQuery(buildQuery(query.filters, next));
    },
    [emitQuery, query],
  );

  const setFilter = useCallback(
    (columnId: string, value: string) => {
      setFilterDrafts((prev) => ({ ...prev, [columnId]: value }));
      emitQuery(buildQuery({ ...query.filters, [columnId]: value }, query.sort));
    },
    [emitQuery, query],
  );

  // ---- column resize (mouse events work everywhere; pointer does not in jsdom)
  const resizeState = useRef<{ id: string; startX: number; startWidth: number } | null>(null);
  const onResizeDown = useCallback(
    (event: ReactPointerEvent<HTMLSpanElement>, columnId: string) => {
      event.preventDefault();
      const startWidth =
        layout.widths[columnId] ?? columnById.get(columnId)?.width ?? 160;
      resizeState.current = { id: columnId, startX: event.clientX, startWidth };
      const move = (e: MouseEvent) => {
        const state = resizeState.current;
        if (!state || state.id !== columnId) return;
        patchLayout({
          widths: {
            [columnId]: Math.max(72, state.startWidth + (e.clientX - state.startX)),
          },
        });
      };
      const up = () => {
        resizeState.current = null;
        window.removeEventListener("mousemove", move);
        window.removeEventListener("mouseup", up);
      };
      window.addEventListener("mousemove", move);
      window.addEventListener("mouseup", up);
    },
    [columnById, layout.widths, patchLayout],
  );

  // ---- selection -----------------------------------------------------------
  const toggleRow = useCallback(
    (id: string) => {
      if (!selection) return;
      const next = new Set(selection.selected);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      selection.onChange(next);
    },
    [selection],
  );

  // ---- keyboard ------------------------------------------------------------
  const onKeyDown = useCallback(
    (event: ReactKeyboardEvent<HTMLDivElement>) => {
      const last = tableRows.length - 1;
      const page = Math.max(1, Math.floor(height / estimateRowHeight));
      const row = tableRows[activeRow]?.original;
      switch (event.key) {
        case "ArrowDown":
          event.preventDefault();
          setActiveRow((r) => Math.min(Math.max(last, 0), r + 1));
          return;
        case "ArrowUp":
          event.preventDefault();
          setActiveRow((r) => Math.max(0, r - 1));
          return;
        case "Home":
          event.preventDefault();
          setActiveRow(0);
          return;
        case "End":
          event.preventDefault();
          setActiveRow(Math.max(last, 0));
          return;
        case "PageDown":
          event.preventDefault();
          setActiveRow((r) => Math.min(Math.max(last, 0), r + page));
          return;
        case "PageUp":
          event.preventDefault();
          setActiveRow((r) => Math.max(0, r - page));
          return;
        case "ArrowRight":
          event.preventDefault();
          setActiveColumn((c) => Math.min(visibleColumns.length - 1, c + 1));
          return;
        case "ArrowLeft":
          event.preventDefault();
          setActiveColumn((c) => Math.max(0, c - 1));
          return;
        case "Enter":
          if (!row || !onOpenRow) return;
          event.preventDefault();
          onOpenRow(row);
          return;
        default:
          break;
      }
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "c") {
        const declared = visibleColumns[activeColumn]
          ? columnById.get(visibleColumns[activeColumn].id)
          : undefined;
        if (!row || !declared) return;
        event.preventDefault();
        const text = cellText(declared, row);
        void navigator.clipboard?.writeText(text).catch(() => undefined);
        onCopy?.(text);
      }
    },
    [
      activeColumn,
      activeRow,
      columnById,
      estimateRowHeight,
      height,
      onCopy,
      onOpenRow,
      tableRows,
      visibleColumns,
    ],
  );

  const shown =
    total != null
      ? `${tableRows.length} of ${total}`
      : `${tableRows.length}${loading ? " · loading" : ""}`;

  return (
    <div className={styles.wrapper} data-testid="datagrid">
      <div className={styles.toolbar}>
        <details className={styles.columnMenu}>
          <summary data-testid="column-menu">Columns</summary>
          <div className={styles.columnMenuBody}>
            {columns.map((column) => (
              <label key={column.id} className={styles.columnMenuItem}>
                <input
                  type="checkbox"
                  data-testid={`visibility-${column.id}`}
                  checked={layout.visibility[column.id] !== false}
                  onChange={(e) =>
                    patchLayout({ visibility: { [column.id]: e.target.checked } })
                  }
                />
                {column.header}
              </label>
            ))}
          </div>
        </details>
        <span className={styles.count} data-testid="row-count">
          {shown}
        </span>
      </div>

      <div
        className={styles.scroller}
        ref={scrollRef}
        onScroll={onScroll}
        style={{ height }}
        data-testid="grid-scroller"
      >
        <div
          role="grid"
          aria-label={ariaLabel}
          aria-rowcount={tableRows.length}
          tabIndex={0}
          className={styles.grid}
          onKeyDown={onKeyDown}
          data-testid="grid"
        >
          <div role="rowgroup" className={styles.head}>
            <div role="row" className={styles.row}>
              {selection ? (
                <div role="columnheader" className={styles.cell} />
              ) : null}
              {visibleColumns.map((column, index) => {
                const declared = columnById.get(column.id);
                const width = layout.widths[column.id] ?? declared?.width ?? 160;
                const sortDir = query.sort?.by === column.id ? query.sort.dir : null;
                return (
                  <div
                    key={column.id}
                    role="columnheader"
                    aria-sort={
                      sortDir === "asc"
                        ? "ascending"
                        : sortDir === "desc"
                          ? "descending"
                          : "none"
                    }
                    className={styles.cell}
                    style={{ width, minWidth: declared?.minWidth ?? 72 }}
                    data-testid={`header-${column.id}`}
                    data-pinned={layout.pinned[column.id] ? "true" : undefined}
                    data-colindex={index}
                  >
                    <button
                      type="button"
                      className={styles.headerButton}
                      data-testid={`sort-${column.id}`}
                      onClick={() => toggleSort(column.id)}
                    >
                      {declared?.header ?? column.id}
                      {sortDir ? (
                        <span aria-hidden="true">
                          {" "}
                          {sortDir === "asc" ? "▲" : "▼"}
                        </span>
                      ) : null}
                    </button>
                    {declared?.pinnable ? (
                      <button
                        type="button"
                        aria-label={`Pin ${declared.header}`}
                        className={styles.pinButton}
                        data-testid={`pin-${column.id}`}
                        onClick={() =>
                          patchLayout({
                            pinned: { [column.id]: !layout.pinned[column.id] },
                          })
                        }
                      >
                        {layout.pinned[column.id] ? "Unpin" : "Pin"}
                      </button>
                    ) : null}
                    {declared?.filterable ? (
                      <input
                        className={styles.filterInput}
                        data-testid={`filter-${column.id}`}
                        aria-label={`Filter ${declared.header}`}
                        value={filterDrafts[column.id] ?? query.filters[column.id] ?? ""}
                        onChange={(e) => setFilter(column.id, e.target.value)}
                      />
                    ) : null}
                    <span
                      role="separator"
                      aria-label={`Resize ${declared?.header ?? column.id}`}
                      className={styles.resizer}
                      data-testid={`resize-${column.id}`}
                      onPointerDown={(e) => onResizeDown(e, column.id)}
                    />
                  </div>
                );
              })}
            </div>
          </div>

          <div
            role="rowgroup"
            className={styles.body}
            style={{ height: rowVirtualizer.getTotalSize() }}
          >
            {renderedItems.map((virtual) => {
              const tableRow = tableRows[virtual.index];
              if (!tableRow) return null;
              const id = getRowId(tableRow.original, virtual.index);
              return (
                <div
                  key={virtual.key}
                  role="row"
                  aria-rowindex={virtual.index + 1}
                  aria-selected={selection?.selected.has(id) || undefined}
                  className={styles.row}
                  data-testid="grid-row"
                  data-rowindex={virtual.index}
                  data-active={activeRow === virtual.index ? "true" : undefined}
                  onClick={() => setActiveRow(virtual.index)}
                  style={{
                    height: virtual.size,
                    transform: `translateY(${virtual.start}px)`,
                  }}
                >
                  {selection ? (
                    <div role="gridcell" className={styles.cell}>
                      <input
                        type="checkbox"
                        aria-label={`Select row ${virtual.index + 1}`}
                        data-testid={`select-${virtual.index}`}
                        checked={selection.selected.has(id)}
                        onChange={() => toggleRow(id)}
                      />
                    </div>
                  ) : null}
                  {tableRow.getVisibleCells().map((cell) => {
                    const declared = columnById.get(cell.column.id);
                    const width = layout.widths[cell.column.id] ?? declared?.width ?? 160;
                    return (
                      <div
                        key={cell.id}
                        role="gridcell"
                        className={styles.cell}
                        style={{ width, minWidth: declared?.minWidth ?? 72 }}
                        data-colid={cell.column.id}
                        data-active={
                          activeRow === virtual.index &&
                          activeColumn === cell.column.getIndex()
                            ? "true"
                            : undefined
                        }
                      >
                        {cell.renderValue() as ReactNode}
                      </div>
                    );
                  })}
                </div>
              );
            })}
          </div>

          {tableRows.length === 0 && !loading ? (
            <p className={styles.empty} data-testid="grid-empty">
              {emptyMessage}
            </p>
          ) : null}
          {mode === "server" && nextCursor ? (
            <button
              type="button"
              className={styles.loadMore}
              data-testid="load-more"
              onClick={() => void loadMore()}
            >
              {loading ? "Loading…" : "Load more"}
            </button>
          ) : null}
        </div>
      </div>
    </div>
  );
}