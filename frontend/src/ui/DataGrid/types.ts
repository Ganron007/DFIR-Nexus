/**
 * DataGrid types (WO-U5 / WP 14.5). The grid is headless: TanStack Table owns
 * column/sort state, TanStack Virtual owns the window, and this module owns
 * only the contract the pages speak (a query object in, pages out).
 */
export type SortDir = "asc" | "desc";

/** What the grid emits when a filter or a sort changes. Pages send it verbatim. */
export interface GridQuery {
  filters: Record<string, string>;
  sort: { by: string; dir: SortDir } | null;
}

export interface GridPage<T> {
  rows: T[];
  /** null = end of the data set (server mode). */
  nextCursor: string | null;
  /** null = the server does not know (client mode, or an unbounded count). */
  total: number | null;
}

export interface GridFetchRequest {
  cursor: string | null;
  query: GridQuery;
  signal?: AbortSignal;
}

export type FetchPage<T> = (req: GridFetchRequest) => Promise<GridPage<T>>;

/**
 * A grid column, in the grid's own terms.
 *
 * Deliberately not TanStack's `AccessorFnColumnDef`: that is an intersection
 * alias, and a kit type that leaks a dependency's internals makes every page
 * compile against TanStack. `DataGrid` maps these into the table.
 */
export interface DataGridColumn<T> {
  id: string;
  header: string;
  /** How the cell reads its value. Defaults to `row[id]`. */
  accessorFn?: (row: T, index: number) => string;
  /** Per-column text filter (emits into GridQuery.filters). */
  filterable?: boolean;
  pinnable?: boolean;
  width?: number;
  minWidth?: number;
  /** Plain-text value used by keyboard copy; defaults to the cell text. */
  copyValue?: (row: T) => string;
}

/** Per-view column layout. A convenience, never state: load/save are guarded. */
export interface ColumnLayout {
  widths: Record<string, number>;
  visibility: Record<string, boolean>;
  pinned: Record<string, boolean>;
}

export interface SelectionState {
  selected: Set<string>;
  onChange: (next: Set<string>) => void;
}

export interface FacetValue {
  value: string;
  count: number;
}

export interface Facet {
  columnId: string;
  values: FacetValue[];
}