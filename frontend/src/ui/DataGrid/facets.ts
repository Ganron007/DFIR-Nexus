/**
 * Facet side-panel hook (WO-U5 / WP 14.5).
 *
 * The panel is headless too: it counts values in whatever rows it is handed and
 * emits into the same query object the filters write to, so a facet click and a
 * filter box are the same operation from the API's point of view. In server
 * mode the counts belong to the server — hand the hook the page and treat the
 * numbers as a sample, or skip it and render the server's facets.
 */
import { useCallback, useMemo } from "react";

import { buildQuery } from "./query";
import type { DataGridColumn, Facet, GridQuery } from "./types";

export interface FacetPanelOptions<T> {
  rows: T[];
  columns: DataGridColumn<T>[];
  query: GridQuery;
  onQueryChange: (query: GridQuery) => void;
  /** Which columns get a facet; defaults to every column. */
  facetColumns?: string[];
  /** Max values per facet before the panel shows "…". */
  limit?: number;
}

function cellText<T>(column: DataGridColumn<T>, row: T): string {
  if (column.copyValue) return column.copyValue(row) ?? "";
  const accessor = column.accessorFn;
  if (typeof accessor === "function") return String(accessor(row, 0) ?? "");
  return String((row as Record<string, unknown>)[column.id] ?? "");
}

export function useFacetPanel<T>(options: FacetPanelOptions<T>): {
  facets: Facet[];
  selected: Record<string, string>;
  toggle: (columnId: string, value: string) => void;
  clear: () => void;
} {
  const { rows, columns, query, onQueryChange, limit = 12 } = options;
  const facetColumns = options.facetColumns ?? columns.map((c) => c.id);

  const facets = useMemo<Facet[]>(() => {
    const out: Facet[] = [];
    for (const columnId of facetColumns) {
      const column = columns.find((c) => c.id === columnId);
      if (!column) continue;
      const counts = new Map<string, number>();
      for (const row of rows) {
        const text = cellText(column, row).trim();
        if (!text) continue;
        counts.set(text, (counts.get(text) ?? 0) + 1);
      }
      out.push({
        columnId,
        values: [...counts.entries()]
          .map(([value, count]) => ({ value, count }))
          .sort((a, b) => b.count - a.count || a.value.localeCompare(b.value))
          .slice(0, limit),
      });
    }
    return out;
  }, [rows, columns, facetColumns, limit]);

  const toggle = useCallback(
    (columnId: string, value: string) => {
      const next = { ...query.filters };
      if (next[columnId] === value) delete next[columnId];
      else next[columnId] = value;
      onQueryChange(buildQuery(next, query.sort));
    },
    [query, onQueryChange],
  );

  const clear = useCallback(() => {
    onQueryChange(buildQuery({}, query.sort));
  }, [query, onQueryChange]);

  return { facets, selected: query.filters, toggle, clear };
}