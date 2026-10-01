/**
 * DataGrid (WO-U5 / WP 14.5) - headless grid + facet hook.
 * Import from "@/ui" - never deep-import a file from page code.
 */
export { DataGrid, type DataGridProps } from "./DataGrid";
export {
  buildQuery,
  emptyQuery,
  layoutKey,
  loadLayout,
  saveLayout,
  useColumnLayout,
} from "./query";
export { useFacetPanel, type FacetPanelOptions } from "./facets";
export type {
  ColumnLayout,
  DataGridColumn,
  Facet,
  FacetValue,
  FetchPage,
  GridFetchRequest,
  GridPage,
  GridQuery,
  SelectionState,
  SortDir,
} from "./types";