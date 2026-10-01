/**
 * Query object + per-view column layout (WO-U5 / WP 14.5).
 *
 * The grid never talks to the API: it emits a `GridQuery` and the page decides.
 * The column layout (widths / visibility / pins) is a convenience remembered in
 * localStorage - every access is guarded, because a browser that refuses
 * storage (private mode, quota) must degrade to defaults, never break a page.
 */
import { useCallback, useEffect, useState } from "react";

import type { ColumnLayout, GridQuery, SortDir } from "./types";

const LAYOUT_VERSION = "v1";

export function layoutKey(viewId: string): string {
  return `nexus.grid.${viewId}.${LAYOUT_VERSION}`;
}

export function emptyQuery(): GridQuery {
  return { filters: {}, sort: null };
}

/** Build the query object the grid emits. Blank filter values are dropped. */
export function buildQuery(
  filters: Record<string, string>,
  sort: { by: string; dir: SortDir } | null,
): GridQuery {
  const clean: Record<string, string> = {};
  for (const [key, value] of Object.entries(filters)) {
    const trimmed = value.trim();
    if (trimmed) clean[key] = trimmed;
  }
  return { filters: clean, sort: sort && sort.by ? sort : null };
}

export function loadLayout(viewId: string): Partial<ColumnLayout> {
  try {
    const raw = window.localStorage.getItem(layoutKey(viewId));
    if (!raw) return {};
    const parsed: unknown = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object") return {};
    return parsed as Partial<ColumnLayout>;
  } catch {
    return {}; // storage unavailable or corrupt: defaults win
  }
}

export function saveLayout(viewId: string, layout: ColumnLayout): void {
  try {
    window.localStorage.setItem(layoutKey(viewId), JSON.stringify(layout));
  } catch {
    /* a convenience that failed to persist is not an error worth surfacing */
  }
}

/**
 * Column layout for one view, remembered across reloads. Returns the merged
 * layout plus setters; a failed write never changes what the grid renders.
 */
export function useColumnLayout(
  viewId: string,
  defaults: ColumnLayout,
): [ColumnLayout, (patch: Partial<ColumnLayout>) => void, () => void] {
  const [layout, setLayout] = useState<ColumnLayout>(() => ({
    widths: { ...defaults.widths },
    visibility: { ...defaults.visibility },
    pinned: { ...defaults.pinned },
  }));

  // hydrate once per view; SSR/jsdom without storage keeps the defaults
  useEffect(() => {
    const stored = loadLayout(viewId);
    setLayout((prev) => ({
      widths: { ...prev.widths, ...(stored.widths ?? {}) },
      visibility: { ...prev.visibility, ...(stored.visibility ?? {}) },
      pinned: { ...prev.pinned, ...(stored.pinned ?? {}) },
    }));
  }, [viewId]);

  const patch = useCallback(
    (next: Partial<ColumnLayout>) => {
      setLayout((prev) => {
        const merged: ColumnLayout = {
          widths: { ...prev.widths, ...(next.widths ?? {}) },
          visibility: { ...prev.visibility, ...(next.visibility ?? {}) },
          pinned: { ...prev.pinned, ...(next.pinned ?? {}) },
        };
        saveLayout(viewId, merged);
        return merged;
      });
    },
    [viewId],
  );

  const reset = useCallback(() => {
    saveLayout(viewId, defaults);
    setLayout({
      widths: { ...defaults.widths },
      visibility: { ...defaults.visibility },
      pinned: { ...defaults.pinned },
    });
  }, [defaults, viewId]);

  return [layout, patch, reset];
}