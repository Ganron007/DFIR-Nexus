/**
 * Entity extraction (WO-U8a / WP 14.8, on the U4 hooks).
 *
 * `api.entities` is a POST with a body (needles), so it cannot ride the GET
 * cache the way a read can. The mutation is still keyed per case, so the
 * result shown belongs to the case that produced it - the old page kept the
 * previous case's table on screen while the next request was in flight.
 */
import { useMutation } from "@tanstack/react-query";

import { api, type EntitiesResponse } from "../client";
import { caseKey } from "./keys";

export type EntityRow = { type: string; value: string; count: number };

/** Flatten the `type -> {value: count}` response, busiest first. */
export function flattenEntities(
  entities: EntitiesResponse["entities"] | null | undefined,
): EntityRow[] {
  const rows: EntityRow[] = [];
  for (const [type, dict] of Object.entries(entities ?? {})) {
    for (const [value, count] of Object.entries(dict ?? {})) {
      rows.push({ type, value, count });
    }
  }
  return rows.sort((a, b) => b.count - a.count);
}

export interface EntitiesResult {
  rows: EntityRow[];
  total: number;
  needles: string;
}

export function useExtractEntities(caseId: string | null | undefined) {
  return useMutation<EntitiesResult, Error, string>({
    mutationKey: caseKey(caseId, "entities"),
    mutationFn: async (needles: string) => {
      const response = await api.entities({ needles: needles || undefined });
      return {
        rows: flattenEntities(response.entities),
        total: response.total,
        needles,
      };
    },
  });
}
