/**
 * Cases queries (WO-U4): the cases list with the active pointer, shared
 * through the cache instead of per-page fetching.
 */
import { useQuery } from "@tanstack/react-query";
import { api } from "../client";
import { systemKey } from "./keys";

export function useCases(intervalMs = 30_000) {
  return useQuery({
    queryKey: systemKey("cases"),
    queryFn: () => api.cases(),
    refetchInterval: intervalMs,
    staleTime: 15_000,
  });
}
