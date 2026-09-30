/**
 * Summary queries (WO-A5): the evidence freshness word the chip renders.
 * Polled lightly — the summary endpoint composes existing state files and
 * never re-hashes.
 */
import { useQuery } from "@tanstack/react-query";
import { api } from "../client";
import { caseKey } from "./keys";

export interface FreshnessBrief {
  verified_at: string;
  result: "ok" | "modified" | "missing" | "unknown" | string;
}

export function useEvidenceFreshness(caseId: string | null, intervalMs = 30_000) {
  return useQuery<FreshnessBrief>({
    queryKey: caseKey(caseId, "summary", "freshness"),
    queryFn: async () => {
      const s = await api.summary();
      const f = (s as { freshness?: FreshnessBrief }).freshness;
      return (
        f ?? { verified_at: "", result: "unknown" }
      );
    },
    enabled: Boolean(caseId),
    refetchInterval: intervalMs,
    staleTime: 15_000,
  });
}
