/**
 * Cross-mode view inside a case (WO-1C item 5): which modes reached the same conclusions
 * and where they contradict. Case-scoped, so switching cases is a key change.
 */
import { useQuery } from "@tanstack/react-query";

import { api } from "../client";
import type { CrossModeReport } from "../domains/runs";
import { caseKey } from "./keys";

export function useCrossMode(caseId: string | null | undefined) {
  return useQuery<CrossModeReport>({
    queryKey: caseKey(caseId, "cross-mode"),
    enabled: Boolean(caseId),
    staleTime: 10_000,
    queryFn: () => api.crossMode(),
  });
}
