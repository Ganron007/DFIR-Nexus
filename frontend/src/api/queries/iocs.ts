/**
 * IOCs queries (WO-U8a / WP 14.8, on the U4 hooks).
 *
 * The page used to fetch on mount with `useEffect` and its own loading and
 * error state. That is a request with no cache key, no cancellation and no
 * case scoping: switching cases could show the previous case's IOCs until the
 * new response landed. The hook is case-scoped by construction, so switching
 * case is a key change and the old rows cannot survive it.
 */
import { useQuery } from "@tanstack/react-query";

import { api, type Ioc } from "../client";
import { caseKey } from "./keys";

export function useIocs(caseId: string | null | undefined) {
  return useQuery<{ iocs: Ioc[] }>({
    queryKey: caseKey(caseId, "iocs"),
    enabled: Boolean(caseId),
    staleTime: 30_000,
    queryFn: () => api.iocs(),
  });
}
