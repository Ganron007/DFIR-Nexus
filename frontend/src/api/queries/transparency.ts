/**
 * Transparency (audit chain verification) query (WO-U8a, on the U4 hooks).
 *
 * Case-scoped: the chain belongs to a case, and the previous page fetched it
 * with an uncached `useEffect` keyed on nothing, so switching case could leave
 * the previous case's verdict on screen.
 */
import { useQuery } from "@tanstack/react-query";

import { api } from "../client";
import { caseKey } from "./keys";

export interface TransparencyResult {
  valid: boolean;
  entries: number;
  error?: string;
  tampered?: number | string;
  expected?: string;
  actual?: string;
  expected_previous?: string;
  actual_previous?: string;
}

export function useTransparency(caseId: string | null | undefined) {
  return useQuery<TransparencyResult>({
    queryKey: caseKey(caseId, "transparency"),
    enabled: Boolean(caseId),
    staleTime: 30_000,
    queryFn: async () => {
      const response = (await api.transparency()) as unknown as TransparencyResult;
      // The endpoint answers a Record; a body without `valid` is not a verdict
      // and must not render as one.
      if (!response || typeof response !== "object" || typeof response.valid !== "boolean") {
        throw new Error("transparency response carried no verdict");
      }
      return response;
    },
  });
}
