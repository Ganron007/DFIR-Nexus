/**
 * The one status query (WO-U3).
 *
 * Case-scoped by construction (U4's key rule), polled on the same cadence as
 * the health probe so the stepper, the gate banner and the page headers cannot
 * drift apart between refreshes.
 */
import { useQuery } from "@tanstack/react-query";
import { useParams } from "react-router-dom";

import { api } from "../client";
import { caseKey } from "./keys";
import { caseIdFromPath } from "../../shell/caseScope";
import type { CaseStatusResponse } from "../../api/caseStatus";

export interface CaseStatusState {
  backend: "ok" | "error";
  status: CaseStatusResponse | null;
  error: string;
}

/** The case id in scope: the URL first, then the server's active case. */
export function useScopedCaseId(fallback: string | null | undefined): string {
  const params = useParams();
  const fromUrl = caseIdFromPath(typeof window === "undefined" ? "" : window.location.pathname);
  void params; // the router param is read by the caller's route element
  return fromUrl || (fallback ?? "");
}

/** Fetch the case status. Disabled without a case id - never guesses one. */
export function useCaseStatus(caseId: string | null | undefined, intervalMs = 30_000) {
  return useQuery<CaseStatusResponse>({
    queryKey: caseKey(caseId, "status"),
    enabled: Boolean(caseId),
    refetchInterval: intervalMs,
    staleTime: 10_000,
    retry: false,
    queryFn: async () => {
      const status = await api.caseStatus(caseId as string);
      if (!status || typeof status !== "object" || !("stages" in status)) {
        throw new Error("case status response is not a status object");
      }
      return status;
    },
  });
}

export { type CaseStatusResponse };