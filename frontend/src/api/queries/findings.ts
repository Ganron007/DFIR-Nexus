/**
 * Findings queries (WO-U8a / WP 14.8, on the U4 hooks).
 *
 * Corroboration (FD-006/007) and the audit trail are per-finding reads, so
 * each is its own case-scoped query rather than a component-level dictionary
 * that a case switch would leave populated with the previous case's results.
 */
import { useQuery } from "@tanstack/react-query";

import { api, type CorroborationResponse, type Finding } from "../client";
import type { SemanticTone } from "@/ui";
import { caseKey } from "./keys";

export function useFindings(caseId: string | null | undefined) {
  return useQuery<{ findings: Finding[] }>({
    queryKey: caseKey(caseId, "findings"),
    enabled: Boolean(caseId),
    staleTime: 15_000,
    queryFn: () => api.findings(),
  });
}

export function useCorroboration(
  caseId: string | null | undefined,
  findingId: string | null,
) {
  return useQuery<CorroborationResponse>({
    queryKey: caseKey(caseId, "corroboration", findingId ?? ""),
    // On demand: the examiner asks whether a claim is corroborated, it is not
    // checked for every finding the moment the list loads.
    enabled: Boolean(caseId && findingId),
    staleTime: 0,
    queryFn: () => api.mode1Corroborate({ finding_id: findingId as string }),
  });
}

export function useFindingAuditTrail(
  caseId: string | null | undefined,
  findingId: string | null,
) {
  return useQuery<unknown[]>({
    queryKey: caseKey(caseId, "finding-audit", findingId ?? ""),
    enabled: Boolean(caseId && findingId),
    staleTime: 0,
    queryFn: () => api.auditForFinding(findingId as string),
  });
}

/** Severity -> semantic tone. The kit's vocabulary, not a second colour set. */
export function severityTone(severity: string | undefined): SemanticTone | undefined {
  switch ((severity ?? "").toLowerCase()) {
    case "critical":
      return "sev-critical";
    case "high":
      return "sev-high";
    case "medium":
      return "sev-medium";
    case "low":
      return "sev-low";
    default:
      return undefined;
  }
}

/** Approval state -> seal/verdict tone. */
export function statusTone(status: string | undefined): SemanticTone | undefined {
  switch ((status ?? "").toUpperCase()) {
    case "APPROVED":
      return "seal-verified";
    case "REJECTED":
      return "verifier-refuted";
    case "DRAFT":
      return "l1-unsupported";
    default:
      return undefined;
  }
}
