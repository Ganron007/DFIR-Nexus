/**
 * Report queries (WO-U8a / WP 14.8, on the U4 hooks).
 *
 * The report page fetched four things in one hand-rolled `Promise.all` inside a
 * `useEffect`, and re-fetched by calling `loadData()` after every steer. Each
 * read is now its own case-scoped query, so a steer invalidates exactly the
 * report view and the round log it changed.
 */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api, type Finding } from "../client";
import { caseKey } from "./keys";

export interface FindingsSummary {
  total: number;
  approved: number;
  draft: number;
  rejected: number;
}

/** APPROVED findings only - the report never includes DRAFT. */
export function useApprovedFindings(caseId: string | null | undefined) {
  return useQuery<{ findings: Finding[]; total: number }>({
    queryKey: caseKey(caseId, "findings", "APPROVED"),
    enabled: Boolean(caseId),
    staleTime: 15_000,
    queryFn: () => api.findings("APPROVED"),
  });
}

export function useFindingsSummary(caseId: string | null | undefined) {
  return useQuery<FindingsSummary>({
    queryKey: caseKey(caseId, "summary"),
    enabled: Boolean(caseId),
    staleTime: 30_000,
    // A missing summary is not an error: the report still renders without it.
    queryFn: async () => {
      try {
        const response = await api.summary();
        return response.findings as FindingsSummary;
      } catch {
        return null as unknown as FindingsSummary;
      }
    },
  });
}

export function useReportView(caseId: string | null | undefined) {
  return useQuery<{ ok: boolean; markdown?: string; error?: string }>({
    queryKey: caseKey(caseId, "report-view"),
    enabled: Boolean(caseId),
    staleTime: 30_000,
    retry: false,
    queryFn: () => api.reportView() as Promise<never>,
  });
}

export interface ReportRound {
  round: number;
  ts: string;
  instruction: string;
  finding_id?: string;
  model?: string;
  findings_hash?: string;
  report_sha256?: string;
  snapshot_path?: string;
  previous_report_sha256?: string;
}

export function useReportRounds(caseId: string | null | undefined) {
  return useQuery<{ rounds: ReportRound[] }>({
    queryKey: caseKey(caseId, "report-rounds"),
    enabled: Boolean(caseId),
    staleTime: 5_000,
    retry: false,
    queryFn: async () => {
      try {
        return (await api.reportRounds()) as { rounds: ReportRound[] };
      } catch {
        return { rounds: [] };
      }
    },
  });
}

/** Compile the official report, then refresh the view it produced. */
export function useGenerateReport(caseId: string | null | undefined) {
  const queryClient = useQueryClient();
  return useMutation<
    { ok: boolean; findings_count?: number; error?: string },
    Error,
    void
  >({
    mutationKey: caseKey(caseId, "report-generate"),
    mutationFn: async () => {
      const response = await api.reportGenerate({ profile: "markdown" });
      if (!response.ok) {
        throw new Error(response.error || "Failed to generate report");
      }
      return response as { ok: boolean; findings_count?: number };
    },
    onSuccess: async () => {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: caseKey(caseId, "report-view") }),
        queryClient.invalidateQueries({ queryKey: caseKey(caseId, "report-rounds") }),
      ]);
    },
  });
}

/**
 * One steer round. Each round re-reads the live evidence with the examiner's
 * direction; the round log is audit-chained, so it is refreshed with the view.
 */
export function useSteerReport(caseId: string | null | undefined) {
  const queryClient = useQueryClient();
  return useMutation<
    { round: number; instructions_applied: number },
    Error,
    { instruction: string; finding_id?: string }
  >({
    mutationKey: caseKey(caseId, "report-steer"),
    mutationFn: async (input) => {
      const response = await api.reportSteer(input);
      if (!response.ok) throw new Error(response.error || "Steer failed");
      return {
        round: response.round,
        instructions_applied: response.instructions_applied,
      };
    },
    onSuccess: async () => {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: caseKey(caseId, "report-view") }),
        queryClient.invalidateQueries({ queryKey: caseKey(caseId, "report-rounds") }),
      ]);
    },
  });
}
