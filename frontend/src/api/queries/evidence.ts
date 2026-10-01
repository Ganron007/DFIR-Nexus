/**
 * Evidence queries (WO-U8a / WP 14.8, on the U4 hooks).
 *
 * Four reads, one write, one verify. The old page fetched all three reads in a
 * hand-rolled `Promise.all` inside a `useEffect` keyed on the case, held 17
 * pieces of component state, and re-fetched by calling `load()` — so a
 * registration on one surface could leave the registry stale everywhere, and a
 * case switch raced the previous case's response.
 *
 * Nothing here re-hashes anything: the freshness word comes from A5's polled
 * summary, and integrity is verified only when the examiner asks.
 */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api } from "../client";
import { caseKey } from "./keys";

export interface EvidenceRow {
  path?: string;
  name?: string;
  sha256?: string;
  description?: string;
  status?: string;
  registered_at?: string;
}

/** The registry itself. */
export function useEvidenceRegistry(caseId: string | null | undefined) {
  return useQuery<{ evidence: EvidenceRow[] }>({
    queryKey: caseKey(caseId, "evidence"),
    enabled: Boolean(caseId),
    staleTime: 15_000,
    queryFn: () => api.evidence() as Promise<{ evidence: EvidenceRow[] }>,
  });
}

/**
 * Case intake — the examiner's question, which Mode 2/3 interpretation
 * reconciles evidence against. Kept as its own query so the N2 guard can read
 * it without the page holding a second copy of the case.
 */
export function useCaseIntake(caseId: string | null | undefined) {
  return useQuery<{ question: string; pipelineComplete: boolean }>({
    queryKey: caseKey(caseId, "case-details"),
    enabled: Boolean(caseId),
    staleTime: 60_000,
    queryFn: async () => {
      try {
        const details = (await api.caseDetails(caseId as string)) as unknown as
          | Record<string, unknown>
          | null;
        const intake = (details?.intake || {}) as Record<string, unknown>;
        return {
          question: String(intake.question || details?.description || ""),
          pipelineComplete: Boolean(details?.pipeline_complete),
        };
      } catch {
        return { question: "", pipelineComplete: false };
      }
    },
  });
}

/** Parser-lane ledger — which parsers ran, on which evidence. */
export function usePipelineLedger(caseId: string | null | undefined) {
  return useQuery<{
    ledger?: {
      tool?: string;
      status?: string;
      argv?: string[];
      output_saved_to?: string;
      reason?: string;
      detail?: string;
    }[];
    run_id?: string;
    run_status?: string;
    evidence_paths?: string[];
    error?: string;
  }>({
    queryKey: caseKey(caseId, "pipeline-ledger"),
    enabled: Boolean(caseId),
    staleTime: 10_000,
    queryFn: async () => {
      // An absent ledger is not an error: the lane may simply never have run.
      try {
        return (await api.pipelineLedger()) as never;
      } catch {
        return {};
      }
    },
  });
}

export interface TsCoverage {
  present?: number;
  missing?: number;
  synthesized?: number;
  tz_assumed?: number;
  year_assumed?: number;
}

/**
 * Timestamp coverage, off the critical path: building the digest can scan the
 * corpus, so it is its own query and its own failure.
 */
export function useTsCoverage(
  caseId: string | null | undefined,
  { enabled = true }: { enabled?: boolean } = {},
) {
  return useQuery<Record<string, TsCoverage>>({
    queryKey: caseKey(caseId, "ts-coverage"),
    enabled: Boolean(caseId) && enabled,
    staleTime: 30_000,
    retry: false,
    queryFn: async () => {
      const digest = (await api.caseDigest()) as {
        digest?: { ts_coverage?: Record<string, TsCoverage> };
      } | null;
      return digest?.digest?.ts_coverage || {};
    },
  });
}

export interface VerifyResult {
  total: number;
  valid: number;
  failed: number;
  /** Keyed by both file_path and name, so a row matches either way. */
  byKey: Record<string, { valid: boolean; error?: string }>;
}

/**
 * Cryptographic integrity check. On demand only - it reads every registered
 * file off disk, so it must never fire because a page happened to mount.
 */
export function useVerifyEvidence(caseId: string | null | undefined) {
  return useMutation<VerifyResult, Error, void>({
    mutationKey: caseKey(caseId, "evidence-verify"),
    mutationFn: async () => {
      const response = await api.evidenceVerify();
      if (!response.ok) {
        throw new Error("Failed to verify evidence integrity");
      }
      const byKey: VerifyResult["byKey"] = {};
      let valid = 0;
      for (const row of response.results) {
        byKey[row.file_path] = { valid: row.valid, error: row.error };
        byKey[row.name] = { valid: row.valid, error: row.error };
        if (row.valid) valid += 1;
      }
      return {
        total: response.results.length,
        valid,
        failed: response.results.length - valid,
        byKey,
      };
    },
  });
}

/**
 * Register one or more paths. Each is registered independently and every
 * failure is reported: a batch of ten paths where the third fails must say so
 * rather than reporting the batch as done.
 */
export function useRegisterEvidence(caseId: string | null | undefined) {
  const queryClient = useQueryClient();
  return useMutation<string[], Error, string[]>({
    mutationKey: caseKey(caseId, "evidence-register"),
    mutationFn: async (rawPaths) => {
      const failures: string[] = [];
      for (const raw of rawPaths) {
        // Examiners paste "C:\path with spaces"; strip the quotes.
        const path = raw.trim().replace(/^["']+|["']+$/g, "").trim();
        if (!path) continue;
        try {
          const response = await api.registerEvidence(path, caseId as string);
          if (!response.ok) {
            failures.push(`${path}: ${response.error || "failed"}`);
          }
        } catch (error) {
          failures.push(`${path}: ${(error as Error).message}`);
        }
      }
      if (failures.length) {
        throw new Error(`Some paths failed: ${failures.join("; ")}`);
      }
      return rawPaths;
    },
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: caseKey(caseId, "evidence") });
    },
  });
}
