/**
 * Findings & approval domain (WO-U4): the findings list, the Mode 1
 * workbench, and the password-gated commit/reject paths.
 */
import { post, request } from "../transport";
import type {
  AuditResponse,
  ChallengeResponse,
  CommitResponse,
  CommitStatusResponse,
  FindingsResponse,
  Mode1FullRunResponse,
  N4Hit,
  WorkbenchAddManyResponse,
  WorkbenchAddResponse,
  WorkbenchClearResponse,
  WorkbenchPromoteResponse,
  WorkbenchRemoveResponse,
  WorkbenchResponse,
} from "../client";

export const findingsApi = {
  findings: (status?: string, limit?: number) => {
    const params = new URLSearchParams();
    if (status) params.set("status", status);
    if (limit) params.set("limit", String(limit));
    const qs = params.toString();
    return request<FindingsResponse>(`/findings${qs ? `?${qs}` : ""}`);
  },
  auditForFinding: (findingId: string) =>
    request<AuditResponse>(`/audit/${findingId}`),

  // Workbench (Mode 1 bookmarks → promote)
  workbench: () => request<WorkbenchResponse>("/workbench"),
  workbenchAdd: (hit: N4Hit, note?: string) =>
    post<WorkbenchAddResponse>("/workbench/add", { hit, note }),
  /** Bookmark every hit matching the current Explore query (same params as
   *  api.search) — the server re-runs the N4 query so "all" means the full
   *  result set, not just the rendered page. */
  workbenchAddMany: (params: {
    needles?: string; query?: string; family?: string; host?: string;
    start?: string; end?: string; note?: string;
  }) => post<WorkbenchAddManyResponse>("/workbench/add_many", params),
  /** Mode 1 full run — scan all needles → bookmark all hits → stage one
   *  DRAFT per needle (heuristic scribe). Approval stays manual. */
  mode1FullRun: (params?: { max_needles?: number; needle_filter?: string; reprocess?: boolean }) =>
    post<Mode1FullRunResponse>("/mode1/full-run", params || {}),
  mode1FullRunStatus: () => request<Mode1FullRunResponse>("/mode1/full-run/status"),
  workbenchRemove: (bookmarkId: string) =>
    post<WorkbenchRemoveResponse>("/workbench/remove", { bookmark_id: bookmarkId }),
  workbenchClear: () => post<WorkbenchClearResponse>("/workbench/clear"),
  workbenchPromote: (params: {
    bookmark_ids: string[];
    title: string;
    scribe?: boolean;
    interpretation?: string;
    confidence?: string;
    confidence_justification?: string;
  }) => post<WorkbenchPromoteResponse>("/workbench/promote", params),

  // Approval & Rejection (HMAC challenge-response)
  getChallenge: () => request<ChallengeResponse>("/commit/challenge"),
  commitStatus: () => request<CommitStatusResponse>("/commit/status"),
  commit: (params: {
    finding_ids: string[];
    challenge_id: string;
    response: string;
    examiner?: string;
    /** WO-2: per-finding reason when the L1 verdict is not PROVEN. */
    override_reasons?: Record<string, string>;
  }) => post<CommitResponse>("/commit", params),
  rejectFindings: (params: {
    finding_ids: string[];
    reason: string;
    examiner?: string;
  }) => post<{ ok: boolean; rejected: string[]; error?: string }>("/findings/reject", params),
};
